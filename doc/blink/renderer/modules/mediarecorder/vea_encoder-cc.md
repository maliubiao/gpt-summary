Response:
Let's break down the thought process for analyzing the `vea_encoder.cc` file.

**1. Understanding the Request:**

The request asks for the functionalities of the `vea_encoder.cc` file, its relation to web technologies (JS, HTML, CSS), logical reasoning (input/output), common user errors, and how a user's action might lead to this code being executed.

**2. Initial Code Scan and Keyword Identification:**

I started by quickly scanning the code, looking for keywords and recognizable patterns. Keywords that stood out were:

* `VEAEncoder`: The main class name, suggesting it's responsible for video encoding acceleration.
* `mediarecorder`: The directory path confirms its role in the MediaRecorder API.
* `VideoEncodeAccelerator`: This is a core media component, indicating hardware-accelerated encoding.
* `GpuFactories`: Implies interaction with the GPU.
* `Bitrate`, `VideoCodecProfile`, `gfx::Size`: These are standard video encoding parameters.
* `EncodeFrame`, `BitstreamBufferReady`:  These are core encoding lifecycle methods.
* `on_encoded_video_cb_`, `on_error_cb_`: Callbacks for delivering encoded data and errors.
* `javascript`, `html`, `css`: Explicit keywords to look for connections to web technologies.

**3. Deciphering the Core Functionality:**

Based on the keywords and the overall structure, I deduced that `VEAEncoder` is a class responsible for encoding video frames using hardware acceleration (via `VideoEncodeAccelerator`). It takes raw video frames as input and produces encoded video data.

**4. Mapping Functionality to Methods:**

I then went through the methods to understand their specific roles:

* **Constructor (`VEAEncoder`)**:  Initializes the encoder with configuration parameters (bitrate, codec, size, etc.) and callbacks.
* **`RequireBitstreamBuffers`**: Sets up the output buffers used to receive encoded data. It interacts with the GPU to allocate shared memory.
* **`BitstreamBufferReady`**: This is a callback from the `VideoEncodeAccelerator`, indicating that encoded data is ready in an output buffer. It packages the encoded data into a `DecoderBuffer` and invokes the `on_encoded_video_cb_`.
* **`NotifyErrorStatus`**: Handles errors reported by the underlying video encoder.
* **`UseOutputBitstreamBufferId`**:  Informs the `VideoEncodeAccelerator` that an output buffer is available for writing.
* **`EncodeFrame`**: The core encoding method. It takes a `VideoFrame` and triggers the encoding process. It handles cases where the encoder needs to be reconfigured and deals with potential format conversions or copies.
* **`Initialize`**: Sets up the encoder with initial parameters.
* **`ConfigureEncoder`**:  Creates and initializes the `VideoEncodeAccelerator` with specific settings.

**5. Identifying Connections to Web Technologies:**

The directory name (`mediarecorder`) immediately suggested a link to the JavaScript MediaRecorder API. I then thought about how this API is used:

* **JavaScript `MediaRecorder`**: The user interacts with this API in JavaScript.
* **HTML `<video>` or `<canvas>`**: The video stream being recorded likely originates from a `<video>` element (from a webcam or media file) or is drawn on a `<canvas>`.
* **CSS (Indirectly)**: While CSS doesn't directly trigger encoding, it can affect the visual presentation that ultimately gets recorded (e.g., applying filters or transformations to a `<video>` or `<canvas>`).

**6. Constructing Examples:**

Based on the identified connections, I created illustrative examples for JavaScript, HTML, and CSS:

* **JavaScript:**  Demonstrating how `MediaRecorder` is used to start and stop recording and how to access the encoded data.
* **HTML:** Showing a simple `<video>` element that could be the source of the recorded stream.
* **CSS:**  Illustrating how CSS could affect the appearance of the video being recorded.

**7. Logical Reasoning (Input/Output):**

I focused on the `EncodeFrame` method and the `BitstreamBufferReady` callback to define the input and output:

* **Input:** `media::VideoFrame` (raw video data), `capture_timestamp`, `request_keyframe`.
* **Output:** Encoded video data (`media::DecoderBuffer`), metadata (keyframe status, encoded size).

**8. Identifying User Errors:**

I considered common mistakes developers might make when using the MediaRecorder API that could indirectly lead to issues in the `VEAEncoder`:

* **Incorrectly setting `mimeType`:** This is a common source of problems as it determines the codec used.
* **Not handling errors:**  Ignoring errors from `MediaRecorder` can lead to unexpected behavior.
* **Modifying the video source during recording:** This can cause issues with frame sizes and encoding.

**9. Tracing User Actions (Debugging Clues):**

I outlined a step-by-step scenario of a user interacting with a web page that uses `MediaRecorder` to demonstrate how the execution might reach the `VEAEncoder`:

1. User opens a webpage using MediaRecorder.
2. JavaScript requests access to the camera/microphone.
3. User grants permission.
4. JavaScript initializes MediaRecorder with specific configurations.
5. User starts recording.
6. Browser captures video frames.
7. These frames are passed to the `VEAEncoder` for hardware-accelerated encoding.

**10. Review and Refinement:**

Finally, I reviewed the entire analysis to ensure clarity, accuracy, and completeness. I made sure the examples were easy to understand and that the explanations were logically connected. I double-checked the code snippets for correctness (though they are illustrative).

This systematic approach, combining code analysis with an understanding of the broader web platform and common developer practices, allowed me to generate a comprehensive and informative response to the request.
好的，让我们来详细分析一下 `blink/renderer/modules/mediarecorder/vea_encoder.cc` 这个文件。

**文件功能：**

`vea_encoder.cc` 文件实现了 Chromium Blink 引擎中用于**硬件加速视频编码**的功能。更具体地说，它是 `MediaRecorder` API 的一部分，利用 GPU 上的 Video Encode Accelerator (VEA) 来高效地将视频帧编码成各种格式（例如 H.264）。

以下是其主要功能点的详细说明：

1. **硬件加速编码:**  核心功能是使用 GPU 提供的硬件编码能力，这比纯软件编码效率更高，能耗更低。它依赖于 `media::VideoEncodeAccelerator` 接口与底层的硬件编码器进行交互。

2. **`MediaRecorder` 集成:**  这个类是 `MediaRecorder` 模块的一部分，负责处理 `MediaRecorder` 接收到的视频帧，并将其编码成可以存储或传输的格式。

3. **支持多种视频格式:** 虽然代码中没有明确列出所有支持的格式，但它通过 `media::VideoCodecProfile` 来指定编码的格式，这通常包括 H.264 等常见的视频编解码器。

4. **帧管理:**  管理输入视频帧的接收、处理和提交给硬件编码器。

5. **比特率控制:**  允许设置目标比特率，以控制编码后视频的质量和文件大小。支持固定比特率 (CBR) 和可变比特率 (VBR)。

6. **关键帧请求:**  可以请求编码器生成关键帧，这对于视频的随机访问和流媒体至关重要。

7. **错误处理:**  包含错误处理机制，当硬件编码器出现问题时，会通过 `OnErrorCB` 回调通知上层。

8. **与 GPU 交互:**  通过 `Platform::Current()->GetGpuFactories()` 获取 GPU 工厂，用于创建与 GPU 相关的资源，如共享内存区域。

9. **输出缓冲管理:**  管理用于接收编码后数据的输出缓冲区，使用共享内存提高效率。

10. **性能指标收集:**  使用 `base::metrics::HistogramMacros` 和 `media::VideoEncoderMetricsProvider` 收集编码性能指标，用于监控和分析。

**与 JavaScript, HTML, CSS 的关系：**

`vea_encoder.cc` 文件本身是用 C++ 编写的，是 Blink 渲染引擎的底层实现，**不直接**与 JavaScript、HTML 或 CSS 代码交互。然而，它作为 `MediaRecorder` API 的一部分，是这些 Web 技术功能实现的基础。

以下是它们之间的关系：

* **JavaScript:**  Web 开发者使用 JavaScript 的 `MediaRecorder` API 来录制音频和视频。当开发者调用 `MediaRecorder.start()` 开始录制视频时，Blink 引擎内部会创建 `VEAEncoder` 的实例（在合适的条件下，例如启用了硬件加速）。`VEAEncoder` 负责处理从媒体流获取的视频帧，并将其编码。编码后的数据会通过 `dataavailable` 事件返回给 JavaScript 代码。

   **举例说明:**
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(function(stream) {
       const mediaRecorder = new MediaRecorder(stream, { mimeType: 'video/webm; codecs=h264' });

       mediaRecorder.ondataavailable = function(event) {
         // event.data 包含编码后的视频数据 (Blob)
         console.log('Encoded data available:', event.data);
       };

       mediaRecorder.start(); // 此时可能会创建 VEAEncoder 实例
       setTimeout(() => mediaRecorder.stop(), 5000);
     });
   ```

* **HTML:** HTML 用于创建网页结构，其中可能包含 `<video>` 元素或 `<canvas>` 元素作为视频录制的来源。`MediaRecorder` 可以捕获来自这些元素的视频流。

   **举例说明:**
   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <title>MediaRecorder Example</title>
   </head>
   <body>
     <video id="myVideo" width="320" height="240" autoplay muted></video>
     <button id="startRecord">Start Recording</button>
     <script>
       // ... (JavaScript 代码，使用 getUserMedia 或 captureStream 从 video 元素获取流)
     </script>
   </body>
   </html>
   ```

* **CSS:** CSS 用于控制网页的样式。虽然 CSS 不会直接触发视频编码，但它可以影响被录制的视频内容的外观。例如，如果 CSS 应用了滤镜或变换到 `<video>` 元素，那么 `MediaRecorder` 捕获的视频流将会包含这些效果，并由 `VEAEncoder` 进行编码。

   **举例说明:**
   ```css
   #myVideo {
     filter: grayscale(100%);
   }
   ```
   如果上面的 CSS 应用于 HTML 中的 `<video>` 元素，并且 `MediaRecorder` 录制该视频，那么编码后的视频将是灰度的。

**逻辑推理 (假设输入与输出):**

假设输入是一个 `media::VideoFrame` 对象，表示一帧原始视频数据，以及一些编码参数：

* **假设输入:**
    * `media::VideoFrame`: 包含像素数据，例如一个 640x480 的 RGB 或 YUV 帧。
    * `capture_timestamp`: 帧捕获的时间戳。
    * `request_keyframe`: `false` (表示不需要强制生成关键帧)。
    * `bits_per_second`: 1000000 (1 Mbps 的目标比特率)。
    * `codec`: `media::VideoCodecProfile::kH264High` (H.264 High Profile)。
    * `size`: `gfx::Size(640, 480)`。

* **逻辑处理:**
    1. `EncodeFrame` 方法被调用，接收到上述 `media::VideoFrame`。
    2. 如果硬件编码器尚未初始化，则会根据提供的参数进行初始化 (`ConfigureEncoder`)。
    3. `VEAEncoder` 将 `media::VideoFrame` 提交给底层的 `media::VideoEncodeAccelerator` 进行编码。这可能涉及将数据复制到共享内存区域，以便 GPU 可以访问。
    4. 硬件编码器执行编码操作。
    5. 编码完成后，`BitstreamBufferReady` 回调被触发，提供编码后的数据和元数据。

* **预期输出:**
    * `media::DecoderBuffer`: 包含编码后的 H.264 视频帧数据，以字节流的形式存在。
    * `media::BitstreamBufferMetadata`: 包含关于编码帧的元数据，例如 `key_frame`（是否是关键帧）、`payload_size_bytes`（编码数据大小）等。
    * `on_encoded_video_cb_` 回调会被调用，传递 `media::DecoderBuffer` 和其他相关信息。

**用户或编程常见的使用错误：**

1. **`MediaRecorder` 配置错误:** 用户或开发者可能在 JavaScript 中设置了错误的 `mimeType`，导致 `VEAEncoder` 无法初始化或找到合适的硬件编码器。
   * **例子:**  `new MediaRecorder(stream, { mimeType: 'video/weird-format' });`  如果浏览器不支持 "video/weird-format" 及其相关的硬件编码器，则编码会失败。

2. **不支持的视频尺寸或格式:** 硬件编码器可能对输入视频的尺寸或像素格式有特定要求。如果输入的 `VideoFrame` 不符合这些要求，编码可能会失败。
   * **例子:**  尝试编码一个非常小的分辨率（小于 `kVEAEncoderMinResolutionWidth` 或 `kVEAEncoderMinResolutionHeight`）的视频，可能会导致回退到软件编码器，或者在某些平台上直接失败。

3. **资源限制:** GPU 资源有限。如果同时有大量的视频编码任务，可能会导致 `VEAEncoder` 初始化或执行失败。
   * **例子:**  在一个网页中同时启动多个 `MediaRecorder` 实例进行硬件编码，可能会超出 GPU 的能力。

4. **错误处理不当:** 开发者可能没有正确处理 `MediaRecorder` 的 `error` 事件，导致编码失败时没有得到通知。
   * **例子:**
     ```javascript
     mediaRecorder.onerror = function(event) {
       console.error('MediaRecorder 错误:', event.error); // 开发者可能忘记添加此错误处理
     };
     ```

5. **在不支持硬件编码的环境中使用:**  如果用户的浏览器或操作系统不支持硬件加速视频编码，`VEAEncoder` 将无法使用，可能会回退到软件编码器（如果可用），或者直接报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个使用 `MediaRecorder` 的网页:** 用户访问了一个需要录制视频的网页，例如一个在线会议应用或一个屏幕录制工具。

2. **JavaScript 代码请求访问摄像头/屏幕共享:** 网页上的 JavaScript 代码使用 `navigator.mediaDevices.getUserMedia()` 或 `navigator.mediaDevices.getDisplayMedia()` 请求用户的摄像头或屏幕共享权限。

3. **用户授予权限:** 用户在浏览器提示中允许了摄像头或屏幕共享。

4. **JavaScript 代码初始化 `MediaRecorder`:**  JavaScript 代码创建了一个 `MediaRecorder` 对象，并传入了从摄像头/屏幕共享获取的媒体流，以及一些配置参数（例如 `mimeType`）。

   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(function(stream) {
       const mediaRecorder = new MediaRecorder(stream, { mimeType: 'video/webm; codecs=h264' });
       // ...
     });
   ```

5. **用户开始录制:**  JavaScript 代码调用 `mediaRecorder.start()` 方法开始录制。

6. **Blink 引擎创建 `VEAEncoder` (如果适用):** 当 `MediaRecorder` 开始录制视频时，Blink 引擎会根据配置（例如 `mimeType`，硬件加速是否可用）决定使用哪个编码器。如果满足条件，`VEAEncoder` 的实例会被创建。

7. **视频帧被传递给 `VEAEncoder`:**  从媒体流中捕获的每一帧视频数据（通常以 `VideoFrame` 的形式）会被传递到 `VEAEncoder` 的 `EncodeFrame` 方法。

8. **`VEAEncoder` 使用 GPU 进行编码:**  `VEAEncoder` 内部调用 `media::VideoEncodeAccelerator` 将视频帧发送到 GPU 进行硬件加速编码。

9. **编码后的数据通过回调返回:**  GPU 完成编码后，编码后的数据和元数据会通过 `BitstreamBufferReady` 回调返回到 `VEAEncoder`。

10. **`VEAEncoder` 将数据传递给上层:** `VEAEncoder` 将编码后的数据封装成 `Blob` 或其他格式，并通过 `dataavailable` 事件传递回 JavaScript 代码。

**调试线索:**

当调试与 `VEAEncoder` 相关的问题时，以下是一些可以关注的线索：

* **检查 `chrome://media-internals`:**  这个 Chrome 内部页面提供了详细的媒体处理信息，包括使用的编码器、配置参数、错误信息等。可以查看 `MediaRecorder` 的相关条目，了解是否成功使用了硬件编码器，以及是否有任何错误发生。

* **查看控制台错误信息:**  检查浏览器的开发者工具控制台，看是否有 JavaScript 或 Blink 引擎输出的错误或警告信息。

* **检查 `mimeType` 配置:**  确认 `MediaRecorder` 构造函数中使用的 `mimeType` 是否被浏览器支持，并且是否有对应的硬件编码器可用。

* **检查视频源:**  确保视频源（例如摄像头或屏幕共享的内容）是正常工作的，并且其分辨率和格式是硬件编码器支持的。

* **断点调试 C++ 代码:**  如果需要深入了解 `VEAEncoder` 的内部行为，可以使用调试器（例如 gdb 或 lldb）附加到 Chrome 进程，并在 `vea_encoder.cc` 中设置断点，跟踪代码执行流程。

* **查看 Chrome 的日志输出:**  可以启动带有特定标志的 Chrome，以获取更详细的日志输出，例如 `--enable-logging=stderr --v=1`。这些日志可能包含关于硬件编码器初始化和操作的详细信息。

希望这个详尽的分析能够帮助你理解 `blink/renderer/modules/mediarecorder/vea_encoder.cc` 文件的功能和与其他 Web 技术的关系。

Prompt: 
```
这是目录为blink/renderer/modules/mediarecorder/vea_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediarecorder/vea_encoder.h"

#include <memory>
#include <string>
#include <utility>

#include "base/metrics/histogram_macros.h"
#include "base/numerics/checked_math.h"
#include "base/task/bind_post_task.h"
#include "base/trace_event/trace_event.h"
#include "media/base/bitrate.h"
#include "media/base/bitstream_buffer.h"
#include "media/base/media_util.h"
#include "media/base/supported_types.h"
#include "media/base/video_encoder_metrics_provider.h"
#include "media/base/video_frame.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "media/video/video_encode_accelerator.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/libyuv/include/libyuv.h"
#include "ui/gfx/geometry/size.h"

using video_track_recorder::kVEAEncoderMinResolutionHeight;
using video_track_recorder::kVEAEncoderMinResolutionWidth;

namespace blink {
namespace {

// HW encoders expect a nonzero bitrate, so |kVEADefaultBitratePerPixel| is used
// to estimate bits per second for ~30 fps with ~1/16 compression rate.
const int kVEADefaultBitratePerPixel = 2;
// Number of output buffers used to copy the encoded data coming from HW
// encoders.
const int kVEAEncoderOutputBufferCount = 4;

}  // anonymous namespace

bool VEAEncoder::OutputBuffer::IsValid() {
  return region.IsValid() && mapping.IsValid();
}

VEAEncoder::VEAEncoder(
    scoped_refptr<base::SequencedTaskRunner> encoding_task_runner,
    const VideoTrackRecorder::OnEncodedVideoCB& on_encoded_video_cb,
    const VideoTrackRecorder::OnErrorCB& on_error_cb,
    media::Bitrate::Mode bitrate_mode,
    uint32_t bits_per_second,
    media::VideoCodecProfile codec,
    std::optional<uint8_t> level,
    const gfx::Size& size,
    bool use_native_input,
    bool is_screencast)
    : Encoder(std::move(encoding_task_runner),
              on_encoded_video_cb,
              bits_per_second > 0
                  ? bits_per_second
                  : size.GetArea() * kVEADefaultBitratePerPixel),
      gpu_factories_(Platform::Current()->GetGpuFactories()),
      codec_(codec),
      level_(level),
      bitrate_mode_(bitrate_mode),
      size_(size),
      use_native_input_(use_native_input),
      is_screencast_(is_screencast),
      error_notified_(false),
      on_error_cb_(on_error_cb) {
  DCHECK(gpu_factories_);
}

VEAEncoder::~VEAEncoder() {
  video_encoder_.reset();
}

void VEAEncoder::RequireBitstreamBuffers(unsigned int /*input_count*/,
                                         const gfx::Size& input_coded_size,
                                         size_t output_buffer_size) {
  DVLOG(3) << __func__;

  vea_requested_input_coded_size_ = input_coded_size;
  output_buffers_.clear();
  input_buffers_.clear();

  for (int i = 0; i < kVEAEncoderOutputBufferCount; ++i) {
    auto output_buffer = std::make_unique<OutputBuffer>();
    output_buffer->region =
        gpu_factories_->CreateSharedMemoryRegion(output_buffer_size);
    output_buffer->mapping = output_buffer->region.Map();
    if (output_buffer->IsValid())
      output_buffers_.push_back(std::move(output_buffer));
  }

  for (size_t i = 0; i < output_buffers_.size(); ++i)
    UseOutputBitstreamBufferId(static_cast<int32_t>(i));
}

void VEAEncoder::BitstreamBufferReady(
    int32_t bitstream_buffer_id,
    const media::BitstreamBufferMetadata& metadata) {
  DVLOG(3) << __func__;

  OutputBuffer* output_buffer = output_buffers_[bitstream_buffer_id].get();
  auto data_span = output_buffer->mapping.GetMemoryAsSpan<const uint8_t>(
      metadata.payload_size_bytes);

  auto front_frame = frames_in_encode_.front();
  frames_in_encode_.pop();

  if (metadata.encoded_size) {
    front_frame.first.visible_rect_size = *metadata.encoded_size;
  }

  auto buffer = media::DecoderBuffer::CopyFrom(data_span);
  buffer->set_is_key_frame(metadata.key_frame);

  on_encoded_video_cb_.Run(front_frame.first, std::move(buffer), std::nullopt,
                           front_frame.second);

  UseOutputBitstreamBufferId(bitstream_buffer_id);
}

void VEAEncoder::NotifyErrorStatus(const media::EncoderStatus& status) {
  DVLOG(3) << __func__;
  CHECK(!status.is_ok());
  DLOG(ERROR) << "NotifyErrorStatus() is called with code="
              << static_cast<int>(status.code())
              << ", message=" << status.message();
  metrics_provider_->SetError(status);
  on_error_cb_.Run();
  error_notified_ = true;
}

void VEAEncoder::UseOutputBitstreamBufferId(int32_t bitstream_buffer_id) {
  DVLOG(3) << __func__;
  metrics_provider_->IncrementEncodedFrameCount();

  video_encoder_->UseOutputBitstreamBuffer(media::BitstreamBuffer(
      bitstream_buffer_id,
      output_buffers_[bitstream_buffer_id]->region.Duplicate(),
      output_buffers_[bitstream_buffer_id]->region.GetSize()));
}

void VEAEncoder::FrameFinished(
    std::unique_ptr<base::MappedReadOnlyRegion> shm) {
  DVLOG(3) << __func__;
  input_buffers_.push_back(std::move(shm));
}

void VEAEncoder::EncodeFrame(scoped_refptr<media::VideoFrame> frame,
                             base::TimeTicks capture_timestamp,
                             bool request_keyframe) {
  TRACE_EVENT0("media", "VEAEncoder::EncodeFrame");
  DVLOG(3) << __func__;

  if (input_visible_size_ != frame->visible_rect().size() && video_encoder_) {
    // TODO(crbug.com/719023): This is incorrect. Flush() should instead be
    // called to ensure submitted outputs are retrieved first.
    video_encoder_.reset();
  }

  if (!video_encoder_) {
    bool use_native_input =
        frame->storage_type() == media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER;
    ConfigureEncoder(frame->visible_rect().size(), use_native_input);
  }

  if (error_notified_) {
    DLOG(ERROR) << "An error occurred in VEA encoder";
    return;
  }

  // Drop frames if RequireBitstreamBuffers() hasn't been called.
  if (output_buffers_.empty() || vea_requested_input_coded_size_.IsEmpty()) {
    // TODO(emircan): Investigate if resetting encoder would help.
    DVLOG(3) << "Might drop frame.";
    last_frame_ = std::make_unique<VideoFrameAndMetadata>(
        std::move(frame), capture_timestamp, request_keyframe);
    return;
  }

  // If first frame hasn't been encoded, do it first.
  if (last_frame_) {
    std::unique_ptr<VideoFrameAndMetadata> last_frame = std::move(last_frame_);
    last_frame_ = nullptr;
    EncodeFrame(last_frame->frame, last_frame->timestamp,
                last_frame->request_keyframe);
  }

  // Lower resolutions may fall back to SW encoder in some platforms, i.e. Mac.
  // In that case, the encoder expects more frames before returning result.
  // Therefore, a copy is necessary to release the current frame.
  // Only STORAGE_SHMEM backed frames can be shared with GPU process, therefore
  // a copy is required for other storage types.
  // With STORAGE_GPU_MEMORY_BUFFER we delay the scaling of the frame to the end
  // of the encoding pipeline.
  scoped_refptr<media::VideoFrame> video_frame = frame;
  bool can_share_frame =
      (video_frame->storage_type() == media::VideoFrame::STORAGE_SHMEM);
  if (frame->storage_type() != media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER &&
      (!can_share_frame ||
       vea_requested_input_coded_size_ != frame->coded_size() ||
       input_visible_size_.width() < kVEAEncoderMinResolutionWidth ||
       input_visible_size_.height() < kVEAEncoderMinResolutionHeight)) {
    TRACE_EVENT0("media", "VEAEncoder::EncodeFrame::Copy");
    // Create SharedMemory backed input buffers as necessary. These SharedMemory
    // instances will be shared with GPU process.
    const size_t desired_mapped_size = media::VideoFrame::AllocationSize(
        media::PIXEL_FORMAT_I420, vea_requested_input_coded_size_);
    std::unique_ptr<base::MappedReadOnlyRegion> input_buffer;
    if (input_buffers_.empty()) {
      input_buffer = std::make_unique<base::MappedReadOnlyRegion>(
          base::ReadOnlySharedMemoryRegion::Create(desired_mapped_size));
      if (!input_buffer->IsValid())
        return;
    } else {
      do {
        input_buffer = std::move(input_buffers_.back());
        input_buffers_.pop_back();
      } while (!input_buffers_.empty() &&
               input_buffer->mapping.size() < desired_mapped_size);
      if (!input_buffer || input_buffer->mapping.size() < desired_mapped_size)
        return;
    }

    video_frame = media::VideoFrame::WrapExternalData(
        media::PIXEL_FORMAT_I420, vea_requested_input_coded_size_,
        gfx::Rect(input_visible_size_), input_visible_size_,
        input_buffer->mapping.GetMemoryAsSpan<uint8_t>().data(),
        input_buffer->mapping.size(), frame->timestamp());
    if (!video_frame) {
      NotifyErrorStatus({media::EncoderStatus::Codes::kEncoderFailedEncode,
                         "Failed to create VideoFrame"});
      return;
    }
    libyuv::I420Copy(
        frame->visible_data(media::VideoFrame::Plane::kY),
        frame->stride(media::VideoFrame::Plane::kY),
        frame->visible_data(media::VideoFrame::Plane::kU),
        frame->stride(media::VideoFrame::Plane::kU),
        frame->visible_data(media::VideoFrame::Plane::kV),
        frame->stride(media::VideoFrame::Plane::kV),
        video_frame->GetWritableVisibleData(media::VideoFrame::Plane::kY),
        video_frame->stride(media::VideoFrame::Plane::kY),
        video_frame->GetWritableVisibleData(media::VideoFrame::Plane::kU),
        video_frame->stride(media::VideoFrame::Plane::kU),
        video_frame->GetWritableVisibleData(media::VideoFrame::Plane::kV),
        video_frame->stride(media::VideoFrame::Plane::kV),
        input_visible_size_.width(), input_visible_size_.height());
    video_frame->BackWithSharedMemory(&input_buffer->region);
    video_frame->AddDestructionObserver(base::BindPostTask(
        encoding_task_runner_,
        WTF::BindOnce(&VEAEncoder::FrameFinished, weak_factory_.GetWeakPtr(),
                      std::move(input_buffer))));
  }
  frames_in_encode_.emplace(media::Muxer::VideoParameters(*frame),
                            capture_timestamp);

  video_encoder_->Encode(video_frame, request_keyframe);
}

void VEAEncoder::Initialize() {
  ConfigureEncoder(size_, use_native_input_);
}

void VEAEncoder::ConfigureEncoder(const gfx::Size& size,
                                  bool use_native_input) {
  DVLOG(3) << __func__;
  DCHECK_NE(bits_per_second_, 0u);

  input_visible_size_ = size;
  vea_requested_input_coded_size_ = gfx::Size();
  video_encoder_ = gpu_factories_->CreateVideoEncodeAccelerator();

  auto pixel_format = media::VideoPixelFormat::PIXEL_FORMAT_I420;
  auto storage_type =
      media::VideoEncodeAccelerator::Config::StorageType::kShmem;
  if (use_native_input) {
    // Currently the VAAPI and V4L2 VEA support only native input mode with NV12
    // DMA-buf buffers.
    pixel_format = media::PIXEL_FORMAT_NV12;
    storage_type =
        media::VideoEncodeAccelerator::Config::StorageType::kGpuMemoryBuffer;
  }

  auto bitrate = media::Bitrate::ConstantBitrate(bits_per_second_);
  if (bitrate_mode_ == media::Bitrate::Mode::kVariable) {
    constexpr uint32_t kNumPixelsIn4KResolution = 3840 * 2160;
    constexpr uint32_t kMaxAllowedBitrate =
        kNumPixelsIn4KResolution * kVEADefaultBitratePerPixel;
    const uint32_t max_peak_bps =
        std::max(bits_per_second_, kMaxAllowedBitrate);
    // This magnification is determined in crbug.com/1342850.
    constexpr uint32_t kPeakBpsMagnification = 2;
    base::CheckedNumeric<uint32_t> peak_bps = bits_per_second_;
    peak_bps *= kPeakBpsMagnification;
    bitrate = media::Bitrate::VariableBitrate(
        bits_per_second_,
        base::strict_cast<uint32_t>(peak_bps.ValueOrDefault(max_peak_bps)));
  }

  metrics_provider_->Initialize(codec_, input_visible_size_,
                                /*is_hardware_encoder=*/true);
  // TODO(b/181797390): Use VBR bitrate mode.
  // TODO(crbug.com/1289907): remove the cast to uint32_t once
  // |bits_per_second_| is stored as uint32_t.
  media::VideoEncodeAccelerator::Config config(
      pixel_format, input_visible_size_, codec_, bitrate,
      media::VideoEncodeAccelerator::kDefaultFramerate, storage_type,
      is_screencast_
          ? media::VideoEncodeAccelerator::Config::ContentType::kDisplay
          : media::VideoEncodeAccelerator::Config::ContentType::kCamera);
  config.h264_output_level = level_;
  config.required_encoder_type =
      media::MayHaveAndAllowSelectOSSoftwareEncoder(
          media::VideoCodecProfileToVideoCodec(codec_))
          ? media::VideoEncodeAccelerator::Config::EncoderType::kNoPreference
          : media::VideoEncodeAccelerator::Config::EncoderType::kHardware;
  if (!video_encoder_ ||
      !video_encoder_->Initialize(config, this,
                                  std::make_unique<media::NullMediaLog>())) {
    NotifyErrorStatus({media::EncoderStatus::Codes::kEncoderInitializationError,
                       "Failed to initialize"});
  }
}

}  // namespace blink

"""

```