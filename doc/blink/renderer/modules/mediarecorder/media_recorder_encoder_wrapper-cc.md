Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

**1. Initial Understanding and Purpose:**

The first step is to understand the overall purpose of the file. The name `media_recorder_encoder_wrapper.cc` strongly suggests it's a wrapper around a video encoder used by the MediaRecorder API in Blink (Chromium's rendering engine). The presence of `third_party/blink` confirms it's part of Blink.

**2. Identifying Key Classes and Members:**

Next, identify the main class and its key member variables and methods:

* **Class:** `MediaRecorderEncoderWrapper`
* **Member Variables:**
    * `encoding_task_runner_`:  Indicates asynchronous processing.
    * `gpu_factories_`:  Suggests hardware acceleration for encoding.
    * `profile_`, `codec_`:  Relate to video encoding formats (e.g., H.264, VP9).
    * `options_`: Configuration for the encoder (bitrate, frame size, etc.).
    * `create_encoder_cb_`:  A function to create the actual encoder instance.
    * `on_encoded_video_cb_`: Callback for when encoding is complete.
    * `on_error_cb_`: Callback for error handling.
    * `encoder_`: The actual video encoder object.
    * `pending_encode_tasks_`: A queue of frames waiting to be encoded.
    * `params_in_encode_`:  Information about frames currently being encoded.
    * `state_`:  The current state of the encoder (initializing, encoding, error).
    * `metrics_provider_`:  Used for tracking encoder performance.
* **Key Methods:**
    * `MediaRecorderEncoderWrapper` (constructor): Initializes the wrapper.
    * `EncodeFrame`:  Receives a video frame to be encoded.
    * `EncodePendingTasks`:  Processes the queue of frames.
    * `CreateAndInitialize`: Creates and initializes the underlying video encoder.
    * `Reconfigure`: Handles changes in frame size or alpha encoding requirements.
    * `OutputEncodeData`: Receives the encoded data from the encoder.
    * `EnterErrorState`: Handles error conditions.
    * `CanEncodeAlphaChannel`: Checks if alpha channel encoding is supported.

**3. Analyzing Functionality (Core Logic):**

Now, delve into the functionality of the key methods:

* **Constructor:** Sets up the initial state, checks supported codecs, and configures encoding options.
* **`EncodeFrame`:** Adds frames to a queue for asynchronous processing.
* **`EncodePendingTasks`:** The heart of the encoding process. It dequeues frames and interacts with the underlying encoder. It handles reconfiguration if the frame size changes.
* **`CreateAndInitialize`:** Creates the actual video encoder instance using the provided callback. It handles both initial setup and reconfiguration.
* **`Reconfigure`:**  Flushes the existing encoder and then calls `CreateAndInitialize` with the new configuration. This indicates that the underlying encoder might not support dynamic resolution changes.
* **`OutputEncodeData`:**  Processes the encoded data received from the underlying encoder, adds metadata, and calls the `on_encoded_video_cb_`.
* **Error Handling:** The `EnterErrorState` method and checks within other methods indicate a robust error handling mechanism.

**4. Identifying Relationships with Web Technologies:**

Consider how this C++ code interacts with JavaScript, HTML, and CSS:

* **JavaScript:** The MediaRecorder API is exposed to JavaScript. This C++ code is the backend implementation that handles the actual encoding when JavaScript calls `start()` on a `MediaRecorder` object.
* **HTML:** The `<video>` element or `<canvas>` element could be the source of the video frames being recorded.
* **CSS:**  While CSS doesn't directly *cause* this code to run, CSS styling can influence the rendering of the video being recorded, which indirectly affects the frames processed by this encoder.

**5. Considering Logical Reasoning (Assumptions and Outputs):**

Think about the flow of data and what happens under different scenarios:

* **Input:** A sequence of `media::VideoFrame` objects with varying sizes and timestamps.
* **Output:** Encoded video data (likely in a format like H.264, VP8, etc.) passed back via the `on_encoded_video_cb_`.
* **Key Assumptions:** The underlying video encoder correctly encodes the frames. The task runner ensures thread safety.

**6. Identifying Potential User/Programming Errors:**

Think about common mistakes when using the MediaRecorder API:

* **Incorrect Codec:** Trying to record with an unsupported codec.
* **Premature Stop:** Stopping the recording before all frames are processed.
* **Large Frame Size Changes:** Rapidly changing the video source resolution might lead to frequent reconfigurations.
* **Resource Exhaustion:**  Insufficient resources might cause the encoder to fail.

**7. Tracing User Operations (Debugging Clues):**

Consider how a user's actions in a web browser lead to this code being executed:

* User opens a web page that uses the MediaRecorder API.
* JavaScript code calls `navigator.mediaDevices.getUserMedia()` to get access to a media stream (camera, screen sharing).
* The JavaScript code creates a `MediaRecorder` object, specifying the desired `mimeType` (which implies a video codec).
* The user calls `mediaRecorder.start()`.
* This triggers the creation of the `MediaRecorderEncoderWrapper` in the Blink rendering engine.
* As new video frames arrive from the media stream, the `EncodeFrame` method is called.

**8. Structuring the Response:**

Finally, organize the information into a clear and structured format, addressing each part of the prompt:

* **Functionality:** Provide a concise summary of the code's purpose and key operations.
* **Relationship to Web Technologies:**  Explain how it connects to JavaScript, HTML, and CSS, with concrete examples.
* **Logical Reasoning:** Detail assumed inputs, processing steps, and expected outputs.
* **Common Errors:**  Illustrate potential user and programming errors with specific scenarios.
* **User Operations (Debugging):** Describe the sequence of user actions that lead to this code being executed.

By following this thought process, you can effectively analyze the given source code and provide a comprehensive and insightful explanation. The process involves understanding the code's domain (video encoding), identifying key components, analyzing the logic, and connecting it to the broader context of web development.
这个C++源代码文件 `media_recorder_encoder_wrapper.cc` 是 Chromium Blink 引擎中 `MediaRecorder` API 的一部分，负责**封装底层的视频编码器**，以便将视频帧编码成特定的格式（如 H.264, VP8, VP9, AV1 等）。  它在 MediaRecorder API 的实现中扮演着关键的角色，将平台无关的视频帧数据转换成可以在网络上传输或存储的编码后的数据。

下面是它的详细功能列表：

**核心功能:**

1. **视频帧编码:** 接收 `media::VideoFrame` 对象，这些对象包含了需要被编码的原始视频数据。
2. **编码器管理:**  创建、初始化和管理底层的 `media::VideoEncoder` 实例。 可以根据需要创建硬件加速或软件编码器。
3. **编码参数配置:**  根据 `MediaRecorder` API 的配置（例如 `mimeType` 中指定的编码器 profile 和 bitrate），设置底层编码器的参数，例如比特率 (`bits_per_second`)、编码 profile (`profile`)、内容提示 (`is_screencast`) 等。
4. **异步编码:**  使用 `base::SequencedTaskRunner` 在独立的线程上执行编码任务，避免阻塞主渲染线程。
5. **帧率控制和关键帧请求:**  虽然代码本身没有直接体现帧率控制，但它接收 `request_keyframe` 参数，允许上层逻辑请求生成关键帧。
6. **错误处理:**  当编码过程中发生错误时，通过 `OnErrorCB` 回调通知上层。
7. **编码数据输出:**  当编码完成后，通过 `OnEncodedVideoCB` 回调将编码后的数据（`media::DecoderBuffer`）以及相关的视频参数信息传递给上层。
8. **动态重配置:**  当视频帧的尺寸发生变化时，能够重新配置底层的编码器。
9. **Alpha 通道支持 (部分):**  对于 VP8 和 VP9 软件编码器，支持编码带有 Alpha 通道的视频帧。
10. **性能指标收集:**  使用 `media::VideoEncoderMetricsProvider` 收集编码相关的性能指标。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

`media_recorder_encoder_wrapper.cc` 并不直接操作 HTML 或 CSS，但它是 MediaRecorder API 的核心组成部分，而 MediaRecorder API 是 JavaScript 中用于录制媒体流（通常来自 `<canvas>` 或用户的摄像头/麦克风）的关键接口。

* **JavaScript:**
    * **启动录制:**  当 JavaScript 代码调用 `MediaRecorder.start()` 时，Blink 内部会创建 `MediaRecorderEncoderWrapper` 实例。
        ```javascript
        let stream = await navigator.mediaDevices.getUserMedia({ video: true });
        let options = { mimeType: 'video/webm; codecs=vp9' };
        let mediaRecorder = new MediaRecorder(stream, options);
        mediaRecorder.start();
        ```
        在这个例子中，`mimeType: 'video/webm; codecs=vp9'`  会最终影响 `MediaRecorderEncoderWrapper` 中 `profile_` 和 `codec_` 的设置，从而决定使用 VP9 编码器。
    * **处理编码后的数据:**  `MediaRecorder` 对象会触发 `dataavailable` 事件，携带编码后的数据。 这些数据是由 `MediaRecorderEncoderWrapper` 编码并传递上来的。
        ```javascript
        mediaRecorder.ondataavailable = (event) => {
          console.log('Encoded data:', event.data);
          // 可以将 event.data 发送给服务器或保存到本地
        };
        ```
    * **指定编码参数:**  `MediaRecorder` 的构造函数允许传入 `options` 对象，其中可以指定 `mimeType`，间接影响 `MediaRecorderEncoderWrapper` 的编码配置。

* **HTML:**
    * **`<video>` 元素作为源:**  用户可以使用 `<video>` 元素播放的视频流作为 `MediaRecorder` 的输入源。
        ```html
        <video id="myVideo" src="my-video.mp4" autoplay muted></video>
        <script>
          const video = document.getElementById('myVideo');
          const stream = video.captureStream();
          const mediaRecorder = new MediaRecorder(stream, { mimeType: 'video/mp4; codecs=avc1' });
          // ...
        </script>
        ```
        在这种情况下，`MediaRecorderEncoderWrapper` 会对 `<video>` 元素捕获的帧进行编码。
    * **`<canvas>` 元素作为源:**  可以使用 `<canvas>` 元素绘制的内容作为 `MediaRecorder` 的输入源，用于录制动画或游戏画面。
        ```html
        <canvas id="myCanvas" width="640" height="480"></canvas>
        <script>
          const canvas = document.getElementById('myCanvas');
          const stream = canvas.captureStream();
          const mediaRecorder = new MediaRecorder(stream, { mimeType: 'video/webm' });
          // ... (在 canvas 上绘制动画)
        </script>
        ```

* **CSS:**
    * **间接影响:** CSS 样式可以影响 `<video>` 或 `<canvas>` 元素的渲染结果，从而影响 `MediaRecorderEncoderWrapper` 接收到的视频帧内容。例如，CSS 的 `transform` 属性可能会改变视频的显示，`MediaRecorder` 会录制经过变换后的内容。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **`frame`:**  一个 `640x480` 像素，格式为 `PIXEL_FORMAT_I420` 的 `media::VideoFrame`，表示摄像头捕获的一帧图像，捕获时间戳为 `base::TimeTicks::Now() - base::Seconds(1)`.
2. **`capture_timestamp`:**  `base::TimeTicks::Now() - base::Seconds(1)`.
3. **`request_keyframe`:** `false`.
4. **`profile_`:**  `media::VideoCodecProfile::kVP9Profile0`.
5. **编码器已初始化完成，状态为 `State::kEncoding`。**

**处理过程:**

1. `EncodeFrame` 方法被调用，将 `frame` 和相关信息添加到 `pending_encode_tasks_` 队列。
2. 由于当前状态是 `kEncoding`，`EncodePendingTasks` 方法会被调用。
3. 从队列中取出 `frame`。
4. 检查帧尺寸和 Alpha 通道需求，与当前编码器配置一致。
5. 将帧的相关参数添加到 `params_in_encode_` 队列。
6. 调用底层 VP9 编码器的 `Encode` 方法，传入 `frame` 和编码选项 (不请求关键帧)。
7. 编码完成后，底层编码器会调用 `OutputEncodeData` 方法。

**预期输出 (OutputEncodeData 的输入):**

1. **`output`:** 一个 `media::VideoEncoderOutput` 对象，包含：
    * `data`:  编码后的 VP9 视频帧数据（一个 `std::vector<uint8_t>`）。
    * `alpha_data`:  `std::nullopt` (因为输入帧没有 Alpha 通道)。
    * `key_frame`: `false` (因为 `request_keyframe` 为 `false`)。
2. **`description`:**  可能包含 VP9 的 SPS/PPS 等描述信息，取决于编码器的实现。

**OutputEncodeData 的处理结果:**

1. `metrics_provider_` 的编码帧计数器会增加。
2. 从 `params_in_encode_` 队列中取出对应的视频参数和捕获时间戳。
3. 创建一个 `media::DecoderBuffer`，包含编码后的数据。
4. 调用 `on_encoded_video_cb_`，传递视频参数、`DecoderBuffer` 和 `description`。

**用户或编程常见的使用错误举例说明:**

1. **尝试编码不支持的格式:**
   * **用户操作:**  在 JavaScript 中设置 `mimeType` 为浏览器或操作系统不支持的编码格式 (例如，过时的或实验性的编码器)。
   * **结果:**  `MediaRecorderEncoderWrapper` 在初始化时会检查支持的编解码器，如果不支持，可能会抛出异常或导致编码失败，并通过 `on_error_cb_` 通知错误。
   * **调试线索:**  检查浏览器的控制台是否有关于不支持的 `mimeType` 或编解码器的错误信息。检查 `MediaRecorderEncoderWrapper` 构造函数中的 `CHECK(base::Contains(kSupportedCodecs, codec_))` 是否失败。

2. **在未初始化的状态下尝试编码:**
   * **编程错误:** 在 `MediaRecorder` 启动之前，或者在异步初始化完成之前就向 `MediaRecorderEncoderWrapper` 发送视频帧。
   * **结果:**  可能导致空指针解引用或程序崩溃，因为底层编码器尚未创建。
   * **调试线索:**  检查 `MediaRecorderEncoderWrapper` 的 `state_` 变量，确保在调用 `EncodeFrame` 之前状态已变为 `kEncoding`。

3. **频繁改变输入帧的尺寸但不处理重配置:**
   * **编程错误:**  如果视频源的尺寸频繁变化，但没有调用 `Reconfigure` 方法来更新编码器配置，会导致编码错误或输出质量下降。
   * **结果:**  编码失败或输出的视频出现失真。
   * **调试线索:**  观察 `EncodePendingTasks` 方法中对于帧尺寸变化的检查逻辑，以及 `Reconfigure` 方法的调用时机。

4. **资源耗尽导致编码失败:**
   * **用户操作/系统状态:**  在资源非常紧张的环境下（例如，CPU 或 GPU 负载过高），编码器可能无法正常工作。
   * **结果:**  编码过程失败，`MediaRecorderEncoderWrapper` 会调用 `on_error_cb_` 通知错误。
   * **调试线索:**  查看系统资源使用情况 (CPU、内存、GPU)。检查 `EnterErrorState` 方法是否被调用，以及传递的 `media::EncoderStatus`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开一个网页，该网页使用了 JavaScript 的 MediaRecorder API 来录制视频。**
2. **JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 获取摄像头或屏幕共享的媒体流。** 这涉及到权限请求和设备选择。
3. **JavaScript 代码创建 `MediaRecorder` 对象，并传入 `stream` 和 `options` (包含 `mimeType`)。**  `mimeType` 的选择会影响 `MediaRecorderEncoderWrapper` 中使用的具体编码器。
4. **JavaScript 代码调用 `mediaRecorder.start()`。**  这个调用会触发 Blink 内部创建 `MediaRecorderEncoderWrapper` 实例，并根据 `options` 中的信息初始化编码器。
5. **当媒体流产生新的视频帧时，Blink 内部会将这些 `media::VideoFrame` 对象传递给 `MediaRecorderEncoderWrapper::EncodeFrame` 方法。**
6. **`MediaRecorderEncoderWrapper` 将帧添加到内部队列，并在编码线程上异步地调用底层编码器的 `Encode` 方法。**
7. **底层编码器完成编码后，会将编码后的数据回调给 `MediaRecorderEncoderWrapper::OutputEncodeData`。**
8. **`MediaRecorderEncoderWrapper` 将编码后的数据通过 `on_encoded_video_cb_` 回调传递给上层 `VideoTrackRecorder`。**
9. **最终，编码后的数据会触发 JavaScript 的 `mediaRecorder.ondataavailable` 事件。**

**调试线索:**

* **检查 JavaScript 代码中 `MediaRecorder` 的 `mimeType` 设置是否正确，并且浏览器支持该格式。**
* **在 Blink 渲染进程的日志中查找与 `MediaRecorderEncoderWrapper` 相关的日志输出，例如编码器初始化、帧编码、错误信息等。** 可以使用 `chrome://tracing` 或 `chrome://media-internals` 查看更详细的媒体信息。
* **断点调试 `MediaRecorderEncoderWrapper` 的关键方法，例如 `EncodeFrame`, `EncodePendingTasks`, `CreateAndInitialize`, `OutputEncodeData`，查看帧数据和编码状态。**
* **检查 `gpu_factories_` 是否为空，以判断是否使用了硬件加速编码。硬件加速相关的问题可能需要检查 GPU 驱动和硬件兼容性。**
* **如果出现编码错误，查看 `EnterErrorState` 方法中记录的 `media::EncoderStatus`，了解具体的错误原因。**
* **如果怀疑是帧尺寸变化导致的问题，可以在 `EncodePendingTasks` 中添加日志，观察帧尺寸的变化以及 `Reconfigure` 的调用情况。**

总而言之，`media_recorder_encoder_wrapper.cc` 是 MediaRecorder API 实现中至关重要的一个环节，它桥接了平台无关的视频帧数据和平台相关的底层视频编码器，使得浏览器能够将视频流编码成各种常见的格式。 理解其功能和工作流程对于调试 MediaRecorder 相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/modules/mediarecorder/media_recorder_encoder_wrapper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediarecorder/media_recorder_encoder_wrapper.h"

#include "base/containers/contains.h"
#include "base/numerics/safe_conversions.h"
#include "media/base/decoder_buffer.h"
#include "media/base/video_encoder_metrics_provider.h"
#include "media/base/video_frame.h"
#include "media/media_buildflags.h"
#include "media/video/alpha_video_encoder_wrapper.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"

namespace blink {

MediaRecorderEncoderWrapper::EncodeTask::EncodeTask(
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks capture_timestamp,
    bool request_keyframe)
    : frame(std::move(frame)),
      capture_timestamp(capture_timestamp),
      request_keyframe(request_keyframe) {}

MediaRecorderEncoderWrapper::EncodeTask::~EncodeTask() = default;

MediaRecorderEncoderWrapper::VideoParamsAndTimestamp::VideoParamsAndTimestamp(
    const media::Muxer::VideoParameters& params,
    base::TimeTicks timestamp)
    : params(params), timestamp(timestamp) {}

MediaRecorderEncoderWrapper::VideoParamsAndTimestamp::
    ~VideoParamsAndTimestamp() = default;

MediaRecorderEncoderWrapper::MediaRecorderEncoderWrapper(
    scoped_refptr<base::SequencedTaskRunner> encoding_task_runner,
    media::VideoCodecProfile profile,
    uint32_t bits_per_second,
    bool is_screencast,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    CreateEncoderCB create_encoder_cb,
    VideoTrackRecorder::OnEncodedVideoCB on_encoded_video_cb,
    OnErrorCB on_error_cb)
    : Encoder(std::move(encoding_task_runner),
              on_encoded_video_cb,
              bits_per_second),
      gpu_factories_(gpu_factories),
      profile_(profile),
      codec_(media::VideoCodecProfileToVideoCodec(profile_)),
      create_encoder_cb_(create_encoder_cb),
      on_error_cb_(std::move(on_error_cb)) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
  CHECK(create_encoder_cb_);
  CHECK(on_error_cb_);
  constexpr media::VideoCodec kSupportedCodecs[] = {
      media::VideoCodec::kH264, media::VideoCodec::kVP8,
      media::VideoCodec::kVP9,  media::VideoCodec::kAV1,
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      media::VideoCodec::kHEVC,
#endif
  };
  CHECK(base::Contains(kSupportedCodecs, codec_));
  options_.latency_mode = media::VideoEncoder::LatencyMode::Quality;
  options_.bitrate = media::Bitrate::VariableBitrate(
      bits_per_second, base::ClampMul(bits_per_second, 2u).RawValue());
  options_.content_hint = is_screencast
                              ? media::VideoEncoder::ContentHint::Screen
                              : media::VideoEncoder::ContentHint::Camera;
  if (codec_ == media::VideoCodec::kH264) {
    options_.avc.produce_annexb = true;
  }
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
  else if (codec_ == media::VideoCodec::kHEVC) {
    options_.hevc.produce_annexb = true;
  }
#endif
}

MediaRecorderEncoderWrapper::~MediaRecorderEncoderWrapper() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

bool MediaRecorderEncoderWrapper::CanEncodeAlphaChannel() const {
  // Alpha encoding is supported only with VP8 and VP9 software encoders.
  return !gpu_factories_ && (codec_ == media::VideoCodec::kVP8 ||
                             codec_ == media::VideoCodec::kVP9);
}

bool MediaRecorderEncoderWrapper::IsScreenContentEncodingForTesting() const {
  return options_.content_hint.has_value() &&
         *options_.content_hint == media::VideoEncoder::ContentHint::Screen;
}

void MediaRecorderEncoderWrapper::EnterErrorState(
    const media::EncoderStatus& status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (state_ == State::kInError) {
    CHECK(!on_error_cb_);
    return;
  }

  metrics_provider_->SetError(status);
  state_ = State::kInError;
  pending_encode_tasks_ = {};
  params_in_encode_ = {};
  CHECK(on_error_cb_);
  std::move(on_error_cb_).Run();
}

void MediaRecorderEncoderWrapper::Reconfigure(const gfx::Size& frame_size,
                                              bool encode_alpha) {
  TRACE_EVENT2(
      "media", "MediaRecorderEncoderWrapper::ReconfigureForNewResolution",
      "frame_size", frame_size.ToString(), "encode_alpha", encode_alpha);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(encoder_);
  CHECK_NE(state_, State::kInError);
  state_ = State::kInitializing;
  encoder_->Flush(
      WTF::BindOnce(&MediaRecorderEncoderWrapper::CreateAndInitialize,
                    weak_factory_.GetWeakPtr(), frame_size, encode_alpha));
}

void MediaRecorderEncoderWrapper::CreateAndInitialize(
    const gfx::Size& frame_size,
    bool encode_alpha,
    media::EncoderStatus status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  TRACE_EVENT1("media", "MediaRecorderEncoderWrapper::CreateAndInitialize",
               "frame_size", frame_size.ToString());
  if (!status.is_ok()) {
    // CreateAndInitialize() is called (1) in VideoFrameBuffer() for the first
    // encoder creation with status=kOk and as Flush done callback. The status
    // can be non kOk only if it is invoked as flush callback.
    DLOG(ERROR) << "Flush() failed: " << status.message();
    EnterErrorState(status);
    return;
  }
  CHECK_NE(state_, State::kInError);
  CHECK(!encoder_ || state_ == State::kInitializing)
      << ", unexpected status: " << static_cast<int>(state_);
  state_ = State::kInitializing;
  options_.frame_size = frame_size;
  encode_alpha_ = encode_alpha;

  if (encode_alpha_) {
    CHECK(CanEncodeAlphaChannel());
    auto yuv_encoder = create_encoder_cb_.Run(gpu_factories_);
    auto alpha_encoder = create_encoder_cb_.Run(gpu_factories_);
    CHECK(yuv_encoder && alpha_encoder);
    encoder_ = std::make_unique<media::AlphaVideoEncoderWrapper>(
        std::move(yuv_encoder), std::move(alpha_encoder));
  } else {
    encoder_ = create_encoder_cb_.Run(gpu_factories_);
  }
  CHECK(encoder_);

  // MediaRecorderEncoderWrapper doesn't require an encoder to post a callback
  // because a given |on_encoded_video_cb_| already hops a thread.
  encoder_->DisablePostedCallbacks();
  metrics_provider_->Initialize(profile_, options_.frame_size,
                                /*is_hardware_encoder=*/gpu_factories_);
  encoder_->Initialize(
      profile_, options_,
      /*info_cb=*/base::DoNothing(),
      WTF::BindRepeating(&MediaRecorderEncoderWrapper::OutputEncodeData,
                         weak_factory_.GetWeakPtr()),
      WTF::BindOnce(&MediaRecorderEncoderWrapper::InitializeDone,
                    weak_factory_.GetWeakPtr()));
}

void MediaRecorderEncoderWrapper::InitializeDone(media::EncoderStatus status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  TRACE_EVENT0("media", "MediaRecorderEncoderWrapper::InitizalizeDone");
  if (!status.is_ok()) {
    DLOG(ERROR) << "Initialize() failed: " << status.message();
    EnterErrorState(status);
    return;
  }
  CHECK_NE(state_, State::kInError);

  state_ = State::kEncoding;
  EncodePendingTasks();
}

void MediaRecorderEncoderWrapper::EncodeFrame(
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks capture_timestamp,
    bool request_keyframe) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  TRACE_EVENT0("media", "MediaRecorderEncoderWrapper::EncodeFrame");
  if (state_ == State::kInError) {
    CHECK(!on_error_cb_);
    return;
  }
  pending_encode_tasks_.emplace_back(std::move(frame), capture_timestamp,
                                     request_keyframe);
  if (state_ == State::kEncoding) {
    EncodePendingTasks();
  }
}

void MediaRecorderEncoderWrapper::EncodePendingTasks() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  while (state_ == State::kEncoding && !pending_encode_tasks_.empty()) {
    auto& task = pending_encode_tasks_.front();
    const gfx::Size& frame_size = task.frame->visible_rect().size();
    CHECK(media::IsOpaque(task.frame->format()) ||
          task.frame->format() == media::PIXEL_FORMAT_I420A);
    const bool need_alpha_encode =
        task.frame->format() == media::PIXEL_FORMAT_I420A;

    // When a frame size is different from the current frame size (or first
    // Encode() call), encoder needs to be re-created because
    // media::VideoEncoder don't support all resolution change cases.
    // If |encoder_| exists, we first Flush() to not drop frames being encoded.
    if (frame_size != options_.frame_size ||
        encode_alpha_ != need_alpha_encode) {
      if (encoder_) {
        Reconfigure(frame_size, need_alpha_encode);
      } else {
        // Only first Encode() call.
        CreateAndInitialize(frame_size, need_alpha_encode,
                            media::EncoderStatus::Codes::kOk);
      }
      return;
    }
    params_in_encode_.emplace_back(media::Muxer::VideoParameters(*task.frame),
                                   task.capture_timestamp);
    bool request_keyframe = task.request_keyframe;
    auto frame = std::move(task.frame);
    pending_encode_tasks_.pop_front();
    // Encode() calls EncodeDone() and OutputEncodeData() within a call because
    // we DisablePostedCallbacks(). Therefore, |params_in_encode_| and
    // |pending_encode_tasks_| must be changed before calling Encode().
    encoder_->Encode(std::move(frame),
                     media::VideoEncoder::EncodeOptions(request_keyframe),
                     WTF::BindOnce(&MediaRecorderEncoderWrapper::EncodeDone,
                                   weak_factory_.GetWeakPtr()));
  }
}

void MediaRecorderEncoderWrapper::EncodeDone(media::EncoderStatus status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!status.is_ok()) {
    DLOG(ERROR) << "EncodeDone() failed: " << status.message();
    EnterErrorState(status);
    return;
  }
}

void MediaRecorderEncoderWrapper::OutputEncodeData(
    media::VideoEncoderOutput output,
    std::optional<media::VideoEncoder::CodecDescription> description) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  TRACE_EVENT0("media", "MediaRecorderEncoderWrapper::OutputEncodeData");
  if (state_ == State::kInError) {
    CHECK(!on_error_cb_);
    return;
  }

  metrics_provider_->IncrementEncodedFrameCount();

  // TODO(crbug.com/1330919): Check OutputEncodeData() in the same order as
  // Encode().
  CHECK(!params_in_encode_.empty());
  auto [video_params, capture_timestamp] = std::move(params_in_encode_.front());
  params_in_encode_.pop_front();
  video_params.codec = codec_;

  auto buffer = media::DecoderBuffer::FromArray(std::move(output.data));
  if (encode_alpha_) {
    buffer->WritableSideData().alpha_data = std::move(output.alpha_data);
  }
  buffer->set_is_key_frame(output.key_frame);

  on_encoded_video_cb_.Run(video_params, std::move(buffer),
                           std::move(description), capture_timestamp);
}

}  // namespace blink
```