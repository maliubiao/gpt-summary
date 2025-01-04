Response:
The user is asking for a summary of the functionality of the C++ code file `media_recorder_handler_unittest.cc`. This file is part of the Chromium Blink rendering engine and is located within the `mediarecorder` module. Since the filename includes `unittest`, it's highly likely this file contains unit tests for the `MediaRecorderHandler` class.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The "unittest" suffix is the biggest clue. This file's primary purpose is testing.

2. **Examine Includes:** The included headers provide hints about the tested functionality. `media_recorder_handler.h` confirms the target of the tests. Other includes like `media/base/`, `media/mojo/`, and `third_party/blink/renderer/modules/mediarecorder/` point to functionalities related to media encoding, potentially using Mojo IPC, and the overall `mediarecorder` module.

3. **Look for Test Structures:**  The code uses Google Test (`testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`). The presence of `TEST_P` indicates parameterized tests. The `MediaRecorderHandlerTest` class inheriting from `TestWithParam` and `MediaRecorderHandlerFixture` confirms this.

4. **Analyze the Fixture (`MediaRecorderHandlerFixture`):** This class sets up the testing environment. Key aspects include:
    * Creating `MediaRecorderHandler`.
    * Managing mock media streams and tracks (audio and video).
    * Providing methods to simulate video and audio frame input (`OnVideoFrameForTesting`, `OnAudioBusForTesting`).
    * Providing methods to simulate encoded data input (`OnEncodedVideoForTesting`, `OnEncodedAudioForTesting`).
    * Helper functions for creating test data.

5. **Analyze the Tests (Examples):**  Skimming through the `TEST_P` functions reveals common testing patterns:
    * `CanSupportMimeType`: Tests if the handler correctly identifies supported MIME types and codecs.
    * `SupportsBitrateMode`: Checks if bitrate mode configuration is handled.
    * `InitializeFailedWhenMP4MuxerFeatureDisabled`:  Tests feature flag control during initialization.
    * `EncodeVideoFrames`, `OpusEncodeAudioFrames`: Verify the encoding of video and audio frames.
    * `WebmMuxerErrorWhileEncoding`: Tests error handling during encoding.
    * `ActualMimeType`: Checks if the correct MIME type is reported.
    * `PauseRecorderForVideo`: Tests pausing and resuming recording.

6. **Infer Functionality from Tests:** Based on the types of tests, the `MediaRecorderHandler` appears responsible for:
    * Accepting media streams.
    * Validating MIME types and codec combinations.
    * Managing video and audio encoders.
    * Muxing encoded data into a specific container format (likely WebM or MP4).
    * Handling errors during the encoding and muxing process.
    * Supporting pausing and resuming recording.

7. **Relate to Web Technologies (JavaScript, HTML, CSS):** The `MediaRecorder` API is a JavaScript API. This C++ code implements the underlying logic for that API in the Blink rendering engine. The tests implicitly relate to:
    * **JavaScript:** The tests simulate how JavaScript calls to `MediaRecorder` would interact with the C++ backend.
    * **HTML:** The `<video>` and `<audio>` elements, along with `<canvas>`, are sources of media streams that `MediaRecorder` can capture.
    * **CSS:** While less direct, CSS can affect the rendering of video content, which might indirectly impact what's captured if the source is a rendered element.

8. **Logical Reasoning (Assumptions and Outputs):**  Most tests involve simulating input (media frames, encoded data) and verifying expected behavior (calls to `WriteData`, error callbacks). For example, providing a video frame should eventually lead to a call to `WriteData` with encoded video data.

9. **User/Programming Errors:**  Errors like providing unsupported MIME types or codecs are tested. A common programming error would be not handling the `dataavailable` event correctly in JavaScript, which relies on the `WriteData` calls in the C++ code.

10. **User Operations (Debugging Clues):**  A user starting recording via JavaScript's `MediaRecorder.start()` would eventually trigger the initialization and start methods in this C++ code. The tests provide examples of how this flow might be traced.

11. **Synthesize the Summary (Part 1):** Combine the above points to create a concise summary of the file's purpose and key functionalities. Focus on the testing aspect and the major responsibilities of the `MediaRecorderHandler`.
这是 blink 渲染引擎中 `media_recorder_handler_unittest.cc` 文件的第一部分，它是一个 **单元测试文件**，专门用于测试 `MediaRecorderHandler` 类的功能。

**功能归纳:**

这部分代码主要定义了用于测试 `MediaRecorderHandler` 行为的框架和一些辅助工具，包括：

* **测试用例参数化:** 使用 `MediaRecorderTestParams` 结构体和 `kMediaRecorderTestParams` 数组来定义不同的测试场景，涵盖了不同的视频/音频轨道组合、MIME 类型、编解码器等。这允许对 `MediaRecorderHandler` 在各种配置下的行为进行测试。
* **模拟和辅助类:**
    * `MockMediaRecorder`:  模拟 `MediaRecorder` JavaScript API 的行为，允许测试代码验证 `MediaRecorderHandler` 是否正确地调用了 `MediaRecorder` 的方法（例如 `WriteData`, `OnError`）。
    * `MediaRecorderHandlerFixture`:  作为一个测试夹具，负责设置和清理测试环境，包括创建 `MediaRecorderHandler` 实例，模拟音视频轨道，以及提供发送音视频数据和编码后数据的辅助方法。
* **媒体流创建辅助函数:**  `CreateMediaStream` 函数用于创建一个包含音频轨道的模拟媒体流，供测试使用。
* **测试平台支持:**  使用了 `IOTaskRunnerTestingPlatformSupport` 和 `TaskEnvironment` 来模拟 Blink 渲染引擎的异步任务处理环境。
* **编解码器支持判断:**  提供了一些辅助函数（例如 `IsTargetAudioCodecSupported`, `IsAv1CodecSupported`) 用于判断当前构建配置是否支持特定的音视频编解码器。
* **数据注入方法:** `OnVideoFrameForTesting`, `OnEncodedVideoForTesting`, `OnAudioBusForTesting`, `OnEncodedAudioForTesting` 等方法允许测试代码模拟接收到原始的或已编码的音视频数据，从而触发 `MediaRecorderHandler` 的内部逻辑。

**与 JavaScript, HTML, CSS 的关系:**

虽然这是一个 C++ 文件，但它直接测试了 Blink 引擎中 `MediaRecorder` JavaScript API 的底层实现。

* **JavaScript:** `MediaRecorderHandler` 是 JavaScript `MediaRecorder` API 的核心 C++ 实现。这个单元测试确保了当 JavaScript 代码调用 `MediaRecorder` 的方法时，底层的 C++ 代码能够按照预期工作。
    * **举例:** 当 JavaScript 调用 `mediaRecorder.start()` 时，会触发 `MediaRecorderHandler` 的 `Start` 方法。这个单元测试会模拟这种情况，并验证 `MediaRecorderHandler` 是否正确地初始化编码器和复用器。当 JavaScript 接收到 `dataavailable` 事件时，这对应于 `MediaRecorderHandler` 调用 `MockMediaRecorder` 的 `WriteData` 方法，将编码后的数据传递回 JavaScript。
* **HTML:** HTML 中的 `<video>` 和 `<audio>` 元素是 `MediaRecorder` 可能捕获的媒体源。这个单元测试模拟了从这些源接收到的音视频数据。
    * **举例:** 当用户通过 HTML 中的 `<video>` 元素播放视频，并且 JavaScript 使用 `MediaRecorder` 捕获该视频流时，`MediaRecorderHandler` 会接收到从视频轨道获取的帧数据。`OnVideoFrameForTesting` 方法就是模拟了这种场景。
* **CSS:** CSS 主要负责页面的样式和布局，与 `MediaRecorderHandler` 的直接关系较弱。但如果 `MediaRecorder` 捕获的是 `<canvas>` 元素的内容，那么 CSS 对 `<canvas>` 的渲染可能会影响捕获的结果。

**逻辑推理 (假设输入与输出):**

假设 `MediaRecorderHandler` 配置为录制 VP8 编码的视频：

* **假设输入:**  通过 `OnVideoFrameForTesting` 方法注入一个 `media::VideoFrame` 对象。
* **预期输出:** `MediaRecorderHandler` 内部的视频编码器会对该帧进行编码，然后 `MockMediaRecorder` 的 `WriteData` 方法会被调用，其参数包含了编码后的 VP8 数据。

假设 `MediaRecorderHandler` 配置为录制 Opus 编码的音频：

* **假设输入:** 通过 `OnAudioBusForTesting` 方法注入一个 `media::AudioBus` 对象。
* **预期输出:** `MediaRecorderHandler` 内部的音频编码器会对该音频数据进行编码，然后 `MockMediaRecorder` 的 `WriteData` 方法会被调用，其参数包含了编码后的 Opus 数据。

**用户或编程常见的使用错误:**

* **不支持的 MIME 类型或编解码器:** 用户在 JavaScript 中调用 `new MediaRecorder(stream, { mimeType: 'unsupported/type' })` 或指定不支持的 `codecs` 时，`MediaRecorderHandler` 会通过 `CanSupportMimeType` 方法进行校验，并可能拒绝初始化或抛出错误。
    * **举例:**  测试用例 `CanSupportMimeType` 就验证了 `MediaRecorderHandler` 对不同 MIME 类型和编解码器组合的支持情况。
* **在未调用 `start()` 前尝试录制数据:**  程序错误地在调用 `mediaRecorder.start()` 之前就向 `MediaRecorderHandler` 发送音视频数据，可能导致程序崩溃或产生未定义的行为。单元测试通过模拟不同的状态转换来验证 `MediaRecorderHandler` 的健壮性。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页，该网页的 JavaScript 代码使用了 `MediaRecorder` API。**
2. **JavaScript 代码获取一个 `MediaStream` 对象 (例如通过 `navigator.mediaDevices.getUserMedia()` 或从 `<canvas>` 元素获取)。**
3. **JavaScript 代码创建一个 `MediaRecorder` 对象，并将 `MediaStream` 对象传递给它，同时可能指定 `mimeType` 和 `codecs` 选项。**
4. **浏览器引擎会将 JavaScript 的 `MediaRecorder` 对象映射到 Blink 渲染引擎中的 `MediaRecorder` C++ 对象。**
5. **当 JavaScript 调用 `mediaRecorder.start()` 方法时，会触发 `MediaRecorderHandler` 的初始化和启动逻辑。**  此时，`MediaRecorderHandler` 会根据指定的 `mimeType` 和 `codecs` 创建相应的音视频编码器和复用器。
6. **当 `MediaStream` 的音视频轨道有新的数据产生时 (例如摄像头捕获了新的视频帧，麦克风采集到新的音频数据)，这些数据会被传递给 `MediaRecorderHandler`。**
7. **`MediaRecorderHandler` 将接收到的数据传递给相应的编码器进行编码。**
8. **编码后的数据会被传递给复用器，复用器将音视频数据组合成指定格式的文件片段。**
9. **复用后的数据会通过 `MockMediaRecorder` 的 `WriteData` 方法回调到 JavaScript 的 `dataavailable` 事件处理函数。**

在调试过程中，如果发现在录制过程中出现问题，例如编码失败、数据丢失或生成的媒体文件损坏，开发人员可能会查看 `media_recorder_handler_unittest.cc` 中的测试用例，以了解 `MediaRecorderHandler` 在各种情况下的预期行为，并以此为依据进行代码分析和问题定位。断点可以设置在 `MediaRecorderHandler` 的关键方法中，例如 `Initialize`, `Start`, `OnVideoFrameForTesting`, `OnEncodedVideo` 等，以跟踪数据的处理流程。

Prompt: 
```
这是目录为blink/renderer/modules/mediarecorder/media_recorder_handler_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediarecorder/media_recorder_handler.h"

#include <stddef.h>

#include <string>
#include <string_view>

#include "base/files/file_path.h"
#include "base/files/memory_mapped_file.h"
#include "base/memory/raw_ptr.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "media/audio/simple_sources.h"
#include "media/base/audio_bus.h"
#include "media/base/decoder_buffer.h"
#include "media/base/video_color_space.h"
#include "media/base/video_frame.h"
#include "media/formats/mp4/box_definitions.h"
#include "media/media_buildflags.h"
#include "media/mojo/clients/mojo_audio_encoder.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/modules/mediarecorder/audio_track_recorder.h"
#include "third_party/blink/renderer/modules/mediarecorder/fake_encoded_video_frame.h"
#include "third_party/blink/renderer/modules/mediarecorder/media_recorder.h"
#include "third_party/blink/renderer/modules/mediarecorder/video_track_recorder.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_registry.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/heap/weak_cell.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

using base::test::RunOnceClosure;
using ::testing::_;
using ::testing::AtLeast;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::InSequence;
using ::testing::InvokeWithoutArgs;
using ::testing::Lt;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

#if BUILDFLAG(IS_WIN)
#include "base/test/scoped_os_info_override_win.h"
#include "media/gpu/windows/mf_audio_encoder.h"
#define HAS_AAC_ENCODER 1
#endif

#if (BUILDFLAG(IS_MAC) || BUILDFLAG(IS_ANDROID)) && \
    BUILDFLAG(USE_PROPRIETARY_CODECS)
#define HAS_AAC_ENCODER 1
#endif

namespace blink {

static String TestVideoTrackId() {
  return "video_track_id";
}

static String TestAudioTrackId() {
  return "audio_track_id";
}
static const int kTestAudioChannels = 2;
static const int kTestAudioSampleRate = 48000;
static const int kTestAudioBufferDurationMs = 10;
// Opus works with 60ms buffers, so 6 MediaStreamAudioTrack Buffers are needed
// to encode one output buffer.
static const int kRatioOpusToTestAudioBuffers = 6;

struct MediaRecorderTestParams {
  const bool mp4_enabled;
  const bool has_video;
  const bool has_audio;
  const char* const mime_type;
  const char* const codecs;
  const bool encoder_supports_alpha;
  const bool use_mp4_muxer = false;
};

// Array of valid combinations of video/audio/codecs and expected collected
// encoded sizes to use for parameterizing MediaRecorderHandlerTest.
static const MediaRecorderTestParams kMediaRecorderTestParams[] = {
    {false, true, false, "video/webm", "vp8", true},
    {false, true, false, "video/webm", "vp9", true},
    {false, true, false, "video/webm", "av01", false},
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    {false, true, false, "video/x-matroska", "avc1", false},
#endif
    {false, false, true, "audio/webm", "opus", true},
    {false, false, true, "audio/webm", "", true},  // Should default to opus.
    {false, false, true, "audio/webm", "pcm", true},
    {false, true, true, "video/webm", "vp9,opus", true},
    // mp4 enabled.
    {true, true, false, "video/webm", "vp8", true},
    {true, true, false, "video/webm", "vp9", true},
    {true, true, false, "video/webm", "av01", false},
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    {true, true, false, "video/x-matroska", "avc1", false},
    {true, true, false, "video/mp4", "avc1", false, true},
    {true, true, true, "video/mp4", "avc1,mp4a.40.2", false, true},
    {true, false, true, "audio/mp4", "mp4a.40.2", false, true},
    {true, true, true, "video/mp4", "avc1,opus", false, true},
    {true, true, true, "video/mp4", "vp9,mp4a.40.2", false, true},
#endif
    {true, false, true, "audio/webm", "opus", true},
    {true, false, true, "audio/webm", "", true},  // Should default to opus.
    {true, false, true, "audio/webm", "pcm", true},
    {true, true, true, "video/webm", "vp9,opus", true},
    {true, false, true, "audio/mp4", "opus", false, true},
    {true, true, false, "video/mp4", "vp9", false, true},
    {true, true, true, "video/mp4", "vp9,opus", false, true},
};

MediaStream* CreateMediaStream(V8TestingScope& scope) {
  auto* source = MakeGarbageCollected<MediaStreamSource>(
      "sourceId", MediaStreamSource::kTypeAudio, "sourceName", false,
      /*platform_source=*/nullptr);
  auto* component = MakeGarbageCollected<MediaStreamComponentImpl>(
      "audioTrack", source,
      std::make_unique<MediaStreamAudioTrack>(/*is_local_track=*/true));

  auto* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component);

  HeapVector<Member<MediaStreamTrack>> tracks;
  tracks.push_back(track);

  MediaStream* stream =
      MediaStream::Create(scope.GetExecutionContext(), tracks);

  return stream;
}

class MockMediaRecorder : public MediaRecorder {
 public:
  explicit MockMediaRecorder(V8TestingScope& scope)
      : MediaRecorder(scope.GetExecutionContext(),
                      CreateMediaStream(scope),
                      MediaRecorderOptions::Create(),
                      scope.GetExceptionState()) {}
  ~MockMediaRecorder() override = default;

  MOCK_METHOD(void, WriteData, (base::span<const uint8_t>, bool, ErrorEvent*));
  MOCK_METHOD(void, OnError, (DOMExceptionCode code, const String& message));
};

class MediaRecorderHandlerFixture : public ScopedMockOverlayScrollbars {
 public:
  MediaRecorderHandlerFixture(bool has_video, bool has_audio)
      : has_video_(has_video),
        has_audio_(has_audio),
        media_recorder_handler_(MakeGarbageCollected<MediaRecorderHandler>(
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            KeyFrameRequestProcessor::Configuration())),
        audio_source_(kTestAudioChannels,
                      440 /* freq */,
                      kTestAudioSampleRate) {
    EXPECT_FALSE(media_recorder_handler_->recording_);

    registry_.Init();
  }

  ~MediaRecorderHandlerFixture() {
    registry_.reset();
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  bool recording() const { return media_recorder_handler_->recording_; }
  bool hasVideoRecorders() const {
    return !media_recorder_handler_->video_recorders_.empty();
  }
  bool hasAudioRecorders() const {
    return !media_recorder_handler_->audio_recorders_.empty();
  }

  bool IsTargetAudioCodecSupported(const String& codecs) {
    if (codecs.Find("mp4a.40.2") != kNotFound) {
#if !defined(HAS_AAC_ENCODER)
      return false;
#else
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      return media::MojoAudioEncoder::IsSupported(media::AudioCodec::kAAC);
#else
      return false;
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
#endif  // !defined(HAS_AAC_ENCODER)
    }

    return true;
  }

  bool IsAv1CodecSupported(const String codecs) {
#if BUILDFLAG(ENABLE_LIBAOM)
    return true;
#else
    return codecs.Find("av1") != kNotFound && codecs.Find("av01") != kNotFound;
#endif
  }

  WeakCell<AudioTrackRecorder::CallbackInterface>* GetAudioCallbackInterface() {
    return media_recorder_handler_->audio_recorders_[0]
        ->callback_interface_for_testing();
  }

  WeakCell<VideoTrackRecorder::CallbackInterface>* GetVideoCallbackInterface() {
    return media_recorder_handler_->video_recorders_[0]->callback_interface();
  }

  void OnVideoFrameForTesting(scoped_refptr<media::VideoFrame> frame) {
    media_recorder_handler_->OnVideoFrameForTesting(std::move(frame),
                                                    base::TimeTicks::Now());
  }

  void OnEncodedVideoForTesting(
      const media::Muxer::VideoParameters& params,
      scoped_refptr<media::DecoderBuffer> encoded_data,
      base::TimeTicks timestamp,
      std::optional<media::VideoEncoder::CodecDescription> codec_description =
          std::nullopt) {
    media_recorder_handler_->OnEncodedVideo(params, std::move(encoded_data),
                                            std::move(codec_description),
                                            timestamp);
  }

  void OnEncodedAudioForTesting(
      const media::AudioParameters& params,
      scoped_refptr<media::DecoderBuffer> encoded_data,
      base::TimeTicks timestamp) {
    media::AudioEncoder::CodecDescription codec_description = {99};
    media_recorder_handler_->OnEncodedAudio(params, std::move(encoded_data),
                                            std::move(codec_description),
                                            timestamp);
  }

  void OnEncodedAudioNoCodeDescriptionForTesting(
      const media::AudioParameters& params,
      scoped_refptr<media::DecoderBuffer> encoded_data,
      base::TimeTicks timestamp) {
    media_recorder_handler_->OnEncodedAudio(params, std::move(encoded_data),
                                            std::nullopt, timestamp);
  }

  void OnAudioBusForTesting(const media::AudioBus& audio_bus) {
    media_recorder_handler_->OnAudioBusForTesting(audio_bus,
                                                  base::TimeTicks::Now());
  }
  void SetAudioFormatForTesting(const media::AudioParameters& params) {
    media_recorder_handler_->SetAudioFormatForTesting(params);
  }

  void AddVideoTrack() {
    video_source_ = registry_.AddVideoTrack(TestVideoTrackId());
  }

  void AddTracks() {
    // Avoid issues with non-parameterized tests by calling this outside of ctr.
    if (has_video_)
      AddVideoTrack();
    if (has_audio_)
      registry_.AddAudioTrack(TestAudioTrackId());
  }

  void ForceOneErrorInWebmMuxer() {
    static_cast<media::WebmMuxer*>(
        media_recorder_handler_->muxer_adapter_->GetMuxerForTesting())
        ->ForceOneLibWebmErrorForTesting();
  }

  std::unique_ptr<media::AudioBus> NextAudioBus() {
    std::unique_ptr<media::AudioBus> bus(media::AudioBus::Create(
        kTestAudioChannels,
        kTestAudioSampleRate * kTestAudioBufferDurationMs / 1000));
    audio_source_.OnMoreData(base::TimeDelta(), base::TimeTicks::Now(), {},
                             bus.get());
    return bus;
  }

  void OnEncodedH264VideoForTesting(
      base::TimeTicks timestamp,
      std::optional<media::VideoEncoder::CodecDescription> codec_description =
          std::nullopt) {
    // It provides valid h264 stream.
    if (h264_video_stream_.empty()) {
      base::MemoryMappedFile mapped_h264_file;
      LoadEncodedFile("h264-320x180-frame-0", mapped_h264_file);
      h264_video_stream_ =
          base::HeapArray<uint8_t>::CopiedFrom(mapped_h264_file.bytes());
    }
    media::Muxer::VideoParameters video_params(
        gfx::Size(), 1, media::VideoCodec::kH264, gfx::ColorSpace());
    auto buffer = media::DecoderBuffer::CopyFrom(h264_video_stream_);
    std::string alpha_data = "alpha";
    buffer->WritableSideData().alpha_data =
        base::HeapArray<uint8_t>::CopiedFrom(base::as_byte_span(alpha_data));
    buffer->set_is_key_frame(true);
    OnEncodedVideoForTesting(video_params, buffer, timestamp,
                             std::move(codec_description));
  }

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  void PopulateAVCDecoderConfiguration(
      std::vector<uint8_t>& codec_description) {
    // copied from box_reader_unittest.cc.
    std::vector<uint8_t> test_data{
        0x1,        // configurationVersion = 1
        0x64,       // AVCProfileIndication = 100
        0x0,        // profile_compatibility = 0
        0xc,        // AVCLevelIndication = 10
        0xff,       // lengthSizeMinusOne = 3
        0xe1,       // numOfSequenceParameterSets = 1
        0x0, 0x19,  // sequenceParameterSetLength = 25

        // sequenceParameterSet
        0x67, 0x64, 0x0, 0xc, 0xac, 0xd9, 0x41, 0x41, 0xfb, 0x1, 0x10, 0x0, 0x0,
        0x3, 0x0, 0x10, 0x0, 0x0, 0x3, 0x1, 0x40, 0xf1, 0x42, 0x99, 0x60,

        0x1,       // numOfPictureParameterSets
        0x0, 0x6,  // pictureParameterSetLength = 6
        0x68, 0xeb, 0xe3, 0xcb, 0x22, 0xc0,

        0xfd,  // chroma_format = 1
        0xf8,  // bit_depth_luma_minus8 = 0
        0xf8,  // bit_depth_chroma_minus8 = 0
        0x0,   // numOfSequanceParameterSetExt = 0
    };

    media::mp4::AVCDecoderConfigurationRecord avc_config;
    ASSERT_TRUE(
        avc_config.Parse(test_data.data(), static_cast<int>(test_data.size())));
    ASSERT_TRUE(avc_config.Serialize(codec_description));
  }
#endif

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  MockMediaStreamRegistry registry_;
  bool has_video_;
  bool has_audio_;
  Persistent<MediaRecorderHandler> media_recorder_handler_;
  media::SineWaveAudioSource audio_source_;
  raw_ptr<MockMediaStreamVideoSource, DanglingUntriaged> video_source_ =
      nullptr;
  base::HeapArray<uint8_t> h264_video_stream_;

 private:
  void LoadEncodedFile(std::string_view filename,
                       base::MemoryMappedFile& mapped_stream) {
    base::FilePath file_path = GetTestDataFilePath(filename);

    ASSERT_TRUE(mapped_stream.Initialize(file_path))
        << "Couldn't open stream file: " << file_path.MaybeAsASCII();
  }

  base::FilePath GetTestDataFilePath(std::string_view name) {
    base::FilePath file_path;
    base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &file_path);
    file_path = file_path.Append(FILE_PATH_LITERAL("media"))
                    .Append(FILE_PATH_LITERAL("test"))
                    .Append(FILE_PATH_LITERAL("data"))
                    .AppendASCII(name);
    return file_path;
  }
};

class MediaRecorderHandlerTest : public TestWithParam<MediaRecorderTestParams>,
                                 public MediaRecorderHandlerFixture {
 public:
  MediaRecorderHandlerTest()
      : MediaRecorderHandlerFixture(GetParam().has_video,
                                    GetParam().has_audio) {
    if (GetParam().mp4_enabled) {
      scoped_feature_list_.InitAndEnableFeature(kMediaRecorderEnableMp4Muxer);
    } else {
      scoped_feature_list_.InitAndDisableFeature(kMediaRecorderEnableMp4Muxer);
    }
  }

  bool IsCodecSupported() {
#if !BUILDFLAG(ENABLE_OPENH264)
    // Test requires OpenH264 encoder. It can't use the VEA encoder.
    if (String(GetParam().codecs).Find("avc1") != kNotFound) {
      return false;
    }
#endif
#if !BUILDFLAG(ENABLE_LIBAOM)
    if (std::string(GetParam().codecs) == "av01") {
      return false;
    }
#endif
    return true;
  }

  bool IsStreamWriteSupported() {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    // TODO(crbug/1480178): Support valid   codec_description  parameter
    // for OnEncodedVideo/Audio to support real stream write.
    if (EqualIgnoringASCIICase(GetParam().mime_type, "video/mp4") ||
        EqualIgnoringASCIICase(GetParam().mime_type, "audio/mp4")) {
      return false;
    }
#endif
    return true;
  }

  bool IsAvc1CodecSupported(const String codecs) {
    return codecs.Find("avc1") != kNotFound;
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Checks that canSupportMimeType() works as expected, by sending supported
// combinations and unsupported ones.
TEST_P(MediaRecorderHandlerTest, CanSupportMimeType) {
  const String unsupported_mime_type("video/mpeg");
  EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(
      unsupported_mime_type, String()));

  const String mime_type_video("video/webm");
  EXPECT_TRUE(
      media_recorder_handler_->CanSupportMimeType(mime_type_video, String()));
  const String mime_type_video_uppercase("video/WEBM");
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video_uppercase, String()));
  const String example_good_codecs_1("vp8");
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_good_codecs_1));
  const String example_good_codecs_2("vp9,opus");
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_good_codecs_2));
  const String example_good_codecs_3("VP9,opus");
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_good_codecs_3));
  const String example_good_codecs_4("H264");
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_good_codecs_4));
#else
  EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_good_codecs_4));
#endif

  const String example_unsupported_codecs_1("daala");
  EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_unsupported_codecs_1));

  const String mime_type_audio("audio/webm");
  EXPECT_TRUE(
      media_recorder_handler_->CanSupportMimeType(mime_type_audio, String()));
  const String example_good_codecs_5("opus");
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_audio, example_good_codecs_5));
  const String example_good_codecs_6("OpUs");
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_audio, example_good_codecs_6));
  const String example_good_codecs_7("pcm");
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_audio, example_good_codecs_7));

  const String example_good_codecs_8("AV01,opus");
  EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_good_codecs_5));

  const String example_unsupported_codecs_2("vorbis");
  EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(
      mime_type_audio, example_unsupported_codecs_2));

  const String example_good_codecs_with_unsupported_tag("HEV1");
  EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_good_codecs_with_unsupported_tag));

  const String example_good_codecs_with_supported_tag("hvc1");
  EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(
      mime_type_video, example_good_codecs_with_supported_tag));
}

// Checks that it uses the specified bitrate mode.
TEST_P(MediaRecorderHandlerTest, SupportsBitrateMode) {
  AddTracks();
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);

  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);

  if (!IsAv1CodecSupported(codecs)) {
    return;
  }

  if (!IsTargetAudioCodecSupported(codecs)) {
    return;
  }

  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
  EXPECT_EQ(media_recorder_handler_->AudioBitrateMode(),
            AudioTrackRecorder::BitrateMode::kVariable);

  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kConstant));
  EXPECT_EQ(media_recorder_handler_->AudioBitrateMode(),
            AudioTrackRecorder::BitrateMode::kConstant);
}

// Checks that the initialization-destruction sequence works fine.
TEST_P(MediaRecorderHandlerTest, InitializeFailedWhenMP4MuxerFeatureDisabled) {
  AddTracks();
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);

  if (!IsAv1CodecSupported(codecs)) {
    return;
  }

  if (!IsTargetAudioCodecSupported(codecs)) {
    return;
  }

  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
  EXPECT_FALSE(recording());
  EXPECT_FALSE(hasVideoRecorders());
  EXPECT_FALSE(hasAudioRecorders());

  EXPECT_TRUE(media_recorder_handler_->Start(0, mime_type, 0, 0));
  EXPECT_TRUE(recording());

  EXPECT_TRUE(hasVideoRecorders() || !GetParam().has_video);
  EXPECT_TRUE(hasAudioRecorders() || !GetParam().has_audio);

  media_recorder_handler_->Stop();
  EXPECT_FALSE(recording());
  EXPECT_FALSE(hasVideoRecorders());
  EXPECT_FALSE(hasAudioRecorders());
}

// Sends 2 opaque frames and 1 transparent frame and expects them as WebM
// contained encoded data in writeData().
TEST_P(MediaRecorderHandlerTest, EncodeVideoFrames) {
  // Video-only test unless it is Mp4 muxer that needs `mp4a.40.2` audio codec.
  if ((GetParam().has_audio && !GetParam().use_mp4_muxer) ||
      !IsCodecSupported()) {
    return;
  }

  if (!GetParam().has_video) {
    return;
  }

  if (!IsTargetAudioCodecSupported(GetParam().codecs)) {
    return;
  }

  AddTracks();

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);
  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
  EXPECT_TRUE(media_recorder_handler_->Start(0, mime_type, 0, 0));

  InSequence s;
  const scoped_refptr<media::VideoFrame> video_frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(160, 80));

  if (GetParam().use_mp4_muxer) {
    {
      const size_t kMfraBoxSize = 76u;
      base::RunLoop run_loop;
      // WriteData is called as many as fragments (`moof` box) in addition
      // to 3 times of `ftyp`, `moov`, `mfra` boxes.
      EXPECT_CALL(*recorder, WriteData(SizeIs(Lt(kMfraBoxSize)), _, _))
          .Times(AtLeast(1));
      EXPECT_CALL(*recorder, WriteData(SizeIs(Gt(kMfraBoxSize)), _, _))
          .Times(AtLeast(1));
      EXPECT_CALL(*recorder, WriteData(SizeIs(kMfraBoxSize), _, _))
          .Times(1)
          .WillOnce(RunOnceClosure(run_loop.QuitClosure()));

      OnVideoFrameForTesting(video_frame);
      test::RunDelayedTasks(base::Seconds(2));

      // Mp4Muxer will flush when it is destroyed.
      media_recorder_handler_->Stop();
      run_loop.Run();
    }
  } else {
    {
      const size_t kEncodedSizeThreshold = 16;
      base::RunLoop run_loop;
      // writeData() is pinged a number of times as the WebM header is written;
      // the last time it is called it has the encoded data.
      EXPECT_CALL(*recorder, WriteData(SizeIs(Lt(kEncodedSizeThreshold)), _, _))
          .Times(AtLeast(1));
      EXPECT_CALL(*recorder, WriteData(SizeIs(Gt(kEncodedSizeThreshold)), _, _))
          .Times(1)
          .WillOnce(RunOnceClosure(run_loop.QuitClosure()));

      OnVideoFrameForTesting(video_frame);
      run_loop.Run();
    }
    Mock::VerifyAndClearExpectations(recorder);
    {
      const size_t kEncodedSizeThreshold = 12;
      base::RunLoop run_loop;
      // The second time around writeData() is called a number of times to write
      // the WebM frame header, and then is pinged with the encoded data.
      EXPECT_CALL(*recorder, WriteData(SizeIs(Lt(kEncodedSizeThreshold)), _, _))
          .Times(AtLeast(1));
      EXPECT_CALL(*recorder, WriteData(SizeIs(Gt(kEncodedSizeThreshold)), _, _))
          .Times(1)
          .WillOnce(RunOnceClosure(run_loop.QuitClosure()));

      OnVideoFrameForTesting(video_frame);
      run_loop.Run();
    }
    Mock::VerifyAndClearExpectations(recorder);
    {
      const scoped_refptr<media::VideoFrame> alpha_frame =
          media::VideoFrame::CreateTransparentFrame(gfx::Size(160, 80));
      const size_t kEncodedSizeThreshold = 16;
      EXPECT_EQ(4u, media::VideoFrame::NumPlanes(alpha_frame->format()));
      base::RunLoop run_loop;
      // The second time around writeData() is called a number of times to write
      // the WebM frame header, and then is pinged with the encoded data.
      EXPECT_CALL(*recorder, WriteData(SizeIs(Lt(kEncodedSizeThreshold)), _, _))
          .Times(AtLeast(1));
      EXPECT_CALL(*recorder, WriteData(SizeIs(Gt(kEncodedSizeThreshold)), _, _))
          .Times(1)
          .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
      if (GetParam().encoder_supports_alpha) {
        EXPECT_CALL(*recorder,
                    WriteData(SizeIs(Lt(kEncodedSizeThreshold)), _, _))
            .Times(AtLeast(1));
        EXPECT_CALL(*recorder,
                    WriteData(SizeIs(Gt(kEncodedSizeThreshold)), _, _))
            .Times(1)
            .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
      }
      OnVideoFrameForTesting(alpha_frame);
      run_loop.Run();
    }
    Mock::VerifyAndClearExpectations(recorder);
  }

  media_recorder_handler_->Stop();
}

// Sends 2 frames and expect them as WebM (or MKV) contained encoded audio data
// in writeData().
TEST_P(MediaRecorderHandlerTest, OpusEncodeAudioFrames) {
  // Audio-only test.
  if (GetParam().has_video || !IsStreamWriteSupported()) {
    return;
  }

  AddTracks();

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);

  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);
  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
  EXPECT_TRUE(media_recorder_handler_->Start(0, mime_type, 0, 0));

  InSequence s;
  const std::unique_ptr<media::AudioBus> audio_bus1 = NextAudioBus();
  const std::unique_ptr<media::AudioBus> audio_bus2 = NextAudioBus();

  media::AudioParameters params(
      media::AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::Stereo(), kTestAudioSampleRate,
      kTestAudioSampleRate * kTestAudioBufferDurationMs / 1000);
  SetAudioFormatForTesting(params);

  if (GetParam().use_mp4_muxer) {
    const size_t kEncodedSizeThreshold = 48u;

    base::RunLoop run_loop;
    // WriteData is called as many as fragments (`moof` box) in addition
    // to 2 times of `ftyp`, `moov` boxes (no 'mfra'box as it is audio only).
    EXPECT_CALL(*recorder, WriteData(SizeIs(Lt(kEncodedSizeThreshold)), _, _))
        .Times(AtLeast(1));
    EXPECT_CALL(*recorder, WriteData(SizeIs(Gt(kEncodedSizeThreshold)), _, _))
        .Times(2)
        .WillOnce(RunOnceClosure(run_loop.QuitClosure()));

    media::AudioParameters audio_params(
        media::AudioParameters::AUDIO_PCM_LINEAR,
        media::ChannelLayoutConfig::Stereo(), kTestAudioSampleRate,
        kTestAudioSampleRate * kTestAudioBufferDurationMs / 1000);

    // Null codec_description is used for Opus.
    auto buffer = media::DecoderBuffer::CopyFrom(base::as_byte_span("audio"));
    OnEncodedAudioNoCodeDescriptionForTesting(audio_params, buffer,
                                              base::TimeTicks::Now());

    media_recorder_handler_->Stop();

    run_loop.Run();

    Mock::VerifyAndClearExpectations(recorder);
  } else {
    const size_t kEncodedSizeThreshold = 24;
    {
      base::RunLoop run_loop;
      // writeData() is pinged a number of times as the WebM header is written;
      // the last time it is called it has the encoded data.
      EXPECT_CALL(*recorder, WriteData(SizeIs(Lt(kEncodedSizeThreshold)), _, _))
          .Times(AtLeast(1));
      EXPECT_CALL(*recorder, WriteData(SizeIs(Gt(kEncodedSizeThreshold)), _, _))
          .Times(1)
          .WillOnce(RunOnceClosure(run_loop.QuitClosure()));

      for (int i = 0; i < kRatioOpusToTestAudioBuffers; ++i) {
        OnAudioBusForTesting(*audio_bus1);
      }
      run_loop.Run();
    }
    Mock::VerifyAndClearExpectations(recorder);

    {
      base::RunLoop run_loop;
      // The second time around writeData() is called a number of times to write
      // the WebM frame header, and then is pinged with the encoded data.
      EXPECT_CALL(*recorder, WriteData(SizeIs(Lt(kEncodedSizeThreshold)), _, _))
          .Times(AtLeast(1));
      EXPECT_CALL(*recorder, WriteData(SizeIs(Gt(kEncodedSizeThreshold)), _, _))
          .Times(1)
          .WillOnce(RunOnceClosure(run_loop.QuitClosure()));

      for (int i = 0; i < kRatioOpusToTestAudioBuffers; ++i) {
        OnAudioBusForTesting(*audio_bus2);
      }
      run_loop.Run();
    }
    Mock::VerifyAndClearExpectations(recorder);
  }

  media_recorder_handler_->Stop();
}

// Starts up recording and forces a WebmMuxer's libwebm error.
TEST_P(MediaRecorderHandlerTest, WebmMuxerErrorWhileEncoding) {
  // Video-only test: Audio would be very similar.
  if (GetParam().has_audio || !IsCodecSupported() ||
      !IsStreamWriteSupported() || GetParam().use_mp4_muxer) {
    return;
  }

  AddTracks();

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);

  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);
  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
  EXPECT_TRUE(media_recorder_handler_->Start(0, mime_type, 0, 0));

  InSequence s;
  const scoped_refptr<media::VideoFrame> video_frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(160, 80));

  {
    const size_t kEncodedSizeThreshold = 16;
    base::RunLoop run_loop;
    EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
    EXPECT_CALL(*recorder, WriteData(SizeIs(Gt(kEncodedSizeThreshold)), _, _))
        .Times(1)
        .WillOnce(RunOnceClosure(run_loop.QuitClosure()));

    OnVideoFrameForTesting(video_frame);
    run_loop.Run();
  }

  ForceOneErrorInWebmMuxer();

  {
    base::RunLoop run_loop;
    EXPECT_CALL(*recorder, WriteData).Times(0);
    EXPECT_CALL(*recorder, OnError)
        .Times(1)
        .WillOnce(RunOnceClosure(run_loop.QuitClosure()));

    OnVideoFrameForTesting(video_frame);
    run_loop.Run();
  }
  Mock::VerifyAndClearExpectations(recorder);

  // Make sure the |media_recorder_handler_| gets destroyed and removing sinks
  // before the MediaStreamVideoTrack dtor, avoiding a DCHECK on a non-empty
  // callback list.
  media_recorder_handler_ = nullptr;
}

// Checks the ActualMimeType() versus the expected.
TEST_P(MediaRecorderHandlerTest, ActualMimeType) {
  AddTracks();

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);

  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);

  if (!IsAv1CodecSupported(codecs)) {
    return;
  }

  if (!IsTargetAudioCodecSupported(codecs)) {
    return;
  }

  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));

  StringBuilder actual_mime_type;
  actual_mime_type.Append(GetParam().mime_type);
  actual_mime_type.Append(";codecs=");
  if (strlen(GetParam().codecs) != 0u) {
    actual_mime_type.Append(GetParam().codecs);
  } else if (GetParam().has_video) {
    actual_mime_type.Append("vp8");
  } else if (GetParam().has_audio) {
    actual_mime_type.Append("opus");
  }

  EXPECT_EQ(media_recorder_handler_->ActualMimeType(),
            actual_mime_type.ToString());
}

TEST_P(MediaRecorderHandlerTest, PauseRecorderForVideo) {
  // Video-only test: Audio would be very similar.
  if (GetParam().has_audio) {
    return;
  }

  AddTracks();

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);

  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);

  if (!IsAv1CodecSupported(codecs)) {
    return;
  }

  EXPECT_TRUE(media_recorder_hand
"""


```