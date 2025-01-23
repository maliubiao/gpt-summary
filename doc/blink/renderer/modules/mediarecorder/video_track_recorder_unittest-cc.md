Response:
The user wants a summary of the functionality of the C++ unit test file `video_track_recorder_unittest.cc`. I need to identify the main purpose of the tests and how they interact with other components.

Here's a breakdown of the file's functionality:

1. **Testing `VideoTrackRecorder`**: The primary goal is to test the `VideoTrackRecorder` class, which is responsible for encoding video frames from a `MediaStreamTrack`.
2. **Encoding Functionality**: Tests cover different encoding scenarios, including:
    - Encoding with different codecs (VP8, VP9, H.264, AV1).
    - Encoding different frame types (software and GPU memory backed).
    - Handling keyframe requests.
    - Encoding frames with different sizes.
    - Encoding frames with alpha channels.
    - Handling encoding errors.
    - Screen content encoding.
3. **Interaction with other components**: The tests involve mocking or using fake implementations of several components:
    - `MediaStreamVideoSource`: To provide video frames.
    - `MediaStreamVideoTrack`: To represent the video track.
    - `VideoEncoder`: (Mocked or using a fake implementation) To perform the actual encoding.
    - `VideoTrackRecorder::CallbackInterface`: To receive the encoded frames and error notifications.
    - `VideoEncoderMetricsProvider`: To track encoding metrics.
4. **Relationship to Javascript/HTML/CSS**:  The `VideoTrackRecorder` is a core component of the MediaRecorder API, which is exposed to Javascript. The tests implicitly cover how the C++ backend handles actions initiated from Javascript, such as starting and stopping recording.
5. **Logical Reasoning**:  The tests often set up specific scenarios (e.g., requesting a keyframe) and verify the expected output (e.g., an encoded frame marked as a keyframe).
6. **Common Usage Errors**: The tests implicitly cover potential errors, such as attempting to encode with an unsupported codec or encountering hardware encoder failures.
7. **User Operations**: The file tests the backend logic triggered by user actions like starting a `MediaRecorder` in a web page.
这个C++源代码文件 `video_track_recorder_unittest.cc` 的主要功能是**测试 blink 引擎中 `VideoTrackRecorder` 类的视频编码功能**。`VideoTrackRecorder` 负责从 `MediaStreamTrack` 接收视频帧，并使用硬件或软件编码器将其编码为可用于媒体录制（MediaRecorder API）的格式。

以下是其功能的详细归纳：

1. **单元测试框架**:  该文件使用 Google Test (gtest) 框架来编写单元测试，以确保 `VideoTrackRecorder` 的各项功能正常工作。
2. **测试 `VideoTrackRecorderImpl` 类**: 重点测试 `VideoTrackRecorderImpl` 这个具体的 `VideoTrackRecorder` 实现类。
3. **模拟依赖**:  为了隔离测试 `VideoTrackRecorder` 的逻辑，该文件使用了 mock 对象（通过 Google Mock (gmock) 框架）来模拟其依赖项，例如：
    - `MockMediaStreamVideoSource`:  模拟视频源，提供测试用的视频帧。
    - `MockVideoTrackRecorderCallbackInterface`: 模拟 `VideoTrackRecorder` 的回调接口，用于验证编码后的数据和错误信息。
    - `MockTestingPlatform`: 模拟平台相关的服务，例如 GPU 视频加速器工厂。
    - `FakeVideoEncodeAccelerator`:  在某些测试中模拟视频编码加速器。
4. **测试不同的视频编码场景**: 文件中包含了多个测试用例，覆盖了 `VideoTrackRecorder` 的不同使用场景，例如：
    - **不同视频编解码器**: 测试 VP8, VP9, H.264, AV1 等不同的视频编解码器。
    - **不同的帧类型**: 测试不同存储方式的视频帧，例如 GPU 内存缓冲区（GpuMemoryBuffer）和软件内存。
    - **关键帧**: 测试关键帧的生成和请求机制。
    - **帧大小变化**: 测试处理不同尺寸视频帧的能力。
    - **Alpha 通道**: 测试是否支持和正确编码带有 Alpha 通道的视频。
    - **屏幕内容编码**: 测试针对屏幕录制优化的编码设置。
    - **编码错误处理**: 测试当编码失败时是否能正确触发错误回调。
5. **验证编码结果**:  测试用例会验证：
    - 编码后的数据是否被正确传递到回调接口。
    - 编码后的帧是否被标记为关键帧或非关键帧。
    - 编码器是否被正确初始化。
    - 编码指标提供器 (VideoEncoderMetricsProvider) 是否被正确调用。

**与 Javascript, HTML, CSS 的功能关系：**

`VideoTrackRecorder` 是 Web API `MediaRecorder` 的幕后功臣，因此它与 Javascript, HTML 和 CSS 的功能有着密切的关系：

* **Javascript (MediaRecorder API)**: Javascript 代码使用 `MediaRecorder` API 来录制来自 `MediaStream` 的音视频数据。`VideoTrackRecorder` 正是处理 `MediaStreamTrack` 中的视频部分并进行编码的核心组件。 当 Javascript 调用 `mediaRecorder.start()` 时，背后的 Blink 引擎会创建 `VideoTrackRecorder` 来处理视频轨道的录制。
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(function(stream) {
        const mediaRecorder = new MediaRecorder(stream);
        mediaRecorder.ondataavailable = function(event) {
          // 处理录制到的数据
        };
        mediaRecorder.start();
      });
    ```
* **HTML (`<video>` 元素)**:  录制到的视频数据最终可能会在 HTML 的 `<video>` 元素中播放。`VideoTrackRecorder` 编码的视频格式需要与浏览器支持的格式兼容，以便在 `<video>` 标签中播放。
* **CSS (样式)**: 虽然 CSS 本身不直接参与视频编码过程，但它可以用来控制 `<video>` 元素的显示样式，例如尺寸、边框等。

**逻辑推理举例：**

**假设输入：**

1. `VideoTrackRecorder` 初始化时指定使用 VP8 编码器。
2. 接收到一系列大小为 640x480 的视频帧。
3. 在第三帧之后，通过 `ForceKeyFrameForNextFrameForTesting()` 请求下一个帧为关键帧。

**预期输出：**

1. 前三个编码后的视频数据包可能不是关键帧（取决于编码器的内部逻辑和初始设置）。
2. 第四个编码后的视频数据包**应该**被标记为关键帧 (`is_key_frame() == true`)。
3. 后续的视频数据包可能是非关键帧，直到再次请求关键帧。

**常见的使用错误举例：**

* **编码器初始化失败**:  如果系统缺少所需的编解码器或者硬件加速器不可用，`VideoTrackRecorder` 尝试初始化编码器时可能会失败，导致 `OnVideoEncodingError` 回调被触发。 这在用户尝试录制时可能会导致录制失败。
* **发送过大的帧**: 某些编码器对输入帧的大小有限制。如果用户提供的 `MediaStreamTrack` 的分辨率过高，超过了编码器的能力，`VideoTrackRecorder` 可能会报错并触发 `OnVideoEncodingError`。
* **尝试编码不支持的格式**:  如果用户尝试使用 `MediaRecorder` 指定 `VideoTrackRecorder` 不支持的编码格式，那么在初始化时就会失败。

**用户操作到达这里的调试线索：**

1. **用户打开一个网页，该网页使用了 `MediaRecorder` API 来录制视频。**
2. **用户允许了摄像头权限，使得 `getUserMedia` 返回了一个包含视频轨道的 `MediaStream`。**
3. **网页 Javascript 代码创建了一个 `MediaRecorder` 对象，并将视频轨道传递给它。**
4. **Javascript 代码调用 `mediaRecorder.start()` 方法开始录制。**
5. **在 Blink 引擎内部，会创建一个 `VideoTrackRecorder` 对象来处理视频轨道的编码。**
6. **`VideoTrackRecorder` 开始接收来自视频源的视频帧。**
7. **如果开发者需要在某些特定场景下调试视频编码过程，他们可能会查看 `video_track_recorder_unittest.cc` 中的测试用例，或者编写新的测试用例来验证 `VideoTrackRecorder` 的行为。** 例如，他们可能想验证特定编码格式的兼容性，或者排查用户反馈的录制失败问题。

**本部分的归纳总结：**

`video_track_recorder_unittest.cc` 是一个关键的单元测试文件，用于验证 Blink 引擎中 `VideoTrackRecorder` 类的核心视频编码功能。它通过模拟依赖项和设置不同的测试场景，确保 `VideoTrackRecorder` 能够正确地编码各种类型的视频帧，处理关键帧请求，并有效地处理错误情况，从而保障了 Web `MediaRecorder` API 的稳定性和可靠性。  它测试了 C++ 后端如何响应 Javascript `MediaRecorder` API 的调用，并确保编码后的视频数据可以被 HTML 的 `<video>` 元素正确播放。

### 提示词
```
这是目录为blink/renderer/modules/mediarecorder/video_track_recorder_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediarecorder/video_track_recorder.h"

#include <sstream>
#include <string_view>

#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/bind.h"
#include "base/test/gmock_callback_support.h"
#include "base/time/time.h"
#include "media/base/decoder_buffer.h"
#include "media/base/limits.h"
#include "media/base/mock_filters.h"
#include "media/base/video_codecs.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "media/media_buildflags.h"
#include "media/video/fake_video_encode_accelerator.h"
#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/modules/mediarecorder/fake_encoded_video_frame.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/video_frame_utils.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/gpu_memory_buffer.h"

using video_track_recorder::kVEAEncoderMinResolutionHeight;
using video_track_recorder::kVEAEncoderMinResolutionWidth;

using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::TestWithParam;
using ::testing::ValuesIn;
using ::testing::WithArg;

namespace blink {
namespace {

// Specifies frame type for test.
enum class TestFrameType {
  kNv12GpuMemoryBuffer,  // Implies media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER
  kNv12Software,         // Implies media::VideoFrame::STORAGE_OWNED_MEMORY
  kI420                  // Implies media::VideoFrame::STORAGE_OWNED_MEMORY
};

const TestFrameType kTestFrameTypes[] = {TestFrameType::kNv12GpuMemoryBuffer,
                                         TestFrameType::kNv12Software,
                                         TestFrameType::kI420};

const VideoTrackRecorder::CodecId kTrackRecorderTestCodec[] = {
    VideoTrackRecorder::CodecId::kVp8,
    VideoTrackRecorder::CodecId::kVp9,
#if BUILDFLAG(ENABLE_OPENH264)
    VideoTrackRecorder::CodecId::kH264,
#endif
#if BUILDFLAG(ENABLE_LIBAOM)
    VideoTrackRecorder::CodecId::kAv1,
#endif
};
const gfx::Size kTrackRecorderTestSize[] = {
    gfx::Size(kVEAEncoderMinResolutionWidth / 2,
              kVEAEncoderMinResolutionHeight / 2),
    gfx::Size(kVEAEncoderMinResolutionWidth, kVEAEncoderMinResolutionHeight)};
static const int kTrackRecorderTestSizeDiff = 20;

constexpr media::VideoCodec MediaVideoCodecFromCodecId(
    VideoTrackRecorder::CodecId id) {
  switch (id) {
    case VideoTrackRecorder::CodecId::kVp8:
      return media::VideoCodec::kVP8;
    case VideoTrackRecorder::CodecId::kVp9:
      return media::VideoCodec::kVP9;
// Note: The H264 tests in this file are written explicitly for OpenH264 and
// will fail for hardware encoders that aren't 1 in 1 out.
#if BUILDFLAG(ENABLE_OPENH264)
    case VideoTrackRecorder::CodecId::kH264:
      return media::VideoCodec::kH264;
#endif
#if BUILDFLAG(ENABLE_LIBAOM)
    case VideoTrackRecorder::CodecId::kAv1:
      return media::VideoCodec::kAV1;
#endif
    default:
      return media::VideoCodec::kUnknown;
  }
}

media::VideoCodecProfile MediaVideoCodecProfileFromCodecId(
    VideoTrackRecorder::CodecId id) {
  switch (id) {
    case VideoTrackRecorder::CodecId::kVp8:
      return media::VideoCodecProfile::VP8PROFILE_ANY;
    case VideoTrackRecorder::CodecId::kVp9:
      return media::VideoCodecProfile::VP9PROFILE_PROFILE0;
// Note: The H264 tests in this file are written explicitly for OpenH264 and
// will fail for hardware encoders that aren't 1 in 1 out.
#if BUILDFLAG(ENABLE_OPENH264)
    case VideoTrackRecorder::CodecId::kH264:
      return media::VideoCodecProfile::H264PROFILE_MIN;
#endif
#if BUILDFLAG(ENABLE_LIBAOM)
    case VideoTrackRecorder::CodecId::kAv1:
      return media::VideoCodecProfile::AV1PROFILE_MIN;
#endif
    default:
      break;
  }
  NOTREACHED() << "Unsupported video codec";
}

}  // namespace

ACTION_P(RunClosure, closure) {
  closure.Run();
}

class MockTestingPlatform : public IOTaskRunnerTestingPlatformSupport {
 public:
  MockTestingPlatform() = default;
  ~MockTestingPlatform() override = default;

  MOCK_METHOD(media::GpuVideoAcceleratorFactories*,
              GetGpuFactories,
              (),
              (override));
};

class MockVideoTrackRecorderCallbackInterface
    : public GarbageCollected<MockVideoTrackRecorderCallbackInterface>,
      public VideoTrackRecorder::CallbackInterface {
 public:
  virtual ~MockVideoTrackRecorderCallbackInterface() = default;
  MOCK_METHOD(void,
              OnPassthroughVideo,
              (const media::Muxer::VideoParameters& params,
               scoped_refptr<media::DecoderBuffer> encoded_data,
               base::TimeTicks timestamp),
              (override));
  MOCK_METHOD(
      void,
      OnEncodedVideo,
      (const media::Muxer::VideoParameters& params,
       scoped_refptr<media::DecoderBuffer> encoded_data,
       std::optional<media::VideoEncoder::CodecDescription> codec_description,
       base::TimeTicks timestamp),
      (override));
  MOCK_METHOD(std::unique_ptr<media::VideoEncoderMetricsProvider>,
              CreateVideoEncoderMetricsProvider,
              (),
              (override));

  MOCK_METHOD(void, OnVideoEncodingError, (), (override));
  MOCK_METHOD(void, OnSourceReadyStateChanged, (), (override));
  void Trace(Visitor* v) const override { v->Trace(weak_factory_); }
  WeakCell<VideoTrackRecorder::CallbackInterface>* GetWeakCell() {
    return weak_factory_.GetWeakCell();
  }

 private:
  WeakCellFactory<VideoTrackRecorder::CallbackInterface> weak_factory_{this};
};

class VideoTrackRecorderTestBase {
 public:
  VideoTrackRecorderTestBase()
      : mock_callback_interface_(
            MakeGarbageCollected<MockVideoTrackRecorderCallbackInterface>()) {
    ON_CALL(*mock_callback_interface_, CreateVideoEncoderMetricsProvider())
        .WillByDefault(
            ::testing::Invoke(this, &VideoTrackRecorderTestBase::
                                        CreateMockVideoEncoderMetricsProvider));
  }

 protected:
  virtual ~VideoTrackRecorderTestBase() {
    mock_callback_interface_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  std::unique_ptr<media::VideoEncoderMetricsProvider>
  CreateMockVideoEncoderMetricsProvider() {
    return std::make_unique<media::MockVideoEncoderMetricsProvider>();
  }

  test::TaskEnvironment task_environment_;
  Persistent<MockVideoTrackRecorderCallbackInterface> mock_callback_interface_;
};

class VideoTrackRecorderTest : public VideoTrackRecorderTestBase {
 public:
  VideoTrackRecorderTest() : mock_source_(new MockMediaStreamVideoSource()) {
    const String track_id("dummy");
    source_ = MakeGarbageCollected<MediaStreamSource>(
        track_id, MediaStreamSource::kTypeVideo, track_id, false /*remote*/,
        base::WrapUnique(mock_source_.get()));
    EXPECT_CALL(*mock_source_, OnRequestRefreshFrame())
        .Times(testing::AnyNumber());
    EXPECT_CALL(*mock_source_, OnCapturingLinkSecured(_))
        .Times(testing::AnyNumber());
    EXPECT_CALL(*mock_source_, GetSubCaptureTargetVersion())
        .Times(testing::AnyNumber())
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*mock_source_, OnSourceCanDiscardAlpha(_))
        .Times(testing::AnyNumber());

    auto platform_track = std::make_unique<MediaStreamVideoTrack>(
        mock_source_, WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
        true /* enabled */);
    track_ = platform_track.get();
    component_ = MakeGarbageCollected<MediaStreamComponentImpl>(
        source_, std::move(platform_track));

    // Paranoia checks.
    EXPECT_EQ(component_->Source()->GetPlatformSource(),
              source_->GetPlatformSource());
    EXPECT_TRUE(scheduler::GetSingleThreadTaskRunnerForTesting()
                    ->BelongsToCurrentThread());

    EXPECT_CALL(*platform_, GetGpuFactories())
        .Times(testing::AnyNumber())
        .WillRepeatedly(Return(nullptr));
  }

  VideoTrackRecorderTest(const VideoTrackRecorderTest&) = delete;
  VideoTrackRecorderTest& operator=(const VideoTrackRecorderTest&) = delete;

  ~VideoTrackRecorderTest() override {
    component_ = nullptr;
    source_ = nullptr;
    video_track_recorder_.reset();
  }

  void InitializeRecorder(
      VideoTrackRecorder::CodecId codec_id,
      KeyFrameRequestProcessor::Configuration keyframe_config =
          KeyFrameRequestProcessor::Configuration()) {
    InitializeRecorder(VideoTrackRecorder::CodecProfile(codec_id),
                       keyframe_config);
  }

  void InitializeRecorder(
      VideoTrackRecorder::CodecProfile codec_profile,
      KeyFrameRequestProcessor::Configuration keyframe_config =
          KeyFrameRequestProcessor::Configuration()) {
    video_track_recorder_ = std::make_unique<VideoTrackRecorderImpl>(
        scheduler::GetSingleThreadTaskRunnerForTesting(), codec_profile,
        WebMediaStreamTrack(component_.Get()),
        mock_callback_interface_->GetWeakCell(),
        /*bits_per_second=*/1000000, keyframe_config,
        /*frame_buffer_pool_limit=*/10);
  }

  void Encode(scoped_refptr<media::VideoFrame> frame,
              base::TimeTicks capture_time,
              bool allow_vea_encoder = true) {
    EXPECT_TRUE(scheduler::GetSingleThreadTaskRunnerForTesting()
                    ->BelongsToCurrentThread());
    video_track_recorder_->OnVideoFrameForTesting(
        std::move(frame), capture_time, allow_vea_encoder);
  }

  void OnFailed() { FAIL(); }
  void OnError() { video_track_recorder_->OnHardwareEncoderError(); }

  bool CanEncodeAlphaChannel() {
    bool result;
    base::WaitableEvent finished;
    video_track_recorder_->encoder_.PostTaskWithThisObject(CrossThreadBindOnce(
        [](base::WaitableEvent* finished, bool* out_result,
           VideoTrackRecorder::Encoder* encoder) {
          *out_result = encoder->CanEncodeAlphaChannel();
          finished->Signal();
        },
        CrossThreadUnretained(&finished), CrossThreadUnretained(&result)));
    finished.Wait();
    return result;
  }

  bool IsScreenContentEncoding() {
    bool result;
    base::WaitableEvent finished;
    video_track_recorder_->encoder_.PostTaskWithThisObject(CrossThreadBindOnce(
        [](base::WaitableEvent* finished, bool* out_result,
           VideoTrackRecorder::Encoder* encoder) {
          *out_result = encoder->IsScreenContentEncodingForTesting();
          finished->Signal();
        },
        CrossThreadUnretained(&finished), CrossThreadUnretained(&result)));
    finished.Wait();
    return result;
  }

  bool HasEncoderInstance() const {
    return !video_track_recorder_->encoder_.is_null();
  }

  ScopedTestingPlatformSupport<MockTestingPlatform> platform_;

  // All members are non-const due to the series of initialize() calls needed.
  // |mock_source_| is owned by |source_|, |track_| by |component_|.
  raw_ptr<MockMediaStreamVideoSource> mock_source_;
  Persistent<MediaStreamSource> source_;
  raw_ptr<MediaStreamVideoTrack> track_;
  Persistent<MediaStreamComponent> component_;

  std::unique_ptr<VideoTrackRecorderImpl> video_track_recorder_;

 protected:
  scoped_refptr<media::VideoFrame> CreateFrameForTest(
      TestFrameType frame_type,
      const gfx::Size& frame_size,
      bool encode_alpha_channel,
      int padding) {
    const gfx::Size padded_size(frame_size.width() + padding,
                                frame_size.height());
    if (frame_type == TestFrameType::kI420) {
      return media::VideoFrame::CreateZeroInitializedFrame(
          encode_alpha_channel ? media::PIXEL_FORMAT_I420A
                               : media::PIXEL_FORMAT_I420,
          padded_size, gfx::Rect(frame_size), frame_size, base::TimeDelta());
    }

    scoped_refptr<media::VideoFrame> video_frame = blink::CreateTestFrame(
        padded_size, gfx::Rect(frame_size), frame_size,
        frame_type == TestFrameType::kNv12Software
            ? media::VideoFrame::STORAGE_OWNED_MEMORY
            : media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER,
        media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());
    scoped_refptr<media::VideoFrame> video_frame2 = video_frame;
    if (frame_type == TestFrameType::kNv12GpuMemoryBuffer) {
      video_frame2 = media::ConvertToMemoryMappedFrame(video_frame);
    }

    // Fade to black.
    const uint8_t kBlackY = 0x00;
    const uint8_t kBlackUV = 0x80;
    memset(video_frame2->writable_data(0), kBlackY,
           video_frame2->stride(0) * frame_size.height());
    memset(video_frame2->writable_data(1), kBlackUV,
           video_frame2->stride(1) * (frame_size.height() / 2));
    if (frame_type == TestFrameType::kNv12GpuMemoryBuffer) {
      return video_frame;
    }
    return video_frame2;
  }
};

class VideoTrackRecorderTestWithAllCodecs : public ::testing::Test,
                                            public VideoTrackRecorderTest {
 public:
  VideoTrackRecorderTestWithAllCodecs() = default;
  ~VideoTrackRecorderTestWithAllCodecs() override = default;
};

TEST_F(VideoTrackRecorderTestWithAllCodecs, NoCrashInConfigureEncoder) {
  constexpr std::pair<VideoTrackRecorder::CodecId, bool> kCodecIds[] = {
      {VideoTrackRecorder::CodecId::kVp8, true},
      {VideoTrackRecorder::CodecId::kVp9, true},
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      {VideoTrackRecorder::CodecId::kH264,
#if BUILDFLAG(ENABLE_OPENH264)
       true
#else
       false
#endif  // BUILDFLAG(ENABLE_OPENH264)
      },
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
      {VideoTrackRecorder::CodecId::kAv1,
#if BUILDFLAG(ENABLE_LIBAOM)
       true
#else
       false
#endif  // BUILDFLAG(ENABLE_LIBAOM)
      },
  };
  for (auto [codec_id, can_sw_encode] : kCodecIds) {
    InitializeRecorder(codec_id);
    const scoped_refptr<media::VideoFrame> video_frame =
        CreateFrameForTest(TestFrameType::kI420,
                           gfx::Size(kVEAEncoderMinResolutionWidth,
                                     kVEAEncoderMinResolutionHeight),
                           /*encode_alpha_channel=*/false, /*padding=*/0);
    if (!video_frame) {
      ASSERT_TRUE(!!video_frame);
    }
    base::RunLoop run_loop;
    InSequence s;
    if (can_sw_encode) {
      EXPECT_CALL(*mock_callback_interface_, OnEncodedVideo)
          .WillOnce(RunClosure(run_loop.QuitClosure()));
    } else {
      EXPECT_CALL(*mock_callback_interface_, OnVideoEncodingError)
          .WillOnce(RunClosure(run_loop.QuitClosure()));
    }
    Encode(video_frame, base::TimeTicks::Now());
    run_loop.Run();
    EXPECT_EQ(HasEncoderInstance(), can_sw_encode);
  }
}

class VideoTrackRecorderTestWithCodec
    : public TestWithParam<testing::tuple<VideoTrackRecorder::CodecId, bool>>,
      public VideoTrackRecorderTest,
      public ScopedMediaRecorderUseMediaVideoEncoderForTest {
 public:
  VideoTrackRecorderTestWithCodec()
      : ScopedMediaRecorderUseMediaVideoEncoderForTest(
            testing::get<1>(GetParam())) {}
  ~VideoTrackRecorderTestWithCodec() override = default;
};

// Construct and destruct all objects, in particular |video_track_recorder_| and
// its inner object(s). This is a non trivial sequence.
TEST_P(VideoTrackRecorderTestWithCodec, ConstructAndDestruct) {
  InitializeRecorder(testing::get<0>(GetParam()));
}

// Initializes an encoder with very large frame that causes an error on the
// initialization. Check if the error is reported via OnVideoEncodingError().
TEST_P(VideoTrackRecorderTestWithCodec,
       SoftwareEncoderInitializeErrorWithLargeFrame) {
  const VideoTrackRecorder::CodecId codec_id = testing::get<0>(GetParam());
  if (codec_id == VideoTrackRecorder::CodecId::kVp9
#if BUILDFLAG(ENABLE_LIBAOM)
      || codec_id == VideoTrackRecorder::CodecId::kAv1
#endif
  ) {
    // The max bits on width and height are 16bits in VP9 and AV1. Since it is
    // more than media::limits::kMaxDimension (15 bits), the larger frame
    // causing VP9 and AV1 initialization cannot be created because
    // CreateBlackFrame() fails.
    GTEST_SKIP();
  }
  InitializeRecorder(codec_id);
  constexpr gfx::Size kTooLargeResolution(media::limits::kMaxDimension - 1, 1);
  auto too_large_frame =
      media::VideoFrame::CreateBlackFrame(kTooLargeResolution);
  ASSERT_TRUE(too_large_frame);
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_, OnVideoEncodingError)
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  Encode(too_large_frame, base::TimeTicks::Now());
  run_loop.Run();
}

INSTANTIATE_TEST_SUITE_P(All,
                         VideoTrackRecorderTestWithCodec,
                         ::testing::Combine(ValuesIn(kTrackRecorderTestCodec),
                                            ::testing::Bool()));

// TODO(crbug/1177593): refactor the test parameter space to something more
// reasonable. Many tests below ignore parts of the space leading to too much
// being tested.
class VideoTrackRecorderTestParam
    : public TestWithParam<testing::tuple<VideoTrackRecorder::CodecId,
                                          gfx::Size,
                                          bool,
                                          TestFrameType,
                                          bool>>,
      public VideoTrackRecorderTest,
      public ScopedMediaRecorderUseMediaVideoEncoderForTest {
 public:
  VideoTrackRecorderTestParam()
      : ScopedMediaRecorderUseMediaVideoEncoderForTest(
            testing::get<4>(GetParam())) {}
  ~VideoTrackRecorderTestParam() override = default;
};

// Matches whether a scoped_refptr<DecoderBuffer> is a key frame or not.
MATCHER_P(IsKeyFrame, is_key_frame, "decoder buffer key frame matcher") {
  return arg->is_key_frame() == is_key_frame;
}

// Creates the encoder and encodes 2 frames of the same size; the encoder
// should be initialised and produce a keyframe, then a non-keyframe. Finally
// a frame of larger size is sent and is expected to be encoded as a keyframe.
// If |encode_alpha_channel| is enabled, encoder is expected to return a
// second output with encoded alpha data.
TEST_P(VideoTrackRecorderTestParam, VideoEncoding) {
  InitializeRecorder(testing::get<0>(GetParam()));

  const bool encode_alpha_channel = testing::get<2>(GetParam());
  // |frame_size| cannot be arbitrarily small, should be reasonable.
  const gfx::Size& frame_size = testing::get<1>(GetParam());
  const TestFrameType test_frame_type = testing::get<3>(GetParam());

  // We don't support alpha channel with GpuMemoryBuffer frames.
  if (test_frame_type != TestFrameType::kI420 && encode_alpha_channel) {
    return;
  }

  const scoped_refptr<media::VideoFrame> video_frame = CreateFrameForTest(
      test_frame_type, frame_size, encode_alpha_channel, /*padding=*/0);
  if (!video_frame) {
    ASSERT_TRUE(!!video_frame);
  }

  const double kFrameRate = 60.0f;
  video_frame->metadata().frame_rate = kFrameRate;

  InSequence s;
  const base::TimeTicks timeticks_now = base::TimeTicks::Now();
  scoped_refptr<media::DecoderBuffer> first_frame_encoded_data;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, timeticks_now))
      .Times(1)
      .WillOnce(SaveArg<1>(&first_frame_encoded_data));

  const base::TimeTicks timeticks_later = base::TimeTicks::Now();
  scoped_refptr<media::DecoderBuffer> second_frame_encoded_data;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, timeticks_later))
      .Times(1)
      .WillOnce(SaveArg<1>(&second_frame_encoded_data));

  const gfx::Size frame_size2(frame_size.width() + kTrackRecorderTestSizeDiff,
                              frame_size.height());
  const scoped_refptr<media::VideoFrame> video_frame2 = CreateFrameForTest(
      test_frame_type, frame_size2, encode_alpha_channel, /*padding=*/0);

  base::RunLoop run_loop;

  scoped_refptr<media::DecoderBuffer> third_frame_encoded_data;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .Times(1)
      .WillOnce(DoAll(SaveArg<1>(&third_frame_encoded_data),
                      RunClosure(run_loop.QuitClosure())));
  // A test-only TSAN problem is fixed by placing the encodes down here and not
  // close to the expectation setups.
  Encode(video_frame, timeticks_now);
  Encode(video_frame, timeticks_later);
  Encode(video_frame2, base::TimeTicks::Now());

  run_loop.Run();

  const size_t kEncodedSizeThreshold = 12;
  EXPECT_GE(first_frame_encoded_data->size(), kEncodedSizeThreshold);
  EXPECT_GE(second_frame_encoded_data->size(), kEncodedSizeThreshold);
  EXPECT_GE(third_frame_encoded_data->size(), kEncodedSizeThreshold);

  // We only support NV12 with GpuMemoryBuffer video frame.
  if (test_frame_type == TestFrameType::kI420 && encode_alpha_channel &&
      CanEncodeAlphaChannel()) {
    EXPECT_GE(first_frame_encoded_data->side_data()->alpha_data.size(),
              kEncodedSizeThreshold);
    EXPECT_GE(second_frame_encoded_data->side_data()->alpha_data.size(),
              kEncodedSizeThreshold);
    EXPECT_GE(third_frame_encoded_data->side_data()->alpha_data.size(),
              kEncodedSizeThreshold);
  } else {
    EXPECT_FALSE(first_frame_encoded_data->has_side_data());
    EXPECT_FALSE(second_frame_encoded_data->has_side_data());
    EXPECT_FALSE(third_frame_encoded_data->has_side_data());
  }

  // The encoder is configured non screen content by default.
  EXPECT_FALSE(IsScreenContentEncoding());

  Mock::VerifyAndClearExpectations(this);
}

// VideoEncoding with the screencast track.
TEST_P(VideoTrackRecorderTestParam, ConfigureEncoderWithScreenContent) {
  track_->SetIsScreencastForTesting(true);

  InitializeRecorder(testing::get<0>(GetParam()));

  const bool encode_alpha_channel = testing::get<2>(GetParam());
  // |frame_size| cannot be arbitrarily small, should be reasonable.
  const gfx::Size& frame_size = testing::get<1>(GetParam());
  const TestFrameType test_frame_type = testing::get<3>(GetParam());

  // We don't support alpha channel with GpuMemoryBuffer frames.
  if (test_frame_type != TestFrameType::kI420 && encode_alpha_channel) {
    return;
  }

  const scoped_refptr<media::VideoFrame> video_frame = CreateFrameForTest(
      test_frame_type, frame_size, encode_alpha_channel, /*padding=*/0);
  if (!video_frame) {
    ASSERT_TRUE(!!video_frame);
  }

  InSequence s;
  base::RunLoop run_loop1;
  EXPECT_CALL(*mock_callback_interface_, OnEncodedVideo)
      .WillOnce(RunClosure(run_loop1.QuitClosure()));
  Encode(video_frame, base::TimeTicks::Now());
  run_loop1.Run();

  EXPECT_TRUE(HasEncoderInstance());

  // MediaRecorderEncoderWrapper is configured with a screen content hint.
  const bool is_media_recorder_encoder_wrapper =
      testing::get<4>(GetParam()) ||
      testing::get<0>(GetParam()) == VideoTrackRecorder::CodecId::kAv1;
  EXPECT_EQ(is_media_recorder_encoder_wrapper, IsScreenContentEncoding());
  Mock::VerifyAndClearExpectations(this);
}

// Same as VideoEncoding but add the EXPECT_CALL for the
// VideoEncoderMetricsProvider.
TEST_P(VideoTrackRecorderTestParam, CheckMetricsProviderInVideoEncoding) {
  InitializeRecorder(testing::get<0>(GetParam()));

  const bool encode_alpha_channel = testing::get<2>(GetParam());
  // |frame_size| cannot be arbitrarily small, should be reasonable.
  const gfx::Size& frame_size = testing::get<1>(GetParam());
  const TestFrameType test_frame_type = testing::get<3>(GetParam());

  // We don't support alpha channel with GpuMemoryBuffer frames.
  if (test_frame_type != TestFrameType::kI420 && encode_alpha_channel) {
    return;
  }

  const media::VideoCodecProfile video_codec_profile =
      MediaVideoCodecProfileFromCodecId(testing::get<0>(GetParam()));

  auto metrics_provider =
      std::make_unique<media::MockVideoEncoderMetricsProvider>();
  media::MockVideoEncoderMetricsProvider* mock_metrics_provider =
      metrics_provider.get();
  int initialize_time = 1;
  if (encode_alpha_channel &&
      (video_codec_profile == media::VideoCodecProfile::VP8PROFILE_ANY ||
       video_codec_profile == media::VideoCodecProfile::VP9PROFILE_PROFILE0) &&
      !testing::get<4>(GetParam())) {
    initialize_time = 2;
  }

  base::RunLoop run_loop1;
  InSequence s;
  EXPECT_CALL(*mock_callback_interface_, CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(::testing::ByMove(std::move(metrics_provider))));
  EXPECT_CALL(*mock_metrics_provider,
              MockInitialize(video_codec_profile, frame_size,
                             /*is_hardware_encoder=*/false,
                             media::SVCScalabilityMode::kL1T1))
      .Times(initialize_time);
  EXPECT_CALL(*mock_metrics_provider, MockIncrementEncodedFrameCount())
      .Times(2);

  const gfx::Size frame_size2(frame_size.width() + kTrackRecorderTestSizeDiff,
                              frame_size.height());
  EXPECT_CALL(*mock_metrics_provider,
              MockInitialize(video_codec_profile, frame_size2,
                             /*is_hardware_encoder=*/false,
                             media::SVCScalabilityMode::kL1T1))
      .Times(initialize_time);
  EXPECT_CALL(*mock_metrics_provider, MockIncrementEncodedFrameCount())
      .WillOnce(RunClosure(run_loop1.QuitClosure()));

  const scoped_refptr<media::VideoFrame> video_frame = CreateFrameForTest(
      test_frame_type, frame_size, encode_alpha_channel, /*padding=*/0);

  const double kFrameRate = 60.0f;
  video_frame->metadata().frame_rate = kFrameRate;
  const scoped_refptr<media::VideoFrame> video_frame2 = CreateFrameForTest(
      test_frame_type, frame_size2, encode_alpha_channel, /*padding=*/0);

  const base::TimeTicks timeticks_now = base::TimeTicks::Now();
  const base::TimeTicks timeticks_later =
      timeticks_now + base::Milliseconds(10);
  const base::TimeTicks timeticks_last =
      timeticks_later + base::Milliseconds(10);

  // A test-only TSAN problem is fixed by placing the encodes down here and not
  // close to the expectation setups.
  Encode(video_frame, timeticks_now);
  Encode(video_frame, timeticks_later);
  Encode(video_frame2, timeticks_last);

  run_loop1.Run();

  // Since |encoder_| is destroyed on the encoder sequence checker, it and the
  // MockVideoEncoderMetricsProvider are asynchronously. It causes the leak
  // mock object, |mock_metrics_provider|. Avoid it by waiting until the
  // mock object is destroyed.
  base::RunLoop run_loop2;

  EXPECT_CALL(*mock_metrics_provider, MockDestroy())
      .WillOnce(RunClosure(run_loop2.QuitClosure()));
  video_track_recorder_.reset();
  run_loop2.Run();

  Mock::VerifyAndClearExpectations(this);
}

// Inserts a frame which has different coded size than the visible rect and
// expects encode to be completed without raising any sanitizer flags.
TEST_P(VideoTrackRecorderTestParam, EncodeFrameWithPaddedCodedSize) {
  InitializeRecorder(testing::get<0>(GetParam()));

  const gfx::Size& frame_size = testing::get<1>(GetParam());
  const size_t kCodedSizePadding = 16;
  const TestFrameType test_frame_type = testing::get<3>(GetParam());
  scoped_refptr<media::VideoFrame> video_frame =
      CreateFrameForTest(test_frame_type, frame_size,
                         /*encode_alpha_channel=*/false, kCodedSizePadding);

  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .Times(1)
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  Encode(video_frame, base::TimeTicks::Now());
  run_loop.Run();

  Mock::VerifyAndClearExpectations(this);
}

TEST_P(VideoTrackRecorderTestParam, EncodeFrameRGB) {
  InitializeRecorder(testing::get<0>(GetParam()));

  const gfx::Size& frame_size = testing::get<1>(GetParam());

  // TODO(crbug/1177593): Refactor test harness to use a cleaner parameter
  // space.
  // Let kI420 indicate owned memory, and kNv12GpuMemoryBuffer to indicate GMB
  // storage. Don't test for kNv12Software.
  const TestFrameType test_frame_type = testing::get<3>(GetParam());
  if (test_frame_type == TestFrameType::kNv12Software) {
    return;
  }

  const bool encode_alpha_channel = testing::get<2>(GetParam());
  media::VideoPixelFormat pixel_format = encode_alpha_channel
                                             ? media::PIXEL_FORMAT_ARGB
                                             : media::PIXEL_FORMAT_XRGB;
  scoped_refptr<media::VideoFrame> video_frame =
      test_frame_type == TestFrameType::kI420
          ? media::VideoFrame::CreateZeroInitializedFrame(
                pixel_format, frame_size, gfx::Rect(frame_size), frame_size,
                base::TimeDelta())
          : blink::CreateTestFrame(frame_size, gfx::Rect(frame_size),
                                   frame_size,
                                   media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER,
                                   pixel_format, base::TimeDelta());

  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .Times(1)
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  Encode(video_frame, base::TimeTicks::Now());
  run_loop.Run();

  Mock::VerifyAndClearExpectations(this);
}

TEST_P(VideoTrackRecorderTestParam, EncoderHonorsKeyFrameRequests) {
  InitializeRecorder(testing::get<0>(GetParam()));
  InSequence s;
  auto frame = media::VideoFrame::CreateBlackFrame(kTrackRecorderTestSize[0]);

  base::RunLoop run_loop1;
  EXPECT_CALL(*mock_callback_interface_, OnEncodedVideo)
      .WillOnce(RunClosure(run_loop1.QuitClosure()));
  Encode(frame, base::TimeTicks::Now());
  run_loop1.Run();

  // Request the next frame to be a key frame, and the following frame a delta
  // frame.
  video_track_recorder_->ForceKeyFrameForNextFrameForTesting();
  base::RunLoop run_loop2;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _))
      .WillOnce(RunClosure(run_loop2.QuitClosure()));
  Encode(frame, base::TimeTicks::Now());
  Encode(frame, base::TimeTicks::Now());
  run_loop2.Run();

  Mock::VerifyAndClearExpectations(this);
}

TEST_P(VideoTrackRecorderTestParam,
       NoSubsequenceKeyFramesWithDefaultKeyFrameConfig) {
  InitializeRecorder(testing::get<0>(GetParam()));

  auto origin = base::TimeTicks::Now();
  InSequence s;
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _))
      .Times(8);
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _))
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  auto frame = media::VideoFrame::CreateBlackFrame(kTrackRecorderTestSize[0]);
  for (int i = 0; i != 10; ++i) {
    Encode(frame, origin + i * base::Minutes(1));
  }
  run_loop.Run();
}

TEST_P(VideoTrackRecorderTestParam, KeyFramesGeneratedWithIntervalCount) {
  // Configure 3 delta frames for every key frame.
  InitializeRecorder(testing::get<0>(GetParam()), /*keyframe_config=*/
```