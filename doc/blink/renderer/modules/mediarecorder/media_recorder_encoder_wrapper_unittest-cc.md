Response:
Let's break down the thought process to analyze the given C++ unittest file for `MediaRecorderEncoderWrapper`.

1. **Understand the Core Purpose:** The file name `media_recorder_encoder_wrapper_unittest.cc` immediately tells us it's testing a class named `MediaRecorderEncoderWrapper`. The "encoder" part suggests it deals with encoding video data. The "wrapper" part hints that it might be wrapping another encoding component.

2. **Examine the Includes:** The `#include` directives provide crucial context:
    * `"third_party/blink/renderer/modules/mediarecorder/media_recorder_encoder_wrapper.h"`:  Confirms the class being tested.
    * `<memory>`: Indicates use of smart pointers (likely `std::unique_ptr`).
    * `"base/containers/heap_array.h"`:  Suggests handling of dynamically allocated byte arrays, likely for encoded data.
    * `"base/memory/raw_ptr.h"`:  Indicates the use of raw pointers, probably for non-owning references.
    * `"media/base/mock_filters.h"`:  Strongly suggests the use of mocking for testing dependencies (like video encoders).
    * `"media/base/video_frame.h"`:  Indicates dealing with raw video frames.
    * `"media/video/gpu_video_accelerator_factories.h"`:  Points to potential interaction with hardware video acceleration (though it's `nullptr` in the tests, meaning it's likely a dependency that *could* be used).
    * `"testing/gtest/include/gtest/gtest.h"`: Confirms this is a Google Test based unit test.
    * `"third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"`:  Indicates interaction with Blink's task scheduler, suggesting asynchronous operations.
    * `"third_party/blink/renderer/platform/testing/task_environment.h"`:  Provides a test environment for asynchronous tasks.

3. **Analyze the Test Structure:**
    * **Namespaces:** `blink` and an anonymous namespace are used for organization.
    * **Constants:** `kDefaultBitrate`, `k720p`, `k360p`, `kChunkSize` define test parameters.
    * **Helper Functions/Matchers:** `DefaultEncoderOutput`, `MatchEncoderOptions`, `MatchEncodeOption`, `MatchDataSizeAndIsKeyFrame`, `MatchVideoParams`, `MatchErrorCode` are custom matchers using Google Mock. These are essential for verifying the correct arguments are passed to mocked objects.
    * **MockVideoEncoderWrapper:** This class *wraps* `media::MockVideoEncoder` and prevents the `std::unique_ptr` in `MediaRecorderEncoderWrapper` from deleting the mock. This is a common pattern in testing to control the lifecycle of mocks.
    * **MediaRecorderEncoderWrapperTest Class:** This is the main test fixture.
        * **Type Parameterization:** `::testing::TestWithParam<media::VideoCodecProfile>` indicates the tests are run for different video codecs.
        * **Member Variables:** `profile_`, `codec_`, `output_cb`, `mock_encoder_`, `mock_metrics_provider_`, `encoder_wrapper_`. These hold test configuration and the object under test.
        * **Mock Methods:** `CreateEncoder`, `OnError`, `MockVideoEncoderWrapperDtor`, `OnEncodedVideo`. These allow the test to observe side effects and interactions.
        * **Helper Methods:** `CreateMockVideoEncoder`, `CreateEncoderWrapper`, `EncodeFrame`, `SetupSuccessful720pEncoderInitialization`. These simplify test setup and interaction with the class under test.

4. **Examine Individual Tests (Examples):** Look at the names and contents of some key tests:
    * `InitializesAndEncodesOneFrame`: Checks basic initialization and encoding of a single frame.
    * `InitializesWithScreenCastAndEncodesOneFrame`: Tests the behavior when the encoder is configured for screen content. Notice the different `ContentHint`.
    * `EncodesTwoFramesWithoutRecreatingEncoder`: Verifies that the encoder is reused for subsequent frames if the resolution doesn't change.
    * `RecreatesEncoderOnNewResolution`:  Tests the logic for creating a new encoder when the input video resolution changes. This is important for adaptability.
    * `HandlesInitializeFailure`, `HandlesEncodeFailure`, `HandlesFlushFailure`: Check error handling paths.
    * Tests involving alpha frames (`InitializesAndEncodesOneAlphaFrame`, `InitializesAndEncodesOneOpaqueFrameAndOneAlphaFrame`): Specifically test support for video with alpha channels (transparency).

5. **Identify Key Functionality based on Tests:** By analyzing the tests, we can deduce the core functionality being tested:
    * Initialization of the video encoder with correct parameters (bitrate, resolution, content hint).
    * Encoding of video frames.
    * Handling of key frames.
    * Re-creation of the encoder on resolution changes.
    * Handling of encoder errors (initialization, encoding, flushing).
    * Support for screen content encoding.
    * Support for video with alpha channels.
    * Interaction with a metrics provider.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `MediaRecorder` API in JavaScript uses this underlying encoder. JavaScript code using `MediaRecorder` to record video would indirectly trigger this C++ code. For example, calling `recorder.start()` and then providing video data to the recorder.
    * **HTML:** The `<video>` element is used to display recorded video. The encoded data produced by this C++ code would eventually be used by a video decoder to render frames in the `<video>` element.
    * **CSS:** CSS can style the `<video>` element, but it doesn't directly interact with the video encoding process itself.

7. **Logical Reasoning (Hypothetical Input/Output):** Consider a simple test like `InitializesAndEncodesOneFrame`:
    * **Input:** A `media::VideoFrame` of size 1280x720, a capture timestamp.
    * **Expected Output:** A call to the `OnEncodedVideo` callback with:
        * `media::Muxer::VideoParameters` indicating 1280x720 and the correct codec.
        * A `media::DecoderBuffer` containing encoded data of size `kChunkSize` (1234 bytes) and marked as a keyframe.
        * The original capture timestamp.

8. **Common User/Programming Errors:**
    * **Incorrect `mimeType` in JavaScript:** If the `mimeType` passed to `MediaRecorder` doesn't match the supported codecs, the encoder might fail to initialize.
    * **Providing frames in the wrong format:**  The encoder expects a specific pixel format. Providing frames in an unsupported format could lead to encoding errors.
    * **Not handling `dataavailable` events correctly:** In JavaScript, the `dataavailable` event provides the encoded data. If not handled, the recorded data will be lost.
    * **Forgetting to stop the recorder:**  Failing to call `recorder.stop()` will prevent the final encoded data from being processed.

9. **Debugging Steps (How to Reach This Code):**
    * A user starts recording video using a web application that utilizes the `MediaRecorder` API.
    * The browser's JavaScript engine executes the `MediaRecorder` code.
    * When video frames are available (e.g., from a webcam or screen capture), the JavaScript `MediaRecorder` implementation calls into the Blink rendering engine.
    * The `MediaRecorderEncoderWrapper` class (the code in this file) is instantiated to handle the video encoding.
    * The `EncodeFrame` method of `MediaRecorderEncoderWrapper` is called for each video frame.
    * If there are issues (e.g., encoder crashes, incorrect configuration), a developer might:
        * Set breakpoints in the `MediaRecorderEncoderWrapper::EncodeFrame` method or its initialization logic.
        * Examine the arguments passed to the mock encoder using Google Mock matchers in the unit tests.
        * Look at the browser's console for error messages related to `MediaRecorder`.
        * Consult Chromium's logging mechanisms to trace the execution flow.

By following these steps, we can comprehensively analyze the C++ unittest file and understand its purpose, relationship to web technologies, and its role in the broader video recording process within the Chromium browser.
这个文件 `media_recorder_encoder_wrapper_unittest.cc` 是 Chromium Blink 引擎中 `MediaRecorderEncoderWrapper` 类的单元测试。它的主要功能是验证 `MediaRecorderEncoderWrapper` 类的各种行为和功能是否符合预期。

以下是该文件功能的详细列表和相关说明：

**1. 单元测试核心功能:**

* **测试视频编码器的封装:**  `MediaRecorderEncoderWrapper` 的主要职责是作为一个中间层，封装底层的视频编码器 (例如，硬件或软件编码器)。这个单元测试验证了 `MediaRecorderEncoderWrapper` 正确地管理和使用这些底层的编码器。
* **测试编码流程:** 测试了视频帧如何传递给 `MediaRecorderEncoderWrapper`，以及它如何将这些帧传递给底层的视频编码器进行编码。
* **测试编码参数的传递:**  验证了 `MediaRecorderEncoderWrapper` 是否将正确的编码参数（例如，比特率、帧大小、内容提示等）传递给底层的视频编码器。
* **测试编码结果的处理:**  验证了 `MediaRecorderEncoderWrapper` 是否正确地接收来自底层编码器的编码后的数据，并将其传递给上层模块 (通过 `OnEncodedVideo` 回调)。
* **测试错误处理:** 验证了当底层视频编码器发生错误时，`MediaRecorderEncoderWrapper` 是否能够正确地捕获并处理这些错误 (通过 `OnError` 回调)。
* **测试动态分辨率切换:** 验证了当输入的视频帧分辨率发生变化时，`MediaRecorderEncoderWrapper` 是否能够正确地重新创建和初始化底层的视频编码器。
* **测试屏幕内容编码:** 验证了 `MediaRecorderEncoderWrapper` 对于屏幕内容 (screencast) 的特殊处理，例如设置不同的内容提示。
* **测试带 Alpha 通道的视频编码:** 验证了 `MediaRecorderEncoderWrapper` 对带有透明度 (alpha channel) 的视频帧的编码支持。
* **使用 Mock 对象进行隔离测试:**  使用了 Google Mock 框架来模拟底层的视频编码器 (`MockVideoEncoder`) 和指标提供器 (`MockVideoEncoderMetricsProvider`)，以便在隔离的环境中测试 `MediaRecorderEncoderWrapper` 的逻辑，避免外部依赖的影响。

**2. 与 JavaScript, HTML, CSS 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript, HTML, 或 CSS 代码，但它所测试的 `MediaRecorderEncoderWrapper` 类是 Web API `MediaRecorder` 的底层实现的一部分。

* **JavaScript:**
    * **举例说明:**  当 JavaScript 代码使用 `MediaRecorder` API 录制视频时，例如：
      ```javascript
      navigator.mediaDevices.getUserMedia({ video: true })
        .then(stream => {
          const recorder = new MediaRecorder(stream, { mimeType: 'video/webm; codecs=vp9' });
          recorder.ondataavailable = event => {
            // 处理编码后的数据
          };
          recorder.start();
          // ... 停止录制
          recorder.stop();
        });
      ```
    *  在这个过程中，`MediaRecorder` 对象会调用 Blink 引擎中相应的 C++ 代码，其中就包括 `MediaRecorderEncoderWrapper`。`MediaRecorderEncoderWrapper` 会接收来自媒体流的视频帧，并将它们编码成指定格式 (例如，VP9)。
* **HTML:**
    * **举例说明:**  编码后的视频数据最终可以通过 `<video>` 元素在 HTML 页面上播放：
      ```html
      <video controls src="blob:http://example.com/encoded-video"></video>
      ```
    *  `MediaRecorderEncoderWrapper` 的工作是生成可以被浏览器解码并在 `<video>` 元素中显示的视频流。
* **CSS:**
    * CSS 主要负责样式和布局。它与 `MediaRecorderEncoderWrapper` 的直接功能没有关系。但是，CSS 可以用来控制 `<video>` 元素的呈现方式。

**3. 逻辑推理 (假设输入与输出):**

假设我们运行 `InitializesAndEncodesOneFrame` 测试，并且一切顺利：

* **假设输入:**
    * `CreateEncoderWrapper(false)` 被调用，创建一个非屏幕内容编码的 `MediaRecorderEncoderWrapper` 实例。
    * 一个尺寸为 1280x720 的黑色视频帧 (`media::VideoFrame::CreateBlackFrame(k720p)`) 被传递给 `EncodeFrame` 方法，同时传递一个捕获时间戳。
* **预期输出:**
    *  首先，`CreateEncoder` 模拟方法会被调用，表明底层编码器正在被创建。
    *  `mock_metrics_provider_->MockInitialize` 会被调用，记录编码器初始化信息。
    *  `mock_encoder_->Initialize` 会被调用，并且参数匹配 `MatchEncoderOptions`，验证了编码器使用正确的配置初始化（比特率、分辨率、内容提示）。
    *  `mock_encoder_->Encode` 会被调用，表明视频帧被传递给模拟的编码器。
    *  `mock_metrics_provider_->MockIncrementEncodedFrameCount` 会被调用，记录编码帧的数量。
    *  `OnEncodedVideo` 模拟方法会被调用，并且参数匹配 `MatchVideoParams` 和 `MatchDataSizeAndIsKeyFrame`，验证了编码后的数据被正确地传回上层，数据大小为 `kChunkSize` (1234 字节)，并且是一个关键帧。

**4. 用户或编程常见的使用错误:**

* **JavaScript 端 `mimeType` 不匹配:**
    * **错误:** 用户在 JavaScript 中使用 `MediaRecorder` 时，指定的 `mimeType` 中的编解码器与浏览器或操作系统不支持的编码器不匹配。
    * **如何到达这里:**  当 `MediaRecorder` 尝试初始化底层的视频编码器时，`MediaRecorderEncoderWrapper` 会根据 `mimeType` 选择合适的编码器。如果找不到或初始化失败，`OnError` 回调会被触发。测试用例 `HandlesInitializeFailure` 就模拟了这种情况。
* **提供错误格式的视频帧:**
    * **错误:**  传递给 `MediaRecorder` 的视频流中的帧格式与编码器期望的格式不一致（例如，颜色空间、分辨率）。
    * **如何到达这里:**  `MediaRecorderEncoderWrapper` 接收到帧后，会将其传递给底层的编码器。如果编码器无法处理该格式，可能会返回错误，导致 `OnError` 回调。虽然这个单元测试主要关注 `MediaRecorderEncoderWrapper` 的逻辑，而不是对不同帧格式的处理，但如果底层的 mock 编码器被配置为对特定格式失败，相关的错误处理路径会被测试到。
* **资源泄漏或未正确释放:**
    * **错误:**  在某些情况下，如果 `MediaRecorder` 的生命周期管理不当，可能会导致底层编码器资源未被正确释放。
    * **如何到达这里:**  虽然这个单元测试主要测试编码过程，但 `MockVideoEncoderWrapperDtor` 的调用可以验证当 `MediaRecorderEncoderWrapper` 对象被销毁时，底层的模拟编码器也被销毁，这有助于发现潜在的资源管理问题。

**5. 用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户打开一个网页，该网页使用了 `MediaRecorder` API 来录制视频或屏幕。**
2. **网页 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` (对于摄像头) 或 `navigator.mediaDevices.getDisplayMedia()` (对于屏幕录制) 获取媒体流。**
3. **JavaScript 代码创建一个 `MediaRecorder` 对象，并将媒体流传递给它，同时指定 `mimeType`。**
4. **JavaScript 代码调用 `recorder.start()` 开始录制。**
5. **浏览器接收到来自摄像头或屏幕的视频帧。**
6. **Blink 渲染引擎中的媒体框架接收到这些视频帧。**
7. **与 `MediaRecorder` 对象关联的 C++ 代码被调用，其中包括 `MediaRecorderEncoderWrapper` 的实例。**
8. **对于每个接收到的视频帧，`MediaRecorderEncoderWrapper::EncodeFrame()` 方法被调用。**
9. **`EncodeFrame()` 方法会进行以下操作:**
    * 检查是否需要创建或重新创建底层的视频编码器。
    * 将视频帧和编码参数传递给底层的视频编码器（通过 mock 对象在单元测试中模拟）。
    * 接收来自编码器的编码后的数据。
    * 调用 `OnEncodedVideo` 回调将编码后的数据传递给上层模块。
10. **如果底层编码器发生错误，`OnError` 回调会被调用。**
11. **当 JavaScript 代码调用 `recorder.stop()` 时，`MediaRecorderEncoderWrapper` 会执行清理操作，例如刷新编码器。**

**作为调试线索:** 如果在录制过程中出现问题（例如，录制失败、视频格式错误），开发者可能会：

* **在 JavaScript 代码中设置断点，检查 `MediaRecorder` 的状态和事件。**
* **查看浏览器的控制台，查找与 `MediaRecorder` 相关的错误消息。**
* **如果怀疑是编码器的问题，开发者可能会需要深入到 Blink 引擎的 C++ 代码中进行调试，这时 `media_recorder_encoder_wrapper_unittest.cc` 中的测试用例可以作为理解 `MediaRecorderEncoderWrapper` 工作原理和验证其正确性的参考。**
* **使用 Chromium 的调试工具和日志记录功能来跟踪视频帧的编码流程，查看 `MediaRecorderEncoderWrapper` 的输入和输出，以及底层编码器的行为。**

总而言之，`media_recorder_encoder_wrapper_unittest.cc` 是一个至关重要的测试文件，用于确保 `MediaRecorderEncoderWrapper` 类的正确性和稳定性，这直接影响到 Web API `MediaRecorder` 的功能和用户体验。

Prompt: 
```
这是目录为blink/renderer/modules/mediarecorder/media_recorder_encoder_wrapper_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediarecorder/media_recorder_encoder_wrapper.h"

#include <memory>

#include "base/containers/heap_array.h"
#include "base/memory/raw_ptr.h"
#include "media/base/mock_filters.h"
#include "media/base/video_frame.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::WithArg;
using ::testing::WithArgs;

namespace blink {
namespace {
constexpr uint32_t kDefaultBitrate = 1280 * 720;
constexpr gfx::Size k720p{1280, 720};
constexpr gfx::Size k360p{640, 360};
constexpr size_t kChunkSize = 1234;
media::VideoEncoderOutput DefaultEncoderOutput() {
  media::VideoEncoderOutput output;
  output.data = base::HeapArray<uint8_t>::Uninit(kChunkSize);
  output.key_frame = true;
  return output;
}

MATCHER_P3(MatchEncoderOptions,
           bitrate,
           frame_size,
           content_hint,
           "encoder option matcher") {
  return arg.bitrate.has_value() &&
         arg.bitrate->mode() == media::Bitrate::Mode::kVariable &&
         arg.bitrate->target_bps() == base::checked_cast<uint32_t>(bitrate) &&
         *arg.content_hint == content_hint && arg.frame_size == frame_size;
}

MATCHER_P(MatchEncodeOption, key_frame, "encode option matcher") {
  return arg.key_frame == key_frame && !arg.quantizer.has_value();
}

MATCHER_P2(MatchDataSizeAndIsKeyFrame,
           data_size,
           is_key_frame,
           "encode data size and key frame matcher") {
  return arg->size() == static_cast<size_t>(data_size) &&
         arg->is_key_frame() == is_key_frame;
}

MATCHER_P2(MatchVideoParams,
           visible_rect_size,
           video_codec,
           "video_params matcher") {
  return arg.visible_rect_size == visible_rect_size && arg.codec == video_codec;
}

MATCHER_P(MatchErrorCode, code, "error code matcher") {
  return arg.code() == code;
}
}  // namespace
// Wraps MockVideoEncoder to not delete the pointer of MockVideoEncoder by
// the std::unique_ptr.
class MockVideoEncoderWrapper : public media::VideoEncoder {
 public:
  explicit MockVideoEncoderWrapper(media::MockVideoEncoder* const mock_encoder,
                                   base::OnceClosure dtor_cb)
      : mock_encoder_(mock_encoder), dtor_cb_(std::move(dtor_cb)) {
    CHECK(mock_encoder_);
  }

  ~MockVideoEncoderWrapper() override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    std::move(dtor_cb_).Run();
  }
  void Initialize(media::VideoCodecProfile profile,
                  const Options& options,
                  EncoderInfoCB info_cb,
                  OutputCB output_cb,
                  EncoderStatusCB done_cb) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    return mock_encoder_->Initialize(profile, options, info_cb, output_cb,
                                     std::move(done_cb));
  }
  void Encode(scoped_refptr<media::VideoFrame> frame,
              const EncodeOptions& options,
              EncoderStatusCB done_cb) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    return mock_encoder_->Encode(std::move(frame), options, std::move(done_cb));
  }
  void ChangeOptions(const Options& options,
                     OutputCB output_cb,
                     EncoderStatusCB done_cb) override {
    NOTREACHED();
  }
  void Flush(EncoderStatusCB done_cb) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    return mock_encoder_->Flush(std::move(done_cb));
  }

 private:
  const raw_ptr<media::MockVideoEncoder> mock_encoder_;
  base::OnceClosure dtor_cb_;

  SEQUENCE_CHECKER(sequence_checker_);
};

class MediaRecorderEncoderWrapperTest
    : public ::testing::TestWithParam<media::VideoCodecProfile> {
 public:
  MediaRecorderEncoderWrapperTest()
      : profile_(GetParam()),
        codec_(media::VideoCodecProfileToVideoCodec(profile_)) {}

  ~MediaRecorderEncoderWrapperTest() override {
    EXPECT_CALL(mock_encoder_, Dtor);
  }

 protected:
  MOCK_METHOD(void, CreateEncoder, (), ());
  MOCK_METHOD(void, OnError, (), ());
  MOCK_METHOD(void, MockVideoEncoderWrapperDtor, (), ());

  std::unique_ptr<media::VideoEncoder> CreateMockVideoEncoder(
      media::GpuVideoAcceleratorFactories* /*gpu_factories*/) {
    CreateEncoder();
    return std::make_unique<MockVideoEncoderWrapper>(
        &mock_encoder_,
        base::BindOnce(
            &MediaRecorderEncoderWrapperTest::MockVideoEncoderWrapperDtor,
            base::Unretained(this)));
  }

  void CreateEncoderWrapper(bool is_screencast) {
    encoder_wrapper_ = std::make_unique<MediaRecorderEncoderWrapper>(
        scheduler::GetSingleThreadTaskRunnerForTesting(), profile_,
        kDefaultBitrate, is_screencast,
        /*gpu_factories=*/nullptr,
        WTF::BindRepeating(
            &MediaRecorderEncoderWrapperTest::CreateMockVideoEncoder,
            base::Unretained(this)),
        WTF::BindRepeating(&MediaRecorderEncoderWrapperTest::OnEncodedVideo,
                           base::Unretained(this)),
        WTF::BindRepeating(&MediaRecorderEncoderWrapperTest::OnError,
                           base::Unretained(this)));
    EXPECT_EQ(is_screencast,
              encoder_wrapper_->IsScreenContentEncodingForTesting());
    auto metrics_provider =
        std::make_unique<media::MockVideoEncoderMetricsProvider>();
    mock_metrics_provider_ = metrics_provider.get();
    encoder_wrapper_->metrics_provider_ = std::move(metrics_provider);

    SetupSuccessful720pEncoderInitialization();
  }

  // EncodeFrame is a private function of MediaRecorderEncoderWrapper.
  // It can be called only in MediaRecorderEncoderWrapperTest.
  void EncodeFrame(scoped_refptr<media::VideoFrame> frame,
                   base::TimeTicks capture_timestamp) {
    encoder_wrapper_->EncodeFrame(std::move(frame), capture_timestamp, false);
  }

  MOCK_METHOD(
      void,
      OnEncodedVideo,
      (const media::Muxer::VideoParameters& params,
       scoped_refptr<media::DecoderBuffer> encoded_data,
       std::optional<media::VideoEncoder::CodecDescription> codec_description,
       base::TimeTicks capture_timestamp),
      ());

  void SetupSuccessful720pEncoderInitialization() {
    ON_CALL(mock_encoder_,
            Initialize(
                profile_,
                MatchEncoderOptions(kDefaultBitrate, k720p,
                                    media::VideoEncoder::ContentHint::Camera),
                _, _, _))
        .WillByDefault(WithArgs<3, 4>(
            [this](media::VideoEncoder::OutputCB output_callback,
                   media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
              this->output_cb = output_callback;
              std::move(initialize_done_cb)
                  .Run(media::EncoderStatus::Codes::kOk);
            }));
    ON_CALL(mock_encoder_, Encode)
        .WillByDefault(WithArgs<2>(
            [this](media::VideoEncoder::EncoderStatusCB encode_done_cb) {
              std::move(encode_done_cb).Run(media::EncoderStatus::Codes::kOk);
              media::VideoEncoderOutput output = DefaultEncoderOutput();
              this->output_cb.Run(std::move(output), std::nullopt);
            }));
    ON_CALL(*mock_metrics_provider_,
            MockInitialize(profile_, k720p, false,
                           media::SVCScalabilityMode::kL1T1))
        .WillByDefault(Return());
  }

  test::TaskEnvironment task_environment_;

  const media::VideoCodecProfile profile_;
  const media::VideoCodec codec_;

  media::VideoEncoder::OutputCB output_cb;

  media::MockVideoEncoder mock_encoder_;
  raw_ptr<media::MockVideoEncoderMetricsProvider, DanglingUntriaged>
      mock_metrics_provider_;
  std::unique_ptr<MediaRecorderEncoderWrapper> encoder_wrapper_;
};

TEST_P(MediaRecorderEncoderWrapperTest, InitializesAndEncodesOneFrame) {
  CreateEncoderWrapper(false);
  InSequence s;
  EXPECT_CALL(*this, CreateEncoder);
  EXPECT_CALL(*mock_metrics_provider_, MockInitialize);
  EXPECT_CALL(mock_encoder_, Initialize);
  EXPECT_CALL(mock_encoder_, Encode);

  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this, OnEncodedVideo(
                         MatchVideoParams(k720p, codec_),
                         MatchDataSizeAndIsKeyFrame(kChunkSize, true), _, _));
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest,
       InitializesWithScreenCastAndEncodesOneFrame) {
  CreateEncoderWrapper(true);
  InSequence s;
  EXPECT_CALL(*this, CreateEncoder);
  EXPECT_CALL(*mock_metrics_provider_, MockInitialize);
  ON_CALL(
      mock_encoder_,
      Initialize(profile_,
                 MatchEncoderOptions(kDefaultBitrate, k720p,
                                     media::VideoEncoder::ContentHint::Screen),
                 _, _, _))
      .WillByDefault(WithArgs<3, 4>(
          [this](media::VideoEncoder::OutputCB output_callback,
                 media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            this->output_cb = output_callback;
            std::move(initialize_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));
  EXPECT_CALL(mock_encoder_, Encode);

  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this, OnEncodedVideo(
                         MatchVideoParams(k720p, codec_),
                         MatchDataSizeAndIsKeyFrame(kChunkSize, true), _, _));
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest,
       EncodesTwoFramesWithoutRecreatingEncoder) {
  CreateEncoderWrapper(false);
  InSequence s;
  const auto capture_timestamp1 = base::TimeTicks::Now();
  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  // OnEncodedVideo to check capture_timestamp1.
  EXPECT_CALL(*this,
              OnEncodedVideo(MatchVideoParams(k720p, codec_),
                             MatchDataSizeAndIsKeyFrame(kChunkSize, true), _,
                             capture_timestamp1));
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p), capture_timestamp1);

  const base::TimeTicks capture_timestamp2 =
      capture_timestamp1 + base::Microseconds(1);
  // Encode to check key_frame=false, and OnEncodedVideo to check
  // key_frame=false and capture_timestamp2.
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(WithArgs<2>(
          [this](media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb).Run(media::EncoderStatus::Codes::kOk);
            media::VideoEncoderOutput output = DefaultEncoderOutput();
            output.key_frame = false;
            this->output_cb.Run(std::move(output), std::nullopt);
          }));
  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this,
              OnEncodedVideo(MatchVideoParams(k720p, codec_),
                             MatchDataSizeAndIsKeyFrame(kChunkSize, false), _,
                             capture_timestamp2));
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p), capture_timestamp2);
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest,
       EncodeTwoFramesAndDelayEncodeDoneAndOutputCB) {
  CreateEncoderWrapper(false);
  InSequence s;
  media::VideoEncoder::EncoderStatusCB encode_done_cb1;
  const auto capture_timestamp1 = base::TimeTicks::Now();
  const base::TimeTicks capture_timestamp2 =
      capture_timestamp1 + base::Microseconds(1);
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(
          WithArgs<2>([&encode_done_cb1](
                          media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            encode_done_cb1 = std::move(encode_done_cb);
          }));
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(WithArgs<2>(
          [this, encode_done_cb1_ptr = &encode_done_cb1](
              media::VideoEncoder::EncoderStatusCB encode_done_cb2) {
            std::move(*encode_done_cb1_ptr)
                .Run(media::EncoderStatus::Codes::kOk);
            std::move(encode_done_cb2).Run(media::EncoderStatus::Codes::kOk);
            media::VideoEncoderOutput output1 = DefaultEncoderOutput();
            media::VideoEncoderOutput output2 = DefaultEncoderOutput();
            output2.key_frame = false;
            this->output_cb.Run(std::move(output1), std::nullopt);
            this->output_cb.Run(std::move(output2), std::nullopt);
          }));
  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this,
              OnEncodedVideo(MatchVideoParams(k720p, codec_),
                             MatchDataSizeAndIsKeyFrame(kChunkSize, true), _,
                             capture_timestamp1));
  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this,
              OnEncodedVideo(MatchVideoParams(k720p, codec_),
                             MatchDataSizeAndIsKeyFrame(kChunkSize, false), _,
                             capture_timestamp2));
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p), capture_timestamp1);
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p), capture_timestamp2);
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest, RecreatesEncoderOnNewResolution) {
  CreateEncoderWrapper(false);
  InSequence s;
  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());

  EXPECT_CALL(mock_encoder_, Flush)
      .WillOnce(
          WithArgs<0>([](media::VideoEncoder::EncoderStatusCB flush_done_cb) {
            std::move(flush_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));
  EXPECT_CALL(*this, CreateEncoder);
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
  EXPECT_CALL(
      *mock_metrics_provider_,
      MockInitialize(profile_, k360p, false, media::SVCScalabilityMode::kL1T1));
  EXPECT_CALL(
      mock_encoder_,
      Initialize(profile_,
                 MatchEncoderOptions(kDefaultBitrate, k360p,
                                     media::VideoEncoder::ContentHint::Camera),
                 _, _, _))
      .WillOnce(WithArgs<3, 4>(
          [this](media::VideoEncoder::OutputCB output_cb,
                 media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            this->output_cb = output_cb;
            std::move(initialize_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(WithArgs<2>(
          [this](media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb).Run(media::EncoderStatus::Codes::kOk);
            media::VideoEncoderOutput output = DefaultEncoderOutput();
            this->output_cb.Run(std::move(output), std::nullopt);
          }));
  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this, OnEncodedVideo(
                         MatchVideoParams(k360p, codec_),
                         MatchDataSizeAndIsKeyFrame(kChunkSize, true), _, _));
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k360p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest, HandlesInitializeFailure) {
  CreateEncoderWrapper(false);
  InSequence s;
  EXPECT_CALL(
      mock_encoder_,
      Initialize(profile_,
                 MatchEncoderOptions(kDefaultBitrate, k720p,
                                     media::VideoEncoder::ContentHint::Camera),
                 _, _, _))
      .WillOnce(WithArgs<4>(
          [](media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            std::move(initialize_done_cb)
                .Run(media::EncoderStatus::Codes::kEncoderInitializationError);
          }));
  EXPECT_CALL(*mock_metrics_provider_,
              MockSetError(MatchErrorCode(
                  media::EncoderStatus::Codes::kEncoderInitializationError)));
  EXPECT_CALL(*this, OnError);
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest, HandlesEncodeFailure) {
  CreateEncoderWrapper(false);
  InSequence s;
  EXPECT_CALL(mock_encoder_, Encode(_, MatchEncodeOption(false), _))
      .WillOnce(
          WithArgs<2>([](media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb)
                .Run(media::EncoderStatus::Codes::kEncoderFailedEncode);
          }));
  EXPECT_CALL(*mock_metrics_provider_,
              MockSetError(MatchErrorCode(
                  media::EncoderStatus::Codes::kEncoderFailedEncode)));
  EXPECT_CALL(*this, OnError);
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest, HandlesFlushFailure) {
  CreateEncoderWrapper(false);
  InSequence s;
  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(mock_encoder_, Flush)
      .WillOnce(
          WithArgs<0>([](media::VideoEncoder::EncoderStatusCB flush_done_cb) {
            std::move(flush_done_cb)
                .Run(media::EncoderStatus::Codes::kEncoderFailedFlush);
          }));
  EXPECT_CALL(*mock_metrics_provider_,
              MockSetError(MatchErrorCode(
                  media::EncoderStatus::Codes::kEncoderFailedFlush)));
  EXPECT_CALL(*this, OnError);
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k360p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest, NotCallOnEncodedVideoCBIfEncodeFail) {
  CreateEncoderWrapper(false);
  InSequence s;
  EXPECT_CALL(mock_encoder_, Encode(_, MatchEncodeOption(false), _))
      .WillOnce(WithArgs<2>(
          [this](media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb)
                .Run(media::EncoderStatus::Codes::kEncoderFailedEncode);
            media::VideoEncoderOutput output = DefaultEncoderOutput();
            this->output_cb.Run(std::move(output), std::nullopt);
          }));
  EXPECT_CALL(*mock_metrics_provider_,
              MockSetError(MatchErrorCode(
                  media::EncoderStatus::Codes::kEncoderFailedEncode)));
  EXPECT_CALL(*this, OnError);
  EXPECT_CALL(*this, OnEncodedVideo).Times(0);
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest,
       NotErrorCallbackTwiceByTwiceEncodeDoneFailure) {
  CreateEncoderWrapper(false);
  InSequence s;
  media::VideoEncoder::EncoderStatusCB encode_done_cb1;
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(
          WithArgs<2>([&encode_done_cb1](
                          media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            encode_done_cb1 = std::move(encode_done_cb);
          }));
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(WithArgs<2>(
          [encode_done_cb1_ptr = &encode_done_cb1](
              media::VideoEncoder::EncoderStatusCB encode_done_cb2) {
            std::move(*encode_done_cb1_ptr)
                .Run(media::EncoderStatus::Codes::kEncoderFailedEncode);
            std::move(encode_done_cb2)
                .Run(media::EncoderStatus::Codes::kEncoderFailedEncode);
          }));
  EXPECT_CALL(*mock_metrics_provider_,
              MockSetError(MatchErrorCode(
                  media::EncoderStatus::Codes::kEncoderFailedEncode)));
  EXPECT_CALL(*this, OnError);
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest, IgnoresEncodeAfterFailure) {
  CreateEncoderWrapper(false);
  InSequence s;
  EXPECT_CALL(
      mock_encoder_,
      Initialize(profile_,
                 MatchEncoderOptions(kDefaultBitrate, k720p,
                                     media::VideoEncoder::ContentHint::Camera),
                 _, _, _))
      .WillOnce(WithArgs<4>(
          [](media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            std::move(initialize_done_cb)
                .Run(media::EncoderStatus::Codes::kEncoderInitializationError);
          }));
  EXPECT_CALL(*mock_metrics_provider_,
              MockSetError(MatchErrorCode(
                  media::EncoderStatus::Codes::kEncoderInitializationError)));
  EXPECT_CALL(*this, OnError);
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k360p),
              base::TimeTicks::Now());
  EncodeFrame(media::VideoFrame::CreateBlackFrame(k720p),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor);
}

TEST_P(MediaRecorderEncoderWrapperTest, InitializesAndEncodesOneAlphaFrame) {
  InSequence s;
  if (codec_ != media::VideoCodec::kVP8 && codec_ != media::VideoCodec::kVP9) {
    GTEST_SKIP() << "no alpha encoding is supported in"
                 << media::GetCodecName(codec_);
  }
  CreateEncoderWrapper(false);
  constexpr size_t kAlphaChunkSize = 2345;
  EXPECT_CALL(*this, CreateEncoder).Times(2);
  EXPECT_CALL(*mock_metrics_provider_, MockInitialize);
  media::VideoEncoder::OutputCB yuv_output_cb;
  media::VideoEncoder::OutputCB alpha_output_cb;
  EXPECT_CALL(mock_encoder_, Initialize(profile_, _, _, _, _))
      .WillOnce(WithArgs<3, 4>(
          [&](media::VideoEncoder::OutputCB output_callback,
              media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            yuv_output_cb = output_callback;
            std::move(initialize_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));
  EXPECT_CALL(mock_encoder_, Initialize(profile_, _, _, _, _))
      .WillOnce(WithArgs<3, 4>(
          [&](media::VideoEncoder::OutputCB output_callback,
              media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            alpha_output_cb = output_callback;
            std::move(initialize_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));

  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(
          WithArgs<2>([yuv_output_cb_ptr = &yuv_output_cb](
                          media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb).Run(media::EncoderStatus::Codes::kOk);
            media::VideoEncoderOutput output;
            output.data = base::HeapArray<uint8_t>::Uninit(kChunkSize);
            output.key_frame = true;
            yuv_output_cb_ptr->Run(std::move(output), std::nullopt);
          }));
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(
          WithArgs<2>([alpha_output_cb_ptr = &alpha_output_cb](
                          media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb).Run(media::EncoderStatus::Codes::kOk);
            media::VideoEncoderOutput output;
            output.data = base::HeapArray<uint8_t>::Uninit(kAlphaChunkSize);
            output.key_frame = true;
            alpha_output_cb_ptr->Run(std::move(output), std::nullopt);
          }));

  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this, OnEncodedVideo(
                         MatchVideoParams(k720p, codec_),
                         MatchDataSizeAndIsKeyFrame(kChunkSize, true), _, _));

  EncodeFrame(media::VideoFrame::CreateZeroInitializedFrame(
                  media::VideoPixelFormat::PIXEL_FORMAT_I420A, k720p,
                  gfx::Rect(k720p), k720p, base::TimeDelta()),
              base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor).Times(2);
}

TEST_P(MediaRecorderEncoderWrapperTest,
       InitializesAndEncodesOneOpaqueFrameAndOneAlphaFrame) {
  InSequence s;
  if (codec_ != media::VideoCodec::kVP8 && codec_ != media::VideoCodec::kVP9) {
    GTEST_SKIP() << "no alpha encoding is supported in"
                 << media::GetCodecName(codec_);
  }
  media::VideoEncoder::OutputCB yuv_output_cb1;
  CreateEncoderWrapper(false);
  EXPECT_CALL(*this, CreateEncoder);
  EXPECT_CALL(*mock_metrics_provider_, MockInitialize);
  EXPECT_CALL(mock_encoder_, Initialize(profile_, _, _, _, _))
      .WillOnce(WithArgs<3, 4>(
          [&](media::VideoEncoder::OutputCB output_callback,
              media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            yuv_output_cb1 = output_callback;
            std::move(initialize_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(
          WithArgs<2>([yuv_output_cb_ptr = &yuv_output_cb1](
                          media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb).Run(media::EncoderStatus::Codes::kOk);
            media::VideoEncoderOutput output;
            output.data = base::HeapArray<uint8_t>::Uninit(kChunkSize);
            output.key_frame = true;
            yuv_output_cb_ptr->Run(std::move(output), std::nullopt);
          }));

  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this, OnEncodedVideo(
                         MatchVideoParams(k720p, codec_),
                         MatchDataSizeAndIsKeyFrame(kChunkSize, true), _, _));
  EXPECT_CALL(mock_encoder_, Flush)
      .WillOnce(
          WithArgs<0>([](media::VideoEncoder::EncoderStatusCB flush_done_cb) {
            std::move(flush_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));
  // Encode Opaque frame.
  constexpr size_t kAlphaChunkSize = 2345;
  EXPECT_CALL(*this, CreateEncoder).Times(2);
  EXPECT_CALL(*mock_metrics_provider_, MockInitialize);
  media::VideoEncoder::OutputCB yuv_output_cb2;
  media::VideoEncoder::OutputCB alpha_output_cb;
  EXPECT_CALL(mock_encoder_, Initialize(profile_, _, _, _, _))
      .WillOnce(WithArgs<3, 4>(
          [&](media::VideoEncoder::OutputCB output_callback,
              media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            yuv_output_cb2 = output_callback;
            std::move(initialize_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));
  EXPECT_CALL(mock_encoder_, Initialize(profile_, _, _, _, _))
      .WillOnce(WithArgs<3, 4>(
          [&](media::VideoEncoder::OutputCB output_callback,
              media::VideoEncoder::EncoderStatusCB initialize_done_cb) {
            alpha_output_cb = output_callback;
            std::move(initialize_done_cb).Run(media::EncoderStatus::Codes::kOk);
          }));

  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(
          WithArgs<2>([yuv_output_cb_ptr = &yuv_output_cb2](
                          media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb).Run(media::EncoderStatus::Codes::kOk);
            media::VideoEncoderOutput output;
            output.data = base::HeapArray<uint8_t>::Uninit(kChunkSize);
            output.key_frame = true;
            yuv_output_cb_ptr->Run(std::move(output), std::nullopt);
          }));
  EXPECT_CALL(mock_encoder_, Encode)
      .WillOnce(
          WithArgs<2>([alpha_output_cb_ptr = &alpha_output_cb](
                          media::VideoEncoder::EncoderStatusCB encode_done_cb) {
            std::move(encode_done_cb).Run(media::EncoderStatus::Codes::kOk);
            media::VideoEncoderOutput output;
            output.data = base::HeapArray<uint8_t>::Uninit(kAlphaChunkSize);
            output.key_frame = true;
            alpha_output_cb_ptr->Run(std::move(output), std::nullopt);
          }));

  EXPECT_CALL(*mock_metrics_provider_, MockIncrementEncodedFrameCount);
  EXPECT_CALL(*this, OnEncodedVideo(
                         MatchVideoParams(k720p, codec_),
                         MatchDataSizeAndIsKeyFrame(kChunkSize, true), _, _));

  auto opaque_frame = media::VideoFrame::CreateZeroInitializedFrame(
      media::VideoPixelFormat::PIXEL_FORMAT_I420, k720p, gfx::Rect(k720p),
      k720p, base::TimeDelta());
  auto alpha_frame = media::VideoFrame::CreateZeroInitializedFrame(
      media::VideoPixelFormat::PIXEL_FORMAT_I420A, k720p, gfx::Rect(k720p),
      k720p, base::TimeDelta());
  EncodeFrame(std::move(opaque_frame), base::TimeTicks::Now());
  EncodeFrame(std::move(alpha_frame), base::TimeTicks::Now());
  EXPECT_CALL(*this, MockVideoEncoderWrapperDtor).Times(2);
}

INSTANTIATE_TEST_SUITE_P(CodecProfile,
                         MediaRecorderEncoderWrapperTest,
                         ::testing::Values(media::H264PROFILE_MIN,
                                           media::VP8PROFILE_MIN,
                                           media::VP9PROFILE_MIN,
                                           media::AV1PROFILE_MIN
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
                                           ,
                                           media::HEVCPROFILE_MIN
#endif
                                           ));

}  // namespace blink

"""

```