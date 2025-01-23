Response:
The user wants a summary of the provided C++ code snippet. I need to identify the main purpose of the code and its key functionalities.

Based on the file path `blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc` and the included headers, it seems to be a unit test file for `RTCVideoEncoder` class within the Chromium Blink engine. This class likely handles video encoding for WebRTC.

Here's a breakdown of the functionalities observed:

- **Testing Framework:** The code uses the `testing/gtest/include/gtest/gtest.h` framework, indicating it's a set of tests.
- **RTCVideoEncoder Class:**  The core of the tests revolves around the `RTCVideoEncoder` class.
- **Mocking:** The code extensively uses mocking frameworks (`testing/gmock/include/gmock/gmock.h`, `media/base/mock_filters.h`, `media/video/mock_gpu_video_accelerator_factories.h`, `media/video/mock_video_encode_accelerator.h`) to simulate dependencies and control behavior during tests.
- **Video Encoding Parameters:** The tests manipulate various video encoding parameters like codec type, resolution, bitrate, frame rate, and spatial/temporal layers.
- **Hardware Acceleration:** The code interacts with `media::GpuVideoAcceleratorFactories` and `media::VideoEncodeAccelerator`, suggesting testing of hardware-accelerated video encoding.
- **Software Fallback:**  There are tests for software fallback scenarios when hardware acceleration is not available or feasible.
- **Callbacks:** The code uses callbacks (`webrtc::EncodedImageCallback`) to handle encoded video frames.
- **Threading:** The code involves multi-threading using `base::Thread` and `base::WaitableEvent` for synchronization.
- **Simulcast/SVC:** Tests related to simulcast and Scalable Video Coding (SVC) are present.
- **Error Handling:** The tests include scenarios to check error handling and fallback mechanisms.
- **Frame Manipulation:**  Utilities for creating and filling video frames are used.

Considering the instructions, I should also look for relationships with JavaScript, HTML, and CSS, although this C++ code is primarily a backend component. The connection would be indirect, as this code supports WebRTC features used in web applications.

Regarding logical inference, the tests implicitly make assumptions about the input and expected output of the `RTCVideoEncoder` under various conditions.

Finally, I need to identify potential user or programming errors related to the use of the `RTCVideoEncoder` class based on the test cases.
这个文件 `blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc` 是 Chromium Blink 引擎中用于测试 `RTCVideoEncoder` 类功能的单元测试文件。`RTCVideoEncoder` 负责处理 WebRTC 视频编码的功能。

**主要功能归纳:**

1. **测试 `RTCVideoEncoder` 类的各种编码场景:**  这个文件包含了一系列的测试用例，用来验证 `RTCVideoEncoder` 类在不同配置和输入下的行为是否符合预期。
2. **验证硬件加速编码:** 通过模拟 `media::GpuVideoAcceleratorFactories` 和 `media::VideoEncodeAccelerator`，测试了 `RTCVideoEncoder` 是否能正确利用硬件加速进行视频编码。
3. **测试软件编码回退:**  当硬件加速不可用或者不适用时，测试 `RTCVideoEncoder` 是否能正确回退到软件编码。
4. **测试不同的视频编解码器:**  测试用例涵盖了 VP8、H264、VP9 和 AV1 等不同的视频编解码器。
5. **测试不同的编码参数:**  测试用例会设置不同的分辨率、码率、帧率等参数，以验证编码器的鲁棒性。
6. **测试 Simulcast 和 SVC (Scalable Video Coding):**  包含了对 Simulcast (同时编码多个不同质量的视频流) 和 SVC (可伸缩视频编码，允许分层编码) 功能的测试。
7. **测试错误处理:**  测试用例会模拟各种错误情况，例如硬件编码错误，来验证 `RTCVideoEncoder` 的错误处理机制是否正确。
8. **测试帧的编码和处理:**  验证编码器能否正确编码视频帧，并保留时间戳等信息。
9. **测试帧的丢弃:**  验证编码器在启用帧丢弃功能时，能否按照预期丢弃帧。
10. **测试编码回调:** 验证编码完成后，`RTCVideoEncoder` 是否能正确调用注册的回调函数，并传递编码后的数据和元数据。

**与 JavaScript, HTML, CSS 的功能关系 (举例说明):**

虽然这个 C++ 文件本身不直接涉及 JavaScript, HTML, 或 CSS 的代码，但它测试的 `RTCVideoEncoder` 类是 WebRTC 功能的核心部分，而 WebRTC 是连接网页与本地设备能力的关键桥梁。

* **JavaScript:**
    * 当网页使用 JavaScript 的 WebRTC API (例如 `RTCPeerConnection`) 发起视频通话时，`RTCVideoEncoder` 负责将从摄像头捕获的视频帧进行编码，以便通过网络传输。
    * JavaScript 代码会设置编码器的参数，例如分辨率、码率等。测试用例中模拟了这些参数的设置，验证了 `RTCVideoEncoder` 能否正确处理这些来自 JavaScript 的配置。
    * **举例:**  一个 JavaScript Web 应用可能会调用 `createSender().replaceTrack(videoTrack)` 来发送视频流。Blink 引擎内部会使用 `RTCVideoEncoder` 对 `videoTrack` 中的视频帧进行编码。这个测试文件就是在验证 `RTCVideoEncoder` 在这个过程中的功能是否正常。

* **HTML:**
    * HTML 用于构建网页结构，其中 `<video>` 元素常用于展示本地或远程的视频流。
    * `RTCVideoEncoder` 编码后的视频数据最终会被解码并在 HTML 的 `<video>` 元素中渲染出来。虽然测试文件不直接操作 HTML 元素，但它保证了编码的正确性，这是视频能在 HTML 中正确显示的基础。

* **CSS:**
    * CSS 用于控制网页的样式，包括 `<video>` 元素的尺寸、边框等外观。
    * `RTCVideoEncoder` 编码的视频分辨率会影响 `<video>` 元素最终呈现的效果。测试文件中针对不同分辨率的测试，间接关联了 CSS 样式可能需要适应的不同视频尺寸。

**逻辑推理 (假设输入与输出):**

假设输入：

* **假设输入 1 (成功编码):**
    * **输入:** 一个指向 `webrtc::I420Buffer` 的视频帧，编码器配置为 VP8，目标码率 100kbps。
    * **预期输出:**  `RTCVideoEncoder` 调用 `media::VideoEncodeAccelerator` (或软件编码器) 对视频帧进行编码，编码完成后调用注册的回调函数，回调函数接收到一个包含编码后数据的 `webrtc::EncodedImage` 对象。

* **假设输入 2 (硬件编码失败，回退到软件编码):**
    * **输入:**  一个指向 `webrtc::I420Buffer` 的视频帧，尝试使用硬件加速的 H264 编码，但模拟的 `media::VideoEncodeAccelerator` 返回错误。
    * **预期输出:** `RTCVideoEncoder` 检测到硬件编码失败，自动回退到软件编码器进行编码，并最终通过回调函数返回编码后的 `webrtc::EncodedImage` 对象。测试用例会验证是否正确触发了回退机制。

**用户或编程常见的使用错误 (举例说明):**

1. **初始化编码器时设置了过高的码率:** 用户或程序员在 JavaScript 中配置 WebRTC 编码器时，可能会设置一个远超硬件或网络能力上限的码率。测试用例 `InitializeWithTooHighBitrateFails` 就模拟了这种情况，验证 `RTCVideoEncoder` 能否正确处理并返回错误，而不是导致崩溃或其他未定义行为。
2. **在不支持硬件加速的平台上尝试强制使用硬件加速:** 用户可能错误地假设所有平台都支持硬件加速，并进行了相关的配置。测试用例通过模拟不支持硬件加速的场景，验证 `RTCVideoEncoder` 能否优雅地处理这种情况，例如回退到软件编码。
3. **在编码过程中没有正确处理编码完成的回调:**  开发者在使用 WebRTC API 时，需要注册回调函数来接收编码后的数据。如果开发者没有正确实现或处理这个回调，可能会导致数据丢失或程序逻辑错误。测试用例会验证 `RTCVideoEncoder` 能否在编码完成后正确地触发回调。
4. **向编码器输入格式错误的视频帧:**  如果提供给 `RTCVideoEncoder` 的视频帧格式不符合预期（例如分辨率不支持，或者内存布局错误），可能会导致编码失败。测试用例 `SoftwareFallbackOnBadEncodeInput` 就模拟了这种情况，验证 `RTCVideoEncoder` 的错误处理和回退机制。

**这是第1部分，共3部分，功能归纳:**

这个代码片段主要集中在测试 `RTCVideoEncoder` 类的 **初始化** 和一些基本的 **编码** 功能。 它验证了在不同编解码器下，`RTCVideoEncoder` 是否能够成功创建、初始化，以及在一些简单场景下能否完成基本的视频帧编码。  特别地，它也测试了在某些情况下，例如低分辨率或不支持的硬件加速配置时，`RTCVideoEncoder` 是否能正确地回退到软件编码。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/peerconnection/rtc_video_encoder.h"

#include <stdint.h>

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "media/base/media_log.h"
#include "media/base/media_switches.h"
#include "media/base/mock_filters.h"
#include "media/base/video_encoder_metrics_provider.h"
#include "media/capture/capture_switches.h"
#include "media/mojo/clients/mock_mojo_video_encoder_metrics_provider_factory.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/video/fake_gpu_memory_buffer.h"
#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "media/video/mock_video_encode_accelerator.h"
#include "media/webrtc/webrtc_features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/testing/video_frame_utils.h"
#include "third_party/blink/renderer/platform/webrtc/testing/mock_webrtc_video_frame_adapter_shared_resources.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_frame_adapter.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/libyuv/include/libyuv/planar_functions.h"
#include "third_party/webrtc/api/video/i420_buffer.h"
#include "third_party/webrtc/api/video/video_frame_buffer.h"
#include "third_party/webrtc/api/video_codecs/video_encoder.h"
#include "third_party/webrtc/common_video/include/video_frame_buffer.h"
#include "third_party/webrtc/modules/video_coding/include/video_codec_interface.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"
#include "third_party/webrtc/rtc_base/time_utils.h"
#if BUILDFLAG(RTC_USE_H265)
#include "third_party/blink/renderer/platform/peerconnection/h265_parameter_sets_tracker.h"
#endif

using ::testing::_;
using ::testing::AllOf;
using ::testing::AtLeast;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::Field;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::NotNull;
using ::testing::Property;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SizeIs;
using ::testing::Values;
using ::testing::ValuesIn;
using ::testing::WithArgs;

using SpatialLayer = media::VideoEncodeAccelerator::Config::SpatialLayer;
using Type = webrtc::VideoFrameBuffer::Type;

namespace blink {

namespace {

const int kInputFrameFillY = 12;
const int kInputFrameFillU = 23;
const int kInputFrameFillV = 34;
// 360p is a valid HW resolution (unless `kForcingSoftwareIncludes360` is
// enabled).
const uint16_t kInputFrameWidth = 480;
const uint16_t kInputFrameHeight = 360;
const uint16_t kStartBitrate = 100;

#if !BUILDFLAG(IS_ANDROID)
// Less than 360p should result in SW fallback.
const uint16_t kSoftwareFallbackInputFrameWidth = 479;
const uint16_t kSoftwareFallbackInputFrameHeight = 359;
const uint16_t kSoftwareFallbackInputFrameHeightForAV1 = 269;
#endif

constexpr size_t kDefaultEncodedPayloadSize = 100;

const webrtc::VideoEncoder::Capabilities kVideoEncoderCapabilities(
    /* loss_notification= */ false);
const webrtc::VideoEncoder::Settings
    kVideoEncoderSettings(kVideoEncoderCapabilities, 1, 12345);

class EncodedImageCallbackWrapper : public webrtc::EncodedImageCallback {
 public:
  using EncodedCallback = base::OnceCallback<void(
      const webrtc::EncodedImage& encoded_image,
      const webrtc::CodecSpecificInfo* codec_specific_info)>;

  EncodedImageCallbackWrapper(EncodedCallback encoded_callback)
      : encoded_callback_(std::move(encoded_callback)) {}

  Result OnEncodedImage(
      const webrtc::EncodedImage& encoded_image,
      const webrtc::CodecSpecificInfo* codec_specific_info) override {
    std::move(encoded_callback_).Run(encoded_image, codec_specific_info);
    return Result(Result::OK);
  }

 private:
  EncodedCallback encoded_callback_;
};

class FakeNativeBufferI420 : public blink::WebRtcVideoFrameAdapter {
 public:
  FakeNativeBufferI420(int width, int height, bool allow_to_i420)
      : blink::WebRtcVideoFrameAdapter(
            media::VideoFrame::CreateBlackFrame(gfx::Size(480, 360))),
        width_(width),
        height_(height),
        allow_to_i420_(allow_to_i420) {}

  Type type() const override { return Type::kNative; }
  int width() const override { return width_; }
  int height() const override { return height_; }

  rtc::scoped_refptr<webrtc::I420BufferInterface> ToI420() override {
    if (allow_to_i420_) {
      return webrtc::I420Buffer::Create(width_, height_);
    } else {
      return nullptr;
    }
  }

  scoped_refptr<media::VideoFrame> getMediaVideoFrame() const override {
    const gfx::Size kSize360p(480, 360);
    const gfx::Rect kRect360p(0, 0, 480, 360);

    // The strictness of the mock ensures zero copy.
    auto resources =
        base::MakeRefCounted<testing::StrictMock<MockSharedResources>>();

    return CreateTestFrame(kSize360p, kRect360p, kSize360p,
                           media::VideoFrame::STORAGE_OWNED_MEMORY,
                           media::VideoPixelFormat::PIXEL_FORMAT_NV12,
                           base::TimeDelta());
  }

 private:
  const int width_;
  const int height_;
  const bool allow_to_i420_;
};

class RTCVideoEncoderWrapper : public webrtc::VideoEncoder {
 public:
  static std::unique_ptr<RTCVideoEncoderWrapper> Create(
      media::VideoCodecProfile profile,
      bool is_constrained_h264,
      media::GpuVideoAcceleratorFactories* gpu_factories,
      scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
          encoder_metrics_provider_factory) {
    auto wrapper = base::WrapUnique(new RTCVideoEncoderWrapper);
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    wrapper->task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](std::unique_ptr<RTCVideoEncoder>* rtc_video_encoder,
               media::VideoCodecProfile profile, bool is_constrained_h264,
               media::GpuVideoAcceleratorFactories* gpu_factories,
               scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
                   encoder_metrics_provider_factory,
               base::WaitableEvent* waiter) {
              *rtc_video_encoder = std::make_unique<RTCVideoEncoder>(
                  profile, is_constrained_h264, gpu_factories,
                  std::move(encoder_metrics_provider_factory));
              waiter->Signal();
            },
            &wrapper->rtc_video_encoder_, profile, is_constrained_h264,
            gpu_factories, std::move(encoder_metrics_provider_factory),
            &waiter));
    waiter.Wait();
    return wrapper;
  }

  int InitEncode(const webrtc::VideoCodec* codec_settings,
                 const webrtc::VideoEncoder::Settings& settings) override {
    int result = 0;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](RTCVideoEncoder* rtc_video_encoder,
               const webrtc::VideoCodec* codec_settings,
               const webrtc::VideoEncoder::Settings& settings,
               base::WaitableEvent* waiter, int* result) {
              *result = rtc_video_encoder->InitEncode(codec_settings, settings);
              waiter->Signal();
            },
            rtc_video_encoder_.get(), codec_settings, settings, &waiter,
            &result));
    waiter.Wait();
    return result;
  }
  int32_t Encode(
      const webrtc::VideoFrame& input_image,
      const std::vector<webrtc::VideoFrameType>* frame_types) override {
    int32_t result = 0;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](RTCVideoEncoder* rtc_video_encoder,
               const webrtc::VideoFrame& input_image,
               const std::vector<webrtc::VideoFrameType>* frame_types,
               base::WaitableEvent* waiter, int32_t* result) {
              *result = rtc_video_encoder->Encode(input_image, frame_types);
              waiter->Signal();
            },
            rtc_video_encoder_.get(), input_image, frame_types, &waiter,
            &result));
    waiter.Wait();
    return result;
  }
  int32_t RegisterEncodeCompleteCallback(
      webrtc::EncodedImageCallback* callback) override {
    int32_t result = 0;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](RTCVideoEncoder* rtc_video_encoder,
               webrtc::EncodedImageCallback* callback,
               base::WaitableEvent* waiter, int32_t* result) {
              *result =
                  rtc_video_encoder->RegisterEncodeCompleteCallback(callback);
              waiter->Signal();
            },
            rtc_video_encoder_.get(), callback, &waiter, &result));
    waiter.Wait();
    return result;
  }
  int32_t Release() override {
    int32_t result = 0;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(
                       [](RTCVideoEncoder* rtc_video_encoder,
                          base::WaitableEvent* waiter, int32_t* result) {
                         *result = rtc_video_encoder->Release();
                         waiter->Signal();
                       },
                       rtc_video_encoder_.get(), &waiter, &result));
    waiter.Wait();
    return result;
  }
  void SetErrorWaiter(base::WaitableEvent* error_waiter) {
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](RTCVideoEncoder* rtc_video_encoder,
               base::WaitableEvent* waiter) {
              rtc_video_encoder->SetErrorCallbackForTesting(CrossThreadBindOnce(
                  [](base::WaitableEvent* waiter) { waiter->Signal(); },
                  CrossThreadUnretained(waiter)));
            },
            rtc_video_encoder_.get(), error_waiter));
    return;
  }

  void SetRates(
      const webrtc::VideoEncoder::RateControlParameters& parameters) override {
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](RTCVideoEncoder* rtc_video_encoder,
               const webrtc::VideoEncoder::RateControlParameters& parameters,
               base::WaitableEvent* waiter) {
              rtc_video_encoder->SetRates(parameters);
              waiter->Signal();
            },
            rtc_video_encoder_.get(), parameters, &waiter));
    waiter.Wait();
  }
  EncoderInfo GetEncoderInfo() const override {
    NOTIMPLEMENTED();
    return EncoderInfo();
  }

  ~RTCVideoEncoderWrapper() override {
    if (task_runner_) {
      task_runner_->DeleteSoon(FROM_HERE, std::move(rtc_video_encoder_));
    }
    webrtc_encoder_thread_.FlushForTesting();
  }

#if BUILDFLAG(RTC_USE_H265)
  void SetH265ParameterSetsTracker(
      std::unique_ptr<H265ParameterSetsTracker> tracker) {
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](RTCVideoEncoder* rtc_video_encoder,
               std::unique_ptr<H265ParameterSetsTracker> tracker,
               base::WaitableEvent* waiter) {
              rtc_video_encoder->SetH265ParameterSetsTrackerForTesting(
                  std::move(tracker));
              waiter->Signal();
            },
            rtc_video_encoder_.get(), std::move(tracker), &waiter));
    waiter.Wait();
  }
#endif

 private:
  RTCVideoEncoderWrapper() : webrtc_encoder_thread_("WebRTC encoder thread") {
    webrtc_encoder_thread_.Start();
    task_runner_ = webrtc_encoder_thread_.task_runner();
  }

  base::Thread webrtc_encoder_thread_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // |webrtc_encoder_thread_| members.
  std::unique_ptr<RTCVideoEncoder> rtc_video_encoder_;
};
}  // anonymous namespace

MATCHER_P3(CheckConfig,
           pixel_format,
           storage_type,
           drop_frame,
           "Check pixel format, storage type and drop frame in VEAConfig") {
  return arg.input_format == pixel_format && arg.storage_type == storage_type &&
         (arg.drop_frame_thresh_percentage > 0) == drop_frame;
}

MATCHER_P(CheckStatusCode, code, "Check the code of media::EncoderStatusCode") {
  return arg.code() == code;
}

class RTCVideoEncoderTest {
 public:
  RTCVideoEncoderTest()
      : encoder_thread_("vea_thread"),
        mock_gpu_factories_(
            new media::MockGpuVideoAcceleratorFactories(nullptr)),
        mock_encoder_metrics_provider_factory_(
            base::MakeRefCounted<
                media::MockMojoVideoEncoderMetricsProviderFactory>(
                media::mojom::VideoEncoderUseCase::kWebRTC)) {
    ON_CALL(*mock_encoder_metrics_provider_factory_,
            CreateVideoEncoderMetricsProvider())
        .WillByDefault(Return(::testing::ByMove(
            std::make_unique<media::MockVideoEncoderMetricsProvider>())));
  }

  void ExpectCreateInitAndDestroyVEA(
      media::VideoPixelFormat pixel_format = media::PIXEL_FORMAT_I420,
      media::VideoEncodeAccelerator::Config::StorageType storage_type =
          media::VideoEncodeAccelerator::Config::StorageType::kShmem,
      bool drop_frame = false) {
    // The VEA will be owned by the RTCVideoEncoder once
    // factory.CreateVideoEncodeAccelerator() is called.
    mock_vea_ = new media::MockVideoEncodeAccelerator();

    EXPECT_CALL(*mock_gpu_factories_.get(), DoCreateVideoEncodeAccelerator())
        .WillRepeatedly(Return(mock_vea_.get()));
    EXPECT_CALL(
        *mock_vea_,
        Initialize(CheckConfig(pixel_format, storage_type, drop_frame), _, _))
        .WillOnce(Invoke(this, &RTCVideoEncoderTest::Initialize));
    EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer).Times(AtLeast(3));
    EXPECT_CALL(*mock_vea_, Destroy()).Times(1);
  }

  void SetUp() {
    DVLOG(3) << __func__;
    ASSERT_TRUE(encoder_thread_.Start());

    EXPECT_CALL(*mock_gpu_factories_.get(), GetTaskRunner())
        .WillRepeatedly(Return(encoder_thread_.task_runner()));
  }

  void TearDown() {
    DVLOG(3) << __func__;
    EXPECT_TRUE(encoder_thread_.IsRunning());
    RunUntilIdle();
    if (rtc_encoder_)
      rtc_encoder_->Release();
    rtc_encoder_.reset();
    encoder_thread_.task_runner()->ReleaseSoon(
        FROM_HERE, std::move(mock_encoder_metrics_provider_factory_));
    RunUntilIdle();
    encoder_thread_.Stop();
  }

  void RunUntilIdle() {
    DVLOG(3) << __func__;
    encoder_thread_.FlushForTesting();
  }

  void CreateEncoder(webrtc::VideoCodecType codec_type) {
    DVLOG(3) << __func__;
    media::VideoCodecProfile media_profile;
    switch (codec_type) {
      case webrtc::kVideoCodecVP8:
        media_profile = media::VP8PROFILE_ANY;
        break;
      case webrtc::kVideoCodecH264:
        media_profile = media::H264PROFILE_BASELINE;
        break;
      case webrtc::kVideoCodecVP9:
        media_profile = media::VP9PROFILE_PROFILE0;
        break;
#if BUILDFLAG(RTC_USE_H265)
      case webrtc::kVideoCodecH265:
        media_profile = media::HEVCPROFILE_MAIN;
        break;
#endif
      case webrtc::kVideoCodecAV1:
        media_profile = media::AV1PROFILE_PROFILE_MAIN;
        break;
      default:
        ADD_FAILURE() << "Unexpected codec type: " << codec_type;
        media_profile = media::VIDEO_CODEC_PROFILE_UNKNOWN;
    }

    rtc_encoder_ = RTCVideoEncoderWrapper::Create(
        media_profile, false, mock_gpu_factories_.get(),
        mock_encoder_metrics_provider_factory_);
  }

  // media::VideoEncodeAccelerator implementation.
  bool Initialize(const media::VideoEncodeAccelerator::Config& config,
                  media::VideoEncodeAccelerator::Client* client,
                  std::unique_ptr<media::MediaLog> media_log) {
    DVLOG(3) << __func__;
    config_ = config;
    client_ = client;

    constexpr size_t kNumInputBuffers = 3;
    client_->RequireBitstreamBuffers(kNumInputBuffers,
                                     config.input_visible_size,
                                     config.input_visible_size.GetArea());
    return true;
  }

  void RegisterEncodeCompleteCallback(
      EncodedImageCallbackWrapper::EncodedCallback callback) {
    callback_wrapper_ =
        std::make_unique<EncodedImageCallbackWrapper>(std::move(callback));
    rtc_encoder_->RegisterEncodeCompleteCallback(callback_wrapper_.get());
  }

  webrtc::VideoCodec GetDefaultCodec() {
    webrtc::VideoCodec codec = {};
    memset(&codec, 0, sizeof(codec));
    codec.width = kInputFrameWidth;
    codec.height = kInputFrameHeight;
    codec.codecType = webrtc::kVideoCodecVP8;
    codec.startBitrate = kStartBitrate;
    return codec;
  }

  webrtc::VideoCodec GetSVCLayerCodec(webrtc::VideoCodecType codec_type,
                                      size_t num_spatial_layers) {
    webrtc::VideoCodec codec{};
    codec.codecType = codec_type;
    codec.width = kInputFrameWidth;
    codec.height = kInputFrameHeight;
    codec.startBitrate = kStartBitrate;
    codec.maxBitrate = codec.startBitrate * 2;
    codec.minBitrate = codec.startBitrate / 2;
    codec.maxFramerate = 24;
    codec.active = true;
    codec.qpMax = 30;
    codec.numberOfSimulcastStreams = 1;
    codec.mode = webrtc::VideoCodecMode::kRealtimeVideo;
    switch (codec_type) {
      case webrtc::kVideoCodecVP9: {
        webrtc::VideoCodecVP9& vp9 = *codec.VP9();
        vp9.numberOfTemporalLayers = 3;
        vp9.numberOfSpatialLayers = num_spatial_layers;
        num_spatial_layers_ = num_spatial_layers;
        for (size_t sid = 0; sid < num_spatial_layers; ++sid) {
          const int denom = 1 << (num_spatial_layers_ - (sid + 1));
          webrtc::SpatialLayer& sl = codec.spatialLayers[sid];
          sl.width = kInputFrameWidth / denom;
          sl.height = kInputFrameHeight / denom;
          sl.maxFramerate = 24;
          sl.numberOfTemporalLayers = vp9.numberOfTemporalLayers;
          sl.targetBitrate = kStartBitrate / denom;
          sl.maxBitrate = sl.targetBitrate / denom;
          sl.minBitrate = sl.targetBitrate / denom;
          sl.qpMax = 30;
          sl.active = true;
        }
      } break;
      case webrtc::kVideoCodecAV1: {
        num_spatial_layers_ = num_spatial_layers;
        for (size_t sid = 0; sid < num_spatial_layers_; ++sid) {
          const int denom = 1 << (num_spatial_layers_ - (sid + 1));
          webrtc::SpatialLayer& sl = codec.spatialLayers[sid];
          sl.width = kInputFrameWidth / denom;
          sl.height = kInputFrameHeight / denom;
          sl.maxFramerate = 24;
          sl.numberOfTemporalLayers = 1;
          sl.targetBitrate = kStartBitrate / denom;
          sl.maxBitrate = sl.targetBitrate / denom;
          sl.minBitrate = sl.targetBitrate / denom;
          sl.qpMax = 30;
          sl.active = true;
        }
      } break;
#if BUILDFLAG(RTC_USE_H265)
      case webrtc::kVideoCodecH265: {
        // Do not support multiple spatial layers
        CHECK_EQ(num_spatial_layers, 1u);
        num_spatial_layers_ = num_spatial_layers;
        webrtc::SpatialLayer& sl = codec.spatialLayers[0];
        sl.width = kInputFrameWidth;
        sl.height = kInputFrameHeight;
        sl.maxFramerate = 24;
        sl.numberOfTemporalLayers = 1;
        sl.targetBitrate = kStartBitrate;
        sl.maxBitrate = sl.targetBitrate;
        sl.minBitrate = sl.targetBitrate;
        sl.qpMax = 30;
        sl.active = true;
        break;
      }
#endif
      default:
        NOTREACHED();
    }
    return codec;
  }

  webrtc::VideoCodec GetSimulcastCodec(webrtc::VideoCodecType codec_type,
                                       size_t num_simulcast_streams) {
    webrtc::VideoCodec codec{};
    codec.codecType = codec_type;
    codec.width = kInputFrameWidth;
    codec.height = kInputFrameHeight;
    codec.startBitrate = kStartBitrate;
    codec.maxBitrate = codec.startBitrate * 2;
    codec.minBitrate = codec.startBitrate / 2;
    codec.maxFramerate = 24;
    codec.active = true;
    codec.qpMax = 30;
    codec.numberOfSimulcastStreams = num_simulcast_streams;
    codec.mode = webrtc::VideoCodecMode::kRealtimeVideo;
    switch (codec_type) {
      case webrtc::kVideoCodecVP9: {
        webrtc::VideoCodecVP9& vp9 = *codec.VP9();
        vp9.numberOfTemporalLayers = 3;
        vp9.numberOfSpatialLayers = 1;
        num_spatial_layers_ = 3;
        for (size_t sid = 0; sid < num_simulcast_streams; ++sid) {
          const int denom = 1 << (num_simulcast_streams - (sid + 1));
          webrtc::SimulcastStream& sl = codec.simulcastStream[sid];
          sl.width = kInputFrameWidth / denom;
          sl.height = kInputFrameHeight / denom;
          sl.maxFramerate = 24;
          sl.numberOfTemporalLayers = vp9.numberOfTemporalLayers;
          sl.targetBitrate = kStartBitrate / denom;
          sl.maxBitrate = sl.targetBitrate / denom;
          sl.minBitrate = sl.targetBitrate / denom;
          sl.qpMax = 30;
          sl.active = true;
        }
      } break;
      default:
        NOTREACHED();
    }
    return codec;
  }

  void FillFrameBuffer(rtc::scoped_refptr<webrtc::I420Buffer> frame) {
    CHECK(libyuv::I420Rect(frame->MutableDataY(), frame->StrideY(),
                           frame->MutableDataU(), frame->StrideU(),
                           frame->MutableDataV(), frame->StrideV(), 0, 0,
                           frame->width(), frame->height(), kInputFrameFillY,
                           kInputFrameFillU, kInputFrameFillV) == 0);
  }

  void VerifyEncodedFrame(scoped_refptr<media::VideoFrame> frame,
                          bool force_keyframe) {
    DVLOG(3) << __func__;
    EXPECT_EQ(kInputFrameWidth, frame->visible_rect().width());
    EXPECT_EQ(kInputFrameHeight, frame->visible_rect().height());
    EXPECT_EQ(kInputFrameFillY,
              frame->visible_data(media::VideoFrame::Plane::kY)[0]);
    EXPECT_EQ(kInputFrameFillU,
              frame->visible_data(media::VideoFrame::Plane::kU)[0]);
    EXPECT_EQ(kInputFrameFillV,
              frame->visible_data(media::VideoFrame::Plane::kV)[0]);
  }

  void DropFrame(scoped_refptr<media::VideoFrame> frame, bool force_keyframe) {
    CHECK(!force_keyframe);
    client_->BitstreamBufferReady(
        0,
        media::BitstreamBufferMetadata::CreateForDropFrame(frame->timestamp()));
  }
  void ReturnSvcFramesThatShouldBeDropped(
      scoped_refptr<media::VideoFrame> frame,
      bool force_keyframe) {
    CHECK(!force_keyframe);
    for (size_t sid = 0; sid < num_spatial_layers_; ++sid) {
      const bool end_of_picture = sid + 1 == num_spatial_layers_;
      client_->BitstreamBufferReady(
          sid, media::BitstreamBufferMetadata::CreateForDropFrame(
                   frame->timestamp(), sid, end_of_picture));
    }
  }
  void ReturnFrameWithTimeStamp(scoped_refptr<media::VideoFrame> frame,
                                bool force_keyframe) {
    client_->BitstreamBufferReady(
        0, media::BitstreamBufferMetadata(kDefaultEncodedPayloadSize,
                                          force_keyframe, frame->timestamp()));
  }

  void FlushComplete(media::VideoEncodeAccelerator::FlushCallback callback) {
    std::move(callback).Run(true);
  }

  void FlushFailure(media::VideoEncodeAccelerator::FlushCallback callback) {
    std::move(callback).Run(false);
  }

  void ReturnSVCLayerFrameWithVp9Metadata(
      scoped_refptr<media::VideoFrame> frame,
      bool force_keyframe) {
    const size_t frame_num = return_svc_layer_frame_times_;
    CHECK(0 <= frame_num && frame_num <= 4);
    for (size_t sid = 0; sid < num_spatial_layers_; ++sid) {
      // Assume the number of TLs is three. TL structure is below.
      // TL2:      [#1]     /-[#3]
      // TL1:     /_____[#2]
      // TL0: [#0]-----------------[#4]
      media::Vp9Metadata vp9;
      vp9.inter_pic_predicted = frame_num != 0 && !force_keyframe;
      constexpr int kNumTemporalLayers = 3;
      vp9.temporal_up_switch = frame_num != kNumTemporalLayers;
      switch (frame_num) {
        case 0:
          vp9.temporal_idx = 0;
          break;
        case 1:
          vp9.temporal_idx = 2;
          vp9.p_diffs = {1};
          break;
        case 2:
          vp9.temporal_idx = 1;
          vp9.p_diffs = {2};
          break;
        case 3:
          vp9.temporal_idx = 2;
          vp9.p_diffs = {1};
          break;
        case 4:
          vp9.temporal_idx = 0;
          vp9.p_diffs = {4};
          break;
      }

      const bool end_of_picture = sid + 1 == num_spatial_layers_;
      media::BitstreamBufferMetadata metadata(
          100u /* payload_size_bytes */, force_keyframe, frame->timestamp());

      // Assume k-SVC encoding.
      metadata.key_frame = frame_num == 0 && sid == 0;
      vp9.end_of_picture = end_of_picture;
      vp9.spatial_idx = sid;
      vp9.reference_lower_spatial_layers = frame_num == 0 && sid != 0;
      vp9.referenced_by_upper_spatial_layers =
          frame_num == 0 && (sid + 1 != num_spatial_layers_);
      if (metadata.key_frame) {
        for (size_t i = 0; i < num_spatial_layers_; ++i) {
          const int denom = 1 << (num_spatial_layers_ - (i + 1));
          vp9.spatial_layer_resolutions.emplace_back(
              gfx::Size(frame->coded_size().width() / denom,
                        frame->coded_size().height() / denom));
        }
        vp9.begin_active_spatial_layer_index = 0;
        vp9.end_active_spatial_layer_index = num_spatial_layers_;
      }
      metadata.vp9 = vp9;
      client_->BitstreamBufferReady(sid, metadata);
    }

    return_svc_layer_frame_times_ += 1;
  }

  void ReturnSVCLayerFrameWithInvalidGenericMetadata(
      scoped_refptr<media::VideoFrame> frame,
      bool force_keyframe) {
    const size_t frame_num = return_svc_layer_frame_times_;
    CHECK(0 <= frame_num && frame_num <= 4);
    for (size_t sid = 0; sid < num_spatial_layers_; ++sid) {
      // Assume the number of TLs is three. expected TL structure is below.
      // TL2:      [#1]     /-[#3]
      // TL1:     /_____[#2]
      // TL0: [#0]-----------------[#4]
      media::SVCGenericMetadata generic;
      generic.follow_svc_spec = false;
      switch (frame_num) {
        case 0:
          generic.temporal_idx = 0;
          generic.reference_flags = 0b00000000;
          generic.refresh_flags = 0b11111111;
          break;
        case 1:
          generic.temporal_idx = 2;
          generic.reference_flags = 0b00000001;
          generic.refresh_flags = 0b00000100;
          break;
        case 2:
          generic.temporal_idx = 1;
          generic.reference_flags = 0b00000001;
          generic.refresh_flags = 0b00000010;
          break;
        case 3:
          // Invalid reference_flags with refs a T2 frame.
          generic.temporal_idx = 2;
          generic.reference_flags = 0b00000110;
          generic.refresh_flags = 0b00000000;
          break;
        case 4:
          // Invalid refreshed encode buffer slot index.
          generic.temporal_idx = 0;
          generic.reference_flags = 0b00000001;
          generic.refresh_flags = 0b111111111;
          break;
      }
      media::BitstreamBufferMetadata metadata(
          100u /* payload_size_bytes */, force_keyframe, frame->timestamp());
      metadata.key_frame = frame_num == 0 && sid == 0;
      metadata.svc_generic = generic;
      client_->BitstreamBufferReady(sid, metadata);
    }
    return_svc_layer_frame_times_ += 1;
  }

  void ResetSVCLayerFrameTimes() { return_svc_layer_frame_times_ = 0; }

  void VerifyTimestamp(uint32_t rtp_timestamp,
                       int64_t capture_time_ms,
                       const webrtc::EncodedImage& encoded_image,
                       const webrtc::CodecSpecificInfo* codec_specific_info) {
    DVLOG(3) << __func__;
    EXPECT_EQ(rtp_timestamp, encoded_image.RtpTimestamp());
    EXPECT_EQ(capture_time_ms, encoded_image.capture_time_ms_);
  }

  std::vector<gfx::Size> ToResolutionList(const webrtc::VideoCodec& codec) {
    std::vector<gfx::Size> resolutions;
    switch (codec.codecType) {
      case webrtc::VideoCodecType::kVideoCodecVP8:
      case webrtc::VideoCodecType::kVideoCodecH264: {
        for (int i = 0; i < codec.numberOfSimulcastStreams; ++i) {
          if (!codec.simulcastStream[i].active) {
            break;
          }
          resolutions.emplace_back(codec.simulcastStream[i].width,
                                   codec.simulcastStream[i].height);
        }
        break;
      }
      case webrtc::VideoCodecType::kVideoCodecVP9: {
        for (int i = 0; i < codec.VP9().numberOfSpatialLayers; ++i) {
          if (!codec.spatialLayers[i].active) {
            break;
          }
          resolutions.emplace_back(codec.spatialLayers[i].width,
                                   codec.spatialLayers[i].height);
        }
        break;
      }
      default: {
        return {};
      }
    }

    return resolutions;
  }

 protected:
  raw_ptr<media::MockVideoEncodeAccelerator, DanglingUntriaged> mock_vea_;
  std::unique_ptr<RTCVideoEncoderWrapper> rtc_encoder_;
  std::optional<media::VideoEncodeAccelerator::Config> config_;
  raw_ptr<media::VideoEncodeAccelerator::Client, DanglingUntriaged> client_;
  base::Thread encoder_thread_;

  std::unique_ptr<media::MockGpuVideoAcceleratorFactories> mock_gpu_factories_;
  scoped_refptr<media::MockMojoVideoEncoderMetricsProviderFactory>
      mock_encoder_metrics_provider_factory_;

 private:
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<EncodedImageCallbackWrapper> callback_wrapper_;
  size_t num_spatial_layers_;
  size_t return_svc_layer_frame_times_ = 0;
};

class RTCVideoEncoderInitTest
    : public RTCVideoEncoderTest,
      public ::testing::TestWithParam<webrtc::VideoCodecType> {
 public:
  RTCVideoEncoderInitTest() {
    std::vector<base::test::FeatureRef> enabled_features;
  }
  ~RTCVideoEncoderInitTest() override = default;
  void SetUp() override { RTCVideoEncoderTest::SetUp(); }
  void TearDown() override { RTCVideoEncoderTest::TearDown(); }
};

TEST_P(RTCVideoEncoderInitTest, CreateAndInitSucceeds) {
  const webrtc::VideoCodecType codec_type = GetParam();
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

TEST_P(RTCVideoEncoderInitTest, RepeatedInitSucceeds) {
  const webrtc::VideoCodecType codec_type = GetParam();
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
              CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(::testing::ByMove(
          std::make_unique<media::MockVideoEncoderMetricsProvider>())));
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
  EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
              CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(::testing::ByMove(
          std::make_unique<media::MockVideoEncoderMetricsProvider>())));
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

// Software fallback for low resolution is not applicable on Android.
#if !BUILDFLAG(IS_ANDROID)

TEST_P(RTCVideoEncoderInitTest, SoftwareFallbackForLowResolution) {
  const webrtc::VideoCodecType codec_type = GetParam();
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.width = kSoftwareFallbackInputFrameWidth;
  if (codec_type == webrtc::kVideoCodecAV1) {
    codec.height = kSoftwareFallbackInputFrameHeightForAV1;
  } else {
    codec.height = kSoftwareFallbackInputFrameHeight;
  }
  codec.codecType = codec_type;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

TEST_P(RTCVideoEncoderInitTest, AV1Supports270p) {
  const webrtc::VideoCodecType codec_type = GetParam();
  if (codec_type != webrtc::kVideoCodecAV1) {
    GTEST_SKIP();
  }
  CreateEncoder(codec_type);
  ExpectCreateInitAndDestroyVEA();
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.width = 480;
  codec.height = 270;
  codec.codecType = codec_type;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

#endif

TEST_P(RTCVideoEncoderInitTest, CreateAndInitSucceedsForTemporalLayer) {
  const webrtc::VideoCodecType codec_type = GetParam();
  if (codec_type == webrtc::kVideoCodecVP8)
    GTEST_SKIP() << "VP8 temporal layer encoding is not supported";
  if (codec_type == webrtc::kVideoCodecH264)
    GTEST_SKIP() << "H264 temporal layer encoding is not supported";
  if (codec_type == webrtc::kVideoCodecAV1) {
    GTEST_SKIP() << "AV1 temporal layer encoding is not supported";
  }

  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(codec_type,
                                                 /*num_spatial_layers=*/1);
  CreateEncoder(tl_codec.codecType);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
}

TEST_P(RTCVideoEncoderInitTest, CreateAndInitFailsForAV1SpatialLayer) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecAV1,
                                                 /*num_spatial_layers=*/3);
  CreateEncoder(tl_codec.codecType);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
}

const webrtc::VideoCodecType kInitTestCases[] = {
    webrtc::kVideoCodecH264,
    webrtc::kVideoCodecVP9,
    webrtc::kVideoCodecVP8,
    webrtc::kVideoCodecAV1,
};

INSTANTIATE_TEST_SUITE_P(InitTimingAndCodecProfiles,
                         RTCVideoEncoderInitTest,
                         ValuesIn(kInitTestCases));

class RTCVideoEncoderEncodeTest : public RTCVideoEncoderTest,
                                  public ::testing::Test {
 public:
  RTCVideoEncoderEncodeTest() : RTCVideoEncoderEncodeTest(false) {}

  explicit RTCVideoEncoderEncodeTest(
      bool enable_keep_encoder_instance_on_release) {
    std::vector<base::test::FeatureRef> enabled_features = {
        features::kZeroCopyTabCapture,
    };
    if (enable_keep_encoder_instance_on_release) {
      enabled_features.push_back(features::kKeepEncoderInstanceOnRelease);
    }
    enabled_features.push_back(media::kWebRTCHardwareVideoEncoderFrameDrop);
    feature_list_.InitWithFeatures(enabled_features,
                                   /*disabled_features=*/{});
  }

  ~RTCVideoEncoderEncodeTest() override = default;
  void SetUp() override { RTCVideoEncoderTest::SetUp(); }
  void TearDown() override { RTCVideoEncoderTest::TearDown(); }

 protected:
  base::test::ScopedFeatureList feature_list_;
};

class RTCVideoEncoderFrameSizeChangeTest : public RTCVideoEncoderEncodeTest {
 public:
  RTCVideoEncoderFrameSizeChangeTest() : RTCVideoEncoderEncodeTest(true) {}

  void ExpectFrameSizeChange(const gfx::Size& expected_size) {
    // potentially validate bitrate and framerate
    EXPECT_CALL(*mock_vea_, RequestEncodingParametersChange(
                                _, _, std::optional<gfx::Size>(expected_size)))
        .WillOnce(Invoke([this, expected_size](
                             const media::Bitrate& bitrate, uint32_t framerate,
                             const std::optional<gfx::Size>& size) {
          EXPECT_EQ(size, expected_size);
          client_->RequireBitstreamBuffers(3, expected_size,
                                           expected_size.GetArea());
        }));
    EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer).Times(AtLeast(3));
  }

  void SetUpEncodingWithFrameSizeChangeSupport(
      const webrtc::VideoCodec& codec) {
    ExpectCreateInitAndDestroyVEA();
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

    EXPECT_CALL(*mock_vea_, RequestEncodingParametersChange(
                                _, _, std::optional<gfx::Size>()));
    webrtc::VideoBitrateAllocation bitrate_allocation;
    bitrate_allocation.SetBitrate(1, 0, 500000);
    rtc_encoder_->SetRates(webrtc::VideoEncoder::RateControlParameters(
        bitrate_allocation, codec.maxFramerate));

      // report frame size change support
      media::VideoEncoderInfo info;
      info.supports_frame_size_change = true;
      encoder_thread_.task_runner()->PostTask(
          FROM_HERE,
          base::BindOnce(
              &media::VideoEncodeAccelerator::Client::NotifyEncoderInfoChange,
              base::Unretained(client_), info));

      for (int i = 0; i < kFramesToEncodeBeforeFrameSizeChange; i++) {
        const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
            webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
        FillFrameBuffer(buffer);
        std::vector<webrtc::VideoFrameType> frame_types;
        frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);

        webrtc::VideoFrame rtc_frame =
            webrtc::VideoFrame::Builder()
                .set_video_frame_buffer(buffer)
                .set_rtp_timestamp(i)
                .set_timestamp_us(i)
                .set_rotation(webrtc::kVideoRotation_0)
                .build();
        base::WaitableEvent event;
        EXPECT_CALL(*mock_vea_, Encode)
            .WillOnce(
                Invoke([this, &event](scoped_refptr<media::VideoFrame> frame,
                                      bool force_keyframe) {
                  client_->BitstreamBufferReady(
                      0, media::BitstreamBufferMetadata(0, force_keyframe,
                                                        frame->timestamp()));
                  event.Signal();
                }));

        EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
                  rtc_encoder_->Encode(rtc_frame, &frame_types));
        event.Wait();
      }
  }

  ~RTCVideoEncoderFrameSizeChangeTest() override = default;

 protected:
  const int kFramesToEncodeBeforeFrameSizeChange = 3;
};

TEST_F(RTCVideoEncoderEncodeTest, H264SoftwareFallbackForOddSize) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecH264;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  codec.width = kInputFrameWidth - 1;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderEncodeTest, VP8CreateAndInitSucceedsForOddSize) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  codec.width = kInputFrameWidth - 1;
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderEncodeTest, VP9CreateAndInitSucceedsForOddSize) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  codec.width = kInputFrameWidth - 1;
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderEncodeTest, VP9SoftwareFallbackForVEANotSupport) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/1);
  CreateEncoder(tl_codec.codecType);
  media::VideoEncodeAccelerator::SupportedProfiles profiles = {
      {media::VP9PROFILE_PROFILE0,
       /*max_resolution*/ gfx::Size(1920, 1088),
       /*max_framerate_numerator*/ 30,
       /*max_framerate_denominator*/ 1,
       media::VideoEncodeAccelerator::kConstantMode,
       {media::SVCScalabilityMode::kL1T1}}};
  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .WillOnce(Return(profiles));
  // The mock gpu factories return |profiles| as VEA supported profiles, which
  // only support VP9 single layer acceleration. When requesting VP9 SVC
  // encoding, InitEncode() will fail in scalability mode check and return
  // WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE.
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderEncodeTest, ClearSetErrorRequestWhenInitNewEncoder) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;

  mock_vea_ = new media::MockVideoEncodeAccelerator();
  EXPECT_CALL(*mock_gpu_factories_.get(), DoCreateVideoEncodeAccelerator())
      .WillOnce(Return(mock_vea_.get()));
  media::VideoPixelFormat pixel_format = media::PIXEL_FORMAT_I420;
  media::VideoEncodeAccelerator::Config::StorageType storage_type =
      media::VideoEncodeAccelerator::Config::StorageType::kShmem;
  bool drop_frame = false;
  EXPECT_CALL(
      *mock_vea_,
      Initialize(CheckConfig(pixel_format, storage_type, drop_frame), _, _))
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::Initialize));
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  // Notify error status to rtc video encoder.
  encoder_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&media::VideoEncodeAccelerator::Client::NotifyErrorStatus,
                     base::Unretained(client_),
                     media::EncoderStatus::Codes::kEncoderFailedEncode));

  auto* mock_vea_new = new media::MockVideoEncodeAccelerator();
  EXPECT_CALL(*mock_gpu_factories_.get(), DoCreateVideoEncodeAccelerator())
      .WillOnce(Return(mock_vea_new));
  EXPECT_CALL(
      *mock_vea_new,
      Initialize(CheckConfig(pixel_format, storage_type, drop_frame), _, _))
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::Initialize));
  auto encoder_metrics_provider =
      std::make_unique<media::MockVideoEncoderMetricsProvider>();
  EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
              CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(::testing::ByMove(std::move(encoder_metrics_provider))));
  // When InitEncode() is called again, RTCVideoEncoder will release current
  // impl_ and create a new instance, the set error request from a released
  // impl_ is regarded as invalid and should be rejected.
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
  // If the invalid set error request is rejected as expected, Encode() will
  // return with WEBRTC_VIDEO_CODEC_OK.
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  rtc_encoder_->Release();
}

// Checks that WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE is returned when there is
// platform error.
TEST_F(RTCVideoEncoderEncodeTest, SoftwareFallbackAfterError) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  EXPECT_CALL(*mock_vea_, Encode(_, _))
      .WillOnce(Invoke([this](scoped_refptr<media::VideoFrame>, bool) {
        encoder_thread_.task_runner()->PostTask(
            FROM_HERE,
            base::BindOnce(
                &media::VideoEncodeAccelerator::Client::NotifyErrorStatus,
                base::Unretained(client_),
                media::EncoderStatus::Codes::kEncoderFailedEncode));
      }));

  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types;
  base::WaitableEvent error_waiter(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  rtc_encoder_->SetErrorWaiter(&error_waiter);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  error_waiter.Wait();
  // Expect the next frame to return SW fallback.
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
}

// On Windows we allow native input that is mappable.
#if BUILDFLAG(IS_WIN)
TEST_F(RTCVideoEncoderEncodeTest, NoSoftwareFallbackOnMappableNativeInput) {
  // Make RTCVideoEncoder expect native input.
  base::CommandLine::ForCurrentProcess()->AppendSwitch(
      switches::kVideoCaptureUseGpuMemoryBuffer);

  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecH264;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  ExpectCreateInitAndDestroyVEA(
      media::PIXEL_FORMAT_NV12,
      media::VideoEncodeAccelerator::Config::StorageType::kGpuMemoryBuffer);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  rtc::scoped_refptr<webrtc::VideoFrameBuffer> mapped_buffer(
      rtc::make_ref_counted<FakeNativeBufferI420>(480, 360,
                                                  /*allow_to_i420=*/false));

  std::vector<webrtc::VideoFrameType> frame_types;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(mapped_buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
}
#endif  // BUILDFLAG(IS_WIN)

TEST_F(RTCVideoEncoderEncodeTest, SoftwareFallbackOnBadEncodeInput) {
  // Make RTCVideoEncoder expect native input.
  base::CommandLine::ForCurrentProcess()->AppendSwitch(
      switches::kVideoCaptureUseGpuMemoryBuffer);

  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  ExpectCreateInitAndDestroyVEA(
      media::PIXEL_FORMAT_NV12,
      media::VideoEncodeAccelerator::Config::StorageType::kGpuMemoryBuffer);
  ASSERT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  auto frame = media::VideoFrame::CreateBlackFrame(
      gfx::Size(kInputFrameWidth, kInputFrameHeight));
  frame->set_timestamp(base::Milliseconds(1));
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_adapter(
      new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(
          frame, base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(
                     nullptr)));
  std::vector<webrtc::VideoFrameType> frame_types;

  // The frame type check is done in media thread asynchronously. The error is
  // reported in the second Encode callback.
  base::WaitableEvent error_waiter(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  rtc_encoder_->SetErrorWaiter(&error_waiter);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(frame_adapter)
                                     .set_rtp_timestamp(1000)
                                     .set_timestamp_us(2000)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  error_waiter.Wait();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(frame_adapter)
                                     .set_rtp_timestamp(2000)
                                     .set_timestamp_us(3000)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
}

TEST_F(RTCVideoEncoderEncodeTest, EncodeScaledFrame) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  EXPECT_CALL(*mock_vea_, Encode(_, _))
      .Times(2)
      .WillRepeatedly(Invoke(this, &RTCVideoEncoderTest::VerifyEncodedFrame));

  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));

  const rtc::scoped_refptr<webrtc::I420Buffer> upscaled_buffer =
      webrtc::I420Buffer::Create(2 * kInputFrameWidth, 2 * kInputFrameHeight);
  FillFrameBuffer(upscaled_buffer);
  webrtc::VideoFrame rtc_frame = webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(upscaled_buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(123456)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(rtc_frame, &frame_types));
}

TEST_F(RTCVideoEncoderEncodeTest, PreserveTimestamps) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  const uint32_t rtp_timestamp = 1234567;
  const uint32_t capture_time_ms = 3456789;
  RegisterEncodeCompleteCallback(
      base::BindOnce(&RTCVideoEncoderTest::VerifyTimestamp,
                     base::Unretained(this), rtp_timestamp, capture_time_ms));

  EXPECT_CALL(*mock_vea_, Encode(_, _))
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::ReturnFrameWithTimeStamp));
  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types;
  webrtc::VideoFrame rtc_frame = webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(rtp_timestamp)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build();
  rtc_frame.set_timestamp_us(capture_time_ms * rtc::kNumMicrosecsPerMillisec);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(rtc_frame, &frame_types));
}

TEST_F(RTCVideoEncoderEncodeTest, AcceptsRepeatedWrappedMediaVideoFrame) {
  // Ensure encoder is accepting subsequent frames with the same timestamp in
  // the wrapped media::VideoFrame.
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  ExpectCreateInitAndDestroyVEA();
  rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings);

  auto frame = media::VideoFrame::CreateBlackFrame(
      gfx::Size(kInputFrameWidth, kInputFrameHeight));
  frame->set_timestamp(base::Milliseconds(1));
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_adapter(
      new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(
          frame, base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(
                     nullptr)));
  std::vector<webrtc::VideoFrameType> frame_types;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(frame_adapter)
                                     .set_rtp_timestamp(1000)
                                     .set_timestamp_us(2000)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(frame_adapter)
                                     .set_rtp_timestamp(2000)
                                     .set_timestamp_us(3000)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
}

TEST_F(RTCVideoEncoderEncodeTest, EncodeVP9TemporalLayer) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/1);
  CreateEncoder(tl_codec.codecType);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
  size_t kNumEncodeFrames = 5u;
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }
    base::WaitableEvent event;
    if (i > 0) {
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_)).Times(1);
    }
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(DoAll(
            Invoke(this,
                   &RTCVideoEncoderTest::ReturnSVCLayerFrameWithVp9Metadata),
            [&event]() { event.Signal(); }));
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(0)
                                       .set_timestamp_us(i)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
}

TEST_F(RTCVideoEncoderEncodeTest, EncodeWithDropFrame) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.SetFrameDropEnabled(/*enabled=*/true);
  ExpectCreateInitAndDestroyVEA(
      media::PIXEL_FORMAT_I420,
      media::VideoEncodeAccelerator::Config::StorageType::kShmem, true);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  constexpr static size_t kNumEncodeFrames = 10u;
  constexpr static size_t kDropIndices[] = {3, 4, 7};
  class DropFrameVerifier : public webrtc::EncodedImageCallback {
   public:
    DropFrameVerifier() = default;
    ~DropFrameVerifier() override = default;

    void OnDroppedFrame(DropReason reason) override {
      AddResult(EncodeResult::kDropped);
    }

    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      if (codec_specific_info->end_of_picture) {
        AddResult(EncodeResult::kEncoded);
      }
      return Result(Result::OK);
    }

    void Verify() {
      base::AutoLock auto_lock(lock_);
      ASSERT_EQ(encode_results_.size(), kNumEncodeFrames);
      for (size_t i = 0; i < kNumEncodeFrames; ++i) {
        EncodeResult expected = EncodeResult::kEncoded;
        if (base::Contains(kDropIndices, i)) {
          expected = EncodeResult::kDropped;
        }
        EXPECT_EQ(encode_results_[i], expected);
      }
    }

   private:
    enum class EncodeResult {
      kEncoded,
      kDropped,
    };

    void AddResult(EncodeResult result) {
      base::AutoLock auto_lock(lock_);
      encode_results_.push_back(result);
    }

    base::Lock lock_;
    std::vector<EncodeResult> encode_results_ GUARDED_BY(lock_);
  };

  DropFrameVerifier dropframe_verifier;
  rtc_encoder_->RegisterEncodeCompleteCallback(&dropframe_verifier);
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }
    base::WaitableEvent event;
    if (i > 0) {
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_)).Times(1);
    }
    if (base::Contains(kDropIndices, i)) {
      EXPECT_CALL(*mock_vea_, Encode)
          .WillOnce(DoAll(Invoke(this, &RTCVideoEncoderTest::DropFrame),
                          [&event]() { event.Signal(); }));
    } else {
      EXPECT_CALL(*mock_vea_, Encode)
          .WillOnce(DoAll(
              Invoke(this, &RTCVideoEncoderTest::ReturnFrameWithTimeStamp),
              [&event]() { event.Signal(); }));
    }

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(0)
                                       .set_timestamp_us(i)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
  RunUntilIdle();
  dropframe_verifier.Verify();
  rtc_encoder_.reset();
}

TEST_F(RTCVideoEncoderEncodeTest, InitializeWithTooHighBitrateFails) {
  // We expect initialization to fail. We do not want a mock video encoder, as
  // it will not be successfully attached to the rtc_encoder_. So we do not call
  // CreateEncoder, but instead CreateEncoderWithoutVea.
  constexpr webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);

  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  codec.startBitrate = std::numeric_limits<uint32_t>::max() / 100;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_ERR_PARAMETER,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

#if defined(ARCH_CPU_X86_FAMILY) && BUILDFLAG(IS_CHROMEOS_ASH)
//  Currently we only test spatial SVC encoding on CrOS since only CrOS platform
//  support spatial SVC encoding.

// http://crbug.com/1226875
TEST_F(RTCVideoEncoderEncodeTest, EncodeSpatialLayer) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  constexpr size_t kNumSpatialLayers = 3;
  webrtc::VideoCodec sl_codec =
      GetSVCLayerCodec(webrtc::kVideoCodecVP9, kNumSpatialLayers);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&sl_codec, kVideoEncoderSettings));

  constexpr size_t kNumEncodeFrames = 5u;
  class CodecSpecificVerifier : public webrtc::EncodedImageCallback {
   public:
    explicit CodecSpecificVerifier(const webrtc::VideoCodec& codec)
        : codec_(codec) {}
    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      if (encoded_image._frameType == webrtc::VideoFrameType::kVideoFrameKey) {
        EXPECT_TRUE(codec_specific_info->codecSpecific.VP9.ss_data_available);
        const size_t num_spatial_layers = codec_->VP9().numberOfSpatialLayers;
        const auto& vp9_specific = codec_specific_info->codecSpecific.VP9;
        EXPECT_EQ(vp9_specific.num_spatial_layers, num_spatial_layers);
        for (size_t i = 0; i < num_spatial_layers; ++i) {
          EXPECT_EQ(vp9_specific.width[i], codec_->spatialLayers[i].width);
          EXPECT_EQ(vp9_specific.height[i], codec_->spatialLayers[i].height);
        }
      }

      if (encoded_image.RtpTimestamp() == kNumEncodeFrames - 1 &&
          codec_specific_info->end_of_picture) {
        waiter_.Signal();
      }

      if (encoded_image.TemporalIndex().has_value()) {
        EXPECT_EQ(encoded_image.TemporalIndex(),
                  codec_specific_info->codecSpecific.VP9.temporal_idx);
      }

      return Result(Result::OK);
    }

    void Wait() { waiter_.Wait(); }

   private:
    const raw_ref<const webrtc::VideoCodec> codec_;
    base::WaitableEvent waiter_;
  };
  CodecSpecificVerifier sl_verifier(sl_codec);
  rtc_encoder_->RegisterEncodeCompleteCallback(&sl_verifier);
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0)
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    base::WaitableEvent event;
    if (i > 0) {
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_))
          .Times(kNumSpatialLayers);
    }
    EXPECT_CALL(*mock_vea_, Encode)
        .WillOnce(DoAll(
            Invoke(this,
                   &RTCVideoEncoderTest::ReturnSVCLayerFrameWithVp9Metadata),
            [&event]() { event.Signal(); }));
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
```