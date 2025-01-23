Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request is to analyze the functionality of the `rtc_video_decoder_adapter_test.cc` file within the Chromium Blink engine. The analysis needs to cover its purpose, relationship to web technologies (JavaScript, HTML, CSS), logical reasoning with inputs/outputs, and common usage errors.

2. **Initial Scan and Key Identifiers:** I start by quickly scanning the code, looking for familiar patterns and keywords:
    * `#include`: Indicates dependencies and the core purpose. Seeing `rtc_video_decoder_adapter.h` immediately tells me this file is testing that specific adapter.
    * `namespace blink`: Confirms this is within the Blink rendering engine.
    * `namespace { ... }`:  Indicates helper classes and functions used only within this test file.
    * `class ...Test : public ::testing::Test`:  This is the standard Google Test framework setup, confirming this is a test file.
    * `MockVideoDecoder`, `MockGpuVideoAcceleratorFactories`: These indicate the use of mocking for dependencies, crucial for unit testing.
    * `EXPECT_CALL`, `ASSERT_TRUE`, `ASSERT_EQ`, `FAIL`: These are Google Test assertion macros.
    * `webrtc::`, `media::`:  These namespaces point to WebRTC and Chromium media components, confirming the context.
    * `Decode`, `Initialize`, `Configure`, `Release`: These are likely methods of the class being tested.

3. **Deconstruct the Helper Classes:** The anonymous namespace contains `FakeResolutionMonitor`, `MockVideoDecoder`, `DecodedImageCallback`, and `RTCVideoDecoderAdapterWrapper`. I analyze each:
    * `FakeResolutionMonitor`: Simulates a resolution monitor, controlling whether a specific resolution is "passed." This hints at testing resolution-based logic.
    * `MockVideoDecoder`: A mock of the actual `media::VideoDecoder` interface. This is used to control the decoder's behavior during tests (success, failure, etc.). The `MOCK_METHOD` macros are key here.
    * `DecodedImageCallback`: Adapts a C++ callback to the WebRTC `DecodedImageCallback` interface. This is likely used to verify that decoded video frames are received correctly.
    * `RTCVideoDecoderAdapterWrapper`:  This is interesting. It seems to wrap the `RTCVideoDecoderAdapter` and run its methods on a separate thread (`webrtc_decoder_thread_`). This suggests asynchronous operations and the need for thread safety in the adapter. The `base::WaitableEvent` usage confirms synchronization.

4. **Analyze the Test Fixture (`RTCVideoDecoderAdapterTest`):** This class sets up the environment for the tests.
    * Member variables like `gpu_factories_`, `video_decoder_`, `sdp_format_`, and `decoded_cb_` are used to configure and interact with the adapter. The use of `StrictMock` means that any unexpected calls to the mocks will cause test failures.
    * Helper methods like `BasicSetup`, `BasicTeardown`, `CreateAndInitialize`, `InitDecode`, `Decode`, `FinishDecode`, and `Release` provide common workflows for interacting with the adapter in tests. These make the individual test cases more readable.

5. **Examine Individual Test Cases:** I go through each test case, understanding what specific aspect of the `RTCVideoDecoderAdapter` it's verifying:
    * `Create_UnknownFormat`, `Create_UnsupportedFormat`: Test how the adapter handles invalid or unsupported video formats.
    * `Lifecycle`: A basic test of creating, using, and destroying the adapter.
    * `InitializationFailure`: Checks how the adapter handles failures during decoder initialization.
    * `Decode`: Verifies basic decoding functionality.
    * `Decode_Error`: Tests error handling during decoding.
    * `Decode_Hang_Short`, `Decode_Hang_Long`: Test scenarios where the decoder might hang, leading to error or fallback.
    * `ReinitializesForHDRColorSpaceInitially`, `HandlesReinitializeFailure`, `HandlesFlushFailure`:  Focus on how the adapter manages color space changes and handles potential failures during re-initialization or flushing.
    * `DecoderCountIsIncrementedByDecode`, `FallsBackForLowResolution`, `DoesNotFailForH256LowResolution`, `DoesNotFallBackForHighResolution`: Test the logic related to managing decoder instances and falling back to software decoding based on resolution and decoder availability.
    * `DecodesImageWithSingleSpatialLayer`: Checks handling of spatial layers in video streams.
    * Tests with `BUILDFLAG(IS_WIN)` and other platform-specific flags:  Show how the adapter might behave differently on different platforms, potentially utilizing platform-specific hardware acceleration.
    * `FallbackToSWInAV1SVC`:  Tests fallback behavior for specific codecs or configurations.
    * `CanReadSharedFrameBuffer`: Verifies that the decoded video frame buffer can be accessed and processed.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**  This requires understanding the context of WebRTC and video decoding in a browser.
    * **JavaScript:**  WebRTC APIs in JavaScript (`RTCPeerConnection`, `RTCRtpReceiver`) are used to establish peer-to-peer connections and receive video streams. The `RTCVideoDecoderAdapter` is a *behind-the-scenes* component that handles the actual decoding of these streams. JavaScript would configure the codecs and potentially receive callbacks when frames are decoded (although the direct interaction is with higher-level WebRTC objects).
    * **HTML:**  The decoded video frames are ultimately displayed in an HTML `<video>` element. The `RTCVideoDecoderAdapter`'s output (video frames) is what gets rendered.
    * **CSS:** CSS can style the `<video>` element, controlling its size, position, and other visual aspects. CSS doesn't directly interact with the decoding process itself.

7. **Identify Logical Reasoning and Inputs/Outputs:** For each test case, I try to determine the "input" to the adapter (e.g., an encoded video frame, a specific configuration) and the expected "output" or behavior (e.g., a decoded video frame, a specific return code, a fallback to software decoding). The test case names and the `EXPECT_CALL` and `ASSERT_*` macros are crucial for this.

8. **Spot Potential User/Programming Errors:** This involves thinking about how a developer might misuse the `RTCVideoDecoderAdapter` or the surrounding WebRTC APIs. Examples include:
    * Not handling decoder initialization failures.
    * Sending data in an incorrect format.
    * Not registering a decode complete callback.
    * Releasing resources prematurely.

9. **Structure the Analysis:**  Finally, I organize the gathered information into a clear and structured format, using headings and bullet points as in the example answer. This makes the analysis easy to read and understand. I ensure I cover all the points requested in the original prompt.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this test file directly tests interactions with the GPU. **Correction:** The presence of `MockGpuVideoAcceleratorFactories` suggests that the *interface* with the GPU is being tested, but the actual GPU interaction is likely mocked out for unit testing purposes.
* **Initial thought:**  How does the threading in `RTCVideoDecoderAdapterWrapper` affect the tests? **Refinement:** Realize that the `WaitableEvent` is crucial for synchronizing the test thread with the `webrtc_decoder_thread_`, making the tests deterministic.
* **Realization:** The different test cases cover various error conditions and edge cases, demonstrating good testing practices.

By following this systematic approach, combining code analysis with domain knowledge (WebRTC, video decoding, testing frameworks), and performing some self-correction, I can generate a comprehensive and accurate analysis of the given C++ test file.
这个文件 `rtc_video_decoder_adapter_test.cc` 是 Chromium Blink 引擎中用于测试 `RTCVideoDecoderAdapter` 类的单元测试代码。`RTCVideoDecoderAdapter` 的作用是作为 WebRTC 的 `webrtc::VideoDecoder` 接口和 Chromium 的 `media::VideoDecoder` 接口之间的适配器。

**主要功能:**

1. **测试 `RTCVideoDecoderAdapter` 的创建和初始化:**  测试在不同的视频格式下，`RTCVideoDecoderAdapter` 是否能够正确创建和初始化底层的 `media::VideoDecoder`。这包括对支持的和不支持的格式的测试。
2. **测试解码流程:** 模拟 WebRTC 的解码过程，包括配置解码器 (`Configure`)、注册解码完成回调 (`RegisterDecodeCompleteCallback`)、提交解码数据 (`Decode`) 和释放资源 (`Release`)。测试在正常解码和发生错误时的行为。
3. **测试错误处理:**  模拟底层 `media::VideoDecoder` 返回错误的情况，验证 `RTCVideoDecoderAdapter` 是否能够正确处理这些错误，例如返回 `WEBRTC_VIDEO_CODEC_ERROR` 或触发软件解码回退 (`WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE`)。
4. **测试解码器挂起的情况:** 模拟底层解码器长时间没有响应的情况，验证 `RTCVideoDecoderAdapter` 是否能够检测到并采取相应的措施，例如触发软件解码回退。
5. **测试颜色空间处理:** 验证当接收到带有 HDR 颜色空间信息的视频帧时，`RTCVideoDecoderAdapter` 是否能够触发底层解码器的重新初始化，以适应新的颜色空间。同时测试重新初始化失败的情况。
6. **测试解码器实例计数:** 验证 `RTCVideoDecoderAdapter` 是否会跟踪当前正在使用的解码器实例数量，并根据这个数量来决定是否应该回退到软件解码，尤其是在低分辨率情况下。
7. **测试空间分层 (Spatial Layers) 解码:** 验证 `RTCVideoDecoderAdapter` 在处理具有空间分层的视频流时的行为，例如，检查解码后的 `media::DecoderBuffer` 是否正确设置了空间分层信息。
8. **测试硬件加速解码:**  针对特定平台（例如 Windows 使用 D3D11）测试硬件加速解码器的使用。模拟硬件解码成功和硬件解码不可用时回退到软件解码的情况。
9. **测试 AV1 SVC (Scalable Video Coding):** 验证在 AV1 SVC 场景下，由于硬件解码支持可能不足，`RTCVideoDecoderAdapter` 是否会正确回退到软件解码。
10. **测试共享帧缓冲区:** 验证解码后的帧缓冲区是否可以被其他线程安全地读取。

**与 JavaScript, HTML, CSS 的功能关系:**

`rtc_video_decoder_adapter_test.cc` 文件本身是用 C++ 编写的，不直接包含 JavaScript、HTML 或 CSS 代码。但是，它测试的 `RTCVideoDecoderAdapter` 类在 WebRTC 的上下文中扮演着关键角色，最终影响到网页上的视频播放功能。

* **JavaScript:** JavaScript 代码通过 WebRTC API (例如 `RTCPeerConnection`) 来建立音视频通信。当接收到视频流时，浏览器会使用底层的视频解码器来解码视频帧。`RTCVideoDecoderAdapter` 负责将 WebRTC 的解码请求适配到 Chromium 的媒体框架，从而使用到合适的硬件或软件解码器。JavaScript 代码不需要直接与 `RTCVideoDecoderAdapter` 交互，但其行为直接影响到 JavaScript 通过 WebRTC 接收到的视频数据的可用性和质量。

   **举例说明:**
   ```javascript
   // JavaScript 代码
   const peerConnection = new RTCPeerConnection();
   peerConnection.ontrack = (event) => {
     if (event.track.kind === 'video') {
       const remoteStream = event.streams[0];
       const videoElement = document.getElementById('remoteVideo');
       videoElement.srcObject = remoteStream;
     }
   };
   // ... (其他 WebRTC 信令代码)
   ```
   在这个例子中，当 `peerConnection` 接收到视频 track 时，浏览器内部会使用 `RTCVideoDecoderAdapter` 来解码接收到的视频数据，然后将解码后的帧数据提供给 `<video>` 元素进行渲染。如果 `RTCVideoDecoderAdapter` 工作不正常，`ontrack` 事件中接收到的视频流可能无法正确解码并显示。

* **HTML:** HTML 提供了 `<video>` 元素，用于在网页上显示视频。`RTCVideoDecoderAdapter` 解码后的视频帧最终会渲染到这个 `<video>` 元素中。

   **举例说明:**
   ```html
   <!-- HTML 代码 -->
   <video id="remoteVideo" autoplay playsinline></video>
   ```
   `RTCVideoDecoderAdapter` 的正确性直接影响到这个 `<video>` 元素能否成功播放远程视频流。

* **CSS:** CSS 用于样式化 HTML 元素，包括 `<video>` 元素。CSS 可以控制视频的尺寸、边框、定位等视觉效果，但它不参与视频的解码过程。`RTCVideoDecoderAdapter` 的功能与 CSS 无直接关系。

**逻辑推理和假设输入/输出:**

以下是一些测试用例中的逻辑推理和假设输入/输出示例：

**示例 1: 测试解码成功**

* **假设输入:**
    * 已创建并初始化 `RTCVideoDecoderAdapter`。
    * 注册了解码完成回调。
    * 提交了一个关键帧的编码数据 (`Decode(0)`)。
* **逻辑推理:**
    * `RTCVideoDecoderAdapter` 应该调用底层 `media::VideoDecoder` 的 `Decode_` 方法。
    * 底层解码器模拟解码成功 (`base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kOk)`).
    * `RTCVideoDecoderAdapter` 应该在媒体线程上完成解码 (`FinishDecode(0)`).
    * 解码完成后，注册的回调函数 (`decoded_cb_`) 应该被调用，并接收到解码后的 `webrtc::VideoFrame`。
* **预期输出:**
    * `Decode(0)` 返回 `WEBRTC_VIDEO_CODEC_OK`。
    * `decoded_cb_` 被调用。

**示例 2: 测试解码错误导致回退**

* **假设输入:**
    * 已创建并初始化 `RTCVideoDecoderAdapter`。
    * 注册了解码完成回调。
    * 提交了一个关键帧的编码数据 (`Decode(0)`)。
    * 底层解码器模拟解码失败 (`base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kFailed)`).
    * 提交了后续的非关键帧编码数据 (`Decode(1)`).
* **逻辑推理:**
    * 第一个 `Decode(0)` 调用底层解码器，但解码失败。
    * 第二个 `Decode(1)` 会因为之前的解码错误，`RTCVideoDecoderAdapter` 判断需要回退到软件解码。
* **预期输出:**
    * `Decode(0)` 返回 `WEBRTC_VIDEO_CODEC_OK` (解码请求已发送，但不保证成功)。
    * `Decode(1)` 返回 `WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE`。

**示例 3: 测试低分辨率时回退到软件解码**

* **假设输入:**
    * 已创建并初始化 `RTCVideoDecoderAdapter`，并且 `FakeResolutionMonitor` 返回一个低分辨率 (例如 1x1)。
    * 当前已经有一定数量的解码器实例在运行 (`IncrementCurrentDecoderCount()` 被多次调用)。
    * 提交了一个编码数据 (`Decode(0)`)。
* **逻辑推理:**
    * `RTCVideoDecoderAdapter` 会检查当前解码器实例数量和当前视频的分辨率。
    * 如果解码器实例数量超过阈值，并且分辨率较低，则会决定回退到软件解码。
    * 底层硬件解码器不会被调用。
* **预期输出:**
    * `Decode(0)` 返回 `WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE`。
    * 对底层 `video_decoder_` 的 `Decode_` 方法不会被调用 (`EXPECT_CALL(*video_decoder_, Decode_(_, _)).Times(0)`).

**用户或编程常见的使用错误:**

虽然用户通常不直接与 `RTCVideoDecoderAdapter` 交互，但编程错误可能发生在 WebRTC 引擎的开发或集成过程中。以下是一些可能与 `RTCVideoDecoderAdapter` 相关的潜在错误：

1. **底层解码器初始化失败未处理:** 如果底层 `media::VideoDecoder` 初始化失败，`RTCVideoDecoderAdapter` 应该能够处理这种情况并可能触发软件解码回退。如果开发者没有正确处理初始化失败的情况，可能导致程序崩溃或视频播放失败。测试用例 `InitializationFailure` 就是为了验证这种情况。
2. **在不兼容的格式下使用解码器:** 尝试使用硬件解码器解码不支持的视频格式。`RTCVideoDecoderAdapter` 应该能够检测到这种情况并回退到软件解码。如果开发者没有考虑到格式兼容性，可能会导致解码失败。测试用例 `Create_UnknownFormat` 和 `Create_UnsupportedFormat` 覆盖了这种情况。
3. **没有正确处理解码错误:**  如果底层解码器返回错误，`RTCVideoDecoderAdapter` 需要正确处理这些错误，并可能通知上层应用或触发重试机制。如果错误处理不当，可能会导致视频播放中断或卡顿。测试用例 `Decode_Error` 验证了错误处理逻辑。
4. **资源泄漏:**  如果在不再需要解码器时没有调用 `Release` 方法释放资源，可能会导致资源泄漏。虽然测试文件中没有直接模拟资源泄漏，但 `Lifecycle` 测试用例确保了 `Release` 方法的正常工作。
5. **在多线程环境下使用不当:**  `RTCVideoDecoderAdapter` 需要在多线程环境下安全地工作。如果对其状态的访问没有进行适当的同步，可能会导致数据竞争和其他并发问题。`RTCVideoDecoderAdapterWrapper` 的使用和线程相关的测试用例旨在验证其线程安全性。

总而言之，`rtc_video_decoder_adapter_test.cc` 是一个关键的测试文件，用于确保 `RTCVideoDecoderAdapter` 能够正确地将 WebRTC 的视频解码需求适配到 Chromium 的媒体框架，处理各种正常和异常情况，并保证视频解码的稳定性和可靠性，最终影响到用户在网页上使用 WebRTC 进行视频通信的体验。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_decoder_adapter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/peerconnection/rtc_video_decoder_adapter.h"

#include <stdint.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/mock_callback.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "gpu/command_buffer/common/mailbox.h"
#include "media/base/decoder_status.h"
#include "media/base/media_switches.h"
#include "media/base/media_util.h"
#include "media/base/video_decoder.h"
#include "media/base/video_decoder_config.h"
#include "media/base/video_frame.h"
#include "media/base/video_types.h"
#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/peerconnection/resolution_monitor.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_utils.h"
#include "third_party/webrtc/api/video_codecs/video_codec.h"
#include "third_party/webrtc/api/video_codecs/vp9_profile.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

namespace blink {

namespace {

class FakeResolutionMonitor : public ResolutionMonitor {
 public:
  explicit FakeResolutionMonitor(bool pass_resolution_monitor,
                                 const webrtc::SdpVideoFormat& format)
      : pass_resolution_monitor_(pass_resolution_monitor),
        codec_(WebRtcToMediaVideoCodec(
            webrtc::PayloadStringToCodecType(format.name))) {}
  ~FakeResolutionMonitor() override = default;

  std::optional<gfx::Size> GetResolution(
      const media::DecoderBuffer& buffer) override {
    if (pass_resolution_monitor_) {
      return gfx::Size(1280, 720);
    } else {
      return gfx::Size(1, 1);
    }
  }
  media::VideoCodec codec() const override { return codec_; }

 private:
  const bool pass_resolution_monitor_;
  const media::VideoCodec codec_;
};

class MockVideoDecoder : public media::VideoDecoder {
 public:
  MockVideoDecoder()
      : current_decoder_type_(media::VideoDecoderType::kTesting) {}

  media::VideoDecoderType GetDecoderType() const override {
    return current_decoder_type_;
  }
  void Initialize(const media::VideoDecoderConfig& config,
                  bool low_delay,
                  media::CdmContext* cdm_context,
                  InitCB init_cb,
                  const OutputCB& output_cb,
                  const media::WaitingCB& waiting_cb) override {
    Initialize_(config, low_delay, cdm_context, init_cb, output_cb, waiting_cb);
  }
  MOCK_METHOD6(Initialize_,
               void(const media::VideoDecoderConfig& config,
                    bool low_delay,
                    media::CdmContext* cdm_context,
                    InitCB& init_cb,
                    const OutputCB& output_cb,
                    const media::WaitingCB& waiting_cb));
  void Decode(scoped_refptr<media::DecoderBuffer> buffer,
              DecodeCB cb) override {
    Decode_(std::move(buffer), cb);
  }
  MOCK_METHOD2(Decode_,
               void(scoped_refptr<media::DecoderBuffer> buffer, DecodeCB&));
  void Reset(base::OnceClosure cb) override { Reset_(cb); }
  MOCK_METHOD1(Reset_, void(base::OnceClosure&));
  bool NeedsBitstreamConversion() const override { return false; }
  bool CanReadWithoutStalling() const override { return true; }
  int GetMaxDecodeRequests() const override { return 1; }
  // We can set the type of decoder we want, the default value is kTesting.
  void SetDecoderType(media::VideoDecoderType expected_decoder_type) {
    current_decoder_type_ = expected_decoder_type;
  }

 private:
  media::VideoDecoderType current_decoder_type_;
};

// Wraps a callback as a webrtc::DecodedImageCallback.
class DecodedImageCallback : public webrtc::DecodedImageCallback {
 public:
  DecodedImageCallback(
      base::RepeatingCallback<void(const webrtc::VideoFrame&)> callback)
      : callback_(callback) {}
  DecodedImageCallback(const DecodedImageCallback&) = delete;
  DecodedImageCallback& operator=(const DecodedImageCallback&) = delete;

  int32_t Decoded(webrtc::VideoFrame& decodedImage) override {
    callback_.Run(decodedImage);
    // TODO(sandersd): Does the return value matter? RTCVideoDecoder
    // ignores it.
    return 0;
  }

 private:
  base::RepeatingCallback<void(const webrtc::VideoFrame&)> callback_;
};

class RTCVideoDecoderAdapterWrapper : public webrtc::VideoDecoder {
 public:
  static std::unique_ptr<RTCVideoDecoderAdapterWrapper> Create(
      media::GpuVideoAcceleratorFactories* gpu_factories,
      const webrtc::SdpVideoFormat& format,
      bool pass_resolution_monitor) {
    auto wrapper = base::WrapUnique(new RTCVideoDecoderAdapterWrapper);
    bool result = false;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    wrapper->task_runner_->PostTask(
        FROM_HERE, base::BindOnce(
                       [](std::unique_ptr<RTCVideoDecoderAdapter>*
                              rtc_video_decoder_adapter,
                          media::GpuVideoAcceleratorFactories* gpu_factories,
                          const webrtc::SdpVideoFormat& format,
                          bool pass_resolution_monitor,
                          base::WaitableEvent* waiter, bool* result) {
                         *rtc_video_decoder_adapter =
                             RTCVideoDecoderAdapter::Create(
                                 gpu_factories, format,
                                 std::make_unique<FakeResolutionMonitor>(
                                     pass_resolution_monitor, format));
                         *result = !!(*rtc_video_decoder_adapter);
                         waiter->Signal();
                       },
                       &wrapper->rtc_video_decoder_adapter_, gpu_factories,
                       format, pass_resolution_monitor, &waiter, &result));
    waiter.Wait();
    return result ? std::move(wrapper) : nullptr;
  }

  bool Configure(const webrtc::VideoDecoder::Settings& settings) override {
    int32_t result = false;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](RTCVideoDecoderAdapter* rtc_video_decoder_adapter,
               webrtc::VideoDecoder::Settings settings,
               base::WaitableEvent* waiter, int32_t* result) {
              *result = rtc_video_decoder_adapter->Configure(settings);
              waiter->Signal();
            },
            rtc_video_decoder_adapter_.get(), settings, &waiter, &result));
    waiter.Wait();
    return result;
  }

  int32_t RegisterDecodeCompleteCallback(
      webrtc::DecodedImageCallback* callback) override {
    int32_t result = false;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](RTCVideoDecoderAdapter* rtc_video_decoder_adapter,
               webrtc::DecodedImageCallback* callback,
               base::WaitableEvent* waiter, int32_t* result) {
              *result =
                  rtc_video_decoder_adapter->RegisterDecodeCompleteCallback(
                      callback);
              waiter->Signal();
            },
            rtc_video_decoder_adapter_.get(), callback, &waiter, &result));
    waiter.Wait();
    return result;
  }
  int32_t Decode(const webrtc::EncodedImage& input_image,
                 bool missing_frames,
                 int64_t render_time_ms) override {
    int32_t result = false;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(
                       [](RTCVideoDecoderAdapter* rtc_video_decoder_adapter,
                          const webrtc::EncodedImage& input_image,
                          bool missing_frames, int64_t render_time_ms,
                          base::WaitableEvent* waiter, int32_t* result) {
                         *result = rtc_video_decoder_adapter->Decode(
                             input_image, missing_frames, render_time_ms);
                         waiter->Signal();
                       },
                       rtc_video_decoder_adapter_.get(), input_image,
                       missing_frames, render_time_ms, &waiter, &result));
    waiter.Wait();
    return result;
  }

  int32_t Release() override {
    int32_t result = false;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(
                       [](RTCVideoDecoderAdapter* rtc_video_decoder_adapter,
                          base::WaitableEvent* waiter, int32_t* result) {
                         *result = rtc_video_decoder_adapter->Release();
                         waiter->Signal();
                       },
                       rtc_video_decoder_adapter_.get(), &waiter, &result));
    waiter.Wait();
    return result;
  }

  ~RTCVideoDecoderAdapterWrapper() override {
    if (task_runner_) {
      task_runner_->DeleteSoon(FROM_HERE,
                               std::move(rtc_video_decoder_adapter_));
    }
    webrtc_decoder_thread_.FlushForTesting();
  }

 private:
  RTCVideoDecoderAdapterWrapper()
      : webrtc_decoder_thread_("WebRTC decoder thread") {
    webrtc_decoder_thread_.Start();
    task_runner_ = webrtc_decoder_thread_.task_runner();
  }

  base::Thread webrtc_decoder_thread_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // webrtc_decoder_thread_ members.
  std::unique_ptr<RTCVideoDecoderAdapter> rtc_video_decoder_adapter_;
};

}  // namespace

class RTCVideoDecoderAdapterTest : public ::testing::Test {
 public:
  RTCVideoDecoderAdapterTest(const RTCVideoDecoderAdapterTest&) = delete;
  RTCVideoDecoderAdapterTest& operator=(const RTCVideoDecoderAdapterTest&) =
      delete;
  RTCVideoDecoderAdapterTest()
      : media_thread_("Media Thread"),
        gpu_factories_(nullptr),
        sdp_format_(webrtc::SdpVideoFormat(
            webrtc::CodecTypeToPayloadString(webrtc::kVideoCodecVP9))),
        decoded_image_callback_(decoded_cb_.Get()),
        spatial_index_(0) {
    media_thread_.Start();

    owned_video_decoder_ = std::make_unique<StrictMock<MockVideoDecoder>>();
    video_decoder_ = owned_video_decoder_.get();

    ON_CALL(gpu_factories_, GetTaskRunner())
        .WillByDefault(Return(media_thread_.task_runner()));
    EXPECT_CALL(gpu_factories_, GetTaskRunner()).Times(AtLeast(0));

    ON_CALL(gpu_factories_, IsDecoderConfigSupported(_))
        .WillByDefault(
            Return(media::GpuVideoAcceleratorFactories::Supported::kTrue));
    EXPECT_CALL(gpu_factories_, IsDecoderConfigSupported(_)).Times(AtLeast(0));

    ON_CALL(gpu_factories_, CreateVideoDecoder(_, _))
        .WillByDefault(
            [this](media::MediaLog* media_log,
                   const media::RequestOverlayInfoCB& request_overlay_info_cb) {
              // If gpu factories tries to get a second video decoder, for
              // testing purposes we will just return null.
              // RTCVideoDecodeAdapter already handles the case where the
              // decoder is null.
              return std::move(owned_video_decoder_);
            });
    EXPECT_CALL(gpu_factories_, CreateVideoDecoder(_, _)).Times(AtLeast(0));
    std::vector<base::test::FeatureRef> enable_features;
#if BUILDFLAG(IS_WIN)
    enable_features.emplace_back(::media::kD3D11Vp9kSVCHWDecoding);
#endif
    if (!enable_features.empty())
      feature_list_.InitWithFeatures(enable_features, {});
  }

  ~RTCVideoDecoderAdapterTest() override {
    adapter_wrapper_.reset();
    media_thread_.FlushForTesting();
  }

 protected:
  bool BasicSetup() {
    if (!CreateAndInitialize())
      return false;
    if (!InitDecode())
      return false;
    if (RegisterDecodeCompleteCallback() != WEBRTC_VIDEO_CODEC_OK)
      return false;
    return true;
  }

  bool BasicTeardown() {
    if (Release() != WEBRTC_VIDEO_CODEC_OK)
      return false;
    return true;
  }

  bool CreateAndInitialize(bool init_cb_result = true,
                           bool pass_resolution_monitor = true) {
    EXPECT_CALL(*video_decoder_, Initialize_(_, _, _, _, _, _))
        .WillOnce(
            DoAll(SaveArg<0>(&vda_config_), SaveArg<4>(&output_cb_),
                  base::test::RunOnceCallback<3>(
                      init_cb_result ? media::DecoderStatus::Codes::kOk
                                     : media::DecoderStatus::Codes::kFailed)));

    adapter_wrapper_ = RTCVideoDecoderAdapterWrapper::Create(
        &gpu_factories_, sdp_format_, pass_resolution_monitor);
    return !!adapter_wrapper_;
  }

  bool InitDecode() {
    webrtc::VideoDecoder::Settings settings;
    settings.set_codec_type(webrtc::kVideoCodecVP9);
    return adapter_wrapper_->Configure(settings);
  }

  int32_t RegisterDecodeCompleteCallback() {
    return adapter_wrapper_->RegisterDecodeCompleteCallback(
        &decoded_image_callback_);
  }

  int32_t Decode(uint32_t timestamp, bool keyframe = true) {
    webrtc::EncodedImage input_image;
    static const uint8_t data[1] = {0};
    input_image.SetSpatialIndex(spatial_index_);
    for (int i = 0; i <= spatial_index_; i++)
      input_image.SetSpatialLayerFrameSize(i, 4);
    input_image.SetEncodedData(
        webrtc::EncodedImageBuffer::Create(data, sizeof(data)));
    if (timestamp == 0 || keyframe) {
      input_image._frameType = webrtc::VideoFrameType::kVideoFrameKey;
    } else {
      input_image._frameType = webrtc::VideoFrameType::kVideoFrameDelta;
    }
    input_image.SetRtpTimestamp(timestamp);
    return adapter_wrapper_->Decode(input_image, false, 0);
  }

  void FinishDecode(uint32_t timestamp) {
    media_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&RTCVideoDecoderAdapterTest::FinishDecodeOnMediaThread,
                       base::Unretained(this), timestamp));
  }

  void FinishDecodeOnMediaThread(uint32_t timestamp) {
    DCHECK(media_thread_.task_runner()->BelongsToCurrentThread());
    scoped_refptr<gpu::ClientSharedImage> shared_image =
        gpu::ClientSharedImage::CreateForTesting();
    scoped_refptr<media::VideoFrame> frame = media::VideoFrame::WrapSharedImage(
        media::PIXEL_FORMAT_ARGB, shared_image, gpu::SyncToken(),
        media::VideoFrame::ReleaseMailboxCB(), gfx::Size(640, 360),
        gfx::Rect(640, 360), gfx::Size(640, 360),
        base::Microseconds(timestamp));
    output_cb_.Run(std::move(frame));
  }

  int32_t Release() { return adapter_wrapper_->Release(); }

  webrtc::EncodedImage GetEncodedImageWithColorSpace(uint32_t timestamp) {
    webrtc::EncodedImage input_image;
    static const uint8_t data[1] = {0};
    input_image.SetEncodedData(
        webrtc::EncodedImageBuffer::Create(data, sizeof(data)));
    input_image._frameType = webrtc::VideoFrameType::kVideoFrameKey;
    input_image.SetRtpTimestamp(timestamp);
    webrtc::ColorSpace webrtc_color_space;
    webrtc_color_space.set_primaries_from_uint8(1);
    webrtc_color_space.set_transfer_from_uint8(1);
    webrtc_color_space.set_matrix_from_uint8(1);
    webrtc_color_space.set_range_from_uint8(1);
    input_image.SetColorSpace(webrtc_color_space);
    return input_image;
  }

  webrtc::EncodedImage GetEncodedImageWithSingleSpatialLayer(
      uint32_t timestamp) {
    constexpr int kSpatialIndex = 1;
    webrtc::EncodedImage input_image;
    static const uint8_t data[1] = {0};
    input_image.SetEncodedData(
        webrtc::EncodedImageBuffer::Create(data, sizeof(data)));
    input_image._frameType = webrtc::VideoFrameType::kVideoFrameKey;
    input_image.SetRtpTimestamp(timestamp);
    // Input image only has 1 spatial layer, but non-zero spatial index.
    input_image.SetSpatialIndex(kSpatialIndex);
    input_image.SetSpatialLayerFrameSize(kSpatialIndex, sizeof(data));
    return input_image;
  }

  int GetCurrentDecoderCount() {
    int cnt = 0;
    base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                               base::WaitableEvent::InitialState::NOT_SIGNALED);
    media_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](base::WaitableEvent* waiter, int32_t* result) {
              *result =
                  RTCVideoDecoderAdapter::GetCurrentDecoderCountForTesting();
              waiter->Signal();
            },
            &waiter, &cnt));
    waiter.Wait();
    return cnt;
  }

  void IncrementCurrentDecoderCount() {
    media_thread_.task_runner()->PostTask(
        FROM_HERE, base::BindOnce([]() {
          RTCVideoDecoderAdapter::IncrementCurrentDecoderCountForTesting();
        }));
    media_thread_.FlushForTesting();
  }
  void DecrementCurrentDecoderCount() {
    media_thread_.task_runner()->PostTask(
        FROM_HERE, base::BindOnce([]() {
          RTCVideoDecoderAdapter::DecrementCurrentDecoderCountForTesting();
        }));
    media_thread_.FlushForTesting();
  }

  void SetSdpFormat(const webrtc::SdpVideoFormat& sdp_format) {
    sdp_format_ = sdp_format;
  }

  // We can set the spatial index we want, the default value is 0.
  void SetSpatialIndex(int spatial_index) { spatial_index_ = spatial_index; }

  base::test::TaskEnvironment task_environment_;
  base::Thread media_thread_;

  // Owned by |rtc_video_decoder_adapter_|.
  raw_ptr<StrictMock<MockVideoDecoder>, DanglingUntriaged> video_decoder_ =
      nullptr;

  StrictMock<base::MockCallback<
      base::RepeatingCallback<void(const webrtc::VideoFrame&)>>>
      decoded_cb_;

  StrictMock<media::MockGpuVideoAcceleratorFactories> gpu_factories_;
  media::VideoDecoderConfig vda_config_;
  std::unique_ptr<RTCVideoDecoderAdapterWrapper> adapter_wrapper_;

 private:
  webrtc::SdpVideoFormat sdp_format_;
  std::unique_ptr<StrictMock<MockVideoDecoder>> owned_video_decoder_;
  DecodedImageCallback decoded_image_callback_;
  media::VideoDecoder::OutputCB output_cb_;
  base::test::ScopedFeatureList feature_list_;
  int spatial_index_;
};

TEST_F(RTCVideoDecoderAdapterTest, Create_UnknownFormat) {
  ASSERT_FALSE(RTCVideoDecoderAdapterWrapper::Create(
      &gpu_factories_,
      webrtc::SdpVideoFormat(
          webrtc::CodecTypeToPayloadString(webrtc::kVideoCodecGeneric)),
      /*pass_resolution_monitor=*/true));
}

TEST_F(RTCVideoDecoderAdapterTest, Create_UnsupportedFormat) {
  EXPECT_CALL(gpu_factories_, IsDecoderConfigSupported(_))
      .WillRepeatedly(
          Return(media::GpuVideoAcceleratorFactories::Supported::kFalse));
  ASSERT_FALSE(RTCVideoDecoderAdapterWrapper::Create(
      &gpu_factories_,
      webrtc::SdpVideoFormat(
          webrtc::CodecTypeToPayloadString(webrtc::kVideoCodecVP9)),
      /*pass_resolution_monitor=*/true));
}

TEST_F(RTCVideoDecoderAdapterTest, Lifecycle) {
  ASSERT_TRUE(BasicSetup());
  ASSERT_TRUE(BasicTeardown());
}

TEST_F(RTCVideoDecoderAdapterTest, InitializationFailure) {
  ASSERT_FALSE(CreateAndInitialize(false));
}

TEST_F(RTCVideoDecoderAdapterTest, Decode) {
  ASSERT_TRUE(BasicSetup());

  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .WillOnce(
          base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kOk));

  ASSERT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_OK);

  EXPECT_CALL(decoded_cb_, Run(_));
  FinishDecode(0);
  media_thread_.FlushForTesting();
}

TEST_F(RTCVideoDecoderAdapterTest, Decode_Error) {
  ASSERT_TRUE(BasicSetup());

  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .WillOnce(
          base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kFailed));

  ASSERT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_OK);
  media_thread_.FlushForTesting();

  ASSERT_EQ(Decode(1), WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);
}

TEST_F(RTCVideoDecoderAdapterTest, Decode_Hang_Short) {
  ASSERT_TRUE(BasicSetup());

  // Ignore Decode() calls.
  EXPECT_CALL(*video_decoder_, Decode_(_, _)).Times(AtLeast(1));

  for (int counter = 0; counter < 11; counter++) {
    // At the ten-th frame, EnqueueBuffer() notifies kErrorRequestKeyFrame for
    // DecodeInternal(). It checks if the frame is keyframe on 11-th frame. If
    // the frame is the keyframe, Decode() doesn't return
    // WEBRTC_VIDEO_CODEC_ERROR. This sets |keyframe|=false so that Decode()
    // returns WEBRTC_VIDEO_CODEC_ERROR.
    int32_t result = Decode(counter, /*keyframe=*/false);
    if (result == WEBRTC_VIDEO_CODEC_ERROR) {
      ASSERT_GT(counter, 2);
      return;
    }
    media_thread_.FlushForTesting();
  }

  FAIL();
}

TEST_F(RTCVideoDecoderAdapterTest, Decode_Hang_Long) {
  ASSERT_TRUE(BasicSetup());

  // Ignore Decode() calls.
  EXPECT_CALL(*video_decoder_, Decode_(_, _)).Times(AtLeast(1));

  for (int counter = 0; counter < 100; counter++) {
    int32_t result = Decode(counter);
    if (result == WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE) {
      ASSERT_GT(counter, 10);
      return;
    }
    media_thread_.FlushForTesting();
  }

  FAIL();
}

TEST_F(RTCVideoDecoderAdapterTest, ReinitializesForHDRColorSpaceInitially) {
  SetSdpFormat(webrtc::SdpVideoFormat(
      "VP9", {{webrtc::kVP9FmtpProfileId,
               webrtc::VP9ProfileToString(webrtc::VP9Profile::kProfile2)}}));
  ASSERT_TRUE(BasicSetup());
  EXPECT_EQ(media::VP9PROFILE_PROFILE2, vda_config_.profile());
  EXPECT_FALSE(vda_config_.color_space_info().IsSpecified());

  // Decode() is expected to be called for EOS flush as well.
  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .Times(3)
      .WillRepeatedly(base::test::RunOnceCallbackRepeatedly<1>(
          media::DecoderStatus::Codes::kOk));
  EXPECT_CALL(decoded_cb_, Run(_)).Times(2);

  // First Decode() should cause a reinitialize as new color space is given.
  EXPECT_CALL(*video_decoder_, Initialize_(_, _, _, _, _, _))
      .WillOnce(DoAll(
          SaveArg<0>(&vda_config_),
          base::test::RunOnceCallback<3>(media::DecoderStatus::Codes::kOk)));
  webrtc::EncodedImage first_input_image = GetEncodedImageWithColorSpace(0);
  ASSERT_EQ(adapter_wrapper_->Decode(first_input_image, false, 0),
            WEBRTC_VIDEO_CODEC_OK);
  media_thread_.FlushForTesting();
  EXPECT_TRUE(vda_config_.color_space_info().IsSpecified());
  FinishDecode(0);
  media_thread_.FlushForTesting();

  // Second Decode() with same params should happen normally.
  webrtc::EncodedImage second_input_image = GetEncodedImageWithColorSpace(1);
  ASSERT_EQ(adapter_wrapper_->Decode(second_input_image, false, 0),
            WEBRTC_VIDEO_CODEC_OK);
  FinishDecode(1);
  media_thread_.FlushForTesting();
}

TEST_F(RTCVideoDecoderAdapterTest, HandlesReinitializeFailure) {
  SetSdpFormat(webrtc::SdpVideoFormat(
      "VP9", {{webrtc::kVP9FmtpProfileId,
               webrtc::VP9ProfileToString(webrtc::VP9Profile::kProfile2)}}));
  ASSERT_TRUE(BasicSetup());
  EXPECT_EQ(media::VP9PROFILE_PROFILE2, vda_config_.profile());
  EXPECT_FALSE(vda_config_.color_space_info().IsSpecified());
  webrtc::EncodedImage input_image = GetEncodedImageWithColorSpace(0);

  // Decode() is expected to be called for EOS flush as well.
  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .WillOnce(
          base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kOk));

  // Set Initialize() to fail.
  EXPECT_CALL(*video_decoder_, Initialize_(_, _, _, _, _, _))
      .WillOnce(
          base::test::RunOnceCallback<3>(media::DecoderStatus::Codes::kFailed));
  ASSERT_EQ(adapter_wrapper_->Decode(input_image, false, 0),
            WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);
}

TEST_F(RTCVideoDecoderAdapterTest, HandlesFlushFailure) {
  SetSdpFormat(webrtc::SdpVideoFormat(
      "VP9", {{webrtc::kVP9FmtpProfileId,
               webrtc::VP9ProfileToString(webrtc::VP9Profile::kProfile2)}}));
  ASSERT_TRUE(BasicSetup());
  EXPECT_EQ(media::VP9PROFILE_PROFILE2, vda_config_.profile());
  EXPECT_FALSE(vda_config_.color_space_info().IsSpecified());
  webrtc::EncodedImage input_image = GetEncodedImageWithColorSpace(0);

  // Decode() is expected to be called for EOS flush, set to fail.
  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .WillOnce(base::test::RunOnceCallback<1>(
          media::DecoderStatus::Codes::kAborted));
  ASSERT_EQ(adapter_wrapper_->Decode(input_image, false, 0),
            WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);
}

TEST_F(RTCVideoDecoderAdapterTest, DecoderCountIsIncrementedByDecode) {
  // If the count is nonzero, then fail immediately -- the test isn't sane.
  ASSERT_EQ(GetCurrentDecoderCount(), 0);

  // Creating a decoder should not increment the count, since we haven't sent
  // anything to decode.
  ASSERT_TRUE(CreateAndInitialize(true));
  EXPECT_EQ(GetCurrentDecoderCount(), 0);

  // The first decode should increment the count.
  EXPECT_CALL(*video_decoder_, Decode_)
      .WillOnce(
          base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kOk));
  EXPECT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_OK);
  media_thread_.FlushForTesting();
  EXPECT_EQ(GetCurrentDecoderCount(), 1);

  // Make sure that it goes back to zero.
  EXPECT_EQ(GetCurrentDecoderCount(), 1);
  adapter_wrapper_.reset();
  media_thread_.FlushForTesting();
  EXPECT_EQ(GetCurrentDecoderCount(), 0);
}

TEST_F(RTCVideoDecoderAdapterTest, FallsBackForLowResolution) {
  // Make sure that low-resolution decoders fall back if there are too many.
  webrtc::VideoDecoder::Settings decoder_settings;
  decoder_settings.set_codec_type(webrtc::kVideoCodecVP9);

  // Pretend that we have many decoders already.
  for (int i = 0; i < RTCVideoDecoderAdapter::kMaxDecoderInstances; i++)
    IncrementCurrentDecoderCount();

  // Creating a decoder should not increment the count, since we haven't sent
  // anything to decode.
  ASSERT_TRUE(CreateAndInitialize(true, false));
  EXPECT_TRUE(adapter_wrapper_->Configure(decoder_settings));

  // The first decode should fail.  It shouldn't forward the decode call to the
  // underlying decoder.
  EXPECT_CALL(*video_decoder_, Decode_(_, _)).Times(0);
  // A fallback is caused when a number of concurrent instances are decoding
  // small resolutions.
  EXPECT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);

  // It should not increment the count, else more decoders might fall back.
  const auto max_decoder_instances =
      RTCVideoDecoderAdapter::kMaxDecoderInstances;
  EXPECT_EQ(GetCurrentDecoderCount(), max_decoder_instances);

  // Reset the count, since it's static.
  for (int i = 0; i < RTCVideoDecoderAdapter::kMaxDecoderInstances; i++)
    DecrementCurrentDecoderCount();

  // Deleting the decoder should not decrement the count.
  adapter_wrapper_.reset();
  media_thread_.FlushForTesting();
  EXPECT_EQ(GetCurrentDecoderCount(), 0);
}

#if BUILDFLAG(RTC_USE_H265)
TEST_F(RTCVideoDecoderAdapterTest, DoesNotFailForH256LowResolution) {
  // Make sure that low-resolution decode does not fail for H.265.
  SetSdpFormat(webrtc::SdpVideoFormat(
      webrtc::CodecTypeToPayloadString(webrtc::kVideoCodecH265)));
  ASSERT_TRUE(CreateAndInitialize(true, false));
  webrtc::VideoDecoder::Settings settings;
  settings.set_codec_type(webrtc::kVideoCodecH265);
  ASSERT_TRUE(adapter_wrapper_->Configure(settings));
  ASSERT_EQ(RegisterDecodeCompleteCallback(), WEBRTC_VIDEO_CODEC_OK);

  EXPECT_CALL(*video_decoder_, Decode_(_, _)).Times(1);

  ASSERT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_OK);

  media_thread_.FlushForTesting();
}
#endif

TEST_F(RTCVideoDecoderAdapterTest, DoesNotFallBackForHighResolution) {
  // Make sure that high-resolution decoders don't fall back.
  webrtc::VideoDecoder::Settings decoder_settings;
  decoder_settings.set_codec_type(webrtc::kVideoCodecVP9);

  // Pretend that we have many decoders already.
  for (int i = 0; i < RTCVideoDecoderAdapter::kMaxDecoderInstances; i++)
    IncrementCurrentDecoderCount();

  // Creating a decoder should not increment the count, since we haven't sent
  // anything to decode.
  ASSERT_TRUE(CreateAndInitialize(true, true));
  EXPECT_TRUE(adapter_wrapper_->Configure(decoder_settings));

  // The first decode should increment the count and succeed.
  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .WillOnce(
          base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kOk));
  EXPECT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_OK);
  media_thread_.FlushForTesting();
  EXPECT_EQ(GetCurrentDecoderCount(),
            RTCVideoDecoderAdapter::kMaxDecoderInstances + 1);

  // Reset the count, since it's static.
  for (int i = 0; i < RTCVideoDecoderAdapter::kMaxDecoderInstances; i++)
    DecrementCurrentDecoderCount();
}

TEST_F(RTCVideoDecoderAdapterTest, DecodesImageWithSingleSpatialLayer) {
  ASSERT_TRUE(BasicSetup());
  webrtc::EncodedImage input_image = GetEncodedImageWithSingleSpatialLayer(0);
  scoped_refptr<media::DecoderBuffer> decoder_buffer;
  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .WillOnce(::testing::DoAll(
          ::testing::SaveArg<0>(&decoder_buffer),
          base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kOk)));
  EXPECT_EQ(adapter_wrapper_->Decode(input_image, false, 0),
            WEBRTC_VIDEO_CODEC_OK);

  EXPECT_CALL(decoded_cb_, Run(_));
  FinishDecode(0);
  media_thread_.FlushForTesting();

  // Check the side data was not set as there was only 1 spatial layer.
  ASSERT_TRUE(decoder_buffer);
  if (decoder_buffer->has_side_data()) {
    EXPECT_TRUE(decoder_buffer->side_data()->spatial_layers.empty());
  }
}

#if BUILDFLAG(IS_WIN)
TEST_F(RTCVideoDecoderAdapterTest, UseD3D11ToDecodeVP9kSVCStream) {
  video_decoder_->SetDecoderType(media::VideoDecoderType::kD3D11);
  ASSERT_TRUE(BasicSetup());
  SetSpatialIndex(2);
  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .WillOnce(
          base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kOk));

  ASSERT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_OK);

  EXPECT_CALL(decoded_cb_, Run(_));
  FinishDecode(0);
  media_thread_.FlushForTesting();
}
#elif !(defined(ARCH_CPU_X86_FAMILY) && BUILDFLAG(IS_CHROMEOS))
// ChromeOS has the ability to decode VP9 kSVC Stream. Other cases should
// fallback to sw decoder.
TEST_F(RTCVideoDecoderAdapterTest,
       FallbackToSWSinceDecodeVP9kSVCStreamWithoutD3D11) {
  ASSERT_TRUE(BasicSetup());
  SetSpatialIndex(2);
  // kTesting will represent hw decoders for other use cases mentioned above.
  EXPECT_CALL(*video_decoder_, Decode_(_, _)).Times(0);

  ASSERT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);

  media_thread_.FlushForTesting();
}
#endif  // BUILDFLAG(IS_WIN)

TEST_F(RTCVideoDecoderAdapterTest, FallbackToSWInAV1SVC) {
  SetSdpFormat(webrtc::SdpVideoFormat(
      webrtc::CodecTypeToPayloadString(webrtc::kVideoCodecAV1)));
  ASSERT_TRUE(CreateAndInitialize());
  webrtc::VideoDecoder::Settings settings;
  settings.set_codec_type(webrtc::kVideoCodecAV1);
  ASSERT_TRUE(adapter_wrapper_->Configure(settings));
  ASSERT_EQ(RegisterDecodeCompleteCallback(), WEBRTC_VIDEO_CODEC_OK);

  SetSpatialIndex(2);
  // kTesting will represent hw decoders for other use cases mentioned above.
  EXPECT_CALL(*video_decoder_, Decode_(_, _)).Times(0);

  ASSERT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);

  media_thread_.FlushForTesting();
}

TEST_F(RTCVideoDecoderAdapterTest, CanReadSharedFrameBuffer) {
  ASSERT_TRUE(BasicSetup());

  EXPECT_CALL(*video_decoder_, Decode_(_, _))
      .WillOnce(
          base::test::RunOnceCallback<1>(media::DecoderStatus::Codes::kOk));

  ASSERT_EQ(Decode(0), WEBRTC_VIDEO_CODEC_OK);

  scoped_refptr<base::SingleThreadTaskRunner> main_thread =
      blink::scheduler::GetSingleThreadTaskRunnerForTesting();

  EXPECT_CALL(decoded_cb_, Run).WillOnce([&](const webrtc::VideoFrame& frame) {
    main_thread->PostTask(FROM_HERE, base::BindOnce(
                                         [](const webrtc::VideoFrame& frame) {
                                           frame.video_frame_buffer()->ToI420();
                                         },
                                         frame));
  });
  FinishDecode(0);
  media_thread_.FlushForTesting();
}

}  // namespace blink
```