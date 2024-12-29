Response:
The user is asking for a summary of the provided C++ code file. The file is a test for the `MediaCapabilities` API within the Chromium Blink rendering engine.

To provide a good summary, I will focus on the following aspects:

1. **Purpose of the test file:** What is being tested?
2. **Key components used for testing:** What are the main building blocks of the test? (e.g., mock services)
3. **Relationship to web technologies:** How does this relate to JavaScript, HTML, and CSS?
4. **Logic and assumptions:** Are there any logical inferences made in the tests?
5. **Common errors and debugging:** What kind of errors or debugging scenarios might lead someone to this code?
6. **User interaction:** How does a user's action eventually trigger this code?

Based on the file content, I can see it uses mock services to simulate browser-side components like `VideoDecodePerfHistory`, `WebrtcVideoPerfHistory`, and `LearningTaskController`. This allows testing the `MediaCapabilities` API in isolation. The tests involve checking the results of the `decodingInfo()` and `encodingInfo()` methods, which are JavaScript APIs.

Therefore, the core function is testing the correctness of the `MediaCapabilities` implementation in Blink by simulating various scenarios through mock services.
这个代码文件是 `media_capabilities_test.cc`，它位于 Chromium Blink 引擎的 `blink/renderer/modules/media_capabilities` 目录下。  从文件名和目录结构来看，它的主要功能是**测试 `MediaCapabilities` API 的实现**。

具体来说，这个测试文件通过以下方式来验证 `MediaCapabilities` 的功能：

1. **模拟浏览器端服务 (Mocking Browser-Side Services):**  它创建了一系列模拟的浏览器端服务，例如 `MockPerfHistoryService`、`MockWebrtcPerfHistoryService` 和 `MockLearningTaskControllerService`。这些服务模拟了浏览器中实际处理媒体能力查询的组件。这使得测试可以在不依赖完整浏览器环境的情况下进行。

2. **测试 `decodingInfo()` 和 `encodingInfo()` 方法:**  `MediaCapabilities` API 提供了 `decodingInfo()` 和 `encodingInfo()` 方法，用于查询特定媒体配置是否支持解码或编码，并提供性能相关的建议（例如，是否平滑、是否节能）。这个测试文件通过调用这些方法，并断言返回的结果是否符合预期来验证其正确性。

3. **使用不同的媒体配置:**  测试中创建了不同的 `MediaDecodingConfiguration` 和 `MediaEncodingConfiguration` 对象，涵盖了不同的视频和音频格式、编解码器、分辨率、帧率等参数，以测试 `MediaCapabilities` 对各种媒体配置的处理能力。

4. **验证预测结果:**  `MediaCapabilities` 的一个重要功能是预测解码或编码的性能。测试文件通过配置模拟服务的行为（例如，`MockPerfHistoryService` 返回的平滑和节能信息，`MockLearningTaskControllerService` 返回的预测分布），来验证 `MediaCapabilities` 是否正确地整合和返回这些预测结果。

5. **使用 Feature Flags 进行测试:**  代码中使用了 `base::test::ScopedFeatureList` 来启用或禁用特定的特性（例如，`media::kMediaCapabilitiesQueryGpuFactories`，`media::kMediaLearningSmoothnessExperiment`），从而测试在不同特性组合下的 `MediaCapabilities` 行为。

**与 JavaScript, HTML, CSS 的关系：**

`MediaCapabilities` API 是一个 Web API，它通过 JavaScript 暴露给开发者。开发者可以使用这个 API 来查询用户的设备和浏览器是否支持特定的媒体格式和配置。这可以帮助开发者在网页中提供更好的媒体体验。

**举例说明:**

* **JavaScript:** 开发者可以使用 `navigator.mediaCapabilities.decodingInfo(configuration)` 方法来查询解码能力。`media_capabilities_test.cc` 中的测试就是模拟了这个 JavaScript 调用，并验证了返回的结果。例如，测试中创建了 `CreateDecodingConfig()` 函数来创建一个 `MediaDecodingConfiguration` 对象，然后在 JavaScript 中，开发者可以构造类似的配置并调用 `decodingInfo()`。

```javascript
// JavaScript 示例
const configuration = {
  type: 'media-source',
  video: {
    contentType: 'video/webm; codecs="vp09.00.10.08"',
    framerate: 20.5,
    width: 3840,
    height: 2160,
    bitrate: 2391000
  }
};

navigator.mediaCapabilities.decodingInfo(configuration)
  .then(result => {
    console.log('解码支持:', result.supported);
    console.log('解码平滑:', result.smooth);
    console.log('解码节能:', result.powerEfficient);
  });
```

* **HTML:**  HTML 的 `<video>` 和 `<audio>` 元素用于在网页中嵌入媒体。`MediaCapabilities` 可以帮助开发者在加载媒体之前，判断当前环境是否适合播放特定的媒体资源，从而避免播放失败或者性能不佳的情况。

* **CSS:**  CSS 本身与 `MediaCapabilities` 的功能没有直接关系。但是，基于 `MediaCapabilities` 的查询结果，开发者可以使用 JavaScript 来动态地修改 CSS，例如，如果不支持某种视频格式，可以隐藏播放按钮或显示错误提示。

**逻辑推理和假设输入输出:**

假设输入一个 `MediaDecodingConfiguration` 对象，描述了一个 VP9 编码的 4K 视频，帧率为 20.5fps。

```cpp
// 假设的输入配置
const MediaDecodingConfiguration* kDecodingConfig = CreateDecodingConfig();
```

测试代码会调用 `decodingInfo()` 方法，并期望模拟的 `MockPerfHistoryService` 会被调用，并根据预设的逻辑返回结果。

**假设的模拟服务行为和输出:**

如果 `MockPerfHistoryService` 被配置为对于这个特定的视频配置返回 `smooth=true` 和 `powerEfficient=false`，那么测试代码会断言 `decodingInfo()` 返回的 `MediaCapabilitiesInfo` 对象的 `smooth()` 方法返回 `true`， `powerEfficient()` 方法返回 `false`。

**用户或编程常见的使用错误:**

* **配置参数错误:**  开发者在构造 `MediaDecodingConfiguration` 或 `MediaEncodingConfiguration` 对象时，可能会设置错误的 `contentType` 或其他参数，导致 `MediaCapabilities` 返回意外的结果。例如，`contentType` 中的编解码器名称拼写错误。
* **异步操作理解不足:** `decodingInfo()` 和 `encodingInfo()` 返回的是 Promise 对象，开发者可能没有正确处理 Promise 的异步结果，导致程序逻辑错误。
* **盲目相信 `supported` 结果:** 即使 `supported` 为 `true`，也并不意味着播放一定流畅或节能。`MediaCapabilities` 提供的 `smooth` 和 `powerEfficient` 属性提供了更细粒度的信息，开发者应该根据这些信息做出更合理的决策。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户访问包含媒体内容的网页:** 用户打开一个包含 `<video>` 或 `<audio>` 元素的网页。
2. **网页 JavaScript 代码调用 `navigator.mediaCapabilities.decodingInfo()` 或 `encodingInfo()`:** 网页的 JavaScript 代码为了判断当前环境是否支持播放或录制特定的媒体，会调用 `MediaCapabilities` API。
3. **Blink 引擎处理 API 调用:** Blink 引擎接收到 JavaScript 的调用，并创建相应的 `MediaDecodingConfiguration` 或 `MediaEncodingConfiguration` 对象。
4. **Blink 引擎查询浏览器端服务:** Blink 引擎会与浏览器进程中的媒体相关服务（例如，`VideoDecodePerfHistory`）进行通信，以获取媒体能力信息。
5. **测试代码模拟上述过程:**  `media_capabilities_test.cc` 中的测试代码模拟了步骤 3 和 4，通过创建配置对象并与模拟的浏览器端服务交互，来验证 Blink 引擎中 `MediaCapabilities` 的实现逻辑。

如果开发者在调试与 `MediaCapabilities` 相关的 bug，他们可能会查看这个测试文件，了解 Blink 引擎是如何测试这个 API 的，以及期望的输入和输出是什么。例如，如果一个网页在特定设备上无法播放某个视频，开发者可能会检查 `media_capabilities_test.cc` 中是否有类似的测试用例，或者根据测试用例的结构编写新的测试用例来复现和定位问题。

**归纳其功能 (第1部分):**

这个代码文件 `media_capabilities_test.cc` 的主要功能是**对 Chromium Blink 引擎中 `MediaCapabilities` API 的实现进行单元测试**。它通过模拟浏览器端的服务，构造不同的媒体配置，并验证 `decodingInfo()` 和 `encodingInfo()` 方法的返回结果，来确保 `MediaCapabilities` API 的正确性和可靠性。  它涵盖了基本的支持性判断以及性能预测（平滑和节能）的测试。

Prompt: 
```
这是目录为blink/renderer/modules/media_capabilities/media_capabilities_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media_capabilities/media_capabilities.h"

#include <math.h>

#include <algorithm>

#include "base/memory/raw_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "media/base/media_switches.h"
#include "media/base/video_codecs.h"
#include "media/learning/common/media_learning_tasks.h"
#include "media/learning/common/target_histogram.h"
#include "media/learning/mojo/public/mojom/learning_task_controller.mojom-blink.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/mojo/mojom/media_metrics_provider.mojom-blink.h"
#include "media/mojo/mojom/media_types.mojom-blink.h"
#include "media/mojo/mojom/video_decode_perf_history.mojom-blink.h"
#include "media/mojo/mojom/watch_time_recorder.mojom-blink.h"
#include "media/mojo/mojom/webrtc_video_perf.mojom-blink.h"
#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_capabilities_decoding_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_capabilities_info.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_decoding_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_encoding_configuration.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_configuration.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_video_encoder_factory.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "third_party/googletest/src/googlemock/include/gmock/gmock-actions.h"
#include "ui/gfx/geometry/size.h"

using ::media::learning::FeatureValue;
using ::media::learning::ObservationCompletion;
using ::media::learning::TargetValue;
using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::Unused;

namespace blink {

namespace {

// Simulating the browser-side service.
class MockPerfHistoryService
    : public media::mojom::blink::VideoDecodePerfHistory {
 public:
  void BindRequest(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(
        mojo::PendingReceiver<media::mojom::blink::VideoDecodePerfHistory>(
            std::move(handle)));
    receiver_.set_disconnect_handler(base::BindOnce(
        &MockPerfHistoryService::OnConnectionError, base::Unretained(this)));
  }

  void OnConnectionError() { receiver_.reset(); }

  // media::mojom::blink::VideoDecodePerfHistory implementation:
  MOCK_METHOD2(GetPerfInfo,
               void(media::mojom::blink::PredictionFeaturesPtr features,
                    GetPerfInfoCallback got_info_cb));

 private:
  mojo::Receiver<media::mojom::blink::VideoDecodePerfHistory> receiver_{this};
};

class MockWebrtcPerfHistoryService
    : public media::mojom::blink::WebrtcVideoPerfHistory {
 public:
  void BindRequest(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(
        mojo::PendingReceiver<media::mojom::blink::WebrtcVideoPerfHistory>(
            std::move(handle)));
    receiver_.set_disconnect_handler(
        base::BindOnce(&MockWebrtcPerfHistoryService::OnConnectionError,
                       base::Unretained(this)));
  }

  void OnConnectionError() { receiver_.reset(); }

  // media::mojom::blink::WebrtcVideoPerfHistory implementation:
  MOCK_METHOD3(GetPerfInfo,
               void(media::mojom::blink::WebrtcPredictionFeaturesPtr features,
                    int frames_per_second,
                    GetPerfInfoCallback got_info_cb));

 private:
  mojo::Receiver<media::mojom::blink::WebrtcVideoPerfHistory> receiver_{this};
};

class MockLearningTaskControllerService
    : public media::learning::mojom::blink::LearningTaskController {
 public:
  void BindRequest(mojo::PendingReceiver<
                   media::learning::mojom::blink::LearningTaskController>
                       pending_receiver) {
    receiver_.Bind(std::move(pending_receiver));
    receiver_.set_disconnect_handler(
        base::BindOnce(&MockLearningTaskControllerService::OnConnectionError,
                       base::Unretained(this)));
  }

  void OnConnectionError() { receiver_.reset(); }

  bool is_bound() const { return receiver_.is_bound(); }

  // media::mojom::blink::LearningTaskController implementation:
  MOCK_METHOD3(BeginObservation,
               void(const base::UnguessableToken& id,
                    const WTF::Vector<FeatureValue>& features,
                    const std::optional<TargetValue>& default_target));
  MOCK_METHOD2(CompleteObservation,
               void(const base::UnguessableToken& id,
                    const ObservationCompletion& completion));
  MOCK_METHOD1(CancelObservation, void(const base::UnguessableToken& id));
  MOCK_METHOD2(UpdateDefaultTarget,
               void(const base::UnguessableToken& id,
                    const std::optional<TargetValue>& default_target));
  MOCK_METHOD2(PredictDistribution,
               void(const WTF::Vector<FeatureValue>& features,
                    PredictDistributionCallback callback));

 private:
  mojo::Receiver<media::learning::mojom::blink::LearningTaskController>
      receiver_{this};
};

class FakeMediaMetricsProvider
    : public media::mojom::blink::MediaMetricsProvider {
 public:
  // Raw pointers to services owned by the test.
  FakeMediaMetricsProvider(
      MockLearningTaskControllerService* bad_window_service,
      MockLearningTaskControllerService* nnr_service)
      : bad_window_service_(bad_window_service), nnr_service_(nnr_service) {}

  ~FakeMediaMetricsProvider() override = default;

  void BindRequest(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(
        mojo::PendingReceiver<media::mojom::blink::MediaMetricsProvider>(
            std::move(handle)));
    receiver_.set_disconnect_handler(base::BindOnce(
        &FakeMediaMetricsProvider::OnConnectionError, base::Unretained(this)));
  }

  void OnConnectionError() { receiver_.reset(); }

  // mojom::WatchTimeRecorderProvider implementation:
  void AcquireWatchTimeRecorder(
      media::mojom::blink::PlaybackPropertiesPtr properties,
      mojo::PendingReceiver<media::mojom::blink::WatchTimeRecorder> receiver)
      override {
    FAIL();
  }
  void AcquireVideoDecodeStatsRecorder(
      mojo::PendingReceiver<media::mojom::blink::VideoDecodeStatsRecorder>
          receiver) override {
    FAIL();
  }
  void AcquireLearningTaskController(
      const WTF::String& taskName,
      mojo::PendingReceiver<
          media::learning::mojom::blink::LearningTaskController>
          pending_receiver) override {
    if (taskName == media::learning::tasknames::kConsecutiveBadWindows) {
      bad_window_service_->BindRequest(std::move(pending_receiver));
      return;
    }

    if (taskName == media::learning::tasknames::kConsecutiveNNRs) {
      nnr_service_->BindRequest(std::move(pending_receiver));
      return;
    }
    FAIL();
  }
  void AcquirePlaybackEventsRecorder(
      mojo::PendingReceiver<media::mojom::blink::PlaybackEventsRecorder>
          receiver) override {
    FAIL();
  }
  void Initialize(bool is_mse,
                  media::mojom::MediaURLScheme url_scheme,
                  media::mojom::MediaStreamType media_stream_type) override {}
  void OnStarted(media::mojom::blink::PipelineStatusPtr status) override {}
  void OnError(media::mojom::blink::PipelineStatusPtr status) override {}
  void OnFallback(::media::mojom::blink::PipelineStatusPtr status) override {}
  void SetIsEME() override {}
  void SetTimeToMetadata(base::TimeDelta elapsed) override {}
  void SetTimeToFirstFrame(base::TimeDelta elapsed) override {}
  void SetTimeToPlayReady(base::TimeDelta elapsed) override {}
  void SetContainerName(
      media::mojom::blink::MediaContainerName container_name) override {}
  void SetRendererType(
      media::mojom::blink::RendererType renderer_type) override {}
  void SetKeySystem(const String& key_system) override {}
  void SetHasWaitingForKey() override {}
  void SetIsHardwareSecure() override {}
  void SetHasPlayed() override {}
  void SetHaveEnough() override {}
  void SetHasAudio(media::mojom::AudioCodec audio_codec) override {}
  void SetHasVideo(media::mojom::VideoCodec video_codec) override {}
  void SetVideoPipelineInfo(
      media::mojom::blink::VideoPipelineInfoPtr info) override {}
  void SetAudioPipelineInfo(
      media::mojom::blink::AudioPipelineInfoPtr info) override {}

 private:
  mojo::Receiver<media::mojom::blink::MediaMetricsProvider> receiver_{this};
  raw_ptr<MockLearningTaskControllerService, DanglingUntriaged>
      bad_window_service_;
  raw_ptr<MockLearningTaskControllerService, DanglingUntriaged> nnr_service_;
};

// Simple helper for saving back-end callbacks for pending decodingInfo() calls.
// Callers can then manually fire the callbacks, gaining fine-grain control of
// the timing and order of their arrival.
class CallbackSaver {
 public:
  void SavePerfHistoryCallback(
      media::mojom::blink::PredictionFeaturesPtr features,
      MockPerfHistoryService::GetPerfInfoCallback got_info_cb) {
    perf_history_cb_ = std::move(got_info_cb);
  }

  void SaveBadWindowCallback(
      Vector<media::learning::FeatureValue> features,
      MockLearningTaskControllerService::PredictDistributionCallback
          predict_cb) {
    bad_window_cb_ = std::move(predict_cb);
  }

  void SaveNnrCallback(
      Vector<media::learning::FeatureValue> features,
      MockLearningTaskControllerService::PredictDistributionCallback
          predict_cb) {
    nnr_cb_ = std::move(predict_cb);
  }

  void SaveGpuFactoriesNotifyCallback(base::OnceClosure cb) {
    gpu_factories_notify_cb_ = std::move(cb);
  }

  MockPerfHistoryService::GetPerfInfoCallback& perf_history_cb() {
    return perf_history_cb_;
  }

  MockLearningTaskControllerService::PredictDistributionCallback&
  bad_window_cb() {
    return bad_window_cb_;
  }

  MockLearningTaskControllerService::PredictDistributionCallback& nnr_cb() {
    return nnr_cb_;
  }

  base::OnceClosure& gpu_factories_notify_cb() {
    return gpu_factories_notify_cb_;
  }

 private:
  MockPerfHistoryService::GetPerfInfoCallback perf_history_cb_;
  MockLearningTaskControllerService::PredictDistributionCallback bad_window_cb_;
  MockLearningTaskControllerService::PredictDistributionCallback nnr_cb_;
  base::OnceClosure gpu_factories_notify_cb_;
};

class MockPlatform : public TestingPlatformSupport {
 public:
  MockPlatform() = default;
  ~MockPlatform() override = default;

  MOCK_METHOD0(GetGpuFactories, media::GpuVideoAcceleratorFactories*());
};

// This would typically be a test fixture, but we need it to be
// STACK_ALLOCATED() in order to use V8TestingScope, and we can't force that on
// whatever gtest class instantiates the fixture.
class MediaCapabilitiesTestContext {
  STACK_ALLOCATED();

 public:
  MediaCapabilitiesTestContext() {
    perf_history_service_ = std::make_unique<MockPerfHistoryService>();
    webrtc_perf_history_service_ =
        std::make_unique<MockWebrtcPerfHistoryService>();
    bad_window_service_ = std::make_unique<MockLearningTaskControllerService>();
    nnr_service_ = std::make_unique<MockLearningTaskControllerService>();
    fake_metrics_provider_ = std::make_unique<FakeMediaMetricsProvider>(
        bad_window_service_.get(), nnr_service_.get());

    CHECK(v8_scope_.GetExecutionContext()
              ->GetBrowserInterfaceBroker()
              .SetBinderForTesting(
                  media::mojom::blink::MediaMetricsProvider::Name_,
                  base::BindRepeating(
                      &FakeMediaMetricsProvider::BindRequest,
                      base::Unretained(fake_metrics_provider_.get()))));

    CHECK(v8_scope_.GetExecutionContext()
              ->GetBrowserInterfaceBroker()
              .SetBinderForTesting(
                  media::mojom::blink::VideoDecodePerfHistory::Name_,
                  base::BindRepeating(
                      &MockPerfHistoryService::BindRequest,
                      base::Unretained(perf_history_service_.get()))));

    CHECK(v8_scope_.GetExecutionContext()
              ->GetBrowserInterfaceBroker()
              .SetBinderForTesting(
                  media::mojom::blink::WebrtcVideoPerfHistory::Name_,
                  base::BindRepeating(
                      &MockWebrtcPerfHistoryService::BindRequest,
                      base::Unretained(webrtc_perf_history_service_.get()))));

    media_capabilities_ = MediaCapabilities::mediaCapabilities(
        *v8_scope_.GetWindow().navigator());
  }

  ~MediaCapabilitiesTestContext() {
    CHECK(v8_scope_.GetExecutionContext()
              ->GetBrowserInterfaceBroker()
              .SetBinderForTesting(
                  media::mojom::blink::MediaMetricsProvider::Name_, {}));

    CHECK(v8_scope_.GetExecutionContext()
              ->GetBrowserInterfaceBroker()
              .SetBinderForTesting(
                  media::mojom::blink::VideoDecodePerfHistory::Name_, {}));

    CHECK(v8_scope_.GetExecutionContext()
              ->GetBrowserInterfaceBroker()
              .SetBinderForTesting(
                  media::mojom::blink::WebrtcVideoPerfHistory::Name_, {}));
  }

  ExceptionState& GetExceptionState() { return v8_scope_.GetExceptionState(); }

  ScriptState* GetScriptState() const { return v8_scope_.GetScriptState(); }

  v8::Isolate* GetIsolate() const { return GetScriptState()->GetIsolate(); }

  MediaCapabilities* GetMediaCapabilities() const {
    return media_capabilities_.Get();
  }

  MockPerfHistoryService* GetPerfHistoryService() const {
    return perf_history_service_.get();
  }

  MockWebrtcPerfHistoryService* GetWebrtcPerfHistoryService() const {
    return webrtc_perf_history_service_.get();
  }

  MockLearningTaskControllerService* GetBadWindowService() const {
    return bad_window_service_.get();
  }

  MockLearningTaskControllerService* GetNnrService() const {
    return nnr_service_.get();
  }

  MockPlatform& GetMockPlatform() { return *mock_platform_; }

  void VerifyAndClearMockExpectations() {
    testing::Mock::VerifyAndClearExpectations(GetPerfHistoryService());
    testing::Mock::VerifyAndClearExpectations(GetWebrtcPerfHistoryService());
    testing::Mock::VerifyAndClearExpectations(GetNnrService());
    testing::Mock::VerifyAndClearExpectations(GetBadWindowService());
    testing::Mock::VerifyAndClearExpectations(&GetMockPlatform());
  }

 private:
  V8TestingScope v8_scope_;
  ScopedTestingPlatformSupport<MockPlatform> mock_platform_;
  std::unique_ptr<MockPerfHistoryService> perf_history_service_;
  std::unique_ptr<MockWebrtcPerfHistoryService> webrtc_perf_history_service_;
  std::unique_ptr<FakeMediaMetricsProvider> fake_metrics_provider_;
  Persistent<MediaCapabilities> media_capabilities_;
  std::unique_ptr<MockLearningTaskControllerService> bad_window_service_;
  std::unique_ptr<MockLearningTaskControllerService> nnr_service_;
};

// |kVideoContentType|, |kCodec|, and |kCodecProfile| must match.
const char kVideoContentType[] = "video/webm; codecs=\"vp09.00.10.08\"";
const char kAudioContentType[] = "audio/webm; codecs=\"opus\"";
const media::VideoCodecProfile kCodecProfile = media::VP9PROFILE_PROFILE0;
const media::VideoCodec kCodec = media::VideoCodec::kVP9;
const double kFramerate = 20.5;
const int kWidth = 3840;
const int kHeight = 2160;
const int kBitrate = 2391000;
const char kWebrtcVideoContentType[] = "video/VP9; profile-id=\"0\"";
const char kWebrtcAudioContentType[] = "audio/opus";

// Construct AudioConfig using the constants above.
template <class T>
T* CreateAudioConfig(const char content_type[], const char type[]) {
  auto* audio_config = MakeGarbageCollected<AudioConfiguration>();
  audio_config->setContentType(content_type);
  auto* decoding_config = MakeGarbageCollected<T>();
  decoding_config->setType(type);
  decoding_config->setAudio(audio_config);
  return decoding_config;
}

// Construct media-source AudioConfig using the constants above.
MediaDecodingConfiguration* CreateAudioDecodingConfig() {
  return CreateAudioConfig<MediaDecodingConfiguration>(kAudioContentType,
                                                       "media-source");
}

// Construct webrtc decoding AudioConfig using the constants above.
MediaDecodingConfiguration* CreateWebrtcAudioDecodingConfig() {
  return CreateAudioConfig<MediaDecodingConfiguration>(kWebrtcAudioContentType,
                                                       "webrtc");
}

// Construct webrtc decoding AudioConfig using the constants above.
MediaEncodingConfiguration* CreateWebrtcAudioEncodingConfig() {
  return CreateAudioConfig<MediaEncodingConfiguration>(kWebrtcAudioContentType,
                                                       "webrtc");
}

// Construct VideoConfig using the constants above.
template <class T>
T* CreateVideoConfig(const char content_type[], const char type[]) {
  auto* video_config = MakeGarbageCollected<VideoConfiguration>();
  video_config->setFramerate(kFramerate);
  video_config->setContentType(content_type);
  video_config->setWidth(kWidth);
  video_config->setHeight(kHeight);
  video_config->setBitrate(kBitrate);
  auto* decoding_config = MakeGarbageCollected<T>();
  decoding_config->setType(type);
  decoding_config->setVideo(video_config);
  return decoding_config;
}

// Construct media-source VideoConfig using the constants above.
MediaDecodingConfiguration* CreateDecodingConfig() {
  return CreateVideoConfig<MediaDecodingConfiguration>(kVideoContentType,
                                                       "media-source");
}

// Construct webrtc decoding VideoConfig using the constants above.
MediaDecodingConfiguration* CreateWebrtcDecodingConfig() {
  return CreateVideoConfig<MediaDecodingConfiguration>(kWebrtcVideoContentType,
                                                       "webrtc");
}

// Construct webrtc encoding VideoConfig using the constants above.
MediaEncodingConfiguration* CreateWebrtcEncodingConfig() {
  return CreateVideoConfig<MediaEncodingConfiguration>(kWebrtcVideoContentType,
                                                       "webrtc");
}

// Construct PredicitonFeatures matching the CreateDecodingConfig, using the
// constants above.
media::mojom::blink::PredictionFeatures CreateFeatures() {
  media::mojom::blink::PredictionFeatures features;
  features.profile =
      static_cast<media::mojom::blink::VideoCodecProfile>(kCodecProfile);
  features.video_size = gfx::Size(kWidth, kHeight);
  features.frames_per_sec = kFramerate;

  // Not set by any tests so far. Choosing sane defaults to mirror production
  // code.
  features.key_system = "";
  features.use_hw_secure_codecs = false;

  return features;
}

Vector<media::learning::FeatureValue> CreateFeaturesML() {
  media::mojom::blink::PredictionFeatures features = CreateFeatures();

  // FRAGILE: Order here MUST match order in
  // WebMediaPlayerImpl::UpdateSmoothnessHelper().
  // TODO(chcunningham): refactor into something more robust.
  Vector<media::learning::FeatureValue> ml_features(
      {media::learning::FeatureValue(static_cast<int>(kCodec)),
       media::learning::FeatureValue(kCodecProfile),
       media::learning::FeatureValue(kWidth),
       media::learning::FeatureValue(kFramerate)});

  return ml_features;
}

// Construct WebrtcPredicitonFeatures matching the CreateWebrtc{Decoding,
// Encoding}Config, using the constants above.
media::mojom::blink::WebrtcPredictionFeatures CreateWebrtcFeatures(
    bool is_decode) {
  media::mojom::blink::WebrtcPredictionFeatures features;
  features.is_decode_stats = is_decode;
  features.profile =
      static_cast<media::mojom::blink::VideoCodecProfile>(kCodecProfile);
  features.video_pixels = kWidth * kHeight;
  return features;
}

// Types of smoothness predictions.
enum class PredictionType {
  kDB,
  kBadWindow,
  kNnr,
  kGpuFactories,
};

// Makes a TargetHistogram with single count at |target_value|.
media::learning::TargetHistogram MakeHistogram(double target_value) {
  media::learning::TargetHistogram histogram;
  histogram += media::learning::TargetValue(target_value);
  return histogram;
}

// Makes DB (PerfHistoryService) callback for use with gtest WillOnce().
// Callback will verify |features| matches |expected_features| and run with
// provided values for |is_smooth| and |is_power_efficient|.
testing::Action<void(media::mojom::blink::PredictionFeaturesPtr,
                     MockPerfHistoryService::GetPerfInfoCallback)>
DbCallback(const media::mojom::blink::PredictionFeatures& expected_features,
           bool is_smooth,
           bool is_power_efficient) {
  return [=](media::mojom::blink::PredictionFeaturesPtr features,
             MockPerfHistoryService::GetPerfInfoCallback got_info_cb) {
    EXPECT_TRUE(features->Equals(expected_features));
    std::move(got_info_cb).Run(is_smooth, is_power_efficient);
  };
}

// Makes ML (LearningTaskControllerService) callback for use with gtest
// WillOnce(). Callback will verify |features| matches |expected_features| and
// run a TargetHistogram containing a single count for |histogram_target|.
testing::Action<void(
    const Vector<media::learning::FeatureValue>&,
    MockLearningTaskControllerService::PredictDistributionCallback predict_cb)>
MlCallback(const Vector<media::learning::FeatureValue>& expected_features,
           double histogram_target) {
  return [=](const Vector<media::learning::FeatureValue>& features,
             MockLearningTaskControllerService::PredictDistributionCallback
                 predict_cb) {
    EXPECT_EQ(features, expected_features);
    std::move(predict_cb).Run(MakeHistogram(histogram_target));
  };
}

// Makes DB (WebrtcPerfHistoryService) callback for use with gtest WillOnce().
// Callback will verify |features| and |framerate| matches |expected_features|
// and |expected_framreate| and run with provided values for |is_smooth|.
testing::Action<void(media::mojom::blink::WebrtcPredictionFeaturesPtr,
                     int,
                     MockWebrtcPerfHistoryService::GetPerfInfoCallback)>
WebrtcDbCallback(
    const media::mojom::blink::WebrtcPredictionFeatures& expected_features,
    int expected_framerate,
    bool is_smooth) {
  return [=](media::mojom::blink::WebrtcPredictionFeaturesPtr features,
             int framerate,
             MockWebrtcPerfHistoryService::GetPerfInfoCallback got_info_cb) {
    EXPECT_TRUE(features->Equals(expected_features));
    EXPECT_EQ(framerate, expected_framerate);
    std::move(got_info_cb).Run(is_smooth);
  };
}

testing::Action<void(base::OnceClosure)> GpuFactoriesNotifyCallback() {
  return [](base::OnceClosure cb) { std::move(cb).Run(); };
}

// Helper to constructs field trial params with given ML prediction thresholds.
base::FieldTrialParams MakeMlParams(double bad_window_threshold,
                                    double nnr_threshold) {
  base::FieldTrialParams params;
  params[MediaCapabilities::kLearningBadWindowThresholdParamName] =
      base::NumberToString(bad_window_threshold);
  params[MediaCapabilities::kLearningNnrThresholdParamName] =
      base::NumberToString(nnr_threshold);
  return params;
}

// Wrapping decodingInfo() call for readability. Await resolution of the promise
// and return its info.
MediaCapabilitiesInfo* DecodingInfo(
    const MediaDecodingConfiguration* decoding_config,
    MediaCapabilitiesTestContext* context) {
  auto promise = context->GetMediaCapabilities()->decodingInfo(
      context->GetScriptState(), decoding_config, context->GetExceptionState());

  ScriptPromiseTester tester(context->GetScriptState(), promise);
  tester.WaitUntilSettled();

  CHECK(!tester.IsRejected()) << " Cant get info from rejected promise.";

  return NativeValueTraits<MediaCapabilitiesInfo>::NativeValue(
      context->GetIsolate(), tester.Value().V8Value(),
      context->GetExceptionState());
}

// Wrapping encodingInfo() call for readability. Await resolution of the promise
// and return its info.
MediaCapabilitiesInfo* EncodingInfo(
    const MediaEncodingConfiguration* encoding_config,
    MediaCapabilitiesTestContext* context) {
  auto promise = context->GetMediaCapabilities()->encodingInfo(
      context->GetScriptState(), encoding_config, context->GetExceptionState());

  ScriptPromiseTester tester(context->GetScriptState(), promise);
  tester.WaitUntilSettled();

  CHECK(!tester.IsRejected()) << " Cant get info from rejected promise.";

  return NativeValueTraits<MediaCapabilitiesInfo>::NativeValue(
      context->GetIsolate(), tester.Value().V8Value(),
      context->GetExceptionState());
}
}  // namespace

TEST(MediaCapabilitiesTests, BasicAudio) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  const MediaDecodingConfiguration* kDecodingConfig =
      CreateAudioDecodingConfig();
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
}

// Other tests will assume these match. Test to be sure they stay in sync.
TEST(MediaCapabilitiesTests, ConfigMatchesFeatures) {
  test::TaskEnvironment task_environment;
  const MediaDecodingConfiguration* kDecodingConfig = CreateDecodingConfig();
  const media::mojom::blink::PredictionFeatures kFeatures = CreateFeatures();

  EXPECT_TRUE(kDecodingConfig->video()->contentType().Contains("vp09.00"));
  EXPECT_EQ(static_cast<media::VideoCodecProfile>(kFeatures.profile),
            media::VP9PROFILE_PROFILE0);
  EXPECT_EQ(kCodecProfile, media::VP9PROFILE_PROFILE0);

  EXPECT_EQ(kDecodingConfig->video()->framerate(), kFeatures.frames_per_sec);
  EXPECT_EQ(kDecodingConfig->video()->width(),
            static_cast<uint32_t>(kFeatures.video_size.width()));
  EXPECT_EQ(kDecodingConfig->video()->height(),
            static_cast<uint32_t>(kFeatures.video_size.height()));
}

// Test that non-integer framerate isn't truncated by IPC.
// https://crbug.com/1024399
TEST(MediaCapabilitiesTests, NonIntegerFramerate) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;

  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      // Enabled features.
      {},
      // Disabled ML predictions + GpuFactories (just use DB).
      {media::kMediaCapabilitiesQueryGpuFactories,
       media::kMediaLearningSmoothnessExperiment});

  const auto* kDecodingConfig = CreateDecodingConfig();
  const media::mojom::blink::PredictionFeatures kFeatures = CreateFeatures();

  // FPS for this test must not be a whole number. Assert to ensure the default
  // config meets that condition.
  ASSERT_NE(fmod(kDecodingConfig->video()->framerate(), 1), 0);

  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce([&](media::mojom::blink::PredictionFeaturesPtr features,
                    MockPerfHistoryService::GetPerfInfoCallback got_info_cb) {
        // Explicitly check for frames_per_sec equality.
        // PredictionFeatures::Equals() will not catch loss of precision if
        // frames_per_sec is made to be int (currently a double).
        EXPECT_EQ(features->frames_per_sec, kFramerate);

        // Check that other things match as well.
        EXPECT_TRUE(features->Equals(kFeatures));

        std::move(got_info_cb).Run(/*smooth*/ true, /*power_efficient*/ true);
      });

  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
}

// Test smoothness predictions from DB (PerfHistoryService).
TEST(MediaCapabilitiesTests, PredictWithJustDB) {
  test::TaskEnvironment task_environment;
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      // Enabled features.
      {},
      // Disabled ML predictions + GpuFactories (just use DB).
      {media::kMediaCapabilitiesQueryGpuFactories,
       media::kMediaLearningSmoothnessExperiment});

  MediaCapabilitiesTestContext context;
  const auto* kDecodingConfig = CreateDecodingConfig();
  const media::mojom::blink::PredictionFeatures kFeatures = CreateFeatures();

  // ML services should not be called for prediction.
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .Times(0);
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _)).Times(0);

  // DB alone (PerfHistoryService) should be called. Signal smooth=true and
  // power_efficient = false.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ true, /*power_eff*/ false));
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());

  // Verify DB call was made. ML services should not even be bound.
  testing::Mock::VerifyAndClearExpectations(context.GetPerfHistoryService());
  EXPECT_FALSE(context.GetBadWindowService()->is_bound());
  EXPECT_FALSE(context.GetNnrService()->is_bound());

  // Repeat test with inverted smooth and power_efficient results.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*power_eff*/ true));
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, PredictPowerEfficientWithGpuFactories) {
  test::TaskEnvironment task_environment;
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      // Enable GpuFactories for power predictions.
      {media::kMediaCapabilitiesQueryGpuFactories},
      // Disable ML predictions (may/may not be disabled by default).
      {media::kMediaLearningSmoothnessExperiment});

  MediaCapabilitiesTestContext context;
  const auto* kDecodingConfig = CreateDecodingConfig();
  const media::mojom::blink::PredictionFeatures kFeatures = CreateFeatures();

  // Setup DB to return powerEfficient = false. We later verify that opposite
  // response from GpuFactories overrides the DB.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*power_eff*/ false));

  auto mock_gpu_factories =
      std::make_unique<media::MockGpuVideoAcceleratorFactories>(nullptr);
  ON_CALL(context.GetMockPlatform(), GetGpuFactories())
      .WillByDefault(Return(mock_gpu_factories.get()));

  // First, lets simulate the scenario where we ask before support is known. The
  // async path should notify us when the info arrives. We then get GpuFactroies
  // again and learn the config is supported.
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories()).Times(2);
  {
    // InSequence because we EXPECT two calls to IsDecoderSupportKnown with
    // different return values.
    InSequence s;
    EXPECT_CALL(*mock_gpu_factories, IsDecoderSupportKnown())
        .WillOnce(Return(false));
    EXPECT_CALL(*mock_gpu_factories, NotifyDecoderSupportKnown(_))
        .WillOnce(GpuFactoriesNotifyCallback());

    // MediaCapabilities calls IsDecoderSupportKnown() once, and
    // GpuVideoAcceleratorFactories::IsDecoderConfigSupported() also calls it
    // once internally.
    EXPECT_CALL(*mock_gpu_factories, IsDecoderSu
"""


```