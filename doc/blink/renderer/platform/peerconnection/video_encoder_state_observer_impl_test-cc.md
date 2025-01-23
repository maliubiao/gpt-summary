Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The primary goal is to understand the *purpose* of this test file within the Chromium Blink rendering engine. Specifically, we need to identify:

* What component is being tested?
* What aspects of that component are being tested?
* How are the tests structured?
* Are there any connections to web technologies (JavaScript, HTML, CSS)?
* Can we infer potential user or programming errors?

**2. Initial Code Scan (Keywords and Structure):**

I start by scanning the code for important keywords and structural elements:

* **`// Copyright ...`**: Standard copyright notice, indicating it's part of Chromium.
* **`#include ...`**:  This is crucial. It tells us the main subject of the test: `"third_party/blink/renderer/platform/peerconnection/video_encoder_state_observer_impl.h"`. This immediately points to the `VideoEncoderStateObserverImpl` class as the target. Other includes give context (testing framework, base library, media library, webrtc).
* **`namespace blink { namespace { ... } namespace }`**:  Indicates the code belongs to the Blink rendering engine and likely contains helper functions within an anonymous namespace.
* **`class VideoEncoderStateObserverImplTest : public ::testing::Test { ... }`**:  This confirms it's a Google Test suite, specifically for the `VideoEncoderStateObserverImpl`. The inheritance from `::testing::Test` is the standard way to define test fixtures in gtest.
* **`TEST_F(VideoEncoderStateObserverImplTest, ...)`**:  These are individual test cases within the test suite. The naming convention often hints at what's being tested (e.g., `FindHighestActiveEncoding_CreateAndDestroy_VP8Vanilla_SingleEncoder`).
* **Helper Functions**:  Functions like `BasicVideoCodec`, `FillSimulcastStreams`, `VP8VideoCodec`, `CreateStreamCodec`, `FillSpatialLayers`, `VP9kSVCVideoCodec`, `PixelRate`, and `GetActiveIndexInfo` suggest the tests involve configuring and manipulating video codecs and their layers.
* **Member Variables**: `observer_` of type `std::unique_ptr<VideoEncoderStateObserverImpl>` confirms that the tests create and interact with instances of the class under test. `processing_stats_` suggests it's tracking some kind of statistical output.
* **`OnEncoderCreated`, `OnEncoderDestroyed`, `OnRatesUpdated`, `OnEncode`, `OnEncodedImage`**: These method calls within the tests indicate the interface of the `VideoEncoderStateObserverImpl` being exercised.

**3. Deciphering the Test Names:**

The test names are very informative:

* `FindHighestActiveEncoding`:  A core function being tested, likely determining which video encoding layer is currently considered "top" or most active.
* `CreateAndDestroy`: Tests the lifecycle of encoders.
* `VP8Vanilla`, `VP8Simulcast`, `VP9kSVC`: Different video coding formats and configurations (simulcast and SVC).
* `SingleEncoder`, `MultipleEncoders`: Testing scenarios with one or multiple video encoders.
* `ActivateLayers`: Tests the dynamic activation/deactivation of encoding layers.
* `OnEncodedImage`: Tests the handling of encoded video frames.
* `DynamicLayerChange`: Specifically focuses on changes in active layers during encoding.

**4. Analyzing Key Test Cases:**

Reading through individual test cases like `FindHighestActiveEncoding_CreateAndDestroy_VP8Vanilla_SingleEncoder` helps to solidify understanding. The test sets up a VP8 encoder, checks if the highest active encoding is correctly identified, and then destroys the encoder. This provides a concrete example of the observer's behavior.

**5. Identifying Relationships to Web Technologies:**

The presence of "peerconnection" in the file path strongly suggests a connection to WebRTC. WebRTC is a core technology for real-time communication in web browsers, heavily involving JavaScript APIs. While this specific *C++* file doesn't directly manipulate HTML or CSS, the tested component is part of the underlying implementation that supports WebRTC features accessible through JavaScript.

* **JavaScript:** The `RTCPeerConnection` JavaScript API allows web developers to establish peer-to-peer connections, including video and audio streaming. The `VideoEncoderStateObserverImpl` likely plays a role in providing information about the state of the video encoder used by a `RTCPeerConnection`.
* **HTML:**  The `<video>` element is used to display video streams received through WebRTC.
* **CSS:** CSS can be used to style the `<video>` element.

**6. Inferring Logic and Potential Errors:**

* **Logic:** The tests involving `OnRatesUpdated` and `FindHighestActiveEncoding` demonstrate the logic for tracking active encoding layers. The `OnEncodedImage` tests show how the observer collects statistics based on encoded frames.
* **User/Programming Errors:**  The tests implicitly reveal potential errors:
    * **Incorrect encoder ID management:**  If encoder IDs are not handled consistently, the observer might not track the correct encoder.
    * **Incorrect layer activation logic:** Errors in the `OnRatesUpdated` logic could lead to misidentification of the active layer.
    * **Missing encoder creation/destruction:** Forgetting to call `OnEncoderCreated` or `OnEncoderDestroyed` could lead to incorrect state tracking.
    * **Incorrect spatial index reporting:** If the `spatial_index` in `OnEncodedImage` is wrong, statistics might be misattributed.

**7. Structuring the Explanation:**

Finally, I organize the findings into a coherent explanation, covering:

* **Core Functionality:**  A high-level description of the file's purpose.
* **Relationship to Web Technologies:**  Connecting the C++ code to the JavaScript/HTML/CSS world of web development.
* **Logic and Assumptions:**  Explaining the underlying logic of the tested component and providing examples with input/output.
* **Common Errors:** Highlighting potential pitfalls for developers using or interacting with this component.

This iterative process of scanning, analyzing, connecting, and synthesizing allows for a comprehensive understanding of the test file's purpose and its significance within the larger Chromium project.
这个C++源文件 `video_encoder_state_observer_impl_test.cc` 是 Chromium Blink 引擎中用于测试 `VideoEncoderStateObserverImpl` 类的单元测试文件。它的主要功能是：

**核心功能：测试 `VideoEncoderStateObserverImpl` 类的各种功能和行为。**

`VideoEncoderStateObserverImpl` 类的作用是观察和跟踪视频编码器的状态，例如：

* **哪个编码器是当前活动的最高质量编码器？** (对于分层编码或多码流编码)
* **收集编码统计信息，如编码处理时间、帧率、关键帧率等。**

**具体测试的功能点包括：**

1. **`FindHighestActiveEncoding()` 的正确性：**
   - 测试在创建和销毁编码器后，`FindHighestActiveEncoding()` 是否能正确返回当前最高质量的活动编码层的信息（包括编码器 ID、空间层 ID 和像素率）。
   - 测试在动态激活和禁用编码层后，`FindHighestActiveEncoding()` 是否能正确反映当前状态。
   - 涵盖了单编码器和多编码器（例如，用于 simulcast 或 SVC）的场景。

2. **编码器生命周期管理：**
   - 测试 `OnEncoderCreated()` 和 `OnEncoderDestroyed()` 是否正确更新了观察者维护的编码器状态。

3. **动态码率和层级更新：**
   - 测试 `OnRatesUpdated()` 是否正确处理了编码层激活状态的更新，并影响了 `FindHighestActiveEncoding()` 的结果。

4. **编码图像事件处理：**
   - 测试 `OnEncodedImage()` 是否正确地记录了编码统计信息，例如编码处理时间、是否是关键帧等。
   - 测试在单编码器和多编码器场景下统计信息的收集。
   - 测试在动态改变激活层后，统计信息的正确收集。

**与 JavaScript, HTML, CSS 的关系：**

虽然这是一个 C++ 测试文件，它测试的 `VideoEncoderStateObserverImpl` 类是 WebRTC (Web Real-Time Communication) 实现的一部分，而 WebRTC 可以通过 JavaScript API 在网页中使用。

* **JavaScript:**  Web 开发者可以使用 JavaScript 的 `RTCPeerConnection` API 来创建和管理实时的音视频通信。`VideoEncoderStateObserverImpl` 在 Blink 引擎内部工作，为这些 JavaScript API 提供底层支持。例如，JavaScript 代码可以通过 `RTCPeerConnection` 的方法来启动和停止视频编码，而 `VideoEncoderStateObserverImpl` 会跟踪这些编码器的状态。
* **HTML:** HTML 的 `<video>` 元素用于显示视频流。WebRTC 接收到的视频流最终会渲染到 `<video>` 元素上。`VideoEncoderStateObserverImpl` 帮助确保编码器以最佳状态工作，从而影响最终显示在 HTML 页面上的视频质量。
* **CSS:** CSS 用于样式化 HTML 元素，包括 `<video>` 元素。虽然 CSS 不直接与 `VideoEncoderStateObserverImpl` 交互，但编码器的状态和性能会间接影响视频流的质量，从而影响用户体验。

**举例说明:**

假设一个 WebRTC 应用使用 simulcast (多码流编码) 来根据网络状况提供不同质量的视频流。

* **JavaScript 调用:**  JavaScript 代码可能会设置 `RTCRtpSender` 的编码参数，启用 simulcast 并指定不同的码率和分辨率。
* **C++ 内部工作:**  Blink 引擎会创建多个视频编码器实例。`VideoEncoderStateObserverImpl` 会跟踪这些编码器，并使用 `FindHighestActiveEncoding()` 来确定当前网络状况下应该选择哪个编码器的输出流。
* **假设输入:**  网络带宽下降。
* **逻辑推理:** `VideoEncoderStateObserverImpl` 可能会检测到高分辨率的编码器性能下降或丢包率上升。
* **假设输出:** `FindHighestActiveEncoding()` 可能会返回较低分辨率的编码器的信息，以便适应当前的网络状况，从而保持视频流的流畅性，即使质量有所下降。

**用户或编程常见的使用错误：**

1. **忘记调用 `OnEncoderCreated()` 或 `OnEncoderDestroyed()`:**
   - **错误场景:** 开发者在创建或销毁视频编码器后，没有通知 `VideoEncoderStateObserverImpl`。
   - **后果:**  `VideoEncoderStateObserverImpl` 维护的状态信息不准确，可能导致 `FindHighestActiveEncoding()` 返回错误的结果，或者统计信息不完整。

2. **在多编码器场景下，编码器 ID 管理不当:**
   - **错误场景:**  开发者创建了多个编码器，但使用了相同的 ID 或者 ID 管理逻辑有误。
   - **后果:**  `VideoEncoderStateObserverImpl` 无法正确区分不同的编码器，导致状态跟踪和统计信息混乱。测试用例 `FindHighestActiveEncoding_CreateAndDestroy_VP8Simulcast_MultipleEncoders` 和 `OnEncodedImage_VP8Simulcast_MultipleEncoders` 就是为了测试在这种场景下的正确性。

3. **在更新编码层激活状态时，传递了错误的信息给 `OnRatesUpdated()`:**
   - **错误场景:**  开发者尝试激活或禁用某些编码层，但传递给 `OnRatesUpdated()` 的布尔向量与实际的层数或状态不匹配。
   - **后果:**  `VideoEncoderStateObserverImpl` 可能会错误地认为某些层是激活的或禁用的，从而影响 `FindHighestActiveEncoding()` 的判断。测试用例 `FindHighestActiveEncoding_ActivateLayers_VP9kSVC_SingleEncoder` 和 `FindHighestActiveEncoding_ActivateLayers_VP8Simulcast_MultipleEncoders` 覆盖了这类场景。

4. **没有考虑到 `VideoEncoderStateObserverImpl` 的统计信息收集延迟:**
   - **错误场景:**  开发者期望在每次编码后立即获取到精确的统计信息。
   - **后果:**  `VideoEncoderStateObserverImpl` 通常会累积一定数量的样本后才会更新统计信息，直接获取可能不是最新的。测试用例 `OnEncodedImage_VP8Simulcast_SingleEncoder` 和其他 `OnEncodedImage` 相关的测试验证了统计信息的收集机制。

总而言之，`video_encoder_state_observer_impl_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎中视频编码状态观察者的正确性和稳定性，这对于 WebRTC 视频通信功能的正常运行至关重要。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/video_encoder_state_observer_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/peerconnection/video_encoder_state_observer_impl.h"

#include <queue>

#include "base/functional/bind.h"
#include "base/numerics/safe_conversions.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "media/base/video_codecs.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/peerconnection/video_encoder_state_observer.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/webrtc/api/video/encoded_image.h"
#include "third_party/webrtc/api/video/video_content_type.h"
#include "third_party/webrtc/api/video/video_frame_type.h"
#include "third_party/webrtc/modules/video_coding/svc/scalability_mode_util.h"

namespace blink {

namespace {

constexpr int kWidth = 1280;
constexpr int kHeight = 720;

webrtc::VideoCodec BasicVideoCodec(webrtc::VideoCodecType codec_type,
                                   int width,
                                   int height) {
  webrtc::VideoCodec video_codec;
  video_codec.codecType = codec_type;
  video_codec.width = width;
  video_codec.height = height;
  video_codec.startBitrate = 300;
  video_codec.minBitrate = 30;
  video_codec.maxBitrate = 300;
  video_codec.maxFramerate = 30;
  video_codec.qpMax = 0;
  video_codec.active = true;
  video_codec.mode = webrtc::VideoCodecMode::kRealtimeVideo;
  return video_codec;
}

void FillSimulcastStreams(webrtc::VideoCodec& video_codec,
                          unsigned int num_simulcast_streams,
                          unsigned int num_temporal_layers) {
  CHECK_LE(num_simulcast_streams, std::size(video_codec.simulcastStream));
  video_codec.numberOfSimulcastStreams = num_simulcast_streams;
  for (unsigned int i = 0; i < num_simulcast_streams; i++) {
    webrtc::SimulcastStream& ss = video_codec.simulcastStream[i];
    const int log_scale = num_simulcast_streams - i - 1;
    ss.width = video_codec.width >> log_scale;
    ss.height = video_codec.height >> log_scale;
    ss.maxFramerate = video_codec.maxFramerate;
    ss.numberOfTemporalLayers = num_temporal_layers;
    ss.targetBitrate = video_codec.maxBitrate >> log_scale;
    ss.maxBitrate = ss.targetBitrate;
    ss.minBitrate = ss.targetBitrate;
    ss.qpMax = 0;
    ss.active = true;
  };
}

webrtc::VideoCodec VP8VideoCodec(unsigned int num_simulcast_streams,
                                 unsigned int num_temporal_layers,
                                 int top_layer_width = kWidth,
                                 int top_layer_height = kHeight) {
  webrtc::VideoCodec video_codec = BasicVideoCodec(
      webrtc::kVideoCodecVP8, top_layer_width, top_layer_height);
  FillSimulcastStreams(video_codec, num_simulcast_streams, num_temporal_layers);
  video_codec.VP8()->numberOfTemporalLayers = num_temporal_layers;
  video_codec.SetScalabilityMode(*webrtc::MakeScalabilityMode(
      /*num_spatial_layers=*/1, num_temporal_layers,
      webrtc::InterLayerPredMode::kOff,
      /*ratio=*/std::nullopt,
      /*shift=*/false));
  return video_codec;
}

// This is based on SimulcastEncoderAdapter::MakeStreamCodec().
webrtc::VideoCodec CreateStreamCodec(const webrtc::VideoCodec& codec,
                                     int stream_idx,
                                     bool is_highest_quality_stream) {
  webrtc::VideoCodec codec_params = codec;
  const webrtc::SimulcastStream& stream_params =
      codec.simulcastStream[stream_idx];

  codec_params.numberOfSimulcastStreams = 0;
  codec_params.width = stream_params.width;
  codec_params.height = stream_params.height;
  codec_params.maxBitrate = stream_params.maxBitrate;
  codec_params.minBitrate = stream_params.minBitrate;
  codec_params.maxFramerate = stream_params.maxFramerate;
  codec_params.qpMax = stream_params.qpMax;
  codec_params.active = stream_params.active;
  std::optional<webrtc::ScalabilityMode> scalability_mode =
      stream_params.GetScalabilityMode();
  if (codec.GetScalabilityMode().has_value()) {
    bool only_active_stream = true;
    for (int i = 0; i < codec.numberOfSimulcastStreams; ++i) {
      if (i != stream_idx && codec.simulcastStream[i].active) {
        only_active_stream = false;
        break;
      }
    }
    if (only_active_stream) {
      scalability_mode = codec.GetScalabilityMode();
    }
  }
  if (scalability_mode.has_value()) {
    codec_params.SetScalabilityMode(*scalability_mode);
  }
  if (codec.codecType == webrtc::kVideoCodecVP8) {
    codec_params.VP8()->numberOfTemporalLayers =
        stream_params.numberOfTemporalLayers;
    if (!is_highest_quality_stream) {
      // For resolutions below CIF, set the codec `complexity` parameter to
      // kComplexityHigher, which maps to cpu_used = -4.
      int pixels_per_frame = codec_params.width * codec_params.height;
      if (pixels_per_frame < 352 * 288) {
        codec_params.SetVideoEncoderComplexity(
            webrtc::VideoCodecComplexity::kComplexityHigher);
      }
      // Turn off denoising for all streams but the highest resolution.
      codec_params.VP8()->denoisingOn = false;
    }
  } else if (codec.codecType == webrtc::kVideoCodecH264) {
    codec_params.H264()->numberOfTemporalLayers =
        stream_params.numberOfTemporalLayers;
  }

  return codec_params;
}

void FillSpatialLayers(webrtc::VideoCodec& video_codec,
                       unsigned int num_spatial_layers,
                       unsigned int num_temporal_layers) {
  CHECK_LE(num_spatial_layers, std::size(video_codec.simulcastStream));
  for (unsigned int i = 0; i < num_spatial_layers; i++) {
    webrtc::SpatialLayer& sl = video_codec.spatialLayers[i];
    const int log_scale = num_spatial_layers - i - 1;
    sl.width = video_codec.width >> log_scale;
    sl.height = video_codec.height >> log_scale;
    sl.maxFramerate = video_codec.maxFramerate;
    sl.numberOfTemporalLayers = num_temporal_layers;
    sl.targetBitrate = video_codec.maxBitrate >> log_scale;
    sl.maxBitrate = sl.targetBitrate;
    sl.minBitrate = sl.targetBitrate;
    sl.qpMax = 0;
    sl.active = true;
  };
}

webrtc::VideoCodec VP9kSVCVideoCodec(unsigned int num_spatial_layers,
                                     unsigned int num_temporal_layers,
                                     int top_layer_width = kWidth,
                                     int top_layer_height = kHeight) {
  webrtc::VideoCodec video_codec = BasicVideoCodec(
      webrtc::kVideoCodecVP9, top_layer_width, top_layer_height);
  FillSpatialLayers(video_codec, num_spatial_layers, num_temporal_layers);
  webrtc::VideoCodecVP9& vp9 = *video_codec.VP9();
  vp9.numberOfTemporalLayers = num_temporal_layers;
  vp9.numberOfSpatialLayers = num_spatial_layers;
  vp9.interLayerPred = webrtc::InterLayerPredMode::kOff;

  video_codec.SetScalabilityMode(*webrtc::MakeScalabilityMode(
      num_spatial_layers, num_temporal_layers,
      webrtc::InterLayerPredMode::kOnKeyPic,
      /*ratio=*/webrtc::ScalabilityModeResolutionRatio::kTwoToOne,
      /*shift=*/false));
  return video_codec;
}

template <typename T>  // webrtc::SimulcastStream, webrtc::VideoCodec.
int PixelRate(const T& config) {
  base::CheckedNumeric<int> pixel_rate = config.width;
  pixel_rate *= config.height;
  pixel_rate *= config.maxFramerate;
  return pixel_rate.ValueOrDie();
}

std::tuple<size_t, size_t, size_t> GetActiveIndexInfo(
    const Vector<bool>& active_layers) {
  size_t num_active_layers = 0;
  int bottom_sid = -1;
  int top_sid = -1;
  for (size_t i = 0; i < active_layers.size(); i++) {
    if (active_layers[i]) {
      num_active_layers++;
      top_sid = i;
      if (bottom_sid == -1) {
        bottom_sid = i;
      }
    }
  }
  if (num_active_layers == 0) {
    return {0, 0, 0};
  }

  return {num_active_layers, bottom_sid, top_sid};
}
}  // namespace

class VideoEncoderStateObserverImplTest : public ::testing::Test {
 public:
  VideoEncoderStateObserverImplTest() = default;
  ~VideoEncoderStateObserverImplTest() override = default;

  void TearDown() override { observer_.reset(); }

 protected:
  using TopLayerInfo = VideoEncoderStateObserverImpl::TopLayerInfo;
  using EncodeResult = VideoEncoderStateObserver::EncodeResult;
  using StatsKey = StatsCollector::StatsKey;
  using VideoStats = StatsCollector::VideoStats;

  void CreateObserver(media::VideoCodecProfile profile) {
    observer_ = std::make_unique<VideoEncoderStateObserverImpl>(
        profile, base::BindRepeating(
                     &VideoEncoderStateObserverImplTest::StoreProcessingStats,
                     base::Unretained(this)));
    ASSERT_TRUE(observer_);
  }

  void ExpectTopLayerForSimulcast(
      size_t stream_idx,
      int encoder_id_offset,
      base::span<const webrtc::VideoCodec> codec_params) {
    ExpectTopLayer(encoder_id_offset + base::checked_cast<int>(stream_idx), 0,
                   PixelRate(codec_params[stream_idx]));
  }

  void ExpectTopLayerForSVC(int spatial_id,
                            int encoder_id,
                            base::span<const int> pixel_rates) {
    ExpectTopLayer(encoder_id, spatial_id,
                   pixel_rates[base::checked_cast<size_t>(spatial_id)]);
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::unique_ptr<VideoEncoderStateObserverImpl> observer_;
  std::queue<std::pair<StatsKey, VideoStats>> processing_stats_;

 private:
  void ExpectTopLayer(int encoder_id, int spatial_id, int pixel_rate) {
    CHECK(observer_);
    const std::optional<VideoEncoderStateObserverImpl::TopLayerInfo> top_layer =
        observer_->FindHighestActiveEncoding();
    ASSERT_TRUE(top_layer.has_value());
    EXPECT_EQ(top_layer->encoder_id, encoder_id);
    EXPECT_EQ(top_layer->spatial_id, spatial_id);
    EXPECT_EQ(top_layer->pixel_rate, pixel_rate);
  }

  void StoreProcessingStats(const StatsKey& stats_key,
                            const VideoStats& video_stats) {
    processing_stats_.emplace(stats_key, video_stats);
  }
};

TEST_F(VideoEncoderStateObserverImplTest,
       FindHighestActiveEncoding_CreateAndDestroy_VP8Vanilla_SingleEncoder) {
  constexpr int kEncoderId = 2;
  constexpr int kSimulcasts = 1;
  constexpr int kTemporalLayers = 3;
  const auto vp8 = VP8VideoCodec(kSimulcasts, kTemporalLayers);

  CreateObserver(media::VP8PROFILE_ANY);
  observer_->OnEncoderCreated(kEncoderId, vp8);

  std::optional<VideoEncoderStateObserverImpl::TopLayerInfo> top_layer =
      observer_->FindHighestActiveEncoding();
  ASSERT_TRUE(top_layer.has_value());
  EXPECT_EQ(top_layer->encoder_id, kEncoderId);
  EXPECT_EQ(top_layer->spatial_id, kSimulcasts - 1);
  EXPECT_EQ(top_layer->pixel_rate, PixelRate(vp8));

  observer_->OnEncoderDestroyed(kEncoderId);

  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());
}

TEST_F(VideoEncoderStateObserverImplTest,
       FindHighestActiveEncoding_CreateAndDestroy_VP8Simulcast_SingleEncoder) {
  constexpr int kEncoderId = 8;
  constexpr int kSimulcasts = 3;
  constexpr int kTemporalLayers = 3;
  const auto vp8 = VP8VideoCodec(kSimulcasts, kTemporalLayers);

  CreateObserver(media::VP8PROFILE_ANY);
  observer_->OnEncoderCreated(kEncoderId, vp8);

  std::optional<VideoEncoderStateObserverImpl::TopLayerInfo> top_layer =
      observer_->FindHighestActiveEncoding();
  ASSERT_TRUE(top_layer.has_value());
  EXPECT_EQ(top_layer->encoder_id, kEncoderId);
  EXPECT_EQ(top_layer->spatial_id, kSimulcasts - 1);
  EXPECT_EQ(top_layer->pixel_rate, PixelRate(vp8));

  observer_->OnEncoderDestroyed(kEncoderId);

  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());
}

TEST_F(
    VideoEncoderStateObserverImplTest,
    FindHighestActiveEncoding_CreateAndDestroy_VP8Simulcast_MultipleEncoders) {
  constexpr int kBaseEncoderId = 8;
  constexpr int kSimulcasts = 3;
  constexpr int kTemporalLayers = 3;

  CreateObserver(media::VP8PROFILE_ANY);
  const auto codec = VP8VideoCodec(kSimulcasts, kTemporalLayers);
  webrtc::VideoCodec codec_params[kSimulcasts];
  for (size_t stream_idx = 0; stream_idx < kSimulcasts; stream_idx++) {
    codec_params[stream_idx] =
        CreateStreamCodec(codec, stream_idx, stream_idx == kSimulcasts - 1);
    observer_->OnEncoderCreated(kBaseEncoderId + stream_idx,
                                codec_params[stream_idx]);
  }

  ExpectTopLayerForSimulcast(2, kBaseEncoderId, codec_params);

  // Destroy the top encoder.
  observer_->OnEncoderDestroyed(kBaseEncoderId + 2);
  ExpectTopLayerForSimulcast(1, kBaseEncoderId, codec_params);

  // Destroy the bottom encoder id.
  observer_->OnEncoderDestroyed(kBaseEncoderId);
  // The top encoder is still the middle one.
  ExpectTopLayerForSimulcast(1, kBaseEncoderId, codec_params);

  observer_->OnEncoderDestroyed(kBaseEncoderId + 1);
  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());
}

TEST_F(VideoEncoderStateObserverImplTest,
       FindHighestActiveEncoding_CreateAndDestroy_VP9kSVC_SingleEncoder) {
  constexpr int kEncoderId = 8;
  constexpr int kSpatialLayers = 3;
  constexpr int kTemporalLayers = 1;
  const auto vp9 = VP9kSVCVideoCodec(kSpatialLayers, kTemporalLayers);

  CreateObserver(media::VP9PROFILE_PROFILE0);
  observer_->OnEncoderCreated(kEncoderId, vp9);

  std::optional<VideoEncoderStateObserverImpl::TopLayerInfo> top_layer =
      observer_->FindHighestActiveEncoding();
  ASSERT_TRUE(top_layer.has_value());
  EXPECT_EQ(top_layer->encoder_id, kEncoderId);
  EXPECT_EQ(top_layer->spatial_id, kSpatialLayers - 1);
  EXPECT_EQ(top_layer->pixel_rate, PixelRate(vp9));

  observer_->OnEncoderDestroyed(kEncoderId);

  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());
}

TEST_F(VideoEncoderStateObserverImplTest,
       FindHighestActiveEncoding_ActivateLayers_VP9kSVC_SingleEncoder) {
  constexpr int kEncoderId = 8;
  constexpr int kSpatialLayers = 3;
  constexpr int kTemporalLayers = 3;
  const auto vp9 = VP9kSVCVideoCodec(kSpatialLayers, kTemporalLayers);
  const int kPixelRates[] = {
      PixelRate(vp9.spatialLayers[0]),
      PixelRate(vp9.spatialLayers[1]),
      PixelRate(vp9.spatialLayers[2]),
  };

  CreateObserver(media::VP9PROFILE_PROFILE0);

  observer_->OnEncoderCreated(kEncoderId, vp9);

  // Unchanged with all active layers.
  observer_->OnRatesUpdated(kEncoderId, {true, true, true});
  ExpectTopLayerForSVC(2, kEncoderId, kPixelRates);

  // Deactivate the top layer.
  observer_->OnRatesUpdated(kEncoderId, {true, true});
  ExpectTopLayerForSVC(1, kEncoderId, kPixelRates);

  // Deactivate the middle layer.
  observer_->OnRatesUpdated(kEncoderId, {true});
  ExpectTopLayerForSVC(0, kEncoderId, kPixelRates);

  // Activate the middle and top layer and deactivate the bottom layer.
  observer_->OnRatesUpdated(kEncoderId, {false, true, true});
  ExpectTopLayerForSVC(2, kEncoderId, kPixelRates);

  // Deactivate all the layers.
  observer_->OnRatesUpdated(kEncoderId, {});
  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());

  // Activate all the layers.
  observer_->OnRatesUpdated(kEncoderId, {true, true, true});
  ExpectTopLayerForSVC(2, kEncoderId, kPixelRates);

  // Deactivate all the layers.
  observer_->OnRatesUpdated(kEncoderId, {});
  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());

  observer_->OnEncoderDestroyed(kEncoderId);
  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());
}

TEST_F(VideoEncoderStateObserverImplTest,
       FindHighestActiveEncoding_ActivateLayers_VP8Simulcast_MultipleEncoders) {
  constexpr int kBaseEncoderId = 8;
  constexpr int kSimulcasts = 3;
  constexpr int kTemporalLayers = 3;
  const auto codec = VP8VideoCodec(kSimulcasts, kTemporalLayers);
  webrtc::VideoCodec codec_params[kSimulcasts];

  CreateObserver(media::VP8PROFILE_ANY);

  for (size_t stream_idx = 0; stream_idx < kSimulcasts; stream_idx++) {
    codec_params[stream_idx] =
        CreateStreamCodec(codec, stream_idx, stream_idx == kSimulcasts - 1);
    observer_->OnEncoderCreated(kBaseEncoderId + stream_idx,
                                codec_params[stream_idx]);
  }

  // Deactivate the bottom layer.
  observer_->OnRatesUpdated(kBaseEncoderId, {});
  ExpectTopLayerForSimulcast(2, kBaseEncoderId, codec_params);

  // Deactivate the top layer.
  observer_->OnRatesUpdated(kBaseEncoderId + 2, {});
  ExpectTopLayerForSimulcast(1, kBaseEncoderId, codec_params);

  // Activate the bottom layer.
  observer_->OnRatesUpdated(kBaseEncoderId, {true});
  ExpectTopLayerForSimulcast(1, kBaseEncoderId, codec_params);

  // Deactivate the bottom and middle layers, so that all layers activated.
  observer_->OnRatesUpdated(kBaseEncoderId, {false});
  observer_->OnRatesUpdated(kBaseEncoderId + 1, {false});
  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());

  // Activate the top layer.
  observer_->OnRatesUpdated(kBaseEncoderId + 2, {true});
  ExpectTopLayerForSimulcast(2, kBaseEncoderId, codec_params);

  // Destroy the top layer.
  observer_->OnEncoderDestroyed(kBaseEncoderId + 2);
  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());

  // Activate the bottom and middle layer.
  observer_->OnRatesUpdated(kBaseEncoderId, {true});
  observer_->OnRatesUpdated(kBaseEncoderId + 1, {true});
  ExpectTopLayerForSimulcast(1, kBaseEncoderId, codec_params);

  // Destroy the bottom layer.
  observer_->OnEncoderDestroyed(kBaseEncoderId);
  ExpectTopLayerForSimulcast(1, kBaseEncoderId, codec_params);

  // Destroy the middle layer.
  observer_->OnEncoderDestroyed(kBaseEncoderId + 1);
  EXPECT_FALSE(observer_->FindHighestActiveEncoding().has_value());
}

TEST_F(VideoEncoderStateObserverImplTest,
       OnEncodedImage_VP8Simulcast_SingleEncoder) {
  constexpr int kEncoderId = 8;
  constexpr int kSimulcasts = 3;
  constexpr int kTemporalLayers = 3;
  const auto vp8 = VP8VideoCodec(kSimulcasts, kTemporalLayers);

  CreateObserver(media::VP8PROFILE_ANY);
  observer_->OnEncoderCreated(kEncoderId, vp8);

  constexpr int kEncodeTimes = StatsCollector::kMinSamplesThreshold * 1.1;
  constexpr int kKeyFrameInterval = 40;
  for (size_t i = 0; i < kEncodeTimes; i++) {
    const uint32_t rtp_timestamp = 100 + i;
    const bool keyframe = i % kKeyFrameInterval == 0;
    observer_->OnEncode(kEncoderId, rtp_timestamp);
    for (size_t stream_idx = 0; stream_idx < kSimulcasts; stream_idx++) {
      observer_->OnEncodedImage(
          kEncoderId, EncodeResult{.width = vp8.width,
                                   .height = vp8.height,
                                   .keyframe = keyframe,
                                   .spatial_index = stream_idx,
                                   .rtp_timestamp = rtp_timestamp,
                                   .encode_end_time = base::TimeTicks::Now(),
                                   .is_hardware_accelerated = true});
    }
  }

  ASSERT_EQ(processing_stats_.size(), 1u);
  const auto& [stats_key, video_stats] = processing_stats_.front();
  EXPECT_EQ(stats_key.is_decode, false);
  EXPECT_EQ(stats_key.codec_profile, media::VP8PROFILE_ANY);
  EXPECT_EQ(stats_key.pixel_size, vp8.width * vp8.height);
  EXPECT_EQ(stats_key.hw_accelerated, true);

  constexpr int kKeyFrames =
      (StatsCollector::kMinSamplesThreshold + kKeyFrameInterval - 1) /
      kKeyFrameInterval;
  EXPECT_EQ(video_stats.frame_count, StatsCollector::kMinSamplesThreshold);
  // The first key frame is ignored.
  EXPECT_EQ(video_stats.key_frame_count, kKeyFrames - 1);
  EXPECT_EQ(video_stats.p99_processing_time_ms, 1u);
}

TEST_F(VideoEncoderStateObserverImplTest,
       OnEncodedImage_VP8Simulcast_MultipleEncoders) {
  constexpr int kBaseEncoderId = 8;
  constexpr int kSimulcasts = 3;
  constexpr int kTemporalLayers = 3;
  const auto codec = VP8VideoCodec(kSimulcasts, kTemporalLayers);

  CreateObserver(media::VP8PROFILE_ANY);

  webrtc::VideoCodec codec_params[kSimulcasts];
  for (size_t stream_idx = 0; stream_idx < kSimulcasts; stream_idx++) {
    codec_params[stream_idx] =
        CreateStreamCodec(codec, stream_idx, stream_idx == kSimulcasts - 1);
    observer_->OnEncoderCreated(kBaseEncoderId + stream_idx,
                                codec_params[stream_idx]);
  }

  constexpr int kEncodeTimes = StatsCollector::kMinSamplesThreshold * 1.1;
  constexpr int kKeyFrameInterval = 40;
  for (size_t i = 0; i < kEncodeTimes; i++) {
    const uint32_t rtp_timestamp = 100 + i;
    const bool keyframe = i % kKeyFrameInterval == 0;
    for (size_t stream_idx = 0; stream_idx < kSimulcasts; stream_idx++) {
      observer_->OnEncode(kBaseEncoderId + stream_idx, rtp_timestamp);
      observer_->OnEncodedImage(
          kBaseEncoderId + stream_idx,
          EncodeResult{.width = codec_params[stream_idx].width,
                       .height = codec_params[stream_idx].height,
                       .keyframe = keyframe,
                       .spatial_index = 0,
                       .rtp_timestamp = rtp_timestamp,
                       .encode_end_time = base::TimeTicks::Now(),
                       .is_hardware_accelerated = true});
    }
  }

  // No stats is recorded because multiple encoders run.
  EXPECT_EQ(processing_stats_.size(), 0u);

  // Destroy the encoders that encode top two streams.
  for (size_t stream_idx = 1; stream_idx < kSimulcasts; stream_idx++) {
    observer_->OnEncoderDestroyed(kBaseEncoderId + stream_idx);
  }

  // kCheckUpdateStatsCollectionInterval in
  // VideoEncoderStateObserverImpl::UpdateStatsCollection().
  // To activate stats collection.
  task_environment_.AdvanceClock(base::Seconds(5) + base::Milliseconds(10));

  // Encode() on the encoder for the lowest resolution stream.
  for (size_t i = kEncodeTimes; i < kEncodeTimes * 2; i++) {
    const bool keyframe = (i - kEncodeTimes) % kKeyFrameInterval == 0;
    const uint32_t rtp_timestamp = 100 + i;
    observer_->OnEncode(kBaseEncoderId, rtp_timestamp);
    observer_->OnEncodedImage(
        kBaseEncoderId, EncodeResult{.width = codec_params[0].width,
                                     .height = codec_params[0].height,
                                     .keyframe = keyframe,
                                     .spatial_index = 0,
                                     .rtp_timestamp = rtp_timestamp,
                                     .encode_end_time = base::TimeTicks::Now(),
                                     .is_hardware_accelerated = true});
  }

  EXPECT_EQ(processing_stats_.size(), 1u);
  const auto& [stats_key, video_stats] = processing_stats_.front();
  EXPECT_EQ(stats_key.is_decode, false);
  EXPECT_EQ(stats_key.codec_profile, media::VP8PROFILE_ANY);
  EXPECT_EQ(stats_key.pixel_size,
            codec_params[0].width * codec_params[0].height);
  EXPECT_EQ(stats_key.hw_accelerated, true);

  constexpr int kKeyFrames =
      (StatsCollector::kMinSamplesThreshold + kKeyFrameInterval - 1) /
      kKeyFrameInterval;
  EXPECT_EQ(video_stats.frame_count, StatsCollector::kMinSamplesThreshold);
  // The first key frame is ignored.
  EXPECT_EQ(video_stats.key_frame_count, kKeyFrames - 1);
  EXPECT_EQ(video_stats.p99_processing_time_ms, 1u);
}

TEST_F(VideoEncoderStateObserverImplTest,
       OnEncodedImage_VP9kSVC_SingleEncoder) {
  constexpr int kEncoderId = 8;
  constexpr int kSpatialLayers = 3;
  constexpr int kTemporalLayers = 1;
  const auto vp9 = VP9kSVCVideoCodec(kSpatialLayers, kTemporalLayers);

  CreateObserver(media::VP9PROFILE_PROFILE0);
  observer_->OnEncoderCreated(kEncoderId, vp9);

  constexpr int kEncodeTimes = StatsCollector::kMinSamplesThreshold * 1.1;
  constexpr int kKeyFrameInterval = 40;
  for (size_t i = 0; i < kEncodeTimes; i++) {
    const uint32_t rtp_timestamp = 100 + i;
    observer_->OnEncode(kEncoderId, rtp_timestamp);
    for (size_t sid = 0; sid < kSpatialLayers; sid++) {
      const bool keyframe = i % kKeyFrameInterval == 0 && sid == 0;
      observer_->OnEncodedImage(
          kEncoderId, EncodeResult{.width = vp9.spatialLayers[sid].width,
                                   .height = vp9.spatialLayers[sid].height,
                                   .keyframe = keyframe,
                                   .spatial_index = sid,
                                   .rtp_timestamp = rtp_timestamp,
                                   .encode_end_time = base::TimeTicks::Now(),
                                   .is_hardware_accelerated = true});
    }
  }

  EXPECT_EQ(processing_stats_.size(), 1u);
  const auto& [stats_key, video_stats] = processing_stats_.front();
  EXPECT_EQ(stats_key.is_decode, false);
  EXPECT_EQ(stats_key.codec_profile, media::VP9PROFILE_PROFILE0);
  EXPECT_EQ(stats_key.pixel_size, vp9.width * vp9.height);
  EXPECT_EQ(stats_key.hw_accelerated, true);

  EXPECT_EQ(video_stats.frame_count, StatsCollector::kMinSamplesThreshold);
  // No keyframe exists on the top spatial layer in k-SVC.
  EXPECT_EQ(video_stats.key_frame_count, 0);
  EXPECT_EQ(video_stats.p99_processing_time_ms, 1u);
}

TEST_F(VideoEncoderStateObserverImplTest,
       DynamicLayerChange_OnEncodedImage_VP9kSVC_SingleEncoder) {
  constexpr int kEncoderId = 8;
  constexpr int kSpatialLayers = 3;
  constexpr int kTemporalLayers = 1;
  const auto vp9 = VP9kSVCVideoCodec(kSpatialLayers, kTemporalLayers);

  CreateObserver(media::VP9PROFILE_PROFILE0);
  observer_->OnEncoderCreated(kEncoderId, vp9);

  const Vector<bool> active_layers_queries[] = {
      {true, false, false},  {false, false, true}, {false, true, true},
      {true, false, true},   {true, true, false},  {false, true, true},
      {false, false, false}, {true, true, true}};
  uint32_t rtp_timestamp = 100;
  size_t expected_processing_stats_size = 0;
  for (const Vector<bool>& active_layers : active_layers_queries) {
    observer_->OnRatesUpdated(kEncoderId, Vector<bool>(active_layers));
    auto [num_active_layers, bottom_sid, top_sid] =
        GetActiveIndexInfo(active_layers);
    if (num_active_layers == 0) {
      // No Encode() must be executed if no active layer exists.
      continue;
    }

    // kProcessingStatsReportingPeriod in stats_collector.cc.
    // To invoke ReportStats() for a regular period.
    task_environment_.AdvanceClock(base::Seconds(15) + base::Milliseconds(10));
    constexpr int kEncodeTimes = StatsCollector::kMinSamplesThreshold * 1.1;
    for (size_t i = 0; i < kEncodeTimes; i++) {
      rtp_timestamp++;
      observer_->OnEncode(kEncoderId, rtp_timestamp);
      for (size_t sid = 0; sid < kSpatialLayers; sid++) {
        if (!active_layers[sid]) {
          continue;
        }
        const bool keyframe = i == 0 && sid == bottom_sid;
        observer_->OnEncodedImage(
            kEncoderId, EncodeResult{.width = vp9.spatialLayers[sid].width,
                                     .height = vp9.spatialLayers[sid].height,
                                     .keyframe = keyframe,
                                     .spatial_index = sid,
                                     .rtp_timestamp = rtp_timestamp,
                                     .encode_end_time = base::TimeTicks::Now(),
                                     .is_hardware_accelerated = true});
      }
    }

    expected_processing_stats_size++;
    ASSERT_EQ(processing_stats_.size(), expected_processing_stats_size);
    const auto& [stats_key, video_stats] = processing_stats_.back();
    EXPECT_EQ(stats_key.is_decode, false);
    EXPECT_EQ(stats_key.codec_profile, media::VP9PROFILE_PROFILE0);
    EXPECT_EQ(stats_key.pixel_size, vp9.spatialLayers[top_sid].width *
                                        vp9.spatialLayers[top_sid].height);
    EXPECT_EQ(stats_key.hw_accelerated, true);

    EXPECT_EQ(video_stats.frame_count, StatsCollector::kMinSamplesThreshold);
    // The first key frame is ignored.
    EXPECT_EQ(video_stats.key_frame_count, 0);
    EXPECT_EQ(video_stats.p99_processing_time_ms, 1u);

    // Clear stats to not invoke ReportStats() on the next Encode().
    observer_->ClearStatsCollection();
  }
}
}  // namespace blink
```