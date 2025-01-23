Response: Let's break down the thought process for analyzing this C++ file.

1. **Understand the Core Purpose:** The filename `video_encoder_state_observer_impl.cc` immediately suggests that this code observes the state of video encoders. The `Impl` suffix often indicates this is the concrete implementation of an interface. The directory `blink/renderer/platform/peerconnection` further clarifies its context: it's part of the Blink rendering engine, specifically dealing with WebRTC's peer-to-peer connections. So, it's likely involved in monitoring and collecting data about the video encoding process during a WebRTC session.

2. **Identify Key Data Structures:**  Scanning the code reveals a few critical data structures:
    * `VideoEncoderStateObserverImpl`: The main class, holding the logic.
    * `EncoderState`: A nested class representing the state of a *single* encoder. This is key – the observer manages multiple encoders.
    * `EncoderState::CodecConfig`: Information about the codec used by the encoder.
    * `EncoderState::EncodeStart`:  Information about when an encoding process began for a specific frame.
    * `TopLayerInfo`:  Information about the "top" or highest quality layer being encoded.
    * `std::queue<EncodeStart>`: Used to track when encoding started for frames.
    * `std::map<int, std::unique_ptr<EncoderState>> encoder_state_by_id_`:  Crucial for managing the state of multiple encoders, indexed by their `encoder_id`.

3. **Analyze Key Methods:** Now, examine the public methods of `VideoEncoderStateObserverImpl` to understand its interactions:
    * `OnEncoderCreated()`: Called when a new video encoder is created. It stores the encoder's configuration.
    * `OnEncoderDestroyed()`: Called when an encoder is destroyed. It handles cleanup and potentially reports statistics.
    * `OnRatesUpdated()`: Called when the encoding rates or active layers are updated.
    * `OnEncode()`: Called when the encoding process for a frame *starts*.
    * `OnEncodedImage()`: Called when an encoded video frame is *finished*. This is a critical point for collecting performance data.
    * `UpdateStatsCollection()`:  Manages when statistics collection should be active or inactive.
    * `FindHighestActiveEncoding()`: Determines which encoder and layer are currently producing the highest quality output.

4. **Trace the Flow of Information:** Follow how data moves through the methods:
    * When an encoder is created (`OnEncoderCreated`), its configuration is stored in an `EncoderState` object.
    * When encoding starts (`OnEncode`), the start time is recorded.
    * When encoding finishes (`OnEncodedImage`), information like encoding time and frame size is available. The observer matches the completed frame with its start time to calculate the duration.
    * `FindHighestActiveEncoding()` is called after encoder creation or rate updates to keep track of the "best" encoding stream.

5. **Identify the Purpose of the Nested Classes:**
    * `EncoderState`:  Encapsulates the data specific to a single encoder, making the main class easier to manage. It tracks the codec configuration, when encoding started for frames, and whether the first frame has been encoded.
    * `EncoderState::CodecConfig`, `EncoderState::EncodeStart`, and `TopLayerInfo`:  Simple data structures to organize related pieces of information.

6. **Look for Connections to External Concepts (JavaScript, HTML, CSS):** Since this is within the Blink renderer, it's part of the machinery that *enables* WebRTC features exposed to JavaScript. Think about how JavaScript uses WebRTC APIs:
    * `RTCPeerConnection`: The JavaScript object managing a WebRTC connection.
    * `addTrack()`: Adds media tracks (including video) to the connection.
    * Encoding parameters (like resolution and bitrate) can be influenced by JavaScript code.

    The `VideoEncoderStateObserverImpl` doesn't directly manipulate the DOM or CSS. Its influence is more indirect – it's part of the underlying implementation that makes video streaming via WebRTC work. The collected statistics could *potentially* be exposed to JavaScript for monitoring or debugging purposes, but the current code doesn't show that directly.

7. **Consider Logic and Assumptions:**
    * **Assumption:** The code assumes that the `rtp_timestamp` uniquely identifies a frame being encoded.
    * **Logic:** The `AppendEncodeStart` and `GetEncodeStart` methods manage a queue of encoding start times to calculate encoding duration. The logic to find the "top layer" prioritizes higher resolution and frame rate.
    * **Logic:** The statistics collection is designed to be active only when a single encoder is active to get a clearer picture of individual encoder performance.

8. **Think About Potential Errors:** What could go wrong?
    * **Missing `OnEncoderCreated`:** If `OnEncode` or `OnEncodedImage` are called before `OnEncoderCreated`, the `encoder_state` map won't have an entry, leading to warnings or incorrect behavior.
    * **Incorrect `rtp_timestamp`:** If the `rtp_timestamp` in `OnEncode` doesn't match the one in `OnEncodedImage`, the encoding time calculation will fail.
    * **Race conditions (less likely in this specific file but a general consideration in multithreaded environments):** While this code uses `SEQUENCE_CHECKER`, if the calling code isn't careful, race conditions could still occur in how encoder IDs are managed.

9. **Review for Specific Features:** Note details like the use of `base::atomic_ref_count`, `base::containers::contains`, `base::sequence_checker`, and the inclusion of Webrtc headers. These provide hints about the code's environment and dependencies.

10. **Structure the Explanation:** Organize the findings into clear categories like functionality, relationships to web technologies, logical reasoning, and potential errors. Use examples to illustrate the connections and errors.

By following these steps, you can systematically analyze the code and generate a comprehensive explanation like the example provided in the initial prompt.
好的，我们来详细分析一下 `blink/renderer/platform/peerconnection/video_encoder_state_observer_impl.cc` 这个文件。

**功能概述:**

这个文件实现了 `VideoEncoderStateObserverImpl` 类，其主要功能是**观察和收集视频编码器的状态信息和性能数据**。它在 Chromium 的 Blink 渲染引擎中，作为 WebRTC peer-to-peer 连接的一部分工作。

更具体地说，它负责：

1. **跟踪多个视频编码器的生命周期:**  记录编码器的创建和销毁。
2. **监控编码器的活动状态:**  记录哪些空间层（spatial layers）是激活的。这对于分层编码（如 simulcast 和 SVC）非常重要。
3. **测量编码性能:**  记录每个编码帧的开始时间和结束时间，从而计算编码耗时。
4. **识别“最优”编码器:**  在多个编码器同时存在的情况下，确定当前哪个编码器正在产生最高质量的输出（基于分辨率和帧率）。
5. **收集统计数据:**  收集编码耗时、帧大小、硬件加速等信息，用于性能分析和监控。
6. **管理统计数据的收集时机:**  例如，可能只在单个编码器活动时收集数据，以获得更清晰的性能指标。

**与 JavaScript, HTML, CSS 的关系:**

虽然这个 C++ 文件本身不直接操作 JavaScript, HTML 或 CSS，但它支撑着 WebRTC 功能，而 WebRTC API 是通过 JavaScript 暴露给 Web 开发者的。

* **JavaScript:**
    * Web 开发者使用 JavaScript 的 `RTCPeerConnection` API 来建立和管理 WebRTC 连接，其中包括视频流的发送和接收。
    * 当 JavaScript 代码创建一个用于发送视频的 `RTCRtpSender` 时，底层的 Blink 引擎会创建相应的视频编码器。`VideoEncoderStateObserverImpl` 会监视这些编码器的状态。
    * JavaScript 代码可以通过设置 `RTCRtpEncodingParameters` 来影响视频编码的参数，例如分辨率、帧率、码率等。这些参数的变化会通过 `OnRatesUpdated` 方法反映到 `VideoEncoderStateObserverImpl` 中。
    * 例如，假设 JavaScript 代码设置了 simulcast 编码，开启了多个不同分辨率的编码器。`VideoEncoderStateObserverImpl` 会跟踪每个编码器的活动状态，包括哪些空间层是激活的。

    ```javascript
    // JavaScript 代码示例
    const sender = peerConnection.addTrack(videoTrack).sender;
    const params = sender.getParameters();
    params.encodings = [
      { rid: 'high', maxBitrate: 1000000 },
      { rid: 'mid',  maxBitrate: 500000  },
      { rid: 'low',  maxBitrate: 250000  }
    ];
    sender.setParameters(params);
    ```
    在这个例子中，`VideoEncoderStateObserverImpl` 会跟踪这三个编码器 (`high`, `mid`, `low`) 的状态。

* **HTML:**
    * HTML 的 `<video>` 元素用于展示视频流。WebRTC 获取到的视频流最终会渲染到 `<video>` 元素上。
    * `VideoEncoderStateObserverImpl` 间接地参与了这个过程，因为它监控着发送端的编码状态，这会影响接收端看到的视频质量和性能。

* **CSS:**
    * CSS 用于控制 HTML 元素的样式，包括 `<video>` 元素的大小、位置等。
    * `VideoEncoderStateObserverImpl` 与 CSS 没有直接关系。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **`OnEncoderCreated(1, codec_config_1)`:** 创建了一个 ID 为 1 的视频编码器，其配置为 `codec_config_1`（包含分辨率、帧率等信息）。
2. **`OnRatesUpdated(1, [true, false])`:**  编码器 1 的速率更新，表示只有第一个空间层是激活的。
3. **`OnEncode(1, 12345)`:**  编码器 1 开始编码 RTP 时间戳为 12345 的帧。
4. **`OnEncodedImage(1, encode_result_1)`:** 编码器 1 完成了 RTP 时间戳为 12345 的帧的编码，`encode_result_1` 包含了编码结束时间、帧大小、是否是关键帧等信息。
5. **`OnEncoderCreated(2, codec_config_2)`:** 创建了一个 ID 为 2 的视频编码器，其配置为 `codec_config_2`。

**预期输出:**

1. `encoder_state_by_id_` 会包含两个条目，分别对应编码器 ID 1 和 2。
2. 编码器 1 的 `EncoderState` 对象会记录其激活的空间层状态为 `[true, false]`。
3. 编码器 1 的 `encode_starts_` 队列会包含一个 `EncodeStart` 对象，记录了编码开始的时间戳和时间。
4. 在 `OnEncodedImage` 调用后，如果满足统计收集的条件，`VideoEncoderStateObserverImpl` 会根据 `encode_result_1` 中的信息计算编码耗时，并将其添加到统计数据中。
5. `top_encoder_info_` 会根据当前激活的编码器和其配置，指向拥有最高像素率的编码器。如果 `codec_config_2` 描述的编码器具有更高的分辨率和帧率，那么在编码器 2 创建后，`top_encoder_info_` 可能会更新指向编码器 2。

**用户或编程常见的使用错误:**

1. **未配对的 `OnEncoderCreated` 和 `OnEncoderDestroyed`:**  如果一个编码器被创建了，但忘记调用 `OnEncoderDestroyed` 进行清理，会导致资源泄漏和状态信息不准确。
   ```c++
   // 错误示例：创建了编码器但没有销毁
   observer->OnEncoderCreated(1, some_codec_config);
   // ... 某些操作 ...
   // 忘记调用 observer->OnEncoderDestroyed(1);
   ```

2. **错误的 `encoder_id`:** 在调用 `OnRatesUpdated`, `OnEncode`, `OnEncodedImage` 等方法时，使用了错误的 `encoder_id`，导致状态更新或统计数据关联到错误的编码器上。
   ```c++
   // 错误示例：使用了错误的 encoder_id
   observer->OnEncoderCreated(1, some_codec_config);
   // ...
   observer->OnEncode(2, some_rtp_timestamp); // 假设当前只有一个 ID 为 1 的编码器
   ```

3. **在编码器未创建前调用 `OnEncode` 或 `OnEncodedImage`:**  这会导致 `GetEncoderState` 返回空指针，从而引发程序错误或未定义的行为。
   ```c++
   // 错误示例：在编码器创建前尝试记录编码开始
   observer->OnEncode(1, some_rtp_timestamp); // 编码器 1 尚未创建
   ```

4. **统计数据收集的误解:**  开发者可能错误地认为无论何时都会收集统计数据。实际上，代码中存在逻辑来控制统计数据收集的时机（例如，只在单个编码器活动时收集）。如果开发者没有理解这个逻辑，可能会对收集到的数据产生误解。

5. **假设编码帧会按顺序到达:**  虽然代码中使用了队列来管理编码开始时间，但实际网络传输可能存在乱序。如果编码完成的回调 (`OnEncodedImage`) 处理不当，可能会导致与错误的编码开始时间关联，从而计算出错误的编码耗时。

**总结:**

`VideoEncoderStateObserverImpl` 是 Blink 渲染引擎中一个关键的组件，它负责监控和收集视频编码器的状态信息和性能数据。虽然它本身不直接与 JavaScript, HTML, CSS 交互，但它支撑着 WebRTC 的视频编码功能，而这些功能最终是通过 JavaScript API 暴露给 Web 开发者的。理解其功能和潜在的使用错误有助于我们更好地理解 WebRTC 的底层工作原理和进行故障排除。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/video_encoder_state_observer_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "base/atomic_ref_count.h"
#include "base/containers/contains.h"
#include "base/sequence_checker.h"
#include "third_party/webrtc/api/video/encoded_image.h"

namespace blink {
namespace {

std::atomic_int g_encoder_counter_{0};

}  // namespace

class VideoEncoderStateObserverImpl::EncoderState {
 public:
  struct CodecConfig {
    webrtc::VideoCodec codec;
    Vector<bool> active_spatial_layers;
  };
  struct EncodeStart {
    // RTIP timestamp that is the unique identifier for the frame to be encoded.
    uint32_t rtp_timestamp;
    // The actual time at which encoding of that frame started.
    base::TimeTicks time;
  };

  explicit EncoderState(const CodecConfig& codec_config)
      : codec_config_(codec_config) {}

  ~EncoderState() = default;

  bool FirstFrameEncodeCalled() const { return first_frame_encode_called_; }
  void MarkFirstFrameEncodeCalled() { first_frame_encode_called_ = true; }

  void SetActiveSpatialLayers(const Vector<bool>& active_spatial_layers) {
    codec_config_.active_spatial_layers = active_spatial_layers;
  }

  void AppendEncodeStart(uint32_t rtp_timestamp, base::TimeTicks time) {
    constexpr size_t kMaxEncodeStartQueueSize = 10;
    if (encode_starts_.size() > kMaxEncodeStartQueueSize) {
      encode_starts_.pop();
    }
    encode_starts_.push(EncodeStart{rtp_timestamp, time});
  }

  std::optional<EncodeStart> GetEncodeStart(uint32_t rtp_timestamp) {
    while (!encode_starts_.empty() &&
           encode_starts_.front().rtp_timestamp != rtp_timestamp) {
      encode_starts_.pop();
    }
    if (encode_starts_.empty()) {
      return std::nullopt;
    }
    return encode_starts_.front();
  }

  std::optional<VideoEncoderStateObserverImpl::TopLayerInfo> TopLayer() const {
    if (!codec_config_.active_spatial_layers.Contains(true)) {
      // No Active layers.
      return std::nullopt;
    }

    const webrtc::VideoCodec& codec = codec_config_.codec;
    int active_vec_size =
        base::saturated_cast<int>(codec_config_.active_spatial_layers.size());

    using TopLayerInfo = VideoEncoderStateObserverImpl::TopLayerInfo;
    std::optional<TopLayerInfo> top_layer;
    if (codec.codecType == webrtc::VideoCodecType::kVideoCodecVP9 &&
        codec.VP9().numberOfSpatialLayers > 0) {
      for (int i = 0; i < codec.VP9().numberOfSpatialLayers; ++i) {
        const webrtc::SpatialLayer& stream = codec.spatialLayers[i];
        int pixel_rate =
            (active_vec_size >= i + 1 && codec_config_.active_spatial_layers[i]
                 ? 1
                 : 0) *
            (stream.active ? 1 : 0) * stream.width * stream.height *
            base::checked_cast<int>(stream.maxFramerate);
        if (!top_layer || top_layer->pixel_rate <= pixel_rate) {
          top_layer = TopLayerInfo{
              .encoder_id = 0, .spatial_id = i, .pixel_rate = pixel_rate};
        }
      }
    } else {
      for (int i = 0; i < codec.numberOfSimulcastStreams; ++i) {
        const webrtc::SimulcastStream& stream = codec.simulcastStream[i];
        int pixel_rate =
            (active_vec_size >= i + 1 && codec_config_.active_spatial_layers[i]
                 ? 1
                 : 0) *
            (stream.active ? 1 : 0) * stream.width * stream.height *
            base::checked_cast<int>(stream.maxFramerate);
        if (!top_layer || top_layer->pixel_rate <= pixel_rate) {
          top_layer = TopLayerInfo{
              .encoder_id = 0, .spatial_id = i, .pixel_rate = pixel_rate};
        }
      }
    }
    if (!top_layer) {
      // No layering configured.
      top_layer = TopLayerInfo{
          .encoder_id = 0,
          .spatial_id = 0,
          .pixel_rate = codec.width * codec.height *
                        base::checked_cast<int>(codec.maxFramerate)};
    }
    return top_layer;
  }

 private:
  CodecConfig codec_config_;
  std::queue<EncodeStart> encode_starts_;
  bool first_frame_encode_called_ = false;
};

VideoEncoderStateObserverImpl::VideoEncoderStateObserverImpl(
    media::VideoCodecProfile profile,
    const StatsCollector::StoreProcessingStatsCB& store_processing_stats_cb)
    : StatsCollector(/*is_decode=*/false, profile, store_processing_stats_cb) {
  DETACH_FROM_SEQUENCE(encoder_sequence_);
}

VideoEncoderStateObserverImpl::~VideoEncoderStateObserverImpl() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(encoder_sequence_);
  for (const auto& kv : encoder_state_by_id_) {
    OnEncoderDestroyed(kv.first);
  }
}

void VideoEncoderStateObserverImpl::OnEncoderCreated(
    int encoder_id,
    const webrtc::VideoCodec& config) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(encoder_sequence_);
  DCHECK(!base::Contains(encoder_state_by_id_, encoder_id));

  // Initially, assume all layers active.
  // TODO(hiroh): Set the number of layers to the currently configured layers?
  Vector<bool> active_spatial_layers(webrtc::kMaxSpatialLayers, true);

  CHECK(encoder_state_by_id_
            .insert_or_assign(
                encoder_id,
                std::make_unique<EncoderState>(EncoderState::CodecConfig{
                    config, std::move(active_spatial_layers)}))
            .second);
  top_encoder_info_ = FindHighestActiveEncoding();
}

void VideoEncoderStateObserverImpl::OnEncoderDestroyed(int encoder_id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(encoder_sequence_);
  EncoderState* encoder_state = GetEncoderState(encoder_id);
  if (!encoder_state) {
    return;
  }

  if (active_stats_collection() &&
      samples_collected() >= kMinSamplesThreshold) {
    ReportStats();
    ClearStatsCollection();
  }

  if (encoder_state->FirstFrameEncodeCalled()) {
    CHECK_GE(--g_encoder_counter_, 0);
  }

  CHECK_EQ(encoder_state_by_id_.erase(encoder_id), 1u);
  top_encoder_info_ = FindHighestActiveEncoding();
}

void VideoEncoderStateObserverImpl::OnRatesUpdated(
    int encoder_id,
    const Vector<bool>& active_spatial_layers) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(encoder_sequence_);
  EncoderState* encoder_state = GetEncoderState(encoder_id);
  if (!encoder_state) {
    return;
  }

  encoder_state->SetActiveSpatialLayers(active_spatial_layers);
  top_encoder_info_ = FindHighestActiveEncoding();
}

VideoEncoderStateObserverImpl::EncoderState*
VideoEncoderStateObserverImpl::GetEncoderState(int encoder_id,
                                               base::Location location) {
  auto it = encoder_state_by_id_.find(encoder_id);
  if (it == encoder_state_by_id_.end()) {
    LOG(WARNING) << "No encoder id: " << encoder_id << " ("
                 << location.function_name() << ")";
    return nullptr;
  }
  return it->second.get();
}

void VideoEncoderStateObserverImpl::OnEncode(int encoder_id,
                                             uint32_t rtp_timestamp) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(encoder_sequence_);
  EncoderState* encoder_state = GetEncoderState(encoder_id);
  if (!encoder_state) {
    return;
  }
  if (!encoder_state->FirstFrameEncodeCalled()) {
    g_encoder_counter_++;
    encoder_state->MarkFirstFrameEncodeCalled();
    return;
  }
  encoder_state->AppendEncodeStart(rtp_timestamp, base::TimeTicks::Now());
}

void VideoEncoderStateObserverImpl::OnEncodedImage(int encoder_id,
                                                   const EncodeResult& result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(encoder_sequence_);
  if (!top_encoder_info_) {
    LOG(WARNING) << "Received encoded frame while no active encoder "
                    "configured, ignoring.";
    return;
  }
  if (encoder_id != top_encoder_info_->encoder_id ||
      result.spatial_index.value_or(0) != top_encoder_info_->spatial_id) {
    return;
  }

  if (stats_collection_finished()) {
    return;
  }

  // Frame from highest active encoder.
  auto now = base::TimeTicks::Now();
  EncoderState* encoder_state = GetEncoderState(encoder_id);
  if (!encoder_state) {
    return;
  }

  auto encode_start = encoder_state->GetEncodeStart(result.rtp_timestamp);
  if (!encode_start) {
    return;
  }

  UpdateStatsCollection(now);

  if (!active_stats_collection()) {
    return;
  }

  const float encode_time_ms =
      (result.encode_end_time - encode_start->time).InMillisecondsF();
  const int pixel_size = result.width * result.height;
  AddProcessingTime(pixel_size, result.is_hardware_accelerated, encode_time_ms,
                    result.keyframe, now);
}

void VideoEncoderStateObserverImpl::UpdateStatsCollection(base::TimeTicks now) {
  constexpr base::TimeDelta kCheckUpdateStatsCollectionInterval =
      base::Seconds(5);
  if ((now - last_update_stats_collection_time_) <
      kCheckUpdateStatsCollectionInterval) {
    return;
  }
  DVLOG(3) << "The number of simultaneous encoders: " << g_encoder_counter_;
  last_update_stats_collection_time_ = now;

  // Limit data collection to when only a single encoder is active. This gives
  // an optimistic estimate of the performance.
  constexpr int kMaximumEncodersToCollectStats = 1;
  if (active_stats_collection()) {
    if (g_encoder_counter_ > kMaximumEncodersToCollectStats) {
      // Too many encoders, cancel stats collection.
      ClearStatsCollection();
    }
  } else if (g_encoder_counter_ <= kMaximumEncodersToCollectStats) {
    // Start up stats collection since there's only a single encoder active.
    StartStatsCollection();
  }
}

std::optional<VideoEncoderStateObserverImpl::TopLayerInfo>
VideoEncoderStateObserverImpl::FindHighestActiveEncoding() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(encoder_sequence_);
  std::optional<TopLayerInfo> top_info;
  for (const auto& kv : encoder_state_by_id_) {
    std::optional<TopLayerInfo> top_of_encoder = kv.second->TopLayer();
    if (top_of_encoder &&
        (!top_info || top_info->pixel_rate < top_of_encoder->pixel_rate)) {
      top_of_encoder->encoder_id = kv.first;
      top_info = top_of_encoder;
    }
  }

#if DCHECK_IS_ON()
  if (top_info && (!top_encoder_info_ ||
                   top_encoder_info_->encoder_id != top_info->encoder_id ||
                   top_encoder_info_->spatial_id != top_info->spatial_id ||
                   top_encoder_info_->pixel_rate != top_info->pixel_rate)) {
    DVLOG(3) << "New top resolution configured for video encoder: encoder id = "
             << top_info->encoder_id
             << ", spatial id = " << top_info->spatial_id
             << ", pixel rate = " << top_info->pixel_rate;
  }
#endif  // DCHECK_IS_ON()

  return top_info;
}
}  // namespace blink
```