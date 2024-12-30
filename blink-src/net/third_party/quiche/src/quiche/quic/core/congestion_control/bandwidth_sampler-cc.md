Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Core Purpose:** The file name and the initial comments clearly indicate this is about `BandwidthSampler`. The inclusion of `congestion_control` in the path reinforces that it's related to managing network traffic and preventing congestion. The comments about copyright from Google/Chromium give context.

2. **Identify Key Classes and Structures:**  A quick scan reveals the main class `BandwidthSampler` and helper classes like `MaxAckHeightTracker` and structures like `SendTimeState` and `BandwidthSample`. Understanding the relationships between these is crucial.

3. **Analyze `SendTimeState`:** This is a simple data structure. Its members (`is_valid`, `is_app_limited`, `total_bytes_sent`, etc.) suggest it's used to store the network state at the time a packet was sent. The `operator<<` overload is for debugging output.

4. **Analyze `MaxAckHeightTracker`:**  This class seems more complex. Its `Update` method takes bandwidth estimates and packet acknowledgments as input. The name suggests it's tracking something related to the maximum "height" of acknowledgments, which likely relates to detecting bursts of acknowledgments and potentially over-estimation of bandwidth. The logic involving `ExtraAckedEvent` and filtering (using `max_ack_height_filter_`) points to a mechanism for smoothing or identifying significant acknowledgment events. The handling of bandwidth increases and full rounds provides clues about its specific goals.

5. **Deep Dive into `BandwidthSampler`:**
    * **Constructor(s):** The constructors initialize member variables. The copy constructor indicates that the state can be copied.
    * **`OnPacketSent`:** This function is called when a packet is sent. It updates `total_bytes_sent_` and stores information about the sent packet in `connection_state_map_`. The logic for handling `bytes_in_flight == 0` is interesting and suggests it's used to initialize sampling at the start of a connection. The bug checks and the `max_tracked_packets_` limit are also important to note.
    * **`OnPacketNeutered`:** This handles cases where a packet is neither acknowledged nor lost, such as when a retransmission makes the original transmission irrelevant.
    * **`OnCongestionEvent`:** This is a core function. It processes acknowledged and lost packets. It calls `OnPacketLost` and `OnPacketAcknowledged`. It calculates the `CongestionEventSample`, which includes bandwidth and RTT information. The interaction with `MaxAckHeightTracker` in `OnAckEventEnd` is a key point.
    * **`OnAckEventEnd`:**  This seems to finalize the processing of an acknowledgment event and updates the `MaxAckHeightTracker`.
    * **`OnPacketAcknowledged` (and `Inner`):** This function is called when a packet is acknowledged. It calculates bandwidth samples using the time difference between acknowledgments. The `overestimate_avoidance_` logic and the `ChooseA0Point` function are significant here. The handling of potentially out-of-order acknowledgments (checking `ack_time <= a0.ack_time`) is crucial for robustness.
    * **`OnPacketLost`:**  Handles packet losses and updates `total_bytes_lost_`.
    * **`OnAppLimited`:**  Marks the connection as application-limited.
    * **`RemoveObsoletePackets`:** Cleans up the `connection_state_map_`.
    * **Getter Methods:**  Provides access to internal state.
    * **`EnableOverestimateAvoidance`:**  A method to enable a specific feature.

6. **Identify Functionality:** Based on the analysis above, we can list the core functions of the `BandwidthSampler`.

7. **JavaScript Relationship:**  Consider if any of the concepts or functionalities have direct counterparts in JavaScript. While JavaScript doesn't have direct access to low-level network stack information in the same way, concepts like bandwidth estimation and congestion control are relevant in higher-level networking libraries or browser implementations of network protocols (like WebTransport or QUIC).

8. **Logical Reasoning (Assumptions and Outputs):**  Choose specific functions with clear inputs and outputs to demonstrate logical flow. For instance, `OnPacketSent` takes packet information and updates internal state. `OnPacketAcknowledged` takes acknowledgment information and produces a `BandwidthSample`. Create simple scenarios to illustrate these.

9. **Common Usage Errors:** Think about how a developer might misuse or misunderstand the `BandwidthSampler`. This involves thinking about preconditions, side effects, and potential race conditions (although the provided code doesn't show explicit threading). For instance, failing to call `OnPacketSent` or misinterpreting the meaning of the returned `BandwidthSample`.

10. **Debugging Scenario:**  Construct a plausible user action and the sequence of events that would lead to the execution of code within `bandwidth_sampler.cc`. This involves tracing the flow from a user action (like loading a webpage) down through the network stack.

11. **Review and Refine:**  Read through the analysis and ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or missing details. Make sure the examples are concrete and easy to understand. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. For example, initially, I might just say "it tracks packets", but refining it to "it tracks the state of sent packets that have retransmittable data" is more accurate.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/congestion_control/bandwidth_sampler.cc` 这个 Chromium 网络栈的源代码文件。

**功能列举:**

这个 `bandwidth_sampler.cc` 文件实现了一个 `BandwidthSampler` 类，它的主要功能是：

1. **采样网络带宽:**  通过记录发送和接收（确认）数据包的时间和大小，来估计当前网络连接的可用带宽。
2. **跟踪发送状态:**  维护已发送但尚未确认的数据包的状态信息，包括发送时间、数据量等。这通过 `ConnectionStateOnSentPacket` 和 `connection_state_map_` 实现。
3. **检测应用层限制:**  判断当前发送速率是否受到应用层数据产生的速度的限制（即 "app-limited"）。
4. **计算往返时间 (RTT):**  基于发送时间和确认时间来估算网络的往返延迟。
5. **处理拥塞事件:**  在发生丢包或收到确认包时，更新带宽估计和 RTT 信息，并生成用于拥塞控制算法的采样数据 (`CongestionEventSample`)。
6. **处理重复确认 (ACK) 的累积效应:** `MaxAckHeightTracker` 用于跟踪在一段时间内收到的额外确认字节数，这有助于更准确地估计带宽，尤其是在网络带宽突然增加的情况下。
7. **避免带宽过估计:** 通过 `overestimate_avoidance_` 特性，使用更保守的策略来选择用于计算带宽的基准点 (A0 点)，从而避免在某些情况下过高地估计带宽。
8. **移除过时的包信息:**  清理 `connection_state_map_` 中已经不可能再被确认的包的信息，例如由于重传而被取代的包。

**与 JavaScript 功能的关系 (间接):**

`BandwidthSampler` 本身是用 C++ 实现的，直接与 JavaScript 没有代码级别的关系。然而，它的功能直接影响着基于 Chromium 内核的浏览器中网络请求的性能，而 JavaScript 代码正是运行在这些浏览器中的。

* **网页加载速度:**  `BandwidthSampler` 更准确的带宽估计和拥塞控制有助于更快地加载网页资源，提升用户体验。JavaScript 可以通过 `Performance API` 等接口来监控页面加载的性能指标，从而间接地反映出 `BandwidthSampler` 的工作效果。例如，`navigationTiming` 或 `resourceTiming` 可以提供资源加载的耗时信息。
* **实时通信 (WebRTC):** 如果 JavaScript 应用使用了 WebRTC 进行实时音视频通信，`BandwidthSampler` 的工作会影响音视频流的质量和流畅度。不准确的带宽估计可能导致卡顿或丢帧。
* **数据传输:**  对于使用 `Fetch API` 或 `XMLHttpRequest` 进行数据上传下载的 JavaScript 应用，`BandwidthSampler` 影响着数据传输的速度。
* **QUIC 协议:**  此代码位于 QUIC 协议相关的目录中，QUIC 是一种旨在替代 TCP 的新型传输层协议，提供更快的连接建立、更低的延迟等特性。JavaScript 可以通过浏览器提供的接口使用基于 QUIC 的连接 (虽然细节通常被浏览器抽象了)。

**举例说明:**

假设一个 JavaScript 代码发起一个 HTTP/3 请求 (HTTP/3 基于 QUIC)：

```javascript
fetch('https://example.com/large_image.jpg')
  .then(response => response.blob())
  .then(imageBlob => {
    // 处理图片数据
    console.log('Image loaded!');
  });
```

在这个过程中，底层的 Chromium 网络栈会使用 `BandwidthSampler` 来估计当前网络到 `example.com` 服务器的可用带宽。

* **输入 (假设):**
    * 连续发送了几个数据包，每个 10KB。
    * 收到了一些确认包，指示这些数据包被成功接收。
    * 一些确认包到达的时间间隔较短。
* **`BandwidthSampler` 的逻辑推理:**
    * `OnPacketSent` 会记录每个发送的数据包的信息 (发送时间、大小)。
    * `OnPacketAcknowledged` 会根据确认包的到达时间计算带宽样本。如果短时间内收到多个确认包，`MaxAckHeightTracker` 会记录这种 "额外" 的确认，并可能提升带宽估计。
* **输出 (影响):**
    * 更高的带宽估计可能允许拥塞控制算法发送更多的数据，从而更快地下载 `large_image.jpg`。
    * 如果网络出现拥塞，`BandwidthSampler` 检测到丢包，会降低带宽估计，从而减缓发送速度，避免进一步拥塞。

**用户或编程常见的使用错误 (在 C++ 代码的上下文中):**

虽然用户不会直接操作 `BandwidthSampler`，但在开发网络相关的 C++ 代码时，可能会遇到以下与 `BandwidthSampler` 相关的错误：

1. **没有正确调用 `OnPacketSent` 或 `OnPacketAcknowledged`:**  如果在数据包发送或接收时没有正确地通知 `BandwidthSampler`，会导致其无法进行准确的带宽估计。
    * **例子:** 在自定义的 QUIC 实现中，忘记在发送数据包后调用 `bandwidth_sampler_->OnPacketSent(...)`。
2. **在不正确的时机调用 `OnAppLimited`:**  如果过早或过晚地标记连接为应用层限制，会影响带宽采样的准确性。
    * **例子:** 在所有数据发送完毕后才调用 `OnAppLimited`，导致在连接的早期阶段的带宽估计不准确。
3. **没有正确处理 `CongestionEventSample` 的返回值:** 拥塞控制算法依赖于 `BandwidthSampler` 提供的采样数据来调整发送速率。如果算法没有正确使用这些信息，可能导致拥塞或欠利用网络。
    * **例子:** 忽略了 `CongestionEventSample::sample_max_bandwidth`，导致拥塞控制算法没有及时根据最新的带宽估计调整窗口大小。
4. **误解 `MaxAckHeightTracker` 的作用:**  可能错误地配置或使用 `MaxAckHeightTracker` 的参数，导致对带宽变化的反应不灵敏或过于敏感。
    * **例子:**  设置过小的 `max_height_tracker_window_length`，导致 `MaxAckHeightTracker` 只能看到很短时间内的确认信息，无法捕捉到持续的带宽提升。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个使用了 HTTP/3 的网站，并且网络出现了一些波动，导致下载速度变慢。作为调试网络问题的开发者，可能会通过以下步骤来分析 `BandwidthSampler` 的行为：

1. **用户操作:** 用户在 Chrome 浏览器中输入网址 `https://example.com/big_file` 并按下回车。
2. **DNS 解析:** 浏览器进行 DNS 查询，解析 `example.com` 的 IP 地址。
3. **连接建立 (QUIC):** 浏览器尝试与服务器建立 QUIC 连接。这涉及到握手过程，期间会交换一些控制信息。
4. **数据请求:** 浏览器发送 HTTP/3 请求，请求 `big_file`。
5. **数据包发送:** Chromium 网络栈开始将 `big_file` 的数据分割成 QUIC 数据包进行发送。
    * **`BandwidthSampler::OnPacketSent` 被调用:**  每次发送一个数据包时，`OnPacketSent` 会被调用，记录发送时间、包大小等信息。
6. **数据包传输:** 数据包经过网络传输到服务器。
7. **数据包接收与确认:** 服务器接收到数据包后，会发送确认 (ACK) 包。
8. **确认包接收:** 客户端接收到确认包。
    * **`BandwidthSampler::OnPacketAcknowledged` 被调用:**  收到确认包后，`OnPacketAcknowledged` 会被调用，根据确认包的到达时间以及之前发送的包的信息，计算带宽样本和 RTT。
    * **`MaxAckHeightTracker::Update` 被调用:**  更新额外确认的统计信息。
9. **拥塞控制:**  Chromium 的拥塞控制算法 (例如 Cubic, BBR) 会定期调用 `BandwidthSampler::OnCongestionEvent`，传入收到的确认包和丢失包的信息。
    * **`BandwidthSampler::OnCongestionEvent` 的逻辑:**  遍历确认包和丢失包，调用 `OnPacketAcknowledged` 和 `OnPacketLost`。根据采样结果更新带宽估计，并返回 `CongestionEventSample` 给拥塞控制算法。
10. **发送速率调整:** 拥塞控制算法根据 `BandwidthSampler` 提供的带宽估计和 RTT 信息，调整发送窗口大小和发送速率。如果网络拥塞，可能会减少发送速率；如果网络状况良好，可能会增加发送速率。
11. **数据持续传输:**  重复步骤 5-10，直到 `big_file` 下载完成。
12. **网络波动:** 假设在下载过程中，网络出现短暂的拥塞，导致一些数据包丢失。
    * **丢包检测:** QUIC 协议栈检测到丢包。
    * **`BandwidthSampler::OnPacketLost` 被调用:**  通知 `BandwidthSampler` 发生了丢包事件。
    * **`OnCongestionEvent` 处理丢失包:** `OnCongestionEvent` 会处理丢失的包，`BandwidthSampler` 的带宽估计可能会下降。
    * **拥塞控制调整:** 拥塞控制算法会根据新的带宽估计和丢包信息，大幅降低发送速率，这可能导致用户感知到下载速度变慢。

通过分析 `bandwidth_sampler.cc` 的代码，结合网络抓包工具 (如 Wireshark) 以及 Chrome 提供的网络调试工具 (`chrome://net-internals/#quic` 或 `chrome://webrtc-internals`)，开发者可以深入了解在网络波动期间，`BandwidthSampler` 是如何工作的，以及拥塞控制算法是如何响应的，从而定位性能瓶颈或网络问题的原因。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/bandwidth_sampler.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/bandwidth_sampler.h"

#include <algorithm>
#include <ostream>

#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

std::ostream& operator<<(std::ostream& os, const SendTimeState& s) {
  os << "{valid:" << s.is_valid << ", app_limited:" << s.is_app_limited
     << ", total_sent:" << s.total_bytes_sent
     << ", total_acked:" << s.total_bytes_acked
     << ", total_lost:" << s.total_bytes_lost
     << ", inflight:" << s.bytes_in_flight << "}";
  return os;
}

QuicByteCount MaxAckHeightTracker::Update(
    QuicBandwidth bandwidth_estimate, bool is_new_max_bandwidth,
    QuicRoundTripCount round_trip_count,
    QuicPacketNumber last_sent_packet_number,
    QuicPacketNumber last_acked_packet_number, QuicTime ack_time,
    QuicByteCount bytes_acked) {
  bool force_new_epoch = false;

  if (reduce_extra_acked_on_bandwidth_increase_ && is_new_max_bandwidth) {
    // Save and clear existing entries.
    ExtraAckedEvent best = max_ack_height_filter_.GetBest();
    ExtraAckedEvent second_best = max_ack_height_filter_.GetSecondBest();
    ExtraAckedEvent third_best = max_ack_height_filter_.GetThirdBest();
    max_ack_height_filter_.Clear();

    // Reinsert the heights into the filter after recalculating.
    QuicByteCount expected_bytes_acked = bandwidth_estimate * best.time_delta;
    if (expected_bytes_acked < best.bytes_acked) {
      best.extra_acked = best.bytes_acked - expected_bytes_acked;
      max_ack_height_filter_.Update(best, best.round);
    }
    expected_bytes_acked = bandwidth_estimate * second_best.time_delta;
    if (expected_bytes_acked < second_best.bytes_acked) {
      QUICHE_DCHECK_LE(best.round, second_best.round);
      second_best.extra_acked = second_best.bytes_acked - expected_bytes_acked;
      max_ack_height_filter_.Update(second_best, second_best.round);
    }
    expected_bytes_acked = bandwidth_estimate * third_best.time_delta;
    if (expected_bytes_acked < third_best.bytes_acked) {
      QUICHE_DCHECK_LE(second_best.round, third_best.round);
      third_best.extra_acked = third_best.bytes_acked - expected_bytes_acked;
      max_ack_height_filter_.Update(third_best, third_best.round);
    }
  }

  // If any packet sent after the start of the epoch has been acked, start a new
  // epoch.
  if (start_new_aggregation_epoch_after_full_round_ &&
      last_sent_packet_number_before_epoch_.IsInitialized() &&
      last_acked_packet_number.IsInitialized() &&
      last_acked_packet_number > last_sent_packet_number_before_epoch_) {
    QUIC_DVLOG(3) << "Force starting a new aggregation epoch. "
                     "last_sent_packet_number_before_epoch_:"
                  << last_sent_packet_number_before_epoch_
                  << ", last_acked_packet_number:" << last_acked_packet_number;
    if (reduce_extra_acked_on_bandwidth_increase_) {
      QUIC_BUG(quic_bwsampler_46)
          << "A full round of aggregation should never "
          << "pass with startup_include_extra_acked(B204) enabled.";
    }
    force_new_epoch = true;
  }
  if (aggregation_epoch_start_time_ == QuicTime::Zero() || force_new_epoch) {
    aggregation_epoch_bytes_ = bytes_acked;
    aggregation_epoch_start_time_ = ack_time;
    last_sent_packet_number_before_epoch_ = last_sent_packet_number;
    ++num_ack_aggregation_epochs_;
    return 0;
  }

  // Compute how many bytes are expected to be delivered, assuming max bandwidth
  // is correct.
  QuicTime::Delta aggregation_delta = ack_time - aggregation_epoch_start_time_;
  QuicByteCount expected_bytes_acked = bandwidth_estimate * aggregation_delta;
  // Reset the current aggregation epoch as soon as the ack arrival rate is less
  // than or equal to the max bandwidth.
  if (aggregation_epoch_bytes_ <=
      ack_aggregation_bandwidth_threshold_ * expected_bytes_acked) {
    QUIC_DVLOG(3) << "Starting a new aggregation epoch because "
                     "aggregation_epoch_bytes_ "
                  << aggregation_epoch_bytes_
                  << " is smaller than expected. "
                     "ack_aggregation_bandwidth_threshold_:"
                  << ack_aggregation_bandwidth_threshold_
                  << ", expected_bytes_acked:" << expected_bytes_acked
                  << ", bandwidth_estimate:" << bandwidth_estimate
                  << ", aggregation_duration:" << aggregation_delta
                  << ", new_aggregation_epoch:" << ack_time
                  << ", new_aggregation_bytes_acked:" << bytes_acked;
    // Reset to start measuring a new aggregation epoch.
    aggregation_epoch_bytes_ = bytes_acked;
    aggregation_epoch_start_time_ = ack_time;
    last_sent_packet_number_before_epoch_ = last_sent_packet_number;
    ++num_ack_aggregation_epochs_;
    return 0;
  }

  aggregation_epoch_bytes_ += bytes_acked;

  // Compute how many extra bytes were delivered vs max bandwidth.
  QuicByteCount extra_bytes_acked =
      aggregation_epoch_bytes_ - expected_bytes_acked;
  QUIC_DVLOG(3) << "Updating MaxAckHeight. ack_time:" << ack_time
                << ", last sent packet:" << last_sent_packet_number
                << ", bandwidth_estimate:" << bandwidth_estimate
                << ", bytes_acked:" << bytes_acked
                << ", expected_bytes_acked:" << expected_bytes_acked
                << ", aggregation_epoch_bytes_:" << aggregation_epoch_bytes_
                << ", extra_bytes_acked:" << extra_bytes_acked;
  ExtraAckedEvent new_event;
  new_event.extra_acked = extra_bytes_acked;
  new_event.bytes_acked = aggregation_epoch_bytes_;
  new_event.time_delta = aggregation_delta;
  max_ack_height_filter_.Update(new_event, round_trip_count);
  return extra_bytes_acked;
}

BandwidthSampler::BandwidthSampler(
    const QuicUnackedPacketMap* unacked_packet_map,
    QuicRoundTripCount max_height_tracker_window_length)
    : total_bytes_sent_(0),
      total_bytes_acked_(0),
      total_bytes_lost_(0),
      total_bytes_neutered_(0),
      total_bytes_sent_at_last_acked_packet_(0),
      last_acked_packet_sent_time_(QuicTime::Zero()),
      last_acked_packet_ack_time_(QuicTime::Zero()),
      is_app_limited_(true),
      connection_state_map_(),
      max_tracked_packets_(GetQuicFlag(quic_max_tracked_packet_count)),
      unacked_packet_map_(unacked_packet_map),
      max_ack_height_tracker_(max_height_tracker_window_length),
      total_bytes_acked_after_last_ack_event_(0),
      overestimate_avoidance_(false),
      limit_max_ack_height_tracker_by_send_rate_(false) {}

BandwidthSampler::BandwidthSampler(const BandwidthSampler& other)
    : total_bytes_sent_(other.total_bytes_sent_),
      total_bytes_acked_(other.total_bytes_acked_),
      total_bytes_lost_(other.total_bytes_lost_),
      total_bytes_neutered_(other.total_bytes_neutered_),
      total_bytes_sent_at_last_acked_packet_(
          other.total_bytes_sent_at_last_acked_packet_),
      last_acked_packet_sent_time_(other.last_acked_packet_sent_time_),
      last_acked_packet_ack_time_(other.last_acked_packet_ack_time_),
      last_sent_packet_(other.last_sent_packet_),
      last_acked_packet_(other.last_acked_packet_),
      is_app_limited_(other.is_app_limited_),
      end_of_app_limited_phase_(other.end_of_app_limited_phase_),
      connection_state_map_(other.connection_state_map_),
      recent_ack_points_(other.recent_ack_points_),
      a0_candidates_(other.a0_candidates_),
      max_tracked_packets_(other.max_tracked_packets_),
      unacked_packet_map_(other.unacked_packet_map_),
      max_ack_height_tracker_(other.max_ack_height_tracker_),
      total_bytes_acked_after_last_ack_event_(
          other.total_bytes_acked_after_last_ack_event_),
      overestimate_avoidance_(other.overestimate_avoidance_),
      limit_max_ack_height_tracker_by_send_rate_(
          other.limit_max_ack_height_tracker_by_send_rate_) {}

void BandwidthSampler::EnableOverestimateAvoidance() {
  if (overestimate_avoidance_) {
    return;
  }

  overestimate_avoidance_ = true;
  // TODO(wub): Change the default value of
  // --quic_ack_aggregation_bandwidth_threshold to 2.0.
  max_ack_height_tracker_.SetAckAggregationBandwidthThreshold(2.0);
}

BandwidthSampler::~BandwidthSampler() {}

void BandwidthSampler::OnPacketSent(
    QuicTime sent_time, QuicPacketNumber packet_number, QuicByteCount bytes,
    QuicByteCount bytes_in_flight,
    HasRetransmittableData has_retransmittable_data) {
  last_sent_packet_ = packet_number;

  if (has_retransmittable_data != HAS_RETRANSMITTABLE_DATA) {
    return;
  }

  total_bytes_sent_ += bytes;

  // If there are no packets in flight, the time at which the new transmission
  // opens can be treated as the A_0 point for the purpose of bandwidth
  // sampling. This underestimates bandwidth to some extent, and produces some
  // artificially low samples for most packets in flight, but it provides with
  // samples at important points where we would not have them otherwise, most
  // importantly at the beginning of the connection.
  if (bytes_in_flight == 0) {
    last_acked_packet_ack_time_ = sent_time;
    if (overestimate_avoidance_) {
      recent_ack_points_.Clear();
      recent_ack_points_.Update(sent_time, total_bytes_acked_);
      a0_candidates_.clear();
      a0_candidates_.push_back(recent_ack_points_.MostRecentPoint());
    }
    total_bytes_sent_at_last_acked_packet_ = total_bytes_sent_;

    // In this situation ack compression is not a concern, set send rate to
    // effectively infinite.
    last_acked_packet_sent_time_ = sent_time;
  }

  if (!connection_state_map_.IsEmpty() &&
      packet_number >
          connection_state_map_.last_packet() + max_tracked_packets_) {
    if (unacked_packet_map_ != nullptr && !unacked_packet_map_->empty()) {
      QuicPacketNumber maybe_least_unacked =
          unacked_packet_map_->GetLeastUnacked();
      QUIC_BUG(quic_bug_10437_1)
          << "BandwidthSampler in-flight packet map has exceeded maximum "
             "number of tracked packets("
          << max_tracked_packets_
          << ").  First tracked: " << connection_state_map_.first_packet()
          << "; last tracked: " << connection_state_map_.last_packet()
          << "; entry_slots_used: " << connection_state_map_.entry_slots_used()
          << "; number_of_present_entries: "
          << connection_state_map_.number_of_present_entries()
          << "; packet number: " << packet_number
          << "; unacked_map: " << unacked_packet_map_->DebugString()
          << "; total_bytes_sent: " << total_bytes_sent_
          << "; total_bytes_acked: " << total_bytes_acked_
          << "; total_bytes_lost: " << total_bytes_lost_
          << "; total_bytes_neutered: " << total_bytes_neutered_
          << "; last_acked_packet_sent_time: " << last_acked_packet_sent_time_
          << "; total_bytes_sent_at_last_acked_packet: "
          << total_bytes_sent_at_last_acked_packet_
          << "; least_unacked_packet_info: "
          << (unacked_packet_map_->IsUnacked(maybe_least_unacked)
                  ? unacked_packet_map_
                        ->GetTransmissionInfo(maybe_least_unacked)
                        .DebugString()
                  : "n/a");
    } else {
      QUIC_BUG(quic_bug_10437_2)
          << "BandwidthSampler in-flight packet map has exceeded maximum "
             "number of tracked packets.";
    }
  }

  bool success = connection_state_map_.Emplace(packet_number, sent_time, bytes,
                                               bytes_in_flight + bytes, *this);
  QUIC_BUG_IF(quic_bug_10437_3, !success)
      << "BandwidthSampler failed to insert the packet "
         "into the map, most likely because it's already "
         "in it.";
}

void BandwidthSampler::OnPacketNeutered(QuicPacketNumber packet_number) {
  connection_state_map_.Remove(
      packet_number, [&](const ConnectionStateOnSentPacket& sent_packet) {
        QUIC_CODE_COUNT(quic_bandwidth_sampler_packet_neutered);
        total_bytes_neutered_ += sent_packet.size();
      });
}

BandwidthSamplerInterface::CongestionEventSample
BandwidthSampler::OnCongestionEvent(QuicTime ack_time,
                                    const AckedPacketVector& acked_packets,
                                    const LostPacketVector& lost_packets,
                                    QuicBandwidth max_bandwidth,
                                    QuicBandwidth est_bandwidth_upper_bound,
                                    QuicRoundTripCount round_trip_count) {
  CongestionEventSample event_sample;

  SendTimeState last_lost_packet_send_state;

  for (const LostPacket& packet : lost_packets) {
    SendTimeState send_state =
        OnPacketLost(packet.packet_number, packet.bytes_lost);
    if (send_state.is_valid) {
      last_lost_packet_send_state = send_state;
    }
  }

  if (acked_packets.empty()) {
    // Only populate send state for a loss-only event.
    event_sample.last_packet_send_state = last_lost_packet_send_state;
    return event_sample;
  }

  SendTimeState last_acked_packet_send_state;
  QuicBandwidth max_send_rate = QuicBandwidth::Zero();
  for (const auto& packet : acked_packets) {
    if (packet.spurious_loss) {
      // If the packet has been detected as lost before, QuicSentPacketManager
      // should set the AckedPacket.bytes_acked to 0 before passing the packet
      // to the congestion controller.
      QUICHE_DCHECK_EQ(packet.bytes_acked, 0);
      continue;
    }
    BandwidthSample sample =
        OnPacketAcknowledged(ack_time, packet.packet_number);
    if (!sample.state_at_send.is_valid) {
      continue;
    }

    last_acked_packet_send_state = sample.state_at_send;

    if (!sample.rtt.IsZero()) {
      event_sample.sample_rtt = std::min(event_sample.sample_rtt, sample.rtt);
    }
    if (sample.bandwidth > event_sample.sample_max_bandwidth) {
      event_sample.sample_max_bandwidth = sample.bandwidth;
      event_sample.sample_is_app_limited = sample.state_at_send.is_app_limited;
    }
    if (!sample.send_rate.IsInfinite()) {
      max_send_rate = std::max(max_send_rate, sample.send_rate);
    }
    const QuicByteCount inflight_sample =
        total_bytes_acked() - last_acked_packet_send_state.total_bytes_acked;
    if (inflight_sample > event_sample.sample_max_inflight) {
      event_sample.sample_max_inflight = inflight_sample;
    }
  }

  if (!last_lost_packet_send_state.is_valid) {
    event_sample.last_packet_send_state = last_acked_packet_send_state;
  } else if (!last_acked_packet_send_state.is_valid) {
    event_sample.last_packet_send_state = last_lost_packet_send_state;
  } else {
    // If two packets are inflight and an alarm is armed to lose a packet and it
    // wakes up late, then the first of two in flight packets could have been
    // acknowledged before the wakeup, which re-evaluates loss detection, and
    // could declare the later of the two lost.
    event_sample.last_packet_send_state =
        lost_packets.back().packet_number > acked_packets.back().packet_number
            ? last_lost_packet_send_state
            : last_acked_packet_send_state;
  }

  bool is_new_max_bandwidth = event_sample.sample_max_bandwidth > max_bandwidth;
  max_bandwidth = std::max(max_bandwidth, event_sample.sample_max_bandwidth);
  if (limit_max_ack_height_tracker_by_send_rate_) {
    max_bandwidth = std::max(max_bandwidth, max_send_rate);
  }
  // TODO(ianswett): Why is the min being passed in here?
  event_sample.extra_acked =
      OnAckEventEnd(std::min(est_bandwidth_upper_bound, max_bandwidth),
                    is_new_max_bandwidth, round_trip_count);

  return event_sample;
}

QuicByteCount BandwidthSampler::OnAckEventEnd(
    QuicBandwidth bandwidth_estimate, bool is_new_max_bandwidth,
    QuicRoundTripCount round_trip_count) {
  const QuicByteCount newly_acked_bytes =
      total_bytes_acked_ - total_bytes_acked_after_last_ack_event_;

  if (newly_acked_bytes == 0) {
    return 0;
  }
  total_bytes_acked_after_last_ack_event_ = total_bytes_acked_;
  QuicByteCount extra_acked = max_ack_height_tracker_.Update(
      bandwidth_estimate, is_new_max_bandwidth, round_trip_count,
      last_sent_packet_, last_acked_packet_, last_acked_packet_ack_time_,
      newly_acked_bytes);
  // If |extra_acked| is zero, i.e. this ack event marks the start of a new ack
  // aggregation epoch, save LessRecentPoint, which is the last ack point of the
  // previous epoch, as a A0 candidate.
  if (overestimate_avoidance_ && extra_acked == 0) {
    a0_candidates_.push_back(recent_ack_points_.LessRecentPoint());
    QUIC_DVLOG(1) << "New a0_candidate:" << a0_candidates_.back();
  }
  return extra_acked;
}

BandwidthSample BandwidthSampler::OnPacketAcknowledged(
    QuicTime ack_time, QuicPacketNumber packet_number) {
  last_acked_packet_ = packet_number;
  ConnectionStateOnSentPacket* sent_packet_pointer =
      connection_state_map_.GetEntry(packet_number);
  if (sent_packet_pointer == nullptr) {
    // See the TODO below.
    return BandwidthSample();
  }
  BandwidthSample sample =
      OnPacketAcknowledgedInner(ack_time, packet_number, *sent_packet_pointer);
  return sample;
}

BandwidthSample BandwidthSampler::OnPacketAcknowledgedInner(
    QuicTime ack_time, QuicPacketNumber packet_number,
    const ConnectionStateOnSentPacket& sent_packet) {
  total_bytes_acked_ += sent_packet.size();
  total_bytes_sent_at_last_acked_packet_ =
      sent_packet.send_time_state().total_bytes_sent;
  last_acked_packet_sent_time_ = sent_packet.sent_time();
  last_acked_packet_ack_time_ = ack_time;
  if (overestimate_avoidance_) {
    recent_ack_points_.Update(ack_time, total_bytes_acked_);
  }

  if (is_app_limited_) {
    // Exit app-limited phase in two cases:
    // (1) end_of_app_limited_phase_ is not initialized, i.e., so far all
    // packets are sent while there are buffered packets or pending data.
    // (2) The current acked packet is after the sent packet marked as the end
    // of the app limit phase.
    if (!end_of_app_limited_phase_.IsInitialized() ||
        packet_number > end_of_app_limited_phase_) {
      is_app_limited_ = false;
    }
  }

  // There might have been no packets acknowledged at the moment when the
  // current packet was sent. In that case, there is no bandwidth sample to
  // make.
  if (sent_packet.last_acked_packet_sent_time() == QuicTime::Zero()) {
    QUIC_BUG(quic_bug_10437_4)
        << "sent_packet.last_acked_packet_sent_time is zero";
    return BandwidthSample();
  }

  // Infinite rate indicates that the sampler is supposed to discard the
  // current send rate sample and use only the ack rate.
  QuicBandwidth send_rate = QuicBandwidth::Infinite();
  if (sent_packet.sent_time() > sent_packet.last_acked_packet_sent_time()) {
    send_rate = QuicBandwidth::FromBytesAndTimeDelta(
        sent_packet.send_time_state().total_bytes_sent -
            sent_packet.total_bytes_sent_at_last_acked_packet(),
        sent_packet.sent_time() - sent_packet.last_acked_packet_sent_time());
  }

  AckPoint a0;
  if (overestimate_avoidance_ &&
      ChooseA0Point(sent_packet.send_time_state().total_bytes_acked, &a0)) {
    QUIC_DVLOG(2) << "Using a0 point: " << a0;
  } else {
    a0.ack_time = sent_packet.last_acked_packet_ack_time(),
    a0.total_bytes_acked = sent_packet.send_time_state().total_bytes_acked;
  }

  // During the slope calculation, ensure that ack time of the current packet is
  // always larger than the time of the previous packet, otherwise division by
  // zero or integer underflow can occur.
  if (ack_time <= a0.ack_time) {
    // TODO(wub): Compare this code count before and after fixing clock jitter
    // issue.
    if (a0.ack_time == sent_packet.sent_time()) {
      // This is the 1st packet after quiescense.
      QUIC_CODE_COUNT_N(quic_prev_ack_time_larger_than_current_ack_time, 1, 2);
    } else {
      QUIC_CODE_COUNT_N(quic_prev_ack_time_larger_than_current_ack_time, 2, 2);
    }
    QUIC_LOG_EVERY_N_SEC(ERROR, 60)
        << "Time of the previously acked packet:"
        << a0.ack_time.ToDebuggingValue()
        << " is larger than the ack time of the current packet:"
        << ack_time.ToDebuggingValue()
        << ". acked packet number:" << packet_number
        << ", total_bytes_acked_:" << total_bytes_acked_
        << ", overestimate_avoidance_:" << overestimate_avoidance_
        << ", sent_packet:" << sent_packet;
    return BandwidthSample();
  }
  QuicBandwidth ack_rate = QuicBandwidth::FromBytesAndTimeDelta(
      total_bytes_acked_ - a0.total_bytes_acked, ack_time - a0.ack_time);

  BandwidthSample sample;
  sample.bandwidth = std::min(send_rate, ack_rate);
  // Note: this sample does not account for delayed acknowledgement time.  This
  // means that the RTT measurements here can be artificially high, especially
  // on low bandwidth connections.
  sample.rtt = ack_time - sent_packet.sent_time();
  sample.send_rate = send_rate;
  SentPacketToSendTimeState(sent_packet, &sample.state_at_send);

  if (sample.bandwidth.IsZero()) {
    QUIC_LOG_EVERY_N_SEC(ERROR, 60)
        << "ack_rate: " << ack_rate << ", send_rate: " << send_rate
        << ". acked packet number:" << packet_number
        << ", overestimate_avoidance_:" << overestimate_avoidance_ << "a1:{"
        << total_bytes_acked_ << "@" << ack_time << "}, a0:{"
        << a0.total_bytes_acked << "@" << a0.ack_time
        << "}, sent_packet:" << sent_packet;
  }
  return sample;
}

bool BandwidthSampler::ChooseA0Point(QuicByteCount total_bytes_acked,
                                     AckPoint* a0) {
  if (a0_candidates_.empty()) {
    QUIC_BUG(quic_bug_10437_5)
        << "No A0 point candicates. total_bytes_acked:" << total_bytes_acked;
    return false;
  }

  if (a0_candidates_.size() == 1) {
    *a0 = a0_candidates_.front();
    return true;
  }

  for (size_t i = 1; i < a0_candidates_.size(); ++i) {
    if (a0_candidates_[i].total_bytes_acked > total_bytes_acked) {
      *a0 = a0_candidates_[i - 1];
      if (i > 1) {
        a0_candidates_.pop_front_n(i - 1);
      }
      return true;
    }
  }

  // All candidates' total_bytes_acked is <= |total_bytes_acked|.
  *a0 = a0_candidates_.back();
  a0_candidates_.pop_front_n(a0_candidates_.size() - 1);
  return true;
}

SendTimeState BandwidthSampler::OnPacketLost(QuicPacketNumber packet_number,
                                             QuicPacketLength bytes_lost) {
  // TODO(vasilvv): see the comment for the case of missing packets in
  // BandwidthSampler::OnPacketAcknowledged on why this does not raise a
  // QUIC_BUG when removal fails.
  SendTimeState send_time_state;

  total_bytes_lost_ += bytes_lost;
  ConnectionStateOnSentPacket* sent_packet_pointer =
      connection_state_map_.GetEntry(packet_number);
  if (sent_packet_pointer != nullptr) {
    SentPacketToSendTimeState(*sent_packet_pointer, &send_time_state);
  }

  return send_time_state;
}

void BandwidthSampler::SentPacketToSendTimeState(
    const ConnectionStateOnSentPacket& sent_packet,
    SendTimeState* send_time_state) const {
  *send_time_state = sent_packet.send_time_state();
  send_time_state->is_valid = true;
}

void BandwidthSampler::OnAppLimited() {
  is_app_limited_ = true;
  end_of_app_limited_phase_ = last_sent_packet_;
}

void BandwidthSampler::RemoveObsoletePackets(QuicPacketNumber least_unacked) {
  // A packet can become obsolete when it is removed from QuicUnackedPacketMap's
  // view of inflight before it is acked or marked as lost. For example, when
  // QuicSentPacketManager::RetransmitCryptoPackets retransmits a crypto packet,
  // the packet is removed from QuicUnackedPacketMap's inflight, but is not
  // marked as acked or lost in the BandwidthSampler.
  connection_state_map_.RemoveUpTo(least_unacked);
}

QuicByteCount BandwidthSampler::total_bytes_sent() const {
  return total_bytes_sent_;
}

QuicByteCount BandwidthSampler::total_bytes_acked() const {
  return total_bytes_acked_;
}

QuicByteCount BandwidthSampler::total_bytes_lost() const {
  return total_bytes_lost_;
}

QuicByteCount BandwidthSampler::total_bytes_neutered() const {
  return total_bytes_neutered_;
}

bool BandwidthSampler::is_app_limited() const { return is_app_limited_; }

QuicPacketNumber BandwidthSampler::end_of_app_limited_phase() const {
  return end_of_app_limited_phase_;
}

}  // namespace quic

"""

```