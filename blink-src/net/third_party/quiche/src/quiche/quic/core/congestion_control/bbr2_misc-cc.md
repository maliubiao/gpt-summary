Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt's questions.

1. **Understanding the Core Task:** The first step is to recognize that this code implements parts of the BBR2 congestion control algorithm for the QUIC protocol. It's focused on *network modeling*—tracking and estimating network conditions like bandwidth and round-trip time.

2. **Initial Skim and Keyword Identification:** Quickly scan the code for important keywords and data structures. This includes:
    * Class names: `RoundTripCounter`, `MinRttFilter`, `Bbr2NetworkModel` (the central one).
    * Member variables: `min_rtt_`, `max_bandwidth_filter_`, `bandwidth_sampler_`, `cwnd_gain_`, `pacing_gain_`, various counters (`round_trip_count_`, `bytes_lost_in_round_`, etc.).
    * Method names: `OnPacketSent`, `OnPacketsAcked`, `Update`, `OnCongestionEventStart`, `AdaptLowerBounds`, `MaybeExpireMinRtt`, `IsInflightTooHigh`, `HasBandwidthGrowth`, etc.
    * Constants/parameters: `Bbr2Params` (even though the definition isn't here, it's clearly a configuration object).

3. **Analyzing Individual Classes/Structures:**

    * **`RoundTripCounter`:**  The name is self-explanatory. It counts round trips based on packet acknowledgments. The logic involves tracking the last sent packet and the end of the current round trip.

    * **`MinRttFilter`:** This filters and maintains a minimum round-trip time estimate. The `Update` method handles new RTT samples, and `ForceUpdate` is for overriding the minimum.

    * **`Bbr2NetworkModel`:** This is the most complex. Break it down method by method:
        * **Constructor:** Initializes various components, including the `BandwidthSampler` and `MinRttFilter`. Note the lambda function for initializing `bandwidth_sampler_` based on whether an `old_sampler` exists.
        * **`OnPacketSent`:** Records packet sending information, updates bytes in flight, and informs the `BandwidthSampler`.
        * **`OnCongestionEventStart`:**  This is a key method. It processes acknowledgments and losses, updates bandwidth and RTT estimates using the `BandwidthSampler` and `MinRttFilter`, and manages various counters related to loss and bytes delivered.
        * **`AdaptLowerBounds`:**  This function dynamically adjusts lower bounds for bandwidth and inflight based on loss events. Notice the different modes controlled by `Params().bw_lo_mode_`.
        * **`OnCongestionEventFinish`:**  Handles end-of-round actions and cleans up the `BandwidthSampler`.
        * **`UpdateNetworkParameters`:** Updates the minimum RTT.
        * **`MaybeExpireMinRtt`:**  Allows the minimum RTT to be refreshed after a certain period.
        * **`IsInflightTooHigh`:**  Determines if the amount of data in flight is excessive based on loss events.
        * **`RestartRoundEarly` and `OnNewRound`:** Manage the start of new round trips.
        * **`cap_inflight_lo`:**  Sets an upper limit on the `inflight_lo_` value.
        * **`inflight_hi_with_headroom`:**  Calculates a headroom value based on `inflight_hi_`.
        * **`HasBandwidthGrowth`:** Detects if the bandwidth is still increasing during the startup phase.
        * **`CheckPersistentQueue`:**  Checks for persistent queue buildup, also relevant for exiting startup.

4. **Identifying Functionality:**  Based on the analysis above, list the core functionalities:
    * Round-trip time tracking
    * Minimum RTT estimation
    * Bandwidth sampling and estimation
    * Loss event tracking
    * Inflight data management
    * Dynamic adjustment of bandwidth and inflight limits
    * Detection of bandwidth growth and persistent queueing

5. **Considering JavaScript Relevance:** Think about how congestion control relates to web browsing or network applications, which are often driven by JavaScript. The key connection is that the congestion control algorithm *impacts the performance* of these applications. Slower bandwidth estimates or tighter congestion windows in BBR2 would result in slower data transfer and potentially affect JavaScript-initiated network requests. Direct interaction with the C++ code from JavaScript is unlikely, but the *effects* are observable.

6. **Constructing Examples (Hypothetical Inputs and Outputs):** Choose a specific function and create a plausible scenario. For example, for `OnPacketsAcked`, consider the last sent packet and the last acknowledged packet. For `Update`, think about different `sample_rtt` values and how they affect `min_rtt_`. Keep the examples simple and illustrate the core logic.

7. **Identifying User/Programming Errors:** Think about common pitfalls when dealing with networking and congestion control:
    * **Incorrect configuration:**  Mentioning `Bbr2Params` is relevant here, even though its definition is external. Incorrectly setting parameters can lead to suboptimal behavior.
    * **Misinterpreting metrics:**  Failing to understand the meaning of the tracked values (like `min_rtt_`, `max_bandwidth_`) can lead to incorrect conclusions when debugging.
    * **Unexpected network conditions:** While not a coding error, the algorithm needs to handle various network behaviors, and understanding how it reacts is important.

8. **Tracing User Actions (Debugging):**  Imagine a scenario where a user reports slow loading times. Trace backward how their actions might lead to this code being executed. Think about the network stack involved: web browser -> Chrome networking library -> QUIC protocol implementation (which includes BBR2). The user's actions initiate network requests, which trigger packet sending, acknowledgments, and potentially congestion events, leading to the execution of the BBR2 code.

9. **Structuring the Answer:** Organize the information logically, starting with the overall functionality, then addressing the JavaScript relevance, providing examples, discussing errors, and finally outlining the debugging process. Use clear and concise language. Use code formatting for relevant parts.

10. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Check if all parts of the prompt have been addressed. Make any necessary corrections or additions. For instance, ensure the explanations for the examples are clear about the input and the expected output.

This systematic approach helps in dissecting a complex piece of code and providing a comprehensive answer to the given prompt. It involves understanding the domain (congestion control), analyzing the code structure and logic, connecting it to broader concepts (like JavaScript interaction), and thinking about practical aspects like debugging and potential errors.
这个文件 `net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_misc.cc` 是 Chromium 网络栈中 QUIC 协议的 BBR2 拥塞控制算法实现的一部分。它包含了一些与 BBR2 算法相关的辅助类和函数，主要用于**追踪和计算网络状态的关键指标**。

下面列举它的主要功能：

**1. `RoundTripCounter` 类:**

* **功能:**  用于跟踪和计算网络连接的往返次数（Round Trip Count, RTC）。
* **工作原理:**
    * 记录最后发送的数据包编号 (`last_sent_packet_`)。
    * 当收到新的 ACK 时，如果 ACK 的数据包编号大于当前轮次的结束点 (`end_of_round_trip_`)，则认为进入了新的轮次，并增加往返次数。
    * 可以手动重启轮次。
* **作用:** BBR2 算法需要知道当前处于第几个往返，以便进行不同的控制策略。
* **假设输入与输出:**
    * **假设输入:**  连续发送数据包，并收到 ACK。
    * **输出:** `round_trip_count_` 会随着新的轮次而递增。`OnPacketsAcked` 函数会返回 `true` 如果进入了新的轮次，否则返回 `false`。

**2. `MinRttFilter` 类:**

* **功能:**  用于过滤和记录最小往返时延（Minimum Round Trip Time, Min RTT）。
* **工作原理:**
    * 维护当前的最小 RTT 值 (`min_rtt_`) 和记录该最小 RTT 的时间戳 (`min_rtt_timestamp_`).
    * 每次收到新的 RTT 采样值 (`sample_rtt`) 时，如果 `sample_rtt` 小于当前 `min_rtt_`，则更新 `min_rtt_` 和 `min_rtt_timestamp_`。
    * 可以强制更新最小 RTT。
* **作用:**  Min RTT 是 BBR2 算法中一个非常重要的指标，用于估计网络的瓶颈带宽。
* **假设输入与输出:**
    * **假设输入:** 持续收到不同大小的 RTT 采样值。
    * **输出:** `min_rtt_` 会记录遇到的最小 RTT 值，并且 `min_rtt_timestamp_` 会更新为记录到该最小 RTT 的时间。

**3. `Bbr2NetworkModel` 类:**

* **功能:**  这是 BBR2 算法的核心组成部分，用于维护和更新网络状态模型。它整合了 `RoundTripCounter` 和 `MinRttFilter` 的功能，并包含了更多用于 BBR2 决策的数据。
* **主要功能:**
    * **带宽采样 (`bandwidth_sampler_`)**:  使用 `BandwidthSampler` 类来采样和估计网络的吞吐量。
    * **维护最小 RTT (`min_rtt_filter_`)**:  使用 `MinRttFilter` 类来维护最小 RTT。
    * **跟踪往返次数 (`round_trip_counter_`)**: 使用 `RoundTripCounter` 类来跟踪往返次数。
    * **记录发送数据包的信息 (`OnPacketSent`)**:  记录数据包的发送时间、飞行中的字节数等信息。
    * **处理拥塞事件 (`OnCongestionEventStart`, `OnCongestionEventFinish`)**:  当发生拥塞事件（收到 ACK 或丢失包）时，更新网络模型的状态，例如更新最大带宽、最小 RTT 等。
    * **自适应调整带宽下限 (`AdaptLowerBounds`)**:  根据网络状况动态调整带宽的下限估计。
    * **判断是否需要过期最小 RTT (`MaybeExpireMinRtt`)**:  定期检查最小 RTT 是否需要被新的采样值更新。
    * **判断飞行中的数据量是否过高 (`IsInflightTooHigh`)**:  根据丢包情况判断当前发送的数据量是否超过了网络容量。
    * **检测带宽是否增长 (`HasBandwidthGrowth`)**:  在启动阶段检测带宽是否持续增长。
    * **检查持久队列 (`CheckPersistentQueue`)**:  在启动阶段检查是否存在持续的排队。
* **关系到 `bbr2_misc.cc` 的成员变量:**
    * `params_`: 指向 `Bbr2Params` 结构的指针，包含了 BBR2 算法的各种参数。
    * `cwnd_gain_`, `pacing_gain_`:  控制拥塞窗口和发送速率的增益值。
    * `bandwidth_latest_`, `inflight_latest_`:  记录最近一个往返中的最大带宽和飞行中数据量。
    * `bandwidth_lo_`, `inflight_lo_`:  记录带宽和飞行中数据量的下限估计。
    * 各种计数器，如 `bytes_lost_in_round_`, `loss_events_in_round_`, `rounds_without_bandwidth_growth_` 等。
* **假设输入与输出:**
    * **假设输入:**  模拟网络连接中数据包的发送、接收、ACK 以及丢包事件。
    * **输出:** `Bbr2NetworkModel` 的内部状态会根据输入事件进行更新，例如 `max_bandwidth_filter_` 会记录估计的最大带宽，`min_rtt_filter_` 会记录最小 RTT，各种计数器会更新。这些状态信息会被 BBR2 的其他模块用于控制发送速率和拥塞窗口。

**与 JavaScript 的关系:**

这个 C++ 代码直接运行在 Chromium 的网络进程中，负责底层的网络拥塞控制。 **JavaScript 代码本身无法直接访问或调用这个文件中的 C++ 代码。**

但是，BBR2 算法的运行会直接影响到浏览器中 JavaScript 发起的网络请求的性能。 例如：

* **更高的带宽估计:**  BBR2 如果估计出更高的可用带宽，那么 JavaScript 发起的 `fetch` 或 `XMLHttpRequest` 请求可以更快地下载数据。
* **更低的延迟:**  准确的 RTT 估计有助于 BBR2 避免过度拥塞，从而减少网络延迟，提升 JavaScript 应用的响应速度。
* **更稳定的连接:**  BBR2 的目标是保持高吞吐量的同时避免网络崩溃，这有助于 JavaScript 应用获得更稳定的网络连接。

**举例说明 JavaScript 的体现:**

假设一个网页加载图片，JavaScript 使用 `fetch` API 发起请求：

```javascript
fetch('https://example.com/image.jpg')
  .then(response => response.blob())
  .then(imageBlob => {
    // 处理图片数据
    document.getElementById('myImage').src = URL.createObjectURL(imageBlob);
  });
```

在这个过程中：

1. 当 JavaScript 发起 `fetch` 请求时，Chromium 的网络栈会处理这个请求。
2. 底层的 QUIC 协议（如果适用）会使用 BBR2 算法来控制数据包的发送速率。
3. `bbr2_misc.cc` 中的代码会参与到 BBR2 算法的计算中，例如根据收到的 ACK 更新带宽和 RTT 的估计值。
4. BBR2 算法的决策（例如增加或减少发送速率）会直接影响到 `image.jpg` 文件的下载速度，最终影响到 JavaScript 代码何时接收到完整的图片数据并显示在网页上。

**逻辑推理的假设输入与输出:**

以 `MinRttFilter::Update` 函数为例：

* **假设输入:**
    * `sample_rtt`:  `QuicTime::Delta(QuicTime::kMillisPerSecond / 10)` (100毫秒)
    * `now`: 当前时间

* **初始状态 (假设):**
    * `min_rtt_`: `QuicTime::Delta(QuicTime::kMillisPerSecond / 5)` (200毫秒)
    * `min_rtt_timestamp_`: 之前的某个时间

* **输出:**
    * 由于 `sample_rtt` (100ms) 小于当前的 `min_rtt_` (200ms)，`min_rtt_` 将会被更新为 `QuicTime::Delta(QuicTime::kMillisPerSecond / 10)` (100毫秒)。
    * `min_rtt_timestamp_` 将会被更新为 `now` 的值。

**用户或编程常见的使用错误:**

* **错误地配置 BBR2 参数:**  虽然用户不能直接修改这个 C++ 文件，但 Chromium 的配置或命令行参数可能会影响 BBR2 的行为。错误地设置 BBR2 相关的标志可能会导致性能下降或连接不稳定。例如，禁用 BBR2 或者使用不合适的 BBR2 变种。
* **在不合适的网络环境下使用 BBR2:**  BBR2 在某些高丢包或突发拥塞的网络环境下可能表现不佳。程序员需要了解 BBR2 的适用场景，并根据实际网络环境选择合适的拥塞控制算法。
* **误解 BBR2 的工作原理:**  在分析网络性能问题时，如果对 BBR2 的工作原理不熟悉，可能会做出错误的判断，例如错误地认为 BBR2 导致了带宽不足，而实际可能是其他原因。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在 Chrome 浏览器中访问一个网站 (例如 `https://example.com`)。**
2. **网页需要加载资源 (例如图片、JavaScript 文件)。**
3. **Chrome 浏览器的网络栈发起 HTTPS 连接。**
4. **如果启用了 QUIC 协议，Chrome 会尝试使用 QUIC 连接到服务器。**
5. **QUIC 连接的拥塞控制算法被设置为 BBR2。**
6. **在数据传输过程中：**
   * **当有数据包发送时，`Bbr2NetworkModel::OnPacketSent` 会被调用。**
   * **当收到 ACK 时，`Bbr2NetworkModel::OnCongestionEventStart` 会被调用，其中会用到 `RoundTripCounter::OnPacketsAcked` 和 `MinRttFilter::Update` 来更新网络状态。**
   * **如果发生丢包，`Bbr2NetworkModel::OnCongestionEventStart` 也会被调用来处理丢包事件。**
7. **如果用户遇到网络性能问题 (例如加载缓慢)，开发人员可能会查看 Chrome 的内部日志或使用网络抓包工具来分析网络连接，这会涉及到对 BBR2 算法行为的理解。**

**调试线索:**

* **Chrome 的 `net-internals` 工具 (`chrome://net-internals/#quic`)** 可以提供关于 QUIC 连接的详细信息，包括 BBR2 的状态变量，例如当前的带宽估计、RTT、拥塞窗口等。
* **网络抓包工具 (如 Wireshark)** 可以捕获网络数据包，分析 ACK 和丢包情况，帮助理解 BBR2 的行为。
* **Chromium 的源代码调试:**  如果需要深入理解 BBR2 的具体行为，开发者可以使用调试器 (如 gdb) 来跟踪 `bbr2_misc.cc` 中的代码执行流程，查看变量的值，分析算法的运行过程。

总而言之，`bbr2_misc.cc` 文件是 Chromium QUIC 协议中 BBR2 拥塞控制算法的关键组成部分，负责维护和更新网络状态模型，为 BBR2 的决策提供基础数据，从而影响用户的网络体验。 虽然 JavaScript 代码不能直接操作它，但其运行结果会直接体现在 JavaScript 发起的网络请求的性能上。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_misc.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/bbr2_misc.h"

#include <algorithm>
#include <limits>

#include "quiche/quic/core/congestion_control/bandwidth_sampler.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

RoundTripCounter::RoundTripCounter() : round_trip_count_(0) {}

void RoundTripCounter::OnPacketSent(QuicPacketNumber packet_number) {
  QUICHE_DCHECK(!last_sent_packet_.IsInitialized() ||
                last_sent_packet_ < packet_number);
  last_sent_packet_ = packet_number;
}

bool RoundTripCounter::OnPacketsAcked(QuicPacketNumber last_acked_packet) {
  if (!end_of_round_trip_.IsInitialized() ||
      last_acked_packet > end_of_round_trip_) {
    round_trip_count_++;
    end_of_round_trip_ = last_sent_packet_;
    return true;
  }
  return false;
}

void RoundTripCounter::RestartRound() {
  end_of_round_trip_ = last_sent_packet_;
}

MinRttFilter::MinRttFilter(QuicTime::Delta initial_min_rtt,
                           QuicTime initial_min_rtt_timestamp)
    : min_rtt_(initial_min_rtt),
      min_rtt_timestamp_(initial_min_rtt_timestamp) {}

void MinRttFilter::Update(QuicTime::Delta sample_rtt, QuicTime now) {
  if (sample_rtt <= QuicTime::Delta::Zero()) {
    return;
  }
  if (sample_rtt < min_rtt_ || min_rtt_timestamp_ == QuicTime::Zero()) {
    min_rtt_ = sample_rtt;
    min_rtt_timestamp_ = now;
  }
}

void MinRttFilter::ForceUpdate(QuicTime::Delta sample_rtt, QuicTime now) {
  if (sample_rtt <= QuicTime::Delta::Zero()) {
    return;
  }
  min_rtt_ = sample_rtt;
  min_rtt_timestamp_ = now;
}

Bbr2NetworkModel::Bbr2NetworkModel(const Bbr2Params* params,
                                   QuicTime::Delta initial_rtt,
                                   QuicTime initial_rtt_timestamp,
                                   float cwnd_gain, float pacing_gain,
                                   const BandwidthSampler* old_sampler)
    : params_(params),
      bandwidth_sampler_([](QuicRoundTripCount max_height_tracker_window_length,
                            const BandwidthSampler* old_sampler) {
        if (old_sampler != nullptr) {
          return BandwidthSampler(*old_sampler);
        }
        return BandwidthSampler(/*unacked_packet_map=*/nullptr,
                                max_height_tracker_window_length);
      }(params->initial_max_ack_height_filter_window, old_sampler)),
      min_rtt_filter_(initial_rtt, initial_rtt_timestamp),
      cwnd_gain_(cwnd_gain),
      pacing_gain_(pacing_gain) {}

void Bbr2NetworkModel::OnPacketSent(QuicTime sent_time,
                                    QuicByteCount bytes_in_flight,
                                    QuicPacketNumber packet_number,
                                    QuicByteCount bytes,
                                    HasRetransmittableData is_retransmittable) {
  // Updating the min here ensures a more realistic (0) value when flows exit
  // quiescence.
  if (bytes_in_flight < min_bytes_in_flight_in_round_) {
    min_bytes_in_flight_in_round_ = bytes_in_flight;
  }
  if (bytes_in_flight + bytes >= inflight_hi_) {
    inflight_hi_limited_in_round_ = true;
  }
  round_trip_counter_.OnPacketSent(packet_number);

  bandwidth_sampler_.OnPacketSent(sent_time, packet_number, bytes,
                                  bytes_in_flight, is_retransmittable);
}

void Bbr2NetworkModel::OnCongestionEventStart(
    QuicTime event_time, const AckedPacketVector& acked_packets,
    const LostPacketVector& lost_packets,
    Bbr2CongestionEvent* congestion_event) {
  const QuicByteCount prior_bytes_acked = total_bytes_acked();
  const QuicByteCount prior_bytes_lost = total_bytes_lost();

  congestion_event->event_time = event_time;
  congestion_event->end_of_round_trip =
      acked_packets.empty() ? false
                            : round_trip_counter_.OnPacketsAcked(
                                  acked_packets.rbegin()->packet_number);

  BandwidthSamplerInterface::CongestionEventSample sample =
      bandwidth_sampler_.OnCongestionEvent(event_time, acked_packets,
                                           lost_packets, MaxBandwidth(),
                                           bandwidth_lo(), RoundTripCount());

  if (sample.extra_acked == 0) {
    cwnd_limited_before_aggregation_epoch_ =
        congestion_event->prior_bytes_in_flight >= congestion_event->prior_cwnd;
  }

  if (sample.last_packet_send_state.is_valid) {
    congestion_event->last_packet_send_state = sample.last_packet_send_state;
  }

  // Avoid updating |max_bandwidth_filter_| if a) this is a loss-only event, or
  // b) all packets in |acked_packets| did not generate valid samples. (e.g. ack
  // of ack-only packets). In both cases, total_bytes_acked() will not change.
  if (prior_bytes_acked != total_bytes_acked()) {
    QUIC_LOG_IF(WARNING, sample.sample_max_bandwidth.IsZero())
        << total_bytes_acked() - prior_bytes_acked << " bytes from "
        << acked_packets.size()
        << " packets have been acked, but sample_max_bandwidth is zero.";
    congestion_event->sample_max_bandwidth = sample.sample_max_bandwidth;
    if (!sample.sample_is_app_limited ||
        sample.sample_max_bandwidth > MaxBandwidth()) {
      max_bandwidth_filter_.Update(congestion_event->sample_max_bandwidth);
    }
  }

  if (!sample.sample_rtt.IsInfinite()) {
    congestion_event->sample_min_rtt = sample.sample_rtt;
    min_rtt_filter_.Update(congestion_event->sample_min_rtt, event_time);
  }

  congestion_event->bytes_acked = total_bytes_acked() - prior_bytes_acked;
  congestion_event->bytes_lost = total_bytes_lost() - prior_bytes_lost;

  if (congestion_event->prior_bytes_in_flight >=
      congestion_event->bytes_acked + congestion_event->bytes_lost) {
    congestion_event->bytes_in_flight =
        congestion_event->prior_bytes_in_flight -
        congestion_event->bytes_acked - congestion_event->bytes_lost;
  } else {
    QUIC_BUG(quic_bbr2_prior_in_flight_too_small)
        << "prior_bytes_in_flight:" << congestion_event->prior_bytes_in_flight
        << " is smaller than the sum of bytes_acked:"
        << congestion_event->bytes_acked
        << " and bytes_lost:" << congestion_event->bytes_lost;
    congestion_event->bytes_in_flight = 0;
  }

  if (congestion_event->bytes_lost > 0) {
    bytes_lost_in_round_ += congestion_event->bytes_lost;
    loss_events_in_round_++;
  }

  if (congestion_event->bytes_acked > 0 &&
      congestion_event->last_packet_send_state.is_valid &&
      total_bytes_acked() >
          congestion_event->last_packet_send_state.total_bytes_acked) {
    QuicByteCount bytes_delivered =
        total_bytes_acked() -
        congestion_event->last_packet_send_state.total_bytes_acked;
    max_bytes_delivered_in_round_ =
        std::max(max_bytes_delivered_in_round_, bytes_delivered);
  }
  // TODO(ianswett) Consider treating any bytes lost as decreasing inflight,
  // because it's a sign of overutilization, not underutilization.
  if (congestion_event->bytes_in_flight < min_bytes_in_flight_in_round_) {
    min_bytes_in_flight_in_round_ = congestion_event->bytes_in_flight;
  }

  // |bandwidth_latest_| and |inflight_latest_| only increased within a round.
  if (sample.sample_max_bandwidth > bandwidth_latest_) {
    bandwidth_latest_ = sample.sample_max_bandwidth;
  }

  if (sample.sample_max_inflight > inflight_latest_) {
    inflight_latest_ = sample.sample_max_inflight;
  }

  // Adapt lower bounds(bandwidth_lo and inflight_lo).
  AdaptLowerBounds(*congestion_event);

  if (!congestion_event->end_of_round_trip) {
    return;
  }

  if (!sample.sample_max_bandwidth.IsZero()) {
    bandwidth_latest_ = sample.sample_max_bandwidth;
  }

  if (sample.sample_max_inflight > 0) {
    inflight_latest_ = sample.sample_max_inflight;
  }
}

void Bbr2NetworkModel::AdaptLowerBounds(
    const Bbr2CongestionEvent& congestion_event) {
  if (Params().bw_lo_mode_ == Bbr2Params::DEFAULT) {
    if (!congestion_event.end_of_round_trip ||
        congestion_event.is_probing_for_bandwidth) {
      return;
    }

    if (bytes_lost_in_round_ > 0) {
      if (bandwidth_lo_.IsInfinite()) {
        bandwidth_lo_ = MaxBandwidth();
      }
      bandwidth_lo_ =
          std::max(bandwidth_latest_, bandwidth_lo_ * (1.0 - Params().beta));
      QUIC_DVLOG(3) << "bandwidth_lo_ updated to " << bandwidth_lo_
                    << ", bandwidth_latest_ is " << bandwidth_latest_;
      if (enable_app_driven_pacing_) {
        // In this mode, we forcibly cap bandwidth_lo_ at the application driven
        // pacing rate when congestion_event.bytes_lost > 0. The idea is to
        // avoid going over what the application needs at the earliest signs of
        // network congestion.
        if (application_bandwidth_target_ < bandwidth_lo_) {
          QUIC_CODE_COUNT(quic_bbr2_app_driven_pacing_in_effect);
        } else {
          QUIC_CODE_COUNT(quic_bbr2_app_driven_pacing_no_effect);
        }
        bandwidth_lo_ = std::min(application_bandwidth_target_, bandwidth_lo_);
        QUIC_DVLOG(3) << "bandwidth_lo_ updated to " << bandwidth_lo_
                      << "after applying application_driven_pacing at "
                      << application_bandwidth_target_;
      }

      if (Params().ignore_inflight_lo) {
        return;
      }
      if (inflight_lo_ == inflight_lo_default()) {
        inflight_lo_ = congestion_event.prior_cwnd;
      }
      inflight_lo_ = std::max<QuicByteCount>(
          inflight_latest_, inflight_lo_ * (1.0 - Params().beta));
    }
    return;
  }

  // Params().bw_lo_mode_ != Bbr2Params::DEFAULT
  if (congestion_event.bytes_lost == 0) {
    return;
  }
  // Ignore losses from packets sent when probing for more bandwidth in
  // STARTUP or PROBE_UP when they're lost in DRAIN or PROBE_DOWN.
  if (pacing_gain_ < 1) {
    return;
  }
  // Decrease bandwidth_lo whenever there is loss.
  // Set bandwidth_lo_ if it is not yet set.
  if (bandwidth_lo_.IsInfinite()) {
    bandwidth_lo_ = MaxBandwidth();
  }
  // Save bandwidth_lo_ if it hasn't already been saved.
  if (prior_bandwidth_lo_.IsZero()) {
    prior_bandwidth_lo_ = bandwidth_lo_;
  }
  switch (Params().bw_lo_mode_) {
    case Bbr2Params::MIN_RTT_REDUCTION:
      bandwidth_lo_ =
          bandwidth_lo_ - QuicBandwidth::FromBytesAndTimeDelta(
                              congestion_event.bytes_lost, MinRtt());
      break;
    case Bbr2Params::INFLIGHT_REDUCTION: {
      // Use a max of BDP and inflight to avoid starving app-limited flows.
      const QuicByteCount effective_inflight =
          std::max(BDP(), congestion_event.prior_bytes_in_flight);
      // This could use bytes_lost_in_round if the bandwidth_lo_ was saved
      // when entering 'recovery', but this BBRv2 implementation doesn't have
      // recovery defined.
      bandwidth_lo_ =
          bandwidth_lo_ * ((effective_inflight - congestion_event.bytes_lost) /
                           static_cast<double>(effective_inflight));
      break;
    }
    case Bbr2Params::CWND_REDUCTION:
      bandwidth_lo_ =
          bandwidth_lo_ *
          ((congestion_event.prior_cwnd - congestion_event.bytes_lost) /
           static_cast<double>(congestion_event.prior_cwnd));
      break;
    case Bbr2Params::DEFAULT:
      QUIC_BUG(quic_bug_10466_1) << "Unreachable case DEFAULT.";
  }
  QuicBandwidth last_bandwidth = bandwidth_latest_;
  // sample_max_bandwidth will be Zero() if the loss is triggered by a timer
  // expiring.  Ideally we'd use the most recent bandwidth sample,
  // but bandwidth_latest is safer than Zero().
  if (!congestion_event.sample_max_bandwidth.IsZero()) {
    // bandwidth_latest_ is the max bandwidth for the round, but to allow
    // fast, conservation style response to loss, use the last sample.
    last_bandwidth = congestion_event.sample_max_bandwidth;
  }
  if (pacing_gain_ > Params().full_bw_threshold) {
    // In STARTUP, pacing_gain_ is applied to bandwidth_lo_ in
    // UpdatePacingRate, so this backs that multiplication out to allow the
    // pacing rate to decrease, but not below
    // last_bandwidth * full_bw_threshold.
    // TODO(ianswett): Consider altering pacing_gain_ when in STARTUP instead.
    bandwidth_lo_ =
        std::max(bandwidth_lo_,
                 last_bandwidth * (Params().full_bw_threshold / pacing_gain_));
  } else {
    // Ensure bandwidth_lo isn't lower than last_bandwidth.
    bandwidth_lo_ = std::max(bandwidth_lo_, last_bandwidth);
  }
  // If it's the end of the round, ensure bandwidth_lo doesn't decrease more
  // than beta.
  if (congestion_event.end_of_round_trip) {
    bandwidth_lo_ =
        std::max(bandwidth_lo_, prior_bandwidth_lo_ * (1.0 - Params().beta));
    prior_bandwidth_lo_ = QuicBandwidth::Zero();
  }
  // These modes ignore inflight_lo as well.
}

void Bbr2NetworkModel::OnCongestionEventFinish(
    QuicPacketNumber least_unacked_packet,
    const Bbr2CongestionEvent& congestion_event) {
  if (congestion_event.end_of_round_trip) {
    OnNewRound();
  }

  bandwidth_sampler_.RemoveObsoletePackets(least_unacked_packet);
}

void Bbr2NetworkModel::UpdateNetworkParameters(QuicTime::Delta rtt) {
  if (!rtt.IsZero()) {
    min_rtt_filter_.Update(rtt, MinRttTimestamp());
  }
}

bool Bbr2NetworkModel::MaybeExpireMinRtt(
    const Bbr2CongestionEvent& congestion_event) {
  if (congestion_event.event_time <
      (MinRttTimestamp() + Params().probe_rtt_period)) {
    return false;
  }
  if (congestion_event.sample_min_rtt.IsInfinite()) {
    return false;
  }
  QUIC_DVLOG(3) << "Replacing expired min rtt of " << min_rtt_filter_.Get()
                << " by " << congestion_event.sample_min_rtt << "  @ "
                << congestion_event.event_time;
  min_rtt_filter_.ForceUpdate(congestion_event.sample_min_rtt,
                              congestion_event.event_time);
  return true;
}

bool Bbr2NetworkModel::IsInflightTooHigh(
    const Bbr2CongestionEvent& congestion_event,
    int64_t max_loss_events) const {
  const SendTimeState& send_state = congestion_event.last_packet_send_state;
  if (!send_state.is_valid) {
    // Not enough information.
    return false;
  }

  if (loss_events_in_round() < max_loss_events) {
    return false;
  }

  const QuicByteCount inflight_at_send = BytesInFlight(send_state);
  // TODO(wub): Consider total_bytes_lost() - send_state.total_bytes_lost, which
  // is the total bytes lost when the largest numbered packet was inflight.
  // bytes_lost_in_round_, OTOH, is the total bytes lost in the "current" round.
  const QuicByteCount bytes_lost_in_round = bytes_lost_in_round_;

  QUIC_DVLOG(3) << "IsInflightTooHigh: loss_events_in_round:"
                << loss_events_in_round()

                << " bytes_lost_in_round:" << bytes_lost_in_round
                << ", lost_in_round_threshold:"
                << inflight_at_send * Params().loss_threshold;

  if (inflight_at_send > 0 && bytes_lost_in_round > 0) {
    QuicByteCount lost_in_round_threshold =
        inflight_at_send * Params().loss_threshold;
    if (bytes_lost_in_round > lost_in_round_threshold) {
      return true;
    }
  }

  return false;
}

void Bbr2NetworkModel::RestartRoundEarly() {
  OnNewRound();
  round_trip_counter_.RestartRound();
  rounds_with_queueing_ = 0;
}

void Bbr2NetworkModel::OnNewRound() {
  bytes_lost_in_round_ = 0;
  loss_events_in_round_ = 0;
  max_bytes_delivered_in_round_ = 0;
  min_bytes_in_flight_in_round_ = std::numeric_limits<uint64_t>::max();
  inflight_hi_limited_in_round_ = false;
}

void Bbr2NetworkModel::cap_inflight_lo(QuicByteCount cap) {
  if (Params().ignore_inflight_lo) {
    return;
  }
  if (inflight_lo_ != inflight_lo_default() && inflight_lo_ > cap) {
    inflight_lo_ = cap;
  }
}

QuicByteCount Bbr2NetworkModel::inflight_hi_with_headroom() const {
  QuicByteCount headroom = inflight_hi_ * Params().inflight_hi_headroom;

  return inflight_hi_ > headroom ? inflight_hi_ - headroom : 0;
}

bool Bbr2NetworkModel::HasBandwidthGrowth(
    const Bbr2CongestionEvent& congestion_event) {
  QUICHE_DCHECK(!full_bandwidth_reached_);
  QUICHE_DCHECK(congestion_event.end_of_round_trip);

  QuicBandwidth threshold =
      full_bandwidth_baseline_ * Params().full_bw_threshold;

  if (MaxBandwidth() >= threshold) {
    QUIC_DVLOG(3) << " CheckBandwidthGrowth at end of round. max_bandwidth:"
                  << MaxBandwidth() << ", threshold:" << threshold
                  << " (Still growing)  @ " << congestion_event.event_time;
    full_bandwidth_baseline_ = MaxBandwidth();
    rounds_without_bandwidth_growth_ = 0;
    return true;
  }
  ++rounds_without_bandwidth_growth_;

  // full_bandwidth_reached is only set to true when not app-limited, except
  // when exit_startup_on_persistent_queue is true.
  if (rounds_without_bandwidth_growth_ >= Params().startup_full_bw_rounds &&
      !congestion_event.last_packet_send_state.is_app_limited) {
    full_bandwidth_reached_ = true;
  }
  QUIC_DVLOG(3) << " CheckBandwidthGrowth at end of round. max_bandwidth:"
                << MaxBandwidth() << ", threshold:" << threshold
                << " rounds_without_growth:" << rounds_without_bandwidth_growth_
                << " full_bw_reached:" << full_bandwidth_reached_ << "  @ "
                << congestion_event.event_time;

  return false;
}

void Bbr2NetworkModel::CheckPersistentQueue(
    const Bbr2CongestionEvent& congestion_event, float target_gain) {
  QUICHE_DCHECK(congestion_event.end_of_round_trip);
  QUICHE_DCHECK_NE(min_bytes_in_flight_in_round_,
                   std::numeric_limits<uint64_t>::max());
  QUICHE_DCHECK_GE(target_gain, Params().full_bw_threshold);
  QuicByteCount target =
      std::max(static_cast<QuicByteCount>(target_gain * BDP()),
               BDP() + QueueingThresholdExtraBytes());
  if (min_bytes_in_flight_in_round_ < target) {
    rounds_with_queueing_ = 0;
    return;
  }
  rounds_with_queueing_++;
  if (rounds_with_queueing_ >= Params().max_startup_queue_rounds) {
    full_bandwidth_reached_ = true;
  }
}

}  // namespace quic

"""

```