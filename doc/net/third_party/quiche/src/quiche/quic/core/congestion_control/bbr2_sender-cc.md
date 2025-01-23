Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The core request is to understand the functionality of the `bbr2_sender.cc` file within the Chromium network stack, specifically focusing on its role in congestion control. We also need to consider connections to JavaScript, potential user errors, and debugging steps.

2. **Initial Code Scan - Identify Key Components:**
   - **Headers:**  Look at the `#include` statements. These tell us about dependencies and related functionalities. We see things like bandwidth sampling, drain logic, cryptography, and core QUIC types.
   - **Namespace:**  The code is within the `quic` namespace, indicating its relevance to the QUIC protocol.
   - **Class Definition:** The central class is `Bbr2Sender`. This will be the primary focus.
   - **Constructor:** The constructor initializes various member variables, providing clues about the class's state. Pay attention to initial values and dependencies (like `RttStats`, `QuicUnackedPacketMap`).
   - **Methods:**  Scan the public methods. Names like `OnCongestionEvent`, `OnPacketSent`, `CanSend`, `GetCongestionWindow`, `PacingRate` strongly suggest this class implements a congestion control algorithm. The `SetFromConfig` and `ApplyConnectionOptions` methods hint at configurability.

3. **Deconstruct the Core Functionality - BBR2 Algorithm:**
   - **Name Recognition:** "BBR2" in the filename and class name immediately points to the Bottleneck Bandwidth and Round-trip propagation time (BBR) congestion control algorithm, specifically a version 2.
   - **State Machine:** The `mode_` member variable and the `BBR2_MODE_DISPATCH` macro are strong indicators of a state machine. The different modes (STARTUP, DRAIN, PROBE_BW, PROBE_RTT) represent the different phases of the BBR2 algorithm.
   - **Key Variables:** Identify crucial variables that influence congestion control:
      - `cwnd_`: Congestion window (number of bytes allowed in flight).
      - `pacing_rate_`: Rate at which packets are sent.
      - `model_`:  An instance of `Bbr2Model` likely holds the core logic for BBR2's estimations (bandwidth, RTT, etc.).
      - `params_`:  Configuration parameters for BBR2.
   - **Congestion Control Logic:**  Focus on the `OnCongestionEvent` method. This is where the core adaptation logic resides. Observe how it updates `cwnd_` and `pacing_rate_` based on acknowledgments and losses.
   - **Pacing and CWND Updates:**  Analyze the `UpdatePacingRate` and `UpdateCongestionWindow` methods. How do they use the `model_` to adjust these values? What are the different conditions for increasing or decreasing them?

4. **Connections to JavaScript:**
   - **Indirect Connection:**  Recognize that this is C++ code running within the Chromium browser. JavaScript running in web pages uses the browser's networking stack. Therefore, BBR2 *indirectly* affects JavaScript performance by managing the TCP/QUIC connection's congestion.
   - **No Direct API:** There's no direct JavaScript API to control or query BBR2's internal state. The browser handles this transparently.
   - **Performance Impact:** Explain how BBR2's congestion control affects the speed at which data is transferred, which directly influences the user experience in JavaScript applications.

5. **Logical Reasoning and Examples:**
   - **Assumptions:**  Make clear assumptions about the network conditions and user actions.
   - **Input/Output:**  For key methods like `OnCongestionEvent`, consider:
      - *Input:* Current state (mode, cwnd, pacing rate), acknowledged packets, lost packets.
      - *Output:* Updated state (potentially new mode, adjusted cwnd and pacing rate).
   - **Illustrative Scenarios:**  Create simple scenarios (e.g., initial connection, network congestion) to demonstrate how BBR2 reacts.

6. **User Errors and Debugging:**
   - **Misconfiguration:**  Focus on common issues: network problems, server limitations. Explain how BBR2 might react to these situations.
   - **Debugging Clues:**  Trace the steps a user might take that would lead to BBR2 being involved. Consider network requests, page loads, etc. Emphasize the server-side nature of BBR2 in a typical client-server interaction. The "chrome://net-internals" tool is crucial for debugging network issues in Chromium.

7. **Structure and Clarity:**
   - **Organize by Topic:** Group related functionalities together (e.g., core functionality, JavaScript connection, debugging).
   - **Use Clear Language:** Avoid overly technical jargon where possible, or explain it simply.
   - **Provide Concrete Examples:**  Illustrate abstract concepts with specific scenarios.
   - **Maintain Flow:** Ensure a logical progression through the explanation.
   - **Review and Refine:** Read through the generated explanation to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that need more detail.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the internal state transitions of BBR2.
* **Correction:**  Realize the importance of explaining the *user-facing impact* and the indirect connection to JavaScript.
* **Initial thought:**  Provide very low-level code details.
* **Correction:**  Focus on the high-level functionality and the purpose of different parts of the code, as requested by the prompt.
* **Initial thought:**  Assume the user has deep networking knowledge.
* **Correction:**  Explain concepts in a way that's understandable to a broader audience, including developers who might not be network experts.

By following this systematic approach, combining code analysis with conceptual understanding and focusing on the specific requirements of the prompt, a comprehensive and informative explanation can be generated.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_sender.cc` 文件的功能详细说明：

**主要功能：BBRv2 拥塞控制发送方实现**

该文件实现了 QUIC 协议中使用的 BBRv2 (Bottleneck Bandwidth and Round-trip propagation time) 拥塞控制算法的发送方逻辑。BBRv2 是一种旨在最大化网络吞吐量并保持较低延迟的拥塞控制算法。它通过主动探测网络瓶颈带宽和往返时延（RTT）来动态调整发送速率和拥塞窗口。

**核心功能模块和概念：**

1. **状态机 (State Machine):** BBRv2 Sender 采用状态机驱动，包含以下主要状态：
   - **STARTUP:** 启动阶段，快速增加发送速率以探测可用带宽。
   - **DRAIN:** 排水阶段，在探测到足够带宽后，降低发送速率以减少排队延迟。
   - **PROBE_BW:** 带宽探测阶段，周期性地增加和减少发送速率，以持续探测最大可用带宽。
   - **PROBE_RTT:** RTT 探测阶段，降低拥塞窗口以测量最小 RTT，用于校准带宽估计。

2. **带宽和 RTT 估计 (Bandwidth and RTT Estimation):**  BBRv2 维护对网络瓶颈带宽和最小 RTT 的估计。
   - **带宽估计:** 通过观察已确认数据包的速率来估计。
   - **最小 RTT 估计:** 跟踪观察到的最小 RTT 值。

3. **拥塞窗口 (Congestion Window - CWND):**  控制网络中允许的最大未确认数据包数量。BBRv2 会根据当前状态和带宽/RTT 估计动态调整 CWND。

4. **发送速率 (Pacing Rate):** 控制发送数据包的速率。BBRv2 会根据当前状态和带宽估计动态调整发送速率。

5. **增益参数 (Gain Parameters):**  不同的状态使用不同的增益参数来调整发送速率和拥塞窗口。例如，启动阶段使用较高的增益来快速增加发送速率。

6. **应用限制感知 (Application Limited Awareness):**  BBRv2 可以感知应用程序是否限制了发送速率，并在这种情况下避免不必要的探测。

7. **模式切换 (Mode Transition):**  根据网络状态的变化（例如，RTT 变化、丢包事件），BBRv2 Sender 会在不同的状态之间切换。

8. **与 BBRv1 的兼容性 (Optional BBRv1 Interaction):** 代码中包含与旧版 BBR (BBRv1) 的交互逻辑，这可能用于平滑迁移或比较不同版本的 BBR。

**与 JavaScript 功能的关系：**

`bbr2_sender.cc` 是 C++ 代码，直接与 JavaScript 没有交互。然而，它作为 Chromium 网络栈的一部分，直接影响着浏览器中所有网络请求的性能，包括由 JavaScript 发起的请求。

**举例说明:**

当用户在网页上执行 JavaScript 代码发起一个 HTTP 请求（例如，使用 `fetch()` API 或 `XMLHttpRequest`）时，Chromium 的网络栈会处理该请求。如果 QUIC 协议被协商成功，并且 BBRv2 被选为拥塞控制算法，那么 `bbr2_sender.cc` 中的代码将控制该 QUIC 连接的数据发送速率和拥塞窗口。

例如：

- **JavaScript 发起大文件下载:**  如果 JavaScript 代码尝试下载一个大文件，BBRv2 会尝试快速提升发送速率（在 STARTUP 阶段），以尽快利用可用的带宽。
- **网络拥塞:** 如果网络出现拥塞，BBRv2 会检测到 RTT 的增加或丢包事件，并可能切换到 DRAIN 或 PROBE_RTT 状态，降低发送速率以避免进一步加剧拥塞。
- **应用限制:** 如果 JavaScript 代码处理数据的速度较慢，导致发送缓冲区为空，BBRv2 会感知到应用限制，并可能暂停积极的带宽探测。

**逻辑推理和假设输入/输出：**

**假设输入:**

- **当前状态:** `mode_ = Bbr2Mode::STARTUP`
- **RTT:**  初始 RTT 为 100ms
- **已确认数据包:**  接收到新的 ACK 包
- **网络条件:**  没有丢包

**逻辑推理和输出:**

1. **STARTUP 阶段的带宽探测:** 在 STARTUP 阶段，`Bbr2Sender` 会使用较高的 `pacing_gain` (例如 `kInitialPacingGain`) 来快速增加发送速率。
2. **更新发送速率:**  `UpdatePacingRate()` 方法会被调用，根据新的带宽估计和增益值更新 `pacing_rate_`。
   - **假设计算结果:** 新的 `pacing_rate_` 可能从初始值增加到更高的值。
3. **更新拥塞窗口:** `UpdateCongestionWindow()` 方法会被调用，根据目标拥塞窗口和已确认的字节数更新 `cwnd_`。
   - **假设计算结果:** `cwnd_` 会增加，允许发送更多的数据包。
4. **状态保持或切换:** 如果在 STARTUP 阶段持续观察到带宽增加且没有丢包，`Bbr2Sender` 会继续保持在 STARTUP 状态，直到满足退出 STARTUP 的条件（例如，达到 full bandwidth）。

**假设输入 (网络拥塞):**

- **当前状态:** `mode_ = Bbr2Mode::PROBE_BW`
- **RTT:**  RTT 突然增加到 200ms
- **丢包:**  检测到数据包丢失

**逻辑推理和输出:**

1. **检测到拥塞:** `OnCongestionEvent()` 方法会被调用，接收到 RTT 更新和丢包信息。
2. **状态切换到 DRAIN 或 PROBE_RTT:**  根据 BBRv2 的逻辑，检测到 RTT 增加和丢包可能会导致状态切换到 DRAIN 阶段（降低发送速率以减少排队）或 PROBE_RTT 阶段（降低 CWND 以测量最小 RTT）。
3. **降低发送速率和拥塞窗口:**  在 DRAIN 或 PROBE_RTT 阶段，`UpdatePacingRate()` 和 `UpdateCongestionWindow()` 会被调用，使用较低的增益值来降低 `pacing_rate_` 和 `cwnd_`。
   - **假设计算结果:** `pacing_rate_` 和 `cwnd_` 都会显著降低。

**用户或编程常见的使用错误：**

由于 `bbr2_sender.cc` 是网络栈的内部实现，用户和开发者通常不会直接与其交互，因此直接的编程错误较少。但以下情况可能导致与 BBRv2 相关的性能问题：

1. **网络配置错误:**  不正确的网络配置（例如，不合理的 MTU 设置）可能会影响 BBRv2 的性能。
2. **服务器端实现问题:** 如果服务器端的 QUIC 实现存在问题，可能会导致 BBRv2 无法正常工作。
3. **不合理的连接选项:**  虽然不太常见，但如果手动配置了不合理的 QUIC 连接选项，可能会影响 BBRv2 的行为。

**作为调试线索的用户操作步骤：**

要观察 BBRv2 的行为，用户或开发者通常需要使用网络调试工具，例如 Chromium 的 `chrome://net-internals`。以下步骤描述了如何间接地观察 BBRv2 的行为：

1. **用户打开网页或应用程序，发起网络请求。** 例如，用户在浏览器中输入一个网址并加载页面。
2. **Chromium 网络栈协商 QUIC 连接，并选择 BBRv2 作为拥塞控制算法。** 这通常在后台发生，用户不可见。
3. **在页面加载或数据传输过程中，网络性能出现问题 (例如，速度慢，延迟高)。** 用户可能会注意到页面加载缓慢或视频缓冲。
4. **开发者打开 `chrome://net-internals` 页面。**
5. **导航到 "QUIC" 选项卡，查看相关的 QUIC 连接信息。**
6. **在连接的详细信息中，查找与拥塞控制相关的指标。**  例如，可以查看 BBRv2 的当前状态、拥塞窗口、发送速率、带宽估计、最小 RTT 等。
7. **观察这些指标随时间的变化，可以帮助理解 BBRv2 如何响应网络条件的变化。** 例如，可以看到当网络拥塞时，拥塞窗口和发送速率如何下降。

**调试线索示例：**

- 如果在 `chrome://net-internals` 中看到 BBRv2 持续处于 STARTUP 状态，但带宽估计没有明显提升，可能表明网络瓶颈或服务器端存在问题。
- 如果看到 BBRv2 频繁在不同状态之间切换，可能表明网络状态不稳定。
- 如果看到最小 RTT 的估计值异常高，可能表明存在持续的排队延迟。

总之，`net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_sender.cc` 文件是 Chromium QUIC 实现中负责网络拥塞控制的关键组件，它通过实现 BBRv2 算法来优化数据传输性能。虽然 JavaScript 代码不直接操作它，但它的行为直接影响着基于 JavaScript 的网络应用的性能。开发者可以通过网络调试工具间接地观察和分析 BBRv2 的行为，以便诊断网络性能问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_sender.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/bbr2_sender.h"

#include <algorithm>
#include <cstddef>
#include <ostream>
#include <sstream>
#include <string>

#include "quiche/quic/core/congestion_control/bandwidth_sampler.h"
#include "quiche/quic/core/congestion_control/bbr2_drain.h"
#include "quiche/quic/core/congestion_control/bbr2_misc.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_tag.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/print_elements.h"

namespace quic {

namespace {
// Constants based on TCP defaults.
// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
// Does not inflate the pacing rate.
const QuicByteCount kDefaultMinimumCongestionWindow = 4 * kMaxSegmentSize;

const float kInitialPacingGain = 2.885f;

const int kMaxModeChangesPerCongestionEvent = 4;
}  // namespace

// Call |member_function_call| based on the current Bbr2Mode we are in. e.g.
//
//   auto result = BBR2_MODE_DISPATCH(Foo());
//
// is equivalent to:
//
//   Bbr2ModeBase& Bbr2Sender::GetCurrentMode() {
//     if (mode_ == Bbr2Mode::STARTUP) { return startup_; }
//     if (mode_ == Bbr2Mode::DRAIN) { return drain_; }
//     ...
//   }
//   auto result = GetCurrentMode().Foo();
//
// Except that BBR2_MODE_DISPATCH guarantees the call to Foo() is non-virtual.
//
#define BBR2_MODE_DISPATCH(member_function_call)     \
  (mode_ == Bbr2Mode::STARTUP                        \
       ? (startup_.member_function_call)             \
       : (mode_ == Bbr2Mode::PROBE_BW                \
              ? (probe_bw_.member_function_call)     \
              : (mode_ == Bbr2Mode::DRAIN            \
                     ? (drain_.member_function_call) \
                     : (probe_rtt_or_die().member_function_call))))

Bbr2Sender::Bbr2Sender(QuicTime now, const RttStats* rtt_stats,
                       const QuicUnackedPacketMap* unacked_packets,
                       QuicPacketCount initial_cwnd_in_packets,
                       QuicPacketCount max_cwnd_in_packets, QuicRandom* random,
                       QuicConnectionStats* stats, BbrSender* old_sender)
    : mode_(Bbr2Mode::STARTUP),
      rtt_stats_(rtt_stats),
      unacked_packets_(unacked_packets),
      random_(random),
      connection_stats_(stats),
      params_(kDefaultMinimumCongestionWindow,
              max_cwnd_in_packets * kDefaultTCPMSS),
      model_(&params_, rtt_stats->SmoothedOrInitialRtt(),
             rtt_stats->last_update_time(),
             /*cwnd_gain=*/1.0,
             /*pacing_gain=*/kInitialPacingGain,
             old_sender ? &old_sender->sampler_ : nullptr),
      initial_cwnd_(cwnd_limits().ApplyLimits(
          (old_sender) ? old_sender->GetCongestionWindow()
                       : (initial_cwnd_in_packets * kDefaultTCPMSS))),
      cwnd_(initial_cwnd_),
      pacing_rate_(kInitialPacingGain *
                   QuicBandwidth::FromBytesAndTimeDelta(
                       cwnd_, rtt_stats->SmoothedOrInitialRtt())),
      startup_(this, &model_, now),
      drain_(this, &model_),
      probe_bw_(this, &model_),
      probe_rtt_(this, &model_),
      last_sample_is_app_limited_(false) {
  QUIC_DVLOG(2) << this << " Initializing Bbr2Sender. mode:" << mode_
                << ", PacingRate:" << pacing_rate_ << ", Cwnd:" << cwnd_
                << ", CwndLimits:" << cwnd_limits() << "  @ " << now;
  QUICHE_DCHECK_EQ(mode_, Bbr2Mode::STARTUP);
}

void Bbr2Sender::SetFromConfig(const QuicConfig& config,
                               Perspective perspective) {
  if (config.HasClientRequestedIndependentOption(kB2NA, perspective)) {
    params_.add_ack_height_to_queueing_threshold = false;
  }
  if (config.HasClientRequestedIndependentOption(kB2RP, perspective)) {
    params_.avoid_unnecessary_probe_rtt = false;
  }
  if (config.HasClientRequestedIndependentOption(k1RTT, perspective)) {
    params_.startup_full_bw_rounds = 1;
  }
  if (config.HasClientRequestedIndependentOption(k2RTT, perspective)) {
    params_.startup_full_bw_rounds = 2;
  }
  if (config.HasClientRequestedIndependentOption(kB2HR, perspective)) {
    params_.inflight_hi_headroom = 0.15;
  }
  if (config.HasClientRequestedIndependentOption(kICW1, perspective)) {
    max_cwnd_when_network_parameters_adjusted_ = 100 * kDefaultTCPMSS;
  }

  ApplyConnectionOptions(config.ClientRequestedIndependentOptions(perspective));
}

void Bbr2Sender::ApplyConnectionOptions(
    const QuicTagVector& connection_options) {
  if (GetQuicReloadableFlag(quic_bbr2_extra_acked_window) &&
      ContainsQuicTag(connection_options, kBBR4)) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_bbr2_extra_acked_window, 1, 2);
    model_.SetMaxAckHeightTrackerWindowLength(20);
  }
  if (GetQuicReloadableFlag(quic_bbr2_extra_acked_window) &&
      ContainsQuicTag(connection_options, kBBR5)) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_bbr2_extra_acked_window, 2, 2);
    model_.SetMaxAckHeightTrackerWindowLength(40);
  }
  if (ContainsQuicTag(connection_options, kBBQ1)) {
    params_.startup_pacing_gain = 2.773;
    params_.drain_pacing_gain = 1.0 / params_.drain_cwnd_gain;
  }
  if (ContainsQuicTag(connection_options, kBBQ2)) {
    params_.startup_cwnd_gain = 2.885;
    params_.drain_cwnd_gain = 2.885;
    model_.set_cwnd_gain(params_.startup_cwnd_gain);
  }
  if (ContainsQuicTag(connection_options, kB2LO)) {
    params_.ignore_inflight_lo = true;
  }
  if (ContainsQuicTag(connection_options, kB2NE)) {
    params_.always_exit_startup_on_excess_loss = true;
  }
  if (ContainsQuicTag(connection_options, kB2SL)) {
    params_.startup_loss_exit_use_max_delivered_for_inflight_hi = false;
  }
  if (ContainsQuicTag(connection_options, kB2H2)) {
    params_.limit_inflight_hi_by_max_delivered = true;
  }
  if (ContainsQuicTag(connection_options, kB2DL)) {
    params_.use_bytes_delivered_for_inflight_hi = true;
  }
  if (ContainsQuicTag(connection_options, kB2RC)) {
    params_.enable_reno_coexistence = false;
  }
  if (ContainsQuicTag(connection_options, kBSAO)) {
    model_.EnableOverestimateAvoidance();
  }
  if (ContainsQuicTag(connection_options, kBBQ6)) {
    params_.decrease_startup_pacing_at_end_of_round = true;
  }
  if (ContainsQuicTag(connection_options, kBBQ7)) {
    params_.bw_lo_mode_ = Bbr2Params::QuicBandwidthLoMode::MIN_RTT_REDUCTION;
  }
  if (ContainsQuicTag(connection_options, kBBQ8)) {
    params_.bw_lo_mode_ = Bbr2Params::QuicBandwidthLoMode::INFLIGHT_REDUCTION;
  }
  if (ContainsQuicTag(connection_options, kBBQ9)) {
    params_.bw_lo_mode_ = Bbr2Params::QuicBandwidthLoMode::CWND_REDUCTION;
  }
  if (ContainsQuicTag(connection_options, kB202)) {
    params_.max_probe_up_queue_rounds = 1;
  }
  if (ContainsQuicTag(connection_options, kB203)) {
    params_.probe_up_ignore_inflight_hi = false;
  }
  if (ContainsQuicTag(connection_options, kB204)) {
    model_.SetReduceExtraAckedOnBandwidthIncrease(true);
  }
  if (ContainsQuicTag(connection_options, kB205)) {
    params_.startup_include_extra_acked = true;
  }
  if (ContainsQuicTag(connection_options, kB207)) {
    params_.max_startup_queue_rounds = 1;
  }
  if (ContainsQuicTag(connection_options, kBBRA)) {
    model_.SetStartNewAggregationEpochAfterFullRound(true);
  }
  if (ContainsQuicTag(connection_options, kBBRB)) {
    model_.SetLimitMaxAckHeightTrackerBySendRate(true);
  }
  if (ContainsQuicTag(connection_options, kADP0)) {
    model_.SetEnableAppDrivenPacing(true);
  }
  if (ContainsQuicTag(connection_options, kB206)) {
    params_.startup_full_loss_count = params_.probe_bw_full_loss_count;
  }
  if (GetQuicReloadableFlag(quic_bbr2_simplify_inflight_hi) &&
      ContainsQuicTag(connection_options, kBBHI)) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_bbr2_simplify_inflight_hi);
    params_.probe_up_simplify_inflight_hi = true;
    // Simplify inflight_hi is intended as an alternative to ignoring it,
    // so ensure we're not ignoring it.
    params_.probe_up_ignore_inflight_hi = false;
  }
  if (GetQuicReloadableFlag(quic_bbr2_probe_two_rounds) &&
      ContainsQuicTag(connection_options, kBB2U)) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_bbr2_probe_two_rounds, 1, 3);
    params_.max_probe_up_queue_rounds = 2;
  }
  if (GetQuicReloadableFlag(quic_bbr2_probe_two_rounds) &&
      ContainsQuicTag(connection_options, kBB2S)) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_bbr2_probe_two_rounds, 2, 3);
    params_.max_startup_queue_rounds = 2;
  }
}

Limits<QuicByteCount> Bbr2Sender::GetCwndLimitsByMode() const {
  switch (mode_) {
    case Bbr2Mode::STARTUP:
      return startup_.GetCwndLimits();
    case Bbr2Mode::PROBE_BW:
      return probe_bw_.GetCwndLimits();
    case Bbr2Mode::DRAIN:
      return drain_.GetCwndLimits();
    case Bbr2Mode::PROBE_RTT:
      return probe_rtt_.GetCwndLimits();
    default:
      QUICHE_NOTREACHED();
      return Unlimited<QuicByteCount>();
  }
}

const Limits<QuicByteCount>& Bbr2Sender::cwnd_limits() const {
  return params().cwnd_limits;
}

void Bbr2Sender::AdjustNetworkParameters(const NetworkParams& params) {
  model_.UpdateNetworkParameters(params.rtt);

  if (mode_ == Bbr2Mode::STARTUP) {
    const QuicByteCount prior_cwnd = cwnd_;

    QuicBandwidth effective_bandwidth =
        std::max(params.bandwidth, model_.BandwidthEstimate());
    connection_stats_->cwnd_bootstrapping_rtt_us =
        model_.MinRtt().ToMicroseconds();

    if (params.max_initial_congestion_window > 0) {
      max_cwnd_when_network_parameters_adjusted_ =
          params.max_initial_congestion_window * kDefaultTCPMSS;
    }
    cwnd_ = cwnd_limits().ApplyLimits(
        std::min(max_cwnd_when_network_parameters_adjusted_,
                 model_.BDP(effective_bandwidth)));

    if (!params.allow_cwnd_to_decrease) {
      cwnd_ = std::max(cwnd_, prior_cwnd);
    }

    pacing_rate_ = std::max(pacing_rate_, QuicBandwidth::FromBytesAndTimeDelta(
                                              cwnd_, model_.MinRtt()));
  }
}

void Bbr2Sender::SetInitialCongestionWindowInPackets(
    QuicPacketCount congestion_window) {
  if (mode_ == Bbr2Mode::STARTUP) {
    // The cwnd limits is unchanged and still applies to the new cwnd.
    cwnd_ = cwnd_limits().ApplyLimits(congestion_window * kDefaultTCPMSS);
  }
}

void Bbr2Sender::SetApplicationDrivenPacingRate(
    QuicBandwidth application_bandwidth_target) {
  QUIC_CODE_COUNT(quic_bbr2_set_app_driven_pacing_rate);
  model_.SetApplicationBandwidthTarget(application_bandwidth_target);
}

void Bbr2Sender::OnCongestionEvent(bool /*rtt_updated*/,
                                   QuicByteCount prior_in_flight,
                                   QuicTime event_time,
                                   const AckedPacketVector& acked_packets,
                                   const LostPacketVector& lost_packets,
                                   QuicPacketCount /*num_ect*/,
                                   QuicPacketCount /*num_ce*/) {
  QUIC_DVLOG(3) << this
                << " OnCongestionEvent. prior_in_flight:" << prior_in_flight
                << " prior_cwnd:" << cwnd_ << "  @ " << event_time;
  Bbr2CongestionEvent congestion_event;
  congestion_event.prior_cwnd = cwnd_;
  congestion_event.prior_bytes_in_flight = prior_in_flight;
  congestion_event.is_probing_for_bandwidth =
      BBR2_MODE_DISPATCH(IsProbingForBandwidth());

  model_.OnCongestionEventStart(event_time, acked_packets, lost_packets,
                                &congestion_event);

  if (InSlowStart()) {
    if (!lost_packets.empty()) {
      connection_stats_->slowstart_packets_lost += lost_packets.size();
      connection_stats_->slowstart_bytes_lost += congestion_event.bytes_lost;
    }
    if (congestion_event.end_of_round_trip) {
      ++connection_stats_->slowstart_num_rtts;
    }
  }

  // Number of mode changes allowed for this congestion event.
  int mode_changes_allowed = kMaxModeChangesPerCongestionEvent;
  while (true) {
    Bbr2Mode next_mode = BBR2_MODE_DISPATCH(
        OnCongestionEvent(prior_in_flight, event_time, acked_packets,
                          lost_packets, congestion_event));

    if (next_mode == mode_) {
      break;
    }

    QUIC_DVLOG(2) << this << " Mode change:  " << mode_ << " ==> " << next_mode
                  << "  @ " << event_time;
    BBR2_MODE_DISPATCH(Leave(event_time, &congestion_event));
    mode_ = next_mode;
    BBR2_MODE_DISPATCH(Enter(event_time, &congestion_event));
    --mode_changes_allowed;
    if (mode_changes_allowed < 0) {
      QUIC_BUG(quic_bug_10443_1)
          << "Exceeded max number of mode changes per congestion event.";
      break;
    }
  }

  UpdatePacingRate(congestion_event.bytes_acked);
  QUIC_BUG_IF(quic_bug_10443_2, pacing_rate_.IsZero())
      << "Pacing rate must not be zero!";

  UpdateCongestionWindow(congestion_event.bytes_acked);
  QUIC_BUG_IF(quic_bug_10443_3, cwnd_ == 0u)
      << "Congestion window must not be zero!";

  model_.OnCongestionEventFinish(unacked_packets_->GetLeastUnacked(),
                                 congestion_event);
  last_sample_is_app_limited_ =
      congestion_event.last_packet_send_state.is_app_limited;
  if (!last_sample_is_app_limited_) {
    has_non_app_limited_sample_ = true;
  }
  if (congestion_event.bytes_in_flight == 0 &&
      params().avoid_unnecessary_probe_rtt) {
    OnEnterQuiescence(event_time);
  }

  QUIC_DVLOG(3)
      << this
      << " END CongestionEvent(acked:" << quiche::PrintElements(acked_packets)
      << ", lost:" << lost_packets.size() << ") "
      << ", Mode:" << mode_ << ", RttCount:" << model_.RoundTripCount()
      << ", BytesInFlight:" << congestion_event.bytes_in_flight
      << ", PacingRate:" << PacingRate(0) << ", CWND:" << GetCongestionWindow()
      << ", PacingGain:" << model_.pacing_gain()
      << ", CwndGain:" << model_.cwnd_gain()
      << ", BandwidthEstimate(kbps):" << BandwidthEstimate().ToKBitsPerSecond()
      << ", MinRTT(us):" << model_.MinRtt().ToMicroseconds()
      << ", BDP:" << model_.BDP(BandwidthEstimate())
      << ", BandwidthLatest(kbps):"
      << model_.bandwidth_latest().ToKBitsPerSecond()
      << ", BandwidthLow(kbps):" << model_.bandwidth_lo().ToKBitsPerSecond()
      << ", BandwidthHigh(kbps):" << model_.MaxBandwidth().ToKBitsPerSecond()
      << ", InflightLatest:" << model_.inflight_latest()
      << ", InflightLow:" << model_.inflight_lo()
      << ", InflightHigh:" << model_.inflight_hi()
      << ", TotalAcked:" << model_.total_bytes_acked()
      << ", TotalLost:" << model_.total_bytes_lost()
      << ", TotalSent:" << model_.total_bytes_sent() << "  @ " << event_time;
}

void Bbr2Sender::UpdatePacingRate(QuicByteCount bytes_acked) {
  if (BandwidthEstimate().IsZero()) {
    return;
  }

  if (model_.total_bytes_acked() == bytes_acked) {
    // After the first ACK, cwnd_ is still the initial congestion window.
    pacing_rate_ = QuicBandwidth::FromBytesAndTimeDelta(cwnd_, model_.MinRtt());
    return;
  }

  QuicBandwidth target_rate = model_.pacing_gain() * model_.BandwidthEstimate();
  if (model_.full_bandwidth_reached()) {
    pacing_rate_ = target_rate;
    return;
  }
  if (params_.decrease_startup_pacing_at_end_of_round &&
      model_.pacing_gain() < Params().startup_pacing_gain) {
    pacing_rate_ = target_rate;
    return;
  }
  if (params_.bw_lo_mode_ != Bbr2Params::DEFAULT &&
      model_.loss_events_in_round() > 0) {
    pacing_rate_ = target_rate;
    return;
  }

  // By default, the pacing rate never decreases in STARTUP.
  if (target_rate > pacing_rate_) {
    pacing_rate_ = target_rate;
  }
}

void Bbr2Sender::UpdateCongestionWindow(QuicByteCount bytes_acked) {
  QuicByteCount target_cwnd = GetTargetCongestionWindow(model_.cwnd_gain());

  const QuicByteCount prior_cwnd = cwnd_;
  if (model_.full_bandwidth_reached() || Params().startup_include_extra_acked) {
    target_cwnd += model_.MaxAckHeight();
    cwnd_ = std::min(prior_cwnd + bytes_acked, target_cwnd);
  } else if (prior_cwnd < target_cwnd || prior_cwnd < 2 * initial_cwnd_) {
    cwnd_ = prior_cwnd + bytes_acked;
  }
  const QuicByteCount desired_cwnd = cwnd_;

  cwnd_ = GetCwndLimitsByMode().ApplyLimits(cwnd_);
  const QuicByteCount model_limited_cwnd = cwnd_;

  cwnd_ = cwnd_limits().ApplyLimits(cwnd_);

  QUIC_DVLOG(3) << this << " Updating CWND. target_cwnd:" << target_cwnd
                << ", max_ack_height:" << model_.MaxAckHeight()
                << ", full_bw:" << model_.full_bandwidth_reached()
                << ", bytes_acked:" << bytes_acked
                << ", inflight_lo:" << model_.inflight_lo()
                << ", inflight_hi:" << model_.inflight_hi() << ". (prior_cwnd) "
                << prior_cwnd << " => (desired_cwnd) " << desired_cwnd
                << " => (model_limited_cwnd) " << model_limited_cwnd
                << " => (final_cwnd) " << cwnd_;
}

QuicByteCount Bbr2Sender::GetTargetCongestionWindow(float gain) const {
  return std::max(model_.BDP(model_.BandwidthEstimate(), gain),
                  cwnd_limits().Min());
}

void Bbr2Sender::OnPacketSent(QuicTime sent_time, QuicByteCount bytes_in_flight,
                              QuicPacketNumber packet_number,
                              QuicByteCount bytes,
                              HasRetransmittableData is_retransmittable) {
  QUIC_DVLOG(3) << this << " OnPacketSent: pkn:" << packet_number
                << ", bytes:" << bytes << ", cwnd:" << cwnd_
                << ", inflight:" << bytes_in_flight + bytes
                << ", total_sent:" << model_.total_bytes_sent() + bytes
                << ", total_acked:" << model_.total_bytes_acked()
                << ", total_lost:" << model_.total_bytes_lost() << "  @ "
                << sent_time;
  if (InSlowStart()) {
    ++connection_stats_->slowstart_packets_sent;
    connection_stats_->slowstart_bytes_sent += bytes;
  }
  if (bytes_in_flight == 0 && params().avoid_unnecessary_probe_rtt) {
    OnExitQuiescence(sent_time);
  }
  model_.OnPacketSent(sent_time, bytes_in_flight, packet_number, bytes,
                      is_retransmittable);
}

void Bbr2Sender::OnPacketNeutered(QuicPacketNumber packet_number) {
  model_.OnPacketNeutered(packet_number);
}

bool Bbr2Sender::CanSend(QuicByteCount bytes_in_flight) {
  const bool result = bytes_in_flight < GetCongestionWindow();
  return result;
}

QuicByteCount Bbr2Sender::GetCongestionWindow() const {
  // TODO(wub): Implement Recovery?
  return cwnd_;
}

QuicBandwidth Bbr2Sender::PacingRate(QuicByteCount /*bytes_in_flight*/) const {
  return pacing_rate_;
}

void Bbr2Sender::OnApplicationLimited(QuicByteCount bytes_in_flight) {
  if (bytes_in_flight >= GetCongestionWindow()) {
    return;
  }

  model_.OnApplicationLimited();
  QUIC_DVLOG(2) << this << " Becoming application limited. Last sent packet: "
                << model_.last_sent_packet()
                << ", CWND: " << GetCongestionWindow();
}

QuicByteCount Bbr2Sender::GetTargetBytesInflight() const {
  QuicByteCount bdp = model_.BDP(model_.BandwidthEstimate());
  return std::min(bdp, GetCongestionWindow());
}

void Bbr2Sender::PopulateConnectionStats(QuicConnectionStats* stats) const {
  stats->num_ack_aggregation_epochs = model_.num_ack_aggregation_epochs();
}

void Bbr2Sender::OnEnterQuiescence(QuicTime now) {
  last_quiescence_start_ = now;
}

void Bbr2Sender::OnExitQuiescence(QuicTime now) {
  if (last_quiescence_start_ != QuicTime::Zero()) {
    Bbr2Mode next_mode = BBR2_MODE_DISPATCH(
        OnExitQuiescence(now, std::min(now, last_quiescence_start_)));
    if (next_mode != mode_) {
      BBR2_MODE_DISPATCH(Leave(now, nullptr));
      mode_ = next_mode;
      BBR2_MODE_DISPATCH(Enter(now, nullptr));
    }
    last_quiescence_start_ = QuicTime::Zero();
  }
}

std::string Bbr2Sender::GetDebugState() const {
  std::ostringstream stream;
  stream << ExportDebugState();
  return stream.str();
}

Bbr2Sender::DebugState Bbr2Sender::ExportDebugState() const {
  DebugState s;
  s.mode = mode_;
  s.round_trip_count = model_.RoundTripCount();
  s.bandwidth_hi = model_.MaxBandwidth();
  s.bandwidth_lo = model_.bandwidth_lo();
  s.bandwidth_est = BandwidthEstimate();
  s.inflight_hi = model_.inflight_hi();
  s.inflight_lo = model_.inflight_lo();
  s.max_ack_height = model_.MaxAckHeight();
  s.min_rtt = model_.MinRtt();
  s.min_rtt_timestamp = model_.MinRttTimestamp();
  s.congestion_window = cwnd_;
  s.pacing_rate = pacing_rate_;
  s.last_sample_is_app_limited = last_sample_is_app_limited_;
  s.end_of_app_limited_phase = model_.end_of_app_limited_phase();

  s.startup = startup_.ExportDebugState();
  s.drain = drain_.ExportDebugState();
  s.probe_bw = probe_bw_.ExportDebugState();
  s.probe_rtt = probe_rtt_.ExportDebugState();

  return s;
}

std::ostream& operator<<(std::ostream& os, const Bbr2Sender::DebugState& s) {
  os << "mode: " << s.mode << "\n";
  os << "round_trip_count: " << s.round_trip_count << "\n";
  os << "bandwidth_hi ~ lo ~ est: " << s.bandwidth_hi << " ~ " << s.bandwidth_lo
     << " ~ " << s.bandwidth_est << "\n";
  os << "min_rtt: " << s.min_rtt << "\n";
  os << "min_rtt_timestamp: " << s.min_rtt_timestamp << "\n";
  os << "congestion_window: " << s.congestion_window << "\n";
  os << "pacing_rate: " << s.pacing_rate << "\n";
  os << "last_sample_is_app_limited: " << s.last_sample_is_app_limited << "\n";

  if (s.mode == Bbr2Mode::STARTUP) {
    os << s.startup;
  }

  if (s.mode == Bbr2Mode::DRAIN) {
    os << s.drain;
  }

  if (s.mode == Bbr2Mode::PROBE_BW) {
    os << s.probe_bw;
  }

  if (s.mode == Bbr2Mode::PROBE_RTT) {
    os << s.probe_rtt;
  }

  return os;
}

}  // namespace quic
```