Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for the functionality of the `PragueSender` class, its relationship to JavaScript, logic, potential errors, and debugging steps. This requires a multi-faceted analysis.

2. **Initial Code Scan (Keywords and Structure):**  I first scanned the code for keywords and structural elements to get a high-level overview:
    * `#include`:  Indicates dependencies (RTT, TCP Cubic, Clock, Stats). This tells me it's related to congestion control in a network context.
    * `namespace quic`:  Confirms it's part of the QUIC protocol implementation.
    * Class declaration `PragueSender`: This is the core of the analysis.
    * Inheritance `TcpCubicSenderBytes`:  Important! It inherits from an existing TCP congestion control mechanism. This suggests `PragueSender` is a modification or extension.
    * Constructor:  Initialization of member variables like `connection_start_time_`, `last_alpha_update_`.
    * Key methods: `OnCongestionEvent`, `GetCongestionControlType`, `EnableECT1`. These are the core functionalities.
    * Member variables:  `ect1_enabled_`, `rtt_virt_`, `prague_alpha_`, `ect_count_`, `ce_count_`, etc. These hold the state of the algorithm.
    * Constants like `kPragueRttVirtMin`, `kPragueEwmaGain`, `kRoundsBeforeReducedRttDependence`. These define parameters of the algorithm.

3. **Focus on Core Functionality (`OnCongestionEvent`):** This is the most complex and important method. I'd break it down step-by-step:
    * **Check `ect1_enabled_`:**  A conditional execution path. If not enabled, it defaults to the base class's behavior. This immediately tells me ECN (Explicit Congestion Notification) is a key aspect.
    * **RTT Updates:**  `rtt_virt_` calculation, use of `smoothed_rtt()`. This links it to network delay estimation.
    * **Alpha Update:**  Conditional update based on time and CE/ECT counts. The formula suggests an Exponential Weighted Moving Average (EWMA). This is about reacting to congestion signals.
    * **Recent Congestion Response Logic:** Checking for packet loss and the timing of the last response. This implies a mechanism to avoid over-reacting to congestion signals.
    * **RTT Dependence Reduction:**  A conditional logic block based on time and network conditions. This addresses the issue of shorter RTTs in some networks.
    * **Congestion Avoidance Deflator:**  Calculation of a factor based on RTT and `rtt_virt_`. This is where the "Prague" part likely comes into play – a modification of standard congestion avoidance.
    * **Fast Path (No CE or Loss):** Delegates to the base class with a potential adjustment for RTT dependence.
    * **Slow Start Handling:**  Exiting slow start on CE.
    * **CE Marked Bytes Estimation:**  Calculation of `bytes_ce`.
    * **Synthetic Loss:**  Crucial part of the Prague algorithm. It simulates a loss event based on CE marks.
    * **CWND Reduction based on Alpha:**  The core of the Prague adaptation. `prague_alpha_` scales the congestion window reduction.
    * **Packet Ack Processing with CE Consideration:**  Adjusting the acknowledged bytes based on the CE fraction.

4. **Identify Key Concepts:**  From the `OnCongestionEvent` analysis, several key concepts emerge:
    * **Congestion Control:** The primary function.
    * **Explicit Congestion Notification (ECN):**  The use of ECT and CE flags.
    * **TCP Cubic:**  The base algorithm being extended.
    * **Slow Start and Congestion Avoidance:**  Standard TCP congestion control phases.
    * **Round-Trip Time (RTT):**  A critical input for the algorithm.
    * **Congestion Window (CWND):** The primary output and control variable.

5. **Relate to JavaScript (or Lack Thereof):**  This requires understanding where this C++ code fits in the Chromium architecture. It's part of the network stack, handling low-level protocol details. JavaScript in the browser interacts with this indirectly through higher-level APIs (like `fetch` or WebSockets). The connection is conceptual (both aim for reliable data transfer) but not direct in terms of code interaction.

6. **Develop Logic Examples (Input/Output):**  To illustrate the logic, I considered scenarios:
    * **Scenario 1 (No CE):** A simple case to show the baseline behavior.
    * **Scenario 2 (First CE):**  Illustrates the initial `alpha` setting and synthetic loss.
    * **Scenario 3 (Subsequent CE):** Shows the `alpha` update and scaled CWND reduction.

7. **Identify Potential Errors:**  Thinking about how this code could be misused or fail:
    * **Incorrect ECN Configuration:**  A common networking issue.
    * **Clock Skew:**  Time-based decisions are sensitive to clock accuracy.
    * **Parameter Tuning:**  The constants might need adjustment for different network conditions.

8. **Outline Debugging Steps:**  How would a developer investigate issues?  Following the request's hint about user actions:
    * Start with user-level actions.
    * Trace through network layers (DevTools).
    * Consider QUIC-specific debugging tools (if they exist).
    * Finally, examine the C++ code itself.

9. **Structure the Explanation:**  Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the core functionality (`OnCongestionEvent`).
    * Address the JavaScript relationship.
    * Provide concrete logic examples.
    * Highlight common errors.
    * Outline debugging steps.

10. **Refine and Elaborate:**  Review the explanation for clarity, accuracy, and completeness. Add details and explanations for technical terms where necessary. For example, explicitly define ECN, slow start, and congestion avoidance. Explain *why* certain logic exists (e.g., the virtual RTT addresses issues with low-latency networks).

By following this thought process, systematically analyzing the code, and considering the different aspects requested, I arrived at the comprehensive explanation provided in the initial example. The key is to break down a complex piece of code into smaller, understandable parts and then connect those parts to the broader context.
```cpp
// Copyright (c) 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/prague_sender.h"

#include <algorithm>

#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/congestion_control/tcp_cubic_sender_bytes.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_connection_stats.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"

namespace quic {

PragueSender::PragueSender(const QuicClock* clock, const RttStats* rtt_stats,
                           QuicPacketCount initial_tcp_congestion_window,
                           QuicPacketCount max_congestion_window,
                           QuicConnectionStats* stats)
    : TcpCubicSenderBytes(clock, rtt_stats, false,
                          initial_tcp_congestion_window, max_congestion_window,
                          stats),
      connection_start_time_(clock->Now()),
      last_alpha_update_(connection_start_time_) {}

void PragueSender::OnCongestionEvent(bool rtt_updated,
                                     QuicByteCount prior_in_flight,
                                     QuicTime event_time,
                                     const AckedPacketVector& acked_packets,
                                     const LostPacketVector& lost_packets,
                                     QuicPacketCount num_ect,
                                     QuicPacketCount num_ce) {
  if (!ect1_enabled_) {
    TcpCubicSenderBytes::OnCongestionEvent(rtt_updated, prior_in_flight,
                                           event_time, acked_packets,
                                           lost_packets, num_ect, num_ce);
    return;
  }
  // Update Prague-specific variables.
  if (rtt_updated) {
    rtt_virt_ = std::max(rtt_stats()->smoothed_rtt(), kPragueRttVirtMin);
  }
  if (prague_alpha_.has_value()) {
    ect_count_ += num_ect;
    ce_count_ += num_ce;
    if (event_time - last_alpha_update_ > rtt_virt_) {
      // Update alpha once per virtual RTT.
      float frac = static_cast<float>(ce_count_) /
                   static_cast<float>(ect_count_ + ce_count_);
      prague_alpha_ =
          (1 - kPragueEwmaGain) * *prague_alpha_ + kPragueEwmaGain * frac;
      last_alpha_update_ = event_time;
      ect_count_ = 0;
      ce_count_ = 0;
    }
  } else if (num_ce > 0) {
    last_alpha_update_ = event_time;
    prague_alpha_ = 1.0;
    ect_count_ = num_ect;
    ce_count_ = num_ce;
  }
  if (!lost_packets.empty() && last_congestion_response_time_.has_value() &&
      (event_time - *last_congestion_response_time_ < rtt_virt_)) {
    // Give credit for recent ECN cwnd reductions if there is a packet loss.
    QuicByteCount previous_reduction = last_congestion_response_size_;
    last_congestion_response_time_.reset();
    set_congestion_window(GetCongestionWindow() + previous_reduction);
  }
  // Due to shorter RTTs with L4S, and the longer virtual RTT, after 500 RTTs
  // congestion avoidance should grow slower than in Cubic.
  if (!reduce_rtt_dependence_) {
    reduce_rtt_dependence_ =
        !InSlowStart() && lost_packets.empty() &&
        (event_time - connection_start_time_) >
            kRoundsBeforeReducedRttDependence * rtt_stats()->smoothed_rtt();
  }
  float congestion_avoidance_deflator;
  if (reduce_rtt_dependence_) {
    congestion_avoidance_deflator =
        static_cast<float>(rtt_stats()->smoothed_rtt().ToMicroseconds()) /
        static_cast<float>(rtt_virt_.ToMicroseconds());
    congestion_avoidance_deflator *= congestion_avoidance_deflator;
  } else {
    congestion_avoidance_deflator = 1.0f;
  }
  QuicByteCount original_cwnd = GetCongestionWindow();
  if (num_ce == 0 || !lost_packets.empty()) {
    // Fast path. No ECN specific logic except updating stats, adjusting for
    // previous CE responses, and reduced RTT dependence.
    TcpCubicSenderBytes::OnCongestionEvent(rtt_updated, prior_in_flight,
                                           event_time, acked_packets,
                                           lost_packets, num_ect, num_ce);
    if (lost_packets.empty() && reduce_rtt_dependence_ &&
        original_cwnd < GetCongestionWindow()) {
      QuicByteCount cwnd_increase = GetCongestionWindow() - original_cwnd;
      set_congestion_window(original_cwnd +
                            cwnd_increase * congestion_avoidance_deflator);
    }
    return;
  }
  // num_ce > 0 and lost_packets is empty.
  if (InSlowStart()) {
    ExitSlowstart();
  }
  // Estimate bytes that were CE marked
  QuicByteCount bytes_acked = 0;
  for (auto packet : acked_packets) {
    bytes_acked += packet.bytes_acked;
  }
  float ce_fraction =
      static_cast<float>(num_ce) / static_cast<float>(num_ect + num_ce);
  QuicByteCount bytes_ce = bytes_acked * ce_fraction;
  QuicPacketCount ce_packets_remaining = num_ce;
  bytes_acked -= bytes_ce;
  if (!last_congestion_response_time_.has_value() ||
      event_time - *last_congestion_response_time_ > rtt_virt_) {
    last_congestion_response_time_ = event_time;
    // Create a synthetic loss to trigger a loss response. The packet number
    // needs to be large enough to not be before the last loss response, which
    // should be easy since acked packet numbers should be higher than lost
    // packet numbers, due to the delay in detecting loss.
    while (ce_packets_remaining > 0) {
      OnPacketLost(acked_packets.back().packet_number, bytes_ce,
                   prior_in_flight);
      bytes_ce = 0;
      ce_packets_remaining--;
    }
    QuicByteCount cwnd_reduction = original_cwnd - GetCongestionWindow();
    last_congestion_response_size_ = cwnd_reduction * *prague_alpha_;
    set_congestion_window(original_cwnd - last_congestion_response_size_);
    set_slowstart_threshold(GetCongestionWindow());
    ExitRecovery();
  }
  if (num_ect == 0) {
    return;
  }
  for (const AckedPacket& acked : acked_packets) {
    // Timing matters so report all of the packets faithfully, but reduce the
    // size to reflect that some bytes were marked CE.
    OnPacketAcked(
        acked.packet_number,
        acked.bytes_acked * (1 - ce_fraction) * congestion_avoidance_deflator,
        prior_in_flight, event_time);
  }
}

CongestionControlType PragueSender::GetCongestionControlType() const {
  return kPragueCubic;
}

bool PragueSender::EnableECT1() {
  ect1_enabled_ = true;
  return true;
}

}  // namespace quic
```

### 功能列表

`net/third_party/quiche/src/quiche/quic/core/congestion_control/prague_sender.cc` 文件实现了名为 `PragueSender` 的 QUIC 拥塞控制算法。其主要功能包括：

1. **继承自 `TcpCubicSenderBytes`:**  `PragueSender` 基于 TCP Cubic 拥塞控制算法，并对其进行修改和增强。这意味着它保留了 Cubic 算法的基本特性，例如在稳定状态下的积极增长和在拥塞时的快速回退。

2. **支持显式拥塞通知 (ECN):**  `PragueSender` 旨在更好地利用 ECN 信号（ECT 和 CE 标记）来响应网络拥塞，而无需像传统的丢包检测那样激进地降低拥塞窗口。

3. **计算和更新 Prague Alpha (α):**  该算法引入了一个名为 `prague_alpha_` 的参数，它代表了网络中经历拥塞的程度。当接收到带有 CE 标记的数据包时，`prague_alpha_` 会根据 CE 标记的比例进行更新，使用指数加权移动平均 (EWMA) 来平滑波动。

4. **虚拟 RTT (rtt_virt_):**  为了更稳定地更新 `prague_alpha_`，算法使用了一个虚拟 RTT，它是实际平滑 RTT 和一个最小值 (`kPragueRttVirtMin`) 中的较大值。这有助于避免因 RTT 波动过大而频繁更新 `alpha`。

5. **基于 ECN 的拥塞响应:** 当接收到带有 CE 标记但没有丢包的数据包时，`PragueSender` 会模拟一个“合成丢包”来触发拥塞响应。但与实际丢包不同，它会根据 `prague_alpha_` 的值来调整拥塞窗口的缩减量。拥塞程度越高（`alpha` 越大），拥塞窗口的缩减也越大。

6. **减少对 RTT 的依赖性:**  对于具有较低 RTT 的连接（例如使用 L4S），`PragueSender` 在一定时间后会降低拥塞避免阶段的增长速度，使其增长慢于标准的 Cubic 算法。这是通过一个 `congestion_avoidance_deflator` 来实现的。

7. **处理丢包事件:**  如果发生丢包，`PragueSender` 会像标准的 Cubic 算法一样进行响应，但也会考虑最近因 ECN 导致的拥塞窗口缩减，以避免过度降低拥塞窗口。

8. **启用 ECT(1):**  `EnableECT1()` 方法用于启用发送端对 ECN 的支持。

### 与 JavaScript 的关系

该 C++ 文件直接存在于 Chromium 的网络栈底层，负责 QUIC 协议的拥塞控制逻辑。**它与 JavaScript 没有直接的代码级别的交互。**

然而，从概念上讲，该文件影响着用户通过 JavaScript 发起的网络请求的性能：

* **`fetch()` API:** 当 JavaScript 代码使用 `fetch()` API 发起 HTTP/3 请求时（QUIC 是 HTTP/3 的底层传输协议），`PragueSender` 的拥塞控制逻辑会影响数据传输的速度和稳定性。例如，如果网络发生拥塞，`PragueSender` 会根据 ECN 信号或丢包事件调整发送速率，这会直接影响 `fetch()` 请求的完成时间。
* **WebSocket API:** 类似地，对于基于 QUIC 的 WebSocket 连接，`PragueSender` 负责管理连接的拥塞窗口，影响实时数据传输的速率。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch()` 下载一个大文件。如果网络中发生拥塞，并且网络设备支持 ECN，以下流程可能会发生：

1. **网络拥塞:** 网络中的路由器开始经历拥塞，并将一些数据包标记为 CE (Congestion Experienced)。
2. **QUIC 端点接收 CE 标记:**  运行 `PragueSender` 的 QUIC 端点接收到带有 CE 标记的数据包。
3. **`PragueSender` 响应:** `PragueSender` 会更新其内部的 `prague_alpha_` 值，并可能触发一个合成丢包事件。
4. **拥塞窗口调整:**  根据 `prague_alpha_` 的值，`PragueSender` 会适当减小拥塞窗口，从而降低发送速率。
5. **JavaScript 观察到的现象:**  在 JavaScript 层面，用户可能会观察到文件下载速度的暂时下降，这是 `PragueSender` 响应网络拥塞的结果。

虽然 JavaScript 代码本身不直接调用 `PragueSender` 的方法，但网络栈的底层行为（如拥塞控制）直接影响着 JavaScript 发起的网络操作的性能和行为。

### 逻辑推理：假设输入与输出

**假设输入：**

* `rtt_updated = true`
* `prior_in_flight = 10000` (字节)
* `event_time = TimeTicks(100)`
* `acked_packets` 包含一个确认包，`bytes_acked = 5000`，没有 CE 标记。
* `lost_packets` 为空。
* `num_ect = 10`
* `num_ce = 3`

**场景：连接处于拥塞避免阶段，且 `ect1_enabled_` 为 true。这是首次接收到 CE 标记。**

**输出推断：**

1. **RTT 更新:** 如果 `rtt_updated` 为 true，`rtt_virt_` 将被更新为 `max(rtt_stats()->smoothed_rtt(), kPragueRttVirtMin)`. 假设 `rtt_stats()->smoothed_rtt()` 为 50ms，`kPragueRttVirtMin` 为 30ms，则 `rtt_virt_` 将为 50ms。
2. **Alpha 更新 (首次):** 因为 `prague_alpha_` 没有值，并且 `num_ce > 0`，`prague_alpha_` 将被设置为 1.0。 `last_alpha_update_` 将被设置为 `event_time`。`ect_count_` 将为 10，`ce_count_` 将为 3。
3. **无丢包，无最近拥塞响应:**  条件不满足。
4. **RTT 依赖性检查:** 根据条件判断是否需要降低 RTT 依赖性。
5. **快速路径 (不满足):** 因为 `num_ce > 0` 且 `lost_packets` 为空，不走快速路径。
6. **退出慢启动 (如果需要):** 假设当前不在慢启动阶段。
7. **估计 CE 标记的字节:** `ce_fraction = 3 / (10 + 3) = 0.23`。 `bytes_ce = 5000 * 0.23 = 1150`。 `ce_packets_remaining = 3`。`bytes_acked` 更新为 `5000 - 1150 = 3850`。
8. **触发合成丢包:** 因为 `last_congestion_response_time_` 没有值或时间间隔足够长，会进入此分支。
   - 循环三次，每次调用 `OnPacketLost`，模拟丢失 `bytes_ce` (1150) 字节。
   - 计算拥塞窗口缩减量。假设 `original_cwnd` 为 10 个数据包（每个 1000 字节，共 10000 字节），缩减量为 `original_cwnd - GetCongestionWindow()`。
   - 更新 `last_congestion_response_size_` 为缩减量乘以 `prague_alpha_` (1.0)。
   - 更新拥塞窗口 `set_congestion_window(original_cwnd - last_congestion_response_size_)`。
   - 更新慢启动阈值 `set_slowstart_threshold(GetCongestionWindow())`。
   - 调用 `ExitRecovery()`。
9. **处理 ACK 包:**  调用 `OnPacketAcked`，调整确认的字节数以反映 CE 标记，并考虑 RTT 依赖性。

**注意:**  具体的数值输出取决于 RTT 统计信息、拥塞窗口大小和相关常量的值，这里只是一个逻辑推断的例子。

### 用户或编程常见的使用错误

1. **未启用 ECN 支持:**  如果发送端或网络路径不支持 ECN，`PragueSender` 的 ECN 特性将无法发挥作用。这通常不是 `PragueSender` 代码本身的问题，而是网络配置问题。

2. **时钟不准确:** `PragueSender` 依赖于准确的时钟 (`QuicClock`) 来计算时间差和更新参数。如果系统时钟不准确，可能会导致 `alpha` 更新频率不正确，影响拥塞控制的性能。

3. **不正确的 RTT 估计:** `PragueSender` 使用 `RttStats` 来获取 RTT 信息。如果 RTT 估计不准确（例如，由于采样不足或网络抖动），可能会导致 `rtt_virt_` 的计算不准确，进而影响 `alpha` 的更新。

4. **参数调优不当:**  `PragueSender` 中有一些常量（例如 `kPragueEwmaGain`, `kPragueRttVirtMin`, `kRoundsBeforeReducedRttDependence`）。如果这些参数的默认值不适用于特定的网络环境，可能需要进行调整。错误的参数配置可能导致拥塞控制过于激进或过于保守。

5. **与其它拥塞控制算法的交互问题:**  在某些复杂的网络场景中，如果网络路径上存在使用不同拥塞控制算法的连接，可能会发生交互问题，影响 `PragueSender` 的性能。

**用户操作如何一步步到达这里（调试线索）:**

假设用户报告了一个网络连接速度慢或者不稳定的问题，开发人员可能会沿着以下步骤进行调试，最终可能需要查看 `prague_sender.cc` 的代码：

1. **用户报告问题:** 用户反馈在使用 Chromium 浏览器访问某个网站或应用时，网络速度很慢，或者连接经常断开。

2. **初步排查（用户层面）:**
   - 检查用户本地网络连接是否正常。
   - 尝试访问其他网站或应用，确认问题是否特定于某个服务。
   - 重启浏览器或计算机。

3. **开发者工具分析:**
   - 打开 Chromium 的开发者工具 (Network 面板)。
   - 观察网络请求的 Timing 信息，查看是否存在延迟、阻塞或频繁的连接建立/断开。
   - 查看请求的协议是否为 HTTP/3 (使用 QUIC)。

4. **QUIC 连接分析:**
   - 如果确定使用了 QUIC，可能需要查看 `chrome://webrtc-internals` 或其他 QUIC 相关的内部工具，以获取更详细的连接统计信息。
   - 检查拥塞窗口 (Congestion Window)、丢包率、RTT 等指标。如果拥塞窗口持续很小，或者丢包率很高，可能表明拥塞控制算法在积极地限制发送速率。

5. **网络栈日志和追踪:**
   - 启用 Chromium 的网络栈日志 (net-internals)。
   - 收集 QUIC 连接的事件日志，例如拥塞事件、ACK 包、丢失包等。
   - 分析日志，查看 `PragueSender` 是否频繁触发拥塞响应，或者 `alpha` 值的变化是否异常。

6. **源代码审查 (最后手段):**
   - 如果通过日志和追踪仍然无法确定问题原因，开发人员可能需要查看 `prague_sender.cc` 的源代码，以理解其具体的拥塞控制逻辑。
   - 重点关注 `OnCongestionEvent` 方法，查看在特定的网络条件下，拥塞窗口是如何被调整的。
   - 可以通过添加额外的日志输出来跟踪关键变量的值，例如 `prague_alpha_`, `rtt_virt_`, 拥塞窗口大小等。

**总结:**  `prague_sender.cc` 的调试通常是网络问题排查的深入阶段，只有在排除了用户本地问题、网络基础设施问题以及其他更高层协议问题后，才会深入到具体的拥塞控制算法实现。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/prague_sender.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/prague_sender.h"

#include <algorithm>

#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/congestion_control/tcp_cubic_sender_bytes.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_connection_stats.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"

namespace quic {

PragueSender::PragueSender(const QuicClock* clock, const RttStats* rtt_stats,
                           QuicPacketCount initial_tcp_congestion_window,
                           QuicPacketCount max_congestion_window,
                           QuicConnectionStats* stats)
    : TcpCubicSenderBytes(clock, rtt_stats, false,
                          initial_tcp_congestion_window, max_congestion_window,
                          stats),
      connection_start_time_(clock->Now()),
      last_alpha_update_(connection_start_time_) {}

void PragueSender::OnCongestionEvent(bool rtt_updated,
                                     QuicByteCount prior_in_flight,
                                     QuicTime event_time,
                                     const AckedPacketVector& acked_packets,
                                     const LostPacketVector& lost_packets,
                                     QuicPacketCount num_ect,
                                     QuicPacketCount num_ce) {
  if (!ect1_enabled_) {
    TcpCubicSenderBytes::OnCongestionEvent(rtt_updated, prior_in_flight,
                                           event_time, acked_packets,
                                           lost_packets, num_ect, num_ce);
    return;
  }
  // Update Prague-specific variables.
  if (rtt_updated) {
    rtt_virt_ = std::max(rtt_stats()->smoothed_rtt(), kPragueRttVirtMin);
  }
  if (prague_alpha_.has_value()) {
    ect_count_ += num_ect;
    ce_count_ += num_ce;
    if (event_time - last_alpha_update_ > rtt_virt_) {
      // Update alpha once per virtual RTT.
      float frac = static_cast<float>(ce_count_) /
                   static_cast<float>(ect_count_ + ce_count_);
      prague_alpha_ =
          (1 - kPragueEwmaGain) * *prague_alpha_ + kPragueEwmaGain * frac;
      last_alpha_update_ = event_time;
      ect_count_ = 0;
      ce_count_ = 0;
    }
  } else if (num_ce > 0) {
    last_alpha_update_ = event_time;
    prague_alpha_ = 1.0;
    ect_count_ = num_ect;
    ce_count_ = num_ce;
  }
  if (!lost_packets.empty() && last_congestion_response_time_.has_value() &&
      (event_time - *last_congestion_response_time_ < rtt_virt_)) {
    // Give credit for recent ECN cwnd reductions if there is a packet loss.
    QuicByteCount previous_reduction = last_congestion_response_size_;
    last_congestion_response_time_.reset();
    set_congestion_window(GetCongestionWindow() + previous_reduction);
  }
  // Due to shorter RTTs with L4S, and the longer virtual RTT, after 500 RTTs
  // congestion avoidance should grow slower than in Cubic.
  if (!reduce_rtt_dependence_) {
    reduce_rtt_dependence_ =
        !InSlowStart() && lost_packets.empty() &&
        (event_time - connection_start_time_) >
            kRoundsBeforeReducedRttDependence * rtt_stats()->smoothed_rtt();
  }
  float congestion_avoidance_deflator;
  if (reduce_rtt_dependence_) {
    congestion_avoidance_deflator =
        static_cast<float>(rtt_stats()->smoothed_rtt().ToMicroseconds()) /
        static_cast<float>(rtt_virt_.ToMicroseconds());
    congestion_avoidance_deflator *= congestion_avoidance_deflator;
  } else {
    congestion_avoidance_deflator = 1.0f;
  }
  QuicByteCount original_cwnd = GetCongestionWindow();
  if (num_ce == 0 || !lost_packets.empty()) {
    // Fast path. No ECN specific logic except updating stats, adjusting for
    // previous CE responses, and reduced RTT dependence.
    TcpCubicSenderBytes::OnCongestionEvent(rtt_updated, prior_in_flight,
                                           event_time, acked_packets,
                                           lost_packets, num_ect, num_ce);
    if (lost_packets.empty() && reduce_rtt_dependence_ &&
        original_cwnd < GetCongestionWindow()) {
      QuicByteCount cwnd_increase = GetCongestionWindow() - original_cwnd;
      set_congestion_window(original_cwnd +
                            cwnd_increase * congestion_avoidance_deflator);
    }
    return;
  }
  // num_ce > 0 and lost_packets is empty.
  if (InSlowStart()) {
    ExitSlowstart();
  }
  // Estimate bytes that were CE marked
  QuicByteCount bytes_acked = 0;
  for (auto packet : acked_packets) {
    bytes_acked += packet.bytes_acked;
  }
  float ce_fraction =
      static_cast<float>(num_ce) / static_cast<float>(num_ect + num_ce);
  QuicByteCount bytes_ce = bytes_acked * ce_fraction;
  QuicPacketCount ce_packets_remaining = num_ce;
  bytes_acked -= bytes_ce;
  if (!last_congestion_response_time_.has_value() ||
      event_time - *last_congestion_response_time_ > rtt_virt_) {
    last_congestion_response_time_ = event_time;
    // Create a synthetic loss to trigger a loss response. The packet number
    // needs to be large enough to not be before the last loss response, which
    // should be easy since acked packet numbers should be higher than lost
    // packet numbers, due to the delay in detecting loss.
    while (ce_packets_remaining > 0) {
      OnPacketLost(acked_packets.back().packet_number, bytes_ce,
                   prior_in_flight);
      bytes_ce = 0;
      ce_packets_remaining--;
    }
    QuicByteCount cwnd_reduction = original_cwnd - GetCongestionWindow();
    last_congestion_response_size_ = cwnd_reduction * *prague_alpha_;
    set_congestion_window(original_cwnd - last_congestion_response_size_);
    set_slowstart_threshold(GetCongestionWindow());
    ExitRecovery();
  }
  if (num_ect == 0) {
    return;
  }
  for (const AckedPacket& acked : acked_packets) {
    // Timing matters so report all of the packets faithfully, but reduce the
    // size to reflect that some bytes were marked CE.
    OnPacketAcked(
        acked.packet_number,
        acked.bytes_acked * (1 - ce_fraction) * congestion_avoidance_deflator,
        prior_in_flight, event_time);
  }
}

CongestionControlType PragueSender::GetCongestionControlType() const {
  return kPragueCubic;
}

bool PragueSender::EnableECT1() {
  ect1_enabled_ = true;
  return true;
}

}  // namespace quic

"""

```