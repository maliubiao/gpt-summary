Response:
My thinking process to analyze the `bbr2_probe_bw.cc` file went something like this:

1. **Understand the Context:** The file path `net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_probe_bw.cc` immediately tells me this is part of the QUIC implementation within the Chromium network stack. Specifically, it's related to congestion control and the BBR2 algorithm. The "probe_bw" part suggests this file handles a phase of BBR2 where the algorithm actively probes for available bandwidth.

2. **Identify Key Classes and Methods:** I scanned the code for class names and their public methods. The main class is `Bbr2ProbeBwMode`. Key methods include:
    * `Enter()`: How the algorithm enters this state.
    * `OnCongestionEvent()`: The core logic responding to network events (acks, losses).
    * `GetCwndLimits()`: Determines congestion window limits.
    * `IsProbingForBandwidth()`: Indicates if the algorithm is actively probing.
    * `EnterProbeDown()`, `EnterProbeCruise()`, `EnterProbeRefill()`, `EnterProbeUp()`:  Methods for transitioning between sub-phases within `PROBE_BW`.
    * `UpdateProbeDown()`, `UpdateProbeCruise()`, `UpdateProbeRefill()`, `UpdateProbeUp()`:  Logic within each sub-phase.
    * Methods related to time and round tracking (`HasCycleLasted`, `HasPhaseLasted`).

3. **Deconstruct the Functionality:** I started breaking down the purpose of the `Bbr2ProbeBwMode` class and its methods:
    * **Overall Goal:**  To estimate the available bandwidth of the network path. This is done by strategically increasing and decreasing the sending rate and observing the network's response.
    * **Phases:** I recognized the distinct phases within `PROBE_BW`: `PROBE_UP`, `PROBE_DOWN`, `PROBE_CRUISE`, and `PROBE_REFILL`. Each phase has a specific goal:
        * `PROBE_UP`:  Aggressively increase the sending rate to see if more bandwidth is available.
        * `PROBE_DOWN`:  Reduce the sending rate after probing upwards, to avoid overwhelming the network and to measure the impact of the increased rate.
        * `PROBE_CRUISE`:  Maintain a sending rate based on the estimated bandwidth.
        * `PROBE_REFILL`: A brief phase before `PROBE_UP` to prepare for increasing the sending rate.
    * **Congestion Control Logic:**  The `OnCongestionEvent()` method is central. It updates the state based on received acknowledgments and lost packets. Key aspects include:
        * Round trip time (RTT) tracking.
        * Adjusting congestion window (cwnd) and pacing rate.
        * Determining when to transition between phases.
        * Handling potential congestion (indicated by losses or increased queuing).
    * **Upper Bound Adaptation (`MaybeAdaptUpperBounds`):** This function focuses on adjusting `inflight_hi` (a target for the number of bytes in flight) based on network conditions. It tries to avoid sending too much data and causing losses.
    * **Probing Logic (`IsTimeToProbeBandwidth`):**  This determines when to initiate a new probing cycle (going from `PROBE_DOWN` to `PROBE_REFILL`). It considers time elapsed and potentially Reno coexistence.

4. **Identify Relationships to Other Components:**  I noted the `#include` statements and mentions of other BBR2 components:
    * `Bbr2Sender`: The main BBR2 sender class, which this `Bbr2ProbeBwMode` interacts with.
    * `Bbr2CongestionEvent`: Data structure containing information about congestion events.
    * `Bbr2Params`:  Configuration parameters for BBR2.
    * `QuicTime`, `QuicBandwidth`, `QuicByteCount`, etc.:  Basic QUIC data types.

5. **Consider JavaScript Interactions (Hypothetical):** I thought about how this C++ code might relate to JavaScript in a browser context. Since this is low-level network stack code, the direct interaction is limited. However:
    * **Indirect Influence:**  The congestion control algorithm implemented here directly affects the performance of network requests made by JavaScript applications. Better congestion control means faster loading times and a more stable connection.
    * **Network APIs:**  JavaScript uses browser APIs like `fetch` or `XMLHttpRequest` which, under the hood, rely on the network stack where this BBR2 code resides. JavaScript doesn't directly manipulate BBR2, but its network traffic is subject to its control.

6. **Logical Reasoning and Examples:**  I tried to create simple scenarios to illustrate the logic:
    * **Entering `PROBE_BW`:**  The initial transition and subsequent returns from `PROBE_RTT`.
    * **`PROBE_UP` and Loss:**  What happens when the algorithm probes too aggressively and encounters packet loss.
    * **`PROBE_DOWN` and Draining:** How the algorithm reduces the sending rate and checks if it has reached a target level.

7. **User/Programming Errors:** I considered potential issues:
    * **Configuration Errors:** Incorrect BBR2 parameters could lead to suboptimal performance.
    * **Misunderstanding the Algorithm:** Developers might make assumptions about BBR2's behavior that are incorrect.

8. **Debugging Steps:** I outlined how a developer might end up inspecting this code during debugging:
    * Observing slow network performance.
    * Analyzing QUIC connection logs.
    * Stepping through the code with a debugger.

Essentially, I started with the high-level context, drilled down into the specific functionalities of the code, identified connections to other parts of the system (and potentially higher-level languages like JavaScript), and then tried to illustrate the logic and potential issues with concrete examples and debugging scenarios. The focus was on understanding *what* the code does, *why* it does it that way, and *how* it fits into the larger picture.
这个文件 `net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_probe_bw.cc` 是 Chromium 网络栈中 QUIC 协议的 BBR2 拥塞控制算法的一个组成部分，专门负责 **BBR2 算法的 Probe Bandwidth (PROBE_BW) 模式** 的实现。

**主要功能:**

该文件的核心功能是实现 BBR2 算法在探测可用带宽时的行为。当 BBR2 进入 `PROBE_BW` 模式时，它会周期性地执行探测循环，以寻找更高的带宽或确认当前的带宽估计。这个文件定义了 `Bbr2ProbeBwMode` 类，该类负责管理 `PROBE_BW` 模式下的各种状态和逻辑，包括：

1. **状态管理:**
   - 维护 `PROBE_BW` 模式下的内部状态，例如当前所处的探测阶段 (`CyclePhase`)，包括 `PROBE_UP` (向上探测), `PROBE_DOWN` (向下调整), `PROBE_CRUISE` (巡航), `PROBE_REFILL` (填充) 和 `PROBE_NOT_STARTED`。
   - 跟踪探测循环和阶段的开始时间、持续时间以及轮次计数。
   - 记录上一次探测循环是否探测过高或者停止了有风险的探测。

2. **进入和退出 `PROBE_BW` 模式:**
   - `Enter()` 方法：处理进入 `PROBE_BW` 模式的逻辑，根据之前的状态决定是开始新的探测循环还是恢复之前的阶段。
   - 从 `PROBE_BW` 切换到其他模式（例如 `PROBE_RTT`）。

3. **响应拥塞事件 (`OnCongestionEvent`):**
   - 这是核心方法，根据收到的 ACK 和丢失的包来更新状态并调整发送行为。
   - 在每个探测阶段执行特定的更新逻辑 (`UpdateProbeUp`, `UpdateProbeDown`, `UpdateProbeCruise`, `UpdateProbeRefill`)。
   - 设置合适的 pacing gain（用于控制发送速率）和拥塞窗口增益。
   - 决定是否需要切换到 `PROBE_RTT` 模式。

4. **管理拥塞窗口限制 (`GetCwndLimits`):**
   - 根据当前所处的探测阶段，返回合适的拥塞窗口上限。
   - 在 `PROBE_CRUISE` 阶段，限制拥塞窗口不超过估计的带宽时延积 (BDP)。
   - 在 `PROBE_UP` 阶段，可以选择忽略 `inflight_hi` 的限制，类似于启动阶段。

5. **判断是否正在探测带宽 (`IsProbingForBandwidth`):**
   - 返回当前是否处于积极探测带宽的阶段 (`PROBE_REFILL` 或 `PROBE_UP`)。

6. **处理退出静默期 (`OnExitQuiescence`):**
   - 在连接从静默期恢复后，调整最小 RTT 的时间戳。

7. **探测阶段的具体逻辑 (`UpdateProbeDown`, `UpdateProbeUp`, ...):**
   - **`UpdateProbeDown`:**  在探测下降阶段，可能会提前推进最大带宽滤波器，并决定何时退出该阶段，进入 `PROBE_CRUISE` 或 `PROBE_REFILL`。
   - **`UpdateProbeUp`:**  在探测上升阶段，会尝试增加 `inflight_hi` (估计的最大在途字节数)，但如果检测到拥塞或排队，可能会提前退出。
   - **`UpdateProbeCruise`:**  在巡航阶段，主要检查是否需要开始新的探测循环。
   - **`UpdateProbeRefill`:**  在填充阶段，为 `PROBE_UP` 阶段做准备。

8. **调整上限 (`MaybeAdaptUpperBounds`):**
   - 根据网络状况（例如是否发生丢包），动态调整 `inflight_hi` 的值。

9. **判断是否需要探测带宽 (`IsTimeToProbeBandwidth`):**
   - 根据时间间隔和 Reno 共存策略，决定是否应该开始新的探测循环。

10. **管理 `inflight_hi` 的增长 (`RaiseInflightHighSlope`, `ProbeInflightHighUpward`):**
    - 在 `PROBE_UP` 阶段，逐步增加 `inflight_hi` 的值，以探测更高的带宽。

11. **进入不同的探测阶段 (`EnterProbeDown`, `EnterProbeCruise`, ...):**
    - 负责状态的切换和相关变量的初始化。

**与 JavaScript 的关系:**

这个 C++ 文件是 Chromium 浏览器底层网络栈的一部分，直接与 JavaScript 没有代码层面的交互。但是，它的行为 **直接影响** 基于 JavaScript 的网络应用（如网页、Web 应用）的性能。

例如：

- 当用户在浏览器中加载网页或执行网络请求时，浏览器底层的 QUIC 协议实现（包括 BBR2 拥塞控制）会负责数据传输。
- `bbr2_probe_bw.cc` 中实现的探测带宽逻辑，会影响 QUIC 连接的发送速率，进而影响网页资源的加载速度和 Web 应用的响应速度。
- 如果 BBR2 算法能够有效地探测到可用的带宽，JavaScript 应用就能更快地获取数据，从而提升用户体验。

**举例说明:**

假设一个用户通过浏览器访问一个资源丰富的网站，网站使用了 HTTPS over QUIC。

1. **假设输入:**
   - BBR2 拥塞控制算法当前处于 `PROBE_BW` 模式。
   - 网络连接相对稳定，有一定的空闲带宽。
   - 收到来自服务器的 ACK 包。

2. **逻辑推理 (基于 `bbr2_probe_bw.cc` 的代码):**
   - 如果当前处于 `PROBE_UP` 阶段，`OnCongestionEvent` 方法会调用 `UpdateProbeUp`。
   - `UpdateProbeUp` 方法会检查是否满足条件来增加 `inflight_hi`。如果之前的发送没有因为达到 `inflight_hi` 而受限，并且当前网络状况良好（没有明显的丢包），则会尝试增加 `inflight_hi`，为后续发送更多数据做准备。
   - 如果当前处于 `PROBE_DOWN` 阶段，`UpdateProbeDown` 方法会检查是否已在该阶段停留足够的时间，或者是否已将在途数据量降至目标水平以下。如果满足条件，则可能会切换到 `PROBE_CRUISE` 或 `PROBE_REFILL` 阶段，准备开始新一轮的带宽探测。

3. **输出:**
   - 如果 `inflight_hi` 成功增加，BBR2 算法可能会在下一轮发送中发送更多的数据包，从而提高带宽利用率。
   - 如果切换到 `PROBE_CRUISE`，BBR2 算法可能会以更稳定的速率发送数据。
   - 如果切换到 `PROBE_REFILL`，则为下一轮 `PROBE_UP` 阶段做准备，可能会在不久的将来再次尝试增加发送速率。

**用户或编程常见的使用错误:**

虽然用户或前端开发者不会直接操作这个 C++ 文件，但对 BBR2 算法的 **错误理解** 或 **不当配置** 可能会导致问题：

- **错误理解 BBR2 的行为:**  开发者可能会错误地认为 BBR2 在所有情况下都会立即达到最大带宽，而忽略了其探测的过程。例如，在网络条件不佳时，BBR2 可能需要更长的时间来探测，或者可能无法达到很高的带宽。
- **不当的网络配置:**  网络管理员如果对中间设备的 QoS (Quality of Service) 或 bufferbloat 管理不当，可能会干扰 BBR2 的探测过程，导致其性能下降。例如，过大的缓冲区可能会掩盖真实的 RTT，导致 BBR2 的带宽估计不准确。
- **实验性标志的滥用:**  Chromium 提供了很多实验性标志来调整 BBR2 的行为。不了解这些标志的含义就随意修改，可能会导致连接不稳定或性能下降。

**用户操作是如何一步步的到达这里，作为调试线索:**

要调试与 `bbr2_probe_bw.cc` 相关的问题，通常需要具备一定的网络知识和 C++ 调试技能。以下是一个可能的调试路径：

1. **用户报告网络问题:** 用户可能会报告网页加载缓慢、视频卡顿等问题。

2. **初步排查:**  开发者或运维人员会进行初步的网络排查，例如检查网络连接是否正常，是否存在丢包等。

3. **QUIC 连接分析:** 如果确定使用了 QUIC 协议，则会开始分析 QUIC 连接的详细信息，例如连接状态、拥塞控制算法等。可以使用 Chrome 的内部工具 `chrome://webrtc-internals` 或 `chrome://net-internals/#quic` 来查看 QUIC 连接的统计信息。

4. **怀疑拥塞控制问题:**  如果发现拥塞控制算法的行为异常，例如发送速率波动很大，或者长时间处于低速状态，可能会怀疑是 BBR2 算法的问题。

5. **查看 QUIC 日志:**  可以通过设置 Chrome 的命令行参数来启用 QUIC 的详细日志，例如 `--log-net-log=/tmp/netlog.json --enable-logging=stderr --v=1`。这些日志会包含 BBR2 算法的状态变化和决策过程。

6. **源码分析和断点调试:**  如果日志信息不足以定位问题，开发者可能会需要查看 `bbr2_probe_bw.cc` 的源代码，理解其具体的实现逻辑。在 Chromium 的开发环境中，可以使用 gdb 或其他调试器，在 `bbr2_probe_bw.cc` 的关键方法上设置断点，例如 `OnCongestionEvent`、`EnterProbeUp`、`UpdateProbeDown` 等，来跟踪 BBR2 算法的执行流程和状态变化。

7. **分析 BBR2 的状态:**  通过断点调试，可以观察 `Bbr2ProbeBwMode` 对象的内部状态，例如当前的探测阶段 (`cycle_.phase`)、各种时间戳、轮次计数、以及 `inflight_hi` 等关键变量的值，从而判断 BBR2 的行为是否符合预期。

8. **结合网络抓包:**  结合 Wireshark 等网络抓包工具，可以分析实际的网络数据包，例如 TCP 或 UDP 包的序列号、ACK 号、时间戳等，来验证 BBR2 算法的决策是否与网络状况相符。例如，可以观察发送速率的变化是否与 BBR2 算法的 pacing gain 设置一致。

总而言之，`bbr2_probe_bw.cc` 是 BBR2 拥塞控制算法中至关重要的一个环节，它直接影响着 QUIC 连接的带宽利用率和传输性能。虽然前端开发者不会直接操作它，但理解其功能有助于理解底层网络行为，并在出现性能问题时提供调试思路。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_probe_bw.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/bbr2_probe_bw.h"

#include <algorithm>
#include <limits>
#include <ostream>

#include "quiche/quic/core/congestion_control/bbr2_misc.h"
#include "quiche/quic/core/congestion_control/bbr2_sender.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

void Bbr2ProbeBwMode::Enter(QuicTime now,
                            const Bbr2CongestionEvent* /*congestion_event*/) {
  if (cycle_.phase == CyclePhase::PROBE_NOT_STARTED) {
    // First time entering PROBE_BW. Start a new probing cycle.
    EnterProbeDown(/*probed_too_high=*/false, /*stopped_risky_probe=*/false,
                   now);
  } else {
    // Transitioning from PROBE_RTT to PROBE_BW. Re-enter the last phase before
    // PROBE_RTT.
    QUICHE_DCHECK(cycle_.phase == CyclePhase::PROBE_CRUISE ||
                  cycle_.phase == CyclePhase::PROBE_REFILL);
    cycle_.cycle_start_time = now;
    if (cycle_.phase == CyclePhase::PROBE_CRUISE) {
      EnterProbeCruise(now);
    } else if (cycle_.phase == CyclePhase::PROBE_REFILL) {
      EnterProbeRefill(cycle_.probe_up_rounds, now);
    }
  }
}

Bbr2Mode Bbr2ProbeBwMode::OnCongestionEvent(
    QuicByteCount prior_in_flight, QuicTime event_time,
    const AckedPacketVector& /*acked_packets*/,
    const LostPacketVector& /*lost_packets*/,
    const Bbr2CongestionEvent& congestion_event) {
  QUICHE_DCHECK_NE(cycle_.phase, CyclePhase::PROBE_NOT_STARTED);

  if (congestion_event.end_of_round_trip) {
    if (cycle_.cycle_start_time != event_time) {
      ++cycle_.rounds_since_probe;
    }
    if (cycle_.phase_start_time != event_time) {
      ++cycle_.rounds_in_phase;
    }
  }

  bool switch_to_probe_rtt = false;

  if (cycle_.phase == CyclePhase::PROBE_UP) {
    UpdateProbeUp(prior_in_flight, congestion_event);
  } else if (cycle_.phase == CyclePhase::PROBE_DOWN) {
    UpdateProbeDown(prior_in_flight, congestion_event);
    // Maybe transition to PROBE_RTT at the end of this cycle.
    if (cycle_.phase != CyclePhase::PROBE_DOWN &&
        model_->MaybeExpireMinRtt(congestion_event)) {
      switch_to_probe_rtt = true;
    }
  } else if (cycle_.phase == CyclePhase::PROBE_CRUISE) {
    UpdateProbeCruise(congestion_event);
  } else if (cycle_.phase == CyclePhase::PROBE_REFILL) {
    UpdateProbeRefill(congestion_event);
  }

  // Do not need to set the gains if switching to PROBE_RTT, they will be set
  // when Bbr2ProbeRttMode::Enter is called.
  if (!switch_to_probe_rtt) {
    model_->set_pacing_gain(PacingGainForPhase(cycle_.phase));
    model_->set_cwnd_gain(Params().probe_bw_cwnd_gain);
  }

  return switch_to_probe_rtt ? Bbr2Mode::PROBE_RTT : Bbr2Mode::PROBE_BW;
}

Limits<QuicByteCount> Bbr2ProbeBwMode::GetCwndLimits() const {
  if (cycle_.phase == CyclePhase::PROBE_CRUISE) {
    return NoGreaterThan(
        std::min(model_->inflight_lo(), model_->inflight_hi_with_headroom()));
  }
  if (Params().probe_up_ignore_inflight_hi &&
      cycle_.phase == CyclePhase::PROBE_UP) {
    // Similar to STARTUP.
    return NoGreaterThan(model_->inflight_lo());
  }

  return NoGreaterThan(std::min(model_->inflight_lo(), model_->inflight_hi()));
}

bool Bbr2ProbeBwMode::IsProbingForBandwidth() const {
  return cycle_.phase == CyclePhase::PROBE_REFILL ||
         cycle_.phase == CyclePhase::PROBE_UP;
}

Bbr2Mode Bbr2ProbeBwMode::OnExitQuiescence(QuicTime now,
                                           QuicTime quiescence_start_time) {
  QUIC_DVLOG(3) << sender_ << " Postponing min_rtt_timestamp("
                << model_->MinRttTimestamp() << ") by "
                << now - quiescence_start_time;
  model_->PostponeMinRttTimestamp(now - quiescence_start_time);
  return Bbr2Mode::PROBE_BW;
}

// TODO(ianswett): Remove prior_in_flight from UpdateProbeDown.
void Bbr2ProbeBwMode::UpdateProbeDown(
    QuicByteCount prior_in_flight,
    const Bbr2CongestionEvent& congestion_event) {
  QUICHE_DCHECK_EQ(cycle_.phase, CyclePhase::PROBE_DOWN);

  if (cycle_.rounds_in_phase == 1 && congestion_event.end_of_round_trip) {
    cycle_.is_sample_from_probing = false;

    if (!congestion_event.last_packet_send_state.is_app_limited) {
      QUIC_DVLOG(2)
          << sender_
          << " Advancing max bw filter after one round in PROBE_DOWN.";
      model_->AdvanceMaxBandwidthFilter();
      cycle_.has_advanced_max_bw = true;
    }

    if (last_cycle_stopped_risky_probe_ && !last_cycle_probed_too_high_) {
      EnterProbeRefill(/*probe_up_rounds=*/0, congestion_event.event_time);
      return;
    }
  }

  MaybeAdaptUpperBounds(congestion_event);

  if (IsTimeToProbeBandwidth(congestion_event)) {
    EnterProbeRefill(/*probe_up_rounds=*/0, congestion_event.event_time);
    return;
  }

  if (HasStayedLongEnoughInProbeDown(congestion_event)) {
    QUIC_DVLOG(3) << sender_ << " Proportional time based PROBE_DOWN exit";
    EnterProbeCruise(congestion_event.event_time);
    return;
  }

  const QuicByteCount inflight_with_headroom =
      model_->inflight_hi_with_headroom();
  QUIC_DVLOG(3)
      << sender_
      << " Checking if have enough inflight headroom. prior_in_flight:"
      << prior_in_flight << " congestion_event.bytes_in_flight:"
      << congestion_event.bytes_in_flight
      << ", inflight_with_headroom:" << inflight_with_headroom;
  QuicByteCount bytes_in_flight = congestion_event.bytes_in_flight;

  if (bytes_in_flight > inflight_with_headroom) {
    // Stay in PROBE_DOWN.
    return;
  }

  // Transition to PROBE_CRUISE iff we've drained to target.
  QuicByteCount bdp = model_->BDP();
  QUIC_DVLOG(3) << sender_ << " Checking if drained to target. bytes_in_flight:"
                << bytes_in_flight << ", bdp:" << bdp;
  if (bytes_in_flight < bdp) {
    EnterProbeCruise(congestion_event.event_time);
  }
}

Bbr2ProbeBwMode::AdaptUpperBoundsResult Bbr2ProbeBwMode::MaybeAdaptUpperBounds(
    const Bbr2CongestionEvent& congestion_event) {
  const SendTimeState& send_state = congestion_event.last_packet_send_state;
  if (!send_state.is_valid) {
    QUIC_DVLOG(3) << sender_ << " " << cycle_.phase
                  << ": NOT_ADAPTED_INVALID_SAMPLE";
    return NOT_ADAPTED_INVALID_SAMPLE;
  }

  // TODO(ianswett): Rename to bytes_delivered if
  // use_bytes_delivered_for_inflight_hi is default enabled.
  QuicByteCount inflight_at_send = BytesInFlight(send_state);
  if (Params().use_bytes_delivered_for_inflight_hi) {
    if (congestion_event.last_packet_send_state.total_bytes_acked <=
        model_->total_bytes_acked()) {
      inflight_at_send =
          model_->total_bytes_acked() -
          congestion_event.last_packet_send_state.total_bytes_acked;
    } else {
      QUIC_BUG(quic_bug_10436_1)
          << "Total_bytes_acked(" << model_->total_bytes_acked()
          << ") < send_state.total_bytes_acked("
          << congestion_event.last_packet_send_state.total_bytes_acked << ")";
    }
  }
  // TODO(ianswett): Inflight too high is really checking for loss, not
  // inflight.
  if (model_->IsInflightTooHigh(congestion_event,
                                Params().probe_bw_full_loss_count)) {
    if (cycle_.is_sample_from_probing) {
      cycle_.is_sample_from_probing = false;
      if (!send_state.is_app_limited ||
          Params().max_probe_up_queue_rounds > 0) {
        const QuicByteCount inflight_target =
            sender_->GetTargetBytesInflight() * (1.0 - Params().beta);
        if (inflight_at_send >= inflight_target) {
          // The new code does not change behavior.
          QUIC_CODE_COUNT(quic_bbr2_cut_inflight_hi_gradually_noop);
        } else {
          // The new code actually cuts inflight_hi slower than before.
          QUIC_CODE_COUNT(quic_bbr2_cut_inflight_hi_gradually_in_effect);
        }
        if (Params().limit_inflight_hi_by_max_delivered) {
          QuicByteCount new_inflight_hi =
              std::max(inflight_at_send, inflight_target);
          if (new_inflight_hi >= model_->max_bytes_delivered_in_round()) {
            QUIC_CODE_COUNT(quic_bbr2_cut_inflight_hi_max_delivered_noop);
          } else {
            QUIC_CODE_COUNT(quic_bbr2_cut_inflight_hi_max_delivered_in_effect);
            new_inflight_hi = model_->max_bytes_delivered_in_round();
          }
          QUIC_DVLOG(3) << sender_
                        << " Setting inflight_hi due to loss. new_inflight_hi:"
                        << new_inflight_hi
                        << ", inflight_at_send:" << inflight_at_send
                        << ", inflight_target:" << inflight_target
                        << ", max_bytes_delivered_in_round:"
                        << model_->max_bytes_delivered_in_round() << "  @ "
                        << congestion_event.event_time;
          model_->set_inflight_hi(new_inflight_hi);
        } else {
          model_->set_inflight_hi(std::max(inflight_at_send, inflight_target));
        }
      }

      QUIC_DVLOG(3) << sender_ << " " << cycle_.phase
                    << ": ADAPTED_PROBED_TOO_HIGH";
      return ADAPTED_PROBED_TOO_HIGH;
    }
    return ADAPTED_OK;
  }

  if (model_->inflight_hi() == model_->inflight_hi_default()) {
    QUIC_DVLOG(3) << sender_ << " " << cycle_.phase
                  << ": NOT_ADAPTED_INFLIGHT_HIGH_NOT_SET";
    return NOT_ADAPTED_INFLIGHT_HIGH_NOT_SET;
  }

  // Raise the upper bound for inflight.
  if (inflight_at_send > model_->inflight_hi()) {
    QUIC_DVLOG(3)
        << sender_ << " " << cycle_.phase
        << ": Adapting inflight_hi from inflight_at_send. inflight_at_send:"
        << inflight_at_send << ", old inflight_hi:" << model_->inflight_hi();
    model_->set_inflight_hi(inflight_at_send);
  }

  return ADAPTED_OK;
}

bool Bbr2ProbeBwMode::IsTimeToProbeBandwidth(
    const Bbr2CongestionEvent& congestion_event) const {
  if (HasCycleLasted(cycle_.probe_wait_time, congestion_event)) {
    return true;
  }

  if (IsTimeToProbeForRenoCoexistence(1.0, congestion_event)) {
    ++sender_->connection_stats_->bbr_num_short_cycles_for_reno_coexistence;
    return true;
  }
  return false;
}

// QUIC only. Used to prevent a Bbr2 flow from staying in PROBE_DOWN for too
// long, as seen in some multi-sender simulator tests.
bool Bbr2ProbeBwMode::HasStayedLongEnoughInProbeDown(
    const Bbr2CongestionEvent& congestion_event) const {
  // Stay in PROBE_DOWN for at most the time of a min rtt, as it is done in
  // BBRv1.
  // TODO(wub): Consider exit after a full round instead, which typically
  // indicates most(if not all) packets sent during PROBE_UP have been acked.
  return HasPhaseLasted(model_->MinRtt(), congestion_event);
}

bool Bbr2ProbeBwMode::HasCycleLasted(
    QuicTime::Delta duration,
    const Bbr2CongestionEvent& congestion_event) const {
  bool result =
      (congestion_event.event_time - cycle_.cycle_start_time) > duration;
  QUIC_DVLOG(3) << sender_ << " " << cycle_.phase
                << ": HasCycleLasted=" << result << ". elapsed:"
                << (congestion_event.event_time - cycle_.cycle_start_time)
                << ", duration:" << duration;
  return result;
}

bool Bbr2ProbeBwMode::HasPhaseLasted(
    QuicTime::Delta duration,
    const Bbr2CongestionEvent& congestion_event) const {
  bool result =
      (congestion_event.event_time - cycle_.phase_start_time) > duration;
  QUIC_DVLOG(3) << sender_ << " " << cycle_.phase
                << ": HasPhaseLasted=" << result << ". elapsed:"
                << (congestion_event.event_time - cycle_.phase_start_time)
                << ", duration:" << duration;
  return result;
}

bool Bbr2ProbeBwMode::IsTimeToProbeForRenoCoexistence(
    double probe_wait_fraction,
    const Bbr2CongestionEvent& /*congestion_event*/) const {
  if (!Params().enable_reno_coexistence) {
    return false;
  }

  uint64_t rounds = Params().probe_bw_probe_max_rounds;
  if (Params().probe_bw_probe_reno_gain > 0.0) {
    QuicByteCount target_bytes_inflight = sender_->GetTargetBytesInflight();
    uint64_t reno_rounds = Params().probe_bw_probe_reno_gain *
                           target_bytes_inflight / kDefaultTCPMSS;
    rounds = std::min(rounds, reno_rounds);
  }
  bool result = cycle_.rounds_since_probe >= (rounds * probe_wait_fraction);
  QUIC_DVLOG(3) << sender_ << " " << cycle_.phase
                << ": IsTimeToProbeForRenoCoexistence=" << result
                << ". rounds_since_probe:" << cycle_.rounds_since_probe
                << ", rounds:" << rounds
                << ", probe_wait_fraction:" << probe_wait_fraction;
  return result;
}

void Bbr2ProbeBwMode::RaiseInflightHighSlope() {
  QUICHE_DCHECK_EQ(cycle_.phase, CyclePhase::PROBE_UP);
  uint64_t growth_this_round = 1 << cycle_.probe_up_rounds;
  // The number 30 below means |growth_this_round| is capped at 1G and the lower
  // bound of |probe_up_bytes| is (practically) 1 mss, at this speed inflight_hi
  // grows by approximately 1 packet per packet acked.
  cycle_.probe_up_rounds = std::min<uint64_t>(cycle_.probe_up_rounds + 1, 30);
  uint64_t probe_up_bytes = sender_->GetCongestionWindow() / growth_this_round;
  cycle_.probe_up_bytes =
      std::max<QuicByteCount>(probe_up_bytes, kDefaultTCPMSS);
  QUIC_DVLOG(3) << sender_ << " Rasing inflight_hi slope. probe_up_rounds:"
                << cycle_.probe_up_rounds
                << ", probe_up_bytes:" << cycle_.probe_up_bytes;
}

void Bbr2ProbeBwMode::ProbeInflightHighUpward(
    const Bbr2CongestionEvent& congestion_event) {
  QUICHE_DCHECK_EQ(cycle_.phase, CyclePhase::PROBE_UP);
  if (Params().probe_up_ignore_inflight_hi) {
    // When inflight_hi is disabled in PROBE_UP, it increases when
    // the number of bytes delivered in a round is larger inflight_hi.
    return;
  }
  if (Params().probe_up_simplify_inflight_hi) {
    // Raise inflight_hi exponentially if it was utilized this round.
    cycle_.probe_up_acked += congestion_event.bytes_acked;
    if (!congestion_event.end_of_round_trip) {
      return;
    }
    if (!model_->inflight_hi_limited_in_round() ||
        model_->loss_events_in_round() > 0) {
      cycle_.probe_up_acked = 0;
      return;
    }
  } else {
    if (congestion_event.prior_bytes_in_flight < congestion_event.prior_cwnd) {
      QUIC_DVLOG(3) << sender_
                    << " Raising inflight_hi early return: Not cwnd limited.";
      // Not fully utilizing cwnd, so can't safely grow.
      return;
    }

    if (congestion_event.prior_cwnd < model_->inflight_hi()) {
      QUIC_DVLOG(3)
          << sender_
          << " Raising inflight_hi early return: inflight_hi not fully used.";
      // Not fully using inflight_hi, so don't grow it.
      return;
    }

    // Increase inflight_hi by the number of probe_up_bytes within
    // probe_up_acked.
    cycle_.probe_up_acked += congestion_event.bytes_acked;
  }

  if (cycle_.probe_up_acked >= cycle_.probe_up_bytes) {
    uint64_t delta = cycle_.probe_up_acked / cycle_.probe_up_bytes;
    cycle_.probe_up_acked -= delta * cycle_.probe_up_bytes;
    QuicByteCount new_inflight_hi =
        model_->inflight_hi() + delta * kDefaultTCPMSS;
    if (new_inflight_hi > model_->inflight_hi()) {
      QUIC_DVLOG(3) << sender_ << " Raising inflight_hi from "
                    << model_->inflight_hi() << " to " << new_inflight_hi
                    << ". probe_up_bytes:" << cycle_.probe_up_bytes
                    << ", delta:" << delta
                    << ", (new)probe_up_acked:" << cycle_.probe_up_acked;

      model_->set_inflight_hi(new_inflight_hi);
    } else {
      QUIC_BUG(quic_bug_10436_2)
          << "Not growing inflight_hi due to wrap around. Old value:"
          << model_->inflight_hi() << ", new value:" << new_inflight_hi;
    }
  }

  if (congestion_event.end_of_round_trip) {
    RaiseInflightHighSlope();
  }
}

void Bbr2ProbeBwMode::UpdateProbeCruise(
    const Bbr2CongestionEvent& congestion_event) {
  QUICHE_DCHECK_EQ(cycle_.phase, CyclePhase::PROBE_CRUISE);
  MaybeAdaptUpperBounds(congestion_event);
  QUICHE_DCHECK(!cycle_.is_sample_from_probing);

  if (IsTimeToProbeBandwidth(congestion_event)) {
    EnterProbeRefill(/*probe_up_rounds=*/0, congestion_event.event_time);
    return;
  }
}

void Bbr2ProbeBwMode::UpdateProbeRefill(
    const Bbr2CongestionEvent& congestion_event) {
  QUICHE_DCHECK_EQ(cycle_.phase, CyclePhase::PROBE_REFILL);
  MaybeAdaptUpperBounds(congestion_event);
  QUICHE_DCHECK(!cycle_.is_sample_from_probing);

  if (cycle_.rounds_in_phase > 0 && congestion_event.end_of_round_trip) {
    EnterProbeUp(congestion_event.event_time);
    return;
  }
}

void Bbr2ProbeBwMode::UpdateProbeUp(
    QuicByteCount prior_in_flight,
    const Bbr2CongestionEvent& congestion_event) {
  QUICHE_DCHECK_EQ(cycle_.phase, CyclePhase::PROBE_UP);
  if (MaybeAdaptUpperBounds(congestion_event) == ADAPTED_PROBED_TOO_HIGH) {
    EnterProbeDown(/*probed_too_high=*/true, /*stopped_risky_probe=*/false,
                   congestion_event.event_time);
    return;
  }

  // TODO(wub): Consider exit PROBE_UP after a certain number(e.g. 64) of RTTs.

  ProbeInflightHighUpward(congestion_event);

  bool is_risky = false;
  bool is_queuing = false;
  if (last_cycle_probed_too_high_ && prior_in_flight >= model_->inflight_hi()) {
    is_risky = true;
    QUIC_DVLOG(3) << sender_
                  << " Probe is too risky. last_cycle_probed_too_high_:"
                  << last_cycle_probed_too_high_
                  << ", prior_in_flight:" << prior_in_flight
                  << ", inflight_hi:" << model_->inflight_hi();
    // TCP uses min_rtt instead of a full round:
    //   HasPhaseLasted(model_->MinRtt(), congestion_event)
  } else if (cycle_.rounds_in_phase > 0) {
    if (Params().max_probe_up_queue_rounds > 0) {
      if (congestion_event.end_of_round_trip) {
        model_->CheckPersistentQueue(congestion_event,
                                     Params().full_bw_threshold);
        if (model_->rounds_with_queueing() >=
            Params().max_probe_up_queue_rounds) {
          QUIC_RELOADABLE_FLAG_COUNT_N(quic_bbr2_probe_two_rounds, 3, 3);
          is_queuing = true;
        }
      }
    } else {
      QuicByteCount queuing_threshold_extra_bytes =
          model_->QueueingThresholdExtraBytes();
      if (Params().add_ack_height_to_queueing_threshold) {
        queuing_threshold_extra_bytes += model_->MaxAckHeight();
      }
      QuicByteCount queuing_threshold =
          (Params().full_bw_threshold * model_->BDP()) +
          queuing_threshold_extra_bytes;

      is_queuing = congestion_event.bytes_in_flight >= queuing_threshold;

      QUIC_DVLOG(3) << sender_
                    << " Checking if building up a queue. prior_in_flight:"
                    << prior_in_flight
                    << ", post_in_flight:" << congestion_event.bytes_in_flight
                    << ", threshold:" << queuing_threshold
                    << ", is_queuing:" << is_queuing
                    << ", max_bw:" << model_->MaxBandwidth()
                    << ", min_rtt:" << model_->MinRtt();
    }
  }

  if (is_risky || is_queuing) {
    EnterProbeDown(/*probed_too_high=*/false, /*stopped_risky_probe=*/is_risky,
                   congestion_event.event_time);
  }
}

void Bbr2ProbeBwMode::EnterProbeDown(bool probed_too_high,
                                     bool stopped_risky_probe, QuicTime now) {
  QUIC_DVLOG(2) << sender_ << " Phase change: " << cycle_.phase << " ==> "
                << CyclePhase::PROBE_DOWN << " after "
                << now - cycle_.phase_start_time << ", or "
                << cycle_.rounds_in_phase
                << " rounds. probed_too_high:" << probed_too_high
                << ", stopped_risky_probe:" << stopped_risky_probe << "  @ "
                << now;
  last_cycle_probed_too_high_ = probed_too_high;
  last_cycle_stopped_risky_probe_ = stopped_risky_probe;

  cycle_.cycle_start_time = now;
  cycle_.phase = CyclePhase::PROBE_DOWN;
  cycle_.rounds_in_phase = 0;
  cycle_.phase_start_time = now;
  ++sender_->connection_stats_->bbr_num_cycles;
  if (Params().bw_lo_mode_ != Bbr2Params::QuicBandwidthLoMode::DEFAULT) {
    // Clear bandwidth lo if it was set in PROBE_UP, because losses in PROBE_UP
    // should not permanently change bandwidth_lo.
    // It's possible for bandwidth_lo to be set during REFILL, but if that was
    // a valid value, it'll quickly be rediscovered.
    model_->clear_bandwidth_lo();
  }

  // Pick probe wait time.
  cycle_.rounds_since_probe =
      sender_->RandomUint64(Params().probe_bw_max_probe_rand_rounds);
  cycle_.probe_wait_time =
      Params().probe_bw_probe_base_duration +
      QuicTime::Delta::FromMicroseconds(sender_->RandomUint64(
          Params().probe_bw_probe_max_rand_duration.ToMicroseconds()));

  cycle_.probe_up_bytes = std::numeric_limits<QuicByteCount>::max();
  cycle_.probe_up_app_limited_since_inflight_hi_limited_ = false;
  cycle_.has_advanced_max_bw = false;
  model_->RestartRoundEarly();
}

void Bbr2ProbeBwMode::EnterProbeCruise(QuicTime now) {
  if (cycle_.phase == CyclePhase::PROBE_DOWN) {
    ExitProbeDown();
  }
  QUIC_DVLOG(2) << sender_ << " Phase change: " << cycle_.phase << " ==> "
                << CyclePhase::PROBE_CRUISE << " after "
                << now - cycle_.phase_start_time << ", or "
                << cycle_.rounds_in_phase << " rounds.  @ " << now;

  model_->cap_inflight_lo(model_->inflight_hi());
  cycle_.phase = CyclePhase::PROBE_CRUISE;
  cycle_.rounds_in_phase = 0;
  cycle_.phase_start_time = now;
  cycle_.is_sample_from_probing = false;
}

void Bbr2ProbeBwMode::EnterProbeRefill(uint64_t probe_up_rounds, QuicTime now) {
  if (cycle_.phase == CyclePhase::PROBE_DOWN) {
    ExitProbeDown();
  }
  QUIC_DVLOG(2) << sender_ << " Phase change: " << cycle_.phase << " ==> "
                << CyclePhase::PROBE_REFILL << " after "
                << now - cycle_.phase_start_time << ", or "
                << cycle_.rounds_in_phase
                << " rounds. probe_up_rounds:" << probe_up_rounds << "  @ "
                << now;
  cycle_.phase = CyclePhase::PROBE_REFILL;
  cycle_.rounds_in_phase = 0;
  cycle_.phase_start_time = now;
  cycle_.is_sample_from_probing = false;
  last_cycle_stopped_risky_probe_ = false;

  model_->clear_bandwidth_lo();
  model_->clear_inflight_lo();
  cycle_.probe_up_rounds = probe_up_rounds;
  cycle_.probe_up_acked = 0;
  model_->RestartRoundEarly();
}

void Bbr2ProbeBwMode::EnterProbeUp(QuicTime now) {
  QUICHE_DCHECK_EQ(cycle_.phase, CyclePhase::PROBE_REFILL);
  QUIC_DVLOG(2) << sender_ << " Phase change: " << cycle_.phase << " ==> "
                << CyclePhase::PROBE_UP << " after "
                << now - cycle_.phase_start_time << ", or "
                << cycle_.rounds_in_phase << " rounds.  @ " << now;
  cycle_.phase = CyclePhase::PROBE_UP;
  cycle_.rounds_in_phase = 0;
  cycle_.phase_start_time = now;
  cycle_.is_sample_from_probing = true;
  RaiseInflightHighSlope();

  model_->RestartRoundEarly();
}

void Bbr2ProbeBwMode::ExitProbeDown() {
  QUICHE_DCHECK_EQ(cycle_.phase, CyclePhase::PROBE_DOWN);
  if (!cycle_.has_advanced_max_bw) {
    QUIC_DVLOG(2) << sender_ << " Advancing max bw filter at end of cycle.";
    model_->AdvanceMaxBandwidthFilter();
    cycle_.has_advanced_max_bw = true;
  }
}

// static
const char* Bbr2ProbeBwMode::CyclePhaseToString(CyclePhase phase) {
  switch (phase) {
    case CyclePhase::PROBE_NOT_STARTED:
      return "PROBE_NOT_STARTED";
    case CyclePhase::PROBE_UP:
      return "PROBE_UP";
    case CyclePhase::PROBE_DOWN:
      return "PROBE_DOWN";
    case CyclePhase::PROBE_CRUISE:
      return "PROBE_CRUISE";
    case CyclePhase::PROBE_REFILL:
      return "PROBE_REFILL";
    default:
      break;
  }
  return "<Invalid CyclePhase>";
}

std::ostream& operator<<(std::ostream& os,
                         const Bbr2ProbeBwMode::CyclePhase phase) {
  return os << Bbr2ProbeBwMode::CyclePhaseToString(phase);
}

Bbr2ProbeBwMode::DebugState Bbr2ProbeBwMode::ExportDebugState() const {
  DebugState s;
  s.phase = cycle_.phase;
  s.cycle_start_time = cycle_.cycle_start_time;
  s.phase_start_time = cycle_.phase_start_time;
  return s;
}

std::ostream& operator<<(std::ostream& os,
                         const Bbr2ProbeBwMode::DebugState& state) {
  os << "[PROBE_BW] phase: " << state.phase << "\n";
  os << "[PROBE_BW] cycle_start_time: " << state.cycle_start_time << "\n";
  os << "[PROBE_BW] phase_start_time: " << state.phase_start_time << "\n";
  return os;
}

const Bbr2Params& Bbr2ProbeBwMode::Params() const { return sender_->Params(); }

float Bbr2ProbeBwMode::PacingGainForPhase(
    Bbr2ProbeBwMode::CyclePhase phase) const {
  if (phase == Bbr2ProbeBwMode::CyclePhase::PROBE_UP) {
    return Params().probe_bw_probe_up_pacing_gain;
  }
  if (phase == Bbr2ProbeBwMode::CyclePhase::PROBE_DOWN) {
    return Params().probe_bw_probe_down_pacing_gain;
  }
  return Params().probe_bw_default_pacing_gain;
}

}  // namespace quic

"""

```