Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `rtt_stats_test.cc` and the inclusion of `rtt_stats.h` strongly suggest this file is testing the `RttStats` class. The `_test.cc` suffix is a common convention for unit tests in C++ projects.

2. **Understand the Test Framework:** The presence of `#include "quiche/quic/platform/api/quic_test.h"` and the use of `TEST_F` macros indicate the use of a testing framework (likely Google Test, as used in Chromium). `QuicTest` likely provides some test setup/teardown functionalities.

3. **Analyze the Test Structure:**  The file defines a test fixture `RttStatsTest` inheriting from `QuicTest`. This means each `TEST_F` within this fixture will have a fresh `RttStats` object (`rtt_stats_`). This is important for isolating test cases.

4. **Examine Individual Test Cases (`TEST_F` blocks):** Go through each test case and try to understand its intent:
    * `DefaultsBeforeUpdate`: Checks initial values of `RttStats` before any updates.
    * `SmoothedRtt`: Focuses on how the smoothed RTT is calculated and how `ack_delay` affects it. It includes edge cases like large erroneous `ack_delay`.
    * `SmoothedRttStability`:  Checks the stability of the EWMA calculation for smoothed RTT over many iterations.
    * `PreviousSmoothedRtt`: Verifies that the `previous_srtt()` method returns the correct value.
    * `MinRtt`: Tests how the minimum RTT is tracked and updated, specifically noting that `ack_delay` is excluded.
    * `ExpireSmoothedMetrics`: Examines the behavior of the `ExpireSmoothedMetrics()` function and its effect on smoothed RTT and mean deviation.
    * `UpdateRttWithBadSendDeltas`: Tests how the class handles invalid `send_delta` values.
    * `ResetAfterConnectionMigrations`: Checks if `OnConnectionMigration()` resets the RTT statistics.
    * `StandardDeviationCalculatorTest1`, `StandardDeviationCalculatorTest2`, `StandardDeviationCalculatorTest3`:  Focus on testing the calculation of standard deviation (or mean deviation when standard deviation is not enabled).

5. **Infer Functionality of `RttStats`:** Based on the tests, deduce the key responsibilities of the `RttStats` class:
    * Track Round Trip Time (RTT).
    * Calculate and update smoothed RTT (using EWMA).
    * Track minimum RTT.
    * Potentially track previous smoothed RTT.
    * Calculate mean deviation.
    * Optionally calculate standard deviation.
    * Handle acknowledgement delay.
    * Reset statistics upon connection migration.

6. **Consider Relevance to JavaScript:** Since the code is C++, there's no direct execution in a JavaScript environment. However, the *concepts* are highly relevant:
    * **Network Performance Measurement:**  JavaScript applications dealing with network communication (e.g., using `fetch`, WebSockets) might need to estimate network latency. The *algorithms* used in `RttStats` (EWMA for smoothing) could be adapted or understood in the context of JavaScript network monitoring.
    * **Congestion Control:**  While JavaScript itself doesn't implement low-level congestion control, understanding these mechanisms is crucial for designing performant web applications. Knowing how RTT is estimated is a fundamental part of that understanding.

7. **Develop Example Scenarios:** Create hypothetical inputs and outputs for some test cases to illustrate the logic. Focus on the key calculations being tested (e.g., smoothed RTT update).

8. **Identify Potential User Errors:** Think about how a developer *using* the `RttStats` class might make mistakes. Common errors include:
    * Providing incorrect timestamps.
    * Misunderstanding the impact of `ack_delay`.
    * Not resetting statistics after connection migration (if needed).

9. **Construct a Debugging Scenario:** Imagine a situation where a user observes unexpected behavior related to RTT. Trace back the user's actions that could lead to this part of the code being relevant for debugging.

10. **Structure the Answer:** Organize the findings into logical sections as requested in the prompt (functionality, JavaScript relevance, logical reasoning, user errors, debugging). Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the `ack_delay` is always included in smoothed RTT.
* **Correction:** The tests show it's considered, but not directly added. It influences the calculation by affecting the effective RTT.
* **Initial thought:**  JavaScript directly uses this C++ code.
* **Correction:**  The concepts are transferable, but the C++ code itself doesn't run in a browser. Focus on the algorithmic ideas.
* **Initial thought:**  Just describe what each test does.
* **Refinement:** Explain the *purpose* of each test and what aspect of `RttStats` it's validating. This provides deeper insight.

By following these steps, we can systematically analyze the C++ test file and provide a comprehensive answer that addresses all parts of the prompt.
这个文件 `rtt_stats_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的组成部分，专门用于测试 `RttStats` 类。`RttStats` 类负责跟踪和计算网络连接的往返时间（Round Trip Time，RTT）相关的统计信息，这对于拥塞控制和网络性能优化至关重要。

**以下是 `rtt_stats_test.cc` 的功能列表：**

1. **验证 RttStats 类的默认行为：** 测试在没有进行任何 RTT 更新之前，`RttStats` 对象的初始状态，例如初始 RTT、最小 RTT 和平滑 RTT 是否为预期值。

2. **测试平滑 RTT (Smoothed RTT) 的计算：**
   - 验证平滑 RTT 的计算逻辑是否正确，包括如何使用指数加权移动平均 (EWMA) 来平滑 RTT 样本。
   - 测试确认延迟 (ack_delay) 对平滑 RTT 的影响，以及如何处理不合理的 ack_delay 值。
   - 验证 EWMA 计算的稳定性，确保在大量相同 RTT 样本下，平滑 RTT 不会偏离真实值太远。

3. **测试上一次平滑 RTT (Previous Smoothed RTT) 的记录：** 验证 `previous_srtt()` 方法是否正确记录了上一次的平滑 RTT 值。

4. **测试最小 RTT (Min RTT) 的跟踪：** 验证 `RttStats` 是否能正确记录和更新观察到的最小 RTT 值，并确认 ack_delay 不会影响最小 RTT 的记录。

5. **测试平滑指标的过期机制 (Expire Smoothed Metrics)：** 验证当网络状况变化较大时，`ExpireSmoothedMetrics()` 方法是否能有效地增加平滑 RTT 和平均偏差，以更快地适应新的网络状况。

6. **测试 `UpdateRtt` 方法对无效发送延迟的处理：** 验证当传入 `UpdateRtt` 方法的发送延迟为零、无穷大或负数时，是否能正确地拒绝更新，并保持原有的 RTT 统计信息不变。

7. **测试连接迁移后的重置行为 (Reset After Connection Migrations)：** 验证当发生连接迁移时，`OnConnectionMigration()` 方法是否能正确地重置 RTT 相关的统计信息。

8. **测试标准差的计算 (Standard Deviation Calculation)：**  虽然默认使用平均偏差，但 `RttStats` 允许启用标准差计算。测试用例验证了在启用标准差计算后，对于不同方差的 RTT 样本，标准差的计算是否正确。

**与 JavaScript 功能的关系：**

`rtt_stats_test.cc` 本身是 C++ 代码，运行在 Chromium 的网络进程中，与 JavaScript 没有直接的执行关系。但是，其测试的 **网络性能监控和拥塞控制** 的概念在 JavaScript 应用中非常重要。

例如，在基于 Web 的实时应用 (如视频会议、在线游戏) 中，JavaScript 需要感知网络延迟，以便做出相应的调整，例如降低视频质量或调整发送速率。虽然 JavaScript 本身不太可能直接实现像 `RttStats` 这样的底层 RTT 统计功能，但可以使用浏览器提供的 API (如 Performance API 中的 `navigationTiming`, `resourceTiming`) 来获取一些网络性能指标，并基于这些指标在 JavaScript 中实现一些简单的 RTT 估计或监控逻辑。

**举例说明 (JavaScript 概念相关)：**

假设一个 JavaScript 应用需要简单地估计当前的 RTT：

```javascript
// 这只是一个非常简化的概念示例，实际应用中可能更复杂
let previousAckTime = 0;
let smoothedRttJs = 0;
const alpha = 0.125; // 平滑因子

function onAcknowledgementReceived() {
  const currentTime = performance.now();
  if (previousAckTime !== 0) {
    const latestRttMs = currentTime - previousAckTime;
    if (smoothedRttJs === 0) {
      smoothedRttJs = latestRttMs;
    } else {
      smoothedRttJs = (1 - alpha) * smoothedRttJs + alpha * latestRttMs;
    }
    console.log("Estimated Smoothed RTT (JS):", smoothedRttJs, "ms");
  }
  previousAckTime = currentTime;
}

// 假设在接收到网络包的确认时调用 onAcknowledgementReceived
// ...
```

这个 JavaScript 示例演示了使用类似 EWMA 的方法来平滑 RTT 估计。虽然实现细节不同，但核心思想与 `RttStats` 类中平滑 RTT 的计算是相似的。

**逻辑推理的假设输入与输出：**

**测试用例：`SmoothedRtt`**

**假设输入：**

1. 第一次更新：RTT = 300ms, ack_delay = 100ms, current_time = 0
2. 第二次更新：RTT = 400ms, ack_delay = 100ms, current_time = 0
3. 第三次更新：RTT = 350ms, ack_delay = 50ms, current_time = 0
4. 第四次更新：RTT = 200ms, ack_delay = 300ms, current_time = 0

**逻辑推理与预期输出：**

*   **第一次更新：**
    *   由于是第一次测量，ack_delay 被忽略。
    *   latest_rtt = 300ms
    *   smoothed_rtt = 300ms
*   **第二次更新：**
    *   latest_rtt = 400ms - 100ms = 300ms  (减去 ack_delay)
    *   smoothed_rtt 使用 EWMA 计算，但由于是第二次，受第一次影响，计算结果仍为 300ms (具体计算公式在 `RttStats` 内部，这里是直观理解)
*   **第三次更新：**
    *   latest_rtt = 350ms - 50ms = 300ms
    *   smoothed_rtt 会根据 EWMA 公式更新，新的样本是 300ms，之前的 smoothed_rtt 是 300ms，所以结果仍然是 300ms。
*   **第四次更新：**
    *   latest_rtt = 200ms - min(300ms, latest_max_ack_delay)  (假设 latest_max_ack_delay 在之前的更新中已更新)
    *   smoothed_rtt 使用 EWMA 计算，新的样本是 200ms，之前的 smoothed_rtt 是 300ms，结果会介于两者之间，具体数值取决于 EWMA 的参数 (alpha)。测试代码中期望的结果是 287.5ms。

**涉及用户或编程常见的使用错误：**

1. **提供不准确的时间戳：** 如果在调用 `UpdateRtt` 时提供的发送时间和接收时间戳不准确，会导致计算出的 RTT 值错误，从而影响拥塞控制的决策。
    *   **例子：**  发送时使用本地系统时间，但由于时钟同步问题，与接收端的时间存在偏差。
2. **错误理解 `ack_delay` 的作用：**  开发者可能错误地认为 `ack_delay` 应该直接加到 RTT 上，而实际上 `RttStats` 会将其从 RTT 中减去，以更准确地估计网络延迟。
    *   **例子：** 在某些场景下，错误地将延迟归咎于网络，而实际上是接收端处理延迟。
3. **在连接迁移后未重置 RTT 统计信息：** 如果连接迁移后没有调用 `OnConnectionMigration()` 重置 `RttStats`，旧连接的 RTT 统计信息可能会影响新连接的拥塞控制，导致性能下降。
    *   **例子：**  用户从 Wi-Fi 切换到蜂窝网络，但旧的 Wi-Fi 网络的低延迟统计信息仍然被使用。
4. **不合理地配置或使用标准差计算：**  如果启用了标准差计算，但对标准差的阈值或使用方式理解不当，可能会导致不必要的拥塞窗口调整。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户报告了 QUIC 连接的吞吐量异常低的问题。以下是可能的调试步骤，最终可能会涉及到 `rtt_stats_test.cc`：

1. **用户发起网络请求：** 用户在浏览器中访问一个使用 QUIC 协议的网站或应用。
2. **QUIC 连接建立：**  Chromium 的网络栈开始建立与服务器的 QUIC 连接。
3. **数据传输与确认：**  数据包在客户端和服务器之间传输，接收方会发送确认 (ACK) 包。
4. **RTT 测量与更新：**  客户端接收到 ACK 包后，会计算 RTT 并调用 `RttStats::UpdateRtt` 更新 RTT 统计信息。
5. **拥塞控制决策：** QUIC 的拥塞控制算法 (例如 Cubic, BBR) 会使用 `RttStats` 提供的 RTT 信息来调整发送窗口大小。
6. **吞吐量下降：** 如果 RTT 估计过高，拥塞控制算法可能会过于保守，减小发送窗口，导致吞吐量下降。

**调试线索：**

*   **抓包分析：**  通过抓包工具 (如 Wireshark) 可以查看网络包的往返时间，与 `RttStats` 计算的值进行对比，看是否存在偏差。
*   **QUIC 内部日志：** Chromium 提供了 QUIC 内部的日志，可以查看 `RttStats` 的更新过程和相关参数，例如 `smoothed_rtt`, `min_rtt` 等。
*   **性能监控工具：**  开发者可以使用 Chromium 的 `net-internals` 工具 (在地址栏输入 `chrome://net-internals/#quic`) 来查看 QUIC 连接的详细信息，包括 RTT 统计。
*   **断点调试：**  开发者可以在 Chromium 源码中，例如 `quiche/quic/core/congestion_control/rtt_stats.cc` 中的 `UpdateRtt` 方法设置断点，跟踪 RTT 的计算过程。

如果怀疑 `RttStats` 的计算逻辑有问题，或者想验证某些边界情况，那么 `rtt_stats_test.cc` 中的测试用例就可以作为参考，或者可以编写新的测试用例来覆盖特定的场景。例如，如果发现平滑 RTT 的计算似乎不符合预期，可以查看 `SmoothedRtt` 相关的测试用例，或者编写新的测试用例来复现和验证问题。

总之，`rtt_stats_test.cc` 是确保 `RttStats` 类正确运行的关键，它通过各种测试用例覆盖了 RTT 统计的各个方面，为 QUIC 协议的稳定性和性能提供了保障。当出现与 RTT 相关的网络问题时，理解这个测试文件的功能和覆盖范围，能够帮助开发者更好地定位和解决问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/rtt_stats_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/rtt_stats.h"

#include <cmath>
#include <vector>

#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

using testing::Message;

namespace quic {
namespace test {

class RttStatsTest : public QuicTest {
 protected:
  RttStats rtt_stats_;
};

TEST_F(RttStatsTest, DefaultsBeforeUpdate) {
  EXPECT_LT(QuicTime::Delta::Zero(), rtt_stats_.initial_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.smoothed_rtt());
}

TEST_F(RttStatsTest, SmoothedRtt) {
  // Verify that ack_delay is ignored in the first measurement.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(300),
                       QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300), rtt_stats_.smoothed_rtt());
  // Verify that a plausible ack delay increases the max ack delay.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(400),
                       QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300), rtt_stats_.smoothed_rtt());
  // Verify that Smoothed RTT includes max ack delay if it's reasonable.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(350),
                       QuicTime::Delta::FromMilliseconds(50), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300), rtt_stats_.smoothed_rtt());
  // Verify that large erroneous ack_delay does not change Smoothed RTT.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(200),
                       QuicTime::Delta::FromMilliseconds(300),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMicroseconds(287500),
            rtt_stats_.smoothed_rtt());
}

// Ensure that the potential rounding artifacts in EWMA calculation do not cause
// the SRTT to drift too far from the exact value.
TEST_F(RttStatsTest, SmoothedRttStability) {
  for (size_t time = 3; time < 20000; time++) {
    RttStats stats;
    for (size_t i = 0; i < 100; i++) {
      stats.UpdateRtt(QuicTime::Delta::FromMicroseconds(time),
                      QuicTime::Delta::FromMilliseconds(0), QuicTime::Zero());
      int64_t time_delta_us = stats.smoothed_rtt().ToMicroseconds() - time;
      ASSERT_LE(std::abs(time_delta_us), 1);
    }
  }
}

TEST_F(RttStatsTest, PreviousSmoothedRtt) {
  // Verify that ack_delay is corrected for in Smoothed RTT.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(200),
                       QuicTime::Delta::FromMilliseconds(0), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.smoothed_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.previous_srtt());
  // Ensure the previous SRTT is 200ms after a 100ms sample.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(100), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMicroseconds(187500).ToMicroseconds(),
            rtt_stats_.smoothed_rtt().ToMicroseconds());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.previous_srtt());
}

TEST_F(RttStatsTest, MinRtt) {
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(200),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.min_rtt());
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(10), QuicTime::Delta::Zero(),
      QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(10));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(50), QuicTime::Delta::Zero(),
      QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(20));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(50), QuicTime::Delta::Zero(),
      QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(30));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(50), QuicTime::Delta::Zero(),
      QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(40));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  // Verify that ack_delay does not go into recording of min_rtt_.
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(7),
      QuicTime::Delta::FromMilliseconds(2),
      QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(50));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(7), rtt_stats_.min_rtt());
}

TEST_F(RttStatsTest, ExpireSmoothedMetrics) {
  QuicTime::Delta initial_rtt = QuicTime::Delta::FromMilliseconds(10);
  rtt_stats_.UpdateRtt(initial_rtt, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(initial_rtt, rtt_stats_.min_rtt());
  EXPECT_EQ(initial_rtt, rtt_stats_.smoothed_rtt());

  EXPECT_EQ(0.5 * initial_rtt, rtt_stats_.mean_deviation());

  // Update once with a 20ms RTT.
  QuicTime::Delta doubled_rtt = 2 * initial_rtt;
  rtt_stats_.UpdateRtt(doubled_rtt, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(1.125 * initial_rtt, rtt_stats_.smoothed_rtt());

  // Expire the smoothed metrics, increasing smoothed rtt and mean deviation.
  rtt_stats_.ExpireSmoothedMetrics();
  EXPECT_EQ(doubled_rtt, rtt_stats_.smoothed_rtt());
  EXPECT_EQ(0.875 * initial_rtt, rtt_stats_.mean_deviation());

  // Now go back down to 5ms and expire the smoothed metrics, and ensure the
  // mean deviation increases to 15ms.
  QuicTime::Delta half_rtt = 0.5 * initial_rtt;
  rtt_stats_.UpdateRtt(half_rtt, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_GT(doubled_rtt, rtt_stats_.smoothed_rtt());
  EXPECT_LT(initial_rtt, rtt_stats_.mean_deviation());
}

TEST_F(RttStatsTest, UpdateRttWithBadSendDeltas) {
  QuicTime::Delta initial_rtt = QuicTime::Delta::FromMilliseconds(10);
  rtt_stats_.UpdateRtt(initial_rtt, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(initial_rtt, rtt_stats_.min_rtt());
  EXPECT_EQ(initial_rtt, rtt_stats_.smoothed_rtt());

  std::vector<QuicTime::Delta> bad_send_deltas;
  bad_send_deltas.push_back(QuicTime::Delta::Zero());
  bad_send_deltas.push_back(QuicTime::Delta::Infinite());
  bad_send_deltas.push_back(QuicTime::Delta::FromMicroseconds(-1000));

  for (QuicTime::Delta bad_send_delta : bad_send_deltas) {
    SCOPED_TRACE(Message() << "bad_send_delta = "
                           << bad_send_delta.ToMicroseconds());
    EXPECT_FALSE(rtt_stats_.UpdateRtt(bad_send_delta, QuicTime::Delta::Zero(),
                                      QuicTime::Zero()));
    EXPECT_EQ(initial_rtt, rtt_stats_.min_rtt());
    EXPECT_EQ(initial_rtt, rtt_stats_.smoothed_rtt());
  }
}

TEST_F(RttStatsTest, ResetAfterConnectionMigrations) {
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(200),
                       QuicTime::Delta::FromMilliseconds(0), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.smoothed_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.min_rtt());

  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(300),
                       QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.smoothed_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.min_rtt());

  // Reset rtt stats on connection migrations.
  rtt_stats_.OnConnectionMigration();
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.smoothed_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.min_rtt());
}

TEST_F(RttStatsTest, StandardDeviationCalculatorTest1) {
  // All samples are the same.
  rtt_stats_.EnableStandardDeviationCalculation();
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(10),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(rtt_stats_.mean_deviation(),
            rtt_stats_.GetStandardOrMeanDeviation());

  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(10),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(10),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.GetStandardOrMeanDeviation());
}

TEST_F(RttStatsTest, StandardDeviationCalculatorTest2) {
  // Small variance.
  rtt_stats_.EnableStandardDeviationCalculation();
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(10),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(10),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(10),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(9),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(11),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_LT(QuicTime::Delta::FromMicroseconds(500),
            rtt_stats_.GetStandardOrMeanDeviation());
  EXPECT_GT(QuicTime::Delta::FromMilliseconds(1),
            rtt_stats_.GetStandardOrMeanDeviation());
}

TEST_F(RttStatsTest, StandardDeviationCalculatorTest3) {
  // Some variance.
  rtt_stats_.EnableStandardDeviationCalculation();
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(50),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(50),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_APPROX_EQ(rtt_stats_.mean_deviation(),
                   rtt_stats_.GetStandardOrMeanDeviation(), 0.25f);
}

}  // namespace test
}  // namespace quic
```