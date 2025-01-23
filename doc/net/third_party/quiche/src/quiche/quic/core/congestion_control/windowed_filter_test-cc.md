Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of `windowed_filter_test.cc`, its relation to JavaScript (if any), logical inferences with examples, potential user errors, and debugging steps.

2. **Identify the Core Subject:** The file name immediately points to testing a component named `WindowedFilter`. The `#include "quiche/quic/core/congestion_control/windowed_filter.h"` confirms this. We can infer that `WindowedFilter` is likely related to QUIC's congestion control mechanisms.

3. **Analyze the Includes:**
    * `windowed_filter.h`:  This is the header file for the code being tested. It will contain the class definition of `WindowedFilter`.
    * `rtt_stats.h`:  Round-trip time statistics. This hints that `WindowedFilter` might be used to smooth or filter RTT measurements.
    * `quic_bandwidth.h`: Represents bandwidth. This suggests that `WindowedFilter` could also be used for bandwidth estimation.
    * `quic_packets.h`:  Basic QUIC packet structures. Less directly relevant but indicates the context.
    * `quic_logging.h`, `quic_test.h`:  Standard QUIC utilities for logging and testing.

4. **Examine the Test Class `WindowedFilterTest`:**
    * **Constructor:** Initializes two `WindowedFilter` instances: `windowed_min_rtt_` and `windowed_max_bw_`. This strongly suggests the filter can be used for both minimum values (like RTT) and maximum values (like bandwidth). The window size is set to 99ms.
    * **`InitializeMinFilter()` and `InitializeMaxFilter()`:** These methods set up specific scenarios for testing. They populate the filters with pre-defined values and timestamps. This is crucial for controlled testing of different conditions. The names themselves are self-explanatory.
    * **Protected Members:** `windowed_min_rtt_` and `windowed_max_bw_` are the actual instances of the `WindowedFilter` being tested. The template parameters reveal important information:
        * `QuicTime::Delta`: The type of value being filtered for RTT (time difference).
        * `MinFilter<QuicTime::Delta>`: Indicates it's tracking the *minimum* value.
        * `QuicBandwidth`: The type of value being filtered for bandwidth.
        * `MaxFilter<QuicBandwidth>`: Indicates it's tracking the *maximum* value.
        * `QuicTime`, `QuicTime::Delta`:  Types used for time and time differences within the filter.

5. **Analyze the Individual Test Cases (`TEST_F`):**  Each test case focuses on a specific aspect of the `WindowedFilter`'s behavior. This is the heart of understanding the functionality. Look for keywords and patterns:
    * **`UninitializedEstimates`:** Checks the initial state of the filter.
    * **`MonotonicallyIncreasingMin` / `MonotonicallyDecreasingMax`:** Tests how the filter responds to consistent trends.
    * **`SampleChangesThirdBestMin` / `SampleChangesThirdBestMax` etc.:** Tests how new samples affect the stored best, second best, and third best values. These are crucial for understanding the ranking/filtering logic.
    * **`ExpireBestMin` / `ExpireBestMax` etc.:** Tests the windowing mechanism – how old data is removed. The time calculations are important here.
    * **`ExpireCounterBasedMax`:** Shows an alternative time representation (a counter).

6. **Infer Functionality:** Based on the test names and the operations within them (especially `Update`, `GetBest`, `GetSecondBest`, `GetThirdBest`), we can deduce the core functionality:
    * The `WindowedFilter` maintains a window of recent values.
    * It tracks the best, second best, and third best values within that window.
    * It supports both minimum and maximum tracking.
    * It uses timestamps or counters to manage the window and expire old data.

7. **Address JavaScript Relationship:**  Given the context of network stacks and congestion control, it's highly unlikely that this specific C++ code has a direct relationship with JavaScript functionality in the *same process*. However, consider broader connections:
    * **Indirectly related:**  JavaScript running in a browser uses the Chromium network stack (which includes this code) to make network requests. The congestion control algorithms (potentially using `WindowedFilter`) impact the performance of those JavaScript applications.
    * **No direct API:** There's no direct JavaScript API to interact with this specific C++ class.

8. **Logical Inferences and Examples:**  Choose a few representative test cases and elaborate on the logic. Explain the input (samples, times), the expected behavior (changes in best/second-best/third-best values), and the underlying reasoning (windowing, comparison).

9. **User/Programming Errors:** Think about how someone might misuse the `WindowedFilter` or its related concepts:
    * Incorrect time source.
    * Mismatched window size.
    * Expecting immediate changes.

10. **Debugging Steps:** Imagine a scenario where the `WindowedFilter` isn't behaving as expected. How would a developer investigate?  This leads to the debugging section.

11. **Structure the Answer:** Organize the information logically with clear headings. Start with a summary of the functionality, then delve into details, and finally address the specific points in the prompt (JavaScript, inferences, errors, debugging). Use code snippets and clear explanations to illustrate the points.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the "window" refers to the number of samples. **Correction:** The constructor clearly uses `QuicTime::Delta`, indicating a time-based window.
* **Considering JavaScript:**  Focus initially on direct code interaction. **Refinement:** Expand to indirect relationships through the browser's network stack.
* **Explaining Inferences:** Don't just say "it works."  Explain *why* a certain output is expected based on the filter's logic and the input.
* **Debugging:**  Think about *practical* debugging steps, not just theoretical ones (e.g., using logs, breakpoints).

By following this systematic approach, combining code analysis with an understanding of networking concepts, and iteratively refining the analysis, a comprehensive and accurate answer can be constructed.
这个文件 `windowed_filter_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的测试文件。它专门用于测试 `WindowedFilter` 类及其相关功能。 `WindowedFilter`  是一个用于在时间窗口内过滤和跟踪特定类型数值的类，它可以用来跟踪窗口内的最小值、最大值，以及第二好、第三好的值。

**主要功能：**

1. **测试 WindowedFilter 类的基本功能：**
   - **初始化状态：** 验证 `WindowedFilter` 在没有数据输入时的初始状态，例如 `GetBest()`, `GetSecondBest()`, `GetThirdBest()` 等方法是否返回默认值 (通常是零值或未定义状态)。
   - **单调递增/递减序列：** 测试当输入单调递增的最小值样本或单调递减的最大值样本时，`WindowedFilter` 如何更新其内部状态并返回正确的最优值。
   - **新样本更新：** 测试当有新的样本值输入时，`WindowedFilter` 如何比较新值与当前存储的最佳、次佳、再次佳值，并进行相应的更新。
   - **窗口过期：**  测试 `WindowedFilter` 的时间窗口机制。当存储的样本数据超过设定的时间窗口时，验证这些过期数据是否会被正确地移除，并且最优值会根据剩余的数据进行更新。
   - **基于计数器的窗口：**  测试 `WindowedFilter` 可以使用计数器（例如，往返次数）而不是时间戳来管理窗口的过期。

2. **测试 MinFilter 和 MaxFilter 模板类：**
   - `WindowedFilter` 是一个模板类，它可以与 `MinFilter` 或 `MaxFilter` 结合使用，分别用于跟踪最小值和最大值。 这个测试文件覆盖了这两种情况。

**与 JavaScript 的关系：**

这个 C++ 测试文件本身与 JavaScript 没有直接的功能关系。它是在 Chromium 的 C++ 代码库中，用于测试网络协议的底层实现。

然而，**间接地**，这个测试覆盖的代码（`WindowedFilter`）可能会被 QUIC 协议栈用于实现拥塞控制等功能。而 QUIC 协议是现代网络连接的基础，浏览器中的 JavaScript 代码通过网络请求与服务器通信时，底层的 QUIC 协议栈可能会使用到类似于 `WindowedFilter` 的机制来优化网络性能。

**举例说明（间接关系）：**

假设一个 JavaScript 应用需要下载大量数据。底层的 QUIC 连接使用 `WindowedFilter` 来跟踪最近的往返时延 (RTT) 的最小值。这个最小值可以用来估计网络的延迟，并作为拥塞控制算法的输入，从而动态调整发送数据的速率，避免网络拥塞，最终提高 JavaScript 应用的数据下载速度。

**逻辑推理，假设输入与输出：**

**场景 1：测试 `MonotonicallyIncreasingMin` (单调递增的最小值)**

* **假设输入：**
    - 时间窗口大小：99ms
    - 初始时间：0ms
    - RTT 样本序列（时间和值）：
        - (0ms, 10ms)
        - (25ms, 20ms)
        - (50ms, 30ms)
        - (75ms, 40ms)
        - (100ms, 50ms)
        - (125ms, 60ms)

* **预期输出：**
    - 在前 3 个样本后（10ms, 20ms, 30ms），`GetBest()` 应该返回 10ms (因为窗口内最小值是 10ms)。
    - 在第 4 个样本后 (40ms)，`GetBest()` 应该返回 20ms (因为 10ms 的样本已经超过 99ms 的窗口期)。
    - 在第 5 和第 6 个样本后 (50ms, 60ms)，`GetBest()` 应该返回 40ms (因为 20ms 的样本也过期了)。

**场景 2：测试 `ExpireBestMax` (最佳最大值过期)**

* **假设输入：**
    - 已经通过 `InitializeMaxFilter()` 初始化了 `windowed_max_bw_`，使其具有以下值：
        - Best = 900 bps (记录于 25ms)
        - Second best = 700 bps (记录于 75ms)
        - Third best = 600 bps (记录于 100ms)
    - 新的带宽样本：550 bps
    - 当前时间：125ms

* **预期输出：**
    - 由于最佳值 (900 bps) 记录于 25ms，窗口期为 99ms，因此在 125ms 时，900 bps 的样本已经过期。
    - `GetBest()` 应该返回 700 bps (之前的第二好值)。
    - `GetSecondBest()` 应该返回 600 bps (之前的第三好值)。
    - `GetThirdBest()` 应该返回 550 bps (新的样本值)。

**用户或编程常见的使用错误：**

1. **时间戳不准确或不一致：**  `WindowedFilter` 依赖于准确的时间戳来判断样本是否过期。如果提供的时间戳不正确或前后不一致，可能导致窗口管理出现问题，例如，本应该过期的样本没有过期，或者本不应该过期的样本被错误地移除了。

   **示例：**  假设用户在更新 `WindowedFilter` 时，错误地使用了系统时间，导致时间回拨。这会让旧的样本看起来像是最近的，从而影响最佳值的计算。

2. **窗口大小设置不合理：**  窗口大小的设置直接影响过滤器的灵敏度和对突发情况的反应速度。如果窗口设置得太小，过滤器可能过于敏感，容易受到噪声的影响。如果窗口设置得太大，过滤器可能反应迟钝，无法及时捕捉到网络状况的变化。

   **示例：**  一个拥塞控制算法使用 `WindowedFilter` 来平滑 RTT。如果窗口设置得非常小，一个短暂的网络抖动可能导致 RTT 的最佳值大幅波动，从而触发不必要的降速。

3. **更新频率过低或过高：**  更新频率需要与被监控指标的变化频率相匹配。更新频率过低可能导致错过重要的变化，而更新频率过高可能会增加计算负担，且可能引入不必要的噪声。

   **示例：**  如果网络的带宽波动很快，但是 `WindowedFilter` 的更新频率很低，那么它可能无法准确地反映当前的带宽状况。

**用户操作如何一步步到达这里（作为调试线索）：**

假设用户在使用 Chromium 浏览器时遇到了网络性能问题，例如网页加载缓慢或视频卡顿。为了调试这个问题，开发者可能会进行以下步骤：

1. **抓取网络日志：** 使用 Chromium 的网络抓包工具 (例如 `chrome://net-export/`) 记录网络请求和响应的详细信息。
2. **分析 QUIC 连接：**  如果连接使用了 QUIC 协议，开发者会查看 QUIC 连接的统计信息，例如 RTT、丢包率、拥塞窗口大小等。
3. **怀疑拥塞控制问题：** 如果发现拥塞窗口大小变化异常或 RTT 波动过大，开发者可能会怀疑底层的拥塞控制算法存在问题。
4. **查看 QUIC 代码：**  开发者可能会深入研究 Chromium 的 QUIC 代码，寻找与拥塞控制相关的模块。
5. **定位到 `WindowedFilter`：**  在拥塞控制相关的代码中，可能会发现 `WindowedFilter` 被用于平滑 RTT 或带宽估计等指标。
6. **查看测试文件 `windowed_filter_test.cc`：** 为了理解 `WindowedFilter` 的具体工作原理和可能存在的缺陷，开发者会查看其对应的测试文件，例如这个 `windowed_filter_test.cc`，来了解各种边界情况和预期行为。

通过查看测试文件，开发者可以了解 `WindowedFilter` 的设计意图，验证其在各种场景下的行为是否符合预期，从而帮助定位和解决网络性能问题。例如，如果测试覆盖了时间戳不一致的情况，开发者可能会检查代码中时间戳的获取和使用是否正确。

总而言之，`windowed_filter_test.cc` 是 QUIC 协议栈中一个重要的测试文件，它确保了 `WindowedFilter` 类的正确性和可靠性，而 `WindowedFilter` 这样的工具在网络拥塞控制和性能优化方面起着关键作用，间接地影响着用户通过浏览器访问网络时的体验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/windowed_filter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/windowed_filter.h"

#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace test {

class WindowedFilterTest : public QuicTest {
 public:
  // Set the window to 99ms, so 25ms is more than a quarter rtt.
  WindowedFilterTest()
      : windowed_min_rtt_(QuicTime::Delta::FromMilliseconds(99),
                          QuicTime::Delta::Zero(), QuicTime::Zero()),
        windowed_max_bw_(QuicTime::Delta::FromMilliseconds(99),
                         QuicBandwidth::Zero(), QuicTime::Zero()) {}

  // Sets up windowed_min_rtt_ to have the following values:
  // Best = 20ms, recorded at 25ms
  // Second best = 40ms, recorded at 75ms
  // Third best = 50ms, recorded at 100ms
  void InitializeMinFilter() {
    QuicTime now = QuicTime::Zero();
    QuicTime::Delta rtt_sample = QuicTime::Delta::FromMilliseconds(10);
    for (int i = 0; i < 5; ++i) {
      windowed_min_rtt_.Update(rtt_sample, now);
      QUIC_VLOG(1) << "i: " << i << " sample: " << rtt_sample.ToMilliseconds()
                   << " mins: "
                   << " " << windowed_min_rtt_.GetBest().ToMilliseconds() << " "
                   << windowed_min_rtt_.GetSecondBest().ToMilliseconds() << " "
                   << windowed_min_rtt_.GetThirdBest().ToMilliseconds();
      now = now + QuicTime::Delta::FromMilliseconds(25);
      rtt_sample = rtt_sample + QuicTime::Delta::FromMilliseconds(10);
    }
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(20),
              windowed_min_rtt_.GetBest());
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(40),
              windowed_min_rtt_.GetSecondBest());
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(50),
              windowed_min_rtt_.GetThirdBest());
  }

  // Sets up windowed_max_bw_ to have the following values:
  // Best = 900 bps, recorded at 25ms
  // Second best = 700 bps, recorded at 75ms
  // Third best = 600 bps, recorded at 100ms
  void InitializeMaxFilter() {
    QuicTime now = QuicTime::Zero();
    QuicBandwidth bw_sample = QuicBandwidth::FromBitsPerSecond(1000);
    for (int i = 0; i < 5; ++i) {
      windowed_max_bw_.Update(bw_sample, now);
      QUIC_VLOG(1) << "i: " << i << " sample: " << bw_sample.ToBitsPerSecond()
                   << " maxs: "
                   << " " << windowed_max_bw_.GetBest().ToBitsPerSecond() << " "
                   << windowed_max_bw_.GetSecondBest().ToBitsPerSecond() << " "
                   << windowed_max_bw_.GetThirdBest().ToBitsPerSecond();
      now = now + QuicTime::Delta::FromMilliseconds(25);
      bw_sample = bw_sample - QuicBandwidth::FromBitsPerSecond(100);
    }
    EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(900),
              windowed_max_bw_.GetBest());
    EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(700),
              windowed_max_bw_.GetSecondBest());
    EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(600),
              windowed_max_bw_.GetThirdBest());
  }

 protected:
  WindowedFilter<QuicTime::Delta, MinFilter<QuicTime::Delta>, QuicTime,
                 QuicTime::Delta>
      windowed_min_rtt_;
  WindowedFilter<QuicBandwidth, MaxFilter<QuicBandwidth>, QuicTime,
                 QuicTime::Delta>
      windowed_max_bw_;
};

namespace {
// Test helper function: updates the filter with a lot of small values in order
// to ensure that it is not susceptible to noise.
void UpdateWithIrrelevantSamples(
    WindowedFilter<uint64_t, MaxFilter<uint64_t>, uint64_t, uint64_t>* filter,
    uint64_t max_value, uint64_t time) {
  for (uint64_t i = 0; i < 1000; i++) {
    filter->Update(i % max_value, time);
  }
}
}  // namespace

TEST_F(WindowedFilterTest, UninitializedEstimates) {
  EXPECT_EQ(QuicTime::Delta::Zero(), windowed_min_rtt_.GetBest());
  EXPECT_EQ(QuicTime::Delta::Zero(), windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(QuicTime::Delta::Zero(), windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(QuicBandwidth::Zero(), windowed_max_bw_.GetBest());
  EXPECT_EQ(QuicBandwidth::Zero(), windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(QuicBandwidth::Zero(), windowed_max_bw_.GetThirdBest());
}

TEST_F(WindowedFilterTest, MonotonicallyIncreasingMin) {
  QuicTime now = QuicTime::Zero();
  QuicTime::Delta rtt_sample = QuicTime::Delta::FromMilliseconds(10);
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), windowed_min_rtt_.GetBest());

  // Gradually increase the rtt samples and ensure the windowed min rtt starts
  // rising.
  for (int i = 0; i < 6; ++i) {
    now = now + QuicTime::Delta::FromMilliseconds(25);
    rtt_sample = rtt_sample + QuicTime::Delta::FromMilliseconds(10);
    windowed_min_rtt_.Update(rtt_sample, now);
    QUIC_VLOG(1) << "i: " << i << " sample: " << rtt_sample.ToMilliseconds()
                 << " mins: "
                 << " " << windowed_min_rtt_.GetBest().ToMilliseconds() << " "
                 << windowed_min_rtt_.GetSecondBest().ToMilliseconds() << " "
                 << windowed_min_rtt_.GetThirdBest().ToMilliseconds();
    if (i < 3) {
      EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10),
                windowed_min_rtt_.GetBest());
    } else if (i == 3) {
      EXPECT_EQ(QuicTime::Delta::FromMilliseconds(20),
                windowed_min_rtt_.GetBest());
    } else if (i < 6) {
      EXPECT_EQ(QuicTime::Delta::FromMilliseconds(40),
                windowed_min_rtt_.GetBest());
    }
  }
}

TEST_F(WindowedFilterTest, MonotonicallyDecreasingMax) {
  QuicTime now = QuicTime::Zero();
  QuicBandwidth bw_sample = QuicBandwidth::FromBitsPerSecond(1000);
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(1000), windowed_max_bw_.GetBest());

  // Gradually decrease the bw samples and ensure the windowed max bw starts
  // decreasing.
  for (int i = 0; i < 6; ++i) {
    now = now + QuicTime::Delta::FromMilliseconds(25);
    bw_sample = bw_sample - QuicBandwidth::FromBitsPerSecond(100);
    windowed_max_bw_.Update(bw_sample, now);
    QUIC_VLOG(1) << "i: " << i << " sample: " << bw_sample.ToBitsPerSecond()
                 << " maxs: "
                 << " " << windowed_max_bw_.GetBest().ToBitsPerSecond() << " "
                 << windowed_max_bw_.GetSecondBest().ToBitsPerSecond() << " "
                 << windowed_max_bw_.GetThirdBest().ToBitsPerSecond();
    if (i < 3) {
      EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(1000),
                windowed_max_bw_.GetBest());
    } else if (i == 3) {
      EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(900),
                windowed_max_bw_.GetBest());
    } else if (i < 6) {
      EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(700),
                windowed_max_bw_.GetBest());
    }
  }
}

TEST_F(WindowedFilterTest, SampleChangesThirdBestMin) {
  InitializeMinFilter();
  // RTT sample lower than the third-choice min-rtt sets that, but nothing else.
  QuicTime::Delta rtt_sample =
      windowed_min_rtt_.GetThirdBest() - QuicTime::Delta::FromMilliseconds(5);
  // This assert is necessary to avoid triggering -Wstrict-overflow
  // See crbug/616957
  ASSERT_GT(windowed_min_rtt_.GetThirdBest(),
            QuicTime::Delta::FromMilliseconds(5));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(101);
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(40),
            windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(20), windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesThirdBestMax) {
  InitializeMaxFilter();
  // BW sample higher than the third-choice max sets that, but nothing else.
  QuicBandwidth bw_sample =
      windowed_max_bw_.GetThirdBest() + QuicBandwidth::FromBitsPerSecond(50);
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(101);
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(700),
            windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(900), windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesSecondBestMin) {
  InitializeMinFilter();
  // RTT sample lower than the second-choice min sets that and also
  // the third-choice min.
  QuicTime::Delta rtt_sample =
      windowed_min_rtt_.GetSecondBest() - QuicTime::Delta::FromMilliseconds(5);
  // This assert is necessary to avoid triggering -Wstrict-overflow
  // See crbug/616957
  ASSERT_GT(windowed_min_rtt_.GetSecondBest(),
            QuicTime::Delta::FromMilliseconds(5));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(101);
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(20), windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesSecondBestMax) {
  InitializeMaxFilter();
  // BW sample higher than the second-choice max sets that and also
  // the third-choice max.
  QuicBandwidth bw_sample =
      windowed_max_bw_.GetSecondBest() + QuicBandwidth::FromBitsPerSecond(50);
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(101);
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(900), windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesAllMins) {
  InitializeMinFilter();
  // RTT sample lower than the first-choice min-rtt sets that and also
  // the second and third-choice mins.
  QuicTime::Delta rtt_sample =
      windowed_min_rtt_.GetBest() - QuicTime::Delta::FromMilliseconds(5);
  // This assert is necessary to avoid triggering -Wstrict-overflow
  // See crbug/616957
  ASSERT_GT(windowed_min_rtt_.GetBest(), QuicTime::Delta::FromMilliseconds(5));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(101);
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesAllMaxs) {
  InitializeMaxFilter();
  // BW sample higher than the first-choice max sets that and also
  // the second and third-choice maxs.
  QuicBandwidth bw_sample =
      windowed_max_bw_.GetBest() + QuicBandwidth::FromBitsPerSecond(50);
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(101);
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireBestMin) {
  InitializeMinFilter();
  QuicTime::Delta old_third_best = windowed_min_rtt_.GetThirdBest();
  QuicTime::Delta old_second_best = windowed_min_rtt_.GetSecondBest();
  QuicTime::Delta rtt_sample =
      old_third_best + QuicTime::Delta::FromMilliseconds(5);
  // Best min sample was recorded at 25ms, so expiry time is 124ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(125);
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(old_third_best, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(old_second_best, windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireBestMax) {
  InitializeMaxFilter();
  QuicBandwidth old_third_best = windowed_max_bw_.GetThirdBest();
  QuicBandwidth old_second_best = windowed_max_bw_.GetSecondBest();
  QuicBandwidth bw_sample =
      old_third_best - QuicBandwidth::FromBitsPerSecond(50);
  // Best max sample was recorded at 25ms, so expiry time is 124ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(125);
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(old_third_best, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(old_second_best, windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireSecondBestMin) {
  InitializeMinFilter();
  QuicTime::Delta old_third_best = windowed_min_rtt_.GetThirdBest();
  QuicTime::Delta rtt_sample =
      old_third_best + QuicTime::Delta::FromMilliseconds(5);
  // Second best min sample was recorded at 75ms, so expiry time is 174ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(175);
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(old_third_best, windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireSecondBestMax) {
  InitializeMaxFilter();
  QuicBandwidth old_third_best = windowed_max_bw_.GetThirdBest();
  QuicBandwidth bw_sample =
      old_third_best - QuicBandwidth::FromBitsPerSecond(50);
  // Second best max sample was recorded at 75ms, so expiry time is 174ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(175);
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(old_third_best, windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireAllMins) {
  InitializeMinFilter();
  QuicTime::Delta rtt_sample =
      windowed_min_rtt_.GetThirdBest() + QuicTime::Delta::FromMilliseconds(5);
  // This assert is necessary to avoid triggering -Wstrict-overflow
  // See crbug/616957
  ASSERT_LT(windowed_min_rtt_.GetThirdBest(),
            QuicTime::Delta::Infinite() - QuicTime::Delta::FromMilliseconds(5));
  // Third best min sample was recorded at 100ms, so expiry time is 199ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(200);
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireAllMaxs) {
  InitializeMaxFilter();
  QuicBandwidth bw_sample =
      windowed_max_bw_.GetThirdBest() - QuicBandwidth::FromBitsPerSecond(50);
  // Third best max sample was recorded at 100ms, so expiry time is 199ms.
  QuicTime now = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(200);
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetBest());
}

// Test the windowed filter where the time used is an exact counter instead of a
// timestamp.  This is useful if, for example, the time is measured in round
// trips.
TEST_F(WindowedFilterTest, ExpireCounterBasedMax) {
  // Create a window which starts at t = 0 and expires after two cycles.
  WindowedFilter<uint64_t, MaxFilter<uint64_t>, uint64_t, uint64_t> max_filter(
      2, 0, 0);

  const uint64_t kBest = 50000;
  // Insert 50000 at t = 1.
  max_filter.Update(50000, 1);
  EXPECT_EQ(kBest, max_filter.GetBest());
  UpdateWithIrrelevantSamples(&max_filter, 20, 1);
  EXPECT_EQ(kBest, max_filter.GetBest());

  // Insert 40000 at t = 2.  Nothing is expected to expire.
  max_filter.Update(40000, 2);
  EXPECT_EQ(kBest, max_filter.GetBest());
  UpdateWithIrrelevantSamples(&max_filter, 20, 2);
  EXPECT_EQ(kBest, max_filter.GetBest());

  // Insert 30000 at t = 3.  Nothing is expected to expire yet.
  max_filter.Update(30000, 3);
  EXPECT_EQ(kBest, max_filter.GetBest());
  UpdateWithIrrelevantSamples(&max_filter, 20, 3);
  EXPECT_EQ(kBest, max_filter.GetBest());
  QUIC_VLOG(0) << max_filter.GetSecondBest();
  QUIC_VLOG(0) << max_filter.GetThirdBest();

  // Insert 20000 at t = 4.  50000 at t = 1 expires, so 40000 becomes the new
  // maximum.
  const uint64_t kNewBest = 40000;
  max_filter.Update(20000, 4);
  EXPECT_EQ(kNewBest, max_filter.GetBest());
  UpdateWithIrrelevantSamples(&max_filter, 20, 4);
  EXPECT_EQ(kNewBest, max_filter.GetBest());
}

}  // namespace test
}  // namespace quic
```