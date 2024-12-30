Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Subject:** The filename `observation_buffer_unittest.cc` and the `#include "net/nqe/observation_buffer.h"` clearly indicate that this file tests the `ObservationBuffer` class. This is the central piece of functionality we need to understand.

2. **Understand the Purpose of Unit Tests:**  Unit tests are designed to verify the behavior of individual units of code (like a class or a function) in isolation. They check specific aspects of its functionality by providing inputs and asserting expected outputs.

3. **Scan for Test Cases:** Look for the `TEST()` macro. Each `TEST()` block represents a distinct test case focused on a particular feature or scenario of the `ObservationBuffer`. Listing these out provides a roadmap of the tested functionality:

    * `BoundedBuffer`: Testing buffer size limits.
    * `GetPercentileWithWeights`:  Testing percentile calculation with time-based weights.
    * `PercentileSameTimestamps`: Testing percentile calculation with identical timestamps.
    * `PercentileDifferentTimestamps`: Testing percentile calculation with varying timestamps.
    * `PercentileDifferentRSSI`: Testing percentile calculation considering RSSI values.
    * `RemoveObservations`: Testing the removal of observations based on their source.
    * `TestGetMedianRTTSince`: Testing the retrieval of median RTT since a given time.

4. **Analyze Each Test Case:** For each test case, try to understand:

    * **Setup:** What data is being created and initialized? (e.g., `NetworkQualityEstimatorParams`, `base::SimpleTestTickClock`, adding observations).
    * **Action:** What method of the `ObservationBuffer` is being called? (e.g., `AddObservation`, `GetPercentile`, `RemoveObservationsWithSource`).
    * **Assertion:** What is being checked using `EXPECT_...` macros? (e.g., buffer size, percentile values, presence of a value). The assertions are the key to understanding the expected behavior.

5. **Look for Patterns and Key Functionality:**  After reviewing the individual tests, synthesize the overall functionality being tested. The recurring themes are:

    * **Adding observations:** The `AddObservation` method is fundamental.
    * **Calculating percentiles:** The `GetPercentile` method is central, and several tests explore different scenarios (same timestamp, different timestamps, different RSSI).
    * **Buffer management:**  The `BoundedBuffer` test and the `Size()` calls highlight the buffer's capacity limits.
    * **Observation removal:** The `RemoveObservationsWithSource` method is tested.
    * **Time-based weighting:** The `GetPercentileWithWeights` and `PercentileDifferentTimestamps` tests demonstrate how older observations are weighted less.
    * **RSSI-based weighting:** The `PercentileDifferentRSSI` test demonstrates weighting based on signal strength.

6. **Consider the Context (Network Stack):**  The "net/nqe" part of the path and the class name "NetworkQualityObservationBuffer" strongly suggest this component is related to network performance monitoring and quality estimation. The `NetworkQualityObservation` and `NetworkQualityEstimatorParams` further reinforce this.

7. **Relate to JavaScript (if applicable):** Think about how network quality information might be used in a web browser's JavaScript environment. Examples include:

    * **Adaptive bitrate streaming:** Adjusting video quality based on network conditions.
    * **Resource loading prioritization:** Loading critical resources first on slow networks.
    * **User experience metrics:**  Reporting network performance to developers.
    * **Network error handling:** Providing better feedback to users.

8. **Identify Potential Errors:**  Based on the tests and the class's purpose, consider common mistakes:

    * **Adding too many observations:** Exceeding buffer limits.
    * **Incorrect percentile calculations:**  Misunderstanding how time or RSSI weighting affects results.
    * **Forgetting to clear the buffer:** Leading to stale data.
    * **Using incorrect timestamps:** Affecting the weighting of observations.

9. **Consider Debugging:** Think about how a developer might end up examining this code. Common scenarios include:

    * **Investigating inaccurate network quality estimates.**
    * **Debugging issues with adaptive streaming or resource loading.**
    * **Tracking down memory leaks or performance problems in the network stack.**

10. **Structure the Answer:** Organize the findings into logical sections (functionality, relationship to JavaScript, logical reasoning, common errors, debugging). Use clear language and provide specific examples from the code.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "It's just a buffer."  **Correction:**  It's a *weighted* buffer that calculates percentiles, making it more complex than a simple FIFO queue.
* **Focus on individual tests too much:** **Correction:**  Step back and see the bigger picture of what the `ObservationBuffer` *does* overall.
* **Overlooking the parameter objects:** **Correction:** Recognize the importance of `NetworkQualityEstimatorParams` and how they influence the buffer's behavior.
* **Not providing concrete JavaScript examples:** **Correction:**  Think of specific browser features and APIs where network quality information would be relevant.

By following these steps, combining detailed analysis with a high-level understanding of the component's purpose, one can generate a comprehensive and accurate description of the `observation_buffer_unittest.cc` file and its related functionality.
这个文件 `net/nqe/observation_buffer_unittest.cc` 是 Chromium 网络栈中 `ObservationBuffer` 类的单元测试文件。它的主要功能是验证 `ObservationBuffer` 类的各种功能是否正常工作。

下面我们来详细列举一下它的功能，并根据你的要求进行分析：

**1. 功能列举:**

* **测试 `ObservationBuffer` 的容量限制 (BoundedBuffer):**
    * 验证当添加大量观测数据时，`ObservationBuffer` 是否会保持在其最大容量之内。
    * 它通过循环添加 1000 个观测数据，并断言缓冲区的实际大小永远不会超过预设的最大值（在这个测试中是 300）。

* **测试带权重的百分位计算 (GetPercentileWithWeights):**
    * 验证在应用时间衰减权重的情况下，计算出的百分位数是否单调不减。
    * 它添加了一系列按时间顺序排列的观测数据，并循环计算不同百分位的值，断言后面的百分位值不小于前面的百分位值。

* **测试相同时间戳的百分位计算 (PercentileSameTimestamps):**
    * 验证当所有观测数据都具有相同的时间戳时，百分位数的计算是否正确。
    * 它添加了一系列具有相同时间戳的观测数据（从 1 到 100），然后计算不同百分位的值，并断言计算结果与预期值接近（允许一定的浮点数误差）。

* **测试不同时间戳的百分位计算 (PercentileDifferentTimestamps):**
    * 验证当观测数据具有不同的时间戳时，百分位数的计算是否正确，并考虑到时间衰减。
    * 它添加了部分较旧的观测数据和部分较新的观测数据，然后计算百分位，验证较新的数据对结果的影响更大。

* **测试不同 RSSI 的百分位计算 (PercentileDifferentRSSI):**
    * 验证当观测数据具有不同的 RSSI (Received Signal Strength Indication) 值时，百分位数的计算是否正确，并考虑到 RSSI 的权重。
    * 它添加了部分低 RSSI 的观测数据和部分高 RSSI 的观测数据，然后分别在低 RSSI 和高 RSSI 的上下文中计算百分位，验证 RSSI 对结果的影响。

* **测试移除特定来源的观测数据 (RemoveObservations):**
    * 验证可以根据观测数据的来源移除特定的观测数据。
    * 它添加了来自不同来源（HTTP, TCP, QUIC）的观测数据，然后测试移除特定来源的数据后，缓冲区的大小和百分位计算是否正确。

* **测试获取指定时间之后的中间 RTT (TestGetMedianRTTSince):**
    * 验证可以获取自给定时间戳以来的 RTT (Round-Trip Time) 中位数。
    * 它添加了两个具有不同时间戳的观测数据，并测试在不同的起始时间戳下获取 RTT 中位数的结果。

**2. 与 JavaScript 的关系及举例说明:**

`ObservationBuffer` 本身是用 C++ 实现的，直接在 JavaScript 中不可见。但是，它收集和处理的网络质量观测数据最终会影响到浏览器提供给 JavaScript 的网络性能相关的 API 和行为。

**举例说明:**

假设一个 JavaScript 应用想要根据当前的网络状况优化视频播放的质量（自适应码率）。它可以利用浏览器提供的 Network Information API (例如 `navigator.connection.downlink` 或 `navigator.connection.effectiveType`) 来获取网络信息。

虽然 JavaScript 代码不能直接访问 `ObservationBuffer`，但是 `ObservationBuffer` 收集的 RTT、吞吐量等信息会被 Chromium 的网络栈用于计算和更新这些 API 返回的值。

* **假设输入 (C++ `ObservationBuffer`):**  `ObservationBuffer` 中积累了过去一段时间内 HTTP 请求的 RTT 数据，例如：
    * `(100ms, now - 5s, HTTP)`
    * `(120ms, now - 3s, HTTP)`
    * `(90ms, now - 1s, HTTP)`

* **逻辑推理 (C++ 代码):** `ObservationBuffer` 会根据这些数据，可能结合时间衰减等因素，计算出 RTT 的百分位值。

* **输出 (影响 JavaScript API):**  Chromium 的网络栈可能会使用 `ObservationBuffer` 计算出的 RTT 中位数或某个百分位值，然后影响 `navigator.connection.rtt` 的返回值。如果计算出的 RTT 较高，`navigator.connection.rtt` 的值也会相应较高。

* **JavaScript 代码行为:** 基于 `navigator.connection.rtt` 的值，JavaScript 应用可能会选择降低视频的清晰度，以避免卡顿。

```javascript
if (navigator.connection && navigator.connection.rtt > 200) {
  // 网络延迟较高，降低视频质量
  setVideoQuality('low');
} else {
  setVideoQuality('high');
}
```

**3. 逻辑推理的假设输入与输出:**

**测试用例：`PercentileSameTimestamps`**

* **假设输入:**
    * `ObservationBuffer` 初始化，时间衰减因子为 0.5。
    * 添加以下观测数据 (值, 时间戳, 来源)：
        * `(1, now, HTTP)`
        * `(3, now, HTTP)`
        * `(5, now, HTTP)`
        * `(2, now, HTTP)`
        * `(4, now, HTTP)`

* **逻辑推理:** `ObservationBuffer` 会将这些数据存储起来，并按值排序。由于时间戳相同，时间衰减不影响排序。

* **输出:**
    * `buffer.GetPercentile(now, INT32_MIN, 0, nullptr)` 应该返回 `1` (0% 百分位，最小值)。
    * `buffer.GetPercentile(now, INT32_MIN, 50, nullptr)` 应该返回 `3` (50% 百分位，中位数)。
    * `buffer.GetPercentile(now, INT32_MIN, 100, nullptr)` 应该返回 `5` (100% 百分位，最大值)。

**4. 涉及用户或者编程常见的使用错误:**

虽然用户不会直接操作 `ObservationBuffer`，但编程错误可能会导致 `ObservationBuffer` 的行为不符合预期，进而影响用户体验。

* **错误地配置时间衰减参数:** 如果时间衰减参数配置不当，可能导致旧的观测数据权重过高或过低，从而导致网络质量评估不准确。例如，如果时间衰减因子设置为 0，则所有历史数据都会被同等对待，即使是很久以前的数据也可能影响当前的评估。

* **添加了不相关的观测数据:** 如果向 `ObservationBuffer` 添加了与当前网络状况无关的观测数据（例如，来自其他网络接口的数据），可能会干扰网络质量的评估。

* **没有正确处理 `ObservationBuffer` 的容量限制:**  虽然 `ObservationBuffer` 自身会处理容量限制，但如果上层逻辑没有意识到这一点，并期望能获取到所有历史数据，则可能会出现问题。

* **在多线程环境下不正确地访问 `ObservationBuffer`:** `ObservationBuffer` 的实现需要考虑线程安全。如果在多线程环境下没有采取适当的同步措施，可能会导致数据竞争和崩溃。

**5. 用户操作如何一步步地到达这里作为调试线索:**

以下是一个用户操作可能如何间接触发对 `ObservationBuffer` 进行调试的场景：

1. **用户遇到网页加载缓慢或视频卡顿的问题。**
2. **用户或技术支持人员怀疑是网络问题。**
3. **开发人员开始调查网络堆栈的性能。**
4. **开发人员可能会查看网络质量估算器 (Network Quality Estimator, NQE) 的相关组件，其中包括 `ObservationBuffer`。**
5. **为了验证 NQE 的行为是否正确，开发人员可能会：**
    * **查看 NQE 的日志，看是否有异常的观测数据或计算结果。**
    * **运行 NQE 相关的单元测试，例如 `observation_buffer_unittest.cc`，以验证其核心逻辑是否正常。**
    * **在 Chromium 源码中设置断点，跟踪 `ObservationBuffer` 的数据添加和百分位计算过程，以诊断问题。**
    * **检查 NQE 的参数配置，看是否有不合理的设置。**

**总结:**

`observation_buffer_unittest.cc` 文件对于确保 Chromium 网络栈中 `ObservationBuffer` 类的正确性和稳定性至关重要。它通过各种测试用例覆盖了 `ObservationBuffer` 的核心功能，包括容量限制、带权重的百分位计算、不同时间戳和 RSSI 下的百分位计算以及观测数据的移除。虽然 JavaScript 开发者不能直接操作 `ObservationBuffer`，但其内部的运作直接影响了提供给 JavaScript 的网络性能相关 API，最终影响用户的网络体验。对这个文件的理解有助于开发者调试网络相关问题，并确保网络质量估算的准确性。

Prompt: 
```
这是目录为net/nqe/observation_buffer_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/nqe/observation_buffer.h"

#include <stddef.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "net/nqe/network_quality_estimator_params.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::nqe::internal {

namespace {

// Verify that the buffer size is never exceeded.
TEST(NetworkQualityObservationBufferTest, BoundedBuffer) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Minutes(1));
  ObservationBuffer observation_buffer(&params, &tick_clock, 1.0, 1.0);
  const base::TimeTicks now = base::TimeTicks() + base::Seconds(1);
  for (int i = 1; i <= 1000; ++i) {
    observation_buffer.AddObservation(
        Observation(i, now, INT32_MIN, NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
    // The number of entries should be at most the maximum buffer size.
    EXPECT_GE(300u, observation_buffer.Size());
  }
}

// Verify that the percentiles are monotonically non-decreasing when a weight is
// applied.
TEST(NetworkQualityObservationBufferTest, GetPercentileWithWeights) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Minutes(1));

  ObservationBuffer observation_buffer(&params, &tick_clock, 0.98, 1.0);
  const base::TimeTicks now = tick_clock.NowTicks();
  for (int i = 1; i <= 100; ++i) {
    tick_clock.Advance(base::Seconds(1));
    observation_buffer.AddObservation(
        Observation(i, tick_clock.NowTicks(), INT32_MIN,
                    NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
  }
  EXPECT_EQ(100U, observation_buffer.Size());

  int32_t result_lowest = INT32_MAX;
  int32_t result_highest = INT32_MIN;

  for (int i = 1; i <= 100; ++i) {
    size_t observations_count = 0;
    // Verify that i'th percentile is more than i-1'th percentile.
    std::optional<int32_t> result_i = observation_buffer.GetPercentile(
        now, INT32_MIN, i, &observations_count);
    EXPECT_EQ(100u, observations_count);
    ASSERT_TRUE(result_i.has_value());
    result_lowest = std::min(result_lowest, result_i.value());

    result_highest = std::max(result_highest, result_i.value());

    std::optional<int32_t> result_i_1 = observation_buffer.GetPercentile(
        now, INT32_MIN, i - 1, &observations_count);
    EXPECT_EQ(100u, observations_count);
    ASSERT_TRUE(result_i_1.has_value());

    EXPECT_LE(result_i_1.value(), result_i.value());
  }
  EXPECT_LT(result_lowest, result_highest);
}

// Verifies that the percentiles are correctly computed. All observations have
// the same timestamp.
TEST(NetworkQualityObservationBufferTest, PercentileSameTimestamps) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Minutes(1));
  ObservationBuffer buffer(&params, &tick_clock, 0.5, 1.0);
  ASSERT_EQ(0u, buffer.Size());
  ASSERT_LT(0u, buffer.Capacity());

  const base::TimeTicks now = tick_clock.NowTicks();

  size_t observations_count = 0;
  // Percentiles should be unavailable when no observations are available.
  EXPECT_FALSE(
      buffer
          .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                         &observations_count)
          .has_value());
  EXPECT_EQ(0u, observations_count);

  // Insert samples from {1,2,3,..., 100}. First insert odd samples, then even
  // samples. This helps in verifying that the order of samples does not matter.
  for (int i = 1; i <= 99; i += 2) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
    EXPECT_TRUE(buffer.GetPercentile(base::TimeTicks(), INT32_MIN, 50, nullptr)
                    .has_value());
    ASSERT_EQ(static_cast<size_t>(i / 2 + 1), buffer.Size());
  }

  for (int i = 2; i <= 100; i += 2) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
    EXPECT_TRUE(buffer.GetPercentile(base::TimeTicks(), INT32_MIN, 50, nullptr)
                    .has_value());
    ASSERT_EQ(static_cast<size_t>(i / 2 + 50), buffer.Size());
  }

  ASSERT_EQ(100u, buffer.Size());

  for (int i = 0; i <= 100; ++i) {
    // Checks if the difference between actual result and the computed result is
    // less than 1. This is required because computed percentiles may be
    // slightly different from what is expected due to floating point
    // computation errors and integer rounding off errors.
    std::optional<int32_t> result = buffer.GetPercentile(
        base::TimeTicks(), INT32_MIN, i, &observations_count);
    EXPECT_EQ(100u, observations_count);
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), i, 1.0);
  }

  EXPECT_FALSE(buffer
                   .GetPercentile(now + base::Seconds(1), INT32_MIN, 50,
                                  &observations_count)
                   .has_value());
  EXPECT_EQ(0u, observations_count);

  // Percentiles should be unavailable when no observations are available.
  buffer.Clear();
  EXPECT_FALSE(
      buffer
          .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                         &observations_count)
          .has_value());
  EXPECT_EQ(0u, observations_count);
}

// Verifies that the percentiles are correctly computed. Observations have
// different timestamps with half the observations being very old and the rest
// of them being very recent. Percentiles should factor in recent observations
// much more heavily than older samples.
TEST(NetworkQualityObservationBufferTest, PercentileDifferentTimestamps) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Minutes(1));
  ObservationBuffer buffer(&params, &tick_clock, 0.5, 1.0);
  const base::TimeTicks now = tick_clock.NowTicks();
  const base::TimeTicks very_old = now - base::Days(7);

  size_t observations_count;

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(
      buffer
          .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                         &observations_count)
          .has_value());
  EXPECT_EQ(0u, observations_count);

  // First 50 samples have very old timestamps.
  for (int i = 1; i <= 50; ++i) {
    buffer.AddObservation(Observation(i, very_old, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // Next 50 (i.e., from 51 to 100) have recent timestamps.
  for (int i = 51; i <= 100; ++i) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // Older samples have very little weight. So, all percentiles are >= 51
  // (lowest value among recent observations).
  for (int i = 1; i < 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    std::optional<int32_t> result =
        buffer.GetPercentile(very_old, INT32_MIN, i, &observations_count);
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), 51 + 0.49 * i, 1);
    EXPECT_EQ(100u, observations_count);
  }

  EXPECT_FALSE(buffer.GetPercentile(now + base::Seconds(1), INT32_MIN, 50,
                                    &observations_count));
  EXPECT_EQ(0u, observations_count);
}

// Verifies that the percentiles are correctly computed. All observations have
// same timestamp with half the observations taken at low RSSI, and half the
// observations with high RSSI. Percentiles should be computed based on the
// current RSSI and the RSSI of the observations.
TEST(NetworkQualityObservationBufferTest, PercentileDifferentRSSI) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Minutes(1));
  ObservationBuffer buffer(&params, &tick_clock, 1.0, 0.25);
  const base::TimeTicks now = tick_clock.NowTicks();
  int32_t high_rssi = 4;
  int32_t low_rssi = 0;

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(buffer.GetPercentile(base::TimeTicks(), INT32_MIN, 50, nullptr)
                   .has_value());

  // First 50 samples have very low RSSI.
  for (int i = 1; i <= 50; ++i) {
    buffer.AddObservation(
        Observation(i, now, low_rssi, NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // Next 50 (i.e., from 51 to 100) have high RSSI.
  for (int i = 51; i <= 100; ++i) {
    buffer.AddObservation(Observation(i, now, high_rssi,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // When the current RSSI is |high_rssi|, higher weight should be assigned
  // to observations that were taken at |high_rssi|.
  for (int i = 1; i < 100; ++i) {
    std::optional<int32_t> result =
        buffer.GetPercentile(now, high_rssi, i, nullptr);
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), 51 + 0.49 * i, 2);
  }

  // When the current RSSI is |low_rssi|, higher weight should be assigned
  // to observations that were taken at |low_rssi|.
  for (int i = 1; i < 100; ++i) {
    std::optional<int32_t> result =
        buffer.GetPercentile(now, low_rssi, i, nullptr);
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), i / 2, 2);
  }
}

// Verifies that the percentiles are correctly computed when some of the
// observation sources are disallowed. All observations have the same timestamp.
TEST(NetworkQualityObservationBufferTest, RemoveObservations) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Minutes(1));

  ObservationBuffer buffer(&params, &tick_clock, 0.5, 1.0);
  const base::TimeTicks now = tick_clock.NowTicks();

  // Insert samples from {1,2,3,..., 100}. First insert odd samples, then even
  // samples. This helps in verifying that the order of samples does not matter.
  for (int i = 1; i <= 99; i += 2) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }
  EXPECT_EQ(50u, buffer.Size());

  // Add samples for TCP and QUIC observations which should not be taken into
  // account when computing the percentile.
  for (int i = 1; i <= 99; i += 2) {
    buffer.AddObservation(Observation(10000, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
    buffer.AddObservation(Observation(10000, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC));
  }
  EXPECT_EQ(150u, buffer.Size());

  for (int i = 2; i <= 100; i += 2) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }
  EXPECT_EQ(200u, buffer.Size());

  bool deleted_observation_sources[NETWORK_QUALITY_OBSERVATION_SOURCE_MAX] = {
      false};

  // Since all entries in |deleted_observation_sources| are set to false, no
  // observations should be deleted.
  buffer.RemoveObservationsWithSource(deleted_observation_sources);
  EXPECT_EQ(200u, buffer.Size());

  // 50 TCP and 50 QUIC observations should be deleted.
  deleted_observation_sources[NETWORK_QUALITY_OBSERVATION_SOURCE_TCP] = true;
  deleted_observation_sources[NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC] = true;
  buffer.RemoveObservationsWithSource(deleted_observation_sources);
  EXPECT_EQ(100u, buffer.Size());

  for (int i = 0; i <= 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    std::optional<int32_t> result =
        buffer.GetPercentile(base::TimeTicks(), INT32_MIN, i, nullptr);
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), i, 1);
  }

  deleted_observation_sources[NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP] = true;
  buffer.RemoveObservationsWithSource(deleted_observation_sources);
  EXPECT_EQ(0u, buffer.Size());
}

TEST(NetworkQualityObservationBufferTest, TestGetMedianRTTSince) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Minutes(1));
  ObservationBuffer buffer(&params, &tick_clock, 0.5, 1.0);
  base::TimeTicks now = tick_clock.NowTicks();
  base::TimeTicks old = now - base::Milliseconds(1);
  ASSERT_NE(old, now);

  // First sample has very old timestamp.
  buffer.AddObservation(
      Observation(1, old, INT32_MIN, NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));

  buffer.AddObservation(Observation(100, now, INT32_MIN,
                                    NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));

  const struct {
    base::TimeTicks start_timestamp;
    bool expect_network_quality_available;
    base::TimeDelta expected_url_request_rtt;
  } tests[] = {
      {now + base::Seconds(10), false, base::Milliseconds(0)},
      {now, true, base::Milliseconds(100)},
      {now - base::Microseconds(500), true, base::Milliseconds(100)},

  };

  for (const auto& test : tests) {
    std::optional<int32_t> url_request_rtt =
        buffer.GetPercentile(test.start_timestamp, INT32_MIN, 50, nullptr);
    EXPECT_EQ(test.expect_network_quality_available,
              url_request_rtt.has_value());

    if (test.expect_network_quality_available) {
      EXPECT_EQ(test.expected_url_request_rtt.InMillisecondsF(),
                url_request_rtt.value());
    }
  }
}


}  // namespace

}  // namespace net::nqe::internal

"""

```