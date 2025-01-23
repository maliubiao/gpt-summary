Response:
Let's break down the thought process for analyzing the `codec_pressure_gauge_test.cc` file.

1. **Understand the Core Purpose:** The file name `codec_pressure_gauge_test.cc` immediately suggests it's a test file for something called `CodecPressureGauge`. The `.cc` extension and inclusion of `<gtest/gtest.h>` reinforce this. The presence of `third_party/blink/renderer` indicates it's part of the Chromium rendering engine.

2. **Identify Key Components:** Scan the includes to understand dependencies:
    * `codec_pressure_gauge.h`:  The main subject of the test.
    * `base/test/bind.h`, `base/test/mock_callback.h`:  Tools for creating mock functions and callbacks for testing asynchronous or event-driven behavior.
    * `build/build_config.h`:  Used for platform-specific logic (like the Windows check).
    * `testing/gmock/include/gmock/gmock.h`: A mocking framework used for verifying interactions with dependencies.
    * `testing/gtest/include/gtest/gtest.h`:  The core Google Test framework.
    * `v8_binding_for_testing.h`: Indicates interaction with the V8 JavaScript engine, likely for testing within a Blink environment.
    * `reclaimable_codec.h`: Suggests the pressure gauge is related to codecs that can be reclaimed or have limited resources.
    * `platform/heap/...`:  Implies memory management and garbage collection concerns.

3. **Analyze the Test Structure:**
    * `namespace blink`:  Confirms it's Blink-related code.
    * Anonymous namespace `namespace { ... }`:  Holds private helper constants and types (`kTestPressureThreshold`, `MockPressureChangeCallback`).
    * `class CodecPressureGaugeTest : public testing::TestWithParam<ReclaimableCodec::CodecType>`:  A test fixture that allows running the same tests with different `CodecType` parameters (Decoder and Encoder). This is a crucial piece of information.
    * `using RegistrationResult = ...`:  A type alias for convenience.
    * Constructor and destructor:  Sets the test threshold.
    * `PressureGauge()` method: Provides access to the singleton `CodecPressureGauge` instance.
    * `TEST_P(...)`: Defines parameterized test cases. Each test focuses on a specific aspect of the `CodecPressureGauge`.

4. **Examine Individual Test Cases:**  Go through each `TEST_P` block and understand its purpose:
    * `DefaultState`: Checks the initial state of the gauge (pressure is 0, not exceeded).
    * `GaugeIsSharedForDecodersEncoders`:  Verifies whether the pressure gauge instance is shared between decoders and encoders (platform-dependent). This is a key architectural detail.
    * `RegisterUnregisterCallbacks`: Tests registering and unregistering callbacks, ensuring they get unique IDs and don't initially report pressure exceeded.
    * `IncrementDecrement`: Verifies incrementing and decrementing the pressure, checking the current pressure value.
    * `UnregisterAllLeftoverPressure`: Tests unregistering a callback and releasing all the pressure it contributed, ensuring the global pressure resets.
    * `UnregisterPartialLeftoverPressure`:  Similar to the previous test, but releases only a portion of the pressure.
    * `ExceedingThresholdRunsCallbacks`:  Checks that registered callbacks are triggered when the pressure exceeds the threshold. Uses `EXPECT_CALL` and `VerifyAndClearExpectations` for mock verification.
    * `PassingUnderThresholdRunsCallbacks_Decrement`: Tests that callbacks are triggered when the pressure drops below the threshold due to `Decrement()`.
    * `PassingUnderThresholdRunsCallbacks_Unregister`: Tests that callbacks are triggered when the pressure drops below the threshold due to unregistering and releasing pressure.
    * `RepeatedlyCrossingThresholds`:  Verifies that callbacks are triggered correctly multiple times when the pressure oscillates around the threshold.
    * `ZeroThreshold`:  Tests the behavior when the pressure threshold is set to zero.

5. **Identify Functionality:** Based on the test cases, summarize the functionality of `CodecPressureGauge`:
    * Tracks global pressure related to codecs.
    * Has a configurable threshold for "pressure exceeded."
    * Allows registering callbacks to be notified when the pressure crosses the threshold.
    * Provides methods to increment and decrement the pressure.
    * Allows unregistering callbacks, optionally releasing pressure associated with them.
    * Seems to be a singleton (based on `GetInstance()`).

6. **Relate to Web Technologies (JavaScript, HTML, CSS):** This is where you connect the backend logic to frontend technologies. Think about *where* codec usage happens in a web browser:
    * **`<video>` and `<audio>` elements:** These elements use codecs to decode and play media. JavaScript controls these elements (play, pause, seeking, etc.). The pressure gauge could be related to the number or complexity of active media decoders.
    * **WebRTC (Real-Time Communication):**  Uses codecs for audio and video streams. JavaScript APIs manage WebRTC connections. High usage could contribute to pressure.
    * **Canvas API (less directly):** While not directly codec-related, complex canvas animations *could* indirectly interact if they involve video processing.
    * **Media Source Extensions (MSE):** Allows JavaScript to feed media data to the HTML media elements. This gives JavaScript direct control over codec usage.
    * **WebCodecs API:** This is the most direct link! The file is located within the `webcodecs` module. This API gives JavaScript explicit control over encoding and decoding media.

7. **Provide Examples:**  Illustrate the connections with concrete scenarios:
    * JavaScript creating multiple `VideoDecoder` instances.
    * HTML page with several `<video>` elements playing high-resolution videos.
    * CSS animations or transitions that might indirectly trigger video decoding or rendering.

8. **Infer Logic and Assumptions:**  For each test, consider the input (e.g., registering a callback, incrementing pressure) and the expected output (callback being called, pressure value).

9. **Identify Potential Usage Errors:** Think about how a developer might misuse this:
    * Registering callbacks and forgetting to unregister them (potential memory leaks or unexpected behavior).
    * Incorrectly estimating the pressure associated with a codec when unregistering.

10. **Trace User Actions:** Imagine the user interactions that could lead to the codec pressure gauge being used:
    * Opening a web page with video content.
    * Starting a WebRTC call.
    * Using a web application that utilizes the WebCodecs API for custom media processing.

By following these steps, you can systematically analyze the code and derive a comprehensive understanding of its functionality, its relation to web technologies, and potential issues. The key is to combine code analysis with knowledge of web browser architecture and common web development patterns.
这个文件 `codec_pressure_gauge_test.cc` 是 Chromium Blink 引擎中 `CodecPressureGauge` 类的单元测试文件。它的主要功能是 **验证 `CodecPressureGauge` 类的各种行为和功能是否正常工作**。

让我们详细列举一下它的功能，并解释它与 JavaScript、HTML、CSS 的关系，以及逻辑推理、用户错误和调试线索：

**1. 功能列举:**

* **测试压力阈值的设置和获取:** 验证是否可以正确设置和获取全局的编解码器压力阈值 (`kTestPressureThreshold`)。
* **测试压力值的增加和减少:** 验证 `Increment()` 和 `Decrement()` 方法是否能正确增加和减少全局压力值。
* **测试压力超过阈值的检测:** 验证 `is_global_pressure_exceeded_for_testing()` 方法是否能在全局压力超过阈值时返回 `true`。
* **测试注册和注销压力变化回调:** 验证 `RegisterPressureCallback()` 和 `UnregisterPressureCallback()` 方法是否能正确地注册和注销回调函数，并在压力状态发生变化时调用这些回调。
* **测试回调函数的触发:** 验证当全局压力超过或低于阈值时，注册的回调函数是否会被正确触发，并传递正确的压力状态（`true` 表示超过，`false` 表示低于）。
* **测试注销回调时释放压力:** 验证在注销回调时，可以指定释放与该回调关联的压力值，并且全局压力值会相应更新。
* **测试解码器和编码器是否共享压力计 (取决于平台):**  验证解码器和编码器是否使用同一个 `CodecPressureGauge` 实例来跟踪压力。这在不同操作系统上可能有不同的实现。
* **测试零阈值情况:** 验证当压力阈值设置为 0 时，压力变化回调是否能正确触发。
* **参数化测试:** 使用 `testing::TestWithParam` 来对不同的 `ReclaimableCodec::CodecType` (例如 `kDecoder` 和 `kEncoder`) 运行相同的测试用例，确保压力计对不同类型的编解码器都能正常工作。

**2. 与 JavaScript, HTML, CSS 的关系:**

虽然这个测试文件是用 C++ 编写的，并且直接测试的是 Blink 引擎的内部组件，但 `CodecPressureGauge` 的存在是为了管理与 WebCodecs API 相关的资源压力。WebCodecs API 是一个 JavaScript API，允许网页开发者访问浏览器的底层编解码器。

* **JavaScript:**  JavaScript 代码通过 WebCodecs API (例如 `VideoDecoder`, `AudioDecoder`, `VideoEncoder`, `AudioEncoder`) 来使用浏览器的编解码器。`CodecPressureGauge` 追踪这些编解码器实例的资源消耗。当 JavaScript 代码创建过多的编解码器实例或者解码/编码高负载的媒体时，`CodecPressureGauge` 会记录压力增加。
    * **示例:**  一个 JavaScript 应用可能同时创建多个 `VideoDecoder` 实例来处理不同的视频流。每个 `VideoDecoder` 的创建和使用都可能增加 `CodecPressureGauge` 的压力值。

* **HTML:** HTML 中的 `<video>` 和 `<audio>` 元素在播放媒体时也会使用浏览器的编解码器。虽然 `<video>` 和 `<audio>` 元素的控制主要通过 JavaScript 实现，但它们底层的解码过程会受到 `CodecPressureGauge` 的影响。
    * **示例:** 一个 HTML 页面包含多个 `<video>` 标签，并且同时播放高分辨率的视频。这会导致多个解码器同时工作，增加 `CodecPressureGauge` 的压力。

* **CSS:** CSS 本身不直接与 `CodecPressureGauge` 交互。然而，复杂的 CSS 动画或转换可能会间接地影响性能，导致 JavaScript 需要更频繁地更新或处理媒体，从而间接影响编解码器的使用和 `CodecPressureGauge` 的压力。

**3. 逻辑推理 (假设输入与输出):**

假设我们运行 `TEST_P(CodecPressureGaugeTest, IncrementDecrement)` 这个测试用例：

* **假设输入:**
    * 初始化时全局压力为 0。
    * 注册一个空的压力变化回调 (不期望被触发)。
    * 循环调用 `Increment()` 方法 `kTestPressureThreshold` (假设为 5) 次。
    * 循环调用 `Decrement()` 方法 `kTestPressureThreshold` 次。
* **预期输出:**
    * 每次 `Increment()` 调用后，全局压力值递增 1，直到达到 `kTestPressureThreshold`。
    * 每次 `Decrement()` 调用后，全局压力值递减 1，直到回到 0。
    * 注册的回调函数不会被调用，因为压力一直低于或等于阈值。

**4. 用户或编程常见的使用错误:**

`CodecPressureGauge` 主要是在 Blink 引擎内部使用，开发者通常不会直接与之交互。然而，与 WebCodecs API 相关的编程错误可能会导致压力增加，从而触发 `CodecPressureGauge` 的机制。

* **错误示例 1 (JavaScript):**  JavaScript 代码创建了大量的 `VideoDecoder` 实例，但没有正确地 `close()` 它们。这会导致资源泄漏，`CodecPressureGauge` 的压力会持续上升，最终可能影响性能。
    * **用户操作:** 用户打开一个使用 WebCodecs API 的网页，该网页存在上述错误。

* **错误示例 2 (JavaScript):** JavaScript 代码在一个非常快的循环中创建和销毁 `VideoDecoder` 实例，导致频繁的资源分配和释放，可能触发压力阈值。
    * **用户操作:** 用户与一个动态生成和销毁视频流的应用进行交互。

**5. 用户操作如何一步步到达这里 (作为调试线索):**

当在 Chromium 中调试与 WebCodecs 或媒体相关的问题时，`CodecPressureGauge` 的状态可以提供有用的线索。以下是一个可能的调试场景：

1. **用户操作:** 用户在浏览器中打开一个包含视频播放的网页。
2. **浏览器行为:** 浏览器解析 HTML，加载 JavaScript 代码。
3. **JavaScript 执行:** JavaScript 代码可能使用 `<video>` 元素或者 WebCodecs API 来解码视频流。
4. **Blink 引擎内部:** 当创建或使用解码器时，`CodecPressureGauge` 的压力值可能会增加。
5. **问题出现:** 用户可能遇到视频播放卡顿、性能下降等问题。
6. **开发者调试:** 开发者可能会使用 Chromium 的开发者工具或其他调试手段来调查性能问题。
7. **`CodecPressureGauge` 作为线索:**
    * 开发者可能会查看 `CodecPressureGauge` 的全局压力值，如果发现压力值异常高，这可能表明存在过多的解码器实例或解码任务。
    * 开发者可以检查压力变化回调的触发情况，了解压力何时以及为何会超过阈值。
    * 通过查看 `CodecPressureGaugeTest` 中的测试用例，开发者可以更好地理解 `CodecPressureGauge` 的工作原理和预期行为，从而更好地诊断问题。

**总结:**

`codec_pressure_gauge_test.cc` 通过一系列单元测试，确保 `CodecPressureGauge` 能够正确地跟踪和管理编解码器相关的资源压力。虽然用户不会直接操作这个 C++ 类，但它在幕后默默地工作，帮助浏览器管理资源，避免因过度使用编解码器而导致性能问题。理解这个测试文件有助于开发者理解 Blink 引擎如何处理媒体资源管理，并为调试 WebCodecs 相关问题提供有价值的线索。

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/codec_pressure_gauge_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_gauge.h"

#include "base/test/bind.h"
#include "base/test/mock_callback.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/modules/webcodecs/reclaimable_codec.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"

using testing::_;

namespace blink {

namespace {

constexpr size_t kTestPressureThreshold = 5;

using MockPressureChangeCallback =
    base::MockCallback<CodecPressureGauge::PressureThresholdChangedCallback>;

}  // namespace

class CodecPressureGaugeTest
    : public testing::TestWithParam<ReclaimableCodec::CodecType> {
 public:
  using RegistrationResult = CodecPressureGauge::RegistrationResult;

  CodecPressureGaugeTest() {
    PressureGauge().set_pressure_threshold_for_testing(kTestPressureThreshold);
  }

  ~CodecPressureGaugeTest() override = default;

  CodecPressureGauge& PressureGauge() {
    return CodecPressureGauge::GetInstance(GetParam());
  }
};

TEST_P(CodecPressureGaugeTest, DefaultState) {
  // Sanity check.
  EXPECT_EQ(0u, PressureGauge().global_pressure_for_testing());
  EXPECT_FALSE(PressureGauge().is_global_pressure_exceeded_for_testing());
}

TEST_P(CodecPressureGaugeTest, GaugeIsSharedForDecodersEncoders) {
  // Sanity check.
  bool gauge_is_shared =
      &CodecPressureGauge::GetInstance(ReclaimableCodec::CodecType::kDecoder) ==
      &CodecPressureGauge::GetInstance(ReclaimableCodec::CodecType::kEncoder);

#if BUILDFLAG(IS_WIN)
  EXPECT_FALSE(gauge_is_shared);
#else
  EXPECT_TRUE(gauge_is_shared);
#endif
}

TEST_P(CodecPressureGaugeTest, RegisterUnregisterCallbacks) {
  MockPressureChangeCallback callback;

  RegistrationResult result_a =
      PressureGauge().RegisterPressureCallback(callback.Get());
  RegistrationResult result_b =
      PressureGauge().RegisterPressureCallback(callback.Get());

  // Callbacks should have different IDs.
  EXPECT_NE(result_a.first, result_b.first);

  // We should not have exceeded global pressure.
  EXPECT_FALSE(result_a.second);
  EXPECT_FALSE(result_b.second);

  PressureGauge().UnregisterPressureCallback(result_a.first, 0);
  PressureGauge().UnregisterPressureCallback(result_b.first, 0);
}

TEST_P(CodecPressureGaugeTest, IncrementDecrement) {
  MockPressureChangeCallback callback;
  EXPECT_CALL(callback, Run(_)).Times(0);

  RegistrationResult result =
      PressureGauge().RegisterPressureCallback(callback.Get());

  for (size_t i = 1u; i <= kTestPressureThreshold; ++i) {
    PressureGauge().Increment();
    EXPECT_EQ(i, PressureGauge().global_pressure_for_testing());
  }

  for (size_t i = kTestPressureThreshold; i > 0; --i) {
    PressureGauge().Decrement();
    EXPECT_EQ(i - 1u, PressureGauge().global_pressure_for_testing());
  }

  // Test cleanup.
  PressureGauge().UnregisterPressureCallback(result.first, 0);
}

TEST_P(CodecPressureGaugeTest, UnregisterAllLeftoverPressure) {
  MockPressureChangeCallback callback;

  RegistrationResult result =
      PressureGauge().RegisterPressureCallback(callback.Get());

  // Increase pressure up to the threshold.
  for (size_t i = 0; i < kTestPressureThreshold; ++i)
    PressureGauge().Increment();

  EXPECT_EQ(kTestPressureThreshold,
            PressureGauge().global_pressure_for_testing());

  // Releasing all pressure should reset global pressure.
  PressureGauge().UnregisterPressureCallback(result.first,
                                             kTestPressureThreshold);

  EXPECT_EQ(0u, PressureGauge().global_pressure_for_testing());
}

TEST_P(CodecPressureGaugeTest, UnregisterPartialLeftoverPressure) {
  MockPressureChangeCallback callback;

  RegistrationResult result =
      PressureGauge().RegisterPressureCallback(callback.Get());

  RegistrationResult other_result =
      PressureGauge().RegisterPressureCallback(callback.Get());

  // Increase pressure up to the threshold.
  for (size_t i = 0; i < kTestPressureThreshold; ++i)
    PressureGauge().Increment();

  constexpr size_t kPartialPressure = 3;

  EXPECT_EQ(kTestPressureThreshold,
            PressureGauge().global_pressure_for_testing());

  // Releasing partial pressure should properly update global pressure.
  PressureGauge().UnregisterPressureCallback(result.first, kPartialPressure);

  EXPECT_EQ(kTestPressureThreshold - kPartialPressure,
            PressureGauge().global_pressure_for_testing());

  // Test cleanup
  PressureGauge().UnregisterPressureCallback(
      other_result.first, PressureGauge().global_pressure_for_testing());
}

TEST_P(CodecPressureGaugeTest, ExceedingThresholdRunsCallbacks) {
  MockPressureChangeCallback callback;
  MockPressureChangeCallback other_callback;
  EXPECT_CALL(callback, Run(true));
  EXPECT_CALL(other_callback, Run(true));

  RegistrationResult result =
      PressureGauge().RegisterPressureCallback(callback.Get());

  RegistrationResult other_result =
      PressureGauge().RegisterPressureCallback(other_callback.Get());

  for (size_t i = 0; i < kTestPressureThreshold; ++i)
    PressureGauge().Increment();

  // We should be at the limit, but not over it.
  EXPECT_FALSE(PressureGauge().is_global_pressure_exceeded_for_testing());

  // Pass over the threshold.
  PressureGauge().Increment();

  EXPECT_TRUE(PressureGauge().is_global_pressure_exceeded_for_testing());

  testing::Mock::VerifyAndClearExpectations(&callback);
  testing::Mock::VerifyAndClearExpectations(&other_callback);

  // Test cleanup
  PressureGauge().UnregisterPressureCallback(
      result.first, PressureGauge().global_pressure_for_testing());
  PressureGauge().UnregisterPressureCallback(other_result.first, 0);
}

TEST_P(CodecPressureGaugeTest, PassingUnderThresholdRunsCallbacks_Decrement) {
  MockPressureChangeCallback callback;
  MockPressureChangeCallback other_callback;
  EXPECT_CALL(other_callback, Run(false));

  RegistrationResult result =
      PressureGauge().RegisterPressureCallback(callback.Get());

  // Make sure we are above the threshold.
  for (size_t i = 0; i < kTestPressureThreshold + 1; ++i)
    PressureGauge().Increment();

  RegistrationResult other_result =
      PressureGauge().RegisterPressureCallback(other_callback.Get());

  // Make the results match the expected global threshold.
  EXPECT_TRUE(PressureGauge().is_global_pressure_exceeded_for_testing());
  EXPECT_TRUE(other_result.second);

  // Reset expectations.
  testing::Mock::VerifyAndClearExpectations(&callback);
  EXPECT_CALL(callback, Run(false));

  // Pass under the global threshold via a call to Decrement().
  PressureGauge().Decrement();

  EXPECT_FALSE(PressureGauge().is_global_pressure_exceeded_for_testing());

  testing::Mock::VerifyAndClearExpectations(&other_callback);

  // Test cleanup
  PressureGauge().UnregisterPressureCallback(
      result.first, PressureGauge().global_pressure_for_testing());
  PressureGauge().UnregisterPressureCallback(other_result.first, 0);
}

TEST_P(CodecPressureGaugeTest, PassingUnderThresholdRunsCallbacks_Unregister) {
  MockPressureChangeCallback callback;
  MockPressureChangeCallback other_callback;
  EXPECT_CALL(other_callback, Run(false));

  RegistrationResult result =
      PressureGauge().RegisterPressureCallback(callback.Get());

  // Make sure we are above the threshold.
  for (size_t i = 0; i < kTestPressureThreshold + 1; ++i)
    PressureGauge().Increment();

  RegistrationResult other_result =
      PressureGauge().RegisterPressureCallback(other_callback.Get());

  // Make the results match the expected global threshold.
  EXPECT_TRUE(PressureGauge().is_global_pressure_exceeded_for_testing());
  EXPECT_TRUE(other_result.second);

  // Pass under the global threshold unregistering.
  constexpr size_t kPartialPressure = 3;
  PressureGauge().UnregisterPressureCallback(result.first, kPartialPressure);

  EXPECT_FALSE(PressureGauge().is_global_pressure_exceeded_for_testing());

  testing::Mock::VerifyAndClearExpectations(&other_callback);

  // Test cleanup.
  PressureGauge().UnregisterPressureCallback(
      other_result.first, PressureGauge().global_pressure_for_testing());
}

TEST_P(CodecPressureGaugeTest, RepeatedlyCrossingThresholds) {
  size_t number_of_exceeds_calls = 0u;
  size_t number_of_receeds_calls = 0u;

  auto pressure_cb = [&](bool pressure_exceeded) {
    if (pressure_exceeded)
      ++number_of_exceeds_calls;
    else
      ++number_of_receeds_calls;
  };

  RegistrationResult result = PressureGauge().RegisterPressureCallback(
      base::BindLambdaForTesting(pressure_cb));

  // Make sure we at the threshold.
  for (size_t i = 0; i < kTestPressureThreshold; ++i)
    PressureGauge().Increment();

  EXPECT_EQ(0u, number_of_exceeds_calls);
  EXPECT_EQ(0u, number_of_receeds_calls);

  constexpr size_t kNumberOfCrossings = 3;

  // Go back and forth across the threshold.
  for (size_t i = 1; i <= kNumberOfCrossings; ++i) {
    PressureGauge().Increment();
    EXPECT_EQ(i, number_of_exceeds_calls);
    PressureGauge().Decrement();
    EXPECT_EQ(i, number_of_receeds_calls);
  }

  // Test cleanup.
  PressureGauge().UnregisterPressureCallback(
      result.first, PressureGauge().global_pressure_for_testing());
}

TEST_P(CodecPressureGaugeTest, ZeroThreshold) {
  constexpr size_t kZeroPressureThreshold = 0u;
  PressureGauge().set_pressure_threshold_for_testing(kZeroPressureThreshold);

  MockPressureChangeCallback callback;
  EXPECT_CALL(callback, Run(true));
  EXPECT_CALL(callback, Run(false));

  RegistrationResult result =
      PressureGauge().RegisterPressureCallback(callback.Get());

  PressureGauge().Increment();
  PressureGauge().Decrement();

  // Test cleanup.
  PressureGauge().UnregisterPressureCallback(result.first, 0);
  PressureGauge().set_pressure_threshold_for_testing(kTestPressureThreshold);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    CodecPressureGaugeTest,
    testing::Values(ReclaimableCodec::CodecType::kDecoder,
                    ReclaimableCodec::CodecType::kEncoder));

}  // namespace blink
```