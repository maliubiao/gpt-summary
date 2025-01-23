Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request is to analyze the given C++ test file, `reclaimable_codec_test.cc`, focusing on its functionality, connections to web technologies, logic, potential errors, and debugging context.

2. **Initial Scan and Identification of Key Components:**
   - The filename itself, `reclaimable_codec_test.cc`, immediately suggests it's a unit test for something called `ReclaimableCodec`.
   - The `#include` statements reveal dependencies:
     - `reclaimable_codec.h`:  The core class being tested.
     - `base/test/...`:  Testing utilities from the Chromium base library.
     - `media/base/test_helpers.h`:  Media-related testing tools (suggests WebCodecs deals with media).
     - `testing/gmock/...` and `testing/gtest/...`:  Google Test and Mocking frameworks.
     - `third_party/blink/...`:  Indicates this is within the Blink rendering engine.
     - `bindings/core/v8/...`: Interaction with V8, JavaScript engine.
     - `modules/webcodecs/...`:  Confirms the context is WebCodecs.
     - `platform/heap/...`:  Garbage collection is involved.
     - `platform/testing/...`: More Blink-specific testing tools.

3. **Focus on the Tested Class:** The core is `ReclaimableCodec`. The test file provides a mock implementation, `FakeReclaimableCodec`, which is crucial for understanding how the real class is intended to behave.

4. **Analyze `FakeReclaimableCodec`:**
   - Constructor takes `CodecType` and `ExecutionContext`. This hints at different types of codecs and their association with a browsing context.
   - `SimulateActivity()`: Marks the codec as active and not reclaimed.
   - `SimulateReset()`: Releases codec pressure.
   - `SimulatePressureExceeded()`: Applies pressure and sets a global flag.
   - `OnCodecReclaimed()`: Sets a flag when the codec is reclaimed.
   - `is_global_pressure_exceeded()`:  Checks the global pressure flag.
   - `reclaimed()`:  Checks if the codec has been reclaimed.
   - `ContextDestroyed()`:  A lifecycle method (empty in the mock).

5. **Examine the Test Structure (`ReclaimableCodecTest`):**
   - It's a parameterized test (`testing::TestWithParam`) based on `ReclaimableCodec::CodecType` (Decoder/Encoder).
   - `CreateCodec()`:  Creates instances of `FakeReclaimableCodec`. It also manages setting a pressure threshold for the `CodecPressureGauge`.

6. **Analyze Individual Test Cases:**  This is where the core logic is verified. Look for patterns and what's being asserted:
   - **`BackgroundInactivityTimerStartStops`:**  Focuses on when the inactivity timer starts and stops in a backgrounded state. Key interactions: `SimulateLifecycleStateForTesting(kHidden)`, `SimulatePressureExceeded()`, `SimulateActivity()`, `SimulateReset()`, and assertions on `IsReclamationTimerActiveForTesting()`.
   - **`BackgroundInactivityTimerWorks`:**  Verifies the timer's functionality using a `SimpleTestTickClock`. It checks if the codec is reclaimed after a certain period of inactivity in the background *after* pressure is applied. Crucially, it simulates the timer firing (`SimulateActivityTimerFiredForTesting()`).
   - **`ForegroundInactivityTimerNeverStarts`:** Checks that the timer doesn't start when the page is in the foreground, even with pressure.
   - **`ForegroundCodecReclaimedOnceBackgrounded`:** Demonstrates that a codec in the foreground isn't reclaimed until it's backgrounded *and* the inactivity timer expires.
   - **`RepeatLifecycleEventsDontBreakState`:** Ensures that sending duplicate lifecycle events (e.g., multiple "foreground" events) doesn't break the state machine of the codec.
   - **`PressureChangesUpdateTimer`:**  Tests how changes in codec-specific pressure and global pressure affect the inactivity timer.

7. **Identify Connections to Web Technologies:**
   - **JavaScript:**  The use of `ExecutionContext` and V8 testing scopes strongly suggests that `ReclaimableCodec` instances are managed within a JavaScript context. WebCodecs are accessed via JavaScript APIs.
   - **HTML:**  The lifecycle states (foreground/background) are tied to the visibility of HTML documents/tabs.
   - **CSS:** While not directly apparent, CSS can influence backgrounding behavior through animations or other resource-intensive operations.

8. **Infer Logic and Assumptions:**
   - **Assumption:** Codecs consume resources. Reclaiming them saves resources when they're not actively used, especially in background tabs.
   - **Logic:**  Reclamation is triggered by a combination of being in the background, global memory pressure, and inactivity. There's a timer mechanism involved.

9. **Consider User/Programming Errors:**
   - **User:** A user might experience unexpected pausing or interruptions in media playback if codecs are prematurely reclaimed.
   - **Programmer:** A developer might incorrectly manage codec instances, leading to unexpected reclamation or memory leaks if not properly handled.

10. **Trace User Operations:**  Think about how a user interacts with a web page that uses WebCodecs:
    - Opening a page with video or audio.
    - Switching tabs (leading to backgrounding).
    - Minimizing the browser window.
    - Extended periods of inactivity on a page with media.

11. **Structure the Explanation:**  Organize the findings logically, addressing each part of the original request. Start with the core functionality, then move to connections to web technologies, logic, errors, and debugging. Use clear and concise language. Provide concrete examples where possible.

**Self-Correction/Refinement During the Process:**

- **Initial Thought:**  Maybe this is purely about memory management.
- **Correction:** The interaction with lifecycle states (`kHidden`, `kNotThrottled`) and the timer mechanism points to a more nuanced approach related to background tab management and resource optimization.
- **Initial Thought:**  The tests are just about starting and stopping the timer.
- **Refinement:**  The tests also cover the conditions under which the timer *should* start and stop, the impact of foreground/background states, and the role of pressure.
- **Initial Thought:**  How does this relate to the actual WebCodecs API?
- **Refinement:** While this is a *unit* test, it provides valuable insight into the internal workings and the intended behavior of the `ReclaimableCodec` class, which is a building block for the actual WebCodecs implementation. The `CodecType` parameter hints at different parts of the WebCodecs API (encoders/decoders).

By following these steps, iterating through the code, and constantly asking "what is this trying to test?" we arrive at a comprehensive understanding of the `reclaimable_codec_test.cc` file.
这个文件 `reclaimable_codec_test.cc` 是 Chromium Blink 引擎中 `webcodecs` 模块的测试文件。它的主要功能是测试 `ReclaimableCodec` 类的行为和逻辑。`ReclaimableCodec` 是一个用于管理 WebCodecs (例如 `VideoDecoder`, `AudioDecoder`, `VideoEncoder`, `AudioEncoder`) 实例的基类，其核心目标是在系统资源紧张时回收不再活跃的编解码器实例，以节省内存和 CPU 资源。

下面我们来详细列举其功能，并分析与 JavaScript, HTML, CSS 的关系，逻辑推理，常见错误和调试线索：

**1. 功能列举:**

* **测试编解码器回收机制:**  核心功能是测试 `ReclaimableCodec` 在不同场景下是否正确启动和停止回收计时器，以及是否在预期的时间点回收编解码器实例。
* **模拟编解码器的活动状态:** 使用 `FakeReclaimableCodec` 模拟编解码器的活动 (`SimulateActivity()`) 和非活动状态。
* **模拟内存压力:** 使用 `CodecPressureGauge` 和 `SetGlobalPressureExceededFlag` 模拟全局内存压力状态。
* **模拟页面生命周期状态:** 使用 `SimulateLifecycleStateForTesting` 模拟页面进入前台 (`kNotThrottled`) 和后台 (`kHidden`, `kThrottled`, `kStopped`) 等不同生命周期状态。
* **测试后台非活动回收:** 测试当页面进入后台且编解码器长时间不活动时，是否会被回收。
* **测试前台不回收:** 测试当页面处于前台时，即使编解码器不活动，也不会被回收。
* **测试内存压力对回收的影响:** 测试只有在内存压力达到一定阈值时，后台非活动的编解码器才会被回收。
* **测试重复生命周期事件的影响:**  确保重复的生命周期事件不会导致 `ReclaimableCodec` 状态异常。
* **测试编解码器自身压力变化的影响:** 测试编解码器自身报告压力 (例如，因为缓冲积压) 和全局压力变化如何影响回收计时器。

**2. 与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * **WebCodecs API:** `ReclaimableCodec` 是 WebCodecs API 实现的基础。JavaScript 代码通过 WebCodecs API (例如 `new VideoDecoder({...})`) 创建编解码器实例。当系统资源紧张时，Blink 引擎会根据 `ReclaimableCodec` 的逻辑回收这些由 JavaScript 创建的编解码器实例。
    * **事件通知:** 当编解码器被回收时，`OnCodecReclaimed` 方法会被调用。虽然在这个测试中 `OnCodecReclaimed` 只是简单地设置了一个标志，但在实际应用中，可能会触发 JavaScript 可监听的事件，告知开发者编解码器被回收，需要进行相应的处理 (例如，释放对编解码器的引用，重新创建编解码器等)。
    * **`ExecutionContext`:**  `ReclaimableCodec` 的构造函数接收 `ExecutionContext` 参数，这代表了 JavaScript 的执行上下文。

    **举例说明:**
    ```javascript
    // JavaScript 代码创建 VideoDecoder
    const decoder = new VideoDecoder({
      output: (frame) => { /* 处理解码后的帧 */ },
      error: (e) => { console.error("解码错误", e); }
    });

    // ... 稍后，当页面进入后台且系统内存紧张时，
    // Blink 引擎的 ReclaimableCodec 可能会回收这个 decoder 实例。
    // 如果有相应的事件监听，JavaScript 可以收到通知。
    ```

* **HTML:**
    * **页面可见性:** `ReclaimableCodec` 的回收机制与 HTML 页面的可见性状态密切相关。当 HTML 页面不可见 (例如，标签页被隐藏或最小化) 时，`ReclaimableCodec` 会更容易启动回收计时器。`scheduler::SchedulingLifecycleState::kHidden` 就对应着页面被隐藏的状态。

    **举例说明:**
    用户切换标签页，将包含正在使用 WebCodecs 的页面切换到后台，此时 `ReclaimableCodec` 可能会启动回收计时器。

* **CSS:**
    * **资源消耗:** 虽然 CSS 本身不直接控制 `ReclaimableCodec` 的行为，但复杂的 CSS 可能会导致页面渲染和资源消耗增加，间接加剧系统内存压力，从而更容易触发 `ReclaimableCodec` 的回收机制。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入:**
    * 编解码器类型: `ReclaimableCodec::CodecType::kDecoder`
    * 页面状态: 后台 (`scheduler::SchedulingLifecycleState::kHidden`)
    * 全局内存压力: 已超过阈值 (`SetGlobalPressureExceededFlag(true)`)
    * 编解码器活动状态:  一段时间内未调用 `SimulateActivity()`
* **预期输出:**
    * `IsReclamationTimerActiveForTesting()` 为 `true` (回收计时器已启动)
    * 经过 `ReclaimableCodec::kInactivityReclamationThreshold` 时间后，`reclaimed()` 为 `true` (编解码器被回收)

* **假设输入:**
    * 编解码器类型: `ReclaimableCodec::CodecType::kEncoder`
    * 页面状态: 前台 (`scheduler::SchedulingLifecycleState::kNotThrottled`)
    * 全局内存压力: 已超过阈值 (`SetGlobalPressureExceededFlag(true)`)
    * 编解码器活动状态:  长时间未调用 `SimulateActivity()`
* **预期输出:**
    * `IsReclamationTimerActiveForTesting()` 为 `false` (回收计时器未启动)
    * `reclaimed()` 为 `false` (编解码器不会被回收)

**4. 用户或编程常见的使用错误:**

* **用户错误:**
    * **长时间在后台运行消耗资源的 Web 应用:** 用户可能在后台打开了多个包含复杂 WebCodecs 应用的标签页，这些标签页即使在后台也可能消耗大量资源。虽然 `ReclaimableCodec` 会尝试回收资源，但如果用户打开过多此类页面，仍然可能导致设备性能下降。
* **编程错误:**
    * **未正确管理编解码器生命周期:** 开发者可能在不再需要编解码器时没有及时释放它们，导致资源浪费。`ReclaimableCodec` 可以作为一种补救机制，但最佳实践仍然是在代码层面进行精细的资源管理。
    * **假设编解码器始终可用:** 开发者可能没有考虑到编解码器可能被系统回收的情况，导致在编解码器被回收后尝试访问它而引发错误。需要监听相关的事件 (如果实现) 或者在必要时重新创建编解码器实例。
    * **过度依赖自动回收:**  开发者不应该完全依赖 `ReclaimableCodec` 进行资源管理，而应该主动优化代码，减少不必要的资源占用。

**5. 用户操作如何一步步到达这里，作为调试线索:**

1. **用户打开一个使用了 WebCodecs 的网页:** 例如，一个在线视频编辑器，一个实时的音视频会议应用，或者一个需要进行视频解码的网页游戏。
2. **网页创建了 `VideoDecoder` 或 `AudioDecoder` 等编解码器实例:**  JavaScript 代码调用 WebCodecs API 创建了这些对象。
3. **用户切换到另一个标签页或最小化浏览器窗口:** 这会导致包含 WebCodecs 的页面进入后台状态 (`scheduler::SchedulingLifecycleState::kHidden`)。
4. **系统检测到内存压力较高:**  其他应用也在消耗内存，或者设备本身内存较小。
5. **`ReclaimableCodec` 检测到编解码器实例在后台并且一段时间内不活跃:**  例如，视频播放被暂停，或者音频流停止传输。
6. **`ReclaimableCodec` 启动回收计时器:**  符合后台、非活动和内存压力高的条件。
7. **计时器到期:**  如果在计时器运行期间，编解码器仍然不活跃。
8. **`ReclaimableCodec` 调用 `OnCodecReclaimed` 方法:**  标志着编解码器实例被回收。

**调试线索:**

* **性能监控工具:**  使用 Chrome 的性能监控工具 (Performance tab) 可以观察内存使用情况，以及是否有频繁的垃圾回收事件发生，这可能与 `ReclaimableCodec` 的回收行为有关。
* **`chrome://webrtc-internals`:**  如果涉及到音视频编解码，`chrome://webrtc-internals` 可以提供关于编解码器实例的信息，包括其创建和销毁时间，以及相关的统计数据。
* **Blink 渲染器日志:**  通过开启 Blink 渲染器的详细日志，可以查看 `ReclaimableCodec` 的相关日志输出，了解其何时启动和停止计时器，以及何时回收编解码器。
* **断点调试:**  在 `reclaimable_codec.cc` 文件中设置断点，可以逐步跟踪 `ReclaimableCodec` 的执行流程，查看其状态变化和决策过程。
* **审查 JavaScript 代码:**  检查 JavaScript 代码中是否正确管理了 WebCodecs 对象的生命周期，以及是否处理了可能发生的编解码器回收事件。

总而言之，`reclaimable_codec_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎能够有效地管理 WebCodecs 资源，在不影响用户体验的前提下，回收不再活跃的编解码器，从而优化内存使用和系统性能。理解这个文件的功能和测试逻辑，对于理解 WebCodecs 的内部工作原理以及进行相关的开发和调试非常有帮助。

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/reclaimable_codec_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/reclaimable_codec.h"

#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "media/base/test_helpers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_gauge.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

// Set a high theshold, so we can fake pressure threshold notifications.
static constexpr size_t kTestPressureThreshold = 100;

namespace {

constexpr base::TimeDelta kTimerPeriod =
    ReclaimableCodec::kInactivityReclamationThreshold / 2;

class FakeReclaimableCodec final
    : public GarbageCollected<FakeReclaimableCodec>,
      public ReclaimableCodec {
 public:
  FakeReclaimableCodec(ReclaimableCodec::CodecType type,
                       ExecutionContext* context)
      : ReclaimableCodec(type, context) {}

  void SimulateActivity() {
    MarkCodecActive();
    reclaimed_ = false;
  }

  void SimulateReset() { ReleaseCodecPressure(); }

  void SimulatePressureExceeded() {
    ApplyCodecPressure();
    SetGlobalPressureExceededFlag(true);
  }

  void OnCodecReclaimed(DOMException* ex) final { reclaimed_ = true; }

  bool is_global_pressure_exceeded() {
    return global_pressure_exceeded_for_testing();
  }

  // GarbageCollected override.
  void Trace(Visitor* visitor) const override {
    ReclaimableCodec::Trace(visitor);
  }

  bool reclaimed() const { return reclaimed_; }

 private:
  // ContextLifecycleObserver override.
  void ContextDestroyed() override {}

  bool reclaimed_ = false;
};

}  // namespace

class ReclaimableCodecTest
    : public testing::TestWithParam<ReclaimableCodec::CodecType> {
 public:
  FakeReclaimableCodec* CreateCodec(ExecutionContext* context) {
    if (!is_gauge_threshold_set_) {
      CodecPressureGauge::GetInstance(GetParam())
          .set_pressure_threshold_for_testing(kTestPressureThreshold);

      is_gauge_threshold_set_ = true;
    }

    return MakeGarbageCollected<FakeReclaimableCodec>(GetParam(), context);
  }

 private:
  bool is_gauge_threshold_set_ = false;
  test::TaskEnvironment task_environment_;
};

void TestBackgroundInactivityTimerStartStops(FakeReclaimableCodec* codec) {
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kHidden);

  // Codecs should not be reclaimable for inactivity until pressure is exceeded.
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  codec->SimulateReset();
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  // Exceeding pressure should start the timer.
  codec->SimulatePressureExceeded();
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());

  // Activity should not stop the timer.
  codec->SimulateActivity();
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());

  // The timer should be stopped when asked.
  codec->SimulateReset();
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  // It should be possible to restart the timer after stopping it.
  codec->SimulatePressureExceeded();
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
}

void TestBackgroundInactivityTimerWorks(FakeReclaimableCodec* codec) {
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kHidden);

  // Codecs should not be reclaimable for inactivity until pressure is exceeded.
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  base::SimpleTestTickClock tick_clock;
  codec->set_tick_clock_for_testing(&tick_clock);

  // Exceeding pressure should start the timer.
  codec->SimulatePressureExceeded();
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->reclaimed());

  // Fire when codec is fresh to ensure first tick isn't treated as idle.
  codec->SimulateActivity();
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_FALSE(codec->reclaimed());

  // One timer period should not be enough to reclaim the codec.
  tick_clock.Advance(kTimerPeriod);
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_FALSE(codec->reclaimed());

  // Advancing an additional timer period should be enough to trigger
  // reclamation.
  tick_clock.Advance(kTimerPeriod);
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_TRUE(codec->reclaimed());

  // Restore default tick clock since |codec| is a garbage collected object that
  // may outlive the scope of this function.
  codec->set_tick_clock_for_testing(base::DefaultTickClock::GetInstance());
}

TEST_P(ReclaimableCodecTest, BackgroundInactivityTimerStartStops) {
  V8TestingScope v8_scope;

  // Only background reclamation permitted, so simulate backgrouding.
  TestBackgroundInactivityTimerStartStops(
      CreateCodec(v8_scope.GetExecutionContext()));
}

TEST_P(ReclaimableCodecTest, BackgroundInactivityTimerWorks) {
  V8TestingScope v8_scope;

  // Only background reclamation permitted, so simulate backgrouding.
  TestBackgroundInactivityTimerWorks(
      CreateCodec(v8_scope.GetExecutionContext()));
}

TEST_P(ReclaimableCodecTest, ForegroundInactivityTimerNeverStarts) {
  V8TestingScope v8_scope;

  auto* codec = CreateCodec(v8_scope.GetExecutionContext());

  // Test codec should start in foreground when kOnlyReclaimBackgroundWebCodecs
  // enabled.
  EXPECT_FALSE(codec->is_backgrounded_for_testing());

  // Codecs should not be reclaimable for inactivity until pressure is exceeded.
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  base::SimpleTestTickClock tick_clock;
  codec->set_tick_clock_for_testing(&tick_clock);

  // Exceeded pressure should not start timer while we remain in foreground.
  codec->SimulatePressureExceeded();
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // First activity should not start timer while we remain in foreground.
  codec->SimulateActivity();
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Advancing time by any amount shouldn't change the above.
  tick_clock.Advance(kTimerPeriod * 100);
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Activity still shouldn't start the timer as we remain in foreground.
  codec->SimulateActivity();
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Restore default tick clock since |codec| is a garbage collected object that
  // may outlive the scope of this function.
  codec->set_tick_clock_for_testing(base::DefaultTickClock::GetInstance());
}

TEST_P(ReclaimableCodecTest, ForegroundCodecReclaimedOnceBackgrounded) {
  V8TestingScope v8_scope;

  auto* codec = CreateCodec(v8_scope.GetExecutionContext());

  // Test codec should start in foreground when kOnlyReclaimBackgroundWebCodecs
  // enabled.
  EXPECT_FALSE(codec->is_backgrounded_for_testing());

  // Codecs should not be reclaimable for inactivity until pressure is exceeded.
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  base::SimpleTestTickClock tick_clock;
  codec->set_tick_clock_for_testing(&tick_clock);

  // Pressure should not start the timer while we are still in the foreground.
  codec->SimulatePressureExceeded();
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Entering background should start timer.
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kHidden);
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Advancing 1 period shouldn't reclaim (it takes 2).
  tick_clock.Advance(kTimerPeriod);
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_FALSE(codec->reclaimed());

  // Re-entering foreground should stop the timer.
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kNotThrottled);
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Advancing any amount of time shouldn't reclaim while in foreground.
  tick_clock.Advance(kTimerPeriod * 100);
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Re-entering background should again start the timer.
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kHidden);
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Fire newly backgrounded to ensure first tick isn't treated as idle.
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_FALSE(codec->reclaimed());

  // Timer should be fresh such that one period is not enough to reclaim.
  tick_clock.Advance(kTimerPeriod);
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Advancing twice through the period should finally reclaim.
  tick_clock.Advance(kTimerPeriod);
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_TRUE(codec->reclaimed());

  // Restore default tick clock since |codec| is a garbage collected object that
  // may outlive the scope of this function.
  codec->set_tick_clock_for_testing(base::DefaultTickClock::GetInstance());
}

TEST_P(ReclaimableCodecTest, RepeatLifecycleEventsDontBreakState) {
  V8TestingScope v8_scope;

  auto* codec = CreateCodec(v8_scope.GetExecutionContext());

  // Test codec should start in foreground when kOnlyReclaimBackgroundWebCodecs
  // enabled.
  EXPECT_FALSE(codec->is_backgrounded_for_testing());

  // Duplicate kNotThrottled (foreground) shouldn't affect codec state.
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kNotThrottled);
  EXPECT_FALSE(codec->is_backgrounded_for_testing());

  // Codecs should not be reclaimable until pressure is exceeded.
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  base::SimpleTestTickClock tick_clock;
  codec->set_tick_clock_for_testing(&tick_clock);

  // Applying pressure should not start the timer while we remain in the
  // foreground.
  codec->SimulatePressureExceeded();
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_FALSE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Entering background should start timer.
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kHidden);
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Advancing 1 period shouldn't reclaim (it takes 2).
  tick_clock.Advance(kTimerPeriod);
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_FALSE(codec->reclaimed());

  // Further background lifecycle progression shouldn't affect codec state.
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kThrottled);
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Further background lifecycle progression shouldn't affect codec state.
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kStopped);
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->reclaimed());

  // Advancing one final time through the period should finally reclaim.
  tick_clock.Advance(kTimerPeriod);
  codec->SimulateActivityTimerFiredForTesting();
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_TRUE(codec->reclaimed());

  // Restore default tick clock since |codec| is a garbage collected object that
  // may outlive the scope of this function.
  codec->set_tick_clock_for_testing(base::DefaultTickClock::GetInstance());
}

TEST_P(ReclaimableCodecTest, PressureChangesUpdateTimer) {
  V8TestingScope v8_scope;

  auto* codec = CreateCodec(v8_scope.GetExecutionContext());

  // Test codec should start in foreground when kOnlyReclaimBackgroundWebCodecs
  // enabled.
  EXPECT_FALSE(codec->is_backgrounded_for_testing());

  // Codecs should not apply pressure by default.
  EXPECT_FALSE(codec->is_applying_codec_pressure());

  // Codecs should not be reclaimable by default.
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  // Pressure must be exceeded for the timer to be active.
  codec->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kHidden);
  EXPECT_TRUE(codec->is_backgrounded_for_testing());
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  // Applying pressure isn't enough to start reclamation, global pressure must
  // be exceeded.
  codec->ApplyCodecPressure();
  EXPECT_TRUE(codec->is_applying_codec_pressure());
  EXPECT_FALSE(codec->is_global_pressure_exceeded());
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  // Setting/unsetting global pressure should start/stop idle reclamation.
  codec->SetGlobalPressureExceededFlag(true);
  EXPECT_TRUE(codec->is_applying_codec_pressure());
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());

  codec->SetGlobalPressureExceededFlag(false);
  EXPECT_TRUE(codec->is_applying_codec_pressure());
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  codec->SetGlobalPressureExceededFlag(true);
  EXPECT_TRUE(codec->is_applying_codec_pressure());
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());

  // Releasing codec pressure should stop the timer.
  codec->ReleaseCodecPressure();
  EXPECT_FALSE(codec->is_applying_codec_pressure());
  EXPECT_FALSE(codec->is_global_pressure_exceeded());
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  // Re-applying codec pressure should not start the timer: the global pressure
  // flag must be set again.
  codec->ApplyCodecPressure();
  EXPECT_TRUE(codec->is_applying_codec_pressure());
  EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  codec->SetGlobalPressureExceededFlag(true);
  EXPECT_TRUE(codec->is_applying_codec_pressure());
  EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
}

INSTANTIATE_TEST_SUITE_P(
    ,
    ReclaimableCodecTest,
    testing::Values(ReclaimableCodec::CodecType::kDecoder,
                    ReclaimableCodec::CodecType::kEncoder));

}  // namespace blink
```