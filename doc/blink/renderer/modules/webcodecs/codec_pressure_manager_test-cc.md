Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `codec_pressure_manager_test.cc` immediately tells us this is a test file specifically for the `CodecPressureManager`. The `_test.cc` suffix is a standard convention in many C++ projects.

2. **Understand the Purpose of Testing:** Test files verify the functionality of a specific piece of code. This file will contain various test cases designed to ensure the `CodecPressureManager` works as expected under different conditions.

3. **Scan the Includes:**  The `#include` directives give crucial context:
    * `"third_party/blink/renderer/modules/webcodecs/codec_pressure_manager.h"`: This confirms that we're testing the `CodecPressureManager` class.
    * `"base/run_loop.h"`: Likely used for synchronizing asynchronous operations within the tests.
    * `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`: These are the core Google Test and Google Mock frameworks used for writing and asserting test results.
    * Other Blink-specific includes (`platform/scheduler`, `bindings/core/v8`, `modules/webcodecs/*`, `platform/heap`, `platform/testing`) indicate the environment and dependencies of the code being tested. Notably, `modules/webcodecs/*` shows the close relationship to other WebCodecs components.

4. **Identify Key Classes and Concepts:**  Looking at the code, we see:
    * `CodecPressureManager`: The central class being tested.
    * `CodecPressureGauge`: A singleton likely tracking overall codec pressure.
    * `ReclaimableCodec`: An interface or base class representing codecs that can be reclaimed (memory freed) under pressure. The `FakeReclaimableCodec` is a test double.
    * `CodecPressureManagerProvider`:  Likely responsible for creating and managing `CodecPressureManager` instances, possibly on a per-context basis.
    * `ExecutionContext`:  A Blink concept representing a browsing context (like a tab or iframe).

5. **Analyze the Test Structure:** The file uses Google Test's structure:
    * `TEST_P`: Parameterized tests, meaning the same test logic is run with different input values (in this case, `ReclaimableCodec::CodecType::kDecoder` and `kEncoder`).
    * `TEST`:  Standard test cases.
    * `SetUpManager`, `TearDown`:  Fixture methods for setting up and cleaning up before and after each test.
    * Helper methods like `CreateCodec`, `CreatePressuringCodec`, `VerifyTimersStarted`, etc., are used to make the tests more readable and maintainable.

6. **Infer Functionality from Test Names and Code:**  This is where the bulk of understanding the *what* happens comes in:
    * `OneManagerPerContext`: Tests that each browsing context (V8 scope) gets its own `CodecPressureManager`.
    * `AllManagersIncrementGlobalPressureGauge`: Verifies that pressure applied in one context is reflected in the global `CodecPressureGauge`.
    * `ManagersAreInitializedWithGlobalPressureValue`: Checks that new managers are aware of existing global pressure.
    * `DifferentManagersForEncodersAndDecoders`: Confirms separate managers for different codec types.
    * `DisposedCodecsRemovePressure`: Tests that when a codec is garbage collected, its pressure contribution is removed.
    * `ZeroPressureThreshold`: Checks behavior when the pressure threshold is set to zero.
    * `AddRemovePressure`: Verifies the basic adding and removing of pressure.
    * `PressureDoesntReclaimForegroundCodecs`: Ensures that foreground (active) codecs aren't reclaimed due to pressure.
    * `PressureStartsTimers`:  Tests that when pressure exceeds a threshold, reclamation timers are started for background codecs.

7. **Connect to Web Concepts (JavaScript, HTML, CSS):**  Consider *how* these internal mechanics relate to web development:
    * **JavaScript:** The WebCodecs API is exposed to JavaScript. This test file indirectly ensures that when a JavaScript using the WebCodecs API creates and uses decoders/encoders, the browser's resource management (through `CodecPressureManager`) behaves correctly.
    * **HTML:**  HTML structure can influence the number of active contexts (iframes). Each context will have its own `CodecPressureManager`. Embedding media elements (`<video>`, `<audio>`) often leads to the creation of decoders.
    * **CSS:** While CSS doesn't directly interact with WebCodecs pressure management, CSS animations or complex layouts might contribute to overall system load, indirectly influencing the conditions under which pressure management becomes active.

8. **Identify Potential User/Programming Errors:**  Think about what could go wrong from a developer's perspective:
    * **Holding onto codec objects unnecessarily:**  If JavaScript keeps references to unused codec objects, they will continue to consume resources and contribute to pressure, even if they're not actively being used. The reclamation mechanism is designed to mitigate this, but it's not a perfect solution.
    * **Creating too many codecs:**  Excessively creating decoders or encoders, especially in background tabs or iframes, can quickly lead to memory pressure.

9. **Trace User Operations:**  Imagine a user interacting with a web page:
    * Opening a page with a `<video>` element: This likely creates a video decoder, potentially managed by a `CodecPressureManager`.
    * Opening multiple tabs with video content:  Each tab will have its own set of codecs and potentially trigger pressure management.
    * Minimizing a tab with a playing video:  The video decoder might transition to a background state, making it eligible for reclamation under pressure.
    * A web application heavily utilizing the WebCodecs API for real-time video processing: This would directly interact with the creation and management of codecs, making the `CodecPressureManager` crucial for performance and stability.

10. **Consider Assumptions and Edge Cases:** The tests themselves often reveal assumptions about how the code should work. For instance, the tests differentiate between foreground and background codecs. Edge cases might involve rapid creation and destruction of codecs, very low memory conditions, or interactions between different pressure management systems in the browser.

By following these steps, we can systematically analyze the code and understand its purpose, relationships to web technologies, potential issues, and how user actions might lead to its execution. The key is to combine code reading with an understanding of the broader context of the Chromium browser and web development principles.
这个C++源代码文件 `codec_pressure_manager_test.cc` 是 Chromium Blink 引擎中用于测试 `CodecPressureManager` 类的单元测试文件。 `CodecPressureManager` 负责管理 WebCodecs API 中编解码器的资源压力，并在资源紧张时触发编解码器的回收。

**功能列举:**

1. **测试 `CodecPressureManager` 的基本功能:**  验证 `CodecPressureManager` 是否能够正确地跟踪和管理编解码器的资源压力。
2. **测试不同执行上下文 (ExecutionContext) 下的 `CodecPressureManager` 实例:** 确保每个浏览上下文都有独立的 `CodecPressureManager` 实例。
3. **测试全局资源压力管理:** 验证多个 `CodecPressureManager` 实例是否能够共同影响全局的资源压力指标 `CodecPressureGauge`。
4. **测试编解码器的压力注册和注销:**  验证当编解码器创建和销毁时，其压力是否能正确地被 `CodecPressureManager` 记录和移除。
5. **测试压力阈值 (Pressure Threshold) 的作用:** 验证当资源压力超过预设阈值时，`CodecPressureManager` 是否会采取相应的措施（例如启动回收定时器）。
6. **测试前台和后台编解码器的不同处理:** 验证 `CodecPressureManager` 是否区分前台和后台的编解码器，并对后台编解码器更积极地进行回收。
7. **测试资源回收定时器的启动和停止:** 验证在资源压力较高时，`CodecPressureManager` 能否正确启动回收定时器，并在压力降低时停止定时器。
8. **使用 FakeReclaimableCodec 进行模拟测试:**  由于实际的编解码器逻辑复杂，测试使用了 `FakeReclaimableCodec` 模拟编解码器的行为，以便进行隔离和可控的测试。
9. **使用 Google Test 框架进行断言和验证:**  使用 `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`, `EXPECT_FALSE` 等断言来验证代码的预期行为。

**与 JavaScript, HTML, CSS 的关系:**

虽然这个文件本身是 C++ 代码，但它测试的功能直接关系到 WebCodecs API，这是一个暴露给 JavaScript 的 Web API，用于在浏览器中进行音视频编解码。

* **JavaScript:**  开发者使用 WebCodecs API 在 JavaScript 中创建和操作 `VideoDecoder` 和 `AudioDecoder` 等对象。  `CodecPressureManager` 的作用是确保当用户创建大量或资源消耗较高的编解码器时，浏览器能够有效地管理这些资源，防止内存泄漏或性能下降。例如：

   ```javascript
   const decoder = new VideoDecoder({
     output: (frame) => { /* 处理解码后的帧 */ },
     error: (e) => { console.error('解码错误:', e); }
   });

   const config = {
     codec: 'avc1.42E01E', // H.264 baseline profile level 3
     // ... 其他配置
   };

   decoder.configure(config);

   // ... 持续解码操作
   ```

   当 JavaScript 代码创建并使用 `VideoDecoder` 时，Blink 引擎内部的 `CodecPressureManager` 会跟踪这个解码器所消耗的资源。

* **HTML:** HTML 中的 `<video>` 和 `<audio>` 元素通常会触发浏览器内部创建相应的解码器来播放媒体内容。 当页面包含多个 `<video>` 元素或者视频分辨率很高时，可能会创建多个解码器，这时 `CodecPressureManager` 就起到了资源管理的作用。

* **CSS:** CSS 本身与 `CodecPressureManager` 没有直接的功能关系。但是，复杂的 CSS 动画或大量的 DOM 元素可能会增加浏览器的整体资源压力，间接地影响 `CodecPressureManager` 的行为，使其更有可能触发编解码器的回收。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 在一个浏览上下文中创建了多个 `FakeReclaimableCodec` 实例，并调用 `ApplyCodecPressure()` 来模拟这些编解码器正在消耗资源。
2. 设置 `CodecPressureGauge` 的压力阈值 `kTestPressureThreshold` 为 3。

**输出:**

*   **当创建的编解码器数量小于等于阈值时:** `ManagerGlobalPressureExceeded()` 返回 `false`，表示全局压力未超过阈值，回收定时器不会被启动。
*   **当创建的编解码器数量大于阈值时:** `ManagerGlobalPressureExceeded()` 返回 `true`，表示全局压力已超过阈值，`VerifyTimersStarted()` 会验证所有后台的 `FakeReclaimableCodec` 实例的回收定时器都已启动。
*   **当部分编解码器通过 `ReleaseCodecPressure()` 释放压力，使总压力降回阈值以下时:** `ManagerGlobalPressureExceeded()` 返回 `false`，`VerifyTimersStopped()` 会验证回收定时器已停止。

**用户或编程常见的使用错误:**

1. **在不需要时保持编解码器对象存活:**  如果 JavaScript 代码创建了编解码器对象，但在不再使用后没有释放对这些对象的引用，这些编解码器会继续消耗资源，增加压力。`CodecPressureManager` 会尝试回收这些资源，但这可能会导致性能抖动。

    ```javascript
    // 错误示例：decoder 对象一直存在，即使不再使用
    let decoder = new VideoDecoder(...);
    // ... 使用 decoder ...
    // 忘记将 decoder 设置为 null 或调用 close()
    ```

2. **在后台标签页中创建过多的编解码器:**  用户在后台标签页中打开包含大量视频或音频内容的网页时，可能会创建大量的编解码器。如果这些编解码器持续消耗资源，即使标签页不可见，也可能导致浏览器资源紧张。`CodecPressureManager` 会尝试回收这些后台编解码器的资源。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个包含 `<video>` 或 `<audio>` 元素的网页:**  浏览器会解析 HTML，遇到媒体元素后，会创建相应的解码器。
2. **用户使用 WebCodecs API 的 JavaScript 代码创建 `VideoDecoder` 或 `AudioDecoder` 对象:** 开发者编写的 JavaScript 代码显式地创建和配置编解码器。
3. **浏览器内部的 WebCodecs 实现会通知 `CodecPressureManager` 有新的编解码器被创建，并记录其资源压力。**  这发生在 C++ 层面，用户或开发者通常不可见。
4. **如果用户持续操作，创建或激活更多的编解码器，或者已有的编解码器持续消耗资源（例如，解码高分辨率视频），则总的资源压力会增加。**
5. **当资源压力超过 `CodecPressureGauge` 中设置的阈值时，`CodecPressureManager` 会被触发。**
6. **`CodecPressureManager` 会检查当前有哪些后台的编解码器。**
7. **对于后台的编解码器，`CodecPressureManager` 会启动回收定时器，尝试回收这些编解码器的资源。** 这可能涉及到释放内存或停止不必要的处理。
8. **如果资源压力仍然很高，并且回收定时器到期，`CodecPressureManager` 可能会强制回收编解码器的资源，并通知相关的 JavaScript 代码（通过 `error` 回调或事件）。**

作为调试线索，当开发者发现 WebCodecs 应用在资源紧张的情况下出现问题（例如解码错误、性能下降），他们可能会查看 Blink 引擎的日志，搜索与 `CodecPressureManager` 相关的消息，以了解资源压力管理是否触发了编解码器的回收。他们也可能使用 Chromium 的性能分析工具来观察内存使用情况和垃圾回收事件，以确定资源压力是否是问题的原因。

总而言之，`codec_pressure_manager_test.cc` 这个测试文件虽然是底层的 C++ 代码，但它验证了 Blink 引擎中一个关键的资源管理机制，该机制直接影响着 WebCodecs API 的稳定性和性能，并与 JavaScript、HTML 等 Web 技术紧密相关。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/codec_pressure_manager_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_manager.h"

#include "base/run_loop.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_gauge.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_manager_provider.h"
#include "third_party/blink/renderer/modules/webcodecs/reclaimable_codec.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/heap_test_utilities.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

static constexpr size_t kTestPressureThreshold = 3;

class FakeReclaimableCodec final
    : public GarbageCollected<FakeReclaimableCodec>,
      public ReclaimableCodec {
 public:
  explicit FakeReclaimableCodec(ReclaimableCodec::CodecType type,
                                ExecutionContext* context)
      : ReclaimableCodec(type, context) {}

  ~FakeReclaimableCodec() override = default;

  void OnCodecReclaimed(DOMException* ex) final { ReleaseCodecPressure(); }

  // GarbageCollected override.
  void Trace(Visitor* visitor) const override {
    ReclaimableCodec::Trace(visitor);
  }

  bool IsGlobalPressureFlagSet() {
    return global_pressure_exceeded_for_testing();
  }

  bool IsTimerActive() { return IsReclamationTimerActiveForTesting(); }

 private:
  // ContextLifecycleObserver override.
  void ContextDestroyed() override {}
};

}  // namespace

class CodecPressureManagerTest
    : public testing::TestWithParam<ReclaimableCodec::CodecType> {
 public:
  using TestCodecSet = HeapHashSet<Member<FakeReclaimableCodec>>;

  CodecPressureManagerTest() {
    GetCodecPressureGauge().set_pressure_threshold_for_testing(
        kTestPressureThreshold);
  }

  ~CodecPressureManagerTest() override = default;

  void SetUpManager(ExecutionContext* context) {
    manager_ = GetManagerFromContext(context);
  }

  void TearDown() override {
    // Force the pre-finalizer call, otherwise the CodecPressureGauge will have
    // leftover pressure between tests.
    if (Manager())
      CleanUpManager(Manager());
  }

  CodecPressureManager* GetManagerFromContext(ExecutionContext* context) {
    auto& provider = CodecPressureManagerProvider::From(*context);

    switch (GetParam()) {
      case ReclaimableCodec::CodecType::kDecoder:
        return provider.GetDecoderPressureManager();
      case ReclaimableCodec::CodecType::kEncoder:
        return provider.GetEncoderPressureManager();
    }

    return nullptr;
  }

  CodecPressureGauge& GetCodecPressureGauge() {
    return CodecPressureGauge::GetInstance(GetParam());
  }

 protected:
  void SyncPressureFlags() {
    base::RunLoop run_loop;
    scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
        FROM_HERE, run_loop.QuitClosure());
    run_loop.Run();
  }

  FakeReclaimableCodec* CreateCodec(ExecutionContext* context) {
    return MakeGarbageCollected<FakeReclaimableCodec>(GetParam(), context);
  }

  void CleanUpManager(CodecPressureManager* manager) {
    // Manually run the pre-finalizer here. Otherwise, CodecPressureGauge will
    // have global pressure leftover from tests, and expectations will fail.
    manager->UnregisterManager();
  }

  FakeReclaimableCodec* CreateBackgroundedCodec(ExecutionContext* context) {
    auto* codec = CreateCodec(context);

    // Mark all codecs as background for test simplicity.
    codec->SimulateLifecycleStateForTesting(
        scheduler::SchedulingLifecycleState::kHidden);

    return codec;
  }

  FakeReclaimableCodec* CreatePressuringCodec(ExecutionContext* context) {
    auto* codec = CreateBackgroundedCodec(context);
    codec->ApplyCodecPressure();
    return codec;
  }

  CodecPressureManager* Manager() { return manager_; }

  void VerifyTimersStarted(const TestCodecSet& codecs) {
    SyncPressureFlags();

    size_t total_started_timers = 0u;
    for (auto& codec : codecs) {
      if (codec->IsTimerActive())
        ++total_started_timers;
    }

    EXPECT_EQ(total_started_timers, codecs.size());
  }

  void VerifyTimersStopped(const TestCodecSet& codecs) {
    SyncPressureFlags();

    size_t total_stopped_timers = 0u;
    for (auto& codec : codecs) {
      if (!codec->IsTimerActive())
        ++total_stopped_timers;
    }

    EXPECT_EQ(total_stopped_timers, codecs.size());
  }

  bool ManagerGlobalPressureExceeded() {
    SyncPressureFlags();

    return Manager()->global_pressure_exceeded_;
  }

 private:
  test::TaskEnvironment task_environment_;
  WeakPersistent<CodecPressureManager> manager_;
};

TEST_P(CodecPressureManagerTest, OneManagerPerContext) {
  V8TestingScope v8_scope;

  {
    V8TestingScope other_v8_scope;
    ASSERT_NE(other_v8_scope.GetExecutionContext(),
              v8_scope.GetExecutionContext());

    EXPECT_NE(GetManagerFromContext(v8_scope.GetExecutionContext()),
              GetManagerFromContext(other_v8_scope.GetExecutionContext()));
  }
}

TEST_P(CodecPressureManagerTest, AllManagersIncrementGlobalPressureGauge) {
  V8TestingScope v8_scope;

  EXPECT_EQ(0u, GetCodecPressureGauge().global_pressure_for_testing());

  auto* codec = CreatePressuringCodec(v8_scope.GetExecutionContext());

  EXPECT_TRUE(codec->is_applying_codec_pressure());

  EXPECT_EQ(1u, GetCodecPressureGauge().global_pressure_for_testing());
  EXPECT_EQ(1u, GetManagerFromContext(v8_scope.GetExecutionContext())
                    ->pressure_for_testing());

  {
    V8TestingScope other_v8_scope;
    ASSERT_NE(other_v8_scope.GetExecutionContext(),
              v8_scope.GetExecutionContext());

    auto* other_codec =
        CreatePressuringCodec(other_v8_scope.GetExecutionContext());

    EXPECT_TRUE(other_codec->is_applying_codec_pressure());

    EXPECT_EQ(2u, GetCodecPressureGauge().global_pressure_for_testing());
    EXPECT_EQ(1u, GetManagerFromContext(other_v8_scope.GetExecutionContext())
                      ->pressure_for_testing());

    // Test cleanup.
    CleanUpManager(GetManagerFromContext(other_v8_scope.GetExecutionContext()));
  }

  CleanUpManager(GetManagerFromContext(v8_scope.GetExecutionContext()));
}

TEST_P(CodecPressureManagerTest,
       ManagersAreInitializedWithGlobalPressureValue) {
  V8TestingScope v8_scope;
  SetUpManager(v8_scope.GetExecutionContext());

  TestCodecSet codecs_with_pressure;

  // Add pressure until we exceed the threshold.
  for (size_t i = 0; i < kTestPressureThreshold + 1; ++i) {
    codecs_with_pressure.insert(
        CreatePressuringCodec(v8_scope.GetExecutionContext()));
  }

  SyncPressureFlags();

  EXPECT_TRUE(Manager()->is_global_pressure_exceeded_for_testing());

  {
    V8TestingScope other_v8_scope;

    // "New" managers should be created with the correct global value.
    EXPECT_TRUE(GetManagerFromContext(other_v8_scope.GetExecutionContext())
                    ->is_global_pressure_exceeded_for_testing());
  }
}

TEST_P(CodecPressureManagerTest, DifferentManagersForEncodersAndDecoders) {
  V8TestingScope v8_scope;

  auto& provider =
      CodecPressureManagerProvider::From(*v8_scope.GetExecutionContext());

  EXPECT_NE(provider.GetDecoderPressureManager(),
            provider.GetEncoderPressureManager());
}

TEST_P(CodecPressureManagerTest, DisposedCodecsRemovePressure) {
  V8TestingScope v8_scope;
  SetUpManager(v8_scope.GetExecutionContext());

  auto* codec = CreatePressuringCodec(v8_scope.GetExecutionContext());

  EXPECT_TRUE(codec->is_applying_codec_pressure());
  EXPECT_EQ(1u, Manager()->pressure_for_testing());

  // Garbage collecting a pressuring codec should release its pressure.
  codec = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_EQ(0u, Manager()->pressure_for_testing());
  EXPECT_EQ(0u, GetCodecPressureGauge().global_pressure_for_testing());
}

TEST_P(CodecPressureManagerTest, ZeroPressureThreshold) {
  V8TestingScope v8_scope;
  GetCodecPressureGauge().set_pressure_threshold_for_testing(0);

  SetUpManager(v8_scope.GetExecutionContext());

  auto* codec = CreatePressuringCodec(v8_scope.GetExecutionContext());

  EXPECT_TRUE(codec->is_applying_codec_pressure());

  SyncPressureFlags();

  // Any codec added should have its global pressure flag set, if the threshold
  // is 0.
  EXPECT_TRUE(codec->IsGlobalPressureFlagSet());
}

TEST_P(CodecPressureManagerTest, AddRemovePressure) {
  V8TestingScope v8_scope;
  SetUpManager(v8_scope.GetExecutionContext());

  TestCodecSet codecs;

  for (size_t i = 0; i < kTestPressureThreshold * 2; ++i) {
    codecs.insert(CreateBackgroundedCodec(v8_scope.GetExecutionContext()));

    // Codecs shouldn't apply pressure by default.
    EXPECT_EQ(0u, Manager()->pressure_for_testing());
  }

  size_t total_pressure = 0;
  for (auto codec : codecs) {
    codec->ApplyCodecPressure();

    EXPECT_EQ(++total_pressure, Manager()->pressure_for_testing());
  }

  EXPECT_EQ(codecs.size(), Manager()->pressure_for_testing());

  for (auto codec : codecs) {
    codec->ReleaseCodecPressure();

    EXPECT_EQ(--total_pressure, Manager()->pressure_for_testing());
  }

  EXPECT_EQ(0u, Manager()->pressure_for_testing());
}

TEST_P(CodecPressureManagerTest, PressureDoesntReclaimForegroundCodecs) {
  V8TestingScope v8_scope;
  SetUpManager(v8_scope.GetExecutionContext());

  TestCodecSet codecs;

  for (size_t i = 0; i < kTestPressureThreshold * 2; ++i) {
    auto* codec = CreateCodec(v8_scope.GetExecutionContext());

    EXPECT_FALSE(codec->is_backgrounded_for_testing());

    codec->ApplyCodecPressure();
    codecs.insert(codec);
  }

  SyncPressureFlags();

  EXPECT_GT(Manager()->pressure_for_testing(), kTestPressureThreshold);

  // No foreground codec should be reclaimable
  for (auto codec : codecs)
    EXPECT_FALSE(codec->IsReclamationTimerActiveForTesting());

  // Backgrounding codecs should start their reclamation.
  for (auto codec : codecs) {
    codec->SimulateLifecycleStateForTesting(
        scheduler::SchedulingLifecycleState::kHidden);
    EXPECT_TRUE(codec->IsReclamationTimerActiveForTesting());
  }
}

TEST_P(CodecPressureManagerTest, PressureStartsTimers) {
  V8TestingScope v8_scope;
  SetUpManager(v8_scope.GetExecutionContext());

  TestCodecSet pressuring_codecs;

  for (size_t i = 0; i < kTestPressureThreshold; ++i) {
    pressuring_codecs.insert(
        CreatePressuringCodec(v8_scope.GetExecutionContext()));
  }

  // We should be at the pressure limit, but not over it.
  ASSERT_EQ(Manager()->pressure_for_testing(), kTestPressureThreshold);
  ASSERT_FALSE(ManagerGlobalPressureExceeded());
  VerifyTimersStopped(pressuring_codecs);

  // Apply slightly more pressure, pushing us over the threshold.
  pressuring_codecs.insert(
      CreatePressuringCodec(v8_scope.GetExecutionContext()));

  // Idle timers should have been started.
  ASSERT_GT(Manager()->pressure_for_testing(), kTestPressureThreshold);
  ASSERT_TRUE(ManagerGlobalPressureExceeded());
  VerifyTimersStarted(pressuring_codecs);

  // Add still more pressure, keeping us over the threshold.
  pressuring_codecs.insert(
      CreatePressuringCodec(v8_scope.GetExecutionContext()));

  // Idle timers should remain active.
  ASSERT_GT(Manager()->pressure_for_testing(), kTestPressureThreshold);
  ASSERT_TRUE(ManagerGlobalPressureExceeded());
  VerifyTimersStarted(pressuring_codecs);

  // Simulate some pressure being released.
  pressuring_codecs.TakeAny()->SimulateCodecReclaimedForTesting();

  // This shouldn't have been enough bring us back down below threshold.
  VerifyTimersStarted(pressuring_codecs);

  // Release once more, bringing us at the threshold.
  auto released_codec = pressuring_codecs.TakeAny();
  released_codec->ReleaseCodecPressure();
  EXPECT_FALSE(released_codec->IsReclamationTimerActiveForTesting());

  ASSERT_EQ(Manager()->pressure_for_testing(), kTestPressureThreshold);
  ASSERT_FALSE(ManagerGlobalPressureExceeded());
  VerifyTimersStopped(pressuring_codecs);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    CodecPressureManagerTest,
    testing::Values(ReclaimableCodec::CodecType::kDecoder,
                    ReclaimableCodec::CodecType::kEncoder));

}  // namespace blink

"""

```