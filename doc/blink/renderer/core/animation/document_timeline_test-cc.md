Response:
The user wants to understand the functionality of the `document_timeline_test.cc` file in the Chromium Blink engine. This file is a test suite, so its primary function is to test the `DocumentTimeline` class.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core purpose of the file:** The file name ends with `_test.cc`, strongly indicating it's a test file. The `#include` statements confirm this by including testing frameworks like `gmock` and `gtest`. The main focus is `DocumentTimeline`.

2. **Determine what `DocumentTimeline` is:** The code includes `<third_party/blink/renderer/core/animation/document_timeline.h>`, pointing to the definition of the class being tested. Based on the tests, `DocumentTimeline` manages the timing of animations within a document.

3. **Analyze the tests to understand `DocumentTimeline`'s functionality:** Go through each `TEST_F` function and summarize what aspect of `DocumentTimeline` it's testing. Look for patterns and common themes.

    * **`EmptyKeyframeAnimation` and `EmptyForwardsKeyframeAnimation`:** Test basic animation playback and the `fill-mode: forwards` behavior.
    * **`ZeroTime`:** Checks if the timeline's current time updates correctly with the animation clock.
    * **`CurrentTimeSeconds`:** Verifies conversion between timeline time and seconds, and handles cases where the timeline is inactive.
    * **`PlaybackRateNormal`, `PlaybackRatePause`, `PlaybackRateSlow`, `PlaybackRateFast`, and their `WithOriginTime` variants:** These extensively test how the playback rate affects the timeline's current time and its internal "zero time" calculation. This is a crucial aspect of `DocumentTimeline`.
    * **`PauseForTesting`:** Shows how the timeline can be programmatically paused and the current time of its animations adjusted for testing purposes.
    * **`DelayBeforeAnimationStart`:** Focuses on the `start-delay` property and how the timeline schedules updates based on it.
    * **`UseAnimationAfterTimelineDeref` and `PlayAfterDocumentDeref`:** These seem like robustness tests, checking for crashes when dealing with dangling pointers or null objects.
    * **`PredictionBehaviorOnlyAppliesOutsideRenderingLoop`:** Tests a specific optimization or behavior related to how the timeline advances time inside and outside the rendering loop. This hints at performance considerations.
    * **`PlaybackRateChangeUninitalizedAnimationClock`:**  Tests how the playback rate is handled even before the animation clock is fully initialized, suggesting a focus on correct initialization order and early behavior.

4. **Identify relationships with web technologies (JavaScript, HTML, CSS):**

    * **JavaScript:**  The tests implicitly show how JavaScript can control animations via the `DocumentTimeline` interface (e.g., `timeline->Play()`, `timeline->SetPlaybackRate()`, accessing `currentTime`). Provide concrete examples using JavaScript syntax.
    * **HTML:**  Animations often target HTML elements. The tests create and manipulate `Element` objects. Explain how CSS properties trigger animations on HTML elements.
    * **CSS:**  Mention CSS animation properties like `animation-duration`, `animation-delay`, `animation-fill-mode`, and `animation-playback-rate`. Explain how these properties map to the concepts tested in the file.

5. **Look for logical reasoning and provide input/output examples:** The playback rate tests are good candidates for this. Explain how the `playbackRate` affects the perceived speed of the animation and relate it to the timeline's internal time calculations. Provide simple input (playback rate, clock time) and expected output (timeline current time).

6. **Identify potential user/programming errors:** Based on the tests and understanding of animation concepts, highlight common mistakes:

    * Setting negative `animation-delay` (though the test focuses on the positive case, it's a related error).
    * Misunderstanding `fill-mode`.
    * Incorrectly calculating animation durations when `playbackRate` is not 1.
    * Forgetting to service animations.

7. **Structure the answer:** Organize the information logically with clear headings and bullet points. Start with the main function, then detail specific functionalities, relationships with web technologies, logical reasoning, and common errors. This makes the answer easy to read and understand.

8. **Review and refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make sure the examples are easy to follow and the explanations are concise. For example, clarify what "servicing animations" means in the context of the test.
这个文件 `blink/renderer/core/animation/document_timeline_test.cc` 是 Chromium Blink 引擎中用于测试 `DocumentTimeline` 类的单元测试文件。`DocumentTimeline` 负责管理特定文档中的动画时间轴。

以下是 `document_timeline_test.cc` 文件的主要功能及其与 JavaScript、HTML 和 CSS 的关系：

**主要功能:**

1. **测试 `DocumentTimeline` 的创建和基本属性:**
   - 验证 `DocumentTimeline` 对象是否能够正确创建。
   - 测试获取和设置时间轴的当前时间 (`CurrentTimeMilliseconds`, `CurrentTimeSeconds`)。
   - 测试获取和设置时间轴的播放速率 (`PlaybackRate`).
   - 测试时间轴的“零时间” (`CalculateZeroTime`)，这是计算当前时间的基础。

2. **测试动画的播放和控制:**
   - 测试在时间轴上播放动画 (`Play`) 的基本功能。
   - 测试空关键帧动画的表现。
   - 测试 `fill-mode: forwards` 对动画结束状态的影响。
   - 测试动画的延迟启动 (`start-delay`)。
   - 测试暂停动画的功能 (`PauseAnimationsForTesting`)，这通常用于测试场景。

3. **测试播放速率对动画时间的影响:**
   - 详细测试不同的播放速率（正常、暂停、慢速、快速）如何影响时间轴的当前时间和动画的进度。
   - 测试在设置了 `origin-time` 的情况下，播放速率的变化如何影响时间计算。

4. **测试时间轴在不同场景下的行为:**
   - 测试在没有关联渲染循环的情况下（例如，在 JavaScript 的 `setInterval` 中）时间轴如何动态更新时间。
   - 测试在文档被释放后使用动画对象是否会导致崩溃。
   - 测试在文档被释放后尝试播放动画是否会导致崩溃。

5. **使用 Mock 对象进行隔离测试:**
   - 使用 `MockPlatformTiming` 来模拟平台相关的定时行为，以便更精确地控制和测试时间轴的逻辑。

**与 JavaScript, HTML, CSS 的关系：**

`DocumentTimeline` 是 Web Animations API 的核心组成部分，它在 JavaScript 中暴露出来，允许开发者控制动画的播放时间和速率。CSS 动画也最终会关联到 `DocumentTimeline`。

**举例说明:**

* **JavaScript:**
   ```javascript
   const element = document.getElementById('myElement');
   const animation = element.animate(
     [{ opacity: 0 }, { opacity: 1 }],
     { duration: 1000, fill: 'forwards' }
   );
   const timeline = document.timeline;

   // 获取当前时间轴的时间
   console.log(timeline.currentTime);

   // 设置播放速率
   timeline.playbackRate = 0.5; // 慢速播放

   // 手动设置动画的当前时间 (测试中模拟)
   // animation.currentTime = 500;
   ```
   测试文件中的 `timeline->Play(keyframe_effect)` 就模拟了 JavaScript 中创建和播放动画的行为。`timeline->SetPlaybackRate(0.5)` 模拟了 JavaScript 中设置 `document.timeline.playbackRate` 的操作。

* **HTML:**
   ```html
   <div id="myElement">Hello</div>
   ```
   测试文件中的 `element = MakeGarbageCollected<Element>(QualifiedName::Null(), document.Get());` 创建了一个模拟的 HTML 元素，动画会作用于这个元素。

* **CSS:**
   CSS 动画和过渡在底层也会使用 `DocumentTimeline` 进行时间管理。虽然测试文件没有直接解析 CSS，但它测试了与 CSS 动画属性相关的概念，例如 `fill-mode` 和 `animation-delay`。
   ```css
   #myElement {
     animation-name: fadeIn;
     animation-duration: 1s;
     animation-fill-mode: forwards;
     animation-delay: 5s;
   }

   @keyframes fadeIn {
     from { opacity: 0; }
     to { opacity: 1; }
   }
   ```
   测试文件中的 `timing.fill_mode = Timing::FillMode::FORWARDS;` 模拟了 CSS 中的 `animation-fill-mode: forwards;` 的效果。 `timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(5));` 模拟了 CSS 中的 `animation-delay: 5s;`。

**逻辑推理与假设输入/输出:**

**测试 `PlaybackRateNormal`:**

* **假设输入:**
    * 初始状态：时间轴的播放速率为 1.0。
    * 时间流逝：动画时钟从 1000ms 更新到 2000ms。
* **逻辑推理:** 在播放速率为 1.0 的情况下，时间轴的当前时间应该与动画时钟的时间一致增长。
* **预期输出:**
    * 在动画时钟为 1000ms 时，`timeline->CurrentTimeMilliseconds()` 应该返回 1000ms。
    * 在动画时钟为 2000ms 时，`timeline->CurrentTimeMilliseconds()` 应该返回 2000ms。

**测试 `PlaybackRatePause`:**

* **假设输入:**
    * 初始状态：时间轴的播放速率为 1.0，动画时钟为 1000ms。
    * 操作：将播放速率设置为 0.0，然后动画时钟更新到 2000ms。
    * 操作：将播放速率恢复为 1.0，然后动画时钟更新到 4000ms。
* **逻辑推理:** 当播放速率为 0.0 时，时间轴的时间应该保持不变。当播放速率恢复为 1.0 后，时间轴的时间将继续增长，但其零点会发生变化。
* **预期输出:**
    * 在设置播放速率为 0.0 后，即使动画时钟更新到 2000ms，`timeline->CurrentTimeMilliseconds()` 仍然返回 1000ms。
    * 当播放速率恢复为 1.0 后，在动画时钟为 4000ms 时，`timeline->CurrentTimeMilliseconds()` 应该返回 3000ms (因为在 1000ms 时暂停，相当于新的零点是 1000ms)。

**涉及用户或编程常见的使用错误:**

1. **未更新动画时钟/未触发服务:**  用户可能会期望动画自动更新，但实际上需要浏览器引擎的调度来更新时间轴和服务动画。测试中的 `UpdateClockAndService(time_ms)` 方法模拟了这种更新过程。如果开发者没有触发类似的操作，动画可能不会按预期进行。

2. **对 `fill-mode` 的误解:**  用户可能不理解 `fill-mode: forwards` 的含义，认为动画结束后会回到初始状态。测试 `EmptyForwardsKeyframeAnimation` 验证了 `fill-mode: forwards` 会使动画在结束后保持结束状态。

3. **播放速率为零时的行为:** 用户可能不清楚当 `playbackRate` 设置为 0 时，时间轴会暂停，动画进度也会停止。测试 `PlaybackRatePause` 演示了这种行为。

4. **延迟启动的误解:**  用户可能期望动画立即开始，但如果设置了 `animation-delay`，动画会延迟启动。测试 `DelayBeforeAnimationStart` 验证了这种延迟行为。一个常见的错误是设置了很大的延迟，导致用户认为动画没有生效。

5. **在不活动的文档中使用时间轴:**  测试 `CurrentTimeSeconds` 中创建了一个没有关联帧的文档 (`ScopedNullExecutionContext`)，并验证了在这种情况下 `CurrentTimeSeconds` 返回 `false`。用户可能会尝试在后台或者没有正确加载的文档中使用时间轴，导致预期外的行为。

总而言之，`document_timeline_test.cc` 通过各种测试用例，确保 `DocumentTimeline` 类能够正确管理动画的时间，并且其行为与 Web Animations API 的规范一致。这些测试覆盖了时间轴的基本功能、播放控制、播放速率的影响以及在不同场景下的行为，有助于发现和修复潜在的 bug，并确保 Blink 引擎中动画功能的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/core/animation/document_timeline_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/animation/document_timeline.h"

#include "base/test/simple_test_tick_clock.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/animation_effect.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/pending_animations.h"
#include "third_party/blink/renderer/core/animation/timing_calculations.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

// NaN has the special property that NaN != NaN.
#define EXPECT_NAN(x) EXPECT_NE(x, x)

namespace {
base::TimeTicks TimeTicksFromMillisecondsD(double seconds) {
  return base::TimeTicks() + base::Milliseconds(seconds);
}

#define EXPECT_TIME_NEAR(expected, value)                              \
  EXPECT_NEAR((expected).InMillisecondsF(), (value).InMillisecondsF(), \
              Animation::kTimeToleranceMs)
}  // namespace

namespace blink {

class MockPlatformTiming : public DocumentTimeline::PlatformTiming {
 public:
  MOCK_METHOD1(WakeAfter, void(base::TimeDelta));

  void Trace(Visitor* visitor) const override {
    DocumentTimeline::PlatformTiming::Trace(visitor);
  }
};

class TestDocumentTimeline : public DocumentTimeline {
 public:
  TestDocumentTimeline(Document* document)
      : DocumentTimeline(document, base::TimeDelta(), nullptr),
        schedule_next_service_called_(false) {}
  void ScheduleServiceOnNextFrame() override {
    DocumentTimeline::ScheduleServiceOnNextFrame();
    schedule_next_service_called_ = true;
  }
  void Trace(Visitor* visitor) const override {
    DocumentTimeline::Trace(visitor);
  }
  bool ScheduleNextServiceCalled() const {
    return schedule_next_service_called_;
  }
  void ResetScheduleNextServiceCalled() {
    schedule_next_service_called_ = false;
  }

 private:
  bool schedule_next_service_called_;
};

class AnimationDocumentTimelineTest : public PageTestBase {
 protected:
  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    document = &GetDocument();
    GetAnimationClock().ResetTimeForTesting();
    GetAnimationClock().SetAllowedToDynamicallyUpdateTime(false);
    element =
        MakeGarbageCollected<Element>(QualifiedName::Null(), document.Get());
    document->Timeline().ResetForTesting();
    platform_timing = MakeGarbageCollected<MockPlatformTiming>();
    timeline = MakeGarbageCollected<TestDocumentTimeline>(document);
    timeline->SetTimingForTesting(platform_timing);

    timeline->ResetForTesting();
    ASSERT_EQ(0, timeline->CurrentTimeMilliseconds());
  }

  void TearDown() override {
    document.Release();
    element.Release();
    timeline.Release();
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  void UpdateClockAndService(double time_ms) {
    GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(time_ms));
    GetPendingAnimations().Update(nullptr, false);
    timeline->ServiceAnimations(kTimingUpdateForAnimationFrame);
    timeline->ScheduleNextService();
  }

  KeyframeEffectModelBase* CreateEmptyEffectModel() {
    return MakeGarbageCollected<StringKeyframeEffectModel>(
        StringKeyframeVector());
  }

  Persistent<Document> document;
  Persistent<Element> element;
  Persistent<TestDocumentTimeline> timeline;
  Timing timing;
  Persistent<MockPlatformTiming> platform_timing;

  double MinimumDelay() { return DocumentTimeline::kMinimumDelay; }
};

class AnimationDocumentTimelineRealTimeTest : public PageTestBase {
 protected:
  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    document = &GetDocument();
    timeline = document->Timeline();
    GetAnimationClock().SetAllowedToDynamicallyUpdateTime(false);
  }

  void TearDown() override {
    document.Release();
    timeline.Release();
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  Persistent<Document> document;
  Persistent<DocumentTimeline> timeline;
};

TEST_F(AnimationDocumentTimelineTest, EmptyKeyframeAnimation) {
  auto* effect =
      MakeGarbageCollected<StringKeyframeEffectModel>(StringKeyframeVector());
  auto* keyframe_effect =
      MakeGarbageCollected<KeyframeEffect>(element.Get(), effect, timing);

  timeline->Play(keyframe_effect);

  UpdateClockAndService(0);
  EXPECT_FLOAT_EQ(0, timeline->CurrentTimeMilliseconds().value());
  EXPECT_FALSE(keyframe_effect->IsInEffect());

  UpdateClockAndService(1000);
  EXPECT_FLOAT_EQ(1000, timeline->CurrentTimeMilliseconds().value());
}

TEST_F(AnimationDocumentTimelineTest, EmptyForwardsKeyframeAnimation) {
  auto* effect =
      MakeGarbageCollected<StringKeyframeEffectModel>(StringKeyframeVector());
  timing.fill_mode = Timing::FillMode::FORWARDS;
  auto* keyframe_effect =
      MakeGarbageCollected<KeyframeEffect>(element.Get(), effect, timing);

  timeline->Play(keyframe_effect);

  UpdateClockAndService(0);
  EXPECT_EQ(0, timeline->CurrentTimeMilliseconds());
  EXPECT_TRUE(keyframe_effect->IsInEffect());

  UpdateClockAndService(1000);
  EXPECT_FLOAT_EQ(1000, timeline->CurrentTimeMilliseconds().value());
}

TEST_F(AnimationDocumentTimelineTest, ZeroTime) {
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(1000));
  EXPECT_EQ(1000, timeline->CurrentTimeMilliseconds());

  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(2000));
  EXPECT_EQ(2000, timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, CurrentTimeSeconds) {
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(2000));
  EXPECT_EQ(2, timeline->CurrentTimeSeconds());
  EXPECT_EQ(2000, timeline->CurrentTimeMilliseconds());

  ScopedNullExecutionContext execution_context;
  auto* document_without_frame =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* inactive_timeline = MakeGarbageCollected<DocumentTimeline>(
      document_without_frame, base::TimeDelta(), platform_timing);

  EXPECT_FALSE(inactive_timeline->CurrentTimeSeconds());
  EXPECT_FALSE(inactive_timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, PlaybackRateNormal) {
  base::TimeTicks zero_time = timeline->CalculateZeroTime();

  timeline->SetPlaybackRate(1.0);
  EXPECT_EQ(1.0, timeline->PlaybackRate());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(1000));
  EXPECT_EQ(zero_time, timeline->CalculateZeroTime());
  EXPECT_EQ(1000, timeline->CurrentTimeMilliseconds());

  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(2000));
  EXPECT_EQ(zero_time, timeline->CalculateZeroTime());
  EXPECT_EQ(2000, timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, PlaybackRateNormalWithOriginTime) {
  base::TimeDelta origin_time = base::Milliseconds(-1000);
  DocumentTimeline* timeline = MakeGarbageCollected<DocumentTimeline>(
      document.Get(), origin_time, platform_timing);
  timeline->ResetForTesting();

  EXPECT_EQ(1.0, timeline->PlaybackRate());
  EXPECT_EQ(base::TimeTicks() + origin_time, timeline->CalculateZeroTime());
  EXPECT_EQ(1000, timeline->CurrentTimeMilliseconds());

  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(100));
  EXPECT_EQ(base::TimeTicks() + origin_time, timeline->CalculateZeroTime());
  EXPECT_EQ(1100, timeline->CurrentTimeMilliseconds());

  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(200));
  EXPECT_EQ(base::TimeTicks() + origin_time, timeline->CalculateZeroTime());
  EXPECT_EQ(1200, timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, PlaybackRatePause) {
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(1000));
  EXPECT_EQ(base::TimeTicks(), timeline->CalculateZeroTime());
  EXPECT_EQ(1000, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(0.0);
  EXPECT_EQ(0.0, timeline->PlaybackRate());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(2000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(1000), timeline->CalculateZeroTime());
  EXPECT_EQ(1000, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(1.0);
  EXPECT_EQ(1.0, timeline->PlaybackRate());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(4000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(1000), timeline->CalculateZeroTime());
  EXPECT_EQ(3000, timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, PlaybackRatePauseWithOriginTime) {
  base::TimeDelta origin_time = base::Milliseconds(-1000);
  DocumentTimeline* timeline = MakeGarbageCollected<DocumentTimeline>(
      document.Get(), origin_time, platform_timing);
  timeline->ResetForTesting();

  EXPECT_EQ(base::TimeTicks() + origin_time, timeline->CalculateZeroTime());
  EXPECT_EQ(1000, timeline->CurrentTimeMilliseconds());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(100));
  EXPECT_EQ(base::TimeTicks() + origin_time, timeline->CalculateZeroTime());
  EXPECT_EQ(1100, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(0.0);
  EXPECT_EQ(0.0, timeline->PlaybackRate());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(200));
  EXPECT_EQ(TimeTicksFromMillisecondsD(1100), timeline->CalculateZeroTime());
  EXPECT_EQ(1100, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(1.0);
  EXPECT_EQ(1.0, timeline->PlaybackRate());
  EXPECT_EQ(TimeTicksFromMillisecondsD(-900), timeline->CalculateZeroTime());
  EXPECT_EQ(1100, timeline->CurrentTimeMilliseconds());

  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(400));
  EXPECT_EQ(TimeTicksFromMillisecondsD(-900), timeline->CalculateZeroTime());
  EXPECT_EQ(1300, timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, PlaybackRateSlow) {
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(1000));
  EXPECT_EQ(base::TimeTicks(), timeline->CalculateZeroTime());
  EXPECT_EQ(1000, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(0.5);
  EXPECT_EQ(0.5, timeline->PlaybackRate());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(3000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(-1000), timeline->CalculateZeroTime());
  EXPECT_EQ(2000, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(1.0);
  EXPECT_EQ(1.0, timeline->PlaybackRate());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(4000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(1000), timeline->CalculateZeroTime());
  EXPECT_EQ(3000, timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, PlaybackRateFast) {
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(1000));
  EXPECT_EQ(base::TimeTicks(), timeline->CalculateZeroTime());
  EXPECT_EQ(1000, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(2.0);
  EXPECT_EQ(2.0, timeline->PlaybackRate());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(3000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(500), timeline->CalculateZeroTime());
  EXPECT_EQ(5000, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(1.0);
  EXPECT_EQ(1.0, timeline->PlaybackRate());
  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(4000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(-2000), timeline->CalculateZeroTime());
  EXPECT_EQ(6000, timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, PlaybackRateFastWithOriginTime) {
  DocumentTimeline* timeline = MakeGarbageCollected<DocumentTimeline>(
      document.Get(), base::Seconds(-1000), platform_timing);
  timeline->ResetForTesting();

  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(100000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(-1000000),
            timeline->CalculateZeroTime());
  EXPECT_EQ(1100000, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(2.0);
  EXPECT_EQ(2.0, timeline->PlaybackRate());
  EXPECT_EQ(TimeTicksFromMillisecondsD(-450000), timeline->CalculateZeroTime());
  EXPECT_EQ(1100000, timeline->CurrentTimeMilliseconds());

  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(300000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(-450000), timeline->CalculateZeroTime());
  EXPECT_EQ(1500000, timeline->CurrentTimeMilliseconds());

  timeline->SetPlaybackRate(1.0);
  EXPECT_EQ(1.0, timeline->PlaybackRate());
  EXPECT_EQ(TimeTicksFromMillisecondsD(-1200000),
            timeline->CalculateZeroTime());
  EXPECT_EQ(1500000, timeline->CurrentTimeMilliseconds());

  GetAnimationClock().UpdateTime(TimeTicksFromMillisecondsD(400000));
  EXPECT_EQ(TimeTicksFromMillisecondsD(-1200000),
            timeline->CalculateZeroTime());
  EXPECT_EQ(1600000, timeline->CurrentTimeMilliseconds());
}

TEST_F(AnimationDocumentTimelineTest, PauseForTesting) {
  AnimationTimeDelta seek_time = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.fill_mode = Timing::FillMode::FORWARDS;
  auto* anim1 = MakeGarbageCollected<KeyframeEffect>(
      element.Get(), CreateEmptyEffectModel(), timing);
  auto* anim2 = MakeGarbageCollected<KeyframeEffect>(
      element.Get(), CreateEmptyEffectModel(), timing);
  Animation* animation1 = timeline->Play(anim1);
  Animation* animation2 = timeline->Play(anim2);
  timeline->PauseAnimationsForTesting(seek_time);

  V8CSSNumberish* current_time = animation1->currentTime();
  EXPECT_NEAR(seek_time.InMillisecondsF(), current_time->GetAsDouble(),
              Animation::kTimeToleranceMs);
  current_time = animation2->currentTime();
  EXPECT_NEAR(seek_time.InMillisecondsF(), current_time->GetAsDouble(),
              Animation::kTimeToleranceMs);
}

TEST_F(AnimationDocumentTimelineTest, DelayBeforeAnimationStart) {
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(2);
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(5));

  auto* keyframe_effect = MakeGarbageCollected<KeyframeEffect>(
      element.Get(), CreateEmptyEffectModel(), timing);

  timeline->Play(keyframe_effect);

  // TODO: Put the animation startTime in the future when we add the capability
  // to change animation startTime
  EXPECT_CALL(
      *platform_timing,
      WakeAfter(base::Seconds(timing.start_delay.AsTimeValue().InSecondsF() -
                              MinimumDelay())));
  UpdateClockAndService(0);

  EXPECT_CALL(
      *platform_timing,
      WakeAfter(base::Seconds(timing.start_delay.AsTimeValue().InSecondsF() -
                              MinimumDelay() - 1.5)));
  UpdateClockAndService(1500);

  timeline->ScheduleServiceOnNextFrame();

  timeline->ResetScheduleNextServiceCalled();
  UpdateClockAndService(4980);
  EXPECT_TRUE(timeline->ScheduleNextServiceCalled());
}

TEST_F(AnimationDocumentTimelineTest, UseAnimationAfterTimelineDeref) {
  Animation* animation = timeline->Play(nullptr);
  timeline.Clear();
  // Test passes if this does not crash.
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(0),
                          ASSERT_NO_EXCEPTION);
}

TEST_F(AnimationDocumentTimelineTest, PlayAfterDocumentDeref) {
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(2);
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(5));

  DocumentTimeline* timeline = &document->Timeline();
  document = nullptr;

  auto* keyframe_effect = MakeGarbageCollected<KeyframeEffect>(
      nullptr, CreateEmptyEffectModel(), timing);
  // Test passes if this does not crash.
  timeline->Play(keyframe_effect);
}

// Regression test for https://crbug.com/995806, ensuring that we do dynamically
// progress the time when outside a rendering loop (so that we can serve e.g.
// setInterval), but also that we *only* dynamically progress the time when
// outside a rendering loop (so that we are mostly spec compliant).
TEST_F(AnimationDocumentTimelineTest,
       PredictionBehaviorOnlyAppliesOutsideRenderingLoop) {
  base::SimpleTestTickClock test_clock;
  GetAnimationClock().OverrideDynamicClockForTesting(&test_clock);
  ASSERT_EQ(GetAnimationClock().CurrentTime(), test_clock.NowTicks());

  // As long as we are inside the rendering loop, we shouldn't update even
  // across tasks.
  base::TimeTicks before_time = GetAnimationClock().CurrentTime();
  test_clock.Advance(base::Seconds(1));
  EXPECT_EQ(GetAnimationClock().CurrentTime(), before_time);

  AnimationClock::NotifyTaskStart();
  test_clock.Advance(base::Seconds(1));
  EXPECT_EQ(GetAnimationClock().CurrentTime(), before_time);

  // Once we leave the rendering loop, however, it is valid for the time to
  // increase *once* per task.
  GetAnimationClock().SetAllowedToDynamicallyUpdateTime(true);
  EXPECT_GT(GetAnimationClock().CurrentTime(), before_time);

  // The clock shouldn't tick again until we change task, however.
  base::TimeTicks current_time = GetAnimationClock().CurrentTime();
  test_clock.Advance(base::Seconds(1));
  EXPECT_EQ(GetAnimationClock().CurrentTime(), current_time);
  AnimationClock::NotifyTaskStart();
  EXPECT_GT(GetAnimationClock().CurrentTime(), current_time);
}

// Ensure that origin time is correctly calculated even when the animation
// clock has not yet been initialized.
TEST_F(AnimationDocumentTimelineRealTimeTest,
       PlaybackRateChangeUninitalizedAnimationClock) {
  GetAnimationClock().ResetTimeForTesting();
  EXPECT_TRUE(GetAnimationClock().CurrentTime().is_null());
  EXPECT_FALSE(
      document->Loader()->GetTiming().ReferenceMonotonicTime().is_null());

  base::TimeDelta origin_time = base::Seconds(1000);
  DocumentTimeline* timeline =
      MakeGarbageCollected<DocumentTimeline>(document.Get(), origin_time);
  timeline->SetPlaybackRate(0.5);

  EXPECT_TIME_NEAR(AnimationTimeDelta(origin_time) * 2,
                   timeline->ZeroTime() - document->Timeline().ZeroTime());
}

}  // namespace blink
```