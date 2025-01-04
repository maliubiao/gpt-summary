Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is a part of a test file for the Chromium Blink engine's animation system.

Here's a breakdown of how to arrive at the summary:

1. **Identify the Core Functionality:** The code consists of multiple `TEST_P` blocks. Each `TEST_P` is a test case for the `Animation` class, focusing on different aspects of its behavior. The suffix `NoCompositing` and `Compositing` in the test fixture names indicate tests related to non-composited and composited animations, respectively.

2. **Group Related Tests:** Look for patterns in the test names and the actions performed within each test. For example, tests with names like `Finish...`, `SetPlaybackRate...`, `UpdatePlaybackRate...` clearly deal with the `finish` method and playback rate manipulation.

3. **Summarize Functionality within Groups:** For each group, describe what aspect of the `Animation` class is being tested. For example, the "Finish" group tests how `finish()` behaves in different scenarios (before start, with zero playback rate, with infinite iteration count).

4. **Identify Interactions with JavaScript/HTML/CSS:** Look for keywords or actions within the tests that relate to these web technologies. Setting `currentTime`, `playbackRate`, `effect`, and checking for exceptions relate to the JavaScript API. The compositing tests and the use of `CSSPropertyID` connect to CSS.

5. **Infer Logical Reasoning:**  For tests involving state changes (e.g., `pause()`, `play()`, `cancel()`), infer the expected state transitions and the conditions under which those transitions occur. Look for `EXPECT_...` statements which define the expected outputs for given actions.

6. **Identify Potential User/Programming Errors:** Tests that explicitly check for exceptions (like `FinishRaisesException`) or handle edge cases (like setting playback rate to zero) often highlight potential errors users or developers might make.

7. **Focus on the Provided Snippet (Part 2):** Since the user specifies this is "part 2", ensure the summary is limited to the functionality covered in this particular code block and does not try to generalize to the entire `animation_test.cc` file.

8. **Structure the Summary:**  Organize the findings into logical sections (e.g., "Finishing Animations," "Playback Rate Manipulation," "Effects").

9. **Refine and Clarify:** Ensure the language is clear and concise, avoiding jargon where possible. Provide concrete examples where requested.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Just list all the test names. **Correction:** This is too low-level. The request is for *functionality*. Grouping is needed.
* **Initial thought:** Focus only on the explicit method names called in the tests. **Correction:**  The *purpose* of the test needs to be captured, not just the method calls. For example, a test calling `setCurrentTime` and then `finish` is testing the behavior of `finish` under a specific condition.
* **Initial thought:** Try to connect every test to JS/HTML/CSS. **Correction:** Only make connections where they are directly evident in the code or the underlying concept. Not all internal logic has a direct user-facing API mapping.
这是`blink/renderer/core/animation/animation_test.cc`文件的第2部分，主要测试了`Animation`类的以下功能，**大部分测试没有涉及到合成（compositing）**：

**核心动画生命周期和控制:**

* **完成动画 (`Finish` 方法):**
    * 测试了在不同状态下调用 `finish()` 方法的效果，例如：
        *  在动画正常播放时调用，会跳转到动画的结束时间。
        *  在动画开始之前（currentTime为负）调用，会跳转到动画的开始时间。
        *  当 `playbackRate` 为 0 时调用，会抛出异常，动画时间不变。
        *  当动画的 `iteration-count` 为无限且 `iteration-duration` 不为零时调用，会抛出异常。
    * **假设输入与输出:**
        * **假设输入:** 动画正在以正向速率播放，当前时间为10000ms。
        * **输出:** 调用 `finish()` 后，动画的当前时间会变为动画的总时长（例如 30000ms）。
        * **假设输入:** 动画的 `playbackRate` 设置为 -1，当前时间为 -10000ms。
        * **输出:** 调用 `finish()` 后，动画的当前时间会变为 0。

* **动画限制 (`Limiting`):**
    * 测试了动画到达其有效时间范围的开始或结束时，是否会停止前进或后退，除非进行显式的时间设置。
    *  验证了在没有 `AnimationEffect` 的情况下，动画会被限制在起始位置。

* **播放速率 (`playbackRate`):**
    * **设置播放速率 (`setPlaybackRate`):**
        * 测试了设置正、负、零以及最大值的播放速率，并验证动画时间的更新是否符合预期。
        * 测试了在动画暂停和受限状态下设置播放速率的效果。
    * **更新播放速率 (`updatePlaybackRate`):**
        * 测试了在动画播放、暂停和完成状态下更新播放速率的效果。
        *  验证了在暂停的动画上更新播放速率的行为，包括同步和异步的情况。
    * **与 JavaScript/CSS 的关系:**  这些测试模拟了 JavaScript 中通过 `Animation.playbackRate` 属性控制动画播放速度的行为。例如，`animation.playbackRate = 2` 会使动画以正常速度的两倍播放。

* **动画效果 (`AnimationEffect`):**
    * **设置动画效果 (`setEffect`):**
        * 测试了动态更改动画的 `AnimationEffect`，并验证动画时间是否保持。
        * 测试了设置新的 `AnimationEffect` 如何限制或取消限制动画的播放范围。
        * 验证了空的动画不会更新效果。
        * 验证了动画会与其关联的 `AnimationEffect` 解除关联。
    * **与 JavaScript/CSS 的关系:**  `AnimationEffect` 对象（如 `KeyframeEffect`）定义了动画的具体样式变化。这些测试模拟了 JavaScript 中通过 `Animation.effect` 属性操作动画效果的行为，这直接影响了 CSS 属性的动画。

* **获取下一个效果变化时间 (`TimeToEffectChange`):**
    * 测试了在不同动画阶段（开始延迟、激活期、结束延迟）以及不同的播放速率下，获取下一个效果变化时间的功能。
    * 测试了在动画暂停和取消状态下获取下一个效果变化时间的行为。
    * **与 JavaScript/CSS 的关系:** 这可能与 JavaScript 中监听动画事件，例如在动画的不同阶段执行回调函数有关。

* **动画依附 (`AttachedAnimations`):**
    * 测试了动画对象与 DOM 元素关联的方式，并验证垃圾回收不会导致关联丢失。
    * **与 HTML 的关系:**  动画通常与特定的 HTML 元素相关联，例如通过 CSS 动画或 JavaScript 创建的动画。

* **动画排序 (`HasLowerCompositeOrdering`):**
    * 测试了动画对象在合成排序中的比较逻辑。

* **取消动画 (`Cancel`):**
    * 测试了取消动画后重新播放、反向播放、完成和暂停的行为，验证了 `currentTime` 和 `startTime` 的状态。
    * **与 JavaScript 的关系:**  模拟了 JavaScript 中调用 `animation.cancel()` 方法的效果。

* **完成后的播放速率 (`SetPlaybackRateAfterFinish`, `UpdatePlaybackRateAfterFinish`):**
    * 测试了在动画完成后设置或更新播放速率的行为，尤其是在反向播放的情况下。

**合成相关测试 (带有 `AnimationTestCompositing` 后缀):**

* **非合成元素不合成 (`NoCompositeWithoutCompositedElementId`):**
    * 测试了只有标记为需要合成的元素上的动画才能在合成器上运行。
    * **与 HTML/CSS 的关系:**  `will-change` CSS 属性或其他触发合成的属性会影响动画是否能在合成器上运行。

* **未解析开始时间时设置合成待处理 (`SetCompositorPendingWithUnresolvedStartTimes`):**
    * 测试了即使在尚未收到 compositor 的开始时间时，暂停动画也应标记 compositor 为待处理。

* **未解析开始时间时的预提交 (`PreCommitWithUnresolvedStartTimes`):**
    * 测试了在没有已解析的开始时间时，`PreCommit` 方法应返回失败。

* **异步取消 (`AsynchronousCancel`):**
    * 测试了在合成线程上异步取消动画的行为。

* **预提交记录直方图 (`PreCommitRecordsHistograms`):**
    * 测试了 `PreCommit` 方法在遇到各种错误情况时是否记录了相应的直方图信息，例如无效的动画效果、不支持的 timing 参数和 CSS 属性。

* **替换合成动画 (`ReplaceCompositedAnimation`):**
    * 测试了替换正在合成的动画的行为。

* **设置关键帧导致合成待处理 (`SetKeyframesCausesCompositorPending`):**
    * 测试了更改合成动画的关键帧是否会标记 compositor 为待处理。

* **无限持续时间的动画 (`InfiniteDurationAnimation`):**
    * 测试了无限持续时间的动画不应在 compositor 上运行。
    * **与 CSS 的关系:**  CSS 动画可以设置为无限循环。

* **零播放速度 (`ZeroPlaybackSpeed`):**
    * 测试了当播放速度接近于零时，动画不应在 compositor 上运行。

* **尺寸更改时重启合成动画 (`RestartCompositedAnimationOnSizeChange`):**
    * 测试了当元素尺寸改变时，依赖于元素尺寸的相对变换的合成动画是否会重启。
    * **与 HTML/CSS 的关系:** 当被动画元素的尺寸改变时，某些 CSS 变换（例如百分比单位的 `translate`）需要重新计算。

**常见的使用错误示例:**

* **尝试完成一个 `playbackRate` 为 0 的动画:** 这会导致异常。
* **尝试完成一个无限循环的动画 (非零 `iteration-duration`)**:  这也是不允许的，会抛出异常。
* **在没有明确设置时间的情况下，期望动画超出其定义的时间范围运行:** 动画会在其开始和结束时被限制。
* **在合成动画上使用 compositor 不支持的 CSS 属性或 timing 参数:**  这会导致动画无法在 compositor 上运行，可能导致性能问题。

**总结:**

这部分代码主要集中测试了 `Animation` 类在非合成场景下的核心功能，包括动画的启动、停止、完成、播放速率控制、动画效果的设置和更新等。同时也包含了一些关于合成动画的测试，主要关注动画在合成器上的运行条件、状态管理以及错误处理。 这些测试覆盖了 `Animation` 对象的关键生命周期和行为，确保了动画功能的正确性和稳定性。

Prompt: 
```
这是目录为blink/renderer/core/animation/animation_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
e(MakeGarbageCollected<V8CSSNumberish>(40000),
                            ASSERT_NO_EXCEPTION);
  animation->finish(exception_state);
  // The finish method triggers a snap to the upper boundary.
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, FinishBeforeStart) {
  NonThrowableExceptionState exception_state;
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  animation->setPlaybackRate(-1);
  animation->finish(exception_state);
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing,
       FinishDoesNothingWithPlaybackRateZero) {
  // Cannot finish an animation that has a playback rate of zero.
  DummyExceptionStateForTesting exception_state;
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(10000),
                            ASSERT_NO_EXCEPTION);
  animation->setPlaybackRate(0);
  animation->finish(exception_state);
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  EXPECT_TRUE(exception_state.HadException());
}

TEST_P(AnimationAnimationTestNoCompositing, FinishRaisesException) {
  // Cannot finish an animation that has an infinite iteration-count and a
  // non-zero iteration-duration.
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.iteration_count = std::numeric_limits<double>::infinity();
  animation->setEffect(MakeGarbageCollected<KeyframeEffect>(
      nullptr, MakeEmptyEffectModel(), timing));
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(10000),
                            ASSERT_NO_EXCEPTION);

  DummyExceptionStateForTesting exception_state;
  animation->finish(exception_state);
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(DOMExceptionCode::kInvalidStateError,
            exception_state.CodeAs<DOMExceptionCode>());
}

TEST_P(AnimationAnimationTestNoCompositing, LimitingAtEffectEnd) {
  SimulateFrame(30000);
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_TRUE(animation->Limited());

  // Cannot run past the end of the animation without a seek.
  SimulateFrame(40000);
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_FALSE(animation->Paused());
}

TEST_P(AnimationAnimationTestNoCompositing, LimitingAtStart) {
  SimulateFrame(30000);
  animation->setPlaybackRate(-2);
  SimulateAwaitReady();

  SimulateFrame(45000);
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_TRUE(animation->Limited());

  SimulateFrame(60000);
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_FALSE(animation->Paused());
}

TEST_P(AnimationAnimationTestNoCompositing, LimitingWithNoEffect) {
  animation->setEffect(nullptr);
  EXPECT_TRUE(animation->Limited());
  SimulateFrame(30000);
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, SetPlaybackRate) {
  animation->setPlaybackRate(2);
  SimulateAwaitReady();
  EXPECT_EQ(2, animation->playbackRate());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));

  SimulateFrame(10000);
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, SetPlaybackRateWhilePaused) {
  SimulateFrame(10000);
  animation->pause();
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  animation->setPlaybackRate(2);
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  SimulateAwaitReady();

  SimulateFrame(20000);
  animation->play();
  // Change to playback rate does not alter current time.
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  SimulateAwaitReady();

  SimulateFrame(25000);
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, SetPlaybackRateWhileLimited) {
  // Animation plays until it hits the upper bound.
  SimulateFrame(40000);
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_TRUE(animation->Limited());
  animation->setPlaybackRate(2);
  SimulateAwaitReady();

  // Already at the end of the animation.
  SimulateFrame(50000);
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  animation->setPlaybackRate(-2);
  SimulateAwaitReady();

  SimulateFrame(60000);
  EXPECT_FALSE(animation->Limited());
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, SetPlaybackRateZero) {
  SimulateFrame(10000);
  animation->setPlaybackRate(0);
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));

  SimulateFrame(20000);
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(20000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, SetPlaybackRateMax) {
  animation->setPlaybackRate(std::numeric_limits<double>::max());
  EXPECT_EQ(std::numeric_limits<double>::max(), animation->playbackRate());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  SimulateAwaitReady();

  SimulateFrame(1);
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, UpdatePlaybackRate) {
  animation->updatePlaybackRate(2);
  EXPECT_EQ(1, animation->playbackRate());
  SimulateAwaitReady();
  EXPECT_EQ(2, animation->playbackRate());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));

  SimulateFrame(10000);
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, UpdatePlaybackRateWhilePaused) {
  animation->pause();

  // Pending playback rate on pending-paused animation is picked up after async
  // tick.
  EXPECT_EQ("paused", animation->playState());
  EXPECT_TRUE(animation->pending());
  animation->updatePlaybackRate(2);
  EXPECT_EQ(1, animation->playbackRate());
  SimulateAwaitReady();
  EXPECT_EQ(2, animation->playbackRate());
  EXPECT_FALSE(animation->pending());

  // Pending playback rate on a paused animation is resolved immediately.
  animation->updatePlaybackRate(3);
  EXPECT_FALSE(animation->pending());
  EXPECT_EQ(3, animation->playbackRate());
}

TEST_P(AnimationAnimationTestNoCompositing, UpdatePlaybackRateWhileLimited) {
  NonThrowableExceptionState exception_state;
  animation->finish(exception_state);
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));

  // Updating playback rate does not affect current time.
  animation->updatePlaybackRate(2);
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));

  // Updating payback rate is resolved immediately for an animation in the
  // finished state.
  EXPECT_EQ(2, animation->playbackRate());
}

TEST_P(AnimationAnimationTestNoCompositing, UpdatePlaybackRateWhileRunning) {
  animation->play();
  SimulateFrame(1000);
  animation->updatePlaybackRate(2);

  // Updating playback rate triggers pending state for the play state.
  // Pending playback rate is not resolved until next async tick.
  EXPECT_TRUE(animation->pending());
  EXPECT_EQ(1, animation->playbackRate());
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  EXPECT_EQ(2, animation->playbackRate());
}

TEST_P(AnimationAnimationTestNoCompositing, SetEffect) {
  animation = timeline->Play(nullptr);
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(0),
                          ASSERT_NO_EXCEPTION);
  AnimationEffect* effect1 = MakeAnimation();
  AnimationEffect* effect2 = MakeAnimation();
  animation->setEffect(effect1);
  EXPECT_EQ(effect1, animation->effect());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(15000),
                            ASSERT_NO_EXCEPTION);
  animation->setEffect(effect2);
  EXPECT_TIME(15000, GetCurrentTimeMs(animation));
  EXPECT_EQ(nullptr, effect1->GetAnimationForTesting());
  EXPECT_EQ(animation, effect2->GetAnimationForTesting());
  EXPECT_EQ(effect2, animation->effect());
}

TEST_P(AnimationAnimationTestNoCompositing, SetEffectLimitsAnimation) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(20000),
                            ASSERT_NO_EXCEPTION);
  animation->setEffect(MakeAnimation(10));
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
  EXPECT_TRUE(animation->Limited());
  SimulateFrame(10000);
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, SetEffectUnlimitsAnimation) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(40000),
                            ASSERT_NO_EXCEPTION);
  animation->setEffect(MakeAnimation(60));
  EXPECT_FALSE(animation->Limited());
  EXPECT_TIME(40000, GetCurrentTimeMs(animation));
  SimulateFrame(10000);
  EXPECT_TIME(50000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, EmptyAnimationsDontUpdateEffects) {
  animation = timeline->Play(nullptr);
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());

  SimulateFrame(1234);
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());
}

TEST_P(AnimationAnimationTestNoCompositing, AnimationsDisassociateFromEffect) {
  AnimationEffect* animation_node = animation->effect();
  Animation* animation2 = timeline->Play(animation_node);
  EXPECT_EQ(nullptr, animation->effect());
  animation->setEffect(animation_node);
  EXPECT_EQ(nullptr, animation2->effect());
}

#define EXPECT_TIMEDELTA(expected, observed)                          \
  EXPECT_NEAR(expected.InMillisecondsF(), observed.InMillisecondsF(), \
              Animation::kTimeToleranceMs)

TEST_P(AnimationAnimationTestNoCompositing, AnimationsReturnTimeToNextEffect) {
  Timing timing;
  timing.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(1));
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
  timing.end_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(1));
  auto* keyframe_effect = MakeGarbageCollected<KeyframeEffect>(
      nullptr, MakeEmptyEffectModel(), timing);
  animation = timeline->Play(keyframe_effect);
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(0),
                          ASSERT_NO_EXCEPTION);

  // Next effect change at end of start delay.
  SimulateFrame(0);
  EXPECT_TIMEDELTA(ANIMATION_TIME_DELTA_FROM_SECONDS(1),
                   animation->TimeToEffectChange().value());

  // Next effect change at end of start delay.
  SimulateFrame(500);
  EXPECT_TIMEDELTA(ANIMATION_TIME_DELTA_FROM_SECONDS(0.5),
                   animation->TimeToEffectChange().value());

  // Start of active phase.
  SimulateFrame(1000);
  EXPECT_TIMEDELTA(AnimationTimeDelta(),
                   animation->TimeToEffectChange().value());

  // Still in active phase.
  SimulateFrame(1500);
  EXPECT_TIMEDELTA(AnimationTimeDelta(),
                   animation->TimeToEffectChange().value());

  // Start of the after phase. Next effect change at end of after phase.
  SimulateFrame(2000);
  EXPECT_TIMEDELTA(ANIMATION_TIME_DELTA_FROM_SECONDS(1),
                   animation->TimeToEffectChange().value());

  // Still in effect if fillmode = forward|both.
  SimulateFrame(3000);
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());

  // Reset to start of animation. Next effect at the end of the start delay.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(0),
                            ASSERT_NO_EXCEPTION);
  SimulateFrame(3000);
  EXPECT_TIMEDELTA(ANIMATION_TIME_DELTA_FROM_SECONDS(1),
                   animation->TimeToEffectChange().value());

  // Start delay is scaled by playback rate.
  animation->setPlaybackRate(2);
  SimulateFrame(3000);
  EXPECT_TIMEDELTA(ANIMATION_TIME_DELTA_FROM_SECONDS(0.5),
                   animation->TimeToEffectChange().value());

  // Effectively a paused animation.
  animation->setPlaybackRate(0);
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());

  // Reversed animation from end time. Next effect after end delay.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(3000),
                            ASSERT_NO_EXCEPTION);
  animation->setPlaybackRate(-1);
  animation->Update(kTimingUpdateOnDemand);
  SimulateFrame(3000);
  EXPECT_TIMEDELTA(ANIMATION_TIME_DELTA_FROM_SECONDS(1),
                   animation->TimeToEffectChange().value());

  // End delay is scaled by playback rate.
  animation->setPlaybackRate(-2);
  animation->Update(kTimingUpdateOnDemand);
  SimulateFrame(3000);
  EXPECT_TIMEDELTA(ANIMATION_TIME_DELTA_FROM_SECONDS(0.5),
                   animation->TimeToEffectChange().value());
}

TEST_P(AnimationAnimationTestNoCompositing, TimeToNextEffectWhenPaused) {
  EXPECT_TIMEDELTA(AnimationTimeDelta(),
                   animation->TimeToEffectChange().value());
  animation->pause();
  EXPECT_TRUE(animation->pending());
  EXPECT_EQ("paused", animation->playState());
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());
}

TEST_P(AnimationAnimationTestNoCompositing,
       TimeToNextEffectWhenCancelledBeforeStart) {
  EXPECT_TIMEDELTA(AnimationTimeDelta(),
                   animation->TimeToEffectChange().value());
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-8000),
                            ASSERT_NO_EXCEPTION);
  animation->setPlaybackRate(2);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(animation->pending());
  animation->Update(kTimingUpdateOnDemand);
  // This frame will fire the finish event event though no start time has been
  // received from the compositor yet, as cancel() nukes start times.
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());
}

TEST_P(AnimationAnimationTestNoCompositing,
       TimeToNextEffectWhenCancelledBeforeStartReverse) {
  EXPECT_TIMEDELTA(AnimationTimeDelta(),
                   animation->TimeToEffectChange().value());
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(9000),
                            ASSERT_NO_EXCEPTION);
  animation->setPlaybackRate(-3);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(animation->pending());
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());
}

TEST_P(AnimationAnimationTestNoCompositing,
       TimeToNextEffectSimpleCancelledBeforeStart) {
  EXPECT_TIMEDELTA(AnimationTimeDelta(),
                   animation->TimeToEffectChange().value());
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(animation->pending());
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());
}

TEST_P(AnimationAnimationTestNoCompositing, AttachedAnimations) {
  // Prevent |element| from being collected by |CollectAllGarbageForTesting|.
  Persistent<Element> element =
      GetDocument().CreateElementForBinding(AtomicString("foo"));

  Timing timing;
  auto* keyframe_effect = MakeGarbageCollected<KeyframeEffect>(
      element.Get(), MakeEmptyEffectModel(), timing);
  Animation* animation = timeline->Play(keyframe_effect);
  SimulateFrame(0);
  timeline->ServiceAnimations(kTimingUpdateForAnimationFrame);
  EXPECT_EQ(
      1U, element->GetElementAnimations()->Animations().find(animation)->value);

  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_TRUE(element->GetElementAnimations()->Animations().empty());
}

TEST_P(AnimationAnimationTestNoCompositing, HasLowerCompositeOrdering) {
  Animation* animation1 = timeline->Play(nullptr);
  Animation* animation2 = timeline->Play(nullptr);
  EXPECT_TRUE(Animation::HasLowerCompositeOrdering(
      animation1, animation2,
      Animation::CompareAnimationsOrdering::kPointerOrder));
}

TEST_P(AnimationAnimationTestNoCompositing, PlayAfterCancel) {
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(CurrentTimeIsSet(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));
  animation->play();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_TIME(0, GetStartTimeMs(animation));

  SimulateFrame(10000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  EXPECT_TIME(0, GetStartTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, PlayBackwardsAfterCancel) {
  animation->setPlaybackRate(-1);
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(15000),
                            ASSERT_NO_EXCEPTION);
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(animation->pending());
  EXPECT_FALSE(CurrentTimeIsSet(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));

  // Snap to the end of the animation.
  animation->play();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  EXPECT_TIME(30000, GetStartTimeMs(animation));

  SimulateFrame(10000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
  EXPECT_TIME(30000, GetStartTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, ReverseAfterCancel) {
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(animation->pending());
  EXPECT_FALSE(CurrentTimeIsSet(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));

  // Reverse snaps to the end of the animation.
  animation->reverse();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  EXPECT_TIME(30000, GetStartTimeMs(animation));

  SimulateFrame(10000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
  EXPECT_TIME(30000, GetStartTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, FinishAfterCancel) {
  NonThrowableExceptionState exception_state;
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(CurrentTimeIsSet(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));

  animation->finish(exception_state);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_TIME(-30000, GetStartTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, PauseAfterCancel) {
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(CurrentTimeIsSet(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));
  animation->pause();
  EXPECT_EQ("paused", animation->playState());
  EXPECT_TRUE(animation->pending());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_FALSE(StartTimeIsSet(animation));
}

// crbug.com/1052217
TEST_P(AnimationAnimationTestNoCompositing, SetPlaybackRateAfterFinish) {
  animation->setEffect(MakeAnimation(30, Timing::FillMode::FORWARDS));
  animation->finish();
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());

  // Reversing a finished animation marks the animation as outdated. Required
  // to recompute the time to next interval.
  animation->setPlaybackRate(-1);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_EQ(animation->playbackRate(), -1);
  EXPECT_TRUE(animation->Outdated());
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_TIMEDELTA(AnimationTimeDelta(),
                   animation->TimeToEffectChange().value());
  EXPECT_FALSE(animation->Outdated());
}

TEST_P(AnimationAnimationTestNoCompositing, UpdatePlaybackRateAfterFinish) {
  animation->setEffect(MakeAnimation(30, Timing::FillMode::FORWARDS));
  animation->finish();
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_EQ(std::nullopt, animation->TimeToEffectChange());

  // Reversing a finished animation marks the animation as outdated. Required
  // to recompute the time to next interval. The pending playback rate is
  // immediately applied when updatePlaybackRate is called on a non-running
  // animation.
  animation->updatePlaybackRate(-1);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_EQ(animation->playbackRate(), -1);
  EXPECT_TRUE(animation->Outdated());
  animation->Update(kTimingUpdateOnDemand);
  EXPECT_TIMEDELTA(AnimationTimeDelta(),
                   animation->TimeToEffectChange().value());
  EXPECT_FALSE(animation->Outdated());
}

TEST_P(AnimationAnimationTestCompositing,
       NoCompositeWithoutCompositedElementId) {
  SetBodyInnerHTML(
      "<div id='foo' style='position: relative; will-change: "
      "opacity;'>composited</div>"
      "<div id='bar' style='position: relative'>not composited</div>");

  LayoutObject* object_composited = GetLayoutObjectByElementId("foo");
  LayoutObject* object_not_composited = GetLayoutObjectByElementId("bar");

  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(30);
  auto* keyframe_effect_composited = MakeGarbageCollected<KeyframeEffect>(
      To<Element>(object_composited->GetNode()), MakeSimpleEffectModel(),
      timing);
  Animation* animation_composited = timeline->Play(keyframe_effect_composited);
  auto* keyframe_effect_not_composited = MakeGarbageCollected<KeyframeEffect>(
      To<Element>(object_not_composited->GetNode()), MakeSimpleEffectModel(),
      timing);
  Animation* animation_not_composited =
      timeline->Play(keyframe_effect_not_composited);

  SimulateFrame(0);
  EXPECT_EQ(animation_composited->CheckCanStartAnimationOnCompositorInternal(),
            CompositorAnimations::kNoFailure);
  const PaintArtifactCompositor* paint_artifact_compositor =
      GetDocument().View()->GetPaintArtifactCompositor();
  ASSERT_TRUE(paint_artifact_compositor);
  EXPECT_EQ(animation_composited->CheckCanStartAnimationOnCompositor(
                paint_artifact_compositor),
            CompositorAnimations::kNoFailure);
  EXPECT_NE(animation_not_composited->CheckCanStartAnimationOnCompositor(
                paint_artifact_compositor),
            CompositorAnimations::kNoFailure);
}

// Regression test for http://crbug.com/819591 . If a compositable animation is
// played and then paused before any start time is set (either blink or
// compositor side), the pausing must still set compositor pending or the pause
// won't be synced.
TEST_P(AnimationAnimationTestCompositing,
       SetCompositorPendingWithUnresolvedStartTimes) {
  ResetWithCompositedAnimation();

  // At this point, the animation exists on both the compositor and blink side,
  // but no start time has arrived on either side. The compositor is currently
  // synced, no update is pending.
  EXPECT_FALSE(animation->CompositorPending());

  // However, if we pause the animation then the compositor should still be
  // marked pending. This is required because otherwise the compositor will go
  // ahead and start playing the animation once it receives a start time (e.g.
  // on the next compositor frame).
  animation->pause();

  EXPECT_TRUE(animation->CompositorPending());
}

TEST_P(AnimationAnimationTestCompositing, PreCommitWithUnresolvedStartTimes) {
  ResetWithCompositedAnimation();

  // At this point, the animation exists on both the compositor and blink side,
  // but no start time has arrived on either side. The compositor is currently
  // synced, no update is pending.
  EXPECT_FALSE(animation->CompositorPending());

  // At this point, a call to PreCommit should bail out and tell us to wait for
  // next commit because there are no resolved start times.
  EXPECT_FALSE(animation->PreCommit(0, nullptr, true));
}

// Cancel is synchronous on the main thread, but asynchronously deferred on the
// compositor to reduce thread contention.
TEST_P(AnimationAnimationTestCompositing, AsynchronousCancel) {
  // Start with a composited animation.
  ResetWithCompositedAnimation();
  ASSERT_TRUE(animation->HasActiveAnimationsOnCompositor());

  animation->cancel();
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_TRUE(animation->CompositorPending());
  EXPECT_TRUE(animation->CompositorPendingCancel());

  GetDocument().GetPendingAnimations().Update(nullptr, false);
  EXPECT_FALSE(animation->CompositorPending());
  EXPECT_FALSE(animation->CompositorPendingCancel());
  EXPECT_FALSE(animation->HasActiveAnimationsOnCompositor());
}

namespace {
int GenerateHistogramValue(CompositorAnimations::FailureReason reason) {
  // The enum values in CompositorAnimations::FailureReasons are stored as 2^i
  // as they are a bitmask, but are recorded into the histogram as (i+1) to give
  // sequential histogram values. The exception is kNoFailure, which is stored
  // as 0 and recorded as 0.
  if (reason == CompositorAnimations::kNoFailure)
    return CompositorAnimations::kNoFailure;
  return std::countr_zero(static_cast<uint32_t>(reason)) + 1;
}
}  // namespace

TEST_P(AnimationAnimationTestCompositing, PreCommitRecordsHistograms) {
  const std::string histogram_name =
      "Blink.Animation.CompositedAnimationFailureReason";

  // Initially the animation in this test has no target, so it is invalid.
  {
    base::HistogramTester histogram;
    ASSERT_TRUE(animation->PreCommit(0, nullptr, true));
    histogram.ExpectBucketCount(
        histogram_name,
        GenerateHistogramValue(CompositorAnimations::kInvalidAnimationOrEffect),
        1);
  }

  // Restart the animation with a target and compositing state.
  {
    base::HistogramTester histogram;
    ResetWithCompositedAnimation();
    histogram.ExpectBucketCount(
        histogram_name,
        GenerateHistogramValue(CompositorAnimations::kNoFailure), 1);
  }

  // Now make the playback rate 0. This trips both the invalid animation and
  // unsupported timing parameter reasons.
  animation->setPlaybackRate(0);
  animation->NotifyReady(ANIMATION_TIME_DELTA_FROM_SECONDS(100));
  {
    base::HistogramTester histogram;
    ASSERT_TRUE(animation->PreCommit(0, nullptr, true));
    histogram.ExpectBucketCount(
        histogram_name,
        GenerateHistogramValue(CompositorAnimations::kInvalidAnimationOrEffect),
        1);
    histogram.ExpectBucketCount(
        histogram_name,
        GenerateHistogramValue(
            CompositorAnimations::kEffectHasUnsupportedTimingParameters),
        1);
  }
  animation->setPlaybackRate(1);

  // Finally, change the keyframes to something unsupported by the compositor.
  StringKeyframe* start_keyframe = MakeGarbageCollected<StringKeyframe>();
  start_keyframe->SetCSSPropertyValue(
      CSSPropertyID::kLeft, "0", SecureContextMode::kInsecureContext, nullptr);
  StringKeyframe* end_keyframe = MakeGarbageCollected<StringKeyframe>();
  end_keyframe->SetCSSPropertyValue(CSSPropertyID::kLeft, "100px",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  To<KeyframeEffect>(animation->effect())
      ->SetKeyframes({start_keyframe, end_keyframe});
  UpdateAllLifecyclePhasesForTest();
  {
    base::HistogramTester histogram;
    ASSERT_TRUE(animation->PreCommit(0, nullptr, true));
    histogram.ExpectBucketCount(
        histogram_name,
        GenerateHistogramValue(CompositorAnimations::kUnsupportedCSSProperty),
        1);
  }
}

// crbug.com/990000.
TEST_P(AnimationAnimationTestCompositing, ReplaceCompositedAnimation) {
  const std::string histogram_name =
      "Blink.Animation.CompositedAnimationFailureReason";

  // Start with a composited animation.
  ResetWithCompositedAnimation();
  ASSERT_TRUE(animation->HasActiveAnimationsOnCompositor());

  // Replace the animation. The new animation should not be incompatible and
  // therefore able to run on the compositor.
  animation->cancel();
  MakeCompositedAnimation();
  ASSERT_TRUE(animation->HasActiveAnimationsOnCompositor());
}

TEST_P(AnimationAnimationTestCompositing, SetKeyframesCausesCompositorPending) {
  ResetWithCompositedAnimation();

  // At this point, the animation exists on both the compositor and blink side,
  // but no start time has arrived on either side. The compositor is currently
  // synced, no update is pending.
  EXPECT_FALSE(animation->CompositorPending());

  // Now change the keyframes; this should mark the animation as compositor
  // pending as we need to sync the compositor side.
  StringKeyframe* start_keyframe = MakeGarbageCollected<StringKeyframe>();
  start_keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "0.0",
                                      SecureContextMode::kInsecureContext,
                                      nullptr);
  StringKeyframe* end_keyframe = MakeGarbageCollected<StringKeyframe>();
  end_keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "1.0",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  StringKeyframeVector keyframes;
  keyframes.push_back(start_keyframe);
  keyframes.push_back(end_keyframe);

  To<KeyframeEffect>(animation->effect())->SetKeyframes(keyframes);

  EXPECT_TRUE(animation->CompositorPending());
}

// crbug.com/1057076
// Infinite duration animations should not run on the compositor.
TEST_P(AnimationAnimationTestCompositing, InfiniteDurationAnimation) {
  ResetWithCompositedAnimation();
  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(nullptr));

  OptionalEffectTiming* effect_timing = OptionalEffectTiming::Create();
  effect_timing->setDuration(
      MakeGarbageCollected<V8UnionCSSNumericValueOrStringOrUnrestrictedDouble>(
          std::numeric_limits<double>::infinity()));
  animation->effect()->updateTiming(effect_timing);
  EXPECT_EQ(CompositorAnimations::kEffectHasUnsupportedTimingParameters,
            animation->CheckCanStartAnimationOnCompositor(nullptr));
}

TEST_P(AnimationAnimationTestCompositing, ZeroPlaybackSpeed) {
  ResetWithCompositedAnimation();
  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(nullptr));

  animation->updatePlaybackRate(0.0);
  EXPECT_TRUE(CompositorAnimations::kInvalidAnimationOrEffect |
              animation->CheckCanStartAnimationOnCompositor(nullptr));

  animation->updatePlaybackRate(1.0E-120);
  EXPECT_TRUE(CompositorAnimations::kInvalidAnimationOrEffect |
              animation->CheckCanStartAnimationOnCompositor(nullptr));

  animation->updatePlaybackRate(0.0001);
  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(nullptr));
}

// crbug.com/1149012
// Regression test to ensure proper restart logic for composited animations on
// relative transforms after a size change. In this test, the transform depends
// on the width and height of the box and a change to either triggers a restart
// of the animation if running.
TEST_P(AnimationAnimationTestCompositing,
       RestartCompositedAnimationOnSizeChange) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="width: 100px; height: 200px; background: blue;
                            will-change: transform">
    </div>
  )HTML");

  Animation* animation = CreateAnimation(
      CSSPropertyID::kTransform, "translate(100%, 100%)", "translate(0%, 0%)");

  UpdateAllLifecyclePhasesForTest();
  animation->play();
  KeyframeEffect* keyframe_effect =
      DynamicTo<KeyframeEffect>(animation->effect());
  ASSERT_TRUE(keyframe_effect);

  EXPECT_EQ(animation->CheckCanStartAnimationOnCompositor(nullptr),
            CompositorAnimations::kNoFailure);

  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());

  // Kick the animati
"""


```