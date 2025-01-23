Response:
The user wants to understand the functionality of the provided C++ code snippet. This is the final part of a three-part explanation. I need to summarize the functionalities covered in this specific part, and relate them to web technologies like Javascript, HTML, and CSS if applicable. I also need to provide examples of logical reasoning with input/output, and common user/programming errors.

**Plan:**

1. **Summarize Functionalities:** Focus on the test cases within this part of the code. These tests seem to cover:
    * Interactions between seeking and watch time reporting.
    * Finalization of watch time data upon object destruction.
    * Mapping of different watch time categories (e.g., based on audio/video presence, power state, controls, display type).
    * Hysteresis behavior for various events (play/pause, volume change, visibility, power state, controls, display type).
    * Specific handling for Media Foundation.
    * Muted state watch time reporting.

2. **Relate to Web Technologies:** Think about how these functionalities manifest in a web browser context.
    * **Seeking:** When a user drags the seek bar in a video player (HTML5 `<video>`), this triggers seeking events.
    * **Finalization on Destruction:**  When a video element is removed from the DOM or the page is closed, the reporting should finalize.
    * **Categories:**
        *  Audio/Video presence relates to the source of the media in HTML (`<video>` vs. `<audio>`).
        *  Power state is a browser-level concern, possibly influenced by Javascript APIs.
        *  Native controls vs. custom controls are managed via HTML attributes or Javascript libraries.
        *  Display types (fullscreen, picture-in-picture, inline) relate to browser APIs and user interactions.
    * **Hysteresis:**  This is an internal implementation detail but could affect how quickly watch time updates are reported after events.
    * **Media Foundation:**  This relates to the browser's underlying media decoding capabilities, not directly controllable by web technologies.
    * **Muted State:** The HTML5 `<video>` and `<audio>` elements have a `muted` property that Javascript can control.

3. **Logical Reasoning (Hypothetical):**  Select a test case and break it down. For example, the seeking test:
    * **Input:** `OnPlaying()` followed by `OnSeeking()`.
    * **Expected Output:** Watch time accumulated *before* `OnSeeking()` is finalized.

4. **Common Errors:** Consider what developers might do incorrectly when interacting with these underlying mechanisms (although they don't directly interact with this C++ code).
    * Relying on immediate reporting of watch time after every event without considering potential delays or finalization.
    * Not understanding how different factors (mute state, power, controls) can affect watch time categorization.

5. **Summarize the Part:** Concisely describe the main themes of the tests in this part of the file.这是 blink 引擎中 `watch_time_reporter_unittest.cc` 文件的第三部分，主要关注以下功能：

**核心功能归纳:**

* **验证在各种媒体状态和用户交互下，媒体观看时间的正确记录和报告。** 这包括了在播放、暂停、seek、改变音量、切换窗口可见性、电源状态变化、控制栏状态变化以及显示模式变化等场景下的测试。
* **测试了“滞后”（hysteresis）机制，用于避免频繁的状态切换导致过度报告。** 这意味着在某些状态变化发生后，会等待一段时间或特定的事件发生后再进行最终的观看时间记录。
* **针对特定的媒体渲染器类型 (Media Foundation) 进行了额外的测试。**
* **专门测试了静音状态下的观看时间记录。**

**与 Javascript, HTML, CSS 的关系及举例说明:**

虽然此 C++ 代码文件本身不直接包含 Javascript, HTML, 或 CSS 代码，但它测试的功能与这些 web 技术密切相关，因为它们共同构成了网页上的媒体播放体验。

1. **HTML (`<video>`, `<audio>`):**
   * **功能关系:**  `WatchTimeReporter` 负责跟踪 HTML5 `<video>` 和 `<audio>` 元素播放的实际时间。
   * **举例:**  当一个用户在网页上播放一个 `<video>` 元素时，`WatchTimeReporter` 会开始记录观看时间。测试用例中的 `Initialize(true, true, kSizeJustRight)`  中的 `true, true` 参数可能就代表了存在视频和音频轨道。

2. **Javascript:**
   * **功能关系:** Javascript 可以控制媒体元素的播放状态 (play/pause)、音量、seek 位置、全屏状态等，这些操作会触发 `WatchTimeReporter` 的相应事件。
   * **举例:**  `wtr_->OnPlaying()` 和 `wtr_->OnPaused()`  模拟了 Javascript 代码调用 `videoElement.play()` 和 `videoElement.pause()` 方法。 `wtr_->OnSeeking()` 模拟了用户通过 Javascript 或原生控件进行 seek 操作。`wtr_->OnVolumeChange(0)` 模拟了 Javascript 设置 `videoElement.volume = 0` 使其静音。

3. **CSS:**
   * **功能关系:** CSS 可以影响媒体元素的外观和布局，例如全屏显示或画中画模式，这会影响 `WatchTimeReporter` 的报告类别。
   * **举例:**  测试用例中的 `OnDisplayTypeChanged(DisplayType::kFullscreen)` 模拟了 CSS 触发了视频进入全屏模式。`OnDisplayTypeChanged(DisplayType::kPictureInPicture)` 模拟了进入画中画模式。

**逻辑推理 (假设输入与输出):**

* **测试用例:** `TEST_P(WatchTimeReporterTest, SeekFinalizes)`
* **假设输入:**
    1. 调用 `Initialize(true, true, kSizeJustRight)` 初始化 `WatchTimeReporter`。
    2. 调用 `wtr_->OnPlaying()` 开始播放。此时内部开始计时。
    3. 经过一段时间 (例如，`kWatchTime = base::Seconds(10)`) 后调用 `wtr_->OnSeeking()`。
* **预期输出:**
    1. 在调用 `wtr_->OnSeeking()` 之前，会调用 `EXPECT_WATCH_TIME()` 系列的宏来验证这段时间内的观看时间被记录在相应的类别中 (例如 `Ac`, `All`, `Eme`, `Mse`, `NativeControlsOff`, `DisplayInline`)。
    2. 调用 `wtr_->OnSeeking()` 会立即触发观看时间的最终记录 (通过 `EXPECT_WATCH_TIME_FINALIZED()`)，这意味着在 seek 操作发生时，之前的观看时间会被上报。

**用户或编程常见的使用错误举例说明:**

* **错误:**  在 Javascript 中，开发者可能会在很短的时间内连续调用 `videoElement.pause()` 和 `videoElement.play()`，例如在处理某些用户交互时。
* **后果 (基于测试代码的推断):**  `WatchTimeReporter` 的“滞后”机制会避免在这种快速切换中产生多次报告，只会在真正稳定的状态下进行记录，从而避免统计数据的偏差。测试用例如 `TEST_P(WatchTimeReporterTest, PlayPauseHysteresisContinuation)` 和 `TEST_P(WatchTimeReporterTest, PlayPauseHysteresisFinalized)` 就是为了验证这种机制的正确性。
* **错误:** 开发者可能没有考虑到用户手动 seek 操作也会导致观看时间报告的最终确定。他们可能会假设只有当视频自然播放结束或用户明确点击暂停时才会报告。
* **后果 (基于测试代码的推断):** 测试用例 `TEST_P(WatchTimeReporterTest, SeekFinalizes)` 明确指出 seek 操作会立即触发最终记录，开发者需要了解这一点，以便在需要精确统计时进行相应的处理。

**本部分的总结:**

这部分 `watch_time_reporter_unittest.cc` 文件主要通过各种细致的测试用例，验证了 `WatchTimeReporter` 能够准确地跟踪和报告媒体元素的观看时间，并能够处理各种用户交互、状态变化以及特定的渲染器类型。 其中重点测试了滞后机制在不同事件下的表现，确保了报告的准确性和效率，并涵盖了静音状态下的特殊处理。 这些测试确保了 Blink 引擎能够为上层应用（如 Chrome 浏览器）提供可靠的媒体观看时间统计数据。

### 提示词
```
这是目录为blink/renderer/platform/media/watch_time_reporter_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
EXPECT_WATCH_TIME_IF_VIDEO(DisplayFullscreen, kWatchTime2 - kWatchTime1);
    EXPECT_WATCH_TIME(Battery, kWatchTime2 - kWatchTime1);
    EXPECT_WATCH_TIME_FINALIZED();
    CycleReportingTimer();

    EXPECT_FALSE(IsMonitoring());
  }

  // Transition controls, battery and display type. Test only works with video.
  if (has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime1))
        .WillOnce(testing::Return(kWatchTime2));
    Initialize(true, true, kSizeJustRight);
    wtr_->OnPlaying();
    EXPECT_TRUE(IsMonitoring());

    OnNativeControlsEnabled(true);
    OnPowerStateChange(true);
    OnDisplayTypeChanged(DisplayType::kPictureInPicture);

    EXPECT_WATCH_TIME(Ac, kWatchTime1);
    EXPECT_WATCH_TIME(All, kWatchTime1);
    EXPECT_WATCH_TIME(Eme, kWatchTime1);
    EXPECT_WATCH_TIME(Mse, kWatchTime1);
    EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime1);
    EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime1);
    EXPECT_CONTROLS_WATCH_TIME_FINALIZED();
    EXPECT_POWER_WATCH_TIME_FINALIZED();
    EXPECT_DISPLAY_WATCH_TIME_FINALIZED();
    CycleReportingTimer();

    wtr_->OnPaused();
    EXPECT_WATCH_TIME(All, kWatchTime2);
    EXPECT_WATCH_TIME(Eme, kWatchTime2);
    EXPECT_WATCH_TIME(Mse, kWatchTime2);
    EXPECT_WATCH_TIME_IF_VIDEO(DisplayPictureInPicture,
                               kWatchTime2 - kWatchTime1);
    EXPECT_WATCH_TIME(NativeControlsOn, kWatchTime2 - kWatchTime1);
    EXPECT_WATCH_TIME(Battery, kWatchTime2 - kWatchTime1);
    EXPECT_WATCH_TIME_FINALIZED();
    CycleReportingTimer();

    EXPECT_FALSE(IsMonitoring());
  }
}

// Tests that starting from a non-zero base works.
TEST_P(WatchTimeReporterTest, WatchTimeReporterNonZeroStart) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(5);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(15);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(kWatchTime1))
      .WillRepeatedly(testing::Return(kWatchTime2));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  const base::TimeDelta kWatchTime = kWatchTime2 - kWatchTime1;
  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Eme, kWatchTime);
  EXPECT_WATCH_TIME(Mse, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  CycleReportingTimer();

  EXPECT_WATCH_TIME_FINALIZED();
}

// Tests that seeking causes an immediate finalization.
TEST_P(WatchTimeReporterTest, SeekFinalizes) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Eme, kWatchTime);
  EXPECT_WATCH_TIME(Mse, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_->OnSeeking();
}

// Tests that seeking can't be undone by anything other than OnPlaying().
TEST_P(WatchTimeReporterTest, SeekOnlyClearedByPlaying) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillRepeatedly(testing::Return(kWatchTime));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Eme, kWatchTime);
  EXPECT_WATCH_TIME(Mse, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_->OnSeeking();
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnHidden();
  wtr_->OnShown();
  wtr_->OnVolumeChange(0);
  wtr_->OnVolumeChange(1);
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  // Because the above calls may tickle the background and muted reporters,
  // we'll receive 2-3 finalize calls upon destruction if they exist.
  if (has_audio_ && has_video_)
    EXPECT_WATCH_TIME_FINALIZED();
  EXPECT_WATCH_TIME_FINALIZED();
  EXPECT_WATCH_TIME_FINALIZED();
}

// Tests that seeking causes an immediate finalization, but does not trample a
// previously set finalize time.
TEST_P(WatchTimeReporterTest, SeekFinalizeDoesNotTramplePreviousFinalize) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Eme, kWatchTime);
  EXPECT_WATCH_TIME(Mse, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_->OnPaused();
  wtr_->OnSeeking();
}

// Tests that watch time is finalized upon destruction.
TEST_P(WatchTimeReporterTest, WatchTimeReporterFinalizeOnDestruction) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());

  // Finalize the histogram before any cycles of the timer have run.
  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Eme, kWatchTime);
  EXPECT_WATCH_TIME(Mse, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
}

// Tests that watch time categories are mapped correctly.
TEST_P(WatchTimeReporterTest, WatchTimeCategoryMapping) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(10);

  // Verify ac, all, src, non-native controls
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(false, false, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Src, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_.reset();

  // Verify ac, all, mse, non-native controls
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(true, false, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Mse, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_.reset();

  // Verify ac, all, eme, src, non-native controls
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(false, true, kSizeJustRight);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Eme, kWatchTime);
  EXPECT_WATCH_TIME(Src, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_.reset();

  // Verify all, battery, src, non-native controls
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(false, false, kSizeJustRight);
  wtr_->OnPlaying();
  SetOnBatteryPower(true);
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Battery, kWatchTime);
  EXPECT_WATCH_TIME(Src, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_.reset();

  // Verify ac, all, src, native controls
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(false, false, kSizeJustRight);
  OnNativeControlsEnabled(true);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Src, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOn, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_.reset();

  // Verify all, battery, src, non-native controls, display fullscreen
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(false, false, kSizeJustRight);
  OnDisplayTypeChanged(DisplayType::kFullscreen);
  wtr_->OnPlaying();
  SetOnBatteryPower(true);
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Battery, kWatchTime);
  EXPECT_WATCH_TIME(Src, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayFullscreen, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_.reset();

  // Verify ac, all, src, native controls, display picture-in-picture
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime));
  Initialize(false, false, kSizeJustRight);
  OnNativeControlsEnabled(true);
  OnDisplayTypeChanged(DisplayType::kPictureInPicture);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME(Ac, kWatchTime);
  EXPECT_WATCH_TIME(All, kWatchTime);
  EXPECT_WATCH_TIME(Src, kWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOn, kWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayPictureInPicture, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_.reset();
}

TEST_P(WatchTimeReporterTest, PlayPauseHysteresisContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest>([this]() {
    wtr_->OnPaused();
    wtr_->OnPlaying();
  });
}

TEST_P(WatchTimeReporterTest, PlayPauseHysteresisFinalized) {
  RunHysteresisTest([this]() { wtr_->OnPaused(); });
}

TEST_P(WatchTimeReporterTest, OnVolumeChangeHysteresisContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest>([this]() {
    wtr_->OnVolumeChange(0);
    wtr_->OnVolumeChange(1);
  });
}

TEST_P(WatchTimeReporterTest, OnVolumeChangeHysteresisFinalized) {
  RunHysteresisTest([this]() { wtr_->OnVolumeChange(0); });
}

TEST_P(WatchTimeReporterTest, OnShownHiddenHysteresisContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest>([this]() {
    wtr_->OnHidden();
    wtr_->OnShown();
  });
}

TEST_P(WatchTimeReporterTest, OnShownHiddenHysteresisFinalized) {
  RunHysteresisTest([this]() { wtr_->OnHidden(); });
}

TEST_P(WatchTimeReporterTest, OnPowerStateChangeHysteresisBatteryContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeExitDoesNotRequireCurrentTime | kStartOnBattery>(
      [this]() {
        OnPowerStateChange(false);
        OnPowerStateChange(true);
      });
}

TEST_P(WatchTimeReporterTest, OnPowerStateChangeHysteresisBatteryFinalized) {
  RunHysteresisTest<kAccumulationContinuesAfterTest | kFinalizePowerWatchTime |
                    kStartOnBattery>([this]() { OnPowerStateChange(false); });
}

TEST_P(WatchTimeReporterTest, OnPowerStateChangeHysteresisAcContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeExitDoesNotRequireCurrentTime>([this]() {
    OnPowerStateChange(true);
    OnPowerStateChange(false);
  });
}

TEST_P(WatchTimeReporterTest, OnPowerStateChangeHysteresisAcFinalized) {
  RunHysteresisTest<kAccumulationContinuesAfterTest | kFinalizePowerWatchTime>(
      [this]() { OnPowerStateChange(true); });
}

TEST_P(WatchTimeReporterTest, OnPowerStateChangeBatteryTransitions) {
  RunHysteresisTest<kAccumulationContinuesAfterTest | kFinalizePowerWatchTime |
                    kStartOnBattery | kTransitionPowerWatchTime>(
      [this]() { OnPowerStateChange(false); });
}

TEST_P(WatchTimeReporterTest, OnPowerStateChangeAcTransitions) {
  RunHysteresisTest<kAccumulationContinuesAfterTest | kFinalizePowerWatchTime |
                    kTransitionPowerWatchTime>(
      [this]() { OnPowerStateChange(true); });
}

TEST_P(WatchTimeReporterTest, OnControlsChangeHysteresisNativeContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeExitDoesNotRequireCurrentTime |
                    kStartWithNativeControls>([this]() {
    OnNativeControlsEnabled(false);
    OnNativeControlsEnabled(true);
  });
}

TEST_P(WatchTimeReporterTest, OnControlsChangeHysteresisNativeFinalized) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeControlsWatchTime | kStartWithNativeControls>(
      [this]() { OnNativeControlsEnabled(false); });
}

TEST_P(WatchTimeReporterTest, OnControlsChangeHysteresisNativeOffContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeExitDoesNotRequireCurrentTime>([this]() {
    OnNativeControlsEnabled(true);
    OnNativeControlsEnabled(false);
  });
}

TEST_P(WatchTimeReporterTest, OnControlsChangeHysteresisNativeOffFinalized) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeControlsWatchTime>(
      [this]() { OnNativeControlsEnabled(true); });
}

TEST_P(WatchTimeReporterTest, OnControlsChangeToNativeOff) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeControlsWatchTime | kStartWithNativeControls |
                    kTransitionControlsWatchTime>(
      [this]() { OnNativeControlsEnabled(false); });
}

TEST_P(WatchTimeReporterTest, OnControlsChangeToNative) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeControlsWatchTime | kTransitionControlsWatchTime>(
      [this]() { OnNativeControlsEnabled(true); });
}

TEST_P(DisplayTypeWatchTimeReporterTest,
       OnDisplayTypeChangeHysteresisFullscreenContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeExitDoesNotRequireCurrentTime |
                    kStartWithDisplayFullscreen>([this]() {
    OnDisplayTypeChanged(DisplayType::kInline);
    OnDisplayTypeChanged(DisplayType::kFullscreen);
  });
}

TEST_P(DisplayTypeWatchTimeReporterTest,
       OnDisplayTypeChangeHysteresisNativeFinalized) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeDisplayWatchTime | kStartWithDisplayFullscreen>(
      [this]() { OnDisplayTypeChanged(DisplayType::kInline); });
}

TEST_P(DisplayTypeWatchTimeReporterTest,
       OnDisplayTypeChangeHysteresisInlineContinuation) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeExitDoesNotRequireCurrentTime>([this]() {
    OnDisplayTypeChanged(DisplayType::kFullscreen);
    OnDisplayTypeChanged(DisplayType::kInline);
  });
}

TEST_P(DisplayTypeWatchTimeReporterTest,
       OnDisplayTypeChangeHysteresisNativeOffFinalized) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeDisplayWatchTime>(
      [this]() { OnDisplayTypeChanged(DisplayType::kFullscreen); });
}

TEST_P(DisplayTypeWatchTimeReporterTest,
       OnDisplayTypeChangeInlineToFullscreen) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeDisplayWatchTime | kStartWithDisplayFullscreen |
                    kTransitionDisplayWatchTime>(
      [this]() { OnDisplayTypeChanged(DisplayType::kInline); });
}

TEST_P(DisplayTypeWatchTimeReporterTest,
       OnDisplayTypeChangeFullscreenToInline) {
  RunHysteresisTest<kAccumulationContinuesAfterTest |
                    kFinalizeDisplayWatchTime | kTransitionDisplayWatchTime>(
      [this]() { OnDisplayTypeChanged(DisplayType::kFullscreen); });
}

// Tests that the first finalize is the only one that matters.
TEST_P(WatchTimeReporterTest, HysteresisFinalizedWithEarliest) {
  RunHysteresisTest([this]() {
    wtr_->OnPaused();

    // These subsequent "stop events" should do nothing since a finalize time
    // has already been selected.
    wtr_->OnHidden();
    wtr_->OnVolumeChange(0);
  });
}

// Tests that if a stop, stop, start sequence occurs, the middle stop is not
// undone and thus finalize still occurs.
TEST_P(WatchTimeReporterTest, HysteresisPartialExitStillFinalizes) {
  auto stop_event = [this](size_t i) {
    if (i == 0) {
      wtr_->OnPaused();
    } else if (i == 1) {
      wtr_->OnVolumeChange(0);
    } else {
      ASSERT_TRUE(has_video_);
      wtr_->OnHidden();
    }
  };

  auto start_event = [this](size_t i) {
    if (i == 0) {
      wtr_->OnPlaying();
    } else if (i == 1) {
      wtr_->OnVolumeChange(1);
    } else {
      ASSERT_TRUE(has_video_);
      wtr_->OnShown();
    }
  };

  const size_t kTestSize = has_video_ ? 3 : 2;
  for (size_t i = 0; i < kTestSize; ++i) {
    for (size_t j = 0; j < kTestSize; ++j) {
      if (i == j)
        continue;

      RunHysteresisTest<kFinalizeInterleavedStartEvent>(
          [i, j, start_event, stop_event]() {
            stop_event(i);
            stop_event(j);
            start_event(i);
          });
    }
  }
}

// Tests Media Foundation related Keys being used and given to recorder.
TEST_P(WatchTimeReporterTest, WatchTimeReporterMediaFoundation) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(5);

  // Will include only audio and only video testing when the related keys are
  // added.
  if (has_audio_ && has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillRepeatedly(testing::Return(kWatchTimeEarly));
    Initialize(true, true, kSizeJustRight,
               media::RendererType::kMediaFoundation);
    wtr_->OnPlaying();

    // Check the following keys are used.
    EXPECT_WATCH_TIME(All, kWatchTimeEarly);
    EXPECT_WATCH_TIME_IF_AUDIO_VIDEO_MEDIAFOUNDATION(All, kWatchTimeEarly);
    EXPECT_WATCH_TIME_IF_AUDIO_VIDEO_MEDIAFOUNDATION(Eme, kWatchTimeEarly);
    EXPECT_WATCH_TIME(Mse, kWatchTimeEarly);
    EXPECT_WATCH_TIME(Eme, kWatchTimeEarly);
    EXPECT_WATCH_TIME(Ac, kWatchTimeEarly);
    EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeEarly);
    EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeEarly);

    EXPECT_TRUE(IsMonitoring());

    EXPECT_WATCH_TIME_FINALIZED();
  }
}

// Tests Media Foundation related keys given no EME.
TEST_P(WatchTimeReporterTest, WatchTimeReporterMediaFoundationNoEme) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(5);

  // Will include only audio and only video testing when the related keys are
  // added.
  if (has_audio_ && has_video_) {
    EXPECT_CALL(*this, GetCurrentMediaTime())
        .WillOnce(testing::Return(base::TimeDelta()))
        .WillRepeatedly(testing::Return(kWatchTimeEarly));
    Initialize(true, false, kSizeJustRight,
               media::RendererType::kMediaFoundation);
    wtr_->OnPlaying();

    // Check the following keys are used.
    EXPECT_WATCH_TIME(All, kWatchTimeEarly);
    EXPECT_WATCH_TIME_IF_AUDIO_VIDEO_MEDIAFOUNDATION(All, kWatchTimeEarly);
    EXPECT_WATCH_TIME(Mse, kWatchTimeEarly);
    EXPECT_WATCH_TIME(Ac, kWatchTimeEarly);
    EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kWatchTimeEarly);
    EXPECT_WATCH_TIME(NativeControlsOff, kWatchTimeEarly);

    EXPECT_TRUE(IsMonitoring());

    EXPECT_WATCH_TIME_FINALIZED();
  }
}

class MutedWatchTimeReporterTest : public WatchTimeReporterTest {};

TEST_P(MutedWatchTimeReporterTest, MutedHysteresis) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(8);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))  // 2x for playing
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTimeEarly))  // 3x for unmute.
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))  // 2x for mute
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))  // 1x for timer cycle.
      .WillRepeatedly(testing::Return(kWatchTimeLate));
  Initialize(true, true, kSizeJustRight);

  wtr_->OnVolumeChange(0);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnVolumeChange(1);
  wtr_->OnVolumeChange(0);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTimeEarly);

  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_TRUE(IsMonitoring());
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTimeLate);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTimeLate);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTimeLate);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTimeLate);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTimeLate);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTimeLate);
  EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(MutedWatchTimeReporterTest, MuteUnmute) {
  constexpr base::TimeDelta kWatchTimeEarly = base::Seconds(8);
  constexpr base::TimeDelta kWatchTimeLate = base::Seconds(10);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillOnce(testing::Return(kWatchTimeEarly))
      .WillRepeatedly(testing::Return(kWatchTimeLate));

  Initialize(true, true, kSizeJustRight);
  wtr_->OnVolumeChange(0);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnVolumeChange(1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTimeEarly);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTimeEarly);
  EXPECT_WATCH_TIME_FINALIZED();

  const base::TimeDelta kExpectedUnmutedWatchTime =
      kWatchTimeLate - kWatchTimeEarly;
  EXPECT_WATCH_TIME(Ac, kExpectedUnmutedWatchTime);
  EXPECT_WATCH_TIME(All, kExpectedUnmutedWatchTime);
  EXPECT_WATCH_TIME(Eme, kExpectedUnmutedWatchTime);
  EXPECT_WATCH_TIME(Mse, kExpectedUnmutedWatchTime);
  EXPECT_WATCH_TIME(NativeControlsOff, kExpectedUnmutedWatchTime);
  EXPECT_WATCH_TIME_IF_VIDEO(DisplayInline, kExpectedUnmutedWatchTime);
  CycleReportingTimer();

  EXPECT_WATCH_TIME_FINALIZED();
}

TEST_P(MutedWatchTimeReporterTest, MutedPaused) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(8);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillRepeatedly(testing::Return(kWatchTime));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnVolumeChange(0);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  wtr_->OnPaused();
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(MutedWatchTimeReporterTest, MutedSeeked) {
  constexpr base::TimeDelta kWatchTime = base::Seconds(8);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillRepeatedly(testing::Return(kWatchTime));
  Initialize(false, true, kSizeJustRight);
  wtr_->OnVolumeChange(0);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Src, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime);
  EXPECT_WATCH_TIME_FINALIZED();
  wtr_->OnSeeking();

  EXPECT_FALSE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(MutedWatchTimeReporterTest, MutedPower) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(8);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(16);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime1))
      .WillOnce(testing::Return(kWatchTime1))
      .WillRepeatedly(testing::Return(kWatchTime2));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnVolumeChange(0);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  OnPowerStateChange(true);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime1);
  EXPECT_POWER_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  wtr_->OnPaused();
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Battery, kWatchTime2 - kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime2);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(MutedWatchTimeReporterTest, MutedControls) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(8);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(16);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime1))
      .WillOnce(testing::Return(kWatchTime1))
      .WillRepeatedly(testing::Return(kWatchTime2));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnVolumeChange(0);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  OnNativeControlsEnabled(true);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime1);
  EXPECT_CONTROLS_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  wtr_->OnPaused();
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOn,
                                         kWatchTime2 - kWatchTime1);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

TEST_P(MutedWatchTimeReporterTest, MutedDisplayType) {
  constexpr base::TimeDelta kWatchTime1 = base::Seconds(8);
  constexpr base::TimeDelta kWatchTime2 = base::Seconds(16);
  EXPECT_CALL(*this, GetCurrentMediaTime())
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(base::TimeDelta()))
      .WillOnce(testing::Return(kWatchTime1))
      .WillOnce(testing::Return(kWatchTime1))
      .WillRepeatedly(testing::Return(kWatchTime2));
  Initialize(true, true, kSizeJustRight);
  wtr_->OnVolumeChange(0);
  wtr_->OnPlaying();
  EXPECT_TRUE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());

  OnDisplayTypeChanged(DisplayType::kFullscreen);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayInline, kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime1);
  EXPECT_DISPLAY_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  wtr_->OnPaused();
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Ac, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(All, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Eme, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(Mse, kWatchTime2);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(DisplayFullscreen,
                                         kWatchTime2 - kWatchTime1);
  EXPECT_MUTED_WATCH_TIME_IF_AUDIO_VIDEO(NativeControlsOff, kWatchTime2);
  EXPECT_WATCH_TIME_FINALIZED();
  CycleReportingTimer();

  EXPECT_FALSE(IsMutedMonitoring());
  EXPECT_FALSE(IsMonitoring());
}

INSTANTIATE_TEST_SUITE_P(WatchTimeReporterTest,
                         WatchTimeReporterTest,
                         testing::ValuesIn({// has_video, has_audio
                                            std::make_tuple(true, true),
                                            // has_video
                                            std::make_tuple(true, false),
                                            // has_audio
                                            std::make_tuple(false, true)}));

// Separate test set since display tests only work with video.
INSTANTIATE_TEST_SUITE_P(DisplayTypeWatchTimeReporterTest,
                         DisplayTypeWatchTimeReporterTest,
                         testing::ValuesIn({// has_video, has_audio
                                            std::make_tuple(true, true),
                                            // has_video
                                            std::make_tuple(true, false)}));

// Separate test set since muted tests only work with audio+video.
INSTANTIATE_TEST_SUITE_P(MutedWatchTimeReporterTest,
                         MutedWatchTimeReporterTest,
                         testing::ValuesIn({
                             // has_video, has_audio
                             std::make_tuple(true, true),
                         }));

}  // namespace blink
```