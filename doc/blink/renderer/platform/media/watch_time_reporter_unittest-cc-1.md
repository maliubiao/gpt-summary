Response: The user wants a summary of the functionality of the provided C++ code, which is the second part of a unit test file for `WatchTimeReporter` in the Chromium Blink engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The filename `watch_time_reporter_unittest.cc` and the test case names clearly indicate that this code is for testing the `WatchTimeReporter` class. This class likely tracks the amount of time a media element (audio or video) is played under various conditions.

2. **Scan for Key Functionalities:** Look for patterns in the test names and the `EXPECT_*` macros. These macros reveal what aspects of `WatchTimeReporter` are being tested.

    * `WatchTimeReporterNonZeroStart`: Tests starting from a non-zero playback position.
    * `SeekFinalizes`: Tests if seeking triggers an immediate finalization of watch time.
    * `SeekOnlyClearedByPlaying`: Tests that only `OnPlaying()` can reset the seeking state.
    * `SeekFinalizeDoesNotTramplePreviousFinalize`: Checks that seeking doesn't interfere with previously set finalization times.
    * `WatchTimeReporterFinalizeOnDestruction`: Verifies that watch time is finalized when the `WatchTimeReporter` object is destroyed.
    * `WatchTimeCategoryMapping`:  Checks that watch time is correctly categorized based on factors like audio/video presence, EME, MSE, native controls, and display type.
    * `PlayPauseHysteresisContinuation/Finalized`: Tests the behavior of the reporter when playback is paused and resumed, focusing on whether accumulation continues or finalizes. Similar tests exist for `OnVolumeChange`, `OnShownHidden`, `OnPowerStateChange`, `OnControlsChange`, and `OnDisplayTypeChange`. These highlight the hysteresis mechanism, which likely involves a delay before finalizing watch time on certain events.
    * `HysteresisFinalizedWithEarliest`: Checks that the earliest stop event triggers finalization.
    * `HysteresisPartialExitStillFinalizes`: Tests scenarios where stop and start events are interleaved.
    * `WatchTimeReporterMediaFoundation/NoEme`: Tests specific behavior when using Media Foundation as the rendering engine, both with and without Encrypted Media Extensions (EME).
    * Tests prefixed with `MutedWatchTimeReporterTest`:  Focus on scenarios where the media is muted, testing how watch time is tracked in these cases for events like pausing, seeking, power state changes, control changes, and display type changes.

3. **Group Related Functionalities:**  Organize the observed functionalities into logical groups.

    * **Basic Playback Tracking:** Starting, stopping, seeking, and destruction.
    * **Categorization:**  How watch time is broken down based on different media characteristics and platform features.
    * **Hysteresis:** The mechanism for delaying finalization on certain events.
    * **Specific Scenarios:** Media Foundation, muted playback.

4. **Identify Potential Relationships with Web Technologies:**  Consider how the tested features relate to JavaScript, HTML, and CSS.

    * **JavaScript:**  JavaScript controls media playback (play, pause, seek, volume). The `WatchTimeReporter` likely interacts with JavaScript events or APIs.
    * **HTML:** The `<video>` and `<audio>` elements are the targets for media playback. Attributes like `controls` (for native controls) are relevant.
    * **CSS:**  Fullscreen mode and potentially picture-in-picture mode can be influenced by CSS.

5. **Infer Assumptions and Potential Errors:**  Think about the assumptions behind the tests and what could go wrong.

    * **Assumptions:** The tests assume accurate reporting of media time and correct triggering of events.
    * **Errors:** Incorrect event handling, inaccurate time reporting, and misunderstanding of the hysteresis mechanism are potential errors.

6. **Formulate the Summary:**  Write a concise summary covering the key functionalities, relationships to web technologies, logic/assumptions, and potential errors.

7. **Refine and Organize:** Ensure the summary is clear, well-organized, and addresses all aspects of the user's request. For the second part of the summary, focus on the functionalities *within* the provided code snippet.

By following these steps, we can effectively analyze the test code and provide a comprehensive and informative summary. The key is to look for patterns, understand the purpose of the tests, and connect them back to the broader context of web media playback.
好的，这是对提供的代码片段（第 2 部分）的功能归纳：

**主要功能归纳：**

这部分代码主要集中在测试 `WatchTimeReporter` 在各种媒体状态变化和用户交互下的行为，特别是关于 watch time 的计算和最终化（finalization）的时机。测试覆盖了以下几个核心方面：

1. **非零起始时间的处理:** 测试当媒体播放从非零时间点开始时，`WatchTimeReporter` 能否正确计算 watch time。

2. **Seek 操作的影响:**  着重测试 `seek` 操作对 watch time 报告的影响，包括：
    *  `seek` 操作会立即触发 watch time 的最终化。
    *  只有 `OnPlaying()` 事件才能清除 `seek` 状态。
    *  `seek` 操作不会覆盖之前设置的最终化时间。

3. **对象析构时的最终化:** 验证当 `WatchTimeReporter` 对象被销毁时，watch time 会被最终化并记录。

4. **Watch Time 的分类映射:**  详细测试了在不同媒体配置和状态下，watch time 如何被正确地归类到不同的桶 (buckets) 中，包括：
    * 是否有音频/视频流 (`Ac`, `All`, `Src`, `Mse`, `Eme`)
    * 是否使用原生控件 (`NativeControlsOn`, `NativeControlsOff`)
    * 是否在电池供电 (`Battery`)
    * 不同的显示类型 (`DisplayInline`, `DisplayFullscreen`, `DisplayPictureInPicture`)

5. **Hysteresis 机制的测试:**  针对多种事件（播放/暂停、音量变化、显示/隐藏、电源状态变化、控件状态变化、显示类型变化）测试了 `WatchTimeReporter` 的 hysteresis 机制。Hysteresis 指的是一个延迟最终化的机制，用于避免频繁的状态切换导致过多的报告。测试了以下两种情况：
    * **Continuation:** 在 hysteresis 时间内，状态恢复，watch time 积累继续。
    * **Finalized:**  在 hysteresis 时间到期后，watch time 被最终化。
    * 特别关注了在多个“停止”事件后，即使有“开始”事件穿插，之前的“停止”事件是否仍然能触发最终化。

6. **Media Foundation 特性测试:**  针对使用 Media Foundation 作为渲染引擎的情况，测试了特定的 watch time 键值对是否被使用和记录。区分了有 EME 和没有 EME 的情况。

7. **静音状态下的 Watch Time 报告 (MutedWatchTimeReporterTest):** 专门针对媒体静音状态下的 watch time 报告进行测试，涵盖了静音状态下的播放、暂停、seek、电源状态变化、控件状态变化和显示类型变化。

**与 JavaScript, HTML, CSS 的功能关系举例：**

虽然这段 C++ 代码本身不直接包含 JavaScript, HTML 或 CSS 代码，但它测试的功能与这些 Web 技术紧密相关：

* **JavaScript:**
    * JavaScript 代码会调用浏览器的 Media API 来控制媒体的播放、暂停、seek、音量调节等操作。`WatchTimeReporter` 监听这些操作，并在内部进行 watch time 的计算和报告。例如，当 JavaScript 调用 `video.play()` 或 `video.pause()` 时，会触发 `WatchTimeReporter` 的 `OnPlaying()` 或 `OnPaused()` 方法。
    * JavaScript 可以查询媒体元素的 `readyState` 和 `networkState`，这些信息可能间接影响 `WatchTimeReporter` 的行为，尽管测试中没有直接体现。

* **HTML:**
    * HTML 的 `<video>` 和 `<audio>` 标签定义了媒体元素。`<video>` 标签的 `controls` 属性决定是否显示原生控件，这会影响 `WatchTimeReporter` 中 `NativeControlsOn` 和 `NativeControlsOff` 的分类。
    * HTML 元素可以通过 JavaScript API 进入和退出全屏或画中画模式，这些状态变化会触发 `WatchTimeReporter` 相应的 `OnDisplayTypeChanged()` 方法，并影响 `DisplayFullscreen` 和 `DisplayPictureInPicture` 的 watch time 统计。

* **CSS:**
    * CSS 可以用于设置媒体元素的样式，包括是否全屏显示，但这通常是通过 JavaScript 控制的。CSS 本身不直接与 `WatchTimeReporter` 交互，但其影响的视觉状态（如全屏）会被 `WatchTimeReporter` 记录。

**逻辑推理的假设输入与输出举例：**

**假设输入 (针对 `SeekFinalizes` 测试):**

1. 初始化 `WatchTimeReporter`。
2. 调用 `OnPlaying()` 开始播放。
3. 经过一段时间后 (例如，累积了 10 秒的 watch time)。
4. 调用 `OnSeeking()`。

**预期输出:**

* 在调用 `OnSeeking()` 之前，watch time 会被记录到相应的分类 (例如，`Ac`, `All`, `Eme`, `Mse`, `NativeControlsOff`, `DisplayInline`)。
* 调用 `OnSeeking()` 时，会立即触发 watch time 的最终化，并将这些累积的 watch time 报告出去。
* 在 `OnSeeking()` 之后，`WatchTimeReporter` 不再处于监控状态，直到再次调用 `OnPlaying()`。

**用户或编程常见的使用错误举例：**

* **未正确调用 `OnPlaying()`:**  如果开发者忘记在媒体开始播放时调用 `OnPlaying()`，`WatchTimeReporter` 将无法开始记录 watch time。这会导致统计数据不准确。
* **过早销毁 `WatchTimeReporter` 对象:**  如果在媒体播放结束前或重要状态变更发生前销毁了 `WatchTimeReporter` 对象，可能会错过最终的 watch time 报告。测试中的 `WatchTimeReporterFinalizeOnDestruction` 就是为了确保即使在未显式调用最终化方法的情况下，在对象销毁时也能进行报告。
* **对 Hysteresis 机制理解不足:**  开发者可能错误地认为某些状态变化会立即触发报告，而实际上由于 hysteresis 机制的存在，报告会有延迟。例如，在快速连续地暂停和播放媒体时，如果时间间隔在 hysteresis 窗口内，可能只会生成一条 watch time 记录，而不是多条。

总而言之，这部分代码深入测试了 `WatchTimeReporter` 在各种复杂场景下的行为，确保其能够准确可靠地统计媒体的观看时长，为后续的性能分析和用户行为研究提供数据基础。

### 提示词
```
这是目录为blink/renderer/platform/media/watch_time_reporter_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
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