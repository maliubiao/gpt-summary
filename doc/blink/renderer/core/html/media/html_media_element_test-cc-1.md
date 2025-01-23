Response:
The user wants a summary of the functionality of the C++ source code file `blink/renderer/core/html/media/html_media_element_test.cc`. This is part 2 of a 3 part request. I need to identify the key features being tested in this section of the code. The test cases seem to revolve around:

1. **Autoplay policies**: Testing how different autoplay policies (user gesture required, no gesture required, document activation) interact with user gestures and Media Engagement Index (MEI).
2. **Window load event**: Checking if media loading (immediate vs. deferred) delays the window's 'load' event.
3. **Default tracks**: Verifying that audio and video tracks are enabled by default.
4. **Lazy loading**: Confirming the creation of a visibility observer for lazy loading.
5. **Document interactive state**: Checking the availability of `DomInteractive`.
6. **Context freezing**: Testing how the media element behaves when the document context is frozen (with and without auto-resume).
7. **GC marking**: Ensuring that certain operations (like using `TimeRanges`) are disallowed during garbage collection marking.
8. **Redirected source URLs**: Verifying that the element captures and uses redirected URLs.
9. **Pending activity**: Testing when the media element has pending activity, especially after reaching `HAVE_CURRENT_DATA` state.
10. **`OnTimeUpdate`**: Checking when `OnTimeUpdate` is called due to duration changes, play/pause/rate changes, ready state changes, and seeking.
11. **`showPoster` flag**: Testing the behavior of the `showPoster` flag during initialization, after play, seek, and autoplay.
12. **Observer notifications**: Verifying that the media element sends notifications to observers for events like playing, paused, muted status change, metadata change, size change, and remote playback metadata change.
13. **Controls visibility**: Testing how the `controls` attribute and user interaction affect the visibility of media controls.
14. **`controlsList` attribute**: Checking how the `controlsList` attribute affects whether all controls are shown.
15. **Media player destruction and reuse**: Testing when the underlying media player is destroyed or reused when moving the media element between documents, especially considering the `DocumentPictureInPictureAPI` feature.
16. **Playing with/without user activation**: Testing the `SetWasPlayedWithUserActivationAndHighMediaEngagement` method based on user interaction and MEI.
17. **Freezing with/without media player**: Checking if the element can be frozen even if the media player is not attached.
18. **Moving to another document**:  Testing basic functionality after moving the element to a different document.

Based on these observations, I can now formulate a concise summary of the functionalities covered in this part of the test file.
这是 `blink/renderer/core/html/media/html_media_element_test.cc` 文件的一部分，主要负责测试 `HTMLMediaElement` 的以下功能：

**核心媒体行为和状态管理:**

* **自动播放策略 (Autoplay Policies):**  测试不同的自动播放策略（例如，需要用户手势、不需要用户手势、文档激活）如何影响媒体元素的自动播放行为。它会模拟不同的场景，例如有用户手势或没有用户手势，以及不同的媒体参与度 (Media Engagement Index, MEI)，来验证自动播放是否被成功启动或阻止。
    * **举例说明:**  如果设置了 "需要用户手势" 的自动播放策略，即使 MEI 很高，只要用户没有进行交互，`Media()->Play()` 就不会真正启动播放 (`EXPECT_FALSE(WasAutoplayInitiated())`)。反之，如果策略是 "不需要用户手势"，`Media()->Play()` 就可以直接启动播放。
* **延迟加载对窗口加载事件的影响:** 测试当底层媒体播放器延迟加载时，是否会延迟 `window.onload` 事件的触发。
    * **举例说明:** 如果底层播放器返回 `WebMediaPlayer::LoadTiming::kDeferred`，则即使调用了 `Media()->load()`，窗口的 'load' 事件也不会被延迟 (`EXPECT_FALSE(ShouldDelayLoadEvent())`)。
* **默认音视频轨道启用:** 验证当媒体元素加载后，默认的音轨和视频轨道是否会自动启用。
* **懒加载和可见性观察者:**  测试当启用懒加载时，是否会创建相应的可见性观察者。
* **文档交互状态:** 验证 `HTMLMediaElement` 可以访问其所在文档的交互状态 (`DomInteractive`)。
* **上下文冻结 (Context Frozen):** 测试当包含媒体元素的文档上下文被冻结时（例如，进入后台），媒体元素是否会暂停播放。同时测试在不同冻结状态下（例如允许自动恢复或不允许自动恢复）的行为。
    * **举例说明:** 当文档上下文被设置为 `mojom::FrameLifecycleState::kFrozenAutoResumeMedia` 时，媒体元素会暂停，但当上下文恢复为 `mojom::FrameLifecycleState::kRunning` 时，它应该自动恢复播放。
* **垃圾回收标记期间的资源分配限制:**  测试在垃圾回收标记阶段是否正确禁止了某些资源的分配，例如 `TimeRanges` 对象。这是为了避免在垃圾回收过程中出现内存错误。
* **捕获重定向后的 URL:**  验证媒体元素是否能正确捕获并记录资源重定向后的最终 URL。
    * **假设输入:**  设置媒体元素的 `src` 属性为一个会发生重定向的 URL。
    * **预期输出:**  `Media()->downloadURL()` 应该返回重定向后的 URL。
* **空重定向 URL 的处理:**  测试当底层播放器返回空的重定向 URL 时，媒体元素是否继续使用原始的 `currentSrc`。
* **`HAVE_CURRENT_DATA` 状态后的活动状态:**  测试当媒体元素达到 `HAVE_CURRENT_DATA` 状态后，是否还有待处理的活动。
* **`ontimeupdate` 事件触发:**  测试在各种情况下（例如，duration 改变、播放/暂停、设置播放速率、readyState 改变、seek 操作）是否会触发 `ontimeupdate` 事件。
    * **假设输入:**  调用 `Media()->DurationChanged(1, false)` 将 duration 从 0 改为 1。
    * **预期输出:**  `MockMediaPlayer()->OnTimeUpdate()` 应该被调用。
* **`showPoster` 标志:** 测试 `showPoster` 标志在不同状态下的行为，例如初始化时、播放后、seek 后以及自动播放后。
    * **举例说明:**  在媒体开始播放后 (`ASSERT_FALSE(Media()->paused())`)，`Media()->IsShowPosterFlagSet()` 应该返回 `false`。

**与浏览器及渲染引擎的交互:**

* **向观察者发送媒体事件通知:** 测试 `HTMLMediaElement` 是否能正确地向观察者发送各种媒体事件的通知，例如播放状态、暂停状态、静音状态、元数据变化、尺寸变化、远程播放元数据变化以及音频服务使用状态的变化。
* **控制条的可见性:** 测试 `controls` 属性以及用户交互如何影响媒体控制条的显示。用户的手动操作应该可以覆盖 `controls` 属性的设置。
* **`controlsList` 属性的影响:** 测试 `controlsList` 属性如何影响媒体元素是否显示所有默认控制按钮。
* **跨文档移动时的媒体播放器生命周期管理:** 测试当 `HTMLMediaElement` 在不同文档之间移动时，底层的媒体播放器是否会被销毁或重用。这部分测试会考虑同源和跨域文档，以及画中画 (Picture-in-Picture) 功能是否启用等因素。
    * **假设输入:**  将一个媒体元素从 "https://a.com" 的文档移动到另一个 "https://a.com" 的文档，且 `kDocumentPictureInPictureAPI` 未启用。
    * **预期输出:**  底层的媒体播放器应该被销毁 (`EXPECT_TRUE(WasPlayerDestroyed())`)。
* **在移动元素后创建媒体播放器:** 测试在将媒体元素移动到另一个文档后再创建底层播放器时，会使用哪个文档的 frame。
* **记录用户激活状态:** 测试媒体元素是否能正确记录播放操作是否由用户激活触发，以及是否具有较高的媒体参与度。

**错误处理和异常情况:**

* **在没有媒体播放器时冻结:** 测试在媒体元素没有关联底层媒体播放器的情况下是否可以被冻结。
* **在有媒体播放器时冻结:** 测试在媒体元素关联有底层媒体播放器的情况下是否可以被冻结。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** 这些测试直接关联 HTML 的 `<video>` 和 `<audio>` 元素，以及它们的属性，例如 `autoplay`、`controls`、`controlsList` 和 `src`。测试验证了这些 HTML 属性对媒体元素行为的影响。
* **JavaScript:** 测试中使用了 JavaScript API 来操作媒体元素，例如 `media.play()`、`media.pause()`、`media.setPlaybackRate()`、`media.setCurrentTime()`，以及访问元素的属性，例如 `media.paused` 和 `media.duration`。 这些测试模拟了 JavaScript 代码与媒体元素的交互。
* **CSS:**  虽然这个测试文件主要是 C++ 代码，但其中测试了控制条的可见性，这与浏览器如何使用 CSS 渲染媒体元素的控制条相关。`ControlsVisible()` 函数的测试间接验证了 CSS 相关的行为。

**用户或编程常见的使用错误：**

虽然这个文件是测试代码，但它隐含地反映了一些用户或编程中可能出现的错误：

* **不理解自动播放策略:**  用户或开发者可能会期望媒体在某些情况下自动播放，但由于自动播放策略的限制而失败。测试用例清晰地展示了不同策略下的行为，有助于理解这些限制。
* **误解 `controls` 属性的作用:**  用户或开发者可能认为设置了 `controls` 属性就一定会显示控制条，但用户的显式操作可以覆盖这个属性。
* **在不合适的时机操作媒体元素:**  例如，在媒体资源尚未加载完成时就尝试播放或 seek，可能导致意想不到的结果。测试中会设置不同的 `readyState` 来模拟这些情况。
* **在跨文档操作时未考虑媒体播放器的生命周期:** 开发者可能没有意识到在某些跨文档移动场景下，底层的媒体播放器会被销毁，需要重新加载媒体资源。

**总结（针对第 2 部分）：**

这部分测试主要关注 `HTMLMediaElement` 的**核心媒体行为控制和状态管理**，以及其与**浏览器渲染引擎的交互**，特别是围绕**自动播放策略**、**播放器生命周期管理（尤其是在跨文档场景下）**、**事件通知**和**控制条显示**等方面进行了深入的测试。它验证了在不同配置和用户交互下，媒体元素是否能按照预期的方式工作，并涵盖了一些可能导致用户或开发者困惑的场景。

### 提示词
```
这是目录为blink/renderer/core/html/media/html_media_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
AutoplayInitiated_DocumentActivation_High_NoGesture) {
  // Setup is the following:
  // - Policy: DocumentUserActivation (aka. unified autoplay)
  // - MEI: high;
  // - Frame did not receive user gesture.
  ScopedMediaEngagementBypassAutoplayPoliciesForTest scoped_feature(true);
  Media()->GetDocument().GetSettings()->SetAutoplayPolicy(
      AutoplayPolicy::Type::kDocumentUserActivationRequired);
  SimulateHighMediaEngagement();

  Media()->Play();

  EXPECT_TRUE(WasAutoplayInitiated());
}

TEST_P(HTMLMediaElementTest, AutoplayInitiated_GestureRequired_Gesture) {
  // Setup is the following:
  // - Policy: user gesture is required.
  // - Frame received a user gesture.
  // - MEI doesn't matter as it's not used by the policy.
  Media()->GetDocument().GetSettings()->SetAutoplayPolicy(
      AutoplayPolicy::Type::kUserGestureRequired);
  LocalFrame::NotifyUserActivation(
      Media()->GetDocument().GetFrame(),
      mojom::UserActivationNotificationType::kTest);

  Media()->Play();

  EXPECT_FALSE(WasAutoplayInitiated());
}

TEST_P(HTMLMediaElementTest, AutoplayInitiated_NoGestureRequired_Gesture) {
  // Setup is the following:
  // - Policy: no user gesture is required.
  // - Frame received a user gesture.
  // - MEI doesn't matter as it's not used by the policy.
  Media()->GetDocument().GetSettings()->SetAutoplayPolicy(
      AutoplayPolicy::Type::kNoUserGestureRequired);
  LocalFrame::NotifyUserActivation(
      Media()->GetDocument().GetFrame(),
      mojom::UserActivationNotificationType::kTest);

  Media()->Play();

  EXPECT_FALSE(WasAutoplayInitiated());
}

TEST_P(HTMLMediaElementTest, AutoplayInitiated_NoGestureRequired_NoGesture) {
  // Setup is the following:
  // - Policy: no user gesture is required.
  // - Frame did not receive a user gesture.
  // - MEI doesn't matter as it's not used by the policy.
  Media()->GetDocument().GetSettings()->SetAutoplayPolicy(
      AutoplayPolicy::Type::kNoUserGestureRequired);

  Media()->Play();

  EXPECT_TRUE(WasAutoplayInitiated());
}

TEST_P(HTMLMediaElementTest,
       DeferredMediaPlayerLoadDoesNotDelayWindowLoadEvent) {
  // Source isn't really important, we just need something to let load algorithm
  // run up to the point of calling WebMediaPlayer::Load().
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));

  // WebMediaPlayer will signal that it will defer loading to some later time.
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());
  EXPECT_CALL(*MockMediaPlayer(), Load(_, _, _, _))
      .WillOnce(Return(WebMediaPlayer::LoadTiming::kDeferred));

  // Window's 'load' event starts out "delayed".
  EXPECT_TRUE(ShouldDelayLoadEvent());
  Media()->load();
  test::RunPendingTasks();

  // No longer delayed because WMP loading is deferred.
  EXPECT_FALSE(ShouldDelayLoadEvent());
}

TEST_P(HTMLMediaElementTest, ImmediateMediaPlayerLoadDoesDelayWindowLoadEvent) {
  // Source isn't really important, we just need something to let load algorithm
  // run up to the point of calling WebMediaPlayer::Load().
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));

  // WebMediaPlayer will signal that it will do the load immediately.
  EXPECT_CALL(*MockMediaPlayer(), Load(_, _, _, _))
      .WillOnce(Return(WebMediaPlayer::LoadTiming::kImmediate));

  // Window's 'load' event starts out "delayed".
  EXPECT_TRUE(ShouldDelayLoadEvent());
  Media()->load();
  test::RunPendingTasks();

  // Still delayed because WMP loading is not deferred.
  EXPECT_TRUE(ShouldDelayLoadEvent());
}

TEST_P(HTMLMediaElementTest, DefaultTracksAreEnabled) {
  // Default tracks should start enabled, not be created then enabled.
  EXPECT_CALL(*MockMediaPlayer(), EnabledAudioTracksChanged(_)).Times(0);
  EXPECT_CALL(*MockMediaPlayer(), SelectedVideoTrackChanged(_)).Times(0);

  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  SetReadyState(HTMLMediaElement::kHaveFutureData);

  ASSERT_EQ(1u, Media()->audioTracks().length());
  ASSERT_EQ(1u, Media()->videoTracks().length());
  EXPECT_TRUE(Media()->audioTracks().AnonymousIndexedGetter(0)->enabled());
  EXPECT_TRUE(Media()->videoTracks().AnonymousIndexedGetter(0)->selected());
}

// Ensure a visibility observer is created for lazy loading.
TEST_P(HTMLMediaElementTest, VisibilityObserverCreatedForLazyLoad) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  EXPECT_CALL(*MockMediaPlayer(), DidLazyLoad()).WillRepeatedly(Return(true));

  SetReadyState(HTMLMediaElement::kHaveFutureData);
  EXPECT_EQ(HasLazyLoadObserver(), GetParam() == MediaTestParam::kVideo);
}

TEST_P(HTMLMediaElementTest, DomInteractive) {
  EXPECT_FALSE(Media()->GetDocument().GetTiming().DomInteractive().is_null());
}

TEST_P(HTMLMediaElementTest, ContextFrozen) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  Media()->Play();

  test::RunPendingTasks();
  SetReadyState(HTMLMediaElement::kHaveFutureData);

  // First, set frozen but with auto resume.
  EXPECT_CALL((*MockMediaPlayer()), OnFrozen());
  EXPECT_FALSE(Media()->paused());
  GetExecutionContext()->SetLifecycleState(
      mojom::FrameLifecycleState::kFrozenAutoResumeMedia);
  EXPECT_TRUE(Media()->paused());
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  // Now, if we set back to running the media should auto resume.
  GetExecutionContext()->SetLifecycleState(
      mojom::FrameLifecycleState::kRunning);
  EXPECT_FALSE(Media()->paused());

  // Then set to frozen without auto resume.
  EXPECT_CALL((*MockMediaPlayer()), OnFrozen());
  GetExecutionContext()->SetLifecycleState(mojom::FrameLifecycleState::kFrozen);
  EXPECT_TRUE(Media()->paused());
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  // Now, the media should stay paused.
  GetExecutionContext()->SetLifecycleState(
      mojom::FrameLifecycleState::kRunning);
  EXPECT_TRUE(Media()->paused());
}

TEST_P(HTMLMediaElementTest, GcMarkingNoAllocWebTimeRanges) {
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  auto* thread_state = ThreadState::Current();
  ThreadState::NoAllocationScope no_allocation_scope(thread_state);
  EXPECT_FALSE(thread_state->IsAllocationAllowed());
  // Use of TimeRanges is not allowed during GC marking (crbug.com/970150)
#if DCHECK_IS_ON()
  EXPECT_DEATH_IF_SUPPORTED(MakeGarbageCollected<TimeRanges>(0, 0), "");
#endif  // DCHECK_IS_ON()
  // Instead of using TimeRanges, WebTimeRanges can be used without GC
  Vector<WebTimeRanges> ranges;
  ranges.emplace_back();
  ranges[0].emplace_back(0, 0);
}

// Reproduce crbug.com/970150
TEST_P(HTMLMediaElementTest, GcMarkingNoAllocHasActivity) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  Media()->Play();

  test::RunPendingTasks();
  SetReadyState(HTMLMediaElement::kHaveFutureData);
  SetError(MakeGarbageCollected<MediaError>(MediaError::kMediaErrDecode, ""));

  EXPECT_FALSE(Media()->paused());

  auto* thread_state = ThreadState::Current();
  ThreadState::NoAllocationScope no_allocation_scope(thread_state);
  EXPECT_FALSE(thread_state->IsAllocationAllowed());
  Media()->HasPendingActivity();
}

TEST_P(HTMLMediaElementTest, CapturesRedirectedSrc) {
  // Verify that the element captures the redirected URL.
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  Media()->Play();
  test::RunPendingTasks();

  // Should start at the original.
  EXPECT_EQ(Media()->downloadURL(), Media()->currentSrc());

  KURL redirected_url("https://redirected.com");
  EXPECT_CALL(*MockMediaPlayer(), GetSrcAfterRedirects())
      .WillRepeatedly(Return(GURL(redirected_url)));
  SetReadyState(HTMLMediaElement::kHaveFutureData);

  EXPECT_EQ(Media()->downloadURL(), redirected_url);
}

TEST_P(HTMLMediaElementTest, EmptyRedirectedSrcUsesOriginal) {
  // If the player returns an empty URL for the redirected src, then the element
  // should continue using currentSrc().
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  Media()->Play();
  test::RunPendingTasks();
  EXPECT_EQ(Media()->downloadURL(), Media()->currentSrc());
  SetReadyState(HTMLMediaElement::kHaveFutureData);
  EXPECT_EQ(Media()->downloadURL(), Media()->currentSrc());
}

TEST_P(HTMLMediaElementTest, NoPendingActivityAfterCurrentData) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  MockWebMediaPlayer* mock_wmpi =
      reinterpret_cast<MockWebMediaPlayer*>(Media()->GetWebMediaPlayer());
  EXPECT_CALL(*mock_wmpi, WouldTaintOrigin()).WillRepeatedly(Return(true));
  EXPECT_NE(mock_wmpi, nullptr);

  EXPECT_TRUE(MediaShouldBeOpaque());
  EXPECT_TRUE(Media()->HasPendingActivity());
  EXPECT_CALL(*MockMediaPlayer(), GetSrcAfterRedirects)
      .WillRepeatedly(Return(GURL()));
  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  SetReadyState(HTMLMediaElement::kHaveCurrentData);
  test::RunPendingTasks();
  EXPECT_FALSE(Media()->HasPendingActivity());
}

TEST_P(HTMLMediaElementTest, OnTimeUpdate_DurationChange) {
  // Prepare the player.
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  // Change from no duration to 1s will trigger OnTimeUpdate().
  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->DurationChanged(1, false);
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  // Change from 1s to 2s will trigger OnTimeUpdate().
  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->DurationChanged(2, false);
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  // No duration change -> no OnTimeUpdate().
  Media()->DurationChanged(2, false);
}

TEST_P(HTMLMediaElementTest, OnTimeUpdate_PlayPauseSetRate) {
  // Prepare the player.
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->Play();
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->setPlaybackRate(0.5);
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate()).Times(testing::AtLeast(1));
  Media()->pause();
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->setPlaybackRate(1.5);
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->Play();
}

TEST_P(HTMLMediaElementTest, OnTimeUpdate_ReadyState) {
  // Prepare the player.
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  // The ready state affects the progress of media time, so the player should
  // be kept informed.
  EXPECT_CALL(*MockMediaPlayer(), GetSrcAfterRedirects)
      .WillRepeatedly(Return(GURL()));
  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  SetReadyState(HTMLMediaElement::kHaveCurrentData);
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  SetReadyState(HTMLMediaElement::kHaveFutureData);
}

TEST_P(HTMLMediaElementTest, OnTimeUpdate_Seeking) {
  // Prepare the player and seekable ranges -- setCurrentTime()'s prerequisites.
  WebTimeRanges seekable;
  seekable.Add(0, 3);
  EXPECT_CALL(*MockMediaPlayer(), Seekable).WillRepeatedly(Return(seekable));
  EXPECT_CALL(*MockMediaPlayer(), GetSrcAfterRedirects)
      .WillRepeatedly(Return(GURL()));
  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  SetReadyState(HTMLMediaElement::kHaveCurrentData);

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->setCurrentTime(1);
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  EXPECT_CALL(*MockMediaPlayer(), Seekable).WillRepeatedly(Return(seekable));
  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());
  Media()->setCurrentTime(2);
}

TEST_P(HTMLMediaElementTest, ShowPosterFlag_InitiallyTrue) {
  // ShowPosterFlag should be true upon initialization
  EXPECT_TRUE(Media()->IsShowPosterFlagSet());

  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  EXPECT_TRUE(Media()->IsShowPosterFlagSet());

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  // ShowPosterFlag should still be true once video is ready to play
  EXPECT_TRUE(Media()->IsShowPosterFlagSet());
}

TEST_P(HTMLMediaElementTest, ShowPosterFlag_FalseAfterPlay) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  Media()->Play();
  test::RunPendingTasks();

  // ShowPosterFlag should be false once video is playing
  ASSERT_FALSE(Media()->paused());
  EXPECT_FALSE(Media()->IsShowPosterFlagSet());
}

TEST_P(HTMLMediaElementTest, ShowPosterFlag_FalseAfterSeek) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  ASSERT_NE(Media()->duration(), 0.0);
  Media()->setCurrentTime(Media()->duration() / 2);
  test::RunPendingTasks();

  EXPECT_FALSE(Media()->IsShowPosterFlagSet());
}

TEST_P(HTMLMediaElementTest, ShowPosterFlag_FalseAfterAutoPlay) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  Media()->SetBooleanAttribute(html_names::kAutoplayAttr, true);
  test::RunPendingTasks();

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  ASSERT_TRUE(WasAutoplayInitiated());
  ASSERT_FALSE(Media()->paused());
  EXPECT_FALSE(Media()->IsShowPosterFlagSet());
}

TEST_P(HTMLMediaElementTest, ShowPosterFlag_FalseAfterPlayBeforeReady) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));

  // Initially we have nothing, we're not playing, trying to play, and the 'show
  // poster' flag is set
  EXPECT_EQ(Media()->getReadyState(), HTMLMediaElement::kHaveNothing);
  EXPECT_TRUE(Media()->paused());
  EXPECT_FALSE(PotentiallyPlaying());
  EXPECT_TRUE(Media()->IsShowPosterFlagSet());

  // Attempt to begin playback
  Media()->Play();
  test::RunPendingTasks();

  // We still have no data, but we're not paused, and the 'show poster' flag is
  // not set
  EXPECT_EQ(Media()->getReadyState(), HTMLMediaElement::kHaveNothing);
  EXPECT_FALSE(Media()->paused());
  EXPECT_FALSE(PotentiallyPlaying());
  EXPECT_FALSE(Media()->IsShowPosterFlagSet());

  // Pretend we have data to begin playback
  SetReadyState(HTMLMediaElement::kHaveFutureData);

  // We should have data, be playing, and the show poster flag should be unset
  EXPECT_EQ(Media()->getReadyState(), HTMLMediaElement::kHaveFutureData);
  EXPECT_FALSE(Media()->paused());
  EXPECT_TRUE(PotentiallyPlaying());
  EXPECT_FALSE(Media()->IsShowPosterFlagSet());
}

TEST_P(HTMLMediaElementTest, SendMediaPlayingToObserver) {
  WaitForPlayer();

  NotifyMediaPlaying();
  EXPECT_TRUE(ReceivedMessageMediaPlaying());
}

TEST_P(HTMLMediaElementTest, SendMediaPausedToObserver) {
  WaitForPlayer();

  NotifyMediaPaused(true);
  EXPECT_TRUE(ReceivedMessageMediaPaused(true));

  NotifyMediaPaused(false);
  EXPECT_TRUE(ReceivedMessageMediaPaused(false));
}

TEST_P(HTMLMediaElementTest, SendMutedStatusChangeToObserver) {
  WaitForPlayer();

  NotifyMutedStatusChange(true);
  EXPECT_TRUE(ReceivedMessageMutedStatusChange(true));

  NotifyMutedStatusChange(false);
  EXPECT_TRUE(ReceivedMessageMutedStatusChange(false));
}

TEST_P(HTMLMediaElementTest, SendMediaMetadataChangedToObserver) {
  WaitForPlayer();

  bool has_audio = false;
  bool has_video = true;
  bool is_encrypted_media = false;
  media::AudioCodec audio_codec = media::AudioCodec::kUnknown;
  media::VideoCodec video_codec = media::VideoCodec::kUnknown;
  media::MediaContentType media_content_type =
      media::MediaContentType::kTransient;

  NotifyMediaMetadataChanged(has_audio, has_video, audio_codec, video_codec,
                             media_content_type, is_encrypted_media);
  EXPECT_TRUE(ReceivedMessageMediaMetadataChanged(has_audio, has_video,
                                                  media_content_type));
  // Change values and test again.
  has_audio = true;
  has_video = false;
  media_content_type = media::MediaContentType::kOneShot;
  NotifyMediaMetadataChanged(has_audio, has_video, audio_codec, video_codec,
                             media_content_type, is_encrypted_media);
  EXPECT_TRUE(ReceivedMessageMediaMetadataChanged(has_audio, has_video,
                                                  media_content_type));

  // Send codecs. Video Codec will be ignored since `has_video` is false.
  audio_codec = media::AudioCodec::kAAC;
  video_codec = media::VideoCodec::kH264;
  NotifyMediaMetadataChanged(has_audio, has_video, audio_codec, video_codec,
                             media_content_type, is_encrypted_media);
  EXPECT_TRUE(ReceivedRemotePlaybackMetadataChange(
      media_session::mojom::blink::RemotePlaybackMetadata::New(
          "unknown", WTF::String(media::GetCodecName(audio_codec)), false,
          false, WTF::String(), is_encrypted_media)));

  has_video = true;
  NotifyMediaMetadataChanged(has_audio, has_video, audio_codec, video_codec,
                             media_content_type, is_encrypted_media);
  EXPECT_TRUE(ReceivedRemotePlaybackMetadataChange(
      media_session::mojom::blink::RemotePlaybackMetadata::New(
          WTF::String(media::GetCodecName(video_codec)),
          WTF::String(media::GetCodecName(audio_codec)), false, false,
          WTF::String(), is_encrypted_media)));
}

TEST_P(HTMLMediaElementTest, SendMediaSizeChangeToObserver) {
  WaitForPlayer();

  const gfx::Size kTestMediaSizeChangedValue(16, 9);
  NotifyMediaSizeChange(kTestMediaSizeChangedValue);
  EXPECT_TRUE(ReceivedMessageMediaSizeChange(kTestMediaSizeChangedValue));
}

TEST_P(HTMLMediaElementTest, SendRemotePlaybackMetadataChangeToObserver) {
  WaitForPlayer();
  media::VideoCodec video_codec = media::VideoCodec::kH264;
  media::AudioCodec audio_codec = media::AudioCodec::kAAC;
  bool is_remote_playback_disabled = true;
  bool is_remote_playback_started = false;
  bool is_encrypted_media = false;
  NotifyMediaMetadataChanged(true, true, audio_codec, video_codec,
                             media::MediaContentType::kTransient,
                             is_encrypted_media);
  NotifyRemotePlaybackDisabled(is_remote_playback_disabled);
  EXPECT_TRUE(ReceivedRemotePlaybackMetadataChange(
      media_session::mojom::blink::RemotePlaybackMetadata::New(
          WTF::String(media::GetCodecName(video_codec)),
          WTF::String(media::GetCodecName(audio_codec)),
          is_remote_playback_disabled, is_remote_playback_started,
          WTF::String(), is_encrypted_media)));
}

TEST_P(HTMLMediaElementTest, SendUseAudioServiceChangedToObserver) {
  WaitForPlayer();

  NotifyUseAudioServiceChanged(false);
  EXPECT_TRUE(ReceivedMessageUseAudioServiceChanged(false));

  NotifyUseAudioServiceChanged(true);
  EXPECT_TRUE(ReceivedMessageUseAudioServiceChanged(true));
}

TEST_P(HTMLMediaElementTest,
       ControlsVisibilityUserChoiceOverridesControlsAttr) {
  // Enable scripts to prevent controls being shown due to no scripts.
  Media()->GetDocument().GetSettings()->SetScriptEnabled(true);

  // Setting the controls attribute to true should show the controls.
  Media()->SetBooleanAttribute(html_names::kControlsAttr, true);
  EXPECT_TRUE(ControlsVisible());

  // Setting it to false should hide them.
  Media()->SetBooleanAttribute(html_names::kControlsAttr, false);
  EXPECT_FALSE(ControlsVisible());

  // If the user explicitly shows them, that should override the controls
  // attribute.
  Media()->SetUserWantsControlsVisible(true);
  EXPECT_TRUE(ControlsVisible());

  // Setting the controls attribute to false again should do nothing.
  Media()->SetBooleanAttribute(html_names::kControlsAttr, false);
  EXPECT_TRUE(ControlsVisible());

  // If the user explicitly hides the controls, that should also override any
  // controls attribute setting.
  Media()->SetUserWantsControlsVisible(false);
  EXPECT_FALSE(ControlsVisible());

  // So setting the controls attribute to true should not show the controls.
  Media()->SetBooleanAttribute(html_names::kControlsAttr, true);
  EXPECT_FALSE(ControlsVisible());
}

TEST_P(HTMLMediaElementTest,
       MediaShouldShowAllControlsDependsOnControlslistAttr) {
  // Enable scripts to prevent controls being shown due to no scripts.
  Media()->GetDocument().GetSettings()->SetScriptEnabled(true);

  // Setting the controls attribute to true should show the controls.
  Media()->SetBooleanAttribute(html_names::kControlsAttr, true);
  EXPECT_TRUE(MediaShouldShowAllControls());

  // Setting the controlsList attribute to a valid value should not show the
  // controls.
  Media()->setAttribute(blink::html_names::kControlslistAttr,
                        AtomicString("nofullscreen"));
  EXPECT_FALSE(MediaShouldShowAllControls());

  // Removing the controlsList attribute should show the controls.
  Media()->removeAttribute(blink::html_names::kControlslistAttr);
  EXPECT_TRUE(MediaShouldShowAllControls());

  // Setting the controlsList attribute to an invalid value should still show
  // the controls.
  Media()->setAttribute(blink::html_names::kControlslistAttr,
                        AtomicString("foo"));
  EXPECT_TRUE(MediaShouldShowAllControls());

  // Setting the controlsList attribute to another valid value should not show
  // the controls.
  Media()->setAttribute(blink::html_names::kControlslistAttr,
                        AtomicString("noplaybackrate"));
  EXPECT_FALSE(MediaShouldShowAllControls());

  // If the user explicitly shows them, that should override the controlsList
  // attribute.
  Media()->SetUserWantsControlsVisible(true);
  EXPECT_TRUE(MediaShouldShowAllControls());
}

TEST_P(HTMLMediaElementTest,
       DestroyMediaPlayerWhenSwitchingSameOriginDocumentsIfReuseIsNotEnabled) {
  // Ensure that the WebMediaPlayer is destroyed when moving to a same-origin
  // document, if `kDocumentPictureInPictureAPI` is not enabled.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(false);
  MoveElementAndTestPlayerDestruction(
      "https://a.com", "https://a.com",
      /*should_destroy=*/true,
      /*is_new_document_picture_in_picture=*/false,
      /*is_old_document_picture_in_picture=*/false,
      /*is_new_document_opener=*/false,
      /*is_old_document_opener=*/false);
}

TEST_P(
    HTMLMediaElementTest,
    DestroyMediaPlayerWhenSwitchingDifferentOriginDocumentsIfReuseIsNotEnabled) {
  // Ensure that the WebMediaPlayer is destroyed when moving to a new origin
  // document, if `kDocumentPictureInPictureAPI` is not enabled.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(false);
  MoveElementAndTestPlayerDestruction(
      "https://a.com", "https://b.com",
      /*should_destroy=*/true,
      /*is_new_document_picture_in_picture=*/false,
      /*is_old_document_picture_in_picture=*/false,
      /*is_new_document_opener=*/false,
      /*is_old_document_opener=*/false);
}

TEST_P(
    HTMLMediaElementTest,
    DoNotDestroyMediaPlayerWhenSwitchingSameOriginDocumentsIfReuseIsEnabled) {
  // Ensure that the WebMediaPlayer is re-used when moving to a same-origin
  // document, if `kDocumentPictureInPictureAPI` is enabled.  Note that this
  // also tests moving from pip back to the opener, which should be retained.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(true);
  MoveElementAndTestPlayerDestruction(
      "https://a.com", "https://a.com",
      /*should_destroy=*/false,
      /*is_new_document_picture_in_picture=*/true,
      /*is_old_document_picture_in_picture=*/false,
      /*is_new_document_opener=*/false,
      /*is_old_document_opener=*/true);
}

TEST_P(
    HTMLMediaElementTest,
    DestroyMediaPlayerWhenSwitchingSameOriginDocumentsIfNewDocumentIsNotInPictureInPicture) {
  // Ensure that the WebMediaPlayer is destroyed when moving to a same-origin
  // document when the new frame is in picture in picture window, if
  // 'kDocumentPictureInPictureAPI' is enabled.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(true);
  MoveElementAndTestPlayerDestruction(
      "https//a.com", "https://a.com",
      /*should_destroy=*/true,
      /*is_new_document_picture_in_picture=*/false,
      /*is_old_document_picture_in_picture=*/false,
      /*is_new_document_opener=*/false,
      /*is_old_document_opener=*/false);
}

TEST_P(
    HTMLMediaElementTest,
    DestroyMediaPlayerWhenSwitchingSameOriginDocumentsIfFirstDocumentIsInPictureInPicture) {
  // Ensure that the WebMediaPlayer is destroyed when moving to a same-origin
  // document when the old document is in picture-in-picture window on the first
  // move, if `kDocumentPictureInPictureAPI` is enabled.  Note that, on
  // subsequent moves, we'd expect it to be retained.  For the special case
  // where the element is never added to the opener, it should be destroyed.
  // See `HTMLMediaElement::ShouldReusePlayer()` for more information.  Note
  // that the 'retained' case is tested elsewhere, since `MoveElement...` tests
  // moving to the new document and also back to the old one: see
  // `DoNotDestroyMediaPlayerWhenSwitchingSameOriginDocumentsIfReuseIsEnabled`.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(true);
  MoveElementAndTestPlayerDestruction(
      "https://a.com", "https://a.com",
      /*should_destroy=*/true,
      /*is_new_document_picture_in_picture=*/false,
      /*is_old_document_picture_in_picture=*/true,
      /*is_new_document_opener=*/true,
      /*is_old_document_opener=*/false);
}

TEST_P(
    HTMLMediaElementTest,
    DestroyMediaPlayerWhenSwitchingSameOriginDocumentsIfNotOpenerPipRelation) {
  // Ensure that the WebMediaPlayer is destroyed when moving to a
  // same-origin document when the new document is in picture-in-picture window
  // but not opened from old document.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(true);
  MoveElementAndTestPlayerDestruction(
      "https://a.com", "https://a.com",
      /*should_destroy=*/true,
      /*is_new_document_picture_in_picture=*/true,
      /*is_old_document_picture_in_picture=*/false,
      /*is_new_document_opener=*/false,
      /*is_old_document_opener=*/false);
}

TEST_P(
    HTMLMediaElementTest,
    DestroyMediaPlayerWhenSwitchingDifferentOriginDocumentsIfReuseIsEnabled) {
  // Ensure that the WebMediaPlayer is destroyed when moving to a new origin
  // document, if `kDocumentPictureInPictureAPI` is enabled. Re-use should only
  // occur if it's a same-origin document.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(true);
  MoveElementAndTestPlayerDestruction(
      "https://a.com", "https://b.com",
      /*should_destroy=*/true,
      /*is_new_document_picture_in_picture=*/true,
      /*is_old_document_picture_in_picture=*/false,
      /*is_new_document_opener=*/false,
      /*is_old_document_opener=*/true);
}

TEST_P(HTMLMediaElementTest,
       DestroyMediaPlayerWhenUnloadingOpenerIfReuseIsEnabled) {
  // Ensure that the WebMediaPlayer is re-used, that navigating the opener away
  // causes the player to be destroyed.
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(true);
  const char* origin = "https://a.com";
  SetSecurityOrigin(origin);
  WaitForPlayer();
  auto new_dummy_page_holder =
      CreatePageWithSecurityOrigin(origin, /*is_picture_in_picture=*/true);
  new_dummy_page_holder->GetDocument().GetFrame()->SetOpener(
      Media()->GetDocument().GetFrame());
  new_dummy_page_holder->GetDocument().adoptNode(Media(), ASSERT_NO_EXCEPTION);

  EXPECT_FALSE(WasPlayerDestroyed());
  GetDomWindow()->FrameDestroyed();
  EXPECT_TRUE(WasPlayerDestroyed());
}

TEST_P(HTMLMediaElementTest,
       CreateMediaPlayerAfterMovingElementUsesOpenerFrameIfReuseIsEnabled) {
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(true);
  // Move the element before creating the player.
  const char* origin = "https://a.com";
  SetSecurityOrigin(origin);
  auto new_dummy_page_holder =
      CreatePageWithSecurityOrigin(origin, /*is_picture_in_picture=*/true);
  Document& new_document = new_dummy_page_holder->GetDocument();
  LocalFrame* old_frame = Media()->GetDocument().GetFrame();
  new_document.GetFrame()->SetOpener(old_frame);
  EXPECT_EQ(old_frame, Media()->LocalFrameForPlayer());
  new_document.adoptNode(Media(), ASSERT_NO_EXCEPTION);
  // The element should still use the original frame.
  EXPECT_EQ(old_frame, Media()->LocalFrameForPlayer());
}

TEST_P(HTMLMediaElementTest,
       CreateMediaPlayerAfterMovingElementUsesNewFrameIfReuseIsNotEnabled) {
  ScopedDocumentPictureInPictureAPIForTest scoped_feature(false);
  // Move the element before creating the player.
  const char* origin = "https://a.com";
  SetSecurityOrigin(origin);
  auto new_dummy_page_holder =
      CreatePageWithSecurityOrigin(origin, /*is_picture_in_picture=*/false);
  Document& new_document = new_dummy_page_holder->GetDocument();
  LocalFrame* old_frame = Media()->GetDocument().GetFrame();
  EXPECT_EQ(old_frame, Media()->LocalFrameForPlayer());
  new_document.adoptNode(Media(), ASSERT_NO_EXCEPTION);
  // The element should no longer use the original frame.
  EXPECT_NE(old_frame, Media()->LocalFrameForPlayer());
}

TEST_P(HTMLMediaElementTest, PlayedWithoutUserActivation) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  EXPECT_CALL(*MockMediaPlayer(),
              SetWasPlayedWithUserActivationAndHighMediaEngagement(false));
  Media()->Play();
}

TEST_P(HTMLMediaElementTest, PlayedWithUserActivation) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  LocalFrame::NotifyUserActivation(
      Media()->GetDocument().GetFrame(),
      mojom::UserActivationNotificationType::kTest);

  EXPECT_CALL(*MockMediaPlayer(),
              SetWasPlayedWithUserActivationAndHighMediaEngagement(false));
  Media()->Play();
}

TEST_P(HTMLMediaElementTest, PlayedWithUserActivationAndHighMediaEngagement) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  SimulateHighMediaEngagement();
  test::RunPendingTasks();

  LocalFrame::NotifyUserActivation(
      Media()->GetDocument().GetFrame(),
      mojom::UserActivationNotificationType::kTest);

  EXPECT_CALL(*MockMediaPlayer(),
              SetWasPlayedWithUserActivationAndHighMediaEngagement(true));
  Media()->Play();
}

TEST_P(HTMLMediaElementTest, PlayedWithUserActivationBeforeLoad) {
  LocalFrame::NotifyUserActivation(
      Media()->GetDocument().GetFrame(),
      mojom::UserActivationNotificationType::kTest);

  EXPECT_CALL(*MockMediaPlayer(),
              SetWasPlayedWithUserActivationAndHighMediaEngagement(_))
      .Times(0);
  Media()->Play();
}

TEST_P(HTMLMediaElementTest, CanFreezeWithoutMediaPlayerAttached) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  EXPECT_CALL(*MockMediaPlayer(),
              SetWasPlayedWithUserActivationAndHighMediaEngagement(false));
  Media()->Play();

  ResetWebMediaPlayer();
  EXPECT_FALSE(Media()->GetWebMediaPlayer());
  EXPECT_TRUE(MediaIsPlaying());

  // Freeze with auto resume.
  MediaContextLifecycleStateChanged(
      mojom::FrameLifecycleState::kFrozenAutoResumeMedia);

  EXPECT_FALSE(MediaIsPlaying());
}

TEST_P(HTMLMediaElementTest, CanFreezeWithMediaPlayerAttached) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  EXPECT_CALL(*MockMediaPlayer(),
              SetWasPlayedWithUserActivationAndHighMediaEngagement(false));
  EXPECT_CALL(*MockMediaPlayer(), OnFrozen());
  Media()->Play();

  EXPECT_TRUE(Media()->GetWebMediaPlayer());
  EXPECT_TRUE(MediaIsPlaying());

  // Freeze with auto resume.
  MediaContextLifecycleStateChanged(
      mojom::FrameLifecycleState::kFrozenAutoResumeMedia);

  EXPECT_FALSE(MediaIsPlaying());
}

TEST_P(HTMLMediaElementTest, MoveToAnotherDocument) {
  auto* second_document =
      dummy_page_holder_->GetDocument().implementation().createHTMLDocument();

  // The second document is not active. When Media() is moved over, it triggers
  // a call to HTMLMediaElement::ShouldShowControls. This should not violate any
  // DCHECKs.
  second_document->body()->AppendChild(Media());

  // Destroying the first document should
```