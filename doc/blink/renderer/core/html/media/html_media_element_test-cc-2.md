Response:
The user wants a summary of the functionalities covered in the provided C++ code snippet for testing the `HTMLMediaElement` in the Chromium Blink engine. This is the third part of a larger file, so I need to synthesize information from the previous parts if possible, though they are not provided.

Here's a breakdown of the functionalities demonstrated in this specific snippet:

1. **Preventing issues after context destruction:**  Tests that loading a media element after its execution context is destroyed throws an error.
2. **Managing Video Visibility Tracker:**  Several tests focus on the lifecycle of the `VideoVisibilityTracker`, ensuring it's detached and attached correctly under various conditions:
    - When the video is paused.
    - When the video ends.
    - When the context is destroyed.
    - When the video is removed from the DOM.
    - When the underlying `WebMediaPlayer` is cleared.
    - When the video is moved within the DOM.
    - During fullscreen transitions (both on the video itself and on other elements).
3. **Handling track selection via URL fragments:** Tests the ability to select specific audio and video tracks when the media URL includes a `#track` fragment. It also covers cases with invalid or multiple track selections.

For each functionality, I'll consider its relation to JavaScript, HTML, and CSS, provide examples, and think about potential user errors.
这是`blink/renderer/core/html/media/html_media_element_test.cc`文件的第三部分，它主要关注以下功能：

**核心功能归纳：**

1. **处理在执行上下文销毁后加载媒体的情况：**  测试了当V8内存被清除（导致元素的执行上下文被销毁）后尝试加载媒体元素是否会抛出错误。
2. **视频可见性追踪器的生命周期管理：**  详细测试了 `VideoVisibilityTracker` 在各种场景下的正确分离和附加，以确保在不需要时不会占用资源，并在需要时能够正常工作。这些场景包括：
    - 视频暂停
    - 视频播放结束
    - 元素的执行上下文被销毁
    - 元素从DOM中移除
    - 底层的 `WebMediaPlayer` 被清除
    - 视频元素插入到DOM中
    - 视频元素进入和退出全屏模式（包括视频元素自身以及其他元素触发的全屏模式）
    - 视频暂停后再次播放并进入全屏模式
    - 视频元素移动到新的文档中
3. **通过URL片段选择媒体轨道：** 测试了通过在媒体URL中使用 `#track` 片段来指定要启用的音轨和选择的视频轨道的功能。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**
    * **错误处理：**  `LoadingFailsAfterContextDestruction` 测试模拟了 JavaScript 执行环境被销毁后，JavaScript 代码尝试调用 `media.load()` 时，media元素能否正确抛出错误。
        * **假设输入：** JavaScript 代码在页面卸载或者其他导致V8内存被清除的情况下，尝试调用一个已存在的 `<video>` 元素的 `load()` 方法。
        * **预期输出：**  JavaScript 代码捕获到一个错误，表明媒体加载失败。
    * **事件监听：**  `VideoVisibilityTrackerStatusUpdatedOnVideoEnterAndExitFullscreen` 等测试关注 `VideoVisibilityTracker` 如何监听 `fullscreenchange` 事件，这与 JavaScript 的事件监听机制密切相关。
        * **假设输入：** JavaScript 代码调用 `videoElement.requestFullscreen()` 进入全屏，或者用户通过浏览器操作退出全屏。
        * **预期输出：**  `fullscreenchange` 事件被触发，`VideoVisibilityTracker` 根据全屏状态进行相应的操作（分离或附加）。
    * **媒体 API：** 测试直接操作 HTMLMediaElement 对象的属性和方法，例如 `play()`, `pause()`, `setSrc()`, `audioTracks`, `videoTracks`, `ended` 等。
        * **假设输入：** JavaScript 代码设置 `<video>` 元素的 `src` 属性为一个包含 `#track` 片段的 URL，例如 `videoElement.src = "http://example.com/foo.mp4#track=audio2"`。
        * **预期输出：**  当媒体加载后，指定的音轨 (audio2) 会被启用。
* **HTML:**
    * **`<video>` 和 `<audio>` 元素：** 这些测试是针对 HTML 中的媒体元素进行的。测试会创建和操作这些元素，例如添加到 `document.body` 中，或者设置其 `src` 属性。
        * **假设输入：** HTML 结构中包含一个 `<video>` 元素，并且通过 JavaScript 设置了其 `src` 属性。
        * **预期输出：**  根据测试逻辑，视频元素会尝试加载指定的资源，并可能触发相应的事件和状态变化。
    * **DOM 操作：**  `VideoVisibilityTrackerDetachedOnRemovedFrom` 和 `VideoVisibilityTrackerInsertingPlayingVideoReusesTracker` 等测试涉及到 DOM 节点的添加和移除操作。
        * **假设输入：**  JavaScript 代码使用 `videoElement.remove()` 将视频元素从 DOM 中移除，或者使用 `parentElement.appendChild(videoElement)` 将视频元素添加到另一个父元素中。
        * **预期输出：**  `VideoVisibilityTracker` 会根据元素的 DOM 结构变化进行相应的处理。
* **CSS:**
    * 虽然这个测试文件本身不直接测试 CSS，但 `VideoVisibilityTrackerStatusUpdatedOnVideoEnterAndExitFullscreen` 等测试间接涉及到全屏 API，而全屏状态的改变通常会影响元素的 CSS 样式。
        * **假设输入：**  用户或 JavaScript 代码请求视频元素进入全屏。
        * **预期输出：**  浏览器可能会应用一些默认的全屏样式，或者开发者可以通过 CSS 自定义全屏样式。`VideoVisibilityTracker` 会根据全屏状态进行分离或附加。

**逻辑推理及假设输入与输出：**

* **`LoadingFailsAfterContextDestruction`:**
    * **假设输入：**  一个 `<video>` 元素已经加载了媒体资源，然后页面的执行上下文被销毁，之后尝试调用 `videoElement.load()`。
    * **预期输出：**  `Media()->error()` 返回 `true`，表示加载失败并产生错误。
* **`VideoVisibilityTrackerDetachedOnPause`:**
    * **假设输入：**  一个 `<video>` 元素正在播放，`VideoVisibilityTracker` 已经附加到文档中。
    * **预期输出：**  调用 `videoElement.pause()` 后，`VideoVisibilityTrackerAttachedToDocument(video)` 返回 `nullptr`，表示追踪器已被分离。
* **`StartVideoWithTrackSelectionFragment`:**
    * **假设输入：**  `<video>` 元素的 `src` 属性设置为 `http://example.com/foo.mp4#track=audio2&track=video3`。
    * **预期输出：**  加载完成后，音轨 "audio2" 被启用，视频轨道 "video3" 被选中。

**用户或编程常见的使用错误举例说明：**

* **在上下文销毁后尝试加载：** 开发者可能会在页面卸载或者组件销毁后，没有正确清理对媒体元素的引用，导致在错误的生命周期阶段尝试调用 `load()` 方法。这可能导致程序崩溃或产生未预期的行为。
* **没有正确处理全屏事件：** 开发者可能没有监听 `fullscreenchange` 事件，或者在全屏状态改变时没有更新 UI 或执行相应的逻辑，导致用户体验不佳。 例如，在进入全屏后，控制栏可能没有正确显示或隐藏。
* **错误的 URL 片段格式：** 开发者可能使用了错误的 `#track` 片段格式，例如 `#track=invalidtrackid`，导致预期的音视频轨道没有被正确选择。
* **同时选择多个互斥的轨道：**  尽管测试中 `StartVideoWithDoubleTrackSelection` 展示了只会选择最后一个指定的音轨，但开发者可能错误地认为可以同时启用多个主音轨或选择多个视频轨道，导致理解上的偏差。

**总结此部分功能：**

这部分测试代码主要集中在 `HTMLMediaElement` 的两个关键方面：**在异常情况下的资源管理和恢复能力**（例如，执行上下文销毁后的行为）以及 **视频可见性追踪器的精细化控制**，确保其在各种场景下的正确生命周期管理，从而优化性能和避免资源浪费。此外，它还测试了 **通过 URL 片段进行媒体轨道选择** 的功能，这为开发者提供了更灵活的媒体资源控制方式。  这些测试共同确保了 `HTMLMediaElement` 在不同场景下的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/core/html/media/html_media_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
not cause anything unusual to happen.
  dummy_page_holder_.reset();

  EXPECT_FALSE(ControlsVisible());
}

TEST_P(HTMLMediaElementTest, LoadingFailsAfterContextDestruction) {
  // Ensure the media element throws an error if loading is attempted after V8
  // memory is purged (which destroys the element's execution context).

  constexpr char kOrigin[] = "https://a.com";
  SetSecurityOrigin(kOrigin);
  WaitForPlayer();
  auto new_dummy_page_holder =
      CreatePageWithSecurityOrigin(kOrigin, /*is_picture_in_picture=*/false);
  EXPECT_FALSE(WasPlayerDestroyed());

  LocalFrame* frame = Media()->LocalFrameForPlayer();
  ASSERT_TRUE(frame);
  frame->ForciblyPurgeV8Memory();
  test::RunPendingTasks();
  EXPECT_TRUE(WasPlayerDestroyed());
  EXPECT_FALSE(Media()->error());

  Media()->load();
  test::RunPendingTasks();
  EXPECT_TRUE(Media()->error());
}

TEST_P(HTMLMediaElementTest, VideoVisibilityTrackerDetachedOnPause) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  video->GetDocument().body()->AppendChild(video);
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();
  video->Play();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);

  // Pause the video, and verify that the visibility tracker has been detached.
  video->pause();
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
}

TEST_P(HTMLMediaElementTest, VideoVisibilityTrackerDetachedOnEnded) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  video->GetDocument().body()->AppendChild(video);
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();
  video->Play();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);

  MockWebMediaPlayer* mock_wmpi =
      reinterpret_cast<MockWebMediaPlayer*>(video->GetWebMediaPlayer());
  ASSERT_NE(mock_wmpi, nullptr);

  // Advance current time to duration, and verify that the visibility tracker
  // has been detached.
  testing::Mock::VerifyAndClearExpectations(mock_wmpi);
  EXPECT_CALL(*mock_wmpi, CurrentTime())
      .WillRepeatedly(Return(video->duration()));
  EXPECT_CALL(*mock_wmpi, IsEnded()).WillRepeatedly(Return(true));
  EXPECT_TRUE(video->ended());
  TimeChanged();
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
}

TEST_P(HTMLMediaElementTest, VideoVisibilityTrackerDetachedOnContextDestroyed) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  video->GetDocument().body()->AppendChild(video);
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();
  video->Play();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);

  // Destroy context, and verify that the visibility tracker has been detached.
  ContextDestroyed();
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
}

TEST_P(HTMLMediaElementTest, VideoVisibilityTrackerDetachedOnRemovedFrom) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();
  video->Play();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);

  // Remove video, and verify that the visibility tracker has been detached.
  NonThrowableExceptionState should_not_throw;
  video->remove(should_not_throw);
  test::RunPendingTasks();

  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
}

TEST_P(HTMLMediaElementTest,
       VideoVisibilityTrackerDetachedOnWebMediaPlayerCleared) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();
  video->Play();
  EXPECT_TRUE(video->GetWebMediaPlayer());
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);

  // Clear media player, and verify that the visibility tracker has been
  // detached.
  ClearMediaPlayer();
  EXPECT_FALSE(Media()->GetWebMediaPlayer());
  EXPECT_TRUE(MediaIsPlaying());
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
}

TEST_P(HTMLMediaElementTest,
       VideoVisibilityTrackerInsertingPlayingVideoReusesTracker) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();

  MockWebMediaPlayer* mock_wmpi =
      reinterpret_cast<MockWebMediaPlayer*>(video->GetWebMediaPlayer());
  ASSERT_NE(mock_wmpi, nullptr);
  EXPECT_CALL(*mock_wmpi, CurrentTime())
      .WillRepeatedly(Return(video->duration() / 2));
  EXPECT_CALL(*mock_wmpi, IsEnded()).WillRepeatedly(Return(false));

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();
  video->Play();
  ASSERT_NE(video->visibility_tracker_for_tests(), nullptr);
  ASSERT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  const auto* tracker_before_append = video->visibility_tracker_for_tests();

  // Create div and append video element to it.
  video->GetDocument().body()->setInnerHTML(
      "<div id='container' style='width:200px; height:200px;'></div>");
  video->GetDocument()
      .body()
      ->getElementById(AtomicString("container"))
      ->AppendChild(video);

  ASSERT_NE(video->visibility_tracker_for_tests(), nullptr);
  ASSERT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  const auto* tracker_after_append = video->visibility_tracker_for_tests();

  // Ensure that tracker is re-used.
  EXPECT_EQ(tracker_before_append, tracker_after_append);
}

TEST_P(HTMLMediaElementTest,
       VideoVisibilityTrackerStatusUpdatedOnVideoEnterAndExitFullscreen) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  video->Play();
  EXPECT_TRUE(video->GetWebMediaPlayer());
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_FALSE(video->IsFullscreen());
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Simulate enter fullscreen, and verify that: the visibility tracker has been
  // detached and, the fullscreen change event listener is not removed.
  SimulateEnterFullscreen(video);
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Simulate exit fullscreen, and verify that: the visibility tracker has been
  // attached and, the fullscreen change event listener is not removed.
  SimulateExitFullscreen(video);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));
}

TEST_P(HTMLMediaElementTest,
       VideoVisibilityTrackerStatusUpdatedOnAnyElementEnterAndExitFullscreen) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());

  video->GetDocument().body()->setInnerHTML(
      "<div id='fullscreen-div' style='width:200px; height:200px;'></div>");
  Element* fullscreen_div = video->GetDocument().body()->getElementById(
      AtomicString("fullscreen-div"));
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(video->GetDocument()));

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  video->Play();
  EXPECT_TRUE(video->GetWebMediaPlayer());
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Simulate enter fullscreen on fullscreen_div, and verify that: the
  // visibility tracker has been detached and, the fullscreen change event
  // listener is not removed.
  SimulateEnterFullscreen(fullscreen_div);
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Simulate exit fullscreen on fullscreen_div, and verify that: the visibility
  // tracker has been attached and, the fullscreen change event listener is not
  // removed.
  SimulateExitFullscreen(fullscreen_div);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));
}

TEST_P(HTMLMediaElementTest,
       VideoVisibilityTrackerDetachedOnEnterFullscreenAfterVideoPauseThenPlay) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  // Play video, and verify that: the visibility tracker has been
  // attached and, the fullscreen change event listener has been registered.
  video->Play();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Pause video, and verify that: the visibility tracker has been
  // detached and, the fullscreen change event listener is not removed.
  video->pause();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Play video once again, and verify that: the visibility tracker has been
  // attached and, the fullscreen change event listener is not removed.
  video->Play();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Simulate enter fullscreen, and verify that: the visibility tracker has been
  // detached and, the fullscreen change event listener is not removed.
  SimulateEnterFullscreen(video);
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Simulate exit fullscreen, and verify that: the visibility tracker has been
  // attached and, the fullscreen change event listener is not removed.
  SimulateExitFullscreen(video);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));
}

TEST_P(
    HTMLMediaElementTest,
    VideoVisibilityTrackerDetachedOnEntereFullscreenAfterInsertingPlayingVideo) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();

  MockWebMediaPlayer* mock_wmpi =
      reinterpret_cast<MockWebMediaPlayer*>(video->GetWebMediaPlayer());
  ASSERT_NE(mock_wmpi, nullptr);
  EXPECT_CALL(*mock_wmpi, CurrentTime())
      .WillRepeatedly(Return(video->duration() / 2));
  EXPECT_CALL(*mock_wmpi, IsEnded()).WillRepeatedly(Return(false));

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  // Play video, and verify that: the visibility tracker has been
  // attached and, the fullscreen change event listener has been registered.
  video->Play();
  ASSERT_NE(video->visibility_tracker_for_tests(), nullptr);
  ASSERT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  const auto* tracker_before_append = video->visibility_tracker_for_tests();
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         tracker_before_append));

  // Create a div and append the video element to it.
  video->GetDocument().body()->setInnerHTML(
      "<div id='container' style='width:200px; height:200px;'></div>");
  video->GetDocument()
      .body()
      ->getElementById(AtomicString("container"))
      ->AppendChild(video);

  // Verify that: the visibility tracker has been detached and, the fullscreen
  // change event listener is not removed.
  ASSERT_NE(video->visibility_tracker_for_tests(), nullptr);
  ASSERT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  const auto* tracker_after_append = video->visibility_tracker_for_tests();
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         tracker_after_append));

  // Verify that tracker is re-used.
  EXPECT_EQ(tracker_before_append, tracker_after_append);

  // Simulate enter fullscreen, and verify that: the visibility tracker has been
  // detached and, the fullscreen change event listener is not removed.
  SimulateEnterFullscreen(video);
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         tracker_after_append));

  // Simulate exit fullscreen, and verify that: the visibility tracker has been
  // attached and, the fullscreen change event listener is not removed.
  SimulateExitFullscreen(video);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         tracker_after_append));
}

TEST_P(
    HTMLMediaElementTest,
    VideoVisibilityTrackerFullScreenEventListenerRemovedOnDidMoveToNewDocument) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();

  MockWebMediaPlayer* mock_wmpi =
      reinterpret_cast<MockWebMediaPlayer*>(video->GetWebMediaPlayer());
  ASSERT_NE(mock_wmpi, nullptr);
  EXPECT_CALL(*mock_wmpi, CurrentTime())
      .WillRepeatedly(Return(video->duration() / 2));
  EXPECT_CALL(*mock_wmpi, IsEnded()).WillRepeatedly(Return(false));

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  // Play video, and verify that: the visibility tracker has been
  // attached and, the fullscreen change event listener has been registered.
  video->Play();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  ASSERT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Remember the old document.
  auto& old_document = video->GetDocument();

  // Create another document and move the video element to it.
  auto* another_document = Document::Create(video->GetDocument());
  another_document->AppendChild(video);

  // Verify that the old and new document are different.
  EXPECT_NE(old_document, *another_document);

  // Verify that for the new document: the visibility tracker has been detached
  // and, the fullscreen change event listener has been removed.
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  ASSERT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_FALSE(HasEventListenerRegistered(video->GetDocument(),
                                          event_type_names::kFullscreenchange,
                                          VideoVisibilityTracker()));

  // Verify that, for the old document, the fullscreen change event listener has
  // been removed.
  EXPECT_FALSE(HasEventListenerRegistered(old_document,
                                          event_type_names::kFullscreenchange,
                                          VideoVisibilityTracker()));
}

TEST_P(HTMLMediaElementTest,
       VideoVisibilityTrackerFullScreenEventListenerRemovedOnRemovedFrom) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  // Play video, and verify that: the visibility tracker has been
  // attached and, the fullscreen change event listener has been registered.
  video->Play();
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_TRUE(HasEventListenerRegistered(video->GetDocument(),
                                         event_type_names::kFullscreenchange,
                                         VideoVisibilityTracker()));

  // Remove video, and verify that: the visibility tracker has been
  // detached and, the fullscreen change event listener has been removed.
  NonThrowableExceptionState should_not_throw;
  video->remove(should_not_throw);
  test::RunPendingTasks();
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);
  EXPECT_FALSE(HasEventListenerRegistered(
      video->GetDocument(), event_type_names::kFullscreenchange,
      video->visibility_tracker_for_tests()));
}

TEST_P(HTMLMediaElementTest,
       RequestVisibilityReturnsFalseWhenTrackerDoesNotExist) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();

  // Request visibility and verify that the returned visibility is false.
  RequestVisibilityWaiter request_visibility_waiter;
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);
  RequestVisibility(request_visibility_waiter.VisibilityCallback());
  request_visibility_waiter.WaitUntilDone();
  EXPECT_FALSE(request_visibility_waiter.MeetsVisibility());
}

TEST_P(HTMLMediaElementTest,
       RequestVisibilityReturnsFalseWhenTrackerIsNotAttached) {
  if (GetParam() != MediaTestParam::kVideo) {
    return;
  }

  auto* video = To<HTMLVideoElement>(Media());
  video->GetDocument().body()->AppendChild(video);
  video->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  test::RunPendingTasks();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  SetReadyState(HTMLMediaElement::kHaveEnoughData);
  test::RunPendingTasks();
  video->Play();
  EXPECT_TRUE(video->GetWebMediaPlayer());
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(video), nullptr);

  // Clear media player, to cause the visibility tracker to detach.
  ClearMediaPlayer();
  EXPECT_FALSE(Media()->GetWebMediaPlayer());
  EXPECT_TRUE(MediaIsPlaying());
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(video), nullptr);

  // Request visibility and verify that the returned visibility is false.
  RequestVisibilityWaiter request_visibility_waiter;
  RequestVisibility(request_visibility_waiter.VisibilityCallback());
  request_visibility_waiter.WaitUntilDone();
  EXPECT_FALSE(request_visibility_waiter.MeetsVisibility());
}

TEST_P(HTMLMediaElementTest, StartVideoWithTrackSelectionFragment) {
  std::string frag_url = "http://example.com/foo.mp4#track=audio2&track=video3";
  EXPECT_CALL(*MockMediaPlayer(), GetSrcAfterRedirects())
      .WillRepeatedly(Return(GURL(frag_url)));
  bool audio_only = GetParam() == MediaTestParam::kAudio;

  EXPECT_CALL(*MockMediaPlayer(), Load(_, _, _, _))
      .Times(1)
      .WillOnce([element = Media(), audio_only](
                    EmptyWebMediaPlayer::LoadType,
                    const blink::WebMediaPlayerSource&,
                    EmptyWebMediaPlayer::CorsMode,
                    bool) -> WebMediaPlayer::LoadTiming {
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio1", media::MediaTrack::AudioKind::kMain, "audio1", "", true,
            0, true));
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio2", media::MediaTrack::AudioKind::kMain, "audio2", "", false,
            0, true));
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio3", media::MediaTrack::AudioKind::kMain, "audio3", "", false,
            0, true));
        if (!audio_only) {
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video1", media::MediaTrack::VideoKind::kMain, "video1", "", true,
              0));
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video2", media::MediaTrack::VideoKind::kMain, "video2", "",
              false, 0));
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video3", media::MediaTrack::VideoKind::kMain, "video3", "",
              false, 0));
        }
        return WebMediaPlayer::LoadTiming::kImmediate;
      });
  Media()->SetSrc(AtomicString(frag_url.c_str()));
  test::RunPendingTasks();

  uint64_t video_tracks = audio_only ? 0 : 3;
  ASSERT_EQ(3u, Media()->audioTracks().length());
  ASSERT_EQ(video_tracks, Media()->videoTracks().length());

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());

  EXPECT_CALL(*MockMediaPlayer(), EnabledAudioTracksChanged(_))
      .WillOnce([](const WebVector<WebMediaPlayer::TrackId>& tracks) {
        ASSERT_EQ(tracks.size(), 1u);
        ASSERT_EQ(tracks[0], "audio2");
      });

  if (!audio_only) {
    EXPECT_CALL(*MockMediaPlayer(), SelectedVideoTrackChanged(_))
        .WillOnce([](std::optional<WebMediaPlayer::TrackId> track) {
          ASSERT_TRUE(track.has_value());
          ASSERT_EQ(track.value(), "video3");
        });
  }

  SetReadyState(HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  EXPECT_TRUE(Media()->audioTracks().AnonymousIndexedGetter(1)->enabled());
  if (!audio_only) {
    EXPECT_TRUE(Media()->videoTracks().AnonymousIndexedGetter(2)->selected());
  }
}

TEST_P(HTMLMediaElementTest, StartVideoWithInvalidTrackSelection) {
  std::string frag_url = "http://example.com/foo.mp4#track=blahblah";
  EXPECT_CALL(*MockMediaPlayer(), GetSrcAfterRedirects())
      .WillRepeatedly(Return(GURL(frag_url)));
  bool audio_only = GetParam() == MediaTestParam::kAudio;

  EXPECT_CALL(*MockMediaPlayer(), Load(_, _, _, _))
      .Times(1)
      .WillOnce([element = Media(), audio_only](
                    EmptyWebMediaPlayer::LoadType,
                    const blink::WebMediaPlayerSource&,
                    EmptyWebMediaPlayer::CorsMode,
                    bool) -> WebMediaPlayer::LoadTiming {
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio1", media::MediaTrack::AudioKind::kMain, "audio1", "", true,
            0, true));
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio2", media::MediaTrack::AudioKind::kMain, "audio2", "", false,
            0, true));
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio3", media::MediaTrack::AudioKind::kMain, "audio3", "", false,
            0, true));
        if (!audio_only) {
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video1", media::MediaTrack::VideoKind::kMain, "video1", "", true,
              0));
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video2", media::MediaTrack::VideoKind::kMain, "video2", "",
              false, 0));
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video3", media::MediaTrack::VideoKind::kMain, "video3", "",
              false, 0));
        }
        return WebMediaPlayer::LoadTiming::kImmediate;
      });
  Media()->SetSrc(AtomicString(frag_url.c_str()));
  test::RunPendingTasks();

  uint64_t video_tracks = audio_only ? 0 : 3;
  ASSERT_EQ(3u, Media()->audioTracks().length());
  ASSERT_EQ(video_tracks, Media()->videoTracks().length());

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());

  EXPECT_CALL(*MockMediaPlayer(), EnabledAudioTracksChanged(_)).Times(0);
  EXPECT_CALL(*MockMediaPlayer(), SelectedVideoTrackChanged(_)).Times(0);

  SetReadyState(HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  EXPECT_TRUE(Media()->audioTracks().AnonymousIndexedGetter(0)->enabled());
  if (!audio_only) {
    EXPECT_TRUE(Media()->videoTracks().AnonymousIndexedGetter(0)->selected());
  }
}

TEST_P(HTMLMediaElementTest, StartVideoWithDoubleTrackSelection) {
  std::string frag_url = "http://example.com/foo.mp4#track=audio2&track=audio3";
  EXPECT_CALL(*MockMediaPlayer(), GetSrcAfterRedirects())
      .WillRepeatedly(Return(GURL(frag_url)));
  bool audio_only = GetParam() == MediaTestParam::kAudio;

  EXPECT_CALL(*MockMediaPlayer(), Load(_, _, _, _))
      .Times(1)
      .WillOnce([element = Media(), audio_only](
                    EmptyWebMediaPlayer::LoadType,
                    const blink::WebMediaPlayerSource&,
                    EmptyWebMediaPlayer::CorsMode,
                    bool) -> WebMediaPlayer::LoadTiming {
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio1", media::MediaTrack::AudioKind::kMain, "audio1", "", true,
            0, true));
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio2", media::MediaTrack::AudioKind::kMain, "audio2", "", false,
            0, true));
        element->AddMediaTrackForTesting(media::MediaTrack::CreateAudioTrack(
            "audio3", media::MediaTrack::AudioKind::kMain, "audio3", "", false,
            0, true));
        if (!audio_only) {
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video1", media::MediaTrack::VideoKind::kMain, "video1", "", true,
              0));
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video2", media::MediaTrack::VideoKind::kMain, "video2", "",
              false, 0));
          element->AddMediaTrackForTesting(media::MediaTrack::CreateVideoTrack(
              "video3", media::MediaTrack::VideoKind::kMain, "video3", "",
              false, 0));
        }
        return WebMediaPlayer::LoadTiming::kImmediate;
      });
  Media()->SetSrc(AtomicString(frag_url.c_str()));
  test::RunPendingTasks();

  uint64_t video_tracks = audio_only ? 0 : 3;
  ASSERT_EQ(3u, Media()->audioTracks().length());
  ASSERT_EQ(video_tracks, Media()->videoTracks().length());

  EXPECT_CALL(*MockMediaPlayer(), OnTimeUpdate());

  EXPECT_CALL(*MockMediaPlayer(), EnabledAudioTracksChanged(_))
      .WillOnce([](const WebVector<WebMediaPlayer::TrackId>& tracks) {
        ASSERT_EQ(tracks.size(), 1u);
        ASSERT_EQ(tracks[0], "audio3");
      });
  EXPECT_CALL(*MockMediaPlayer(), SelectedVideoTrackChanged(_)).Times(0);

  SetReadyState(HTMLMediaElement::kHaveMetadata);
  test::RunPendingTasks();

  EXPECT_TRUE(Media()->audioTracks().AnonymousIndexedGetter(2)->enabled());
  if (!audio_only) {
    EXPECT_TRUE(Media()->videoTracks().AnonymousIndexedGetter(0)->selected());
  }
}

}  // namespace blink
```