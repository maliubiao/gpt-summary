Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink engine and specifically tests the `MediaControlsImpl` class.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Class Under Test:** The filename `media_controls_impl_test.cc` and the frequent use of `MediaControls()` clearly indicate that the tests are centered around the `MediaControlsImpl` class.

2. **Understand the Purpose of Tests:**  Test files verify the behavior of a specific component. Therefore, the functionality of this file is to test various aspects of `MediaControlsImpl`.

3. **Scan the Test Names and Test Logic:**  The names of the `TEST_F` functions are highly descriptive and provide direct clues about the features being tested. I'll go through them one by one and categorize them:

    * **Time Display Formatting:** `CurrentTimeDisplayUpdates` tests how the current and remaining time are displayed and formatted.
    * **Visibility Control on Seeking:** `SeekingShowsControls` and `SeekingDoesNotShowControlsWhenNoControlsAttr` test whether the media controls appear when the user seeks, and if this behavior is affected by the `controls` attribute.
    * **Visibility During Interaction:** `ControlsRemainVisibleDuringKeyboardInteraction` and `ControlsHideAfterFocusedAndMouseMovement`/`ControlsHideAfterFocusedAndMouseMoveout` test how user interactions (keyboard, mouse) affect the visibility of the controls.
    * **Cursor Hiding:** `CursorHidesWhenControlsHide` tests if the mouse cursor is hidden when the controls are hidden.
    * **Accessibility Focus:** `AccessibleFocusShowsControls` tests if focusing on the controls via accessibility features makes them visible.
    * **Lifecycle Management:** `RemovingFromDocumentRemovesListenersAndCallbacks` and `ReInsertingInDocumentRestoresListenersAndCallbacks` test how the media controls handle being removed from and re-inserted into the DOM, focusing on event listeners and callbacks. `RemovingFromDocumentWhenResettingSrcAllowsReclamation` tests garbage collection related to detached video elements.
    * **Duration Handling:** `InitialInfinityDurationHidesDurationField` and `InfinityDurationChangeHidesDurationField` test how the controls handle infinite duration values.
    * **Volume Slider Behavior:** `ShowVolumeSliderAfterHoverTimerFired` and `VolumeSliderBehaviorWhenFocused`/`VolumeSliderDoesNotOpenWithoutAudio` test the behavior of the volume slider, including its appearance on hover and focus, and its dependency on audio presence.
    * **Cast Overlay Behavior:** `CastOverlayDefaultHidesOnTimer` and `CastOverlayShowsOnSomeEvents` test the visibility of the cast overlay button and the events that trigger its appearance.
    * **Connectivity Check:** `isConnected` tests a method to check if the media controls are connected to the DOM.
    * **Safe Area Insets:** `ControlsShouldUseSafeAreaInsets` tests if the controls respect safe area insets.
    * **Disabled State:** `MediaControlsDisabledWithNoSource` tests the initial disabled state of the controls when no media source is provided and how it changes as the source is set and metadata is loaded.
    * **Double-Tap Seeking:** `DoubleTouchChangesTime` and `DoubleTouchChangesTimeWhenZoomed` test the functionality of double-tapping on the video to seek forward or backward.
    * **Deferred Style Calculation:** `HideControlsDefersStyleCalculationOnPlaying` and `HideControlsDefersStyleCalculationOnWaiting` test if style calculations are deferred when the controls are hidden during playing and waiting states.
    * **State on Playing for Future Data:** `CheckStateOnPlayingForFutureData` tests the state of the controls when playing with potentially incomplete data.
    * **Overflow Menu in Paint Containment:** `OverflowMenuInPaintContainment` tests the rendering of the overflow menu when the media element has `contain: paint` style.

4. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**

    * **HTML:** The tests interact with HTML elements (`<video>`, `<audio>`) and their attributes (`controls`, `preload`). The presence or absence of the `controls` attribute directly affects the visibility logic being tested.
    * **CSS:** The tests check the visibility of elements using CSS properties like `display` and manipulate CSS classes (e.g., for the volume slider). The `kCursor` property is checked for cursor hiding. Safe area insets are CSS concepts.
    * **JavaScript:** Although not explicitly testing JavaScript code *in this file*, the functionality of `MediaControlsImpl` is to provide the user interface for media elements, which are heavily interacted with via JavaScript APIs in a web page. Events like `click`, `focusin`, `pointermove`, `gesturetap` are fundamental to JavaScript interaction.

5. **Identify Logic and Assumptions:**

    * **Assumptions:**  The tests assume a specific structure of the media controls (shadow DOM elements with specific pseudo-IDs). They also rely on the timing mechanisms within the Blink engine.
    * **Logic:** The tests often involve setting up a scenario (e.g., setting a media source, playing the media), performing an action (e.g., simulating a seek, a mouse move), and then asserting the expected outcome (e.g., controls are visible, time is updated).

6. **Identify Potential User/Programming Errors:**

    * **Incorrect `controls` Attribute:** A common user error is forgetting to include the `controls` attribute on a `<video>` or `<audio>` tag if they want the browser's default controls. The tests explicitly check this scenario.
    * **Unexpected Visibility:**  Developers might be surprised by when the controls appear or disappear, especially with interactions like seeking or focusing. These tests help ensure predictable behavior.
    * **Incorrect Time Formatting:** The tests for `CurrentTimeDisplayUpdates` ensure that the time is formatted correctly, which is a common UI concern.

7. **Trace User Operations (Debugging Clues):**

    * **Loading Media:** A user loading a video or audio file is the starting point.
    * **Playback Controls:** Interacting with the play/pause button, seeking bar, volume slider.
    * **Full-screen:** Entering or exiting full-screen mode (though not explicitly tested in this snippet, it's a related user action).
    * **Right-click context menu:**  Accessing the browser's context menu on the video.
    * **Keyboard shortcuts:** Using keyboard shortcuts for playback control.
    * **Casting:** Initiating casting to a remote device.
    * **Accessibility tools:** Using screen readers or keyboard navigation.

8. **Synthesize the Summary:** Combine the information gathered from the previous steps to create a concise and informative summary of the file's functionality. Focus on the "what" and "why" of the tests.

By following these steps, I can create a comprehensive and accurate summary of the provided code snippet.
这是对 `blink/renderer/modules/media_controls/media_controls_impl_test.cc` 文件第二部分的分析总结。 基于第一部分的分析，我们可以将第二部分的功能归纳如下：

**第二部分主要关注 `MediaControlsImpl` 在各种场景下的行为和状态变化，特别是与用户交互、时间管理、显示控制以及生命周期管理相关的测试。**

更具体地说，它测试了以下几个方面的功能：

1. **时间显示更新 (续):**  延续了第一部分的测试，进一步验证了在更长视频时长下，当前时间和剩余时间的显示格式和更新是否正确。

2. **控制面板的显示与隐藏逻辑 (更细致的测试):**
   * **基于用户交互的显示:** 测试了在用户进行诸如拖动进度条、点击静音按钮等键盘交互时，控制面板是否能保持显示状态，避免意外隐藏。
   * **基于鼠标移动和焦点变化的显示/隐藏:** 详细测试了在控制面板获得焦点时，鼠标移动或移出是否会影响控制面板的显示与隐藏，以及隐藏的延迟机制。
   * **光标的显示与隐藏:**  测试了当控制面板隐藏时，鼠标光标是否也会随之隐藏，以及在用户交互时重新显示的逻辑。
   * **基于无障碍焦点的显示:** 测试了通过无障碍功能获得焦点时，控制面板是否能正确显示，并在失去焦点后隐藏。

3. **生命周期管理:**
   * **从文档中移除时的清理:**  测试了当包含 `<video>` 或 `<audio>` 元素的节点从文档中移除时，相关的事件监听器和回调函数是否被正确移除，避免内存泄漏。
   * **重新插入文档后的恢复:** 测试了被移除的元素重新插入文档后，其媒体控件的监听器和回调是否能正确恢复。
   * **资源回收:** 测试了在重置媒体元素的 `src` 属性后，相关资源能否被垃圾回收，特别是针对 ResizeObserver 的影响。

4. **时长处理:**
   * **初始无限时长:** 测试了当媒体的初始时长为无限值时，时长显示字段是否会被隐藏。
   * **时长变为无限值:** 测试了当媒体时长从有限值变为无限值时，时长显示字段是否会被正确隐藏。

5. **音量滑块行为:**
   * **悬停显示延迟:** 测试了鼠标悬停在静音按钮上时，音量滑块是否会在一定延迟后显示，以及鼠标移开时的隐藏逻辑。
   * **焦点状态下的行为:** 测试了当音量滑块获得焦点时，是否会立即显示，以及在焦点状态下鼠标移开是否会隐藏滑块。
   * **无音频时的行为:** 测试了当媒体没有音频时，音量滑块是否不会显示。

6. **投屏 Overlay 的显示与隐藏:**
   * **默认隐藏:** 测试了在没有设置 `controls` 属性的情况下，投屏 overlay 按钮是否会在一段时间后自动隐藏。
   * **特定事件触发显示:** 测试了某些用户交互事件（例如点击、手势点击）是否会触发投屏 overlay 按钮的显示。

7. **连接状态:** 测试了 `isConnected()` 方法是否能正确反映 `MediaControlsImpl` 是否与 DOM 树连接。

8. **安全区域内边距 (Safe Area Insets):** 测试了媒体控件是否能正确应用安全区域的内边距，确保在异形屏幕上的显示效果。

9. **无资源时的禁用状态:** 测试了当媒体元素没有设置 `src` 属性时，播放按钮、溢出菜单按钮和时间线是否处于禁用状态，以及在设置 `src` 和加载元数据后状态的变化。

10. **双击/双指触控改变时间:** 测试了在视频区域双击或双指触控屏幕的左半部分和右半部分是否能分别实现快退和快进的功能，并考虑了页面缩放的影响。

11. **隐藏控制面板时的样式计算优化:** 测试了当控制面板被设置为隐藏时，播放状态或缓冲状态的改变是否会延迟样式计算，提高性能。

12. **播放未来数据时的状态检查:** 测试了在播放可能不完整或未来数据时，媒体控件的状态是否正确。

13. **溢出菜单在 `contain: paint` 时的行为:** 测试了当媒体元素设置了 `contain: paint` CSS 属性时，溢出菜单是否能正确显示在顶层 (top layer)。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:**  测试中频繁操作 HTML 元素，例如通过 `GetElementByShadowPseudoId` 获取 shadow DOM 中的特定元素 (例如 `-webkit-media-controls-panel`)，设置或移除元素的属性 (`controls`)，以及通过 `AppendChild` 和 `RemoveChild` 操作 DOM 结构。
* **CSS:**  通过 `IsElementVisible` 检查元素的可见性，这与 CSS 的 `display` 属性有关。`IsCursorHidden` 检查了 `cursor: none` 样式是否被应用。测试了安全区域内边距，这直接关联到 CSS 环境变量。音量滑块的显示与隐藏也可能通过添加或移除 CSS 类 (`closed`) 来实现。
* **JavaScript:**  虽然测试代码是 C++，但它模拟了 JavaScript 事件的触发，例如 `DispatchEvent(*Event::CreateBubble(event_type_names::kFocusin))` 模拟了 `focusin` 事件，`CreatePointerEvent(event_type_names::kClick)` 模拟了鼠标点击事件。`MediaControls().MediaElement().Play()` 和 `MediaControls().MediaElement().setCurrentTime()` 等方法调用了模拟的 JavaScript API。

**逻辑推理举例:**

**假设输入:** 用户在一个没有设置 `controls` 属性的 `<video>` 元素上开始播放视频。
**预期输出:**  初始状态下，媒体控件面板应该是隐藏的。

**假设输入:** 用户在播放过程中，将鼠标悬停在静音按钮上超过 0.2 秒。
**预期输出:** 音量滑块应该显示出来。

**用户或编程常见的使用错误举例:**

* **忘记设置 `controls` 属性:** 用户（开发者）在 HTML 中使用 `<video>` 或 `<audio>` 标签时，忘记添加 `controls` 属性，导致浏览器默认的媒体控件不会显示。这个测试用例(`SeekingDoesNotShowControlsWhenNoControlsAttr`)验证了在没有 `controls` 属性时，即使 seek 操作也不会显示控件。
* **意外的控制面板隐藏:** 开发者可能期望在某些用户交互后控制面板仍然显示，但由于某些原因（例如焦点丢失），控制面板意外隐藏。相关的测试用例(`ControlsHideAfterFocusedAndMouseMovement`)可以帮助开发者理解和避免这类问题。

**用户操作到达此处的调试线索:**

1. **用户加载包含 `<video>` 或 `<audio>` 标签的网页。**
2. **如果标签包含 `controls` 属性，浏览器会创建默认的媒体控件。**
3. **用户与媒体控件进行交互:** 例如，点击播放/暂停按钮，拖动进度条，点击静音按钮，或者将鼠标悬停在控件上。
4. **用户可能使用键盘快捷键控制媒体播放。**
5. **在某些情况下，用户可能会通过辅助功能 (例如 Tab 键) 聚焦到媒体控件上。**
6. **用户可能会发起投屏操作。**
7. **用户可能会双击或双指触控视频区域。**
8. **如果开发者没有设置 `controls` 属性，他们可能会使用 JavaScript API 来控制媒体的播放和行为，而 `MediaControlsImpl` 仍然在后台管理一些默认行为。**

当开发者发现媒体控件的行为不符合预期时，他们可能会查看 Blink 引擎的源代码，包括这些测试用例，来理解其内部逻辑。这些测试用例可以作为调试的线索，帮助开发者理解在特定用户操作下，媒体控件的哪些代码会被执行，以及预期的行为是什么。 开发者可以通过运行这些测试用例来验证他们对媒体控件行为的理解，或者在修改相关代码后确保没有引入新的 bug。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
{360600, "100:10:00"},
  };

  double duration = 360600;  // Long enough to check each of the tests.
  LoadMediaWithDuration(duration);
  EnsureSizing();
  test::RunPendingTasks();

  MediaControlCurrentTimeDisplayElement* current_display =
      GetCurrentTimeDisplayElement();
  MediaControlRemainingTimeDisplayElement* duration_display =
      GetRemainingTimeDisplayElement();

  // The value and format of the duration display should be correct.
  EXPECT_EQ(360600, duration_display->CurrentValue());
  EXPECT_EQ("/ 100:10:00", GetDisplayedTime(duration_display));

  for (const auto& testcase : tests) {
    current_display->SetCurrentValue(testcase.time);

    // Current value should be updated.
    EXPECT_EQ(testcase.time, current_display->CurrentValue());

    // Display text should be updated and correctly formatted.
    EXPECT_EQ(testcase.expected_result, GetDisplayedTime(current_display));
  }
}

namespace {

class MediaControlsImplTestWithMockScheduler : public MediaControlsImplTest {
 public:
  MediaControlsImplTestWithMockScheduler()
      : MediaControlsImplTest(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    EnablePlatform();
  }

 protected:
  void SetUp() override {
    // DocumentParserTiming has DCHECKS to make sure time > 0.0.
    AdvanceClock(base::Seconds(1));

    MediaControlsImplTest::SetUp();
  }

  void TearDown() override { PageTestBase::TearDown(); }

  void ToggleOverflowMenu() {
    MediaControls().ToggleOverflowMenu();
    platform()->RunUntilIdle();
  }

  bool IsCursorHidden() {
    const CSSPropertyValueSet* style = MediaControls().InlineStyle();
    if (!style)
      return false;
    return style->GetPropertyValue(CSSPropertyID::kCursor) == "none";
  }
};

}  // namespace

TEST_F(MediaControlsImplTestWithMockScheduler, SeekingShowsControls) {
  Element* panel = GetElementByShadowPseudoId(MediaControls(),
                                              "-webkit-media-controls-panel");
  ASSERT_NE(nullptr, panel);

  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();

  // Hide the controls to start.
  MediaControls().Hide();
  EXPECT_FALSE(IsElementVisible(*panel));

  // Seeking should cause the controls to become visible.
  SimulateOnSeeking();
  EXPECT_TRUE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTestWithMockScheduler,
       SeekingDoesNotShowControlsWhenNoControlsAttr) {
  Element* panel = GetElementByShadowPseudoId(MediaControls(),
                                              "-webkit-media-controls-panel");
  ASSERT_NE(nullptr, panel);

  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();

  // Hide the controls to start.
  MediaControls().Hide();
  EXPECT_FALSE(IsElementVisible(*panel));

  // Seeking should not cause the controls to become visible because the
  // controls attribute is not set.
  SimulateOnSeeking();
  EXPECT_FALSE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTestWithMockScheduler,
       ControlsRemainVisibleDuringKeyboardInteraction) {
  EnsureSizing();

  Element* panel = MediaControls().PanelElement();

  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();

  // Controls start out visible.
  EXPECT_TRUE(IsElementVisible(*panel));

  // Tabbing between controls prevents controls from hiding.
  FastForwardBy(base::Seconds(2));
  MuteButtonElement()->DispatchEvent(
      *Event::CreateBubble(event_type_names::kFocusin));
  FastForwardBy(base::Seconds(2));
  EXPECT_TRUE(IsElementVisible(*panel));

  // Seeking on the timeline or volume bar prevents controls from hiding.
  TimelineElement()->DispatchEvent(
      *Event::CreateBubble(event_type_names::kInput));
  FastForwardBy(base::Seconds(2));
  EXPECT_TRUE(IsElementVisible(*panel));

  // Pressing a key prevents controls from hiding.
  MuteButtonElement()->DispatchEvent(
      *Event::CreateBubble(event_type_names::kKeypress));
  FastForwardBy(base::Seconds(2));
  EXPECT_TRUE(IsElementVisible(*panel));

  // Once user interaction stops, controls can hide.
  FastForwardBy(base::Seconds(2));
  SimulateTransitionEnd(*panel);
  EXPECT_FALSE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTestWithMockScheduler,
       ControlsHideAfterFocusedAndMouseMovement) {
  EnsureSizing();

  Element* panel = MediaControls().PanelElement();
  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();

  // Controls start out visible
  EXPECT_TRUE(IsElementVisible(*panel));
  FastForwardBy(base::Seconds(1));

  // Mouse move while focused
  MediaControls().DispatchEvent(*Event::Create(event_type_names::kFocusin));
  MediaControls().MediaElement().SetFocused(true,
                                            mojom::blink::FocusType::kNone);
  MediaControls().DispatchEvent(
      *CreatePointerEvent(event_type_names::kPointermove));

  // Controls should remain visible
  FastForwardBy(base::Seconds(2));
  EXPECT_TRUE(IsElementVisible(*panel));

  // Controls should hide after being inactive for 4 seconds.
  FastForwardBy(base::Seconds(2));
  EXPECT_FALSE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTestWithMockScheduler,
       ControlsHideAfterFocusedAndMouseMoveout) {
  EnsureSizing();

  Element* panel = MediaControls().PanelElement();
  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();

  // Controls start out visible
  EXPECT_TRUE(IsElementVisible(*panel));
  FastForwardBy(base::Seconds(1));

  // Mouse move out while focused, controls should hide
  MediaControls().DispatchEvent(*Event::Create(event_type_names::kFocusin));
  MediaControls().MediaElement().SetFocused(true,
                                            mojom::blink::FocusType::kNone);
  MediaControls().DispatchEvent(*Event::Create(event_type_names::kPointerout));
  EXPECT_FALSE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTestWithMockScheduler, CursorHidesWhenControlsHide) {
  EnsureSizing();

  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));

  // Cursor is not initially hidden.
  EXPECT_FALSE(IsCursorHidden());

  MediaControls().MediaElement().Play();

  // Tabbing into the controls shows the controls and therefore the cursor.
  MediaControls().DispatchEvent(*Event::Create(event_type_names::kFocusin));
  EXPECT_FALSE(IsCursorHidden());

  // Once the controls hide, the cursor is hidden.
  FastForwardBy(base::Seconds(4));
  EXPECT_TRUE(IsCursorHidden());

  // If the mouse moves, the controls are shown and the cursor is no longer
  // hidden.
  MediaControls().DispatchEvent(
      *CreatePointerEvent(event_type_names::kPointermove));
  EXPECT_FALSE(IsCursorHidden());

  // Once the controls hide again, the cursor is hidden again.
  FastForwardBy(base::Seconds(4));
  EXPECT_TRUE(IsCursorHidden());
}

TEST_F(MediaControlsImplTestWithMockScheduler, AccessibleFocusShowsControls) {
  EnsureSizing();

  Element* panel = MediaControls().PanelElement();

  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();

  FastForwardBy(base::Seconds(4));
  EXPECT_TRUE(IsElementVisible(*panel));

  MediaControls().OnAccessibleFocus();
  FastForwardBy(base::Seconds(4));
  EXPECT_TRUE(IsElementVisible(*panel));

  FastForwardBy(base::Seconds(4));
  SimulateHideMediaControlsTimerFired();
  EXPECT_TRUE(IsElementVisible(*panel));

  MediaControls().OnAccessibleBlur();
  FastForwardBy(base::Seconds(4));
  SimulateHideMediaControlsTimerFired();
  EXPECT_FALSE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTest,
       RemovingFromDocumentRemovesListenersAndCallbacks) {
  auto page_holder = std::make_unique<DummyPageHolder>();

  auto* element =
      MakeGarbageCollected<HTMLVideoElement>(page_holder->GetDocument());
  page_holder->GetDocument().body()->AppendChild(element);

  RemotePlayback& remote_playback = RemotePlayback::From(*element);

  EXPECT_TRUE(remote_playback.HasEventListeners());
  EXPECT_TRUE(HasAvailabilityCallbacks(remote_playback));

  WeakPersistent<HTMLMediaElement> weak_persistent_video = element;
  {
    Persistent<HTMLMediaElement> persistent_video = element;
    page_holder->GetDocument().body()->setInnerHTML("");

    // When removed from the document, the event listeners should have been
    // dropped.
    EXPECT_FALSE(remote_playback.HasEventListeners());
    EXPECT_FALSE(HasAvailabilityCallbacks(remote_playback));
  }

  page_holder->GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  // It has been GC'd.
  EXPECT_EQ(nullptr, weak_persistent_video);
}

TEST_F(MediaControlsImplTest,
       RemovingFromDocumentWhenResettingSrcAllowsReclamation) {
  // Regression test: https://crbug.com/918064
  //
  // Test ensures that unified heap garbage collections are able to collect
  // detached HTMLVideoElements. The tricky part is that ResizeObserver's are
  // treated as roots as long as they have observations which prevent the video
  // element from being collected.

  auto page_holder = std::make_unique<DummyPageHolder>();
  page_holder->GetDocument().write("<video controls>");
  page_holder->GetDocument().Parser()->Finish();

  auto& video = To<HTMLVideoElement>(
      *page_holder->GetDocument().QuerySelector(AtomicString("video")));
  WeakPersistent<HTMLMediaElement> weak_persistent_video = &video;

  video.remove();
  page_holder->GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(nullptr, weak_persistent_video);
}

TEST_F(MediaControlsImplTest,
       ReInsertingInDocumentRestoresListenersAndCallbacks) {
  auto page_holder = std::make_unique<DummyPageHolder>();

  auto* element =
      MakeGarbageCollected<HTMLVideoElement>(page_holder->GetDocument());
  page_holder->GetDocument().body()->AppendChild(element);

  RemotePlayback& remote_playback = RemotePlayback::From(*element);

  // This should be a no-op. We keep a reference on the media element to avoid
  // an unexpected GC.
  {
    Persistent<HTMLMediaElement> video_holder = element;
    page_holder->GetDocument().body()->RemoveChild(element);
    page_holder->GetDocument().body()->AppendChild(video_holder.Get());
    EXPECT_TRUE(remote_playback.HasEventListeners());
    EXPECT_TRUE(HasAvailabilityCallbacks(remote_playback));
  }
}

TEST_F(MediaControlsImplTest, InitialInfinityDurationHidesDurationField) {
  EnsureSizing();

  LoadMediaWithDuration(std::numeric_limits<double>::infinity());

  MediaControlRemainingTimeDisplayElement* duration_display =
      GetRemainingTimeDisplayElement();

  EXPECT_FALSE(duration_display->IsWanted());
  EXPECT_EQ(std::numeric_limits<double>::infinity(),
            duration_display->CurrentValue());
}

TEST_F(MediaControlsImplTest, InfinityDurationChangeHidesDurationField) {
  EnsureSizing();

  LoadMediaWithDuration(42);

  MediaControlRemainingTimeDisplayElement* duration_display =
      GetRemainingTimeDisplayElement();

  EXPECT_TRUE(duration_display->IsWanted());
  EXPECT_EQ(42, duration_display->CurrentValue());

  MediaControls().MediaElement().DurationChanged(
      std::numeric_limits<double>::infinity(), false /* request_seek */);
  test::RunPendingTasks();

  EXPECT_FALSE(duration_display->IsWanted());
  EXPECT_EQ(std::numeric_limits<double>::infinity(),
            duration_display->CurrentValue());
}

TEST_F(MediaControlsImplTestWithMockScheduler,
       ShowVolumeSliderAfterHoverTimerFired) {
  const double kTimeToShowVolumeSlider = 0.2;

  EnsureSizing();
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  FastForwardBy(base::Seconds(1));
  SetHasAudio(true);
  SimulateLoadedMetadata();

  ScopedWebTestMode web_test_mode(false);

  Element* volume_slider = VolumeSliderElement();
  Element* mute_btn = MuteButtonElement();

  ASSERT_NE(nullptr, volume_slider);
  ASSERT_NE(nullptr, mute_btn);

  EXPECT_TRUE(IsElementVisible(*mute_btn));
  EXPECT_TRUE(volume_slider->classList().contains(AtomicString("closed")));

  DOMRect* mute_btn_rect = mute_btn->GetBoundingClientRect();
  gfx::PointF mute_btn_center(
      mute_btn_rect->left() + mute_btn_rect->width() / 2,
      mute_btn_rect->top() + mute_btn_rect->height() / 2);
  gfx::PointF edge(0, 0);

  // Hover on mute button and stay
  MouseMoveTo(mute_btn_center);
  FastForwardBy(base::Seconds(kTimeToShowVolumeSlider - 0.001));
  EXPECT_TRUE(volume_slider->classList().contains(AtomicString("closed")));

  FastForwardBy(base::Seconds(0.002));
  EXPECT_FALSE(volume_slider->classList().contains(AtomicString("closed")));

  MouseMoveTo(edge);
  EXPECT_TRUE(volume_slider->classList().contains(AtomicString("closed")));

  // Hover on mute button and move away before timer fired
  MouseMoveTo(mute_btn_center);
  FastForwardBy(base::Seconds(kTimeToShowVolumeSlider - 0.001));
  EXPECT_TRUE(volume_slider->classList().contains(AtomicString("closed")));

  MouseMoveTo(edge);
  EXPECT_TRUE(volume_slider->classList().contains(AtomicString("closed")));
}

TEST_F(MediaControlsImplTestWithMockScheduler,
       VolumeSliderBehaviorWhenFocused) {
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  FastForwardBy(base::Seconds(1));

  SetHasAudio(true);

  ScopedWebTestMode web_test_mode(false);

  Element* volume_slider = VolumeSliderElement();

  ASSERT_NE(nullptr, volume_slider);

  // Volume slider starts out hidden
  EXPECT_TRUE(volume_slider->classList().contains(AtomicString("closed")));

  // Tab focus should open volume slider immediately.
  volume_slider->SetFocused(true, mojom::blink::FocusType::kNone);
  volume_slider->DispatchEvent(*Event::Create(event_type_names::kFocus));
  EXPECT_FALSE(volume_slider->classList().contains(AtomicString("closed")));

  // Unhover slider while focused should not close slider.
  volume_slider->DispatchEvent(*Event::Create(event_type_names::kMouseout));
  EXPECT_FALSE(volume_slider->classList().contains(AtomicString("closed")));
}

TEST_F(MediaControlsImplTestWithMockScheduler,
       VolumeSliderDoesNotOpenWithoutAudio) {
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  FastForwardBy(base::Seconds(1));
  SetHasAudio(false);

  ScopedWebTestMode web_test_mode(false);

  Element* volume_slider = VolumeSliderElement();
  Element* mute_button = MuteButtonElement();

  ASSERT_NE(nullptr, volume_slider);

  // Volume slider starts out hidden.
  EXPECT_TRUE(volume_slider->classList().contains(AtomicString("closed")));

  // Tab focus on the mute button should not open the volume slider since there
  // is no audio to control.
  mute_button->SetFocused(true, mojom::blink::FocusType::kNone);
  mute_button->DispatchEvent(*Event::Create(event_type_names::kFocus));
  EXPECT_TRUE(volume_slider->classList().contains(AtomicString("closed")));
}

TEST_F(MediaControlsImplTest, CastOverlayDefaultHidesOnTimer) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  Element* cast_overlay_button = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overlay-cast-button");
  ASSERT_NE(nullptr, cast_overlay_button);

  SimulateRemotePlaybackAvailable();
  EXPECT_TRUE(IsElementVisible(*cast_overlay_button));

  // Starts playback because overlay never hides if paused.
  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();
  test::RunPendingTasks();

  SimulateHideMediaControlsTimerFired();
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));
}

TEST_F(MediaControlsImplTest, CastOverlayShowsOnSomeEvents) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  Element* cast_overlay_button = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overlay-cast-button");
  ASSERT_NE(nullptr, cast_overlay_button);

  Element* overlay_enclosure = GetElementByShadowPseudoId(
      MediaControls(), "-webkit-media-controls-overlay-enclosure");
  ASSERT_NE(nullptr, overlay_enclosure);

  SimulateRemotePlaybackAvailable();
  EXPECT_TRUE(IsElementVisible(*cast_overlay_button));

  // Starts playback because overlay never hides if paused.
  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();
  test::RunPendingTasks();

  SimulateRemotePlaybackAvailable();
  SimulateHideMediaControlsTimerFired();
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));

  // The overlay button appears on tap and click.
  for (const AtomicString& event_name :
       {event_type_names::kGesturetap, event_type_names::kClick}) {
    overlay_enclosure->DispatchEvent(event_name == "gesturetap"
                                         ? *Event::Create(event_name)
                                         : *CreatePointerEvent(event_name));
    EXPECT_TRUE(IsElementVisible(*cast_overlay_button));

    SimulateHideMediaControlsTimerFired();
    EXPECT_FALSE(IsElementVisible(*cast_overlay_button));
  }

  // The overlay button does not appear on pointer move.
  overlay_enclosure->DispatchEvent(
      *CreatePointerEvent(event_type_names::kPointerover));
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));

  // The overlay button does not appear on click if the overlay button shouldn't
  // be shown.
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     true);
  overlay_enclosure->DispatchEvent(
      *CreatePointerEvent(event_type_names::kClick));
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));
}

TEST_F(MediaControlsImplTest, isConnected) {
  EXPECT_TRUE(MediaControls().isConnected());
  MediaControls().MediaElement().remove();
  EXPECT_FALSE(MediaControls().isConnected());
}

TEST_F(MediaControlsImplTest, ControlsShouldUseSafeAreaInsets) {
  UpdateAllLifecyclePhasesForTest();
  {
    const ComputedStyle* style = MediaControls().GetComputedStyle();
    EXPECT_EQ(0.0, style->MarginTop().Pixels());
    EXPECT_EQ(0.0, style->MarginLeft().Pixels());
    EXPECT_EQ(0.0, style->MarginBottom().Pixels());
    EXPECT_EQ(0.0, style->MarginRight().Pixels());
  }

  GetStyleEngine().EnsureEnvironmentVariables().SetVariable(
      UADefinedVariable::kSafeAreaInsetTop, "1px");
  GetStyleEngine().EnsureEnvironmentVariables().SetVariable(
      UADefinedVariable::kSafeAreaInsetLeft, "2px");
  GetStyleEngine().EnsureEnvironmentVariables().SetVariable(
      UADefinedVariable::kSafeAreaInsetBottom, "3px");
  GetStyleEngine().EnsureEnvironmentVariables().SetVariable(
      UADefinedVariable::kSafeAreaInsetRight, "4px");

  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  {
    const ComputedStyle* style = MediaControls().GetComputedStyle();
    EXPECT_EQ(1.0, style->MarginTop().Pixels());
    EXPECT_EQ(2.0, style->MarginLeft().Pixels());
    EXPECT_EQ(3.0, style->MarginBottom().Pixels());
    EXPECT_EQ(4.0, style->MarginRight().Pixels());
  }
}

TEST_F(MediaControlsImplTest, MediaControlsDisabledWithNoSource) {
  EXPECT_EQ(MediaControls().State(), MediaControlsImpl::kNoSource);

  EXPECT_TRUE(PlayButtonElement()->FastHasAttribute(html_names::kDisabledAttr));
  EXPECT_TRUE(
      OverflowMenuButtonElement()->FastHasAttribute(html_names::kDisabledAttr));
  EXPECT_TRUE(TimelineElement()->FastHasAttribute(html_names::kDisabledAttr));

  MediaControls().MediaElement().setAttribute(html_names::kPreloadAttr,
                                              AtomicString("none"));
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  test::RunPendingTasks();
  SimulateLoadedMetadata();

  EXPECT_EQ(MediaControls().State(), MediaControlsImpl::kNotLoaded);

  EXPECT_FALSE(
      PlayButtonElement()->FastHasAttribute(html_names::kDisabledAttr));
  EXPECT_FALSE(
      OverflowMenuButtonElement()->FastHasAttribute(html_names::kDisabledAttr));
  EXPECT_TRUE(TimelineElement()->FastHasAttribute(html_names::kDisabledAttr));

  MediaControls().MediaElement().removeAttribute(html_names::kPreloadAttr);
  SimulateLoadedMetadata();

  EXPECT_EQ(MediaControls().State(), MediaControlsImpl::kLoadingMetadataPaused);

  EXPECT_FALSE(
      PlayButtonElement()->FastHasAttribute(html_names::kDisabledAttr));
  EXPECT_FALSE(
      OverflowMenuButtonElement()->FastHasAttribute(html_names::kDisabledAttr));
  EXPECT_FALSE(TimelineElement()->FastHasAttribute(html_names::kDisabledAttr));
}

TEST_F(MediaControlsImplTest, DoubleTouchChangesTime) {
  double duration = 60;  // 1 minute.
  LoadMediaWithDuration(duration);
  EnsureSizing();
  MediaControls().MediaElement().setCurrentTime(30);
  test::RunPendingTasks();

  // We've set the video to the halfway mark.
  EXPECT_EQ(30, MediaControls().MediaElement().currentTime());

  DOMRect* videoRect = MediaControls().MediaElement().GetBoundingClientRect();
  ASSERT_LT(0, videoRect->width());
  gfx::PointF leftOfCenter(videoRect->left() + (videoRect->width() / 2) - 5,
                           videoRect->top() + 5);
  gfx::PointF rightOfCenter(videoRect->left() + (videoRect->width() / 2) + 5,
                            videoRect->top() + 5);

  // Double-tapping left of center should shift the time backwards by 10
  // seconds.
  GestureDoubleTapAt(leftOfCenter);
  test::RunPendingTasks();
  EXPECT_EQ(20, MediaControls().MediaElement().currentTime());

  // Double-tapping right of center should shift the time forwards by 10
  // seconds.
  GestureDoubleTapAt(rightOfCenter);
  test::RunPendingTasks();
  EXPECT_EQ(30, MediaControls().MediaElement().currentTime());
}

TEST_F(MediaControlsImplTest, DoubleTouchChangesTimeWhenZoomed) {
  double duration = 60;  // 1 minute.
  LoadMediaWithDuration(duration);
  EnsureSizing();
  MediaControls().MediaElement().setCurrentTime(30);
  test::RunPendingTasks();

  // We've set the video to the halfway mark.
  EXPECT_EQ(30, MediaControls().MediaElement().currentTime());

  DOMRect* videoRect = MediaControls().MediaElement().GetBoundingClientRect();
  ASSERT_LT(0, videoRect->width());
  gfx::PointF leftOfCenter(videoRect->left() + (videoRect->width() / 2) - 5,
                           videoRect->top() + 10);
  gfx::PointF rightOfCenter(videoRect->left() + (videoRect->width() / 2) + 5,
                            videoRect->top() + 10);

  // Add a zoom factor and ensure that it's properly handled.
  MediaControls().GetDocument().GetFrame()->SetLayoutZoomFactor(2);

  // Double-tapping left of center should shift the time backwards by 10
  // seconds.
  GestureDoubleTapAt(leftOfCenter);
  test::RunPendingTasks();
  EXPECT_EQ(20, MediaControls().MediaElement().currentTime());

  // Double-tapping right of center should shift the time forwards by 10
  // seconds.
  GestureDoubleTapAt(rightOfCenter);
  test::RunPendingTasks();
  EXPECT_EQ(30, MediaControls().MediaElement().currentTime());
}

TEST_F(MediaControlsImplTest, HideControlsDefersStyleCalculationOnPlaying) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  MediaControls().MediaElement().Play();
  test::RunPendingTasks();

  Element* panel = GetElementByShadowPseudoId(MediaControls(),
                                              "-webkit-media-controls-panel");
  ASSERT_NE(nullptr, panel);
  EXPECT_FALSE(IsElementVisible(*panel));
  UpdateAllLifecyclePhasesForTest();
  Document& document = this->GetDocument();
  EXPECT_FALSE(document.NeedsLayoutTreeUpdate());

  int old_element_count = document.GetStyleEngine().StyleForElementCount();

  SimulateMediaControlPlaying();
  SimulateOnPlaying();
  EXPECT_EQ(MediaControls().State(),
            MediaControlsImpl::ControlsState::kPlaying);

  // With the controls hidden, playback state change should not trigger style
  // calculation.
  EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();
  int new_element_count = document.GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(old_element_count, new_element_count);

  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     true);
  EXPECT_TRUE(IsElementVisible(*panel));

  // Showing the controls should trigger the deferred style calculation.
  EXPECT_TRUE(document.NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();
  new_element_count = document.GetStyleEngine().StyleForElementCount();
  EXPECT_LT(old_element_count, new_element_count);
}

TEST_F(MediaControlsImplTest, HideControlsDefersStyleCalculationOnWaiting) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  MediaControls().MediaElement().Play();
  test::RunPendingTasks();

  Element* panel = GetElementByShadowPseudoId(MediaControls(),
                                              "-webkit-media-controls-panel");
  ASSERT_NE(nullptr, panel);
  EXPECT_FALSE(IsElementVisible(*panel));
  UpdateAllLifecyclePhasesForTest();
  Document& document = this->GetDocument();
  EXPECT_FALSE(document.NeedsLayoutTreeUpdate());

  int old_element_count = document.GetStyleEngine().StyleForElementCount();

  SimulateMediaControlBuffering();
  SimulateOnWaiting();
  EXPECT_EQ(MediaControls().State(),
            MediaControlsImpl::ControlsState::kBuffering);

  // With the controls hidden, playback state change should not trigger style
  // calculation.
  EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();
  int new_element_count = document.GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(old_element_count, new_element_count);

  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     true);
  EXPECT_TRUE(IsElementVisible(*panel));

  // Showing the controls should trigger the deferred style calculation.
  EXPECT_TRUE(document.NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();
  new_element_count = document.GetStyleEngine().StyleForElementCount();
  EXPECT_LT(old_element_count, new_element_count);
}

TEST_F(MediaControlsImplTest, CheckStateOnPlayingForFutureData) {
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  MediaControls().MediaElement().Play();
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();

  SimulateMediaControlPlayingForFutureData();
  EXPECT_EQ(MediaControls().State(),
            MediaControlsImpl::ControlsState::kPlaying);
}

TEST_F(MediaControlsImplTest, OverflowMenuInPaintContainment) {
  // crbug.com/1244130
  auto page_holder = std::make_unique<DummyPageHolder>();
  page_holder->GetDocument().write("<audio controls style='contain:paint'>");
  page_holder->GetDocument().Parser()->Finish();
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();
  SetMediaControlsFromElement(To<HTMLMediaElement>(
      *page_holder->GetDocument().QuerySelector(AtomicString("audio"))));

  MediaControls().ToggleOverflowMenu();
  UpdateAllLifecyclePhasesForTest();
  Element* overflow_list = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overflow-menu-list");
  ASSERT_TRUE(overflow_list);
  EXPECT_TRUE(overflow_list->IsInTopLayer());

  MediaControls().ToggleOverflowMenu();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(overflow_list->IsInTopLayer());
}

}  // namespace blink

"""


```