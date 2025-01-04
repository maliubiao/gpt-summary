Response:
The user wants to understand the functionality of the `media_controls_impl_test.cc` file in the Chromium Blink engine. They have requested a breakdown of its purpose, its relation to web technologies (JavaScript, HTML, CSS), examples of logic with inputs and outputs, common usage errors, debugging hints, and a summary of its functionality.

Here's a plan to address each point:

1. **Functionality:** The file contains unit tests for the `MediaControlsImpl` class. This class is responsible for implementing the native media controls for `<video>` and `<audio>` elements in Chromium.

2. **Relationship with JavaScript, HTML, CSS:**
    - **HTML:** The tests create and interact with `<video>` elements, checking how the media controls respond to different HTML attributes like `controls`, `disableremoteplayback`, `controlslist`.
    - **CSS:** The tests verify the visibility of various control elements by inspecting their CSS `display`, `opacity`, and `visibility` properties. They also check for the existence of specific shadow DOM elements identified by pseudo-IDs.
    - **JavaScript:** While the test file is in C++, it simulates JavaScript events like `click`, `input`, and `transitionend` that would typically be triggered by user interaction or JavaScript code. It also uses V8 bindings for creating PointerEvents.

3. **Logic Reasoning (Hypothetical Input/Output):**
    - **Input:** Setting the `disableremoteplayback` attribute on a `<video>` element.
    - **Output:** The cast button in the media controls should become hidden.
    - **Input:** Clicking on the timeline at a specific position.
    - **Output:** The `currentTime` of the media element should be updated to the corresponding time.

4. **Common Usage Errors:**
    - Incorrectly assuming that a control element is visible without considering its CSS properties or the state of the media element.
    - Not accounting for the asynchronous nature of some media events.

5. **User Operation to Reach Here (Debugging Clues):**
    - A user interacting with the native media controls on a web page (e.g., clicking play, seeking, toggling fullscreen).
    - A developer inspecting the behavior of the media controls and setting breakpoints in the `MediaControlsImpl` code or related classes.

6. **Summary of Functionality (Part 1):**  The first part of the file focuses on testing the basic visibility and behavior of various media control elements, their interaction with HTML attributes, and some core functionalities like hiding/showing controls and handling the cast button.

Let's construct the answer based on these points.
这是 `blink/renderer/modules/media_controls/media_controls_impl_test.cc` 文件的前半部分，它是一个 Chromium Blink 引擎的源代码文件，专门用于测试 `MediaControlsImpl` 类的功能。`MediaControlsImpl` 类负责实现 HTML5 `<video>` 和 `<audio>` 元素的内置媒体控件。

**功能归纳 (第 1 部分):**

这个文件的前半部分主要测试了 `MediaControlsImpl` 的以下功能：

1. **控件的显示和隐藏：**  测试了媒体控件面板 (`-webkit-media-controls-panel`) 的显示和隐藏逻辑，例如调用 `Hide()` 和 `MaybeShow()` 方法是否能正确控制其可见性。
2. **控件的重置：** 测试了 `Reset()` 方法是否能正确重置媒体控件的状态，但并不会触发不必要的布局。
3. **投屏按钮 (Cast Button) 的行为：**
    - 测试了投屏按钮的可见性是否依赖于是否有可用的投屏路由。
    - 测试了 `disableremoteplayback` 属性对投屏按钮可见性的影响。
    - 测试了在没有浏览器原生媒体控件时（例如设置了 `controls` 属性为 `false`），投屏覆盖按钮的显示和隐藏逻辑。
    - 测试了 `controlslist` 属性对投屏按钮可见性的影响。
4. **下载按钮 (Download Button) 的行为：**
    - 测试了下载按钮在不同情况下的可见性，例如是否有可下载的资源、URL 是否为空、视频时长是否为无限、是否是 HLS 流等。
    - 测试了 `controlslist` 属性对下载按钮可见性的影响。
5. **全屏按钮 (Fullscreen Button) 的行为：**
    - 测试了 `controlslist` 属性对全屏按钮是否禁用的影响。
6. **播放速度按钮 (Playback Speed Button) 的行为：**
    - 测试了 `controlslist` 属性对播放速度按钮可见性的影响。
7. **溢出菜单 (Overflow Menu) 的行为：**
    - 测试了当溢出菜单列表可见时，是否会阻止媒体控件面板的隐藏。
8. **时间轴 (Timeline) 的交互：**
    - 测试了拖动时间轴到接近视频结尾时的精度问题。
    - 测试了拖动时间轴时，当前时间显示是否会立即更新。
9. **时间指示器的更新：** 测试了在视频开始 `seeking` 时，当前时间和时间轴指示器是否会立即更新。
10. **时间格式化：**  虽然这部分没有完全展示，但暗示了后续部分会测试时间显示元素是如何格式化时间的。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **`<video controls>`:** 代码中使用 `GetDocument().write("<video controls>");` 创建了一个带有浏览器原生控件的视频元素。测试的目标就是这些原生控件的行为。
    * **`disableremoteplayback` 属性:**  测试了设置 `<video disableremoteplayback>` 是否会影响投屏按钮的显示。
    * **`controlslist` 属性:** 测试了例如 `<video controlslist="nodownload">` 如何阻止下载按钮的显示。
    * **Shadow DOM:** 代码中大量使用 `GetElementByShadowPseudoId` 来获取媒体控件的内部元素，这些元素是通过 Shadow DOM 实现的。例如，`-webkit-media-controls-panel` 就是媒体控件的主面板。
* **CSS:**
    * **`IsElementVisible()` 函数:**  这个函数检查元素的 CSS 属性（如 `display`, `opacity`, `visibility`）来判断元素是否可见。例如，测试 `MediaControls().Hide()` 后，会使用 `IsElementVisible(*panel)` 检查面板的 `display` 是否变成了 `none`。
    * **内联样式 (`InlineStyle()`):**  代码中检查内联样式来判断元素的可见性，例如溢出菜单项的显示和隐藏通常通过修改其父元素的内联 `display` 属性来实现。
* **JavaScript (模拟事件):**
    * **`DispatchSimulatedClick()`:** 用于模拟用户点击按钮的行为，例如 `ClickOverflowButton()` 模拟了点击溢出按钮。
    * **`DispatchInputEvent()`:** 用于模拟用户在时间轴滑块上的操作，触发 `input` 事件。
    * **`Event::Create(event_type_names::kTransitionend)`:** 模拟 `transitionend` 事件，用于测试动画完成后的状态。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个 `<video>` 元素设置了 `controlslist="nodownload"` 属性，并且媒体资源可以下载。
* **输出:**  下载按钮在溢出菜单中将不可见 (`IsOverflowElementVisible(*download_button)` 返回 `false`)。

* **假设输入:** 用户点击了溢出菜单按钮。
* **输出:** 溢出菜单列表元素 (`-internal-media-controls-overflow-menu-list`) 的 CSS `display` 属性将变为非 `none`，从而使其可见。

**用户或编程常见的使用错误 (举例说明):**

* **用户错误:** 用户可能期望在所有视频上都能看到下载按钮，但如果视频是 HLS 流，或者设置了 `controlslist="nodownload"`，下载按钮就不会显示。
* **编程错误:** 开发者可能直接操作媒体控件的 Shadow DOM 元素，而没有考虑到 `MediaControlsImpl` 内部的逻辑，导致状态不一致。例如，直接设置某个按钮的 `display: none;` 而没有调用 `MediaControlsImpl` 提供的接口。
* **测试错误:** 在编写测试时，没有充分考虑到各种 HTML 属性和媒体状态对控件可见性的影响，导致测试覆盖不全。例如，只测试了默认情况下下载按钮的可见性，而没有测试 `controlslist="nodownload"` 的情况。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在网页上加载包含 `<video controls>` 的 HTML 页面。** 浏览器会解析 HTML 并创建 `HTMLVideoElement` 对象。
2. **`HTMLVideoElement` 会创建 `MediaControlsImpl` 对象来管理其内置控件。**
3. **用户与媒体控件交互：**
    * **点击播放/暂停按钮：**  这会触发 JavaScript 事件，最终导致 `MediaControlsImpl` 内部状态的改变。
    * **拖动时间轴：**  这会触发鼠标事件和 `input` 事件，`MediaControlsImpl` 会根据时间轴的位置更新视频的播放进度。
    * **点击全屏按钮：**  会触发全屏相关的请求。
    * **点击溢出菜单按钮：**  会显示或隐藏溢出菜单。
    * **如果支持投屏，点击投屏按钮：**  会触发投屏相关的操作。
    * **如果资源可下载，点击下载按钮：**  会触发下载操作。
4. **调试时，开发者可能会在 `MediaControlsImpl` 的相关方法中设置断点。** 例如，在 `Hide()`、`MaybeShow()`、处理按钮点击事件的方法中设置断点，来观察代码的执行流程和状态变化。
5. **开发者也可能通过浏览器的开发者工具，检查媒体控件的 Shadow DOM 结构和 CSS 属性。** 这有助于理解控件的布局和样式。

总而言之，这个文件的前半部分专注于测试 `MediaControlsImpl` 类的基础控件显示逻辑和部分按钮的核心功能，以及它们如何响应 HTML 属性的变化。它模拟了用户与媒体控件的交互，并验证了控件的状态和可见性是否符合预期。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"

#include <limits>
#include <memory>

#include "base/test/metrics/histogram_tester.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_pointer_event_init.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/document_style_environment_variables.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_parser.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_cast_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_current_time_display_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_download_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_fullscreen_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_mute_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_overflow_menu_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_overflow_menu_list_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_play_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_playback_speed_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_remaining_time_display_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_timeline_element.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_volume_slider_element.h"
#include "third_party/blink/renderer/modules/remoteplayback/remote_playback.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/media/remote_playback_client.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "ui/display/mojom/screen_orientation.mojom-blink.h"
#include "ui/display/screen_info.h"

// The MediaTimelineWidths histogram suffix expected to be encountered in these
// tests.
#define TIMELINE_W "256_511"

namespace blink {

namespace {

class FakeChromeClient : public EmptyChromeClient {
 public:
  FakeChromeClient() {
    screen_info_.orientation_type =
        display::mojom::blink::ScreenOrientation::kLandscapePrimary;
  }

  // ChromeClient overrides.
  const display::ScreenInfo& GetScreenInfo(LocalFrame&) const override {
    return screen_info_;
  }

 private:
  display::ScreenInfo screen_info_;
};

class MockWebMediaPlayerForImpl : public EmptyWebMediaPlayer {
 public:
  // WebMediaPlayer overrides:
  WebTimeRanges Seekable() const override { return seekable_; }
  bool HasVideo() const override { return true; }
  bool HasAudio() const override { return has_audio_; }

  bool has_audio_ = false;
  WebTimeRanges seekable_;
};

class StubLocalFrameClientForImpl : public EmptyLocalFrameClient {
 public:
  std::unique_ptr<WebMediaPlayer> CreateWebMediaPlayer(
      HTMLMediaElement&,
      const WebMediaPlayerSource&,
      WebMediaPlayerClient*) override {
    return std::make_unique<MockWebMediaPlayerForImpl>();
  }

  RemotePlaybackClient* CreateRemotePlaybackClient(
      HTMLMediaElement& element) override {
    return &RemotePlayback::From(element);
  }
};

Element* GetElementByShadowPseudoId(Node& root_node,
                                    const char* shadow_pseudo_id) {
  for (Element& element : ElementTraversal::DescendantsOf(root_node)) {
    if (element.ShadowPseudoId() == shadow_pseudo_id)
      return &element;
  }
  return nullptr;
}

bool IsElementVisible(Element& element) {
  const CSSPropertyValueSet* inline_style = element.InlineStyle();

  if (!inline_style)
    return element.getAttribute(html_names::kClassAttr) != "transparent";

  if (inline_style->GetPropertyValue(CSSPropertyID::kDisplay) == "none")
    return false;

  if (inline_style->HasProperty(CSSPropertyID::kOpacity) &&
      inline_style->GetPropertyValue(CSSPropertyID::kOpacity).ToDouble() ==
          0.0) {
    return false;
  }

  if (inline_style->GetPropertyValue(CSSPropertyID::kVisibility) == "hidden")
    return false;

  if (Element* parent = element.parentElement())
    return IsElementVisible(*parent);

  return true;
}

void SimulateTransitionEnd(Element& element) {
  element.DispatchEvent(*Event::Create(event_type_names::kTransitionend));
}

// This must match MediaControlDownloadButtonElement::DownloadActionMetrics.
enum DownloadActionMetrics {
  kShown = 0,
  kClicked,
  kCount  // Keep last.
};

}  // namespace

class MediaControlsImplTest : public PageTestBase,
                              private ScopedMediaCastOverlayButtonForTest {
 public:
  explicit MediaControlsImplTest(
      base::test::TaskEnvironment::TimeSource time_source)
      : PageTestBase(time_source), ScopedMediaCastOverlayButtonForTest(true) {}
  MediaControlsImplTest() : ScopedMediaCastOverlayButtonForTest(true) {}

 protected:
  void SetUp() override {
    InitializePage();
  }

  void InitializePage() {
    SetupPageWithClients(MakeGarbageCollected<FakeChromeClient>(),
                         MakeGarbageCollected<StubLocalFrameClientForImpl>());

    GetDocument().write("<video controls>");
    auto& video = To<HTMLVideoElement>(
        *GetDocument().QuerySelector(AtomicString("video")));
    media_controls_ = static_cast<MediaControlsImpl*>(video.GetMediaControls());

    // Scripts are disabled by default which forces controls to be on.
    GetFrame().GetSettings()->SetScriptEnabled(true);
  }

  void SetMediaControlsFromElement(HTMLMediaElement& elm) {
    media_controls_ = static_cast<MediaControlsImpl*>(elm.GetMediaControls());
  }

  void SimulateRemotePlaybackAvailable() {
    RemotePlayback::From(media_controls_->MediaElement())
        .AvailabilityChangedForTesting(/* screen_is_available */ true);
  }

  void EnsureSizing() {
    // Fire the size-change callback to ensure that the controls have
    // been properly notified of the video size.
    media_controls_->NotifyElementSizeChanged(
        media_controls_->MediaElement().GetBoundingClientRect());
  }

  void SimulateHideMediaControlsTimerFired() {
    media_controls_->HideMediaControlsTimerFired(nullptr);
  }

  void SimulateLoadedMetadata() { media_controls_->OnLoadedMetadata(); }

  void SimulateOnSeeking() { media_controls_->OnSeeking(); }
  void SimulateOnSeeked() { media_controls_->OnSeeked(); }
  void SimulateOnWaiting() { media_controls_->OnWaiting(); }
  void SimulateOnPlaying() { media_controls_->OnPlaying(); }

  void SimulateMediaControlPlaying() {
    MediaControls().MediaElement().SetReadyState(
        HTMLMediaElement::kHaveEnoughData);
    MediaControls().MediaElement().SetNetworkState(
        WebMediaPlayer::NetworkState::kNetworkStateLoading);
  }

  void SimulateMediaControlPlayingForFutureData() {
    MediaControls().MediaElement().SetReadyState(
        HTMLMediaElement::kHaveFutureData);
    MediaControls().MediaElement().SetNetworkState(
        WebMediaPlayer::NetworkState::kNetworkStateLoading);
  }

  void SimulateMediaControlBuffering() {
    MediaControls().MediaElement().SetReadyState(
        HTMLMediaElement::kHaveCurrentData);
    MediaControls().MediaElement().SetNetworkState(
        WebMediaPlayer::NetworkState::kNetworkStateLoading);
  }

  MediaControlsImpl& MediaControls() { return *media_controls_; }
  MediaControlVolumeSliderElement* VolumeSliderElement() const {
    return media_controls_->volume_slider_.Get();
  }
  MediaControlTimelineElement* TimelineElement() const {
    return media_controls_->timeline_.Get();
  }
  Element* TimelineTrackElement() const {
    if (!TimelineElement())
      return nullptr;
    return &TimelineElement()->GetTrackElement();
  }
  MediaControlCurrentTimeDisplayElement* GetCurrentTimeDisplayElement() const {
    return media_controls_->current_time_display_.Get();
  }
  MediaControlRemainingTimeDisplayElement* GetRemainingTimeDisplayElement()
      const {
    return media_controls_->duration_display_.Get();
  }
  MediaControlMuteButtonElement* MuteButtonElement() const {
    return media_controls_->mute_button_.Get();
  }
  MediaControlCastButtonElement* CastButtonElement() const {
    return media_controls_->cast_button_.Get();
  }
  MediaControlDownloadButtonElement* DownloadButtonElement() const {
    return media_controls_->download_button_.Get();
  }
  MediaControlFullscreenButtonElement* FullscreenButtonElement() const {
    return media_controls_->fullscreen_button_.Get();
  }
  MediaControlPlaybackSpeedButtonElement* PlaybackSpeedButtonElement() const {
    return media_controls_->playback_speed_button_.Get();
  }
  MediaControlPlayButtonElement* PlayButtonElement() const {
    return media_controls_->play_button_.Get();
  }
  MediaControlOverflowMenuButtonElement* OverflowMenuButtonElement() const {
    return media_controls_->overflow_menu_.Get();
  }
  MediaControlOverflowMenuListElement* OverflowMenuListElement() const {
    return media_controls_->overflow_list_.Get();
  }

  MockWebMediaPlayerForImpl* WebMediaPlayer() {
    return static_cast<MockWebMediaPlayerForImpl*>(
        MediaControls().MediaElement().GetWebMediaPlayer());
  }

  base::HistogramTester& GetHistogramTester() { return histogram_tester_; }

  void LoadMediaWithDuration(double duration) {
    MediaControls().MediaElement().SetSrc(
        AtomicString("https://example.com/foo.mp4"));
    test::RunPendingTasks();
    WebTimeRange time_range(0.0, duration);
    WebMediaPlayer()->seekable_.Assign(base::span_from_ref(time_range));
    MediaControls().MediaElement().DurationChanged(duration,
                                                   false /* requestSeek */);
    SimulateLoadedMetadata();
  }

  void SetHasAudio(bool has_audio) { WebMediaPlayer()->has_audio_ = has_audio; }

  void ClickOverflowButton() {
    MediaControls()
        .download_button_->OverflowElementForTests()
        ->DispatchSimulatedClick(nullptr);
  }

  void SetReady() {
    MediaControls().MediaElement().SetReadyState(
        HTMLMediaElement::kHaveEnoughData);
  }

  void MouseDownAt(gfx::PointF pos);
  void MouseMoveTo(gfx::PointF pos);
  void MouseUpAt(gfx::PointF pos);

  void GestureTapAt(gfx::PointF pos);
  void GestureDoubleTapAt(gfx::PointF pos);

  bool HasAvailabilityCallbacks(RemotePlayback& remote_playback) {
    return !remote_playback.availability_callbacks_.empty();
  }

  const String GetDisplayedTime(MediaControlTimeDisplayElement* display) {
    return To<Text>(display->firstChild())->data();
  }

  bool IsOverflowElementVisible(MediaControlInputElement& element) {
    MediaControlInputElement* overflow_element =
        element.OverflowElementForTests();
    if (!overflow_element)
      return false;

    Element* overflow_parent_label = overflow_element->parentElement();
    if (!overflow_parent_label)
      return false;

    const CSSPropertyValueSet* inline_style =
        overflow_parent_label->InlineStyle();
    if (inline_style->GetPropertyValue(CSSPropertyID::kDisplay) == "none")
      return false;

    return true;
  }

  PointerEvent* CreatePointerEvent(const AtomicString& name) {
    PointerEventInit* init = PointerEventInit::Create();
    return PointerEvent::Create(name, init);
  }

 private:
  Persistent<MediaControlsImpl> media_controls_;
  base::HistogramTester histogram_tester_;
};

void MediaControlsImplTest::MouseDownAt(gfx::PointF pos) {
  WebMouseEvent mouse_down_event(WebInputEvent::Type::kMouseDown,
                                 pos /* client pos */, pos /* screen pos */,
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  mouse_down_event.SetFrameScale(1);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      mouse_down_event);
}

void MediaControlsImplTest::MouseMoveTo(gfx::PointF pos) {
  WebMouseEvent mouse_move_event(WebInputEvent::Type::kMouseMove,
                                 pos /* client pos */, pos /* screen pos */,
                                 WebPointerProperties::Button::kLeft, 1,
                                 WebInputEvent::Modifiers::kLeftButtonDown,
                                 WebInputEvent::GetStaticTimeStampForTests());
  mouse_move_event.SetFrameScale(1);
  GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
      mouse_move_event, {}, {});
}

void MediaControlsImplTest::MouseUpAt(gfx::PointF pos) {
  WebMouseEvent mouse_up_event(
      WebMouseEvent::Type::kMouseUp, pos /* client pos */, pos /* screen pos */,
      WebPointerProperties::Button::kLeft, 1, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests());
  mouse_up_event.SetFrameScale(1);
  GetDocument().GetFrame()->GetEventHandler().HandleMouseReleaseEvent(
      mouse_up_event);
}

void MediaControlsImplTest::GestureTapAt(gfx::PointF pos) {
  WebGestureEvent gesture_tap_event(
      WebInputEvent::Type::kGestureTap, WebInputEvent::kNoModifiers,
      WebInputEvent::GetStaticTimeStampForTests());

  // Adjust |pos| by current frame scale.
  float frame_scale = GetDocument().GetFrame()->LayoutZoomFactor();
  gesture_tap_event.SetFrameScale(frame_scale);
  pos.Scale(frame_scale);
  gesture_tap_event.SetPositionInWidget(pos);

  // Fire the event.
  GetDocument().GetFrame()->GetEventHandler().HandleGestureEvent(
      gesture_tap_event);
}

void MediaControlsImplTest::GestureDoubleTapAt(gfx::PointF pos) {
  GestureTapAt(pos);
  GestureTapAt(pos);
}

TEST_F(MediaControlsImplTest, HideAndShow) {
  Element* panel = GetElementByShadowPseudoId(MediaControls(),
                                              "-webkit-media-controls-panel");
  ASSERT_NE(nullptr, panel);

  ASSERT_TRUE(IsElementVisible(*panel));
  MediaControls().Hide();
  ASSERT_FALSE(IsElementVisible(*panel));
  MediaControls().MaybeShow();
  ASSERT_TRUE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTest, Reset) {
  Element* panel = GetElementByShadowPseudoId(MediaControls(),
                                              "-webkit-media-controls-panel");
  ASSERT_NE(nullptr, panel);

  ASSERT_TRUE(IsElementVisible(*panel));
  MediaControls().Reset();
  ASSERT_TRUE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTest, HideAndReset) {
  Element* panel = GetElementByShadowPseudoId(MediaControls(),
                                              "-webkit-media-controls-panel");
  ASSERT_NE(nullptr, panel);

  ASSERT_TRUE(IsElementVisible(*panel));
  MediaControls().Hide();
  ASSERT_FALSE(IsElementVisible(*panel));
  MediaControls().Reset();
  ASSERT_FALSE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTest, ResetDoesNotTriggerInitialLayout) {
  Document& document = GetDocument();
  int old_element_count = document.GetStyleEngine().StyleForElementCount();
  // Also assert that there are no layouts yet.
  ASSERT_EQ(0, old_element_count);
  MediaControls().Reset();
  int new_element_count = document.GetStyleEngine().StyleForElementCount();
  ASSERT_EQ(old_element_count, new_element_count);
}

TEST_F(MediaControlsImplTest, CastButtonRequiresRoute) {
  EnsureSizing();

  MediaControlCastButtonElement* cast_button = CastButtonElement();
  ASSERT_NE(nullptr, cast_button);

  ASSERT_FALSE(IsOverflowElementVisible(*cast_button));

  SimulateRemotePlaybackAvailable();
  ASSERT_TRUE(IsOverflowElementVisible(*cast_button));
}

TEST_F(MediaControlsImplTest, CastButtonDisableRemotePlaybackAttr) {
  EnsureSizing();

  MediaControlCastButtonElement* cast_button = CastButtonElement();
  ASSERT_NE(nullptr, cast_button);

  ASSERT_FALSE(IsOverflowElementVisible(*cast_button));
  SimulateRemotePlaybackAvailable();
  ASSERT_TRUE(IsOverflowElementVisible(*cast_button));

  MediaControls().MediaElement().SetBooleanAttribute(
      html_names::kDisableremoteplaybackAttr, true);
  test::RunPendingTasks();
  ASSERT_FALSE(IsOverflowElementVisible(*cast_button));

  MediaControls().MediaElement().SetBooleanAttribute(
      html_names::kDisableremoteplaybackAttr, false);
  test::RunPendingTasks();
  ASSERT_TRUE(IsOverflowElementVisible(*cast_button));
}

TEST_F(MediaControlsImplTest, CastOverlayDefault) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  Element* cast_overlay_button = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overlay-cast-button");
  ASSERT_NE(nullptr, cast_overlay_button);

  SimulateRemotePlaybackAvailable();
  ASSERT_TRUE(IsElementVisible(*cast_overlay_button));
}

TEST_F(MediaControlsImplTest, CastOverlayDisabled) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  ScopedMediaCastOverlayButtonForTest media_cast_overlay_button(false);

  Element* cast_overlay_button = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overlay-cast-button");
  ASSERT_NE(nullptr, cast_overlay_button);

  SimulateRemotePlaybackAvailable();
  ASSERT_FALSE(IsElementVisible(*cast_overlay_button));
}

TEST_F(MediaControlsImplTest, CastOverlayDisableRemotePlaybackAttr) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  Element* cast_overlay_button = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overlay-cast-button");
  ASSERT_NE(nullptr, cast_overlay_button);

  ASSERT_FALSE(IsElementVisible(*cast_overlay_button));
  SimulateRemotePlaybackAvailable();
  ASSERT_TRUE(IsElementVisible(*cast_overlay_button));

  MediaControls().MediaElement().SetBooleanAttribute(
      html_names::kDisableremoteplaybackAttr, true);
  test::RunPendingTasks();
  ASSERT_FALSE(IsElementVisible(*cast_overlay_button));

  MediaControls().MediaElement().SetBooleanAttribute(
      html_names::kDisableremoteplaybackAttr, false);
  test::RunPendingTasks();
  ASSERT_TRUE(IsElementVisible(*cast_overlay_button));
}

TEST_F(MediaControlsImplTest, CastOverlayMediaControlsDisabled) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  Element* cast_overlay_button = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overlay-cast-button");
  ASSERT_NE(nullptr, cast_overlay_button);

  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));
  SimulateRemotePlaybackAvailable();
  EXPECT_TRUE(IsElementVisible(*cast_overlay_button));

  GetDocument().GetSettings()->SetMediaControlsEnabled(false);
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));

  GetDocument().GetSettings()->SetMediaControlsEnabled(true);
  EXPECT_TRUE(IsElementVisible(*cast_overlay_button));
}

TEST_F(MediaControlsImplTest, CastOverlayDisabledMediaControlsDisabled) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  ScopedMediaCastOverlayButtonForTest media_cast_overlay_button(false);

  Element* cast_overlay_button = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overlay-cast-button");
  ASSERT_NE(nullptr, cast_overlay_button);

  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));
  SimulateRemotePlaybackAvailable();
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));

  GetDocument().GetSettings()->SetMediaControlsEnabled(false);
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));

  GetDocument().GetSettings()->SetMediaControlsEnabled(true);
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));
}

TEST_F(MediaControlsImplTest, CastOverlayDisabledAutoplayMuted) {
  MediaControls().MediaElement().SetBooleanAttribute(html_names::kControlsAttr,
                                                     false);

  // Set the video to autoplay muted.
  ScopedMediaEngagementBypassAutoplayPoliciesForTest scoped_feature(true);
  MediaControls().MediaElement().GetDocument().GetSettings()->SetAutoplayPolicy(
      AutoplayPolicy::Type::kDocumentUserActivationRequired);
  MediaControls().MediaElement().setMuted(true);

  Element* cast_overlay_button = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overlay-cast-button");
  ASSERT_NE(nullptr, cast_overlay_button);

  SimulateRemotePlaybackAvailable();
  EXPECT_FALSE(IsElementVisible(*cast_overlay_button));
}

TEST_F(MediaControlsImplTest, CastButtonVisibilityDependsOnControlslistAttr) {
  EnsureSizing();

  MediaControlCastButtonElement* cast_button = CastButtonElement();
  ASSERT_NE(nullptr, cast_button);

  SimulateRemotePlaybackAvailable();
  ASSERT_TRUE(IsOverflowElementVisible(*cast_button));

  MediaControls().MediaElement().setAttribute(
      blink::html_names::kControlslistAttr, AtomicString("noremoteplayback"));
  test::RunPendingTasks();

  // Cast button should not be displayed because of
  // controlslist="noremoteplayback".
  ASSERT_FALSE(IsOverflowElementVisible(*cast_button));

  // If the user explicitly shows all controls, that should override the
  // controlsList attribute and cast button should be displayed.
  MediaControls().MediaElement().SetUserWantsControlsVisible(true);
  ASSERT_TRUE(IsOverflowElementVisible(*cast_button));
}

TEST_F(MediaControlsImplTest, KeepControlsVisibleIfOverflowListVisible) {
  Element* overflow_list = GetElementByShadowPseudoId(
      MediaControls(), "-internal-media-controls-overflow-menu-list");
  ASSERT_NE(nullptr, overflow_list);

  Element* panel = GetElementByShadowPseudoId(MediaControls(),
                                              "-webkit-media-controls-panel");
  ASSERT_NE(nullptr, panel);

  MediaControls().MediaElement().SetSrc(AtomicString("http://example.com"));
  MediaControls().MediaElement().Play();
  test::RunPendingTasks();

  MediaControls().MaybeShow();
  MediaControls().ToggleOverflowMenu();
  EXPECT_TRUE(IsElementVisible(*overflow_list));

  SimulateHideMediaControlsTimerFired();
  EXPECT_TRUE(IsElementVisible(*overflow_list));
  EXPECT_TRUE(IsElementVisible(*panel));
}

TEST_F(MediaControlsImplTest, DownloadButtonDisplayed) {
  EnsureSizing();

  MediaControlDownloadButtonElement* download_button = DownloadButtonElement();
  ASSERT_NE(nullptr, download_button);

  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  test::RunPendingTasks();
  SimulateLoadedMetadata();

  // Download button should normally be displayed.
  EXPECT_TRUE(IsOverflowElementVisible(*download_button));
}

TEST_F(MediaControlsImplTest, DownloadButtonNotDisplayedEmptyUrl) {
  EnsureSizing();

  MediaControlDownloadButtonElement* download_button = DownloadButtonElement();
  ASSERT_NE(nullptr, download_button);

  // Download button should not be displayed when URL is empty.
  MediaControls().MediaElement().SetSrc(g_empty_atom);
  test::RunPendingTasks();
  SimulateLoadedMetadata();
  EXPECT_FALSE(IsOverflowElementVisible(*download_button));
}

TEST_F(MediaControlsImplTest, DownloadButtonNotDisplayedInfiniteDuration) {
  EnsureSizing();

  MediaControlDownloadButtonElement* download_button = DownloadButtonElement();
  ASSERT_NE(nullptr, download_button);

  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  test::RunPendingTasks();

  // Download button should not be displayed when duration is infinite.
  MediaControls().MediaElement().DurationChanged(
      std::numeric_limits<double>::infinity(), false /* requestSeek */);
  SimulateLoadedMetadata();
  EXPECT_FALSE(IsOverflowElementVisible(*download_button));

  // Download button should be shown if the duration changes back to finite.
  MediaControls().MediaElement().DurationChanged(20.0f,
                                                 false /* requestSeek */);
  SimulateLoadedMetadata();
  EXPECT_TRUE(IsOverflowElementVisible(*download_button));
}

TEST_F(MediaControlsImplTest, DownloadButtonNotDisplayedHLS) {
  EnsureSizing();

  MediaControlDownloadButtonElement* download_button = DownloadButtonElement();
  ASSERT_NE(nullptr, download_button);

  // Download button should not be displayed for HLS streams.
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.m3u8"));
  test::RunPendingTasks();
  SimulateLoadedMetadata();
  EXPECT_FALSE(IsOverflowElementVisible(*download_button));

  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.m3u8?title=foo"));
  test::RunPendingTasks();
  SimulateLoadedMetadata();
  EXPECT_FALSE(IsOverflowElementVisible(*download_button));

  // However, it *should* be displayed for otherwise valid sources containing
  // the text 'm3u8'.
  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.m3u8.mp4"));
  test::RunPendingTasks();
  SimulateLoadedMetadata();
  EXPECT_TRUE(IsOverflowElementVisible(*download_button));
}

TEST_F(MediaControlsImplTest,
       DownloadButtonVisibilityDependsOnControlslistAttr) {
  EnsureSizing();

  MediaControlDownloadButtonElement* download_button = DownloadButtonElement();
  ASSERT_NE(nullptr, download_button);

  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  MediaControls().MediaElement().setAttribute(
      blink::html_names::kControlslistAttr, AtomicString("nodownload"));
  test::RunPendingTasks();
  SimulateLoadedMetadata();

  // Download button should not be displayed because of
  // controlslist="nodownload".
  EXPECT_FALSE(IsOverflowElementVisible(*download_button));

  // If the user explicitly shows all controls, that should override the
  // controlsList attribute and download button should be displayed.
  MediaControls().MediaElement().SetUserWantsControlsVisible(true);
  EXPECT_TRUE(IsOverflowElementVisible(*download_button));
}

TEST_F(MediaControlsImplTest,
       FullscreenButtonDisabledDependsOnControlslistAttr) {
  EnsureSizing();

  MediaControlFullscreenButtonElement* fullscreen_button =
      FullscreenButtonElement();
  ASSERT_NE(nullptr, fullscreen_button);

  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  MediaControls().MediaElement().setAttribute(
      blink::html_names::kControlslistAttr, AtomicString("nofullscreen"));
  test::RunPendingTasks();
  SimulateLoadedMetadata();

  // Fullscreen button should be disabled because of
  // controlslist="nofullscreen".
  EXPECT_TRUE(fullscreen_button->IsDisabled());

  // If the user explicitly shows all controls, that should override the
  // controlsList attribute and fullscreen button should be enabled.
  MediaControls().MediaElement().SetUserWantsControlsVisible(true);
  EXPECT_FALSE(fullscreen_button->IsDisabled());
}

TEST_F(MediaControlsImplTest,
       PlaybackSpeedButtonVisibilityDependsOnControlslistAttr) {
  EnsureSizing();

  MediaControlPlaybackSpeedButtonElement* playback_speed_button =
      PlaybackSpeedButtonElement();
  ASSERT_NE(nullptr, playback_speed_button);

  MediaControls().MediaElement().SetSrc(
      AtomicString("https://example.com/foo.mp4"));
  MediaControls().MediaElement().setAttribute(
      blink::html_names::kControlslistAttr, AtomicString("noplaybackrate"));
  test::RunPendingTasks();
  SimulateLoadedMetadata();

  // Fullscreen button should not be displayed because of
  // controlslist="noplaybackrate".
  EXPECT_FALSE(IsOverflowElementVisible(*playback_speed_button));

  // If the user explicitly shows all controls, that should override the
  // controlsList attribute and playback speed button should be displayed.
  MediaControls().MediaElement().SetUserWantsControlsVisible(true);
  EXPECT_TRUE(IsOverflowElementVisible(*playback_speed_button));
}

TEST_F(MediaControlsImplTest, TimelineSeekToRoundedEnd) {
  EnsureSizing();

  // Tests the case where the real length of the video, |exact_duration|, gets
  // rounded up slightly to |rounded_up_duration| when setting the timeline's
  // |max| attribute (crbug.com/695065).
  double exact_duration = 596.586667;
  double rounded_up_duration = 596.586667;
  LoadMediaWithDuration(exact_duration);

  // Simulate a click slightly past the end of the track of the timeline's
  // underlying <input type="range">. This would set the |value| to the |max|
  // attribute, which can be slightly rounded relative to the duration.
  MediaControlTimelineElement* timeline = TimelineElement();
  timeline->setValueAsNumber(rounded_up_duration, ASSERT_NO_EXCEPTION);
  ASSERT_EQ(rounded_up_duration, timeline->valueAsNumber());
  EXPECT_EQ(0.0, MediaControls().MediaElement().currentTime());
  timeline->DispatchInputEvent();
  EXPECT_EQ(exact_duration, MediaControls().MediaElement().currentTime());
}

TEST_F(MediaControlsImplTest, TimelineImmediatelyUpdatesCurrentTime) {
  EnsureSizing();

  MediaControlCurrentTimeDisplayElement* current_time_display =
      GetCurrentTimeDisplayElement();
  double duration = 600;
  LoadMediaWithDuration(duration);

  // Simulate seeking the underlying range to 50%. Current time display should
  // update synchronously (rather than waiting for media to finish seeking).
  TimelineElement()->setValueAsNumber(duration / 2, ASSERT_NO_EXCEPTION);
  TimelineElement()->DispatchInputEvent();
  EXPECT_EQ(duration / 2, current_time_display->CurrentValue());
}

TEST_F(MediaControlsImplTest, TimeIndicatorsUpdatedOnSeeking) {
  EnsureSizing();

  MediaControlCurrentTimeDisplayElement* current_time_display =
      GetCurrentTimeDisplayElement();
  MediaControlTimelineElement* timeline = TimelineElement();
  double duration = 1000;
  LoadMediaWithDuration(duration);

  EXPECT_EQ(0, current_time_display->CurrentValue());
  EXPECT_EQ(0, timeline->valueAsNumber());

  MediaControls().MediaElement().setCurrentTime(duration / 4);

  // Time indicators are not yet updated.
  EXPECT_EQ(0, current_time_display->CurrentValue());
  EXPECT_EQ(0, timeline->valueAsNumber());

  SimulateOnSeeking();

  // The time indicators should be updated immediately when the 'seeking' event
  // is fired.
  EXPECT_EQ(duration / 4, current_time_display->CurrentValue());
  EXPECT_EQ(duration / 4, timeline->valueAsNumber());
}

TEST_F(MediaControlsImplTest, TimeIsCorrectlyFormatted) {
  struct {
    double time;
    String expected_result;
  } tests[] = {
      {-3661, "-1:01:01"},   {-1, "-0:01"},     {0, "0:00"},
      {1, "0:01"},           {15, "0:15"},      {125, "2:05"},
      {615, "10:15"},        {3666, "1:01:06"}, {75123, "20:52:03"},
      
"""


```