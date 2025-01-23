Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The primary goal is to understand the purpose of this specific test file (`html_video_element_test.cc`) within the Chromium Blink rendering engine. This means identifying what aspect of the code it's testing and how.

2. **Initial Scan for Keywords and Structure:** Quickly scan the file for important keywords and structural elements:
    * `#include`:  This tells us what other parts of the codebase this file depends on. We see `HTMLVideoElement.h`, testing frameworks like `gmock` and `gtest`, and Blink-specific headers related to media, DOM, layout, and testing. This immediately suggests the file tests the `HTMLVideoElement` class.
    * `namespace blink`:  Confirms this is Blink-specific code.
    * Class names like `HTMLVideoElementTest` and `HTMLVideoElementMockMediaPlayer`:  These are the core testing constructs. The "Mock" in the latter suggests a test double for the real media player.
    * `TEST_P`: Indicates parameterized tests, which are tests run with different sets of input data (though not heavily used in *this specific* file's examples).
    * `SetUp()`: A standard setup function in `gtest`, meaning it's run before each test case.
    * Function names like `PictureInPictureInterstitialAndTextContainer`, `EffectivelyFullscreen_DisplayType`, `RecordVideoOcclusionStateCalledWhenVisibilityIsRequested`, etc.: These clearly indicate the specific features or scenarios being tested.

3. **Identify the Core Tested Class:** The filename and the `#include` statement for `HTMLVideoElement.h` make it obvious that the primary focus is testing the `HTMLVideoElement` class.

4. **Analyze the Mock Object:** The `HTMLVideoElementMockMediaPlayer` is crucial. It uses `gmock` to create a mock implementation of the `WebMediaPlayer` interface. This allows the tests to control and verify interactions between the `HTMLVideoElement` and the underlying media player without needing a real media player. The `MOCK_METHOD` macros define which methods of the media player are being mocked, giving hints about what aspects of the `HTMLVideoElement` are being tested (e.g., fullscreen status, display type, video frame availability, occlusion state, natural size).

5. **Examine Individual Test Cases:**  Go through each `TEST_P` block and its content:
    * **`PictureInPictureInterstitialAndTextContainer`:** Tests the interaction of Picture-in-Picture mode with text tracks and the creation of shadow DOM elements. The `EXPECT_CALL` checks if the mock media player's `OnDisplayTypeChanged` method is called with the correct `DisplayType`.
    * **`PictureInPictureInterstitial_Reattach`:** Checks if detaching and reattaching a video element in PiP mode causes issues (specifically, a crash).
    * **`EffectivelyFullscreen_DisplayType`:**  Tests how the `HTMLVideoElement` updates its `DisplayType` based on the effective fullscreen status reported by the media player. This clearly relates to how the video is presented visually.
    * **`ChangeLayerNeedsCompositingUpdate`:** Tests if changing the associated `cc::Layer` (used for compositing) correctly triggers a repaint. This is a rendering-related test.
    * **`HasAvailableVideoFrameChecksWMP`:** Verifies that the `HTMLVideoElement` correctly delegates the `HasAvailableVideoFrame()` check to the underlying media player.
    * **`AutoPIPExitPIPTest`:**  Tests the behavior of automatic Picture-in-Picture exit when entering fullscreen.
    * **`DefaultPosterImage`:** Tests the functionality of setting and using a default poster image for the video.
    * **`RecordVideoOcclusionStateCalledWhenVisibilityIsRequested`**, **`RecordVideoOcclusionStateNotCalledIfVisibilityIsNotRequested`**, **`RecordVideoOcclusionStateCalledWhenTrackerNotAttached`:** These tests focus on the `MediaVideoVisibilityTracker` and how and when it reports the video's occlusion state to the media player. This is related to performance and resource optimization.
    * **`VideoVisibilityTrackerVideoElementRectDimensions`:**  Tests the calculation of the video element's rectangle used by the visibility tracker, considering styling and natural size.

6. **Connect to Web Technologies (HTML, CSS, JavaScript):**  As each test case is analyzed, think about how the tested functionality relates to web development:
    * **HTML:** The `<video>` tag, attributes like `controls`, `src`, `poster`, and inline styles.
    * **CSS:**  Styling the video element's size, potentially affecting its visibility and layout.
    * **JavaScript:**  Controlling video playback (`play()`), interacting with the video element's properties (e.g., checking `videoWidth`, `videoHeight`), and potentially using the Picture-in-Picture API.

7. **Identify Logic and Assumptions:**  For tests involving conditional behavior (like the fullscreen/display type test), note the assumed inputs and expected outputs. For example, setting `WebFullscreenVideoStatus::kFullscreenAndPictureInPictureEnabled` *should* result in `DisplayType::kFullscreen`.

8. **Consider User and Programming Errors:**  Think about common mistakes developers might make when working with video elements:
    * Not handling different fullscreen states correctly.
    * Incorrectly assuming the video has a frame available.
    * Misunderstanding how the visibility tracker works.
    * Potential issues with detaching and reattaching elements, especially in complex scenarios like Picture-in-Picture.

9. **Structure the Answer:** Organize the findings into logical sections:
    * **Core Functionality:**  The primary purpose of the test file.
    * **Relationship to Web Technologies:**  Specific examples linking the tests to HTML, CSS, and JavaScript.
    * **Logic and Assumptions:**  Illustrative examples of input/output scenarios.
    * **Common Errors:** Examples of mistakes developers might make.

10. **Refine and Elaborate:**  Review the generated answer for clarity, accuracy, and completeness. Add more details or explanations where needed. For instance, explicitly mentioning the role of the mock object in isolating the tests.

This methodical approach, starting with a high-level understanding and gradually diving into specifics, helps to thoroughly analyze the purpose and implications of a complex code file like this.
这个文件 `html_video_element_test.cc` 是 Chromium Blink 引擎中用于测试 `HTMLVideoElement` 类功能的单元测试文件。它使用 Google Test (gtest) 框架来编写测试用例，并通过模拟 (mocking) 相关依赖来隔离被测试的代码。

以下是该文件主要测试的功能以及与 JavaScript、HTML、CSS 的关系，逻辑推理，以及可能的用户/编程错误：

**主要功能：**

1. **Picture-in-Picture (画中画) 功能测试:**
   - 测试进入和退出画中画模式时 `HTMLVideoElement` 的行为，例如更新其显示类型 (DisplayType)。
   - 测试画中画模式下字幕轨道 (text track) 的显示。
   - 测试在画中画模式下重新附加 (reattach) `HTMLVideoElement` 的稳定性。

2. **全屏 (Fullscreen) 功能测试:**
   - 测试 `HTMLVideoElement` 如何根据其有效的全屏状态 (effectivelyFullscreen) 更新其显示类型。
   - 模拟不同的全屏状态 (`kNotEffectivelyFullscreen`, `kFullscreenAndPictureInPictureEnabled`, `kFullscreenAndPictureInPictureDisabled`) 并验证 `DisplayType` 是否正确更新。

3. **渲染层 (cc::Layer) 管理测试:**
   - 测试当 `HTMLVideoElement` 关联的渲染层发生变化时，是否会触发必要的重绘 (repaint) 操作。

4. **视频帧可用性 (Video Frame Availability) 测试:**
   - 测试 `HTMLVideoElement` 的 `HasAvailableVideoFrame()` 方法是否正确地调用了底层媒体播放器 (WebMediaPlayer) 的相应方法。

5. **自动退出画中画 (Auto Picture-in-Picture Exit) 测试:**
   - 测试当 `HTMLVideoElement` 设置为自动进入画中画，然后尝试进入全屏时，是否会正确处理退出画中画的逻辑。

6. **默认海报图像 (Default Poster Image) 测试:**
   - 测试当全局设置了默认视频海报图像时，`HTMLVideoElement` 是否能正确识别并使用。

7. **视频遮挡状态 (Video Occlusion State) 记录测试:**
   - 测试当请求视频可见性时，`HTMLVideoElement` 是否会调用底层媒体播放器的 `RecordVideoOcclusionState` 方法来记录视频的遮挡状态。
   - 测试在不同的生命周期状态下，以及在 `HTMLVideoElement` 从文档中移除后，遮挡状态记录的行为。

8. **视频可见性追踪器 (Video Visibility Tracker) 测试:**
   - 测试 `MediaVideoVisibilityTracker` 如何计算 `HTMLVideoElement` 的尺寸，并将其用于遮挡状态的报告。

**与 JavaScript, HTML, CSS 的关系及举例：**

* **HTML:**
    - **功能:** 该测试文件测试的是 `<video>` 元素在 HTML 文档中的行为。
    - **举例:** 测试中创建了 `HTMLVideoElement` 对象，并设置了 `src` 和 `controls` 属性，这对应于在 HTML 中使用 `<video src="http://example.com/foo.mp4" controls></video>`。
    - **举例:** 测试设置了 `poster` 属性 (`setAttribute(html_names::kPosterAttr, ...)`), 这对应于 HTML 中的 `<video poster="image.jpg"></video>`。

* **JavaScript:**
    - **功能:**  `HTMLVideoElement` 的行为直接影响 JavaScript 可以如何操作视频。例如，JavaScript 可以调用 `video.play()`，监听 `enterpictureinpicture` 和 `exitpictureinpicture` 事件，以及访问 `videoWidth` 和 `videoHeight` 属性。
    - **举例:** 测试中模拟了进入画中画 (`video()->OnEnteredPictureInPicture()`)，这与 JavaScript 调用 `videoElement.requestPictureInPicture()` 或浏览器自动触发进入画中画相关。
    - **举例:** 测试验证了 `HasAvailableVideoFrame()` 方法，JavaScript 可以使用这个方法来判断视频是否有可用的帧用于绘制到 `<canvas>` 或进行其他处理。

* **CSS:**
    - **功能:** CSS 可以影响 `HTMLVideoElement` 的布局和外观，例如尺寸、定位、以及是否可见。
    - **举例:** 测试中设置了 `style` 属性 (`video()->setAttribute(html_names::kStyleAttr, ...)`), 这对应于在 HTML 中使用内联样式或通过 CSS 规则设置视频元素的尺寸。测试也考虑了视频元素的布局信息 (`LayoutBox`) 来计算可见性。
    - **举例:** 视频的遮挡状态直接受到其他 HTML 元素通过 CSS 叠加在视频之上而影响。测试中的 `RecordVideoOcclusionState` 涉及到判断视频是否被遮挡。

**逻辑推理及假设输入与输出：**

* **假设输入:** 设置 `HTMLVideoElement` 的 `isEffectivelyFullscreen` 状态为 `WebFullscreenVideoStatus::kFullscreenAndPictureInPictureEnabled`。
* **预期输出:** 底层媒体播放器的 `OnDisplayTypeChanged` 方法会被调用，且 `DisplayType` 参数为 `DisplayType::kFullscreen`。
* **代码体现:** `TEST_P(HTMLVideoElementTest, EffectivelyFullscreen_DisplayType)` 中的循环就模拟了不同的 `WebFullscreenVideoStatus` 输入，并验证了预期的 `DisplayType` 输出。

* **假设输入:**  一个 `HTMLVideoElement` 播放视频，并且其 `MediaVideoVisibilityTracker` 已经连接到文档。当请求可见性时。
* **预期输出:** 底层媒体播放器的 `RecordVideoOcclusionState` 方法会被调用，参数包含当前视频的可见性状态信息，例如是否足够可见，遮挡面积，交集矩形等。
* **代码体现:** `TEST_P(HTMLVideoElementTest, RecordVideoOcclusionStateCalledWhenVisibilityIsRequested)` 就测试了这种情况，并使用了 `EXPECT_CALL` 来验证 `RecordVideoOcclusionState` 方法是否被调用，并断言了预期的参数值。

**用户或编程常见的使用错误及举例：**

1. **在画中画模式下未正确处理元素生命周期:**
   - **错误:**  在进入或退出画中画时，没有正确地更新相关的 UI 或释放资源，可能导致内存泄漏或渲染问题。
   - **测试体现:** `PictureInPictureInterstitial_Reattach` 测试尝试在画中画模式下移除并重新添加视频元素，以确保这种操作不会导致崩溃。

2. **错误地假设视频帧总是可用:**
   - **错误:** 在没有检查 `HasAvailableVideoFrame()` 的情况下尝试访问视频帧数据，可能导致错误或崩溃。
   - **测试体现:** `HasAvailableVideoFrameChecksWMP` 测试验证了 `HTMLVideoElement` 正确地将帧可用性检查委托给底层播放器，提醒开发者应该使用这个方法来判断帧是否可用。

3. **未考虑默认海报图像的影响:**
   - **错误:**  开发者可能假设如果没有设置 `poster` 属性，视频元素就不会显示任何海报，但实际上可能显示了全局设置的默认海报图像。
   - **测试体现:** `DefaultPosterImage` 测试明确了默认海报图像的设置和使用，帮助开发者理解这种机制。

4. **对视频可见性状态的误解:**
   - **错误:**  开发者可能错误地认为只要视频元素在文档中就认为是可见的，而忽略了被其他元素遮挡的情况。
   - **测试体现:** `RecordVideoOcclusionStateCalledWhenVisibilityIsRequested` 等测试展示了如何通过 `MediaVideoVisibilityTracker` 来获取更准确的视频可见性状态，包括遮挡信息。

总而言之，`html_video_element_test.cc` 是一个非常重要的测试文件，它覆盖了 `HTMLVideoElement` 类的核心功能，并确保其在各种场景下的行为符合预期。通过这些测试，Chromium 团队可以保证视频播放功能的稳定性和正确性，并帮助开发者避免常见的错误用法。

### 提示词
```
这是目录为blink/renderer/core/html/media/html_video_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/html_video_element.h"

#include "cc/layers/layer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/media/display_type.h"
#include "third_party/blink/public/platform/web_fullscreen_video_status.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/media/html_media_test_helper.h"
#include "third_party/blink/renderer/core/html/media/media_video_visibility_tracker.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

using testing::_;
using testing::Return;

namespace blink {

namespace {

class HTMLVideoElementMockMediaPlayer : public EmptyWebMediaPlayer {
 public:
  MOCK_METHOD1(SetIsEffectivelyFullscreen, void(WebFullscreenVideoStatus));
  MOCK_METHOD1(OnDisplayTypeChanged, void(DisplayType));
  MOCK_CONST_METHOD0(HasAvailableVideoFrame, bool());
  MOCK_CONST_METHOD0(HasReadableVideoFrame, bool());
  MOCK_METHOD(void,
              RecordVideoOcclusionState,
              (std::string_view occlusion_state));
  MOCK_METHOD(gfx::Size, NaturalSize, (), (const));
};
}  // namespace

class HTMLVideoElementTest : public PaintTestConfigurations,
                             public RenderingTest {
 public:
  void SetUp() override {
    auto mock_media_player =
        std::make_unique<HTMLVideoElementMockMediaPlayer>();
    media_player_ = mock_media_player.get();
    SetupPageWithClients(nullptr,
                         MakeGarbageCollected<test::MediaStubLocalFrameClient>(
                             std::move(mock_media_player)),
                         nullptr);
    video_ = MakeGarbageCollected<HTMLVideoElement>(GetDocument());
    GetDocument().body()->appendChild(video_);
  }

  void SetFakeCcLayer(cc::Layer* layer) { video_->SetCcLayer(layer); }

  HTMLVideoElement* video() { return video_.Get(); }

  HTMLVideoElementMockMediaPlayer* MockWebMediaPlayer() {
    return media_player_;
  }

  HTMLVideoElementMockMediaPlayer* MockMediaPlayer() { return media_player_; }

  MediaVideoVisibilityTracker* VideoVisibilityTracker() {
    return video_ ? video_->visibility_tracker_for_tests() : nullptr;
  }

  MediaVideoVisibilityTracker::TrackerAttachedToDocument
  VideoVisibilityTrackerAttachedToDocument() const {
    DCHECK(video_);
    DCHECK(video_->visibility_tracker_for_tests());
    return video_->visibility_tracker_for_tests()
        ->tracker_attached_to_document_;
  }

  void RequestVisibility(HTMLMediaElement::RequestVisibilityCallback
                             request_visibility_callback) const {
    DCHECK(video_);
    video_->RequestVisibility(std::move(request_visibility_callback));
  }

  const MediaVideoVisibilityTracker::OcclusionState& TrackerOcclusionState() {
    DCHECK(video_);
    DCHECK(video_->visibility_tracker_for_tests());
    return video_->visibility_tracker_for_tests()->occlusion_state_;
  }

 private:
  Persistent<HTMLVideoElement> video_;

  // Owned by HTMLVideoElementFrameClient.
  HTMLVideoElementMockMediaPlayer* media_player_;
};
INSTANTIATE_PAINT_TEST_SUITE_P(HTMLVideoElementTest);

TEST_P(HTMLVideoElementTest, PictureInPictureInterstitialAndTextContainer) {
  scoped_refptr<cc::Layer> layer = cc::Layer::Create();
  SetFakeCcLayer(layer.get());

  video()->SetBooleanAttribute(html_names::kControlsAttr, true);
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();

  // Simulate the text track being displayed.
  video()->UpdateTextTrackDisplay();
  video()->UpdateTextTrackDisplay();

  // Simulate entering Picture-in-Picture.
  EXPECT_CALL(*MockWebMediaPlayer(),
              OnDisplayTypeChanged(DisplayType::kInline));
  video()->OnEnteredPictureInPicture();

  // Simulate that text track are displayed again.
  video()->UpdateTextTrackDisplay();

  EXPECT_EQ(3u, video()->EnsureUserAgentShadowRoot().CountChildren());
  EXPECT_CALL(*MockWebMediaPlayer(),
              OnDisplayTypeChanged(DisplayType::kInline));
  // Reset cc::layer to avoid crashes depending on timing.
  SetFakeCcLayer(nullptr);
}

TEST_P(HTMLVideoElementTest, PictureInPictureInterstitial_Reattach) {
  scoped_refptr<cc::Layer> layer = cc::Layer::Create();
  SetFakeCcLayer(layer.get());

  video()->SetBooleanAttribute(html_names::kControlsAttr, true);
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();

  EXPECT_CALL(*MockWebMediaPlayer(),
              OnDisplayTypeChanged(DisplayType::kInline));
  EXPECT_CALL(*MockWebMediaPlayer(), HasAvailableVideoFrame())
      .WillRepeatedly(testing::Return(true));

  // Simulate entering Picture-in-Picture.
  video()->OnEnteredPictureInPicture();

  EXPECT_CALL(*MockWebMediaPlayer(), OnDisplayTypeChanged(DisplayType::kInline))
      .Times(3);

  // Try detaching and reattaching. This should not crash.
  GetDocument().body()->removeChild(video());
  GetDocument().body()->appendChild(video());
  GetDocument().body()->removeChild(video());
}

TEST_P(HTMLVideoElementTest, EffectivelyFullscreen_DisplayType) {
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(DisplayType::kInline, video()->GetDisplayType());

  // Vector of data to use for tests. First value is to be set when calling
  // SetIsEffectivelyFullscreen(). The second one is the expected DisplayType.
  // This is testing all possible values of WebFullscreenVideoStatus and then
  // sets the value back to a value that should put the DisplayType back to
  // inline.
  Vector<std::pair<WebFullscreenVideoStatus, DisplayType>> tests = {
      {WebFullscreenVideoStatus::kNotEffectivelyFullscreen,
       DisplayType::kInline},
      {WebFullscreenVideoStatus::kFullscreenAndPictureInPictureEnabled,
       DisplayType::kFullscreen},
      {WebFullscreenVideoStatus::kFullscreenAndPictureInPictureDisabled,
       DisplayType::kFullscreen},
      {WebFullscreenVideoStatus::kNotEffectivelyFullscreen,
       DisplayType::kInline},
  };

  for (const auto& test : tests) {
    EXPECT_CALL(*MockWebMediaPlayer(), SetIsEffectivelyFullscreen(test.first));
    EXPECT_CALL(*MockWebMediaPlayer(), OnDisplayTypeChanged(test.second));
    video()->SetIsEffectivelyFullscreen(test.first);

    EXPECT_EQ(test.second, video()->GetDisplayType());
    testing::Mock::VerifyAndClearExpectations(MockWebMediaPlayer());
  }
}

TEST_P(HTMLVideoElementTest, ChangeLayerNeedsCompositingUpdate) {
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();

  auto layer1 = cc::Layer::Create();
  SetFakeCcLayer(layer1.get());
  auto* painting_layer =
      To<LayoutBoxModelObject>(video()->GetLayoutObject())->PaintingLayer();
  EXPECT_TRUE(painting_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(painting_layer->SelfNeedsRepaint());

  // Change to another cc layer.
  auto layer2 = cc::Layer::Create();
  SetFakeCcLayer(layer2.get());
  EXPECT_TRUE(painting_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(painting_layer->SelfNeedsRepaint());

  // Remove cc layer.
  SetFakeCcLayer(nullptr);
  EXPECT_TRUE(painting_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(painting_layer->SelfNeedsRepaint());
}

TEST_P(HTMLVideoElementTest, HasAvailableVideoFrameChecksWMP) {
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_CALL(*MockWebMediaPlayer(), HasAvailableVideoFrame())
      .WillOnce(testing::Return(false))
      .WillOnce(testing::Return(true));
  EXPECT_FALSE(video()->HasAvailableVideoFrame());
  EXPECT_TRUE(video()->HasAvailableVideoFrame());
}

TEST_P(HTMLVideoElementTest, AutoPIPExitPIPTest) {
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();

  // Set in auto PIP.
  video()->SetPersistentState(true);

  // Shouldn't get to PictureInPictureController::ExitPictureInPicture
  // and fail the DCHECK.
  EXPECT_NO_FATAL_FAILURE(video()->DidEnterFullscreen());
  test::RunPendingTasks();
}

// TODO(1190335): Remove this once we no longer support "default poster image"
// Blink embedders (such as Webview) can set the default poster image for a
// video using `blink::Settings`. In some cases we still need to distinguish
// between a "real" poster image and the default poster image.
TEST_P(HTMLVideoElementTest, DefaultPosterImage) {
  String const kDefaultPosterImage = "http://www.example.com/foo.jpg";

  // Override the default poster image
  GetDocument().GetSettings()->SetDefaultVideoPosterURL(kDefaultPosterImage);

  // Need to create a new video element, since
  // `HTMLVideoElement::default_poster_url_` is set upon construction.
  auto* video = MakeGarbageCollected<HTMLVideoElement>(GetDocument());
  GetDocument().body()->appendChild(video);

  // Assert that video element (without an explicitly set poster image url) has
  // the same poster image URL as what we just set.
  EXPECT_TRUE(video->IsDefaultPosterImageURL());
  EXPECT_EQ(kDefaultPosterImage, video->PosterImageURL());

  // Set the poster image of the video to something
  video->setAttribute(html_names::kPosterAttr,
                      AtomicString("http://www.example.com/bar.jpg"));
  EXPECT_FALSE(video->IsDefaultPosterImageURL());
  EXPECT_NE(kDefaultPosterImage, video->PosterImageURL());
}

TEST_P(HTMLVideoElementTest,
       RecordVideoOcclusionStateCalledWhenVisibilityIsRequested) {
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  video()->Play();
  EXPECT_TRUE(video()->GetWebMediaPlayer());
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(), nullptr);

  // Request visibility and verify `RecordVideoOcclusionState` is called.
  const std::string expected_occlusion_state =
      "has sufficiently visible video: {True}, occluded area: {0.00}, "
      "occluding rects: {None}, intersection rect: {x: 8, y: 8, width: 300, "
      "height: 150}, video element rect: {x: 8, y: 8, width: 300, height: "
      "150}, visibility threshold: {10000}";
  EXPECT_CALL((*MockMediaPlayer()),
              RecordVideoOcclusionState(expected_occlusion_state));
  RequestVisibility(base::DoNothing());

  // Verify that `RecordVideoOcclusionState` is also called when the document is
  // not in the `DocumentUpdateReason::kPaintClean` lifecycle state.
  //
  // Set the lifecycle state to a value < `DocumentUpdateReason::kPaintClean`.
  // This will cause the tracker to used the cached
  // `meets_visibility_threshold_` value when we request visibility.
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_CALL((*MockMediaPlayer()),
              RecordVideoOcclusionState(expected_occlusion_state));
  RequestVisibility(base::DoNothing());
}

TEST_P(HTMLVideoElementTest,
       RecordVideoOcclusionStateNotCalledIfVisibilityIsNotRequested) {
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  video()->Play();

  // Update all lifecycle phases and verify `RecordVideoOcclusionState` is not
  // called.
  EXPECT_CALL((*MockMediaPlayer()), RecordVideoOcclusionState(_)).Times(0);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(video()->GetWebMediaPlayer());
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(), nullptr);
}

TEST_P(HTMLVideoElementTest,
       RecordVideoOcclusionStateCalledWhenTrackerNotAttached) {
  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  video()->Play();
  EXPECT_TRUE(video()->GetWebMediaPlayer());
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(), nullptr);

  // Remove video, and verify that the visibility tracker has been detached.
  NonThrowableExceptionState should_not_throw;
  video()->remove(should_not_throw);
  test::RunPendingTasks();
  EXPECT_EQ(VideoVisibilityTrackerAttachedToDocument(), nullptr);

  // Request visibility and verify `RecordVideoOcclusionState` is called since
  // the tracker has a request visibility callback.
  const std::string expected_occlusion_state =
      "has sufficiently visible video: {False}, occluded area: {0.00}, "
      "occluding rects: {None}, intersection rect: {None}, video element rect: "
      "{None}, visibility threshold: {10000}";
  EXPECT_CALL((*MockMediaPlayer()),
              RecordVideoOcclusionState(expected_occlusion_state));
  RequestVisibility(base::DoNothing());
}

TEST_P(HTMLVideoElementTest, VideoVisibilityTrackerVideoElementRectDimensions) {
  const auto& expected_natural_size = gfx::Size(1920, 1080);
  EXPECT_CALL(*MockMediaPlayer(), NaturalSize())
      .WillRepeatedly(Return(expected_natural_size));

  video()->SetSrc(AtomicString("http://example.com/foo.mp4"));
  video()->setAttribute(html_names::kStyleAttr,
                        AtomicString("width: 300px; height: 300px"));
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(VideoVisibilityTracker(), nullptr);

  video()->Play();
  EXPECT_TRUE(video()->GetWebMediaPlayer());
  ASSERT_EQ(expected_natural_size,
            gfx::Size(video()->videoWidth(), video()->videoHeight()));
  ASSERT_NE(VideoVisibilityTracker(), nullptr);
  EXPECT_NE(VideoVisibilityTrackerAttachedToDocument(), nullptr);

  RequestVisibility(base::DoNothing());

  // Verify that the visibility tracker is using the content rect for the
  // `video_element_rect`.
  const auto occlusion_state = TrackerOcclusionState();
  LayoutBox* box = To<LayoutBox>(video()->GetLayoutObject());
  EXPECT_EQ(box->AbsoluteBoundingBoxRect().width(),
            occlusion_state.video_element_rect.Width());
  EXPECT_GT(box->AbsoluteBoundingBoxRect().height(),
            occlusion_state.video_element_rect.Height());

  // Verify that the `video_element_rect` intersects the `HTMLVideoElement`
  // bounds.
  const auto intersection = Intersection(VisualRectInDocument(*box),
                                         occlusion_state.video_element_rect);
  EXPECT_EQ(occlusion_state.video_element_rect, intersection);
}

}  // namespace blink
```