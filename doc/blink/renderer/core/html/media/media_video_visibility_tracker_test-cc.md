Response:
My thinking process to analyze the given C++ test file went something like this:

1. **Understand the Goal:** The request asks for the functionality of the provided C++ test file (`media_video_visibility_tracker_test.cc`). It also asks for relationships to web technologies (HTML, CSS, JavaScript), logical inferences, and common usage errors. Finally, it asks for a summary of the functionality (since it's part 1 of 2).

2. **Initial Skim for Keywords and Structure:**  I quickly scanned the code, looking for obvious clues:
    * `#include`:  Confirms it's C++ code. The included headers (`media_video_visibility_tracker.h`, `html_video_element.h`, testing headers) immediately suggest this file is testing the `MediaVideoVisibilityTracker` class.
    * `namespace blink`:  Indicates this is part of the Blink rendering engine.
    * Class `MediaVideoVisibilityTrackerTest`:  This is the main test fixture, confirming the purpose.
    * `TEST_F`: These are Google Test macros, indicating individual test cases.
    * Method names like `LoadMainResource`, `VideoElement`, `CreateTracker`, `Attach`, `Detach`:  These suggest common test setup and teardown actions.
    * Assertions like `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_CALL`:  Standard testing assertions to verify behavior.

3. **Identify the Core Class Under Test:**  The name `MediaVideoVisibilityTrackerTest` and the inclusion of `media_video_visibility_tracker.h` clearly point to the `MediaVideoVisibilityTracker` class as the target of these tests.

4. **Infer the Purpose of `MediaVideoVisibilityTracker`:** Based on the test names and the methods used, I started to infer what `MediaVideoVisibilityTracker` likely does:
    * It tracks the visibility of a video element.
    * It uses a "visibility threshold" (an integer parameter).
    * It interacts with the rendering engine to determine occlusion by other elements.
    * It reports visibility changes through a callback.
    * It considers factors like viewport intersection, element opacity, stacking order (z-index), and potentially shadow DOM.

5. **Analyze Individual Test Cases:** I went through each `TEST_F` case, trying to understand the scenario being tested:
    * **Basic Visibility:** Tests whether a video is considered visible or not when there's no occlusion or when its area meets a certain threshold.
    * **Occlusion:** Tests scenarios where other HTML elements overlap the video, checking if the tracker correctly identifies the occluding elements and calculates the occluded area.
    * **Viewport Intersection:** Tests whether the video is visible within the viewport.
    * **Ignoring Factors:** Tests whether certain elements (like video controls or elements with zero opacity) are correctly ignored for visibility calculations.
    * **Dynamic Changes:** Tests how the tracker reacts to changes in the DOM after it's been attached (e.g., adding an occluding element).
    * **Client IDs:** Tests a feature likely related to identifying specific rendering objects involved in visibility calculations.
    * **On-Demand Visibility:** Tests a method to check visibility outside the normal update cycle.

6. **Relate to Web Technologies:**  This is where I connected the C++ code to HTML, CSS, and JavaScript:
    * **HTML:** The tests manipulate HTML structures (creating video elements, adding divs, setting attributes). The visibility tracker directly relates to how video elements are rendered and perceived by the user.
    * **CSS:** CSS properties like `width`, `height`, `position`, `opacity`, and `z-index` are crucial for determining element layout and occlusion, which the tracker tests.
    * **JavaScript:** While this specific test file doesn't directly involve JavaScript execution, the underlying `MediaVideoVisibilityTracker` would likely be used by JavaScript APIs or internal browser logic related to media playback and visibility reporting (e.g., Intersection Observer API).

7. **Identify Logical Inferences and Assumptions:**  For each test, I considered the input (the HTML structure, CSS styles, viewport size, scroll position) and the expected output (whether the video meets the visibility threshold, the set of occluding rectangles). This involved some logical reasoning about how the rendering engine should behave based on CSS rules.

8. **Consider Common Usage Errors:** I thought about how developers might misuse the underlying functionality (even though this is a test file). This led to ideas like setting an invalid threshold or not attaching the tracker correctly.

9. **Synthesize the Functionality (for Part 1):** Based on the analysis, I summarized the main purpose of the test file as verifying the correctness of the `MediaVideoVisibilityTracker` in various scenarios related to video visibility. I highlighted the key factors it tests (occlusion, viewport, thresholds) and its relationship to HTML and CSS.

10. **Refine and Organize:** I structured my response to address each part of the request clearly, using examples and clear explanations. I paid attention to the phrasing to ensure it was accurate and easy to understand.

Essentially, I approached it like reverse-engineering the purpose of the code by examining its tests. The test cases provide concrete examples of how the `MediaVideoVisibilityTracker` is expected to behave under different conditions.

```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/media_video_visibility_tracker.h"

#include "base/test/mock_callback.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using ::testing::_;
using ::testing::Return;
using ::testing::UnorderedElementsAreArray;

namespace {

// Helper class to mock `RequestVisibility` callbacks.
class RequestVisibilityCallback {
 public:
  RequestVisibilityCallback() = default;
  RequestVisibilityCallback(const RequestVisibilityCallback&) = delete;
  RequestVisibilityCallback(RequestVisibilityCallback&&) = delete;
  RequestVisibilityCallback& operator=(const RequestVisibilityCallback&) =
      delete;

  MediaVideoVisibilityTracker::RequestVisibilityCallback VisibilityCallback() {
    meets_visibility_ = std::nullopt;
    // base::Unretained() is safe since no further tasks can run after
    // RunLoop::Run() returns.
    return base::BindOnce(&RequestVisibilityCallback::RequestVisibility,
                          base::Unretained(this));
  }

  void WaitUntilDone() {
    if (meets_visibility_) {
      return;
    }
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

  bool MeetsVisibility() {
    DCHECK(meets_visibility_);
    return meets_visibility_.value();
  }

 private:
  void RequestVisibility(bool meets_visibility) {
    meets_visibility_ = meets_visibility;
    if (run_loop_) {
      run_loop_->Quit();
    }
  }

  std::unique_ptr<base::RunLoop> run_loop_;
  std::optional<bool> meets_visibility_;
};

}  // namespace

class MediaVideoVisibilityTrackerTest : public SimTest {
 public:
  MediaVideoVisibilityTrackerTest()
      : SimTest(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

 protected:
  void TearDown() override {
    if (tracker_) {
      tracker_->Detach();
    }
    SimTest::TearDown();
  }

  void LoadMainResource(const String& html) {
    SimRequest main_resource("https://example.com/", "text/html");
    LoadURL("https://example.com/");
    main_resource.Complete(html);
    ASSERT_NE(VideoElement(), nullptr);
  }

  HTMLVideoElement* VideoElement() {
    HTMLVideoElement* video_element = To<HTMLVideoElement>(
        GetDocument().QuerySelector(AtomicString("video")));
    DCHECK(video_element);
    return video_element;
  }

  MediaVideoVisibilityTracker* CreateTracker(const int visibility_threshold) {
    DCHECK(!tracker_);
    tracker_ = MakeGarbageCollected<MediaVideoVisibilityTracker>(
        *VideoElement(), visibility_threshold, ReportVisibilityCb().Get());
    return tracker_;
  }

  MediaVideoVisibilityTracker* CreateAndAttachVideoVisibilityTracker(
      const int visibility_threshold) {
    CreateTracker(visibility_threshold);
    tracker_->Attach();
    return tracker_;
  }

  float ComputeArea(const PhysicalRect& rect) {
    return static_cast<float>(ToRoundedSize(rect.size).Area64());
  }

  base::MockRepeatingCallback<void(bool)>& ReportVisibilityCb() {
    return report_visibility_cb_;
  }

  const PhysicalRect IntersectionRect() const {
    DCHECK(tracker_);
    return tracker_->occlusion_state_.intersection_rect;
  }

  const VectorOf<SkIRect> OccludingRects() const {
    DCHECK(tracker_);
    return tracker_->occlusion_state_.occluding_rects;
  }

  float OccludedArea() const {
    DCHECK(tracker_);
    return tracker_->occlusion_state_.occluded_area;
  }

  const MediaVideoVisibilityTracker::ClientIdsSet GetClientIdsSet(
      DisplayItemClientId start_after_display_item_client_id) const {
    DCHECK(tracker_);
    return tracker_->GetClientIdsSet(start_after_display_item_client_id);
  }

  const MediaVideoVisibilityTracker::TrackerAttachedToDocument TrackerAttached()
      const {
    DCHECK(tracker_);
    return tracker_->tracker_attached_to_document_;
  }

  void SetRequestVisibilityCbForTesting(
      RequestVisibilityCallback& request_visibility_callback) {
    DCHECK(tracker_);
    tracker_->request_visibility_callback_ =
        request_visibility_callback.VisibilityCallback();
  }

  void DetachVideoVisibilityTracker() {
    DCHECK(tracker_);
    tracker_->Detach();
  }

 private:
  Persistent<MediaVideoVisibilityTracker> tracker_;
  base::MockRepeatingCallback<void(bool)> report_visibility_cb_;
};

#if DCHECK_IS_ON()
TEST_F(MediaVideoVisibilityTrackerTest, InvalidThreshold) {
  auto* video = GetDocument().CreateRawElement(html_names::kVideoTag);
  GetDocument().body()->AppendChild(video);
  EXPECT_DEATH_IF_SUPPORTED(CreateAndAttachVideoVisibilityTracker(0), "");
}
#endif  // DCHECK_IS_ON()

TEST_F(MediaVideoVisibilityTrackerTest,
       NoOcclusionDoesNotMeetVisibilityThreshold) {
  LoadMainResource(R"HTML(
    <style>
      video {
        object-fit: fill;
        width: 50px;
        height: 50px;
      }
    </style>
    <video></video>
  )HTML");
  EXPECT_FALSE(VideoElement()->ShouldShowControls());

  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest, NoOcclusionMeetsVisibilityThreshold) {
  LoadMainResource(R"HTML(
    <style>
      video {
        object-fit: fill;
        width: 150px;
        height: 150px;
      }
    </style>
    <video></video>
  )HTML");
  EXPECT_FALSE(VideoElement()->ShouldShowControls());

  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest, VideoControlsAreIgnored) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(700, 700));
  LoadMainResource(R"HTML(
    <style>
      video {
        object-fit: fill;
        width: 150px;
        height: 150px;
      }
    </style>
    <video controls></video>
  )HTML");
  EXPECT_TRUE(VideoElement()->ShouldShowControls());

  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest, NoViewPortIntersection) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      video {
        object-fit: fill;
        width: 150px;
        height: 150px;
      }
      .spacer {
        height: 500px;
      }
    </style>
    <video></video>
    <div class="spacer"></div>
  )HTML");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_CALL(ReportVisibilityCb(), Run(false));

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 500), mojom::blink::ScrollType::kProgrammatic);

  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_TRUE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rect{
      SkIRect::MakeXYWH(8, -158, 150, 150)};
  EXPECT_EQ(expected_occludning_rect, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       SingleElementNotOccludingAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 500px;
        height: 500px;
        top:0;
        left:0
      }
      div {
        background-color: blue;
        width: 100px;
        height: 100px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rect{SkIRect::MakeXYWH(0, 0, 100, 100)};
  EXPECT_EQ(expected_occludning_rect, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest, SingleElementOccludingAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(700, 700));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 500px;
        height: 500px;
        top:0;
        left:0
      }
      div {
        background-color: blue;
        width: 490px;
        height: 490px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(0, 0, 490, 490)};
  EXPECT_EQ(expected_occludning_rects, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       MultipleElementsOccludingEqualToThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 250px;
        height: 250px;
        position: absolute;
        top: 0;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 250px;
        height: 250px;
        position: absolute;
        top: 0;
        right: 0;
      }
    </style>
    <video></video>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
  )HTML");
  const int visibility_threshold = 125000;
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(visibility_threshold);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(250, 0, 250, 250), SkIRect::MakeXYWH(0, 0, 250, 250)};
  EXPECT_THAT(expected_occludning_rects,
              UnorderedElementsAreArray(OccludingRects()));
  EXPECT_EQ(visibility_threshold,
            ComputeArea(IntersectionRect()) - OccludedArea());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       MultipleElementsOccludingGreaterThanThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 250px;
        height: 500px;
        position: absolute;
        top: 0;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 250px;
        height: 490px;
        position: absolute;
        top: 0;
        right: 0;
      }
    </style>
    <video></video>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(250, 0, 250, 490), SkIRect::MakeXYWH(0, 0, 250, 500)};
  EXPECT_THAT(expected_occludning_rects,
              UnorderedElementsAreArray(OccludingRects()));
}

TEST_F(MediaVideoVisibilityTrackerTest, ElementWithZeroOpacityIsIgnored) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(700, 700));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 500px;
        height: 500px;
        top:0;
        left:0
      }
      div {
        background-color: blue;
        width: 500px;
        height: 500px;
        position: absolute;
        top: 0;
        left: 0;
        opacity: 0.2;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  // First ensure that we report the video as not visible, when an element has
  // opacity greater than zero and occludes an area greater than what's allowed
  // by the threshold.
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  EXPECT_EQ(VectorOf<SkIRect>{SkIRect::MakeXYWH(0, 0, 500, 500)},
            OccludingRects());

  // Now set opacity to zero and verify that the video is considered visible.
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  div->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.0"));

  EXPECT_CALL(ReportVisibilityCb(), Run(true));

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest, ElementsBehindVideoAreIgnored) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 250px;
        height: 500px;
        position: absolute;
        top: 0;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 250px;
        height: 500px;
        position: absolute;
        top: 0;
        right: 0;
      }
    </style>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
    <video></video>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       MultipleIntersectingElementsOccludingGreaterThanThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 100%;
        height: 100%;
        position: absolute;
        top: 0;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 100%;
        height: 50px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(0, 0, 500, 50), SkIRect::MakeXYWH(0, 0, 500, 500)};
  EXPECT_THAT(expected_occludning_rects,
              UnorderedElementsAreArray(OccludingRects()));
  EXPECT_EQ(1, OccludedArea() / ComputeArea(IntersectionRect()));
}

TEST_F(MediaVideoVisibilityTrackerTest,
       MultipleIntersectingElementsOccludingBelowThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
  <style>
    body {
      margin: 0;
    }
    video {
      object-fit: fill;
      position: relative;
      width: 500px;
      height: 500px;
    }
    .occluding_div_1 {
      background-color: blue;
      width: 500px;
      height: 50px;
      position: absolute;
      top: 0;
      left: 0;
    }
    .occluding_div_2 {
      background-color: red;
      width: 500px;
      height: 50px;
      position: absolute;
      top: 25px;
      left: 0;
    }
    .occluding_div_3 {
      background-color: yellow;
      width: 500px;
      height: 50px;
      position: absolute;
      top: 25px;
      left: 0;
    }
    .occluding_div_4 {
      background-color: green;
      width: 500px;
      height: 50px;
      position: absolute;
      top: 25px;
      left: 0;
    }
  </style>
  <video></video>
  <div class="occluding_div_1"></div>
  <div class="occluding_div_2"></div>
  <div class="occluding_div_3"></div>
  <div class="occluding_div_4"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  // Verify that overlapping intersections were not counted multiple times.
  EXPECT_EQ(37500, OccludedArea());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       HitTestingStopsWhenOcclusionAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 100%;
        height: 10px;
        position: absolute;
        top: 485px;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 100%;
        height: 360px;
        position: absolute;
        top: 125px;
        left: 0;
      }
      .occluding_div_3 {
        background-color: yellow;
        width: 100%;
        height: 125px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
    <div class="occluding_div_3"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(0, 0, 500, 125), SkIRect::MakeXYWH(0, 125, 500, 360)};
  EXPECT_THAT(expected_occludning_rects,
              UnorderedElementsAreArray(OccludingRects()));
}

TEST_F(MediaVideoVisibilityTrackerTest,
       ViewportIntersectionFromVisibleToNotVisibleWithNoOcclusion) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        height: 2000px;
      }
      video {
        object-fit: fill;
        width: 100px;
        height: 100px;
      }
    </style>
    <video></video>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());

  // Scroll page and verify that the visibility threshold is not met.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 500), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_CALL(ReportVisibilityCb(), Run(false));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       ViewportIntersectionFromNotVisibleToVisibleWithNoOcclusion) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        height: 2000px;
      }
      video {
        object-fit: fill;
        width: 100px;
        height: 100px;
        position: absolute;
        top: 600px;
        left: 0px;
      }
    </style>
    <video></video>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_TRUE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  // Scroll page and verify that the visibility threshold is not met.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 600), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_CALL(ReportVisibilityCb(), Run(true));

  
### 提示词
```
这是目录为blink/renderer/core/html/media/media_video_visibility_tracker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/media_video_visibility_tracker.h"

#include "base/test/mock_callback.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using ::testing::_;
using ::testing::Return;
using ::testing::UnorderedElementsAreArray;

namespace {

// Helper class to mock `RequestVisibility` callbacks.
class RequestVisibilityCallback {
 public:
  RequestVisibilityCallback() = default;
  RequestVisibilityCallback(const RequestVisibilityCallback&) = delete;
  RequestVisibilityCallback(RequestVisibilityCallback&&) = delete;
  RequestVisibilityCallback& operator=(const RequestVisibilityCallback&) =
      delete;

  MediaVideoVisibilityTracker::RequestVisibilityCallback VisibilityCallback() {
    meets_visibility_ = std::nullopt;
    // base::Unretained() is safe since no further tasks can run after
    // RunLoop::Run() returns.
    return base::BindOnce(&RequestVisibilityCallback::RequestVisibility,
                          base::Unretained(this));
  }

  void WaitUntilDone() {
    if (meets_visibility_) {
      return;
    }
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
  }

  bool MeetsVisibility() {
    DCHECK(meets_visibility_);
    return meets_visibility_.value();
  }

 private:
  void RequestVisibility(bool meets_visibility) {
    meets_visibility_ = meets_visibility;
    if (run_loop_) {
      run_loop_->Quit();
    }
  }

  std::unique_ptr<base::RunLoop> run_loop_;
  std::optional<bool> meets_visibility_;
};

}  // namespace

class MediaVideoVisibilityTrackerTest : public SimTest {
 public:
  MediaVideoVisibilityTrackerTest()
      : SimTest(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

 protected:
  void TearDown() override {
    if (tracker_) {
      tracker_->Detach();
    }
    SimTest::TearDown();
  }

  void LoadMainResource(const String& html) {
    SimRequest main_resource("https://example.com/", "text/html");
    LoadURL("https://example.com/");
    main_resource.Complete(html);
    ASSERT_NE(VideoElement(), nullptr);
  }

  HTMLVideoElement* VideoElement() {
    HTMLVideoElement* video_element = To<HTMLVideoElement>(
        GetDocument().QuerySelector(AtomicString("video")));
    DCHECK(video_element);
    return video_element;
  }

  MediaVideoVisibilityTracker* CreateTracker(const int visibility_threshold) {
    DCHECK(!tracker_);
    tracker_ = MakeGarbageCollected<MediaVideoVisibilityTracker>(
        *VideoElement(), visibility_threshold, ReportVisibilityCb().Get());
    return tracker_;
  }

  MediaVideoVisibilityTracker* CreateAndAttachVideoVisibilityTracker(
      const int visibility_threshold) {
    CreateTracker(visibility_threshold);
    tracker_->Attach();
    return tracker_;
  }

  float ComputeArea(const PhysicalRect& rect) {
    return static_cast<float>(ToRoundedSize(rect.size).Area64());
  }

  base::MockRepeatingCallback<void(bool)>& ReportVisibilityCb() {
    return report_visibility_cb_;
  }

  const PhysicalRect IntersectionRect() const {
    DCHECK(tracker_);
    return tracker_->occlusion_state_.intersection_rect;
  }

  const VectorOf<SkIRect> OccludingRects() const {
    DCHECK(tracker_);
    return tracker_->occlusion_state_.occluding_rects;
  }

  float OccludedArea() const {
    DCHECK(tracker_);
    return tracker_->occlusion_state_.occluded_area;
  }

  const MediaVideoVisibilityTracker::ClientIdsSet GetClientIdsSet(
      DisplayItemClientId start_after_display_item_client_id) const {
    DCHECK(tracker_);
    return tracker_->GetClientIdsSet(start_after_display_item_client_id);
  }

  const MediaVideoVisibilityTracker::TrackerAttachedToDocument TrackerAttached()
      const {
    DCHECK(tracker_);
    return tracker_->tracker_attached_to_document_;
  }

  void SetRequestVisibilityCbForTesting(
      RequestVisibilityCallback& request_visibility_callback) {
    DCHECK(tracker_);
    tracker_->request_visibility_callback_ =
        request_visibility_callback.VisibilityCallback();
  }

  void DetachVideoVisibilityTracker() {
    DCHECK(tracker_);
    tracker_->Detach();
  }

 private:
  Persistent<MediaVideoVisibilityTracker> tracker_;
  base::MockRepeatingCallback<void(bool)> report_visibility_cb_;
};

#if DCHECK_IS_ON()
TEST_F(MediaVideoVisibilityTrackerTest, InvalidThreshold) {
  auto* video = GetDocument().CreateRawElement(html_names::kVideoTag);
  GetDocument().body()->AppendChild(video);
  EXPECT_DEATH_IF_SUPPORTED(CreateAndAttachVideoVisibilityTracker(0), "");
}
#endif  // DCHECK_IS_ON()

TEST_F(MediaVideoVisibilityTrackerTest,
       NoOcclusionDoesNotMeetVisibilityThreshold) {
  LoadMainResource(R"HTML(
    <style>
      video {
        object-fit: fill;
        width: 50px;
        height: 50px;
      }
    </style>
    <video></video>
  )HTML");
  EXPECT_FALSE(VideoElement()->ShouldShowControls());

  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest, NoOcclusionMeetsVisibilityThreshold) {
  LoadMainResource(R"HTML(
    <style>
      video {
        object-fit: fill;
        width: 150px;
        height: 150px;
      }
    </style>
    <video></video>
  )HTML");
  EXPECT_FALSE(VideoElement()->ShouldShowControls());

  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest, VideoControlsAreIgnored) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(700, 700));
  LoadMainResource(R"HTML(
    <style>
      video {
        object-fit: fill;
        width: 150px;
        height: 150px;
      }
    </style>
    <video controls></video>
  )HTML");
  EXPECT_TRUE(VideoElement()->ShouldShowControls());

  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest, NoViewPortIntersection) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      video {
        object-fit: fill;
        width: 150px;
        height: 150px;
      }
      .spacer {
        height: 500px;
      }
    </style>
    <video></video>
    <div class="spacer"></div>
  )HTML");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_CALL(ReportVisibilityCb(), Run(false));

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 500), mojom::blink::ScrollType::kProgrammatic);

  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_TRUE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rect{
      SkIRect::MakeXYWH(8, -158, 150, 150)};
  EXPECT_EQ(expected_occludning_rect, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       SingleElementNotOccludingAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 500px;
        height: 500px;
        top:0;
        left:0
      }
      div {
        background-color: blue;
        width: 100px;
        height: 100px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rect{SkIRect::MakeXYWH(0, 0, 100, 100)};
  EXPECT_EQ(expected_occludning_rect, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest, SingleElementOccludingAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(700, 700));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 500px;
        height: 500px;
        top:0;
        left:0
      }
      div {
        background-color: blue;
        width: 490px;
        height: 490px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(0, 0, 490, 490)};
  EXPECT_EQ(expected_occludning_rects, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       MultipleElementsOccludingEqualToThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 250px;
        height: 250px;
        position: absolute;
        top: 0;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 250px;
        height: 250px;
        position: absolute;
        top: 0;
        right: 0;
      }
    </style>
    <video></video>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
  )HTML");
  const int visibility_threshold = 125000;
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(visibility_threshold);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(250, 0, 250, 250), SkIRect::MakeXYWH(0, 0, 250, 250)};
  EXPECT_THAT(expected_occludning_rects,
              UnorderedElementsAreArray(OccludingRects()));
  EXPECT_EQ(visibility_threshold,
            ComputeArea(IntersectionRect()) - OccludedArea());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       MultipleElementsOccludingGreaterThanThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 250px;
        height: 500px;
        position: absolute;
        top: 0;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 250px;
        height: 490px;
        position: absolute;
        top: 0;
        right: 0;
      }
    </style>
    <video></video>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(250, 0, 250, 490), SkIRect::MakeXYWH(0, 0, 250, 500)};
  EXPECT_THAT(expected_occludning_rects,
              UnorderedElementsAreArray(OccludingRects()));
}

TEST_F(MediaVideoVisibilityTrackerTest, ElementWithZeroOpacityIsIgnored) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(700, 700));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 500px;
        height: 500px;
        top:0;
        left:0
      }
      div {
        background-color: blue;
        width: 500px;
        height: 500px;
        position: absolute;
        top: 0;
        left: 0;
        opacity: 0.2;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  // First ensure that we report the video as not visible, when an element has
  // opacity greater than zero and occludes an area greater than what's allowed
  // by the threshold.
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  EXPECT_EQ(VectorOf<SkIRect>{SkIRect::MakeXYWH(0, 0, 500, 500)},
            OccludingRects());

  // Now set opacity to zero and verify that the video is considered visible.
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  div->setAttribute(html_names::kStyleAttr, AtomicString("opacity: 0.0"));

  EXPECT_CALL(ReportVisibilityCb(), Run(true));

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest, ElementsBehindVideoAreIgnored) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 250px;
        height: 500px;
        position: absolute;
        top: 0;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 250px;
        height: 500px;
        position: absolute;
        top: 0;
        right: 0;
      }
    </style>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
    <video></video>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       MultipleIntersectingElementsOccludingGreaterThanThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 100%;
        height: 100%;
        position: absolute;
        top: 0;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 100%;
        height: 50px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(0, 0, 500, 50), SkIRect::MakeXYWH(0, 0, 500, 500)};
  EXPECT_THAT(expected_occludning_rects,
              UnorderedElementsAreArray(OccludingRects()));
  EXPECT_EQ(1, OccludedArea() / ComputeArea(IntersectionRect()));
}

TEST_F(MediaVideoVisibilityTrackerTest,
       MultipleIntersectingElementsOccludingBelowThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
  <style>
    body {
      margin: 0;
    }
    video {
      object-fit: fill;
      position: relative;
      width: 500px;
      height: 500px;
    }
    .occluding_div_1 {
      background-color: blue;
      width: 500px;
      height: 50px;
      position: absolute;
      top: 0;
      left: 0;
    }
    .occluding_div_2 {
      background-color: red;
      width: 500px;
      height: 50px;
      position: absolute;
      top: 25px;
      left: 0;
    }
    .occluding_div_3 {
      background-color: yellow;
      width: 500px;
      height: 50px;
      position: absolute;
      top: 25px;
      left: 0;
    }
    .occluding_div_4 {
      background-color: green;
      width: 500px;
      height: 50px;
      position: absolute;
      top: 25px;
      left: 0;
    }
  </style>
  <video></video>
  <div class="occluding_div_1"></div>
  <div class="occluding_div_2"></div>
  <div class="occluding_div_3"></div>
  <div class="occluding_div_4"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  // Verify that overlapping intersections were not counted multiple times.
  EXPECT_EQ(37500, OccludedArea());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       HitTestingStopsWhenOcclusionAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 100%;
        height: 100%;
      }
      .occluding_div_1 {
        background-color: blue;
        width: 100%;
        height: 10px;
        position: absolute;
        top: 485px;
        left: 0;
      }
      .occluding_div_2 {
        background-color: red;
        width: 100%;
        height: 360px;
        position: absolute;
        top: 125px;
        left: 0;
      }
      .occluding_div_3 {
        background-color: yellow;
        width: 100%;
        height: 125px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div class="occluding_div_1"></div>
    <div class="occluding_div_2"></div>
    <div class="occluding_div_3"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rects{
      SkIRect::MakeXYWH(0, 0, 500, 125), SkIRect::MakeXYWH(0, 125, 500, 360)};
  EXPECT_THAT(expected_occludning_rects,
              UnorderedElementsAreArray(OccludingRects()));
}

TEST_F(MediaVideoVisibilityTrackerTest,
       ViewportIntersectionFromVisibleToNotVisibleWithNoOcclusion) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        height: 2000px;
      }
      video {
        object-fit: fill;
        width: 100px;
        height: 100px;
      }
    </style>
    <video></video>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());

  // Scroll page and verify that the visibility threshold is not met.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 500), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_CALL(ReportVisibilityCb(), Run(false));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       ViewportIntersectionFromNotVisibleToVisibleWithNoOcclusion) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 500));
  LoadMainResource(R"HTML(
    <style>
      body {
        height: 2000px;
      }
      video {
        object-fit: fill;
        width: 100px;
        height: 100px;
        position: absolute;
        top: 600px;
        left: 0px;
      }
    </style>
    <video></video>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_TRUE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  // Scroll page and verify that the visibility threshold is not met.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 600), mojom::blink::ScrollType::kProgrammatic);
  EXPECT_CALL(ReportVisibilityCb(), Run(true));

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_TRUE(OccludingRects().empty());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       SingleElementPartiallyIntersectingNotOccludingAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 200px;
        height: 200px;
        top: 0;
        left: 0}
      div {
        background-color: blue;
        width: 650px;
        height: 100px;
        position: absolute;
        top: 0;
        right: 0;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rect{
      SkIRect::MakeXYWH(150, 0, 50, 100)};
  EXPECT_EQ(expected_occludning_rect, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       NonUserAgentShadowDomElementOccludingAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
  <style>
    body {
      margin: 0;
    }
    video {
      object-fit: fill;
      position: relative;
      width: 100%;
      height: 100%;
    }
  </style>
  <video></video>
  <host-element>
    <template shadowrootmode="open">
      <style>
        div {
          position: absolute;
          top: 0;
          bottom: 0;
          width: 100%;
          height: 100%;
          background-color: blue;
        }
      </style>
      <div>
      </div>
    </template>
  </host-element>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(false));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rect{SkIRect::MakeXYWH(0, 0, 800, 800)};
  EXPECT_EQ(expected_occludning_rect, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       ElementAddedAfterPlayOccludingAboveThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 500px;
        height: 500px;
        top:0;
        left:0
      }
      div {
        background-color: blue;
        width: 100px;
        height: 100px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  VectorOf<SkIRect> expected_occludning_rect{SkIRect::MakeXYWH(0, 0, 100, 100)};
  EXPECT_EQ(expected_occludning_rect, OccludingRects());

  // Update div to a size that would cause the video to not meet the visibility
  // threshold.
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  div->setAttribute(html_names::kStyleAttr,
                    AtomicString("width:100%; height: 100%;"));
  EXPECT_CALL(ReportVisibilityCb(), Run(false));

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  // Observe that video does not meet visibility threshold, now that the div
  // occludes 100% of the video.
  EXPECT_FALSE(IntersectionRect().IsEmpty());
  EXPECT_FALSE(OccludingRects().empty());

  expected_occludning_rect = {SkIRect::MakeXYWH(0, 0, 500, 500)};
  EXPECT_EQ(expected_occludning_rect, OccludingRects());
}

TEST_F(MediaVideoVisibilityTrackerTest, ClientIdsSetContents) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
  <style>
    body {
      margin: 0;
    }
    video {
      object-fit: fill;
      position: relative;
      width: 500px;
      height: 500px;
      top:0;
      left:0;
    }
    #ignored_div {
      background-color: blue;
      width: 50px;
      height: 50px;
      position: relative;
    }
    #visible_div {
      background-color: yellow;
      width: 50px;
      height: 50px;
      position: absolute;
      top: 0;
      left: 0;
    }
    #invisible_div {
      width: 50px;
      height: 50px;
      position: absolute;
      top: 0;
      left: 0;
    }
  </style>
  <video></video>
  <div id="ignored_div"></div>
  <div id="visible_div"></div>
  <div id="invisible_div"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  // Verify that the DisplayItemClientId passed as a parameter to
  // `GetClientIdsSet` is not in the set.
  auto* ignored_div = GetDocument().getElementById(AtomicString("ignored_div"));
  ASSERT_TRUE(ignored_div);
  const auto set = GetClientIdsSet(ignored_div->GetLayoutObject()->Id());
  EXPECT_FALSE(set.Contains(ignored_div->GetLayoutObject()->Id()));

  // Verify that elements that do not produce visual output are not in the set.
  auto* invisible_div =
      GetDocument().getElementById(AtomicString("invisible_div"));
  ASSERT_TRUE(invisible_div);
  EXPECT_FALSE(set.Contains(invisible_div->GetLayoutObject()->Id()));

  // Verify that elements that produce visual output are in the set.
  auto* visible_div = GetDocument().getElementById(AtomicString("visible_div"));
  ASSERT_TRUE(visible_div);
  EXPECT_TRUE(set.Contains(visible_div->GetLayoutObject()->Id()));
}

TEST_F(MediaVideoVisibilityTrackerTest, ClientIdsSetEndIndexEqualToStartIndex) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
  <style>
    body {
      margin: 0;
    }
    video {
      object-fit: fill;
      position: relative;
      width: 500px;
      height: 500px;
      top:0;
      left:0;
    }
    div {
      background-color: yellow;
      width: 50px;
      height: 50px;
      position: absolute;
      top: 0;
      left: 0;
    }
  </style>
  <video></video>
  <div id="target_div"></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  auto* target_div = GetDocument().getElementById(AtomicString("target_div"));
  ASSERT_TRUE(target_div);
  const auto set = GetClientIdsSet(target_div->GetLayoutObject()->Id());

  EXPECT_EQ(0u, set.size());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       ClientIdsSetBeginIndexGreaterThanEndIndex) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
  <style>
    body {
      margin: 0;
    }
    video {
      object-fit: fill;
      position: relative;
      width: 500px;
      height: 500px;
      top:0;
      left:0;
    }
    div {
      background-color: yellow;
      width: 50px;
      height: 50px;
      position: absolute;
      top: 0;
      left: 0;
    }
  </style>
  <video></video>
  <div></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  CreateAndAttachVideoVisibilityTracker(10000);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  const auto set = GetClientIdsSet(VideoElement()->GetLayoutObject()->Id());

  EXPECT_EQ(0u, set.size());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       ComputeVisibilityOnDemandReportsFalseWhenTrackerNotAttached) {
  auto* video = GetDocument().CreateRawElement(html_names::kVideoTag);
  GetDocument().body()->AppendChild(video);

  // Verify that `ReportVisibilityCb` does not run, when computing visibility on
  // demand, for a document's LocalFrameView in
  // `DocumentUpdateReason::kPaintClean` state.
  EXPECT_CALL(ReportVisibilityCb(), Run(_)).Times(0);

  // Create tracker and verify that it is not attached.
  auto* tracker = CreateTracker(10000);
  ASSERT_FALSE(TrackerAttached());

  // Create a `RequestVisibilityCallback` and verify that `MeetsVisibility`
  // returns false.
  RequestVisibilityCallback request_visibility_callback;
  tracker->RequestVisibility(request_visibility_callback.VisibilityCallback());
  request_visibility_callback.WaitUntilDone();
  EXPECT_FALSE(request_visibility_callback.MeetsVisibility());
}

TEST_F(MediaVideoVisibilityTrackerTest,
       ComputeVisibilityOnDemandReportsTrueWhenVideoMeetsVisibility) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));
  LoadMainResource(R"HTML(
    <style>
      body {
        margin: 0;
      }
      video {
        object-fit: fill;
        position: relative;
        width: 500px;
        height: 500px;
        top:0;
        left:0
      }
      div {
        background-color: blue;
        width: 100px;
        height: 100px;
        position: absolute;
        top: 0;
        left: 0;
      }
    </style>
    <video></video>
    <div></div>
  )HTML");
  EXPECT_CALL(ReportVisibilityCb(), Run(true));
  auto* tracker = CreateAndAttachVideoVisibilityTracker(10000);

  // Initially set the lifecycle state to a value <
  // DocumentUpdateReason::kPaintClean. The `RequestVisibilityCallback` should
  // run with the `false` cached value.
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  test::RunPendingTasks();
  task_environment().FastForwardUntilNoTasksRemain();

  // Create the `RequestVisibilityCallback`, and verify that: no visibility
  // computations are performed when the tracker takes the callback, and we
  // report that visibility is not met, since the document lifecycle state is
  // not `DocumentUpdateReason::kPaintClean`.
  RequestVisibilityCallback request_visibility_callback;
  tracker->RequestVisibility(request_visibilit
```