Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `browser_capture_media_stream_track_test.cc` immediately suggests this file contains tests for the `BrowserCaptureMediaStreamTrack` class. The "browser capture" part hints at its involvement in capturing media from the browser environment (like tabs or windows). The "test" suffix confirms it's a testing file.

2. **Understand the Test Framework:**  The includes reveal the use of Google Test (`gtest/gtest.h`). This tells us we'll see test cases defined using `TEST_F` and assertions like `EXPECT_TRUE`, `EXPECT_EQ`, etc.

3. **Examine Included Headers:**  These provide crucial context:
    * **Self-include:**  `browser_capture_media_stream_track.h` (implied by the `#include` of the `.cc` file) means we'll be testing the public interface of this class.
    * **`base/test/metrics/histogram_tester.h`:** Indicates testing of UMA (User Metrics Analysis) histograms, which are used to track usage and performance.
    * **`base/uuid.h`:**  Suggests the use of UUIDs, likely for identifying capture targets.
    * **`build/build_config.h`:**  Points to platform-specific behavior (we see an `#if !BUILDFLAG(IS_ANDROID)`).
    * **Blink-specific headers:**  These are the most important for understanding the functionality:
        * `web/web_heap.h`: Garbage collection in Blink.
        * `bindings/core/v8/...` and `bindings/modules/v8/...`: Interaction with JavaScript via V8. This is a strong indicator of its connection to web APIs. Specifically, `ScriptPromiseTester`, `V8TestingScope`, `V8ConstrainLongRange`, `MediaTrackConstraints` tell us we're dealing with asynchronous operations (Promises) and media constraints as defined in web standards.
        * `modules/mediastream/...`:  This is the core domain. `CropTarget`, `MediaStreamVideoTrack`, `MockMediaStreamVideoSource`, `SubCaptureTarget` are key classes. The "mock" hints at isolated testing.
        * `platform/mediastream/...`: Lower-level media stream components.
        * `platform/region_capture_crop_id.h`: More details about region capture.
        * `platform/testing/...`: Utilities for testing Blink internals.

4. **Analyze the Test Structure:**
    * **Namespaces:** The `blink` namespace and the anonymous namespace group related code.
    * **Helper Functions:** `MakeMockMediaStreamVideoSource` and `MakeTrack` are setup functions to create instances of the classes under test, often with mocked dependencies. This is a standard testing practice.
    * **Test Fixture:** `BrowserCaptureMediaStreamTrackTest` is a test fixture using `testing::Test` and `testing::WithParamInterface`. The parameterization with `SubCaptureTarget::Type` indicates that the same tests will be run for both `kCropTarget` and `kRestrictionTarget`. This helps in ensuring consistency across different target types.
    * **`ApplySubCaptureTarget` Function:** This method simulates calling the `cropTo` or `restrictTo` methods on the `BrowserCaptureMediaStreamTrack`, based on the parameterized `type_`.
    * **`CheckHistograms` Function:**  Verifies that the expected UMA histograms are recorded with the correct counts and values.
    * **`TearDown` Function:** Cleans up garbage collected objects after each test.
    * **Individual Tests (`TEST_P`):** Each test focuses on a specific aspect of the `BrowserCaptureMediaStreamTrack`'s behavior. The names of the tests are descriptive (e.g., `ApplySubCaptureTargetOnValidIdResultFirst`).

5. **Focus on Key Interactions:** The tests revolve around the `ApplySubCaptureTarget` method. We see mocking of `MockMediaStreamVideoSource` to control the behavior of the underlying media source. The tests check different scenarios:
    * Successful application of a sub-capture target.
    * Rejection due to errors from the browser process.
    * Rejection due to an invalid target.
    * Platform-specific behavior (Android).
    * Preservation of constraints when cloning the track.

6. **Connect to Web APIs:** Now we can explicitly link the code to web technologies:
    * **JavaScript:** The `cropTo()` and `restrictTo()` methods in the C++ code directly correspond to JavaScript methods available on `MediaStreamTrack` objects when dealing with browser capture. The `ScriptPromiseTester` confirms the asynchronous nature of these operations, aligning with how Promises work in JavaScript.
    * **HTML:**  While this specific test file doesn't directly interact with HTML parsing, the functionality it tests is crucial for features initiated from HTML. For example, a user might select a specific part of their screen to share via a `<button>` that triggers JavaScript calling `cropTo()` on a `MediaStreamTrack`.
    * **CSS:**  CSS doesn't directly trigger the logic in this file. However, the *effects* of region capture or element capture *could* be reflected in the visual layout and rendering, which CSS controls.

7. **Infer User Actions and Debugging:**  Consider how a developer might end up looking at this file:
    * A bug report about region capture or element capture not working correctly.
    * Investigating performance issues related to these features (the histogram tests are relevant here).
    * Understanding the implementation details of how `cropTo()` or `restrictTo()` work.

8. **Construct Examples and Scenarios:**  Based on the understanding of the code and its relation to web APIs, create concrete examples for each point in the prompt. Think about how a user would interact with the browser to trigger these features and the potential errors they might encounter.

9. **Review and Refine:**  Go through the analysis and ensure it's clear, accurate, and addresses all aspects of the prompt. Organize the information logically.

This structured approach, starting with the high-level purpose and progressively digging into the details, helps in comprehensively understanding the functionality and context of the given source code file.
This C++ source code file, `browser_capture_media_stream_track_test.cc`, contains **unit tests** for the `BrowserCaptureMediaStreamTrack` class within the Chromium Blink rendering engine.

Here's a breakdown of its functionality and its relationship to web technologies:

**Core Functionality Being Tested:**

The primary focus of these tests is to verify the behavior of `BrowserCaptureMediaStreamTrack`, particularly its ability to:

1. **Apply Sub-Capture Targets:** This involves using `cropTo()` and `restrictTo()` methods to define a specific region or element to be captured from a browser tab or window.
2. **Handle Asynchronous Operations:** The `cropTo()` and `restrictTo()` methods likely involve communication with the browser process, making them asynchronous. The tests use `ScriptPromiseTester` to handle promises returned by these methods.
3. **Track Metrics:** The tests use `HistogramTester` to ensure that User Metrics Analysis (UMA) histograms are correctly recorded for latency and success/failure of sub-capture operations.
4. **Handle Different Outcomes:** The tests cover scenarios where applying a sub-capture target succeeds, fails due to various reasons (generic error, invalid target), or is not supported on the current platform (Android).
5. **Preserve Constraints:** The tests check if cloning a `BrowserCaptureMediaStreamTrack` correctly preserves the applied media constraints.

**Relationship to JavaScript, HTML, and CSS:**

`BrowserCaptureMediaStreamTrack` is a core component in the implementation of **browser media capture**, which is exposed to web developers through JavaScript APIs.

* **JavaScript:**
    * **`MediaStreamTrack` API:**  `BrowserCaptureMediaStreamTrack` is a specific type of `MediaStreamTrack`, representing a video or audio track captured from the browser. JavaScript code can obtain instances of this track through APIs like `getUserMedia()` with the `displayMedia` option, or through the `getDisplayMedia()` API.
    * **`cropTo()` and `restrictTo()` methods:** The tests directly exercise the underlying implementation of the JavaScript `MediaStreamTrack.cropTo()` and `MediaStreamTrack.restrictTo()` methods. These methods allow web developers to programmatically control what part of the captured surface is included in the media stream.
    * **Promises:** The asynchronous nature of `cropTo()` and `restrictTo()` is reflected in their return values being JavaScript Promises. The tests use `ScriptPromiseTester` to simulate how JavaScript would interact with these promises.

    **Example:**

    ```javascript
    navigator.mediaDevices.getDisplayMedia({ video: true })
      .then(stream => {
        const track = stream.getVideoTracks()[0];
        // Assuming 'elementToCrop' is a DOM element
        track.cropTo({ element: elementToCrop })
          .then(() => {
            console.log("Cropping successful!");
          })
          .catch(error => {
            console.error("Cropping failed:", error);
          });
      });
    ```

* **HTML:**
    * **User Interface for Capture:** HTML elements like `<button>` can trigger JavaScript code that initiates the display media capture process. The `cropTo()` or `restrictTo()` methods might be called in response to user interactions with HTML elements.

    **Example:**

    ```html
    <button id="cropButton">Crop to Selected Area</button>
    <div id="targetArea" style="border: 1px solid blue; width: 200px; height: 150px;"></div>

    <script>
      const cropButton = document.getElementById('cropButton');
      const targetArea = document.getElementById('targetArea');

      cropButton.addEventListener('click', () => {
        navigator.mediaDevices.getDisplayMedia({ video: true })
          .then(stream => {
            const track = stream.getVideoTracks()[0];
            track.cropTo({ element: targetArea })
              .catch(error => console.error("Cropping failed:", error));
          });
      });
    </script>
    ```

* **CSS:**
    * **Styling Capture Targets:** While CSS doesn't directly control the `cropTo()` or `restrictTo()` functionality, it's used to style the HTML elements that might be targeted for capture or cropping (e.g., the `targetArea` in the HTML example).

**Logical Reasoning (Hypothetical Inputs and Outputs):**

Let's consider the `ApplySubCaptureTargetOnValidIdResultFirst` test:

* **Hypothetical Input:**
    * A `BrowserCaptureMediaStreamTrack` object is created.
    * A valid UUID (`valid_id`) representing a potential capture target is generated.
    * The `cropTo()` or `restrictTo()` method is called with this UUID.
    * The underlying media source successfully applies the sub-capture target and reports `kSuccess`.
    * The `OnSubCaptureTargetVersionObservedForTesting` method is called with the expected version.

* **Expected Output:**
    * The promise returned by `cropTo()` or `restrictTo()` is fulfilled (resolves successfully).
    * UMA histograms are recorded indicating a successful operation.

**User or Programming Common Usage Errors:**

1. **Providing an Invalid Target ID:**  A common user error or programming error would be to provide an ID that doesn't correspond to a valid, capturable surface. This would likely lead to the promise being rejected. The test `ApplySubCaptureTargetRejectsIfSourceReturnsNulloptForNextSubCaptureTargetVersion` simulates a scenario where the source can't find the target.

    **Example (JavaScript):**

    ```javascript
    track.cropTo({ element: document.getElementById('nonExistentElement') })
      .catch(error => console.error("Cropping failed:", error));
    ```

2. **Calling `cropTo()` or `restrictTo()` on a Track That Doesn't Support It:** Not all `MediaStreamTrack` objects support these methods. Attempting to call them on a track obtained from a user's camera, for example, would result in an error. While this specific test file focuses on browser capture tracks, it highlights the importance of checking track capabilities.

3. **Incorrectly Handling Promises:**  Forgetting to add `.then()` and `.catch()` to the promises returned by `cropTo()` or `restrictTo()` would lead to unhandled rejections if the operation fails.

**User Operations Leading to This Code (Debugging Clues):**

A developer might be looking at this test file when debugging issues related to:

1. **Region Capture (Tab/Window Cropping):**  A user reports that when they try to share a specific portion of their screen (e.g., using the `getDisplayMedia()` API with cropping), it's not working as expected. The developer might investigate the `cropTo()` functionality.
    * **User Steps:**
        1. User navigates to a website that uses the `getDisplayMedia()` API.
        2. User selects a browser tab or window to share.
        3. The website's JavaScript code attempts to apply a crop to the shared surface, potentially based on user interaction (e.g., drawing a rectangle).
        4. The cropping fails or behaves unexpectedly.

2. **Element Capture (Restricting Capture to a Specific Element):** A user might encounter issues when a website tries to only capture a specific DOM element. The developer might then investigate the `restrictTo()` functionality.
    * **User Steps:**
        1. User navigates to a website that uses the `getDisplayMedia()` API with element capture.
        2. User interacts with the website in a way that triggers the capture of a specific element.
        3. The capture includes more than just the intended element, or fails entirely.

3. **Performance Issues with Capture:**  If users experience lag or other performance problems during screen sharing with cropping or element capture, developers might look at the UMA histograms being tested here to understand the latency of these operations.

4. **Platform-Specific Bugs:** If a bug is reported specifically on non-Android platforms related to sub-capture, a developer might focus on the tests within the `#if !BUILDFLAG(IS_ANDROID)` block.

In essence, this test file provides a low-level verification of the core logic behind the JavaScript `cropTo()` and `restrictTo()` methods for browser-captured media streams. Developers would likely consult it when investigating issues or ensuring the correctness of these features.

### 提示词
```
这是目录为blink/renderer/modules/mediastream/browser_capture_media_stream_track_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/browser_capture_media_stream_track.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/uuid.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_constrain_long_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_constrainlongrange_long.h"
#include "third_party/blink/renderer/modules/mediastream/crop_target.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/sub_capture_target.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/region_capture_crop_id.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

using ::testing::_;
using ::testing::Args;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::Return;

std::unique_ptr<MockMediaStreamVideoSource> MakeMockMediaStreamVideoSource() {
  // TODO(crbug.com/1488083): Remove the NiceMock and explicitly expect
  // only truly expected calls.
  return base::WrapUnique(new ::testing::NiceMock<MockMediaStreamVideoSource>(
      media::VideoCaptureFormat(gfx::Size(640, 480), 30.0,
                                media::PIXEL_FORMAT_I420),
      true));
}

BrowserCaptureMediaStreamTrack* MakeTrack(
    V8TestingScope& v8_scope,
    std::unique_ptr<MockMediaStreamVideoSource> media_stream_video_source) {
  auto media_stream_video_track = std::make_unique<MediaStreamVideoTrack>(
      media_stream_video_source.get(),
      WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      /*enabled=*/true);

  MediaStreamSource* const source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeVideo, "name",
      /*remote=*/false, std::move(media_stream_video_source));

  MediaStreamComponent* const component =
      MakeGarbageCollected<MediaStreamComponentImpl>(
          "component_id", source, std::move(media_stream_video_track));

  return MakeGarbageCollected<BrowserCaptureMediaStreamTrack>(
      v8_scope.GetExecutionContext(), component,
      /*callback=*/base::DoNothing());
}

}  // namespace

class BrowserCaptureMediaStreamTrackTest
    : public testing::Test,
      public testing::WithParamInterface<SubCaptureTarget::Type> {
 public:
  BrowserCaptureMediaStreamTrackTest() : type_(GetParam()) {}
  ~BrowserCaptureMediaStreamTrackTest() override = default;

  ScriptPromise<IDLUndefined> ApplySubCaptureTarget(
      V8TestingScope& v8_scope,
      BrowserCaptureMediaStreamTrack& track,
      WTF::String id_string) {
    switch (type_) {
      case SubCaptureTarget::Type::kCropTarget:
        return track.cropTo(
            v8_scope.GetScriptState(),
            MakeGarbageCollected<CropTarget>(std::move(id_string)),
            v8_scope.GetExceptionState());
      case SubCaptureTarget::Type::kRestrictionTarget:
        return track.restrictTo(
            v8_scope.GetScriptState(),
            MakeGarbageCollected<RestrictionTarget>(std::move(id_string)),
            v8_scope.GetExceptionState());
    }
    NOTREACHED();
  }

  void CheckHistograms(
      int expected_count,
      BrowserCaptureMediaStreamTrack::ApplySubCaptureTargetResult
          expected_result) {
    std::string uma_latency_name;
    std::string uma_result_name;
    switch (type_) {
      case SubCaptureTarget::Type::kCropTarget:
        uma_latency_name = "Media.RegionCapture.CropTo.Latency";
        uma_result_name = "Media.RegionCapture.CropTo.Result2";
        break;
      case SubCaptureTarget::Type::kRestrictionTarget:
        uma_latency_name = "Media.ElementCapture.RestrictTo.Latency";
        uma_result_name = "Media.ElementCapture.RestrictTo.Result";
        break;
    }

    histogram_tester_.ExpectTotalCount(uma_result_name, expected_count);
    histogram_tester_.ExpectUniqueSample(uma_result_name, expected_result,
                                         expected_count);
    histogram_tester_.ExpectTotalCount(uma_latency_name, expected_count);
  }

  void TearDown() override { WebHeap::CollectAllGarbageForTesting(); }

 protected:
  test::TaskEnvironment task_environment_;
  const SubCaptureTarget::Type type_;
  base::HistogramTester histogram_tester_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
};

INSTANTIATE_TEST_SUITE_P(
    _,
    BrowserCaptureMediaStreamTrackTest,
    testing::Values(SubCaptureTarget::Type::kCropTarget,
                    SubCaptureTarget::Type::kRestrictionTarget));

#if !BUILDFLAG(IS_ANDROID)
TEST_P(BrowserCaptureMediaStreamTrackTest,
       ApplySubCaptureTargetOnValidIdResultFirst) {
  V8TestingScope v8_scope;

  const base::Uuid valid_id = base::Uuid::GenerateRandomV4();

  std::unique_ptr<MockMediaStreamVideoSource> media_stream_video_source =
      MakeMockMediaStreamVideoSource();

  EXPECT_CALL(*media_stream_video_source, GetNextSubCaptureTargetVersion)
      .Times(1)
      .WillOnce(Return(std::optional<uint32_t>(1)));

  EXPECT_CALL(*media_stream_video_source,
              ApplySubCaptureTarget(type_, GUIDToToken(valid_id), _, _))
      .Times(1)
      .WillOnce(::testing::WithArg<3>(::testing::Invoke(
          [](base::OnceCallback<void(media::mojom::ApplySubCaptureTargetResult)>
                 cb) {
            std::move(cb).Run(
                media::mojom::ApplySubCaptureTargetResult::kSuccess);
          })));

  BrowserCaptureMediaStreamTrack* const track =
      MakeTrack(v8_scope, std::move(media_stream_video_source));

  const auto promise = ApplySubCaptureTarget(
      v8_scope, *track, WTF::String(valid_id.AsLowercaseString()));

  track->OnSubCaptureTargetVersionObservedForTesting(
      /*sub_capture_target_version=*/1);

  ScriptPromiseTester script_promise_tester(v8_scope.GetScriptState(), promise);
  script_promise_tester.WaitUntilSettled();
  EXPECT_TRUE(script_promise_tester.IsFulfilled());
  CheckHistograms(
      /*expected_count=*/1,
      BrowserCaptureMediaStreamTrack::ApplySubCaptureTargetResult::kOk);
}

TEST_P(BrowserCaptureMediaStreamTrackTest,
       ApplySubCaptureTargetRejectsIfResultFromBrowserProcessIsNotSuccess) {
  V8TestingScope v8_scope;

  const base::Uuid valid_id = base::Uuid::GenerateRandomV4();

  std::unique_ptr<MockMediaStreamVideoSource> media_stream_video_source =
      MakeMockMediaStreamVideoSource();

  EXPECT_CALL(*media_stream_video_source, GetNextSubCaptureTargetVersion)
      .Times(1)
      .WillOnce(Return(std::optional<uint32_t>(1)));

  EXPECT_CALL(*media_stream_video_source,
              ApplySubCaptureTarget(type_, GUIDToToken(valid_id), _, _))
      .Times(1)
      .WillOnce(::testing::WithArg<3>(::testing::Invoke(
          [](base::OnceCallback<void(media::mojom::ApplySubCaptureTargetResult)>
                 cb) {
            std::move(cb).Run(
                media::mojom::ApplySubCaptureTargetResult::kErrorGeneric);
          })));

  BrowserCaptureMediaStreamTrack* const track =
      MakeTrack(v8_scope, std::move(media_stream_video_source));

  const auto promise = ApplySubCaptureTarget(
      v8_scope, *track, WTF::String(valid_id.AsLowercaseString()));

  track->OnSubCaptureTargetVersionObservedForTesting(
      /*sub_capture_target_version=*/1);

  ScriptPromiseTester script_promise_tester(v8_scope.GetScriptState(), promise);
  script_promise_tester.WaitUntilSettled();
  EXPECT_TRUE(script_promise_tester.IsRejected());
  CheckHistograms(
      /*expected_count=*/1,
      BrowserCaptureMediaStreamTrack::ApplySubCaptureTargetResult::
          kRejectedWithErrorGeneric);
}

TEST_P(
    BrowserCaptureMediaStreamTrackTest,
    ApplySubCaptureTargetRejectsIfSourceReturnsNulloptForNextSubCaptureTargetVersion) {
  V8TestingScope v8_scope;

  const base::Uuid valid_id = base::Uuid::GenerateRandomV4();

  std::unique_ptr<MockMediaStreamVideoSource> media_stream_video_source =
      MakeMockMediaStreamVideoSource();

  EXPECT_CALL(*media_stream_video_source, GetNextSubCaptureTargetVersion)
      .Times(1)
      .WillOnce(Return(std::nullopt));

  EXPECT_CALL(*media_stream_video_source,
              ApplySubCaptureTarget(type_, GUIDToToken(valid_id), _, _))
      .Times(0);

  BrowserCaptureMediaStreamTrack* const track =
      MakeTrack(v8_scope, std::move(media_stream_video_source));

  const auto promise = ApplySubCaptureTarget(
      v8_scope, *track, WTF::String(valid_id.AsLowercaseString()));

  ScriptPromiseTester script_promise_tester(v8_scope.GetScriptState(), promise);
  script_promise_tester.WaitUntilSettled();
  EXPECT_TRUE(script_promise_tester.IsRejected());
  CheckHistograms(
      /*expected_count=*/1, BrowserCaptureMediaStreamTrack::
                                ApplySubCaptureTargetResult::kInvalidTarget);
}

#else

TEST_P(BrowserCaptureMediaStreamTrackTest,
       ApplySubCaptureTargetFailsOnAndroid) {
  V8TestingScope v8_scope;

  const base::Uuid valid_id = base::Uuid::GenerateRandomV4();

  std::unique_ptr<MockMediaStreamVideoSource> media_stream_video_source =
      MakeMockMediaStreamVideoSource();

  EXPECT_CALL(*media_stream_video_source, ApplySubCaptureTarget(type_, _, _, _))
      .Times(0);

  BrowserCaptureMediaStreamTrack* const track =
      MakeTrack(v8_scope, std::move(media_stream_video_source));

  const auto promise = ApplySubCaptureTarget(
      v8_scope, *track, WTF::String(valid_id.AsLowercaseString()));

  ScriptPromiseTester script_promise_tester(v8_scope.GetScriptState(), promise);
  script_promise_tester.WaitUntilSettled();
  EXPECT_TRUE(script_promise_tester.IsRejected());
  CheckHistograms(
      /*expected_count=*/1,
      BrowserCaptureMediaStreamTrack::ApplySubCaptureTargetResult::
          kUnsupportedPlatform);
}
#endif

TEST_P(BrowserCaptureMediaStreamTrackTest, CloningPreservesConstraints) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockMediaStreamVideoSource> media_stream_video_source =
      MakeMockMediaStreamVideoSource();

  EXPECT_CALL(*media_stream_video_source, ApplySubCaptureTarget(type_, _, _, _))
      .Times(0);

  BrowserCaptureMediaStreamTrack* const track =
      MakeTrack(v8_scope, std::move(media_stream_video_source));

  MediaConstraints constraints;
  MediaTrackConstraintSetPlatform basic;
  basic.width.SetMax(240);
  constraints.Initialize(basic, Vector<MediaTrackConstraintSetPlatform>());
  track->SetInitialConstraints(constraints);

  MediaStreamTrack* clone = track->clone(v8_scope.GetExecutionContext());
  MediaTrackConstraints* clone_constraints = clone->getConstraints();
  EXPECT_TRUE(clone_constraints->hasWidth());
  EXPECT_EQ(clone_constraints->width()->GetAsConstrainLongRange()->max(), 240);
}

}  // namespace blink
```