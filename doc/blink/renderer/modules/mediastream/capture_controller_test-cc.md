Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ code for its functionality within the Chromium Blink engine. This includes:

* **Core Function:** What is this code testing?
* **Relationships:** How does it interact with JavaScript, HTML, and CSS?
* **Logic:** Can we infer the internal logic and predict inputs and outputs?
* **Error Handling:** What common user or programming errors does it test for?
* **Debugging Clues:** How does a user end up interacting with this code, providing debugging information?
* **Summary:** A concise overview of its purpose.

**2. Initial Code Scan (Keywords and Structure):**

I started by scanning the `#include` statements. These provide immediate clues:

* `"capture_controller.h"`:  This is the central piece of code being tested.
* `"testing/gtest/include/gtest/gtest.h"`: This indicates unit tests using Google Test.
* `"public/mojom/mediastream/media_stream.mojom-blink.h"`:  Deals with inter-process communication (IPC) related to media streams. "mojom" is a strong signal for this.
* `"bindings/core/v8/...` and `"bindings/modules/v8/...`: These headers suggest interaction with the V8 JavaScript engine.
* `"core/dom/...` and `"core/events/...`:  Relates to the Document Object Model and event handling.
* `"core/html/...`:  Involves HTML elements.
* `"modules/mediastream/...`: Indicates it's part of the media stream module.

The code also contains a lot of `TEST_F` macros, confirming these are unit tests. The class names like `CaptureControllerGetSupportedZoomLevelsTest`, `CaptureControllerGetZoomLevelTest`, `CaptureControllerSetZoomLevelTest`, and `CaptureControllerScrollTest` are very descriptive and hint at the specific functionalities being tested.

**3. Identifying Key Classes and Concepts:**

Based on the includes and test names, the key class is `CaptureController`. The tests revolve around its methods related to:

* **Zoom Levels:** Getting supported levels, getting the current level, and setting the level.
* **Scroll Control:**  Sending wheel events.
* **Media Streams:** Specifically video tracks (`MediaStreamVideoTrack`).
* **Display Capture:**  Capturing browser tabs, windows, and monitors (`SurfaceType`).
* **Events:** `capturedzoomlevelchange`.

**4. Analyzing Individual Tests (Inferring Functionality):**

I examined the individual test cases to understand the specific scenarios being tested. For example:

* **`ReturnsMonotonicallyIncreasingSequence`:**  This clearly tests the `getSupportedZoomLevels()` method.
* **`GetZoomLevelFailsIfCaptureControllerNotBound`:** This suggests `CaptureController` has a "bound" state, likely tied to the start of a capture session.
* **`SetZoomLevelSuccessIfSupportedValue`:** This confirms that `setZoomLevel` accepts only specific values. The use of `DispatcherHost()` points to communication with a browser process component.

By analyzing several tests, patterns emerged, revealing how `CaptureController` works and what conditions lead to errors.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The presence of V8 binding headers (`bindings/core/v8/...`) and the use of `ScriptPromiseTester` clearly indicate interaction with JavaScript. The test involving `addEventListener` for `capturedzoomlevelchange` directly relates to JavaScript event handling.

HTML comes into play because the capture process often targets HTML content. The tests use `HTMLDivElement` and `HTMLElement`, showing that the capture mechanism interacts with the DOM.

CSS is less directly tested in this file, but it's indirectly related. The visual content being captured is styled by CSS. While the tests don't manipulate CSS directly, the captured output *reflects* the applied CSS.

**6. Inferring Logic, Inputs, and Outputs:**

Based on the test names and assertions, I could start inferring the logic:

* `CaptureController` likely holds the current zoom level.
* Setting the zoom level involves communication with a browser process component.
* There's validation of zoom level values against the supported levels.
* Scroll events are sent to the browser process.

For inputs and outputs, I focused on the method calls within the tests. For example, `setZoomLevel(v8_scope.GetScriptState(), 125)` clearly takes a zoom level as input and returns a Promise (as indicated by `ScriptPromiseTester`). The success or failure of the Promise is the output.

**7. Identifying User/Programming Errors:**

The tests that check for exceptions (`DOMExceptionCode`) highlight common errors:

* Calling methods before the `CaptureController` is properly initialized/bound.
* Attempting to set invalid zoom levels.
* Trying to perform actions on a stopped video track.
* Trying to control capture for non-tab sources (windows, monitors).

**8. Tracing User Operations (Debugging Clues):**

I considered how a user's actions in a browser could lead to the execution of this code. The key is the `getDisplayMedia()` JavaScript API. When a website calls `getDisplayMedia()`, and the user selects a browser tab for capture, the `CaptureController` is likely instantiated. Actions like zooming and scrolling within the captured tab would then trigger the methods being tested.

**9. Structuring the Answer:**

Finally, I organized the information into the requested categories:

* **Functionality:**  A high-level summary of what the file does.
* **Relationship to Web Technologies:**  Specific examples of interaction with JavaScript, HTML, and CSS.
* **Logic Inference:**  Hypothetical input and output examples based on the tests.
* **User/Programming Errors:** Concrete examples derived from the exception tests.
* **User Operation to Reach Code:**  A step-by-step scenario involving `getDisplayMedia()`.
* **Summary:** A concise wrap-up of the file's purpose.

**Self-Correction/Refinement:**

Initially, I might have focused too much on the low-level details of the C++ code. However, the prompt specifically asked about the *functionality* and its relation to web technologies. Therefore, I shifted the focus to the higher-level purpose of the tests and how they relate to user interactions and web APIs. I also ensured that the examples were concrete and easy to understand, rather than just listing technical terms.
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/capture_controller.h"

#include <tuple>

#include "base/run_loop.h"
#include "base/test/gmock_callback_support.h"
#include "base/unguessable_token.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_wheel_event_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_captured_wheel_action.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/mediastream/browser_capture_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/mock_mojo_media_stream_dispatcher_host.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

using SurfaceType = ::media::mojom::DisplayCaptureSurfaceType;

using ::base::test::RunOnceCallback;
using ::base::test::RunOnceCallbackRepeatedly;
using ::testing::_;
using ::testing::Combine;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::SaveArgPointee;
using ::testing::StrictMock;
using ::testing::Values;
using ::testing::WithParamInterface;
using CscResult = ::blink::mojom::blink::CapturedSurfaceControlResult;

enum class ScrollDirection {
  kNone,
  kForwards,
  kBackwards,
};

class MockEventListener : public NativeEventListener {
 public:
  MOCK_METHOD(void, Invoke, (ExecutionContext*, Event*));
};

// TODO(crbug.com/1505223): Avoid this helper's duplication throughout Blink.
bool IsDOMException(ScriptState* script_state,
                    const ScriptValue& value,
                    DOMExceptionCode code) {
  DOMException* const dom_exception =
      V8DOMException::ToWrappable(script_state->GetIsolate(), value.V8Value());
  return dom_exception && dom_exception->name() == DOMException(code).name();
}

bool IsDOMException(V8TestingScope& v8_scope,
                    const ScriptValue& value,
                    DOMExceptionCode code) {
  return IsDOMException(v8_scope.GetScriptState(), value, code);
}

// Note that we don't actually care what the message is. We use this as a way
// to sanity-check the tests themselves against false-positives through
// failures on different code paths that yield the same DOMException.
String GetDOMExceptionMessage(ScriptState* script_state,
                              const ScriptValue& value) {
  DOMException* const dom_exception =
      V8DOMException::ToWrappable(script_state->GetIsolate(), value.V8Value());
  CHECK(dom_exception) << "Malformed test.";
  return dom_exception->message();
}
String GetDOMExceptionMessage(V8TestingScope& v8_scope,
                              const ScriptValue& value) {
  return GetDOMExceptionMessage(v8_scope.GetScriptState(), value);
}

// Extract the MediaStreamVideoTrack which the test has previously injected
// into the track. CHECKs and casts used here are valid because this is a
// controlled test environment.
MediaStreamVideoTrack* GetMediaStreamVideoTrack(MediaStreamTrack* track) {
  MediaStreamComponent* const component = track->Component();
  CHECK(component);
  return MediaStreamVideoTrack::From(component);
}

MediaStreamTrack* MakeTrack(
    ExecutionContext* execution_context,
    SurfaceType display_surface,
    int initial_zoom_level = CaptureController::getSupportedZoomLevels()[0],
    bool use_session_id = true) {
  std::unique_ptr<MockMediaStreamVideoSource> media_stream_video_source =
      base::WrapUnique(new ::testing::NiceMock<MockMediaStreamVideoSource>(
          media::VideoCaptureFormat(gfx::Size(640, 480), 30.0,
                                    media::PIXEL_FORMAT_I420),
          true));

  // Set the reported SurfaceType.
  MediaStreamDevice device = media_stream_video_source->device();
  device.display_media_info = media::mojom::DisplayMediaInformation::New(
      display_surface,
      /*logical_surface=*/true, media::mojom::CursorCaptureType::NEVER,
      /*capture_handle=*/nullptr, initial_zoom_level);
  if (use_session_id) {
    device.set_session_id(base::UnguessableToken::Create());
  }
  media_stream_video_source->SetDevice(device);

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

  switch (display_surface) {
    case SurfaceType::BROWSER:
      return MakeGarbageCollected<BrowserCaptureMediaStreamTrack>(
          execution_context, component,
          /*callback=*/base::DoNothing());
    case SurfaceType::WINDOW:
    case SurfaceType::MONITOR:
      return MakeGarbageCollected<MediaStreamTrackImpl>(
          execution_context, component,
          /*callback=*/base::DoNothing());
  }
  NOTREACHED();
}

MediaStreamTrack* MakeTrack(
    V8TestingScope& testing_scope,
    SurfaceType display_surface,
    int initial_zoom_level = CaptureController::getSupportedZoomLevels()[0],
    bool use_session_id = true) {
  return MakeTrack(testing_scope.GetExecutionContext(), display_surface,
                   initial_zoom_level, use_session_id);
}

void SimulateFrameArrival(MediaStreamTrack* track,
                          gfx::Size frame_size = gfx::Size(1000, 1000)) {
  GetMediaStreamVideoTrack(track)->SetTargetSize(frame_size.width(),
                                                 frame_size.height());
}

}  // namespace

class CaptureControllerTestSupport {
 protected:
  virtual ~CaptureControllerTestSupport() = default;

  MockMojoMediaStreamDispatcherHost& DispatcherHost() {
    return mock_dispatcher_host_;
  }

  CaptureController* MakeController(ExecutionContext* execution_context) {
    auto* controller =
        MakeGarbageCollected<CaptureController>(execution_context);
    controller->SetMediaStreamDispatcherHostForTesting(
        mock_dispatcher_host_.CreatePendingRemoteAndBind());
    return controller;
  }

 private:
  MockMojoMediaStreamDispatcherHost mock_dispatcher_host_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
};

class CaptureControllerBaseTest : public testing::Test,
                                  public CaptureControllerTestSupport {
 public:
  ~CaptureControllerBaseTest() override = default;

 private:
  test::TaskEnvironment task_environment_;
};

// Test suite for CaptureController functionality from the Captured Surface
// Control spec, focusing on reading the supported zoom levels.
class CaptureControllerGetSupportedZoomLevelsTest
    : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerGetSupportedZoomLevelsTest() override = default;
};

TEST_F(CaptureControllerGetSupportedZoomLevelsTest,
       ReturnsMonotonicallyIncreasingSequence) {
  V8TestingScope v8_scope;
  const Vector<int> supported_levels =
      CaptureController::getSupportedZoomLevels();
  ASSERT_GE(supported_levels.size(), 2u);  // Test holds vacuously otherwise.
  for (wtf_size_t i = 1; i < supported_levels.size(); ++i) {
    EXPECT_LT(supported_levels[i - 1], supported_levels[i]);
  }
}

// Test suite for CaptureController functionality from the
// Captured Surface Control spec, focusing on GetZoomLevel.
class CaptureControllerGetZoomLevelTest : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerGetZoomLevelTest() override = default;
};

TEST_F(CaptureControllerGetZoomLevelTest,
       GetZoomLevelFailsIfCaptureControllerNotBound) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  // Test avoids calling CaptureController::SetIsBound().

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(),
            "getDisplayMedia() not called yet.");
}

TEST_F(CaptureControllerGetZoomLevelTest,
       GetZoomLevelFailsIfCaptureControllerBoundButNoVideoTrack) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  // Test avoids calling CaptureController::SetVideoTrack().

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(),
            "Capture-session not started.");
}

TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelFailsIfVideoTrackEnded) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  track->stopTrack(v8_scope.GetExecutionContext());  // Ends the track.

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(), "Video track ended.");
}

TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelSuccessInitialZoomLevel) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::BROWSER,
      /*initial_zoom_level=*/CaptureController::getSupportedZoomLevels()[1]);
  controller->SetVideoTrack(track, "descriptor");

  int zoom_level = controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(zoom_level, CaptureController::getSupportedZoomLevels()[1]);
}

TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelSuccessZoomLevelUpdate) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::BROWSER,
      /*initial_zoom_level=*/CaptureController::getSupportedZoomLevels()[0]);
  controller->SetVideoTrack(track, "descriptor");

  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);

  int zoom_level = controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(zoom_level, CaptureController::getSupportedZoomLevels()[1]);
}

// Note that the setup differs from that of GetZoomLevelSuccessInitialZoomLevel
// only in the SurfaceType provided to MakeTrack().
TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelFailsIfCapturingWindow) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::WINDOW,
      /*initial_zoom_level=*/CaptureController::getSupportedZoomLevels()[1]);
  controller->SetVideoTrack(track, "descriptor");

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kNotSupportedError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(),
            "Action only supported for tab-capture.");
}

// Note that the setup differs from that of GetZoomLevelSuccessInitialZoomLevel
// only in the SurfaceType provided to MakeTrack().
TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelFailsIfCapturingMonitor) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::MONITOR,
      /*initial_zoom_level=*/CaptureController::getSupportedZoomLevels()[1]);
  controller->SetVideoTrack(track, "descriptor");

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kNotSupportedError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(),
            "Action only supported for tab-capture.");
}

// Test suite for CaptureController functionality from the Captured Surface
// Control spec, focusing on OnCapturedZoomLevelChange events.
class CaptureControllerOnCapturedZoomLevelChangeTest
    : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerOnCapturedZoomLevelChangeTest() override = default;
};

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest, NoEventOnInit) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());

  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(0);
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);

  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
}

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest,
       EventWhenDifferentFromInitValue) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(1);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);
}

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest,
       NoEventWhenSameAsInitValue) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(0);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[0]);
}

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest,
       EventWhenDifferentFromPreviousUpdate) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(1);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);
  Mock::VerifyAndClearExpectations(event_listener);
  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(1);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[0]);
}

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest,
       EventWhenSameAsPreviousUpdate) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(1);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);
  Mock::VerifyAndClearExpectations(event_listener);
  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(0);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);
}

// Test suite for CaptureController functionality from the
// Captured Surface Control spec, focusing on SetZoomLevel.
class CaptureControllerSetZoomLevelTest : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerSetZoomLevelTest() override = default;
};

TEST_F(CaptureControllerSetZoomLevelTest,
       SetZoomLevelFailsIfCaptureControllerNotBound) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  // Test avoids calling CaptureController::SetIsBound().

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "getDisplayMedia() not called yet.");
}

TEST_F(CaptureControllerSetZoomLevelTest,
       SetZoomLevelFailsIfCaptureControllerBoundButNoVideoTrack) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  // Test avoids calling CaptureController::SetVideoTrack().

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Capture-session not started.");
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfVideoTrackEnded) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  track->stopTrack(v8_scope.GetExecutionContext());  // Ends the track.

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Video track ended.");
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelSuccessIfSupportedValue) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  const Vector<int> supported_levels =
      CaptureController::getSupportedZoomLevels();
  for (int zoom_level : supported_levels) {
    EXPECT_CALL(DispatcherHost(), SetZoomLevel(_, zoom_level, _))
        .WillOnce(RunOnceCallback<2>(CscResult::kSuccess));
    const auto promise =
        controller->setZoomLevel(v8_scope.GetScriptState(), zoom_level);

    ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
    promise_tester.WaitUntilSettled();
    EXPECT_TRUE(promise_tester.IsFulfilled());
  }
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfLevelTooLow) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise = controller->setZoomLevel(
      v8_scope.GetScriptState(),
      controller->getSupportedZoomLevels().front() - 1);
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Only values returned by getSupportedZoomLevels() are valid.");
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfLevelTooHigh) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise =
      controller->setZoomLevel(v8_scope.GetScriptState(),
                               controller->getSupportedZoomLevels().back() + 1);
### 提示词
```
这是目录为blink/renderer/modules/mediastream/capture_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/capture_controller.h"

#include <tuple>

#include "base/run_loop.h"
#include "base/test/gmock_callback_support.h"
#include "base/unguessable_token.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_wheel_event_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_captured_wheel_action.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/mediastream/browser_capture_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/mock_mojo_media_stream_dispatcher_host.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

using SurfaceType = ::media::mojom::DisplayCaptureSurfaceType;

using ::base::test::RunOnceCallback;
using ::base::test::RunOnceCallbackRepeatedly;
using ::testing::_;
using ::testing::Combine;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::SaveArgPointee;
using ::testing::StrictMock;
using ::testing::Values;
using ::testing::WithParamInterface;
using CscResult = ::blink::mojom::blink::CapturedSurfaceControlResult;

enum class ScrollDirection {
  kNone,
  kForwards,
  kBackwards,
};

class MockEventListener : public NativeEventListener {
 public:
  MOCK_METHOD(void, Invoke, (ExecutionContext*, Event*));
};

// TODO(crbug.com/1505223): Avoid this helper's duplication throughout Blink.
bool IsDOMException(ScriptState* script_state,
                    const ScriptValue& value,
                    DOMExceptionCode code) {
  DOMException* const dom_exception =
      V8DOMException::ToWrappable(script_state->GetIsolate(), value.V8Value());
  return dom_exception && dom_exception->name() == DOMException(code).name();
}

bool IsDOMException(V8TestingScope& v8_scope,
                    const ScriptValue& value,
                    DOMExceptionCode code) {
  return IsDOMException(v8_scope.GetScriptState(), value, code);
}

// Note that we don't actually care what the message is. We use this as a way
// to sanity-check the tests themselves against false-positives through
// failures on different code paths that yield the same DOMException.
String GetDOMExceptionMessage(ScriptState* script_state,
                              const ScriptValue& value) {
  DOMException* const dom_exception =
      V8DOMException::ToWrappable(script_state->GetIsolate(), value.V8Value());
  CHECK(dom_exception) << "Malformed test.";
  return dom_exception->message();
}
String GetDOMExceptionMessage(V8TestingScope& v8_scope,
                              const ScriptValue& value) {
  return GetDOMExceptionMessage(v8_scope.GetScriptState(), value);
}

// Extract the MediaStreamVideoTrack which the test has previously injected
// into the track. CHECKs and casts used here are valid because this is a
// controlled test environment.
MediaStreamVideoTrack* GetMediaStreamVideoTrack(MediaStreamTrack* track) {
  MediaStreamComponent* const component = track->Component();
  CHECK(component);
  return MediaStreamVideoTrack::From(component);
}

MediaStreamTrack* MakeTrack(
    ExecutionContext* execution_context,
    SurfaceType display_surface,
    int initial_zoom_level = CaptureController::getSupportedZoomLevels()[0],
    bool use_session_id = true) {
  std::unique_ptr<MockMediaStreamVideoSource> media_stream_video_source =
      base::WrapUnique(new ::testing::NiceMock<MockMediaStreamVideoSource>(
          media::VideoCaptureFormat(gfx::Size(640, 480), 30.0,
                                    media::PIXEL_FORMAT_I420),
          true));

  // Set the reported SurfaceType.
  MediaStreamDevice device = media_stream_video_source->device();
  device.display_media_info = media::mojom::DisplayMediaInformation::New(
      display_surface,
      /*logical_surface=*/true, media::mojom::CursorCaptureType::NEVER,
      /*capture_handle=*/nullptr, initial_zoom_level);
  if (use_session_id) {
    device.set_session_id(base::UnguessableToken::Create());
  }
  media_stream_video_source->SetDevice(device);

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

  switch (display_surface) {
    case SurfaceType::BROWSER:
      return MakeGarbageCollected<BrowserCaptureMediaStreamTrack>(
          execution_context, component,
          /*callback=*/base::DoNothing());
    case SurfaceType::WINDOW:
    case SurfaceType::MONITOR:
      return MakeGarbageCollected<MediaStreamTrackImpl>(
          execution_context, component,
          /*callback=*/base::DoNothing());
  }
  NOTREACHED();
}

MediaStreamTrack* MakeTrack(
    V8TestingScope& testing_scope,
    SurfaceType display_surface,
    int initial_zoom_level = CaptureController::getSupportedZoomLevels()[0],
    bool use_session_id = true) {
  return MakeTrack(testing_scope.GetExecutionContext(), display_surface,
                   initial_zoom_level, use_session_id);
}

void SimulateFrameArrival(MediaStreamTrack* track,
                          gfx::Size frame_size = gfx::Size(1000, 1000)) {
  GetMediaStreamVideoTrack(track)->SetTargetSize(frame_size.width(),
                                                 frame_size.height());
}

}  // namespace

class CaptureControllerTestSupport {
 protected:
  virtual ~CaptureControllerTestSupport() = default;

  MockMojoMediaStreamDispatcherHost& DispatcherHost() {
    return mock_dispatcher_host_;
  }

  CaptureController* MakeController(ExecutionContext* execution_context) {
    auto* controller =
        MakeGarbageCollected<CaptureController>(execution_context);
    controller->SetMediaStreamDispatcherHostForTesting(
        mock_dispatcher_host_.CreatePendingRemoteAndBind());
    return controller;
  }

 private:
  MockMojoMediaStreamDispatcherHost mock_dispatcher_host_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
};

class CaptureControllerBaseTest : public testing::Test,
                                  public CaptureControllerTestSupport {
 public:
  ~CaptureControllerBaseTest() override = default;

 private:
  test::TaskEnvironment task_environment_;
};

// Test suite for CaptureController functionality from the Captured Surface
// Control spec, focusing on reading the supported zoom levels.
class CaptureControllerGetSupportedZoomLevelsTest
    : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerGetSupportedZoomLevelsTest() override = default;
};

TEST_F(CaptureControllerGetSupportedZoomLevelsTest,
       ReturnsMonotonicallyIncreasingSequence) {
  V8TestingScope v8_scope;
  const Vector<int> supported_levels =
      CaptureController::getSupportedZoomLevels();
  ASSERT_GE(supported_levels.size(), 2u);  // Test holds vacuously otherwise.
  for (wtf_size_t i = 1; i < supported_levels.size(); ++i) {
    EXPECT_LT(supported_levels[i - 1], supported_levels[i]);
  }
}

// Test suite for CaptureController functionality from the
// Captured Surface Control spec, focusing on GetZoomLevel.
class CaptureControllerGetZoomLevelTest : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerGetZoomLevelTest() override = default;
};

TEST_F(CaptureControllerGetZoomLevelTest,
       GetZoomLevelFailsIfCaptureControllerNotBound) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  // Test avoids calling CaptureController::SetIsBound().

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(),
            "getDisplayMedia() not called yet.");
}

TEST_F(CaptureControllerGetZoomLevelTest,
       GetZoomLevelFailsIfCaptureControllerBoundButNoVideoTrack) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  // Test avoids calling CaptureController::SetVideoTrack().

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(),
            "Capture-session not started.");
}

TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelFailsIfVideoTrackEnded) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  track->stopTrack(v8_scope.GetExecutionContext());  // Ends the track.

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(), "Video track ended.");
}

TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelSuccessInitialZoomLevel) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::BROWSER,
      /*initial_zoom_level=*/CaptureController::getSupportedZoomLevels()[1]);
  controller->SetVideoTrack(track, "descriptor");

  int zoom_level = controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(zoom_level, CaptureController::getSupportedZoomLevels()[1]);
}

TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelSuccessZoomLevelUpdate) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::BROWSER,
      /*initial_zoom_level=*/CaptureController::getSupportedZoomLevels()[0]);
  controller->SetVideoTrack(track, "descriptor");

  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);

  int zoom_level = controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(zoom_level, CaptureController::getSupportedZoomLevels()[1]);
}

// Note that the setup differs from that of GetZoomLevelSuccessInitialZoomLevel
// only in the SurfaceType provided to MakeTrack().
TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelFailsIfCapturingWindow) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::WINDOW,
      /*initial_zoom_level=*/CaptureController::getSupportedZoomLevels()[1]);
  controller->SetVideoTrack(track, "descriptor");

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kNotSupportedError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(),
            "Action only supported for tab-capture.");
}

// Note that the setup differs from that of GetZoomLevelSuccessInitialZoomLevel
// only in the SurfaceType provided to MakeTrack().
TEST_F(CaptureControllerGetZoomLevelTest, GetZoomLevelFailsIfCapturingMonitor) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::MONITOR,
      /*initial_zoom_level=*/CaptureController::getSupportedZoomLevels()[1]);
  controller->SetVideoTrack(track, "descriptor");

  controller->getZoomLevel(v8_scope.GetExceptionState());
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(v8_scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kNotSupportedError);

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(v8_scope.GetExceptionState().Message(),
            "Action only supported for tab-capture.");
}

// Test suite for CaptureController functionality from the Captured Surface
// Control spec, focusing on OnCapturedZoomLevelChange events.
class CaptureControllerOnCapturedZoomLevelChangeTest
    : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerOnCapturedZoomLevelChangeTest() override = default;
};

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest, NoEventOnInit) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());

  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(0);
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);

  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
}

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest,
       EventWhenDifferentFromInitValue) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(1);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);
}

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest,
       NoEventWhenSameAsInitValue) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(0);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[0]);
}

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest,
       EventWhenDifferentFromPreviousUpdate) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(1);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);
  Mock::VerifyAndClearExpectations(event_listener);
  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(1);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[0]);
}

TEST_F(CaptureControllerOnCapturedZoomLevelChangeTest,
       EventWhenSameAsPreviousUpdate) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  StrictMock<MockEventListener>* event_listener =
      MakeGarbageCollected<StrictMock<MockEventListener>>();
  controller->addEventListener(event_type_names::kCapturedzoomlevelchange,
                               event_listener);
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(1);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);
  Mock::VerifyAndClearExpectations(event_listener);
  EXPECT_CALL(*event_listener, Invoke(_, _)).Times(0);
  track->Component()->Source()->OnZoomLevelChange(
      MediaStreamDevice(), CaptureController::getSupportedZoomLevels()[1]);
}

// Test suite for CaptureController functionality from the
// Captured Surface Control spec, focusing on SetZoomLevel.
class CaptureControllerSetZoomLevelTest : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerSetZoomLevelTest() override = default;
};

TEST_F(CaptureControllerSetZoomLevelTest,
       SetZoomLevelFailsIfCaptureControllerNotBound) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  // Test avoids calling CaptureController::SetIsBound().

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "getDisplayMedia() not called yet.");
}

TEST_F(CaptureControllerSetZoomLevelTest,
       SetZoomLevelFailsIfCaptureControllerBoundButNoVideoTrack) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  // Test avoids calling CaptureController::SetVideoTrack().

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Capture-session not started.");
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfVideoTrackEnded) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");
  track->stopTrack(v8_scope.GetExecutionContext());  // Ends the track.

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Video track ended.");
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelSuccessIfSupportedValue) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  const Vector<int> supported_levels =
      CaptureController::getSupportedZoomLevels();
  for (int zoom_level : supported_levels) {
    EXPECT_CALL(DispatcherHost(), SetZoomLevel(_, zoom_level, _))
        .WillOnce(RunOnceCallback<2>(CscResult::kSuccess));
    const auto promise =
        controller->setZoomLevel(v8_scope.GetScriptState(), zoom_level);

    ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
    promise_tester.WaitUntilSettled();
    EXPECT_TRUE(promise_tester.IsFulfilled());
  }
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfLevelTooLow) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise = controller->setZoomLevel(
      v8_scope.GetScriptState(),
      controller->getSupportedZoomLevels().front() - 1);
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Only values returned by getSupportedZoomLevels() are valid.");
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfLevelTooHigh) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise =
      controller->setZoomLevel(v8_scope.GetScriptState(),
                               controller->getSupportedZoomLevels().back() + 1);
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Only values returned by getSupportedZoomLevels() are valid.");
}

// This test is distinct from SetZoomLevelFailsIfLevelTooLow and
// SetZoomLevelFailsIfLevelTooHigh in that it uses a value that's within the
// permitted range, thereby ensuring that the validation does not just check
// the range, but rather actually uses the supported value as an allowlist.
TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfUnsupportedValue) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  // Find an unsupported value.
  const Vector<int> supported_levels = controller->getSupportedZoomLevels();
  ASSERT_GE(supported_levels.size(), 2u);
  const int unsupported_level = (supported_levels[0] + supported_levels[1]) / 2;
  ASSERT_FALSE(supported_levels.Contains(unsupported_level));

  const auto promise =
      controller->setZoomLevel(v8_scope.GetScriptState(), unsupported_level);

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Only values returned by getSupportedZoomLevels() are valid.");
}

// Note that the setup differs from that of SetZoomLevelSuccess only in the
// SurfaceType provided to MakeTrack().
TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfCapturingWindow) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::WINDOW);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kNotSupportedError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Action only supported for tab-capture.");
}

// Note that the setup differs from that of SetZoomLevelSuccess only in the
// SurfaceType provided to MakeTrack().
TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsIfCapturingMonitor) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::MONITOR);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kNotSupportedError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Action only supported for tab-capture.");
}

// Note that the setup differs from that of SetZoomLevelSuccess only in the
// simulated result from the browser process.
TEST_F(CaptureControllerSetZoomLevelTest, SimulatedFailureFromDispatcherHost) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(v8_scope, SurfaceType::BROWSER);
  controller->SetVideoTrack(track, "descriptor");

  EXPECT_CALL(DispatcherHost(), SetZoomLevel(_, _, _))
      .WillOnce(RunOnceCallback<2>(CscResult::kUnknownError));
  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 125);
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kUnknownError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Unknown error.");
}

TEST_F(CaptureControllerSetZoomLevelTest, SetZoomLevelFailsWithoutSessionId) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  controller->SetIsBound(true);
  MediaStreamTrack* track = MakeTrack(
      v8_scope, SurfaceType::BROWSER,
      CaptureController::getSupportedZoomLevels()[0], /*use_session_id=*/false);
  controller->SetVideoTrack(track, "descriptor");

  const auto promise = controller->setZoomLevel(v8_scope.GetScriptState(), 100);
  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kUnknownError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "Invalid capture");
}

// Test suite for CaptureController functionality from the
// Captured Surface Control spec, focusing on scroll-control.
class CaptureControllerScrollTest : public CaptureControllerBaseTest {
 public:
  ~CaptureControllerScrollTest() override = default;
};

TEST_F(CaptureControllerScrollTest, SendWheelFailsIfCaptureControllerNotBound) {
  V8TestingScope v8_scope;
  CaptureController* controller =
      MakeController(v8_scope.GetExecutionContext());
  // Test avoids calling CaptureController::SetIsBound().

  const auto promise = controller->sendWheel(v8_scope.GetScriptState(),
                                             CapturedWheelAction::Create());

  ScriptPromiseTester promise_tester(v8_scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(v8_scope, promise_tester.Value(),
                             DOMExceptionCode::kInvalidStateError));

  // Avoid false-positives through different error paths terminating in
  // exception with the same code.
  EXPECT_EQ(GetDOMExceptionMessage(v8_scope, promise_tester.Value()),
            "getDisplayMedia() not called yet.");
}

TEST_F(CaptureControllerScrollTest,
       SendWheelFailsIfCaptureControllerBoundButNoVide
```