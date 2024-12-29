Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `media_stream_video_capturer_source_test.cc` immediately tells us this is a test file for the `MediaStreamVideoCapturerSource` class. The `_test.cc` suffix is a standard convention.

2. **Examine Includes:** The `#include` statements are crucial for understanding dependencies and functionality. Key includes here are:
    * `media_stream_video_capturer_source.h`: The header file for the class being tested.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  Indicates the use of Google Test and Google Mock frameworks for testing.
    * `third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h`:  Signals interaction with the Mojo interface for Media Streams. Mojo is Chromium's inter-process communication system.
    * `third_party/blink/public/web/modules/mediastream/media_stream_video_sink.h` and `third_party/blink/public/web/web_heap.h`:  Points to interaction with the Web platform's MediaStream API.
    * `third_party/blink/renderer/core/dom/dom_exception.h`: Indicates handling of DOM exceptions.
    * `third_party/blink/renderer/modules/mediastream/...`: A collection of headers related to the internal implementation of Media Streams in Blink. Notably, `mock_mojo_media_stream_dispatcher_host.h` and `mock_video_capturer_source.h` reveal the use of mocks for testing dependencies.
    * `third_party/blink/renderer/platform/...`: Headers relating to the platform-specific aspects of Blink, including threading, task scheduling, and video capture.

3. **Understand the Test Structure (Google Test):** Look for the `TEST_F` macros. Each `TEST_F` defines an individual test case within the `MediaStreamVideoCapturerSourceTest` fixture.

4. **Analyze the Test Fixture:** The `MediaStreamVideoCapturerSourceTest` class sets up the testing environment. Key things to note:
    * **Mocking:** It creates a `MockVideoCapturerSource` (`delegate_`) to isolate the `MediaStreamVideoCapturerSource` being tested. This allows controlled simulation of the underlying video capture mechanism.
    * **Instantiation:** It instantiates the `MediaStreamVideoCapturerSource` (`video_capturer_source_`).
    * **Dependency Injection:** It sets a mock `MediaStreamDispatcherHost`. This shows interaction with the broader Media Stream infrastructure.
    * **`StartSource` Helper:** The `StartSource` method is a helper function to simplify the process of starting the video source for testing various scenarios. Pay attention to its parameters (adapter settings, noise reduction, screencast, frame rate).
    * **Callbacks:** The `OnSourceStopped` and `OnStarted` methods are callbacks used to observe the behavior of the tested class.
    * **`RecreateVideoCapturerSource`:** This method hints at testing scenarios involving re-creating the underlying video capturer.

5. **Examine Individual Test Cases:**  Go through each `TEST_F` method and understand its purpose by analyzing the sequence of actions and the `EXPECT_CALL` assertions:
    * **`StartAndStop`:** Tests basic start and stop functionality, including how the `MediaStreamVideoCapturerSource` reacts to the underlying capturer's state changes.
    * **`CaptureTimeAndMetadataPlumbing`:** Focuses on verifying that video frames and their associated metadata (capture time, frame rate) are correctly propagated. The `FakeMediaStreamVideoSink` is key here.
    * **`Restart`:** Tests the more complex restart logic, which involves stopping and then restarting the underlying video capture.
    * **`StartStopAndNotify`:** Tests the `StopAndNotify` method, ensuring the correct sequence of actions and notifications.
    * **`ChangeSource`:** Tests the ability to switch the underlying video capture device.
    * **`FailStartSystemPermission` and `FailStartCamInUse`:**  Focus on handling error conditions during the start process.

6. **Look for Connections to Web Technologies (JavaScript, HTML, CSS):**
    * **`WebMediaStreamTrack` and `MediaStreamVideoSink`:** These classes are part of the Web Media Streams API, directly exposed to JavaScript. The tests show how the C++ implementation interacts with these web-facing interfaces.
    * **DOM Exceptions:** The `IsExpectedDOMException` matcher indicates that the C++ code can trigger DOM exceptions that are observable in JavaScript.
    * **User Interaction:** Consider how a user might initiate actions that lead to these code paths. Requesting camera access via `getUserMedia()` is the primary entry point.

7. **Identify Logical Reasoning and Assumptions:**
    * **Mocking Assumptions:** The tests assume that the `MockVideoCapturerSource` accurately simulates the behavior of a real video capturer.
    * **State Transitions:** The tests explicitly verify state transitions (`MediaStreamSource::kReadyStateLive`, `kReadyStateEnded`), demonstrating an understanding of the expected lifecycle of a video stream.
    * **Asynchronous Operations:** The use of `base::RunLoop().RunUntilIdle()` highlights the asynchronous nature of media stream processing.

8. **Consider Potential User/Programming Errors:** Think about what mistakes developers might make when using the Media Streams API:
    * Not handling errors when requesting camera access.
    * Incorrectly managing the lifecycle of `MediaStreamTrack` objects.
    * Making assumptions about the timing of asynchronous operations.

9. **Trace User Operations (Debugging Clues):**  Think about how a user's actions in a web browser could lead to this code being executed:
    * A user clicks a button that triggers JavaScript code to call `navigator.mediaDevices.getUserMedia({ video: true })`.
    * The browser prompts the user for camera permission.
    * If permission is granted, the browser starts the video capture device, which involves the `MediaStreamVideoCapturerSource`.
    * If permission is denied or the camera is in use, the error handling logic in the test file is exercised.
    * The user might interact with the video stream by displaying it in a `<video>` element, which would involve `MediaStreamVideoSink`.

10. **Review and Refine:**  After the initial analysis, go back and refine the descriptions, ensuring clarity and accuracy. Pay attention to specific details and how they relate to the overall functionality. For example, the significance of the `InSequence` matcher in Google Mock.

By following these steps, you can systematically analyze a C++ test file like this and extract the necessary information to understand its purpose, its relationship to web technologies, and its role in the broader browser architecture.
这个文件 `media_stream_video_capturer_source_test.cc` 是 Chromium Blink 引擎中用于测试 `MediaStreamVideoCapturerSource` 类的单元测试文件。 `MediaStreamVideoCapturerSource` 的作用是将底层的视频捕获器 (Video Capturer) 产生的视频帧数据转换为可以在 Web 平台上使用的 `MediaStreamTrack`。

以下是该文件的功能分解以及与 JavaScript, HTML, CSS 的关系：

**核心功能：测试 `MediaStreamVideoCapturerSource` 的以下方面：**

1. **启动和停止视频捕获:**
   - 测试 `MediaStreamVideoCapturerSource` 如何启动底层的视频捕获器 (`MockVideoCapturerSource` 在测试中被用作模拟)。
   - 测试当底层捕获器停止时，`MediaStreamVideoCapturerSource` 如何更新其状态并通知监听者。

2. **视频帧数据传递和元数据处理:**
   - 测试从底层捕获器接收到的视频帧数据是否正确地传递到连接的 `MediaStreamVideoSink` (在 Web 平台上对应 JavaScript 中的 `MediaStreamTrack` 的 `onframe` 事件或者通过 `captureStream()` 获取的流)。
   - 测试视频帧的元数据 (例如捕获时间) 是否被正确地传递。

3. **重启视频捕获:**
   - 测试在不完全停止 `MediaStreamTrack` 的情况下，如何暂停和重启底层的视频捕获器，例如在改变视频分辨率或帧率等设置时。

4. **停止并通知:**
   - 测试 `StopAndNotify` 方法，该方法用于停止视频捕获并通知相关的监听者 (例如，当 JavaScript 中调用 `MediaStreamTrack.stop()` 时)。

5. **更换视频源:**
   - 测试在运行时更换底层的视频捕获源 (例如，从一个摄像头切换到另一个摄像头)。

6. **处理启动失败的情况:**
   - 测试当底层视频捕获器启动失败时 (`RunState::kSystemPermissionsError`, `RunState::kCameraBusyError`)，`MediaStreamVideoCapturerSource` 如何处理并通知错误。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`MediaStreamVideoCapturerSource` 是 Web Media Streams API 的底层实现部分，它直接影响 JavaScript 中关于摄像头访问和视频流处理的功能。

1. **JavaScript `getUserMedia()`:**
   - 当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })` 请求访问摄像头时，Chromium 内部会创建 `MediaStreamVideoCapturerSource` 来处理底层的视频捕获。
   - **假设输入：** 用户在网页中点击了一个按钮，触发了 `getUserMedia({ video: true })` 的调用。
   - **对应的 `media_stream_video_capturer_source_test.cc` 测试:** `StartAndStop`, `FailStartSystemPermission`, `FailStartCamInUse` 等测试模拟了 `getUserMedia` 成功或失败的情况。

2. **JavaScript `MediaStreamTrack`:**
   - `MediaStreamVideoCapturerSource` 创建的视频流数据最终会通过 `MediaStreamVideoTrack` 对象暴露给 JavaScript。
   - JavaScript 可以通过 `MediaStreamTrack` 的 `onended` 事件监听视频流的结束，这与 `MediaStreamVideoCapturerSource` 的停止逻辑相关。
   - **假设输入：** JavaScript 获取到一个 `MediaStreamTrack` 对象。
   - **对应的 `media_stream_video_capturer_source_test.cc` 测试:** `StartStopAndNotify` 测试了当底层捕获停止时，是否会触发相应的通知。

3. **HTML `<video>` 元素:**
   - JavaScript 可以将 `MediaStreamTrack` 对象赋值给 `<video>` 元素的 `srcObject` 属性，从而在网页上显示摄像头捕获的视频。
   - **假设输入：** JavaScript 代码将一个 `MediaStreamTrack` 对象赋值给 `<video>` 元素的 `srcObject`。
   - **虽然测试文件本身不直接涉及 HTML，但其功能是 `<video>` 元素显示视频流的基础。**

4. **CSS 控制视频显示:**
   - CSS 可以控制 `<video>` 元素的样式，例如大小、位置等。
   - **`media_stream_video_capturer_source_test.cc` 不直接与 CSS 交互。**

**逻辑推理 (假设输入与输出):**

* **假设输入 (针对 `CaptureTimeAndMetadataPlumbing` 测试):**
    - 底层 `MockVideoCapturerSource` 捕获到一帧视频，并设置了捕获时间 `reference_capture_time` 和帧率 `30.0`。
    - 一个 `FakeMediaStreamVideoSink` 连接到 `MediaStreamVideoTrack`。
* **预期输出:**
    - `FakeMediaStreamVideoSink` 的 `OnVideoFrame` 回调被调用。
    - `capture_time_` 被设置为 `reference_capture_time`。
    - `metadata_.frame_rate` 被设置为 `30.0`。

* **假设输入 (针对 `Restart` 测试):**
    - `MediaStreamVideoCapturerSource` 处于运行状态。
    - 调用 `StopForRestart` 方法。
    - 之后调用 `Restart` 方法。
* **预期输出:**
    - `StopForRestart` 调用后，底层捕获器被停止，但 `MediaStreamSource` 的状态仍然是 `kReadyStateLive`。
    - `Restart` 调用后，底层捕获器重新启动，`MediaStreamSource` 的状态保持 `kReadyStateLive`。

**用户或编程常见的使用错误举例说明：**

1. **用户未授权摄像头访问:**
   - **用户操作:** 用户在浏览器中访问一个请求摄像头权限的网页，并在浏览器提示时点击“拒绝”。
   - **`media_stream_video_capturer_source_test.cc` 关联:** `FailStartSystemPermission` 测试模拟了这种情况，验证了当系统权限被拒绝时，`MediaStreamVideoCapturerSource` 能否正确处理并通知。
   - **结果:** `getUserMedia()` Promise 将会 reject，并返回一个 `NotAllowedError` 类型的 `DOMException`。

2. **摄像头正在被其他应用占用:**
   - **用户操作:** 用户已经打开了另一个使用摄像头的应用程序 (例如 Skype)，然后访问了一个也请求使用摄像头的网页。
   - **`media_stream_video_capturer_source_test.cc` 关联:** `FailStartCamInUse` 测试模拟了这种情况，验证了当摄像头被占用时，`MediaStreamVideoCapturerSource` 能否正确处理并通知。
   - **结果:** `getUserMedia()` Promise 将会 reject，并返回一个 `OverconstrainedError` 或特定于平台的错误，指示设备忙碌。

3. **程序员没有正确处理 `getUserMedia()` 的错误:**
   - **编程错误:** JavaScript 开发者调用 `getUserMedia()` 后，没有正确地处理 Promise 的 `reject` 情况。
   - **虽然测试文件不直接测试 JavaScript 代码，但它确保了当底层发生错误时，会传递相应的错误信息，以便 JavaScript 代码能够捕获并处理。**

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个网页:** 用户在浏览器中输入网址或点击链接，打开了一个包含需要访问摄像头的 JavaScript 代码的网页。

2. **JavaScript 发起摄像头请求:** 网页中的 JavaScript 代码执行，调用了 `navigator.mediaDevices.getUserMedia({ video: true })`。

3. **浏览器处理权限请求:**
   - 浏览器会检查用户是否已经授予过该网站摄像头权限。
   - 如果没有，浏览器会弹出权限请求提示。

4. **用户授权或拒绝:**
   - **授权:** 用户点击“允许”或类似的按钮，授权该网站使用摄像头。这会触发 `MediaStreamVideoCapturerSource` 的启动逻辑 (`StartAndStop` 测试覆盖的场景)。
   - **拒绝:** 用户点击“阻止”或类似的按钮，拒绝授权。这会触发 `MediaStreamVideoCapturerSource` 的错误处理逻辑 (`FailStartSystemPermission` 测试覆盖的场景)。

5. **底层视频捕获启动:** 如果用户授权，Chromium 会尝试启动底层的视频捕获设备，这由 `MockVideoCapturerSource` (在测试中) 或真实的视频捕获器负责。

6. **视频帧数据传输:** 成功启动后，底层捕获器会不断产生视频帧数据，这些数据通过 `MediaStreamVideoCapturerSource` 传递给 `MediaStreamVideoTrack`，最终可以在 JavaScript 中处理和显示 (`CaptureTimeAndMetadataPlumbing` 测试覆盖了数据传输的正确性)。

7. **用户停止或切换视频源:**
   - 用户可能关闭网页或执行某些操作，导致 JavaScript 调用 `MediaStreamTrack.stop()`，这会触发 `MediaStreamVideoCapturerSource` 的停止逻辑 (`StartStopAndNotify` 测试覆盖的场景)。
   - 用户可能在网页中操作，要求切换摄像头，这会触发 `MediaStreamVideoCapturerSource` 的更换视频源逻辑 (`ChangeSource` 测试覆盖的场景)。

**作为调试线索，当在 Chromium 开发中遇到与摄像头相关的 bug 时，开发者可能会：**

- **查看 `media_stream_video_capturer_source_test.cc` 中的测试用例:** 确认是否已经有覆盖该 bug 场景的测试，或者是否需要添加新的测试用例来重现和验证修复。
- **使用断点调试:** 在 `MediaStreamVideoCapturerSource` 的相关代码中设置断点，跟踪视频流的启动、数据传输和停止过程，以找出问题所在。
- **查看日志:** Chromium 的日志系统会记录 Media Streams 相关的事件和错误信息，可以帮助定位问题。

总而言之，`media_stream_video_capturer_source_test.cc` 是一个至关重要的测试文件，用于确保 Chromium Blink 引擎中视频捕获功能的正确性和稳定性，它直接关系到 Web 平台上依赖摄像头功能的各种应用。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_video_capturer_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_video_capturer_source.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/task/bind_post_task.h"
#include "base/test/mock_callback.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_sink.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_mojo_media_stream_dispatcher_host.h"
#include "third_party/blink/renderer/modules/mediastream/mock_video_capturer_source.h"
#include "third_party/blink/renderer/modules/mediastream/video_track_adapter_settings.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/video_capture/video_capturer_source.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_media.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using ::testing::_;
using ::testing::InSequence;
using ::testing::Return;

namespace blink {

using mojom::blink::MediaStreamRequestResult;

namespace {

MATCHER_P2(IsExpectedDOMException, name, message, "") {
  return arg->name() == name && arg->message() == message;
}

class FakeMediaStreamVideoSink : public MediaStreamVideoSink {
 public:
  FakeMediaStreamVideoSink(base::TimeTicks* capture_time,
                           media::VideoFrameMetadata* metadata,
                           base::OnceClosure got_frame_cb)
      : capture_time_(capture_time),
        metadata_(metadata),
        got_frame_cb_(std::move(got_frame_cb)) {}

  void ConnectToTrack(const WebMediaStreamTrack& track) {
    MediaStreamVideoSink::ConnectToTrack(
        track,
        ConvertToBaseRepeatingCallback(
            CrossThreadBindRepeating(&FakeMediaStreamVideoSink::OnVideoFrame,
                                     WTF::CrossThreadUnretained(this))),
        MediaStreamVideoSink::IsSecure::kYes,
        MediaStreamVideoSink::UsesAlpha::kDefault);
  }

  void DisconnectFromTrack() { MediaStreamVideoSink::DisconnectFromTrack(); }

  void OnVideoFrame(scoped_refptr<media::VideoFrame> frame,
                    base::TimeTicks capture_time) {
    *capture_time_ = capture_time;
    *metadata_ = frame->metadata();
    std::move(got_frame_cb_).Run();
  }

 private:
  const raw_ptr<base::TimeTicks> capture_time_;
  const raw_ptr<media::VideoFrameMetadata> metadata_;
  base::OnceClosure got_frame_cb_;
};

}  // namespace

class MediaStreamVideoCapturerSourceTest : public testing::Test {
 public:
  MediaStreamVideoCapturerSourceTest() : source_stopped_(false) {
    auto delegate = std::make_unique<MockVideoCapturerSource>();
    delegate_ = delegate.get();
    EXPECT_CALL(*delegate_, GetPreferredFormats());
    auto video_capturer_source =
        std::make_unique<MediaStreamVideoCapturerSource>(
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            /*LocalFrame =*/nullptr,
            WTF::BindOnce(&MediaStreamVideoCapturerSourceTest::OnSourceStopped,
                          WTF::Unretained(this)),
            std::move(delegate));
    video_capturer_source_ = video_capturer_source.get();
    video_capturer_source_->SetMediaStreamDispatcherHostForTesting(
        mock_dispatcher_host_.CreatePendingRemoteAndBind());
    stream_source_ = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeVideo, "dummy_source_name",
        false /* remote */, std::move(video_capturer_source));
    stream_source_id_ = stream_source_->Id();

    MediaStreamVideoCapturerSource::DeviceCapturerFactoryCallback callback =
        WTF::BindRepeating(
            &MediaStreamVideoCapturerSourceTest::RecreateVideoCapturerSource,
            WTF::Unretained(this));
    video_capturer_source_->SetDeviceCapturerFactoryCallbackForTesting(
        std::move(callback));
  }

  void TearDown() override {
    stream_source_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  WebMediaStreamTrack StartSource(
      const VideoTrackAdapterSettings& adapter_settings,
      const std::optional<bool>& noise_reduction,
      bool is_screencast,
      double min_frame_rate) {
    bool enabled = true;
    // CreateVideoTrack will trigger StartDone.
    return MediaStreamVideoTrack::CreateVideoTrack(
        video_capturer_source_, adapter_settings, noise_reduction,
        is_screencast, min_frame_rate, nullptr, false,
        WTF::BindOnce(&MediaStreamVideoCapturerSourceTest::StartDone,
                      base::Unretained(this)),
        enabled);
  }

  MockVideoCapturerSource& mock_delegate() { return *delegate_; }

  void OnSourceStopped(const WebMediaStreamSource& source) {
    source_stopped_ = true;
    if (source.IsNull())
      return;
    EXPECT_EQ(String(source.Id()), stream_source_id_);
  }
  void OnStarted(bool result) {
    RunState run_state = result ? RunState::kRunning : RunState::kStopped;
    video_capturer_source_->OnRunStateChanged(delegate_->capture_params(),
                                              run_state);
  }

  void SetStopCaptureFlag() { stop_capture_flag_ = true; }

  MOCK_METHOD0(MockNotification, void());

  std::unique_ptr<VideoCapturerSource> RecreateVideoCapturerSource(
      const base::UnguessableToken& session_id) {
    auto delegate = std::make_unique<MockVideoCapturerSource>();
    delegate_ = delegate.get();
    EXPECT_CALL(*delegate_, MockStartCapture(_, _, _))
        .WillOnce(Return(RunState::kRunning));
    return delegate;
  }

 protected:
  void StartDone(WebPlatformMediaStreamSource* source,
                 MediaStreamRequestResult result,
                 const WebString& result_name) {
    start_result_ = result;
  }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;

  Persistent<MediaStreamSource> stream_source_;
  MockMojoMediaStreamDispatcherHost mock_dispatcher_host_;
  raw_ptr<MediaStreamVideoCapturerSource, DanglingUntriaged>
      video_capturer_source_;  // owned by |stream_source_|.
  raw_ptr<MockVideoCapturerSource, DanglingUntriaged>
      delegate_;  // owned by |source_|.
  String stream_source_id_;
  bool source_stopped_;
  bool stop_capture_flag_ = false;
  MediaStreamRequestResult start_result_;
};

TEST_F(MediaStreamVideoCapturerSourceTest, StartAndStop) {
  InSequence s;
  EXPECT_CALL(mock_delegate(), MockStartCapture(_, _, _));
  WebMediaStreamTrack track =
      StartSource(VideoTrackAdapterSettings(), std::nullopt, false, 0.0);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_FALSE(source_stopped_);

  // A bogus notification of running from the delegate when the source has
  // already started should not change the state.
  delegate_->SetRunning(RunState::kRunning);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_FALSE(source_stopped_);
  EXPECT_TRUE(video_capturer_source_->GetCurrentFormat().has_value());

  // If the delegate stops, the source should stop.
  EXPECT_CALL(mock_delegate(), MockStopCapture());
  delegate_->SetRunning(RunState::kStopped);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateEnded,
            stream_source_->GetReadyState());
  // Verify that WebPlatformMediaStreamSource::SourceStoppedCallback has
  // been triggered.
  EXPECT_TRUE(source_stopped_);
}

TEST_F(MediaStreamVideoCapturerSourceTest, CaptureTimeAndMetadataPlumbing) {
  VideoCaptureDeliverFrameCB deliver_frame_cb;
  VideoCapturerSource::RunningCallback running_cb;

  InSequence s;
  EXPECT_CALL(mock_delegate(), MockStartCapture(_, _, _))
      .WillOnce(testing::DoAll(testing::SaveArg<1>(&deliver_frame_cb),
                               testing::SaveArg<2>(&running_cb),
                               Return(RunState::kRunning)));
  EXPECT_CALL(mock_delegate(), RequestRefreshFrame());
  EXPECT_CALL(mock_delegate(), MockStopCapture());
  WebMediaStreamTrack track =
      StartSource(VideoTrackAdapterSettings(), std::nullopt, false, 0.0);
  running_cb.Run(RunState::kRunning);

  base::RunLoop run_loop;
  base::TimeTicks reference_capture_time =
      base::TimeTicks::FromInternalValue(60013);
  base::TimeTicks capture_time;
  media::VideoFrameMetadata metadata;
  FakeMediaStreamVideoSink fake_sink(
      &capture_time, &metadata,
      base::BindPostTaskToCurrentDefault(run_loop.QuitClosure()));
  fake_sink.ConnectToTrack(track);
  const scoped_refptr<media::VideoFrame> frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(2, 2));
  frame->metadata().frame_rate = 30.0;
  PostCrossThreadTask(
      *Platform::Current()->GetIOTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(deliver_frame_cb, frame, reference_capture_time));
  run_loop.Run();
  fake_sink.DisconnectFromTrack();
  EXPECT_EQ(reference_capture_time, capture_time);
  EXPECT_EQ(30.0, *metadata.frame_rate);
}

TEST_F(MediaStreamVideoCapturerSourceTest, Restart) {
  InSequence s;
  EXPECT_CALL(mock_delegate(), MockStartCapture(_, _, _))
      .WillOnce(Return(RunState::kRunning));
  WebMediaStreamTrack track =
      StartSource(VideoTrackAdapterSettings(), std::nullopt, false, 0.0);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_FALSE(source_stopped_);

  EXPECT_CALL(mock_delegate(), MockStopCapture());
  EXPECT_TRUE(video_capturer_source_->IsRunning());
  video_capturer_source_->StopForRestart(
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::IS_STOPPED);
      }));
  base::RunLoop().RunUntilIdle();
  // When the source has stopped for restart, the source is not considered
  // stopped, even if the underlying delegate is not running anymore.
  // WebPlatformMediaStreamSource::SourceStoppedCallback should not be
  // triggered.
  EXPECT_EQ(stream_source_->GetReadyState(),
            MediaStreamSource::kReadyStateLive);
  EXPECT_FALSE(source_stopped_);
  EXPECT_FALSE(video_capturer_source_->IsRunning());

  // A second StopForRestart() should fail with invalid state, since it only
  // makes sense when the source is running. Existing ready state should remain
  // the same.
  EXPECT_FALSE(video_capturer_source_->IsRunning());
  video_capturer_source_->StopForRestart(
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::INVALID_STATE);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(stream_source_->GetReadyState(),
            MediaStreamSource::kReadyStateLive);
  EXPECT_FALSE(source_stopped_);
  EXPECT_FALSE(video_capturer_source_->IsRunning());

  // Restart the source. With the mock delegate, any video format will do.
  EXPECT_CALL(mock_delegate(), MockStartCapture(_, _, _))
      .WillOnce(Return(RunState::kRunning));
  EXPECT_FALSE(video_capturer_source_->IsRunning());
  video_capturer_source_->Restart(
      media::VideoCaptureFormat(),
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::IS_RUNNING);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(stream_source_->GetReadyState(),
            MediaStreamSource::kReadyStateLive);
  EXPECT_TRUE(video_capturer_source_->IsRunning());

  // A second Restart() should fail with invalid state since Restart() is
  // defined only when the source is stopped for restart. Existing ready state
  // should remain the same.
  EXPECT_TRUE(video_capturer_source_->IsRunning());
  video_capturer_source_->Restart(
      media::VideoCaptureFormat(),
      WTF::BindOnce([](MediaStreamVideoSource::RestartResult result) {
        EXPECT_EQ(result, MediaStreamVideoSource::RestartResult::INVALID_STATE);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(stream_source_->GetReadyState(),
            MediaStreamSource::kReadyStateLive);
  EXPECT_TRUE(video_capturer_source_->IsRunning());

  // An delegate stop should stop the source and change the track state to
  // "ended".
  EXPECT_CALL(mock_delegate(), MockStopCapture());
  delegate_->SetRunning(RunState::kStopped);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateEnded,
            stream_source_->GetReadyState());
  // Verify that WebPlatformMediaStreamSource::SourceStoppedCallback has
  // been triggered.
  EXPECT_TRUE(source_stopped_);
  EXPECT_FALSE(video_capturer_source_->IsRunning());
}

TEST_F(MediaStreamVideoCapturerSourceTest, StartStopAndNotify) {
  InSequence s;
  EXPECT_CALL(mock_delegate(), MockStartCapture(_, _, _))
      .WillOnce(Return(RunState::kRunning));
  WebMediaStreamTrack web_track =
      StartSource(VideoTrackAdapterSettings(), std::nullopt, false, 0.0);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_FALSE(source_stopped_);
  EXPECT_EQ(start_result_, MediaStreamRequestResult::OK);

  stop_capture_flag_ = false;
  EXPECT_CALL(mock_delegate(), MockStopCapture())
      .WillOnce(InvokeWithoutArgs(
          this, &MediaStreamVideoCapturerSourceTest::SetStopCaptureFlag));
  EXPECT_CALL(*this, MockNotification());
  MediaStreamTrackPlatform* track =
      MediaStreamTrackPlatform::GetTrack(web_track);
  track->StopAndNotify(
      WTF::BindOnce(&MediaStreamVideoCapturerSourceTest::MockNotification,
                    base::Unretained(this)));
  EXPECT_EQ(MediaStreamSource::kReadyStateEnded,
            stream_source_->GetReadyState());
  EXPECT_TRUE(source_stopped_);
  // It is a requirement that StopCapture() gets called in the same task as
  // StopAndNotify(), as CORS security checks for element capture rely on this.
  EXPECT_TRUE(stop_capture_flag_);
  // The readyState is updated in the current task, but the notification is
  // received on a separate task.
  base::RunLoop().RunUntilIdle();
}

TEST_F(MediaStreamVideoCapturerSourceTest, ChangeSource) {
  InSequence s;
  EXPECT_CALL(mock_delegate(), MockStartCapture(_, _, _))
      .WillOnce(Return(RunState::kRunning));
  WebMediaStreamTrack track =
      StartSource(VideoTrackAdapterSettings(), std::nullopt, false, 0.0);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_FALSE(source_stopped_);
  EXPECT_EQ(start_result_, MediaStreamRequestResult::OK);

  // A bogus notification of running from the delegate when the source has
  // already started should not change the state.
  delegate_->SetRunning(RunState::kRunning);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_FALSE(source_stopped_);

  // |ChangeSourceImpl()| will recreate the |delegate_|, so check the
  // |MockStartCapture()| invoking in the |RecreateVideoCapturerSource()|.
  EXPECT_CALL(mock_delegate(), MockStopCapture());
  MediaStreamDevice fake_video_device(
      mojom::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE, "Fake_Video_Device",
      "Fake Video Device");
  video_capturer_source_->ChangeSourceImpl(fake_video_device);
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_FALSE(source_stopped_);

  // If the delegate stops, the source should stop.
  EXPECT_CALL(mock_delegate(), MockStopCapture());
  delegate_->SetRunning(RunState::kStopped);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(MediaStreamSource::kReadyStateEnded,
            stream_source_->GetReadyState());
  // Verify that WebPlatformMediaStreamSource::SourceStoppedCallback has
  // been triggered.
  EXPECT_TRUE(source_stopped_);
}

TEST_F(MediaStreamVideoCapturerSourceTest, FailStartSystemPermission) {
  InSequence s;
  EXPECT_CALL(mock_delegate(), MockStartCapture(_, _, _))
      .WillOnce(Return(RunState::kSystemPermissionsError));
  WebMediaStreamTrack track =
      StartSource(VideoTrackAdapterSettings(), std::nullopt, false, 0.0);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(source_stopped_);
  EXPECT_EQ(start_result_, MediaStreamRequestResult::SYSTEM_PERMISSION_DENIED);
}

TEST_F(MediaStreamVideoCapturerSourceTest, FailStartCamInUse) {
  InSequence s;
  EXPECT_CALL(mock_delegate(), MockStartCapture(_, _, _))
      .WillOnce(Return(RunState::kCameraBusyError));
  WebMediaStreamTrack track =
      StartSource(VideoTrackAdapterSettings(), std::nullopt, false, 0.0);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(source_stopped_);
  EXPECT_EQ(start_result_, MediaStreamRequestResult::DEVICE_IN_USE);
}

}  // namespace blink

"""

```