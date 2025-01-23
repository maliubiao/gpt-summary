Response:
Let's break down the thought process for analyzing the given C++ test file and generating the summary.

**1. Understanding the Goal:**

The request asks for a functional overview of a specific Chromium Blink test file (`media_stream_track_impl_test.cc`). It also requires identifying relationships with web technologies (JavaScript, HTML, CSS), explaining logical reasoning through examples, highlighting potential user/programming errors, and describing how a user might reach this code (debugging context). Finally, it asks for a high-level summary of the file's purpose.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for key terms and patterns. This reveals:

* **Includes:**  `MediaStreamTrackImpl.h`, `gtest/gtest.h`, various `mojom` files (related to inter-process communication), `MediaStreamVideoSource.h`, `MediaStreamAudioSource.h`,  `ScriptPromise`,  `MediaTrackConstraints`.
* **Namespaces:** `blink`, suggesting this is related to the Blink rendering engine.
* **Class Names:** `MediaStreamTrackImplTest`, `TestObserver`, `MockMediaStreamVideoSource`, `LocalMediaStreamAudioSource`. The `Test` suffix in `MediaStreamTrackImplTest` strongly indicates this is a unit test file.
* **Macros/Functions:** `TEST_F`, `EXPECT_EQ`, `EXPECT_TRUE`, `MakeMock...`, `MakeLocal...`, `MakeMediaTrackConstraints`. The `TEST_F` macro confirms the unit testing nature. `EXPECT_*` macros are typical assertion mechanisms in unit tests. The `Make...` functions likely create test objects.
* **Concepts:** "Constraints," "Muted State," "Clone," "Apply Constraints," "Video," "Audio."

**3. Deduction of Core Functionality:**

Based on the keywords and structure, the primary function of this file is clearly **testing the `MediaStreamTrackImpl` class**. This class is likely a concrete implementation of the `MediaStreamTrack` interface, a core component of the WebRTC API for handling individual media streams (audio or video).

**4. Identifying Relationships with Web Technologies:**

* **JavaScript:** The presence of `ScriptPromise`,  `V8TestingScope`, and mentions of "constraints" immediately link this code to the JavaScript WebRTC API. JavaScript code uses `getUserMedia()` to obtain media streams, which are represented by `MediaStream` objects. Each `MediaStream` contains `MediaStreamTrack` objects. The testing here likely validates how the underlying C++ implementation behaves in response to JavaScript calls and events.
* **HTML:** While not directly manipulating HTML elements, the functionality tested here is crucial for web pages that use media. For example, a `<video>` or `<audio>` element might display or play a stream whose track is being tested.
* **CSS:** CSS isn't directly involved in the *logic* of media stream tracks, but it can style the `<video>` element that displays the stream. Therefore, the relationship is indirect.

**5. Analyzing Specific Tests and Inferring Logic:**

By looking at the individual `TEST_F` functions, we can understand specific aspects being tested:

* `StopTrackTriggersObservers`: Tests that stopping a track notifies registered observers. *Hypothesis:* If we call `stopTrack()` in JS, observers in C++ should be notified.
* `StopTrackSynchronouslyDisablesMedia`: Tests that stopping a track immediately disables the underlying media source. *Hypothesis:* Calling `stopTrack()` should immediately prevent media flow.
* `MutedStateUpdates`: Tests that the `muted` state of the track reflects the underlying source's state. *Hypothesis:* When the media source is muted, the JavaScript `track.muted` property should be true.
* `Clone...Track`: Tests the cloning mechanism for both video and audio tracks. *Hypothesis:* Cloning creates a new track object that shares the same underlying source.
* `ApplyConstraints...`:  These are crucial. They test the `applyConstraints()` method, which is how JavaScript code modifies the properties of a media track (resolution, frame rate, etc.). The tests verify that:
    * Constraints are applied correctly.
    * The underlying media source is restarted when necessary.
    * Certain combinations of constraints interact as expected (e.g., changing framerate doesn't affect resolution).
    * There are conditions where constraints are *not* applied (e.g., for cropped sources).

**6. Identifying Potential Errors:**

The tests themselves suggest potential error scenarios:

* Failing to notify observers when a track is stopped.
* The `muted` state not being correctly synchronized with the source.
* Cloning not preserving constraints.
* `applyConstraints()` not updating the source correctly or failing to restart the source when required.
* Incorrect handling of constraint combinations.
* Trying to apply constraints to a cropped source and expecting changes in the source format.

**7. Describing the User Journey (Debugging Context):**

To arrive at this C++ code during debugging, a developer would likely:

1. **Observe a WebRTC issue:**  A user reports a problem with their camera or microphone in a web application. This might involve incorrect resolution, unexpected muting, or issues with applying video constraints.
2. **Investigate the JavaScript API:** The developer would start by examining the JavaScript code using `getUserMedia()` and the `MediaStreamTrack` API (`applyConstraints`, `stop`, `muted`).
3. **Look at browser console logs:** The browser console might show errors or warnings related to media constraints or track states.
4. **Dive into browser internals:** If the JavaScript debugging doesn't reveal the root cause, the developer might need to examine the browser's internal implementation. This often involves searching the Chromium codebase for relevant keywords like "MediaStreamTrack," "applyConstraints," etc.
5. **Land on test files:**  Test files like this one provide valuable insights into how the C++ implementation *should* behave. By understanding the tests, the developer can better understand the expected behavior and identify deviations in the actual code execution.
6. **Set breakpoints in C++ code:**  Using a debugger, the developer could set breakpoints in `MediaStreamTrackImpl::applyConstraints`, `MediaStreamTrackImpl::stopTrack`, or related methods to trace the execution flow and identify the source of the issue.

**8. Synthesizing the Summary:**

Finally, the individual observations are combined into a concise summary that captures the essence of the file's purpose and its relationship to the broader WebRTC ecosystem. This involves rephrasing the detailed findings into more general terms.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This file just tests stopping and starting media tracks."  *Correction:* While stopping is tested, the focus on `applyConstraints` reveals a more complex purpose related to dynamic track configuration.
* **Initial thought:** "The user directly interacts with this C++ code." *Correction:*  Users interact with the *web page* which *uses* the JavaScript API, which in turn interacts with this C++ code. The user's path is indirect.
* **Ensuring clarity:** Using clear and concise language, avoiding overly technical jargon where possible, and providing concrete examples to illustrate the concepts.
这是文件 `blink/renderer/modules/mediastream/media_stream_track_impl_test.cc` 的功能总结：

**主要功能:**

这个文件包含了针对 `MediaStreamTrackImpl` 类的单元测试。`MediaStreamTrackImpl` 是 Chromium Blink 引擎中 `MediaStreamTrack` 接口的具体实现。`MediaStreamTrack` 代表了一个媒体流中的单个轨道，例如音频轨道或视频轨道。

**详细功能分解:**

1. **测试 `stopTrack()` 方法:**
   - 验证调用 `stopTrack()` 方法会触发已注册的观察者 (`Observer`)。
   - 验证 `stopTrack()` 方法会同步禁用底层的媒体轨道 (`MediaStreamAudioTrack` 或 `MediaStreamVideoTrack`)。

2. **测试 `muted` 属性:**
   - 验证 `muted` 属性能够正确反映底层 `MediaStreamSource` 的静音状态变化。
   - 验证在轨道结束后，即使底层源的静音状态改变，`muted` 属性也不会更新。

3. **测试 `clone()` 方法:**
   - 验证 `clone()` 方法能够为视频轨道和音频轨道创建新的 `MediaStreamTrackImpl` 实例。
   - 验证克隆的轨道与其原始轨道共享相同的底层 `MediaStreamSource` 对象。
   - 验证克隆的轨道会保留原始轨道的约束 (`constraints`)。

4. **测试 `applyConstraints()` 方法:**
   - 验证 `applyConstraints()` 方法能够更新底层媒体源的格式设置（例如，分辨率、帧率）。
   - 验证 `applyConstraints()` 方法在必要时会重启底层的媒体源。
   - 测试了各种约束组合对媒体源格式的影响，例如：
     - 仅更新分辨率。
     - 仅更新帧率。
     - 同时更新分辨率和帧率。
     - 更新宽度但不影响宽高比，或同时更新宽度和宽高比。
   - 测试了在某些情况下 `applyConstraints()` 不会更新媒体源格式，例如当媒体源被裁剪时（`cropTo()` 功能）。
   - 测试了当 `kApplyConstraintsRestartsVideoContentSources` 特性被禁用时，`applyConstraints()` 不会更新源格式。
   - 测试了当应用与当前设置相同的约束时，不会重启媒体源。
   - 测试了在无法重启媒体源的情况下应用约束的行为。
   - 验证了 `applyConstraints()` 方法能够更新视频轨道的最小帧率。

**与 JavaScript, HTML, CSS 的关系及举例:**

`MediaStreamTrackImpl` 是 WebRTC API 的一部分，它在 JavaScript 中暴露给开发者使用。

* **JavaScript:**
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(function(stream) {
        const videoTrack = stream.getVideoTracks()[0];
        console.log(videoTrack.label); // 获取轨道标签
        videoTrack.stop(); // 调用 stopTrack() 方法
        console.log(videoTrack.muted); // 获取 muted 属性

        // 应用约束
        videoTrack.applyConstraints({
          width: { ideal: 640 },
          frameRate: { ideal: 30 }
        }).then(() => {
          console.log("Constraints applied successfully");
        }).catch(error => {
          console.error("Failed to apply constraints:", error);
        });

        const clonedTrack = videoTrack.clone(); // 调用 clone() 方法
        console.log(clonedTrack.label);
      });
    ```
    这个 JavaScript 例子演示了如何获取视频轨道，并调用 `stop()`, 获取 `muted` 属性，以及使用 `applyConstraints()` 和 `clone()` 方法。`media_stream_track_impl_test.cc` 中的测试就是验证这些 JavaScript 方法调用在 Blink 引擎中的底层实现是否正确。

* **HTML:**
    ```html
    <video id="myVideo" autoplay playsinline></video>
    ```
    HTML 的 `<video>` 元素通常用于显示来自 `MediaStreamTrack` 的视频流。虽然这个 C++ 文件本身不直接操作 HTML，但它测试的功能是支持在 HTML 中显示和控制媒体流的关键部分。

* **CSS:**
    ```css
    #myVideo {
      width: 320px;
      height: 240px;
    }
    ```
    CSS 用于样式化显示媒体流的 HTML 元素。同样，这个 C++ 文件不直接涉及 CSS，但它确保了媒体流的正确工作，从而可以在应用 CSS 样式后正常显示。

**逻辑推理 (假设输入与输出):**

假设我们有一个视频轨道，其初始分辨率为 1280x720，帧率为 30fps。

**假设输入 (JavaScript 调用):**

```javascript
videoTrack.applyConstraints({ width: { ideal: 640 }, height: { ideal: 480 } });
```

**逻辑推理 (C++ 代码中的处理):**

`MediaStreamTrackImpl::applyConstraints()` 方法会被调用，它会：

1. 将 JavaScript 传递的约束转换为内部表示 (`MediaTrackConstraints`).
2. 尝试与底层 `MediaStreamVideoSource` 协商新的格式。
3. 如果协商成功，`MockMediaStreamVideoSource` (在测试中) 的 `max_requested_width()` 和 `max_requested_height()` 成员变量将被更新为 640 和 480。
4. 如果需要，底层的媒体源会被重启以应用新的设置。

**假设输出 (测试断言):**

测试会断言：

```c++
EXPECT_EQ(platform_source_ptr->max_requested_width(), 640);
EXPECT_EQ(platform_source_ptr->max_requested_height(), 480);
// ... 其他相关的断言
```

**用户或编程常见的使用错误举例:**

1. **在轨道停止后尝试应用约束:** 用户可能会在调用 `videoTrack.stop()` 后尝试调用 `videoTrack.applyConstraints()`。测试可能会验证这种情况下的行为，例如，约束是否会被忽略或抛出错误。

2. **提供无法满足的约束:** 用户可能会提供设备无法支持的约束，例如请求一个远超摄像头能力的帧率或分辨率。测试会验证 `applyConstraints()` 在这种情况下是否会拒绝 Promise 或者选择最接近的可用设置。

3. **假设约束会立即生效:**  `applyConstraints()` 返回一个 Promise，表示异步操作。用户可能会错误地认为约束会立即生效，并在 Promise 完成之前就进行后续操作。测试可以验证异步操作的正确性。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个使用 WebRTC 的网页:** 用户访问一个需要访问摄像头或麦克风的网站，例如视频会议应用。
2. **网页 JavaScript 调用 `getUserMedia()`:** 网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 来请求访问用户的媒体设备。
3. **浏览器创建 `MediaStreamTrack` 对象:**  如果用户授权访问，浏览器会创建 `MediaStreamTrackImpl` 的实例来代表音视频轨道。
4. **用户操作触发 JavaScript 方法调用:** 用户在网页上执行某些操作，例如点击 "静音" 按钮或更改视频分辨率设置，这会导致 JavaScript 代码调用 `videoTrack.stop()`, 设置 `videoTrack.muted` 属性，或调用 `videoTrack.applyConstraints()`。
5. **Blink 引擎执行相应的 C++ 代码:**  这些 JavaScript 方法调用最终会映射到 Blink 引擎中 `MediaStreamTrackImpl` 类的相应方法执行。
6. **如果出现问题，开发者可能会查看 `media_stream_track_impl_test.cc`:**  当开发者在调试 WebRTC 相关问题时，他们可能会查看这个测试文件来理解 `MediaStreamTrackImpl` 的预期行为，并编写新的测试来重现和修复 bug。他们可能会在 `MediaStreamTrackImpl` 的方法中设置断点，例如 `stopTrack()`, `setMuted()`, 或 `applyConstraints()`, 来跟踪代码执行流程。

**归纳一下它的功能 (第1部分):**

这个测试文件主要负责验证 `MediaStreamTrackImpl` 类中与**生命周期管理 (停止)**、**状态管理 (静音)** 和**基本操作 (克隆)** 相关的核心功能是否按照预期工作。它确保了这些基本操作的正确性和稳定性，为更复杂的媒体流处理功能奠定了基础。在第2部分中，很可能会继续测试 `MediaStreamTrackImpl` 的其他方面，例如事件处理、数据处理等。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_track_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"

#include <tuple>

#include "base/run_loop.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/scoped_feature_list.h"
#include "media/base/video_frame.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_constrain_long_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_constrainlongrange_long.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_reader.h"
#include "third_party/blink/renderer/modules/mediastream/apply_constraints_processor.h"
#include "third_party/blink/renderer/modules/mediastream/local_media_stream_audio_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_content.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

using testing::_;

namespace blink {

namespace {
const gfx::Size kTestScreenSize{kDefaultScreenCastWidth,
                                kDefaultScreenCastHeight};
constexpr int kReducedWidth = 640;
constexpr int kReducedHeight = 320;
constexpr float kAspectRatio = kReducedWidth / kReducedHeight;
constexpr float kMaxFrameRate = 11.0f;
constexpr float kMinFrameRate = 0.0f;

class TestObserver : public GarbageCollected<TestObserver>,
                     public MediaStreamTrack::Observer {
 public:
  void TrackChangedState() override { observation_count_++; }
  int ObservationCount() const { return observation_count_; }

 private:
  int observation_count_ = 0;
};

std::unique_ptr<MockMediaStreamVideoSource> MakeMockMediaStreamVideoSource() {
  return base::WrapUnique(new MockMediaStreamVideoSource(
      media::VideoCaptureFormat(gfx::Size(640, 480), 30.0,
                                media::PIXEL_FORMAT_I420),
      true));
}

std::unique_ptr<blink::LocalMediaStreamAudioSource>
MakeLocalMediaStreamAudioSource() {
  blink::MediaStreamDevice device;
  device.type = blink::mojom::MediaStreamType::DEVICE_AUDIO_CAPTURE;
  return std::make_unique<blink::LocalMediaStreamAudioSource>(
      /*blink::WebLocalFrame=*/nullptr, device,
      /*requested_buffer_size=*/nullptr,
      /*disable_local_echo=*/false,
      /*enable_system_echo_cancellation=*/false,
      blink::WebPlatformMediaStreamSource::ConstraintsRepeatingCallback(),
      blink::scheduler::GetSingleThreadTaskRunnerForTesting());
}

MediaStreamComponent* MakeMockVideoComponent() {
  std::unique_ptr<MockMediaStreamVideoSource> platform_source =
      MakeMockMediaStreamVideoSource();
  MockMediaStreamVideoSource* platform_source_ptr = platform_source.get();
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeVideo, "name",
      /*remote=*/false, std::move(platform_source));
  return MakeGarbageCollected<MediaStreamComponentImpl>(
      source, std::make_unique<MediaStreamVideoTrack>(
                  platform_source_ptr,
                  MediaStreamVideoSource::ConstraintsOnceCallback(),
                  /*enabled=*/true));
}

MediaStreamComponent* MakeMockAudioComponent() {
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeAudio, "name",
      /*remote=*/false, MakeLocalMediaStreamAudioSource());
  auto platform_track =
      std::make_unique<MediaStreamAudioTrack>(true /* is_local_track */);
  return MakeGarbageCollected<MediaStreamComponentImpl>(
      source, std::move(platform_track));
}

media::VideoCaptureFormat GetDefaultVideoContentCaptureFormat() {
  MediaConstraints constraints;
  constraints.Initialize();
  return blink::SelectSettingsVideoContentCapture(
             constraints, mojom::MediaStreamType::DISPLAY_VIDEO_CAPTURE,
             kTestScreenSize.width(), kTestScreenSize.height())
      .Format();
}

std::tuple<MediaStreamComponent*, MockMediaStreamVideoSource*>
MakeMockDisplayVideoCaptureComponent() {
  auto platform_source = std::make_unique<MockMediaStreamVideoSource>(
      GetDefaultVideoContentCaptureFormat(), false);
  platform_source->SetDevice(
      MediaStreamDevice(mojom::MediaStreamType::DISPLAY_VIDEO_CAPTURE,
                        "fakeSourceId", "fakeWindowCapturer"));
  MockMediaStreamVideoSource* platform_source_ptr = platform_source.get();
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeVideo, "name",
      false /* remote */, std::move(platform_source));
  auto platform_track = std::make_unique<MediaStreamVideoTrack>(
      platform_source_ptr,
      WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      true /* enabled */);
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>(source,
                                                     std::move(platform_track));
  return std::make_tuple(component, platform_source_ptr);
}

MediaTrackConstraints* MakeMediaTrackConstraints(
    std::optional<int> exact_width,
    std::optional<int> exact_height,
    std::optional<float> min_frame_rate,
    std::optional<float> max_frame_rate,
    std::optional<float> aspect_ratio = std::nullopt) {
  MediaConstraints constraints;
  MediaTrackConstraintSetPlatform basic;
  if (exact_width) {
    basic.width.SetExact(*exact_width);
  }
  if (exact_height) {
    basic.height.SetExact(*exact_height);
  }
  if (min_frame_rate) {
    basic.frame_rate.SetMin(*min_frame_rate);
  }
  if (max_frame_rate) {
    basic.frame_rate.SetMax(*max_frame_rate);
  }
  if (aspect_ratio) {
    basic.aspect_ratio.SetExact(*aspect_ratio);
  }

  constraints.Initialize(basic, Vector<MediaTrackConstraintSetPlatform>());
  return media_constraints_impl::ConvertConstraints(constraints);
}

}  // namespace

class MediaStreamTrackImplTest : public testing::Test {
 public:
  ~MediaStreamTrackImplTest() override {
    WebHeap::CollectAllGarbageForTesting();
  }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
};

TEST_F(MediaStreamTrackImplTest, StopTrackTriggersObservers) {
  V8TestingScope v8_scope;
  std::unique_ptr<MockMediaStreamVideoSource> platform_source =
      MakeMockMediaStreamVideoSource();
  MockMediaStreamVideoSource* platform_source_ptr = platform_source.get();
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeVideo, "name",
      /*remote=*/false, std::move(platform_source));
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>(
          source, std::make_unique<MediaStreamVideoTrack>(
                      platform_source_ptr,
                      MediaStreamVideoSource::ConstraintsOnceCallback(),
                      /*enabled=*/true));
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  TestObserver* testObserver = MakeGarbageCollected<TestObserver>();
  track->AddObserver(testObserver);

  source->SetReadyState(MediaStreamSource::kReadyStateMuted);
  EXPECT_EQ(testObserver->ObservationCount(), 1);

  track->stopTrack(v8_scope.GetExecutionContext());
  EXPECT_EQ(testObserver->ObservationCount(), 2);
}

TEST_F(MediaStreamTrackImplTest, StopTrackSynchronouslyDisablesMedia) {
  V8TestingScope v8_scope;

  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeAudio, "name",
      /*remote=*/false, MakeMockMediaStreamVideoSource());
  auto platform_track =
      std::make_unique<MediaStreamAudioTrack>(true /* is_local_track */);
  MediaStreamAudioTrack* platform_track_ptr = platform_track.get();
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>(source,
                                                     std::move(platform_track));
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  ASSERT_TRUE(platform_track_ptr->IsEnabled());
  track->stopTrack(v8_scope.GetExecutionContext());
  EXPECT_FALSE(platform_track_ptr->IsEnabled());
}

TEST_F(MediaStreamTrackImplTest, MutedStateUpdates) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockMediaStreamVideoSource> platform_source =
      MakeMockMediaStreamVideoSource();
  MockMediaStreamVideoSource* platform_source_ptr = platform_source.get();
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeVideo, "name",
      /*remote=*/false, std::move(platform_source));
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>(
          source, std::make_unique<MediaStreamVideoTrack>(
                      platform_source_ptr,
                      MediaStreamVideoSource::ConstraintsOnceCallback(),
                      /*enabled=*/true));
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  EXPECT_EQ(track->muted(), false);

  source->SetReadyState(MediaStreamSource::kReadyStateMuted);
  EXPECT_EQ(track->muted(), true);

  source->SetReadyState(MediaStreamSource::kReadyStateLive);
  EXPECT_EQ(track->muted(), false);
}

TEST_F(MediaStreamTrackImplTest, MutedDoesntUpdateAfterEnding) {
  V8TestingScope v8_scope;
  std::unique_ptr<MockMediaStreamVideoSource> platform_source =
      MakeMockMediaStreamVideoSource();
  MockMediaStreamVideoSource* platform_source_ptr = platform_source.get();
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeVideo, "name",
      false /* remote */, std::move(platform_source));
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>(
          source, std::make_unique<MediaStreamVideoTrack>(
                      platform_source_ptr,
                      MediaStreamVideoSource::ConstraintsOnceCallback(),
                      /*enabled=*/true));
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  ASSERT_EQ(track->muted(), false);

  track->stopTrack(v8_scope.GetExecutionContext());

  source->SetReadyState(MediaStreamSource::kReadyStateMuted);

  EXPECT_EQ(track->muted(), false);
}

TEST_F(MediaStreamTrackImplTest, CloneVideoTrack) {
  V8TestingScope v8_scope;
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), MakeMockVideoComponent());

  MediaStreamTrack* clone = track->clone(v8_scope.GetExecutionContext());

  // The clone should have a component initialized with a MediaStreamVideoTrack
  // instance as its platform track.
  EXPECT_TRUE(clone->Component()->GetPlatformTrack());
  EXPECT_TRUE(MediaStreamVideoTrack::From(clone->Component()));

  // Clones should share the same source object.
  EXPECT_EQ(clone->Component()->Source(), track->Component()->Source());
}

TEST_F(MediaStreamTrackImplTest, CloneAudioTrack) {
  V8TestingScope v8_scope;

  MediaStreamComponent* component = MakeMockAudioComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  MediaStreamTrack* clone = track->clone(v8_scope.GetExecutionContext());

  // The clone should have a component initialized with a MediaStreamAudioTrack
  // instance as its platform track.
  EXPECT_TRUE(clone->Component()->GetPlatformTrack());
  EXPECT_TRUE(MediaStreamAudioTrack::From(clone->Component()));

  // Clones should share the same source object.
  EXPECT_EQ(clone->Component()->Source(), component->Source());
}

TEST_F(MediaStreamTrackImplTest, CloningPreservesConstraints) {
  V8TestingScope v8_scope;

  auto platform_source = std::make_unique<MockMediaStreamVideoSource>(
      media::VideoCaptureFormat(gfx::Size(1280, 720), 1000.0,
                                media::PIXEL_FORMAT_I420),
      false);
  MockMediaStreamVideoSource* platform_source_ptr = platform_source.get();
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "id", MediaStreamSource::StreamType::kTypeVideo, "name",
      false /* remote */, std::move(platform_source));
  auto platform_track = std::make_unique<MediaStreamVideoTrack>(
      platform_source_ptr,
      WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      true /* enabled */);
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>(source,
                                                     std::move(platform_track));
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

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

TEST_F(MediaStreamTrackImplTest, ApplyConstraintsUpdatesSourceFormat) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);
  MediaStreamVideoTrack* video_track = MediaStreamVideoTrack::From(component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Verify that initial settings are not the same as the constraints.
  EXPECT_NE(platform_source_ptr->max_requested_width(), kReducedWidth);
  EXPECT_NE(platform_source_ptr->max_requested_height(), kReducedHeight);
  EXPECT_NE(platform_source_ptr->max_requested_frame_rate(), kMaxFrameRate);
  EXPECT_FALSE(video_track->min_frame_rate());
  // Apply new frame rate constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      kReducedWidth, kReducedHeight, kMinFrameRate, kMaxFrameRate);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify updated settings and that the source was restarted.
  EXPECT_EQ(platform_source_ptr->restart_count(), 1);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), kReducedWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(), kReducedHeight);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), kMaxFrameRate);
  // Verify that min frame rate is updated.
  EXPECT_EQ(video_track->min_frame_rate(), kMinFrameRate);
}

TEST_F(MediaStreamTrackImplTest,
       ApplyConstraintsFramerateDoesNotAffectResolution) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Get initial settings and verify that initial frame rate is not same as the
  // new constraint.
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  EXPECT_NE(initialFrameRate, kMaxFrameRate);
  // Apply new frame rate constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      std::nullopt, std::nullopt, kMinFrameRate, kMaxFrameRate);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify updated settings and that the source was restarted.
  EXPECT_EQ(platform_source_ptr->restart_count(), 1);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), initialWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(), initialHeight);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), kMaxFrameRate);
}

TEST_F(MediaStreamTrackImplTest,
       ApplyConstraintsResolutionDoesNotAffectFramerate) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Get initial settings and verify that the initial resolution is not the same
  // as the new constraint.
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  EXPECT_NE(initialWidth, kReducedWidth);
  EXPECT_NE(initialHeight, kReducedHeight);
  // Apply new frame rate constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      kReducedWidth, kReducedHeight, std::nullopt, std::nullopt);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify updated settings and that the source was restarted.
  EXPECT_EQ(platform_source_ptr->restart_count(), 1);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), kReducedWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(), kReducedHeight);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), initialFrameRate);
}

TEST_F(MediaStreamTrackImplTest,
       ApplyConstraintsWidthDoesNotAffectAspectRatio) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Get initial settings and verify that the initial resolution is not the same
  // as the new constraint.
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  EXPECT_NE(initialWidth, kReducedWidth);
  EXPECT_NE(initialHeight, kReducedHeight);
  // Apply new frame rate constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      kReducedWidth, std::nullopt, std::nullopt, std::nullopt);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify updated settings and that the source was restarted.
  EXPECT_EQ(platform_source_ptr->restart_count(), 1);
  float aspect_ratio =
      static_cast<float>(initialWidth) / static_cast<float>(initialHeight);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), kReducedWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(),
            kReducedWidth / aspect_ratio);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), initialFrameRate);
}

TEST_F(MediaStreamTrackImplTest, ApplyConstraintsWidthAndAspectRatio) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Get initial settings and verify that the initial resolution is not the same
  // as the new constraint.
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  EXPECT_NE(initialWidth, kReducedWidth);
  EXPECT_NE(initialHeight, kReducedHeight);
  // Apply new frame rate constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      kReducedWidth, std::nullopt, std::nullopt, std::nullopt, kAspectRatio);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify updated settings and that the source was restarted.
  EXPECT_EQ(platform_source_ptr->restart_count(), 1);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), kReducedWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(),
            kReducedWidth / kAspectRatio);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), initialFrameRate);
}

// cropTo() is not supported on Android.
#if BUILDFLAG(IS_ANDROID)
#define MAYBE_ApplyConstraintsDoesNotUpdateFormatForCroppedSources \
  DISABLED_ApplyConstraintsDoesNotUpdateFormatForCroppedSources
#else
#define MAYBE_ApplyConstraintsDoesNotUpdateFormatForCroppedSources \
  ApplyConstraintsDoesNotUpdateFormatForCroppedSources
#endif

TEST_F(MediaStreamTrackImplTest,
       MAYBE_ApplyConstraintsDoesNotUpdateFormatForCroppedSources) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Get initial settings and verify that resolution and frame rate are
  // different than the new constraints.
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  EXPECT_NE(initialWidth, kReducedWidth);
  EXPECT_NE(initialHeight, kReducedHeight);
  EXPECT_NE(initialFrameRate, kMaxFrameRate);
  // Apply new constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      kReducedWidth, kReducedHeight, kMinFrameRate, kMaxFrameRate);
  EXPECT_CALL(*platform_source_ptr, GetSubCaptureTargetVersion)
      .WillRepeatedly(testing::Return(1));
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify that the settings are not updated and that the source was not
  // restarted.
  EXPECT_EQ(platform_source_ptr->restart_count(), 0);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), initialWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(), initialHeight);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), initialFrameRate);
}

TEST_F(MediaStreamTrackImplTest,
       ApplyConstraintsDoesNotUpdateSourceFormatIfDisabled) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      // Enabled features.
      {},
      // Disabled features.
      {kApplyConstraintsRestartsVideoContentSources});

  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Get initial settings and verify that resolution and frame rate are
  // different than the new constraints.
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  EXPECT_NE(initialWidth, kReducedWidth);
  EXPECT_NE(initialHeight, kReducedHeight);
  EXPECT_NE(initialFrameRate, kMaxFrameRate);
  // Apply new constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      kReducedWidth, kReducedHeight, kMinFrameRate, kMaxFrameRate);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify that the settings are not updated and that the source was not
  // restarted.
  EXPECT_EQ(platform_source_ptr->restart_count(), 0);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), initialWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(), initialHeight);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), initialFrameRate);
}

TEST_F(MediaStreamTrackImplTest, ApplyConstraintsWithUnchangedConstraints) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Get initial settings
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  // Apply new constraints that are fulfilled by the current settings.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      initialWidth, initialHeight, initialFrameRate, initialFrameRate);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify that the settings are the same and that the source did not restart.
  EXPECT_EQ(platform_source_ptr->restart_count(), 0);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), initialWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(), initialHeight);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), initialFrameRate);
}

TEST_F(MediaStreamTrackImplTest, ApplyConstraintsCannotRestartSource) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);

  // Start the source.
  platform_source_ptr->DisableStopForRestart();
  platform_source_ptr->StartMockedSource();
  // Get initial settings and verify that resolution and frame rate are
  // different than the new constraints.
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  EXPECT_NE(initialWidth, kReducedWidth);
  EXPECT_NE(initialHeight, kReducedHeight);
  EXPECT_NE(initialFrameRate, kMaxFrameRate);
  // Apply new constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      kReducedWidth, kReducedHeight, kMinFrameRate, kMaxFrameRate);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);

  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  // Verify that the settings are not updated and that the source was not
  // restarted.
  EXPECT_EQ(platform_source_ptr->restart_count(), 0);
  EXPECT_EQ(platform_source_ptr->max_requested_width(), initialWidth);
  EXPECT_EQ(platform_source_ptr->max_requested_height(), initialHeight);
  EXPECT_EQ(platform_source_ptr->max_requested_frame_rate(), initialFrameRate);
}

TEST_F(MediaStreamTrackImplTest, ApplyConstraintsUpdatesMinFps) {
  V8TestingScope v8_scope;
  MediaStreamComponent* component;
  MockMediaStreamVideoSource* platform_source_ptr;
  std::tie(component, platform_source_ptr) =
      MakeMockDisplayVideoCaptureComponent();
  MediaStreamTrack* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(), component);
  MediaStreamVideoTrack* video_track = MediaStreamVideoTrack::From(component);

  // Start the source.
  platform_source_ptr->StartMockedSource();
  // Get initial settings and verify that resolution and frame rate are
  // different than the new constraints.
  int initialWidth = platform_source_ptr->max_requested_width();
  int initialHeight = platform_source_ptr->max_requested_height();
  float initialFrameRate = platform_source_ptr->max_requested_frame_rate();
  // Min frame rate not set.
  EXPECT_FALSE(video_track->min_frame_rate());

  // Apply new constraints.
  MediaTrackConstraints* track_constraints = MakeMediaTrackConstraints(
      std::nullopt, std::nullopt, kMinFrameRate, initialFrameRate);
  auto apply_constraints_promise =
      track->applyConstraints(v8_scope.GetScriptState(), track_constraints);
  ScriptPromiseTester tester(v8_scope.GetScriptState(),
                             apply_constraints_promise);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulf
```