Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the Chromium Blink engine's media stream implementation.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The filename `user_media_client_test.cc` and the `TEST_F` macros indicate this is a unit test file. The tests focus on `UserMediaClient`, suggesting it tests the logic for requesting and managing user media (camera and microphone).

2. **Analyze the Test Cases:** Go through each `TEST_F` block and understand what it's testing. Look for keywords like "Generate", "Stop", "Fail", "Load", "Constraints", "ApplyConstraints", and "Histograms".

3. **Group Related Tests:**  Combine similar tests into functional categories. For instance, tests involving `GenerateMediaStream` are about creating media streams. Tests involving `StopLocalTracks` are about stopping media tracks.

4. **Identify Interactions with Web Technologies:**  Consider how the tested functionality relates to JavaScript, HTML, and CSS. User media access is a core web API feature (`getUserMedia`), so the connection is strong.

5. **Look for Logical Reasoning:**  Tests that compare the behavior of creating multiple streams with the same or different sources involve logical deduction.

6. **Spot Potential User Errors:**  Tests that simulate failures (e.g., `MediaVideoSourceFailToStart`) can highlight common user or programming errors.

7. **Trace User Operations (Debugging Angle):**  Think about how a user action in a browser could trigger the code being tested. This involves the `getUserMedia` API.

8. **Address the "Part 2" Request:**  Focus on the functionality covered specifically in this snippet and avoid repeating information from previous parts.

9. **Structure the Summary:**  Organize the findings into logical sections: main functionalities, connections to web technologies, logical reasoning, user errors, debugging, and the overall summary for part 2.

**Pre-computation and Pre-analysis (Internal "Sandbox"):**

* **`MediaStreamDescriptor`:** This class likely represents the object returned by `getUserMedia` containing audio and video tracks.
* **`MediaStreamTrackPlatform`:** Represents the underlying platform-specific implementation of a media track.
* **`UserMediaClient`:** The central class being tested, responsible for handling user media requests.
* **`UserMediaProcessor`:** Likely handles the actual processing of the media request, including device selection and stream creation.
* **`mock_dispatcher_host_`:** A mock object used for testing interactions with lower-level components (like the browser process). The counters (`stop_audio_device_counter`, `stop_video_device_counter`, `request_stream_counter`) are crucial for verifying behavior.
* **Constraints:** Tests involving "Constraints" directly relate to the options passed to `getUserMedia` in JavaScript.

**Drafting and Refinement:**

Initial drafts might list each test individually. The refinement stage involves grouping similar tests and summarizing their purpose more concisely. For example, instead of saying "Test X generates a stream, Test Y generates another stream with the same source...", summarize it as "Tests the generation of media streams, including scenarios with the same and different sources."

The request to provide input and output for logical reasoning requires careful consideration of the test setup. The input is the sequence of `RequestLocalMediaStream` calls and the state of `mock_dispatcher_host_`. The output is the comparison of the `Source` objects of the resulting media tracks.

For user errors, the failure scenarios are direct examples. A user might grant permission, but the camera might fail to start due to a hardware issue, which is what the `MediaVideoSourceFailToStart` test simulates.

Finally, the debugging section needs to link the code to actual user interaction within a web page. The `getUserMedia` call in JavaScript is the starting point.

By following these steps, the detailed and organized summary provided as the model answer can be constructed.
这是`blink/renderer/modules/mediastream/user_media_client_test.cc` 文件的第二部分，主要功能是**测试 `UserMediaClient` 在不同场景下管理本地媒体流（摄像头和麦克风）的行为，特别是关注媒体流的生命周期管理和约束的应用。**

以下是针对其功能的详细说明，并结合了与 JavaScript, HTML, CSS 的关系进行举例说明：

**主要功能归纳：**

* **测试停止本地媒体轨道 (StopLocalTracks):**
    * 验证当通过 JavaScript 获取的媒体流中的轨道（例如摄像头或麦克风的轨道）被停止时，底层的设备资源是否被正确释放。
    * 测试了在单个媒体流中停止音视频轨道的情况，以及在两个共享相同设备的媒体流中停止轨道的情况，验证了只有当所有使用该设备的轨道都停止后，设备才会被真正停止。
* **测试当媒体流超出作用域时停止源 (StopSourceWhenMediaStreamGoesOutOfScope):**
    * 模拟 JavaScript 中创建的 `MediaStream` 对象不再被引用（例如，变量被设置为 `null` 或函数执行完毕），并通过垃圾回收来验证底层的音视频源是否会被自动停止。
* **测试在帧中加载新文档时删除媒体流 (LoadNewDocumentInFrame):**
    * 模拟用户在浏览器中导航到新页面或刷新当前页面，验证之前通过 `getUserMedia` 获取的媒体流是否会被清理，并且底层的设备资源会被释放。
* **测试媒体源启动失败的情况 (MediaVideoSourceFailToStart, MediaAudioSourceFailToInitialize):**
    * 模拟摄像头或麦克风启动失败的情况（例如，设备被禁用或发生错误），验证 `UserMediaClient` 是否能正确处理这些错误，并通知上层 (可能通过 Promise 的 reject 回调)。
* **测试 `UserMediaClient` 在源启动前关闭 (MediaStreamImplShutDown):**
    * 模拟在 `getUserMedia` 请求正在进行中但设备尚未启动时，`UserMediaClient` 对象被销毁的情况，验证是否能避免资源泄漏或崩溃。
* **测试在生成媒体流过程中重新加载帧 (ReloadFrameWhileGeneratingStream):**
    * 模拟在 `getUserMedia` 请求正在处理中，但尚未完成（例如，用户还未授权或设备正在初始化）时，用户刷新页面的情况，验证请求是否会被正确取消，资源是否会被释放。
* **测试在源启动过程中重新加载帧 (ReloadFrameWhileGeneratingSources):**
    * 模拟在 `getUserMedia` 请求已获得授权，但音视频源正在启动时，用户刷新页面的情况，验证资源释放是否正确。
* **测试在重新加载帧后停止轨道 (StopTrackAfterReload):**
    * 验证在页面重新加载后，尝试停止之前创建的媒体流轨道是否仍然能够正确释放底层设备资源。
* **测试默认约束的传播 (DefaultConstraintsPropagate):**
    * 验证当 JavaScript 调用 `getUserMedia` 时不提供任何约束条件时，Blink 引擎是否会应用默认的音视频约束设置，例如默认分辨率、帧率、音频处理等。
* **测试 Tab 捕捉和桌面捕捉的默认约束传播 (DefaultTabCapturePropagate, DefaultDesktopCapturePropagate):**
    * 验证当使用 `getDisplayMedia` API 进行屏幕或标签页共享时，Blink 引擎是否会应用针对屏幕共享的默认约束设置。
* **测试非默认音频约束的传播 (NonDefaultAudioConstraintsPropagate):**
    * 验证当 JavaScript 调用 `getUserMedia` 时提供了特定的音频约束条件（例如，指定的设备 ID，是否禁用本地回声）时，这些约束是否会被正确地传递和应用。
* **测试使用强制的无效设备 ID 创建媒体流 (CreateWithMandatoryInvalidAudioDeviceId, CreateWithMandatoryInvalidVideoDeviceId):**
    * 验证当 JavaScript 调用 `getUserMedia` 并强制指定一个不存在的设备 ID 时，请求是否会失败并返回错误。
* **测试使用强制的有效设备 ID 创建媒体流 (CreateWithMandatoryValidDeviceIds):**
    * 验证当 JavaScript 调用 `getUserMedia` 并强制指定有效的设备 ID 时，请求是否能够成功。
* **测试使用理想的有效设备 ID 创建媒体流 (CreateWithBasicIdealValidDeviceId):**
    * 验证当 JavaScript 调用 `getUserMedia` 并提供理想的设备 ID 时，Blink 引擎是否会选择该设备（如果可用）。
* **测试使用高级精确的有效设备 ID 创建媒体流 (CreateWithAdvancedExactValidDeviceId):**
    * 验证当 JavaScript 调用 `getUserMedia` 并通过高级约束精确指定设备 ID 时，Blink 引擎是否会选择该设备。
* **测试使用所有可选的无效设备 ID 创建媒体流 (CreateWithAllOptionalInvalidDeviceId):**
    * 验证当 JavaScript 调用 `getUserMedia` 并提供了可选的但无效的设备 ID 时，Blink 引擎如何处理，通常会回退到默认设备。
* **测试使用 `facingMode` 创建媒体流 (CreateWithFacingModeUser, CreateWithFacingModeEnvironment):**
    * 验证当 JavaScript 调用 `getUserMedia` 并指定 `facingMode` 约束（例如，"user" 代表前置摄像头，"environment" 代表后置摄像头）时，Blink 引擎是否会选择符合条件的摄像头。
* **测试应用约束到单个视频轨道 (ApplyConstraintsVideoDeviceSingleTrack):**
    * 验证当通过 JavaScript 的 `MediaStreamTrack.applyConstraints()` 方法动态修改视频轨道的约束时，底层的视频源是否会按照新的约束进行调整，例如更改分辨率和帧率。
* **测试摄像头捕获能力直方图 (CameraCaptureCapabilityHistograms):**
    * 验证 Blink 引擎是否会收集用户摄像头设备的捕获能力信息（例如，支持的分辨率），并将其记录到直方图中用于分析。
* **测试应用约束到两个视频轨道 (ApplyConstraintsVideoDeviceTwoTracks):**
    * 验证当多个视频轨道共享同一个视频源时，应用约束到一个轨道上会如何影响其他轨道，通常情况下，所有共享同一源的轨道都会受到影响。

**与 JavaScript, HTML, CSS 的关系举例：**

1. **`GenerateMediaStream`:**  这个测试模拟了 JavaScript 中调用 `navigator.mediaDevices.getUserMedia()`  并成功返回 `MediaStream` 对象的情况。
   ```javascript
   navigator.mediaDevices.getUserMedia({ audio: true, video: true })
     .then(function(stream) {
       // stream 是一个 MediaStream 对象
     })
     .catch(function(err) {
       // 处理错误
     });
   ```

2. **`StopLocalTracks`:**  这个测试模拟了 JavaScript 中调用 `MediaStreamTrack.stop()` 方法来停止媒体轨道。
   ```javascript
   navigator.mediaDevices.getUserMedia({ audio: true, video: true })
     .then(function(stream) {
       let audioTrack = stream.getAudioTracks()[0];
       audioTrack.stop(); // 停止音频轨道
       let videoTrack = stream.getVideoTracks()[0];
       videoTrack.stop(); // 停止视频轨道
     });
   ```

3. **`LoadNewDocumentInFrame`:** 这个测试模拟了用户在浏览器中点击链接或通过 JavaScript 跳转到新的 HTML 页面。

4. **`MediaVideoSourceFailToStart`:**  当摄像头无法启动时，`getUserMedia()` 的 Promise 会被 reject，并传递一个错误对象。
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .catch(function(err) {
       console.error("摄像头启动失败:", err);
     });
   ```

5. **`DefaultConstraintsPropagate`:**  以下 JavaScript 代码会触发默认约束的传播。
   ```javascript
   navigator.mediaDevices.getUserMedia({ audio: true, video: true }); // 没有提供具体的约束
   ```

6. **`NonDefaultAudioConstraintsPropagate`:**  以下 JavaScript 代码提供了非默认的音频约束。
   ```javascript
   navigator.mediaDevices.getUserMedia({
     audio: { deviceId: "specific-audio-device-id" }
   });
   ```

7. **`ApplyConstraintsVideoDeviceSingleTrack`:**  以下 JavaScript 代码会应用约束到视频轨道。
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(function(stream) {
       let videoTrack = stream.getVideoTracks()[0];
       videoTrack.applyConstraints({ width: 1024, height: 768 });
     });
   ```

**逻辑推理的假设输入与输出：**

* **`GenerateTwoMediaStreamsWithSameSource`:**
    * **假设输入:**  连续两次调用 `RequestLocalMediaStream()`，并且 `mock_dispatcher_host_.SetAppendSessionIdToDeviceIds(true)` 被设置，这意味着同一次会话会使用相同的设备 ID。
    * **预期输出:**  两次调用返回的 `MediaStreamDescriptor` 中的音视频 `Source` 对象（`MediaStreamVideoSource`, `MediaStreamAudioSource`) 是相同的。

* **`GenerateTwoMediaStreamsWithDifferentSources`:**
    * **假设输入:**  第一次调用 `RequestLocalMediaStream()`，然后调用 `mock_dispatcher_host_.ResetSessionId()` 来模拟切换设备，之后再次调用 `RequestLocalMediaStream()`。
    * **预期输出:**  两次调用返回的 `MediaStreamDescriptor` 中的音视频 `Source` 对象是不同的。

**涉及用户或编程常见的使用错误举例：**

* **未处理 `getUserMedia` 的 Promise reject:** 如果用户拒绝权限或设备不可用，`getUserMedia` 的 Promise 会被 reject。开发者需要正确处理这种情况，否则可能会导致应用功能异常。
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(function(stream) {
       // 使用 stream
     })
     .catch(function(err) {
       console.error("获取媒体失败:", err); // 正确处理错误
       // 可以向用户显示提示信息
     });
   ```

* **在轨道停止后尝试使用它:**  一旦 `MediaStreamTrack.stop()` 被调用，该轨道就不能再使用了。尝试访问其数据或应用约束会导致错误。

* **忘记在不再需要时停止轨道:**  如果不主动停止媒体轨道，即使 `MediaStream` 对象不再被引用，底层的设备可能仍然在运行，导致资源浪费或隐私问题。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户打开一个网页:** 用户在浏览器中访问一个包含使用 `getUserMedia` API 的 JavaScript 代码的网页。
2. **JavaScript 代码请求用户媒体:** 网页中的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 请求访问用户的摄像头和/或麦克风。
3. **浏览器提示用户授权:** 浏览器会弹出一个权限请求提示，询问用户是否允许该网站访问其媒体设备。
4. **用户授权或拒绝:**
    * **授权:** 如果用户点击 "允许"，浏览器会将请求传递给 Blink 引擎的媒体栈。`UserMediaClient` 会被创建并处理这个请求，与底层的媒体设备进行交互。相关的测试用例就是模拟这个过程，验证 `UserMediaClient` 的行为是否符合预期。
    * **拒绝:** 如果用户点击 "拒绝"，`getUserMedia` 的 Promise 会被 reject，JavaScript 代码会收到错误信息。相关的测试用例可能会模拟用户拒绝的情况，验证错误处理逻辑。
5. **媒体流的生命周期管理:** 一旦 `MediaStream` 对象被创建，用户与网页的交互（例如，导航到其他页面，关闭标签页，或者 JavaScript 代码显式停止轨道）会触发媒体流的生命周期事件，而 `UserMediaClient` 负责管理这些事件，例如在页面卸载时停止设备。相关的测试用例会验证这些生命周期管理逻辑。
6. **应用约束:**  JavaScript 代码可能会使用 `applyConstraints()` 方法动态修改媒体流的约束，测试用例会验证这些约束是否被正确应用到硬件设备上。

**作为调试线索：** 当开发者在使用 `getUserMedia` API 时遇到问题（例如，摄像头无法启动，约束不生效，资源泄漏），他们可以参考 `user_media_client_test.cc` 中的测试用例，了解 Blink 引擎在各种场景下的预期行为，从而帮助他们定位问题。例如，如果开发者发现他们的网页在用户离开页面后摄像头指示灯仍然亮着，他们可以参考 `StopSourceWhenMediaStreamGoesOutOfScope` 和 `LoadNewDocumentInFrame` 等测试用例，检查他们的代码是否正确管理了媒体流的生命周期。

**这是第2部分的功能归纳：**

这部分测试主要关注 `UserMediaClient` 对本地媒体流的**生命周期管理**（创建、停止、页面卸载时的清理）以及对 **`getUserMedia` 请求中约束条件的处理和应用**。它验证了在各种场景下，`UserMediaClient` 是否能够正确地与底层媒体设备交互，并按照预期的方式管理资源和应用约束。特别是强调了在多轨道、多媒体流以及页面导航等复杂场景下的行为正确性。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/user_media_client_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
iaProcessorUnderTest> user_media_processor_;
  WeakPersistent<UserMediaProcessorUnderTest> display_user_media_processor_;
  Persistent<UserMediaClientUnderTest> user_media_client_impl_;
  RequestState state_ = kRequestNotStarted;
  raw_ptr<FakeDeviceIds> fake_ids_ = FakeDeviceIds::GetInstance();
};

TEST_F(UserMediaClientTest, GenerateMediaStream) {
  // Generate a stream with both audio and video.
  MediaStreamDescriptor* mixed_desc = RequestLocalMediaStream();
  EXPECT_TRUE(mixed_desc);
}

// Test that the same source object is used if two MediaStreams are generated
// using the same source.
TEST_F(UserMediaClientTest, GenerateTwoMediaStreamsWithSameSource) {
  mock_dispatcher_host_.SetAppendSessionIdToDeviceIds(true);
  MediaStreamDescriptor* desc1 = RequestLocalMediaStream();
  MediaStreamDescriptor* desc2 = RequestLocalMediaStream();

  auto desc1_video_components = desc1->VideoComponents();
  auto desc2_video_components = desc2->VideoComponents();
  EXPECT_EQ(desc1_video_components[0]->Source()->GetName(),
            desc2_video_components[0]->Source()->GetName());

  EXPECT_EQ(desc1_video_components[0]->Source()->GetPlatformSource(),
            desc2_video_components[0]->Source()->GetPlatformSource());

  auto desc1_audio_components = desc1->AudioComponents();
  auto desc2_audio_components = desc2->AudioComponents();
  EXPECT_EQ(desc1_audio_components[0]->Source()->GetName(),
            desc2_audio_components[0]->Source()->GetName());

  EXPECT_EQ(MediaStreamAudioSource::From(desc1_audio_components[0]->Source()),
            MediaStreamAudioSource::From(desc2_audio_components[0]->Source()));
}

// Test that the same source object is not used if two MediaStreams are
// generated using different sources.
TEST_F(UserMediaClientTest, GenerateTwoMediaStreamsWithDifferentSources) {
  mock_dispatcher_host_.SetAppendSessionIdToDeviceIds(true);
  MediaStreamDescriptor* desc1 = RequestLocalMediaStream();
  // Make sure another device is selected (another |session_id|) in  the next
  // gUM request.
  mock_dispatcher_host_.ResetSessionId();
  MediaStreamDescriptor* desc2 = RequestLocalMediaStream();

  auto desc1_video_components = desc1->VideoComponents();
  auto desc2_video_components = desc2->VideoComponents();
  EXPECT_NE(desc1_video_components[0]->Source()->GetName(),
            desc2_video_components[0]->Source()->GetName());

  EXPECT_NE(desc1_video_components[0]->Source()->GetPlatformSource(),
            desc2_video_components[0]->Source()->GetPlatformSource());

  auto desc1_audio_components = desc1->AudioComponents();
  auto desc2_audio_components = desc2->AudioComponents();
  EXPECT_NE(desc1_audio_components[0]->Source()->GetName(),
            desc2_audio_components[0]->Source()->GetName());

  EXPECT_NE(MediaStreamAudioSource::From(desc1_audio_components[0]->Source()),
            MediaStreamAudioSource::From(desc2_audio_components[0]->Source()));
}

TEST_F(UserMediaClientTest, StopLocalTracks) {
  // Generate a stream with both audio and video.
  MediaStreamDescriptor* mixed_desc = RequestLocalMediaStream();

  auto audio_components = mixed_desc->AudioComponents();
  MediaStreamTrackPlatform* audio_track = MediaStreamTrackPlatform::GetTrack(
      WebMediaStreamTrack(audio_components[0]));
  audio_track->Stop();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());

  auto video_components = mixed_desc->VideoComponents();
  MediaStreamTrackPlatform* video_track = MediaStreamTrackPlatform::GetTrack(
      WebMediaStreamTrack(video_components[0]));
  video_track->Stop();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());
}

// This test that a source is not stopped even if the tracks in a
// MediaStream is stopped if there are two MediaStreams with tracks using the
// same device. The source is stopped
// if there are no more MediaStream tracks using the device.
TEST_F(UserMediaClientTest, StopLocalTracksWhenTwoStreamUseSameDevices) {
  // Generate a stream with both audio and video.
  MediaStreamDescriptor* desc1 = RequestLocalMediaStream();
  MediaStreamDescriptor* desc2 = RequestLocalMediaStream();

  auto audio_components1 = desc1->AudioComponents();
  MediaStreamTrackPlatform* audio_track1 = MediaStreamTrackPlatform::GetTrack(
      WebMediaStreamTrack(audio_components1[0]));
  audio_track1->Stop();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, mock_dispatcher_host_.stop_audio_device_counter());

  auto audio_components2 = desc2->AudioComponents();
  MediaStreamTrackPlatform* audio_track2 = MediaStreamTrackPlatform::GetTrack(
      WebMediaStreamTrack(audio_components2[0]));
  audio_track2->Stop();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());

  auto video_components1 = desc1->VideoComponents();
  MediaStreamTrackPlatform* video_track1 = MediaStreamTrackPlatform::GetTrack(
      WebMediaStreamTrack(video_components1[0]));
  video_track1->Stop();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, mock_dispatcher_host_.stop_video_device_counter());

  auto video_components2 = desc2->VideoComponents();
  MediaStreamTrackPlatform* video_track2 = MediaStreamTrackPlatform::GetTrack(
      WebMediaStreamTrack(video_components2[0]));
  video_track2->Stop();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());
}

TEST_F(UserMediaClientTest, StopSourceWhenMediaStreamGoesOutOfScope) {
  // Generate a stream with both audio and video.
  RequestLocalMediaStream();
  // Makes sure the test itself don't hold a reference to the created
  // MediaStream.
  user_media_processor_->ClearLastGeneratedStream();
  blink::WebHeap::CollectAllGarbageForTesting();
  base::RunLoop().RunUntilIdle();

  // Expect the sources to be stopped when the MediaStream goes out of scope.
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());
}

// Test that the MediaStreams are deleted if a new document is loaded in the
// frame.
TEST_F(UserMediaClientTest, LoadNewDocumentInFrame) {
  // Test a stream with both audio and video.
  MediaStreamDescriptor* mixed_desc = RequestLocalMediaStream();
  EXPECT_TRUE(mixed_desc);
  MediaStreamDescriptor* desc2 = RequestLocalMediaStream();
  EXPECT_TRUE(desc2);
  LoadNewDocumentInFrame();
  WebHeap::CollectAllGarbageForTesting();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());
}

// This test what happens if a video source to a MediaSteam fails to start.
TEST_F(UserMediaClientTest, MediaVideoSourceFailToStart) {
  user_media_client_impl_->RequestUserMediaForTest();
  FailToStartMockedVideoSource();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(kRequestFailed, request_state());
  EXPECT_EQ(
      blink::mojom::blink::MediaStreamRequestResult::TRACK_START_FAILURE_VIDEO,
      user_media_processor_->error_reason());
  blink::WebHeap::CollectAllGarbageForTesting();
  EXPECT_EQ(1, mock_dispatcher_host_.request_stream_counter());
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());
}

// This test what happens if an audio source fail to initialize.
TEST_F(UserMediaClientTest, MediaAudioSourceFailToInitialize) {
  user_media_processor_->SetCreateSourceThatFails(true);
  user_media_client_impl_->RequestUserMediaForTest();
  StartMockedVideoSource(user_media_processor_);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(kRequestFailed, request_state());
  EXPECT_EQ(
      blink::mojom::blink::MediaStreamRequestResult::TRACK_START_FAILURE_AUDIO,
      user_media_processor_->error_reason());
  blink::WebHeap::CollectAllGarbageForTesting();
  EXPECT_EQ(1, mock_dispatcher_host_.request_stream_counter());
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());
}

// This test what happens if UserMediaClient is deleted before a source has
// started.
TEST_F(UserMediaClientTest, MediaStreamImplShutDown) {
  user_media_client_impl_->RequestUserMediaForTest();
  EXPECT_EQ(1, mock_dispatcher_host_.request_stream_counter());
  EXPECT_EQ(kRequestNotComplete, request_state());
  // TearDown() nulls out |user_media_client_impl_| and forces GC to garbage
  // collect it.
}

// This test what happens if a new document is loaded in the frame while the
// MediaStream is being generated by the blink::WebMediaStreamDeviceObserver.
TEST_F(UserMediaClientTest, ReloadFrameWhileGeneratingStream) {
  mock_dispatcher_host_.DoNotRunCallback();

  user_media_client_impl_->RequestUserMediaForTest();
  LoadNewDocumentInFrame();
  EXPECT_EQ(1, mock_dispatcher_host_.request_stream_counter());
  EXPECT_EQ(0, mock_dispatcher_host_.stop_audio_device_counter());
  EXPECT_EQ(0, mock_dispatcher_host_.stop_video_device_counter());
  EXPECT_EQ(kRequestNotComplete, request_state());
}

// This test what happens if a newdocument is loaded in the frame while the
// sources are being started.
TEST_F(UserMediaClientTest, ReloadFrameWhileGeneratingSources) {
  user_media_client_impl_->RequestUserMediaForTest();
  EXPECT_EQ(1, mock_dispatcher_host_.request_stream_counter());
  LoadNewDocumentInFrame();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());
  EXPECT_EQ(kRequestNotComplete, request_state());
}

// This test what happens if stop is called on a track after the frame has
// been reloaded.
TEST_F(UserMediaClientTest, StopTrackAfterReload) {
  MediaStreamDescriptor* mixed_desc = RequestLocalMediaStream();
  EXPECT_EQ(1, mock_dispatcher_host_.request_stream_counter());
  LoadNewDocumentInFrame();
  WebHeap::CollectAllGarbageForTesting();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());

  auto audio_components = mixed_desc->AudioComponents();
  MediaStreamTrackPlatform* audio_track = MediaStreamTrackPlatform::GetTrack(
      WebMediaStreamTrack(audio_components[0]));
  audio_track->Stop();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_audio_device_counter());

  auto video_components = mixed_desc->VideoComponents();
  MediaStreamTrackPlatform* video_track = MediaStreamTrackPlatform::GetTrack(
      WebMediaStreamTrack(video_components[0]));
  video_track->Stop();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, mock_dispatcher_host_.stop_video_device_counter());
}

TEST_F(UserMediaClientTest, DefaultConstraintsPropagate) {
  UserMediaRequest* request = UserMediaRequest::CreateForTesting(
      CreateDefaultConstraints(), CreateDefaultConstraints());
  user_media_client_impl_->RequestUserMediaForTest(request);
  blink::AudioCaptureSettings audio_capture_settings =
      user_media_processor_->AudioSettings();
  blink::VideoCaptureSettings video_capture_settings =
      user_media_processor_->VideoSettings();
  user_media_client_impl_->CancelUserMediaRequest(request);

  // Check default values selected by the constraints algorithm.
  EXPECT_TRUE(audio_capture_settings.HasValue());
  EXPECT_EQ(media::AudioDeviceDescription::kDefaultDeviceId,
            audio_capture_settings.device_id());
  EXPECT_TRUE(audio_capture_settings.disable_local_echo());
  EXPECT_FALSE(audio_capture_settings.render_to_associated_sink());

  const blink::AudioProcessingProperties& properties =
      audio_capture_settings.audio_processing_properties();
  EXPECT_EQ(EchoCancellationType::kEchoCancellationAec3,
            properties.echo_cancellation_type);
  EXPECT_TRUE(properties.auto_gain_control);
  EXPECT_TRUE(properties.noise_suppression);

  EXPECT_TRUE(video_capture_settings.HasValue());
  EXPECT_EQ(video_capture_settings.Width(),
            blink::MediaStreamVideoSource::kDefaultWidth);
  EXPECT_EQ(video_capture_settings.Height(),
            blink::MediaStreamVideoSource::kDefaultHeight);
  EXPECT_EQ(
      video_capture_settings.FrameRate(),
      static_cast<float>(blink::MediaStreamVideoSource::kDefaultFrameRate));
  EXPECT_EQ(video_capture_settings.ResolutionChangePolicy(),
            media::ResolutionChangePolicy::FIXED_RESOLUTION);
  EXPECT_FALSE(video_capture_settings.noise_reduction());
  EXPECT_FALSE(video_capture_settings.min_frame_rate().has_value());

  const blink::VideoTrackAdapterSettings& track_settings =
      video_capture_settings.track_adapter_settings();
  EXPECT_FALSE(track_settings.target_size().has_value());
  EXPECT_EQ(
      track_settings.min_aspect_ratio(),
      1.0 / static_cast<double>(blink::MediaStreamVideoSource::kDefaultHeight));
  EXPECT_EQ(track_settings.max_aspect_ratio(),
            static_cast<double>(blink::MediaStreamVideoSource::kDefaultWidth));
  EXPECT_EQ(track_settings.max_frame_rate(), std::nullopt);
}

TEST_F(UserMediaClientTest, DefaultTabCapturePropagate) {
  blink::MockConstraintFactory factory;
  factory.basic().media_stream_source.SetExact(kMediaStreamSourceTab);
  MediaConstraints audio_constraints = factory.CreateMediaConstraints();
  MediaConstraints video_constraints = factory.CreateMediaConstraints();
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(audio_constraints, video_constraints);
  user_media_client_impl_->RequestUserMediaForTest(request);
  blink::AudioCaptureSettings audio_capture_settings =
      UserMediaProcessorForDisplayCapture()->AudioSettings();
  blink::VideoCaptureSettings video_capture_settings =
      UserMediaProcessorForDisplayCapture()->VideoSettings();
  user_media_client_impl_->CancelUserMediaRequest(request);

  // Check default values selected by the constraints algorithm.
  EXPECT_TRUE(audio_capture_settings.HasValue());
  EXPECT_EQ(std::string(), audio_capture_settings.device_id());
  EXPECT_TRUE(audio_capture_settings.disable_local_echo());
  EXPECT_FALSE(audio_capture_settings.render_to_associated_sink());

  const blink::AudioProcessingProperties& properties =
      audio_capture_settings.audio_processing_properties();
  EXPECT_EQ(EchoCancellationType::kEchoCancellationDisabled,
            properties.echo_cancellation_type);
  EXPECT_FALSE(properties.auto_gain_control);
  EXPECT_FALSE(properties.noise_suppression);

  EXPECT_TRUE(video_capture_settings.HasValue());
  EXPECT_EQ(video_capture_settings.Width(), blink::kDefaultScreenCastWidth);
  EXPECT_EQ(video_capture_settings.Height(), blink::kDefaultScreenCastHeight);
  EXPECT_EQ(video_capture_settings.FrameRate(),
            blink::kDefaultScreenCastFrameRate);
  EXPECT_EQ(video_capture_settings.ResolutionChangePolicy(),
            media::ResolutionChangePolicy::FIXED_RESOLUTION);
  EXPECT_FALSE(video_capture_settings.noise_reduction());
  EXPECT_FALSE(video_capture_settings.min_frame_rate().has_value());
  EXPECT_FALSE(video_capture_settings.max_frame_rate().has_value());

  const blink::VideoTrackAdapterSettings& track_settings =
      video_capture_settings.track_adapter_settings();
  EXPECT_EQ(track_settings.target_width(), blink::kDefaultScreenCastWidth);
  EXPECT_EQ(track_settings.target_height(), blink::kDefaultScreenCastHeight);
  EXPECT_EQ(track_settings.min_aspect_ratio(),
            1.0 / blink::kMaxScreenCastDimension);
  EXPECT_EQ(track_settings.max_aspect_ratio(), blink::kMaxScreenCastDimension);
  EXPECT_EQ(track_settings.max_frame_rate(), std::nullopt);
}

TEST_F(UserMediaClientTest, DefaultDesktopCapturePropagate) {
  blink::MockConstraintFactory factory;
  factory.basic().media_stream_source.SetExact(kMediaStreamSourceDesktop);
  MediaConstraints audio_constraints = factory.CreateMediaConstraints();
  MediaConstraints video_constraints = factory.CreateMediaConstraints();
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(audio_constraints, video_constraints);
  user_media_client_impl_->RequestUserMediaForTest(request);
  blink::AudioCaptureSettings audio_capture_settings =
      UserMediaProcessorForDisplayCapture()->AudioSettings();
  blink::VideoCaptureSettings video_capture_settings =
      UserMediaProcessorForDisplayCapture()->VideoSettings();
  user_media_client_impl_->CancelUserMediaRequest(request);
  base::RunLoop().RunUntilIdle();

  // Check default values selected by the constraints algorithm.
  EXPECT_TRUE(audio_capture_settings.HasValue());
  EXPECT_EQ(std::string(), audio_capture_settings.device_id());
  EXPECT_FALSE(audio_capture_settings.disable_local_echo());
  EXPECT_FALSE(audio_capture_settings.render_to_associated_sink());

  const blink::AudioProcessingProperties& properties =
      audio_capture_settings.audio_processing_properties();
  EXPECT_EQ(EchoCancellationType::kEchoCancellationDisabled,
            properties.echo_cancellation_type);
  EXPECT_FALSE(properties.auto_gain_control);
  EXPECT_FALSE(properties.noise_suppression);

  EXPECT_TRUE(video_capture_settings.HasValue());
  EXPECT_EQ(video_capture_settings.Width(), blink::kDefaultScreenCastWidth);
  EXPECT_EQ(video_capture_settings.Height(), blink::kDefaultScreenCastHeight);
  EXPECT_EQ(video_capture_settings.FrameRate(),
            blink::kDefaultScreenCastFrameRate);
  EXPECT_EQ(video_capture_settings.ResolutionChangePolicy(),
            media::ResolutionChangePolicy::ANY_WITHIN_LIMIT);
  EXPECT_FALSE(video_capture_settings.noise_reduction());
  EXPECT_FALSE(video_capture_settings.min_frame_rate().has_value());
  EXPECT_FALSE(video_capture_settings.max_frame_rate().has_value());

  const blink::VideoTrackAdapterSettings& track_settings =
      video_capture_settings.track_adapter_settings();
  EXPECT_EQ(track_settings.target_width(), blink::kDefaultScreenCastWidth);
  EXPECT_EQ(track_settings.target_height(), blink::kDefaultScreenCastHeight);
  EXPECT_EQ(track_settings.min_aspect_ratio(),
            1.0 / blink::kMaxScreenCastDimension);
  EXPECT_EQ(track_settings.max_aspect_ratio(), blink::kMaxScreenCastDimension);
  EXPECT_EQ(track_settings.max_frame_rate(), std::nullopt);
}

TEST_F(UserMediaClientTest, NonDefaultAudioConstraintsPropagate) {
  mock_dispatcher_host_.DoNotRunCallback();

  blink::MockConstraintFactory factory;
  factory.basic().device_id.SetExact(fake_ids_->audio_input_1);
  factory.basic().disable_local_echo.SetExact(true);
  factory.basic().render_to_associated_sink.SetExact(true);
  factory.basic().echo_cancellation.SetExact(false);
  MediaConstraints audio_constraints = factory.CreateMediaConstraints();
  // Request contains only audio
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(audio_constraints, MediaConstraints());
  user_media_client_impl_->RequestUserMediaForTest(request);
  blink::AudioCaptureSettings audio_capture_settings =
      user_media_processor_->AudioSettings();
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_FUCHSIA)
  if (base::FeatureList::IsEnabled(
          features::kGetUserMediaDeferredDeviceSettingsSelection)) {
    audio_capture_settings = user_media_processor_->EligibleAudioSettings()[0];
  }
#endif

  blink::VideoCaptureSettings video_capture_settings =
      user_media_processor_->VideoSettings();
  user_media_client_impl_->CancelUserMediaRequest(request);

  EXPECT_FALSE(video_capture_settings.HasValue());

  EXPECT_TRUE(audio_capture_settings.HasValue());
  EXPECT_EQ(fake_ids_->audio_input_1.Ascii(),
            audio_capture_settings.device_id());
  EXPECT_TRUE(audio_capture_settings.disable_local_echo());
  EXPECT_TRUE(audio_capture_settings.render_to_associated_sink());

  const blink::AudioProcessingProperties& properties =
      audio_capture_settings.audio_processing_properties();
  EXPECT_EQ(EchoCancellationType::kEchoCancellationDisabled,
            properties.echo_cancellation_type);
  EXPECT_FALSE(properties.auto_gain_control);
  EXPECT_FALSE(properties.noise_suppression);
}

TEST_F(UserMediaClientTest, CreateWithMandatoryInvalidAudioDeviceId) {
  MediaConstraints audio_constraints =
      CreateDeviceConstraints(fake_ids_->invalid_device);
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(audio_constraints, MediaConstraints());
  user_media_client_impl_->RequestUserMediaForTest(request);
  EXPECT_EQ(kRequestFailed, request_state());
}

TEST_F(UserMediaClientTest, CreateWithMandatoryInvalidVideoDeviceId) {
  MediaConstraints video_constraints =
      CreateDeviceConstraints(fake_ids_->invalid_device);
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(MediaConstraints(), video_constraints);
  user_media_client_impl_->RequestUserMediaForTest(request);
  EXPECT_EQ(kRequestFailed, request_state());
}

TEST_F(UserMediaClientTest, CreateWithMandatoryValidDeviceIds) {
  MediaConstraints audio_constraints =
      CreateDeviceConstraints(fake_ids_->audio_input_1);
  MediaConstraints video_constraints =
      CreateDeviceConstraints(fake_ids_->video_input_1);
  TestValidRequestWithConstraints(audio_constraints, video_constraints,
                                  fake_ids_->audio_input_1,
                                  fake_ids_->video_input_1);
}

TEST_F(UserMediaClientTest, CreateWithBasicIdealValidDeviceId) {
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_FUCHSIA)
  // Ideal device ids are overridden by user preference under this flag.
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndDisableFeature(
      features::kGetUserMediaDeferredDeviceSettingsSelection);
#endif
  MediaConstraints audio_constraints =
      CreateDeviceConstraints(g_empty_string, fake_ids_->audio_input_1);
  MediaConstraints video_constraints =
      CreateDeviceConstraints(g_empty_string, fake_ids_->video_input_1);
  TestValidRequestWithConstraints(audio_constraints, video_constraints,
                                  fake_ids_->audio_input_1,
                                  fake_ids_->video_input_1);
}

TEST_F(UserMediaClientTest, CreateWithAdvancedExactValidDeviceId) {
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_FUCHSIA)
  // Advanced exact device id constraints are overridden by user preference
  // under this flag.
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndDisableFeature(
      features::kGetUserMediaDeferredDeviceSettingsSelection);
#endif
  MediaConstraints audio_constraints = CreateDeviceConstraints(
      g_empty_string, g_empty_string, fake_ids_->audio_input_1);
  MediaConstraints video_constraints = CreateDeviceConstraints(
      g_empty_string, g_empty_string, fake_ids_->video_input_1);
  TestValidRequestWithConstraints(audio_constraints, video_constraints,
                                  fake_ids_->audio_input_1,
                                  fake_ids_->video_input_1);
}

TEST_F(UserMediaClientTest, CreateWithAllOptionalInvalidDeviceId) {
  MediaConstraints audio_constraints = CreateDeviceConstraints(
      g_empty_string, fake_ids_->invalid_device, fake_ids_->invalid_device);
  MediaConstraints video_constraints = CreateDeviceConstraints(
      g_empty_string, fake_ids_->invalid_device, fake_ids_->invalid_device);
  // MockMojoMediaStreamDispatcherHost uses empty string as default audio device
  // ID. MockMediaDevicesDispatcher uses the first device in the enumeration as
  // default audio or video device ID.
  String expected_audio_device_id =
      String(media::AudioDeviceDescription::kDefaultDeviceId);
  TestValidRequestWithConstraints(audio_constraints, video_constraints,
                                  expected_audio_device_id,
                                  fake_ids_->video_input_1);
}

TEST_F(UserMediaClientTest, CreateWithFacingModeUser) {
  MediaConstraints audio_constraints =
      CreateDeviceConstraints(fake_ids_->audio_input_1);
  MediaConstraints video_constraints = CreateFacingModeConstraints("user");
  // fake_ids_->video_input_1 has user facing mode.
  TestValidRequestWithConstraints(audio_constraints, video_constraints,
                                  fake_ids_->audio_input_1,
                                  fake_ids_->video_input_1);
}

TEST_F(UserMediaClientTest, CreateWithFacingModeEnvironment) {
  MediaConstraints audio_constraints =
      CreateDeviceConstraints(fake_ids_->audio_input_1);
  MediaConstraints video_constraints =
      CreateFacingModeConstraints("environment");
  // fake_ids_->video_input_2 has kEnvironment facing mode.
  TestValidRequestWithConstraints(audio_constraints, video_constraints,
                                  fake_ids_->audio_input_1,
                                  fake_ids_->video_input_2);
}

TEST_F(UserMediaClientTest, ApplyConstraintsVideoDeviceSingleTrack) {
  MediaStreamTrack* track = RequestLocalVideoTrack();
  MediaStreamComponent* component = track->Component();
  MediaStreamVideoTrack* platform_track =
      MediaStreamVideoTrack::From(component);
  blink::MediaStreamVideoSource* source = platform_track->source();
  CheckVideoSource(source, 0, 0, 0.0);

  media_devices_dispatcher_.SetVideoSource(source);

  // The following applyConstraint() request should force a source restart and
  // produce a video mode with 1024x768.
  ApplyConstraintsVideoMode(track, 1024, 768);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 1024, 768, 20.0);

  // The following applyConstraints() requests should not result in a source
  // restart since the only format supported by the mock MDDH that supports
  // 801x600 is the existing 1024x768 mode with downscaling.
  ApplyConstraintsVideoMode(track, 801, 600);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 801, 600, 20.0);

  // The following applyConstraints() requests should result in a source restart
  // since there is a native mode of 800x600 supported by the mock MDDH.
  ApplyConstraintsVideoMode(track, 800, 600);
  CheckVideoSourceAndTrack(source, 800, 600, 30.0, component, 800, 600, 30.0);

  // The following applyConstraints() requests should fail since the mock MDDH
  // does not have any mode that can produce 2000x2000.
  ApplyConstraintsVideoMode(track, 2000, 2000);
  CheckVideoSourceAndTrack(source, 800, 600, 30.0, component, 800, 600, 30.0);
}

TEST_F(UserMediaClientTest, CameraCaptureCapabilityHistograms) {
  // With two HD/FullHD capable devices.
  {
    base::HistogramTester histogram_tester;

    Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr> capabilities;
    // The first device supports 360p and 720p.
    blink::mojom::blink::VideoInputDeviceCapabilitiesPtr device1 =
        blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device1->device_id = FakeDeviceIds::GetInstance()->video_input_1;
    device1->group_id = String("dummy1");
    device1->facing_mode = mojom::blink::FacingMode::kUser;
    device1->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 360), 30.0f, media::PIXEL_FORMAT_NV12));
    device1->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(1280, 720), 30.0f, media::PIXEL_FORMAT_NV12));
    capabilities.push_back(std::move(device1));
    // The second device supports 480p and 1080p.
    blink::mojom::blink::VideoInputDeviceCapabilitiesPtr device2 =
        blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device2->device_id = FakeDeviceIds::GetInstance()->video_input_2;
    device2->group_id = String("dummy2");
    device2->facing_mode = mojom::blink::FacingMode::kUser;
    device2->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 480), 30.0f, media::PIXEL_FORMAT_NV12));
    device2->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(1920, 1080), 30.0f, media::PIXEL_FORMAT_NV12));
    capabilities.push_back(std::move(device2));
    media_devices_dispatcher_.SetVideoInputCapabilities(
        std::move(capabilities));

    // Perform getUserMedia() and verify one camera capability value per device.
    RequestLocalVideoTrack();
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdOrFullHd, 0);
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdOrFullHd_360p, 1);
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdOrFullHd_480p, 1);
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdOrFullHd_360p_480p, 0);
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdAndFullHdMissing, 0);
  }

  // With three devices: No HD, HD with both 360p and 480p, and HD with neither.
  {
    base::HistogramTester histogram_tester;

    Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr> capabilities;
    // The first device supports 360p and 480p.
    blink::mojom::blink::VideoInputDeviceCapabilitiesPtr device1 =
        blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device1->device_id = FakeDeviceIds::GetInstance()->video_input_1;
    device1->group_id = String("dummy1");
    device1->facing_mode = mojom::blink::FacingMode::kUser;
    device1->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 360), 30.0f, media::PIXEL_FORMAT_NV12));
    device1->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 480), 30.0f, media::PIXEL_FORMAT_NV12));
    capabilities.push_back(std::move(device1));
    // The second device supports 360p, 480p and 720p.
    blink::mojom::blink::VideoInputDeviceCapabilitiesPtr device2 =
        blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device2->device_id = FakeDeviceIds::GetInstance()->video_input_2;
    device2->group_id = String("dummy2");
    device2->facing_mode = mojom::blink::FacingMode::kUser;
    device2->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 360), 30.0f, media::PIXEL_FORMAT_NV12));
    device2->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 480), 30.0f, media::PIXEL_FORMAT_NV12));
    device2->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(1280, 720), 30.0f, media::PIXEL_FORMAT_NV12));
    capabilities.push_back(std::move(device2));
    // The third device supports 720p and 1080p.
    blink::mojom::blink::VideoInputDeviceCapabilitiesPtr device3 =
        blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device3->device_id = FakeDeviceIds::GetInstance()->video_input_3;
    device3->group_id = String("dummy3");
    device3->facing_mode = mojom::blink::FacingMode::kUser;
    device3->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(1280, 720), 30.0f, media::PIXEL_FORMAT_NV12));
    device3->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(1920, 1080), 30.0f, media::PIXEL_FORMAT_NV12));
    capabilities.push_back(std::move(device3));
    media_devices_dispatcher_.SetVideoInputCapabilities(
        std::move(capabilities));

    // Perform getUserMedia() and verify one camera capability value per device.
    RequestLocalVideoTrack();
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdOrFullHd, 1);
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdOrFullHd_360p, 0);
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdOrFullHd_480p, 0);
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdOrFullHd_360p_480p, 1);
    histogram_tester.ExpectBucketCount(
        "Media.MediaDevices.GetUserMedia.CameraCaptureCapability",
        CameraCaptureCapability::kHdAndFullHdMissing, 1);
  }
}

TEST_F(UserMediaClientTest, ApplyConstraintsVideoDeviceTwoTracks) {
  MediaStreamTrack* track = RequestLocalVideoTrack();
  MediaStreamComponent* component = track->Component();
  MockMediaStreamVideoCapturerSource* source =
      user_media_processor_->last_created_video_source();
  CheckVideoSource(source, 0, 0, 0.0);
  media_devices_dispatcher_.SetVideoSource(source);

  // Switch the source and track to 1024x768@20Hz.
  ApplyConstraintsVideoMode(track, 1024, 768);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 1024, 768, 20.0);

  // Create a new track and verify that it uses the same source and that the
  // source's format did not change. The new track uses the same for
"""


```