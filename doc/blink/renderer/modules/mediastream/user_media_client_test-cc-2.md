Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This code is a test file for `UserMediaClient` in the Chromium Blink engine. It tests various aspects of how the browser handles requests for user media (audio and video).

Here's a plan to address the request:

1. **Identify the Core Functionality:** The primary purpose is to test the `UserMediaClient` class, focusing on how it manages media tracks, sources, and constraints.

2. **Categorize the Tests:** Group the tests based on the features they are testing. Key areas include:
    - Applying constraints to video tracks (resolution, frame rate).
    - Handling scenarios where applying constraints might fail (due to multiple tracks or device limitations).
    - Managing device states (stopping, restarting).
    - Associated output device ID handling.
    - Desktop capture functionality (changing sources).
    - Pan/Tilt/Zoom permission requests.
    - Handling multiple devices in a stream.
    - Deferred device selection (if the feature is enabled).

3. **Explain the Relevance to Web Technologies:**  Connect the C++ test code to the corresponding JavaScript, HTML, and CSS APIs that trigger these functionalities. For example, `getUserMedia()` in JavaScript and the `MediaTrackConstraints` interface.

4. **Illustrate with Examples:** Provide simple hypothetical scenarios involving JavaScript calls and the expected behavior tested in the C++ code.

5. **Address Potential User Errors:** Highlight common mistakes developers might make when using the related web APIs, and how these tests ensure the browser handles such situations correctly.

6. **Explain the User Journey for Debugging:** Describe the steps a user might take in a web browser that would eventually lead to the execution paths tested by this C++ code.

7. **Summarize the Overall Functionality:** Provide a concise summary of the file's purpose.

**Detailed Breakdown of the Code Snippet:**

- **Apply Constraints Tests:**  Several tests focus on `applyConstraints()` and its behavior with video tracks. They check how resolution and frame rate changes are handled, especially when multiple tracks share a source or when the underlying device has limitations.
- **Device State Tests:** Tests cover scenarios where a video source might fail to stop or restart during constraint changes.
- **Associated Output Device ID Tests:**  These verify that the `renderToAssociatedSink` constraint correctly influences the output device ID.
- **Desktop Capture Tests:** These tests deal with changing the source of a desktop capture stream, including scenarios where audio might be present or absent in the new source.
- **Pan/Tilt/Zoom Tests:** These check if requesting pan, tilt, or zoom in constraints triggers a permission request.
- **Multi-Device Test:** This verifies the handling of a stream with multiple devices.
- **Deferred Device Selection Tests (Conditional):** These tests (enabled by a feature flag) focus on scenarios where device selection is deferred, particularly around invalid device IDs.

**Relating to Web Technologies:**

- **JavaScript:** The core interaction point is the `navigator.mediaDevices.getUserMedia()` API. The constraints passed to this function directly influence the behavior tested in this C++ code. The `MediaStreamTrack.applyConstraints()` method is also directly relevant.
- **HTML:** While not directly involved in the logic being tested, HTML provides the context where JavaScript code requesting media is executed (e.g., a button click triggering `getUserMedia()`).
- **CSS:**  CSS is generally not directly related to the core functionality tested here, which is about media stream acquisition and management, not rendering.

**User Errors:**  A common user error is providing invalid or unsupported constraint values in `getUserMedia()` or `applyConstraints()`. These tests ensure the browser gracefully handles such errors.

**Debugging Journey:** A user might encounter issues related to video resolution or frame rate in their web application. By examining the behavior tested here, developers can understand how the browser interprets and applies constraints, helping them debug why a specific resolution or frame rate isn't being achieved.

By following this plan, I can create a comprehensive and accurate summary of the provided code snippet.
这是 `blink/renderer/modules/mediastream/user_media_client_test.cc` 文件的第 3 部分，延续了前两部分的内容，主要关注于测试 `UserMediaClient` 类在处理用户媒体请求时的各种场景，特别是关于 **视频轨道约束的应用 (applyConstraints)** 以及其他一些边缘情况。

**归纳一下它的功能：**

这部分代码主要测试了以下 `UserMediaClient` 的功能：

1. **`applyConstraints()` 对视频轨道的影响 (深入测试):**
   - 测试在有多个视频轨道共享同一个视频源时，使用 `applyConstraints()` 修改其中一个轨道的约束（例如分辨率、帧率）的行为。验证在多轨道情况下，源通常不会被重新配置，而是通过下采样来满足约束。
   - 测试尝试使用 `applyConstraints()` 修改视频轨道的帧率，当底层视频源不支持动态重新配置并且有多个轨道时，修改会失败。
   - 测试当只有一个视频轨道连接到源时，`applyConstraints()` 可以成功重新配置视频源。
   - 测试当视频源因为某些原因（例如 `DisableStopForRestart()`）无法停止并重启时，`applyConstraints()` 的行为，通常会采用下采样。
   - 测试当视频源因为某些原因（例如 `DisableRestart()`）无法重启时，`applyConstraints()` 的行为，会导致轨道和源都被停止。
   - 测试当视频轨道已经被停止后，再调用 `applyConstraints()` 的行为，确认轨道和源仍然处于停止状态。

2. **关联输出设备 ID 的设置:**
   - 测试 `renderToAssociatedSink` 约束属性是否正确地设置了音频源的关联输出设备 ID。

3. **判断是否正在捕获媒体流:**
   - 测试 `IsCapturing()` 方法是否能够正确反映当前是否有正在活动的媒体流捕获。

4. **桌面共享场景下的源切换:**
   - 测试在桌面共享场景下，当底层捕获的视频或音频源发生变化时，`UserMediaClient` 如何处理。包括成功切换视频源和音频源的情况。
   - 测试当新的桌面共享源没有音频时，如何停止之前的音频源。

5. **Pan/Tilt/Zoom 约束的权限请求:**
   - 测试当用户媒体约束中包含 `pan`、`tilt` 或 `zoom` 属性时，是否会触发相应的 PTZ 权限请求。

6. **处理多个设备:**
   - 测试在 `OnStreamsGenerated` 回调中处理多个设备的能力。

7. **延迟设备选择 (通过 Feature Flag 启用):**
   - 这部分代码被 `#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_FUCHSIA)` 包裹，意味着这些测试主要在桌面平台上运行。
   - 测试在启用了延迟设备选择功能后，成功生成包含音频和视频的媒体流。
   - 测试在启用了延迟设备选择功能后，使用无效的强制音频或视频设备 ID 创建媒体流会失败。
   - 测试在启用了延迟设备选择功能后，使用有效的强制设备 ID 创建媒体流会成功。

**与 JavaScript, HTML, CSS 的关系：**

这些测试直接对应于 Web API `navigator.mediaDevices.getUserMedia()` 和 `MediaStreamTrack.applyConstraints()` 的行为。

* **JavaScript:** 开发者在 JavaScript 中调用 `navigator.mediaDevices.getUserMedia(constraints)` 请求用户媒体，`constraints` 对象定义了需要的音视频轨道类型和属性。当获得 `MediaStreamTrack` 对象后，可以调用 `track.applyConstraints(constraints)` 来尝试修改轨道的属性（例如分辨率、帧率）。这部分 C++ 测试验证了 Blink 引擎在底层如何处理这些 JavaScript 调用和约束。
    ```javascript
    // JavaScript 示例
    navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 } })
      .then(function(stream) {
        const videoTrack = stream.getVideoTracks()[0];
        videoTrack.applyConstraints({ width: 1280, height: 720 });
      })
      .catch(function(error) {
        console.error('Error accessing media devices.', error);
      });
    ```
* **HTML:** HTML 提供了网页结构，JavaScript 代码通常在 HTML 页面中执行，例如通过 `<script>` 标签引入。用户操作（例如点击按钮）可以触发 JavaScript 代码调用 `getUserMedia()`。
* **CSS:** CSS 主要负责网页的样式和布局，与媒体流的获取和约束管理没有直接关系。

**逻辑推理与假设输入输出：**

以 `TEST_F(UserMediaClientTest, ApplyConstraintsVideoDeviceWithTwoTracks)` 为例：

* **假设输入:**
    - 通过 `RequestLocalVideoTrack()` 创建第一个视频轨道 `track`。
    - 通过 `RequestLocalVideoTrack()` 创建第二个视频轨道 `track2`，这两个轨道共享同一个视频源 `source`。
    - 使用 `ApplyConstraintsVideoMode(track, 800, 600)` 尝试将第一个轨道的分辨率修改为 800x600。
    - 再次使用 `ApplyConstraintsVideoMode(track, 800, 600, 30.0)` 尝试修改第一个轨道的帧率为 30Hz。
    - 停止第二个轨道 `track2`。
    - 再次使用 `ApplyConstraintsVideoMode(track, 800, 600, 30.0)` 尝试修改第一个轨道的帧率为 30Hz。
* **逻辑推理:**
    - 当有多个轨道共享同一个源时，直接修改源的分辨率通常是不允许的，会采用下采样。
    - 当有多个轨道共享同一个源时，并且源不支持动态重新配置帧率，修改帧率会失败。
    - 当只有一个轨道连接到源时，可以成功修改源的配置（包括帧率）。
* **预期输出:**
    - 第一次 `applyConstraints()` 后，`track` 的分辨率变为 800x600，但 `source` 的分辨率仍然是 1024x768。`track2` 的分辨率保持不变。
    - 第二次 `applyConstraints()` 修改帧率会失败，`track` 和 `track2` 的帧率保持不变。
    - 停止 `track2` 后，最后一次 `applyConstraints()` 可以成功修改 `track` 和 `source` 的分辨率和帧率。

**用户或编程常见的使用错误：**

* **不理解 `applyConstraints()` 的行为:** 开发者可能期望在有多个轨道共享同一个源时，调用 `applyConstraints()` 可以直接修改源的配置，但实际上通常会进行下采样。
* **在不支持动态重新配置的设备上尝试修改帧率:** 一些摄像头可能不支持在运行时修改帧率，调用 `applyConstraints()` 修改帧率可能会失败。
* **在轨道停止后仍然尝试调用 `applyConstraints()`:**  这通常不会报错，但操作不会有实际效果，开发者可能没有正确管理轨道的生命周期。
* **在 `getUserMedia()` 或 `applyConstraints()` 中使用无效的约束值:** 例如，请求超出设备支持范围的分辨率或帧率。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户打开一个网页，该网页使用了 WebRTC 技术。**
2. **网页上的 JavaScript 代码调用了 `navigator.mediaDevices.getUserMedia(constraints)` 请求访问用户的摄像头。** `constraints` 对象可能包含特定的分辨率、帧率或其他媒体轨道属性要求。
3. **浏览器接收到这个请求，并创建 `UserMediaClient` 实例来处理。**
4. **`UserMediaClient` 与底层的媒体设备交互，获取摄像头数据。**
5. **用户可能与网页上的控件交互，触发了 JavaScript 代码调用 `videoTrack.applyConstraints(newConstraints)` 来尝试更改视频轨道的属性。**
6. **Blink 引擎的 `UserMediaClient` 中的代码（例如本文件中的测试覆盖的代码）会被执行，来处理 `applyConstraints()` 的请求。**
7. **如果在调试过程中发现视频分辨率或帧率没有按照预期工作，开发者可能会查看 Blink 引擎的源代码或者相关的测试用例，例如 `user_media_client_test.cc`，来理解浏览器在处理约束时的行为。** 这些测试用例模拟了各种场景，可以帮助开发者理解约束是如何被解析和应用的，以及在不同情况下可能出现的结果。

总而言之，这部分测试代码专注于验证 `UserMediaClient` 在处理视频轨道约束变更时的各种复杂情况，确保了 WebRTC 相关的 JavaScript API 在 Chromium 中的正确实现和行为。它覆盖了多轨道共享源、设备能力限制、轨道生命周期等多个关键方面，为开发者理解和调试 WebRTC 应用提供了重要的参考。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/user_media_client_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
mat as the
  // source by default.
  MediaStreamTrack* track2 = RequestLocalVideoTrack();
  MediaStreamComponent* component2 = track2->Component();
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component2, 1024, 768,
                           20.0);

  // Use applyConstraints() to change the first track to 800x600 and verify
  // that the source is not reconfigured. Downscaling is used instead because
  // there is more than one track using the source. The second track is left
  // unmodified.
  ApplyConstraintsVideoMode(track, 800, 600);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 800, 600, 20.0);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component2, 1024, 768,
                           20.0);

  // Try to use applyConstraints() to change the first track to 800x600@30Hz.
  // It fails, because the source is open in native 20Hz mode and it does not
  // support reconfiguration when more than one track is connected.
  // TODO(guidou): Allow reconfiguring sources with more than one track.
  // https://crbug.com/768205.
  ApplyConstraintsVideoMode(track, 800, 600, 30.0);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 800, 600, 20.0);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component2, 1024, 768,
                           20.0);

  // Try to use applyConstraints() to change the first track to 800x600@30Hz.
  // after stopping the second track. In this case, the source is left with a
  // single track and it supports reconfiguration to the requested mode.
  blink::MediaStreamTrackPlatform::GetTrack(WebMediaStreamTrack(component2))
      ->Stop();
  ApplyConstraintsVideoMode(track, 800, 600, 30.0);
  CheckVideoSourceAndTrack(source, 800, 600, 30.0, component, 800, 600, 30.0);
}

TEST_F(UserMediaClientTest, ApplyConstraintsVideoDeviceFailsToStopForRestart) {
  MediaStreamTrack* track = RequestLocalVideoTrack();
  MediaStreamComponent* component = track->Component();
  MockMediaStreamVideoCapturerSource* source =
      user_media_processor_->last_created_video_source();
  CheckVideoSource(source, 0, 0, 0.0);
  media_devices_dispatcher_.SetVideoSource(source);

  // Switch the source and track to 1024x768@20Hz.
  ApplyConstraintsVideoMode(track, 1024, 768);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 1024, 768, 20.0);

  // Try to switch the source and track to 640x480. Since the source cannot
  // stop for restart, downscaling is used for the track.
  source->DisableStopForRestart();
  ApplyConstraintsVideoMode(track, 640, 480);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 640, 480, 20.0);
}

TEST_F(UserMediaClientTest,
       ApplyConstraintsVideoDeviceFailsToRestartAfterStop) {
  MediaStreamTrack* track = RequestLocalVideoTrack();
  MediaStreamComponent* component = track->Component();
  MockMediaStreamVideoCapturerSource* source =
      user_media_processor_->last_created_video_source();
  CheckVideoSource(source, 0, 0, 0.0);
  media_devices_dispatcher_.SetVideoSource(source);

  // Switch the source and track to 1024x768.
  ApplyConstraintsVideoMode(track, 1024, 768);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 1024, 768, 20.0);

  // Try to switch the source and track to 640x480. Since the source cannot
  // restart, source and track are stopped.
  source->DisableRestart();
  ApplyConstraintsVideoMode(track, 640, 480);

  EXPECT_EQ(component->GetReadyState(), MediaStreamSource::kReadyStateEnded);
  EXPECT_FALSE(source->IsRunning());
}

TEST_F(UserMediaClientTest, ApplyConstraintsVideoDeviceStopped) {
  MediaStreamTrack* track = RequestLocalVideoTrack();
  MediaStreamComponent* component = track->Component();
  MockMediaStreamVideoCapturerSource* source =
      user_media_processor_->last_created_video_source();
  CheckVideoSource(source, 0, 0, 0.0);
  media_devices_dispatcher_.SetVideoSource(source);

  // Switch the source and track to 1024x768.
  ApplyConstraintsVideoMode(track, 1024, 768);
  CheckVideoSourceAndTrack(source, 1024, 768, 20.0, component, 1024, 768, 20.0);

  // Try to switch the source and track to 640x480 after stopping the track.
  MediaStreamTrackPlatform* platform_track =
      MediaStreamTrackPlatform::GetTrack(WebMediaStreamTrack(component));
  platform_track->Stop();
  EXPECT_EQ(component->GetReadyState(), MediaStreamSource::kReadyStateEnded);
  EXPECT_FALSE(source->IsRunning());
  {
    MediaStreamTrackPlatform::Settings settings;
    platform_track->GetSettings(settings);
    EXPECT_EQ(settings.width, -1);
    EXPECT_EQ(settings.height, -1);
    EXPECT_EQ(settings.frame_rate, -1.0);
  }

  ApplyConstraintsVideoMode(track, 640, 480);
  EXPECT_EQ(component->GetReadyState(), MediaStreamSource::kReadyStateEnded);
  EXPECT_FALSE(source->IsRunning());
  {
    MediaStreamTrackPlatform::Settings settings;
    platform_track->GetSettings(settings);
    EXPECT_EQ(settings.width, -1);
    EXPECT_EQ(settings.height, -1);
    EXPECT_EQ(settings.frame_rate, -1.0);
  }
}

// These tests check that the associated output device id is
// set according to the renderToAssociatedSink constrainable property.
TEST_F(UserMediaClientTest,
       RenderToAssociatedSinkTrueAssociatedOutputDeviceId) {
  MediaStreamComponent* component =
      RequestLocalAudioTrackWithAssociatedSink(true);
  MediaStreamAudioSource* source =
      MediaStreamAudioSource::From(component->Source());
  EXPECT_TRUE(source->device().matched_output_device_id);
}

TEST_F(UserMediaClientTest,
       RenderToAssociatedSinkFalseAssociatedOutputDeviceId) {
  MediaStreamComponent* component =
      RequestLocalAudioTrackWithAssociatedSink(false);
  MediaStreamAudioSource* source =
      MediaStreamAudioSource::From(component->Source());
  EXPECT_FALSE(source->device().matched_output_device_id);
}

TEST_F(UserMediaClientTest, IsCapturing) {
  EXPECT_FALSE(user_media_client_impl_->IsCapturing());
  MediaStreamDescriptor* descriptor = RequestLocalMediaStream();
  EXPECT_TRUE(user_media_client_impl_->IsCapturing());

  user_media_client_impl_->StopTrack(descriptor->AudioComponents()[0]);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(user_media_client_impl_->IsCapturing());

  user_media_client_impl_->StopTrack(descriptor->VideoComponents()[0]);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(user_media_client_impl_->IsCapturing());
}

TEST_F(UserMediaClientTest, DesktopCaptureChangeSource) {
  blink::MockConstraintFactory factory;
  factory.basic().media_stream_source.SetExact(
      blink::WebString::FromASCII(blink::kMediaStreamSourceDesktop));
  MediaConstraints audio_constraints = factory.CreateMediaConstraints();
  MediaConstraints video_constraints = factory.CreateMediaConstraints();
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(audio_constraints, video_constraints);
  user_media_client_impl_->RequestUserMediaForTest(request);

  // Test changing video source.
  MockMediaStreamVideoCapturerSource* video_source =
      UserMediaProcessorForDisplayCapture()->last_created_video_source();
  blink::MediaStreamDevice fake_video_device(
      blink::mojom::blink::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE,
      fake_ids_->video_input_1.Ascii(), "Fake Video Device");
  EXPECT_CALL(*video_source, ChangeSourceImpl(_));
  UserMediaProcessorForDisplayCapture()->OnDeviceChanged(video_source->device(),
                                                         fake_video_device);

  // Test changing audio source.
  MockLocalMediaStreamAudioSource* audio_source =
      UserMediaProcessorForDisplayCapture()->last_created_local_audio_source();
  EXPECT_NE(audio_source, nullptr);
  blink::MediaStreamDevice fake_audio_device(
      blink::mojom::blink::MediaStreamType::GUM_DESKTOP_AUDIO_CAPTURE,
      fake_ids_->video_input_1.Ascii(), "Fake Audio Device");
  EXPECT_CALL(*audio_source, EnsureSourceIsStopped()).Times(2);
  UserMediaProcessorForDisplayCapture()->OnDeviceChanged(audio_source->device(),
                                                         fake_audio_device);

  user_media_client_impl_->CancelUserMediaRequest(request);
  base::RunLoop().RunUntilIdle();
}

TEST_F(UserMediaClientTest, DesktopCaptureChangeSourceWithoutAudio) {
  blink::MockConstraintFactory factory;
  factory.basic().media_stream_source.SetExact(kMediaStreamSourceDesktop);
  MediaConstraints audio_constraints = factory.CreateMediaConstraints();
  MediaConstraints video_constraints = factory.CreateMediaConstraints();
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(audio_constraints, video_constraints);
  user_media_client_impl_->RequestUserMediaForTest(request);
  EXPECT_NE(
      std::nullopt,
      MediaStreamDispatcherHostForDisplayCapture().devices().audio_device);
  EXPECT_NE(
      std::nullopt,
      MediaStreamDispatcherHostForDisplayCapture().devices().video_device);

  // If the new desktop capture source doesn't have audio, the previous audio
  // device should be stopped. Here |EnsureSourceIsStopped()| should be called
  // only once by |OnDeviceChanged()|.
  MockLocalMediaStreamAudioSource* audio_source =
      UserMediaProcessorForDisplayCapture()->last_created_local_audio_source();
  EXPECT_NE(audio_source, nullptr);
  EXPECT_CALL(*audio_source, EnsureSourceIsStopped()).Times(1);
  blink::MediaStreamDevice fake_audio_device(
      blink::mojom::blink::MediaStreamType::NO_SERVICE, "", "");
  UserMediaProcessorForDisplayCapture()->OnDeviceChanged(audio_source->device(),
                                                         fake_audio_device);
  base::RunLoop().RunUntilIdle();

  Mock::VerifyAndClearExpectations(audio_source);
  EXPECT_CALL(*audio_source, EnsureSourceIsStopped()).Times(0);
  user_media_client_impl_->CancelUserMediaRequest(request);
  base::RunLoop().RunUntilIdle();
}

TEST_F(UserMediaClientTest, PanConstraintRequestPanTiltZoomPermission) {
  EXPECT_FALSE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      CreateDefaultConstraints()));

  blink::MockConstraintFactory basic_factory;
  basic_factory.basic().pan.SetIsPresent(true);
  EXPECT_TRUE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      basic_factory.CreateMediaConstraints()));

  blink::MockConstraintFactory advanced_factory;
  auto& exact_advanced = advanced_factory.AddAdvanced();
  exact_advanced.pan.SetIsPresent(true);
  EXPECT_TRUE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      advanced_factory.CreateMediaConstraints()));
}

TEST_F(UserMediaClientTest, TiltConstraintRequestPanTiltZoomPermission) {
  EXPECT_FALSE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      CreateDefaultConstraints()));

  blink::MockConstraintFactory basic_factory;
  basic_factory.basic().tilt.SetIsPresent(true);
  EXPECT_TRUE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      basic_factory.CreateMediaConstraints()));

  blink::MockConstraintFactory advanced_factory;
  auto& exact_advanced = advanced_factory.AddAdvanced();
  exact_advanced.tilt.SetIsPresent(true);
  EXPECT_TRUE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      advanced_factory.CreateMediaConstraints()));
}

TEST_F(UserMediaClientTest, ZoomConstraintRequestPanTiltZoomPermission) {
  EXPECT_FALSE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      CreateDefaultConstraints()));

  blink::MockConstraintFactory basic_factory;
  basic_factory.basic().zoom.SetIsPresent(true);
  EXPECT_TRUE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      basic_factory.CreateMediaConstraints()));

  blink::MockConstraintFactory advanced_factory;
  auto& exact_advanced = advanced_factory.AddAdvanced();
  exact_advanced.zoom.SetIsPresent(true);
  EXPECT_TRUE(UserMediaProcessor::IsPanTiltZoomPermissionRequested(
      advanced_factory.CreateMediaConstraints()));
}

TEST_F(UserMediaClientTest, MultiDeviceOnStreamsGenerated) {
  const size_t devices_count = 5u;
  const int32_t request_id = 0;
  std::unique_ptr<blink::MediaDevicesDispatcherHostMock>
      media_devices_dispatcher_host_mock =
          std::make_unique<blink::MediaDevicesDispatcherHostMock>();
  blink::Member<blink::UserMediaRequest> user_media_request =
      blink::UserMediaRequest::CreateForTesting(CreateDefaultConstraints(),
                                                CreateDefaultConstraints());
  user_media_request->set_request_id(request_id);
  user_media_processor_->ProcessRequest(user_media_request, base::DoNothing());
  user_media_processor_->media_devices_dispatcher_cb_ =
      base::BindLambdaForTesting(
          [&media_devices_dispatcher_host_mock]()
              -> blink::mojom::blink::MediaDevicesDispatcherHost* {
            return media_devices_dispatcher_host_mock.get();
          });

  blink::mojom::blink::StreamDevicesSetPtr stream_devices_set =
      blink::mojom::blink::StreamDevicesSet::New();
  for (size_t stream_index = 0; stream_index < devices_count; ++stream_index) {
    stream_devices_set->stream_devices.emplace_back(
        blink::mojom::blink::StreamDevices::New(std::nullopt,
                                                blink::MediaStreamDevice()));
  }
  user_media_processor_->OnStreamsGenerated(
      request_id, blink::mojom::MediaStreamRequestResult::OK, "",
      std::move(stream_devices_set), /*pan_tilt_zoom_allowed=*/false);
  base::RunLoop run_loop;
  DCHECK_EQ(devices_count, media_devices_dispatcher_host_mock->devices_count());
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_FUCHSIA)

class UserMediaClientDeferredDeviceSelectionTest : public UserMediaClientTest {
  void SetUp() override {
    feature_list.InitWithFeatures(
        /*enabled_features=*/
        {
            features::kCameraMicPreview,
            features::kGetUserMediaDeferredDeviceSettingsSelection,
        },
        /*disabled_features=*/{});
    UserMediaClientTest::SetUp();
  }

 private:
  base::test::ScopedFeatureList feature_list;
};

TEST_F(UserMediaClientDeferredDeviceSelectionTest, GenerateMediaStream) {
  // Generate a stream with both audio and video.
  MediaStreamDescriptor* mixed_desc = RequestLocalMediaStream();
  EXPECT_TRUE(mixed_desc);
}

TEST_F(UserMediaClientDeferredDeviceSelectionTest,
       CreateWithMandatoryInvalidAudioDeviceId) {
  MediaConstraints audio_constraints =
      CreateDeviceConstraints(fake_ids_->invalid_device);
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(audio_constraints, MediaConstraints());
  user_media_client_impl_->RequestUserMediaForTest(request);
  EXPECT_EQ(kRequestFailed, request_state());
}

TEST_F(UserMediaClientDeferredDeviceSelectionTest,
       CreateWithMandatoryInvalidVideoDeviceId) {
  MediaConstraints video_constraints =
      CreateDeviceConstraints(fake_ids_->invalid_device);
  UserMediaRequest* request =
      UserMediaRequest::CreateForTesting(MediaConstraints(), video_constraints);
  user_media_client_impl_->RequestUserMediaForTest(request);
  EXPECT_EQ(kRequestFailed, request_state());
}

TEST_F(UserMediaClientDeferredDeviceSelectionTest,
       CreateWithMandatoryValidDeviceIds) {
  MediaConstraints audio_constraints =
      CreateDeviceConstraints(fake_ids_->audio_input_1);
  MediaConstraints video_constraints =
      CreateDeviceConstraints(fake_ids_->video_input_1);
  TestValidRequestWithConstraints(audio_constraints, video_constraints,
                                  fake_ids_->audio_input_1,
                                  fake_ids_->video_input_1);
}

#endif
}  // namespace blink
```