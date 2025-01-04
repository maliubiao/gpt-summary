Response:
The user wants to understand the functionality of the provided C++ code, which is a test file for a serializer in the Chromium Blink engine. This serializer handles JavaScript values in the context of modules.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `v8_script_value_serializer_for_modules_test.cc` clearly indicates this file tests the `V8ScriptValueSerializer` specifically for modules. The "serializer" part suggests it deals with converting JavaScript values to a byte stream and back, often for inter-process communication or storage. The "modules" part implies it handles objects and concepts specific to JavaScript modules.

2. **Analyze the test structure:** The file is a series of `TEST` functions. Each `TEST` focuses on a specific scenario or object type. This suggests the core functionality is tested case by case for different kinds of data that might be passed between modules.

3. **Categorize the tested functionalities:**  Go through each `TEST` function and identify the core functionality being tested:
    * `RoundTripVideoFrame`: Serializing and deserializing a `VideoFrame`.
    * `TransferVideoFrame`: Transferring a `VideoFrame` (likely meaning the original becomes unusable).
    * `ClosedVideoFrameThrows`:  Ensuring an error is thrown when trying to serialize a closed `VideoFrame`.
    * `RoundTripAudioData`: Serializing and deserializing `AudioData`. Notably, it checks that the data is copied, not transferred.
    * `TransferAudioData`:  Transferring `AudioData`. Crucially, it verifies the original is closed after transfer.
    * `ClosedAudioDataThrows`: Ensuring an error when serializing closed `AudioData`.
    * `TransferMediaStreamTrack`: Transferring a `MediaStreamTrack`. This involves checking the properties of the transferred track.
    * `TransferMediaStreamTrackRegionCaptureDisabled`: Testing `MediaStreamTrack` transfer when region capture is disabled.
    * `TransferAudioMediaStreamTrack`: Transferring an audio `MediaStreamTrack`.
    * `TransferClonedMediaStreamTrackFails`: Verifying that transferring a cloned `MediaStreamTrack` results in an error.
    * `TransferDeviceCaptureMediaStreamTrackFails`: Ensuring transferring a device capture `MediaStreamTrack` fails.
    * `TransferScreenCaptureMediaStreamTrackFails`: Ensuring transferring a screen capture `MediaStreamTrack` fails.
    * `TransferWindowCaptureMediaStreamTrackFails`: Ensuring transferring a window capture `MediaStreamTrack` fails.
    * `TransferClosedMediaStreamTrackFails`: Ensuring transferring a closed `MediaStreamTrack` fails.
    * `TransferMediaStreamTrackInvalidContentHintFails`:  Verifying an error when transferring a `MediaStreamTrack` with an invalid content hint.
    * `TransferMediaStreamTrackNoSessionIdThrows`: Verifying an error when transferring a `MediaStreamTrack` without a session ID.
    * `TransferRTCDataChannel`: Transferring an `RTCDataChannel` and observing its state changes.
    * `RoundTripCropTarget`: Serializing and deserializing a `CropTarget`.
    * `RoundTripRestrictionTarget`: Serializing and deserializing a `RestrictionTarget`.
    * `ArrayBufferDetachKeyPreventsTransfer`: Testing that a detach key on an `ArrayBuffer` prevents transfer.
    * `ArrayBufferDetachKeyDoesNotPreventSerialize`: Testing that a detach key on an `ArrayBuffer` doesn't prevent serialization (when not transferring).

4. **Relate to JavaScript, HTML, CSS:** Identify how the tested objects relate to web technologies:
    * `VideoFrame`:  Used in `<video>` elements and the Canvas API.
    * `AudioData`:  Used in the Web Audio API.
    * `MediaStreamTrack`: Used in the Media Streams API (webcam, microphone, screen sharing).
    * `RTCDataChannel`: Used in WebRTC for peer-to-peer data communication.
    * `CropTarget`, `RestrictionTarget`: Related to screen sharing and controlling which parts of the screen are shared.
    * `ArrayBuffer`: A fundamental data type in JavaScript for representing raw binary data.

5. **Provide examples:** For each relation, give concrete examples of how these objects are used in JavaScript, HTML, or CSS.

6. **Infer logic and provide input/output:** For tests involving transfer, the assumption is that the *original* object becomes unusable or in a specific "transferred" state, while the *new* object contains the transferred data. For round-trip tests, the input and output should be equivalent. For error cases, the expected output is an exception.

7. **Identify common usage errors:**  Think about common mistakes developers might make when working with these APIs, such as trying to use a closed object or transferring an object that isn't meant to be transferred.

8. **Explain user actions leading to these tests:** Consider how a user interacting with a web page might trigger the creation and transfer of these objects (e.g., using a webcam, sharing the screen, using WebRTC).

9. **Summarize the overall functionality:** Based on the individual tests, synthesize a high-level description of what the file does. Emphasize the core purpose of testing the serialization and transfer mechanisms for module contexts.

10. **Structure the answer:** Organize the information logically with clear headings and bullet points to make it easy to read and understand. Use bolding for key terms.

11. **Review and refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make sure the language is appropriate for the user's likely technical level. For example, initially, I might have used more internal Chromium terminology, but I'd refine it to be more generally understandable.
这是对 Chromium Blink 引擎中 `blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules_test.cc` 文件功能的总结，作为第 3 部分。

**总体功能归纳:**

这个测试文件主要负责测试 `V8ScriptValueSerializerForModules` 类，这个类的作用是在 JavaScript 模块的上下文中序列化和反序列化 JavaScript 值。  它专注于确保各种特定的 Web API 对象（如 `VideoFrame`、`AudioData`、`MediaStreamTrack`、`RTCDataChannel` 等）在模块环境下的序列化和传输行为是正确的。

**具体测试的功能点包括:**

* **序列化与反序列化的正确性 (Round Trip):** 测试将特定的对象序列化后再反序列化后，其状态和数据是否保持不变。这验证了基本的序列化/反序列化机制的正确性。
* **对象传输 (Transfer):** 测试将对象从一个上下文传输到另一个上下文的行为。这通常意味着原始对象会变得不可用或处于特定状态，而新上下文中的对象包含了传输的数据。测试重点在于验证传输后原始对象的状态，以及新对象是否正确接收了数据。
* **错误处理:** 测试在尝试序列化或传输某些特定状态的对象时（例如，已关闭的 `VideoFrame` 或 `AudioData`，或者某些类型的 `MediaStreamTrack`）是否会抛出预期的错误（`DataCloneError`）。
* **特定 API 对象的处理:** 针对不同的 Web API 对象进行专门的测试，确保序列化器能够正确处理它们特有的属性和状态。
* **`ArrayBuffer` 的特殊处理:** 测试 `ArrayBuffer` 的 `detachKey` 属性如何影响传输行为。
* **模块环境下的行为:**  明确针对模块环境进行测试，这意味着它可能涉及到模块特定的隔离和传输机制。

**与 JavaScript, HTML, CSS 的关系举例:**

这个测试文件虽然是 C++ 代码，但它直接测试了 JavaScript API 在 Blink 引擎中的实现。以下是一些与 JavaScript, HTML, CSS 功能相关的举例：

* **`VideoFrame`**:
    * **JavaScript:**  JavaScript 代码可以使用 `VideoFrame` 对象来处理视频帧数据，例如从 `<video>` 元素或 Canvas API 中获取。
    * **HTML:**  `<video>` 元素用于在网页中嵌入视频。
    * **测试用例:**  测试确保在模块间传输 `VideoFrame` 对象时，其图像数据能够被正确序列化和反序列化。
* **`AudioData`**:
    * **JavaScript:**  Web Audio API 使用 `AudioData` 对象来表示音频数据，可以用于音频处理和合成。
    * **测试用例:**  测试确保在模块间传输 `AudioData` 对象时，其音频采样率、声道数和音频数据本身能够被正确处理。
* **`MediaStreamTrack`**:
    * **JavaScript:**  Media Streams API 使用 `MediaStreamTrack` 对象来表示音频或视频轨道，例如从摄像头或麦克风获取的媒体流。
    * **测试用例:** 测试确保在模块间传输 `MediaStreamTrack` 对象时，其状态（例如是否启用、是否静音、是否结束）以及相关的元数据（例如会话 ID、内容提示）能够被正确传递。
* **`RTCDataChannel`**:
    * **JavaScript:**  WebRTC API 使用 `RTCDataChannel` 对象在浏览器之间建立点对点的数据连接。
    * **测试用例:** 测试确保在模块间传输 `RTCDataChannel` 对象时，其连接状态和底层传输机制能够被正确处理。
* **`ArrayBuffer`**:
    * **JavaScript:** `ArrayBuffer` 是 JavaScript 中用于表示原始二进制数据的对象，常用于处理图像、音频或进行网络传输。
    * **测试用例:** 测试 `ArrayBuffer` 在模块间的传输，特别是 `detachKey` 属性如何阻止非授权的传输。

**逻辑推理与假设输入/输出:**

假设我们关注 `TransferAudioData` 这个测试用例：

* **假设输入:**
    * 创建一个包含特定音频数据的 `AudioData` 对象。
    * 将这个 `AudioData` 对象添加到传输列表 (Transferables)。
* **逻辑:**  `RoundTripForModules` 函数会模拟将该对象序列化并发送到另一个模块，然后在另一个模块中反序列化。因为对象在传输列表中，所以原始对象会被“转移”，变得不可用。
* **预期输出:**
    * 原始的 `AudioData` 对象 (`audio_data`) 的内部数据应该被清除或者标记为已关闭 (`audio_data->format()` 为空)。
    * 新创建的 `AudioData` 对象 (`new_data`) 应该包含与原始对象相同的音频数据和元信息（采样率、声道数、帧数等）。
    * `media::AudioBuffer` 的引用计数应该正确管理，确保在传输后没有内存泄漏。

**用户或编程常见的使用错误举例:**

* **尝试使用已传输的对象:**  在 JavaScript 中，如果一个对象被添加到 `transferList` 并发送给 `postMessage` 等函数，原始对象会变得不可用。如果 JavaScript 代码仍然尝试访问或操作这个原始对象，将会导致错误。
    * **示例:**
        ```javascript
        let audioData = new AudioData({...});
        postMessage({data: audioData}, [audioData]);
        // 错误：此时 audioData 已经被转移，无法再使用
        console.log(audioData.numberOfChannels);
        ```
* **在不支持传输的对象上尝试传输:** 并非所有 JavaScript 对象都支持传输。尝试传输不支持的对象通常会导致 `DataCloneError`。
    * **示例:** 尝试传输一个包含了闭包的复杂对象。
* **没有正确处理异步操作:**  在处理涉及模块间通信或序列化/反序列化的操作时，通常是异步的。如果代码没有正确处理 Promise 或回调，可能会在对象完成传输前就尝试访问它。
* **`ArrayBuffer` 的 `detachKey` 使用不当:** 如果错误地设置了 `detachKey`，可能会导致原本应该能够传输的 `ArrayBuffer` 无法被传输。

**用户操作如何一步步到达这里 (调试线索):**

这个测试文件是单元测试，通常不会直接由用户的网页操作触发。但是，它测试的代码逻辑是用户在进行以下操作时会用到的：

1. **使用 Web Workers 或 Service Workers:** 当网页使用 Web Workers 或 Service Workers 进行多线程处理时，需要在不同的线程（不同的模块上下文）之间传递数据。例如，主线程可能将图像数据 (以 `VideoFrame` 或 `ArrayBuffer` 的形式) 发送给 Worker 进行处理。
2. **使用 `postMessage` API 进行跨 Frame 或跨 Window 通信:**  当一个网页需要向其嵌入的 iframe 或弹出的新窗口发送消息时，可以使用 `postMessage` API 并附带 `transfer` 数组来传输对象的所有权。
3. **使用 WebRTC 进行点对点通信:**  当两个浏览器通过 WebRTC 建立连接并交换数据时，可以使用 `RTCDataChannel` API 发送各种类型的数据，包括媒体数据 (`VideoFrame`, `AudioData`) 或其他自定义数据。
4. **使用 Screen Capture API 或 Media Devices API:** 当用户授权网页访问屏幕内容或摄像头/麦克风时，会涉及到 `MediaStreamTrack` 对象的创建和可能的跨模块传输。

**总结 (作为第 3 部分):**

这个测试文件的主要目的是**验证 Chromium Blink 引擎中用于模块间 JavaScript 值序列化和传输的 `V8ScriptValueSerializerForModules` 类的正确性和健壮性**。它通过一系列针对不同 Web API 对象和场景的单元测试，确保在模块化 JavaScript 环境下，数据的序列化、反序列化和传输行为符合预期，并且能够正确处理各种边界情况和错误场景。这些测试对于保证 Web API 在 Chromium 浏览器中的稳定性和互操作性至关重要。

Prompt: 
```
这是目录为blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
>close();

  // Serializing the closed frame should throw an error.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<VideoFrame>::ToV8(scope.GetScriptState(), blink_frame);
  EXPECT_FALSE(
      V8ScriptValueSerializer(scope.GetScriptState())
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(HadDOMExceptionInModulesTest("DataCloneError",
                                           scope.GetScriptState(), try_catch));
}

TEST(V8ScriptValueSerializerForModulesTest, RoundTripAudioData) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  const unsigned kChannels = 2;
  const unsigned kSampleRate = 8000;
  const unsigned kFrames = 500;
  constexpr base::TimeDelta kTimestamp = base::Milliseconds(314);

  auto audio_bus = media::AudioBus::Create(kChannels, kFrames);

  // Populate each sample with a unique value.
  const unsigned kTotalSamples = (kFrames * kChannels);
  const float kSampleMultiplier = 1.0 / kTotalSamples;
  for (unsigned ch = 0; ch < kChannels; ++ch) {
    float* data = audio_bus->channel(ch);
    for (unsigned i = 0; i < kFrames; ++i)
      data[i] = (i + ch * kFrames) * kSampleMultiplier;
  }

  // Copying the data from an AudioBus instead of creating a media::AudioBuffer
  // directly is acceptable/desirable here, as it's a path often exercised when
  // receiving microphone/WebCam data.
  auto audio_buffer =
      media::AudioBuffer::CopyFrom(kSampleRate, kTimestamp, audio_bus.get());

  auto* audio_data = MakeGarbageCollected<AudioData>(std::move(audio_buffer));

  // Round trip the frame and make sure the size is the same.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<AudioData>::ToV8(scope.GetScriptState(), audio_data);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);

  // The data should have been copied, not transferred.
  EXPECT_TRUE(audio_data->data());

  AudioData* new_data = V8AudioData::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_data, nullptr);
  EXPECT_EQ(base::Microseconds(new_data->timestamp()), kTimestamp);
  EXPECT_EQ(new_data->numberOfChannels(), kChannels);
  EXPECT_EQ(new_data->numberOfFrames(), kFrames);
  EXPECT_EQ(new_data->sampleRate(), kSampleRate);

  // Copy out the frames to make sure they haven't been changed during the
  // transfer.
  DOMArrayBuffer* copy_dest = DOMArrayBuffer::Create(kFrames, sizeof(float));
  AllowSharedBufferSource* dest =
      MakeGarbageCollected<AllowSharedBufferSource>(copy_dest);
  AudioDataCopyToOptions* options =
      MakeGarbageCollected<AudioDataCopyToOptions>();

  for (unsigned int ch = 0; ch < kChannels; ++ch) {
    options->setPlaneIndex(ch);
    new_data->copyTo(dest, options, scope.GetExceptionState());
    EXPECT_FALSE(scope.GetExceptionState().HadException());

    float* new_samples = static_cast<float*>(copy_dest->Data());

    for (unsigned int i = 0; i < kFrames; ++i)
      ASSERT_EQ(new_samples[i], (i + ch * kFrames) * kSampleMultiplier);
  }

  // Closing the original |audio_data| should not affect |new_data|.
  audio_data->close();
  EXPECT_TRUE(new_data->data());
}

TEST(V8ScriptValueSerializerForModulesTest, TransferAudioData) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  const unsigned kFrames = 500;
  auto audio_buffer = media::AudioBuffer::CreateEmptyBuffer(
      media::ChannelLayout::CHANNEL_LAYOUT_STEREO,
      /*channel_count=*/2,
      /*sample_rate=*/8000, kFrames, base::Milliseconds(314));

  auto* audio_data = MakeGarbageCollected<AudioData>(audio_buffer);

  // Transfer the frame and make sure the size is the same.
  Transferables transferables;
  AudioDataTransferList* transfer_list =
      transferables.GetOrCreateTransferList<AudioDataTransferList>();
  transfer_list->audio_data_collection.push_back(audio_data);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<AudioData>::ToV8(scope.GetScriptState(), audio_data);
  v8::Local<v8::Value> result =
      RoundTripForModules(wrapper, scope, &transferables);

  AudioData* new_data = V8AudioData::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_data, nullptr);
  EXPECT_EQ(new_data->numberOfFrames(), kFrames);

  EXPECT_FALSE(audio_buffer->HasOneRef());

  // The transfer should have closed the source data.
  EXPECT_EQ(audio_data->format(), std::nullopt);

  // Closing |new_data| should remove all references to |audio_buffer|.
  new_data->close();
  EXPECT_TRUE(audio_buffer->HasOneRef());
}

TEST(V8ScriptValueSerializerForModulesTest, ClosedAudioDataThrows) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::TryCatch try_catch(scope.GetIsolate());

  auto audio_buffer = media::AudioBuffer::CreateEmptyBuffer(
      media::ChannelLayout::CHANNEL_LAYOUT_STEREO,
      /*channel_count=*/2,
      /*sample_rate=*/8000,
      /*frame_count=*/500, base::Milliseconds(314));

  // Create and close the frame.
  auto* audio_data = MakeGarbageCollected<AudioData>(std::move(audio_buffer));
  audio_data->close();

  // Serializing the closed frame should throw an error.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<AudioData>::ToV8(scope.GetScriptState(), audio_data);
  EXPECT_FALSE(
      V8ScriptValueSerializer(scope.GetScriptState())
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(HadDOMExceptionInModulesTest("DataCloneError",
                                           scope.GetScriptState(), try_catch));
}

TEST(V8ScriptValueSerializerForModulesTest, TransferMediaStreamTrack) {
  test::TaskEnvironment task_environment;
  // This flag is default-off for Android, so we force it on to test this
  // functionality.
  ScopedRegionCaptureForTest region_capture(true);
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;

  const auto session_id = base::UnguessableToken::Create();
  MediaStreamComponent* component =
      MakeTabCaptureVideoComponentForTest(&scope.GetFrame(), session_id);
  MediaStreamTrack* blink_track =
      MakeGarbageCollected<BrowserCaptureMediaStreamTrack>(
          scope.GetExecutionContext(), component,
          MediaStreamSource::ReadyState::kReadyStateMuted,
          /*callback=*/base::DoNothing());
  blink_track->setEnabled(false);

  ScopedMockMediaStreamTrackFromTransferredState mock_impl;

  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  v8::Local<v8::Value> result =
      RoundTripForModules(wrapper, scope, &transferables);

  // Transferring should have ended the original track.
  EXPECT_TRUE(blink_track->Ended());

  EXPECT_EQ(V8MediaStreamTrack::ToWrappable(scope.GetIsolate(), result),
            mock_impl.return_value.Get());

  const auto& data = mock_impl.last_argument;
  // The assertions here match the TransferredValues in
  // MediaStreamTrackTransferTest.TabCaptureVideoFromTransferredState. If you
  // change this test, please augment MediaStreamTrackTransferTest to test the
  // new scenario.
  EXPECT_EQ(data.track_impl_subtype,
            BrowserCaptureMediaStreamTrack::GetStaticWrapperTypeInfo());
  EXPECT_EQ(data.session_id, session_id);
  // TODO(crbug.com/1352414): assert correct data.transfer_id
  EXPECT_EQ(data.kind, "video");
  EXPECT_EQ(data.id, "component_id");
  EXPECT_EQ(data.label, "test_name");
  EXPECT_EQ(data.enabled, false);
  EXPECT_EQ(data.muted, true);
  EXPECT_EQ(data.content_hint,
            WebMediaStreamTrack::ContentHintType::kVideoMotion);
  EXPECT_EQ(data.ready_state, MediaStreamSource::ReadyState::kReadyStateLive);
  EXPECT_EQ(data.sub_capture_target_version, std::optional<uint32_t>(0));
}

TEST(V8ScriptValueSerializerForModulesTest,
     TransferMediaStreamTrackRegionCaptureDisabled) {
  test::TaskEnvironment task_environment;
  // Test with region capture disabled, since this is the default for Android.
  ScopedRegionCaptureForTest region_capture(false);
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;

  const auto session_id = base::UnguessableToken::Create();
  MediaStreamComponent* component =
      MakeTabCaptureVideoComponentForTest(&scope.GetFrame(), session_id);
  MediaStreamTrack* blink_track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component,
      MediaStreamSource::ReadyState::kReadyStateLive,
      /*callback=*/base::DoNothing());

  ScopedMockMediaStreamTrackFromTransferredState mock_impl;

  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  v8::Local<v8::Value> result =
      RoundTripForModules(wrapper, scope, &transferables);

  EXPECT_EQ(V8MediaStreamTrack::ToWrappable(scope.GetIsolate(), result),
            mock_impl.return_value.Get());

  const auto& data = mock_impl.last_argument;
  EXPECT_EQ(data.track_impl_subtype,
            MediaStreamTrack::GetStaticWrapperTypeInfo());
  EXPECT_FALSE(data.sub_capture_target_version.has_value());
}

TEST(V8ScriptValueSerializerForModulesTest, TransferAudioMediaStreamTrack) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  const auto session_id = base::UnguessableToken::Create();
  MediaStreamComponent* component =
      MakeTabCaptureAudioComponentForTest(session_id);
  MediaStreamTrack* blink_track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component,
      MediaStreamSource::ReadyState::kReadyStateMuted,
      /*callback=*/base::DoNothing());

  ScopedMockMediaStreamTrackFromTransferredState mock_impl;

  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  v8::Local<v8::Value> result =
      RoundTripForModules(wrapper, scope, &transferables);

  // Transferring should have ended the original track.
  EXPECT_TRUE(blink_track->Ended());

  EXPECT_EQ(V8MediaStreamTrack::ToWrappable(scope.GetIsolate(), result),
            mock_impl.return_value.Get());

  const auto& data = mock_impl.last_argument;
  // The assertions here match the TransferredValues in
  // MediaStreamTrackTransferTest.TabCaptureAudioFromTransferredState. If you
  // change this test, please augment MediaStreamTrackTransferTest to test the
  // new scenario.
  EXPECT_EQ(data.track_impl_subtype,
            MediaStreamTrack::GetStaticWrapperTypeInfo());
  EXPECT_EQ(data.session_id, session_id);
  // TODO(crbug.com/1352414): assert correct data.transfer_id
  EXPECT_EQ(data.kind, "audio");
  EXPECT_EQ(data.id, "component_id");
  EXPECT_EQ(data.label, "test_name");
  EXPECT_EQ(data.enabled, true);
  EXPECT_EQ(data.muted, true);
  EXPECT_EQ(data.content_hint,
            WebMediaStreamTrack::ContentHintType::kAudioSpeech);
  EXPECT_EQ(data.ready_state, MediaStreamSource::ReadyState::kReadyStateLive);
}

TEST(V8ScriptValueSerializerForModulesTest,
     TransferClonedMediaStreamTrackFails) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;
  ScriptState* script_state = scope.GetScriptState();
  MediaStreamComponent* video_component = MakeTabCaptureVideoComponentForTest(
      &scope.GetFrame(), base::UnguessableToken::Create());
  // audio_component cases are disabled due to DCHECKs, see crbug.com/371234481.
  // MediaStreamComponent* audio_component =
  //    MakeTabCaptureAudioComponentForTest(base::UnguessableToken::Create());
  for (MediaStreamComponent* component :
       {video_component, /* audio_component */}) {
    MediaStreamTrack* original_track =
        MakeGarbageCollected<BrowserCaptureMediaStreamTrack>(
            scope.GetExecutionContext(), component,
            MediaStreamSource::ReadyState::kReadyStateMuted,
            /*callback=*/base::DoNothing());
    MediaStreamTrack* cloned_track =
        original_track->clone(scope.GetExecutionContext());
    for (MediaStreamTrack* track : {original_track, cloned_track}) {
      v8::TryCatch try_catch(scope.GetIsolate());
      Transferables transferables;
      transferables.media_stream_tracks.push_back(track);
      v8::Local<v8::Value> wrapper =
          ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), track);
      V8ScriptValueSerializer::Options serialize_options;
      serialize_options.transferables = &transferables;
      EXPECT_FALSE(
          V8ScriptValueSerializerForModules(script_state, serialize_options)
              .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
      EXPECT_TRUE(HadDOMExceptionInModulesTest("DataCloneError", script_state,
                                               try_catch));
    }
  }
}

TEST(V8ScriptValueSerializerForModulesTest,
     TransferDeviceCaptureMediaStreamTrackFails) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;

  auto mock_source = std::make_unique<MediaStreamVideoCapturerSource>(
      scope.GetFrame().GetTaskRunner(TaskType::kInternalMediaRealTime),
      &scope.GetFrame(),
      MediaStreamVideoCapturerSource::SourceStoppedCallback(),
      std::make_unique<MockVideoCapturerSource>());
  auto platform_track = std::make_unique<MediaStreamVideoTrack>(
      mock_source.get(),
      WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      /*enabled=*/true);

  MediaStreamDevice device(mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE,
                           "device_id", "device_name");
  device.set_session_id(base::UnguessableToken::Create());
  mock_source->SetDevice(device);
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "test_id", MediaStreamSource::StreamType::kTypeVideo, "test_name",
      /*remote=*/false, std::move(mock_source));
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>("component_id", source,
                                                     std::move(platform_track));
  component->SetContentHint(WebMediaStreamTrack::ContentHintType::kVideoMotion);
  MediaStreamTrack* blink_track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component,
      MediaStreamSource::ReadyState::kReadyStateMuted,
      /*callback=*/base::DoNothing());

  // Transferring MediaStreamTrack should fail for Device Capture type device.
  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = &transferables;
  ScriptState* script_state = scope.GetScriptState();
  v8::TryCatch try_catch(scope.GetIsolate());
  EXPECT_FALSE(
      V8ScriptValueSerializerForModules(script_state, serialize_options)
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(
      HadDOMExceptionInModulesTest("DataCloneError", script_state, try_catch));
}

TEST(V8ScriptValueSerializerForModulesTest,
     TransferScreenCaptureMediaStreamTrackFails) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;

  auto mock_source = std::make_unique<MediaStreamVideoCapturerSource>(
      scope.GetFrame().GetTaskRunner(TaskType::kInternalMediaRealTime),
      &scope.GetFrame(),
      MediaStreamVideoCapturerSource::SourceStoppedCallback(),
      std::make_unique<MockVideoCapturerSource>());
  auto platform_track = std::make_unique<MediaStreamVideoTrack>(
      mock_source.get(),
      WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      /*enabled=*/true);

  MediaStreamDevice device(mojom::MediaStreamType::DISPLAY_VIDEO_CAPTURE,
                           "device_id", "device_name");
  device.set_session_id(base::UnguessableToken::Create());
  device.display_media_info = media::mojom::DisplayMediaInformation::New(
      media::mojom::DisplayCaptureSurfaceType::MONITOR,
      /*logical_surface=*/true, media::mojom::CursorCaptureType::NEVER,
      /*capture_handle=*/nullptr,
      /*initial_zoom_level=*/100);
  mock_source->SetDevice(device);
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "test_id", MediaStreamSource::StreamType::kTypeVideo, "test_name",
      /*remote=*/false, std::move(mock_source));
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>("component_id", source,
                                                     std::move(platform_track));
  component->SetContentHint(WebMediaStreamTrack::ContentHintType::kVideoMotion);
  MediaStreamTrack* blink_track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component,
      MediaStreamSource::ReadyState::kReadyStateMuted,
      /*callback=*/base::DoNothing());

  // Transferring MediaStreamTrack should fail for screen captures.
  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = &transferables;
  ScriptState* script_state = scope.GetScriptState();
  v8::TryCatch try_catch(scope.GetIsolate());
  EXPECT_FALSE(
      V8ScriptValueSerializerForModules(script_state, serialize_options)
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(
      HadDOMExceptionInModulesTest("DataCloneError", script_state, try_catch));
}

TEST(V8ScriptValueSerializerForModulesTest,
     TransferWindowCaptureMediaStreamTrackFails) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;

  auto mock_source = std::make_unique<MediaStreamVideoCapturerSource>(
      scope.GetFrame().GetTaskRunner(TaskType::kInternalMediaRealTime),
      &scope.GetFrame(),
      MediaStreamVideoCapturerSource::SourceStoppedCallback(),
      std::make_unique<MockVideoCapturerSource>());
  auto platform_track = std::make_unique<MediaStreamVideoTrack>(
      mock_source.get(),
      WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      /*enabled=*/true);

  MediaStreamDevice device(mojom::MediaStreamType::DISPLAY_VIDEO_CAPTURE,
                           "device_id", "device_name");
  device.set_session_id(base::UnguessableToken::Create());
  device.display_media_info = media::mojom::DisplayMediaInformation::New(
      media::mojom::DisplayCaptureSurfaceType::WINDOW,
      /*logical_surface=*/true, media::mojom::CursorCaptureType::NEVER,
      /*capture_handle=*/nullptr,
      /*zoom_level=*/100);
  mock_source->SetDevice(device);
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "test_id", MediaStreamSource::StreamType::kTypeVideo, "test_name",
      /*remote=*/false, std::move(mock_source));
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>("component_id", source,
                                                     std::move(platform_track));
  component->SetContentHint(WebMediaStreamTrack::ContentHintType::kVideoMotion);
  MediaStreamTrack* blink_track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component,
      MediaStreamSource::ReadyState::kReadyStateMuted,
      /*callback=*/base::DoNothing());

  // Transferring MediaStreamTrack should fail for window captures.
  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = &transferables;
  ScriptState* script_state = scope.GetScriptState();
  v8::TryCatch try_catch(scope.GetIsolate());
  EXPECT_FALSE(
      V8ScriptValueSerializerForModules(script_state, serialize_options)
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(
      HadDOMExceptionInModulesTest("DataCloneError", script_state, try_catch));
}

TEST(V8ScriptValueSerializerForModulesTest,
     TransferClosedMediaStreamTrackFails) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;
  ScriptState* script_state = scope.GetScriptState();
  v8::TryCatch try_catch(scope.GetIsolate());

  MediaStreamComponent* component = MakeTabCaptureVideoComponentForTest(
      &scope.GetFrame(), base::UnguessableToken::Create());
  MediaStreamTrack* blink_track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component,
      MediaStreamSource::ReadyState::kReadyStateMuted,
      /*callback=*/base::DoNothing());
  blink_track->stopTrack(scope.GetExecutionContext());
  ASSERT_TRUE(blink_track->Ended());

  // Transferring a closed MediaStreamTrack should throw an error.
  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = &transferables;
  EXPECT_FALSE(
      V8ScriptValueSerializerForModules(script_state, serialize_options)
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(
      HadDOMExceptionInModulesTest("DataCloneError", script_state, try_catch));
}

TEST(V8ScriptValueSerializerForModulesTest,
     TransferMediaStreamTrackInvalidContentHintFails) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;
  ScriptState* script_state = scope.GetScriptState();
  v8::TryCatch try_catch(scope.GetIsolate());

  MediaStreamComponent* component = MakeTabCaptureVideoComponentForTest(
      &scope.GetFrame(), base::UnguessableToken::Create());
  component->SetContentHint(
      static_cast<WebMediaStreamTrack::ContentHintType>(666));
  MediaStreamTrack* blink_track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component,
      MediaStreamSource::ReadyState::kReadyStateMuted,
      /*callback=*/base::DoNothing());

  // Transfer a MediaStreamTrack with an invalid contentHint which should throw
  // an error.
  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = &transferables;
  EXPECT_FALSE(
      V8ScriptValueSerializer(script_state, serialize_options)
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(
      HadDOMExceptionInModulesTest("DataCloneError", script_state, try_catch));
  EXPECT_FALSE(blink_track->Ended());
}

TEST(V8ScriptValueSerializerForModulesTest,
     TransferMediaStreamTrackNoSessionIdThrows) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform;
  ScriptState* script_state = scope.GetScriptState();
  v8::TryCatch try_catch(scope.GetIsolate());

  auto mock_source = std::make_unique<MediaStreamVideoCapturerSource>(
      scope.GetFrame().GetTaskRunner(TaskType::kInternalMediaRealTime),
      &scope.GetFrame(),
      MediaStreamVideoCapturerSource::SourceStoppedCallback(),
      std::make_unique<MockVideoCapturerSource>());
  auto platform_track = std::make_unique<MediaStreamVideoTrack>(
      mock_source.get(),
      WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      /*enabled=*/true);

  MediaStreamDevice device(mojom::MediaStreamType::DISPLAY_VIDEO_CAPTURE,
                           "device_id", "device_name");
  device.display_media_info = media::mojom::DisplayMediaInformation::New(
      media::mojom::DisplayCaptureSurfaceType::BROWSER,
      /*logical_surface=*/true, media::mojom::CursorCaptureType::NEVER,
      /*capture_handle=*/nullptr,
      /*zoom_level=*/100);
  mock_source->SetDevice(device);
  MediaStreamSource* source = MakeGarbageCollected<MediaStreamSource>(
      "test_id", MediaStreamSource::StreamType::kTypeVideo, "test_name",
      /*remote=*/false, std::move(mock_source));
  MediaStreamComponent* component =
      MakeGarbageCollected<MediaStreamComponentImpl>("component_id", source,
                                                     std::move(platform_track));
  component->SetContentHint(WebMediaStreamTrack::ContentHintType::kVideoMotion);
  MediaStreamTrack* blink_track = MakeGarbageCollected<MediaStreamTrackImpl>(
      scope.GetExecutionContext(), component,
      MediaStreamSource::ReadyState::kReadyStateMuted,
      /*callback=*/base::DoNothing());

  // Transfer a MediaStreamTrack with no session id should throw an error.
  Transferables transferables;
  transferables.media_stream_tracks.push_back(blink_track);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MediaStreamTrack>::ToV8(scope.GetScriptState(), blink_track);
  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = &transferables;
  EXPECT_FALSE(
      V8ScriptValueSerializerForModules(script_state, serialize_options)
          .Serialize(wrapper, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(
      HadDOMExceptionInModulesTest("DataCloneError", script_state, try_catch));
  EXPECT_FALSE(blink_track->Ended());
}

TEST(V8ScriptValueSerializerForModulesTest, TransferRTCDataChannel) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedTransferableRTCDataChannelForTest scoped_feature(/*enabled=*/true);

  auto native_channel = FakeWebRTCDataChannel::Create();

  auto* original_channel = MakeGarbageCollected<RTCDataChannel>(
      scope.GetExecutionContext(), native_channel);

  EXPECT_TRUE(original_channel->IsTransferable());
  EXPECT_EQ(native_channel->unregister_call_count(), 0);
  EXPECT_EQ(native_channel->unregister_call_count(), 0);

  // Transfer the frame and make sure the size is the same.
  Transferables transferables;
  RTCDataChannelTransferList* transfer_list =
      transferables.GetOrCreateTransferList<RTCDataChannelTransferList>();
  transfer_list->data_channel_collection.push_back(original_channel);
  v8::Local<v8::Value> wrapper = ToV8Traits<RTCDataChannel>::ToV8(
      scope.GetScriptState(), original_channel);
  v8::Local<v8::Value> result =
      RoundTripForModules(wrapper, scope, &transferables);

  RTCDataChannel* new_channel =
      V8RTCDataChannel::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_channel, nullptr);

  // An RTCDataChannel is "neutered" after a single transfer, and cannot be
  // transferred again. However, the new RTCDataChannel can also be transferred
  // once. This allows chaining of transfers of the underlying `native_channel`.
  EXPECT_FALSE(original_channel->IsTransferable());
  EXPECT_TRUE(new_channel->IsTransferable());

  // The transfer should have closed the original channel but not the underlying
  // transport.
  EXPECT_EQ(original_channel->readyState(),
            V8RTCDataChannelState::Enum::kClosed);
  EXPECT_FALSE(native_channel->close_was_called());
  EXPECT_EQ(native_channel->unregister_call_count(), 0);

  // The new channel should not have immediately registered its observer. This
  // gives the new RTCDataChannel a brief opportunity to be transferred again;
  // transferring the underlying `native_channel` is allowed until we call
  // `send()`, or register an observer (after which we could lose incoming
  // messages during a transfer).
  EXPECT_EQ(native_channel->register_call_count(), 0);

  task_environment.RunUntilIdle();

  EXPECT_FALSE(new_channel->IsTransferable());

  EXPECT_EQ(native_channel->register_call_count(), 1);
  EXPECT_EQ(native_channel->unregister_call_count(), 0);
  EXPECT_FALSE(native_channel->close_was_called());
}

#if !BUILDFLAG(IS_ANDROID)  // SubCaptureTargets are not exposed on Android.
TEST(V8ScriptValueSerializerForModulesTest, RoundTripCropTarget) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  const String crop_id("8e7e0c22-67a0-4c39-b4dc-a20433262f8e");

  CropTarget* const crop_target = MakeGarbageCollected<CropTarget>(crop_id);

  v8::Local<v8::Value> wrapper =
      ToV8Traits<CropTarget>::ToV8(scope.GetScriptState(), crop_target);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);

  CropTarget* const new_crop_target =
      V8CropTarget::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_crop_target, nullptr);
  EXPECT_EQ(new_crop_target->GetId(), crop_id);
}

TEST(V8ScriptValueSerializerForModulesTest, RoundTripRestrictionTarget) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedElementCaptureForTest element_capture(true);

  const String restriction_id("8e7e0c22-67a0-4c39-b4dc-a20433262f8e");

  RestrictionTarget* const restriction_target =
      MakeGarbageCollected<RestrictionTarget>(restriction_id);

  v8::Local<v8::Value> wrapper = ToV8Traits<RestrictionTarget>::ToV8(
      scope.GetScriptState(), restriction_target);
  v8::Local<v8::Value> result = RoundTripForModules(wrapper, scope);

  RestrictionTarget* const new_restriction_target =
      V8RestrictionTarget::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_restriction_target, nullptr);
  EXPECT_EQ(new_restriction_target->GetId(), restriction_id);
}
#endif

TEST(V8ScriptValueSerializerForModulesTest,
     ArrayBufferDetachKeyPreventsTransfer) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  DOMArrayBuffer* ab = DOMArrayBuffer::Create(10, sizeof(float));
  v8::Local<v8::ArrayBuffer> v8_ab =
      ToV8Traits<DOMArrayBuffer>::ToV8(script_state, ab)
          .As<v8::ArrayBuffer>();
  v8_ab->SetDetachKey(V8AtomicString(isolate, "my key"));

  // Attempt to transfer the ArrayBuffer. It should fail with a TypeError
  // because the ArrayBufferDetachKey used to transfer is not "my key".
  Transferables transferables;
  transferables.array_buffers.push_back(ab);
  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = &transferables;
  v8::TryCatch try_catch(isolate);
  EXPECT_FALSE(
      V8ScriptValueSerializerForModules(script_state, serialize_options)
          .Serialize(v8_ab, PassThroughException(scope.GetIsolate())));
  EXPECT_TRUE(try_catch.HasCaught());
  EXPECT_THAT(
      ToCoreString(
          isolate,
          try_catch.Exception()->ToString(scope.GetContext()).ToLocalChecked())
          .Ascii(),
      testing::StartsWith("TypeError"));
  EXPECT_FALSE(v8_ab->WasDetached());
}

TEST(V8ScriptValueSerializerForModulesTest,
     ArrayBufferDetachKeyDoesNotPreventSerialize) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  DOMArrayBuffer* ab = DOMArrayBuffer::Create(10, sizeof(float));
  v8::Local<v8::ArrayBuffer> v8_ab =
      ToV8Traits<DOMArrayBuffer>::ToV8(script_state, ab)
          .As<v8::ArrayBuffer>();
  v8_ab->SetDetachKey(V8AtomicString(isolate, "my key"));

  // Attempt to serialize the ArrayBuffer. It should not fail with a TypeError
  // even though it has an ArrayBufferDetachKey because it will not be detached.
  V8ScriptValueSerializer::Options serialize_options;
  ExceptionState exception_state(isolate, v8::ExceptionContext::kOperation,
                                 "Window", "postMessage");
  EXPECT_TRUE(V8ScriptValueSerializerForModules(script_state, serialize_options)
                  .Serialize(v8_ab, exception_state));
  EXPECT_FALSE(exception_state.HadException());
  EXPECT_FALSE(v8_ab->WasDetached());
}

}  // namespace
}  // namespace blink

"""


```