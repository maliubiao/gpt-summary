Response:
The user wants to understand the functionality of the provided C++ code snippet from `media_recorder_handler_unittest.cc`. This is part 2 of the analysis. I need to summarize the functionality of this second part, considering any connections to JavaScript, HTML, CSS, logical inferences, potential user errors, and the user actions that might lead to this code being executed.

**Part 2 Analysis Plan:**

1. **Identify the main purpose of the tests:** This section focuses on various scenarios involving starting, stopping, pausing, and initializing the `MediaRecorderHandler` with different media types (audio/video), codecs, and configurations (especially the MP4 muxer). It also includes tests for the `CanSupportMimeType` functionality and handling encoded media data.
2. **Summarize the individual test cases:** Briefly describe what each test is checking. Pay attention to the assertions (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_CALL`, `EXPECT_EQ`).
3. **Analyze the relationships with web technologies:** Look for connections to JavaScript APIs (like `MediaRecorder`), HTML elements (like `<video>` or `<audio>`), and CSS (though less likely in this unit test context).
4. **Identify logical inferences and assumptions:**  Examine the test logic and note any assumptions about the input and expected output.
5. **Point out potential user/programmer errors:**  Consider how incorrect usage of the `MediaRecorder` API or misconfigurations could lead to failures or unexpected behavior tested here.
6. **Describe the user journey:**  Outline the steps a user might take in a web browser that would eventually trigger the execution of this backend code.
7. **Synthesize a concise summary:**  Combine the findings into a clear and comprehensive overview of the code's functionality.
这是 `blink/renderer/modules/mediarecorder/media_recorder_handler_unittest.cc` 文件的第二部分，主要功能是 **测试 `MediaRecorderHandler` 类在各种复杂场景下的行为**。这些场景包括：

**核心功能测试:**

* **`StartStopStartRecorderForVideo`:** 测试视频录制中途停止后再次启动是否正常工作。
* **MP4 Muxer 功能测试:**
    * **`InitializeFailedWhenMP4MuxerFeatureDisabled`:**  测试在禁用 MP4 muxer 特性时，初始化是否会失败。
    * **`CanSupportMimeTypeForMp4`:**  测试 `MediaRecorderHandler` 的 `CanSupportMimeType` 方法在启用或禁用 MP4 muxer 特性时，对于各种 MP4 相关的 MIME 类型和编解码器的支持情况判断是否正确。
    * **`CanSupportAacCodecForWinNSku`:** (Windows 平台特定) 测试在 Windows N 版本 SKU 上是否正确判断 AAC 编解码器的支持情况。
* **音频和视频混合录制测试:**
    * **`IgnoresStaleEncodedMediaOnRestart`:** 测试在停止并重新启动录制后，是否会忽略之前录制会话中产生的过时编码数据。
    * **`EmitsCachedAudioDataOnStop` 和 `EmitsCachedVideoDataOnStop`:** 测试在调用 `Stop()` 后，是否会发出缓存的音频或视频数据。
    * **`CorrectH264LevelOnWrite`:** (启用专有编解码器时) 测试在写入数据时是否能正确处理和设置 H.264 的 Level 信息。
    * **`EmitsCachedAudioDataAfterVideoTrackEnded`:** 测试在视频轨道结束后，是否能发出缓存的音频数据。
* **H.264 Profile 测试:**
    * **`ActualMimeType`:** 测试对于不同的 H.264 Profile，`ActualMimeType` 方法是否返回正确的 MIME 类型字符串。
* **Windows AAC 编解码器测试:**
    * **`AudioBitsPerSeconds`:** (Windows 平台特定, 启用专有编解码器时) 测试在指定音频比特率后，`MediaRecorderHandler` 是否能正确设置并传递该比特率。
* **Passthrough 模式测试:**
    * **`PassesThrough`:** 测试在 Passthrough 模式下，`MediaRecorderHandler` 是否能直接传递编码后的视频帧。
    * **`ErrorsOutOnCodecSwitch`:** 测试在 Passthrough 模式下，如果编码的视频帧的编解码器发生变化，是否会产生错误。
* **编解码器 Profile 测试:**
    * **`VideoStringToCodecProfile`:** 测试 `VideoStringToCodecProfile` 函数是否能正确将编解码器字符串转换为 `CodecProfile` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript (MediaRecorder API):** 这些测试直接关联到 JavaScript 的 `MediaRecorder` API。例如，用户在 JavaScript 中调用 `navigator.mediaDevices.getUserMedia()` 获取媒体流，然后创建一个 `MediaRecorder` 对象，并调用 `start()`, `stop()`, `pause()` 等方法。这些 JavaScript 调用最终会触发 Blink 引擎中 `MediaRecorderHandler` 及其相关类的操作。
    * **假设输入:**  JavaScript 代码调用 `recorder.start()`。
    * **输出:**  `MediaRecorderHandler` 的 `Start` 方法被调用，开始处理媒体数据。
* **HTML (Media 元素: `<video>`, `<audio>`):**  `MediaRecorder` 通常用于录制来自 `<video>` 或 `<audio>` 元素的媒体流，或者通过 `getUserMedia` 获取的摄像头或麦克风的流。
    * **举例:** 用户在 HTML 页面中有一个 `<video>` 元素，通过 JavaScript 获取了该元素的流，并用该流创建了 `MediaRecorder`。
* **CSS:**  CSS 与此文件的功能关系较弱，主要负责页面的样式，而 `MediaRecorderHandler` 专注于媒体数据的处理和编码。

**逻辑推理与假设输入/输出:**

* **`StartStopStartRecorderForVideo`:**
    * **假设输入:**  调用 `Start()`, 然后调用 `Stop()`, 最后再次调用 `Start()`。
    * **输出:**  两次 `Start()` 调用都能成功启动录制，并且在录制过程中能够接收并处理视频数据。
* **`CanSupportMimeTypeForMp4`:**
    * **假设输入:**  传递不同的 MIME 类型字符串（例如 "video/mp4", "audio/mp4"）和编解码器字符串（例如 "avc1", "opus"）给 `CanSupportMimeType` 方法。
    * **输出:**  方法返回 `true` 或 `false`，指示是否支持该 MIME 类型和编解码器组合，结果取决于 MP4 muxer 特性是否启用以及编解码器是否受支持。
* **`IgnoresStaleEncodedMediaOnRestart`:**
    * **假设输入:**  启动录制，产生一些编码数据，停止录制，然后再次启动录制。
    * **输出:**  第二次录制不应包含第一次录制产生的任何数据。

**用户或编程常见的使用错误:**

* **MIME 类型和编解码器不匹配:** 用户在 JavaScript 中创建 `MediaRecorder` 时，指定的 `mimeType` 参数可能与实际的媒体流的编解码器不兼容，导致初始化失败或录制过程中出现错误。
    * **举例:** 用户尝试使用 "video/webm" 录制一个 H.264 编码的视频流。
* **在不支持的平台上使用特定的编解码器:**  例如，在某些浏览器或操作系统上可能不支持 AAC 编解码器，用户尝试使用该编解码器进行录制会导致失败。
* **在 Passthrough 模式下切换编解码器:** 用户在 Passthrough 模式下期望 `MediaRecorder` 能处理不同编解码器的视频帧，但实际上这是不支持的，会导致错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户打开一个网页:** 网页中包含使用 `MediaRecorder` API 的 JavaScript 代码。
2. **网页 JavaScript 请求访问用户媒体设备:**  例如，调用 `navigator.mediaDevices.getUserMedia({ video: true, audio: true })`。
3. **用户授权访问:** 用户允许网页访问摄像头和麦克风。
4. **网页 JavaScript 创建 `MediaRecorder` 对象:** 使用获取的媒体流和指定的 `mimeType` (例如 "video/webm; codecs=vp9")。
5. **网页 JavaScript 调用 `recorder.start()`:**  开始录制。
6. **用户进行操作 (例如对着摄像头说话或移动):** 产生音视频数据。
7. **Blink 引擎处理媒体流:**  `MediaStream` 对象接收来自底层媒体管道的数据。
8. **`MediaRecorderHandler` 开始处理数据:**  `MediaRecorderHandler` 从 `MediaStreamTrack` 获取编码后的数据（或者在非 Passthrough 模式下进行编码）。
9. **如果启用了 MP4 muxer 并且 `mimeType` 包含 MP4:** 相关的 MP4 muxer 代码会被调用。
10. **网页 JavaScript 调用 `recorder.stop()`:** 停止录制。
11. **`MediaRecorderHandler` 完成录制:** 将所有缓存的数据写入到 `Blob` 中，并通过 `ondataavailable` 事件返回给 JavaScript。

**归纳一下它的功能 (第二部分):**

这部分代码全面测试了 `MediaRecorderHandler` 类在各种高级和特定的场景下的行为，包括：

* **录制生命周期的管理:**  测试启动、停止和暂停操作的正确性。
* **MP4 封装的支持:**  测试在启用和禁用 MP4 muxer 特性时，`MediaRecorderHandler` 对 MP4 容器格式的支持和 MIME 类型判断。
* **音频和视频混合录制:**  测试同时录制音频和视频时的行为，包括数据缓存和事件处理。
* **特定编解码器的处理:**  测试对 H.264 和 AAC 等编解码器的特定处理逻辑，例如 Profile 和 Level 的设置。
* **Passthrough 模式:** 测试直接传递编码后媒体数据的能力和限制。
* **错误处理:**  测试在遇到不支持的编解码器或配置时的错误处理机制。

总而言之，这部分单元测试旨在确保 `MediaRecorderHandler` 在各种复杂的用例下都能可靠且正确地工作，为 Web 开发者提供稳定的 `MediaRecorder` API 功能。

### 提示词
```
这是目录为blink/renderer/modules/mediarecorder/media_recorder_handler_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
  EXPECT_TRUE(media_recorder_handler_->Start(0, mime_type, 0, 0));

  Mock::VerifyAndClearExpectations(recorder);
  media_recorder_handler_->Pause();

  if (GetParam().use_mp4_muxer) {
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
    media::Muxer::VideoParameters params(
        gfx::Size(), 1, media::VideoCodec::kH264, gfx::ColorSpace());
    std::vector<uint8_t> codec_description;
    PopulateAVCDecoderConfiguration(codec_description);
    OnEncodedH264VideoForTesting(base::TimeTicks::Now(),
                                 std::move(codec_description));
    media_recorder_handler_->Stop();
#endif
  } else {
    EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
    media::Muxer::VideoParameters params(
        gfx::Size(), 1, media::VideoCodec::kVP9, gfx::ColorSpace());
    if (IsAvc1CodecSupported(codecs)) {
      OnEncodedH264VideoForTesting(base::TimeTicks::Now());
    } else {
      auto buffer =
          media::DecoderBuffer::CopyFrom(base::as_byte_span("vp9 frame"));
      std::string alpha_data = "alpha";
      buffer->WritableSideData().alpha_data =
          base::HeapArray<uint8_t>::CopiedFrom(base::as_byte_span(alpha_data));
      buffer->set_is_key_frame(true);
      OnEncodedVideoForTesting(params, buffer, base::TimeTicks::Now());
    }
  }

  Mock::VerifyAndClearExpectations(recorder);

  // Make sure the |media_recorder_handler_| gets destroyed and removing sinks
  // before the MediaStreamVideoTrack dtor, avoiding a DCHECK on a non-empty
  // callback list.
  media_recorder_handler_ = nullptr;
}

TEST_P(MediaRecorderHandlerTest, StartStopStartRecorderForVideo) {
  // Video-only test: Audio would be very similar.
  if (GetParam().has_audio || !IsStreamWriteSupported()) {
    return;
  }

  AddTracks();

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);

  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);

  if (!IsAv1CodecSupported(codecs)) {
    return;
  }

  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
  EXPECT_TRUE(media_recorder_handler_->Start(0, mime_type, 0, 0));
  media_recorder_handler_->Stop();

  Mock::VerifyAndClearExpectations(recorder);
  EXPECT_TRUE(media_recorder_handler_->Start(0, mime_type, 0, 0));

  EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
  media::Muxer::VideoParameters params(gfx::Size(), 1, media::VideoCodec::kVP9,
                                       gfx::ColorSpace());
  if (IsAvc1CodecSupported(codecs)) {
    OnEncodedH264VideoForTesting(base::TimeTicks::Now());
  } else {
    auto buffer =
        media::DecoderBuffer::CopyFrom(base::as_byte_span("vp9 frame"));
    std::string alpha_data = "alpha";
    buffer->WritableSideData().alpha_data =
        base::HeapArray<uint8_t>::CopiedFrom(base::as_byte_span(alpha_data));
    buffer->set_is_key_frame(true);
    OnEncodedVideoForTesting(params, buffer, base::TimeTicks::Now());
  }

  Mock::VerifyAndClearExpectations(recorder);

  // Make sure the |media_recorder_handler_| gets destroyed and removing sinks
  // before the MediaStreamVideoTrack dtor, avoiding a DCHECK on a non-empty
  // callback list.
  media_recorder_handler_ = nullptr;
}

INSTANTIATE_TEST_SUITE_P(All,
                         MediaRecorderHandlerTest,
                         ValuesIn(kMediaRecorderTestParams));
class MediaRecorderHandlerTestForMp4
    : public TestWithParam<MediaRecorderTestParams>,
      public MediaRecorderHandlerFixture {
 public:
  MediaRecorderHandlerTestForMp4()
      : MediaRecorderHandlerFixture(GetParam().has_video,
                                    GetParam().has_audio) {
    scoped_feature_list_.InitAndDisableFeature(kMediaRecorderEnableMp4Muxer);
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Array of valid combinations of video/audio/codecs for mp4.
static const MediaRecorderTestParams kMediaRecorderTestParamsForMp4[] = {
    {false, true, false, "video/mp4", "avc1", false},
    {false, true, false, "video/mp4", "avc1", false},
    {false, false, true, "audio/mp4", "mp4a.40.2", false},
    {false, true, true, "video/mp4", "avc1,mp4a.40.2", false},
    {false, true, true, "audio/mp4", "opus", false},
    {false, true, true, "video/mp4", "avc1,opus", false},
};

TEST_P(MediaRecorderHandlerTestForMp4,
       InitializeFailedWhenMP4MuxerFeatureDisabled) {
  if (!IsTargetAudioCodecSupported(GetParam().codecs)) {
    return;
  }

  // When feature is disabled, Initialize will fail.
  AddTracks();
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);
  EXPECT_FALSE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
}

INSTANTIATE_TEST_SUITE_P(All,
                         MediaRecorderHandlerTestForMp4,
                         ValuesIn(kMediaRecorderTestParamsForMp4));

class MediaRecorderHandlerIsSupportedTypeTestForMp4
    : public TestWithParam<bool>,
      public MediaRecorderHandlerFixture {
 public:
  MediaRecorderHandlerIsSupportedTypeTestForMp4()
      : MediaRecorderHandlerFixture(true, true) {
    if (GetParam()) {
      scoped_feature_list_.InitAndEnableFeature(kMediaRecorderEnableMp4Muxer);
    } else {
      scoped_feature_list_.InitAndDisableFeature(kMediaRecorderEnableMp4Muxer);
    }
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Checks that canSupportMimeType() works as expected, by sending supported
// combinations and unsupported ones.
TEST_P(MediaRecorderHandlerIsSupportedTypeTestForMp4,
       CanSupportMimeTypeForMp4) {
  // video types.
  const String good_mp4_video_mime_types[] = {"video/mp4"};
  const String bad_mp4_video_mime_types[] = {"video/MP4"};

  const String good_mp4_video_codecs[] = {"avc1", "avc1.420034", "vp9", "av01",
                                          "av01.2.19H.08.0.000.09.16.09.1"};
  const String bad_mp4_video_codecs[] = {"h264", "vp8",         "avc11",
                                         "aVc1", "avc1.123456", "av1"};

  const String good_mp4_video_codecs_non_proprietory[] = {
      "vp9", "av01", "av01.2.19H.08.0.000.09.16.09.1"};
  const String bad_mp4_video_codecs_non_proprietory[] = {
      "avc1", "h264", "vp8", "avc11", "aVc1", "avc1.123456", "av1"};

  // audio types.
  const String good_mp4_audio_mime_types[] = {"audio/mp4"};
  const String bad_mp4_audio_mime_types[] = {"AUDIO/mp4"};

  const String good_mp4_audio_codecs[] = {"mp4a.40.2, opus"};
  const String bad_mp4_audio_codecs[] = {"mp4a", "mp4a.40", "mP4a.40.2", "aac",
                                         "pcm"};

  const String good_mp4_audio_codecs_non_proprietory[] = {"opus"};
  const String bad_mp4_audio_codecs_non_proprietory[] = {
      "mp4a.40.2", "mp4a", "mp4a.40", "mP4a.40.2", "aac", "pcm"};

  if (GetParam()) {
    // mp4, enabled feature of kMediaRecorderEnableMp4Muxer.
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    // success cases.
    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& codec : good_mp4_video_codecs) {
        if (!IsAv1CodecSupported(codec)) {
          continue;
        }
        EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& codec : good_mp4_audio_codecs) {
        if (!IsTargetAudioCodecSupported(codec)) {
          continue;
        }
        EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& video_codec : good_mp4_video_codecs) {
        if (!IsAv1CodecSupported(video_codec)) {
          continue;
        }
        for (const auto& audio_codec : good_mp4_audio_codecs) {
          if (!IsTargetAudioCodecSupported(audio_codec)) {
            continue;
          }
          String codecs = video_codec + "," + audio_codec;
          EXPECT_TRUE(
              media_recorder_handler_->CanSupportMimeType(type, codecs));

          String codecs2 = audio_codec + "," + video_codec;
          EXPECT_TRUE(
              media_recorder_handler_->CanSupportMimeType(type, codecs2));
        }
      }
    }

    // failure cases.
    for (const auto& type : bad_mp4_video_mime_types) {
      for (const auto& codec : good_mp4_video_codecs) {
        if (!IsAv1CodecSupported(codec)) {
          continue;
        }
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& codec : bad_mp4_video_codecs) {
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }
#else
    // success cases.
    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& codec : good_mp4_video_codecs_non_proprietory) {
        if (!IsAv1CodecSupported(codec)) {
          continue;
        }
        EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& codec : good_mp4_audio_codecs_non_proprietory) {
        EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& video_codec : good_mp4_video_codecs_non_proprietory) {
        if (!IsAv1CodecSupported(video_codec)) {
          continue;
        }
        for (const auto& audio_codec : good_mp4_audio_codecs_non_proprietory) {
          String codecs = video_codec + "," + audio_codec;
          EXPECT_TRUE(
              media_recorder_handler_->CanSupportMimeType(type, codecs));

          String codecs2 = audio_codec + "," + video_codec;
          EXPECT_TRUE(
              media_recorder_handler_->CanSupportMimeType(type, codecs2));
        }
      }
    }

    // failure cases.
    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& codec : bad_mp4_video_codecs) {
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }
#endif

    // audio mime types.
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    // success cases.
    for (const auto& type : good_mp4_audio_mime_types) {
      for (const auto& codec : good_mp4_audio_codecs) {
        if (!IsTargetAudioCodecSupported(codec)) {
          continue;
        }
        EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    // failure cases.
    for (const auto& type : bad_mp4_audio_mime_types) {
      for (const auto& codec : good_mp4_audio_codecs) {
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    for (const auto& type : good_mp4_audio_mime_types) {
      for (const auto& codec : bad_mp4_audio_codecs) {
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    for (const auto& type : good_mp4_audio_mime_types) {
      for (const auto& codec : good_mp4_video_codecs) {
        if (!IsAv1CodecSupported(codec)) {
          continue;
        }
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    for (const auto& type : good_mp4_audio_mime_types) {
      for (const auto& video_codec : good_mp4_video_codecs) {
        if (!IsAv1CodecSupported(video_codec)) {
          continue;
        }
        for (const auto& audio_codec : good_mp4_audio_codecs) {
          String codecs = video_codec + "," + audio_codec;
          EXPECT_FALSE(
              media_recorder_handler_->CanSupportMimeType(type, codecs));

          String codecs2 = audio_codec + "," + video_codec;
          EXPECT_FALSE(
              media_recorder_handler_->CanSupportMimeType(type, codecs2));
        }
      }
    }
#else
    // success cases.
    for (const auto& type : good_mp4_audio_mime_types) {
      for (const auto& codec : good_mp4_audio_codecs_non_proprietory) {
        EXPECT_TRUE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }

    // failure cases.
    for (const auto& type : good_mp4_audio_mime_types) {
      for (const auto& codec : bad_mp4_audio_codecs) {
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }
#endif
  } else {
    // TODO(crbug.com/1072056): Once the feature, MediaRecorderEnableMp4Muxer,
    // is enabled, remove the below test.
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& codec : good_mp4_video_codecs) {
        if (!IsAv1CodecSupported(codec)) {
          continue;
        }
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }
#else
    for (const auto& type : good_mp4_video_mime_types) {
      for (const auto& codec : good_mp4_video_codecs) {
        if (!IsAv1CodecSupported(codec)) {
          continue;
        }
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }
#endif

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    for (const auto& type : good_mp4_audio_mime_types) {
      for (const auto& codec : good_mp4_audio_codecs) {
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }
#else
    for (const auto& type : good_mp4_audio_mime_types) {
      for (const auto& codec : good_mp4_audio_codecs) {
        EXPECT_FALSE(media_recorder_handler_->CanSupportMimeType(type, codec));
      }
    }
#endif
  }
}

#if BUILDFLAG(IS_WIN) && BUILDFLAG(USE_PROPRIETARY_CODECS)
TEST_P(MediaRecorderHandlerIsSupportedTypeTestForMp4,
       CanSupportAacCodecForWinNSku) {
  if (!GetParam()) {
    GTEST_SKIP();
  }

  if (!IsTargetAudioCodecSupported("mp4a.40.2")) {
    return;
  }

  {
    base::test::ScopedOSInfoOverride scoped_os_info_override(
        base::test::ScopedOSInfoOverride::Type::kWin11Home);
    EXPECT_TRUE(
        media_recorder_handler_->CanSupportMimeType("audio/mp4", "mp4a.40.2"));
  }

  {
    base::test::ScopedOSInfoOverride scoped_os_info_override(
        base::test::ScopedOSInfoOverride::Type::kWin11HomeN);
    EXPECT_FALSE(
        media_recorder_handler_->CanSupportMimeType("audio/mp4", "mp4a.40.2"));
  }
}
#endif  // BUILDFLAG(IS_WIN) && BUILDFLAG(USE_PROPRIETARY_CODECS)

INSTANTIATE_TEST_SUITE_P(
    All,
    MediaRecorderHandlerIsSupportedTypeTestForMp4,
    ValuesIn({/*MediaRecorderEnableMp4Muxer enabled=*/true,
              /*MediaRecorderEnableMp4Muxer disabled=*/false}));

class MediaRecorderHandlerAudioVideoTest : public testing::Test,
                                           public MediaRecorderHandlerFixture {
 public:
  MediaRecorderHandlerAudioVideoTest()
      : MediaRecorderHandlerFixture(/*has_video=*/true,
                                    /*has_audio=*/true) {}

  void FeedVideo() {
    media::Muxer::VideoParameters video_params(
        gfx::Size(), 1, media::VideoCodec::kVP9, gfx::ColorSpace());
    auto buffer = media::DecoderBuffer::CopyFrom(base::as_byte_span("video"));
    std::string alpha_data = "alpha";
    buffer->WritableSideData().alpha_data =
        base::HeapArray<uint8_t>::CopiedFrom(base::as_byte_span(alpha_data));
    buffer->set_is_key_frame(true);
    OnEncodedVideoForTesting(video_params, buffer, timestamp_);
    timestamp_ += base::Milliseconds(10);
  }

  void FeedAudio() {
    media::AudioParameters audio_params(
        media::AudioParameters::AUDIO_PCM_LINEAR,
        media::ChannelLayoutConfig::Stereo(), kTestAudioSampleRate,
        kTestAudioSampleRate * kTestAudioBufferDurationMs / 1000);
    auto buffer = media::DecoderBuffer::CopyFrom(base::as_byte_span("audio"));
    OnEncodedAudioForTesting(audio_params, buffer, timestamp_);
    timestamp_ += base::Milliseconds(10);
  }

  base::TimeTicks timestamp_ = base::TimeTicks::Now();
};

TEST_F(MediaRecorderHandlerAudioVideoTest, IgnoresStaleEncodedMediaOnRestart) {
  AddTracks();
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), "video/webm", "vp9,opus",
      AudioTrackRecorder::BitrateMode::kVariable);
  media_recorder_handler_->Start(std::numeric_limits<int>::max(), "video/webm",
                                 0, 0);
  auto* audio_weak_cell = GetAudioCallbackInterface();
  auto* video_weak_cell = GetVideoCallbackInterface();
  EXPECT_TRUE(audio_weak_cell->Get());
  EXPECT_TRUE(video_weak_cell->Get());
  media_recorder_handler_->Stop();
  EXPECT_FALSE(audio_weak_cell->Get());
  EXPECT_FALSE(video_weak_cell->Get());

  // Start with a new session serial created by Stop.
  media_recorder_handler_->Start(std::numeric_limits<int>::max(), "video/webm",
                                 0, 0);
  EXPECT_TRUE(GetAudioCallbackInterface()->Get());
  EXPECT_TRUE(GetVideoCallbackInterface()->Get());
  media_recorder_handler_->Stop();
  media_recorder_handler_ = nullptr;
}

TEST_F(MediaRecorderHandlerAudioVideoTest, EmitsCachedAudioDataOnStop) {
  AddTracks();
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), "video/webm", "vp9,opus",
      AudioTrackRecorder::BitrateMode::kVariable);
  media_recorder_handler_->Start(std::numeric_limits<int>::max(), "video/webm",
                                 0, 0);

  // Feed some encoded data into the recorder. Expect that data cached by the
  // muxer is emitted on the call to Stop.
  FeedVideo();
  FeedAudio();
  EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
  media_recorder_handler_->Stop();
  media_recorder_handler_ = nullptr;
  Mock::VerifyAndClearExpectations(recorder);
}

TEST_F(MediaRecorderHandlerAudioVideoTest, EmitsCachedVideoDataOnStop) {
  AddTracks();
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), "video/webm", "vp9,opus",
      AudioTrackRecorder::BitrateMode::kVariable);
  media_recorder_handler_->Start(std::numeric_limits<int>::max(), "video/webm",
                                 0, 0);

  // Feed some encoded data into the recorder. Expect that data cached by the
  // muxer is emitted on the call to Stop.
  FeedAudio();
  FeedVideo();
  EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
  media_recorder_handler_->Stop();
  media_recorder_handler_ = nullptr;
  Mock::VerifyAndClearExpectations(recorder);
}

#if BUILDFLAG(USE_PROPRIETARY_CODECS)
TEST_F(MediaRecorderHandlerAudioVideoTest, CorrectH264LevelOnWrite) {
  AddTracks();
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), "video/webm", "avc1.640022,opus",
      AudioTrackRecorder::BitrateMode::kVariable);

  EXPECT_EQ(media_recorder_handler_->ActualMimeType(),
            "video/x-matroska;codecs=avc1.640022,opus");
  media_recorder_handler_->Start(std::numeric_limits<int>::max(), "video/webm",
                                 0, 0);

  // Feed some encoded data into the recorder. Expect that data cached by the
  // muxer is emitted on the call to Stop.
  FeedAudio();
  OnEncodedH264VideoForTesting(base::TimeTicks::Now());
  EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
  media_recorder_handler_->Stop();

  EXPECT_EQ(media_recorder_handler_->ActualMimeType(),
            "video/x-matroska;codecs=avc1.64000d,opus");
  media_recorder_handler_ = nullptr;
  Mock::VerifyAndClearExpectations(recorder);
}
#endif

TEST_F(MediaRecorderHandlerAudioVideoTest,
       EmitsCachedAudioDataAfterVideoTrackEnded) {
  AddTracks();
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), "video/webm", "vp9,opus",
      AudioTrackRecorder::BitrateMode::kVariable);
  media_recorder_handler_->Start(std::numeric_limits<int>::max(), "video/webm",
                                 0, 0);

  // Feed some encoded data into the recorder. Expect that data cached by the
  // muxer is emitted on the call to Stop.
  FeedVideo();
  registry_.test_stream()->VideoComponents()[0]->GetPlatformTrack()->Stop();
  FeedAudio();
  FeedAudio();
  EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
  media_recorder_handler_->Stop();
  media_recorder_handler_ = nullptr;
  Mock::VerifyAndClearExpectations(recorder);
}

#if BUILDFLAG(USE_PROPRIETARY_CODECS)

struct H264ProfileTestParams {
  const bool has_audio;
  const char* const mime_type;
  const char* const codecs;
};

static const H264ProfileTestParams kH264ProfileTestParams[] = {
    {false, "video/x-matroska", "avc1.42000c"},  // H264PROFILE_BASELINE
    {false, "video/x-matroska", "avc1.4d000c"},  // H264PROFILE_MAIN
    {false, "video/x-matroska", "avc1.64000c"},  // H264PROFILE_HIGH
    {false, "video/x-matroska", "avc1.640029"},
    {false, "video/x-matroska", "avc1.640034"},
    {true, "video/x-matroska", "avc1.64000c,pcm"},
    {false, "video/mp4", "avc1.42000c"},  // H264PROFILE_BASELINE
    {false, "video/mp4", "avc1.4d000c"},  // H264PROFILE_MAIN
    {false, "video/mp4", "avc1.64000c"},  // H264PROFILE_HIGH
    {false, "video/mp4", "avc1.640029"},
    {false, "video/mp4", "avc1.640034"},
};

class MediaRecorderHandlerH264ProfileTest
    : public TestWithParam<H264ProfileTestParams>,
      public MediaRecorderHandlerFixture {
 public:
  MediaRecorderHandlerH264ProfileTest()
      : MediaRecorderHandlerFixture(true, GetParam().has_audio) {
    scoped_feature_list_.InitAndEnableFeature(kMediaRecorderEnableMp4Muxer);
  }

  MediaRecorderHandlerH264ProfileTest(
      const MediaRecorderHandlerH264ProfileTest&) = delete;
  MediaRecorderHandlerH264ProfileTest& operator=(
      const MediaRecorderHandlerH264ProfileTest&) = delete;

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_P(MediaRecorderHandlerH264ProfileTest, ActualMimeType) {
  AddTracks();

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);

  const String mime_type(GetParam().mime_type);
  const String codecs(GetParam().codecs);
  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));

  String actual_mime_type =
      String(GetParam().mime_type) + ";codecs=" + GetParam().codecs;

  EXPECT_EQ(media_recorder_handler_->ActualMimeType(), actual_mime_type);

  media_recorder_handler_ = nullptr;
}

INSTANTIATE_TEST_SUITE_P(All,
                         MediaRecorderHandlerH264ProfileTest,
                         ValuesIn(kH264ProfileTestParams));

#if BUILDFLAG(IS_WIN)
class MediaRecorderHandlerWinAacCodecTest : public TestWithParam<unsigned int>,
                                            public MediaRecorderHandlerFixture {
 public:
  MediaRecorderHandlerWinAacCodecTest()
      : MediaRecorderHandlerFixture(false, true) {
    scoped_feature_list_.InitAndEnableFeature(kMediaRecorderEnableMp4Muxer);
  }

  MediaRecorderHandlerWinAacCodecTest(
      const MediaRecorderHandlerWinAacCodecTest&) = delete;
  MediaRecorderHandlerWinAacCodecTest& operator=(
      const MediaRecorderHandlerWinAacCodecTest&) = delete;

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_P(MediaRecorderHandlerWinAacCodecTest, AudioBitsPerSeconds) {
  const String codecs("mp4a.40.2");
  if (!IsTargetAudioCodecSupported(codecs)) {
    return;
  }

  AddTracks();

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);

  const String mime_type("audio/mp4");
  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), mime_type, codecs,
      AudioTrackRecorder::BitrateMode::kVariable));
  media_recorder_handler_->Start(0, mime_type, GetParam(), 0);

  EXPECT_EQ(media::MFAudioEncoder::ClampAccCodecBitrate(GetParam()),
            recorder->audioBitsPerSecond());

  media_recorder_handler_->Stop();
  media_recorder_handler_ = nullptr;
}

INSTANTIATE_TEST_SUITE_P(All,
                         MediaRecorderHandlerWinAacCodecTest,
                         ValuesIn({5000u, 96000u, 128000u, 160000u, 192000u,
                                   256000u, 300000u}));

#endif  // BUILDFLAG(IS_WIN)
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)

struct MediaRecorderPassthroughTestParams {
  const char* mime_type;
  media::VideoCodec codec;
};

static const MediaRecorderPassthroughTestParams
    kMediaRecorderPassthroughTestParams[] = {
        {"video/webm;codecs=vp8", media::VideoCodec::kVP8},
        {"video/webm;codecs=vp9", media::VideoCodec::kVP9},
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
        {"video/x-matroska;codecs=avc1", media::VideoCodec::kH264},
#endif
        {"video/webm;codecs=av01", media::VideoCodec::kAV1},
};

class MediaRecorderHandlerPassthroughTest
    : public TestWithParam<MediaRecorderPassthroughTestParams>,
      public ScopedMockOverlayScrollbars {
 public:
  MediaRecorderHandlerPassthroughTest() {
    registry_.Init();
    video_source_ = registry_.AddVideoTrack(TestVideoTrackId());
    ON_CALL(*video_source_, SupportsEncodedOutput).WillByDefault(Return(true));
    media_recorder_handler_ = MakeGarbageCollected<MediaRecorderHandler>(
        scheduler::GetSingleThreadTaskRunnerForTesting(),
        KeyFrameRequestProcessor::Configuration());
    EXPECT_FALSE(media_recorder_handler_->recording_);
  }

  MediaRecorderHandlerPassthroughTest(
      const MediaRecorderHandlerPassthroughTest&) = delete;
  MediaRecorderHandlerPassthroughTest& operator=(
      const MediaRecorderHandlerPassthroughTest&) = delete;

  ~MediaRecorderHandlerPassthroughTest() override {
    registry_.reset();
    media_recorder_handler_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  void OnVideoFrameForTesting(scoped_refptr<EncodedVideoFrame> frame) {
    media_recorder_handler_->OnEncodedVideoFrameForTesting(
        std::move(frame), base::TimeTicks::Now());
  }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  MockMediaStreamRegistry registry_;
  raw_ptr<MockMediaStreamVideoSource, DanglingUntriaged> video_source_ =
      nullptr;
  Persistent<MediaRecorderHandler> media_recorder_handler_;
};

TEST_P(MediaRecorderHandlerPassthroughTest, PassesThrough) {
  // Setup the mock video source to allow for passthrough recording.
  EXPECT_CALL(*video_source_, OnEncodedSinkEnabled);
  EXPECT_CALL(*video_source_, OnEncodedSinkDisabled);

  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), "", "",
      AudioTrackRecorder::BitrateMode::kVariable);
  media_recorder_handler_->Start(0, "", 0, 0);

  const size_t kFrameSize = 42;
  auto frame = FakeEncodedVideoFrame::Builder()
                   .WithKeyFrame(true)
                   .WithCodec(GetParam().codec)
                   .WithData(std::string(kFrameSize, 'P'))
                   .BuildRefPtr();
  {
    base::RunLoop run_loop;
    EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));
    EXPECT_CALL(*recorder, WriteData(SizeIs(Ge(kFrameSize)), _, _))
        .Times(1)
        .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
    OnVideoFrameForTesting(frame);
    run_loop.Run();
  }

  EXPECT_EQ(media_recorder_handler_->ActualMimeType(),
            String(GetParam().mime_type));
  Mock::VerifyAndClearExpectations(recorder);

  media_recorder_handler_->Stop();
}

TEST_F(MediaRecorderHandlerPassthroughTest, ErrorsOutOnCodecSwitch) {
  V8TestingScope scope;
  auto* recorder = MakeGarbageCollected<MockMediaRecorder>(scope);
  EXPECT_TRUE(media_recorder_handler_->Initialize(
      recorder, registry_.test_stream(), "", "",
      AudioTrackRecorder::BitrateMode::kVariable));
  EXPECT_TRUE(media_recorder_handler_->Start(0, "", 0, 0));

  // NOTE, Asan: the prototype of WriteData which has a const char* as data
  // ptr plays badly with gmock which tries to interpret it as a null-terminated
  // string. However, it points to binary data which causes gmock to overrun the
  // bounds of buffers and this manifests as an ASAN crash.
  // The expectation here works around this issue.
  EXPECT_CALL(*recorder, WriteData).Times(AtLeast(1));

  EXPECT_CALL(*recorder, OnError).WillOnce(InvokeWithoutArgs([&]() {
    // Simulate MediaRecorder behavior which is to Stop() the handler on error.
    media_recorder_handler_->Stop();
  }));
  OnVideoFrameForTesting(FakeEncodedVideoFrame::Builder()
                             .WithKeyFrame(true)
                             .WithCodec(media::VideoCodec::kVP8)
                             .WithData(std::string("vp8 frame"))
                             .BuildRefPtr());
  // Switch to VP9 frames. This is expected to cause the call to OnError
  // above.
  OnVideoFrameForTesting(FakeEncodedVideoFrame::Builder()
                             .WithKeyFrame(true)
                             .WithCodec(media::VideoCodec::kVP9)
                             .WithData(std::string("vp9 frame"))
                             .BuildRefPtr());
  // Send one more frame to verify that continued frame of different codec
  // transfer doesn't crash the media recorder.
  OnVideoFrameForTesting(FakeEncodedVideoFrame::Builder()
                             .WithKeyFrame(true)
                             .WithCodec(media::VideoCodec::kVP8)
                             .WithData(std::string("vp8 frame"))
                             .BuildRefPtr());
  platform_->RunUntilIdle();
  Mock::VerifyAndClearExpectations(recorder);
}

INSTANTIATE_TEST_SUITE_P(All,
                         MediaRecorderHandlerPassthroughTest,
                         ValuesIn(kMediaRecorderPassthroughTestParams));

struct MediaRecorderCodecProfileTestParams {
  const char* const codecs;
  VideoTrackRecorder::CodecProfile codec_profile;
};

static const MediaRecorderCodecProfileTestParams
    kMediaRecorderCodecProfileTestParams[] = {
        {"vp8,mp4a.40.2",
         VideoTrackRecorder::CodecProfile(VideoTrackRecorder::CodecId::kVp8)},
        {"vp9,opus",
         VideoTrackRecorder::CodecProfile(VideoTrackRecorder::CodecId::kVp9)},
        {"av1,opus",
         VideoTrackRecorder::CodecProfile(VideoTrackRecorder::CodecId::kAv1)},
        {"av01,opus",
         VideoTrackRecorder::CodecProfile(VideoTrackRecorder::CodecId::kAv1)},
        {"av01.0.04M.08,opus",
         VideoTrackRecorder::CodecProfile(VideoTrackRecorder::CodecId::kAv1)},
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
        {"h264,mp4a.40.2",
         VideoTrackRecorder::CodecProfile(VideoTrackRecorder::CodecId::kH264)},
        {"avc1,opus",
         VideoTrackRecorder::CodecProfile(VideoTrackRecorder::CodecId::kH264)},
        {"avc1.42E01E,opus", VideoTrackRecorder::CodecProfile(
                                 VideoTrackRecorder::CodecId::kH264,
                                 media::VideoCodecProfile::H264PROFILE_BASELINE,
                                 30u)},
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
        {"hvc1,opus",
         VideoTrackRecorder::CodecProfile(VideoTrackRecorder::CodecId::kHevc)},
        {"hvc1.1.6.L93.B0,opus", VideoTrackRecorder::CodecProfile(
                                     VideoTrackRecorder::CodecId::kHevc,
                                     media::VideoCodecProfile::HEVCPROFILE_MAIN,
                                     93u)},
#endif  // BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
};

class MediaRecorderHandlerCodecProfileTest
    : public TestWithParam<MediaRecorderCodecProfileTestParams> {};

TEST_P(MediaRecorderHandlerCodecProfileTest, VideoStringToCodecProfile) {
  EXPECT_EQ(VideoStringToCodecProfile(GetParam().codecs),
            GetParam().codec_profile);
}

INSTANTIATE_TEST_SUITE_P(All,
                         MediaRecorderHandlerCodecProfileTest,
                         ValuesIn(kMediaRecorderCodecProfileTestParams));

}  // namespace blink
```