Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the second part of a unit test file for `VideoTrackRecorder` in the Chromium Blink engine.

Here's a breakdown of my thought process to arrive at the summary:

1. **Identify the Core Class Under Test:** The filename `video_track_recorder_unittest.cc` and the presence of `TEST_P(VideoTrackRecorderTestParam, ...)` and `class VideoTrackRecorderTestMediaVideoEncoderParam` clearly indicate that `VideoTrackRecorder` is the primary class being tested.

2. **Recognize the Testing Framework:** The use of `TEST_P`, `EXPECT_CALL`, `InSequence`, `RunClosure`, `RunLoop`, and `Mock` strongly suggests the use of Google Test and Google Mock frameworks for unit testing.

3. **Analyze Test Case Names and Structures:**  The test case names provide hints about the features being tested. I'll categorize them:
    * **Keyframe Generation:** `KeyFramesGeneratedWithFrameCount`, `KeyFramesGeneratedWithIntervalDuration`. These tests verify the logic for inserting keyframes based on frame count and time intervals.
    * **Timestamp Handling:** `UsesFrameTimestampsIfProvided`. This test checks if the recorder correctly uses timestamps provided in the input video frames.
    * **MediaVideoEncoder Interaction:** Tests within `VideoTrackRecorderTestMediaVideoEncoderParam` focus on the interaction with the underlying `MediaVideoEncoder`: `RelaysReadyStateEnded`, `ForceKeyframeOnAlphaSwitch`, `HandlesOnError`, `HandleSoftwareEncoderFallback`, `ReleasesFrame`, `WaitForEncoderSupport`, `RequiredRefreshRate`.
    * **Passthrough Mode:** Tests within `VideoTrackRecorderPassthroughTest` examine the "passthrough" mode where the encoded frames are directly forwarded: `RequestsAndFinishesEncodedOutput`, `HandlesFrames`, `DoesntForwardDeltaFrameFirst`, `PausesAndResumes`.
    * **Codec Enumeration:** Tests within `CodecEnumeratorTest` are about selecting appropriate video codecs based on available hardware capabilities: `GetPreferredCodecIdDefault`, `GetPreferredCodecIdVp8`, `GetPreferredCodecIdVp9`, `GetPreferredCodecIdVp8Vp9`, `MakeSupportedProfilesVp9`, `MakeSupportedProfilesNoVp8`, `GetFirstSupportedVideoCodecProfileVp9`, `GetFirstSupportedVideoCodecProfileNoVp8`, `GetFirstSupportedVideoCodecProfileVp9VBR`, `GetFirstSupportedVideoCodecProfileNoVp8VBR`, and tests related to H.264 if enabled.

4. **Identify Mock Objects:** The presence of `mock_callback_interface_` and `mock_source_` indicates the use of mock objects to isolate the `VideoTrackRecorder` and control the behavior of its dependencies. `MockMediaStreamVideoSource` is specifically used in the passthrough tests.

5. **Look for Specific Logic and Assertions:**  `EXPECT_CALL` defines expectations on mock object methods, verifying that certain methods are called with specific arguments and in a specific order. Assertions like `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_GT` confirm the expected behavior of the `VideoTrackRecorder`.

6. **Consider Relationships to Web Technologies:** The class name `VideoTrackRecorder` and the context of the Blink renderer suggest it's related to the `MediaRecorder` API in JavaScript, which allows recording audio and video in web browsers. Key concepts like codecs, keyframes, and frame timestamps directly relate to how video is encoded and handled in web applications.

7. **Infer User Actions and Debugging:**  The tests simulate various scenarios that could occur during media recording, such as pausing, resuming, encountering errors, and switching between opaque and transparent frames. Understanding these scenarios is crucial for debugging issues related to `MediaRecorder`.

8. **Structure the Summary:**  Organize the identified functionalities into logical groups for clarity. Start with the primary purpose of the file and then detail the specific aspects being tested. Include information about relationships to web technologies, potential user errors, and debugging.

9. **Address Specific Instructions:** Ensure the summary explicitly mentions the relationship with JavaScript, HTML, and CSS (even if indirect), provides examples where possible, discusses potential user errors, and explains how a user might reach this code path. Also, highlight the assumption/input and output for any logical reasoning observed.

By following these steps, I could construct a comprehensive and accurate summary of the provided code snippet.
这是对 `blink/renderer/modules/mediarecorder/video_track_recorder_unittest.cc` 文件的第二部分进行的功能归纳。 基于之前第一部分的分析，我们可以将这部分的功能总结如下：

**核心功能： 针对 `VideoTrackRecorder` 类的更深入的单元测试，侧重于其视频编码和数据处理的细节。**

**具体功能点 (延续第一部分的测试范围)：**

1. **关键帧生成策略的验证 (延续):**
   - **基于时间间隔的关键帧生成:**  测试 `VideoTrackRecorder` 是否能按照指定的时间间隔插入关键帧。
     - **假设输入:** 初始化 `VideoTrackRecorder` 时配置关键帧间隔为 2 秒，并按时间顺序提供视频帧。
     - **预期输出:** `OnEncodedVideo` 回调中，关键帧的 `is_key_frame` 参数为 `true` 的帧会按照接近 2 秒的时间间隔出现。
   - **用户或编程常见错误:**  如果设置的关键帧间隔过短，可能会导致编码器频繁生成关键帧，降低编码效率。如果设置过长，可能会影响视频的查找和解码性能。

2. **帧时间戳的处理:**
   - 测试 `VideoTrackRecorder` 是否优先使用视频帧元数据中提供的 capture_begin_time 或 reference_time 作为编码后的时间戳，如果没有，则使用估计的捕获时间。
     - **假设输入:** 提供带有 `capture_begin_time`、`reference_time` 或没有时间戳元数据的视频帧。
     - **预期输出:** `OnEncodedVideo` 回调中，编码后的帧的时间戳参数会对应视频帧元数据中提供的时间戳，如果没有则使用预估时间。

3. **`VideoTrackRecorderTestMediaVideoEncoderParam` 参数化测试:**
   - 这是一个参数化测试套件，专门用于测试 `VideoTrackRecorder` 在使用 `MediaVideoEncoder` (硬件或软件编码器) 时的行为。
   - **测试 `MediaVideoEncoder` 的生命周期和状态管理:**
     - **就绪状态结束 (`RelaysReadyStateEnded`):** 测试当底层视频源停止时，`VideoTrackRecorder` 是否能正确地通过回调通知状态变化。
       - **用户操作到达这里:** 用户在网页上停止视频流的捕获或播放。
     - **处理编码错误 (`HandlesOnError`):** 测试当底层的 `MediaVideoEncoder` 发生错误时，`VideoTrackRecorder` 是否能正确处理，例如重建编码器。
       - **用户操作到达这里:**  底层硬件编码器出现故障或驱动问题。
     - **软件编码器回退 (`HandleSoftwareEncoderFallback`):** 测试当硬件编码器初始化或使用失败时，`VideoTrackRecorder` 是否能够回退到使用软件编码器。
       - **用户操作到达这里:**  用户的硬件不支持指定的视频编码格式，或者硬件编码器资源被占用。
   - **编码参数和行为:**
     - **透明度切换强制关键帧 (`ForceKeyframeOnAlphaSwitch`):** 测试当视频帧的透明度发生变化时（从不透明到透明），`VideoTrackRecorder` 是否会强制生成一个关键帧。这对于确保透明度信息正确解码非常重要。
       - **假设输入:**  先编码一个不透明的帧，然后编码一个透明的帧。
       - **预期输出:**  编码透明帧时会生成一个关键帧，并且编码后的数据会包含 alpha 信息。
       - **用户操作到达这里:** 用户正在录制包含透明区域的视频内容，例如带有透明背景的动画或屏幕共享。
     - **帧的释放 (`ReleasesFrame`):** 测试 `VideoTrackRecorder` 在编码完成后是否会释放视频帧的资源，防止内存泄漏。
     - **等待编码器支持 (`WaitForEncoderSupport`):** 测试 `VideoTrackRecorder` 在初始化时，如果硬件编码器支持尚未就绪，是否会等待支持信息后再进行编码。
       - **用户操作到达这里:**  用户开始录制时，浏览器可能需要一些时间来初始化和检测可用的硬件编码器。
     - **需要的刷新率 (`RequiredRefreshRate`):**  针对屏幕录制场景，测试 `VideoTrackRecorder` 是否能根据需要请求源提供刷新帧，以保证录制的流畅性。
       - **用户操作到达这里:** 用户正在进行屏幕录制。
   - **用户或编程常见错误:**
     - 没有正确处理编码错误，导致录制中断或数据丢失。
     - 没有考虑到硬件编码器的可用性，在不支持的平台上尝试使用硬件编码，导致失败。
     - 在透明度切换时没有生成关键帧，导致透明度信息丢失或显示异常。

4. **`VideoTrackRecorderPassthroughTest` 测试套件:**
   - 专门测试 `VideoTrackRecorderPassthrough` 模式，在这种模式下，假设输入的是已经编码的视频帧，`VideoTrackRecorder` 负责将其直接传递给回调接口。
   - **基本功能:**
     - **请求和完成编码输出 (`RequestsAndFinishesEncodedOutput`):** 测试 `VideoTrackRecorderPassthrough` 的初始化和清理过程，涉及到启用和禁用编码数据输出。
     - **处理编码帧 (`HandlesFrames`):** 测试 `VideoTrackRecorderPassthrough` 能否正确接收并传递编码后的视频帧（包括关键帧和非关键帧）。
       - **假设输入:** 提供已经编码好的视频帧，并指定是否为关键帧。
       - **预期输出:** `OnPassthroughVideo` 回调会接收到相应的编码数据和关键帧信息。
   - **关键帧处理:**
     - **不转发首个非关键帧 (`DoesntForwardDeltaFrameFirst`):** 测试 `VideoTrackRecorderPassthrough` 在开始时，如果收到的是非关键帧，会等待接收到第一个关键帧后再开始转发数据。
       - **用户操作到达这里:**  视频源一开始就提供了非关键帧的编码数据。
   - **暂停和恢复:**
     - **暂停和恢复 (`PausesAndResumes`):** 测试 `VideoTrackRecorderPassthrough` 的暂停和恢复功能，暂停时停止转发数据，恢复后会请求一个关键帧。
       - **用户操作到达这里:** 用户在录制过程中暂停和恢复录制。

5. **`CodecEnumeratorTest` 测试套件:**
   - 专门测试 `VideoTrackRecorder::CodecEnumerator` 类，该类负责枚举和选择可用的视频编码器和配置。
   - **测试编码器选择逻辑:**
     - **获取首选编码器 ID (`GetPreferredCodecIdDefault`, `GetPreferredCodecIdVp8`, `GetPreferredCodecIdVp9`, `GetPreferredCodecIdVp8Vp9`):** 测试在不同硬件支持情况下，`CodecEnumerator` 是否能选择合适的默认编码器 (例如 VP8 或 VP9)。
     - **获取支持的编码配置 (`MakeSupportedProfilesVp9`, `MakeSupportedProfilesNoVp8`):** 测试 `CodecEnumerator` 能否根据指定的编码器 ID 返回其支持的编码配置 (例如 profile)。
     - **获取首个支持的编码配置 (`GetFirstSupportedVideoCodecProfileVp9`, `GetFirstSupportedVideoCodecProfileNoVp8`, `GetFirstSupportedVideoCodecProfileVp9VBR`, `GetFirstSupportedVideoCodecProfileNoVp8VBR`):** 测试 `CodecEnumerator` 能否找到指定编码器的首个支持的编码配置，并考虑可变比特率 (VBR) 的支持。
     - **查找支持的特定编码配置 (`FindSupportedVideoCodecProfileH264`, `FindSupportedVideoCodecProfileH264VBR`, `FindSupportedVideoCodecProfileNoProfileH264`, `FindSupportedVideoCodecProfileNoProfileH264VBR`):**  测试 `CodecEnumerator` 能否找到指定编码器和特定 profile 的支持情况。这部分特别关注 H.264 编码器的测试，并且会根据编译选项 (`BUILDFLAG(ENABLE_OPENH264)`) 来决定是否执行相关的测试。

**与 JavaScript, HTML, CSS 的关系：**

- **JavaScript:**  `VideoTrackRecorder` 是 Chromium 中 `MediaRecorder` API 的底层实现部分。JavaScript 代码通过 `MediaRecorder` 接口调用浏览器的视频录制功能，而 `VideoTrackRecorder` 负责处理实际的视频编码。例如，当 JavaScript 代码调用 `recorder.start()` 开始录制时，最终会涉及到 `VideoTrackRecorder` 的初始化和帧处理。
- **HTML:** HTML 中的 `<video>` 元素可以用于显示录制下来的视频。用户通过 HTML 页面上的按钮或其他交互元素来触发 JavaScript 代码，从而启动或停止录制。
- **CSS:** CSS 可以用于样式化网页上的录制控件，例如录制按钮的样式。

**用户操作到达这里 (调试线索):**

1. 用户在网页上点击“开始录制”按钮。
2. JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 获取视频流。
3. JavaScript 代码创建 `MediaRecorder` 对象，并将视频流传递给它。
4. JavaScript 代码调用 `mediaRecorder.start()` 开始录制。
5. `MediaRecorder` 内部会创建 `VideoTrackRecorder` 实例来处理视频轨道的编码。
6. 当视频源有新的帧到达时，`VideoTrackRecorder` 会接收这些帧并进行编码。
7. 这些单元测试模拟了 `VideoTrackRecorder` 在接收到视频帧后进行的各种处理逻辑，包括关键帧的插入、时间戳的处理、与底层编码器的交互等。

**总结归纳：**

这部分单元测试主要集中在 `VideoTrackRecorder` 类在各种视频编码场景下的行为验证，特别是与底层 `MediaVideoEncoder` 的交互，以及在 "passthrough" 模式下的数据传递。此外，还包括对 `CodecEnumerator` 类的测试，确保了编码器选择逻辑的正确性。 这些测试覆盖了关键帧生成、时间戳处理、错误处理、硬件/软件编码器切换、透明度处理以及暂停/恢复等核心功能，为 `MediaRecorder` API 的视频录制功能提供了可靠的保障。

### 提示词
```
这是目录为blink/renderer/modules/mediarecorder/video_track_recorder_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
3u);

  auto origin = base::TimeTicks::Now();
  InSequence s;
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _))
      .Times(3);
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _))
      .Times(2);
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _))
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  auto frame = media::VideoFrame::CreateBlackFrame(kTrackRecorderTestSize[0]);
  for (int i = 0; i != 8; ++i) {
    Encode(frame, origin);
  }
  run_loop.Run();
}

TEST_P(VideoTrackRecorderTestParam, KeyFramesGeneratedWithIntervalDuration) {
  // Configure 1 key frame every 2 secs.
  InitializeRecorder(testing::get<0>(GetParam()),
                     /*keyframe_config=*/base::Seconds(2));
  InSequence s;
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  auto origin = base::TimeTicks();
  auto frame = media::VideoFrame::CreateBlackFrame(kTrackRecorderTestSize[0]);
  Encode(frame, origin);                             // Key frame emitted.
  Encode(frame, origin + base::Milliseconds(1000));  //
  Encode(frame, origin + base::Milliseconds(2100));  // Key frame emitted.
  Encode(frame, origin + base::Milliseconds(4099));  //
  Encode(frame, origin + base::Milliseconds(4100));  // Key frame emitted.
  run_loop.Run();
}

TEST_P(VideoTrackRecorderTestParam, UsesFrameTimestampsIfProvided) {
  // Configure 1 key frame every 2 secs.
  InitializeRecorder(testing::get<0>(GetParam()),
                     /*keyframe_config=*/base::Seconds(2));
  base::TimeTicks estimated_capture_time = base::TimeTicks() + base::Seconds(3);
  base::TimeTicks reference_time = base::TimeTicks() + base::Seconds(2);
  base::TimeTicks capture_begin_time = base::TimeTicks() + base::Seconds(1);
  auto frame1 = media::VideoFrame::CreateBlackFrame(kTrackRecorderTestSize[0]);
  frame1->metadata().capture_begin_time = capture_begin_time;
  auto frame2 = media::VideoFrame::CreateBlackFrame(kTrackRecorderTestSize[0]);
  frame2->metadata().reference_time = reference_time;
  // No metadata timestamp is set up here.
  auto frame3 = media::VideoFrame::CreateBlackFrame(kTrackRecorderTestSize[0]);

  InSequence s;
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, _, _, capture_begin_time));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, _, _, reference_time));
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, _, _, estimated_capture_time))
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  Encode(frame1, estimated_capture_time);
  Encode(frame2, estimated_capture_time);
  Encode(frame3, estimated_capture_time);
  run_loop.Run();
}

std::string PrintTestParams(
    const testing::TestParamInfo<testing::tuple<VideoTrackRecorder::CodecId,
                                                gfx::Size,
                                                bool,
                                                TestFrameType,
                                                bool>>& info) {
  std::stringstream ss;
  ss << "codec ";
  switch (testing::get<0>(info.param)) {
    case VideoTrackRecorder::CodecId::kVp8:
      ss << "vp8";
      break;
    case VideoTrackRecorder::CodecId::kVp9:
      ss << "vp9";
      break;
#if BUILDFLAG(ENABLE_OPENH264)
    case VideoTrackRecorder::CodecId::kH264:
      ss << "h264";
      break;
#endif
#if BUILDFLAG(ENABLE_LIBAOM)
    case VideoTrackRecorder::CodecId::kAv1:
      ss << "av1";
      break;
#endif
    case VideoTrackRecorder::CodecId::kLast:
    default:
      ss << "invalid";
      break;
  }

  ss << " size " + testing::get<1>(info.param).ToString() << " encode alpha "
     << (testing::get<2>(info.param) ? "true" : "false") << " frame type ";
  switch (testing::get<3>(info.param)) {
    case TestFrameType::kNv12GpuMemoryBuffer:
      ss << "NV12 GMB";
      break;
    case TestFrameType::kNv12Software:
      ss << "I420 SW";
      break;
    case TestFrameType::kI420:
      ss << "I420";
      break;
  }
  ss << " mediaVideoEncoder "
     << (testing::get<4>(info.param) ? "true" : "false");

  std::string out;
  base::ReplaceChars(ss.str(), " ", "_", &out);
  return out;
}

INSTANTIATE_TEST_SUITE_P(All,
                         VideoTrackRecorderTestParam,
                         ::testing::Combine(ValuesIn(kTrackRecorderTestCodec),
                                            ValuesIn(kTrackRecorderTestSize),
                                            ::testing::Bool(),
                                            ValuesIn(kTestFrameTypes),
                                            ::testing::Bool()),
                         PrintTestParams);

class VideoTrackRecorderTestMediaVideoEncoderParam
    : public ::testing::TestWithParam<bool>,
      public VideoTrackRecorderTest,
      public ScopedMediaRecorderUseMediaVideoEncoderForTest {
 public:
  VideoTrackRecorderTestMediaVideoEncoderParam()
      : ScopedMediaRecorderUseMediaVideoEncoderForTest(GetParam()) {}
  ~VideoTrackRecorderTestMediaVideoEncoderParam() override = default;
};

TEST_P(VideoTrackRecorderTestMediaVideoEncoderParam, RelaysReadyStateEnded) {
  InitializeRecorder(VideoTrackRecorder::CodecId::kVp8);
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_, OnSourceReadyStateChanged)
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  mock_source_->StopSource();
  run_loop.Run();
}

// Inserts an opaque frame followed by two transparent frames and expects the
// newly introduced transparent frame to force keyframe output.
TEST_P(VideoTrackRecorderTestMediaVideoEncoderParam,
       ForceKeyframeOnAlphaSwitch) {
  InitializeRecorder(VideoTrackRecorder::CodecId::kVp8);

  const gfx::Size& frame_size = kTrackRecorderTestSize[0];
  const scoped_refptr<media::VideoFrame> opaque_frame =
      media::VideoFrame::CreateBlackFrame(frame_size);

  InSequence s;
  auto first_frame_encoded_alpha =
      media::DecoderBuffer::CopyFrom(base::as_byte_span("test"));
  first_frame_encoded_alpha->set_is_key_frame(true);
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .Times(1)
      .WillOnce(SaveArg<1>(&first_frame_encoded_alpha));
  Encode(opaque_frame, base::TimeTicks::Now());

  const scoped_refptr<media::VideoFrame> alpha_frame =
      media::VideoFrame::CreateTransparentFrame(frame_size);
  auto second_frame_encoded_alpha =
      media::DecoderBuffer::CopyFrom(base::as_byte_span("test"));
  second_frame_encoded_alpha->set_is_key_frame(true);
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .Times(1)
      .WillOnce(SaveArg<1>(&second_frame_encoded_alpha));
  Encode(alpha_frame, base::TimeTicks::Now());

  base::RunLoop run_loop;
  auto third_frame_encoded_alpha =
      media::DecoderBuffer::CopyFrom(base::as_byte_span("test"));
  third_frame_encoded_alpha->set_is_key_frame(false);
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(false), _, _))
      .Times(1)
      .WillOnce(DoAll(SaveArg<1>(&third_frame_encoded_alpha),
                      RunClosure(run_loop.QuitClosure())));
  Encode(alpha_frame, base::TimeTicks::Now());
  run_loop.Run();

  const size_t kEmptySize = 0;
  EXPECT_FALSE(first_frame_encoded_alpha->has_side_data());
  EXPECT_TRUE(second_frame_encoded_alpha->has_side_data());
  EXPECT_GT(second_frame_encoded_alpha->side_data()->alpha_data.size(),
            kEmptySize);
  EXPECT_TRUE(third_frame_encoded_alpha->has_side_data());
  EXPECT_GT(third_frame_encoded_alpha->side_data()->alpha_data.size(),
            kEmptySize);

  Mock::VerifyAndClearExpectations(this);
}

// Inserts an OnError() call between sent frames.
TEST_P(VideoTrackRecorderTestMediaVideoEncoderParam, HandlesOnError) {
  InitializeRecorder(VideoTrackRecorder::CodecId::kVp8);

  const gfx::Size& frame_size = kTrackRecorderTestSize[0];
  const scoped_refptr<media::VideoFrame> video_frame =
      media::VideoFrame::CreateBlackFrame(frame_size);

  InSequence s;
  base::RunLoop run_loop1;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .WillOnce(RunClosure(run_loop1.QuitClosure()));
  Encode(video_frame, base::TimeTicks::Now());
  run_loop1.Run();

  EXPECT_TRUE(HasEncoderInstance());
  OnError();
  EXPECT_FALSE(HasEncoderInstance());

  base::RunLoop run_loop2;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .WillOnce(RunClosure(run_loop2.QuitClosure()));
  Encode(video_frame, base::TimeTicks::Now());
  run_loop2.Run();

  Mock::VerifyAndClearExpectations(this);
}

// Hardware encoder fails and fallbacks a software encoder.
TEST_P(VideoTrackRecorderTestMediaVideoEncoderParam,
       HandleSoftwareEncoderFallback) {
  // Skip this test case with VEAEncoder.
  // VEAEncoder drops frames until RequireBitstreamBufferReady() is dropped.
  // It is tricky to pass this test with VEAEncoder due to the issue.
  if (!GetParam()) {
    GTEST_SKIP();
  }
  media::MockGpuVideoAcceleratorFactories mock_gpu_factories(nullptr);
  EXPECT_CALL(*platform_, GetGpuFactories())
      .WillRepeatedly(Return(&mock_gpu_factories));
  EXPECT_CALL(mock_gpu_factories, NotifyEncoderSupportKnown)
      .WillRepeatedly(base::test::RunOnceClosure<0>());
  EXPECT_CALL(mock_gpu_factories, GetTaskRunner)
      .WillRepeatedly(Return(scheduler::GetSingleThreadTaskRunnerForTesting()));
  EXPECT_CALL(mock_gpu_factories, GetVideoEncodeAcceleratorSupportedProfiles)
      .WillRepeatedly(
          Return(std::vector<media::VideoEncodeAccelerator::SupportedProfile>{
              media::VideoEncodeAccelerator::SupportedProfile(
                  media::VideoCodecProfile::VP8PROFILE_ANY,
                  gfx::Size(1920, 1080)),
          }));
  EXPECT_CALL(mock_gpu_factories, DoCreateVideoEncodeAccelerator)
      .WillRepeatedly([]() {
        return new media::FakeVideoEncodeAccelerator(
            scheduler::GetSingleThreadTaskRunnerForTesting());
      });
  InitializeRecorder(VideoTrackRecorder::CodecId::kVp8);

  const gfx::Size& frame_size =
      gfx::Size(kVEAEncoderMinResolutionWidth, kVEAEncoderMinResolutionHeight);
  const scoped_refptr<media::VideoFrame> video_frame =
      media::VideoFrame::CreateBlackFrame(frame_size);

  InSequence s;
  base::RunLoop run_loop1;
  EXPECT_CALL(*mock_callback_interface_, OnEncodedVideo)
      .WillOnce(RunClosure(run_loop1.QuitClosure()));
  Encode(video_frame, base::TimeTicks::Now());
  run_loop1.Run();

  EXPECT_TRUE(HasEncoderInstance());
  OnError();
  EXPECT_FALSE(HasEncoderInstance());
  base::RunLoop run_loop2;
  EXPECT_CALL(*mock_callback_interface_, OnEncodedVideo)
      .WillOnce(RunClosure(run_loop2.QuitClosure()));
  // Create a software video encoder by setting |allow_vea_encoder| to false.
  Encode(video_frame, base::TimeTicks::Now(), /*allow_vea_encoder=*/false);
  run_loop2.Run();

  Mock::VerifyAndClearExpectations(this);
}

// Inserts a frame for encode and makes sure that it is released.
TEST_P(VideoTrackRecorderTestMediaVideoEncoderParam, ReleasesFrame) {
  InitializeRecorder(VideoTrackRecorder::CodecId::kVp8);

  const gfx::Size& frame_size = kTrackRecorderTestSize[0];
  scoped_refptr<media::VideoFrame> video_frame =
      media::VideoFrame::CreateBlackFrame(frame_size);

  base::RunLoop run_loop;
  video_frame->AddDestructionObserver(base::BindOnce(run_loop.QuitClosure()));
  Encode(std::move(video_frame), base::TimeTicks::Now());
  run_loop.Run();

  Mock::VerifyAndClearExpectations(this);
}

// Waits for HW encoder support to be enumerated before setting up and
// performing an encode.
TEST_P(VideoTrackRecorderTestMediaVideoEncoderParam, WaitForEncoderSupport) {
  media::MockGpuVideoAcceleratorFactories mock_gpu_factories(nullptr);
  EXPECT_CALL(*platform_, GetGpuFactories())
      .WillRepeatedly(Return(&mock_gpu_factories));

  EXPECT_CALL(mock_gpu_factories, NotifyEncoderSupportKnown)
      .WillOnce(base::test::RunOnceClosure<0>());
  InitializeRecorder(VideoTrackRecorder::CodecId::kVp8);

  const gfx::Size& frame_size = kTrackRecorderTestSize[0];
  scoped_refptr<media::VideoFrame> video_frame =
      media::VideoFrame::CreateBlackFrame(frame_size);

  base::RunLoop run_loop;
  EXPECT_CALL(*mock_callback_interface_,
              OnEncodedVideo(_, IsKeyFrame(true), _, _))
      .WillOnce(RunClosure(run_loop.QuitWhenIdleClosure()));
  Encode(video_frame, base::TimeTicks::Now());
  run_loop.Run();
}

TEST_P(VideoTrackRecorderTestMediaVideoEncoderParam, RequiredRefreshRate) {
  // |RequestRefreshFrame| will be called first by |AddSink| and the second time
  // by the refresh timer using the required min fps.
  EXPECT_CALL(*mock_source_, OnRequestRefreshFrame).Times(2);

  track_->SetIsScreencastForTesting(true);
  InitializeRecorder(VideoTrackRecorder::CodecId::kVp8);

  EXPECT_EQ(video_track_recorder_->GetRequiredMinFramesPerSec(), 1);

  test::RunDelayedTasks(base::Seconds(1));
}

INSTANTIATE_TEST_SUITE_P(All,
                         VideoTrackRecorderTestMediaVideoEncoderParam,
                         ::testing::Bool());

class VideoTrackRecorderPassthroughTest
    : public TestWithParam<VideoTrackRecorder::CodecId>,
      public VideoTrackRecorderTestBase {
 public:
  using CodecId = VideoTrackRecorder::CodecId;

  VideoTrackRecorderPassthroughTest()
      : mock_source_(new MockMediaStreamVideoSource()) {
    ON_CALL(*mock_source_, SupportsEncodedOutput).WillByDefault(Return(true));
    const String track_id("dummy");
    source_ = MakeGarbageCollected<MediaStreamSource>(
        track_id, MediaStreamSource::kTypeVideo, track_id, false /*remote*/,
        base::WrapUnique(mock_source_.get()));
    component_ = MakeGarbageCollected<MediaStreamComponentImpl>(
        source_, std::make_unique<MediaStreamVideoTrack>(
                     mock_source_,
                     WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
                     true /* enabled */));

    // Paranoia checks.
    EXPECT_EQ(component_->Source()->GetPlatformSource(),
              source_->GetPlatformSource());
    EXPECT_TRUE(scheduler::GetSingleThreadTaskRunnerForTesting()
                    ->BelongsToCurrentThread());
  }

  ~VideoTrackRecorderPassthroughTest() override {
    component_ = nullptr;
    source_ = nullptr;
    video_track_recorder_.reset();
    WebHeap::CollectAllGarbageForTesting();
  }

  void InitializeRecorder() {
    video_track_recorder_ = std::make_unique<VideoTrackRecorderPassthrough>(
        scheduler::GetSingleThreadTaskRunnerForTesting(),
        WebMediaStreamTrack(component_.Get()),
        mock_callback_interface_->GetWeakCell(),
        KeyFrameRequestProcessor::Configuration());
  }

  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;

  // All members are non-const due to the series of initialize() calls needed.
  // |mock_source_| is owned by |source_|.
  raw_ptr<MockMediaStreamVideoSource, DanglingUntriaged> mock_source_;
  Persistent<MediaStreamSource> source_;
  Persistent<MediaStreamComponent> component_;

  std::unique_ptr<VideoTrackRecorderPassthrough> video_track_recorder_;
};

scoped_refptr<FakeEncodedVideoFrame> CreateFrame(
    bool is_key_frame,
    VideoTrackRecorder::CodecId codec) {
  return FakeEncodedVideoFrame::Builder()
      .WithKeyFrame(is_key_frame)
      .WithData("abc")
      .WithCodec(MediaVideoCodecFromCodecId(codec))
      .BuildRefPtr();
}

TEST_F(VideoTrackRecorderPassthroughTest, RequestsAndFinishesEncodedOutput) {
  EXPECT_CALL(*mock_source_, OnEncodedSinkEnabled);
  EXPECT_CALL(*mock_source_, OnEncodedSinkDisabled);
  InitializeRecorder();
}

void DoNothing() {}

// Matcher for checking codec type
MATCHER_P(IsSameCodec, codec, "") {
  return arg.codec == MediaVideoCodecFromCodecId(codec);
}

TEST_P(VideoTrackRecorderPassthroughTest, HandlesFrames) {
  ON_CALL(*mock_source_, OnEncodedSinkEnabled).WillByDefault(DoNothing);
  ON_CALL(*mock_source_, OnEncodedSinkDisabled).WillByDefault(DoNothing);
  InitializeRecorder();

  // Frame 1 (keyframe)
  auto frame = CreateFrame(/*is_key_frame=*/true, GetParam());
  scoped_refptr<media::DecoderBuffer> encoded_data;
  EXPECT_CALL(*mock_callback_interface_,
              OnPassthroughVideo(IsSameCodec(GetParam()), IsKeyFrame(true), _))
      .WillOnce(DoAll(SaveArg<1>(&encoded_data)));
  auto now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
  std::string str = "abc";
  EXPECT_EQ(encoded_data->AsSpan(), base::as_byte_span(str));

  // Frame 2 (deltaframe)
  frame = CreateFrame(/*is_key_frame=*/false, GetParam());
  EXPECT_CALL(
      *mock_callback_interface_,
      OnPassthroughVideo(IsSameCodec(GetParam()), IsKeyFrame(false), _));
  now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
}

TEST_F(VideoTrackRecorderPassthroughTest, DoesntForwardDeltaFrameFirst) {
  EXPECT_CALL(*mock_source_, OnEncodedSinkEnabled);
  InitializeRecorder();
  Mock::VerifyAndClearExpectations(mock_source_);

  // Frame 1 (deltaframe) - not forwarded
  auto frame = CreateFrame(/*is_key_frame=*/false, CodecId::kVp9);
  EXPECT_CALL(*mock_callback_interface_,
              OnPassthroughVideo(_, IsKeyFrame(false), _))
      .Times(0);
  // We already requested a keyframe when starting the recorder, so expect
  // no keyframe request now
  EXPECT_CALL(*mock_source_, OnEncodedSinkEnabled).Times(0);
  EXPECT_CALL(*mock_source_, OnEncodedSinkDisabled).Times(0);
  auto now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(mock_source_);

  // Frame 2 (keyframe)
  frame = CreateFrame(/*is_key_frame=*/true, CodecId::kVp9);
  EXPECT_CALL(*mock_callback_interface_,
              OnPassthroughVideo(_, IsKeyFrame(true), _));
  now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
  Mock::VerifyAndClearExpectations(this);

  // Frame 3 (deltaframe) - forwarded
  base::RunLoop run_loop;
  frame = CreateFrame(/*is_key_frame=*/false, CodecId::kVp9);
  EXPECT_CALL(*mock_callback_interface_, OnPassthroughVideo)
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
  run_loop.Run();
  EXPECT_CALL(*mock_source_, OnEncodedSinkDisabled);
}

TEST_F(VideoTrackRecorderPassthroughTest, PausesAndResumes) {
  InitializeRecorder();
  // Frame 1 (keyframe)
  auto frame = CreateFrame(/*is_key_frame=*/true, CodecId::kVp9);
  auto now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
  video_track_recorder_->Pause();

  // Expect no frame throughput now.
  frame = CreateFrame(/*is_key_frame=*/false, CodecId::kVp9);
  EXPECT_CALL(*mock_callback_interface_, OnPassthroughVideo).Times(0);
  now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
  Mock::VerifyAndClearExpectations(this);

  // Resume - expect keyframe request
  Mock::VerifyAndClearExpectations(mock_source_);
  // Expect no callback registration, but expect a keyframe.
  EXPECT_CALL(*mock_source_, OnEncodedSinkEnabled).Times(0);
  EXPECT_CALL(*mock_source_, OnEncodedSinkDisabled).Times(0);
  EXPECT_CALL(*mock_source_, OnRequestKeyFrame);
  video_track_recorder_->Resume();
  Mock::VerifyAndClearExpectations(mock_source_);

  // Expect no transfer from deltaframe and transfer of keyframe
  frame = CreateFrame(/*is_key_frame=*/false, CodecId::kVp9);
  EXPECT_CALL(*mock_callback_interface_, OnPassthroughVideo).Times(0);
  now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
  Mock::VerifyAndClearExpectations(this);

  frame = CreateFrame(/*is_key_frame=*/true, CodecId::kVp9);
  EXPECT_CALL(*mock_callback_interface_, OnPassthroughVideo);
  now = base::TimeTicks::Now();
  video_track_recorder_->OnEncodedVideoFrameForTesting(now, frame, now);
}

INSTANTIATE_TEST_SUITE_P(All,
                         VideoTrackRecorderPassthroughTest,
                         ValuesIn(kTrackRecorderTestCodec));

class CodecEnumeratorTest : public ::testing::Test {
 public:
  using CodecEnumerator = VideoTrackRecorder::CodecEnumerator;
  using CodecId = VideoTrackRecorder::CodecId;

  CodecEnumeratorTest() = default;

  CodecEnumeratorTest(const CodecEnumeratorTest&) = delete;
  CodecEnumeratorTest& operator=(const CodecEnumeratorTest&) = delete;

  ~CodecEnumeratorTest() override = default;

  media::VideoEncodeAccelerator::SupportedProfiles MakeVp8Profiles() {
    media::VideoEncodeAccelerator::SupportedProfiles profiles;
    profiles.emplace_back(media::VP8PROFILE_ANY, gfx::Size(1920, 1080), 30, 1);
    return profiles;
  }

  media::VideoEncodeAccelerator::SupportedProfiles MakeVp9Profiles(
      bool vbr_support = false) {
    media::VideoEncodeAccelerator::SupportedProfiles profiles;
    auto rc_mode =
        media::VideoEncodeAccelerator::SupportedRateControlMode::kConstantMode;
    if (vbr_support) {
      rc_mode |= media::VideoEncodeAccelerator::SupportedRateControlMode::
          kVariableMode;
    }

    profiles.emplace_back(media::VP9PROFILE_PROFILE1, gfx::Size(1920, 1080), 60,
                          1, rc_mode);
    profiles.emplace_back(media::VP9PROFILE_PROFILE2, gfx::Size(1920, 1080), 30,
                          1, rc_mode);
    return profiles;
  }

  media::VideoEncodeAccelerator::SupportedProfiles MakeVp8Vp9Profiles() {
    media::VideoEncodeAccelerator::SupportedProfiles profiles =
        MakeVp8Profiles();
    media::VideoEncodeAccelerator::SupportedProfiles vp9_profiles =
        MakeVp9Profiles();
    profiles.insert(profiles.end(), vp9_profiles.begin(), vp9_profiles.end());
    return profiles;
  }

  media::VideoEncodeAccelerator::SupportedProfiles MakeH264Profiles(
      bool vbr_support = false) {
    media::VideoEncodeAccelerator::SupportedProfiles profiles;
    auto rc_mode =
        media::VideoEncodeAccelerator::SupportedRateControlMode::kConstantMode;
    if (vbr_support) {
      rc_mode |= media::VideoEncodeAccelerator::SupportedRateControlMode::
          kVariableMode;
    }

    profiles.emplace_back(media::H264PROFILE_BASELINE, gfx::Size(1920, 1080),
                          24, 1, rc_mode);
    profiles.emplace_back(media::H264PROFILE_MAIN, gfx::Size(1920, 1080), 30, 1,
                          rc_mode);
    profiles.emplace_back(media::H264PROFILE_HIGH, gfx::Size(1920, 1080), 60, 1,
                          rc_mode);
    return profiles;
  }
  test::TaskEnvironment task_environment_;
};

TEST_F(CodecEnumeratorTest, GetPreferredCodecIdDefault) {
  // Empty supported profiles.
  MediaTrackContainerType type = GetMediaContainerTypeFromString("");
  const CodecEnumerator emulator(
      (media::VideoEncodeAccelerator::SupportedProfiles()));
  EXPECT_EQ(CodecId::kVp8, emulator.GetPreferredCodecId(type));
}

TEST_F(CodecEnumeratorTest, GetPreferredCodecIdVp8) {
  MediaTrackContainerType type = GetMediaContainerTypeFromString("");
  const CodecEnumerator emulator(MakeVp8Profiles());
  EXPECT_EQ(CodecId::kVp8, emulator.GetPreferredCodecId(type));
}

TEST_F(CodecEnumeratorTest, GetPreferredCodecIdVp9) {
  MediaTrackContainerType type = GetMediaContainerTypeFromString("");
  const CodecEnumerator emulator(MakeVp9Profiles());
  EXPECT_EQ(CodecId::kVp9, emulator.GetPreferredCodecId(type));
}

TEST_F(CodecEnumeratorTest, GetPreferredCodecIdVp8Vp9) {
  MediaTrackContainerType type = GetMediaContainerTypeFromString("");
  const CodecEnumerator emulator(MakeVp8Vp9Profiles());
  EXPECT_EQ(CodecId::kVp8, emulator.GetPreferredCodecId(type));
}

TEST_F(CodecEnumeratorTest, MakeSupportedProfilesVp9) {
  const CodecEnumerator emulator(MakeVp9Profiles());
  media::VideoEncodeAccelerator::SupportedProfiles profiles =
      emulator.GetSupportedProfiles(CodecId::kVp9);
  EXPECT_EQ(2u, profiles.size());
  EXPECT_EQ(media::VP9PROFILE_PROFILE1, profiles[0].profile);
  EXPECT_EQ(media::VP9PROFILE_PROFILE2, profiles[1].profile);
}

TEST_F(CodecEnumeratorTest, MakeSupportedProfilesNoVp8) {
  const CodecEnumerator emulator(MakeVp9Profiles());
  media::VideoEncodeAccelerator::SupportedProfiles profiles =
      emulator.GetSupportedProfiles(CodecId::kVp8);
  EXPECT_TRUE(profiles.empty());
}

TEST_F(CodecEnumeratorTest, GetFirstSupportedVideoCodecProfileVp9) {
  const CodecEnumerator emulator(MakeVp9Profiles());
  EXPECT_EQ(std::make_pair(media::VP9PROFILE_PROFILE1, /*vbr_support=*/false),
            emulator.GetFirstSupportedVideoCodecProfile(CodecId::kVp9));
}

TEST_F(CodecEnumeratorTest, GetFirstSupportedVideoCodecProfileNoVp8) {
  const CodecEnumerator emulator(MakeVp9Profiles());
  EXPECT_EQ(
      std::make_pair(media::VIDEO_CODEC_PROFILE_UNKNOWN, /*vbr_support=*/false),
      emulator.GetFirstSupportedVideoCodecProfile(CodecId::kVp8));
}

TEST_F(CodecEnumeratorTest, GetFirstSupportedVideoCodecProfileVp9VBR) {
  const CodecEnumerator emulator(MakeVp9Profiles(/*vbr_support=*/true));
  EXPECT_EQ(std::make_pair(media::VP9PROFILE_PROFILE1, /*vbr_support=*/true),
            emulator.GetFirstSupportedVideoCodecProfile(CodecId::kVp9));
}

TEST_F(CodecEnumeratorTest, GetFirstSupportedVideoCodecProfileNoVp8VBR) {
  const CodecEnumerator emulator(MakeVp9Profiles(/*vbr_support=*/true));
  EXPECT_EQ(
      std::make_pair(media::VIDEO_CODEC_PROFILE_UNKNOWN, /*vbr_support=*/false),
      emulator.GetFirstSupportedVideoCodecProfile(CodecId::kVp8));
}

#if BUILDFLAG(ENABLE_OPENH264)
TEST_F(CodecEnumeratorTest, FindSupportedVideoCodecProfileH264) {
  const CodecEnumerator emulator(MakeH264Profiles());
  EXPECT_EQ(std::make_pair(media::H264PROFILE_HIGH, /*vbr_support=*/false),
            emulator.FindSupportedVideoCodecProfile(CodecId::kH264,
                                                    media::H264PROFILE_HIGH));
}

TEST_F(CodecEnumeratorTest, FindSupportedVideoCodecProfileH264VBR) {
  const CodecEnumerator emulator(MakeH264Profiles(/*vbr_support=*/true));
  EXPECT_EQ(std::make_pair(media::H264PROFILE_HIGH, /*vbr_support=*/true),
            emulator.FindSupportedVideoCodecProfile(CodecId::kH264,
                                                    media::H264PROFILE_HIGH));
}

TEST_F(CodecEnumeratorTest, FindSupportedVideoCodecProfileNoProfileH264) {
  const CodecEnumerator emulator(MakeH264Profiles());
  EXPECT_EQ(
      std::make_pair(media::VIDEO_CODEC_PROFILE_UNKNOWN, /*vbr_support=*/false),
      emulator.FindSupportedVideoCodecProfile(
          CodecId::kH264, media::H264PROFILE_HIGH422PROFILE));
}

TEST_F(CodecEnumeratorTest, FindSupportedVideoCodecProfileNoProfileH264VBR) {
  const CodecEnumerator emulator(MakeH264Profiles(/*vbr_support=*/true));
  EXPECT_EQ(
      std::make_pair(media::VIDEO_CODEC_PROFILE_UNKNOWN, /*vbr_support=*/false),
      emulator.FindSupportedVideoCodecProfile(
          CodecId::kH264, media::H264PROFILE_HIGH422PROFILE));
}

#endif

}  // namespace blink
```