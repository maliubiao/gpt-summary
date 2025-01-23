Response:
The user wants a summary of the functionalities implemented in the provided C++ code snippet, which is part of a test file for the `VideoFrameSubmitter` class in the Chromium Blink engine.

I need to identify the different test cases and their purpose. For each test case, I will describe the functionality being tested.

If a test case involves interaction with web technologies (JavaScript, HTML, CSS), I need to explain that connection. However, since this is a unit test file, the direct interaction with these technologies is likely abstract or simulated through mocks.

For logical deductions, I need to identify the input and expected output of each test case. The input will be the setup of the test, and the output will be the assertions made within the test.

For common usage errors, I need to infer potential mistakes a developer might make when using or extending the `VideoFrameSubmitter` based on the tested scenarios.

Finally, I need to synthesize all the identified functionalities into a concise summary.
这是对 `blink/renderer/platform/graphics/video_frame_submitter_test.cc` 文件功能的归纳总结（第 2 部分）：

**功能归纳:**

这部分代码继续测试 `VideoFrameSubmitter` 类的各种功能，重点在于验证视频帧的提交和渲染流程在不同条件下的正确性。具体测试的功能包括：

* **手动提交帧后的 LocalSurfaceId 更新：** 测试在手动提交一帧后，`LocalSurfaceId` 的 parent sequence number 会递增，但 child sequence number 仍然是初始值。后续提交的帧会递增 child sequence number。这验证了 `VideoFrameSubmitter` 在手动提交帧时正确管理了 compositor surface 的标识符。
* **视频旋转和输出矩形：** 测试 `VideoFrameSubmitter` 如何处理视频的旋转。它验证了当设置不同的旋转角度时，提交的 `CompositorFrame` 的尺寸会相应调整，并且 `ResourceProvider` 会使用正确的 `VideoTransformation` 参数调用 `AppendQuads` 方法。这确保了视频旋转能够正确地反映在最终的渲染输出中。
* **页面可见性控制提交：** 测试页面可见性对视频帧提交的影响。当页面隐藏时，`VideoFrameSubmitter` 不应该请求 begin frames，并且不应该提交帧。当页面变为可见时，它应该恢复帧的提交。这保证了在页面不可见时不会浪费资源进行视频渲染。
* **首选帧间隔 (Preferred Interval)：** 测试 `VideoFrameSubmitter` 如何使用 `VideoFrameProvider` 提供的首选帧间隔。它验证了提交的 `CompositorFrame` 的 metadata 中包含了正确的首选帧间隔信息。这对于实现流畅的视频播放至关重要。
* **防止重复帧提交 (BeginFrame 触发)：** 测试在收到 `BeginFrame` 事件后，即使 `VideoFrameProvider` 声称有新帧，如果实际上是相同的帧，`VideoFrameSubmitter` 也不会重复提交。这避免了不必要的渲染和资源浪费。
* **防止重复帧提交 (DidReceiveFrame 触发)：** 测试通过 `DidReceiveFrame` 接收到帧后，如果后续再次收到相同的帧，`VideoFrameSubmitter` 不会重复提交。这与上一个测试类似，但触发机制不同。
* **零尺寸帧不提交：** 测试 `VideoFrameSubmitter` 不会提交尺寸为零的视频帧（例如 EOS 帧）。这避免了处理无效的视频帧数据。
* **处理定时细节 (ProcessTimingDetails)：** 测试 `VideoFrameSubmitter` 如何收集和处理帧的定时信息，并调用回调函数报告视频播放的粗糙度。这涉及到模拟多帧的提交，并提供 presentation feedback 数据，以触发粗糙度报告的回调。
* **不透明帧通知嵌入器 (OpaqueFramesNotifyEmbedder)：** 测试当接收到的视频帧的不透明度发生变化时，`VideoFrameSubmitter` 会通知嵌入器。这允许嵌入器根据视频的透明度进行优化或执行其他操作。

**与 JavaScript, HTML, CSS 的关系：**

虽然这是一个 C++ 的单元测试，但它间接关联了这些 Web 技术：

* **HTML `<video>` 元素：**  `VideoFrameSubmitter` 最终负责将解码后的视频帧渲染到 HTML 页面上的 `<video>` 元素中。虽然测试本身不涉及 HTML，但它模拟了渲染过程的关键部分。
* **CSS 样式：**  视频的旋转（`VideoRotationOutputRect` 测试）可能会受到 CSS `transform` 属性的影响。`VideoFrameSubmitter` 的测试确保了即使在底层进行了旋转，最终渲染的结果也是正确的。
* **JavaScript API：**  JavaScript 可以通过 Video API 控制视频的播放、暂停、seek 等操作，这些操作会间接影响 `VideoFrameSubmitter` 的行为，例如开始和停止渲染。页面可见性（`PageVisibilityControlsSubmission` 测试）也与 JavaScript 的 Page Visibility API 相关。

**逻辑推理、假设输入与输出：**

以下是一些测试用例的逻辑推理示例：

* **`ManualSoftwareSubmission` 测试：**
    * **假设输入：** 模拟手动提交一帧视频帧。
    * **预期输出：** 验证 `SetNeedsBeginFrame(true)` 被调用，`DoSubmitCompositorFrame` 被调用一次，`LocalSurfaceId` 的 parent sequence number 递增，child sequence number 为初始值。后续提交的帧 child sequence number 会递增。
* **`VideoRotationOutputRect` 测试：**
    * **假设输入：**  设置不同的视频旋转角度（90°，180°，270°）。
    * **预期输出：**  验证提交的 `CompositorFrame` 的尺寸会根据旋转角度进行调整，并且 `ResourceProvider` 的 `AppendQuads` 方法会使用相应的 `VideoTransformation` 参数调用。
* **`PageVisibilityControlsSubmission` 测试：**
    * **假设输入：**  模拟页面可见性的切换（隐藏 -> 可见 -> 隐藏）。
    * **预期输出：**  验证当页面隐藏时，`SetNeedsBeginFrame(false)` 被调用，不进行帧提交。当页面变为可见时，`SetNeedsBeginFrame(true)` 被调用，开始帧提交。

**用户或编程常见的使用错误：**

基于这些测试，可以推断出一些常见的使用错误：

* **不正确的 LocalSurfaceId 管理：**  如果开发者没有正确处理 `LocalSurfaceId` 的更新，可能会导致 compositor 无法正确渲染视频内容。`ManualSoftwareSubmission` 测试强调了这一点。
* **未考虑视频旋转：**  如果开发者在处理视频渲染时没有考虑到视频的旋转信息，可能会导致视频显示方向错误。`VideoRotationOutputRect` 测试验证了 `VideoFrameSubmitter` 正确处理了旋转。
* **在页面不可见时继续渲染：**  在页面不可见时继续提交视频帧会浪费资源。`PageVisibilityControlsSubmission` 测试表明 `VideoFrameSubmitter` 可以避免这种情况。
* **忽略首选帧间隔：**  如果没有正确使用 `VideoFrameProvider` 提供的首选帧间隔，可能会导致视频播放不流畅。`PreferredInterval` 测试确保了 `VideoFrameSubmitter` 考虑了这个因素。
* **重复提交相同的帧：**  不必要的帧提交会浪费计算资源。`NoDuplicateFramesOnBeginFrame` 和 `NoDuplicateFramesDidReceiveFrame` 测试验证了 `VideoFrameSubmitter` 可以避免重复提交。
* **处理零尺寸帧：**  尝试提交零尺寸的视频帧可能会导致错误或崩溃。`ZeroSizedFramesAreNotSubmitted` 测试表明 `VideoFrameSubmitter` 会忽略这些帧。
* **未能处理视频透明度变化：**  某些场景下，需要根据视频的透明度进行特殊处理。`OpaqueFramesNotifyEmbedder` 测试表明 `VideoFrameSubmitter` 可以通知嵌入器视频透明度的变化。

总而言之，这部分测试代码全面地验证了 `VideoFrameSubmitter` 在各种场景下的核心功能，确保了视频帧能够被正确、高效地提交和渲染，并考虑了各种边缘情况和潜在的错误。

### 提示词
```
这是目录为blink/renderer/platform/graphics/video_frame_submitter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
PECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kManual);
  SubmitSingleFrame();
  task_environment_.RunUntilIdle();

  {
    viz::LocalSurfaceId local_surface_id =
        child_local_surface_id_allocator().GetCurrentLocalSurfaceId();
    EXPECT_TRUE(local_surface_id.is_valid());
    EXPECT_EQ(11u, local_surface_id.parent_sequence_number());
    EXPECT_EQ(viz::kInitialChildSequenceNumber,
              local_surface_id.child_sequence_number());
    EXPECT_EQ(gfx::Size(8, 8), frame_size());
    AckSubmittedFrame();
  }

  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(2, 2), gfx::Rect(gfx::Size(2, 2)),
          gfx::Size(2, 2), base::TimeDelta())));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_, AppendQuads(_, _, _, _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  SubmitSingleFrame();
  task_environment_.RunUntilIdle();

  {
    viz::LocalSurfaceId local_surface_id =
        child_local_surface_id_allocator().GetCurrentLocalSurfaceId();
    EXPECT_TRUE(local_surface_id.is_valid());
    EXPECT_EQ(11u, local_surface_id.parent_sequence_number());
    EXPECT_EQ(viz::kInitialChildSequenceNumber + 1,
              local_surface_id.child_sequence_number());
    EXPECT_EQ(gfx::Size(2, 2), frame_size());
  }
}

TEST_P(VideoFrameSubmitterTest, VideoRotationOutputRect) {
  MakeSubmitter();
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  EXPECT_TRUE(IsRendering());

  gfx::Size coded_size(1280, 720);
  gfx::Size natural_size(1280, 1024);
  gfx::Size rotated_size(1024, 1280);

  {
    submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_90);

    EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
        .WillOnce(Return(media::VideoFrame::CreateFrame(
            media::PIXEL_FORMAT_YV12, coded_size, gfx::Rect(coded_size),
            natural_size, base::TimeDelta())));
    EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
    EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
    EXPECT_CALL(*resource_provider_,
                AppendQuads(_, _,
                            media::VideoTransformation(
                                media::VideoRotation::VIDEO_ROTATION_90),
                            _));
    EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
    EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

    viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
        BEGINFRAME_FROM_HERE, now_src_.get());
    OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
    task_environment_.RunUntilIdle();

    EXPECT_EQ(sink_->last_submitted_compositor_frame().size_in_pixels(),
              rotated_size);

    AckSubmittedFrame();
  }

  {
    submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_180);

    EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
        .WillOnce(Return(media::VideoFrame::CreateFrame(
            media::PIXEL_FORMAT_YV12, coded_size, gfx::Rect(coded_size),
            natural_size, base::TimeDelta())));
    EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
    EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
    EXPECT_CALL(*resource_provider_,
                AppendQuads(_, _,
                            media::VideoTransformation(
                                media::VideoRotation::VIDEO_ROTATION_180),
                            _));
    EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
    EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

    viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
        BEGINFRAME_FROM_HERE, now_src_.get());
    OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
    task_environment_.RunUntilIdle();

    // 180 deg rotation has same size.
    EXPECT_EQ(sink_->last_submitted_compositor_frame().size_in_pixels(),
              natural_size);

    AckSubmittedFrame();
  }

  {
    submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_270);

    EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
        .WillOnce(Return(media::VideoFrame::CreateFrame(
            media::PIXEL_FORMAT_YV12, coded_size, gfx::Rect(coded_size),
            natural_size, base::TimeDelta())));
    EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
    EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
    EXPECT_CALL(*resource_provider_,
                AppendQuads(_, _,
                            media::VideoTransformation(
                                media::VideoRotation::VIDEO_ROTATION_270),
                            _));
    EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
    EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

    viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
        BEGINFRAME_FROM_HERE, now_src_.get());
    OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
    task_environment_.RunUntilIdle();

    EXPECT_EQ(sink_->last_submitted_compositor_frame().size_in_pixels(),
              rotated_size);

    AckSubmittedFrame();
  }
}

TEST_P(VideoFrameSubmitterTest, PageVisibilityControlsSubmission) {
  // Hide the page and ensure no begin frames are issued.
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->SetIsPageVisible(false);
  task_environment_.RunUntilIdle();
  EXPECT_FALSE(ShouldSubmit());

  // Start rendering, but since page is hidden nothing should start yet.
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  // Mark the page as visible and confirm frame submission.
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->SetIsPageVisible(true);
  task_environment_.RunUntilIdle();

  // Transition back to the page being hidden and ensure begin frames stop.
  EXPECT_TRUE(ShouldSubmit());
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame()).Times(0);
  submitter_->SetIsPageVisible(false);
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, PreferredInterval) {
  video_frame_provider_->preferred_interval = base::Seconds(1);

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kBeginFrame);
  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();

  EXPECT_EQ(sink_->last_submitted_compositor_frame()
                .metadata.begin_frame_ack.preferred_frame_interval,
            video_frame_provider_->preferred_interval);
  const auto& frame_interval_inputs =
      sink_->last_submitted_compositor_frame().metadata.frame_interval_inputs;
  ASSERT_EQ(frame_interval_inputs.content_interval_info.size(), 1u);
  EXPECT_EQ(frame_interval_inputs.content_interval_info[0].frame_interval,
            video_frame_provider_->preferred_interval);
  EXPECT_EQ(frame_interval_inputs.content_interval_info[0].type,
            viz::ContentFrameIntervalType::kVideo);
  EXPECT_EQ(frame_interval_inputs.content_interval_info[0].duplicate_count, 0u);
  EXPECT_TRUE(frame_interval_inputs.has_only_content_frame_interval_updates);
  EXPECT_EQ(args.frame_time, frame_interval_inputs.frame_time);
}

TEST_P(VideoFrameSubmitterTest, NoDuplicateFramesOnBeginFrame) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();
  EXPECT_TRUE(IsRendering());

  auto vf = media::VideoFrame::CreateFrame(
      media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
      gfx::Size(8, 8), base::TimeDelta());

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame()).WillOnce(Return(vf));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*resource_provider_, AppendQuads(_, _, _, _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());
  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  // Trying to submit the same frame again does nothing... even if
  // UpdateCurrentFrame() lies about there being a new frame.
  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame()).WillOnce(Return(vf));
  EXPECT_CALL(*sink_, DidNotProduceFrame(_));
  args = begin_frame_source_->CreateBeginFrameArgs(BEGINFRAME_FROM_HERE,
                                                   now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, NoDuplicateFramesDidReceiveFrame) {
  auto vf = media::VideoFrame::CreateFrame(
      media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
      gfx::Size(8, 8), base::TimeDelta());

  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame()).WillOnce(Return(vf));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*resource_provider_, AppendQuads(_, _, _, _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());
  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  // Trying to submit the same frame again does nothing...
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame()).WillOnce(Return(vf));
  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, ZeroSizedFramesAreNotSubmitted) {
  auto vf = media::VideoFrame::CreateEOSFrame();
  ASSERT_TRUE(vf->natural_size().IsEmpty());

  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame()).WillOnce(Return(vf));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _)).Times(0);
  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
}

// Check that given enough frames with wallclock duration and enough
// presentation feedback data, VideoFrameSubmitter will call the video roughness
// reporting callback.
TEST_P(VideoFrameSubmitterTest, ProcessTimingDetails) {
  int fps = 24;
  int reports = 0;
  base::TimeDelta frame_duration = base::Seconds(1.0 / fps);
  int frames_to_run =
      fps * (cc::VideoPlaybackRoughnessReporter::kMinWindowsBeforeSubmit + 1);
  WTF::HashMap<uint32_t, viz::FrameTimingDetails> timing_details;

  MakeSubmitter(base::BindLambdaForTesting(
      [&](const cc::VideoPlaybackRoughnessReporter::Measurement& measurement) {
        ASSERT_EQ(measurement.frame_size.width(), 8);
        ASSERT_EQ(measurement.frame_size.height(), 8);
        reports++;
      }));
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();
  EXPECT_TRUE(IsRendering());

  auto sink_submit = [&](const viz::LocalSurfaceId&,
                         viz::CompositorFrame* frame) {
    auto token = frame->metadata.frame_token;
    viz::FrameTimingDetails details;
    details.presentation_feedback.timestamp =
        base::TimeTicks() + frame_duration * token;
    details.presentation_feedback.flags =
        gfx::PresentationFeedback::kHWCompletion;
    timing_details.clear();
    timing_details.Set(token, details);
  };

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame).Times(AnyNumber());
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame)
      .WillRepeatedly(Invoke(sink_submit));
  EXPECT_CALL(*resource_provider_, AppendQuads).Times(AnyNumber());
  EXPECT_CALL(*resource_provider_, PrepareSendToParent).Times(AnyNumber());
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources).Times(AnyNumber());

  for (int i = 0; i < frames_to_run; i++) {
    auto frame = media::VideoFrame::CreateFrame(
        media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
        gfx::Size(8, 8), i * frame_duration);
    frame->metadata().wallclock_frame_duration = frame_duration;
    EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
        .WillRepeatedly(Return(frame));

    auto args = begin_frame_source_->CreateBeginFrameArgs(BEGINFRAME_FROM_HERE,
                                                          now_src_.get());
    OnBeginFrame(args, timing_details, false,
                 WTF::Vector<viz::ReturnedResource>());
    task_environment_.RunUntilIdle();
    AckSubmittedFrame();
  }
  submitter_->StopRendering();
  EXPECT_EQ(reports, 1);
}

TEST_P(VideoFrameSubmitterTest, OpaqueFramesNotifyEmbedder) {
  // Verify that the submitter notifies the embedder about opacity changes in
  // the video frames.

  const gfx::Size size(8, 8);
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame()).Times(AnyNumber());
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _)).Times(AnyNumber());
  EXPECT_CALL(*resource_provider_, AppendQuads(_, _, _, _)).Times(AnyNumber());
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _))
      .Times(AnyNumber());
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources()).Times(AnyNumber());

  // Send an opaque frame, and expect a callback immediately.
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateBlackFrame(size)));
  EXPECT_CALL(*surface_embedder_, OnOpacityChanged(true));
  submitter_->DidReceiveFrame();
  DrainMainThread();
  AckSubmittedFrame();

  // Send a second frame and expect no call since opacity didn't change.
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateBlackFrame(size)));
  EXPECT_CALL(*surface_embedder_, OnOpacityChanged(true)).Times(0);
  submitter_->DidReceiveFrame();
  DrainMainThread();
  AckSubmittedFrame();

  // Send a non-opaque frame and expect a call back.
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateTransparentFrame(size)));
  EXPECT_CALL(*surface_embedder_, OnOpacityChanged(false));
  submitter_->DidReceiveFrame();
  DrainMainThread();
  AckSubmittedFrame();

  // Send a second non-opaque frame and expect no call back.
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateTransparentFrame(size)));
  EXPECT_CALL(*surface_embedder_, OnOpacityChanged(false)).Times(0);
  submitter_->DidReceiveFrame();
  DrainMainThread();
}

INSTANTIATE_TEST_SUITE_P(,
                         VideoFrameSubmitterTest,
                         testing::Bool(),
                         [](auto& info) {
                           return info.param ? "BeginFrameAcks"
                                             : "CompositorFrameAcks";
                         });

}  // namespace blink
```