Response:
My thinking process to analyze the provided C++ test file went something like this:

1. **Identify the Core Class Under Test:** The filename `video_frame_submitter_test.cc` and the included header `#include "third_party/blink/renderer/platform/graphics/video_frame_submitter.h"` immediately tell me the primary focus is testing the `VideoFrameSubmitter` class.

2. **Scan for Key Components and Mock Objects:** I looked for declarations of mock objects. The presence of `MockVideoFrameProvider`, `VideoMockCompositorFrameSink`, `MockVideoFrameResourceProvider`, and `MockSurfaceEmbedder` indicates the dependencies of `VideoFrameSubmitter` that are being simulated for testing purposes. This gives me a high-level understanding of what the `VideoFrameSubmitter` interacts with.

3. **Analyze Test Fixture and Setup:** The `VideoFrameSubmitterTest` class is a test fixture. I noted the use of `base::test::TaskEnvironment` for managing asynchronous tasks, `base::SimpleTestTickClock` for controlling time, and `viz::FakeExternalBeginFrameSource` for simulating BeginFrame events. The `SetUp` method (or constructor in this case) will initialize the `VideoFrameSubmitter` and its mock dependencies. The `MakeSubmitter` function appears to be a helper for setting up the `VideoFrameSubmitter` instance.

4. **Examine Individual Test Cases (TEST_P):** I started reading through the `TEST_P` macros, which indicate parameterized tests. For each test case, I tried to understand:
    * **What aspect of `VideoFrameSubmitter` is being tested?**  The test names are often descriptive (e.g., `StatRenderingFlipsBits`, `StopRenderingSkipsUpdateCurrentFrame`).
    * **What are the expected behaviors and interactions?** The `EXPECT_CALL` statements on the mock objects reveal the expected sequence of method calls and their arguments. The `EXPECT_TRUE` and `EXPECT_FALSE` statements check the internal state of the `VideoFrameSubmitter`.
    * **What are the inputs and outputs (implicit or explicit)?**  While explicit inputs are less common in these unit tests, I considered the setup conditions and the actions performed (e.g., calling `StartRendering()`, `DidReceiveFrame()`, `OnBeginFrame()`). The outputs are the state changes in the `VideoFrameSubmitter` and the calls to its dependencies.

5. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**  I considered how the tested functionalities relate to the web platform.
    * **Video Playback:** The core purpose of `VideoFrameSubmitter` is to manage the submission of video frames for rendering. This directly relates to the `<video>` HTML element and its associated JavaScript API for controlling playback.
    * **Compositing:** The interaction with `CompositorFrameSink` suggests a connection to the browser's compositing process, which is crucial for smooth rendering of web pages, including elements positioned with CSS.
    * **BeginFrame/Synchronization:** The use of `BeginFrame` events highlights the synchronization mechanism between the rendering pipeline and the video frame provider. This ensures timely updates and prevents jank.

6. **Infer Logic and Assumptions:** By analyzing the test cases, I could infer the internal logic of `VideoFrameSubmitter`. For example:
    * It maintains a rendering state (`is_rendering_`).
    * It uses a `VideoFrameProvider` to obtain video frames.
    * It interacts with a `CompositorFrameSink` to submit frames for rendering.
    * It handles `BeginFrame` events to trigger frame updates.
    * It manages resource allocation and release.
    * It considers visibility and other factors (`ShouldSubmit()`) to optimize frame submission.

7. **Identify Potential User/Programming Errors:** I looked for test cases that indirectly revealed potential misuse or error scenarios:
    * Failing to call `StartRendering()` when expecting video to play.
    * Not handling the `OnContextLost()` event properly, leading to rendering issues.
    * Incorrectly managing the lifecycle of the `VideoFrameProvider`.

8. **Structure the Summary:**  I organized my findings into the requested categories: functionality, relationships with web technologies, logical inference, and potential errors. I used the evidence gathered from the test cases to support my claims.

9. **Address the "Part 1 of 2" Instruction:**  Since this is part one, I focused on summarizing the *current* functionality demonstrated by the provided code. I avoided making predictions about what might be in the second part, beyond acknowledging that further functionalities likely exist.

By following these steps, I could systematically analyze the provided code and generate a comprehensive summary of its functionality and its relevance to the broader web development context.
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/video_frame_submitter.h"

#include <memory>
#include <tuple>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/read_only_shared_memory_region.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "cc/layers/video_frame_provider.h"
#include "cc/metrics/video_playback_roughness_reporter.h"
#include "cc/test/layer_test_common.h"
#include "cc/trees/layer_tree_settings.h"
#include "cc/trees/task_runner_provider.h"
#include "components/viz/common/features.h"
#include "components/viz/test/fake_external_begin_frame_source.h"
#include "components/viz/test/test_context_provider.h"
#include "gpu/ipc/client/client_shared_image_interface.h"
#include "media/base/video_frame.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/viz/public/mojom/compositing/compositor_frame_sink.mojom-blink.h"
#include "services/viz/public/mojom/compositing/layer_context.mojom-blink.h"
#include "services/viz/public/mojom/hit_test/hit_test_region_list.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_compositor_frame_sink.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_embedded_frame_sink_provider.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_resource_provider.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using testing::_;
using testing::AnyNumber;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;

namespace blink {

namespace {

class MockVideoFrameProvider : public cc::VideoFrameProvider {
 public:
  MockVideoFrameProvider() = default;
  MockVideoFrameProvider(const MockVideoFrameProvider&) = delete;
  MockVideoFrameProvider& operator=(const MockVideoFrameProvider&) = delete;
  ~MockVideoFrameProvider() override = default;

  MOCK_METHOD1(SetVideoFrameProviderClient, void(Client*));
  MOCK_METHOD2(UpdateCurrentFrame, bool(base::TimeTicks, base::TimeTicks));
  MOCK_METHOD0(HasCurrentFrame, bool());
  MOCK_METHOD0(GetCurrentFrame, scoped_refptr<media::VideoFrame>());
  MOCK_METHOD0(PutCurrentFrame, void());
  MOCK_METHOD0(OnContextLost, void());

  base::TimeDelta GetPreferredRenderInterval() override {
    return preferred_interval;
  }

  base::TimeDelta preferred_interval;
};

class VideoMockCompositorFrameSink
    : public viz::mojom::blink::CompositorFrameSink {
 public:
  VideoMockCompositorFrameSink(
      mojo::PendingReceiver<viz::mojom::blink::CompositorFrameSink> receiver) {
    receiver_.Bind(std::move(receiver));
  }
  VideoMockCompositorFrameSink(const VideoMockCompositorFrameSink&) = delete;
  VideoMockCompositorFrameSink& operator=(const VideoMockCompositorFrameSink&) =
      delete;
  ~VideoMockCompositorFrameSink() override = default;

  const viz::CompositorFrame& last_submitted_compositor_frame() const {
    return last_submitted_compositor_frame_;
  }

  MOCK_METHOD1(SetNeedsBeginFrame, void(bool));
  MOCK_METHOD0(SetWantsAnimateOnlyBeginFrames, void());
  MOCK_METHOD0(SetWantsBeginFrameAcks, void());
  MOCK_METHOD0(SetAutoNeedsBeginFrame, void());

  MOCK_METHOD2(DoSubmitCompositorFrame,
               void(const viz::LocalSurfaceId&, viz::CompositorFrame*));
  void SubmitCompositorFrame(
      const viz::LocalSurfaceId& id,
      viz::CompositorFrame frame,
      std::optional<viz::HitTestRegionList> hit_test_region_list,
      uint64_t submit_time) override {
    last_submitted_compositor_frame_ = std::move(frame);
    DoSubmitCompositorFrame(id, &last_submitted_compositor_frame_);
  }
  void SubmitCompositorFrameSync(
      const viz::LocalSurfaceId& id,
      viz::CompositorFrame frame,
      std::optional<viz::HitTestRegionList> hit_test_region_list,
      uint64_t submit_time,
      const SubmitCompositorFrameSyncCallback callback) override {
    last_submitted_compositor_frame_ = std::move(frame);
    DoSubmitCompositorFrame(id, &last_submitted_compositor_frame_);
  }

  MOCK_METHOD1(DidNotProduceFrame, void(const viz::BeginFrameAck&));
  MOCK_METHOD2(DidAllocateSharedBitmap,
               void(base::ReadOnlySharedMemoryRegion region,
                    const viz::SharedBitmapId& id));
  MOCK_METHOD1(DidDeleteSharedBitmap, void(const viz::SharedBitmapId& id));
  MOCK_METHOD1(InitializeCompositorFrameSinkType,
               void(viz::mojom::CompositorFrameSinkType));
  MOCK_METHOD1(BindLayerContext,
               void(viz::mojom::blink::PendingLayerContextPtr));
  MOCK_METHOD1(SetThreads, void(const WTF::Vector<viz::Thread>&));

 private:
  mojo::Receiver<viz::mojom::blink::CompositorFrameSink> receiver_{this};

  viz::CompositorFrame last_submitted_compositor_frame_;
};

class MockVideoFrameResourceProvider
    : public blink::VideoFrameResourceProvider {
 public:
  MockVideoFrameResourceProvider(
      viz::RasterContextProvider* context_provider,
      viz::SharedBitmapReporter* shared_bitmap_reporter,
      scoped_refptr<gpu::ClientSharedImageInterface> shared_image_interface)
      : blink::VideoFrameResourceProvider(cc::LayerTreeSettings(), false) {
    blink::VideoFrameResourceProvider::Initialize(
        context_provider, shared_bitmap_reporter, shared_image_interface);
  }
  MockVideoFrameResourceProvider(const MockVideoFrameResourceProvider&) =
      delete;
  MockVideoFrameResourceProvider& operator=(
      const MockVideoFrameResourceProvider&) = delete;
  ~MockVideoFrameResourceProvider() override = default;

  MOCK_METHOD3(Initialize,
               void(viz::RasterContextProvider*,
                    viz::SharedBitmapReporter*,
                    scoped_refptr<gpu::ClientSharedImageInterface>
                        shared_image_interface));
  MOCK_METHOD4(AppendQuads,
               void(viz::CompositorRenderPass*,
                    scoped_refptr<media::VideoFrame>,
                    media::VideoTransformation,
                    bool));
  MOCK_METHOD0(ReleaseFrameResources, void());
  MOCK_METHOD2(PrepareSendToParent,
               void(const WebVector<viz::ResourceId>&,
                    WebVector<viz::TransferableResource>*));
  MOCK_METHOD1(ReceiveReturnsFromParent,
               void(Vector<viz::ReturnedResource> transferable_resources));
  MOCK_METHOD0(ObtainContextProvider, void());
};

class MockSurfaceEmbedder : public mojom::blink::SurfaceEmbedder {
 public:
  MOCK_METHOD1(SetLocalSurfaceId, void(const viz::LocalSurfaceId&));
  MOCK_METHOD1(OnOpacityChanged, void(bool));
  mojo::Receiver<mojom::blink::SurfaceEmbedder> receiver_{this};
};
}  // namespace

// Supports testing features::OnBeginFrameAcks, which changes the expectations
// of what IPCs are sent to the CompositorFrameSinkClient. When enabled
// OnBeginFrame also handles ReturnResources as well as
// DidReceiveCompositorFrameAck.
class VideoFrameSubmitterTest : public testing::Test,
                                public testing::WithParamInterface<bool> {
 public:
  VideoFrameSubmitterTest()
      : now_src_(new base::SimpleTestTickClock()),
        begin_frame_source_(new viz::FakeExternalBeginFrameSource(0.f, false)),
        video_frame_provider_(new StrictMock<MockVideoFrameProvider>()),
        context_provider_(viz::TestContextProvider::Create()) {
    if (HasBeginFrameAcks()) {
      scoped_feature_list_.InitAndEnableFeature(features::kOnBeginFrameAcks);
    } else {
      scoped_feature_list_.InitAndDisableFeature(features::kOnBeginFrameAcks);
    }
    context_provider_->BindToCurrentSequence();
    MakeSubmitter();
    task_environment_.RunUntilIdle();
  }

  bool HasBeginFrameAcks() const { return GetParam(); }

  void MakeSubmitter() { MakeSubmitter(base::DoNothing()); }

  void MakeSubmitter(
      cc::VideoPlaybackRoughnessReporter::ReportingCallback reporting_cb) {
    resource_provider_ = new StrictMock<MockVideoFrameResourceProvider>(
        context_provider_.get(), nullptr, nullptr);
    submitter_ = std::make_unique<VideoFrameSubmitter>(
        base::DoNothing(), reporting_cb,
        base::WrapUnique<MockVideoFrameResourceProvider>(
            resource_provider_.get()));

    submitter_->Initialize(video_frame_provider_.get(), false);
    mojo::PendingRemote<viz::mojom::blink::CompositorFrameSink> submitter_sink;
    sink_ = std::make_unique<StrictMock<VideoMockCompositorFrameSink>>(
        submitter_sink.InitWithNewPipeAndPassReceiver());

    // By setting the submission state before we set the sink, we can make
    // testing easier without having to worry about the first sent frame.
    submitter_->SetIsSurfaceVisible(true);
    submitter_->remote_frame_sink_.Bind(std::move(submitter_sink));
    submitter_->compositor_frame_sink_ = submitter_->remote_frame_sink_.get();
    surface_embedder_ = std::make_unique<StrictMock<MockSurfaceEmbedder>>();
    EXPECT_CALL(*surface_embedder_, SetLocalSurfaceId(_)).Times(AnyNumber());
    EXPECT_CALL(*surface_embedder_, OnOpacityChanged(_)).Times(AnyNumber());
    submitter_->surface_embedder_.Bind(
        surface_embedder_->receiver_.BindNewPipeAndPassRemote());
    auto surface_id = viz::SurfaceId(
        viz::FrameSinkId(1, 1),
        viz::LocalSurfaceId(
            11, base::UnguessableToken::CreateForTesting(0x111111, 0)));
    submitter_->frame_sink_id_ = surface_id.frame_sink_id();
    submitter_->child_local_surface_id_allocator_.UpdateFromParent(
        surface_id.local_surface_id());
  }

  bool IsRendering() const { return submitter_->is_rendering_; }

  cc::VideoFrameProvider* GetProvider() const {
    return submitter_->video_frame_provider_;
  }

  bool ShouldSubmit() const { return submitter_->ShouldSubmit(); }

  void SubmitSingleFrame() { submitter_->SubmitSingleFrame(); }

  const viz::ChildLocalSurfaceIdAllocator& child_local_surface_id_allocator()
      const {
    return submitter_->child_local_surface_id_allocator_;
  }

  gfx::Size frame_size() const { return submitter_->frame_size_; }

  // Replacement for RunUntilIdle(). Post a quit closure to the end of the main
  // thread queue and wait for it.
  void DrainMainThread() {
    task_environment_.GetMainThreadTaskRunner()->PostTask(
        FROM_HERE, task_environment_.QuitClosure());
    task_environment_.RunUntilQuit();
  }

  void OnReceivedContextProvider(
      bool use_gpu_compositing,
      scoped_refptr<viz::RasterContextProvider> context_provider,
      scoped_refptr<gpu::ClientSharedImageInterface> shared_image_interface) {
    submitter_->OnReceivedContextProvider(use_gpu_compositing,
                                          std::move(context_provider),
                                          std::move(shared_image_interface));
  }

  void AckSubmittedFrame() {
    WTF::Vector<viz::ReturnedResource> resources;
    EXPECT_CALL(*resource_provider_, ReceiveReturnsFromParent(_));
    submitter_->DidReceiveCompositorFrameAck(std::move(resources));
  }

  void OnBeginFrame(
      const viz::BeginFrameArgs& args,
      const WTF::HashMap<uint32_t, viz::FrameTimingDetails>& timing_details,
      bool frame_ack,
      WTF::Vector<viz::ReturnedResource> resources) {
    if (HasBeginFrameAcks() && frame_ack) {
      EXPECT_CALL(*resource_provider_, ReceiveReturnsFromParent(_));
    }
    submitter_->OnBeginFrame(args, timing_details, frame_ack,
                             std::move(resources));
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<base::SimpleTestTickClock> now_src_;
  std::unique_ptr<viz::FakeExternalBeginFrameSource> begin_frame_source_;
  std::unique_ptr<StrictMock<VideoMockCompositorFrameSink>> sink_;
  std::unique_ptr<StrictMock<MockVideoFrameProvider>> video_frame_provider_;
  std::unique_ptr<StrictMock<MockSurfaceEmbedder>> surface_embedder_;
  scoped_refptr<viz::TestContextProvider> context_provider_;
  std::unique_ptr<VideoFrameSubmitter> submitter_;
  raw_ptr<StrictMock<MockVideoFrameResourceProvider>> resource_provider_;

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

enum class SubmissionType {
  kBeginFrame,
  kStateChange,
  kManual,
};

#define EXPECT_GET_PUT_FRAME()                                                 \
  do {                                                                         \
    EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())                     \
        .WillOnce(Return(media::VideoFrame::CreateFrame(                       \
            media::PIXEL_FORMAT_YV12, gfx::Size(8, 8),                         \
            gfx::Rect(gfx::Size(8, 8)), gfx::Size(8, 8), base::TimeDelta()))); \
    EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());                    \
  } while (0)

// Create submission state macro to ease complexity. Use a macro instead of a
// function so that line numbers are useful in test failures.
#define EXPECT_SUBMISSION(type)                                     \
  do {                                                              \
    if (type == SubmissionType::kBeginFrame) {                      \
      EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _)) \
          .WillOnce(Return(true));                                  \
    }                                                               \
    EXPECT_GET_PUT_FRAME();                                         \
    EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));             \
    EXPECT_CALL(*resource_provider_, AppendQuads(_, _, _, _));      \
    EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));    \
    EXPECT_CALL(*resource_provider_, ReleaseFrameResources());      \
  } while (0)

TEST_P(VideoFrameSubmitterTest, StatRenderingFlipsBits) {
  EXPECT_FALSE(IsRendering());
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();

  task_environment_.RunUntilIdle();

  EXPECT_TRUE(IsRendering());
}

TEST_P(VideoFrameSubmitterTest, StopRenderingSkipsUpdateCurrentFrame) {
  EXPECT_FALSE(IsRendering());
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();

  task_environment_.RunUntilIdle();

  EXPECT_TRUE(IsRendering());

  // OnBeginFrame() submits one frame.
  EXPECT_SUBMISSION(SubmissionType::kBeginFrame);
  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  // StopRendering submits one more frame.
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->StopRendering();
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  // No frames should be produced after StopRendering().
  EXPECT_CALL(*sink_, DidNotProduceFrame(_));
  args = begin_frame_source_->CreateBeginFrameArgs(BEGINFRAME_FROM_HERE,
                                                   now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, StopUsingProviderNullsProvider) {
  EXPECT_FALSE(IsRendering());
  EXPECT_EQ(video_frame_provider_.get(), GetProvider());

  submitter_->StopUsingProvider();

  EXPECT_EQ(nullptr, GetProvider());
}

TEST_P(VideoFrameSubmitterTest,
       StopUsingProviderSubmitsFrameAndStopsRendering) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(IsRendering());

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->StopUsingProvider();

  task_environment_.RunUntilIdle();

  EXPECT_FALSE(IsRendering());
}

TEST_P(VideoFrameSubmitterTest, DidReceiveFrameStillSubmitsIfRendering) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(IsRendering());

  EXPECT_SUBMISSION(SubmissionType::kManual);
  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, DidReceiveFrameSubmitsFrame) {
  EXPECT_FALSE(IsRendering());

  EXPECT_SUBMISSION(SubmissionType::kManual);
  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, ShouldSubmitPreventsSubmission) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->SetIsSurfaceVisible(false);
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(ShouldSubmit());

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->SetIsSurfaceVisible(true);
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  EXPECT_TRUE(ShouldSubmit());

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame()).Times(0);
  submitter_->SetIsSurfaceVisible(false);
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(ShouldSubmit());

  // We should only see a GetCurrentFrame() without a PutCurrentFrame() since
  // we drop the submission because !ShouldSubmit().
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));

  SubmitSingleFrame();
}

// Tests that when set to true SetForceSubmit forces frame submissions.
// regardless of the internal submit state.
TEST_P(VideoFrameSubmitterTest, SetForceSubmitForcesSubmission) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->SetIsSurfaceVisible(false);
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(ShouldSubmit());

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->SetForceSubmit(true);
  AckSubmittedFrame();

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->SetIsSurfaceVisible(true);
  task_environment_.RunUntilIdle();
  EXPECT_TRUE(ShouldSubmit());
  AckSubmittedFrame();

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->SetIsSurfaceVisible(false);
  task_environment_.RunUntilIdle();
  EXPECT_TRUE(ShouldSubmit());
  AckSubmittedFrame();

  EXPECT_SUBMISSION(SubmissionType::kManual);
  SubmitSingleFrame();
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, RotationInformationPassedToResourceProvider) {
  // Check to see if rotation is communicated pre-rendering.
  EXPECT_FALSE(IsRendering());

  submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_90);

  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_,
              AppendQuads(_, _,
                          media::VideoTransformation(
                              media::VideoRotation::VIDEO_ROTATION_90),
                          _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  // Check to see if an update to rotation just before rendering is
  // communicated.
  submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_180);

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));
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
  AckSubmittedFrame();

  // Check to see if changing rotation while rendering is handled.
  submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_270);

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_,
              AppendQuads(_, _,
                          media::VideoTransformation(
                              media::VideoRotation::VIDEO_ROTATION_270),
                          _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  args = begin_frame_source_->CreateBeginFrameArgs(BEGINFRAME_FROM_HERE,
                                                   now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, FrameTransformTakesPrecedent) {
  EXPECT_FALSE(IsRendering());

  submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_90);

  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_,
              AppendQuads(_, _,
                          media::VideoTransformation(
                              media::VideoRotation::VIDEO_ROTATION_90),
                          _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  auto frame = media::VideoFrame::CreateFrame(
      media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
      gfx::Size(8, 8), base::TimeDelta());
  frame->metadata().transformation = media::VideoTransformation(
      media::VideoRotation::VIDEO_ROTATION_180, /*mirrored=*/true);

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(frame));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_,
              AppendQuads(_, _, frame->metadata().transformation.value(), _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();
}

TEST_P(VideoFrameSubmitterTest, OnBeginFrameSubmitsFrame) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kBeginFrame);
  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, MissedFrameArgDoesNotProduceFrame) {
  EXPECT_CALL(*sink_, DidNotProduceFrame(_));

  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src
Prompt: 
```
这是目录为blink/renderer/platform/graphics/video_frame_submitter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/video_frame_submitter.h"

#include <memory>
#include <tuple>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/read_only_shared_memory_region.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "cc/layers/video_frame_provider.h"
#include "cc/metrics/video_playback_roughness_reporter.h"
#include "cc/test/layer_test_common.h"
#include "cc/trees/layer_tree_settings.h"
#include "cc/trees/task_runner_provider.h"
#include "components/viz/common/features.h"
#include "components/viz/test/fake_external_begin_frame_source.h"
#include "components/viz/test/test_context_provider.h"
#include "gpu/ipc/client/client_shared_image_interface.h"
#include "media/base/video_frame.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/viz/public/mojom/compositing/compositor_frame_sink.mojom-blink.h"
#include "services/viz/public/mojom/compositing/layer_context.mojom-blink.h"
#include "services/viz/public/mojom/hit_test/hit_test_region_list.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_compositor_frame_sink.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_embedded_frame_sink_provider.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_resource_provider.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using testing::_;
using testing::AnyNumber;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;

namespace blink {

namespace {

class MockVideoFrameProvider : public cc::VideoFrameProvider {
 public:
  MockVideoFrameProvider() = default;
  MockVideoFrameProvider(const MockVideoFrameProvider&) = delete;
  MockVideoFrameProvider& operator=(const MockVideoFrameProvider&) = delete;
  ~MockVideoFrameProvider() override = default;

  MOCK_METHOD1(SetVideoFrameProviderClient, void(Client*));
  MOCK_METHOD2(UpdateCurrentFrame, bool(base::TimeTicks, base::TimeTicks));
  MOCK_METHOD0(HasCurrentFrame, bool());
  MOCK_METHOD0(GetCurrentFrame, scoped_refptr<media::VideoFrame>());
  MOCK_METHOD0(PutCurrentFrame, void());
  MOCK_METHOD0(OnContextLost, void());

  base::TimeDelta GetPreferredRenderInterval() override {
    return preferred_interval;
  }

  base::TimeDelta preferred_interval;
};

class VideoMockCompositorFrameSink
    : public viz::mojom::blink::CompositorFrameSink {
 public:
  VideoMockCompositorFrameSink(
      mojo::PendingReceiver<viz::mojom::blink::CompositorFrameSink> receiver) {
    receiver_.Bind(std::move(receiver));
  }
  VideoMockCompositorFrameSink(const VideoMockCompositorFrameSink&) = delete;
  VideoMockCompositorFrameSink& operator=(const VideoMockCompositorFrameSink&) =
      delete;
  ~VideoMockCompositorFrameSink() override = default;

  const viz::CompositorFrame& last_submitted_compositor_frame() const {
    return last_submitted_compositor_frame_;
  }

  MOCK_METHOD1(SetNeedsBeginFrame, void(bool));
  MOCK_METHOD0(SetWantsAnimateOnlyBeginFrames, void());
  MOCK_METHOD0(SetWantsBeginFrameAcks, void());
  MOCK_METHOD0(SetAutoNeedsBeginFrame, void());

  MOCK_METHOD2(DoSubmitCompositorFrame,
               void(const viz::LocalSurfaceId&, viz::CompositorFrame*));
  void SubmitCompositorFrame(
      const viz::LocalSurfaceId& id,
      viz::CompositorFrame frame,
      std::optional<viz::HitTestRegionList> hit_test_region_list,
      uint64_t submit_time) override {
    last_submitted_compositor_frame_ = std::move(frame);
    DoSubmitCompositorFrame(id, &last_submitted_compositor_frame_);
  }
  void SubmitCompositorFrameSync(
      const viz::LocalSurfaceId& id,
      viz::CompositorFrame frame,
      std::optional<viz::HitTestRegionList> hit_test_region_list,
      uint64_t submit_time,
      const SubmitCompositorFrameSyncCallback callback) override {
    last_submitted_compositor_frame_ = std::move(frame);
    DoSubmitCompositorFrame(id, &last_submitted_compositor_frame_);
  }

  MOCK_METHOD1(DidNotProduceFrame, void(const viz::BeginFrameAck&));
  MOCK_METHOD2(DidAllocateSharedBitmap,
               void(base::ReadOnlySharedMemoryRegion region,
                    const viz::SharedBitmapId& id));
  MOCK_METHOD1(DidDeleteSharedBitmap, void(const viz::SharedBitmapId& id));
  MOCK_METHOD1(InitializeCompositorFrameSinkType,
               void(viz::mojom::CompositorFrameSinkType));
  MOCK_METHOD1(BindLayerContext,
               void(viz::mojom::blink::PendingLayerContextPtr));
  MOCK_METHOD1(SetThreads, void(const WTF::Vector<viz::Thread>&));

 private:
  mojo::Receiver<viz::mojom::blink::CompositorFrameSink> receiver_{this};

  viz::CompositorFrame last_submitted_compositor_frame_;
};

class MockVideoFrameResourceProvider
    : public blink::VideoFrameResourceProvider {
 public:
  MockVideoFrameResourceProvider(
      viz::RasterContextProvider* context_provider,
      viz::SharedBitmapReporter* shared_bitmap_reporter,
      scoped_refptr<gpu::ClientSharedImageInterface> shared_image_interface)
      : blink::VideoFrameResourceProvider(cc::LayerTreeSettings(), false) {
    blink::VideoFrameResourceProvider::Initialize(
        context_provider, shared_bitmap_reporter, shared_image_interface);
  }
  MockVideoFrameResourceProvider(const MockVideoFrameResourceProvider&) =
      delete;
  MockVideoFrameResourceProvider& operator=(
      const MockVideoFrameResourceProvider&) = delete;
  ~MockVideoFrameResourceProvider() override = default;

  MOCK_METHOD3(Initialize,
               void(viz::RasterContextProvider*,
                    viz::SharedBitmapReporter*,
                    scoped_refptr<gpu::ClientSharedImageInterface>
                        shared_image_interface));
  MOCK_METHOD4(AppendQuads,
               void(viz::CompositorRenderPass*,
                    scoped_refptr<media::VideoFrame>,
                    media::VideoTransformation,
                    bool));
  MOCK_METHOD0(ReleaseFrameResources, void());
  MOCK_METHOD2(PrepareSendToParent,
               void(const WebVector<viz::ResourceId>&,
                    WebVector<viz::TransferableResource>*));
  MOCK_METHOD1(ReceiveReturnsFromParent,
               void(Vector<viz::ReturnedResource> transferable_resources));
  MOCK_METHOD0(ObtainContextProvider, void());
};

class MockSurfaceEmbedder : public mojom::blink::SurfaceEmbedder {
 public:
  MOCK_METHOD1(SetLocalSurfaceId, void(const viz::LocalSurfaceId&));
  MOCK_METHOD1(OnOpacityChanged, void(bool));
  mojo::Receiver<mojom::blink::SurfaceEmbedder> receiver_{this};
};
}  // namespace

// Supports testing features::OnBeginFrameAcks, which changes the expectations
// of what IPCs are sent to the CompositorFrameSinkClient. When enabled
// OnBeginFrame also handles ReturnResources as well as
// DidReceiveCompositorFrameAck.
class VideoFrameSubmitterTest : public testing::Test,
                                public testing::WithParamInterface<bool> {
 public:
  VideoFrameSubmitterTest()
      : now_src_(new base::SimpleTestTickClock()),
        begin_frame_source_(new viz::FakeExternalBeginFrameSource(0.f, false)),
        video_frame_provider_(new StrictMock<MockVideoFrameProvider>()),
        context_provider_(viz::TestContextProvider::Create()) {
    if (HasBeginFrameAcks()) {
      scoped_feature_list_.InitAndEnableFeature(features::kOnBeginFrameAcks);
    } else {
      scoped_feature_list_.InitAndDisableFeature(features::kOnBeginFrameAcks);
    }
    context_provider_->BindToCurrentSequence();
    MakeSubmitter();
    task_environment_.RunUntilIdle();
  }

  bool HasBeginFrameAcks() const { return GetParam(); }

  void MakeSubmitter() { MakeSubmitter(base::DoNothing()); }

  void MakeSubmitter(
      cc::VideoPlaybackRoughnessReporter::ReportingCallback reporting_cb) {
    resource_provider_ = new StrictMock<MockVideoFrameResourceProvider>(
        context_provider_.get(), nullptr, nullptr);
    submitter_ = std::make_unique<VideoFrameSubmitter>(
        base::DoNothing(), reporting_cb,
        base::WrapUnique<MockVideoFrameResourceProvider>(
            resource_provider_.get()));

    submitter_->Initialize(video_frame_provider_.get(), false);
    mojo::PendingRemote<viz::mojom::blink::CompositorFrameSink> submitter_sink;
    sink_ = std::make_unique<StrictMock<VideoMockCompositorFrameSink>>(
        submitter_sink.InitWithNewPipeAndPassReceiver());

    // By setting the submission state before we set the sink, we can make
    // testing easier without having to worry about the first sent frame.
    submitter_->SetIsSurfaceVisible(true);
    submitter_->remote_frame_sink_.Bind(std::move(submitter_sink));
    submitter_->compositor_frame_sink_ = submitter_->remote_frame_sink_.get();
    surface_embedder_ = std::make_unique<StrictMock<MockSurfaceEmbedder>>();
    EXPECT_CALL(*surface_embedder_, SetLocalSurfaceId(_)).Times(AnyNumber());
    EXPECT_CALL(*surface_embedder_, OnOpacityChanged(_)).Times(AnyNumber());
    submitter_->surface_embedder_.Bind(
        surface_embedder_->receiver_.BindNewPipeAndPassRemote());
    auto surface_id = viz::SurfaceId(
        viz::FrameSinkId(1, 1),
        viz::LocalSurfaceId(
            11, base::UnguessableToken::CreateForTesting(0x111111, 0)));
    submitter_->frame_sink_id_ = surface_id.frame_sink_id();
    submitter_->child_local_surface_id_allocator_.UpdateFromParent(
        surface_id.local_surface_id());
  }

  bool IsRendering() const { return submitter_->is_rendering_; }

  cc::VideoFrameProvider* GetProvider() const {
    return submitter_->video_frame_provider_;
  }

  bool ShouldSubmit() const { return submitter_->ShouldSubmit(); }

  void SubmitSingleFrame() { submitter_->SubmitSingleFrame(); }

  const viz::ChildLocalSurfaceIdAllocator& child_local_surface_id_allocator()
      const {
    return submitter_->child_local_surface_id_allocator_;
  }

  gfx::Size frame_size() const { return submitter_->frame_size_; }

  // Replacement for RunUntilIdle().  Post a quit closure to the end of the main
  // thread queue and wait for it.
  void DrainMainThread() {
    task_environment_.GetMainThreadTaskRunner()->PostTask(
        FROM_HERE, task_environment_.QuitClosure());
    task_environment_.RunUntilQuit();
  }

  void OnReceivedContextProvider(
      bool use_gpu_compositing,
      scoped_refptr<viz::RasterContextProvider> context_provider,
      scoped_refptr<gpu::ClientSharedImageInterface> shared_image_interface) {
    submitter_->OnReceivedContextProvider(use_gpu_compositing,
                                          std::move(context_provider),
                                          std::move(shared_image_interface));
  }

  void AckSubmittedFrame() {
    WTF::Vector<viz::ReturnedResource> resources;
    EXPECT_CALL(*resource_provider_, ReceiveReturnsFromParent(_));
    submitter_->DidReceiveCompositorFrameAck(std::move(resources));
  }

  void OnBeginFrame(
      const viz::BeginFrameArgs& args,
      const WTF::HashMap<uint32_t, viz::FrameTimingDetails>& timing_details,
      bool frame_ack,
      WTF::Vector<viz::ReturnedResource> resources) {
    if (HasBeginFrameAcks() && frame_ack) {
      EXPECT_CALL(*resource_provider_, ReceiveReturnsFromParent(_));
    }
    submitter_->OnBeginFrame(args, timing_details, frame_ack,
                             std::move(resources));
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<base::SimpleTestTickClock> now_src_;
  std::unique_ptr<viz::FakeExternalBeginFrameSource> begin_frame_source_;
  std::unique_ptr<StrictMock<VideoMockCompositorFrameSink>> sink_;
  std::unique_ptr<StrictMock<MockVideoFrameProvider>> video_frame_provider_;
  std::unique_ptr<StrictMock<MockSurfaceEmbedder>> surface_embedder_;
  scoped_refptr<viz::TestContextProvider> context_provider_;
  std::unique_ptr<VideoFrameSubmitter> submitter_;
  raw_ptr<StrictMock<MockVideoFrameResourceProvider>> resource_provider_;

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

enum class SubmissionType {
  kBeginFrame,
  kStateChange,
  kManual,
};

#define EXPECT_GET_PUT_FRAME()                                                 \
  do {                                                                         \
    EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())                     \
        .WillOnce(Return(media::VideoFrame::CreateFrame(                       \
            media::PIXEL_FORMAT_YV12, gfx::Size(8, 8),                         \
            gfx::Rect(gfx::Size(8, 8)), gfx::Size(8, 8), base::TimeDelta()))); \
    EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());                    \
  } while (0)

// Create submission state macro to ease complexity. Use a macro instead of a
// function so that line numbers are useful in test failures.
#define EXPECT_SUBMISSION(type)                                     \
  do {                                                              \
    if (type == SubmissionType::kBeginFrame) {                      \
      EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _)) \
          .WillOnce(Return(true));                                  \
    }                                                               \
    EXPECT_GET_PUT_FRAME();                                         \
    EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));             \
    EXPECT_CALL(*resource_provider_, AppendQuads(_, _, _, _));      \
    EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));    \
    EXPECT_CALL(*resource_provider_, ReleaseFrameResources());      \
  } while (0)

TEST_P(VideoFrameSubmitterTest, StatRenderingFlipsBits) {
  EXPECT_FALSE(IsRendering());
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();

  task_environment_.RunUntilIdle();

  EXPECT_TRUE(IsRendering());
}

TEST_P(VideoFrameSubmitterTest, StopRenderingSkipsUpdateCurrentFrame) {
  EXPECT_FALSE(IsRendering());
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();

  task_environment_.RunUntilIdle();

  EXPECT_TRUE(IsRendering());

  // OnBeginFrame() submits one frame.
  EXPECT_SUBMISSION(SubmissionType::kBeginFrame);
  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  // StopRendering submits one more frame.
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->StopRendering();
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  // No frames should be produced after StopRendering().
  EXPECT_CALL(*sink_, DidNotProduceFrame(_));
  args = begin_frame_source_->CreateBeginFrameArgs(BEGINFRAME_FROM_HERE,
                                                   now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, StopUsingProviderNullsProvider) {
  EXPECT_FALSE(IsRendering());
  EXPECT_EQ(video_frame_provider_.get(), GetProvider());

  submitter_->StopUsingProvider();

  EXPECT_EQ(nullptr, GetProvider());
}

TEST_P(VideoFrameSubmitterTest,
       StopUsingProviderSubmitsFrameAndStopsRendering) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(IsRendering());

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->StopUsingProvider();

  task_environment_.RunUntilIdle();

  EXPECT_FALSE(IsRendering());
}

TEST_P(VideoFrameSubmitterTest, DidReceiveFrameStillSubmitsIfRendering) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_TRUE(IsRendering());

  EXPECT_SUBMISSION(SubmissionType::kManual);
  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, DidReceiveFrameSubmitsFrame) {
  EXPECT_FALSE(IsRendering());

  EXPECT_SUBMISSION(SubmissionType::kManual);
  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, ShouldSubmitPreventsSubmission) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->SetIsSurfaceVisible(false);
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(ShouldSubmit());

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->SetIsSurfaceVisible(true);
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  EXPECT_TRUE(ShouldSubmit());

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame()).Times(0);
  submitter_->SetIsSurfaceVisible(false);
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(ShouldSubmit());

  // We should only see a GetCurrentFrame() without a PutCurrentFrame() since
  // we drop the submission because !ShouldSubmit().
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));

  SubmitSingleFrame();
}

// Tests that when set to true SetForceSubmit forces frame submissions.
// regardless of the internal submit state.
TEST_P(VideoFrameSubmitterTest, SetForceSubmitForcesSubmission) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->SetIsSurfaceVisible(false);
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(ShouldSubmit());

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->SetForceSubmit(true);
  AckSubmittedFrame();

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->SetIsSurfaceVisible(true);
  task_environment_.RunUntilIdle();
  EXPECT_TRUE(ShouldSubmit());
  AckSubmittedFrame();

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  submitter_->SetIsSurfaceVisible(false);
  task_environment_.RunUntilIdle();
  EXPECT_TRUE(ShouldSubmit());
  AckSubmittedFrame();

  EXPECT_SUBMISSION(SubmissionType::kManual);
  SubmitSingleFrame();
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, RotationInformationPassedToResourceProvider) {
  // Check to see if rotation is communicated pre-rendering.
  EXPECT_FALSE(IsRendering());

  submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_90);

  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_,
              AppendQuads(_, _,
                          media::VideoTransformation(
                              media::VideoRotation::VIDEO_ROTATION_90),
                          _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  // Check to see if an update to rotation just before rendering is
  // communicated.
  submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_180);

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));
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
  AckSubmittedFrame();

  // Check to see if changing rotation while rendering is handled.
  submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_270);

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_,
              AppendQuads(_, _,
                          media::VideoTransformation(
                              media::VideoRotation::VIDEO_ROTATION_270),
                          _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  args = begin_frame_source_->CreateBeginFrameArgs(BEGINFRAME_FROM_HERE,
                                                   now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, FrameTransformTakesPrecedent) {
  EXPECT_FALSE(IsRendering());

  submitter_->SetTransform(media::VideoRotation::VIDEO_ROTATION_90);

  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_,
              AppendQuads(_, _,
                          media::VideoTransformation(
                              media::VideoRotation::VIDEO_ROTATION_90),
                          _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();

  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  auto frame = media::VideoFrame::CreateFrame(
      media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
      gfx::Size(8, 8), base::TimeDelta());
  frame->metadata().transformation = media::VideoTransformation(
      media::VideoRotation::VIDEO_ROTATION_180, /*mirrored=*/true);

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(frame));
  EXPECT_CALL(*sink_, DoSubmitCompositorFrame(_, _));
  EXPECT_CALL(*video_frame_provider_, PutCurrentFrame());
  EXPECT_CALL(*resource_provider_,
              AppendQuads(_, _, frame->metadata().transformation.value(), _));
  EXPECT_CALL(*resource_provider_, PrepareSendToParent(_, _));
  EXPECT_CALL(*resource_provider_, ReleaseFrameResources());

  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
  AckSubmittedFrame();
}

TEST_P(VideoFrameSubmitterTest, OnBeginFrameSubmitsFrame) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kBeginFrame);
  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, MissedFrameArgDoesNotProduceFrame) {
  EXPECT_CALL(*sink_, DidNotProduceFrame(_));

  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  args.type = viz::BeginFrameArgs::MISSED;
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, MissingProviderDoesNotProduceFrame) {
  submitter_->StopUsingProvider();

  EXPECT_CALL(*sink_, DidNotProduceFrame(_));

  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, NoUpdateOnFrameDoesNotProduceFrame) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));
  submitter_->StartRendering();

  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .WillOnce(Return(false));
  EXPECT_CALL(*sink_, DidNotProduceFrame(_));

  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, NotRenderingDoesNotProduceFrame) {
  // We don't care if UpdateCurrentFrame is called or not; it doesn't matter
  // if we're not rendering.
  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _))
      .Times(AnyNumber());
  EXPECT_CALL(*sink_, DidNotProduceFrame(_));

  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

TEST_P(VideoFrameSubmitterTest, ReturnsResourceOnCompositorAck) {
  AckSubmittedFrame();
  task_environment_.RunUntilIdle();
}

// Tests that after submitting a frame, no frame will be submitted until an ACK
// was received. This is tested by simulating another BeginFrame message.
TEST_P(VideoFrameSubmitterTest, WaitingForAckPreventsNewFrame) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kBeginFrame);
  viz::BeginFrameArgs args = begin_frame_source_->CreateBeginFrameArgs(
      BEGINFRAME_FROM_HERE, now_src_.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();

  // DidNotProduceFrame should be called because no frame will be submitted
  // given that the ACK is still pending.
  EXPECT_CALL(*sink_, DidNotProduceFrame(_)).Times(1);

  // UpdateCurrentFrame should still be called, however, so that the compositor
  // knows that we missed a frame.
  EXPECT_CALL(*video_frame_provider_, UpdateCurrentFrame(_, _)).Times(1);

  std::unique_ptr<base::SimpleTestTickClock> new_time =
      std::make_unique<base::SimpleTestTickClock>();
  args = begin_frame_source_->CreateBeginFrameArgs(BEGINFRAME_FROM_HERE,
                                                   new_time.get());
  OnBeginFrame(args, {}, false, WTF::Vector<viz::ReturnedResource>());
  task_environment_.RunUntilIdle();
}

// Similar to above but verifies the single-frame paint path.
TEST_P(VideoFrameSubmitterTest, WaitingForAckPreventsSubmitSingleFrame) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kManual);
  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();

  // GetCurrentFrame() should be called, but PutCurrentFrame() should not, since
  // the frame is dropped waiting for the ack.
  EXPECT_CALL(*video_frame_provider_, GetCurrentFrame())
      .WillOnce(Return(media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_YV12, gfx::Size(8, 8), gfx::Rect(gfx::Size(8, 8)),
          gfx::Size(8, 8), base::TimeDelta())));

  submitter_->DidReceiveFrame();
  task_environment_.RunUntilIdle();
}

// Test that after context is lost, the CompositorFrameSink is recreated but the
// SurfaceEmbedder isn't.
TEST_P(VideoFrameSubmitterTest, RecreateCompositorFrameSinkAfterContextLost) {
  MockEmbeddedFrameSinkProvider mock_embedded_frame_sink_provider;
  mojo::ReceiverSet<mojom::blink::EmbeddedFrameSinkProvider>
      embedded_frame_sink_provider_receivers;
  auto override =
      mock_embedded_frame_sink_provider.CreateScopedOverrideMojoInterface(
          embedded_frame_sink_provider_receivers);

  EXPECT_CALL(*resource_provider_, Initialize(_, _, _));
  EXPECT_CALL(mock_embedded_frame_sink_provider, ConnectToEmbedder(_, _))
      .Times(0);
  EXPECT_CALL(mock_embedded_frame_sink_provider, CreateCompositorFrameSink_(_))
      .Times(1);
  EXPECT_CALL(*video_frame_provider_, OnContextLost()).Times(1);
  submitter_->OnContextLost();
  OnReceivedContextProvider(true, context_provider_, nullptr);
  task_environment_.RunUntilIdle();
}

// Test that after context is lost, the CompositorFrameSink is recreated but the
// SurfaceEmbedder isn't even with software compositing.
TEST_P(VideoFrameSubmitterTest,
       RecreateCompositorFrameSinkAfterContextLostSoftwareCompositing) {
  MockEmbeddedFrameSinkProvider mock_embedded_frame_sink_provider;
  mojo::ReceiverSet<mojom::blink::EmbeddedFrameSinkProvider>
      embedded_frame_sink_provider_receivers;
  auto override =
      mock_embedded_frame_sink_provider.CreateScopedOverrideMojoInterface(
          embedded_frame_sink_provider_receivers);

  EXPECT_CALL(*resource_provider_, Initialize(_, _, _));
  EXPECT_CALL(mock_embedded_frame_sink_provider, ConnectToEmbedder(_, _))
      .Times(0);
  EXPECT_CALL(mock_embedded_frame_sink_provider, CreateCompositorFrameSink_(_))
      .Times(1);
  EXPECT_CALL(*video_frame_provider_, OnContextLost()).Times(1);
  submitter_->OnContextLost();
  OnReceivedContextProvider(false, nullptr, nullptr);
  task_environment_.RunUntilIdle();
}

// This test simulates a race condition in which the |video_frame_provider_| is
// destroyed before OnReceivedContextProvider returns.
TEST_P(VideoFrameSubmitterTest, StopUsingProviderDuringContextLost) {
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(true));

  submitter_->StartRendering();
  task_environment_.RunUntilIdle();

  EXPECT_SUBMISSION(SubmissionType::kStateChange);
  EXPECT_CALL(*sink_, SetNeedsBeginFrame(false));
  submitter_->StopUsingProvider();

  task_environment_.RunUntilIdle();

  // OnReceivedContextProvider returns. We don't run the actual function
  // because it would overwrite our fake |sink_| with a real one.
  SubmitSingleFrame();

  task_environment_.RunUntilIdle();
}

// Test the behaviour of the ChildLocalSurfaceIdAllocator instance. It checks
// that the LocalSurfaceId is properly set at creation and updated when the
// video frames change.
TEST_P(VideoFrameSubmitterTest, FrameSizeChangeUpdatesLocalSurfaceId) {
  {
    viz::LocalSurfaceId local_surface_id =
        child_local_surface_id_allocator().GetCurrentLocalSurfaceId();
    EXPECT_TRUE(local_surface_id.is_valid());
    EXPECT_EQ(11u, local_surface_id.parent_sequence_number());
    EXPECT_EQ(viz::kInitialChildSequenceNumber,
              local_surface_id.child_sequence_number());
    EXPECT_TRUE(frame_size().IsEmpty());
  }

  EX
"""


```