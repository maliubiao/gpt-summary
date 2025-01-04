Response: Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code and explain its functionality, its relation to web technologies (if any), and common usage patterns/errors. Since it's a `_unittest.cc` file, the core function is testing another piece of code.

2. **Identify the Core Class Under Test:** The filename `video_frame_compositor_unittest.cc` strongly suggests that the class being tested is `VideoFrameCompositor`. This is the central piece of the puzzle.

3. **Examine Includes and Namespaces:**
    * `#include "third_party/blink/public/platform/media/video_frame_compositor.h"`: This confirms that we are dealing with the `VideoFrameCompositor` class. The path indicates it's part of the Blink rendering engine and related to media.
    * Other includes (`base/...`, `components/viz/...`, `media/...`, `testing/...`): These provide hints about the dependencies and the testing framework being used (Google Test/GMock). `viz` suggests interaction with the visual rendering pipeline. `media` confirms the domain.
    * `namespace blink`:  Reinforces that this is Blink-specific code.

4. **Identify Key Helper Classes and Mocks:**
    * `MockWebVideoFrameSubmitter`: This is a crucial observation. The presence of a mock suggests that `VideoFrameCompositor` interacts with another component through the `WebVideoFrameSubmitter` interface. The mock allows isolating the `VideoFrameCompositor` during testing. Look at the mocked methods – they provide valuable clues about the interactions: `EnableSubmission`, `StartRendering`, `SetTransform`, etc.
    * `VideoFrameCompositorTest`:  This is the test fixture class, inheriting from `media::VideoRendererSink::RenderCallback` and `testing::Test`. This indicates that `VideoFrameCompositor` likely implements or interacts with the `VideoRendererSink::RenderCallback` interface. The mocked `Render`, `OnFrameDropped`, and `OnNewFramePresented` methods in the test fixture are important for verifying callbacks.

5. **Analyze the Test Fixture Setup (`SetUp`):**
    * Instantiation of `VideoFrameCompositor` with the mock `WebVideoFrameSubmitter`.
    * Initial setup calls on the mock (`Initialize`, `SetTransform`, `SetForceSubmit`, `EnableSubmission`). These show the expected initial state and configuration.
    * Setting the tick clock – indicates testing of time-dependent behavior.
    * Disabling background rendering by default.

6. **Analyze Individual Test Cases:**  Go through each `TEST_F` function and understand what aspect of `VideoFrameCompositor` is being tested. Look for:
    * **Arrange:** What setup is done before the action? (e.g., creating frames, setting up expectations on mocks).
    * **Act:** What is the core action being performed on the `VideoFrameCompositor`? (e.g., calling `PaintSingleFrame`, `Start`, `Stop`, `UpdateCurrentFrame`).
    * **Assert:** What are the expectations after the action? (e.g., checking the return value, verifying mock method calls, comparing frame data).

7. **Identify Relationships to Web Technologies:**
    * **JavaScript's `requestVideoFrameCallback()`:**  The test `RenderFiresPresentationCallback` and `PresentationCallbackForcesBeginFrames` directly relate to this JavaScript API. The callback mechanism in the C++ code is designed to support this web feature.
    * **HTML `<video>` element:** Although not explicitly tested, the `VideoFrameCompositor` is a core component for rendering video within the `<video>` element. The concepts of video frames, presentation time, and visibility are directly tied to the `<video>` element's functionality.
    * **CSS:** The `SetTransform` method hints at CSS transformations being applied to the video. Visibility control (`SetIsSurfaceVisible`, `SetIsPageVisible`) is also connected to CSS visibility properties.

8. **Infer Functionality Based on Tests:**  Even without seeing the implementation of `VideoFrameCompositor`, the tests provide strong clues about its responsibilities:
    * Receiving and managing video frames.
    * Submitting frames for rendering (through `WebVideoFrameSubmitter`).
    * Handling visibility changes.
    * Implementing a rendering loop (with background rendering).
    * Providing callbacks for frame presentation.
    * Handling context loss (for GPU resources).

9. **Identify Potential Usage Errors:**  Think about how a developer using `VideoFrameCompositor` (or a related API) might misuse it, based on the test scenarios:
    * Not calling `PutCurrentFrame()` after `GetCurrentFrame()`, leading to dropped frames.
    * Misunderstanding the lifecycle of presentation callbacks (they are one-shot).
    * Incorrectly assuming background rendering behavior.
    * Potential issues when dealing with GPU frames and context loss.

10. **Formulate Input/Output Examples (Logical Reasoning):** Choose specific test cases that illustrate a logical flow and create concrete examples of how different inputs to the `VideoFrameCompositor` (like calling certain methods) result in specific outputs (like mock calls or changes in state).

11. **Structure the Explanation:**  Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Reasoning, and Common Usage Errors. Use clear and concise language. Provide specific code snippets from the tests as examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just manages video frames."  **Correction:**  The interaction with `WebVideoFrameSubmitter` shows it's not just about *managing* frames, but also *submitting* them for rendering.
* **Initial thought:** "Background rendering is always on." **Correction:** The `SetUp` method explicitly disables background rendering by default, indicating it's an optional feature.
* **Noticing patterns:** The repeated use of `base::RunLoop().RunUntilIdle()` suggests asynchronous operations are involved. The consistent use of mocks points to testing in isolation.

By following these steps, and continuously refining the understanding based on the code, a comprehensive analysis like the example provided in the prompt can be generated.
这个C++源代码文件 `video_frame_compositor_unittest.cc` 是 Chromium Blink 引擎的一部分，它专门用于测试 `VideoFrameCompositor` 类的功能。`VideoFrameCompositor` 的主要职责是管理和提交视频帧以进行渲染。

以下是这个单元测试文件的功能分解：

**核心功能：测试 `VideoFrameCompositor` 类的各种行为和交互。**

这个测试文件通过创建各种场景和调用 `VideoFrameCompositor` 的方法，来验证其是否按预期工作。它使用 Google Test (gtest) 和 Google Mock (gmock) 框架进行断言和模拟。

**具体测试的功能点包括：**

1. **初始状态:** 验证 `VideoFrameCompositor` 在创建后的初始状态，例如是否没有当前帧。
2. **表面可见性控制 (`SetIsSurfaceVisible`):** 测试当视频表面可见性发生变化时，`VideoFrameCompositor` 是否正确地通知 `WebVideoFrameSubmitter`。
3. **页面可见性控制 (`SetIsPageVisible`):**  测试当页面可见性发生变化时，`VideoFrameCompositor` 是否正确地通知 `WebVideoFrameSubmitter`。
4. **单帧绘制 (`PaintSingleFrame`):**  测试向 `VideoFrameCompositor` 提交单个视频帧是否能被正确接收和记录。
5. **渲染回调触发 (`RenderFiresPresentationCallback`):** 测试当视频帧被渲染时，是否触发了预期的回调函数，并且包含了正确的元数据（如呈现时间）。这关系到 JavaScript 的 `requestVideoFrameCallback` API。
6. **呈现回调强制开始帧 (`PresentationCallbackForcesBeginFrames`):** 测试设置呈现回调是否会导致 `VideoFrameCompositor` 强制请求新的渲染帧。
7. **多个呈现回调 (`MultiplePresentationCallbacks`):** 测试设置和触发多个呈现回调的情况，验证回调的单次触发特性以及帧元数据的更新。
8. **视频渲染器 Sink 帧丢弃 (`VideoRendererSinkFrameDropped`):** 测试当新的视频帧到达时，旧的未渲染的帧是否会被正确丢弃，并触发相应的回调。
9. **视频渲染器 Sink 获取当前帧无丢弃 (`VideoRendererSinkGetCurrentFrameNoDrops`):** 测试在获取当前帧后，即使有新的帧到达，也不会立即触发丢帧回调。
10. **启动触发后台渲染 (`StartFiresBackgroundRender`):** 测试启动视频渲染器时，是否会触发后台渲染，即使没有明确请求渲染。
11. **后台渲染 Tick (`BackgroundRenderTicks`):** 测试在启用后台渲染的情况下，`VideoFrameCompositor` 是否会定期请求渲染新的帧。
12. **后台渲染时更新当前帧 (`UpdateCurrentFrameWorksWhenBackgroundRendered`):** 测试在后台渲染启用时，`UpdateCurrentFrame` 方法的行为是否符合预期。
13. **过时时更新当前帧 (`UpdateCurrentFrameIfStale`):** 测试在一定时间没有新帧到达时，`VideoFrameCompositor` 是否会主动请求新的帧。
14. **绕过客户端更新当前帧 (`UpdateCurrentFrameIfStale_ClientBypass`):** 测试即使有客户端在驱动帧更新，也可以强制更新当前帧。
15. **首选渲染间隔 (`PreferredRenderInterval`):** 测试 `VideoFrameCompositor` 是否能获取和使用首选的渲染时间间隔。
16. **上下文丢失处理 (`OnContextLost`):** 测试在图形上下文丢失时，`VideoFrameCompositor` 如何处理 GPU 相关的视频帧。

**与 JavaScript, HTML, CSS 功能的关系及举例：**

这个测试文件直接测试了与 JavaScript 的 `requestVideoFrameCallback` API 相关的逻辑。`VideoFrameCompositor` 是实现这个 API 的关键组件之一。

* **JavaScript `requestVideoFrameCallback()`:**
    * **关系:**  `VideoFrameCompositor` 的 `SetOnFramePresentedCallback` 方法对应于 JavaScript 中调用 `requestVideoFrameCallback()` 设置的回调函数。当视频帧准备好呈现时，`VideoFrameCompositor` 会调用这个回调函数。
    * **举例:** 测试用例 `RenderFiresPresentationCallback` 验证了当 `VideoFrameCompositor` 接收到可以渲染的帧时，会调用通过 `SetOnFramePresentedCallback` 设置的回调。这模拟了 JavaScript 调用 `requestVideoFrameCallback()` 后，当浏览器准备好渲染新帧时，传递给该 API 的回调函数被执行的情况。

* **HTML `<video>` 元素:**
    * **关系:** `VideoFrameCompositor` 是 `<video>` 元素渲染视频的核心组件之一。它负责接收解码后的视频帧，并将其提交给渲染流水线进行绘制。
    * **举例:** 虽然测试文件本身不直接涉及 HTML，但 `VideoFrameCompositor` 的目标是为 `<video>` 元素提供流畅的视频渲染。例如，`PaintSingleFrame` 测试模拟了 `<video>` 元素接收到新的视频帧并传递给 `VideoFrameCompositor` 的过程。

* **CSS 动画和变换:**
    * **关系:** `VideoFrameCompositor` 的 `SetTransform` 方法用于设置视频帧的变换（例如旋转、镜像）。这些变换通常与 CSS 动画或变换相关联。
    * **举例:** 测试用例的 `SetUp` 方法中，`EXPECT_CALL(*submitter_, SetTransform(Eq(kTestTransform)));` 模拟了当 CSS 中应用了视频变换时，`VideoFrameCompositor` 如何接收并传递这个变换信息。

**逻辑推理，假设输入与输出：**

**假设输入：** 调用 `compositor()->PaintSingleFrame(expected_frame);`

**输出：**
* `compositor()->GetCurrentFrame()` 将返回 `expected_frame`。
* `submitter_->did_receive_frame_count()` 的值会增加 1。

**假设输入：** 调用 `compositor()->Start(this);` (其中 `this` 是实现了 `media::VideoRendererSink::RenderCallback` 的对象)。

**输出：**
* `submitter_->StartRendering()` 方法会被调用。
* 如果之前有当前帧，那么启动后仍然有当前帧。

**涉及用户或者编程常见的使用错误，举例说明：**

1. **忘记调用 `PutCurrentFrame()`:**
   * **错误场景:**  用户调用 `compositor()->GetCurrentFrame()` 获取了当前帧，但是忘记在渲染完成后调用 `compositor()->PutCurrentFrame()`。
   * **后果:** 下次调用 `UpdateCurrentFrame()` 时，`VideoFrameCompositor` 会认为之前的帧没有被处理，从而触发 `OnFrameDropped()` 回调，导致可能丢帧或者性能问题。
   * **测试用例体现:** `VideoRendererSinkFrameDropped` 测试用例模拟了这种情况，验证了在 `GetCurrentFrame()` 后没有 `PutCurrentFrame()` 的情况下，新的帧到达会导致丢帧回调。

2. **误解呈现回调的触发时机:**
   * **错误场景:**  用户期望在每次调用 `PaintSingleFrame()` 后都立即触发通过 `SetOnFramePresentedCallback` 设置的回调。
   * **后果:**  呈现回调通常在帧实际被渲染到屏幕上后触发，而不是在帧被提交给 `VideoFrameCompositor` 时。如果用户基于提交帧的动作来假设回调触发，可能会导致逻辑错误。
   * **测试用例体现:** `MultiplePresentationCallbacks` 测试用例验证了回调是单次的，需要在每次期望触发时重新设置。

3. **不理解后台渲染的机制:**
   * **错误场景:** 用户可能认为只有在调用 `UpdateCurrentFrame()` 时才会请求新的帧，而忽略了后台渲染也会定期请求帧。
   * **后果:**  在启用后台渲染的情况下，即使没有明确的渲染请求，`VideoFrameCompositor` 也会尝试获取新的帧，这可能会导致一些非预期的行为，例如资源消耗增加。
   * **测试用例体现:** `BackgroundRenderTicks` 和 `UpdateCurrentFrameWorksWhenBackgroundRendered` 测试用例演示了后台渲染的触发和行为。

4. **在图形上下文丢失后仍然持有 GPU 帧:**
   * **错误场景:**  用户可能在图形上下文丢失后，仍然持有通过 GPU 资源创建的视频帧。
   * **后果:**  这些帧可能变得无效，导致渲染错误或者崩溃。
   * **测试用例体现:** `OnContextLost` 测试用例验证了在上下文丢失后，`VideoFrameCompositor` 会重置持有 GPU 资源的帧。

总而言之，`video_frame_compositor_unittest.cc` 通过详尽的测试用例，确保 `VideoFrameCompositor` 能够正确地管理和提交视频帧，处理各种状态变化，并与 Chromium 的其他组件（如渲染流水线和 JavaScript API 实现）进行良好的交互。 这些测试对于保证视频播放功能的稳定性和正确性至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/media/video_frame_compositor_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/platform/media/video_frame_compositor.h"

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "components/viz/common/surfaces/frame_sink_id.h"
#include "media/base/video_frame.h"
#include "media/video/fake_gpu_memory_buffer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_video_frame_submitter.h"

namespace blink {

using ::base::test::RunClosure;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::StrictMock;

using RenderingMode = ::media::VideoRendererSink::RenderCallback::RenderingMode;

class MockWebVideoFrameSubmitter : public WebVideoFrameSubmitter {
 public:
  // WebVideoFrameSubmitter implementation.
  void StopUsingProvider() override {}
  MOCK_METHOD1(EnableSubmission, void(viz::SurfaceId));
  MOCK_METHOD0(StartRendering, void());
  MOCK_METHOD0(StopRendering, void());
  MOCK_CONST_METHOD0(IsDrivingFrameUpdates, bool(void));
  MOCK_METHOD2(Initialize, void(cc::VideoFrameProvider*, bool));
  MOCK_METHOD1(SetTransform, void(media::VideoTransformation));
  MOCK_METHOD1(SetIsSurfaceVisible, void(bool));
  MOCK_METHOD1(SetIsPageVisible, void(bool));
  MOCK_METHOD1(SetForceSubmit, void(bool));
  MOCK_METHOD1(SetForceBeginFrames, void(bool));
  void DidReceiveFrame() override { ++did_receive_frame_count_; }

  int did_receive_frame_count() { return did_receive_frame_count_; }

 private:
  int did_receive_frame_count_ = 0;
};

class VideoFrameCompositorTest
    : public media::VideoRendererSink::RenderCallback,
      public testing::Test {
 public:
  VideoFrameCompositorTest() = default;
  VideoFrameCompositorTest(const VideoFrameCompositorTest&) = delete;
  VideoFrameCompositorTest& operator=(const VideoFrameCompositorTest&) = delete;

  void SetUp() override {
    submitter_ = client_.get();

    EXPECT_CALL(*submitter_, Initialize(_, _));
    compositor_ = std::make_unique<VideoFrameCompositor>(task_runner_,
                                                         std::move(client_));
    base::RunLoop().RunUntilIdle();
    constexpr auto kTestTransform = media::VideoTransformation(
        media::VideoRotation::VIDEO_ROTATION_90, /*mirrored=*/false);
    EXPECT_CALL(*submitter_, SetTransform(Eq(kTestTransform)));
    EXPECT_CALL(*submitter_, SetForceSubmit(false));
    EXPECT_CALL(*submitter_, EnableSubmission(Eq(viz::SurfaceId())));
    compositor_->EnableSubmission(viz::SurfaceId(), kTestTransform, false);

    compositor_->set_tick_clock_for_testing(&tick_clock_);
    // Disable background rendering by default.
    compositor_->set_background_rendering_for_testing(false);
  }

  ~VideoFrameCompositorTest() override {
    compositor_->SetVideoFrameProviderClient(nullptr);
  }

  scoped_refptr<media::VideoFrame> CreateOpaqueFrame() {
    return CreateOpaqueFrame(8, 8);
  }

  scoped_refptr<media::VideoFrame> CreateOpaqueFrame(int width, int height) {
    gfx::Size size(width, height);
    return media::VideoFrame::CreateFrame(media::PIXEL_FORMAT_I420, size,
                                          gfx::Rect(size), size,
                                          base::TimeDelta());
  }

  VideoFrameCompositor* compositor() { return compositor_.get(); }

  VideoFrameCompositor::OnNewFramePresentedCB GetNewFramePresentedCB() {
    return base::BindOnce(&VideoFrameCompositorTest::OnNewFramePresented,
                          base::Unretained(this));
  }

 protected:
  // VideoRendererSink::RenderCallback implementation.
  MOCK_METHOD3(Render,
               scoped_refptr<media::VideoFrame>(base::TimeTicks,
                                                base::TimeTicks,
                                                RenderingMode));
  MOCK_METHOD0(OnFrameDropped, void());
  MOCK_METHOD0(OnNewFramePresented, void());

  base::TimeDelta GetPreferredRenderInterval() override {
    return preferred_render_interval_;
  }

  void StartVideoRendererSink() {
    EXPECT_CALL(*submitter_, StartRendering());
    const bool had_current_frame = !!compositor_->GetCurrentFrame();
    compositor()->Start(this);
    // If we previously had a frame, we should still have one now.
    EXPECT_EQ(had_current_frame, !!compositor_->GetCurrentFrame());
    base::RunLoop().RunUntilIdle();
  }

  void StopVideoRendererSink(bool have_client) {
    if (have_client)
      EXPECT_CALL(*submitter_, StopRendering());
    const bool had_current_frame = !!compositor_->GetCurrentFrame();
    compositor()->Stop();
    // If we previously had a frame, we should still have one now.
    EXPECT_EQ(had_current_frame, !!compositor_->GetCurrentFrame());
    base::RunLoop().RunUntilIdle();
  }

  void RenderFrame() {
    compositor()->GetCurrentFrame();
    compositor()->PutCurrentFrame();
  }

  base::test::SingleThreadTaskEnvironment task_environment_;
  base::TimeDelta preferred_render_interval_;
  base::SimpleTestTickClock tick_clock_;
  std::unique_ptr<StrictMock<MockWebVideoFrameSubmitter>> client_ =
      std::make_unique<StrictMock<MockWebVideoFrameSubmitter>>();
  std::unique_ptr<VideoFrameCompositor> compositor_;
  raw_ptr<StrictMock<MockWebVideoFrameSubmitter>> submitter_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_ =
      task_environment_.GetMainThreadTaskRunner();
};

TEST_F(VideoFrameCompositorTest, InitialValues) {
  EXPECT_FALSE(compositor()->GetCurrentFrame().get());
}

TEST_F(VideoFrameCompositorTest, SetIsSurfaceVisible) {
  auto cb = compositor()->GetUpdateSubmissionStateCallback();

  {
    base::RunLoop run_loop;
    EXPECT_CALL(*submitter_, SetIsSurfaceVisible(true));
    cb.Run(true, nullptr);
    task_runner_->PostTask(FROM_HERE, run_loop.QuitClosure());
    run_loop.Run();
  }

  {
    base::RunLoop run_loop;
    EXPECT_CALL(*submitter_, SetIsSurfaceVisible(false));
    cb.Run(false, nullptr);
    task_runner_->PostTask(FROM_HERE, run_loop.QuitClosure());
    run_loop.Run();
  }

  {
    base::RunLoop run_loop;
    base::WaitableEvent true_event;
    EXPECT_CALL(*submitter_, SetIsSurfaceVisible(true));
    cb.Run(true, &true_event);
    task_runner_->PostTask(FROM_HERE, run_loop.QuitClosure());
    run_loop.Run();
    EXPECT_TRUE(true_event.IsSignaled());
  }

  {
    base::RunLoop run_loop;
    base::WaitableEvent false_event;
    EXPECT_CALL(*submitter_, SetIsSurfaceVisible(false));
    cb.Run(false, &false_event);

    task_runner_->PostTask(FROM_HERE, run_loop.QuitClosure());
    run_loop.Run();
    EXPECT_TRUE(false_event.IsSignaled());
  }
}

TEST_F(VideoFrameCompositorTest, SetIsPageVisible) {
  EXPECT_CALL(*submitter_, SetIsPageVisible(true));
  compositor()->SetIsPageVisible(true);

  EXPECT_CALL(*submitter_, SetIsPageVisible(false));
  compositor()->SetIsPageVisible(false);
}

TEST_F(VideoFrameCompositorTest, PaintSingleFrame) {
  scoped_refptr<media::VideoFrame> expected =
      media::VideoFrame::CreateEOSFrame();

  // Should notify compositor synchronously.
  EXPECT_EQ(0, submitter_->did_receive_frame_count());
  compositor()->PaintSingleFrame(expected);
  scoped_refptr<media::VideoFrame> actual = compositor()->GetCurrentFrame();
  EXPECT_EQ(expected, actual);
  EXPECT_EQ(1, submitter_->did_receive_frame_count());
}

TEST_F(VideoFrameCompositorTest, RenderFiresPresentationCallback) {
  // Advance the clock so we can differentiate between base::TimeTicks::Now()
  // and base::TimeTicks().
  tick_clock_.Advance(base::Seconds(1));

  scoped_refptr<media::VideoFrame> opaque_frame = CreateOpaqueFrame();
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kStartup))
      .WillRepeatedly(Return(opaque_frame));
  EXPECT_CALL(*this, OnNewFramePresented());
  EXPECT_CALL(*submitter_, SetForceBeginFrames(true)).Times(AnyNumber());
  compositor()->SetOnFramePresentedCallback(GetNewFramePresentedCB());
  StartVideoRendererSink();
  StopVideoRendererSink(true);

  auto metadata = compositor()->GetLastPresentedFrameMetadata();
  EXPECT_NE(base::TimeTicks(), metadata->presentation_time);
  EXPECT_NE(base::TimeTicks(), metadata->expected_display_time);
}

TEST_F(VideoFrameCompositorTest, PresentationCallbackForcesBeginFrames) {
  // A call to the requestVideoFrameCallback() API should set ForceBeginFrames.
  EXPECT_CALL(*submitter_, SetForceBeginFrames(true));
  compositor()->SetOnFramePresentedCallback(GetNewFramePresentedCB());
  base::RunLoop().RunUntilIdle();

  testing::Mock::VerifyAndClear(submitter_);

  // The flag should be un-set when stop receiving callbacks.
  base::RunLoop run_loop;
  EXPECT_CALL(*submitter_, SetForceBeginFrames(false))
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  run_loop.Run();

  testing::Mock::VerifyAndClear(submitter_);
}

TEST_F(VideoFrameCompositorTest, MultiplePresentationCallbacks) {
  // Advance the clock so we can differentiate between base::TimeTicks::Now()
  // and base::TimeTicks().
  tick_clock_.Advance(base::Seconds(1));

  // Create frames of different sizes so we can differentiate them.
  constexpr int kSize1 = 8;
  constexpr int kSize2 = 16;
  constexpr int kSize3 = 24;
  scoped_refptr<media::VideoFrame> opaque_frame_1 =
      CreateOpaqueFrame(kSize1, kSize1);
  scoped_refptr<media::VideoFrame> opaque_frame_2 =
      CreateOpaqueFrame(kSize2, kSize2);
  scoped_refptr<media::VideoFrame> opaque_frame_3 =
      CreateOpaqueFrame(kSize3, kSize3);

  EXPECT_CALL(*this, OnNewFramePresented()).Times(1);
  EXPECT_CALL(*submitter_, SetForceBeginFrames(_)).Times(AnyNumber());
  compositor()->SetOnFramePresentedCallback(GetNewFramePresentedCB());
  compositor()->PaintSingleFrame(opaque_frame_1);

  auto metadata = compositor()->GetLastPresentedFrameMetadata();
  EXPECT_EQ(metadata->width, kSize1);
  uint32_t first_presented_frames = metadata->presented_frames;

  // Callbacks are one-shot, and shouldn't fire if they are not re-queued.
  EXPECT_CALL(*this, OnNewFramePresented()).Times(0);
  compositor()->PaintSingleFrame(opaque_frame_2);

  // We should get the 2nd frame's metadata when we query for it.
  metadata = compositor()->GetLastPresentedFrameMetadata();
  EXPECT_EQ(first_presented_frames + 1, metadata->presented_frames);
  EXPECT_EQ(metadata->width, kSize2);

  EXPECT_CALL(*this, OnNewFramePresented()).Times(1);
  compositor()->SetOnFramePresentedCallback(GetNewFramePresentedCB());
  compositor()->PaintSingleFrame(opaque_frame_3);

  // The presentated frames counter should have gone up twice by now.
  metadata = compositor()->GetLastPresentedFrameMetadata();
  EXPECT_EQ(first_presented_frames + 2, metadata->presented_frames);
  EXPECT_EQ(metadata->width, kSize3);
}

TEST_F(VideoFrameCompositorTest, VideoRendererSinkFrameDropped) {
  scoped_refptr<media::VideoFrame> opaque_frame = CreateOpaqueFrame();

  EXPECT_CALL(*this, Render(_, _, _)).WillRepeatedly(Return(opaque_frame));
  StartVideoRendererSink();

  EXPECT_TRUE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  // Another call should trigger a dropped frame callback.
  EXPECT_CALL(*this, OnFrameDropped());
  EXPECT_FALSE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  // Ensure it always happens until the frame is rendered.
  EXPECT_CALL(*this, OnFrameDropped());
  EXPECT_FALSE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  // Call GetCurrentFrame() but not PutCurrentFrame()
  compositor()->GetCurrentFrame();

  // The frame should still register as dropped until PutCurrentFrame is called.
  EXPECT_CALL(*this, OnFrameDropped());
  EXPECT_FALSE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  RenderFrame();
  EXPECT_FALSE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  StopVideoRendererSink(true);
}

TEST_F(VideoFrameCompositorTest, VideoRendererSinkGetCurrentFrameNoDrops) {
  scoped_refptr<media::VideoFrame> opaque_frame = CreateOpaqueFrame();

  EXPECT_CALL(*this, Render(_, _, _)).WillRepeatedly(Return(opaque_frame));
  StartVideoRendererSink();

  EXPECT_TRUE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  auto frame = compositor()->GetCurrentFrameOnAnyThread();
  EXPECT_FALSE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  StopVideoRendererSink(true);
}

TEST_F(VideoFrameCompositorTest, StartFiresBackgroundRender) {
  scoped_refptr<media::VideoFrame> opaque_frame = CreateOpaqueFrame();
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kStartup))
      .WillRepeatedly(Return(opaque_frame));
  StartVideoRendererSink();
  StopVideoRendererSink(true);
}

TEST_F(VideoFrameCompositorTest, BackgroundRenderTicks) {
  scoped_refptr<media::VideoFrame> opaque_frame = CreateOpaqueFrame();
  compositor_->set_background_rendering_for_testing(true);

  base::RunLoop run_loop;
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kStartup))
      .WillOnce(Return(opaque_frame));
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kBackground))
      .WillOnce(
          DoAll(RunClosure(run_loop.QuitClosure()), Return(opaque_frame)));
  StartVideoRendererSink();
  run_loop.Run();

  // UpdateCurrentFrame() calls should indicate they are not synthetic.
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kNormal))
      .WillOnce(Return(opaque_frame));
  EXPECT_FALSE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  // Background rendering should tick another render callback.
  StopVideoRendererSink(true);
}

TEST_F(VideoFrameCompositorTest,
       UpdateCurrentFrameWorksWhenBackgroundRendered) {
  scoped_refptr<media::VideoFrame> opaque_frame = CreateOpaqueFrame();
  compositor_->set_background_rendering_for_testing(true);

  // Background render a frame that succeeds immediately.
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kStartup))
      .WillOnce(Return(opaque_frame));
  StartVideoRendererSink();

  // The background render completes immediately, so the next call to
  // UpdateCurrentFrame is expected to return true to account for the frame
  // rendered in the background.
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kNormal))
      .WillOnce(Return(scoped_refptr<media::VideoFrame>(opaque_frame)));
  EXPECT_TRUE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));
  RenderFrame();

  // Second call to UpdateCurrentFrame will return false as no new frame has
  // been created since the last call.
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kNormal))
      .WillOnce(Return(scoped_refptr<media::VideoFrame>(opaque_frame)));
  EXPECT_FALSE(
      compositor()->UpdateCurrentFrame(base::TimeTicks(), base::TimeTicks()));

  StopVideoRendererSink(true);
}

TEST_F(VideoFrameCompositorTest, UpdateCurrentFrameIfStale) {
  scoped_refptr<media::VideoFrame> opaque_frame_1 = CreateOpaqueFrame();
  scoped_refptr<media::VideoFrame> opaque_frame_2 = CreateOpaqueFrame();
  compositor_->set_background_rendering_for_testing(true);

  EXPECT_CALL(*submitter_, IsDrivingFrameUpdates)
      .Times(AnyNumber())
      .WillRepeatedly(Return(true));

  // Starting the video renderer should return a single frame.
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kStartup))
      .WillOnce(Return(opaque_frame_1));
  StartVideoRendererSink();
  EXPECT_EQ(opaque_frame_1, compositor()->GetCurrentFrame());

  // Since we have a client, this call should not call background render, even
  // if a lot of time has elapsed between calls.
  tick_clock_.Advance(base::Seconds(1));
  EXPECT_CALL(*this, Render(_, _, _)).Times(0);
  compositor()->UpdateCurrentFrameIfStale();

  // Have the client signal that it will not drive the frame clock, so that
  // calling UpdateCurrentFrameIfStale may update the frame.
  EXPECT_CALL(*submitter_, IsDrivingFrameUpdates)
      .Times(AnyNumber())
      .WillRepeatedly(Return(false));

  // Wait for background rendering to tick.
  base::RunLoop run_loop;
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kBackground))
      .WillOnce(
          DoAll(RunClosure(run_loop.QuitClosure()), Return(opaque_frame_2)));
  run_loop.Run();

  // This call should still not call background render, because not enough time
  // has elapsed since the last background render call.
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kBackground)).Times(0);
  compositor()->UpdateCurrentFrameIfStale();
  EXPECT_EQ(opaque_frame_2, compositor()->GetCurrentFrame());

  // Advancing the tick clock should allow a new frame to be requested.
  tick_clock_.Advance(base::Milliseconds(10));
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kBackground))
      .WillOnce(Return(opaque_frame_1));
  compositor()->UpdateCurrentFrameIfStale();
  EXPECT_EQ(opaque_frame_1, compositor()->GetCurrentFrame());

  // Clear our client, which means no mock function calls for Client.  It will
  // also permit UpdateCurrentFrameIfStale to update the frame.
  compositor()->SetVideoFrameProviderClient(nullptr);

  // Advancing the tick clock should allow a new frame to be requested.
  tick_clock_.Advance(base::Milliseconds(10));
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kBackground))
      .WillOnce(Return(opaque_frame_2));
  compositor()->UpdateCurrentFrameIfStale();
  EXPECT_EQ(opaque_frame_2, compositor()->GetCurrentFrame());

  // Background rendering should tick another render callback.
  StopVideoRendererSink(false);
}

TEST_F(VideoFrameCompositorTest, UpdateCurrentFrameIfStale_ClientBypass) {
  scoped_refptr<media::VideoFrame> opaque_frame_1 = CreateOpaqueFrame();
  scoped_refptr<media::VideoFrame> opaque_frame_2 = CreateOpaqueFrame();
  compositor_->set_background_rendering_for_testing(true);

  EXPECT_CALL(*submitter_, IsDrivingFrameUpdates)
      .Times(AnyNumber())
      .WillRepeatedly(Return(true));

  // Move the clock forward. Otherwise, the current time will be 0, will appear
  // null, and will cause DCHECKs.
  tick_clock_.Advance(base::Seconds(1));

  // Starting the video renderer should return a single frame.
  EXPECT_CALL(*this, Render(_, _, RenderingMode::kStartup))
      .WillOnce(Return(opaque_frame_1));
  StartVideoRendererSink();
  EXPECT_EQ(opaque_frame_1, compositor()->GetCurrentFrame());

  // This call should return true even if we have a client that is driving frame
  // updates.
  tick_clock_.Advance(base::Seconds(1));
  EXPECT_CALL(*this, Render(_, _, _)).WillOnce(Return(opaque_frame_2));
  compositor()->UpdateCurrentFrameIfStale(
      VideoFrameCompositor::UpdateType::kBypassClient);
  EXPECT_EQ(opaque_frame_2, compositor()->GetCurrentFrame());

  StopVideoRendererSink(true);
}

TEST_F(VideoFrameCompositorTest, PreferredRenderInterval) {
  preferred_render_interval_ = base::Seconds(1);
  compositor_->Start(this);
  EXPECT_EQ(compositor_->GetPreferredRenderInterval(),
            preferred_render_interval_);
  compositor_->Stop();
  EXPECT_EQ(compositor_->GetPreferredRenderInterval(),
            viz::BeginFrameArgs::MinInterval());
}

TEST_F(VideoFrameCompositorTest, OnContextLost) {
  scoped_refptr<media::VideoFrame> non_gpu_frame = CreateOpaqueFrame();

  gfx::Size encode_size(320, 240);
  std::unique_ptr<gfx::GpuMemoryBuffer> gmb =
      std::make_unique<media::FakeGpuMemoryBuffer>(
          encode_size, gfx::BufferFormat::YUV_420_BIPLANAR);
  scoped_refptr<media::VideoFrame> gpu_frame =
      media::VideoFrame::WrapExternalGpuMemoryBuffer(
          gfx::Rect(encode_size), encode_size, std::move(gmb),
          base::TimeDelta());

  compositor_->set_background_rendering_for_testing(true);

  EXPECT_CALL(*submitter_, IsDrivingFrameUpdates)
      .Times(AnyNumber())
      .WillRepeatedly(Return(true));

  // Move the clock forward. Otherwise, the current time will be 0, will appear
  // null, and will cause DCHECKs.
  tick_clock_.Advance(base::Seconds(1));

  EXPECT_CALL(*this, Render(_, _, RenderingMode::kStartup))
      .WillOnce(Return(non_gpu_frame));
  StartVideoRendererSink();
  compositor()->OnContextLost();
  // frame which dose not have gpu resource should be maintained even though
  // context is lost.
  EXPECT_EQ(non_gpu_frame, compositor()->GetCurrentFrame());

  tick_clock_.Advance(base::Seconds(1));
  EXPECT_CALL(*this, Render(_, _, _)).WillOnce(Return(gpu_frame));
  compositor()->UpdateCurrentFrameIfStale(
      VideoFrameCompositor::UpdateType::kBypassClient);
  compositor()->OnContextLost();
  // frame which has gpu resource should be reset if context is lost
  EXPECT_NE(gpu_frame, compositor()->GetCurrentFrame());

  StopVideoRendererSink(true);
}

}  // namespace blink

"""

```