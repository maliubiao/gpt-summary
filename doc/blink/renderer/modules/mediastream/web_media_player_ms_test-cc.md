Response:
The user wants to understand the functionality of the provided C++ source code file `web_media_player_ms_test.cc`. I need to analyze the code and identify its purpose, focusing on:

1. **Core Functionality:** What does this code do? What components does it interact with?
2. **Relationship to Web Technologies:** Does it relate to JavaScript, HTML, or CSS? How?
3. **Logical Reasoning:** Are there any test scenarios or logical checks implemented?
4. **Common Usage Errors:** What mistakes might a user or programmer make when dealing with the functionality tested here?
5. **User Journey (Debugging Context):** How might a user's actions lead to this code being involved during debugging?
6. **Summary of Functionality (Part 1):** Based on the first section of the code, what is its primary purpose?

**Analysis of the Code Snippet:**

*   The file name `web_media_player_ms_test.cc` strongly suggests that this is a unit test file for `WebMediaPlayerMS`.
*   It includes headers related to media, testing, and the Blink rendering engine.
*   It defines mock classes (`MockSurfaceLayerBridge`, `FakeWebMediaPlayerDelegate`, `MockMediaStreamVideoRenderer`, `MockMediaStreamAudioRenderer`, `MockWebVideoFrameSubmitter`, `MockRenderFactory`) to simulate dependencies and control their behavior during testing.
*   It sets up a testing environment using `base::test::TaskEnvironment`.
*   It defines a `WebMediaPlayerMSTest` class, which seems to be the main test fixture.
*   The tests likely involve simulating the loading and playback of media streams (`MediaStream`) within the Blink rendering engine, specifically focusing on `WebMediaPlayerMS`.
*   The use of `FrameType` enum and the `MockMediaStreamVideoRenderer` suggests testing the rendering of video frames.
*   The interactions with `cc::Layer` and `WebSurfaceLayerBridge` indicate involvement in the compositing process.
```
这是目录为blink/renderer/modules/mediastream/web_media_player_ms_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

**功能列举:**

1. **单元测试:** 该文件是 Chromium Blink 引擎中 `WebMediaPlayerMS` 类的单元测试文件。它的主要功能是测试 `WebMediaPlayerMS` 的各种功能和行为是否符合预期。
2. **模拟媒体流渲染:**  它创建并使用了模拟的媒体流视频渲染器 (`MockMediaStreamVideoRenderer`) 和音频渲染器 (`MockMediaStreamAudioRenderer`)，用于向 `WebMediaPlayerMS` 提供模拟的视频和音频帧数据，以便在测试环境中验证播放器的行为。
3. **模拟 WebMediaPlayerDelegate:**  它使用 `FakeWebMediaPlayerDelegate` 模拟了 `WebMediaPlayerDelegate` 接口，该接口用于 `WebMediaPlayerMS` 与其上层进行通信，例如通知播放状态变化。
4. **模拟 SurfaceLayerBridge:**  它使用了 `MockSurfaceLayerBridge` 模拟了 `WebSurfaceLayerBridge` 接口，用于测试在合成线程中处理视频帧的方式，特别是涉及到 SurfaceLayer 的情况。
5. **模拟 VideoFrame 提交器:**  它使用了 `MockWebVideoFrameSubmitter` 模拟了视频帧的提交过程，用于测试 `WebMediaPlayerMS` 如何将渲染的帧提交到合成器。
6. **测试视频帧处理:**  代码中包含了生成和注入不同类型的视频帧（正常帧、损坏帧、测试中断信号帧）的逻辑，用于测试 `WebMediaPlayerMS` 在不同帧状态下的处理能力。
7. **测试播放器状态管理:**  测试用例会模拟播放、暂停等操作，并验证 `WebMediaPlayerMS` 的状态变化是否正确，例如 `ReadyState` 和 `NetworkState` 的变化。
8. **测试合成层集成:**  通过 `SetCcLayer` 方法和 `MockSurfaceLayerBridge`，测试 `WebMediaPlayerMS` 如何与合成层 (`cc::Layer`) 集成，以进行视频渲染。
9. **异步操作测试:**  使用了 `base::RunLoop` 和 `ReusableMessageLoopEvent` 来处理和同步异步操作，确保测试的可靠性。

**与 JavaScript, HTML, CSS 的关系 (举例说明):**

虽然这个 C++ 文件本身不直接包含 JavaScript, HTML, 或 CSS 代码，但它测试的 `WebMediaPlayerMS` 类是 Web 平台媒体播放功能的核心实现部分，与这些技术密切相关：

*   **HTML `<video>` 元素:**  `WebMediaPlayerMS` 是 `<video>` 元素在 Blink 渲染引擎中的底层实现之一。当 JavaScript 代码创建一个 `<video>` 元素并设置其 `src` 属性为媒体流 URL 时，Blink 可能会创建 `WebMediaPlayerMS` 的实例来处理该媒体流。
    *   **举例:**  HTML 代码 `<video id="myVideo"></video>`，JavaScript 代码 `document.getElementById('myVideo').srcObject = myMediaStream;`，这个操作最终会导致 `WebMediaPlayerMS` 被创建并开始处理 `myMediaStream`。
*   **JavaScript MediaStream API:**  `WebMediaPlayerMS` 专门用于处理通过 JavaScript 的 `MediaStream API` 获取的媒体流数据。测试中的 `MockMediaStreamVideoRenderer` 模拟了从 `MediaStream` 中获取视频帧的过程。
    *   **举例:** JavaScript 代码使用 `navigator.mediaDevices.getUserMedia()` 获取用户摄像头和麦克风的流，并将此流赋值给 `<video>` 元素的 `srcObject` 属性。
*   **CSS 控制:** 虽然这个测试不直接测试 CSS，但 CSS 样式可以影响 `<video>` 元素的显示大小、位置等。`WebMediaPlayerMS` 需要与渲染流程配合，确保视频内容在 CSS 指定的区域内正确渲染。
    *   **举例:**  CSS 规则 `video { width: 640px; height: 480px; }` 会影响 `<video>` 元素的显示尺寸，`WebMediaPlayerMS` 需要根据这些尺寸调整视频帧的渲染。

**逻辑推理 (假设输入与输出):**

*   **假设输入:**  `MockMediaStreamVideoRenderer` 被配置为生成一系列包含时间戳 `0, 33, 66` 的正常视频帧，然后是一个 `TEST_BRAKE` 信号帧。
*   **逻辑推理:**  测试代码会调用 `player_->Play()`，然后 `MockMediaStreamVideoRenderer` 会按照配置的时间间隔注入视频帧。当 `WebMediaPlayerMS` 接收到第一帧时，它会触发 `SizeChanged` 事件，并将视频的自然尺寸设置为模拟帧的尺寸。当接收到 `TEST_BRAKE` 帧时，消息循环会暂停，允许测试代码进行断言或执行其他操作。
*   **预期输出:**  `ReadyStateChanged` 事件会被触发，状态变为 `kReadyStateHaveMetadata` 和 `kReadyStateHaveEnoughData`。 `SizeChanged` 回调函数会被调用，并且传递的尺寸与模拟帧的尺寸一致。

**用户或编程常见的使用错误 (举例说明):**

*   **用户错误:**
    *   **未正确设置 `srcObject`:** 用户可能忘记将 `MediaStream` 对象赋值给 `<video>` 元素的 `srcObject` 属性，导致 `WebMediaPlayerMS` 无法获取到视频数据，播放器状态停留在 `kReadyStateHaveNothing`。
    *   **网络问题:**  虽然这个测试模拟的是本地的 `MediaStream`，但在实际应用中，如果用户尝试播放来自网络的媒体流，但网络连接不稳定，可能会导致 `NetworkStateChanged` 事件触发，状态变为 `kNetworkStateNetworkError`。
*   **编程错误:**
    *   **过早调用播放控制方法:**  开发者可能在 `MediaStream` 尚未准备好之前就调用了 `video.play()`，这可能会导致播放失败或出现未定义的行为。测试中通过模拟不同的 ReadyState 来验证播放器的状态管理。
    *   **未处理播放错误:** 开发者可能没有正确监听和处理 `error` 事件，当 `WebMediaPlayerMS` 因为解码错误或其他原因进入错误状态时，用户界面可能无法提供有用的反馈。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个包含 `<video>` 元素的网页:**  用户在浏览器中打开了一个使用了 `<video>` 标签的网页。
2. **JavaScript 代码获取或创建 `MediaStream`:**  网页上的 JavaScript 代码可能使用 `navigator.mediaDevices.getUserMedia()` 获取了用户的摄像头或麦克风流，或者从其他来源创建了一个 `MediaStream` 对象。
3. **将 `MediaStream` 赋值给 `<video>` 元素:**  JavaScript 代码将获取到的 `MediaStream` 对象赋值给 `<video>` 元素的 `srcObject` 属性。例如：`document.getElementById('myVideo').srcObject = myStream;`
4. **Blink 创建 `WebMediaPlayerMS`:**  当 Blink 渲染引擎检测到 `<video>` 元素的 `srcObject` 被设置为 `MediaStream` 时，会创建一个 `WebMediaPlayerMS` 的实例来处理这个媒体流。
5. **调试器断点命中:**  如果开发者在调试 `WebMediaPlayerMS` 相关问题，可能会在 `blink/renderer/modules/mediastream/web_media_player_ms.cc` 文件中的某个函数（例如 `Load`、`Play`、`OnReceivedVideoFrame` 等）设置断点。当用户进行上述操作导致 `WebMediaPlayerMS` 的代码被执行时，断点就会被命中。
6. **查看调用堆栈:**  通过调试器的调用堆栈，开发者可以回溯到导致 `WebMediaPlayerMS` 代码执行的用户操作和 JavaScript 代码。

**功能归纳 (第 1 部分):**

这部分代码主要定义了用于测试 `WebMediaPlayerMS` 核心功能的框架和基础组件。它创建了各种模拟对象，如媒体流渲染器、委托对象和合成层桥接器，以便在隔离的环境中验证 `WebMediaPlayerMS` 在处理媒体流时的行为，包括状态管理、视频帧处理和与合成层的交互。 重点在于搭建测试环境，为后续的更具体的测试用例提供基础。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/web_media_player_ms_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/web/modules/mediastream/web_media_player_ms.h"

#include <stddef.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/containers/circular_deque.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/gmock_callback_support.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/layers/layer.h"
#include "media/base/media_content_type.h"
#include "media/base/media_util.h"
#include "media/base/test_helpers.h"
#include "media/base/video_frame.h"
#include "media/video/fake_gpu_memory_buffer.h"
#include "media/video/mock_gpu_memory_buffer_video_frame_pool.h"
#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "third_party/blink/public/common/media/display_type.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_fullscreen_video_status.h"
#include "third_party/blink/public/platform/web_media_player.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_audio_renderer.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_renderer_factory.h"
#include "third_party/blink/renderer/modules/mediastream/web_media_player_ms_compositor.h"
#include "third_party/blink/renderer/platform/media/media_player_client.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using ::testing::_;
using ::testing::ByRef;
using ::testing::Eq;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SaveArg;
using ::testing::StrictMock;
using ::testing::WithArgs;

namespace blink {

enum class FrameType {
  NORMAL_FRAME = 0,
  BROKEN_FRAME = -1,
  TEST_BRAKE = -2,  // Signal to pause message loop.
  MIN_TYPE = TEST_BRAKE
};

class MockSurfaceLayerBridge : public WebSurfaceLayerBridge {
 public:
  MockSurfaceLayerBridge() {
    ON_CALL(*this, GetSurfaceId).WillByDefault(ReturnRef(surface_id_));
  }

  MOCK_CONST_METHOD0(GetCcLayer, cc::Layer*());
  MOCK_CONST_METHOD0(GetFrameSinkId, const viz::FrameSinkId&());
  MOCK_CONST_METHOD0(GetSurfaceId, const viz::SurfaceId&());
  MOCK_METHOD1(SetContentsOpaque, void(bool));
  MOCK_METHOD0(CreateSurfaceLayer, void());
  MOCK_METHOD0(ClearSurfaceId, void());
  MOCK_METHOD0(ClearObserver, void());
  MOCK_METHOD0(RegisterFrameSinkHierarchy, void());
  MOCK_METHOD0(UnregisterFrameSinkHierarchy, void());

  viz::FrameSinkId frame_sink_id_ = viz::FrameSinkId(1, 1);
  viz::LocalSurfaceId local_surface_id_ = viz::LocalSurfaceId(
      11,
      base::UnguessableToken::CreateForTesting(0x111111, 0));
  viz::SurfaceId surface_id_ =
      viz::SurfaceId(frame_sink_id_, local_surface_id_);
};

using TestFrame = std::pair<FrameType, scoped_refptr<media::VideoFrame>>;

static const int kOddSizeOffset = 3;
static const int kStandardWidth = 320;
static const int kStandardHeight = 240;

class FakeWebMediaPlayerDelegate : public WebMediaPlayerDelegate {
 public:
  FakeWebMediaPlayerDelegate() {}

  FakeWebMediaPlayerDelegate(const FakeWebMediaPlayerDelegate&) = delete;
  FakeWebMediaPlayerDelegate& operator=(const FakeWebMediaPlayerDelegate&) =
      delete;

  ~FakeWebMediaPlayerDelegate() override {
    DCHECK(!observer_);
    DCHECK(is_gone_);
  }

  int AddObserver(Observer* observer) override {
    observer_ = observer;
    return delegate_id_;
  }

  void RemoveObserver(int delegate_id) override {
    EXPECT_EQ(delegate_id_, delegate_id);
    observer_ = nullptr;
  }

  void DidMediaMetadataChange(int delegate_id,
                              bool has_audio,
                              bool has_video,
                              media::MediaContentType type) override {
    EXPECT_EQ(delegate_id_, delegate_id);
  }

  void DidPlay(int delegate_id) override {
    EXPECT_EQ(delegate_id_, delegate_id);
    is_gone_ = false;
  }

  void DidPause(int delegate_id, bool reached_end_of_stream) override {
    EXPECT_EQ(delegate_id_, delegate_id);
    EXPECT_FALSE(reached_end_of_stream);
    EXPECT_FALSE(is_gone_);
  }

  void PlayerGone(int delegate_id) override {
    EXPECT_EQ(delegate_id_, delegate_id);
    is_gone_ = true;
  }

  void SetIdle(int delegate_id, bool is_idle) override {
    EXPECT_EQ(delegate_id_, delegate_id);
    is_idle_ = is_idle;
  }

  bool IsIdle(int delegate_id) override {
    EXPECT_EQ(delegate_id_, delegate_id);
    return is_idle_;
  }

  void ClearStaleFlag(int delegate_id) override {
    EXPECT_EQ(delegate_id_, delegate_id);
  }

  bool IsStale(int delegate_id) override {
    EXPECT_EQ(delegate_id_, delegate_id);
    return false;
  }

  bool IsPageHidden() override { return is_page_hidden_; }

  bool IsFrameHidden() override { return false; }

  void set_page_hidden(bool is_page_hidden) {
    is_page_hidden_ = is_page_hidden;
  }

  int delegate_id() { return delegate_id_; }

 private:
  int delegate_id_ = 1234;
  raw_ptr<Observer> observer_ = nullptr;
  bool is_page_hidden_ = false;
  bool is_gone_ = true;
  bool is_idle_ = false;
};

class ReusableMessageLoopEvent {
 public:
  ReusableMessageLoopEvent() : event_(new media::WaitableMessageLoopEvent()) {}

  base::OnceClosure GetClosure() const { return event_->GetClosure(); }

  media::PipelineStatusCallback GetPipelineStatusCB() const {
    return event_->GetPipelineStatusCB();
  }

  void RunAndWait() {
    event_->RunAndWait();
    event_ = std::make_unique<media::WaitableMessageLoopEvent>();
  }

  void RunAndWaitForStatus(media::PipelineStatus expected) {
    event_->RunAndWaitForStatus(expected);
    event_ = std::make_unique<media::WaitableMessageLoopEvent>();
  }

 private:
  std::unique_ptr<media::WaitableMessageLoopEvent> event_;
};

// The class is used mainly to inject VideoFrames into WebMediaPlayerMS.
class MockMediaStreamVideoRenderer : public MediaStreamVideoRenderer {
 public:
  MockMediaStreamVideoRenderer(
      const scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      ReusableMessageLoopEvent* message_loop_controller,
      const MediaStreamVideoRenderer::RepaintCB& repaint_cb,
      raw_ptr<base::test::TaskEnvironment> task_environment)
      : started_(false),
        standard_size_(kStandardWidth, kStandardHeight),
        task_runner_(task_runner),
        message_loop_controller_(message_loop_controller),
        repaint_cb_(repaint_cb),
        delay_till_next_generated_frame_(base::Seconds(1.0 / 30.0)),
        task_environment_(task_environment) {}

  // Implementation of MediaStreamVideoRenderer
  void Start() override;
  void Stop() override;
  void Resume() override;
  void Pause() override;

  // Methods for test use
  void QueueFrames(const Vector<int>& timestamps_or_frame_type,
                   bool opaque_frame = true,
                   bool odd_size_frame = false,
                   int double_size_index = -1,
                   media::VideoRotation rotation = media::VIDEO_ROTATION_0);
  bool Started() { return started_; }
  bool Paused() { return paused_; }

  void set_standard_size(const gfx::Size& size) { standard_size_ = size; }
  const gfx::Size& get_standard_size() { return standard_size_; }

  // Main function that pushes a frame into WebMediaPlayerMS
  void InjectFrame();

 private:
  ~MockMediaStreamVideoRenderer() override = default;

  // Methods for test use
  void AddFrame(FrameType category, scoped_refptr<media::VideoFrame> frame);

  bool started_;
  bool paused_;
  gfx::Size standard_size_;

  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  const raw_ptr<ReusableMessageLoopEvent, DanglingUntriaged>
      message_loop_controller_;
  const MediaStreamVideoRenderer::RepaintCB repaint_cb_;

  base::circular_deque<TestFrame> frames_;
  base::TimeDelta delay_till_next_generated_frame_;
  // Used for computing the display time for frames.
  raw_ptr<base::test::TaskEnvironment> task_environment_;
};

class MockMediaStreamAudioRenderer : public MediaStreamAudioRenderer {
 public:
  MockMediaStreamAudioRenderer() {}

  void Start() override {}
  void Stop() override {}
  void Play() override {}
  void Pause() override {}
  void SetVolume(float volume) override {}

  void SwitchOutputDevice(const std::string& device_id,
                          media::OutputDeviceStatusCB callback) override {}
  base::TimeDelta GetCurrentRenderTime() override { return base::TimeDelta(); }

 protected:
  ~MockMediaStreamAudioRenderer() override {}
};

void MockMediaStreamVideoRenderer::Start() {
  started_ = true;
  paused_ = false;
  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&MockMediaStreamVideoRenderer::InjectFrame,
                          WrapRefCounted(this)));
}

void MockMediaStreamVideoRenderer::Stop() {
  started_ = false;
  frames_.clear();
}

void MockMediaStreamVideoRenderer::Resume() {
  CHECK(started_);
  paused_ = false;
}

void MockMediaStreamVideoRenderer::Pause() {
  CHECK(started_);
  paused_ = true;
}

void MockMediaStreamVideoRenderer::AddFrame(
    FrameType category,
    scoped_refptr<media::VideoFrame> frame) {
  frames_.push_back(std::make_pair(category, std::move(frame)));
}

void MockMediaStreamVideoRenderer::QueueFrames(
    const Vector<int>& timestamp_or_frame_type,
    bool opaque_frame,
    bool odd_size_frame,
    int double_size_index,
    media::VideoRotation rotation) {
  gfx::Size standard_size = standard_size_;
  // Advance the tick clock by 100 milliseconds at the start of QueueFrames.
  task_environment_->AdvanceClock(base::Milliseconds(100));
  for (wtf_size_t i = 0; i < timestamp_or_frame_type.size(); i++) {
    // Advance the tick clock by 10 milliseconds for each frame.
    task_environment_->AdvanceClock(base::Milliseconds(10));
    const int token = timestamp_or_frame_type[i];
    if (static_cast<int>(i) == double_size_index) {
      standard_size =
          gfx::Size(standard_size_.width() * 2, standard_size_.height() * 2);
    }
    if (token < static_cast<int>(FrameType::MIN_TYPE)) {
      CHECK(false) << "Unrecognized frame type: " << token;
      return;
    }

    if (token < 0) {
      AddFrame(static_cast<FrameType>(token), nullptr);
      continue;
    }

    if (token >= 0) {
      gfx::Size frame_size;
      if (odd_size_frame) {
        frame_size.SetSize(standard_size.width() - kOddSizeOffset,
                           standard_size.height() - kOddSizeOffset);
      } else {
        frame_size.SetSize(standard_size.width(), standard_size.height());
      }

      auto frame = media::VideoFrame::CreateZeroInitializedFrame(
          opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
          frame_size, gfx::Rect(frame_size), frame_size,
          base::Milliseconds(token));

      // MediaStreamRemoteVideoSource does not explicitly set the rotation
      // for unrotated frames, so that is not done here either.
      if (rotation != media::VIDEO_ROTATION_0)
        frame->metadata().transformation = rotation;

      frame->metadata().reference_time =
          base::TimeTicks::Now() + base::Milliseconds(token);

      AddFrame(FrameType::NORMAL_FRAME, frame);
      continue;
    }
  }
}

void MockMediaStreamVideoRenderer::InjectFrame() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (!started_)
    return;

  if (frames_.empty()) {
    message_loop_controller_->GetClosure().Run();
    return;
  }

  auto frame = frames_.front();
  frames_.pop_front();

  if (frame.first == FrameType::BROKEN_FRAME)
    return;

  // For pause case, the provider will still let the stream continue, but
  // not send the frames to the player. As is the same case in reality.
  if (frame.first == FrameType::NORMAL_FRAME) {
    if (!paused_)
      repaint_cb_.Run(frame.second);

    for (size_t i = 0; i < frames_.size(); ++i) {
      if (frames_[i].first == FrameType::NORMAL_FRAME) {
        delay_till_next_generated_frame_ =
            (frames_[i].second->timestamp() - frame.second->timestamp()) /
            (i + 1);
        break;
      }
    }
  }

  PostDelayedCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&MockMediaStreamVideoRenderer::InjectFrame,
                          WrapRefCounted(this)),
      delay_till_next_generated_frame_);

  // This will pause the |message_loop_|, and the purpose is to allow the main
  // test function to do some operations (e.g. call pause(), switch to
  // background rendering, etc) on WebMediaPlayerMS before resuming
  // |message_loop_|.
  if (frame.first == FrameType::TEST_BRAKE)
    message_loop_controller_->GetClosure().Run();
}

class MockWebVideoFrameSubmitter : public WebVideoFrameSubmitter {
 public:
  // WebVideoFrameSubmitter implementation.
  MOCK_METHOD0(StopUsingProvider, void());
  MOCK_METHOD0(DidReceiveFrame, void());
  MOCK_METHOD1(EnableSubmission, void(viz::SurfaceId));
  MOCK_METHOD0(StartRendering, void());
  MOCK_METHOD0(StopRendering, void());
  MOCK_METHOD1(MockInitialize, void(cc::VideoFrameProvider*));
  MOCK_METHOD1(SetTransform, void(media::VideoTransformation));
  MOCK_METHOD1(SetIsSurfaceVisible, void(bool));
  MOCK_METHOD1(SetIsPageVisible, void(bool));
  MOCK_METHOD1(SetForceSubmit, void(bool));
  MOCK_METHOD1(SetForceBeginFrames, void(bool));
  MOCK_CONST_METHOD0(IsDrivingFrameUpdates, bool());

  void Initialize(cc::VideoFrameProvider* provider,
                  bool is_media_stream) override {
    provider_ = provider;
    MockInitialize(provider);
  }

 private:
  raw_ptr<cc::VideoFrameProvider> provider_;
};

// The class is used to generate a MockVideoProvider in
// WebMediaPlayerMS::load().
class MockRenderFactory : public MediaStreamRendererFactory {
 public:
  MockRenderFactory(
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
      ReusableMessageLoopEvent* message_loop_controller,
      raw_ptr<base::test::TaskEnvironment> task_environment)
      : task_runner_(task_runner),
        message_loop_controller_(message_loop_controller),
        task_environment_(task_environment) {}

  scoped_refptr<MediaStreamVideoRenderer> GetVideoRenderer(
      const WebMediaStream& web_stream,
      const MediaStreamVideoRenderer::RepaintCB& repaint_cb,
      scoped_refptr<base::SequencedTaskRunner> video_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> main_render_task_runner)
      override;

  MockMediaStreamVideoRenderer* provider() {
    return static_cast<MockMediaStreamVideoRenderer*>(provider_.get());
  }

  scoped_refptr<MediaStreamAudioRenderer> GetAudioRenderer(
      const WebMediaStream& web_stream,
      WebLocalFrame* web_frame,
      const WebString& device_id,
      base::RepeatingCallback<void()> on_render_error_callback) override {
    return audio_renderer_;
  }

  void set_audio_renderer(scoped_refptr<MediaStreamAudioRenderer> renderer) {
    audio_renderer_ = std::move(renderer);
  }

  void set_support_video_renderer(bool support) {
    DCHECK(!provider_);
    support_video_renderer_ = support;
  }

  bool support_video_renderer() const { return support_video_renderer_; }

 private:
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<MediaStreamVideoRenderer> provider_;
  const raw_ptr<ReusableMessageLoopEvent> message_loop_controller_;
  bool support_video_renderer_ = true;
  scoped_refptr<MediaStreamAudioRenderer> audio_renderer_;
  raw_ptr<base::test::TaskEnvironment> task_environment_;
};

scoped_refptr<MediaStreamVideoRenderer> MockRenderFactory::GetVideoRenderer(
    const WebMediaStream& web_stream,
    const MediaStreamVideoRenderer::RepaintCB& repaint_cb,
    scoped_refptr<base::SequencedTaskRunner> video_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> main_render_task_runner) {
  if (!support_video_renderer_)
    return nullptr;

  provider_ = base::MakeRefCounted<MockMediaStreamVideoRenderer>(
      task_runner_, message_loop_controller_, repaint_cb, task_environment_);

  return provider_;
}

// This is the main class coordinating the tests.
// Basic workflow:
// 1. WebMediaPlayerMS::Load will generate and start
// MediaStreamVideoRenderer.
// 2. MediaStreamVideoRenderer will start pushing frames into
//    WebMediaPlayerMS repeatedly.
// 3. On WebMediaPlayerMS receiving the first frame, a cc::Layer will be
//    created.
// 4. The cc::Layer will call
//    WebMediaPlayerMSCompositor::SetVideoFrameProviderClient, which in turn
//    will trigger cc::VideoFrameProviderClient::StartRendering.
// 5. Then cc::VideoFrameProviderClient will start calling
//    WebMediaPlayerMSCompositor::UpdateCurrentFrame, GetCurrentFrame for
//    rendering repeatedly.
// 6. When WebMediaPlayerMS::pause gets called, it should trigger
//    MediaStreamVideoRenderer::Pause, and then the provider will stop
//    pushing frames into WebMediaPlayerMS, but instead digesting them;
//    simultanously, it should call cc::VideoFrameProviderClient::StopRendering,
//    so cc::VideoFrameProviderClient will stop asking frames from
//    WebMediaPlayerMSCompositor.
// 7. When WebMediaPlayerMS::play gets called, evething paused in step 6 should
//    be resumed.
class WebMediaPlayerMSTest
    : public testing::TestWithParam<
          testing::tuple<bool /* enable_surface_layer_for_video */,
                         bool /* opaque_frame */,
                         bool /* odd_size_frame */>>,
      public MediaPlayerClient,
      public cc::VideoFrameProvider::Client {
 public:
  WebMediaPlayerMSTest()
      : render_factory_(new MockRenderFactory(
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            &message_loop_controller_,
            &task_environment_)),
        gpu_factories_(new media::MockGpuVideoAcceleratorFactories(nullptr)),
        surface_layer_bridge_(
            std::make_unique<NiceMock<MockSurfaceLayerBridge>>()),
        submitter_(std::make_unique<NiceMock<MockWebVideoFrameSubmitter>>()),
        layer_set_(false),
        rendering_(false),
        background_rendering_(false) {
    surface_layer_bridge_ptr_ = surface_layer_bridge_.get();
    submitter_ptr_ = submitter_.get();
  }
  ~WebMediaPlayerMSTest() override {
    player_.reset();
    base::RunLoop().RunUntilIdle();
  }

  void InitializeWebMediaPlayerMS();

  MockMediaStreamVideoRenderer* LoadAndGetFrameProvider(bool algorithm_enabled);

  // Implementation of WebMediaPlayerClient
  void NetworkStateChanged() override;
  void ReadyStateChanged() override;
  void TimeChanged() override {}
  void Repaint() override {}
  void DurationChanged() override {}
  void SizeChanged() override;
  void SetCcLayer(cc::Layer* layer) override;
  void OnFirstFrame(base::TimeTicks, size_t) override {}

  void RemoveMediaTrack(const media::MediaTrack&) override {}
  void AddMediaTrack(const media::MediaTrack& track) override {}

  void MediaSourceOpened(std::unique_ptr<WebMediaSource>) override {}
  void RemotePlaybackCompatibilityChanged(const KURL& url,
                                          bool is_compatible) override {}
  bool WasAlwaysMuted() override { return false; }
  bool HasSelectedVideoTrack() override { return false; }
  WebMediaPlayer::TrackId GetSelectedVideoTrackId() override {
    return WebMediaPlayer::TrackId();
  }
  bool HasNativeControls() override { return false; }
  bool IsAudioElement() override { return is_audio_element_; }
  bool IsInAutoPIP() const override { return false; }
  void MediaRemotingStarted(
      const WebString& remote_device_friendly_name) override {}
  void MediaRemotingStopped(int error_code) override {}
  void ResumePlayback() override {}
  void PausePlayback(PauseReason) override {}
  void DidPlayerStartPlaying() override {}
  void DidPlayerPaused(bool) override {}
  void DidPlayerMutedStatusChange(bool muted) override {}
  void DidMediaMetadataChange(bool has_audio,
                              bool has_video,
                              media::AudioCodec audio_codec,
                              media::VideoCodec video_codec,
                              media::MediaContentType media_content_type,
                              bool is_encrypted_media) override {}
  void DidPlayerMediaPositionStateChange(double playback_rate,
                                         base::TimeDelta duration,
                                         base::TimeDelta position,
                                         bool end_of_media) override {}
  void DidDisableAudioOutputSinkChanges() override {}
  void DidUseAudioServiceChange(bool uses_audio_service) override {}
  void DidPlayerSizeChange(const gfx::Size& size) override {}
  void OnRemotePlaybackDisabled(bool disabled) override {}

  // Implementation of cc::VideoFrameProvider::Client
  void StopUsingProvider() override;
  void StartRendering() override;
  void StopRendering() override;
  void DidReceiveFrame() override;
  bool IsDrivingFrameUpdates() const override { return true; }
  void OnPictureInPictureStateChange() override {}

  // For test use
  void SetBackgroundRendering(bool background_rendering) {
    background_rendering_ = background_rendering;
  }

  void SetGpuMemoryBufferVideoForTesting() {
#if BUILDFLAG(IS_WIN)
    render_factory_->provider()->set_standard_size(
        WebMediaPlayerMS::kUseGpuMemoryBufferVideoFramesMinResolution);
#endif  // BUILDFLAG(IS_WIN)

    player_->SetGpuMemoryBufferVideoForTesting(
        new media::MockGpuMemoryBufferVideoFramePool(&frame_ready_cbs_));
  }

  // Sets the value of the rendering_ flag. Called from expectations in the
  // test.
  void SetRendering(bool rendering) { rendering_ = rendering; }

 protected:
  MOCK_METHOD0(DoStartRendering, void());
  MOCK_METHOD0(DoStopRendering, void());
  MOCK_METHOD0(DoDidReceiveFrame, void());
  MOCK_METHOD0(DoOnPictureInPictureStateChange, void());

  MOCK_METHOD1(DoSetCcLayer, void(bool));
  MOCK_METHOD1(DoNetworkStateChanged, void(WebMediaPlayer::NetworkState));
  MOCK_METHOD1(DoReadyStateChanged, void(WebMediaPlayer::ReadyState));
  MOCK_METHOD1(CheckSizeChanged, void(gfx::Size));
  MOCK_CONST_METHOD0(GetDisplayType, DisplayType());
  MOCK_CONST_METHOD0(CouldPlayIfEnoughData, bool());
  MOCK_METHOD0(OnRequestVideoFrameCallback, void());
  MOCK_METHOD0(GetElementId, int());

  std::unique_ptr<WebSurfaceLayerBridge> CreateMockSurfaceLayerBridge(
      WebSurfaceLayerBridgeObserver*,
      cc::UpdateSubmissionStateCB) {
    return std::move(surface_layer_bridge_);
  }

  // Testing harness for the GetVideoFramePresentationMetadata test.
  void TestGetVideoFramePresentationMetadata(bool algorithm_enabled);

  // Testing harness for the RequestVideoFrameCallback test.
  void TestRequestFrameCallbackWithVideoFrameMetadata(bool algorithm_enabled);

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  raw_ptr<MockRenderFactory, DanglingUntriaged> render_factory_;
  std::unique_ptr<media::MockGpuVideoAcceleratorFactories> gpu_factories_;
  FakeWebMediaPlayerDelegate delegate_;
  std::unique_ptr<WebMediaPlayerMS> player_;
  raw_ptr<WebMediaPlayerMSCompositor, DanglingUntriaged> compositor_;
  ReusableMessageLoopEvent message_loop_controller_;
  raw_ptr<cc::Layer> layer_;
  bool is_audio_element_ = false;
  std::vector<base::OnceClosure> frame_ready_cbs_;
  std::unique_ptr<NiceMock<MockSurfaceLayerBridge>> surface_layer_bridge_;
  std::unique_ptr<NiceMock<MockWebVideoFrameSubmitter>> submitter_;
  raw_ptr<NiceMock<MockSurfaceLayerBridge>, DanglingUntriaged>
      surface_layer_bridge_ptr_ = nullptr;
  raw_ptr<NiceMock<MockWebVideoFrameSubmitter>, DanglingUntriaged>
      submitter_ptr_ = nullptr;
  bool enable_surface_layer_for_video_ = false;
  base::TimeTicks deadline_min_;
  base::TimeTicks deadline_max_;

 private:
  // Main function trying to ask WebMediaPlayerMS to submit a frame for
  // rendering.
  void RenderFrame();

  bool layer_set_;
  bool rendering_;
  bool background_rendering_;

  base::WeakPtrFactory<WebMediaPlayerMSTest> weak_factory_{this};
};

void WebMediaPlayerMSTest::InitializeWebMediaPlayerMS() {
  enable_surface_layer_for_video_ = testing::get<0>(GetParam());
  player_ = std::make_unique<WebMediaPlayerMS>(
      nullptr, this, &delegate_, std::make_unique<media::NullMediaLog>(),
      scheduler::GetSingleThreadTaskRunnerForTesting(),
      scheduler::GetSingleThreadTaskRunnerForTesting(),
      scheduler::GetSingleThreadTaskRunnerForTesting(),
      scheduler::GetSingleThreadTaskRunnerForTesting(),
      scheduler::GetSingleThreadTaskRunnerForTesting(), gpu_factories_.get(),
      WebString(),
      WTF::BindOnce(&WebMediaPlayerMSTest::CreateMockSurfaceLayerBridge,
                    WTF::Unretained(this)),
      std::move(submitter_), enable_surface_layer_for_video_);
  player_->SetMediaStreamRendererFactoryForTesting(
      std::unique_ptr<MediaStreamRendererFactory>(render_factory_));
}

MockMediaStreamVideoRenderer* WebMediaPlayerMSTest::LoadAndGetFrameProvider(
    bool algorithm_enabled) {
  EXPECT_FALSE(!!render_factory_->provider()) << "There should not be a "
                                                 "FrameProvider yet.";

  EXPECT_CALL(*this,
              DoNetworkStateChanged(WebMediaPlayer::kNetworkStateLoading));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveNothing));
  player_->Load(WebMediaPlayer::kLoadTypeURL, WebMediaPlayerSource(),
                WebMediaPlayer::kCorsModeUnspecified,
                /*is_cache_disabled=*/false);
  compositor_ = player_->compositor_.get();
  EXPECT_TRUE(!!compositor_);
  compositor_->SetAlgorithmEnabledForTesting(algorithm_enabled);

  MockMediaStreamVideoRenderer* provider = nullptr;
  if (render_factory_->support_video_renderer()) {
    provider = render_factory_->provider();
    EXPECT_TRUE(!!provider);
    EXPECT_TRUE(provider->Started());
  }

  testing::Mock::VerifyAndClearExpectations(this);
  return provider;
}

void WebMediaPlayerMSTest::NetworkStateChanged() {
  WebMediaPlayer::NetworkState state = player_->GetNetworkState();
  DoNetworkStateChanged(state);
  if (state == WebMediaPlayer::NetworkState::kNetworkStateFormatError ||
      state == WebMediaPlayer::NetworkState::kNetworkStateDecodeError ||
      state == WebMediaPlayer::NetworkState::kNetworkStateNetworkError) {
    message_loop_controller_.GetPipelineStatusCB().Run(
        media::PIPELINE_ERROR_NETWORK);
  }
}

void WebMediaPlayerMSTest::ReadyStateChanged() {
  WebMediaPlayer::ReadyState state = player_->GetReadyState();
  DoReadyStateChanged(state);
  if (state == WebMediaPlayer::ReadyState::kReadyStateHaveMetadata &&
      !player_->HasAudio()) {
    const auto& size = player_->NaturalSize();
    EXPECT_GT(size.width(), 0);
    EXPECT_GT(size.height(), 0);
  }
  if (state == WebMediaPlayer::ReadyState::kReadyStateHaveEnoughData)
    player_->Play();
}

void WebMediaPlayerMSTest::SetCcLayer(cc::Layer* layer) {
  // Make sure that the old layer is still alive, see https://crbug.com/705448.
  if (layer_set_)
    EXPECT_TRUE(layer_);
  layer_set_ = layer ? true : false;

  layer_ = layer;
  if (layer) {
    if (enable_surface_layer_for_video_)
      compositor_->SetVideoFrameProviderClient(submitter_ptr_);
    else
      compositor_->SetVideoFrameProviderClient(this);
  }
  DoSetCcLayer(!!layer);
}

void WebMediaPlayerMSTest::StopUsingProvider() {
  if (rendering_)
    StopRendering();
}

void WebMediaPlayerMSTest::StartRendering() {
  if (!rendering_) {
    rendering_ = true;
    scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
        FROM_HERE, WTF::BindOnce(&WebMediaPlayerMSTest::RenderFrame,
                                 weak_factory_.GetWeakPtr()));
  }
  DoStartRendering();
}

void WebMediaPlayerMSTest::StopRendering() {
  rendering_ = false;
  DoStopRendering();
}

void WebMediaPlayerMSTest::DidReceiveFrame() {
  if (background_rendering_)
    DoDidReceiveFrame();
}

void WebMediaPlayerMSTest::RenderFrame() {
  if (!rendering_ || !compositor_)
    return;

  // Advance the clock by 100 milliseconds for each RenderFrame call.
  task_environment_.AdvanceClock(base::Milliseconds(100));

  base::TimeTicks now = base::TimeTicks::Now();
  deadline_min_ = now + base::Seconds(1.0 / 60.0);
  deadline_max_ = deadline_min_ + base::Seconds(1.0 / 60.0);

  // Background rendering is different from stop rendering. The rendering loop
  // is still running but we do not ask frames from |compositor_|. And
  // background rendering is not initiated from |compositor_|.
  if (!background_rendering_) {
    compositor_->UpdateCurrentFrame(deadline_min_, deadline_max_);
    auto frame = compositor_->GetCurrentFrame();
    compositor_->PutCurrentFrame();
  }
  scheduler::GetSingleThreadTaskRunnerForTesting()->PostDelayedTask(
      FROM_HERE,
      WTF::BindOnce(&WebMediaPlayerMSTest::RenderFrame,
                    weak_factory_.GetWeakPtr()),
      base::Seconds(1.0 / 60.0));
}

void WebMediaPlayerMSTest::SizeChanged() {
  gfx::Size frame_size = compositor_->GetMetadata().natural_size;
  CheckSizeChanged(frame_size);
}

void WebMediaPlayerMSTest::TestGetVideoFramePresentationMetadata(
    bool algorithm_enabled) {
  InitializeWebMediaPlayerMS();

  MockMediaStreamVideoRenderer* provider =
      LoadAndGetFrameProvider(algorithm_enabled);

  const int kTestBrake = static_cast<int>(FrameType::TEST_BRAKE);
  Vector<int> timestamps({0, kTestBrake, 33, kTestBrake, 66, kTestBrake});
  provider->QueueFrames(timestamps);

  // Chain calls to video.rVFC.
  int num_frames = 3;
  player_->RequestVideoFrameCallback();

  // Verify that the presentation frame counter is monotonically increasing.
  // Queue up a rVFC call immediately after each frame.
  int last_frame_counter = -1;
  EXPECT_CALL(*this, OnRequestVideoFrameCallback())
      .Times(num_frames)
      .WillRepeatedly([&]() {
        auto metadata = player_->GetVideoFramePresentationMetadata();
        EXPECT_GT((int)metadata->presented_frames, last_frame_counter);
        last_frame_counter = metadata->presented_frames;
        if (!algorithm_enabled && !enable_surface_layer_for_video_ &&
            !deadline_min_.is_null()) {
          // We use EXPECT_GE to compare the deadline_max value with the
          // expected display time. This is because the deadline_max_ member
          // gets updated in the RenderFrame() function which may get called
          // multiple times before the OnRequestVideoFrameCallback() is invoked.
          EXPECT_GE(deadline_max_, metadata->expected_display_time);
        }
        player_->RequestVideoFrameCallback();
      });

  // Wait for each of the frame/kTestBreak pairs.
  while (num_frames--) {
    // Advance the clock by 10 milliseconds before each frame is retrieved to
    // emulate real system clock behavior.
    task_environment_.AdvanceClock(base::Milliseconds(10));
    message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  }
  testing::Mock::VerifyAndClearExpectations(this);
}

void WebMediaPlayerMSTest::TestRequestFrameCallbackWithVideoFrameMetadata(
    bool algorithm_enabled) {
  InitializeWebMediaPlayerMS();

  MockMediaStreamVideoRenderer* provider =
      LoadAndGetFrameProvider(algorithm_enabled);

  const int kTestBrake = static_cast<int>(FrameType::TEST_BRAKE);
  Vector<int> timestamps({0, 33, kTestBrake, 66, 100, 133, 166});
  provider->QueueFrames(timestamps);

  // Verify a basic call to rVFC
  player_->RequestVideoFrameCallback();
  EXPECT_CALL(*this, OnRequestVideoFrameCallback()).Times(1);
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);

  auto metadata = player_->GetVideoFramePresentationMetadata();

  EXPECT_GT(metadata->presentation_time, base::TimeTicks());
  EXPECT_GE(metadata->expected_display_time, metadata->presentation_time);
  testing::Mock::VerifyAndClearExpectations(this);

  // Make sure multiple calls to rVFC only result in one call per frame to
  // OnRVFC.
  player_->RequestVideoFrameCallback();
  player_->RequestVideoFrameCallback();
  player_->RequestVideoFrameCallback();

  EXPECT_CALL(*this, OnReques
```