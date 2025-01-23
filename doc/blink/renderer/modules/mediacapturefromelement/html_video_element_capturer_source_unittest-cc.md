Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Understanding the Goal:**

The primary goal is to understand what this code *does* and how it relates to web technologies like JavaScript, HTML, and CSS. Since it's a unit test, the focus is on testing a specific component in isolation.

**2. Identifying the Core Component:**

The file name itself, `html_video_element_capturer_source_unittest.cc`, is a huge clue. It suggests the code under test is `HTMLVideoElementCapturerSource`. The `#include` statement at the top confirms this.

**3. Deciphering the Test Setup:**

Unit tests typically have a setup phase. We see the creation of `MockWebMediaPlayer` and `HtmlVideoElementCapturerSource` within the `HTMLVideoElementCapturerSourceTest` class.

* **`MockWebMediaPlayer`:**  The name "Mock" immediately tells us this isn't a real `WebMediaPlayer`. It's a simplified version used for testing purposes. Examining its methods reveals it's designed to mimic the core functionalities of a video player (play, pause, seek, paint, etc.) but allows the test to control its behavior. Key things to note here are `Paint()`, `GetCurrentFrameThenUpdate()`, `is_video_opaque_`, and `size_`. These are likely the aspects the `HTMLVideoElementCapturerSource` interacts with.

* **`HtmlVideoElementCapturerSource`:**  This is the class being tested. The constructor takes a `WebMediaPlayer` (as a weak pointer) and task runners. This suggests it's responsible for taking frames from the media player and making them available for capture.

* **`HTMLVideoElementCapturerSourceTest`:** This is the test fixture, inheriting from `testing::TestWithParam` which indicates parameterized testing (testing with different inputs). It sets up the mock player and the capturer. The `MOCK_METHOD`s are for verifying interactions with callbacks.

**4. Analyzing the Individual Test Cases:**

Now we go through each `TEST_F` or `TEST_P` individually:

* **`ConstructAndDestruct`:** This simple test verifies that creating and destroying the objects doesn't lead to crashes or errors. It's a basic sanity check.

* **`EmptyWebMediaPlayerFailsCapture`:** This checks the scenario where the `WebMediaPlayer` is invalid. It expects the `OnRunning` callback to be called with `false`, indicating a failure to start capture.

* **`GetFormatsAndStartAndStop`:** This is a more comprehensive test. It verifies the sequence of getting preferred formats, starting capture, receiving frames, and stopping capture. The `EXPECT_CALL`s with `SaveArg` and `RunOnceClosure` show how the test captures the delivered video frames for inspection. The `GetParam()` and `SetVideoPlayerOpacity()` highlight the parameterized testing for opaque and transparent videos. The assertions on the frame format (`PIXEL_FORMAT_I420` and `PIXEL_FORMAT_I420A`) are crucial for understanding how opacity affects the output.

* **`StartAndStopInSameTaskCaptureZeroFrames`:** This test explores the scenario where capture is immediately stopped after starting, likely due to a condition like cross-origin restrictions. It verifies that no frames are delivered in this case.

* **`AlphaAndNot`:** This focuses on how changes in the video player's opacity dynamically affect the captured frame format. It calls `SetVideoPlayerOpacity` multiple times and verifies the corresponding frame formats.

* **`SizeChange`:** This test checks if changing the video player's size causes issues. The comment `TODO(crbug.com/1817203)` is a valuable piece of information, suggesting that full size change support might not be implemented or fully tested yet.

* **`TaintedPlayerDoesNotDeliverFrames`:** This test simulates a cross-origin scenario by setting `would_taint_origin_` to `true` on the mock player. It verifies that no frames are delivered in this case, demonstrating the security mechanism.

**5. Connecting to Web Technologies:**

As we analyze the test cases, we consider how they relate to web technologies:

* **HTML `<video>` element:** The core component being tested directly relates to capturing content from an HTML `<video>` element.

* **JavaScript `getUserMedia()` and `captureStream()`:** The functionality being tested is likely used behind the scenes when JavaScript code calls `videoElement.captureStream()`. The captured stream can then be used with WebRTC or other media APIs.

* **CSS `opacity` property:** The `AlphaAndNot` test directly links to the CSS `opacity` property applied to a `<video>` element. The test verifies that the capturer correctly handles the transparency.

* **Cross-Origin Issues:** The `TaintedPlayerDoesNotDeliverFrames` test highlights the browser's security model and how it prevents capturing content from cross-origin videos without proper CORS headers.

**6. Identifying Potential User Errors and Debugging:**

Based on the tests, we can infer potential user errors:

* **Trying to capture from a cross-origin video without CORS:** This is covered by the `TaintedPlayerDoesNotDeliverFrames` test.

* **Expecting transparent output when the video source is opaque:** The `GetFormatsAndStartAndStop` test with different opacity values clarifies the behavior.

* **Unexpected behavior when the video size changes:**  The `SizeChange` test (and its TODO comment) suggest potential issues or limitations here.

**7. Logical Inferences (Hypothetical Inputs and Outputs):**

For each test, we can imagine specific scenarios:

* **`GetFormatsAndStartAndStop` (Opaque):**
    * Input: A `<video>` element playing an opaque video.
    * Output: Captured frames in `I420` format.

* **`GetFormatsAndStartAndStop` (Transparent):**
    * Input: A `<video>` element with `opacity < 1` or a video with inherent transparency.
    * Output: Captured frames in `I420A` format.

* **`TaintedPlayerDoesNotDeliverFrames`:**
    * Input: JavaScript attempts to capture a `<video>` element whose source is on a different domain without proper CORS headers.
    * Output: No video frames are captured.

**8. Tracing User Actions:**

We can outline the steps a user might take to reach this code:

1. **User opens a webpage containing a `<video>` element.**
2. **The video starts playing.**
3. **JavaScript code on the page calls `videoElement.captureStream()`.**
4. **The browser's rendering engine (Blink in this case) initiates the capture process.**
5. **The `HTMLVideoElementCapturerSource` is created to handle the capture.**
6. **The tests in this file simulate different scenarios and edge cases of this capture process.**

By following these steps, we can systematically understand the purpose and functionality of the C++ code and its relevance to the broader web platform.
这个C++文件 `html_video_element_capturer_source_unittest.cc` 是 Chromium Blink 引擎中用于测试 `HTMLVideoElementCapturerSource` 类的单元测试文件。 `HTMLVideoElementCapturerSource` 的主要功能是**从 HTML `<video>` 元素捕获视频帧数据**。

以下是该文件的功能分解和它与 JavaScript、HTML 和 CSS 的关系：

**1. 主要功能：测试 HTML `<video>` 元素捕获功能**

   - **创建和管理视频帧捕获源:** `HTMLVideoElementCapturerSource` 负责从一个 `WebMediaPlayer`（代表 HTML `<video>` 元素的媒体播放器）获取视频帧，并将其转换为可供其他组件（例如 WebRTC 或 MediaRecorder）使用的格式。
   - **处理视频帧的格式和属性:**  测试用例会检查捕获的视频帧的像素格式（例如，是否包含 Alpha 通道）是否与源视频的属性（例如，是否透明）一致。
   - **处理跨域安全问题:** 测试用例会验证当尝试捕获来自不同域的视频时，是否会按照浏览器的安全策略阻止捕获。
   - **处理视频大小变化:** 测试用例会检查当 HTML `<video>` 元素的尺寸发生变化时，捕获器是否能正常工作，虽然目前的测试只是验证不会崩溃，但未来的目标是完全支持尺寸变化。
   - **处理捕获的启动和停止:** 测试用例会验证启动和停止捕获的流程是否正确。

**2. 与 JavaScript、HTML、CSS 的关系和举例说明：**

   - **HTML `<video>` 元素:** 这是捕获功能的直接目标。 `HTMLVideoElementCapturerSource` 的作用就是从 `<video>` 元素渲染的内容中提取视频帧。
     ```html
     <video id="myVideo" src="my-video.mp4" controls></video>
     ```
     JavaScript 可以使用 `document.getElementById('myVideo')` 获取这个元素，然后通过 `captureStream()` 方法来利用 `HTMLVideoElementCapturerSource` 的功能。

   - **JavaScript `captureStream()` 方法:**  JavaScript 的 `captureStream()` 方法是触发 `HTMLVideoElementCapturerSource` 工作的入口点。当 JavaScript 调用这个方法时，浏览器会创建一个媒体流，其视频轨道由 `HTMLVideoElementCapturerSource` 提供。
     ```javascript
     const video = document.getElementById('myVideo');
     const stream = video.captureStream();
     const videoTrack = stream.getVideoTracks()[0];
     ```

   - **CSS `opacity` 属性:** 测试用例 `AlphaAndNot` 验证了当 HTML `<video>` 元素设置了 `opacity` CSS 属性时，`HTMLVideoElementCapturerSource` 能否正确捕获包含 Alpha 通道的透明帧。
     ```css
     #myVideo {
       opacity: 0.5; /* 设置视频半透明 */
     }
     ```
     当 `opacity` 小于 1 时，`HTMLVideoElementCapturerSource` 应该输出 `media::PIXEL_FORMAT_I420A` 格式的视频帧，其中包含 Alpha 通道。

   - **跨域安全 (CORS):** 测试用例 `TaintedPlayerDoesNotDeliverFrames` 模拟了当 `<video>` 元素的 `src` 属性指向一个不同源的资源，并且该资源没有设置正确的 CORS 头时，捕获器会阻止捕获。这是浏览器安全策略的一部分，防止恶意网站捕获用户不知情的视频内容。

**3. 逻辑推理、假设输入与输出：**

   - **假设输入 (针对 `GetFormatsAndStartAndStop` 测试用例):**
     - 一个 `MockWebMediaPlayer` 实例，模拟一个正在播放的 HTML `<video>` 元素，其自然尺寸为 16x10。
     - 设置 `is_video_opaque_` 为 `true` (不透明)。
     - 调用 `StartCapture` 方法开始捕获。
   - **预期输出:**
     - `GetPreferredFormats` 方法返回一个包含一个 `VideoCaptureFormat` 的向量，其 `frame_size` 为 16x10。
     - `OnRunning` 回调被调用，参数为 `true`。
     - `OnDeliverFrame` 回调被调用两次，每次传递一个 `media::VideoFrame`。
     - 第一个和第二个 `media::VideoFrame` 的格式为 `media::PIXEL_FORMAT_I420` (因为视频是不透明的)。
     - 第二个 `media::VideoFrame` 的时间戳大于第一个。

   - **假设输入 (针对 `GetFormatsAndStartAndStop` 测试用例，`is_video_opaque_` 为 `false`):**
     - 其他输入与上面相同。
     - 设置 `is_video_opaque_` 为 `false` (透明)。
   - **预期输出:**
     - 与上面相同，除了 `OnDeliverFrame` 回调传递的 `media::VideoFrame` 的格式为 `media::PIXEL_FORMAT_I420A` (因为视频是透明的)。

   - **假设输入 (针对 `TaintedPlayerDoesNotDeliverFrames` 测试用例):**
     - 一个 `MockWebMediaPlayer` 实例。
     - 设置 `would_taint_origin_` 为 `true`，模拟跨域视频。
     - 调用 `StartCapture` 方法。
   - **预期输出:**
     - `OnRunning` 回调被调用，参数为 `true`。
     - `OnDeliverFrame` 回调**不会**被调用，因为跨域视频被阻止捕获。

**4. 用户或编程常见的使用错误：**

   - **尝试捕获跨域视频但未配置 CORS:**
     - **用户操作:** 在一个网站上嵌入一个来自其他域的 `<video>` 元素，并尝试使用 JavaScript 的 `captureStream()` 方法捕获它。
     - **错误:**  `TaintedPlayerDoesNotDeliverFrames` 测试模拟了这种情况。由于浏览器安全策略的限制，捕获会失败，`OnDeliverFrame` 不会被调用。开发者需要确保视频服务器设置了正确的 CORS 头信息，允许当前域访问视频资源。

   - **假设捕获的帧总是包含 Alpha 通道:**
     - **用户操作:** 开发者可能期望使用捕获的视频流进行一些图像处理，并假设所有捕获的帧都带有 Alpha 通道，以便处理透明度。
     - **错误:**  `AlphaAndNot` 测试验证了只有当源视频本身是透明的（例如，通过 CSS `opacity` 设置）时，捕获的帧才会是 `I420A` 格式。如果源视频是不透明的，捕获的帧将是 `I420` 格式，不包含 Alpha 通道。开发者需要根据实际情况处理不同格式的帧。

   - **未处理捕获启动失败的情况:**
     - **用户操作:**  开发者直接调用 `captureStream()` 并假设它总是成功，然后直接使用返回的流。
     - **错误:** `EmptyWebMediaPlayerFailsCapture` 测试验证了如果 `WebMediaPlayer` 无效（例如，`<video>` 元素加载失败），捕获会启动失败，`OnRunning` 回调会收到 `false`。开发者应该检查捕获是否成功启动，并处理失败的情况。

**5. 用户操作到达这里的调试线索：**

   1. **用户在浏览器中访问一个网页，该网页包含一个 `<video>` 元素。**
   2. **JavaScript 代码在该网页上执行。**
   3. **JavaScript 代码获取到 `<video>` 元素的引用 (例如通过 `document.getElementById`)。**
   4. **JavaScript 代码调用 `<video>` 元素的 `captureStream()` 方法。**
   5. **浏览器内部，Blink 引擎接收到 `captureStream()` 的请求。**
   6. **Blink 引擎创建 `HTMLVideoElementCapturerSource` 实例，负责从与该 `<video>` 元素关联的 `WebMediaPlayer` 获取视频帧。**
   7. **`HTMLVideoElementCapturerSource` 会尝试与 `WebMediaPlayer` 交互，获取视频帧数据。**
   8. **这个单元测试文件 `html_video_element_capturer_source_unittest.cc` 中的测试用例就是为了验证 `HTMLVideoElementCapturerSource` 在各种情况下的行为是否正确。**

在调试过程中，如果涉及到从 HTML `<video>` 元素捕获视频流的问题，开发者可能会需要查看以下内容：

- **JavaScript 代码:** 检查 `captureStream()` 的调用是否正确，以及如何处理返回的媒体流。
- **HTML 代码:** 确保 `<video>` 元素存在，并且 `src` 属性指向有效的视频资源。
- **CSS 样式:**  检查是否有影响视频透明度的 CSS 规则。
- **网络请求:** 检查视频资源是否成功加载，以及服务器是否返回了正确的 CORS 头信息（如果涉及到跨域）。
- **浏览器控制台:** 查看是否有与媒体捕获相关的错误或警告信息。
- **Blink 渲染引擎的日志:**  更深入的调试可能需要查看 Blink 引擎的日志，以了解 `HTMLVideoElementCapturerSource` 的内部状态和操作。这个单元测试文件可以帮助开发者理解 `HTMLVideoElementCapturerSource` 的预期行为，从而更好地定位问题。

### 提示词
```
这是目录为blink/renderer/modules/mediacapturefromelement/html_video_element_capturer_source_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediacapturefromelement/html_video_element_capturer_source.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/gmock_callback_support.h"
#include "cc/paint/paint_canvas.h"
#include "cc/paint/paint_flags.h"
#include "media/base/limits.h"
#include "media/base/video_frame.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_media_player.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using base::test::RunOnceClosure;
using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::SaveArg;

namespace blink {

namespace {

// An almost empty WebMediaPlayer to override paint() method.
class MockWebMediaPlayer : public WebMediaPlayer {
 public:
  MockWebMediaPlayer() = default;
  ~MockWebMediaPlayer() override = default;

  LoadTiming Load(LoadType,
                  const WebMediaPlayerSource&,
                  CorsMode,
                  bool is_cache_disabled) override {
    return LoadTiming::kImmediate;
  }
  void Play() override {}
  void Pause() override {}
  void Seek(double seconds) override {}
  void SetRate(double) override {}
  void SetVolume(double) override {}
  void SetLatencyHint(double) override {}
  void SetPreservesPitch(bool) override {}
  void SetWasPlayedWithUserActivationAndHighMediaEngagement(bool) override {}
  void SetShouldPauseWhenFrameIsHidden(bool) override {}
  void OnRequestPictureInPicture() override {}
  WebTimeRanges Buffered() const override { return WebTimeRanges(); }
  WebTimeRanges Seekable() const override { return WebTimeRanges(); }
  void OnFrozen() override {}
  bool SetSinkId(const WebString& sinkId,
                 WebSetSinkIdCompleteCallback) override {
    return false;
  }
  bool HasVideo() const override { return true; }
  bool HasAudio() const override { return false; }
  gfx::Size NaturalSize() const override { return size_; }
  gfx::Size VisibleSize() const override { return size_; }
  bool Paused() const override { return false; }
  bool Seeking() const override { return false; }
  double Duration() const override { return 0.0; }
  double CurrentTime() const override { return 0.0; }
  bool IsEnded() const override { return false; }
  NetworkState GetNetworkState() const override { return kNetworkStateEmpty; }
  ReadyState GetReadyState() const override { return kReadyStateHaveNothing; }
  WebString GetErrorMessage() const override { return WebString(); }

  bool DidLoadingProgress() override { return true; }
  bool WouldTaintOrigin() const override { return would_taint_origin_; }
  double MediaTimeForTimeValue(double timeValue) const override { return 0.0; }
  unsigned DecodedFrameCount() const override { return 0; }
  unsigned DroppedFrameCount() const override { return 0; }
  unsigned CorruptedFrameCount() const override { return 0; }
  uint64_t AudioDecodedByteCount() const override { return 0; }
  uint64_t VideoDecodedByteCount() const override { return 0; }
  void SetVolumeMultiplier(double multiplier) override {}
  void SuspendForFrameClosed() override {}

  void SetWouldTaintOrigin(bool taint) { would_taint_origin_ = taint; }
  bool PassedTimingAllowOriginCheck() const override { return true; }

  void Paint(cc::PaintCanvas* canvas,
             const gfx::Rect& rect,
             cc::PaintFlags&) override {
    return;
  }

  scoped_refptr<media::VideoFrame> GetCurrentFrameThenUpdate() override {
    // We could fill in |canvas| with a meaningful pattern in ARGB and verify
    // that is correctly captured (as I420) by HTMLVideoElementCapturerSource
    // but I don't think that'll be easy/useful/robust, so just let go here.
    return is_video_opaque_ ? media::VideoFrame::CreateBlackFrame(size_)
                            : media::VideoFrame::CreateTransparentFrame(size_);
  }

  std::optional<media::VideoFrame::ID> CurrentFrameId() const override {
    return std::nullopt;
  }

  bool IsOpaque() const override { return is_video_opaque_; }
  bool HasAvailableVideoFrame() const override { return true; }
  bool HasReadableVideoFrame() const override { return true; }

  base::WeakPtr<WebMediaPlayer> AsWeakPtr() override {
    return weak_factory_.GetWeakPtr();
  }

  bool is_video_opaque_ = true;
  gfx::Size size_ = gfx::Size(16, 10);
  bool would_taint_origin_ = false;

  base::WeakPtrFactory<MockWebMediaPlayer> weak_factory_{this};
};

}  // namespace

class HTMLVideoElementCapturerSourceTest : public testing::TestWithParam<bool> {
 public:
  HTMLVideoElementCapturerSourceTest()
      : web_media_player_(new MockWebMediaPlayer()),
        html_video_capturer_(new HtmlVideoElementCapturerSource(
            web_media_player_->AsWeakPtr(),
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            scheduler::GetSingleThreadTaskRunnerForTesting())) {}

  // Necessary callbacks and MOCK_METHODS for them.
  MOCK_METHOD2(DoOnDeliverFrame,
               void(scoped_refptr<media::VideoFrame>, base::TimeTicks));
  void OnDeliverFrame(
      scoped_refptr<media::VideoFrame> video_frame,
      base::TimeTicks estimated_capture_time) {
    DoOnDeliverFrame(std::move(video_frame), estimated_capture_time);
  }

  MOCK_METHOD1(DoOnRunning, void(bool));
  void OnRunning(blink::RunState run_state) {
    bool state = (run_state == blink::RunState::kRunning) ? true : false;
    DoOnRunning(state);
  }

  void SetVideoPlayerOpacity(bool opacity) {
    web_media_player_->is_video_opaque_ = opacity;
  }

  void SetVideoPlayerSize(const gfx::Size& size) {
    web_media_player_->size_ = size;
  }

 protected:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<MockWebMediaPlayer> web_media_player_;
  std::unique_ptr<HtmlVideoElementCapturerSource> html_video_capturer_;
};

// Constructs and destructs all objects, in particular |html_video_capturer_|
// and its inner object(s). This is a non trivial sequence.
TEST_F(HTMLVideoElementCapturerSourceTest, ConstructAndDestruct) {}

TEST_F(HTMLVideoElementCapturerSourceTest, EmptyWebMediaPlayerFailsCapture) {
  web_media_player_.reset();
  EXPECT_CALL(*this, DoOnRunning(false)).Times(1);

  html_video_capturer_->StartCapture(
      media::VideoCaptureParams(),
      WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnDeliverFrame,
                         base::Unretained(this)),
      base::DoNothing(), base::DoNothing(),
      WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnRunning,
                         base::Unretained(this)));
}

// Checks that the usual sequence of GetPreferredFormats() ->
// StartCapture() -> StopCapture() works as expected and let it capture two
// frames, that are tested for format vs the expected source opacity.
TEST_P(HTMLVideoElementCapturerSourceTest, GetFormatsAndStartAndStop) {
  InSequence s;
  media::VideoCaptureFormats formats =
      html_video_capturer_->GetPreferredFormats();
  ASSERT_EQ(1u, formats.size());
  EXPECT_EQ(web_media_player_->NaturalSize(), formats[0].frame_size);

  media::VideoCaptureParams params;
  params.requested_format = formats[0];

  EXPECT_CALL(*this, DoOnRunning(true)).Times(1);

  const bool is_video_opaque = GetParam();
  SetVideoPlayerOpacity(is_video_opaque);

  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();
  scoped_refptr<media::VideoFrame> first_frame;
  scoped_refptr<media::VideoFrame> second_frame;
  EXPECT_CALL(*this, DoOnDeliverFrame(_, _)).WillOnce(SaveArg<0>(&first_frame));
  EXPECT_CALL(*this, DoOnDeliverFrame(_, _))
      .Times(1)
      .WillOnce(DoAll(SaveArg<0>(&second_frame),
                      RunOnceClosure(std::move(quit_closure))));

  html_video_capturer_->StartCapture(
      params,
      WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnDeliverFrame,
                         base::Unretained(this)),
      base::DoNothing(), base::DoNothing(),
      WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnRunning,
                         base::Unretained(this)));

  run_loop.Run();

  EXPECT_EQ(0u, first_frame->timestamp().InMilliseconds());
  EXPECT_GT(second_frame->timestamp().InMilliseconds(), 30u);
  if (is_video_opaque)
    EXPECT_EQ(media::PIXEL_FORMAT_I420, first_frame->format());
  else
    EXPECT_EQ(media::PIXEL_FORMAT_I420A, first_frame->format());

  html_video_capturer_->StopCapture();
  Mock::VerifyAndClearExpectations(this);
}

INSTANTIATE_TEST_SUITE_P(All,
                         HTMLVideoElementCapturerSourceTest,
                         ::testing::Bool());

// When a new source is created and started, it is stopped in the same task
// when cross-origin data is detected. This test checks that no data is
// delivered in this case.
TEST_F(HTMLVideoElementCapturerSourceTest,
       StartAndStopInSameTaskCaptureZeroFrames) {
  InSequence s;
  media::VideoCaptureFormats formats =
      html_video_capturer_->GetPreferredFormats();
  ASSERT_EQ(1u, formats.size());
  EXPECT_EQ(web_media_player_->NaturalSize(), formats[0].frame_size);

  media::VideoCaptureParams params;
  params.requested_format = formats[0];

  EXPECT_CALL(*this, DoOnRunning(true));
  EXPECT_CALL(*this, DoOnDeliverFrame(_, _)).Times(0);

  html_video_capturer_->StartCapture(
      params,
      WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnDeliverFrame,
                         base::Unretained(this)),
      base::DoNothing(), base::DoNothing(),
      WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnRunning,
                         base::Unretained(this)));
  html_video_capturer_->StopCapture();
  base::RunLoop().RunUntilIdle();

  Mock::VerifyAndClearExpectations(this);
}

// Verify that changes in the opacicty of the source WebMediaPlayer are followed
// by corresponding changes in the format of the captured VideoFrame.
TEST_F(HTMLVideoElementCapturerSourceTest, AlphaAndNot) {
  InSequence s;
  media::VideoCaptureFormats formats =
      html_video_capturer_->GetPreferredFormats();
  media::VideoCaptureParams params;
  params.requested_format = formats[0];

  {
    SetVideoPlayerOpacity(false);

    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    scoped_refptr<media::VideoFrame> frame;
    EXPECT_CALL(*this, DoOnRunning(true)).Times(1);
    EXPECT_CALL(*this, DoOnDeliverFrame(_, _))
        .WillOnce(
            DoAll(SaveArg<0>(&frame), RunOnceClosure(std::move(quit_closure))));
    html_video_capturer_->StartCapture(
        params,
        WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnDeliverFrame,
                           base::Unretained(this)),
        base::DoNothing(), base::DoNothing(),
        WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnRunning,
                           base::Unretained(this)));
    run_loop.Run();

    EXPECT_EQ(media::PIXEL_FORMAT_I420A, frame->format());
  }
  {
    SetVideoPlayerOpacity(true);

    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    scoped_refptr<media::VideoFrame> frame;
    EXPECT_CALL(*this, DoOnDeliverFrame(_, _))
        .WillOnce(
            DoAll(SaveArg<0>(&frame), RunOnceClosure(std::move(quit_closure))));
    run_loop.Run();

    EXPECT_EQ(media::PIXEL_FORMAT_I420, frame->format());
  }
  {
    SetVideoPlayerOpacity(false);

    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    scoped_refptr<media::VideoFrame> frame;
    EXPECT_CALL(*this, DoOnDeliverFrame(_, _))
        .WillOnce(
            DoAll(SaveArg<0>(&frame), RunOnceClosure(std::move(quit_closure))));
    run_loop.Run();

    EXPECT_EQ(media::PIXEL_FORMAT_I420A, frame->format());
  }

  html_video_capturer_->StopCapture();
  Mock::VerifyAndClearExpectations(this);
}

// Verify that changes in the natural size of the source WebMediaPlayer do not
// crash.
// TODO(crbug.com/1817203): Verify that size changes are fully supported.
TEST_F(HTMLVideoElementCapturerSourceTest, SizeChange) {
  InSequence s;
  media::VideoCaptureFormats formats =
      html_video_capturer_->GetPreferredFormats();
  media::VideoCaptureParams params;
  params.requested_format = formats[0];

  {
    SetVideoPlayerSize(gfx::Size(16, 10));

    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    scoped_refptr<media::VideoFrame> frame;
    EXPECT_CALL(*this, DoOnRunning(true)).Times(1);
    EXPECT_CALL(*this, DoOnDeliverFrame(_, _))
        .WillOnce(
            DoAll(SaveArg<0>(&frame), RunOnceClosure(std::move(quit_closure))));
    html_video_capturer_->StartCapture(
        params,
        WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnDeliverFrame,
                           base::Unretained(this)),
        base::DoNothing(), base::DoNothing(),
        WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnRunning,
                           base::Unretained(this)));
    run_loop.Run();
  }
  {
    SetVideoPlayerSize(gfx::Size(32, 20));

    base::RunLoop run_loop;
    base::RepeatingClosure quit_closure = run_loop.QuitClosure();
    scoped_refptr<media::VideoFrame> frame;
    EXPECT_CALL(*this, DoOnDeliverFrame(_, _))
        .WillOnce(
            DoAll(SaveArg<0>(&frame), RunOnceClosure(std::move(quit_closure))));
    run_loop.Run();
  }

  html_video_capturer_->StopCapture();
  Mock::VerifyAndClearExpectations(this);
}

// Checks that the usual sequence of GetPreferredFormats() ->
// StartCapture() -> StopCapture() works as expected and let it capture two
// frames, that are tested for format vs the expected source opacity.
TEST_F(HTMLVideoElementCapturerSourceTest, TaintedPlayerDoesNotDeliverFrames) {
  InSequence s;
  media::VideoCaptureFormats formats =
      html_video_capturer_->GetPreferredFormats();
  ASSERT_EQ(1u, formats.size());
  EXPECT_EQ(web_media_player_->NaturalSize(), formats[0].frame_size);
  web_media_player_->SetWouldTaintOrigin(true);

  media::VideoCaptureParams params;
  params.requested_format = formats[0];

  EXPECT_CALL(*this, DoOnRunning(true)).Times(1);

  // No frames should be delivered.
  EXPECT_CALL(*this, DoOnDeliverFrame(_, _)).Times(0);
  html_video_capturer_->StartCapture(
      params,
      WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnDeliverFrame,
                         base::Unretained(this)),
      base::DoNothing(), base::DoNothing(),
      WTF::BindRepeating(&HTMLVideoElementCapturerSourceTest::OnRunning,
                         base::Unretained(this)));

  // Wait for frames to be potentially sent in a follow-up task.
  base::RunLoop().RunUntilIdle();

  html_video_capturer_->StopCapture();
  Mock::VerifyAndClearExpectations(this);
}

}  // namespace blink
```