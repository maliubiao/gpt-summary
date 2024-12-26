Response:
Let's break down the thought process for analyzing the C++ test file.

**1. Initial Scan and Purpose Identification:**

* **Filename:** `webrtc_video_track_source_test.cc`. The `_test` suffix immediately signals this is a testing file. The `webrtc_video_track_source` part suggests it tests the `WebRtcVideoTrackSource` class. The location in `blink/renderer/platform/peerconnection/` confirms it's related to WebRTC in the Blink rendering engine.
* **Includes:** The included headers provide clues about the functionalities being tested:
    * `webrtc_video_track_source.h`:  The primary class under test.
    * `<algorithm>`:  Likely for general utility.
    * `base/...`:  Various base library utilities (callbacks, strings, tasks, testing). This is a strong indicator of asynchronous operations and unit testing.
    * `media/base/...`:  Media-related data structures like `VideoFrame`, `VideoCaptureFeedback`, and `VideoPixelFormat`. This confirms the focus on video processing.
    * `media/video/...`: Specific video components like `FakeGpuMemoryBuffer`. Indicates testing of GPU-backed video frames.
    * `testing/gmock/...`, `testing/gtest/...`:  C++ testing frameworks being used.
    * `video_frame_utils.h`:  Utilities for creating test video frames.
    * `convert_to_webrtc_video_frame_buffer.h`: Suggests conversion between internal Blink video frames and WebRTC's representation.
    * `third_party/webrtc/...`: WebRTC API headers.
* **Namespaces:** The code is within the `blink` namespace, further confirming its location within the Blink engine.

**2. Core Class Under Test:**

* The filename and includes point to `WebRtcVideoTrackSource`. The tests aim to verify its behavior.

**3. Key Functionality Areas (Derived from Test Names and Setup):**

* **Frame Refresh:** The `WebRtcVideoTrackSourceRefreshFrameTest` and its single test `CallsRefreshFrame` directly target the frame refresh mechanism.
* **Frame Delivery and Timestamps:**  The `TestTimestamps` test verifies that frames are delivered to a sink (`MockVideoSink`) and have correct timestamps.
* **Frame Cropping and Scaling:** Tests like `CropFrameTo640360`, `CropFrameTo320320`, and `Scale720To640360` indicate testing of how the `WebRtcVideoTrackSource` handles different frame dimensions and scaling. The use of `SetCustomFrameAdaptationParamsForTesting` is a strong signal.
* **Color Space Handling:** `TestColorSpaceSettings` explicitly tests how color space information is passed through.
* **Feedback Mechanism:** `SetsFeedback` tests how the source provides feedback (likely to the video capture pipeline) based on the sink's requirements.
* **Update Rectangles (Partial Frame Updates):** The various `UpdateRectWith...` tests are crucial for understanding how the source handles and propagates information about which parts of a frame have changed. This is important for efficiency.
* **GPU Memory Buffer Handling:** Tests involving `FakeGpuMemoryBuffer`, `SendTestFrameWithMappableGMB`, and `PassesMappedFramesInOrder` focus on the handling of video frames backed by GPU memory. The `MapCallbackController` interface is key here.
* **Asynchronous Frame Processing:** The `PassesMappedFramesInOrder` test heavily relies on asynchronous callbacks, highlighted by `InvokeNextMapCallback`.
* **Resource Management:**  `DoesntCrashOnLateCallbacks` checks for robustness when callbacks occur after the source is disposed of.

**4. Identifying Relationships to Web Technologies:**

* **JavaScript:** WebRTC is exposed to JavaScript. The `WebRtcVideoTrackSource` is a core component in the browser's implementation of the `MediaStreamTrack` API for video. JavaScript code using `getUserMedia()` or `getDisplayMedia()` would indirectly interact with this class.
* **HTML:**  The `<video>` element in HTML is used to display video streams. The output of the `WebRtcVideoTrackSource` would eventually be rendered by the video decoder and displayed in a `<video>` element.
* **CSS:** CSS can style the `<video>` element (e.g., size, positioning). While the C++ code doesn't directly interact with CSS, the visual output it produces is affected by CSS.

**5. Logic Inference and Examples:**

* **Assumption:**  The tests often assume a "mock sink" (`MockVideoSink`) to verify the output of the `WebRtcVideoTrackSource`.
* **Input/Output Example (UpdateRectWithNoTransform):**
    * **Input:** A sequence of video frames with varying `capture_counter` and `capture_update_rect` metadata, with no scaling or cropping applied.
    * **Output:** The `update_rect()` of the `webrtc::VideoFrame` passed to the mock sink is verified against expected values based on the input metadata and whether frames were dropped. Specific scenarios like the first frame, subsequent frames, dropped frames, and gaps in `capture_counter` are tested.

**6. Identifying Potential User/Programming Errors:**

* **Incorrect Frame Metadata:**  If a video source provides incorrect `capture_counter` or `capture_update_rect` values, the partial updates might not work correctly. The tests implicitly cover this by setting specific metadata.
* **Misunderstanding Asynchronous Operations:**  When dealing with GPU memory buffers, the mapping and unmapping operations are asynchronous. Failing to handle the callbacks correctly could lead to errors or crashes. The `PassesMappedFramesInOrder` and `DoesntCrashOnLateCallbacks` tests address this.
* **Incorrectly Setting Sink Wants:**  If the `rtc::VideoSinkWants` are set incorrectly (e.g., requesting a `max_pixel_count` or `max_framerate_fps` that the source cannot provide), the behavior might be unexpected. The `SetsFeedback` test indirectly touches on this.

By systematically analyzing the code, includes, test names, and underlying concepts, we can gain a comprehensive understanding of the functionality being tested and its relevance to web technologies.
这个C++源代码文件 `webrtc_video_track_source_test.cc` 是 Chromium Blink 引擎中用于测试 `WebRtcVideoTrackSource` 类的单元测试文件。 `WebRtcVideoTrackSource` 类在 WebRTC (Web Real-Time Communication) 的实现中扮演着关键角色，它负责从各种来源（如摄像头、屏幕共享等）获取视频帧，并将其转换为 WebRTC 可以处理的格式，最终通过网络发送出去。

**功能列表:**

1. **测试 `WebRtcVideoTrackSource` 的基本功能:**
   - 验证 `WebRtcVideoTrackSource` 是否能够正确地接收视频帧。
   - 检查接收到的视频帧是否被正确地传递给注册的接收器 (sink)。
   - 测试是否能请求刷新帧 (`RequestRefreshFrame`).

2. **测试时间戳处理:**
   - 验证 `WebRtcVideoTrackSource` 在将视频帧传递给接收器时，是否设置了正确的捕获时间戳 (`capture_time_identifier`).
   - 确保连续的帧具有递增的时间戳。

3. **测试帧裁剪和缩放 (Frame Adaptation):**
   - 验证 `WebRtcVideoTrackSource` 是否能够根据接收器的需求（通过 `rtc::VideoSinkWants` 设置）或者自定义的参数，对接收到的视频帧进行裁剪和缩放。
   - 测试不同裁剪区域和缩放比例下的帧处理。

4. **测试颜色空间处理:**
   - 验证 `WebRtcVideoTrackSource` 是否能够正确地处理和传递视频帧的颜色空间信息。
   - 检查是否根据配置正确设置了 `webrtc::VideoFrame` 的颜色空间属性。

5. **测试反馈机制:**
   - 验证 `WebRtcVideoTrackSource` 是否能够根据接收器的需求（例如最大像素数、最大帧率）生成并发送反馈 (`media::VideoCaptureFeedback`).

6. **测试更新区域 (Update Rect) 处理:**
   - 验证 `WebRtcVideoTrackSource` 是否能够正确地处理视频帧元数据中包含的更新区域信息 (`capture_update_rect`).
   - 检查在没有变换、裁剪和缩放的情况下，更新区域是否被正确传递。
   - 测试在进行裁剪和缩放时，更新区域是否被相应地转换。
   - 验证在帧被丢弃后，下一个帧的更新区域是否正确合并了之前未传递的更新区域。
   - 测试 `capture_counter` 中断时，是否将整个帧标记为更新。
   - 测试空更新区域的处理。

7. **测试 GPU 内存缓冲区 (GPU Memory Buffer) 的处理:**
   - 验证 `WebRtcVideoTrackSource` 是否能够正确处理基于 GPU 内存缓冲区的视频帧。
   - 检查 GPU 内存缓冲区的映射和回调机制是否正常工作。
   - 测试异步映射帧的传递顺序。

8. **测试资源管理:**
   - 验证在 `WebRtcVideoTrackSource` 对象被销毁后，延迟的回调是否不会导致崩溃。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript, HTML 或 CSS 代码，但它测试的 `WebRtcVideoTrackSource` 类是 WebRTC API 在浏览器内部实现的关键部分，直接影响这些 Web 技术的功能。

* **JavaScript:**
    - **关系:** JavaScript 通过 WebRTC API (例如 `getUserMedia()` 获取摄像头视频流，或者 `getDisplayMedia()` 获取屏幕共享流) 与 `WebRtcVideoTrackSource` 间接交互。当 JavaScript 代码请求一个视频轨道时，浏览器内部会创建并使用 `WebRtcVideoTrackSource` 来管理视频数据的获取和处理。
    - **举例:**  当 JavaScript 调用 `navigator.mediaDevices.getUserMedia({ video: true })` 时，浏览器内部会创建一个 `WebRtcVideoTrackSource` 的实例来从用户的摄像头捕获视频帧。这个测试文件确保了这个捕获的视频帧能够被正确处理并传递给后续的 WebRTC 组件。

* **HTML:**
    - **关系:** HTML 的 `<video>` 元素用于展示视频流。 `WebRtcVideoTrackSource` 处理的视频帧最终会被解码并在 `<video>` 元素中渲染。
    - **举例:**  一个网页使用 `<video>` 元素来显示本地摄像头视频流：
      ```html
      <video id="localVideo" autoplay playsinline></video>
      <script>
        navigator.mediaDevices.getUserMedia({ video: true })
          .then(stream => {
            const videoElement = document.getElementById('localVideo');
            videoElement.srcObject = stream;
          });
      </script>
      ```
      在这个例子中，`WebRtcVideoTrackSource` 负责将摄像头捕获的视频帧传递给浏览器，最终这些帧会被渲染到 `localVideo` 元素中。此测试文件确保了 `WebRtcVideoTrackSource` 在这个过程中正确地处理了视频帧的各种属性，例如时间戳、裁剪信息等。

* **CSS:**
    - **关系:** CSS 用于样式化 HTML 元素，包括 `<video>` 元素。虽然 `WebRtcVideoTrackSource` 本身不涉及 CSS，但它处理的视频数据最终会受到 CSS 样式的影响 (例如视频的大小、边框等)。
    - **举例:**  CSS 可以设置 `<video>` 元素的尺寸：
      ```css
      #localVideo {
        width: 640px;
        height: 480px;
      }
      ```
      `WebRtcVideoTrackSource` 确保了即使视频帧被裁剪或缩放，最终传递给 `<video>` 元素的数据仍然是有效的，并且可以按照 CSS 的样式正确显示。

**逻辑推理的假设输入与输出举例:**

**测试用例:** `TEST_P(WebRtcVideoTrackSourceTest, CropFrameTo640360)`

* **假设输入:**
    - 一个 `media::VideoFrame` 对象，其 `coded_size` 为 640x480，`visible_rect` 为 (0, 60, 640, 360)，`natural_size` 为 640x360。
    - 通过 `track_source_->SetCustomFrameAdaptationParamsForTesting(FrameAdaptation_KeepAsIs(kNaturalSize));` 设置帧适配参数，指示保持自然尺寸。
* **逻辑推理:** 由于设置了保持自然尺寸的帧适配参数，即使原始帧的 `coded_size` 和 `visible_rect` 不同，传递给 `mock_sink_` 的 `webrtc::VideoFrame` 的宽度和高度应该等于 `natural_size`，即 640x360。
* **预期输出:**  `mock_sink_.OnFrame(_)` 被调用，并且传递的 `webrtc::VideoFrame` 的 `width()` 等于 640，`height()` 等于 360。

**涉及用户或编程常见的使用错误及举例说明:**

1. **未正确处理异步操作 (与 GPU 内存缓冲区相关):**
   - **错误场景:** 当使用 GPU 内存缓冲区时，帧数据的映射可能是异步的。如果代码在映射完成前就尝试访问帧数据，可能会导致崩溃或数据错误。
   - **测试用例覆盖:** `TEST_P(WebRtcVideoTrackSourceTest, PassesMappedFramesInOrder)` 和 `TEST_P(WebRtcVideoTrackSourceTest, DoesntCrashOnLateCallbacks)` 验证了 `WebRtcVideoTrackSource` 正确地处理了这些异步操作，以及即使回调延迟发生也不会崩溃。
   - **用户/编程错误示例:**  一个开发者在获取到 GPU 内存缓冲区的帧后，没有等待映射完成的回调就尝试读取帧数据。

2. **假设更新区域总是相对于完整帧:**
   - **错误场景:** 开发者可能错误地认为 `capture_update_rect` 总是相对于视频的完整编码尺寸，而忽略了可能存在的裁剪或缩放。
   - **测试用例覆盖:** 像 `TEST_P(WebRtcVideoTrackSourceTest, UpdateRectWithCropFromUpstream)` 和 `TEST_P(WebRtcVideoTrackSourceTest, UpdateRectWithScaling)` 这样的测试用例确保了 `WebRtcVideoTrackSource` 在进行裁剪和缩放时能够正确地转换和处理更新区域。
   - **用户/编程错误示例:**  一个视频捕获源报告的更新区域是相对于原始的全尺寸帧，但 WebRTC 应用期望的是相对于当前显示的裁剪后或缩放后的帧。

3. **未能正确设置或理解 `rtc::VideoSinkWants`:**
   - **错误场景:** 开发者可能没有根据自己的需求正确设置 `rtc::VideoSinkWants`，例如没有设置合适的最大像素数或帧率，导致 `WebRtcVideoTrackSource` 无法做出最佳的帧适配决策。
   - **测试用例覆盖:** `TEST_P(WebRtcVideoTrackSourceTest, SetsFeedback)` 验证了 `WebRtcVideoTrackSource` 根据 `rtc::VideoSinkWants` 提供反馈的能力，帮助开发者理解如何正确使用这个机制。
   - **用户/编程错误示例:**  一个接收端希望接收低分辨率的视频，但没有设置 `max_pixel_count`，导致发送端仍然发送高分辨率的视频，浪费带宽和计算资源。

总而言之，`webrtc_video_track_source_test.cc` 这个文件通过一系列详尽的单元测试，确保了 `WebRtcVideoTrackSource` 类的各种功能能够正确可靠地运行，这对于保证 WebRTC 视频通信的质量和稳定性至关重要。 这些测试覆盖了从基本的帧传递到复杂的帧处理、元数据管理以及异步操作等多个方面。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/webrtc_video_track_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/peerconnection/webrtc_video_track_source.h"

#include <algorithm>

#include "base/functional/callback_helpers.h"
#include "base/strings/strcat.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "media/base/format_utils.h"
#include "media/base/media_switches.h"
#include "media/base/video_frame.h"
#include "media/video/fake_gpu_memory_buffer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/testing/video_frame_utils.h"
#include "third_party/blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer.h"
#include "third_party/webrtc/api/video/video_frame.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"

using testing::_;
using testing::Invoke;
using testing::Mock;
using testing::Sequence;

namespace blink {

void ExpectUpdateRectEquals(const gfx::Rect& expected,
                            const webrtc::VideoFrame::UpdateRect actual) {
  EXPECT_EQ(expected.x(), actual.offset_x);
  EXPECT_EQ(expected.y(), actual.offset_y);
  EXPECT_EQ(expected.width(), actual.width);
  EXPECT_EQ(expected.height(), actual.height);
}

class MockVideoSink : public rtc::VideoSinkInterface<webrtc::VideoFrame> {
 public:
  MOCK_METHOD1(OnFrame, void(const webrtc::VideoFrame&));
};

TEST(WebRtcVideoTrackSourceRefreshFrameTest, CallsRefreshFrame) {
  bool called = false;
  scoped_refptr<WebRtcVideoTrackSource> track_source =
      new rtc::RefCountedObject<WebRtcVideoTrackSource>(
          /*is_screencast=*/false,
          /*needs_denoising=*/std::nullopt,
          base::BindLambdaForTesting([](const media::VideoCaptureFeedback&) {}),
          base::BindLambdaForTesting([&called] { called = true; }),
          /*gpu_factories=*/nullptr);
  track_source->RequestRefreshFrame();
  EXPECT_TRUE(called);
}

class WebRtcVideoTrackSourceTest
    : public ::testing::TestWithParam<
          std::tuple<media::VideoFrame::StorageType, media::VideoPixelFormat>>,
      public media::FakeGpuMemoryBuffer::MapCallbackController {
 public:
  WebRtcVideoTrackSourceTest()
      : shared_resources_(
            base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(
                /*gpu_factories=*/nullptr)),
        track_source_(new rtc::RefCountedObject<WebRtcVideoTrackSource>(
            /*is_screencast=*/false,
            /*needs_denoising=*/std::nullopt,
            base::BindRepeating(&WebRtcVideoTrackSourceTest::ProcessFeedback,
                                base::Unretained(this)),
            base::BindLambdaForTesting([] {}),
            /*gpu_factories=*/nullptr,
            shared_resources_)) {
    track_source_->AddOrUpdateSink(&mock_sink_, rtc::VideoSinkWants());
  }

  void ProcessFeedback(const media::VideoCaptureFeedback& feedback) {
    feedback_ = feedback;
  }

  ~WebRtcVideoTrackSourceTest() override {
    if (track_source_) {
      track_source_->RemoveSink(&mock_sink_);
    }
  }

  struct FrameParameters {
    const gfx::Size coded_size;
    gfx::Rect visible_rect;
    const gfx::Size natural_size;
    media::VideoFrame::StorageType storage_type;
    media::VideoPixelFormat pixel_format;
  };

  void RegisterCallback(base::OnceCallback<void(bool)> result_cb) override {
    map_callbacks_.push_back(std::move(result_cb));
  }

  void InvokeNextMapCallback() {
    ASSERT_FALSE(map_callbacks_.empty());
    auto cb = std::move(map_callbacks_.front());
    map_callbacks_.pop_front();
    std::move(cb).Run(true);
  }

  void SendTestFrame(const FrameParameters& frame_parameters,
                     base::TimeDelta timestamp) {
    scoped_refptr<media::VideoFrame> frame = CreateTestFrame(
        frame_parameters.coded_size, frame_parameters.visible_rect,
        frame_parameters.natural_size, frame_parameters.storage_type,
        frame_parameters.pixel_format, timestamp);
    track_source_->OnFrameCaptured(frame);
  }

  void SendTestFrameWithMappableGMB(const FrameParameters& frame_parameters,
                                    base::TimeDelta timestamp,
                                    bool premapped) {
    std::unique_ptr<media::FakeGpuMemoryBuffer> fake_gmb =
        std::make_unique<media::FakeGpuMemoryBuffer>(
            frame_parameters.coded_size,
            media::VideoPixelFormatToGfxBufferFormat(
                frame_parameters.pixel_format)
                .value(),
            premapped, this);
    scoped_refptr<media::VideoFrame> frame = CreateTestFrame(
        frame_parameters.coded_size, frame_parameters.visible_rect,
        frame_parameters.natural_size, frame_parameters.storage_type,
        frame_parameters.pixel_format, timestamp, std::move(fake_gmb));
    track_source_->OnFrameCaptured(frame);
  }

  void SendTestFrameAndVerifyFeedback(const FrameParameters& frame_parameters,
                                      int max_pixels,
                                      float max_framerate) {
    scoped_refptr<media::VideoFrame> frame = CreateTestFrame(
        frame_parameters.coded_size, frame_parameters.visible_rect,
        frame_parameters.natural_size, frame_parameters.storage_type,
        frame_parameters.pixel_format, base::TimeDelta());
    track_source_->OnFrameCaptured(frame);
    EXPECT_EQ(feedback_.max_pixels, max_pixels);
    EXPECT_EQ(feedback_.max_framerate_fps, max_framerate);
  }

  void SendTestFrameWithUpdateRect(const FrameParameters& frame_parameters,
                                   int capture_counter,
                                   const gfx::Rect& update_rect) {
    scoped_refptr<media::VideoFrame> frame = CreateTestFrame(
        frame_parameters.coded_size, frame_parameters.visible_rect,
        frame_parameters.natural_size, frame_parameters.storage_type,
        frame_parameters.pixel_format, base::TimeDelta());
    frame->metadata().capture_counter = capture_counter;
    frame->metadata().capture_update_rect = update_rect;
    track_source_->OnFrameCaptured(frame);
  }

  void SendTestFrameWithColorSpace(const FrameParameters& frame_parameters,
                                   const gfx::ColorSpace& color_space) {
    scoped_refptr<media::VideoFrame> frame = CreateTestFrame(
        frame_parameters.coded_size, frame_parameters.visible_rect,
        frame_parameters.natural_size, frame_parameters.storage_type,
        frame_parameters.pixel_format, base::TimeDelta());
    frame->set_color_space(color_space);
    track_source_->OnFrameCaptured(frame);
  }

  WebRtcVideoTrackSource::FrameAdaptationParams FrameAdaptation_KeepAsIs(
      const gfx::Size& natural_size) {
    return WebRtcVideoTrackSource::FrameAdaptationParams{
        false /*should_drop_frame*/,
        0 /*crop_x*/,
        0 /*crop_y*/,
        natural_size.width() /*crop_width*/,
        natural_size.height() /*crop_height*/,
        natural_size.width() /*scale_to_width*/,
        natural_size.height() /*scale_to_height*/
    };
  }

  WebRtcVideoTrackSource::FrameAdaptationParams FrameAdaptation_DropFrame() {
    return WebRtcVideoTrackSource::FrameAdaptationParams{
        true /*should_drop_frame*/,
        0 /*crop_x*/,
        0 /*crop_y*/,
        0 /*crop_width*/,
        0 /*crop_height*/,
        0 /*scale_to_width*/,
        0 /*scale_to_height*/
    };
  }

  WebRtcVideoTrackSource::FrameAdaptationParams FrameAdaptation_Scale(
      const gfx::Size& natural_size,
      const gfx::Size& scale_to_size) {
    return WebRtcVideoTrackSource::FrameAdaptationParams{
        false /*should_drop_frame*/,
        0 /*crop_x*/,
        0 /*crop_y*/,
        natural_size.width() /*crop_width*/,
        natural_size.height() /*crop_height*/,
        scale_to_size.width() /*scale_to_width*/,
        scale_to_size.height() /*scale_to_height*/
    };
  }

  void SetRequireMappedFrame(bool require_mapped_frame) {
    shared_resources_->SetFeedback(
        media::VideoCaptureFeedback().RequireMapped(require_mapped_frame));
  }

 protected:
  MockVideoSink mock_sink_;
  scoped_refptr<WebRtcVideoFrameAdapter::SharedResources> shared_resources_;
  scoped_refptr<WebRtcVideoTrackSource> track_source_;
  media::VideoCaptureFeedback feedback_;
  WTF::Deque<base::OnceCallback<void(bool)>> map_callbacks_;
};

namespace {
std::vector<WebRtcVideoTrackSourceTest::ParamType> TestParams() {
  std::vector<WebRtcVideoTrackSourceTest::ParamType> test_params;
  // All formats for owned memory.
  for (media::VideoPixelFormat format :
       GetPixelFormatsMappableToWebRtcVideoFrameBuffer()) {
    test_params.emplace_back(
        media::VideoFrame::StorageType::STORAGE_OWNED_MEMORY, format);
  }
  test_params.emplace_back(
      media::VideoFrame::StorageType::STORAGE_GPU_MEMORY_BUFFER,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12);
  test_params.emplace_back(media::VideoFrame::STORAGE_OPAQUE,
                           media::VideoPixelFormat::PIXEL_FORMAT_NV12);
  return test_params;
}
}  // namespace

// Tests that the two generated test frames are received in sequence and have
// correct |capture_time_identifier| set in webrtc::VideoFrame.
TEST_P(WebRtcVideoTrackSourceTest, TestTimestamps) {
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(640, 480),
      .visible_rect = gfx::Rect(0, 60, 640, 360),
      .natural_size = gfx::Size(640, 360),
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};

  Sequence s;
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .InSequence(s)
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ASSERT_TRUE(frame.capture_time_identifier().has_value());
        EXPECT_EQ(frame.capture_time_identifier().value().us(), 0);
      }));
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .InSequence(s)
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ASSERT_TRUE(frame.capture_time_identifier().has_value());
        EXPECT_EQ(frame.capture_time_identifier().value().us(), 16666);
      }));
  SendTestFrame(frame_parameters, base::Seconds(0));
  const float kFps = 60.0;
  SendTestFrame(frame_parameters, base::Seconds(1 / kFps));
}

TEST_P(WebRtcVideoTrackSourceTest, CropFrameTo640360) {
  const gfx::Size kNaturalSize(640, 360);
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(640, 480),
      .visible_rect = gfx::Rect(0, 60, 640, 360),
      .natural_size = kNaturalSize,
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};

  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_KeepAsIs(kNaturalSize));

  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([kNaturalSize](const webrtc::VideoFrame& frame) {
        EXPECT_EQ(kNaturalSize.width(), frame.width());
        EXPECT_EQ(kNaturalSize.height(), frame.height());
      }));
  SendTestFrame(frame_parameters, base::TimeDelta());
}

TEST_P(WebRtcVideoTrackSourceTest, TestColorSpaceSettings) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      /* enabled_features*/ {media::kWebRTCColorAccuracy},
      /* disabled_features*/ {});
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(640, 480),
      .visible_rect = gfx::Rect(0, 60, 640, 360),
      .natural_size = gfx::Size(640, 360),
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};

  Sequence s;

  EXPECT_CALL(mock_sink_, OnFrame(_))
      .InSequence(s)
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ASSERT_TRUE(frame.color_space().has_value());
        EXPECT_EQ(frame.color_space().value().matrix(),
                  webrtc::ColorSpace::MatrixID::kSMPTE170M);
        EXPECT_EQ(frame.color_space().value().transfer(),
                  webrtc::ColorSpace::TransferID::kBT709);
        EXPECT_EQ(frame.color_space().value().primaries(),
                  webrtc::ColorSpace::PrimaryID::kBT709);
        EXPECT_EQ(frame.color_space().value().range(),
                  webrtc::ColorSpace::RangeID::kLimited);
      }));
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .InSequence(s)
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ASSERT_TRUE(frame.color_space().has_value());
        EXPECT_EQ(frame.color_space().value().matrix(),
                  webrtc::ColorSpace::MatrixID::kBT709);
        EXPECT_EQ(frame.color_space().value().transfer(),
                  webrtc::ColorSpace::TransferID::kBT709);
        EXPECT_EQ(frame.color_space().value().primaries(),
                  webrtc::ColorSpace::PrimaryID::kBT709);
        EXPECT_EQ(frame.color_space().value().range(),
                  webrtc::ColorSpace::RangeID::kFull);
      }));

  // For default REC709{BT709,BT709,BT709,Limited}, we will not set color space
  // and transmit it by RTP since decoder side would guess it if color space is
  // invalid.
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .InSequence(s)
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ASSERT_FALSE(frame.color_space().has_value());
      }));

  gfx::ColorSpace color_range_limited(
      gfx::ColorSpace::PrimaryID::BT709, gfx::ColorSpace::TransferID::BT709,
      gfx::ColorSpace::MatrixID::SMPTE170M, gfx::ColorSpace::RangeID::LIMITED);
  SendTestFrameWithColorSpace(frame_parameters, color_range_limited);

  gfx::ColorSpace color_range_full(
      gfx::ColorSpace::PrimaryID::BT709, gfx::ColorSpace::TransferID::BT709,
      gfx::ColorSpace::MatrixID::BT709, gfx::ColorSpace::RangeID::FULL);
  SendTestFrameWithColorSpace(frame_parameters, color_range_full);

  gfx::ColorSpace default_bt709_color_space(
      gfx::ColorSpace::PrimaryID::BT709, gfx::ColorSpace::TransferID::BT709,
      gfx::ColorSpace::MatrixID::BT709, gfx::ColorSpace::RangeID::LIMITED);
  SendTestFrameWithColorSpace(frame_parameters, default_bt709_color_space);
}

TEST_P(WebRtcVideoTrackSourceTest, SetsFeedback) {
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(640, 480),
      .visible_rect = gfx::Rect(0, 60, 640, 360),
      .natural_size = gfx::Size(640, 360),
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};
  const gfx::Size kScaleToSize = gfx::Size(320, 180);
  const float k5Fps = 5.0;

  rtc::VideoSinkWants sink_wants;
  sink_wants.max_pixel_count = kScaleToSize.GetArea();
  sink_wants.max_framerate_fps = static_cast<int>(k5Fps);
  track_source_->SetSinkWantsForTesting(sink_wants);

  EXPECT_CALL(mock_sink_, OnFrame(_));
  SendTestFrameAndVerifyFeedback(frame_parameters, kScaleToSize.GetArea(),
                                 k5Fps);
}

TEST_P(WebRtcVideoTrackSourceTest, CropFrameTo320320) {
  const gfx::Size kNaturalSize(320, 320);
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(640, 480),
      .visible_rect = gfx::Rect(80, 0, 480, 480),
      .natural_size = kNaturalSize,
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};

  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_KeepAsIs(kNaturalSize));

  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([kNaturalSize](const webrtc::VideoFrame& frame) {
        EXPECT_EQ(kNaturalSize.width(), frame.width());
        EXPECT_EQ(kNaturalSize.height(), frame.height());
      }));
  SendTestFrame(frame_parameters, base::TimeDelta());
}

TEST_P(WebRtcVideoTrackSourceTest, Scale720To640360) {
  const gfx::Size kNaturalSize(640, 360);
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(1280, 720),
      .visible_rect = gfx::Rect(0, 0, 1280, 720),
      .natural_size = kNaturalSize,
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};
  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_KeepAsIs(kNaturalSize));

  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([kNaturalSize](const webrtc::VideoFrame& frame) {
        EXPECT_EQ(kNaturalSize.width(), frame.width());
        EXPECT_EQ(kNaturalSize.height(), frame.height());
      }));
  SendTestFrame(frame_parameters, base::TimeDelta());
}

TEST_P(WebRtcVideoTrackSourceTest, UpdateRectWithNoTransform) {
  const gfx::Rect kVisibleRect(0, 0, 640, 480);
  FrameParameters frame_parameters = {.coded_size = gfx::Size(640, 480),
                                      .visible_rect = kVisibleRect,
                                      .natural_size = gfx::Size(640, 480),
                                      .storage_type = std::get<0>(GetParam()),
                                      .pixel_format = std::get<1>(GetParam())};
  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_KeepAsIs(frame_parameters.natural_size));

  // Any UPDATE_RECT for the first received frame is expected to get
  // ignored and the full frame should be marked as updated.
  const gfx::Rect kUpdateRect1(1, 2, 3, 4);
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(gfx::Rect(0, 0, frame.width(), frame.height()),
                               frame.update_rect());
      }));
  int capture_counter = 101;  // arbitrary absolute value
  SendTestFrameWithUpdateRect(frame_parameters, capture_counter, kUpdateRect1);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // Update rect for second frame should get passed along.
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([kUpdateRect1](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(kUpdateRect1, frame.update_rect());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect1);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // Simulate the next frame getting dropped
  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_DropFrame());
  const gfx::Rect kUpdateRect2(2, 3, 4, 5);
  EXPECT_CALL(mock_sink_, OnFrame(_)).Times(0);
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect2);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // The |update_rect| for the next frame is expected to contain the union
  // of the current an previous |update_rects|.
  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_KeepAsIs(frame_parameters.natural_size));
  const gfx::Rect kUpdateRect3(3, 4, 5, 6);
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(
          Invoke([kUpdateRect2, kUpdateRect3](const webrtc::VideoFrame& frame) {
            gfx::Rect expected_update_rect(kUpdateRect2);
            expected_update_rect.Union(kUpdateRect3);
            ExpectUpdateRectEquals(expected_update_rect, frame.update_rect());
          }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect3);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // Simulate a gap in |capture_counter|. This is expected to cause the whole
  // frame to get marked as updated.
  ++capture_counter;
  const gfx::Rect kUpdateRect4(4, 5, 6, 7);
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([kVisibleRect](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(kVisibleRect, frame.update_rect());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect4);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // Important edge case (expected to be fairly common): An empty update rect
  // indicates that nothing has changed.
  const gfx::Rect kEmptyRectWithZeroOrigin(0, 0, 0, 0);
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        EXPECT_TRUE(frame.update_rect().IsEmpty());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kEmptyRectWithZeroOrigin);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  const gfx::Rect kEmptyRectWithNonZeroOrigin(10, 20, 0, 0);
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        EXPECT_TRUE(frame.update_rect().IsEmpty());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kEmptyRectWithNonZeroOrigin);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // A frame without a CAPTURE_COUNTER and CAPTURE_UPDATE_RECT is treated as the
  // whole content having changed.
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([kVisibleRect](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(kVisibleRect, frame.update_rect());
      }));
  SendTestFrame(frame_parameters, base::TimeDelta());
  Mock::VerifyAndClearExpectations(&mock_sink_);
}

TEST_P(WebRtcVideoTrackSourceTest, UpdateRectWithCropFromUpstream) {
  const gfx::Rect kVisibleRect(100, 50, 200, 80);
  FrameParameters frame_parameters = {.coded_size = gfx::Size(640, 480),
                                      .visible_rect = kVisibleRect,
                                      .natural_size = gfx::Size(200, 80),
                                      .storage_type = std::get<0>(GetParam()),
                                      .pixel_format = std::get<1>(GetParam())};
  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_KeepAsIs(frame_parameters.natural_size));

  // Any UPDATE_RECT for the first received frame is expected to get
  // ignored and the full frame should be marked as updated.
  const gfx::Rect kUpdateRect1(120, 70, 160, 40);
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(gfx::Rect(0, 0, frame.width(), frame.height()),
                               frame.update_rect());
      }));
  int capture_counter = 101;  // arbitrary absolute value
  SendTestFrameWithUpdateRect(frame_parameters, capture_counter, kUpdateRect1);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // Update rect for second frame should get passed along.
  // Update rect fully contained in crop region.
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(
          Invoke([kUpdateRect1, kVisibleRect](const webrtc::VideoFrame& frame) {
            gfx::Rect expected_update_rect(kUpdateRect1);
            expected_update_rect.Offset(-kVisibleRect.x(), -kVisibleRect.y());
            ExpectUpdateRectEquals(expected_update_rect, frame.update_rect());
          }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect1);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // Update rect outside crop region.
  const gfx::Rect kUpdateRect2(2, 3, 4, 5);
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        EXPECT_TRUE(frame.update_rect().IsEmpty());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect2);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // Update rect partly overlapping crop region.
  const gfx::Rect kUpdateRect3(kVisibleRect.x() + 10, kVisibleRect.y() + 8,
                               kVisibleRect.width(), kVisibleRect.height());
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([kVisibleRect](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(gfx::Rect(10, 8, kVisibleRect.width() - 10,
                                         kVisibleRect.height() - 8),
                               frame.update_rect());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect3);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // When crop origin changes, the whole frame is expected to be marked as
  // changed.
  const gfx::Rect kVisibleRect2(kVisibleRect.x() + 1, kVisibleRect.y(),
                                kVisibleRect.width(), kVisibleRect.height());
  frame_parameters.visible_rect = kVisibleRect2;
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(gfx::Rect(0, 0, frame.width(), frame.height()),
                               frame.update_rect());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect1);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // When crop size changes, the whole frame is expected to be marked as
  // changed.
  const gfx::Rect kVisibleRect3(kVisibleRect2.x(), kVisibleRect2.y(),
                                kVisibleRect2.width(),
                                kVisibleRect2.height() - 1);
  frame_parameters.visible_rect = kVisibleRect3;
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(gfx::Rect(0, 0, frame.width(), frame.height()),
                               frame.update_rect());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect1);
  Mock::VerifyAndClearExpectations(&mock_sink_);
}

TEST_P(WebRtcVideoTrackSourceTest, UpdateRectWithScaling) {
  const gfx::Size kNaturalSize = gfx::Size(200, 80);
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(640, 480),
      .visible_rect = gfx::Rect(100, 50, 200, 80),
      .natural_size = kNaturalSize,
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};
  const gfx::Size kScaleToSize = gfx::Size(120, 50);
  if (frame_parameters.storage_type == media::VideoFrame::STORAGE_OPAQUE) {
    // Texture has no cropping support yet http://crbug/503653.
    return;
  }
  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_Scale(kNaturalSize, kScaleToSize));

  // Any UPDATE_RECT for the first received frame is expected to get
  // ignored and no update rect should be set.
  const gfx::Rect kUpdateRect1(120, 70, 160, 40);
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        EXPECT_FALSE(frame.has_update_rect());
      }));
  int capture_counter = 101;  // arbitrary absolute value
  SendTestFrameWithUpdateRect(frame_parameters, capture_counter, kUpdateRect1);
  Mock::VerifyAndClearExpectations(&mock_sink_);

  // When scaling is applied and UPDATE_RECT is not empty, we scale the
  // update rect.
  // Calculated by hand according to KNaturalSize and KScaleToSize.
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        ExpectUpdateRectEquals(gfx::Rect(10, 10, 100, 30), frame.update_rect());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter,
                              kUpdateRect1);

  // When UPDATE_RECT is empty, we expect to deliver an empty UpdateRect even if
  // scaling is applied.
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        EXPECT_TRUE(frame.update_rect().IsEmpty());
      }));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter, gfx::Rect());

  // When UPDATE_RECT is empty, but the scaling has changed, we expect to
  // deliver no known update_rect.
  EXPECT_CALL(mock_sink_, OnFrame(_))
      .WillOnce(Invoke([](const webrtc::VideoFrame& frame) {
        EXPECT_FALSE(frame.has_update_rect());
      }));
  const gfx::Size kScaleToSize2 = gfx::Size(60, 26);
  track_source_->SetCustomFrameAdaptationParamsForTesting(
      FrameAdaptation_Scale(kNaturalSize, kScaleToSize2));
  SendTestFrameWithUpdateRect(frame_parameters, ++capture_counter, gfx::Rect());

  Mock::VerifyAndClearExpectations(&mock_sink_);
}

TEST_P(WebRtcVideoTrackSourceTest, PassesMappedFramesInOrder) {
  base::test::SingleThreadTaskEnvironment task_environment;
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(640, 480),
      .visible_rect = gfx::Rect(0, 60, 640, 360),
      .natural_size = gfx::Size(640, 360),
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};
  if (frame_parameters.storage_type !=
      media::VideoFrame::StorageType::STORAGE_GPU_MEMORY_BUFFER) {
    // Mapping is only valid for GMB backed frames.
    return;
  }
  constexpr int kSentFrames = 10;
  Sequence s;
  for (int i = 0; i < kSentFrames; ++i) {
    EXPECT_CALL(mock_sink_, OnFrame(_))
        .InSequence(s)
        .WillOnce(Invoke([=](const webrtc::VideoFrame& frame) {
          EXPECT_EQ(frame.capture_time_identifier().value().us(), 1000000 * i);
        }));
  }

  SetRequireMappedFrame(false);
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(0),
                               /*premapped=*/false);

  SetRequireMappedFrame(true);
  // This will be the 1st async frame.
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(1),
                               /*premapped=*/false);

  SetRequireMappedFrame(true);
  // This will be the 2nd async frame.
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(2),
                               /*premapped=*/false);

  SetRequireMappedFrame(true);
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(3),
                               /*premapped=*/true);

  // This will return the 1st async frame.
  InvokeNextMapCallback();

  SetRequireMappedFrame(true);
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(4),
                               /*premapped=*/true);

  SetRequireMappedFrame(true);
  // This will be the 3rd async frame.
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(5),
                               /*premapped=*/false);

  SetRequireMappedFrame(false);
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(6),
                               /*premapped=*/false);

  // This will return the 2nd async frame.
  InvokeNextMapCallback();

  SetRequireMappedFrame(true);
  // This will be the 4th async frame.
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(7),
                               /*premapped=*/false);

  // This will return the 3rd async frame.
  InvokeNextMapCallback();

  // This will return the 4th async frame.
  InvokeNextMapCallback();

  SetRequireMappedFrame(true);
  // This will be the 5th async frame.
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(8),
                               /*premapped=*/false);

  SetRequireMappedFrame(true);
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(9),
                               /*premapped=*/true);

  // This will return the 5th async frame.
  InvokeNextMapCallback();
}

TEST_P(WebRtcVideoTrackSourceTest, DoesntCrashOnLateCallbacks) {
  base::test::SingleThreadTaskEnvironment task_environment;
  FrameParameters frame_parameters = {
      .coded_size = gfx::Size(640, 480),
      .visible_rect = gfx::Rect(0, 60, 640, 360),
      .natural_size = gfx::Size(640, 360),
      .storage_type = std::get<0>(GetParam()),
      .pixel_format = std::get<1>(GetParam())};
  if (frame_parameters.storage_type !=
      media::VideoFrame::StorageType::STORAGE_GPU_MEMORY_BUFFER) {
    // Mapping is only valid for GMB backed frames.
    return;
  }

  SetRequireMappedFrame(true);
  SendTestFrameWithMappableGMB(frame_parameters, base::Seconds(0),
                               /*premapped=*/false);

  track_source_->Dispose();
  track_source_->RemoveSink(&mock_sink_);
  track_source_.reset();

  InvokeNextMapCallback();
}

INSTANTIATE_TEST_SUITE_P(
    WebRtcVideoTrackSourceTest,
    WebRtcVideoTrackSourceTest,
    testing::ValuesIn(TestParams()),
    [](const auto& info) {
      return base::StrCat(
          {media::VideoFrame::StorageTypeToString(std::get<0>(info.param)), "_",
           media::VideoPixelFormatToString(std::get<1>(info.param))});
    });

}  // namespace blink

"""

```