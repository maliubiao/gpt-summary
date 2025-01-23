Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The first and most crucial step is recognizing this is a *unit test* file (`*_unittest.cc`). This immediately tells us its primary function: to test the functionality of another C++ class. The filename `canvas_capture_handler_unittest.cc` strongly suggests it's testing the `CanvasCaptureHandler` class.

2. **Identify the Target Class:**  The `#include` directives at the beginning confirm this. Specifically, `#include "third_party/blink/renderer/modules/mediacapturefromelement/canvas_capture_handler.h"` tells us the class being tested is `CanvasCaptureHandler`.

3. **Infer the Target Class's Purpose:** The namespace `blink::modules::mediacapturefromelement` gives a strong hint about the `CanvasCaptureHandler`'s responsibilities. It's likely involved in capturing content from a `<canvas>` element and making it available for media streams (like video).

4. **Analyze the Test Structure:** Unit tests in Google Test (gtest) typically follow a pattern:
    * **Test Fixture:** A class derived from `::testing::Test` or `::testing::TestWithParam` (like `CanvasCaptureHandlerTest` here). This sets up common resources and provides helper functions for the tests.
    * **Individual Tests:** Functions using the `TEST_F` or `TEST_P` macros, each focusing on a specific aspect of the target class.
    * **Assertions:**  Macros like `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_NEAR`, and `ASSERT_EQ` to verify the behavior of the code under test.
    * **Mocking (Optional):**  Using a mocking framework like Google Mock (gmock) to simulate dependencies of the target class. We see this with `MOCK_METHOD2` and the `DoOnDeliverFrame` function.

5. **Examine Individual Tests:** Go through each `TEST_F` or `TEST_P` to understand what it's testing.
    * **`ConstructAndDestruct`:**  Basic test to ensure the object can be created and destroyed without errors.
    * **`DestructTrack` and `DestructHandler`:** Test different scenarios for destruction involving related objects (`component_`).
    * **`GetFormatsStartAndStop`:** Tests the lifecycle of capturing: getting supported formats, starting capture, receiving a frame, and stopping. The `InSequence` keyword suggests it's testing the order of calls.
    * **`VerifyFrame`:** Tests that captured frames have the expected properties (size, pixel format, color). The use of `TEST_P` indicates this test is parameterized to run with different inputs (opaque/transparent, different sizes).
    * **`DropAlphaDeliversOpaqueFrame`:**  Specifically tests the scenario where alpha is dropped, resulting in an opaque video frame.
    * **`CheckNeedsNewFrame`:** Tests a specific method (`NeedsNewFrame`) related to whether the handler requires a new frame to process.

6. **Identify Key Dependencies and Interactions:** Look for interactions with other classes or components:
    * `StaticBitmapImageToVideoFrameCopier`:  Responsible for converting `SkImage` (from the canvas) to `media::VideoFrame`.
    * `MediaStreamComponent`: Represents a media stream track.
    * `MediaStreamVideoCapturerSource`:  A source of video for media streams.
    * `VideoCapturerSource`:  The underlying interface for capturing video.
    * `SkImage`, `SkBitmap`: Skia graphics library classes representing the canvas content.
    * `media::VideoFrame`: The standard representation of video frames in Chromium.

7. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Now, relate the C++ code to web technologies.
    * **`<canvas>` element:** The `CanvasCaptureHandler` directly interacts with the content of a `<canvas>` element. JavaScript drawing operations on the canvas are what ultimately generate the `SkImage` that gets captured.
    * **`captureStream()` method:** This JavaScript method on the `<canvas>` element is the entry point for using `CanvasCaptureHandler`.
    * **`MediaStream` API:** The captured content is provided as a `MediaStreamTrack`, which can be used with other WebRTC APIs or recorded.

8. **Consider User Actions and Debugging:** Think about how a developer might end up in this code during debugging:
    * A website using `canvas.captureStream()` might encounter issues with the captured video.
    * A Chromium developer working on the media capture implementation might be writing or debugging this code.
    * Breakpoints in the `CanvasCaptureHandler` or related classes would lead here.

9. **Infer Logic and Assumptions:** Based on the test names and assertions, deduce the logic being tested. For example, the `VerifyFrame` test assumes that converting a specific `SkBitmap` will result in a `media::VideoFrame` with particular color values after conversion to I420 or I420A.

10. **Structure the Explanation:**  Organize the findings into clear categories (functionality, relation to web technologies, logic, user errors, debugging). Use examples to illustrate the connections and make the explanation easier to understand.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This tests how canvas content is captured."  **Refinement:**  Be more specific. It tests the `CanvasCaptureHandler` class, which is *part of* the canvas capture mechanism.
* **Initial thought:** "It handles video frames." **Refinement:** It handles the *conversion* of canvas content (as `SkImage`) into `media::VideoFrame` objects.
* **While looking at mocking:** Recognize the importance of the `VideoCapturerSource` interface and how the tests interact with it via mock expectations.

By following this kind of structured analysis, we can effectively understand the purpose and functionality of even complex C++ unit test files within a large project like Chromium.
这个C++文件 `canvas_capture_handler_unittest.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `CanvasCaptureHandler` 类的功能。 `CanvasCaptureHandler` 的主要职责是将 HTML `<canvas>` 元素的内容捕获为视频帧，以便用于例如 `MediaStream` API。

以下是该文件的功能列表，以及与 JavaScript, HTML, CSS 的关系说明，逻辑推理，常见错误和调试线索：

**文件功能:**

1. **单元测试 `CanvasCaptureHandler` 类:** 该文件包含了多个测试用例，用于验证 `CanvasCaptureHandler` 类的各种功能是否按预期工作。
2. **测试帧的捕获和传递:** 测试用例模拟 `<canvas>` 元素的绘制，并验证 `CanvasCaptureHandler` 是否正确地捕获这些帧，并将其转换为 `media::VideoFrame` 对象。
3. **测试帧的元数据:**  测试用例检查捕获到的视频帧的属性，例如尺寸、像素格式（是否包含 Alpha 通道）、颜色值等。
4. **测试启动和停止捕获:**  测试用例验证启动和停止 `CanvasCaptureHandler` 的捕获过程是否正确。
5. **测试 `needsNewFrame()` 方法:**  验证 `CanvasCaptureHandler` 何时需要新的帧进行处理。
6. **测试 Alpha 通道的处理:**  测试用例检查 `CanvasCaptureHandler` 在处理包含 Alpha 通道的画布内容时的行为，包括是否可以丢弃 Alpha 通道。
7. **模拟 `VideoCapturerSource` 的行为:**  使用 Google Mock 框架模拟 `VideoCapturerSource` 的回调，以验证 `CanvasCaptureHandler` 与其交互是否正确。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML (`<canvas>` 元素):** `CanvasCaptureHandler` 的核心功能是捕获 HTML `<canvas>` 元素的内容。在 HTML 中，开发者可以使用 `<canvas>` 标签创建一个用于动态渲染图形的区域。
    ```html
    <canvas id="myCanvas" width="320" height="240"></canvas>
    ```
* **JavaScript (Canvas API, `captureStream()` 方法):** JavaScript 用于在 `<canvas>` 元素上进行绘制操作。  `CanvasCaptureHandler` 的工作是在 JavaScript 调用 `canvas.captureStream()` 方法时启动的。`captureStream()` 方法会返回一个 `MediaStream` 对象，其中包含由 `CanvasCaptureHandler` 提供的视频轨道。
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const stream = canvas.captureStream();
    const videoTrack = stream.getVideoTracks()[0];
    ```
* **CSS (影响 Canvas 的渲染):** CSS 可以影响 `<canvas>` 元素的尺寸和样式，但这通常不会直接影响 `CanvasCaptureHandler` 捕获的帧内容。`CanvasCaptureHandler` 主要关注的是画布上绘制的像素数据。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个在 `<canvas>` 元素上绘制了红色方块的 `SkImage` 对象，画布尺寸为 100x100，不透明。
* **预期输出:** `CanvasCaptureHandler` 将会产生一个 `media::VideoFrame` 对象，其尺寸为 100x100，像素格式为 `PIXEL_FORMAT_I420` (因为是不透明的)，并且帧数据中代表红色的颜色分量具有相应的数值。  测试用例中的 `OnVerifyDeliveredFrame` 方法会检查这些属性。

* **假设输入:** 一个在 `<canvas>` 元素上绘制了半透明蓝色圆形的 `SkImage` 对象，画布尺寸为 50x50，包含 Alpha 通道。
* **预期输出:**  如果 `CanvasCaptureHandler` 没有被设置为丢弃 Alpha 通道，它将产生一个 `media::VideoFrame` 对象，像素格式为 `PIXEL_FORMAT_I420A`，并且 Alpha 通道的值将对应于蓝色圆形的半透明度。如果设置了丢弃 Alpha 通道，则输出的帧格式可能是 `PIXEL_FORMAT_I420`，并且蓝色将变为完全不透明。

**用户或编程常见的使用错误:**

1. **未调用 `captureStream()`:** 用户需要在 JavaScript 中调用 `<canvas>` 元素的 `captureStream()` 方法才能触发 `CanvasCaptureHandler` 的工作。如果忘记调用此方法，将不会有任何视频帧被捕获。
    ```javascript
    // 错误示例：忘记调用 captureStream()
    const canvas = document.getElementById('myCanvas');
    // ... 在 canvas 上绘制 ...
    // 缺少 canvas.captureStream()
    ```
2. **在画布上绘制后立即捕获:**  有时，用户可能会在画布上进行绘制操作后立即尝试捕获，但渲染可能尚未完成。这可能导致捕获到不完整的帧。应该确保绘制操作完成后再调用 `captureStream()` 或在捕获时考虑到可能的渲染延迟。
3. **错误地配置 `captureStream()` 的帧率:** `captureStream()` 方法可以接受一个配置对象来指定帧率。如果帧率设置不当，可能会导致性能问题或捕获到的视频不流畅。
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const stream = canvas.captureStream(30); // 设置帧率为 30fps
    ```
4. **期望捕获 CSS 样式:**  `CanvasCaptureHandler` 主要捕获的是画布上绘制的像素数据，而不是 CSS 样式。如果用户期望捕获应用到画布上的 CSS 效果，可能会得到不符合预期的结果。
5. **在没有激活的 `MediaStreamTrack` 的情况下期望捕获:**  `CanvasCaptureHandler` 生成的视频帧会通过 `MediaStreamTrack` 传递。如果 `MediaStreamTrack` 没有被正确使用（例如，没有连接到 `MediaStream` 或没有被启用），则可能看不到捕获的帧。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在网页上使用 `<canvas>` 元素并通过 `captureStream()` 方法获取了视频流，但发现捕获到的视频内容有问题（例如，帧率不正确，内容缺失，颜色错误）。作为调试线索，可以按照以下步骤追踪到 `canvas_capture_handler_unittest.cc`：

1. **用户报告问题:** 用户观察到 canvas 捕获的视频流存在异常。
2. **开发者检查 JavaScript 代码:** 开发者首先会检查 JavaScript 代码中关于 `<canvas>` 绘制和 `captureStream()` 的使用，确保逻辑正确，参数设置合理。
3. **怀疑是 Blink 渲染引擎的问题:** 如果 JavaScript 代码没有明显错误，开发者可能会怀疑是浏览器渲染引擎在处理 canvas 捕获时出现了问题。
4. **搜索相关 Blink 代码:**  开发者可能会搜索 Blink 引擎中与 "canvas capture" 或 "captureStream" 相关的代码。 `CanvasCaptureHandler` 是一个关键的组件，因此会找到 `canvas_capture_handler.cc` 和其对应的测试文件 `canvas_capture_handler_unittest.cc`。
5. **查看单元测试:** 开发者会查看 `canvas_capture_handler_unittest.cc` 中的测试用例，了解 `CanvasCaptureHandler` 应该如何工作，以及测试覆盖了哪些方面。
6. **运行本地测试:** 开发者可能会尝试在本地编译并运行这些单元测试，以验证 `CanvasCaptureHandler` 的基本功能是否正常。
7. **调试 Blink 代码:** 如果单元测试通过，但用户仍然遇到问题，开发者可能需要深入到 `canvas_capture_handler.cc` 的代码中进行调试，例如设置断点，查看帧数据的处理流程，以及与 `VideoCapturerSource` 的交互。
8. **检查 Chromium 的 Media Pipeline:**  如果问题涉及到更底层的视频处理，开发者可能需要查看 Chromium 的 Media Pipeline 中与视频捕获相关的其他组件。
9. **分析崩溃或错误日志:**  如果捕获过程中发生崩溃或出现错误，相关的日志信息可能会提供关于问题发生位置的线索，有可能指向 `CanvasCaptureHandler` 或其依赖的模块。

总之，`canvas_capture_handler_unittest.cc` 文件对于理解和调试 Chromium Blink 引擎中 canvas 捕获功能的实现至关重要。它提供了关于 `CanvasCaptureHandler` 类预期行为的清晰示例，并可以作为开发和调试过程中的参考。

### 提示词
```
这是目录为blink/renderer/modules/mediacapturefromelement/canvas_capture_handler_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/mediacapturefromelement/canvas_capture_handler.h"

#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/test/gmock_callback_support.h"
#include "media/base/limits.h"
#include "media/base/video_frame_converter.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_capturer_source.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image_to_video_frame_copier.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/video_capture/video_capturer_source.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "ui/gfx/geometry/size.h"

using base::test::RunOnceClosure;
using ::testing::_;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::SaveArg;
using ::testing::Test;
using ::testing::TestWithParam;

namespace blink {

namespace {

static const int kTestCanvasCaptureWidth = 320;
static const int kTestCanvasCaptureHeight = 240;
static const double kTestCanvasCaptureFramesPerSecond = 55.5;

static const int kTestCanvasCaptureFrameEvenSize = 2;
static const int kTestCanvasCaptureFrameOddSize = 3;
static const int kTestCanvasCaptureFrameColorErrorTolerance = 2;
static const int kTestAlphaValue = 175;

}  // namespace

class CanvasCaptureHandlerTest
    : public TestWithParam<testing::tuple<bool, int, int>> {
 public:
  CanvasCaptureHandlerTest() = default;

  CanvasCaptureHandlerTest(const CanvasCaptureHandlerTest&) = delete;
  CanvasCaptureHandlerTest& operator=(const CanvasCaptureHandlerTest&) = delete;

  void SetUp() override {
    MediaStreamComponent* component = nullptr;
    copier_ = std::make_unique<StaticBitmapImageToVideoFrameCopier>(
        /*allow_accelerated_frame_pool=*/false);
    canvas_capture_handler_ = CanvasCaptureHandler::CreateCanvasCaptureHandler(
        /*LocalFrame =*/nullptr,
        gfx::Size(kTestCanvasCaptureWidth, kTestCanvasCaptureHeight),
        kTestCanvasCaptureFramesPerSecond,
        scheduler::GetSingleThreadTaskRunnerForTesting(),
        scheduler::GetSingleThreadTaskRunnerForTesting(), &component);
    component_ = component;
  }

  void TearDown() override {
    component_ = nullptr;
    blink::WebHeap::CollectAllGarbageForTesting();
    canvas_capture_handler_.reset();

    // Let the message loop run to finish destroying the capturer.
    base::RunLoop().RunUntilIdle();
  }

  // Necessary callbacks and MOCK_METHODS for VideoCapturerSource.
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

  // Verify returned frames.
  static scoped_refptr<StaticBitmapImage> GenerateTestImage(bool opaque,
                                                            int width,
                                                            int height) {
    SkImageInfo info = SkImageInfo::MakeN32(
        width, height, opaque ? kOpaque_SkAlphaType : kPremul_SkAlphaType,
        SkColorSpace::MakeSRGB());
    SkBitmap testBitmap;
    testBitmap.allocPixels(info);
    testBitmap.eraseARGB(opaque ? 255 : kTestAlphaValue, 30, 60, 200);
    return UnacceleratedStaticBitmapImage::Create(
        SkImages::RasterFromBitmap(testBitmap));
  }

  void OnVerifyDeliveredFrame(
      bool opaque,
      int expected_width,
      int expected_height,
      scoped_refptr<media::VideoFrame> video_frame,
      base::TimeTicks estimated_capture_time) {
    if (video_frame->format() != media::PIXEL_FORMAT_I420 &&
        video_frame->format() != media::PIXEL_FORMAT_I420A) {
      auto size = video_frame->visible_rect().size();
      auto converted_format =
          opaque ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A;
      auto i420_frame = media::VideoFrame::CreateFrame(
          converted_format, size, gfx::Rect(size), size,
          video_frame->timestamp());
      auto status = converter_.ConvertAndScale(*video_frame, *i420_frame);
      EXPECT_TRUE(status.is_ok());
      video_frame = i420_frame;
    }

    if (opaque)
      EXPECT_EQ(media::PIXEL_FORMAT_I420, video_frame->format());
    else
      EXPECT_EQ(media::PIXEL_FORMAT_I420A, video_frame->format());

    const gfx::Size& size = video_frame->visible_rect().size();
    EXPECT_EQ(expected_width, size.width());
    EXPECT_EQ(expected_height, size.height());
    const uint8_t* y_plane =
        video_frame->visible_data(media::VideoFrame::Plane::kY);
    EXPECT_NEAR(74, y_plane[0], kTestCanvasCaptureFrameColorErrorTolerance);
    const uint8_t* u_plane =
        video_frame->visible_data(media::VideoFrame::Plane::kU);
    EXPECT_NEAR(193, u_plane[0], kTestCanvasCaptureFrameColorErrorTolerance);
    const uint8_t* v_plane =
        video_frame->visible_data(media::VideoFrame::Plane::kV);
    EXPECT_NEAR(105, v_plane[0], kTestCanvasCaptureFrameColorErrorTolerance);
    if (!opaque) {
      const uint8_t* a_plane =
          video_frame->visible_data(media::VideoFrame::Plane::kA);
      EXPECT_EQ(kTestAlphaValue, a_plane[0]);
    }
  }

  test::TaskEnvironment task_environment_;
  Persistent<MediaStreamComponent> component_;
  std::unique_ptr<StaticBitmapImageToVideoFrameCopier> copier_;
  // The Class under test. Needs to be scoped_ptr to force its destruction.
  std::unique_ptr<CanvasCaptureHandler> canvas_capture_handler_;
  media::VideoFrameConverter converter_;

 protected:
  VideoCapturerSource* GetVideoCapturerSource(
      blink::MediaStreamVideoCapturerSource* ms_source) {
    return ms_source->GetSourceForTesting();
  }

  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
};

// Checks that the initialization-destruction sequence works fine.
TEST_F(CanvasCaptureHandlerTest, ConstructAndDestruct) {
  EXPECT_TRUE(canvas_capture_handler_->NeedsNewFrame());
  base::RunLoop().RunUntilIdle();
}

// Checks that the destruction sequence works fine.
TEST_F(CanvasCaptureHandlerTest, DestructTrack) {
  EXPECT_TRUE(canvas_capture_handler_->NeedsNewFrame());
  component_ = nullptr;
  base::RunLoop().RunUntilIdle();
}

// Checks that the destruction sequence works fine.
TEST_F(CanvasCaptureHandlerTest, DestructHandler) {
  EXPECT_TRUE(canvas_capture_handler_->NeedsNewFrame());
  canvas_capture_handler_.reset();
  base::RunLoop().RunUntilIdle();
}

// Checks that VideoCapturerSource call sequence works fine.
TEST_P(CanvasCaptureHandlerTest, GetFormatsStartAndStop) {
  InSequence s;
  MediaStreamSource* const media_stream_source = component_->Source();
  EXPECT_TRUE(media_stream_source);
  blink::MediaStreamVideoCapturerSource* const ms_source =
      static_cast<blink::MediaStreamVideoCapturerSource*>(
          media_stream_source->GetPlatformSource());
  EXPECT_TRUE(ms_source);
  VideoCapturerSource* source = GetVideoCapturerSource(ms_source);
  EXPECT_TRUE(source);

  media::VideoCaptureFormats formats = source->GetPreferredFormats();
  ASSERT_EQ(2u, formats.size());
  EXPECT_EQ(kTestCanvasCaptureWidth, formats[0].frame_size.width());
  EXPECT_EQ(kTestCanvasCaptureHeight, formats[0].frame_size.height());
  media::VideoCaptureParams params;
  params.requested_format = formats[0];

  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(*this, DoOnRunning(true)).Times(1);
  EXPECT_CALL(*this, DoOnDeliverFrame(_, _))
      .Times(1)
      .WillOnce(RunOnceClosure(std::move(quit_closure)));
  source->StartCapture(
      params,
      base::BindRepeating(&CanvasCaptureHandlerTest::OnDeliverFrame,
                          base::Unretained(this)),
      /*sub_capture_target_version_callback=*/base::DoNothing(),
      /*frame_dropped_callback=*/base::DoNothing(),
      base::BindRepeating(&CanvasCaptureHandlerTest::OnRunning,
                          base::Unretained(this)));
  copier_->Convert(GenerateTestImage(testing::get<0>(GetParam()),
                                     testing::get<1>(GetParam()),
                                     testing::get<2>(GetParam())),
                   canvas_capture_handler_->CanDiscardAlpha(),
                   /*context_provider=*/nullptr,
                   canvas_capture_handler_->GetNewFrameCallback());
  run_loop.Run();

  source->StopCapture();
}

// Verifies that SkImage is processed and produces VideoFrame as expected.
TEST_P(CanvasCaptureHandlerTest, VerifyFrame) {
  const bool opaque_frame = testing::get<0>(GetParam());
  const bool width = testing::get<1>(GetParam());
  const bool height = testing::get<1>(GetParam());
  InSequence s;
  VideoCapturerSource* const source = GetVideoCapturerSource(
      static_cast<blink::MediaStreamVideoCapturerSource*>(
          component_->Source()->GetPlatformSource()));
  EXPECT_TRUE(source);

  base::RunLoop run_loop;
  EXPECT_CALL(*this, DoOnRunning(true)).Times(1);
  media::VideoCaptureParams params;
  source->StartCapture(
      params,
      base::BindRepeating(&CanvasCaptureHandlerTest::OnVerifyDeliveredFrame,
                          base::Unretained(this), opaque_frame, width, height),
      /*sub_capture_target_version_callback=*/base::DoNothing(),
      /*frame_dropped_callback=*/base::DoNothing(),
      base::BindRepeating(&CanvasCaptureHandlerTest::OnRunning,
                          base::Unretained(this)));
  copier_->Convert(GenerateTestImage(opaque_frame, width, height),
                   canvas_capture_handler_->CanDiscardAlpha(),
                   /*context_provider=*/nullptr,
                   canvas_capture_handler_->GetNewFrameCallback());
  run_loop.RunUntilIdle();
}

// Verifies that SkImage is processed and produces VideoFrame as expected.
TEST_F(CanvasCaptureHandlerTest, DropAlphaDeliversOpaqueFrame) {
  const int width = 2;
  const int height = 2;
  InSequence s;
  VideoCapturerSource* const source = GetVideoCapturerSource(
      static_cast<blink::MediaStreamVideoCapturerSource*>(
          component_->Source()->GetPlatformSource()));
  EXPECT_TRUE(source);

  base::RunLoop run_loop;
  EXPECT_CALL(*this, DoOnRunning(true)).Times(1);
  media::VideoCaptureParams params;
  source->SetCanDiscardAlpha(true);
  source->StartCapture(
      params,
      base::BindRepeating(&CanvasCaptureHandlerTest::OnVerifyDeliveredFrame,
                          base::Unretained(this), /*opaque_frame=*/true, width,
                          height),
      /*sub_capture_target_version_callback=*/base::DoNothing(),
      /*frame_dropped_callback=*/base::DoNothing(),
      base::BindRepeating(&CanvasCaptureHandlerTest::OnRunning,
                          base::Unretained(this)));
  copier_->Convert(GenerateTestImage(/*opaque=*/false, width, height),
                   canvas_capture_handler_->CanDiscardAlpha(),
                   /*context_provider=*/nullptr,
                   canvas_capture_handler_->GetNewFrameCallback());
  run_loop.RunUntilIdle();
}

// Checks that needsNewFrame() works as expected.
TEST_F(CanvasCaptureHandlerTest, CheckNeedsNewFrame) {
  InSequence s;
  VideoCapturerSource* source = GetVideoCapturerSource(
      static_cast<blink::MediaStreamVideoCapturerSource*>(
          component_->Source()->GetPlatformSource()));
  EXPECT_TRUE(source);
  EXPECT_TRUE(canvas_capture_handler_->NeedsNewFrame());
  source->StopCapture();
  EXPECT_FALSE(canvas_capture_handler_->NeedsNewFrame());
}

INSTANTIATE_TEST_SUITE_P(
    All,
    CanvasCaptureHandlerTest,
    ::testing::Combine(::testing::Bool(),
                       ::testing::Values(kTestCanvasCaptureFrameEvenSize,
                                         kTestCanvasCaptureFrameOddSize),
                       ::testing::Values(kTestCanvasCaptureFrameEvenSize,
                                         kTestCanvasCaptureFrameOddSize)));

}  // namespace blink
```