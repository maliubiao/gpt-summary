Response:
My thinking process to analyze the `video_painter_test.cc` file went something like this:

1. **Understand the Purpose:** The filename `video_painter_test.cc` immediately suggests this is a test file specifically for the `VideoPainter` class. The inclusion of "paint" in the name further indicates it focuses on how videos are rendered or "painted" within the Blink rendering engine.

2. **Identify Key Imports:**  I scanned the `#include` directives to understand the dependencies and the core functionalities being tested. Key includes that stood out were:
    * `video_painter.h`: The header for the class being tested.
    * `cc/layers/layer.h`: Indicates interaction with the Compositor thread's layer system, which is crucial for rendering performance.
    * `third_party/blink/renderer/core/html/media/html_media_element.h`:  Confirms the tests involve the `<video>` HTML element.
    * `third_party/blink/renderer/core/paint/paint_controller_paint_test.h`: Shows this is part of a larger framework for testing painting within Blink.
    * `third_party/blink/renderer/platform/testing/...`:  Indicates the use of Blink's testing utilities.

3. **Analyze Test Fixtures and Helper Classes:** I noticed the `VideoPainterTest` class inheriting from `PaintControllerPaintTestBase`. This tells me it's setting up a testing environment mimicking a browser page and allowing for control over the rendering process. The `StubWebMediaPlayer` and `MockWebMediaPlayer` classes are clearly mock objects used to simulate the behavior of a real video player, allowing for controlled testing without relying on actual video decoding. `VideoStubLocalFrameClient` helps in setting up the frame environment needed for media playback. `VideoPaintPreviewTest` focuses on paint preview scenarios.

4. **Examine Individual Tests:** I went through each `TEST_F` macro to understand what specific aspects of video painting were being tested:
    * `VideoLayerAppearsInLayerTree`: Tests whether the video element correctly creates and attaches a `cc::Layer` to the compositor tree. This is fundamental for hardware acceleration.
    * `URLIsRecordedWhenPaintingPreview`: Checks if the URL of the page is correctly recorded during a paint preview operation. This is relevant for features like "Save as PDF" or offline page generation.
    * `PosterFlagToggleFrameCapture`:  Tests how the presence or absence of the `poster` attribute on the `<video>` element affects whether the poster image or a video frame is captured during a paint preview.
    * `PosterFlagToggleNoPosterFrameCapture`: Similar to the above, but specifically tests the case where there's no `poster` attribute.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** I started to bridge the gap between the C++ test code and the web technologies:
    * **HTML:** The tests directly manipulate the DOM by inserting `<video>` elements with various attributes (`src`, `width`, `height`, `poster`, `controls`, `loop`).
    * **CSS:** The tests implicitly rely on CSS styling for layout and object fitting. The `VideoLayerAppearsInLayerTree` test specifically verifies the layer's `offset_to_transform_parent()` and `bounds()`, which are influenced by CSS properties like `object-fit`. The style tag in the paint preview tests demonstrates direct CSS usage.
    * **JavaScript:** While not explicitly tested through JS code execution here, the underlying functionality of playing the video (`element->Play()`) is triggered, which is something a web page would typically do using JavaScript. The test uses `LocalFrame::NotifyUserActivation` which is often a prerequisite for media playback initiated by script.

6. **Infer Logic and Assumptions:** I looked for patterns in the test setup and assertions:
    * **Assumption:**  The tests assume a composited rendering path is enabled (`EnableCompositing()`).
    * **Input/Output (Examples):**
        * *Input:* `<video width=300 height=300 src=test.ogv>`
        * *Output:* A `cc::Layer` with bounds (300, 150) if `object-fit: contain` is the default or inferred behavior.
        * *Input:*  Calling `CapturePaintPreview(true)` when the video is playing and has a poster.
        * *Output:* The paint record contains the poster image.
        * *Input:* Calling `CapturePaintPreview(false)` when the video is playing.
        * *Output:* The `MockWebMediaPlayer`'s `Paint` method is called (simulating capturing a video frame).

7. **Consider User Errors and Debugging:** I thought about common mistakes developers might make and how this test helps catch them:
    * **Incorrect Layer Attachment:**  Forgetting to attach the video's layer to the compositor tree would break hardware acceleration and potentially lead to rendering issues. This is tested by `HasLayerAttached`.
    * **Incorrect Layer Sizing:**  Miscalculating the layer bounds based on aspect ratio and `object-fit` would result in visual artifacts. This is checked by comparing the expected and actual layer bounds.
    * **Paint Preview Issues:**  Failing to capture the correct content (poster or video frame) during paint previews would lead to incorrect offline representations of the page. The paint preview tests address this.

8. **Trace User Interaction:** I tried to imagine how a user's action could lead to this code being executed:
    * A user navigates to a webpage containing a `<video>` element.
    * The browser's rendering engine processes the HTML, CSS, and (potentially) JavaScript.
    * The `VideoPainter` class is responsible for drawing the video content onto the appropriate `cc::Layer`.
    * When a paint preview is triggered (e.g., "Save as PDF"), the paint preview code interacts with the rendering engine, potentially calling methods tested in this file to capture the video content.

By following these steps, I could systematically analyze the C++ code and understand its purpose, its relationship to web technologies, the logic it implements, potential errors it helps prevent, and how it fits into the broader context of a user's web browsing experience.
这个文件 `video_painter_test.cc` 是 Chromium Blink 引擎中用于测试 `VideoPainter` 类的功能的单元测试文件。 `VideoPainter` 负责将 HTML `<video>` 元素的内容绘制到渲染层（cc::Layer）上。

**主要功能：**

1. **测试视频层是否正确添加到层树 (Layer Tree):**  验证当页面包含 `<video>` 元素时，`VideoPainter` 是否创建并正确地将对应的 `cc::Layer` 对象添加到 Chromium 的合成器（Compositor）层树中。这对于视频的硬件加速渲染至关重要。

2. **测试视频层的属性配置:** 验证视频层的大小、位置等属性是否根据 `<video>` 元素的属性（如 `width`, `height`）和 CSS 样式进行正确配置。 例如，测试 `object-fit` 属性如何影响视频层的边界和偏移。

3. **模拟和测试视频帧的绘制:** 通过使用 `StubWebMediaPlayer` 和 `MockWebMediaPlayer` 模拟视频播放器的行为，测试 `VideoPainter` 如何在不同的视频状态下（例如，有可用帧、没有可用帧）进行绘制。 `MockWebMediaPlayer` 允许对 `Paint` 方法进行 mocking，从而验证绘制逻辑。

4. **测试 Paint Preview 功能中的视频处理:**  测试在生成页面 Paint Preview (例如，用于离线保存或打印) 时，`VideoPainter` 如何处理视频内容。这包括：
    * **URL 记录:** 验证在 Paint Preview 中是否记录了包含视频的页面的 URL。
    * **Poster 图像处理:** 测试当 `<video>` 元素定义了 `poster` 属性时，在 Paint Preview 中是否会绘制 poster 图像。
    * **视频帧捕获:** 测试当视频正在播放时，在 Paint Preview 中是否可以捕获并绘制视频的当前帧（尽管测试中使用了 Mock 对象，实际上并不会绘制真实的视频帧）。
    * **跳过加速内容:** 测试在 Paint Preview 中跳过加速内容（例如视频层）的逻辑。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**  测试的核心围绕 HTML 的 `<video>` 元素。测试会动态创建和操作 `<video>` 元素，例如设置 `width`, `height`, `src`, `poster` 等属性。
    * **举例:** `SetBodyInnerHTML("<video width=300 height=300 src=test.ogv>");`  这行代码在测试中插入一个简单的 `<video>` 元素。

* **CSS:**  虽然测试代码本身不直接写 CSS，但它会验证 CSS 的效果。例如，`VideoLayerAppearsInLayerTree` 测试中，会检查视频层的 `offset_to_transform_parent()` 和 `bounds()`，这些值会受到 CSS 的 `object-fit` 属性影响。默认情况下，视频可能会保持其纵横比并适应容器，导致实际绘制的区域小于容器大小。
    * **举例:** 假设 `<video width=300 height=300>` 但视频的原始比例是 16:9， 默认的 `object-fit: contain` 会导致视频在 300x300 的区域内居中显示，上下或左右留白。测试会验证视频层的 `bounds()` 是否反映了实际绘制的视频区域，例如可能是 300x168.75。

* **JavaScript:**  虽然这个测试文件主要是 C++ 代码，但它测试的功能是与 JavaScript API 密切相关的。例如，测试中的 `element->Play()` 模拟了 JavaScript 调用 `videoElement.play()` 来开始播放视频。  Paint Preview 功能也可能通过 JavaScript API 触发。
    * **举例:**  `ASSERT_TRUE(PlayVideo());` 这行代码模拟了用户或脚本调用视频的 `play()` 方法。测试会验证在视频播放后，Paint Preview 的行为是否符合预期。

**逻辑推理及假设输入与输出：**

**假设输入 (针对 `VideoLayerAppearsInLayerTree` 测试):**

* HTML: `<video width=300 height=300 src=test.ogv>`
* CSS: 无特别样式影响视频的布局 (默认 `object-fit: contain`)
* 视频源 (`test.ogv`): 假设其原始宽高比不是 1:1

**预期输出:**

* 创建一个 `cc::Layer` 对象。
* 该 `cc::Layer` 对象被添加到文档的层树中。
* `layer->offset_to_transform_parent()` 的值可能为 `gfx::Vector2dF(0, 75)`，这表示为了保持纵横比，视频在 300x300 的容器中垂直居中。
* `layer->bounds()` 的值可能为 `gfx::Size(300, 150)`，假设视频源的原始宽高比是 2:1。

**假设输入 (针对 `PosterFlagToggleFrameCapture` 测试):**

* HTML: `<video width=300 height=300 src="test.ogv" poster="data:image/gif;base64,..." controls loop>`
* 视频正在播放 (`PlayVideo()` 返回 true)。
* 第一次调用 `CapturePaintPreview(/*skip_accelerated_content=*/true)`。
* 第二次调用 `CapturePaintPreview(/*skip_accelerated_content=*/false)`。

**预期输出:**

* 第一次 `CapturePaintPreview` (跳过加速内容) 会捕获 poster 图像 (GIF)，因为加速内容（视频层）被跳过。`CountImagesOfType(record, cc::ImageType::kGIF)` 返回 1。
* 第二次 `CapturePaintPreview` (不跳过加速内容) 应该尝试绘制视频帧。由于使用了 `MockWebMediaPlayer`，实际绘制的内容是空的，但会调用 `MockWebMediaPlayer::Paint` 方法。`CountImagesOfType(record, cc::ImageType::kGIF)` 返回 0。

**用户或编程常见的使用错误及举例说明：**

1. **忘记设置视频元素的尺寸:** 用户可能在 HTML 中添加了 `<video>` 标签，但没有设置 `width` 和 `height` 属性或相应的 CSS 样式。这会导致浏览器不知道如何布局视频，可能会导致视频不可见或尺寸异常。测试会验证在给定尺寸的情况下，视频层是否被正确配置。

2. **`object-fit` 属性使用不当:** 开发者可能错误地使用了 `object-fit` 属性，导致视频内容变形或超出容器边界。例如，使用 `object-fit: fill` 可能会拉伸视频以填充整个容器，即使这破坏了原始的纵横比。测试可以帮助验证在不同 `object-fit` 值下，视频层的边界是否符合预期。

3. **在 Paint Preview 中期望看到动态视频内容:** 用户或开发者可能期望在离线保存的页面或打印预览中看到正在播放的视频的动画。然而，Paint Preview 通常只捕获页面的一个静态快照。测试验证了在 Paint Preview 中是否正确处理了视频，例如显示 poster 图像或一个静止帧。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问包含 `<video>` 元素的网页:**  这是最基本的前提。用户通过浏览器地址栏输入 URL 或点击链接，访问了一个包含视频的页面。

2. **浏览器解析 HTML 并构建 DOM 树:** 浏览器会解析 HTML 代码，将 `<video>` 元素添加到文档对象模型 (DOM) 树中。

3. **Blink 渲染引擎处理 DOM 树并创建渲染对象:** Blink 渲染引擎会根据 DOM 树创建相应的渲染对象（RenderObject），对于 `<video>` 元素，会创建 `RenderVideo` 或类似的渲染对象。

4. **布局计算:** 渲染引擎会计算页面元素的布局，包括 `<video>` 元素的大小和位置，这会受到 HTML 属性和 CSS 样式的影响。

5. **合成层创建:**  当涉及到硬件加速渲染时，Blink 会创建合成层 (cc::Layer)。对于 `<video>` 元素，`VideoPainter` 负责创建和管理与视频内容相关的层。

6. **`VideoPainter::Paint()` 方法被调用:** 当需要绘制视频内容时，例如在初始渲染、页面滚动、视频播放状态变化时，`VideoPainter::Paint()` 方法会被调用。这个方法会使用 `WebMediaPlayer` 提供的数据来绘制视频帧或 poster 图像到 `cc::Layer` 上。

7. **Paint Preview 触发:**  用户可能通过浏览器菜单选择 "打印" 或 "另存为 PDF" 功能，这会触发 Paint Preview 的生成过程。

8. **Paint Preview 代码调用 `CapturePaintPreview()`:**  在生成 Paint Preview 的过程中，相关的代码会遍历渲染树并捕获每个元素的内容。对于 `<video>` 元素，可能会调用类似 `LocalFrame::CapturePaintPreview()` 的方法，最终会涉及到 `VideoPainter` 如何处理视频内容（是绘制 poster 还是视频帧，取决于当时的视频状态和配置）。

9. **测试文件 `video_painter_test.cc` 的作用:**  这个测试文件模拟了上述的一些关键步骤，但是在一个隔离的测试环境中进行。开发者可以通过运行这些测试来验证 `VideoPainter` 的逻辑是否正确，确保在各种场景下（包括不同的视频状态、CSS 样式、Paint Preview 功能）视频能够被正确渲染和处理。如果测试失败，说明 `VideoPainter` 的实现可能存在 bug，需要进行调试和修复。

总而言之，`video_painter_test.cc` 是确保 Chromium 能够正确渲染和处理 HTML `<video>` 元素的关键组成部分，它覆盖了视频渲染的多个方面，并与 HTML、CSS 和 JavaScript 的相关功能紧密联系。

### 提示词
```
这是目录为blink/renderer/core/paint/video_painter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/video_painter.h"

#include <memory>

#include "base/unguessable_token.h"
#include "cc/layers/layer.h"
#include "components/paint_preview/common/paint_preview_tracker.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/paint/paint_controller_paint_test.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/media/media_player_client.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

// Integration tests of video painting code (in CAP mode).

namespace blink {
namespace {

void ExtractLinks(const PaintRecord& record,
                  std::vector<std::pair<GURL, SkRect>>* links) {
  for (const cc::PaintOp& op : record) {
    if (op.GetType() == cc::PaintOpType::kAnnotate) {
      const auto& annotate_op = static_cast<const cc::AnnotateOp&>(op);
      links->push_back(std::make_pair(
          GURL(std::string(
              reinterpret_cast<const char*>(annotate_op.data->data()),
              annotate_op.data->size())),
          annotate_op.rect));
    } else if (op.GetType() == cc::PaintOpType::kDrawRecord) {
      const auto& record_op = static_cast<const cc::DrawRecordOp&>(op);
      ExtractLinks(record_op.record, links);
    }
  }
}

size_t CountImagesOfType(const PaintRecord& record, cc::ImageType image_type) {
  size_t count = 0;
  for (const cc::PaintOp& op : record) {
    if (op.GetType() == cc::PaintOpType::kDrawImage) {
      const auto& image_op = static_cast<const cc::DrawImageOp&>(op);
      if (image_op.image.GetImageHeaderMetadata()->image_type == image_type) {
        ++count;
      }
    } else if (op.GetType() == cc::PaintOpType::kDrawImageRect) {
      const auto& image_op = static_cast<const cc::DrawImageRectOp&>(op);
      if (image_op.image.GetImageHeaderMetadata()->image_type == image_type) {
        ++count;
      }
    } else if (op.GetType() == cc::PaintOpType::kDrawRecord) {
      const auto& record_op = static_cast<const cc::DrawRecordOp&>(op);
      count += CountImagesOfType(record_op.record, image_type);
    }
  }
  return count;
}

class StubWebMediaPlayer : public EmptyWebMediaPlayer {
 public:
  explicit StubWebMediaPlayer(WebMediaPlayerClient* client)
      : client_(static_cast<MediaPlayerClient*>(client)) {}

  const cc::Layer* GetCcLayer() { return layer_.get(); }

  // WebMediaPlayer
  LoadTiming Load(LoadType,
                  const WebMediaPlayerSource&,
                  CorsMode,
                  bool is_cache_disabled) override {
    network_state_ = kNetworkStateLoaded;
    client_->NetworkStateChanged();
    ready_state_ = kReadyStateHaveEnoughData;
    client_->ReadyStateChanged();
    layer_ = cc::Layer::Create();
    layer_->SetIsDrawable(true);
    layer_->SetHitTestable(true);
    client_->SetCcLayer(layer_.get());
    return LoadTiming::kImmediate;
  }
  NetworkState GetNetworkState() const override { return network_state_; }
  ReadyState GetReadyState() const override { return ready_state_; }

 private:
  MediaPlayerClient* client_;
  scoped_refptr<cc::Layer> layer_;
  NetworkState network_state_ = kNetworkStateEmpty;
  ReadyState ready_state_ = kReadyStateHaveNothing;
};

class VideoStubLocalFrameClient : public EmptyLocalFrameClient {
 public:
  // LocalFrameClient
  std::unique_ptr<WebMediaPlayer> CreateWebMediaPlayer(
      HTMLMediaElement&,
      const WebMediaPlayerSource&,
      WebMediaPlayerClient* client) override {
    return std::make_unique<StubWebMediaPlayer>(client);
  }
};

class VideoPainterTest : public PaintControllerPaintTestBase {
 public:
  VideoPainterTest()
      : PaintControllerPaintTestBase(
            MakeGarbageCollected<VideoStubLocalFrameClient>()) {}

  void SetUp() override {
    EnableCompositing();
    PaintControllerPaintTestBase::SetUp();
    GetDocument().SetURL(KURL(NullURL(), "https://example.com/"));
  }

  bool HasLayerAttached(const cc::Layer& layer) {
    return GetChromeClient().HasLayer(layer);
  }
};

TEST_F(VideoPainterTest, VideoLayerAppearsInLayerTree) {
  // Insert a <video> and allow it to begin loading.
  SetBodyInnerHTML("<video width=300 height=300 src=test.ogv>");
  test::RunPendingTasks();

  // Force the page to paint.
  UpdateAllLifecyclePhasesForTest();

  // Fetch the layer associated with the <video>, and check that it was
  // correctly configured in the layer tree.
  auto* element = To<HTMLMediaElement>(GetDocument().body()->firstChild());
  StubWebMediaPlayer* player =
      static_cast<StubWebMediaPlayer*>(element->GetWebMediaPlayer());
  const cc::Layer* layer = player->GetCcLayer();
  ASSERT_TRUE(layer);
  EXPECT_TRUE(HasLayerAttached(*layer));
  // The layer bounds reflects the aspect ratio and object-fit of the video.
  EXPECT_EQ(gfx::Vector2dF(0, 75), layer->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(300, 150), layer->bounds());
}

class MockWebMediaPlayer : public StubWebMediaPlayer {
 public:
  explicit MockWebMediaPlayer(WebMediaPlayerClient* client)
      : StubWebMediaPlayer(client) {}
  MOCK_CONST_METHOD0(HasAvailableVideoFrame, bool());
  MOCK_CONST_METHOD0(HasReadableVideoFrame, bool());
  MOCK_METHOD3(Paint,
               void(cc::PaintCanvas*, const gfx::Rect&, cc::PaintFlags&));
};

class TestWebFrameClientImpl : public frame_test_helpers::TestWebFrameClient {
 public:
  std::unique_ptr<WebMediaPlayer> CreateMediaPlayer(
      const WebMediaPlayerSource&,
      WebMediaPlayerClient* client,
      blink::MediaInspectorContext*,
      WebMediaPlayerEncryptedMediaClient*,
      WebContentDecryptionModule*,
      const WebString& sink_id,
      const cc::LayerTreeSettings* settings,
      scoped_refptr<base::TaskRunner> compositor_worker_task_runner) override {
    auto player = std::make_unique<MockWebMediaPlayer>(client);
    EXPECT_CALL(*player, HasAvailableVideoFrame)
        .WillRepeatedly(testing::Return(false));
    return player;
  }
};

class VideoPaintPreviewTest : public testing::Test,
                              public PaintTestConfigurations {
 public:
  ~VideoPaintPreviewTest() {
    CSSDefaultStyleSheets::Instance().PrepareForLeakDetection();
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  void SetUp() override {
    web_view_helper_.Initialize(&web_frame_client_);

    WebLocalFrameImpl& frame_impl = GetLocalMainFrame();
    frame_impl.ViewImpl()->MainFrameViewWidget()->Resize(
        gfx::Size(bounds().size()));

    frame_test_helpers::LoadFrame(&GetLocalMainFrame(), "about:blank");
    GetDocument().View()->SetParentVisible(true);
    GetDocument().View()->SetSelfVisible(true);
  }

  void TearDown() override { web_view_helper_.Reset(); }

  void SetBodyInnerHTML(const std::string& content) {
    frame_test_helpers::LoadHTMLString(&GetLocalMainFrame(), content,
                                       KURL("http://test.com"));
  }

  Document& GetDocument() { return *GetFrame()->GetDocument(); }

  WebLocalFrameImpl& GetLocalMainFrame() {
    return *web_view_helper_.LocalMainFrame();
  }

  const gfx::Rect& bounds() { return bounds_; }

  bool PlayVideo() {
    LocalFrame::NotifyUserActivation(
        GetFrame(), mojom::UserActivationNotificationType::kTest);
    auto* element = To<HTMLMediaElement>(GetDocument().body()->firstChild());
    MockWebMediaPlayer* player =
        static_cast<MockWebMediaPlayer*>(element->GetWebMediaPlayer());
    EXPECT_CALL(*player, HasAvailableVideoFrame)
        .WillRepeatedly(testing::Return(true));
    auto play_result = element->Play();
    EXPECT_FALSE(play_result.has_value())
        << "DOM Exception when playing: "
        << static_cast<int>(play_result.value());
    return !play_result.has_value();
  }

  cc::PaintRecord CapturePaintPreview(bool skip_accelerated_content) {
    auto token = base::UnguessableToken::Create();
    const base::UnguessableToken embedding_token =
        base::UnguessableToken::Create();
    const bool is_main_frame = true;

    cc::PaintRecorder recorder;
    paint_preview::PaintPreviewTracker tracker(token, embedding_token,
                                               is_main_frame);
    cc::PaintCanvas* canvas = recorder.beginRecording();
    canvas->SetPaintPreviewTracker(&tracker);

    GetLocalMainFrame().CapturePaintPreview(
        bounds(), canvas,
        /*include_linked_destinations=*/true,
        /*skip_accelerated_content=*/skip_accelerated_content);
    return recorder.finishRecordingAsPicture();
  }

 private:
  test::TaskEnvironment task_environment_;

  LocalFrame* GetFrame() { return GetLocalMainFrame().GetFrame(); }

  TestWebFrameClientImpl web_frame_client_;

  // This must be destroyed before `web_frame_client_`; when the WebViewHelper
  // is deleted, it destroys child views that were created, but the list of
  // child views is maintained on `web_frame_client_`.
  frame_test_helpers::WebViewHelper web_view_helper_;
  gfx::Rect bounds_ = {0, 0, 640, 480};
};

INSTANTIATE_PAINT_TEST_SUITE_P(VideoPaintPreviewTest);

TEST_P(VideoPaintPreviewTest, URLIsRecordedWhenPaintingPreview) {
  // Insert a <video> and allow it to begin loading. The image was taken from
  // the RFC for the data URI scheme https://tools.ietf.org/html/rfc2397.
  SetBodyInnerHTML(R"HTML(
    <style>body{margin:0}</style>
    <video width=300 height=300 src="test.ogv" poster="data:image/gif;base64,R0
      lGODdhMAAwAPAAAAAAAP///ywAAAAAMAAwAAAC8IyPqcvt3wCcDkiLc7C0qwyGHhSWpjQu5yq
      mCYsapyuvUUlvONmOZtfzgFzByTB10QgxOR0TqBQejhRNzOfkVJ+5YiUqrXF5Y5lKh/DeuNcP
      5yLWGsEbtLiOSpa/TPg7JpJHxyendzWTBfX0cxOnKPjgBzi4diinWGdkF8kjdfnycQZXZeYGe
      jmJlZeGl9i2icVqaNVailT6F5iJ90m6mvuTS4OK05M0vDk0Q4XUtwvKOzrcd3iq9uisF81M1O
      IcR7lEewwcLp7tuNNkM3uNna3F2JQFo97Vriy/Xl4/f1cf5VWzXyym7PHhhx4dbgYKAAA7"
      controls>
  )HTML");
  test::RunPendingTasks();

  auto record = CapturePaintPreview(/*skip_accelerated_content=*/false);

  std::vector<std::pair<GURL, SkRect>> links;
  ExtractLinks(record, &links);
  ASSERT_EQ(1lu, links.size());
  EXPECT_EQ("http://test.com/", links[0].first);

  // The captured record will contain a poster image (GIF) even through the flag
  // is not set since the video is not playing.
  EXPECT_EQ(1U, CountImagesOfType(record, cc::ImageType::kGIF));
}

TEST_P(VideoPaintPreviewTest, PosterFlagToggleFrameCapture) {
  // Insert a <video> and allow it to begin loading. The image was taken from
  // the RFC for the data URI scheme https://tools.ietf.org/html/rfc2397.
  SetBodyInnerHTML(R"HTML(
    <style>body{margin:0}</style>
    <video width=300 height=300 src="test.ogv" poster="data:image/gif;base64,R0
      lGODdhMAAwAPAAAAAAAP///ywAAAAAMAAwAAAC8IyPqcvt3wCcDkiLc7C0qwyGHhSWpjQu5yq
      mCYsapyuvUUlvONmOZtfzgFzByTB10QgxOR0TqBQejhRNzOfkVJ+5YiUqrXF5Y5lKh/DeuNcP
      5yLWGsEbtLiOSpa/TPg7JpJHxyendzWTBfX0cxOnKPjgBzi4diinWGdkF8kjdfnycQZXZeYGe
      jmJlZeGl9i2icVqaNVailT6F5iJ90m6mvuTS4OK05M0vDk0Q4XUtwvKOzrcd3iq9uisF81M1O
      IcR7lEewwcLp7tuNNkM3uNna3F2JQFo97Vriy/Xl4/f1cf5VWzXyym7PHhhx4dbgYKAAA7"
      controls loop>
  )HTML");
  test::RunPendingTasks();

  // Play the video.
  ASSERT_TRUE(PlayVideo());

  // Capture using poster.
  auto* element = To<HTMLMediaElement>(GetDocument().body()->firstChild());
  MockWebMediaPlayer* player =
      static_cast<MockWebMediaPlayer*>(element->GetWebMediaPlayer());
  EXPECT_CALL(*player, Paint(testing::_, testing::_, testing::_)).Times(0);
  auto record = CapturePaintPreview(/*skip_accelerated_content=*/true);

  std::vector<std::pair<GURL, SkRect>> links;
  ExtractLinks(record, &links);
  ASSERT_EQ(1lu, links.size());
  EXPECT_EQ("http://test.com/", links[0].first);

  // The captured record will contain a poster image (GIF) even though the video
  // is playing.
  EXPECT_EQ(1U, CountImagesOfType(record, cc::ImageType::kGIF));

  // Capture using video frame.
  EXPECT_CALL(*player, Paint(testing::_, testing::_, testing::_));
  record = CapturePaintPreview(/*skip_accelerated_content=*/false);

  links.clear();
  ExtractLinks(record, &links);
  ASSERT_EQ(1lu, links.size());
  EXPECT_EQ("http://test.com/", links[0].first);

  // A video frame is recorded rather than the poster image (GIF) as the video
  // is "playing". Note: this is actually just empty since we are using a
  // MockWebMediaPlayer.
  EXPECT_EQ(0U, CountImagesOfType(record, cc::ImageType::kGIF));
}

TEST_P(VideoPaintPreviewTest, PosterFlagToggleNoPosterFrameCapture) {
  // Insert a <video> and allow it to begin loading. The image was taken from
  // the RFC for the data URI scheme https://tools.ietf.org/html/rfc2397.
  SetBodyInnerHTML(R"HTML(
    <style>body{margin:0}</style>
    <video width=300 height=300 src="test.ogv" controls loop>
  )HTML");
  test::RunPendingTasks();

  // Play the video.
  ASSERT_TRUE(PlayVideo());

  // Expect to not have to paint the video as empty will be painted without a
  // poster.
  auto* element = To<HTMLMediaElement>(GetDocument().body()->firstChild());
  MockWebMediaPlayer* player =
      static_cast<MockWebMediaPlayer*>(element->GetWebMediaPlayer());
  EXPECT_CALL(*player, Paint(testing::_, testing::_, testing::_)).Times(0);

  // Capture without poster.
  auto record = CapturePaintPreview(/*skip_accelerated_content=*/true);

  std::vector<std::pair<GURL, SkRect>> links;
  ExtractLinks(record, &links);
  ASSERT_EQ(1lu, links.size());
  EXPECT_EQ("http://test.com/", links[0].first);
}

}  // namespace
}  // namespace blink
```