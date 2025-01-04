Response:
The user wants a summary of the functionality of the provided C++ code file `svg_image_test.cc`. I need to analyze the code to understand its purpose and how it interacts with other components, particularly Javascript, HTML, and CSS.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The file name `svg_image_test.cc` strongly suggests that it contains unit tests for the `SVGImage` class. The presence of `#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"` confirms this.

2. **Analyze the Test Structure:** The code uses the Google Test framework (`testing::Test`). Each `TEST_F` macro defines an individual test case. I need to examine the operations performed within each test to understand the specific aspects of `SVGImage` being tested.

3. **Identify Key Operations and Concepts:** Scan the code for common operations and data structures related to `SVGImage`. Look for:
    * Loading SVG data (`Load`, `LoadUsingFileName`, `SetData`).
    * Rendering/drawing (`PumpFrame`, `Draw`).
    * Animation control (`TimelineSuspendAndResume`, `ResetAnimation`, timers).
    * Interaction with the DOM (`LocalFrame`, `Document`, `Element`).
    * Layout (`LayoutObject`, `LayoutView`).
    * Painting (`PaintRecord`, `GraphicsContext`).
    * Events and scripting (SMIL, although the tests seem to focus on *disabling* them in this context).
    * Image caching (`SupportsSubsequenceCaching`).
    * Size and viewport handling (`SetSizeOnVisualViewport`, `IsSizeAvailable`).
    * Interaction with the compositor (`Compositor().BeginFrame()`).
    * Page visibility (`PageVisibilityHiddenToVisible`).
    * Scrolling and visibility (`AnimationsPausedWhenImageScrolledOutOfView`, `AnimationsResumedWhenImageScrolledIntoView`).
    * Multi-image scenarios (`TwoImagesSameSVGImageDifferentSize`).
    * XSLT processing (`SVGWithXSLT`).
    * Sprite sheet culling (`SpriteSheetCulling`, `SpriteSheetCullingBorderRadius`, `ClippedAbsoluteImageSpriteSheetCulling`, `ClippedStaticImageSpriteSheetCulling`, `InterestRectDoesNotCullImageSpriteSheet`).

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Consider how these tests relate to web development.
    * **HTML:** The tests load SVG content, often within the context of an `<img>` tag or as a background image. This directly relates to how developers embed SVGs in HTML.
    * **CSS:**  CSS animation (`@keyframes`) is used in the animated SVG tests. Background images, background positioning, `border-radius`, and `overflow: hidden` are tested in the sprite sheet culling scenarios. This demonstrates the interaction of `SVGImage` with CSS properties.
    * **JavaScript:** While not explicitly testing JavaScript interaction *in this file*, the tests verify behaviors that JavaScript might trigger (e.g., causing repaints that resume animations). The disabling of SMIL events is also relevant to how JavaScript might interact with SVG animation.

5. **Infer Logical Reasoning and Assumptions:**  When tests use specific input and check for specific output (even if implicit through side effects like timer activity), try to understand the underlying logic being tested. For example, the `TimelineSuspendAndResume` test assumes that an observer can control animation pausing.

6. **Identify Potential User Errors:** Think about common mistakes developers might make when working with SVGs, and see if the tests cover related scenarios. For instance,  incorrectly assuming animations will always run regardless of visibility.

7. **Trace User Actions (Debugging Clues):** Consider how a user's interaction with a web page might lead to the execution paths tested in this file. Loading a page with an SVG image, scrolling, changing visibility, and using CSS to style SVGs are all relevant.

8. **Synthesize and Summarize:**  Based on the analysis, formulate a concise summary of the file's purpose, highlighting its key functionalities and connections to web technologies.

9. **Address the "Part 1" Instruction:** Explicitly state that this is the first part of the analysis and that the focus is on summarizing the *functionality* demonstrated by the tests.

**Self-Correction/Refinement:**

* **Initial thought:** Focus solely on the `SVGImage` class.
* **Correction:**  Realize that the tests also implicitly cover the interaction between `SVGImage` and other Blink components like the layout engine, paint system, and compositor.
* **Initial thought:**  Assume direct JavaScript interaction is tested.
* **Correction:** Observe that while animation behavior is tested, explicit JavaScript manipulation of the SVG isn't the primary focus of *these specific tests*. The disabling of SMIL events is a related concept.
* **Initial thought:** Simply list the test names.
* **Correction:** Group tests by the functionality they are verifying for a more coherent summary. For example, group the animation-related tests together.

By following these steps, I can arrive at a comprehensive and accurate summary of the `svg_image_test.cc` file, addressing all aspects of the user's request.
这是 `blink/renderer/core/svg/graphics/svg_image_test.cc` 文件的第一部分，它的主要功能是**测试 Blink 渲染引擎中 `SVGImage` 类的各项功能。**  `SVGImage` 类负责处理和渲染 SVG (Scalable Vector Graphics) 图像。

具体来说，从提供的代码片段来看，这个测试文件涵盖了以下几个方面的功能测试：

**核心功能测试:**

* **SVG 图像的加载和解析:**  测试 `SVGImage` 类是否能正确加载和解析 SVG 数据，包括从字符串和文件中加载。
* **动画控制:**  测试 SVG 动画的暂停、恢复和重置功能。
* **渲染和绘制:** 测试 `SVGImage` 是否能正确地绘制自身，即使在动画过程中。
* **与 Blink 内部机制的交互:**
    * **时间线管理:** 测试 `SVGImage` 如何与 Blink 的动画时间线进行交互，例如在页面可见性改变时的行为。
    * **图层和缓存:** 测试 `SVGImage` 的渲染结果是否支持子序列缓存。
    * **布局:**  测试 `SVGImage` 在布局过程中如何影响布局偏移追踪器。
    * **视口:** 测试 `SVGImage` 如何处理视觉视口的大小。
* **特性检测:**  测试 `SVGImage` 是否能正确判断自身的大小是否可用。
* **事件处理:**  测试 `SVGImage` 是否禁用了 SMIL (Synchronized Multimedia Integration Language) 事件。
* **缩放和媒体查询:** 测试在不同缩放级别和媒体查询条件下，`SVGImage` 的渲染结果是否正确。
* **嵌套 SVG:** 测试 `SVGImage` 是否能正确处理包含动画的嵌套 SVG。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件虽然是用 C++ 编写的，但它测试的 `SVGImage` 类是浏览器渲染引擎的核心部分，与 JavaScript, HTML, CSS 的功能息息相关。

* **HTML:**
    * **举例:**  测试中使用了 `<img>` 标签加载 SVG 图片 (`<img src='image.svg' width='100' id='image'>`)。`SVGImage` 类负责处理这些通过 HTML 引入的 SVG 资源。
    * **功能关系:**  HTML 定义了如何将 SVG 嵌入到网页中。`SVGImage` 负责解析这些嵌入的 SVG 代码。

* **CSS:**
    * **举例:** 测试中使用了 CSS 动画 (`@keyframes`) 来定义 SVG 元素的动画效果。`SVGImage` 需要能够正确解析和执行这些 CSS 动画。
    * **功能关系:** CSS 用于样式化 SVG 元素，包括颜色、大小、动画等。`SVGImage` 需要根据 CSS 规则进行渲染。
    * **举例:** 测试中使用了 CSS 的 `background-image` 属性来加载 SVG，并测试了 `background-position-y` 的效果。
    * **举例:** 测试了 `border-radius` 属性对 SVG 背景图片渲染的影响。
    * **举例:**  测试了 `overflow: hidden` 对 SVG 图片的裁剪效果。

* **JavaScript:**
    * **举例:**  虽然这个测试文件本身不直接测试 JavaScript 代码，但它测试了当页面可见性改变时 (`WebView().SetVisibilityState`)，SVG 动画的暂停和恢复行为。这些行为可以通过 JavaScript API 来触发。
    * **功能关系:**  JavaScript 可以操作 DOM，包括修改 SVG 元素的属性和样式，从而影响 `SVGImage` 的渲染。JavaScript 也可以通过监听事件来与 SVG 动画进行交互（尽管此测试文件侧重于禁用 SMIL 事件）。

**逻辑推理和假设输入/输出:**

以下是一些基于代码的逻辑推理和假设输入/输出示例：

* **假设输入:**  一个包含 CSS 动画定义的 SVG 字符串 (`kAnimatedDocument`) 被加载到 `SVGImage` 中。
* **预期输出:**  `GetImage().MaybeAnimated()` 返回 `true`，表示这个 SVG 包含动画。在渲染过程中，会触发定时器来更新动画帧。

* **假设输入:**  调用 `GetImage().ResetAnimation()`。
* **预期输出:**  SVG 动画会被重置到初始状态，但动画定时器可能仍然在运行，直到下一次渲染触发。

* **假设输入:**  页面从可见状态切换到隐藏状态。
* **预期输出:**  `SVGImage` 的动画时间线会被暂停。

* **假设输入:**  一个带有媒体查询的 SVG 被加载，并且在不同的容器尺寸下渲染。
* **预期输出:**  `SVGImage` 会根据当前的媒体查询条件渲染不同的样式（例如，`fill` 颜色会根据视口宽度而改变）。

**用户或编程常见的使用错误举例:**

* **错误地假设 SVG 动画在页面不可见时仍然会消耗资源。**  Blink 引擎为了优化性能，会在页面不可见时暂停 SVG 动画。这个测试文件验证了这种行为。
* **在使用 JavaScript 操作 SVG 动画时，依赖于 SMIL 事件，但 SVG 图片的上下文禁用了 SMIL 事件。** 这个测试文件验证了在某些情况下，`SVGImage` 会禁用 SMIL 事件。
* **没有考虑到不同缩放级别下 SVG 的渲染效果。** 这个测试文件包含了测试在不同缩放级别下渲染 SVG 的场景。
* **在使用 CSS `background-image` 加载 SVG 时，没有正确理解 `background-position` 的工作方式，导致图片显示不正确。** 测试文件中包含了测试 `background-position-y` 的用例。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中打开一个包含 SVG 图片的网页。** 这可能是通过直接访问 HTML 文件，或者通过导航到包含 SVG 图片的网站。
2. **浏览器解析 HTML 代码，遇到 `<img>` 标签或者 CSS 的 `background-image` 属性指向 SVG 文件。**
3. **Blink 渲染引擎的网络模块会请求 SVG 资源。**
4. **`SVGImage` 类被创建，用于处理下载的 SVG 数据。** `Load` 或 `LoadUsingFileName` 函数模拟了这个过程。
5. **如果 SVG 包含动画，Blink 的动画系统会尝试启动动画。** `TimelineSuspendAndResume` 和 `ResetAnimation` 等测试模拟了动画的控制流程。
6. **当需要渲染页面时，`SVGImage` 的 `Draw` 方法会被调用，将 SVG 内容绘制到画布上。** `PumpFrame` 函数模拟了渲染过程。
7. **用户的交互行为，例如滚动页面、调整窗口大小、切换标签页等，可能会影响 SVG 动画的播放状态和渲染结果。** `PageVisibilityHiddenToVisible` 和 `AnimationsPausedWhenImageScrolledOutOfView` 等测试模拟了这些交互。

**本部分功能归纳:**

总而言之，`svg_image_test.cc` 的第一部分主要专注于测试 `SVGImage` 类的**核心加载、解析、渲染和动画控制功能**，以及它与 **Blink 内部机制**的交互。 这些测试覆盖了 SVG 图片在浏览器中的基本生命周期和关键行为，并验证了它与 HTML、CSS 的集成，为确保 SVG 功能的正确性和性能提供了保障。

Prompt: 
```
这是目录为blink/renderer/core/svg/graphics/svg_image_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"

#include <memory>

#include "base/memory/ptr_util.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "cc/paint/paint_flags.h"
#include "cc/paint/paint_op.h"
#include "cc/paint/paint_op_buffer_iterator.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/scheme_registry.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/svg/animation/smil_time_container.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image_chrome_client.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image_for_container.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/utils/SkNullCanvas.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

class SVGImageTest : public testing::Test, private ScopedMockOverlayScrollbars {
 public:
  SVGImage& GetImage() { return *image_; }

  void Load(const char* data, bool should_pause) {
    observer_ = MakeGarbageCollected<PauseControlImageObserver>(should_pause);
    image_ = SVGImage::Create(observer_);
    image_->SetData(SharedBuffer::Create(data, strlen(data)), true);
    test::RunPendingTasks();
  }

  void LoadUsingFileName(const String& file_name) {
    String file_path = test::BlinkWebTestsDir() + file_name;
    std::optional<Vector<char>> data = test::ReadFromFile(file_path);
    EXPECT_TRUE(data && data->size());
    scoped_refptr<SharedBuffer> image_data =
        SharedBuffer::Create(std::move(*data));

    observer_ = MakeGarbageCollected<PauseControlImageObserver>(true);
    image_ = SVGImage::Create(observer_);
    image_->SetData(image_data, true);
    test::RunPendingTasks();
  }

  void PumpFrame() {
    Image* image = image_.get();
    std::unique_ptr<SkCanvas> null_canvas = SkMakeNullCanvas();
    SkiaPaintCanvas canvas(null_canvas.get());
    cc::PaintFlags flags;
    gfx::RectF dummy_rect(0, 0, 100, 100);
    image->Draw(&canvas, flags, dummy_rect, dummy_rect, ImageDrawOptions());
  }

 private:
  class PauseControlImageObserver
      : public GarbageCollected<PauseControlImageObserver>,
        public ImageObserver {
   public:
    PauseControlImageObserver(bool should_pause)
        : should_pause_(should_pause) {}

    void DecodedSizeChangedTo(const Image*, size_t new_size) override {}

    bool ShouldPauseAnimation(const Image*) override { return should_pause_; }

    void Changed(const Image*) override {}

    void AsyncLoadCompleted(const blink::Image*) override {}

    void Trace(Visitor* visitor) const override {
      ImageObserver::Trace(visitor);
    }

   private:
    bool should_pause_;
  };
  test::TaskEnvironment task_environment_;
  Persistent<PauseControlImageObserver> observer_;
  scoped_refptr<SVGImage> image_;
};

const char kAnimatedDocument[] =
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>"
    "<style>"
    "@keyframes rot {"
    " from { transform: rotate(0deg); } to { transform: rotate(-360deg); }"
    "}"
    ".spinner {"
    " transform-origin: 50%% 50%%;"
    " animation-name: rot;"
    " animation-duration: 4s;"
    " animation-iteration-count: infinite;"
    " animation-timing-function: linear;"
    "}"
    "</style>"
    "<path class='spinner' fill='none' d='M 8,1.125 A 6.875,6.875 0 1 1 "
    "1.125,8' stroke-width='2' stroke='blue'/>"
    "</svg>";

TEST_F(SVGImageTest, TimelineSuspendAndResume) {
  const bool kShouldPause = true;
  Load(kAnimatedDocument, kShouldPause);
  SVGImageChromeClient& chrome_client = GetImage().ChromeClientForTesting();
  DisallowNewWrapper<HeapTaskRunnerTimer<SVGImageChromeClient>>* timer =
      MakeGarbageCollected<
          DisallowNewWrapper<HeapTaskRunnerTimer<SVGImageChromeClient>>>(
          scheduler::GetSingleThreadTaskRunnerForTesting(), &chrome_client,
          &SVGImageChromeClient::AnimationTimerFired);
  chrome_client.SetTimerForTesting(timer);

  // Simulate a draw. Cause a frame (timer) to be scheduled.
  PumpFrame();
  EXPECT_TRUE(GetImage().MaybeAnimated());
  EXPECT_TRUE(timer->Value().IsActive());

  // Fire the timer/trigger a frame update. Since the observer always returns
  // true for shouldPauseAnimation, this will result in the timeline being
  // suspended.
  test::RunDelayedTasks(base::Milliseconds(1) +
                        timer->Value().NextFireInterval());
  EXPECT_TRUE(chrome_client.IsSuspended());
  EXPECT_FALSE(timer->Value().IsActive());

  // Simulate a draw. This should resume the animation again.
  PumpFrame();
  EXPECT_TRUE(timer->Value().IsActive());
  EXPECT_FALSE(chrome_client.IsSuspended());
}

TEST_F(SVGImageTest, ResetAnimation) {
  const bool kShouldPause = false;
  Load(kAnimatedDocument, kShouldPause);
  SVGImageChromeClient& chrome_client = GetImage().ChromeClientForTesting();
  DisallowNewWrapper<HeapTaskRunnerTimer<SVGImageChromeClient>>* timer =
      MakeGarbageCollected<
          DisallowNewWrapper<HeapTaskRunnerTimer<SVGImageChromeClient>>>(
          scheduler::GetSingleThreadTaskRunnerForTesting(), &chrome_client,
          &SVGImageChromeClient::AnimationTimerFired);
  chrome_client.SetTimerForTesting(timer);

  // Simulate a draw. Cause a frame (timer) to be scheduled.
  PumpFrame();
  EXPECT_TRUE(GetImage().MaybeAnimated());
  EXPECT_TRUE(timer->Value().IsActive());

  // Reset the animation. This will suspend the timeline but not cancel the
  // timer.
  GetImage().ResetAnimation();
  EXPECT_TRUE(chrome_client.IsSuspended());
  EXPECT_TRUE(timer->Value().IsActive());

  // Fire the timer/trigger a frame update. The timeline will remain
  // suspended and no frame will be scheduled.
  test::RunDelayedTasks(base::Milliseconds(1) +
                        timer->Value().NextFireInterval());
  EXPECT_TRUE(chrome_client.IsSuspended());
  EXPECT_FALSE(timer->Value().IsActive());

  // Simulate a draw. This should resume the animation again.
  PumpFrame();
  EXPECT_FALSE(chrome_client.IsSuspended());
  EXPECT_TRUE(timer->Value().IsActive());
}

TEST_F(SVGImageTest, SupportsSubsequenceCaching) {
  const bool kShouldPause = true;
  Load(kAnimatedDocument, kShouldPause);
  PumpFrame();
  LocalFrame* local_frame =
      To<LocalFrame>(GetImage().GetPageForTesting()->MainFrame());
  EXPECT_TRUE(local_frame->GetDocument()->IsSVGDocument());
  LayoutObject* svg_root = local_frame->View()->GetLayoutView()->FirstChild();
  EXPECT_TRUE(svg_root->IsSVGRoot());
  EXPECT_TRUE(To<LayoutBoxModelObject>(svg_root)
                  ->Layer()
                  ->SupportsSubsequenceCaching());
}

TEST_F(SVGImageTest, LayoutShiftTrackerDisabled) {
  const bool kDontPause = false;
  Load("<svg xmlns='http://www.w3.org/2000/svg'></svg>", kDontPause);
  LocalFrame* local_frame =
      To<LocalFrame>(GetImage().GetPageForTesting()->MainFrame());
  EXPECT_TRUE(local_frame->GetDocument()->IsSVGDocument());
  auto& layout_shift_tracker = local_frame->View()->GetLayoutShiftTracker();
  EXPECT_FALSE(layout_shift_tracker.IsActive());
}

TEST_F(SVGImageTest, SetSizeOnVisualViewport) {
  const bool kDontPause = false;
  Load(
      "<svg xmlns='http://www.w3.org/2000/svg'>"
      "   <rect id='green' width='100%' height='100%' fill='green' />"
      "</svg>",
      kDontPause);
  PumpFrame();
  LocalFrame* local_frame =
      To<LocalFrame>(GetImage().GetPageForTesting()->MainFrame());
  ASSERT_FALSE(local_frame->View()->Size().IsEmpty());
  EXPECT_EQ(local_frame->View()->Size(),
            GetImage().GetPageForTesting()->GetVisualViewport().Size());
}

TEST_F(SVGImageTest, IsSizeAvailable) {
  const bool kShouldPause = false;
  Load("<svg xmlns='http://www.w3.org/2000/svg'></svg>", kShouldPause);
  EXPECT_TRUE(GetImage().IsSizeAvailable());

  Load("<notsvg></notsvg>", kShouldPause);
  EXPECT_FALSE(GetImage().IsSizeAvailable());

  Load("<notsvg xmlns='http://www.w3.org/2000/svg'></notsvg>", kShouldPause);
  EXPECT_FALSE(GetImage().IsSizeAvailable());
}

TEST_F(SVGImageTest, DisablesSMILEvents) {
  const bool kShouldPause = true;
  Load(kAnimatedDocument, kShouldPause);
  LocalFrame* local_frame =
      To<LocalFrame>(GetImage().GetPageForTesting()->MainFrame());
  EXPECT_TRUE(local_frame->GetDocument()->IsSVGDocument());
  SMILTimeContainer* time_container =
      To<SVGSVGElement>(local_frame->GetDocument()->documentElement())
          ->TimeContainer();
  EXPECT_TRUE(time_container->EventsDisabled());
}

TEST_F(SVGImageTest, PaintFrameForCurrentFrameWithMQAndZoom) {
  const bool kShouldPause = false;
  Load(R"SVG(
         <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 10'>
           <style>@media(max-width:50px){rect{fill:blue}}</style>
           <rect width='10' height='10' fill='red'/>
         </svg>)SVG",
       kShouldPause);

  auto container =
      SVGImageForContainer::Create(GetImage(), gfx::SizeF(100, 100), 2, nullptr,
                                   mojom::blink::PreferredColorScheme::kLight);
  SkBitmap bitmap =
      container->AsSkBitmapForCurrentFrame(kDoNotRespectImageOrientation);
  ASSERT_EQ(bitmap.width(), 100);
  ASSERT_EQ(bitmap.height(), 100);
  EXPECT_EQ(bitmap.getColor(10, 10), SK_ColorBLUE);
  EXPECT_EQ(bitmap.getColor(90, 10), SK_ColorBLUE);
  EXPECT_EQ(bitmap.getColor(10, 90), SK_ColorBLUE);
  EXPECT_EQ(bitmap.getColor(90, 90), SK_ColorBLUE);
}

TEST_F(SVGImageTest, SVGWithSmilAnimationIsAnimated) {
  const bool kShouldPause = true;
  Load(R"SVG(
         <svg xmlns="http://www.w3.org/2000/svg">
           <rect width="10" height="10"/>
           <animateTransform attributeName="transform" type="rotate"
                             from="0 5 5" to="360 5 5" dur="1s"
                             repeatCount="indefinite"/>
         </svg>)SVG",
       kShouldPause);

  EXPECT_TRUE(GetImage().MaybeAnimated());
}

TEST_F(SVGImageTest, NestedSVGWithSmilAnimationIsAnimated) {
  const bool kShouldPause = true;
  Load(R"SVG(
         <svg xmlns="http://www.w3.org/2000/svg">
           <svg>
             <rect width="10" height="10"/>
             <animateTransform attributeName="transform" type="rotate"
                               from="0 5 5" to="360 5 5" dur="1s"
                               repeatCount="indefinite"/>
           </svg>
         </svg>)SVG",
       kShouldPause);

  EXPECT_TRUE(GetImage().MaybeAnimated());
}

class SVGImageSimTest : public SimTest, private ScopedMockOverlayScrollbars {
 public:
  static void WaitForTimer(TimerBase& timer) {
    if (!timer.IsActive()) {
      return;
    }
    test::RunDelayedTasks(base::Milliseconds(1) + timer.NextFireInterval());
  }
};

TEST_F(SVGImageSimTest, PageVisibilityHiddenToVisible) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimSubresourceRequest image_resource("https://example.com/image.svg",
                                       "image/svg+xml");
  LoadURL("https://example.com/");
  main_resource.Complete("<img src='image.svg' width='100' id='image'>");
  image_resource.Complete(kAnimatedDocument);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  Element* element = GetDocument().getElementById(AtomicString("image"));
  ASSERT_TRUE(IsA<HTMLImageElement>(element));

  ImageResourceContent* image_content =
      To<HTMLImageElement>(*element).CachedImage();
  ASSERT_TRUE(image_content);
  ASSERT_TRUE(image_content->IsLoaded());
  ASSERT_TRUE(image_content->HasImage());
  Image* image = image_content->GetImage();
  ASSERT_TRUE(IsA<SVGImage>(image));
  SVGImageChromeClient& svg_image_chrome_client =
      To<SVGImage>(*image).ChromeClientForTesting();
  TimerBase& timer = svg_image_chrome_client.GetTimerForTesting();

  // Wait for the next animation frame to be triggered, and then trigger a new
  // frame. The image animation timeline should be running.
  WaitForTimer(timer);
  Compositor().BeginFrame();

  EXPECT_FALSE(svg_image_chrome_client.IsSuspended());

  // Set page visibility to 'hidden', and then wait for the animation timer to
  // fire. This should suspend the image animation. (Suspend the image's
  // animation timeline.)
  WebView().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               /*initial_state=*/false);
  test::RunDelayedTasks(base::Milliseconds(1) + timer.NextFireInterval());

  EXPECT_TRUE(svg_image_chrome_client.IsSuspended());

  // Set page visibility to 'visible' - this should schedule a new animation
  // frame and resume the image animation.
  WebView().SetVisibilityState(mojom::blink::PageVisibilityState::kVisible,
                               /*initial_state=*/false);
  test::RunDelayedTasks(base::Milliseconds(1) + timer.NextFireInterval());
  Compositor().BeginFrame();

  EXPECT_FALSE(svg_image_chrome_client.IsSuspended());
}

const char kSmilAnimatedDocument[] = R"SVG(
<svg xmlns='http://www.w3.org/2000/svg' fill='red' width='10' height='10'>
  <circle cx='5' cy='5'>
    <animate attributeName='r' values='0; 10; 0' dur='10s'
             repeatCount='indefinite'/>
  </circle>
</svg>
)SVG";

TEST_F(SVGImageSimTest, AnimationsPausedWhenImageScrolledOutOfView) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimSubresourceRequest image_resource("https://example.com/image.svg",
                                       "image/svg+xml");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <img src="image.svg" width="20" id="image">
    <div style="height: 10000px"></div>
  )HTML");
  image_resource.Complete(kSmilAnimatedDocument);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  Element* element = GetDocument().getElementById(AtomicString("image"));
  ASSERT_TRUE(IsA<HTMLImageElement>(element));

  ImageResourceContent* image_content =
      To<HTMLImageElement>(*element).CachedImage();
  ASSERT_TRUE(image_content);
  ASSERT_TRUE(image_content->IsLoaded());
  ASSERT_TRUE(image_content->HasImage());
  Image* image = image_content->GetImage();
  ASSERT_TRUE(IsA<SVGImage>(image));
  SVGImage& svg_image = To<SVGImage>(*image);
  ASSERT_TRUE(svg_image.MaybeAnimated());
  auto& svg_image_chrome_client = svg_image.ChromeClientForTesting();
  TimerBase& timer = svg_image_chrome_client.GetTimerForTesting();

  // Wait for the next animation frame to be triggered, and then trigger a new
  // frame. The image animation timeline should be running.
  WaitForTimer(timer);
  Compositor().BeginFrame();

  EXPECT_FALSE(svg_image_chrome_client.IsSuspended());
  EXPECT_TRUE(timer.IsActive());

  // Scroll down to the bottom of the document to move the image out of the
  // viewport, and then wait for the animation timer to fire. This triggers an
  // "image changed" notification, which (re)sets the delay-invalidation
  // flag. The following begin-frame then observes that the image is not
  // visible.
  GetDocument().domWindow()->scrollBy(0, 10000);
  test::RunDelayedTasks(base::Milliseconds(1) + timer.NextFireInterval());
  Compositor().BeginFrame();
  EXPECT_TRUE(timer.IsActive());

  // Trigger another animation frame. This makes the WillRenderImage() query
  // return false (because delay-invalidation is set), which in turn suspends
  // the image animation. (Suspend the image's animation timeline.)
  test::RunDelayedTasks(base::Milliseconds(1) + timer.NextFireInterval());

  EXPECT_TRUE(svg_image_chrome_client.IsSuspended());
  EXPECT_FALSE(timer.IsActive());

  // Scroll back up to make the image visible. The following paint observes
  // that the image is now visible, and triggers a paint that resume the image
  // animation.
  GetDocument().domWindow()->scrollBy(0, -10000);
  Compositor().BeginFrame();

  EXPECT_FALSE(svg_image_chrome_client.IsSuspended());
  EXPECT_TRUE(timer.IsActive());
}

TEST_F(SVGImageSimTest, AnimationsResumedWhenImageScrolledIntoView) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimSubresourceRequest image_resource("https://example.com/image.svg",
                                       "image/svg+xml");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      .change {
        will-change: transform;
      }
    </style>
    <div style="height: 100vh"></div>
    <div class="change">
      <img src="image.svg" width="20" id="image">
    </div>
  )HTML");
  image_resource.Complete(kAnimatedDocument);

  Compositor().BeginFrame();

  Element* element = GetDocument().getElementById(AtomicString("image"));
  ASSERT_TRUE(IsA<HTMLImageElement>(element));

  ImageResourceContent* image_content =
      To<HTMLImageElement>(*element).CachedImage();
  ASSERT_TRUE(image_content);
  ASSERT_TRUE(image_content->IsLoaded());
  ASSERT_TRUE(image_content->HasImage());
  Image* image = image_content->GetImage();
  ASSERT_TRUE(IsA<SVGImage>(image));
  SVGImage& svg_image = To<SVGImage>(*image);
  ASSERT_TRUE(svg_image.MaybeAnimated());
  auto& svg_image_chrome_client = svg_image.ChromeClientForTesting();
  TimerBase& timer = svg_image_chrome_client.GetTimerForTesting();

  // The image animation is running after being started by the paint above.
  EXPECT_FALSE(svg_image_chrome_client.IsSuspended());
  EXPECT_TRUE(timer.IsActive());

  // Process pending timers. This will suspend the image animation.
  WaitForTimer(timer);
  WaitForTimer(timer);

  EXPECT_TRUE(svg_image_chrome_client.IsSuspended());
  EXPECT_FALSE(timer.IsActive());

  // Mutate the image's container triggering a paint that restarts the image
  // animation.
  Element* div = element->parentElement();
  div->removeAttribute(html_names::kClassAttr);

  Compositor().BeginFrame();

  // Wait for the next animation frame.
  WaitForTimer(timer);

  // Scroll down to make the image appear in the viewport, and then wait for
  // the animation timer to fire.
  GetDocument().domWindow()->scrollBy(0, 10000);
  Compositor().BeginFrame();

  EXPECT_FALSE(svg_image_chrome_client.IsSuspended());
  EXPECT_TRUE(timer.IsActive());
}

TEST_F(SVGImageSimTest, TwoImagesSameSVGImageDifferentSize) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimSubresourceRequest image_resource("https://example.com/image.svg",
                                       "image/svg+xml");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <img src="image.svg" style="width: 100px">
    <img src="image.svg" style="width: 200px">
  )HTML");
  image_resource.Complete(R"SVG(
    <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
       <rect fill="green" width="100" height="100"/>
    </svg>
  )SVG");

  Compositor().BeginFrame();
  test::RunPendingTasks();
  // The previous frame should result in a stable state and should not schedule
  // new visual updates.
  EXPECT_FALSE(Compositor().NeedsBeginFrame());
}

TEST_F(SVGImageSimTest, SVGWithXSLT) {
  // To make "https" scheme counted as "Blink.UseCounter.Extensions.Features",
  // we should make it recognized as an extension.
  CommonSchemeRegistry::RegisterURLSchemeAsExtension("https");

  SimRequest main_resource("https://example.com/", "text/html");
  SimSubresourceRequest image_resource("https://example.com/image.svg",
                                       "image/svg+xml");

  base::HistogramTester histograms;
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <img src="image.svg">
  )HTML");
  image_resource.Complete(R"SVG(<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="#stylesheet"?>
<!DOCTYPE svg [
<!ATTLIST xsl:stylesheet
id ID #REQUIRED>
]>
<svg>
    <xsl:stylesheet id="stylesheet" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:svg="http://www.w3.org/2000/svg"></xsl:stylesheet>
</svg>)SVG");

  Compositor().BeginFrame();
  test::RunPendingTasks();
  // The previous frame should result in a stable state and should not schedule
  // new visual updates.
  EXPECT_FALSE(Compositor().NeedsBeginFrame());

  // Ensure |UseCounter.DidCommitLoad| is called once.
  // Since we cannot use |UseCounter.IsCounted(WebFeature::kPageVisits)|, we
  // check the histogram updated in |DidCommitLoad|.
  histograms.ExpectBucketCount("Blink.UseCounter.Extensions.Features",
                               WebFeature::kPageVisits, 1);
}

namespace {

size_t CountPaintOpType(const cc::PaintRecord& record, cc::PaintOpType type) {
  size_t count = 0;
  for (const cc::PaintOp& op : record) {
    if (op.IsPaintOpWithFlags()) {
      const cc::PaintFlags& flags =
          static_cast<const cc::PaintOpWithFlags&>(op).flags;
      if (const cc::PaintShader* shader = flags.getShader()) {
        if (shader->shader_type() == cc::PaintShader::Type::kPaintRecord) {
          count += CountPaintOpType(*shader->paint_record(), type);
        }
      }
    }
    if (op.GetType() == type) {
      ++count;
    } else if (op.GetType() == cc::PaintOpType::kDrawRecord) {
      const auto& record_op = static_cast<const cc::DrawRecordOp&>(op);
      count += CountPaintOpType(record_op.record, type);
    }
  }
  return count;
}

}  // namespace

// Tests the culling of invisible sprites from a larger sprite sheet.
TEST_F(SVGImageSimTest, SpriteSheetCulling) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(
      "<style>"
      "  body { zoom: 2.5; }"
      "  #div {"
      "    width: 100px;"
      "    height: 100px;"
      "    background-image: url(\"data:image/svg+xml,"
      "      <svg xmlns='http://www.w3.org/2000/svg' width='100' height='300'>"
      "        <circle cx='50' cy='50' r='10' fill='red'/>"
      "        <circle cx='50' cy='150' r='10' fill='green'/>"
      "        <circle cx='25' cy='250' r='10' fill='blue'/>"
      "        <circle cx='50' cy='250' r='10' fill='blue'/>"
      "        <circle cx='75' cy='250' r='10' fill='blue'/>"
      "      </svg>\");"
      "    background-position-y: -100px;"
      "    background-repeat: no-repeat;"
      "  }"
      "</style>"
      "<div id='div'></div>");

  Compositor().BeginFrame();

  // Initially, only the green circle should be recorded.
  PaintRecord record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(1U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));

  // Adjust the height so one green circle and three blue circles are visible,
  // and ensure four circles are recorded.
  Element* div = GetDocument().getElementById(AtomicString("div"));
  div->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px;"));
  Compositor().BeginFrame();
  record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(4U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));

  // Adjust the background position so only the three blue circles are visible,
  // and ensure three circles are recorded.
  div->setAttribute(
      html_names::kStyleAttr,
      AtomicString("height: 200px; background-position-y: -200px;"));
  Compositor().BeginFrame();
  record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(3U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));
}

// Tests the culling of invisible sprites from a larger sprite sheet where the
// element also has a border-radius. This is intended to cover the
// Image::ApplyShader() fast-path in GraphicsContext::DrawImageRRect().
TEST_F(SVGImageSimTest, SpriteSheetCullingBorderRadius) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(
      "<style>"
      "  body { zoom: 2.5; }"
      "  #div {"
      "    width: 100px;"
      "    height: 100px;"
      "    background-image: url(\"data:image/svg+xml,"
      "      <svg xmlns='http://www.w3.org/2000/svg' width='100' height='300'>"
      "        <circle cx='50' cy='50' r='10' fill='red'/>"
      "        <circle cx='50' cy='150' r='10' fill='green'/>"
      "        <circle cx='25' cy='250' r='10' fill='blue'/>"
      "        <circle cx='50' cy='250' r='10' fill='blue'/>"
      "        <circle cx='75' cy='250' r='10' fill='blue'/>"
      "      </svg>\");"
      "    background-position-y: -100px;"
      "    background-repeat: no-repeat;"
      "    border-radius: 5px;"
      "  }"
      "</style>"
      "<div id='div'></div>");

  Compositor().BeginFrame();

  // Initially, only the green circle should be recorded.
  PaintRecord record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(1U, CountPaintOpType(record, cc::PaintOpType::kDrawRRect));
  EXPECT_EQ(1U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));

  // Adjust the height so one green circle and three blue circles are visible,
  // and ensure four circles are recorded.
  Element* div = GetDocument().getElementById(AtomicString("div"));
  div->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px;"));
  Compositor().BeginFrame();
  record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(1U, CountPaintOpType(record, cc::PaintOpType::kDrawRRect));
  EXPECT_EQ(4U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));
}

// Similar to `SpriteSheetCulling` but using a full-sized sprite sheet <img>
// element with absolute positioning under overflow: hidden. This pattern is
// used by Google Docs.
TEST_F(SVGImageSimTest, ClippedAbsoluteImageSpriteSheetCulling) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
        body { zoom: 2.5; }
        #div {
          width: 100px;
          height: 100px;
          overflow: hidden;
          position: relative;
        }
        #image {
          position: absolute;
          left: 0;
          top: -100px;
        }
      </style>
      <div id="div">
        <img id="image" src="data:image/svg+xml,
            <svg xmlns='http://www.w3.org/2000/svg' width='100' height='400'>
              <circle cx='50' cy='50' r='10' fill='red'/>
              <circle cx='50' cy='150' r='10' fill='green'/>
              <circle cx='25' cy='250' r='10' fill='blue'/>
              <circle cx='50' cy='250' r='10' fill='blue'/>
              <circle cx='75' cy='250' r='10' fill='blue'/>
            </svg>">
      </div>
  )HTML");

  Compositor().BeginFrame();

  // Initially, only the green circle should be recorded.
  PaintRecord record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(1U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));

  // Adjust the div's height so one green circle and three blue circles are
  // visible, and ensure four circles are recorded.
  Element* div_element = GetDocument().getElementById(AtomicString("div"));
  div_element->setAttribute(html_names::kStyleAttr,
                            AtomicString("height: 200px;"));
  Compositor().BeginFrame();
  record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(4U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));

  // Adjust the image's position so only the three blue circles are visible,
  // and ensure three circles are recorded.
  Element* image_element = GetDocument().getElementById(AtomicString("image"));
  image_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("top: -200px;"));
  Compositor().BeginFrame();
  record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(3U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));
}

// Similar to `SpriteSheetCulling` but using a full-sized sprite sheet <img>
// element under overflow: hidden. This differs from
// `ClippedAbsoluteImageSpriteSheetCulling` because static positioning and
// margin are used to position the image, rather than absolute positioning.
TEST_F(SVGImageSimTest, ClippedStaticImageSpriteSheetCulling) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
        body { zoom: 2.5; }
        #div {
          width: 100px;
          height: 100px;
          overflow: hidden;
          position: relative;
        }
        #image {
          margin-top: -100px;
        }
      </style>
      <div id="div">
        <img id="image" src="data:image/svg+xml,
            <svg xmlns='http://www.w3.org/2000/svg' width='100' height='400'>
              <circle cx='50' cy='50' r='10' fill='red'/>
              <circle cx='50' cy='150' r='10' fill='green'/>
              <circle cx='25' cy='250' r='10' fill='blue'/>
              <circle cx='50' cy='250' r='10' fill='blue'/>
              <circle cx='75' cy='250' r='10' fill='blue'/>
            </svg>">
      </div>
  )HTML");

  Compositor().BeginFrame();

  // Initially, only the green circle should be recorded.
  PaintRecord record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(1U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));

  // Adjust the div's height so one green circle and three blue circles are
  // visible, and ensure four circles are recorded.
  Element* div_element = GetDocument().getElementById(AtomicString("div"));
  div_element->setAttribute(html_names::kStyleAttr,
                            AtomicString("height: 200px;"));
  Compositor().BeginFrame();
  record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(4U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));

  // Adjust the image's position so only the three blue circles are visible,
  // and ensure three circles are recorded.
  Element* image_element = GetDocument().getElementById(AtomicString("image"));
  image_element->setAttribute(html_names::kStyleAttr,
                              AtomicString("margin-top: -200px;"));
  Compositor().BeginFrame();
  record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(3U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));

  // Adjust the div's position to be fractional and ensure only three blue
  // circles are still recorded.
  div_element->setAttribute(html_names::kStyleAttr,
                            AtomicString("margin-left: 0.5px; height: 200px;"));
  Compositor().BeginFrame();
  record = GetDocument().View()->GetPaintRecord();
  EXPECT_EQ(3U, CountPaintOpType(record, cc::PaintOpType::kDrawOval));
}

// Similar to `SpriteSheetCulling` but using a regular scrolling interest rect
// that isn't clipping to a specific sprite within the image. To avoid
// regressing non-sprite-sheet paint performance with additional invalidatoins,
// we want to avoid special culling in these cases.
TEST_F(SVGImageSimTest, InterestRectDoesNotCullImageSpriteSheet) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
        body { zoom: 2.5; }
        #div {
          width: 200px;
          height: 10000px;
          overflow: hidden;
          position: relative;
        }
        #image {
          position: absolute;
          left: 0;
          top: 0;
        }
      </style>
      <div id="div">
        <img id="image" src="data:image/svg+xml,
            <svg xmlns='http://www.w3.org/2000/svg' width='100' height='6000'>
              <circle cx='50' cy='50' r='10' fill='green'/>
              <circle cx='25' cy='595
"""


```