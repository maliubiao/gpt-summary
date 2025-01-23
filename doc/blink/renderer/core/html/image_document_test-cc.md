Response:
Let's break down the thought process for analyzing the `image_document_test.cc` file.

1. **Identify the Core Purpose:** The filename `image_document_test.cc` immediately suggests this is a test file. Looking at the `#include` directives confirms this, particularly the inclusion of `testing/gtest/include/gtest/gtest.h` and files in the `blink/renderer/core/testing/` directory. The "test" suffix is a strong indicator.

2. **Determine What's Being Tested:** The `#include "third_party/blink/renderer/core/html/image_document.h"` line reveals the target of these tests: the `ImageDocument` class.

3. **Infer Functionality of `ImageDocument`:** Based on its name, `ImageDocument` likely represents the document structure used specifically when displaying a single image in a browser tab. It's not a general HTML document, but one tailored for images.

4. **Analyze the Test Cases (the `TEST_F` blocks):**  This is the heart of understanding what aspects of `ImageDocument` are being verified. Go through each `TEST_F` and try to understand its intent:

    * `ImageLoad`:  Checks if the image loads correctly and its dimensions are as expected.
    * `LargeImageScalesDown`: Verifies that if an image is larger than the viewport, it's scaled down to fit.
    * `RestoreImageOnClick`:  Examines the behavior when the image is clicked – it seems to revert to its original size (no longer scaled down).
    * `InitialZoomDoesNotAffectScreenFit`: Tests if the initial page zoom level impacts the initial scaling to fit the screen.
    * `ZoomingDoesNotChangeRelativeSize`:  Investigates how subsequent zooming affects the image dimensions.
    * `ImageScalesDownWithDsf`:  Looks at how the device scale factor (DSF) affects image scaling.
    * `ImageNotCenteredWithForceZeroLayoutHeight` and `ImageCenteredWithoutForceZeroLayoutHeight`:  These check the centering behavior of the image based on a specific setting.
    * `DomInteractive`: Checks if the `DomInteractive` timing is set, implying the document loading reaches a certain stage.
    * `ImageSrcChangedBeforeFinish`:  Handles the case where the image source is changed before the initial load completes.
    * `ImageStyleContainsTransitionForNonAnimatedImage` and `ImageStyleDoesNotContainTransitionForAnimatedImage`: Verifies the presence or absence of CSS transitions based on whether the image is animated.
    * `MAYBE(ImageCenteredAtDeviceScaleFactor)`: A more complex test involving clicks, scrolling, and device scale factors. The "MAYBE" suggests it might be platform-specific or have known issues on some platforms.
    * The `ImageDocumentViewportTest` class and its tests (`HidingURLBarDoesntChangeImageLocation`, `ScaleImage`, `DivWidth`) focus on interactions between the `ImageDocument` and the viewport, especially regarding scaling and positioning under different conditions (like hiding the URL bar or varying device scale factors).

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**

    * **HTML:** The tests directly interact with the `HTMLImageElement`. This shows the `ImageDocument`'s role in managing an `<img>` tag. The presence of attributes like `src` and `style` links directly to HTML.
    * **CSS:** The tests involving `ImageStyleContainsTransitionForNonAnimatedImage` directly examine the `style` attribute, demonstrating a connection to CSS. The scaling and centering behaviors are also influenced by CSS properties.
    * **JavaScript:** While this specific test file doesn't have explicit JavaScript code, the actions like "ImageClicked" imply that JavaScript event handling is part of the `ImageDocument`'s functionality. The DOM manipulation (e.g., `removeAttribute`) also suggests a JavaScript interaction. The `GetBoundingClientRect()` method is a common JavaScript API for layout information.

6. **Look for Logical Reasoning and Assumptions:**  The tests often make assumptions about the expected behavior. For instance, when a large image is loaded into a smaller viewport, the assumption is that it *should* scale down. The specific scaling factors in some tests are also based on internal logic or design decisions.

7. **Identify Potential User/Programming Errors:**  The tests that cover edge cases or unusual scenarios (like changing the `src` attribute mid-load) hint at potential issues a developer might encounter. For example, not handling the case where an image is much larger than the viewport could lead to poor user experience. Incorrectly setting viewport meta tags could also lead to unexpected scaling, as tested in `ImageDocumentViewportTest`.

8. **Structure the Output:** Organize the findings logically:
    * Start with a concise summary of the file's purpose.
    * Detail the functionalities of the tested class (`ImageDocument`).
    * Provide concrete examples linking to HTML, CSS, and JavaScript.
    * Explain logical reasoning with input/output examples (even if simplified).
    * Illustrate potential user errors with scenarios.

9. **Refine and Elaborate:** Review the generated output for clarity and completeness. Add more details or examples where needed. For instance, when mentioning CSS, you could specify properties like `width`, `height`, `object-fit`, or `transition`. For JavaScript, you could mention event listeners.

This systematic approach, moving from the general purpose to specific details, allows for a comprehensive understanding of the test file and the functionality it verifies.
这个文件 `image_document_test.cc` 是 Chromium Blink 引擎中用于测试 `ImageDocument` 类的单元测试文件。 `ImageDocument` 类是 Blink 渲染引擎中专门用于显示单个图像资源的文档类型。

以下是该文件的功能列表：

1. **测试 `ImageDocument` 的基本加载功能:**  测试当加载一个图像资源时，`ImageDocument` 能否正确地创建和初始化。
2. **测试图像的缩放行为:** 验证当图像尺寸大于浏览器窗口尺寸时，`ImageDocument` 是否能正确地缩放图像以适应窗口。
3. **测试点击图像后的行为:**  测试当用户点击缩放后的图像时，`ImageDocument` 能否将图像恢复到原始大小。
4. **测试初始缩放级别的影响:** 验证初始页面缩放级别是否会影响图像的初始显示大小。
5. **测试动态缩放的影响:**  测试在 `ImageDocument` 加载后，改变页面缩放级别是否会正确地调整图像的显示大小。
6. **测试设备像素比 (DPR) 的影响:** 验证设备像素比是否会影响图像的缩放行为。
7. **测试 `forceZeroLayoutHeight` 设置的影响:** 验证当设置 `forceZeroLayoutHeight` 时，图像是否会居中显示。
8. **测试 DOMContentLoaded 事件:** 验证 `ImageDocument` 是否会触发 `DOMContentLoaded` 事件。
9. **测试在加载完成前修改 `src` 属性的行为:** 验证在图像加载完成之前修改 `<img>` 元素的 `src` 属性是否会产生预期行为。
10. **测试动画图像和非动画图像的样式差异:** 验证 `ImageDocument` 对于动画图像和非动画图像是否应用了不同的默认样式 (例如，非动画图像有 `transition` 属性)。
11. **测试在不同设备像素比下的图像居中和滚动:**  更深入地测试在特定设备像素比下，点击图像后的居中显示以及滚动行为。
12. **测试与视口 (Viewport) 相关的行为:**
    * 测试隐藏 URL 栏是否会影响图像的位置。
    * 测试在不同视口大小和设备像素比下，图像的缩放行为。
    * 测试 `<div>` 元素的宽度计算，这影响图像在视口中的布局。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * `ImageDocument` 最终会渲染一个包含 `<img>` 元素的 HTML 文档。测试中会获取和操作这个 `<img>` 元素，例如：
        * `GetDocument().ImageElement()`: 获取文档中的 `<img>` 元素。
        * `GetDocument().ImageElement()->width()` 和 `GetDocument().ImageElement()->height()`: 获取 `<img>` 元素的宽度和高度，这对应 HTML 元素的属性或 CSS 计算后的值。
        * `GetDocument().ImageElement()->removeAttribute(html_names::kSrcAttr)`: 移除 `<img>` 元素的 `src` 属性，这是一个 HTML 属性。
        * `GetDocument().ImageElement()->getAttribute(html_names::kStyleAttr)`: 获取 `<img>` 元素的 `style` 属性，该属性包含 CSS 样式。
* **CSS:**
    * `ImageDocument` 会应用一些默认的 CSS 样式来控制图像的显示，例如缩放和居中。
    * 测试会检查 `<img>` 元素的 `style` 属性来验证 CSS 样式的应用情况：
        * `EXPECT_NE(style.Find("transition:"), kNotFound)`: 验证非动画图像的 `style` 属性中是否包含 CSS 的 `transition` 属性。
        * `EXPECT_EQ(style.Find("transition:"), kNotFound)`: 验证动画图像的 `style` 属性中是否不包含 CSS 的 `transition` 属性。
    * 图像的缩放行为很大程度上受到 CSS 的 `width` 和 `height` 属性以及一些布局相关属性的影响。
* **JavaScript:**
    * 虽然这个测试文件主要是 C++ 代码，但它测试的功能与 JavaScript 在浏览器中的行为密切相关。 例如：
        * `GetDocument().ImageClicked(4, 4)`: 模拟用户点击图像，这会触发 JavaScript 事件处理逻辑。
        * `GetDocument().GetTiming().DomInteractive()`: 获取 DOM Interactive 的时间，这与浏览器的文档加载模型和 JavaScript 的执行时机有关。
        * 页面缩放和视口变化通常会触发浏览器的重新渲染和 JavaScript 事件。

**逻辑推理与假设输入输出:**

* **假设输入:**  一个尺寸为 100x100 的 JPEG 图像，浏览器窗口大小为 50x50。
* **逻辑推理:**  `ImageDocument` 应该检测到图像大于窗口，并将其缩小以适应窗口。缩小的比例应该保持图像的宽高比。
* **预期输出:** `ImageWidth()` 和 `ImageHeight()` 返回的值都小于或等于 50，且宽高比与原始图像相同。例如，如果保持宽高比，可能输出 50x50。如果以宽度为基准缩小，可能输出 50x50。

* **假设输入:**  `forceZeroLayoutHeight` 设置为 `true`，浏览器窗口大小为 80x70，加载一个 50x50 的图像。
* **逻辑推理:**  当 `forceZeroLayoutHeight` 为 `true` 时，图像不应该为了适应窗口而缩小，并且会从左上角开始显示，不会居中。
* **预期输出:** `GetDocument().ShouldShrinkToFit()` 返回 `false`。 `GetDocument().ImageElement()->OffsetLeft()` 和 `GetDocument().ImageElement()->OffsetTop()` 返回 `0`。 `ImageWidth()` 和 `ImageHeight()` 返回 `50`。

**用户或编程常见的使用错误举例说明:**

1. **未正确处理大图片:**  如果 `ImageDocument` 没有正确实现缩放逻辑，当用户打开一个非常大的图片时，可能会导致内存占用过高或者性能问题，甚至浏览器崩溃。这个测试用例 `LargeImageScalesDown` 就是为了确保这种情况得到正确处理。

2. **错误的缩放逻辑导致图片变形:** 如果缩放逻辑没有保持图片的宽高比，可能会导致图片被拉伸或挤压，影响用户体验。测试中的缩放相关用例（例如 `LargeImageScalesDown`，`ZoomingDoesNotChangeRelativeSize`）旨在验证缩放逻辑的正确性。

3. **忽略设备像素比的影响:**  开发者在处理图像显示时，需要考虑设备像素比，以保证在不同屏幕上图像的清晰度。测试用例 `ImageScalesDownWithDsf` 和 `MAYBE(ImageCenteredAtDeviceScaleFactor)` 就是为了验证 `ImageDocument` 是否正确处理了设备像素比。

4. **对动画图像应用不必要的过渡效果:**  对于动画图像，应用 CSS 的 `transition` 属性通常是没有意义的，反而可能引起性能问题或视觉上的不协调。测试用例 `ImageStyleDoesNotContainTransitionForAnimatedImage` 确保了 `ImageDocument` 针对动画图像没有添加默认的过渡效果。

5. **在图片加载完成前错误地操作 `<img>` 元素:**  如果在图片加载完成之前就尝试获取图片的尺寸或其他属性，可能会得到不正确的结果。测试用例 `ImageSrcChangedBeforeFinish` 涵盖了在加载过程中修改 `src` 属性的情况，以确保引擎能正确处理。

总而言之，`image_document_test.cc` 通过一系列单元测试，细致地检验了 `ImageDocument` 类在各种场景下的行为，确保其能够正确、高效地显示图像，并与浏览器的其他组件（如视口、缩放功能）以及 Web 标准（HTML, CSS）良好地协同工作。这些测试有助于预防和发现潜在的 bug 和性能问题，从而提升用户的浏览体验。

### 提示词
```
这是目录为blink/renderer/core/html/image_document_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/image_document.h"

#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/document_parser.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

// A non-animated jpeg image of size 50x50.
Vector<unsigned char> JpegImage() {
  Vector<unsigned char> jpeg;

  static const unsigned char kData[] = {
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43,
      0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdb, 0x00, 0x43, 0x01, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x32, 0x00, 0x32, 0x03,
      0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0xff, 0xc4, 0x00,
      0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x10,
      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xc4, 0x00, 0x15, 0x01, 0x01, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x02, 0xff, 0xc4, 0x00, 0x14, 0x11, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xff, 0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03,
      0x11, 0x00, 0x3f, 0x00, 0x00, 0x94, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x03, 0xff, 0xd9};

  jpeg.Append(kData, sizeof(kData));
  return jpeg;
}

// An animated webp image of size 50x50.
Vector<unsigned char> AnimatedWebpImage() {
  Vector<unsigned char> animated_webp;

  static const unsigned char kData[] = {
      0x52, 0x49, 0x46, 0x46, 0x90, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
      0x56, 0x50, 0x38, 0x58, 0x0a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
      0x31, 0x00, 0x00, 0x31, 0x00, 0x00, 0x41, 0x4e, 0x49, 0x4d, 0x06, 0x00,
      0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x41, 0x4e, 0x4d, 0x46,
      0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00,
      0x00, 0x31, 0x00, 0x00, 0x64, 0x00, 0x00, 0x02, 0x56, 0x50, 0x38, 0x4c,
      0x15, 0x00, 0x00, 0x00, 0x2f, 0x31, 0x40, 0x0c, 0x00, 0x07, 0x10, 0xe5,
      0x8f, 0xfe, 0x07, 0x80, 0x84, 0xf0, 0x7f, 0xbd, 0x18, 0xd1, 0xff, 0x94,
      0x0b, 0x00, 0x41, 0x4e, 0x4d, 0x46, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x31, 0x00, 0x00, 0x64, 0x00,
      0x00, 0x00, 0x56, 0x50, 0x38, 0x4c, 0x15, 0x00, 0x00, 0x00, 0x2f, 0x31,
      0x40, 0x0c, 0x00, 0x07, 0xd0, 0xbf, 0x88, 0xfe, 0x07, 0x80, 0x84, 0xf0,
      0x7f, 0xbd, 0x18, 0xd1, 0xff, 0x94, 0x0b, 0x00};

  animated_webp.Append(kData, sizeof(kData));
  return animated_webp;
}
}  // namespace

class WindowToViewportScalingChromeClient : public EmptyChromeClient {
 public:
  WindowToViewportScalingChromeClient()
      : EmptyChromeClient(), scale_factor_(1.f) {}

  void SetScalingFactor(float s) { scale_factor_ = s; }
  float WindowToViewportScalar(LocalFrame*, const float s) const override {
    return s * scale_factor_;
  }

 private:
  float scale_factor_;
};

class ImageDocumentTest : public testing::Test {
 protected:
  void TearDown() override {
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  void CreateDocumentWithoutLoadingImage(int view_width,
                                         int view_height,
                                         bool is_animated);
  void CreateDocument(int view_width,
                      int view_height,
                      bool is_animated = false);

  ImageDocument& GetDocument() const;

  int ImageWidth() const { return GetDocument().ImageElement()->width(); }
  int ImageHeight() const { return GetDocument().ImageElement()->height(); }

  void SetPageZoom(float);
  void SetWindowToViewportScalingFactor(float);
  void SetForceZeroLayoutHeight(bool);

 private:
  test::TaskEnvironment task_environment_;
  Persistent<WindowToViewportScalingChromeClient> chrome_client_;
  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
  float zoom_factor_ = 0.0f;
  float viewport_scaling_factor_ = 0.0f;
  std::optional<bool> force_zero_layout_height_;
};

void ImageDocumentTest::CreateDocumentWithoutLoadingImage(int view_width,
                                                          int view_height,
                                                          bool is_animated) {
  chrome_client_ = MakeGarbageCollected<WindowToViewportScalingChromeClient>();
  dummy_page_holder_ = nullptr;
  dummy_page_holder_ = std::make_unique<DummyPageHolder>(
      gfx::Size(view_width, view_height), chrome_client_);

  if (zoom_factor_) {
    dummy_page_holder_->GetFrame().SetLayoutZoomFactor(zoom_factor_);
  }
  if (viewport_scaling_factor_)
    chrome_client_->SetScalingFactor(viewport_scaling_factor_);
  if (force_zero_layout_height_.has_value()) {
    dummy_page_holder_->GetPage().GetSettings().SetForceZeroLayoutHeight(
        force_zero_layout_height_.value());
  }

  auto params = std::make_unique<WebNavigationParams>();
  params->url = is_animated ? KURL("http://www.example.com/image.webp")
                            : KURL("http://www.example.com/image.jpg");

  const Vector<unsigned char>& data =
      is_animated ? AnimatedWebpImage() : JpegImage();
  WebNavigationParams::FillStaticResponse(
      params.get(), is_animated ? "image/webp" : "image/jpeg", "UTF-8",
      base::as_chars(base::span(data)));
  dummy_page_holder_->GetFrame().Loader().CommitNavigation(std::move(params),
                                                           nullptr);
}

void ImageDocumentTest::CreateDocument(int view_width,
                                       int view_height,
                                       bool is_animated /*=false*/) {
  CreateDocumentWithoutLoadingImage(view_width, view_height, is_animated);
  blink::test::RunPendingTasks();
}

ImageDocument& ImageDocumentTest::GetDocument() const {
  Document* document = dummy_page_holder_->GetFrame().DomWindow()->document();
  ImageDocument* image_document = static_cast<ImageDocument*>(document);
  return *image_document;
}

void ImageDocumentTest::SetPageZoom(float factor) {
  zoom_factor_ = factor;
  if (dummy_page_holder_)
    dummy_page_holder_->GetFrame().SetLayoutZoomFactor(factor);
}

void ImageDocumentTest::SetWindowToViewportScalingFactor(float factor) {
  viewport_scaling_factor_ = factor;
  if (chrome_client_)
    chrome_client_->SetScalingFactor(factor);
}

void ImageDocumentTest::SetForceZeroLayoutHeight(bool force) {
  force_zero_layout_height_ = force;
  if (dummy_page_holder_) {
    dummy_page_holder_->GetPage().GetSettings().SetForceZeroLayoutHeight(force);
  }
}

TEST_F(ImageDocumentTest, ImageLoad) {
  CreateDocument(50, 50);
  EXPECT_EQ(50, ImageWidth());
  EXPECT_EQ(50, ImageHeight());
}

TEST_F(ImageDocumentTest, LargeImageScalesDown) {
  CreateDocument(25, 30);
  EXPECT_EQ(25, ImageWidth());
  EXPECT_EQ(25, ImageHeight());

  CreateDocument(35, 20);
  EXPECT_EQ(20, ImageWidth());
  EXPECT_EQ(20, ImageHeight());
}

TEST_F(ImageDocumentTest, RestoreImageOnClick) {
  CreateDocument(30, 40);
  GetDocument().ImageClicked(4, 4);
  EXPECT_EQ(50, ImageWidth());
  EXPECT_EQ(50, ImageHeight());
}

TEST_F(ImageDocumentTest, InitialZoomDoesNotAffectScreenFit) {
  SetPageZoom(2.f);
  CreateDocument(20, 10);
  EXPECT_EQ(10, ImageWidth());
  EXPECT_EQ(10, ImageHeight());
  GetDocument().ImageClicked(4, 4);
  EXPECT_EQ(50, ImageWidth());
  EXPECT_EQ(50, ImageHeight());
}

TEST_F(ImageDocumentTest, ZoomingDoesNotChangeRelativeSize) {
  CreateDocument(75, 75);
  SetPageZoom(0.5f);
  GetDocument().WindowSizeChanged();
  EXPECT_EQ(50, ImageWidth());
  EXPECT_EQ(50, ImageHeight());
  SetPageZoom(2.f);
  GetDocument().WindowSizeChanged();
  EXPECT_EQ(50, ImageWidth());
  EXPECT_EQ(50, ImageHeight());
}

TEST_F(ImageDocumentTest, ImageScalesDownWithDsf) {
  SetWindowToViewportScalingFactor(2.f);
  CreateDocument(20, 30);
  EXPECT_EQ(10, ImageWidth());
  EXPECT_EQ(10, ImageHeight());
}

TEST_F(ImageDocumentTest, ImageNotCenteredWithForceZeroLayoutHeight) {
  SetForceZeroLayoutHeight(true);
  CreateDocument(80, 70);
  EXPECT_FALSE(GetDocument().ShouldShrinkToFit());
  EXPECT_EQ(0, GetDocument().ImageElement()->OffsetLeft());
  EXPECT_EQ(0, GetDocument().ImageElement()->OffsetTop());
  EXPECT_EQ(50, ImageWidth());
  EXPECT_EQ(50, ImageHeight());
}

TEST_F(ImageDocumentTest, ImageCenteredWithoutForceZeroLayoutHeight) {
  SetForceZeroLayoutHeight(false);
  CreateDocument(80, 70);
  EXPECT_TRUE(GetDocument().ShouldShrinkToFit());
  EXPECT_EQ(15, GetDocument().ImageElement()->OffsetLeft());
  EXPECT_EQ(10, GetDocument().ImageElement()->OffsetTop());
  EXPECT_EQ(50, ImageWidth());
  EXPECT_EQ(50, ImageHeight());
}

TEST_F(ImageDocumentTest, DomInteractive) {
  CreateDocument(25, 30);
  EXPECT_FALSE(GetDocument().GetTiming().DomInteractive().is_null());
}

TEST_F(ImageDocumentTest, ImageSrcChangedBeforeFinish) {
  CreateDocumentWithoutLoadingImage(80, 70, /*is_animated*/ false);
  GetDocument().ImageElement()->removeAttribute(html_names::kSrcAttr);
  blink::test::RunPendingTasks();
}

TEST_F(ImageDocumentTest, ImageStyleContainsTransitionForNonAnimatedImage) {
  CreateDocument(50, 50);
  auto& style =
      GetDocument().ImageElement()->getAttribute(html_names::kStyleAttr);
  EXPECT_NE(style.Find("transition:"), kNotFound);
}

TEST_F(ImageDocumentTest, ImageStyleDoesNotContainTransitionForAnimatedImage) {
  CreateDocument(50, 50, /*is_animated*/ true);
  auto& style =
      GetDocument().ImageElement()->getAttribute(html_names::kStyleAttr);
  EXPECT_EQ(style.Find("transition:"), kNotFound);
}

#if BUILDFLAG(IS_ANDROID)
#define MAYBE(test) DISABLED_##test
#else
#define MAYBE(test) test
#endif

TEST_F(ImageDocumentTest, MAYBE(ImageCenteredAtDeviceScaleFactor)) {
  SetWindowToViewportScalingFactor(1.5f);
  CreateDocument(30, 30);

  EXPECT_TRUE(GetDocument().ShouldShrinkToFit());
  GetDocument().ImageClicked(15, 27);
  ScrollOffset offset =
      GetDocument().GetFrame()->View()->LayoutViewport()->GetScrollOffset();
  EXPECT_EQ(20, offset.x());
  EXPECT_EQ(20, offset.y());

  GetDocument().ImageClicked(20, 20);

  GetDocument().ImageClicked(12, 15);
  offset =
      GetDocument().GetFrame()->View()->LayoutViewport()->GetScrollOffset();
  if (RuntimeEnabledFeatures::FractionalScrollOffsetsEnabled()) {
    EXPECT_EQ(11.25f, offset.x());
    EXPECT_EQ(20, offset.y());
  } else {
    EXPECT_EQ(11, offset.x());
    EXPECT_EQ(20, offset.y());
  }
}

class ImageDocumentViewportTest : public SimTest {
 public:
  ImageDocumentViewportTest() = default;
  ~ImageDocumentViewportTest() override = default;

  void SetUp() override {
    SimTest::SetUp();
    WebView().GetSettings()->SetViewportEnabled(true);
    WebView().GetSettings()->SetViewportMetaEnabled(true);
    WebView().GetSettings()->SetShrinksViewportContentToFit(true);
    WebView().GetSettings()->SetMainFrameResizesAreOrientationChanges(true);
  }

  VisualViewport& GetVisualViewport() {
    return WebView().GetPage()->GetVisualViewport();
  }

  ImageDocument& GetDocument() {
    Document* document = To<LocalFrame>(WebView().GetPage()->MainFrame())
                             ->DomWindow()
                             ->document();
    ImageDocument* image_document = static_cast<ImageDocument*>(document);
    return *image_document;
  }
};

// Tests that hiding the URL bar doesn't cause a "jump" when viewing an image
// much wider than the viewport.
TEST_F(ImageDocumentViewportTest, HidingURLBarDoesntChangeImageLocation) {
  v8::HandleScope handle_scope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());

  // Initialize with the URL bar showing. Make the viewport very thin so that
  // we load an image much wider than the viewport but fits vertically. The
  // page will load zoomed out so the image will be vertically centered.
  WebView().ResizeWithBrowserControls(gfx::Size(5, 40), 10, 10, true);
  SimRequest request("https://example.com/test.jpg", "image/jpeg");
  LoadURL("https://example.com/test.jpg");

  Vector<char> data;
  data.AppendVector(JpegImage());
  request.Complete(data);

  Compositor().BeginFrame();

  HTMLImageElement* img = GetDocument().ImageElement();
  DOMRect* rect = img->GetBoundingClientRect();

  // Some initial sanity checking. We'll use the BoundingClientRect for the
  // image location since that's relative to the layout viewport and the layout
  // viewport is unscrollable in this test. Since the image is 10X wider than
  // the viewport, we'll zoom out to 0.1. This means the layout viewport is 400
  // pixels high so the image will be centered in that.
  ASSERT_EQ(50u, img->width());
  ASSERT_EQ(50u, img->height());
  ASSERT_EQ(0.1f, GetVisualViewport().Scale());
  ASSERT_EQ(0, rect->x());
  ASSERT_EQ(175, rect->y());

  // Hide the URL bar. This will make the viewport taller but won't change the
  // layout size so the image location shouldn't change.
  WebView().ResizeWithBrowserControls(gfx::Size(5, 50), 10, 10, false);
  Compositor().BeginFrame();
  rect = img->GetBoundingClientRect();
  EXPECT_EQ(50, rect->width());
  EXPECT_EQ(50, rect->height());
  EXPECT_EQ(0, rect->x());
  EXPECT_EQ(125, rect->y());
}

TEST_F(ImageDocumentViewportTest, ScaleImage) {
  v8::HandleScope handle_scope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  SimRequest request("https://example.com/test.jpg", "image/jpeg");
  LoadURL("https://example.com/test.jpg");

  Vector<char> data;
  data.AppendVector(JpegImage());
  request.Complete(data);

  HTMLImageElement* img = GetDocument().ImageElement();

  // no zoom
  WebView().MainFrameWidget()->Resize(gfx::Size(100, 100));
  WebView().SetZoomFactorForDeviceScaleFactor(1.f);
  Compositor().BeginFrame();
  EXPECT_EQ(50u, img->width());
  EXPECT_EQ(50u, img->height());
  EXPECT_EQ(100, GetDocument().CalculateDivWidth());
  EXPECT_EQ(1.f, GetVisualViewport().Scale());
  EXPECT_EQ(100, GetVisualViewport().Width());
  EXPECT_EQ(100, GetVisualViewport().Height());

  // zoom-for-dsf = 4. WebView size is in physical pixel(400*400), image and
  // visual viewport should be same in CSS pixel, as no dsf applied.
  // This simulates running on two phones with different screen densities but
  // same (physical) screen size, image document should displayed the same.
  WebView().MainFrameWidget()->Resize(gfx::Size(400, 400));
  WebView().SetZoomFactorForDeviceScaleFactor(4.f);
  Compositor().BeginFrame();
  EXPECT_EQ(50u, img->width());
  EXPECT_EQ(50u, img->height());
  EXPECT_EQ(100, GetDocument().CalculateDivWidth());
  EXPECT_EQ(1.f, GetVisualViewport().Scale());
  EXPECT_EQ(100, GetVisualViewport().Width());
  EXPECT_EQ(100, GetVisualViewport().Height());
}

// Tests that with zoom factor for device scale factor, image with different
// size fit in the viewport correctly.
TEST_F(ImageDocumentViewportTest, DivWidth) {
  v8::HandleScope handle_scope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  SimRequest request("https://example.com/test.jpg", "image/jpeg");
  LoadURL("https://example.com/test.jpg");

  Vector<char> data;
  data.AppendVector(JpegImage());
  request.Complete(data);

  HTMLImageElement* img = GetDocument().ImageElement();

  WebView().SetZoomFactorForDeviceScaleFactor(2.f);

  // Image smaller then webview size, visual viewport is not zoomed, and image
  // will be centered in the viewport.
  WebView().MainFrameWidget()->Resize(gfx::Size(200, 200));
  Compositor().BeginFrame();
  EXPECT_EQ(50u, img->width());
  EXPECT_EQ(50u, img->height());
  EXPECT_EQ(100, GetDocument().CalculateDivWidth());
  EXPECT_EQ(1.f, GetVisualViewport().Scale());
  EXPECT_EQ(100, GetVisualViewport().Width());
  EXPECT_EQ(100, GetVisualViewport().Height());
  DOMRect* rect = img->GetBoundingClientRect();
  EXPECT_EQ(25, rect->x());
  EXPECT_EQ(25, rect->y());

  // Image wider than webview size, image should fill the visual viewport, and
  // visual viewport zoom out to 0.5.
  WebView().MainFrameWidget()->Resize(gfx::Size(50, 50));
  Compositor().BeginFrame();
  EXPECT_EQ(50u, img->width());
  EXPECT_EQ(50u, img->height());
  EXPECT_EQ(50, GetDocument().CalculateDivWidth());
  EXPECT_EQ(0.5f, GetVisualViewport().Scale());
  EXPECT_EQ(50, GetVisualViewport().Width());
  EXPECT_EQ(50, GetVisualViewport().Height());

  // When image is more than 10X wider than webview, shrink the image to fit the
  // width of the screen.
  WebView().MainFrameWidget()->Resize(gfx::Size(4, 20));
  Compositor().BeginFrame();
  EXPECT_EQ(20u, img->width());
  EXPECT_EQ(20u, img->height());
  EXPECT_EQ(20, GetDocument().CalculateDivWidth());
  EXPECT_EQ(0.1f, GetVisualViewport().Scale());
  EXPECT_EQ(20, GetVisualViewport().Width());
  EXPECT_EQ(100, GetVisualViewport().Height());
  rect = img->GetBoundingClientRect();
  EXPECT_EQ(0, rect->x());
  EXPECT_EQ(40, rect->y());
}

#undef MAYBE
}  // namespace blink
```