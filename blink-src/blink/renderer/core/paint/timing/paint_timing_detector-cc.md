Response:
My thought process to analyze the `paint_timing_detector.cc` file went something like this:

1. **Understand the Core Purpose:** The file name itself, "paint_timing_detector.cc", strongly suggests its primary function is to detect and record various paint timing metrics within the Chromium Blink rendering engine. This is my initial and most crucial understanding.

2. **Identify Key Dependencies (Includes):** I scanned the `#include` directives to identify the main components and concepts this file interacts with. This revealed:
    * **`base/metrics/histogram_functions.h`**:  Indicates the file reports data using histograms (for performance analysis).
    * **`third_party/blink/public/common/features.h`**:  Suggests feature flags might control some of its behavior.
    * **`third_party/blink/public/common/input/web_input_event.h`**:  Points to interaction with user input events.
    * **`third_party/blink/public/common/performance/largest_contentful_paint_type.h`**:  Confirms involvement in Largest Contentful Paint (LCP) calculation.
    * A large number of Blink-specific headers related to DOM, frames, layout, loading, painting, styling, and timing. These indicate the file works deep within the rendering pipeline.

3. **Analyze Class Structure:**  I noticed the definition of the `PaintTimingDetector` class. This is the central entity, so I started examining its methods and member variables.

4. **Deconstruct Key Methods:** I focused on the most important methods, based on their names and context:
    * **`NotifyPaintFinished()`**: Likely triggered after a paint operation, used to finalize and report timing data.
    * **`NotifyBackgroundImagePaint()` and `NotifyImagePaint()`**: Clearly responsible for detecting and recording paint times for background and regular images.
    * **`NotifyImageFinished()`**:  Called when an image has finished loading.
    * **`OnInputOrScroll()`**: Handles user interactions that can impact paint timing.
    * **`RestartRecordingLCP()` and `SoftNavigationDetected()`**:  Related to handling soft navigations and their impact on LCP.
    * **`UpdateMetricsLcp()` and `UpdateLcpCandidate()`**: Update and report LCP metrics.
    * **`CalculateVisualRect()`**:  Calculates the visual position of elements.

5. **Identify Sub-Components:** I noticed the member variables `text_paint_timing_detector_`, `image_paint_timing_detector_`, and `largest_contentful_paint_calculator_`. This suggests the `PaintTimingDetector` delegates specific tasks to these sub-detectors and calculators.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  With the understanding of the methods, I could start linking them to web technologies:
    * **HTML:** The detector interacts with `HTMLImageElement`, `<body>`, `<html>` elements, indicating its role in measuring the paint time of content defined in HTML.
    * **CSS:** The handling of background images (`NotifyBackgroundImagePaint`) directly relates to CSS `background-image` properties. The detection of contentful background images based on not being attached to `<body>` or `<html>` reflects CSS best practices for meaningful content.
    * **JavaScript:** While this specific file doesn't directly *execute* JavaScript, its measurements are exposed to JavaScript via the Performance API. The code interacts with `DOMWindowPerformance`.

7. **Infer Logic and Assumptions:** Based on the method names and the surrounding code, I could infer logical flows:
    *  A paint happens -> `NotifyPaintFinished` is called.
    *  An image is painted -> `NotifyImagePaint` is called, recording its size and timing.
    *  User interacts with the page -> `OnInputOrScroll` stops recording LCP.
    *  Soft navigation is detected -> `SoftNavigationDetected` adjusts LCP calculations.

8. **Consider User and Programming Errors:**  The code analyzing image pixel inaccuracy suggested potential developer errors related to using incorrect image sizes in HTML or CSS (`sizes` attribute). The handling of input and scroll events highlighted potential misuse where a single `keyup` isn't considered a significant user interaction for LCP.

9. **Trace User Actions (Debugging Scenario):**  I thought about how a user action leads to this code being executed. A page load, rendering, and any subsequent paint operation would involve this detector. Specific user interactions like scrolling or clicking would trigger the `OnInputOrScroll` logic.

10. **Refine and Organize:** I then organized my findings into the requested categories (functionality, relationship to web technologies, logic, errors, debugging). I used examples to illustrate the connections to HTML, CSS, and JavaScript. I also made sure to present the assumptions and potential issues clearly.

Essentially, I performed a code review with a focus on understanding the *what*, *why*, and *how* of the code, relating it back to the user-facing web experience and potential developer pitfalls. I leveraged the naming conventions, the included headers, and the overall structure of the code to build a comprehensive understanding.
好的，让我们来分析一下 `blink/renderer/core/paint/timing/paint_timing_detector.cc` 这个文件。

**文件功能总览：**

`paint_timing_detector.cc` 文件的核心功能是**检测和记录页面渲染过程中的关键时间点，特别是与首次内容绘制 (First Contentful Paint, FCP) 和最大内容绘制 (Largest Contentful Paint, LCP) 相关的指标。**  它负责监听渲染管道中的事件，判断哪些元素是潜在的 FCP 和 LCP 候选者，并记录它们的绘制时间，最终将这些数据暴露给 JavaScript 的 Performance API。

**具体功能点：**

1. **FCP 和 LCP 的检测与记录:**
   -  跟踪文本和图片元素的绘制过程。
   -  判断哪些文本或图片是 FCP 和 LCP 的候选元素。
   -  记录这些候选元素的绘制时间、大小、位置等信息。
   -  处理软导航 (Soft Navigation) 对 LCP 的影响，并能重启 LCP 的记录。

2. **处理背景图片:**
   -  识别并记录有意义的背景图片的绘制时间，但会排除应用于 `<body>` 或 `<html>` 元素的背景图片，因为这些通常用于装饰目的。

3. **处理用户交互:**
   -  监听用户的输入事件（如鼠标点击、键盘输入）和滚动事件。
   -  一旦检测到用户交互，会停止记录当前的 LCP 指标，因为用户交互意味着页面已经对用户可见并可交互。

4. **处理图片加载完成:**
   -  接收图片加载完成的通知，用于更精确地计算 LCP 时间。

5. **处理元素销毁:**
   -  监听布局对象（LayoutObject）的销毁事件，以便清理相关的计时信息。

6. **报告指标:**
   -  将收集到的 FCP 和 LCP 数据更新到 `DOMWindowPerformance` 对象，使其可以通过 JavaScript 的 Performance API 访问。
   -  使用 UMA (User Metrics Analysis) 记录一些内部指标，例如图片像素不准确的情况。

7. **软导航支持:**
   -  能够检测软导航事件，并在软导航发生时重启 LCP 的记录，以便更准确地衡量单页应用等场景下的性能。

8. **可视化调试:**
   -  如果启用了 `PaintTimingVisualizer`，可以记录主框架的视口信息，用于调试。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **JavaScript (Performance API):**
   - **功能关系：** `paint_timing_detector.cc` 收集的 FCP 和 LCP 数据最终会通过 `DOMWindowPerformance` 对象暴露给 JavaScript 的 Performance API。开发者可以使用 `performance.getEntriesByType('paint')` 来获取这些性能指标。
   - **举例说明：**
     ```javascript
     performance.getEntriesByType('paint').forEach(entry => {
       console.log(entry.name, entry.startTime);
     });
     ```
     这段 JavaScript 代码可以获取到 FCP 和 LCP 的时间戳，这些时间戳的记录逻辑就位于 `paint_timing_detector.cc` 中。

2. **HTML (元素和结构):**
   - **功能关系：** `paint_timing_detector.cc` 需要识别 HTML 中的文本节点 (`TextPaintTimingDetector`) 和图片元素 (`ImagePaintTimingDetector`)，以便跟踪它们的绘制时间。它会检查元素的类型（例如 `HTMLImageElement`）。
   - **举例说明：**
     ```html
     <!DOCTYPE html>
     <html>
     <head>
       <title>Paint Timing Example</title>
     </head>
     <body>
       <h1>Hello, World!</h1> <!-  可能成为 FCP 候选者 -->
       <img src="image.jpg" alt="A test image"> <!- 可能成为 FCP 或 LCP 候选者 -->
     </body>
     </html>
     ```
     当浏览器渲染这个 HTML 页面时，`paint_timing_detector.cc` 会检测到 `<h1>` 标签中的文本和 `<img>` 标签，并记录它们的绘制时间。

3. **CSS (样式和渲染):**
   - **功能关系：** CSS 样式会影响元素的渲染方式和可见性，从而影响 FCP 和 LCP 的计算。`paint_timing_detector.cc` 会考虑元素的样式信息，例如背景图片 (`NotifyBackgroundImagePaint`)。
   - **举例说明：**
     ```css
     .content {
       background-image: url('background.png'); /* 可能成为 FCP 或 LCP 候选者 */
       width: 200px;
       height: 100px;
     }
     ```
     如果一个带有背景图片的 `div` 元素是页面上最大的可见内容，并且在首屏内，那么 `paint_timing_detector.cc` 可能会将其识别为 LCP 候选者，并记录 `background.png` 的绘制时间。

**逻辑推理、假设输入与输出：**

**假设输入：**

1. 一个 HTML 页面包含一个较大的 `<img>` 标签，它是首屏中渲染的最大的元素。
2. 用户首次访问该页面，页面开始渲染。
3. 图片资源加载完成并被绘制到屏幕上。

**逻辑推理：**

1. 当渲染引擎遇到 `<img>` 标签时，`ImagePaintTimingDetector` 会开始跟踪该元素。
2. 当图片资源加载完成后，`NotifyImageFinished` 会被调用。
3. 在图片被绘制到屏幕上时，`NotifyImagePaint` 会被调用，并记录绘制时间、大小和位置信息。
4. 如果该图片是当前为止渲染的最大的内容元素，则它会被标记为 LCP 候选者。
5. 当页面渲染完成后，或者当用户发生交互时，LCP 的最终值会被确定并记录到 `DOMWindowPerformance` 中。

**假设输出：**

- JavaScript 的 Performance API 可以获取到一个 `paint` 类型的条目，其 `name` 属性为 `"largest-contentful-paint"`，`startTime` 属性是该图片完成绘制的时间戳。

**用户或编程常见的使用错误及举例说明：**

1. **错误：** 开发者误认为所有背景图片都会被计入 LCP。
   - **说明：** `paint_timing_detector.cc` 中有逻辑判断，排除了应用于 `<body>` 或 `<html>` 元素的背景图片，因为这些通常是装饰性的。
   - **举例：** 如果开发者将一个很大的背景图片应用于 `<body>` 元素，并期望它能被计入 LCP，那么实际的 LCP 可能会是其他元素。

2. **错误：** 开发者在页面加载完成后很久才动态插入一个很大的图片，并期望它能被计入 LCP。
   - **说明：** LCP 的计算通常会在页面初始加载阶段进行，并在用户首次交互后停止记录。
   - **举例：** 如果一个用户在页面加载 5 秒后才通过点击按钮加载并显示一张大图，这张图片很可能不会被计入最初的 LCP。

3. **错误：** 开发者没有优化图片加载，导致 LCP 时间过长，但不知道具体是哪个图片影响了 LCP。
   - **说明：** `paint_timing_detector.cc` 记录了 LCP 候选元素的信息，开发者可以通过 Performance API 获取这些信息进行分析。
   - **调试：** 开发者可以使用浏览器的开发者工具 (Performance 面板) 来查看 LCP 指标，并找到导致 LCP 的元素。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入网址或点击链接，发起页面加载请求。**
2. **浏览器接收到 HTML 响应，开始解析 HTML 文档，构建 DOM 树。**
3. **解析过程中，浏览器发现需要加载 CSS 和图片等资源，发起资源请求。**
4. **渲染引擎开始布局 (Layout) 过程，计算元素的位置和大小。**  在这个阶段，`PaintTimingDetector` 开始工作，监听布局变化。
5. **渲染引擎进入绘制 (Paint) 阶段。**
   - 当文本内容被绘制时，`TextPaintTimingDetector::Record()` 等方法会被调用。
   - 当图片元素或背景图片被绘制时，`PaintTimingDetector::NotifyImagePaint()` 或 `NotifyBackgroundImagePaint()` 会被调用。
   - 这些方法会检查元素是否是 FCP 或 LCP 的候选者，并记录相关的绘制时间戳。
6. **如果用户在页面加载过程中进行了交互（例如滚动、点击），`PaintTimingDetector::OnInputOrScroll()` 会被调用，停止 LCP 的记录。**
7. **页面加载完成后，`PaintTimingDetector` 会将收集到的 FCP 和 LCP 数据更新到 `DOMWindowPerformance` 对象。**
8. **开发者可以使用 JavaScript 代码 `performance.getEntriesByType('paint')` 来查看这些性能指标。**
9. **在调试时，开发者可以在 Performance 面板中查看 "Timings" 或 "Experience" 部分，找到 "LCP" 或 "FCP" 的标记，从而定位到导致这些指标的元素和时间点。**  Blink 开发者也可以通过在 `paint_timing_detector.cc` 中添加日志输出来跟踪代码的执行流程和关键变量的值。

总而言之，`paint_timing_detector.cc` 是 Chromium Blink 引擎中一个至关重要的组件，它默默地监控着页面的渲染过程，记录关键的性能指标，为开发者优化网页性能提供了重要的数据支持。理解它的工作原理有助于我们更好地理解浏览器的渲染过程和性能指标的含义。

Prompt: 
```
这是目录为blink/renderer/core/paint/timing/paint_timing_detector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"

#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/performance/largest_contentful_paint_type.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/timing/image_paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/timing/largest_contentful_paint_calculator.h"
#include "third_party/blink/renderer/core/paint/timing/text_paint_timing_detector.h"
#include "third_party/blink/renderer/core/style/style_fetched_image.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/graphics/paint/float_clip_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/property_tree_state.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/loader/fetch/media_timing.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {

namespace {

// In the context of FCP++, we define contentful background image as one that
// satisfies all of the following conditions:
// * has image reources attached to style of the object, i.e.,
//  { background-image: url('example.gif') }
// * not attached to <body> or <html>
// This function contains the above heuristics.
bool IsBackgroundImageContentful(const LayoutObject& object,
                                 const Image& image) {
  // Background images attached to <body> or <html> are likely for background
  // purpose, so we rule them out.
  if (IsA<LayoutView>(object) || object.IsBody() ||
      object.IsDocumentElement()) {
    return false;
  }
  return true;
}

void ReportImagePixelInaccuracy(HTMLImageElement* image_element) {
  DCHECK(image_element);
  ImageResourceContent* image_content = image_element->CachedImage();
  if (!image_content || !image_content->IsLoaded()) {
    return;
  }
  Document& document = image_element->GetDocument();
  // Get the intrinsic dimensions from the image resource
  gfx::Size intrinsic_dimensions =
      image_content->IntrinsicSize(kRespectImageOrientation);

  // Get the layout dimensions and screen DPR
  uint32_t layout_width = image_element->LayoutBoxWidth();
  uint32_t layout_height = image_element->LayoutBoxHeight();
  float document_dpr = document.DevicePixelRatio();

  // Get the size attribute calculated width, if any
  std::optional<float> sizes_width = image_element->GetResourceWidth();
  // Report offset in pixels between intrinsic and layout dimensions
  const float kDPRCap = 2.0;
  float capped_dpr = std::min(document_dpr, kDPRCap);
  uint64_t fetched_pixels = intrinsic_dimensions.Area64();
  uint64_t needed_pixels = base::saturated_cast<uint64_t>(
      (layout_width * document_dpr) * (layout_height * document_dpr));
  uint64_t capped_pixels = base::saturated_cast<uint64_t>(
      (layout_width * capped_dpr) * (layout_height * capped_dpr));

  bool has_overfetched_pixels = fetched_pixels > needed_pixels;
  base::UmaHistogramBoolean("Renderer.Images.HasOverfetchedPixels",
                            has_overfetched_pixels);
  if (has_overfetched_pixels) {
    uint64_t overfetched_pixels = fetched_pixels - needed_pixels;
    base::UmaHistogramCounts10M("Renderer.Images.OverfetchedPixels",
                                base::saturated_cast<int>(overfetched_pixels));
  }

  bool has_overfetched_capped_pixels = fetched_pixels > capped_pixels;
  base::UmaHistogramBoolean("Renderer.Images.HasOverfetchedCappedPixels",
                            has_overfetched_capped_pixels);
  if (has_overfetched_capped_pixels) {
    uint64_t overfetched_capped_pixels = fetched_pixels - capped_pixels;
    base::UmaHistogramCounts10M(
        "Renderer.Images.OverfetchedCappedPixels",
        base::saturated_cast<int>(overfetched_capped_pixels));
  }

  // Report offset in pixels between layout width and sizes result
  if (sizes_width) {
    int sizes_miss =
        base::saturated_cast<int>(sizes_width.value() - layout_width);

    base::UmaHistogramBoolean("Renderer.Images.HasSizesAttributeMiss",
                              sizes_miss > 0);
    if (sizes_miss > 0) {
      base::UmaHistogramCounts10000("Renderer.Images.SizesAttributeMiss",
                                    sizes_miss);
    }
  }
}

}  // namespace

PaintTimingDetector::PaintTimingDetector(LocalFrameView* frame_view)
    : frame_view_(frame_view),
      text_paint_timing_detector_(
          MakeGarbageCollected<TextPaintTimingDetector>(frame_view,
                                                        this,
                                                        nullptr /*set later*/)),
      image_paint_timing_detector_(
          MakeGarbageCollected<ImagePaintTimingDetector>(
              frame_view,
              nullptr /*set later*/)),
      callback_manager_(
          MakeGarbageCollected<PaintTimingCallbackManagerImpl>(frame_view)) {
  if (PaintTimingVisualizer::IsTracingEnabled()) {
    visualizer_.emplace();
  }
  text_paint_timing_detector_->ResetCallbackManager(callback_manager_.Get());
  image_paint_timing_detector_->ResetCallbackManager(callback_manager_.Get());
}

void PaintTimingDetector::NotifyPaintFinished() {
  if (PaintTimingVisualizer::IsTracingEnabled()) {
    if (!visualizer_) {
      visualizer_.emplace();
    }
    visualizer_->RecordMainFrameViewport(*frame_view_);
  } else {
    visualizer_.reset();
  }
  text_paint_timing_detector_->OnPaintFinished();
  if (image_paint_timing_detector_) {
    image_paint_timing_detector_->OnPaintFinished();
  }
  if (callback_manager_->CountCallbacks() > 0) {
    callback_manager_->RegisterPaintTimeCallbackForCombinedCallbacks();
  }
  LocalDOMWindow* window = frame_view_->GetFrame().DomWindow();
  if (window) {
    DOMWindowPerformance::performance(*window)->OnPaintFinished();
  }
}

// static
bool PaintTimingDetector::NotifyBackgroundImagePaint(
    const Node& node,
    const Image& image,
    const StyleImage& style_image,
    const PropertyTreeStateOrAlias& current_paint_chunk_properties,
    const gfx::Rect& image_border) {
  LayoutObject* object = node.GetLayoutObject();
  if (!object) {
    return false;
  }
  LocalFrameView* frame_view = object->GetFrameView();
  if (!frame_view) {
    return false;
  }

  PaintTimingDetector& paint_timing_detector =
      frame_view->GetPaintTimingDetector();
  if (paint_timing_detector.IsUnrelatedSoftNavigationPaint(node)) {
    return false;
  }
  ImagePaintTimingDetector& image_paint_timing_detector =
      paint_timing_detector.GetImagePaintTimingDetector();
  if (!image_paint_timing_detector.IsRecordingLargestImagePaint()) {
    return false;
  }

  if (!IsBackgroundImageContentful(*object, image)) {
    return false;
  }

  ImageResourceContent* cached_image = style_image.CachedImage();
  DCHECK(cached_image);
  // TODO(yoav): |image| and |cached_image.GetImage()| are not the same here in
  // the case of SVGs. Figure out why and if we can remove this footgun.

  return image_paint_timing_detector.RecordImage(
      *object, image.Size(), *cached_image, current_paint_chunk_properties,
      &style_image, image_border);
}

// static
bool PaintTimingDetector::NotifyImagePaint(
    const LayoutObject& object,
    const gfx::Size& intrinsic_size,
    const MediaTiming& media_timing,
    const PropertyTreeStateOrAlias& current_paint_chunk_properties,
    const gfx::Rect& image_border) {
  if (IgnorePaintTimingScope::ShouldIgnore()) {
    return false;
  }
  LocalFrameView* frame_view = object.GetFrameView();
  if (!frame_view) {
    return false;
  }
  PaintTimingDetector& paint_timing_detector =
      frame_view->GetPaintTimingDetector();
  ImagePaintTimingDetector& image_paint_timing_detector =
      paint_timing_detector.GetImagePaintTimingDetector();
  if (!image_paint_timing_detector.IsRecordingLargestImagePaint()) {
    return false;
  }

  Node* image_node = object.GetNode();
  if (image_node &&
      paint_timing_detector.IsUnrelatedSoftNavigationPaint(*image_node)) {
    return false;
  }
  HTMLImageElement* element = DynamicTo<HTMLImageElement>(image_node);

  if (element) {
    // This doesn't capture poster. That's probably fine.
    ReportImagePixelInaccuracy(element);
  }

  return image_paint_timing_detector.RecordImage(
      object, intrinsic_size, media_timing, current_paint_chunk_properties,
      nullptr, image_border);
}

void PaintTimingDetector::NotifyImageFinished(const LayoutObject& object,
                                              const MediaTiming* media_timing) {
  if (IgnorePaintTimingScope::ShouldIgnore() ||
      !image_paint_timing_detector_->IsRecordingLargestImagePaint()) {
    return;
  }
  image_paint_timing_detector_->NotifyImageFinished(object, media_timing);
}

void PaintTimingDetector::LayoutObjectWillBeDestroyed(
    const LayoutObject& object) {
  text_paint_timing_detector_->LayoutObjectWillBeDestroyed(object);
}

void PaintTimingDetector::NotifyImageRemoved(
    const LayoutObject& object,
    const ImageResourceContent* cached_image) {
  if (image_paint_timing_detector_->IsRecordingLargestImagePaint()) {
    image_paint_timing_detector_->NotifyImageRemoved(object, cached_image);
  }
}

void PaintTimingDetector::OnInputOrScroll() {
  // If we have already stopped and we're no longer recording the largest image
  // paint, then abort.
  if (!image_paint_timing_detector_->IsRecordingLargestImagePaint()) {
    return;
  }

  // TextPaintTimingDetector is used for both Largest Contentful Paint and for
  // Element Timing. Therefore, here we only want to stop recording Largest
  // Contentful Paint.
  text_paint_timing_detector_->StopRecordingLargestTextPaint();
  // ImagePaintTimingDetector is currently only being used for
  // LargestContentfulPaint.
  image_paint_timing_detector_->StopRecordEntries();
  image_paint_timing_detector_->StopRecordingLargestImagePaint();
  largest_contentful_paint_calculator_ = nullptr;
  record_lcp_to_metrics_ = false;

  // Set first_input_or_scroll_notified_timestamp_ only once.
  if (first_input_or_scroll_notified_timestamp_ == base::TimeTicks()) {
    first_input_or_scroll_notified_timestamp_ = base::TimeTicks::Now();
  }

  DidChangePerformanceTiming();
}

void PaintTimingDetector::NotifyInputEvent(WebInputEvent::Type type) {
  // A single keyup event should be ignored. It could be caused by user actions
  // such as refreshing via Ctrl+R.
  if (type == WebInputEvent::Type::kMouseMove ||
      type == WebInputEvent::Type::kMouseEnter ||
      type == WebInputEvent::Type::kMouseLeave ||
      type == WebInputEvent::Type::kKeyUp ||
      WebInputEvent::IsPinchGestureEventType(type)) {
    return;
  }
  OnInputOrScroll();
}

void PaintTimingDetector::NotifyScroll(mojom::blink::ScrollType scroll_type) {
  if (scroll_type != mojom::blink::ScrollType::kUser &&
      scroll_type != mojom::blink::ScrollType::kCompositor) {
    return;
  }
  OnInputOrScroll();
}

bool PaintTimingDetector::NeedToNotifyInputOrScroll() const {
  DCHECK(text_paint_timing_detector_);
  return text_paint_timing_detector_->IsRecordingLargestTextPaint() ||
         image_paint_timing_detector_;
}

void PaintTimingDetector::RestartRecordingLCP() {
  text_paint_timing_detector_->RestartRecordingLargestTextPaint();
  image_paint_timing_detector_->RestartRecordingLargestImagePaint();
  lcp_was_restarted_ = true;
  soft_navigation_was_detected_ = false;
  GetLargestContentfulPaintCalculator()->ResetMetricsLcp();
}

void PaintTimingDetector::SoftNavigationDetected(LocalDOMWindow* window) {
  soft_navigation_was_detected_ = true;
  auto* lcp_calculator = GetLargestContentfulPaintCalculator();
  // If the window is detached (no calculator) or we haven't yet got any
  // presentation times for neither a text record nor an image one, bail. The
  // web exposed entry will get updated when the presentation times callback
  // will be called.
  if (!lcp_calculator || (!potential_soft_navigation_text_record_ &&
                          !potential_soft_navigation_image_record_)) {
    return;
  }
  if (!lcp_was_restarted_ ||
      RuntimeEnabledFeatures::SoftNavigationHeuristicsEnabled(window)) {
    lcp_calculator->UpdateWebExposedLargestContentfulPaintIfNeeded(
        potential_soft_navigation_text_record_,
        potential_soft_navigation_image_record_,
        /*is_triggered_by_soft_navigation=*/lcp_was_restarted_);
  }

  // Report the soft navigation LCP to metrics.
  CHECK(record_soft_navigation_lcp_for_metrics_);
  soft_navigation_lcp_details_for_metrics_ =
      largest_contentful_paint_calculator_->LatestLcpDetails();
  DidChangePerformanceTiming();
}

void PaintTimingDetector::RestartRecordingLCPToUkm() {
  text_paint_timing_detector_->RestartRecordingLargestTextPaint();
  image_paint_timing_detector_->RestartRecordingLargestImagePaint();
  record_soft_navigation_lcp_for_metrics_ = true;
  // Reset the lcp candidate and the soft navigation LCP for reporting to UKM
  // when a new soft navigation happens. When this resetting happens, the
  // previous lcp details should already be updated.
  soft_navigation_lcp_details_for_metrics_ = LargestContentfulPaintDetails();
}

LargestContentfulPaintCalculator*
PaintTimingDetector::GetLargestContentfulPaintCalculator() {
  if (largest_contentful_paint_calculator_) {
    return largest_contentful_paint_calculator_.Get();
  }

  auto* dom_window = frame_view_->GetFrame().DomWindow();
  if (!dom_window) {
    return nullptr;
  }

  largest_contentful_paint_calculator_ =
      MakeGarbageCollected<LargestContentfulPaintCalculator>(
          DOMWindowPerformance::performance(*dom_window));
  return largest_contentful_paint_calculator_.Get();
}

void PaintTimingDetector::UpdateMetricsLcp() {
  // The DidChangePerformanceTiming method which triggers the reporting of
  // metrics LCP would not be called when we are not recording metrics LCP.
  if (!record_lcp_to_metrics_ && !record_soft_navigation_lcp_for_metrics_) {
    return;
  }

  if (record_lcp_to_metrics_) {
    auto latest_lcp_details =
        GetLargestContentfulPaintCalculator()->LatestLcpDetails();
    lcp_details_for_metrics_ = latest_lcp_details;
  }

  // If we're waiting on a softnav and it wasn't detected yet, keep on waiting
  // and don't update.
  if (record_soft_navigation_lcp_for_metrics_ &&
      soft_navigation_was_detected_) {
    auto latest_lcp_details =
        GetLargestContentfulPaintCalculator()->LatestLcpDetails();
    soft_navigation_lcp_details_for_metrics_ = latest_lcp_details;
  }

  DidChangePerformanceTiming();
}

void PaintTimingDetector::DidChangePerformanceTiming() {
  Document* document = frame_view_->GetFrame().GetDocument();
  if (!document) {
    return;
  }
  DocumentLoader* loader = document->Loader();
  if (!loader) {
    return;
  }
  loader->DidChangePerformanceTiming();
}

gfx::RectF PaintTimingDetector::BlinkSpaceToDIPs(const gfx::RectF& rect) const {
  FrameWidget* widget = frame_view_->GetFrame().GetWidgetForLocalRoot();
  // May be nullptr in tests.
  if (!widget) {
    return rect;
  }
  return widget->BlinkSpaceToDIPs(rect);
}

gfx::RectF PaintTimingDetector::CalculateVisualRect(
    const gfx::Rect& visual_rect,
    const PropertyTreeStateOrAlias& current_paint_chunk_properties) const {
  // This case should be dealt with outside the function.
  DCHECK(!visual_rect.IsEmpty());

  // As Layout objects live in different transform spaces, the object's rect
  // should be projected to the viewport's transform space.
  FloatClipRect float_clip_visual_rect((gfx::RectF(visual_rect)));
  const LocalFrame& local_root = frame_view_->GetFrame().LocalFrameRoot();
  GeometryMapper::LocalToAncestorVisualRect(current_paint_chunk_properties,
                                            local_root.ContentLayoutObject()
                                                ->FirstFragment()
                                                .LocalBorderBoxProperties(),
                                            float_clip_visual_rect);
  if (local_root.IsOutermostMainFrame()) {
    return BlinkSpaceToDIPs(float_clip_visual_rect.Rect());
  }

  // TODO(crbug.com/1346602): Enabling frames from a fenced frame tree to map
  // to the outermost main frame enables fenced content to learn about its
  // position in the embedder which can be used to communicate from embedder to
  // embeddee. For now, return the rect in the local root (not great for remote
  // frames) to avoid introducing a side channel but this will require design
  // work to fix in the long term.
  if (local_root.IsInFencedFrameTree()) {
    return BlinkSpaceToDIPs(float_clip_visual_rect.Rect());
  }

  // OOPIF. The final rect lives in the iframe's root frame space. We need to
  // project it to the top frame space.
  auto layout_visual_rect =
      PhysicalRect::EnclosingRect(float_clip_visual_rect.Rect());
  frame_view_->GetFrame()
      .LocalFrameRoot()
      .View()
      ->MapToVisualRectInRemoteRootFrame(layout_visual_rect);
  return BlinkSpaceToDIPs(gfx::RectF(layout_visual_rect));
}

void PaintTimingDetector::UpdateLcpCandidate() {
  auto* lcp_calculator = GetLargestContentfulPaintCalculator();
  if (!lcp_calculator) {
    return;
  }

  // * nullptr means there is no new candidate update, which could be caused by
  // user input or no content show up on the page.
  // * Record.paint_time == 0 means there is an image but the image is still
  // loading. The perf API should wait until the paint-time is available.
  std::pair<TextRecord*, bool> text_update_result = {nullptr, false};
  std::pair<ImageRecord*, bool> image_update_result = {nullptr, false};

  if (text_paint_timing_detector_->IsRecordingLargestTextPaint()) {
    text_update_result = text_paint_timing_detector_->UpdateMetricsCandidate();
  }

  if (image_paint_timing_detector_->IsRecordingLargestImagePaint()) {
    image_update_result =
        image_paint_timing_detector_->UpdateMetricsCandidate();
  }

  if (image_update_result.second || text_update_result.second) {
    UpdateMetricsLcp();
  }
  // If we stopped and then restarted LCP measurement (to support soft
  // navigations), and didn't yet detect a soft navigation, put aside the
  // records as potential soft navigation LCP ones, and don't update the web
  // exposed entries just yet. We'll do that once we actually detect the soft
  // navigation.
  if (lcp_was_restarted_ && !soft_navigation_was_detected_) {
    potential_soft_navigation_text_record_ = text_update_result.first;
    potential_soft_navigation_image_record_ = image_update_result.first;
    return;
  }
  potential_soft_navigation_text_record_ = nullptr;
  potential_soft_navigation_image_record_ = nullptr;

  // If we're still recording the initial LCP, or if LCP was explicitly
  // restarted for soft navigations, fire the web exposed entry.
  if (record_lcp_to_metrics_ || lcp_was_restarted_) {
    lcp_calculator->UpdateWebExposedLargestContentfulPaintIfNeeded(
        text_update_result.first, image_update_result.first,
        /*is_triggered_by_soft_navigation=*/lcp_was_restarted_);
  }
}

void PaintTimingDetector::ReportIgnoredContent() {
  text_paint_timing_detector_->ReportLargestIgnoredText();
  if (image_paint_timing_detector_->IsRecordingLargestImagePaint()) {
    image_paint_timing_detector_->ReportLargestIgnoredImage();
  }
}

const LargestContentfulPaintDetails&
PaintTimingDetector::LatestLcpDetailsForTest() const {
  return largest_contentful_paint_calculator_->LatestLcpDetails();
}

bool PaintTimingDetector::IsUnrelatedSoftNavigationPaint(const Node& node) {
  return (WasLCPRestarted() &&
          !(IsSoftNavigationDetected() || node.IsModifiedBySoftNavigation()));
}

ScopedPaintTimingDetectorBlockPaintHook*
    ScopedPaintTimingDetectorBlockPaintHook::top_ = nullptr;

void ScopedPaintTimingDetectorBlockPaintHook::EmplaceIfNeeded(
    const LayoutBoxModelObject& aggregator,
    const PropertyTreeStateOrAlias& property_tree_state) {
  if (IgnorePaintTimingScope::IgnoreDepth() > 1) {
    return;
  }
  // |reset_top_| is unset when |aggregator| is anonymous so that each
  // aggregation corresponds to an element. See crbug.com/988593. When set,
  // |top_| becomes |this|, and |top_| is restored to the previous value when
  // the ScopedPaintTimingDetectorBlockPaintHook goes out of scope.
  if (!aggregator.GetNode()) {
    return;
  }

  reset_top_.emplace(&top_, this);
  TextPaintTimingDetector& detector = aggregator.GetFrameView()
                                          ->GetPaintTimingDetector()
                                          .GetTextPaintTimingDetector();
  // Only set |data_| if we need to walk the object.
  if (detector.ShouldWalkObject(aggregator)) {
    data_.emplace(aggregator, property_tree_state, &detector);
  }
}

ScopedPaintTimingDetectorBlockPaintHook::Data::Data(
    const LayoutBoxModelObject& aggregator,
    const PropertyTreeStateOrAlias& property_tree_state,
    TextPaintTimingDetector* detector)
    : aggregator_(aggregator),
      property_tree_state_(property_tree_state),
      detector_(detector) {}

ScopedPaintTimingDetectorBlockPaintHook::
    ~ScopedPaintTimingDetectorBlockPaintHook() {
  if (!data_ || data_->aggregated_visual_rect_.IsEmpty()) {
    return;
  }
  // TODO(crbug.com/987804): Checking |ShouldWalkObject| again is necessary
  // because the result can change, but more investigation is needed as to why
  // the change is possible.
  if (!data_->detector_ ||
      !data_->detector_->ShouldWalkObject(data_->aggregator_)) {
    return;
  }
  data_->detector_->RecordAggregatedText(data_->aggregator_,
                                         data_->aggregated_visual_rect_,
                                         data_->property_tree_state_);
}

void PaintTimingDetector::Trace(Visitor* visitor) const {
  visitor->Trace(text_paint_timing_detector_);
  visitor->Trace(image_paint_timing_detector_);
  visitor->Trace(frame_view_);
  visitor->Trace(largest_contentful_paint_calculator_);
  visitor->Trace(callback_manager_);
  visitor->Trace(potential_soft_navigation_image_record_);
  visitor->Trace(potential_soft_navigation_text_record_);
}

}  // namespace blink

"""

```