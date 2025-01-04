Response:
Let's break down the request and the provided code to formulate a comprehensive answer.

**1. Understanding the Goal:**

The core request is to analyze the `largest_contentful_paint_calculator.cc` file within the Chromium Blink rendering engine. The analysis needs to cover its functionality, relationships with web technologies (HTML, CSS, JavaScript), internal logic with examples, potential usage errors, and debugging context.

**2. Initial Code Scan and Keyword Identification:**

I started by scanning the code for key terms and structures:

* **`LargestContentfulPaintCalculator`**: This is the central class, indicating its responsibility for calculating LCP.
* **`LargestContentfulPaintType`**:  An enum suggesting different types of LCP candidates (images, text, video, etc.).
* **`UpdateWebExposedLargestContentfulPaintIfNeeded`**, **`UpdateWebExposedLargestContentfulImage`**, **`UpdateWebExposedLargestContentfulText`**:  These functions clearly handle updating the browser's exposed LCP metric.
* **`TextRecord`**, **`ImageRecord`**: Structures holding information about potential LCP candidates.
* **`WindowPerformance`**: A dependency, suggesting this calculator interacts with the browser's performance monitoring.
* **`PaintTiming`**:  Another dependency related to paint timing metrics.
* **`features::kExcludeLowEntropyImagesFromLCP`**, **`features::kMinimumEntropyForLCP`**: Feature flags indicating configuration options.
* **`TRACE_EVENT_MARK`**:  Indicates the calculator contributes to performance tracing.
* **`DOMNodeIds`**, **`Element`**, **`HTMLImageElement`**: References to DOM elements, confirming interaction with the HTML structure.
* **`MediaTiming`**: Information about loading times for media (images, videos).
* **`SecurityOrigin`**:  Suggests handling of cross-origin scenarios.
* **`loading_attr`**:  Reference to the HTML `loading` attribute for images.

**3. Deconstructing Functionality:**

Based on the keywords and function names, I deduced the following core functionalities:

* **Identifying LCP Candidates:**  The calculator receives information about potential LCP candidates (text and images) and determines which is the "largest."
* **Calculating LCP Time:** It tracks the paint time of the largest contentful element.
* **Exposing LCP to Web APIs:**  It updates `window.performance.getEntriesByType('paint')` with LCP information.
* **Filtering Candidates:** It applies criteria like minimum entropy for images.
* **Handling Different Content Types:** It distinguishes between text and image LCP candidates, with specific logic for images (animated, cross-origin, data URIs).
* **Contributing to Performance Tracing:** It logs events for debugging and analysis.

**4. Establishing Relationships with Web Technologies:**

* **HTML:** The calculator directly interacts with HTML elements (images, text nodes) to get their size, paint time, and attributes like `loading`.
* **CSS:** While not directly manipulating CSS, the *result* of CSS styling (layout, visibility, etc.) influences what gets painted and becomes an LCP candidate. The size of the rendered element is crucial.
* **JavaScript:** The calculated LCP value is exposed to JavaScript through the Performance API, allowing developers to access this metric.

**5. Crafting Examples and Scenarios:**

* **HTML/CSS Example:**  Created a simple HTML structure with a large image and text block to illustrate how the calculator might choose an LCP candidate.
* **JavaScript Example:** Showed how JavaScript can retrieve the LCP value.
* **Logic Inference (Assumptions and Outputs):**  Developed scenarios with different input sizes and paint times for text and images to demonstrate the calculator's decision-making process.

**6. Identifying Potential User/Programming Errors:**

* **Lazy Loading:** Highlighted the interaction between the `loading` attribute and LCP.
* **Dynamic Content:**  Discussed how dynamically added or modified content can affect LCP.
* **Hidden Content:** Pointed out that initially hidden content doesn't typically contribute to LCP.

**7. Constructing the Debugging Narrative:**

This involved outlining the steps a user might take that would lead to the execution of this code, emphasizing the paint process and performance monitoring. I included:

* Initial page load.
* Image loading and decoding.
* Text rendering.
* Potential for dynamic updates.
* How the browser uses this calculator during these steps.

**8. Structuring the Answer:**

I organized the information into clear sections based on the request's prompts:

* Functionality
* Relationship with Web Technologies
* Logic Inference
* Common Errors
* Debugging Context

**Self-Correction/Refinement:**

* **Initial thought:**  Focus heavily on the specific code implementations of each function.
* **Correction:**  Shifted the focus to the *high-level purpose* of the functions and how they contribute to the overall goal of LCP calculation. Avoided getting bogged down in every line of code.
* **Initial thought:** Provide very technical explanations of internal Blink concepts.
* **Correction:**  Simplified explanations, focusing on the user-facing aspects and the connection to web technologies. Used analogies where appropriate.
* **Initial thought:**  Treat each point in isolation.
* **Correction:**  Emphasized the interconnectedness of the concepts, showing how HTML, CSS, JavaScript, and the internal calculator work together.

By following this process of analysis, decomposition, example generation, and structured presentation, I aimed to provide a comprehensive and easy-to-understand explanation of the `largest_contentful_paint_calculator.cc` file.
好的，让我们来分析一下 `largest_contentful_paint_calculator.cc` 这个文件。

**功能概述**

`LargestContentfulPaintCalculator` 类的主要功能是**计算和跟踪 Largest Contentful Paint (LCP)**。LCP 是一个重要的 Web 性能指标，用于衡量用户在页面首次开始加载后，视窗内最大的可见元素完成渲染的时间。这个文件中的代码负责识别潜在的 LCP 候选元素（主要是图片和文本），并记录和更新 LCP 的相关信息。

更具体地说，这个类的功能包括：

1. **识别 LCP 候选者:** 接收来自其他 Blink 组件的通知，关于潜在的 LCP 候选元素（文本块或图片）的渲染完成事件。
2. **跟踪最大的内容元素:**  比较不同候选者的渲染大小和时间，并记录当前最大的内容元素及其渲染时间。
3. **区分文本和图片 LCP:**  分别处理文本和图片的 LCP 候选者，并存储各自的信息。
4. **处理图片 LCP 的特殊情况:**  考虑图片加载状态、是否为动画、是否跨域、以及图片的熵值等因素。
5. **将 LCP 信息暴露给 Web API:**  更新 `window.performance.getEntriesByType('paint')` 中类型为 "largest-contentful-paint" 的性能条目，使得 JavaScript 可以访问 LCP 值。
6. **支持软导航:**  区分由软导航触发的 LCP 更新。
7. **集成性能追踪:**  使用 `TRACE_EVENT_MARK` 记录 LCP 候选者的信息，用于性能分析和调试。
8. **根据 Feature Flags 调整行为:**  例如，根据 `features::kExcludeLowEntropyImagesFromLCP` 决定是否排除低熵图片作为 LCP 候选者。

**与 JavaScript, HTML, CSS 的关系**

这个文件直接参与了浏览器如何理解和报告 Web 页面性能的关键指标，因此与 JavaScript, HTML, CSS 都有密切关系。

* **HTML:**
    * **识别元素:**  代码需要识别 HTML 中的 `<img>` 元素和文本节点作为潜在的 LCP 候选者。
    * **`loading` 属性:** 代码会读取 `<img>` 标签上的 `loading` 属性（`value->SetString("loadingAttr", loading_attr);`），这会影响图片的加载时机，进而影响 LCP。例如，`loading="lazy"` 的图片可能不会立即成为 LCP 候选者。
    * **元素 ID:**  代码会获取 LCP 候选元素的 ID 属性 (`image_element->GetIdAttribute()` 和 `text_element->GetIdAttribute()`)，以便在性能条目中提供元素标识。

    **例子:**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
        <title>LCP Example</title>
    </head>
    <body>
        <img src="large-image.jpg" id="main-image" loading="eager">
        <p id="main-text">This is some important text.</p>
    </body>
    </html>
    ```
    在这个例子中，`LargestContentfulPaintCalculator` 可能会考虑 `<img>` 元素和 `<p>` 元素作为 LCP 候选者。它会获取它们的 ID（"main-image" 和 "main-text"）以及 `<img>` 元素的 `loading` 属性。

* **CSS:**
    * **渲染大小:**  CSS 样式会影响元素最终的渲染大小和可见性，这是判断 LCP 的关键因素。`LargestContentfulPaintCalculator` 依赖于渲染引擎提供的元素渲染尺寸信息 (`largest_text->recorded_size` 和 `largest_image->recorded_size`)。
    * **可见性:** 只有视窗内可见的元素才能成为 LCP 候选者。CSS 的 `display: none;` 或 `visibility: hidden;` 等属性会排除元素成为 LCP 候选者。

    **例子:**
    ```css
    #main-image {
        width: 80%;
    }

    #main-text {
        font-size: 20px;
    }
    ```
    这些 CSS 规则会影响 `#main-image` 的宽度和 `#main-text` 的字体大小，从而影响它们作为 LCP 候选者时的大小。

* **JavaScript:**
    * **访问 LCP 值:** JavaScript 可以通过 Performance API 获取 LCP 值：
    ```javascript
    const observer = new PerformanceObserver((list) => {
      const lcpEntry = list.getEntriesByType('largest-contentful-paint')[0];
      console.log('LCP:', lcpEntry.startTime, 'ms', 'Element:', lcpEntry.element);
    });
    observer.observe({ type: 'largest-contentful-paint', buffered: true });
    ```
    `LargestContentfulPaintCalculator` 正是负责将计算出的 LCP 时间、URL 和元素等信息传递给这个 API。
    * **动态修改 DOM:** JavaScript 动态地添加、删除或修改 DOM 元素可能会影响 LCP。`LargestContentfulPaintCalculator` 需要能够处理这些变化并更新 LCP。

**逻辑推理 (假设输入与输出)**

假设我们有以下 HTML 和 CSS：

```html
<!DOCTYPE html>
<html>
<head>
    <title>LCP Example</title>
    <style>
        #image1 { width: 500px; }
        #text1 { font-size: 24px; }
    </style>
</head>
<body>
    <img id="image1" src="image1.jpg">
    <p id="text1">Large Text Content</p>
    <img id="image2" src="image2.jpg" loading="lazy">
</body>
</html>
```

**假设输入:**

1. **`image1` 渲染完成:**  大小为 500x300 像素，渲染时间为 `t1`。
2. **`text1` 渲染完成:** 大小为 400x50 像素，渲染时间为 `t2`。
3. **`image2` 渲染完成:** (由于 `loading="lazy"`, 可能在初始视窗外，或者稍后加载)

**逻辑推理过程 (简化):**

* `LargestContentfulPaintCalculator` 会收到 `image1` 渲染完成的通知，记录其大小和渲染时间。此时，`image1` 成为当前的 LCP 候选者。
* 接着，收到 `text1` 渲染完成的通知。比较 `image1` 和 `text1` 的 `recorded_size`：
    * 假设 `image1` 的 `recorded_size` 大于 `text1` 的 `recorded_size`。
    * 如果 `t1 < t2`，那么 `image1` 仍然是 LCP 元素，LCP 时间为 `t1`。
    * 如果 `t2 < t1` 且 `text1` 的 `recorded_size` 足够接近 `image1`， 并且 `text1` 的渲染时间更早，那么 LCP 可能会更新为 `text1`，LCP 时间为 `t2`。
* 如果 `image2` 之后渲染完成，且在视窗内，并且其大小大于当前的 LCP 元素，那么 LCP 可能会更新为 `image2` 的渲染时间和大小。

**假设输出 (基于上述假设):**

* 如果 `image1` 是最大的，且渲染最早，那么最终的 LCP 性能条目可能会包含：
    * `startTime`: `t1` (渲染时间)
    * `size`: `image1` 的渲染大小 (500 * 300)
    * `element`: `image1` 对应的 DOM 元素
    * `url`: `image1.jpg`

**用户或编程常见的使用错误**

1. **延迟加载关键图片导致 LCP 延迟:** 使用 `loading="lazy"` 可能导致初始视窗内的重要图片延迟加载，从而推迟 LCP。开发者应该谨慎地对首屏图片使用延迟加载。

    **例子:**  首屏大图使用了 `<img src="hero.jpg" loading="lazy">`。用户滚动到图片出现后才触发加载和渲染，导致 LCP 时间很晚。

2. **隐藏初始 LCP 元素:**  使用 CSS 初始隐藏（例如 `display: none;`）潜在的 LCP 元素，然后通过 JavaScript 显示。这会导致 LCP 在元素显示之后才被计算，延迟了 LCP。

    **例子:**
    ```html
    <img id="lcp-image" src="main.jpg" style="display: none;">
    <script>
        setTimeout(() => { document.getElementById('lcp-image').style.display = 'block'; }, 1000);
    </script>
    ```
    LCP 的时间会被延迟到图片显示出来之后。

3. **动态插入内容导致 LCP 不稳定:**  在页面加载完成后，通过 JavaScript 动态插入大型图片或文本块，可能会导致 LCP 值发生变化，影响性能监控的准确性。

    **例子:**  页面初始加载时 LCP 是一个小的文本块，但在几秒后，JavaScript 加载并插入了一个大的横幅广告图片，导致 LCP 指向了这个广告图片，使得初始 LCP 值失去了意义。

4. **错误的理解 LCP 的计算时机:** 开发者可能认为只要元素出现在屏幕上就算作 LCP，但实际上 LCP 指标关注的是元素**完成渲染**的时间。

**用户操作是如何一步步的到达这里，作为调试线索**

当用户访问一个网页时，以下步骤可能会触发 `LargestContentfulPaintCalculator` 的相关逻辑：

1. **用户在浏览器中输入 URL 或点击链接开始导航。**
2. **浏览器发起 HTTP 请求获取 HTML 文档。**
3. **浏览器接收到 HTML 文档，开始解析 HTML。**
4. **解析 HTML 过程中，遇到 `<img>` 标签或文本内容时，会创建对应的 DOM 节点。**
5. **浏览器开始加载 `<img>` 标签的图片资源。**
6. **渲染引擎开始布局和绘制页面。**
7. **当图片资源加载完成并解码后，渲染引擎会进行图片的绘制。`ImagePaintTimingDetector` 可能会检测到图片的首次绘制时间，并通知 `LargestContentfulPaintCalculator`。**
8. **当文本内容被布局并绘制到屏幕上时，`TextPaintTimingDetector` 可能会检测到文本的绘制时间，并通知 `LargestContentfulPaintCalculator`。**
9. **`LargestContentfulPaintCalculator` 会比较不同候选者的渲染大小和时间，更新当前的 LCP 元素和时间。**
10. **在页面加载完成后的某个时刻，最终的 LCP 值会被确定并暴露给 Performance API。**
11. **开发者可以使用浏览器的开发者工具 (Performance 面板) 或 JavaScript 代码来查看 LCP 值。**

**调试线索:**

* **Performance 面板 (Chrome DevTools):**  在 "Performance" 面板中录制页面加载过程，可以查看到 "Largest Contentful Paint" 的标记，以及触发 LCP 的元素。
* **`performance.getEntriesByType('largest-contentful-paint')`:**  在浏览器的 Console 中运行此 JavaScript 代码，可以实时获取 LCP 条目信息，包括 `startTime` 和 `element` 属性。
* **`chrome://tracing`:**  可以启用 Chrome 的 tracing 功能，查看更底层的渲染事件，包括图片解码、绘制等事件，有助于理解 LCP 的计算过程。
* **断点调试:** 如果需要深入了解 `LargestContentfulPaintCalculator` 的具体工作方式，可以在相关代码处设置断点进行调试。例如，在 `UpdateWebExposedLargestContentfulPaintIfNeeded`、`UpdateWebExposedLargestContentfulImage` 或 `UpdateWebExposedLargestContentfulText` 等函数中设置断点。

总而言之，`largest_contentful_paint_calculator.cc` 是 Blink 渲染引擎中一个至关重要的组件，它负责计算并报告 Largest Contentful Paint 指标，帮助开发者了解和优化网页的加载性能。它与 HTML 结构、CSS 样式以及暴露给 JavaScript 的 Performance API 紧密相关。

Prompt: 
```
这是目录为blink/renderer/core/paint/timing/largest_contentful_paint_calculator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/timing/largest_contentful_paint_calculator.h"

#include "base/check.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/loading_attribute.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/paint/timing/image_element_timing.h"
#include "third_party/blink/renderer/core/paint/timing/image_paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/text_paint_timing_detector.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

constexpr const char kTraceCategories[] = "loading,rail,devtools.timeline";

constexpr const char kLCPCandidate[] = "largestContentfulPaint::Candidate";

}  // namespace

LargestContentfulPaintType GetLargestContentfulPaintTypeFromString(
    const AtomicString& type_string) {
  if (type_string.empty()) {
    return LargestContentfulPaintType::kNone;
  }

  using LargestContentfulPaintTypeMap =
      HashMap<AtomicString, LargestContentfulPaintType>;

  DEFINE_STATIC_LOCAL(LargestContentfulPaintTypeMap,
                      largest_contentful_paint_type_map,
                      ({{"svg", LargestContentfulPaintType::kSVG},
                        {"gif", LargestContentfulPaintType::kGIF},
                        {"png", LargestContentfulPaintType::kPNG},
                        {"jpg", LargestContentfulPaintType::kJPG},
                        {"avif", LargestContentfulPaintType::kAVIF},
                        {"webp", LargestContentfulPaintType::kWebP}}));

  auto it = largest_contentful_paint_type_map.find(type_string);
  if (it != largest_contentful_paint_type_map.end()) {
    return it->value;
  }

  return LargestContentfulPaintType::kNone;
}

LargestContentfulPaintCalculator::LargestContentfulPaintCalculator(
    WindowPerformance* window_performance)
    : window_performance_(window_performance) {}

void LargestContentfulPaintCalculator::
    UpdateWebExposedLargestContentfulPaintIfNeeded(
        const TextRecord* largest_text,
        const ImageRecord* largest_image,
        bool is_triggered_by_soft_navigation) {
  uint64_t text_size = largest_text ? largest_text->recorded_size : 0u;
  uint64_t image_size = largest_image ? largest_image->recorded_size : 0u;
  if (image_size > text_size) {
    if (image_size > largest_reported_size_ &&
        largest_image->paint_time > base::TimeTicks()) {
      UpdateWebExposedLargestContentfulImage(largest_image,
                                             is_triggered_by_soft_navigation);
    }
  } else {
    if (text_size > largest_reported_size_ &&
        largest_text->paint_time > base::TimeTicks()) {
      UpdateWebExposedLargestContentfulText(*largest_text,
                                            is_triggered_by_soft_navigation);
    }
  }
}

void LargestContentfulPaintCalculator::UpdateWebExposedLargestContentfulImage(
    const ImageRecord* largest_image,
    bool is_triggered_by_soft_navigation) {
  DCHECK(window_performance_);
  DCHECK(largest_image);
  const MediaTiming* media_timing = largest_image->media_timing;
  Node* image_node = DOMNodeIds::NodeForId(largest_image->node_id);

  // |media_timing| is a weak pointer, so it may be null. This can only happen
  // if the image has been removed, which means that the largest image is not
  // up-to-date. This can happen when this method call came from
  // OnLargestTextUpdated(). If a largest-image is added and removed so fast
  // that it does not get to be reported here, we consider it safe to ignore.
  // For similar reasons, |image_node| may be null and it is safe to ignore
  // the |largest_image| content in this case as well.
  if (!media_timing || !image_node)
    return;

  uint64_t size = largest_image->recorded_size;
  double bpp = largest_image->EntropyForLCP();

  if (base::FeatureList::IsEnabled(features::kExcludeLowEntropyImagesFromLCP)) {
    if (bpp < features::kMinimumEntropyForLCP.Get()) {
      return;
    }
  }
  largest_image_bpp_ = bpp;
  largest_reported_size_ = size;
  const KURL& url = media_timing->Url();
  bool expose_paint_time_to_api =
      url.ProtocolIsData() || media_timing->TimingAllowPassed() ||
      RuntimeEnabledFeatures::ExposeCoarsenedRenderTimeEnabled();
  const String& image_string = url.GetString();
  const String& image_url =
      url.ProtocolIsData()
          ? image_string.Left(ImageElementTiming::kInlineImageMaxChars)
          : image_string;
  // Do not expose element attribution from shadow trees.
  Element* image_element =
      image_node->IsInShadowTree() ? nullptr : To<Element>(image_node);
  const AtomicString& image_id =
      image_element ? image_element->GetIdAttribute() : AtomicString();

  base::TimeTicks render_time;
  base::TimeTicks start_time = largest_image->load_time;
  if (expose_paint_time_to_api) {
    start_time = render_time = largest_image->paint_time;
  }

  if (RuntimeEnabledFeatures::ExposeRenderTimeNonTaoDelayedImageEnabled() &&
      !expose_paint_time_to_api) {
    // For Non-Tao images, set start time to the max of FCP and load time.
    base::TimeTicks fcp =
        PaintTiming::From(*window_performance_->DomWindow()->document())
            .FirstContentfulPaintPresentation();
    DCHECK(!fcp.is_null());
    start_time = std::max(fcp, largest_image->load_time);
  }

  window_performance_->OnLargestContentfulPaintUpdated(
      /*start_time=*/start_time, /*render_time=*/render_time,
      /*paint_size=*/largest_image->recorded_size,
      /*load_time=*/largest_image->load_time,
      /*first_animated_frame_time=*/
      expose_paint_time_to_api ? largest_image->first_animated_frame_time
                               : base::TimeTicks(),
      /*id=*/image_id, /*url=*/image_url, /*element=*/image_element,
      is_triggered_by_soft_navigation);

  // TODO: update trace value with animated frame data
  if (LocalDOMWindow* window = window_performance_->DomWindow()) {
    if (!largest_image->origin_clean) {
      UseCounter::Count(window->document(),
                        WebFeature::kLCPCandidateImageFromOriginDirtyStyle);
    }

    TRACE_EVENT_MARK_WITH_TIMESTAMP2(
        kTraceCategories, kLCPCandidate, largest_image->paint_time, "data",
        ImageCandidateTraceData(largest_image, is_triggered_by_soft_navigation,
                                image_element),
        "frame", GetFrameIdForTracing(window->GetFrame()));
  }
}

void LargestContentfulPaintCalculator::UpdateWebExposedLargestContentfulText(
    const TextRecord& largest_text,
    bool is_triggered_by_soft_navigation) {
  DCHECK(window_performance_);
  // |node_| could be null and |largest_text| should be ignored in this
  // case. This can happen when the largest-text gets removed too fast and does
  // not get to be reported here.
  if (!largest_text.node_)
    return;
  Node* text_node = largest_text.node_;
  largest_reported_size_ = largest_text.recorded_size;
  // Do not expose element attribution from shadow trees. Also note that @page
  // margin boxes do not create Element nodes.
  Element* text_element =
      text_node->IsInShadowTree() ? nullptr : DynamicTo<Element>(text_node);
  const AtomicString& text_id =
      text_element ? text_element->GetIdAttribute() : AtomicString();
  // Always use paint time as start time for text LCP candidate.
  window_performance_->OnLargestContentfulPaintUpdated(
      /*start_time=*/largest_text.paint_time,
      /*render_time=*/largest_text.paint_time,
      /*paint_size=*/largest_text.recorded_size,
      /*load_time=*/base::TimeTicks(),
      /*first_animated_frame_time=*/base::TimeTicks(), /*id=*/text_id,
      /*url=*/g_empty_string, /*element=*/text_element,
      is_triggered_by_soft_navigation);

  if (LocalDOMWindow* window = window_performance_->DomWindow()) {
    TRACE_EVENT_MARK_WITH_TIMESTAMP2(
        kTraceCategories, kLCPCandidate, largest_text.paint_time, "data",
        TextCandidateTraceData(largest_text, is_triggered_by_soft_navigation),
        "frame", GetFrameIdForTracing(window->GetFrame()));
  }
}

bool LargestContentfulPaintCalculator::HasLargestImagePaintChangedForMetrics(
    base::TimeTicks largest_image_paint_time,
    uint64_t largest_image_paint_size) const {
  return largest_image_paint_time !=
             latest_lcp_details_.largest_image_paint_time ||
         largest_image_paint_size !=
             latest_lcp_details_.largest_image_paint_size;
}

bool LargestContentfulPaintCalculator::HasLargestTextPaintChangedForMetrics(
    base::TimeTicks largest_text_paint_time,
    uint64_t largest_text_paint_size) const {
  return largest_text_paint_time !=
             latest_lcp_details_.largest_text_paint_time ||
         largest_text_paint_size != latest_lcp_details_.largest_text_paint_size;
}

bool LargestContentfulPaintCalculator::NotifyMetricsIfLargestImagePaintChanged(
    base::TimeTicks image_paint_time,
    uint64_t image_paint_size,
    ImageRecord* image_record,
    double image_bpp,
    std::optional<WebURLRequest::Priority> priority) {
  // (Experimental) Images with insufficient entropy are not considered
  // candidates for LCP
  if (base::FeatureList::IsEnabled(features::kExcludeLowEntropyImagesFromLCP)) {
    if (image_bpp < features::kMinimumEntropyForLCP.Get()) {
      return false;
    }
  }
  if (!HasLargestImagePaintChangedForMetrics(image_paint_time,
                                             image_paint_size)) {
    return false;
  }

  latest_lcp_details_.largest_contentful_paint_type =
      blink::LargestContentfulPaintType::kNone;
  if (image_record) {
    // TODO(yoav): Once we'd enable the kLCPAnimatedImagesReporting flag by
    // default, we'd be able to use the value of
    // largest_image_record->first_animated_frame_time directly.
    if (image_record && image_record->media_timing) {
      if (!image_record->media_timing->GetFirstVideoFrameTime().is_null()) {
        // Set the video flag.
        latest_lcp_details_.largest_contentful_paint_type |=
            blink::LargestContentfulPaintType::kVideo;
      } else if (image_record->media_timing->IsPaintedFirstFrame()) {
        // Set the animated image flag.
        latest_lcp_details_.largest_contentful_paint_type |=
            blink::LargestContentfulPaintType::kAnimatedImage;
      }

      // Set image type flag.
      latest_lcp_details_.largest_contentful_paint_type |=
          blink::LargestContentfulPaintType::kImage;

      // Set specific type of the image.
      latest_lcp_details_.largest_contentful_paint_type |=
          GetLargestContentfulPaintTypeFromString(
              image_record->media_timing->MediaType());

      // Set DataURI type.
      if (image_record->media_timing->IsDataUrl()) {
        latest_lcp_details_.largest_contentful_paint_type |=
            blink::LargestContentfulPaintType::kDataURI;
      }

      // Set cross-origin flag of the image.
      if (auto* window = window_performance_->DomWindow()) {
        auto image_url = image_record->media_timing->Url();
        if (!image_url.IsEmpty() && image_url.ProtocolIsInHTTPFamily() &&
            window->GetFrame()->IsOutermostMainFrame()) {
          auto image_origin = SecurityOrigin::Create(image_url);
          if (!image_origin->IsSameOriginWith(window->GetSecurityOrigin())) {
            latest_lcp_details_.largest_contentful_paint_type |=
                blink::LargestContentfulPaintType::kCrossOrigin;
          }
        }
      }

      latest_lcp_details_.resource_load_timings.discovery_time =
          image_record->media_timing->DiscoveryTime();
      latest_lcp_details_.resource_load_timings.load_start =
          image_record->media_timing->LoadStart();
      latest_lcp_details_.resource_load_timings.load_end =
          image_record->media_timing->LoadEnd();
    }
  }
  latest_lcp_details_.largest_image_paint_time = image_paint_time;
  latest_lcp_details_.largest_image_paint_size = image_paint_size;
  latest_lcp_details_.largest_contentful_paint_image_bpp = image_bpp;
  latest_lcp_details_.largest_contentful_paint_image_request_priority =
      std::move(priority);
  UpdateLatestLcpDetails();
  return true;
}

bool LargestContentfulPaintCalculator::NotifyMetricsIfLargestTextPaintChanged(
    base::TimeTicks text_paint_time,
    uint64_t text_paint_size) {
  if (!HasLargestTextPaintChangedForMetrics(text_paint_time, text_paint_size)) {
    return false;
  }

  DCHECK(!text_paint_time.is_null());
  latest_lcp_details_.largest_text_paint_time = text_paint_time;
  latest_lcp_details_.largest_text_paint_size = text_paint_size;
  UpdateLatestLcpDetails();

  return true;
}

void LargestContentfulPaintCalculator::UpdateLatestLcpDetails() {
  if (latest_lcp_details_.largest_text_paint_size >
      latest_lcp_details_.largest_image_paint_size) {
    latest_lcp_details_.largest_contentful_paint_time =
        latest_lcp_details_.largest_text_paint_time;

    // We set latest_lcp_details_.largest_contentful_paint_type_ only here
    // because we use latest_lcp_details_.largest_contentful_paint_type_ to
    // track the LCP type of the largest image only. When the largest image gets
    // updated, the latest_lcp_details_.largest_contentful_paint_type_ gets
    // reset and updated accordingly in the
    // NotifyMetricsIfLargestImagePaintChanged() method. If the LCP element
    // turns out to be the largest text, we simply set the
    // latest_lcp_details_.largest_contentful_paint_type_ to be kText here. This
    // is possible because currently text elements have only 1 LCP type kText.
    latest_lcp_details_.largest_contentful_paint_type =
        LargestContentfulPaintType::kText;
  } else if (latest_lcp_details_.largest_text_paint_size <
             latest_lcp_details_.largest_image_paint_size) {
    latest_lcp_details_.largest_contentful_paint_time =
        latest_lcp_details_.largest_image_paint_time;
  } else {
    // Size is the same, take the shorter time.
    latest_lcp_details_.largest_contentful_paint_time =
        std::min(latest_lcp_details_.largest_text_paint_time,
                 latest_lcp_details_.largest_image_paint_time);

    if (latest_lcp_details_.largest_text_paint_time <
        latest_lcp_details_.largest_image_paint_time) {
      latest_lcp_details_.largest_contentful_paint_type =
          LargestContentfulPaintType::kText;
    }
  }
}
void LargestContentfulPaintCalculator::Trace(Visitor* visitor) const {
  visitor->Trace(window_performance_);
}

std::unique_ptr<TracedValue>
LargestContentfulPaintCalculator::TextCandidateTraceData(
    const TextRecord& largest_text,
    bool is_triggered_by_soft_navigation) {
  auto value = std::make_unique<TracedValue>();
  value->SetString("type", "text");
  value->SetInteger("nodeId",
                    static_cast<int>(largest_text.node_->GetDomNodeId()));
  value->SetInteger("size", static_cast<int>(largest_text.recorded_size));
  value->SetInteger("candidateIndex", ++count_candidates_);
  auto* window = window_performance_->DomWindow();
  value->SetBoolean("isOutermostMainFrame",
                    window->GetFrame()->IsOutermostMainFrame());
  value->SetBoolean("isMainFrame", window->GetFrame()->IsMainFrame());
  value->SetString("navigationId", is_triggered_by_soft_navigation
                                       ? window->GetNavigationId()
                                       : IdentifiersFactory::LoaderId(
                                             window->document()->Loader()));
  return value;
}

std::unique_ptr<TracedValue>
LargestContentfulPaintCalculator::ImageCandidateTraceData(
    const ImageRecord* largest_image,
    bool is_triggered_by_soft_navigation,
    Element* image_element) {
  auto value = std::make_unique<TracedValue>();
  value->SetString("type", "image");
  value->SetInteger("nodeId", static_cast<int>(largest_image->node_id));
  value->SetInteger("size", static_cast<int>(largest_image->recorded_size));
  value->SetInteger("candidateIndex", ++count_candidates_);
  auto* window = window_performance_->DomWindow();
  value->SetBoolean("isOutermostMainFrame",
                    window->GetFrame()->IsOutermostMainFrame());
  value->SetBoolean("isMainFrame", window->GetFrame()->IsMainFrame());
  value->SetString("navigationId", is_triggered_by_soft_navigation
                                       ? window->GetNavigationId()
                                       : IdentifiersFactory::LoaderId(
                                             window->document()->Loader()));

  value->SetDouble("imageDiscoveryTime",
                   window_performance_->MonotonicTimeToDOMHighResTimeStamp(
                       largest_image->media_timing->DiscoveryTime()));
  value->SetDouble("imageLoadStart",
                   window_performance_->MonotonicTimeToDOMHighResTimeStamp(
                       largest_image->media_timing->LoadStart()));
  value->SetDouble("imageLoadEnd",
                   window_performance_->MonotonicTimeToDOMHighResTimeStamp(
                       largest_image->media_timing->LoadEnd()));

  String loading_attr = "";

  if (HTMLImageElement* html_image_element =
          DynamicTo<HTMLImageElement>(image_element)) {
    loading_attr =
        html_image_element->FastGetAttribute(html_names::kLoadingAttr);
  }
  value->SetString("loadingAttr", loading_attr);

  return value;
}

}  // namespace blink

"""

```