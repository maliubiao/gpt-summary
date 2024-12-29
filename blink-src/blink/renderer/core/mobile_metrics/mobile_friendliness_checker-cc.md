Response:
Let's break down the thought process to analyze the provided C++ code and generate the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand what this C++ file (`mobile_friendliness_checker.cc`) does within the Chromium Blink rendering engine. The request specifically asks about its functionality, its relationship to web technologies (HTML, CSS, JavaScript), logical reasoning, potential user errors, and how a user action might trigger this code.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for recognizable keywords and patterns:

* **Headers:** `#include` directives give hints about dependencies and functionality. We see headers related to frames, documents, layout, painting, metrics, and viewport. This strongly suggests the file is involved in measuring aspects of a web page related to how it fits on a mobile screen.
* **Class Name:** `MobileFriendlinessChecker` is the central class. This immediately suggests its purpose is to check something related to "mobile friendliness."
* **Methods:**  Methods like `NotifyPaintBegin`, `NotifyPaintEnd`, `MaybeRecompute`, `ComputeNow`, `UpdateTextAreaSizes`, `UpdateBeyondViewportAreaSizes`, `NotifyPaintTextFragment`, and `NotifyPaintReplaced` suggest it's tracking events during the rendering process.
* **Data Members:** Variables like `viewport_device_width_`, `allow_user_zoom_`, `viewport_initial_scale_x10_`, `viewport_hardcoded_width_`, `area_sizes_`, `initial_scale_`, and `viewport_width_` point to specific aspects being measured.
* **Constants:** Constants like `kSmallFontThresholdInDips`, `kMaximumScalePreventsZoomingThreshold`, `kEvaluationInterval`, and `kEvaluationDelay` define thresholds and timing parameters, which are crucial for the checker's logic.
* **UKM:**  The use of `ukm::builders::MobileFriendliness` indicates that this code reports metrics using the User Keyed Metrics (UKM) system, which is used for collecting anonymous usage data in Chrome.
* **Namespaces:** `blink` clearly indicates this is part of the Blink rendering engine.
* **Comments:** The initial comments about copyright and BSD-style license are standard.

**3. Deductive Reasoning and Functionality Identification:**

Based on the keywords and the structure, we can start deducing the file's functionality:

* **Mobile Friendliness Assessment:** The class name and the metrics being tracked (viewport width, initial scale, user zoom, small text, content outside the viewport) directly indicate this is about assessing how well a webpage adapts to mobile devices.
* **Rendering Integration:** The `NotifyPaintBegin`, `NotifyPaintEnd`, `NotifyPaintTextFragment`, and `NotifyPaintReplaced` methods clearly show this code interacts with the rendering pipeline. It's listening to paint events.
* **Metric Collection:** The UKM usage confirms the goal is to collect and report metrics.
* **Thresholds and Heuristics:** The constants suggest the use of thresholds and heuristics to determine mobile friendliness (e.g., a font size below `kSmallFontThresholdInDips` is considered small).
* **Periodic Evaluation:** The `MaybeRecompute` method and the time-related constants (`kEvaluationInterval`, `kEvaluationDelay`) indicate that the checks are performed periodically, not necessarily on every single paint.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

Now, let's connect the observed functionality to web technologies:

* **HTML:** The checker looks at the `<meta name="viewport">` tag to extract information like `width=device-width`, `initial-scale`, `maximum-scale`, and `user-scalable`. This directly relates to the `viewport_device_width_`, `viewport_initial_scale_x10_`, and `allow_user_zoom_` variables. It also considers the overall structure and content that might extend beyond the viewport.
* **CSS:**  The checker measures font sizes. This directly relates to CSS `font-size` properties. The detection of text outside the viewport could be influenced by CSS layout properties (e.g., fixed positioning, absolute positioning).
* **JavaScript:** While this specific C++ code doesn't directly *execute* JavaScript, JavaScript can *modify* the DOM and CSS that this code then analyzes. For example, JavaScript could dynamically change the viewport meta tag or the font sizes of elements.

**5. Logical Reasoning and Examples:**

To illustrate the logic, we can create hypothetical scenarios:

* **Small Text:** If the checker encounters a `<p>` tag styled with `font-size: 8px;`, it will contribute to the `small_font_area`.
* **Content Overflow:** If a `<div>` has `width: 150%` on a mobile viewport, it will likely contribute to the `content_beyond_viewport_area`.
* **Disabled Zoom:** If the meta tag is `<meta name="viewport" content="maximum-scale=1.0">`, the `allow_user_zoom_` will likely be `false`.

**6. Identifying User/Programming Errors:**

Thinking about how developers might misuse or misunderstand mobile optimization leads to examples:

* **Ignoring Viewport:** Not including a viewport meta tag at all.
* **Too Small Initial Scale:** Setting `initial-scale` to a very small value, making the initial view tiny.
* **Disabling Zoom Unnecessarily:** Setting `user-scalable=no` or a very low `maximum-scale` can hinder accessibility.
* **Overly Wide Content:** Creating content that is significantly wider than typical mobile screen widths.
* **Using Tiny Fonts:**  Setting font sizes that are too small to be easily readable on mobile.

**7. Tracing User Actions (Debugging Clues):**

To understand how a user's action reaches this code, we trace back from the visual output:

1. **User requests a webpage:** The user enters a URL or clicks a link.
2. **Browser requests and receives resources:** The browser fetches HTML, CSS, JavaScript, and images.
3. **Rendering engine parses resources:** Blink parses the HTML, CSS, and executes JavaScript.
4. **Layout and Paint:** Blink calculates the layout of the page and then paints it to the screen. *This is where the `MobileFriendlinessChecker` gets involved.*  The `NotifyPaintBegin`, `NotifyPaintTextFragment`, `NotifyPaintReplaced`, and `NotifyPaintEnd` methods are called during the paint process.
5. **Periodic Evaluation:**  After some initial delay and then at regular intervals, the `MaybeRecompute` and `ComputeNow` methods are called to calculate and report the mobile friendliness metrics.

**8. Iteration and Refinement:**

After the initial analysis, reviewing the code again can reveal more subtle points or connections. For example, noticing the bucketing functions (`GetBucketedViewportInitialScale`, `GetBucketedViewportHardcodedWidth`) explains how the raw metric values are anonymized for privacy when reporting to UKM.

By following these steps, combining code analysis with knowledge of web technologies and the rendering process, we can construct a comprehensive explanation like the example provided in the initial prompt.
这个文件 `mobile_friendliness_checker.cc` 的主要功能是**检查网页在移动设备上的友好程度，并收集相关的性能指标用于分析和改进 Chromium 浏览器对移动端网页的支持。**

更具体地说，它会监控和分析以下方面：

**主要功能：**

1. **视口 (Viewport) 配置分析:**
   - 检测是否存在 `<meta name="viewport">` 标签。
   - 解析视口标签的内容，提取诸如 `width=device-width`、`initial-scale`、`maximum-scale`、`user-scalable` 等属性的值。
   - 记录视口的设备宽度 (`viewport_device_width_`)、是否允许用户缩放 (`allow_user_zoom_`)、初始缩放比例 (`viewport_initial_scale_x10_`) 以及硬编码的宽度值 (`viewport_hardcoded_width_`)。

2. **文本内容分析:**
   - **小字体检测:** 遍历渲染的文本内容，计算小于一定阈值（`kSmallFontThresholdInDips`，默认为 9 dips）的文本区域的比例 (`SmallTextRatio()`)。这有助于识别在移动设备上难以阅读的过小字体。
   - **视口外文本检测:**  追踪渲染过程中超出当前视口范围的文本内容面积 (`TextContentsOutsideViewportPercentage()`)。这有助于发现水平溢出等问题，表明页面没有很好地适应移动设备屏幕。

3. **性能指标上报 (UKM):**
   - 定期（默认 `kEvaluationInterval` 为 1 分钟）收集上述分析得到的指标，并通过 User Keyed Metrics (UKM) 系统上报。这些指标包括视口配置信息、小字体比例以及视口外文本比例。

**与 JavaScript, HTML, CSS 的关系：**

这个文件主要通过分析 HTML 结构和 CSS 样式来判断移动友好性。JavaScript 可以动态修改 DOM 和 CSS，从而影响 `MobileFriendlinessChecker` 的分析结果。

* **HTML:**
    - **`<meta name="viewport">` 标签:** 这是 `MobileFriendlinessChecker` 关注的核心 HTML 元素。它直接影响视口的配置，例如：
        ```html
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        ```
        `MobileFriendlinessChecker` 会提取 `width` 和 `initial-scale` 的值。
    - **文本内容:**  `MobileFriendlinessChecker` 会遍历 HTML 中的文本节点，获取其渲染后的位置和大小，以及关联的字体大小。

* **CSS:**
    - **`font-size` 属性:**  CSS 的 `font-size` 属性直接决定了文本的大小，`MobileFriendlinessChecker` 会根据此判断文本是否过小。
        ```css
        p {
          font-size: 8px; /* 可能被认为是过小的字体 */
        }
        ```
    - **布局相关的属性 (例如 `width`, `overflow`, `position`):** 这些属性会影响元素的位置和大小，从而决定文本内容是否超出视口范围。 例如，如果一个元素的宽度超过了视口的宽度，并且 `overflow: hidden` 或 `overflow: scroll` 没有正确设置，就可能导致文本溢出。

* **JavaScript:**
    - **动态修改视口:** JavaScript 可以通过修改 DOM 来动态改变 `<meta name="viewport">` 标签的内容。
        ```javascript
        const viewportMeta = document.querySelector('meta[name="viewport"]');
        viewportMeta.setAttribute('content', 'width=500');
        ```
        `MobileFriendlinessChecker` 在下一次评估时会反映这些变化。
    - **动态修改样式:** JavaScript 可以改变元素的 CSS 样式，包括 `font-size` 和布局属性。
        ```javascript
        const paragraph = document.querySelector('p');
        paragraph.style.fontSize = '10px';
        ```
        这将影响小字体检测的结果。
    - **动态生成内容:** JavaScript 动态生成的内容也会被 `MobileFriendlinessChecker` 分析。

**逻辑推理、假设输入与输出：**

**假设输入:** 一个包含以下 HTML 和 CSS 的网页：

```html
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=0.8, maximum-scale=1.0">
  <style>
    body { font-size: 8px; }
    .wide-content { width: 150%; }
  </style>
</head>
<body>
  <p>This is some text.</p>
  <div class="wide-content">This content is wider than the viewport.</div>
</body>
</html>
```

**逻辑推理:**

1. **视口分析:**
   - `viewport_device_width_` 将为 true (因为设置了 `width=device-width`)。
   - `allow_user_zoom_` 将为 false (因为 `maximum-scale` 为 1.0，低于 `kMaximumScalePreventsZoomingThreshold`)。
   - `viewport_initial_scale_x10_` 将为 8 (0.8 * 10)。

2. **小字体检测:**
   - 页面所有文本的字体大小都被设置为 8px，低于默认的阈值 (9 dips)。
   - `area_sizes_.small_font_area` 将会累加文本的面积。
   - `area_sizes_.total_text_area` 也会累加文本的面积。
   - `SmallTextRatio()` 将接近 100%。

3. **视口外文本检测:**
   - `.wide-content` 的宽度是视口的 150%。
   - 部分 `.wide-content` 的文本内容会超出视口的右边界。
   - `area_sizes_.content_beyond_viewport_area` 将会计算超出部分的面积。
   - `TextContentsOutsideViewportPercentage()` 将会是一个大于 0 的值。

**可能输出 (UKM Metrics):**

```
ukm::builders::MobileFriendliness builder;
builder.SetViewportDeviceWidth(true);
builder.SetAllowUserZoom(false);
builder.SetViewportInitialScaleX10(8); // GetBucketedViewportInitialScale(8)
builder.SetTextContentOutsideViewportPercentage(/* 大于 0 的值 */);
builder.SetSmallTextRatio(100);
builder.Record(...);
```

**用户或编程常见的使用错误：**

1. **忘记设置视口 `meta` 标签:**
   - **错误:** 页面没有 `<meta name="viewport">` 标签。
   - **后果:** 移动设备可能会以桌面模式渲染页面，导致页面缩小且难以交互。`MobileFriendlinessChecker` 会记录缺少视口信息。

2. **错误地设置 `initial-scale`:**
   - **错误:** 设置了过小的 `initial-scale`，例如 `initial-scale=0.1`。
   - **后果:** 页面初始加载时会非常小，用户需要手动放大才能看清内容。`MobileFriendlinessChecker` 会记录较小的 `viewport_initial_scale_x10_` 值。

3. **禁用用户缩放 (不必要的 `user-scalable=no` 或过小的 `maximum-scale`):**
   - **错误:** 设置了 `<meta name="viewport" content="user-scalable=no">` 或 `<meta name="viewport" content="maximum-scale=1.0">`。
   - **后果:** 阻止了有视觉障碍的用户进行缩放，影响可访问性。`MobileFriendlinessChecker` 会记录 `allow_user_zoom_` 为 false。

4. **使用过小的字体:**
   - **错误:** 在 CSS 中使用了过小的 `font-size`，例如 `font-size: 6px;`。
   - **后果:** 文本在移动设备上难以阅读。`MobileFriendlinessChecker` 会增加 `SmallTextRatio()` 的值。

5. **创建超出视口宽度的内容:**
   - **错误:** 元素的宽度超过了视口的宽度，且没有合适的处理方式 (例如滚动)。
   - **后果:** 用户需要水平滚动才能看到所有内容，影响用户体验。`MobileFriendlinessChecker` 会增加 `TextContentsOutsideViewportPercentage()` 的值。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在 Chromium 浏览器中打开一个网页。**
2. **Blink 渲染引擎开始解析 HTML、CSS 并构建 DOM 树和渲染树。**
3. **在布局 (Layout) 阶段，Blink 确定元素的大小和位置，包括视口的尺寸。**
4. **在绘制 (Paint) 阶段，`MobileFriendlinessChecker` 的实例被创建（仅针对最外层的 MainFrame）。**
5. **当页面开始绘制时，`NotifyPaintBegin()` 方法被调用。** 这会初始化一些状态，例如标记正在绘制、获取视口变换信息。
6. **在绘制文本片段时，`NotifyPaintTextFragment()` 方法被调用。** 这个方法会接收文本的绘制区域 (`paint_rect`) 和字体大小 (`font_size`)。`MobileFriendlinessChecker` 会根据这些信息更新小字体区域和视口外文本区域的统计。
7. **在绘制其他替换元素 (例如图片) 时，`NotifyPaintReplaced()` 方法被调用。**  这个方法也会更新视口外区域的统计。
8. **当页面绘制结束时，`NotifyPaintEnd()` 方法被调用。**
9. **在一定的间隔 (`kEvaluationInterval`) 后，`MaybeRecompute()` 方法会被调用。** 如果距离上次评估的时间足够长，它会调用 `ComputeNow()`。
10. **`ComputeNow()` 方法会计算最终的移动友好性指标，并将这些指标通过 UKM 系统记录下来。**

**作为调试线索：**

* **检查 `NotifyPaintBegin()` 和 `NotifyPaintEnd()` 是否被正确调用:**  如果这些方法没有被调用，可能意味着 `MobileFriendlinessChecker` 没有被正确初始化或者页面没有进行绘制。
* **在 `NotifyPaintTextFragment()` 中断点调试:** 可以查看传入的 `paint_rect` 和 `font_size`，确认小字体和视口外文本的计算是否正确。
* **查看 UKM 的上报数据:** 可以检查上报的指标是否符合预期，从而判断 `MobileFriendlinessChecker` 的分析结果是否正确。
* **检查视口 `meta` 标签的解析逻辑:** 如果关于视口的指标不正确，可以检查 `ViewportDescription` 的解析过程。
* **关注 `initial_scale_` 的值:**  这个值来自 `PageScaleConstraintsSet`，可以帮助理解页面的初始缩放状态。

总而言之，`mobile_friendliness_checker.cc` 是 Chromium 中一个重要的模块，它通过分析渲染过程中的信息，帮助开发者了解其网页在移动设备上的表现，并为 Chromium 团队提供数据以改进对移动端网页的支持。

Prompt: 
```
这是目录为blink/renderer/core/mobile_metrics/mobile_friendliness_checker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/mobile_metrics/mobile_friendliness_checker.h"

#include <cmath>
#include <optional>

#include "base/metrics/histogram_functions.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_get_root_node_options.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_size.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "ui/display/screen_info.h"

namespace blink {

namespace {

int32_t BucketWithOffsetAndUnit(int32_t num, int32_t offset, int32_t unit) {
  DCHECK_LT(0, unit);
  // Bucketing raw number with `offset` centered.
  const int32_t grid = (num - offset) / unit;
  const int32_t bucketed =
      grid == 0  ? 0
      : grid > 0 ? std::pow(2, static_cast<int32_t>(std::log2(grid)))
                 : -std::pow(2, static_cast<int32_t>(std::log2(-grid)));
  return bucketed * unit + offset;
}

// Viewport initial scale x10 metrics is exponentially bucketed by offset of 10
// (most common initial-scale=1.0 is the center) to preserve user's privacy.
int32_t GetBucketedViewportInitialScale(int32_t initial_scale_x10) {
  DCHECK_LE(0, initial_scale_x10);
  return BucketWithOffsetAndUnit(initial_scale_x10, 10, 2);
}

// Viewport hardcoded width metrics is exponentially bucketed by offset of 500
// to preserve user's privacy.
int32_t GetBucketedViewportHardcodedWidth(int32_t hardcoded_width) {
  DCHECK_LE(0, hardcoded_width);
  return BucketWithOffsetAndUnit(hardcoded_width, 500, 10);
}

}  // namespace

static constexpr int kSmallFontThresholdInDips = 9;

// Values of maximum-scale smaller than this threshold will be considered to
// prevent the user from scaling the page as if user-scalable=no was set.
static constexpr double kMaximumScalePreventsZoomingThreshold = 1.2;

static constexpr base::TimeDelta kEvaluationInterval = base::Minutes(1);
static constexpr base::TimeDelta kEvaluationDelay = base::Seconds(5);

// Basically MF evaluation invoked every |kEvaluationInterval|, but its first
// evaluation invoked |kEvaluationDelay| after initialization of this module.
// Time offsetting with their difference simplifies these requirements.
static constexpr base::TimeDelta kFirstEvaluationOffsetTime =
    kEvaluationInterval - kEvaluationDelay;

MobileFriendlinessChecker::MobileFriendlinessChecker(LocalFrameView& frame_view)
    : frame_view_(&frame_view),
      viewport_scalar_(
          frame_view_->GetFrame().GetWidgetForLocalRoot()
              ? frame_view_->GetPage()
                    ->GetChromeClient()
                    .WindowToViewportScalar(&frame_view_->GetFrame(), 1)
              : 1.0),
      last_evaluated_(base::TimeTicks::Now() - kFirstEvaluationOffsetTime) {}

MobileFriendlinessChecker::~MobileFriendlinessChecker() = default;

void MobileFriendlinessChecker::NotifyPaintBegin() {
  DCHECK(frame_view_->GetFrame().Client()->IsLocalFrameClientImpl());
  DCHECK(frame_view_->GetFrame().IsOutermostMainFrame());

  ignore_beyond_viewport_scope_count_ =
      frame_view_->LayoutViewport()->MaximumScrollOffset().x() == 0 &&
      frame_view_->GetPage()
              ->GetVisualViewport()
              .MaximumScrollOffsetAtScale(initial_scale_)
              .x() == 0;
  is_painting_ = true;
  viewport_transform_ = &frame_view_->GetLayoutView()
                             ->FirstFragment()
                             .ContentsProperties()
                             .Transform();
  previous_transform_ = viewport_transform_;
  current_x_offset_ = 0.0;

  const ViewportDescription& viewport = frame_view_->GetFrame()
                                            .GetDocument()
                                            ->GetViewportData()
                                            .GetViewportDescription();
  if (viewport.type == ViewportDescription::Type::kViewportMeta) {
    const double zoom = viewport.zoom_is_explicit ? viewport.zoom : 1.0;
    viewport_device_width_ = viewport.max_width.IsDeviceWidth();
    if (viewport.max_width.IsFixed()) {
      // Convert value from Blink space to device-independent pixels.
      viewport_hardcoded_width_ =
          viewport.max_width.GetFloatValue() / viewport_scalar_;
    }

    if (viewport.zoom_is_explicit)
      viewport_initial_scale_x10_ = std::round(viewport.zoom * 10);

    if (viewport.user_zoom_is_explicit) {
      allow_user_zoom_ = viewport.user_zoom;
      // If zooming is only allowed slightly.
      if (viewport.max_zoom / zoom < kMaximumScalePreventsZoomingThreshold)
        allow_user_zoom_ = false;
    }
  }

  initial_scale_ = frame_view_->GetPage()
                       ->GetPageScaleConstraintsSet()
                       .FinalConstraints()
                       .initial_scale;
  int frame_width = frame_view_->GetPage()->GetVisualViewport().Size().width();
  viewport_width_ = frame_width * viewport_scalar_ / initial_scale_;
}

void MobileFriendlinessChecker::NotifyPaintEnd() {
  DCHECK(frame_view_->GetFrame().Client()->IsLocalFrameClientImpl());
  DCHECK(frame_view_->GetFrame().IsOutermostMainFrame());
  ignore_beyond_viewport_scope_count_ = 0;
  is_painting_ = false;
}

MobileFriendlinessChecker* MobileFriendlinessChecker::Create(
    LocalFrameView& frame_view) {
  // Only run the mobile friendliness checker for the outermost main
  // frame. The checker will iterate through all local frames in the
  // current blink::Page. Also skip the mobile friendliness checks for
  // "non-ordinary" pages by checking IsLocalFrameClientImpl(), since
  // it's not useful to generate mobile friendliness metrics for
  // devtools, svg, etc.
  if (!frame_view.GetFrame().Client()->IsLocalFrameClientImpl() ||
      !frame_view.GetFrame().IsOutermostMainFrame() ||
      !frame_view.GetPage()->GetSettings().GetViewportEnabled() ||
      !frame_view.GetPage()->GetSettings().GetViewportMetaEnabled()) {
    return nullptr;
  }
  return MakeGarbageCollected<MobileFriendlinessChecker>(frame_view);
}

MobileFriendlinessChecker* MobileFriendlinessChecker::From(
    const Document& document) {
  DCHECK(document.GetFrame());

  auto* local_frame = DynamicTo<LocalFrame>(document.GetFrame()->Top());
  if (local_frame == nullptr)
    return nullptr;

  MobileFriendlinessChecker* mfc =
      local_frame->View()->GetMobileFriendlinessChecker();
  if (!mfc || !mfc->is_painting_)
    return nullptr;

  DCHECK_EQ(DocumentLifecycle::kInPaint, document.Lifecycle().GetState());
  DCHECK(!document.IsPrintingOrPaintingPreview());
  return mfc;
}

void MobileFriendlinessChecker::MaybeRecompute() {
  DCHECK(frame_view_->GetFrame().Client()->IsLocalFrameClientImpl());
  DCHECK(frame_view_->GetFrame().IsOutermostMainFrame());
  base::TimeTicks now = base::TimeTicks::Now();
  if (now - last_evaluated_ < kEvaluationInterval)
    return;

  ComputeNow();
}

void MobileFriendlinessChecker::ComputeNow() {
  ukm::builders::MobileFriendliness builder(
      frame_view_->GetFrame().GetDocument()->UkmSourceID());

  builder.SetViewportDeviceWidth(viewport_device_width_);
  builder.SetAllowUserZoom(allow_user_zoom_);
  if (viewport_initial_scale_x10_) {
    builder.SetViewportInitialScaleX10(
        GetBucketedViewportInitialScale(*viewport_initial_scale_x10_));
  }
  if (viewport_hardcoded_width_) {
    builder.SetViewportHardcodedWidth(
        GetBucketedViewportHardcodedWidth(*viewport_hardcoded_width_));
  }
  builder.SetTextContentOutsideViewportPercentage(
      area_sizes_.TextContentsOutsideViewportPercentage(
          // Use SizeF when computing the area to avoid integer overflow.
          gfx::SizeF(frame_view_->GetPage()->GetVisualViewport().Size())
              .GetArea()));
  builder.SetSmallTextRatio(area_sizes_.SmallTextRatio());

  builder.Record(frame_view_->GetFrame().GetDocument()->UkmRecorder());
  last_evaluated_ = base::TimeTicks::Now();
}

int MobileFriendlinessChecker::AreaSizes::SmallTextRatio() const {
  if (total_text_area == 0)
    return 0;

  return small_font_area * 100 / total_text_area;
}

int MobileFriendlinessChecker::AreaSizes::TextContentsOutsideViewportPercentage(
    double viewport_area) const {
  return std::ceil(content_beyond_viewport_area * 100 / viewport_area);
}

void MobileFriendlinessChecker::UpdateTextAreaSizes(
    const PhysicalRect& text_rect,
    int font_size) {
  double actual_font_size = font_size * initial_scale_ / viewport_scalar_;
  double area = text_rect.Width() * text_rect.Height();
  if (std::round(actual_font_size) < kSmallFontThresholdInDips)
    area_sizes_.small_font_area += area;

  area_sizes_.total_text_area += area;
}

void MobileFriendlinessChecker::UpdateBeyondViewportAreaSizes(
    const PhysicalRect& paint_rect,
    const TransformPaintPropertyNodeOrAlias& current_transform) {
  DCHECK(is_painting_);
  if (ignore_beyond_viewport_scope_count_ != 0)
    return;

  if (previous_transform_ != &current_transform) {
    auto projection = GeometryMapper::SourceToDestinationProjection(
        current_transform, *viewport_transform_);
    if (projection.IsIdentityOr2dTranslation()) {
      current_x_offset_ = projection.To2dTranslation().x();
      previous_transform_ = &current_transform;
    } else {
      // For now we ignore offsets caused by non-2d-translation transforms.
      current_x_offset_ = 0;
    }
  }

  float right = paint_rect.Right() + current_x_offset_;
  float width = paint_rect.Width();
  float width_beyond_viewport =
      std::min(std::max(right - viewport_width_, 0.f), width);

  area_sizes_.content_beyond_viewport_area +=
      width_beyond_viewport * paint_rect.Height();
}

void MobileFriendlinessChecker::NotifyPaintTextFragment(
    const PhysicalRect& paint_rect,
    int font_size,
    const TransformPaintPropertyNodeOrAlias& current_transform) {
  DCHECK(frame_view_->GetFrame().Client()->IsLocalFrameClientImpl());
  DCHECK(frame_view_->GetFrame().IsOutermostMainFrame());

  UpdateTextAreaSizes(paint_rect, font_size);
  UpdateBeyondViewportAreaSizes(paint_rect, current_transform);
}

void MobileFriendlinessChecker::NotifyPaintReplaced(
    const PhysicalRect& paint_rect,
    const TransformPaintPropertyNodeOrAlias& current_transform) {
  DCHECK(frame_view_->GetFrame().Client()->IsLocalFrameClientImpl());
  DCHECK(frame_view_->GetFrame().IsLocalRoot());

  UpdateBeyondViewportAreaSizes(paint_rect, current_transform);
}

void MobileFriendlinessChecker::Trace(Visitor* visitor) const {
  visitor->Trace(frame_view_);
  visitor->Trace(viewport_transform_);
  visitor->Trace(previous_transform_);
}

}  // namespace blink

"""

```