Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of `text_paint_timing_detector.cc`, its relation to web technologies (JS/HTML/CSS), examples, assumptions, user errors, and debugging hints.

2. **Initial Code Scan - Identify Key Classes and Members:**  A quick skim reveals the core class `TextPaintTimingDetector` and related classes like `LargestTextPaintManager` and `TextRecord`. Key member functions like `OnPaintFinished`, `RecordAggregatedText`, `StopRecordingLargestTextPaint`, etc., stand out.

3. **Infer Primary Functionality from Class Names and Member Names:**
    * `TextPaintTimingDetector`:  The name strongly suggests it's involved in measuring the timing of text rendering.
    * `LargestTextPaintManager`:  Likely tracks and manages the "largest" text paint, possibly related to performance metrics like Largest Contentful Paint (LCP).
    * `TextRecord`: Seems to be a data structure holding information about a painted text element.
    * `OnPaintFinished`:  Called when a paint operation is completed.
    * `RecordAggregatedText`:  Called when text is rendered, providing information about the rendered area.
    * `StopRecordingLargestTextPaint`/`RestartRecordingLargestTextPaint`: Controls whether the detector is actively tracking the largest text paint.
    * `ReportPresentationTime`:  Handles the timing information after the rendering is presented on the screen.

4. **Connect to Web Technologies (JS/HTML/CSS):**
    * **HTML:** The code interacts with `Node` and `LayoutObject`, which are core concepts in the HTML rendering pipeline. The `elementtiming` attribute is explicitly mentioned, linking it to HTML.
    * **CSS:**  The code checks for CSS properties like `color`, `text-shadow`, and `text-stroke-width`. It also references fonts. This establishes the connection to CSS styling affecting text rendering.
    * **JavaScript:** The code interacts with `LocalDOMWindow` and `TextElementTiming`. `TextElementTiming` is likely an API exposed to JavaScript (or at least accessible from it) for performance monitoring. The concept of "soft navigation" also suggests potential interaction with JavaScript-driven page updates.

5. **Deep Dive into Specific Functions - Logic and Assumptions:**
    * **`RecordAggregatedText`:**  This function is crucial. It checks if the text should be recorded based on the `ShouldWalkObject` function. It considers transparency, shadows, and text strokes. It calculates the visual size and interacts with `LargestTextPaintManager`. *Assumption:*  The `aggregated_visual_rect` represents the bounding box of the rendered text.
    * **`LargestTextPaintManager::MaybeUpdateLargestText`:**  A simple comparison to track the largest text based on `recorded_size`. *Assumption:* `recorded_size` is a metric that represents the "size" of the rendered text, likely its area.
    * **`AssignPaintTimeToQueuedRecords`:** This function associates a presentation timestamp with the recorded text elements. It iterates through `texts_queued_for_paint_time_`. *Assumption:* Text elements are queued *before* their actual presentation time is known.
    * **`ShouldWalkObject`:**  Determines if a layout object should be considered for text paint timing. The logic involves checking if largest text paint recording is active and the presence of the `elementtiming` attribute. *Assumption:*  Not walking an object prevents it from being considered for LCP.

6. **Identify Potential User/Programming Errors:**
    * **Incorrect `elementtiming` usage:**  Misspelling the attribute or applying it to inappropriate elements.
    * **CSS causing unintended exclusion:** Setting text color to fully transparent might prevent it from being considered for LCP if the flag is enabled.
    * **Large amounts of hidden text:** If the `ExcludeTransparentTextsFromBeingLcpEligibleEnabled` feature is on, large blocks of initially hidden text might not be accounted for in LCP until they become visible.

7. **Develop Examples:**  Based on the understanding of the code, create simple HTML/CSS examples that demonstrate the functionality. Show how changing text size, color, or using `elementtiming` impacts the behavior.

8. **Trace User Actions:**  Think about the sequence of steps a user takes that would lead to this code being executed. Start with basic page loading and then consider more complex scenarios like dynamic content updates.

9. **Debugging Hints:**  Relate the code's logging and tracing mechanisms (like `TRACE_EVENT_MARK_WITH_TIMESTAMP2`) to how a developer would debug issues related to text paint timing.

10. **Structure the Answer:** Organize the findings logically, addressing each point in the original request. Use clear headings and examples. Explain the connection to web technologies concisely.

11. **Review and Refine:** Read through the generated answer, ensuring accuracy and clarity. Check for any inconsistencies or missing information. For instance, ensure the explanation of "soft navigation" is understandable.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  The detector might directly measure the time it takes to render each character.
* **Correction:** The code focuses on *aggregated* text and seems to be more about identifying the *largest* painted text block for performance metrics, not individual character rendering times.

* **Initial thought:**  `elementtiming` is solely for developer tools.
* **Refinement:**  `elementtiming` seems to directly influence the recording logic, suggesting it's a more fundamental part of the paint timing mechanism.

By following this iterative process of understanding, inferring, connecting, and refining, a comprehensive and accurate explanation of the code's functionality can be constructed.
好的，让我们来详细分析一下 `blink/renderer/core/paint/timing/text_paint_timing_detector.cc` 这个文件。

**功能概述**

`TextPaintTimingDetector` 的主要功能是**检测和记录文本绘制相关的性能指标，特别是与 Largest Contentful Paint (LCP) 有关的文本元素**。它跟踪页面中渲染的文本，并尝试识别出对 LCP 贡献最大的文本元素。此外，它还支持通过 `elementtiming` 属性为特定文本元素记录绘制时间。

更具体地说，它的功能包括：

1. **记录聚合文本信息:**  当布局对象（`LayoutBoxModelObject`）的文本被绘制时，它会记录文本的大小、位置等信息。
2. **识别 Largest Text Paint (LTP):**  它会跟踪绘制的文本，并尝试识别出尺寸最大的文本块，这被认为是 LCP 的一个潜在候选者。
3. **处理 `elementtiming` 属性:**  如果 HTML 元素上使用了 `elementtiming` 属性，它会记录该元素文本的绘制时间。
4. **在绘制完成后报告时间:**  当一帧绘制完成后，它会将记录到的绘制时间（Presentation Time）与相应的文本记录关联起来。
5. **处理软导航 (Soft Navigation):**  它会考虑软导航对文本绘制的影响，并可能在软导航发生时重新开始记录 LTP。
6. **忽略特定文本:**  根据配置，某些文本（例如完全透明的文本）可能被排除在 LCP 候选之外。
7. **在 LCP 计算器中更新指标:**  当识别到新的 LTP 候选者时，它会通知 `LargestContentfulPaintCalculator`。
8. **提供调试信息:**  通过 tracing (例如 `TRACE_EVENT_MARK_WITH_TIMESTAMP2`) 提供关于 LTP 候选者的信息，用于性能分析和调试。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`TextPaintTimingDetector` 的工作直接受到 HTML 结构、CSS 样式以及可能的 JavaScript 交互的影响。

1. **HTML:**
   - **`elementtiming` 属性:**  HTML 元素可以使用 `elementtiming` 属性来标记，以便更精确地追踪其渲染时间。`TextPaintTimingDetector` 会识别这些属性并记录相应文本的绘制时间。
     ```html
     <p elementtiming="my-text">这是一段需要追踪绘制时间的文本。</p>
     ```
   - **文本内容:**  `TextPaintTimingDetector` 关注的是实际渲染到屏幕上的文本内容。HTML 中文本内容的变化（例如通过 JavaScript 动态修改）会影响其记录。

2. **CSS:**
   - **文本样式属性:**  CSS 属性如 `font-size`、`color`、`text-shadow`、`text-stroke` 等会直接影响文本的渲染大小和可见性。
     - 例如，如果文本颜色设置为完全透明 (`color: transparent;`) 且开启了 `ExcludeTransparentTextsFromBeingLcpEligibleEnabled` 功能，则该文本可能不会被视为 LCP 候选者。
     ```css
     .transparent-text {
       color: transparent;
     }
     ```
   - **字体加载:**  自定义字体的加载和应用也会影响文本的绘制时机和大小。`WebFontResizeLCPEnabled` 功能表明，当使用自定义字体时，文本框的大小变化可能会使其重新成为 LCP 候选者。

3. **JavaScript:**
   - **动态修改 DOM:** JavaScript 可以动态地添加、删除或修改包含文本的 HTML 元素。这些操作会触发新的渲染，并影响 `TextPaintTimingDetector` 的记录。
     ```javascript
     document.getElementById('my-text').textContent = '新的文本内容';
     ```
   - **软导航 (Soft Navigation):**  JavaScript 框架可能会执行不触发完整页面加载的导航（软导航）。`TextPaintTimingDetector` 考虑了这种情况，并可能在软导航发生时重置 LTP 的记录。`SoftNavigationHeuristics` 类用于判断是否发生了软导航。
   - **Performance API:**  虽然这个 C++ 文件本身不直接与 JavaScript Performance API 交互，但其记录的数据最终会被用于计算和报告给 JavaScript 的性能指标，例如 LCP。

**逻辑推理、假设输入与输出**

**假设输入:**

1. **HTML:**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Text Paint Timing Example</title>
      <style>
        #large-text { font-size: 24px; }
        #small-text { font-size: 12px; }
      </style>
    </head>
    <body>
      <p id="small-text">这是一小段文本。</p>
      <p id="large-text">这是一大段文本，内容较多，可能成为 Largest Text Paint。</p>
    </body>
    </html>
    ```
2. **用户操作:**  用户打开了这个网页。

**逻辑推理:**

- `TextPaintTimingDetector` 会在页面渲染过程中被调用。
- 当 `#small-text` 和 `#large-text` 的文本被绘制时，`RecordAggregatedText` 会被调用。
- `MaybeUpdateLargestText` 会比较两段文本的大小（基于 `font-size` 和文本长度计算出的渲染面积）。
- **假设** `#large-text` 的渲染面积大于 `#small-text`，那么 `#large-text` 将被认为是当前的 Largest Text Paint 候选者。
- 当绘制完成后，`OnPaintFinished` 会被调用，准备报告绘制时间。

**可能的输出 (通过 tracing):**

```
TRACE_EVENT_MARK_WITH_TIMESTAMP2(
    "loading", "LargestTextPaint::Candidate", <paint_time_of_large_text>,
    "data", {"DOMNodeId": <id_of_large_text_element>, "size": <calculated_size_of_large_text>, ...},
    "frame", ...);
```

**假设输入 (包含 `elementtiming`):**

1. **HTML:**
    ```html
    <p elementtiming="important-paragraph">这段文本很重要，需要追踪绘制时间。</p>
    ```

**逻辑推理:**

- `TextPaintTimingDetector` 会识别出带有 `elementtiming="important-paragraph"` 属性的 `<p>` 元素。
- 当该段文本被绘制时，其绘制时间会被记录下来。
- 在 `ReportPresentationTime` 中，如果 `text_element_timing_` 可用，`OnTextObjectPainted` 会被调用，将绘制时间与该元素关联。

**用户或编程常见的使用错误**

1. **错误地使用 `elementtiming` 属性:**
   - **拼写错误:**  `elementtiming` 被拼写成其他形式（例如 `elementTiming`）。
   - **应用到非文本元素:**  虽然不一定会报错，但将 `elementtiming` 应用到不包含文本的元素上是无意义的。
   - **重复使用相同的 ID:**  在同一个页面上对多个元素使用相同的 `elementtiming` 值可能会导致混淆。

2. **CSS 导致意外的排除:**
   - **将文本颜色设置为 `transparent` 并期望其被计入 LCP:**  如果 `ExcludeTransparentTextsFromBeingLcpEligibleEnabled` 功能开启，这会导致文本被忽略。
   - **过度使用 `text-shadow` 或 `text-stroke`:**  虽然这些属性可以增强文本效果，但在某些情况下，浏览器可能会对渲染方式进行优化，这可能影响到 `TextPaintTimingDetector` 的判断逻辑（虽然这种情况比较少见）。

3. **JavaScript 动态修改导致的追踪问题:**
   - **在页面初始渲染完成后，通过 JavaScript 快速替换大量文本:**  如果替换发生在 LCP 计算完成之后，新的大段文本可能不会被正确识别为 LCP。
   - **软导航处理不当:**  如果 JavaScript 框架的软导航机制与浏览器的 LCP 计算逻辑不兼容，可能会导致 LCP 指标不准确。

**用户操作是如何一步步到达这里，作为调试线索**

假设开发者正在调查一个网页的 LCP 指标偏高的问题，并且怀疑是某个大的文本元素导致的。以下是用户操作和调试线索：

1. **用户打开开发者工具 (F12)。**
2. **切换到 "Performance" 或 "Lighthouse" 面板。**
3. **进行性能分析或生成 Lighthouse 报告。**
4. **LCP 指标较高，开发者查看详细的 LCP 元素。**  开发者可能会看到一个大的文本块被标记为 LCP 元素。
5. **开发者怀疑该文本块的渲染性能有问题，希望了解其绘制时机。**
6. **开发者可能会尝试在 Performance 面板中查看 "Timings" 或 "Frames" 相关的 track。**  虽然这里可能无法直接看到 `TextPaintTimingDetector` 的信息，但可以观察到大的 paint 事件。
7. **为了更深入地了解，开发者可能会启用 Chromium 的 tracing 功能 (通过 `chrome://tracing`)。**
8. **在 tracing 结果中，开发者可以搜索 "LargestTextPaint::Candidate"。**  这里会记录 `TextPaintTimingDetector` 识别出的 LTP 候选者，包括其 DOM 节点 ID、大小和绘制时间。
9. **开发者可以根据 DOM 节点 ID 在 "Elements" 面板中找到对应的 HTML 元素。**
10. **开发者检查该元素的 CSS 样式，查看是否存在影响渲染性能的属性（例如复杂的文本阴影）。**
11. **如果该元素使用了 `elementtiming` 属性，开发者可以进一步分析该元素的绘制时间线。**
12. **开发者还可以检查 JavaScript 代码，查看是否有动态修改该文本元素的操作，以及这些操作是否影响了渲染时机。**

**总结**

`TextPaintTimingDetector` 是 Blink 渲染引擎中一个关键的组件，它负责识别和记录与文本渲染相关的性能指标，特别是为了优化 Largest Contentful Paint。它与 HTML 结构、CSS 样式以及 JavaScript 行为紧密相关。理解其工作原理有助于开发者更好地诊断和优化网页的渲染性能。通过开发者工具和 tracing 功能，开发者可以深入了解 `TextPaintTimingDetector` 的行为，并找到性能瓶颈。

### 提示词
```
这是目录为blink/renderer/core/paint/timing/text_paint_timing_detector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/timing/text_paint_timing_detector.h"

#include <memory>

#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/timing/largest_contentful_paint_calculator.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

void TextRecord::Trace(Visitor* visitor) const {
  visitor->Trace(node_);
}

TextPaintTimingDetector::TextPaintTimingDetector(
    LocalFrameView* frame_view,
    PaintTimingDetector* paint_timing_detector,
    PaintTimingCallbackManager* callback_manager)
    : callback_manager_(callback_manager),
      frame_view_(frame_view),
      ltp_manager_(MakeGarbageCollected<LargestTextPaintManager>(
          frame_view,
          paint_timing_detector)) {}

void LargestTextPaintManager::PopulateTraceValue(
    TracedValue& value,
    const TextRecord& first_text_paint) {
  value.SetInteger("DOMNodeId",
                   static_cast<int>(first_text_paint.node_->GetDomNodeId()));
  value.SetInteger("size", static_cast<int>(first_text_paint.recorded_size));
  value.SetInteger("candidateIndex", ++count_candidates_);
  value.SetBoolean("isMainFrame", frame_view_->GetFrame().IsMainFrame());
  value.SetBoolean("isOutermostMainFrame",
                   frame_view_->GetFrame().IsOutermostMainFrame());
  value.SetBoolean("isEmbeddedFrame",
                   !frame_view_->GetFrame().LocalFrameRoot().IsMainFrame() ||
                       frame_view_->GetFrame().IsInFencedFrameTree());
  if (first_text_paint.lcp_rect_info_) {
    first_text_paint.lcp_rect_info_->OutputToTraceValue(value);
  }
}

void LargestTextPaintManager::ReportCandidateToTrace(
    const TextRecord& largest_text_record) {
  if (!PaintTimingDetector::IsTracing())
    return;
  auto value = std::make_unique<TracedValue>();
  PopulateTraceValue(*value, largest_text_record);
  TRACE_EVENT_MARK_WITH_TIMESTAMP2(
      "loading", "LargestTextPaint::Candidate", largest_text_record.paint_time,
      "data", std::move(value), "frame",
      GetFrameIdForTracing(&frame_view_->GetFrame()));
}

std::pair<TextRecord*, bool> LargestTextPaintManager::UpdateMetricsCandidate() {
  if (!largest_text_) {
    return {nullptr, false};
  }
  const base::TimeTicks time = largest_text_->paint_time;
  const uint64_t size = largest_text_->recorded_size;
  CHECK(paint_timing_detector_);
  CHECK(paint_timing_detector_->GetLargestContentfulPaintCalculator());

  bool changed = paint_timing_detector_->GetLargestContentfulPaintCalculator()
                     ->NotifyMetricsIfLargestTextPaintChanged(time, size);
  if (changed) {
    // It is not possible for an update to happen with a candidate that has no
    // paint time.
    DCHECK(!time.is_null());
    ReportCandidateToTrace(*largest_text_);
  }
  return {largest_text_.Get(), changed};
}

void TextPaintTimingDetector::OnPaintFinished() {
  if (!added_entry_in_latest_frame_)
    return;

  // |WeakPersistent| guarantees that when |this| is killed,
  // the callback function will not be invoked.
  RegisterNotifyPresentationTime(
      WTF::BindOnce(&TextPaintTimingDetector::ReportPresentationTime,
                    WrapWeakPersistent(this), frame_index_++));
  added_entry_in_latest_frame_ = false;
}

void TextPaintTimingDetector::LayoutObjectWillBeDestroyed(
    const LayoutObject& object) {
  recorded_set_.erase(&object);
  rewalkable_set_.erase(&object);
  texts_queued_for_paint_time_.erase(&object);
}

void TextPaintTimingDetector::RegisterNotifyPresentationTime(
    PaintTimingCallbackManager::LocalThreadCallback callback) {
  callback_manager_->RegisterCallback(std::move(callback));
}

void TextPaintTimingDetector::ReportPresentationTime(
    uint32_t frame_index,
    base::TimeTicks timestamp) {
  if (!text_element_timing_) {
    Document* document = frame_view_->GetFrame().GetDocument();
    if (document) {
      LocalDOMWindow* window = document->domWindow();
      if (window) {
        text_element_timing_ = TextElementTiming::From(*window);
      }
    }
  }
  AssignPaintTimeToQueuedRecords(frame_index, timestamp);
}

bool TextPaintTimingDetector::ShouldWalkObject(
    const LayoutBoxModelObject& object) const {
  // TODO(crbug.com/933479): Use LayoutObject::GeneratingNode() to include
  // anonymous objects' rect.
  Node* node = object.GetNode();
  if (!node)
    return false;
  // If we have finished recording Largest Text Paint and the element is a
  // shadow element or has no elementtiming attribute, then we should not record
  // its text.
  if (!IsRecordingLargestTextPaint() &&
      !TextElementTiming::NeededForElementTiming(*node)) {
    return false;
  }

  if (rewalkable_set_.Contains(&object))
    return true;

  // This metric defines the size of a text block by its first size, so we
  // should not walk the object if it has been recorded.
  return !recorded_set_.Contains(&object);
}

void TextPaintTimingDetector::RecordAggregatedText(
    const LayoutBoxModelObject& aggregator,
    const gfx::Rect& aggregated_visual_rect,
    const PropertyTreeStateOrAlias& property_tree_state) {
  if (RuntimeEnabledFeatures::
          ExcludeTransparentTextsFromBeingLcpEligibleEnabled()) {
    bool is_color_transparent =
        aggregator.StyleRef()
            .VisitedDependentColor(GetCSSPropertyColor())
            .IsFullyTransparent();
    bool has_shadow = !!aggregator.StyleRef().TextShadow();
    bool has_text_stroke = aggregator.StyleRef().TextStrokeWidth();

    if (is_color_transparent && !has_shadow && !has_text_stroke) {
      return;
    }
  }

  DCHECK(ShouldWalkObject(aggregator));

  // The caller should check this.
  DCHECK(!aggregated_visual_rect.IsEmpty());

  gfx::RectF mapped_visual_rect =
      frame_view_->GetPaintTimingDetector().CalculateVisualRect(
          aggregated_visual_rect, property_tree_state);
  uint64_t aggregated_size = mapped_visual_rect.size().GetArea();

  DCHECK_LE(IgnorePaintTimingScope::IgnoreDepth(), 1);
  // Record the largest aggregated text that is hidden due to documentElement
  // being invisible but by no other reason (i.e. IgnoreDepth() needs to be 1).
  if (IgnorePaintTimingScope::IgnoreDepth() == 1) {
    if (IgnorePaintTimingScope::IsDocumentElementInvisible() &&
        IsRecordingLargestTextPaint()) {
      ltp_manager_->MaybeUpdateLargestIgnoredText(aggregator, aggregated_size,
                                                  aggregated_visual_rect,
                                                  mapped_visual_rect);
    }
    return;
  }

  // Web font styled node should be rewalkable so that resizing during swap
  // would make the node eligible to be LCP candidate again.
  if (RuntimeEnabledFeatures::WebFontResizeLCPEnabled()) {
    if (aggregator.StyleRef().GetFont().HasCustomFont()) {
      rewalkable_set_.insert(&aggregator);
    }
  }

  LocalFrame& frame = frame_view_->GetFrame();
  if (LocalDOMWindow* window = frame.DomWindow()) {
    if (SoftNavigationHeuristics* heuristics =
            SoftNavigationHeuristics::From(*window)) {
      heuristics->RecordPaint(
          &frame, mapped_visual_rect.size().GetArea(),
          aggregator.GetNode()->IsModifiedBySoftNavigation());
    }
  }
  recorded_set_.insert(&aggregator);
  MaybeRecordTextRecord(aggregator, aggregated_size, property_tree_state,
                        aggregated_visual_rect, mapped_visual_rect);
  if (std::optional<PaintTimingVisualizer>& visualizer =
          frame_view_->GetPaintTimingDetector().Visualizer()) {
    visualizer->DumpTextDebuggingRect(aggregator, mapped_visual_rect);
  }
}

void TextPaintTimingDetector::StopRecordingLargestTextPaint() {
  recording_largest_text_paint_ = false;
}

void TextPaintTimingDetector::RestartRecordingLargestTextPaint() {
  recording_largest_text_paint_ = true;
  texts_queued_for_paint_time_.clear();
  ltp_manager_->Clear();
}

void TextPaintTimingDetector::ReportLargestIgnoredText() {
  if (!ltp_manager_)
    return;
  TextRecord* record = ltp_manager_->PopLargestIgnoredText();
  // If the content has been removed, abort. It was never visible.
  if (!record || !record->node_ || !record->node_->GetLayoutObject())
    return;

  // Trigger FCP if it's not already set.
  Document* document = frame_view_->GetFrame().GetDocument();
  DCHECK(document);
  PaintTiming::From(*document).MarkFirstContentfulPaint();

  record->frame_index_ = frame_index_;
  QueueToMeasurePaintTime(*record->node_->GetLayoutObject(), record);
}

void TextPaintTimingDetector::Trace(Visitor* visitor) const {
  visitor->Trace(callback_manager_);
  visitor->Trace(frame_view_);
  visitor->Trace(text_element_timing_);
  visitor->Trace(rewalkable_set_);
  visitor->Trace(recorded_set_);
  visitor->Trace(text_element_timing_);
  visitor->Trace(texts_queued_for_paint_time_);
  visitor->Trace(ltp_manager_);
}

LargestTextPaintManager::LargestTextPaintManager(
    LocalFrameView* frame_view,
    PaintTimingDetector* paint_timing_detector)
    : frame_view_(frame_view), paint_timing_detector_(paint_timing_detector) {}

void LargestTextPaintManager::MaybeUpdateLargestText(TextRecord* record) {
  if (!largest_text_ || largest_text_->recorded_size < record->recorded_size) {
    largest_text_ = record;
  }
}

void LargestTextPaintManager::MaybeUpdateLargestIgnoredText(
    const LayoutObject& object,
    const uint64_t& size,
    const gfx::Rect& frame_visual_rect,
    const gfx::RectF& root_visual_rect) {
  if (size &&
      (!largest_ignored_text_ || size > largest_ignored_text_->recorded_size)) {
    // Create the largest ignored text with a |frame_index_| of 0. When it is
    // queued for paint, we'll set the appropriate |frame_index_|.
    largest_ignored_text_ = MakeGarbageCollected<TextRecord>(
        *object.GetNode(), size, gfx::RectF(), frame_visual_rect,
        root_visual_rect, 0u);
  }
}

void LargestTextPaintManager::Trace(Visitor* visitor) const {
  visitor->Trace(largest_text_);
  visitor->Trace(largest_ignored_text_);
  visitor->Trace(frame_view_);
  visitor->Trace(paint_timing_detector_);
}

void TextPaintTimingDetector::AssignPaintTimeToQueuedRecords(
    uint32_t frame_index,
    const base::TimeTicks& timestamp) {
  bool can_report_element_timing =
      text_element_timing_ ? text_element_timing_->CanReportElements() : false;
  HeapVector<Member<const LayoutObject>> keys_to_be_removed;
  for (const auto& it : texts_queued_for_paint_time_) {
    const auto& record = it.value;
    if (!record->paint_time.is_null() || record->frame_index_ > frame_index) {
      continue;
    }
    record->paint_time = timestamp;
    if (can_report_element_timing)
      text_element_timing_->OnTextObjectPainted(*record);

    if (ltp_manager_ && (record->recorded_size > 0u) &&
        !(record->node_ &&
          ltp_manager_->IsUnrelatedSoftNavigationPaint(*(record->node_)))) {
      ltp_manager_->MaybeUpdateLargestText(record);
    }
    keys_to_be_removed.push_back(it.key);
  }
  texts_queued_for_paint_time_.RemoveAll(keys_to_be_removed);
}

void TextPaintTimingDetector::MaybeRecordTextRecord(
    const LayoutObject& object,
    const uint64_t& visual_size,
    const PropertyTreeStateOrAlias& property_tree_state,
    const gfx::Rect& frame_visual_rect,
    const gfx::RectF& root_visual_rect) {
  Node* node = object.GetNode();
  DCHECK(node);
  // If the node is not required by LCP and not required by ElementTiming, we
  // can bail out early.
  if ((visual_size == 0u || !IsRecordingLargestTextPaint()) &&
      !TextElementTiming::NeededForElementTiming(*node)) {
    return;
  }
  TextRecord* record;
  if (visual_size == 0u) {
    record = MakeGarbageCollected<TextRecord>(
        *node, 0, gfx::RectF(), gfx::Rect(), gfx::RectF(), frame_index_);
  } else {
    record = MakeGarbageCollected<TextRecord>(
        *object.GetNode(), visual_size,
        TextElementTiming::ComputeIntersectionRect(
            object, frame_visual_rect, property_tree_state, frame_view_),
        frame_visual_rect, root_visual_rect, frame_index_);
  }
  QueueToMeasurePaintTime(object, record);
}

}  // namespace blink
```