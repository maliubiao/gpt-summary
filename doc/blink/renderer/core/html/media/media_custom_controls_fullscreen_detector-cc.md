Response:
Let's break down the thought process for analyzing this code and generating the explanation.

1. **Understand the Goal:** The request is to analyze a specific Chromium source file (`media_custom_controls_fullscreen_detector.cc`) and explain its functionality, relationships with web technologies, logic, and potential usage errors.

2. **Initial Skim and Identify Key Components:**  Read through the code to get a general sense of its purpose. Look for keywords and class names that hint at functionality. In this case, "fullscreen," "detector," "intersection," and "viewport" are prominent. The class name `MediaCustomControlsFullscreenDetector` itself is a strong indicator.

3. **Focus on the Core Functionality (the `Detect` Part):** The class name suggests it *detects* something related to fullscreen. The presence of `IntersectionObserver` strongly suggests the detection involves how much of the video is visible within the viewport.

4. **Analyze Key Methods:**  Go through the important methods to understand their roles:
    * **Constructor/Destructor/Attach/Detach:**  These handle the lifecycle of the detector and its connection to the video element and document. Notice the event listeners for fullscreen changes and `loadedmetadata`.
    * **`OnIntersectionChanged`:** This is the heart of the detection logic. It's triggered by the `IntersectionObserver`. Pay close attention to the thresholds and the conditions for considering a video "effectively fullscreen."
    * **`IsFullscreenVideoOfDifferentRatio`:** This helper function deals with a specific edge case – videos with aspect ratios different from the viewport. Analyze its conditions.
    * **`ReportEffectivelyFullscreen`:** This method actually sets the "effectively fullscreen" status on the video element. Note the logic regarding picture-in-picture.
    * **`UpdateDominantAndFullscreenStatus`:** This method combines setting both the "dominant visible content" and "effectively fullscreen" status, using a posted task to avoid synchronous DOM modifications.
    * **`TriggerObservation`:**  This is a way to manually trigger the intersection observation.
    * **`IsVideoOrParentFullscreen`:** This checks if the video is actually within a standard fullscreen element.

5. **Identify Relationships with Web Technologies:**
    * **JavaScript:** Event listeners (`loadedmetadata`, `webkitfullscreenchange`, `fullscreenchange`) are clearly related to JavaScript events that developers can interact with. The `IntersectionObserver` API is also a JavaScript API.
    * **HTML:** The code directly interacts with `HTMLVideoElement` and its attributes (like `disablepictureinpicture`). The concept of an element being "fullscreen" is fundamental to HTML's fullscreen API.
    * **CSS:** While not explicitly manipulating CSS properties, the *visibility* and *size* of the video element, which influence the intersection ratio, are ultimately determined by CSS layout and styling. The "margins" concept in `kMaxAllowedVideoMarginRatio` indirectly relates to CSS margins.

6. **Reconstruct the Logic Flow:** Trace the execution path, especially within `OnIntersectionChanged`:
    * Check if the video is visible at all.
    * Check if the video is inside a *real* fullscreen element.
    * Check if the video fills most of the viewport.
    * If not, apply the `IsFullscreenVideoOfDifferentRatio` heuristic.

7. **Consider Edge Cases and Assumptions:** The code makes assumptions about what constitutes a "fullscreen" experience beyond the browser's native fullscreen API. Think about scenarios where these heuristics might be inaccurate. The comments in the code itself are very helpful here (e.g., the explanation for `kMinPossibleFullscreenIntersectionThreshold`).

8. **Identify Potential Usage Errors:**  Think about how a developer or the browser itself might misuse or encounter issues with this logic:
    * Relying solely on this "effectively fullscreen" status instead of the native fullscreen API.
    * Unexpected behavior if custom controls interfere with the intersection ratios.
    * Performance implications of constantly observing intersection changes.

9. **Formulate Input/Output Examples (Hypothetical):**  Create simplified scenarios to illustrate the logic. Focus on the key conditions in `OnIntersectionChanged` and `IsFullscreenVideoOfDifferentRatio`.

10. **Structure the Explanation:** Organize the findings into logical sections: Functionality, Web Technology Relationships, Logic and Reasoning, Common Usage Errors. Use clear and concise language. Provide concrete examples where possible.

11. **Review and Refine:** Read through the explanation to ensure accuracy, clarity, and completeness. Check for any jargon that needs further explanation.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just detects when a video is fullscreen."  **Correction:**  It detects a *custom* notion of "effectively fullscreen," even if the browser isn't in native fullscreen mode.
* **Focus too much on implementation details:**  **Correction:** Shift focus to the *purpose* and how it relates to the user experience and web development concepts.
* **Missing the nuance of `UpdateDominantAndFullscreenStatus`:** **Correction:**  Realize the asynchronous nature of DOM updates from intersection observers and the reason for using `PostTask`.
* **Not enough concrete examples:** **Correction:** Add specific examples related to HTML, CSS, and JavaScript APIs.

By following these steps, iterating, and refining, we arrive at a comprehensive and accurate explanation of the provided code.这个C++源代码文件 `media_custom_controls_fullscreen_detector.cc`  是 Chromium Blink 渲染引擎的一部分，它的主要功能是 **检测视频元素是否处于一种 "有效地全屏" 状态，即使该视频元素没有使用浏览器原生的全屏 API 进入全屏模式。**  这个检测器是为了支持自定义媒体控件的全屏行为而设计的。

**功能详细说明:**

1. **监听相关事件:**
   - 监听 `loadedmetadata` 事件：当视频的元数据加载完成后触发，此时可以获取视频的尺寸信息。
   - 监听 `webkitfullscreenchange` 和 `fullscreenchange` 事件：监听浏览器原生全屏状态的变化。

2. **使用 IntersectionObserver 观察视频元素:**
   - 创建一个 `IntersectionObserver` 来监视视频元素在视口中的可见性。
   - 设置不同的阈值 (`thresholds`) 来触发观察回调，例如当视频占视口面积达到 15%, 20%, 30%... 85% 时。
   - 观察回调函数 `OnIntersectionChanged` 会在视频的视口交叉状态发生变化时被调用。

3. **基于启发式规则判断 "有效地全屏":**
   - **完全占据大部分视口:** 如果视频占据了视口很大一部分（超过 `kMostlyFillViewportIntersectionThreshold`，默认为 85%），并且处于原生全屏模式或其父元素处于原生全屏模式，则认为它是有效地全屏。
   - **宽高比不同的全屏视频:**  如果视频的宽高比与屏幕的宽高比不同（例如竖屏视频在横屏显示器上播放），则会使用 `IsFullscreenVideoOfDifferentRatio` 函数进行判断。 这个函数会检查：
     - 视频至少在一个维度上占据了视口的大部分（不超过 `kMaxAllowedVideoMarginRatio` 允许的边距）。
     - 视频的大部分是可见的（不超过 `kMaxAllowedPortionOfVideoOffScreen` 允许的遮挡）。
   - **最小可见阈值:** 如果视频在视口中可见的比例低于 `kMinPossibleFullscreenIntersectionThreshold` (默认为 15%)，则直接认为它不是有效地全屏。

4. **更新视频元素的 "有效地全屏" 状态:**
   - 通过 `VideoElement().SetIsEffectivelyFullscreen()` 方法来设置视频元素的 "有效地全屏" 状态。这个状态会被自定义媒体控件用来调整其显示。
   - 如果允许画中画 (`picture_in_picture_allowed`)，则可以设置为 `kFullscreenAndPictureInPictureEnabled`，否则设置为 `kFullscreenAndPictureInPictureDisabled`。

5. **更新视频元素的 "主要可见内容" 状态:**
   - 通过 `VideoElement().SetIsDominantVisibleContent()` 方法来设置视频元素是否是当前页面上主要可见的内容。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - **事件监听:**  `addEventListener` 用于监听 JavaScript 事件，例如 `loadedmetadata`，`webkitfullscreenchange`，`fullscreenchange`。
        ```javascript
        // 在 JavaScript 中，可以监听这些事件来了解视频和全屏状态的变化
        videoElement.addEventListener('loadedmetadata', () => {
          console.log('Video metadata loaded');
        });

        document.addEventListener('fullscreenchange', () => {
          if (document.fullscreenElement) {
            console.log('Entered fullscreen');
          } else {
            console.log('Exited fullscreen');
          }
        });
        ```
    - **Intersection Observer API:**  这个 C++ 代码内部使用了 Blink 的 `IntersectionObserver` 实现，它对应于浏览器的 JavaScript `IntersectionObserver` API。JavaScript 可以创建 `IntersectionObserver` 来监视元素与视口的交叉情况。
        ```javascript
        // JavaScript 中使用 IntersectionObserver 的示例
        const observer = new IntersectionObserver((entries) => {
          entries.forEach(entry => {
            if (entry.isIntersecting) {
              console.log('Video is intersecting the viewport');
            } else {
              console.log('Video is not intersecting the viewport');
            }
          });
        }, { threshold: [0.15, 0.85] }); // 类似于 C++ 代码中的阈值
        const videoElement = document.querySelector('video');
        observer.observe(videoElement);
        ```
    - **修改 DOM 属性:** `VideoElement().SetIsEffectivelyFullscreen()` 最终会影响到视频元素的内部状态，这些状态可能会通过 JavaScript API 暴露出来，或者被 JavaScript 代码用来控制自定义 UI。

* **HTML:**
    - **`HTMLVideoElement`:** 这个 C++ 文件直接操作 `HTMLVideoElement` 对象，这是 HTML 中 `<video>` 标签对应的 DOM 对象。
        ```html
        <video id="myVideo" src="myvideo.mp4" controls></video>
        ```
    - **`disablepictureinpicture` 属性:**  代码中检查了 `html_names::kDisablepictureinpictureAttr`，这对应于 HTML 视频元素的 `disablepictureinpicture` 属性。
        ```html
        <video id="myVideo" src="myvideo.mp4" controls disablepictureinpicture></video>
        ```

* **CSS:**
    - **视频元素的布局和尺寸:** CSS 决定了视频元素在页面上的布局和尺寸，这直接影响了 `IntersectionObserver` 的观察结果。例如，如果视频被 CSS 设置为 `position: fixed; width: 100%; height: 100%;`，那么它很可能被判断为有效地全屏。
    - **自定义控件的样式:** 虽然这个文件不直接操作 CSS，但它检测到的 "有效地全屏" 状态可以被 JavaScript 代码用来添加或移除 CSS 类，从而改变自定义媒体控件的样式，使其看起来像全屏模式下的控件。

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

* 视频元素 `<video id="myVideo" src="myvideo.mp4"></video>`
* 用户点击按钮，通过 JavaScript 将视频元素放入浏览器原生全屏模式。

**输出 1:**

* `IsVideoOrParentFullscreen()` 返回 `true`.
* `OnIntersectionChanged` 被触发，如果视频占据了视口超过 85%，则 `is_mostly_filling_viewport` 为 `true`.
* `UpdateDominantAndFullscreenStatus` 被调用，设置视频元素的 "有效地全屏" 状态为 `kFullscreenAndPictureInPictureEnabled` 或 `kFullscreenAndPictureInPictureDisabled`，并且 "主要可见内容" 为 `true`.

**假设输入 2:**

* 视频元素 `<video id="myVideo" src="myvideo.mp4"></video>`
* 用户没有使用浏览器原生全屏，但通过自定义 JavaScript 代码调整了视频元素的样式，使其占据了浏览器窗口的大部分，但留有一些边距。

**输出 2:**

* `IsVideoOrParentFullscreen()` 返回 `false`.
* `OnIntersectionChanged` 被触发。
* 如果视频占据了视口大部分，但没有超过 85%，则 `is_mostly_filling_viewport` 为 `false`.
* `IsFullscreenVideoOfDifferentRatio` 函数会被调用，如果视频满足其内部的启发式条件（例如，至少在一个维度上占据了大部分视口，且大部分可见），则 `UpdateDominantAndFullscreenStatus` 会将视频的 "有效地全屏" 状态设置为 `true`。

**假设输入 3:**

* 视频元素 `<video id="myVideo" src="myvideo.mp4"></video>`
* 视频很小，只占据视口的一小部分。

**输出 3:**

* `OnIntersectionChanged` 被触发。
* `entries.back()->intersectionRatio()` 小于 `kMinPossibleFullscreenIntersectionThreshold`.
* `UpdateDominantAndFullscreenStatus` 被调用，设置视频元素的 "有效地全屏" 状态为 `kNotEffectivelyFullscreen`，并且 "主要可见内容" 为 `false`.

**用户或编程常见的使用错误:**

1. **错误地依赖 "有效地全屏" 状态来判断是否真的处于原生全屏:**  开发者应该区分 "有效地全屏" 和浏览器原生的全屏状态。  "有效地全屏" 只是一个启发式的判断，用于自定义控件的行为。要判断是否真的处于原生全屏，应该使用标准的 Fullscreen API (例如 `document.fullscreenElement`)。

2. **自定义控件的尺寸或布局干扰了检测逻辑:** 如果自定义控件本身占据了视频元素周围的大量空间，可能会导致 `IntersectionObserver` 错误地判断视频是否处于 "有效地全屏"。 例如，如果自定义控件在视频上方覆盖了很大一部分，可能会导致 `intersectionRatio` 降低，即使视频本身看起来是全屏的。

3. **在不必要的情况下频繁触发 `TriggerObservation`:**  `TriggerObservation` 会强制重新计算交叉状态，如果频繁调用可能会影响性能。这个方法通常应该在视频的尺寸或视口发生变化后调用，而不是无节制地调用。

4. **假设所有浏览器都以相同的方式计算交叉比例:**  虽然 `IntersectionObserver` 是一个标准 API，但不同浏览器可能在边缘情况下有细微的实现差异，开发者不应该对特定浏览器的行为做过于绝对的假设。

5. **忘记处理原生全屏状态变化:**  即使使用了 "有效地全屏" 检测，开发者仍然需要监听 `webkitfullscreenchange` 和 `fullscreenchange` 事件，以便在用户使用浏览器原生全屏功能时进行相应的处理。

总而言之，`media_custom_controls_fullscreen_detector.cc` 文件实现了一个复杂的逻辑，用于在没有使用浏览器原生全屏 API 的情况下，判断视频元素是否看起来像是在全屏播放，这主要是为了提供更好的自定义媒体控件体验。 理解其工作原理以及与 Web 技术的关系，可以帮助开发者更有效地使用和调试相关的 Web 功能。

### 提示词
```
这是目录为blink/renderer/core/html/media/media_custom_controls_fullscreen_detector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/media_custom_controls_fullscreen_detector.h"

#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_fullscreen_video_status.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/geometry/size_conversions.h"

namespace blink {

using blink::WebFullscreenVideoStatus;

namespace {

// If a video takes more that this much of the viewport, it's counted as
// fullscreen without applying the fullscreen heuristics.
// (Assuming we're in the fullscreen mode.)
constexpr float kMostlyFillViewportIntersectionThreshold = 0.85f;

// If a video takes less that this much of the viewport, we don't
// apply the fullscreen heuristics and just declare it not fullscreen.
// A portrait ultrawide video (21:9) playing on a landscape ultrawide screen
// takes about 18% of the screen, that's why 15% looks like a reasonable
// lowerbound of a real-world fullscreen video.
constexpr float kMinPossibleFullscreenIntersectionThreshold = 0.15f;

// This is how much of the viewport around the video can be taken by
// margins and framing for it to still be counted as fullscreen.
// It is measured only in the dominant direction, because of potential ratio
// mismatch that would cause big margins in the other direction.
// For example: portrain video on a landscape screen.
constexpr float kMaxAllowedVideoMarginRatio = 0.15;

// This is how much of the video can be hidden by something
// before it is nor longer counted as fullscreen.
// This helps to disregard custom controls, ads, accidental markup mistakes.
constexpr float kMaxAllowedPortionOfVideoOffScreen = 0.25;

// This heuristic handles a case of videos with an aspect ratio
// different from the screen's aspect ratio.
// Examples: A 4:3 video playing on a 16:9 screen.
//           A portrait video playing on a landscape screen.
// In a nutshell:
//  1. The video should occupy most of the viewport in at least one dimension.
//  2. The video should be almost fully visible on the screen.
bool IsFullscreenVideoOfDifferentRatio(const gfx::Size& video_size,
                                       const gfx::Size& viewport_size,
                                       const gfx::Size& intersection_size) {
  if (video_size.IsEmpty() || viewport_size.IsEmpty())
    return false;

  const float x_occupation_proportion =
      1.0f * intersection_size.width() / viewport_size.width();
  const float y_occupation_proportion =
      1.0f * intersection_size.height() / viewport_size.height();

  // The video should occupy most of the viewport in at least one dimension.
  if (std::max(x_occupation_proportion, y_occupation_proportion) <
      (1.0 - kMaxAllowedVideoMarginRatio)) {
    return false;
  }

  // The video should be almost fully visible on the screen.
  return video_size.Area64() * (1.0 - kMaxAllowedPortionOfVideoOffScreen) <=
         intersection_size.Area64();
}

}  // anonymous namespace

MediaCustomControlsFullscreenDetector::MediaCustomControlsFullscreenDetector(
    HTMLVideoElement& video)
    : video_element_(video), viewport_intersection_observer_(nullptr) {
  if (VideoElement().isConnected())
    Attach();
}

void MediaCustomControlsFullscreenDetector::Attach() {
  VideoElement().addEventListener(event_type_names::kLoadedmetadata, this,
                                  true);
  VideoElement().GetDocument().addEventListener(
      event_type_names::kWebkitfullscreenchange, this, true);
  VideoElement().GetDocument().addEventListener(
      event_type_names::kFullscreenchange, this, true);

  viewport_intersection_observer_ = IntersectionObserver::Create(
      video_element_->GetDocument(),
      WTF::BindRepeating(
          &MediaCustomControlsFullscreenDetector::OnIntersectionChanged,
          WrapWeakPersistent(this)),
      LocalFrameUkmAggregator::kMediaIntersectionObserver,
      IntersectionObserver::Params{
          // Ideally we'd like to monitor all minute intersection changes
          // here, because any change can potentially affect the fullscreen
          // heuristics, but it's not practical from perf point of view.
          // Given that the heuristics are more of a guess that exact science,
          // it wouldn't be well spent CPU cycles anyway. That's why the
          // observer only triggers on 10% steps in viewport area occupation.
          .thresholds = {kMinPossibleFullscreenIntersectionThreshold, 0.2, 0.3,
                         0.4, 0.5, 0.6, 0.7, 0.8,
                         kMostlyFillViewportIntersectionThreshold},
          .semantics = IntersectionObserver::kFractionOfRoot,
          .always_report_root_bounds = true,
      });
  viewport_intersection_observer_->observe(&VideoElement());
}

void MediaCustomControlsFullscreenDetector::Detach() {
  if (viewport_intersection_observer_) {
    viewport_intersection_observer_->disconnect();
    viewport_intersection_observer_ = nullptr;
  }
  VideoElement().removeEventListener(event_type_names::kLoadedmetadata, this,
                                     true);
  VideoElement().GetDocument().removeEventListener(
      event_type_names::kWebkitfullscreenchange, this, true);
  VideoElement().GetDocument().removeEventListener(
      event_type_names::kFullscreenchange, this, true);
  VideoElement().SetIsEffectivelyFullscreen(
      WebFullscreenVideoStatus::kNotEffectivelyFullscreen);
}

void MediaCustomControlsFullscreenDetector::Invoke(ExecutionContext* context,
                                                   Event* event) {
  DCHECK(event->type() == event_type_names::kLoadedmetadata ||
         event->type() == event_type_names::kWebkitfullscreenchange ||
         event->type() == event_type_names::kFullscreenchange);

  // Video is not loaded yet.
  if (VideoElement().getReadyState() < HTMLMediaElement::kHaveMetadata)
    return;

  TriggerObservation();
}

void MediaCustomControlsFullscreenDetector::ContextDestroyed() {
  Detach();
}

void MediaCustomControlsFullscreenDetector::ReportEffectivelyFullscreen(
    bool effectively_fullscreen) {
  if (!effectively_fullscreen) {
    VideoElement().SetIsEffectivelyFullscreen(
        WebFullscreenVideoStatus::kNotEffectivelyFullscreen);
    return;
  }

  bool picture_in_picture_allowed = !VideoElement().FastHasAttribute(
      html_names::kDisablepictureinpictureAttr);

  if (picture_in_picture_allowed) {
    VideoElement().SetIsEffectivelyFullscreen(
        WebFullscreenVideoStatus::kFullscreenAndPictureInPictureEnabled);
  } else {
    VideoElement().SetIsEffectivelyFullscreen(
        WebFullscreenVideoStatus::kFullscreenAndPictureInPictureDisabled);
  }
}

void MediaCustomControlsFullscreenDetector::UpdateDominantAndFullscreenStatus(
    bool is_dominant_visible_content,
    bool is_effectively_fullscreen) {
  DCHECK(viewport_intersection_observer_);

  auto update_dominant_and_fullscreen =
      [](MediaCustomControlsFullscreenDetector* self,
         bool is_dominant_visible_content, bool is_effectively_fullscreen) {
        if (!self || !self->viewport_intersection_observer_)
          return;

        self->VideoElement().SetIsDominantVisibleContent(
            is_dominant_visible_content);
        self->ReportEffectivelyFullscreen(is_effectively_fullscreen);
      };

  // Post these updates, since callbacks from |viewport_intersection_observer_|
  // are not allowed to synchronously modify DOM elements.
  VideoElement()
      .GetDocument()
      .GetTaskRunner(TaskType::kInternalMedia)
      ->PostTask(FROM_HERE, WTF::BindOnce(update_dominant_and_fullscreen,
                                          WrapWeakPersistent(this),
                                          is_dominant_visible_content,
                                          is_effectively_fullscreen));
}

void MediaCustomControlsFullscreenDetector::OnIntersectionChanged(
    const HeapVector<Member<IntersectionObserverEntry>>& entries) {
  if (!viewport_intersection_observer_ || entries.empty())
    return;

  auto* layout = VideoElement().GetLayoutObject();
  if (!layout || entries.back()->intersectionRatio() <
                     kMinPossibleFullscreenIntersectionThreshold) {
    // Video is not shown at all.
    UpdateDominantAndFullscreenStatus(false, false);
    return;
  }

  const bool is_mostly_filling_viewport =
      entries.back()->intersectionRatio() >=
      kMostlyFillViewportIntersectionThreshold;

  if (!IsVideoOrParentFullscreen()) {
    // The video is outside of a fullscreen element.
    // This is definitely not a fullscreen video experience.
    UpdateDominantAndFullscreenStatus(is_mostly_filling_viewport, false);
    return;
  }

  if (is_mostly_filling_viewport) {
    // Video takes most part (85%) of the screen, report fullscreen.
    UpdateDominantAndFullscreenStatus(true, true);
    return;
  }

  const IntersectionGeometry& geometry = entries.back()->GetGeometry();
  gfx::Size target_size = gfx::ToRoundedSize(geometry.TargetRect().size());
  gfx::Size intersection_size =
      gfx::ToRoundedSize(geometry.IntersectionRect().size());
  gfx::Size root_size = gfx::ToRoundedSize(geometry.RootRect().size());

  UpdateDominantAndFullscreenStatus(
      false, IsFullscreenVideoOfDifferentRatio(target_size, root_size,
                                               intersection_size));
}

void MediaCustomControlsFullscreenDetector::TriggerObservation() {
  if (!viewport_intersection_observer_)
    return;

  // Removing and re-adding the observable element is just a way to
  // trigger the observation callback and reevaluate the intersection ratio.
  viewport_intersection_observer_->unobserve(&VideoElement());
  viewport_intersection_observer_->observe(&VideoElement());
}

bool MediaCustomControlsFullscreenDetector::IsVideoOrParentFullscreen() {
  Element* fullscreen_element =
      Fullscreen::FullscreenElementFrom(VideoElement().GetDocument());
  if (!fullscreen_element)
    return false;

  return fullscreen_element->contains(&VideoElement());
}

void MediaCustomControlsFullscreenDetector::Trace(Visitor* visitor) const {
  NativeEventListener::Trace(visitor);
  visitor->Trace(video_element_);
  visitor->Trace(viewport_intersection_observer_);
}

// static
bool MediaCustomControlsFullscreenDetector::
    IsFullscreenVideoOfDifferentRatioForTesting(
        const gfx::Size& video_size,
        const gfx::Size& viewport_size,
        const gfx::Size& intersection_size) {
  return IsFullscreenVideoOfDifferentRatio(video_size, viewport_size,
                                           intersection_size);
}

}  // namespace blink
```