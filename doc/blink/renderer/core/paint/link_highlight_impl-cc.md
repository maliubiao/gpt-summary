Response:
Let's break down the thought process for analyzing this code and generating the detailed explanation.

1. **Understand the Goal:** The request is to analyze the `link_highlight_impl.cc` file, focusing on its functionality, relationships with web technologies (HTML, CSS, JavaScript), logic, potential errors, and how it's triggered.

2. **Initial Skim and Keyword Identification:**  Read through the code quickly to get a general sense. Look for keywords like `LinkHighlight`, `Paint`, `Animation`, `Compositor`, `Opacity`, `Node`, `Layout`, `Fragment`, `Color`, etc. These keywords give strong clues about the file's purpose.

3. **High-Level Functionality Identification:**  The name itself, "link highlight implementation," strongly suggests its purpose is to visually highlight links when they are interacted with (typically on touch devices). The code confirms this by manipulating opacity and drawing shapes.

4. **Dissecting Key Components and Methods:**  Now, go through the code more systematically, focusing on the main classes and methods:

    * **`LinkHighlightImpl` Constructor and Destructor:**  Note the initialization of `compositor_animation_`, `effect_`, and the attachment to a `Node`. The destructor handles resource release and detaching the animation. This establishes the basic lifecycle of a link highlight.

    * **`ReleaseResources()`:** Identify what resources are released and why (optimization, preventing leaks when the highlight is no longer needed).

    * **Animation Related Methods (`StartCompositorAnimation`, `StopCompositorAnimation`, `NotifyAnimationFinished`):** Understand how the fade-in/fade-out effect is achieved using compositor animations. Pay attention to the timing and the use of `KeyframeModel` and `CubicBezierTimingFunction`. Note the target opacity being 0 (fading out).

    * **Painting Related Methods (`Paint`, `PaintContentsToDisplayList`):**  Analyze how the highlight is actually drawn. Notice the use of `GraphicsContext`, `PaintRecorder`, `Path`, `cc::PaintFlags`, and `cc::PictureLayer`. The logic for handling fragmented links (multiple rectangles) and rounded corners is important.

    * **Update Methods (`UpdateBeforePrePaint`, `UpdateAfterPrePaint`, `UpdateAfterPaint`):**  Understand when and why these methods are called during the rendering pipeline. `UpdateBeforePrePaint` handles throttling, `UpdateAfterPrePaint` manages the number of fragments, and `UpdateAfterPaint` starts the compositor animation after the initial paint.

    * **`SetNeedsRepaintAndCompositingUpdate()` and `UpdateOpacity()`:** These are crucial for triggering visual updates and managing the opacity of the highlight.

    * **`LinkHighlightFragment`:** Understand this inner class is responsible for painting an individual fragment of the highlight, using a `cc::PictureLayer`.

5. **Connecting to Web Technologies:**  Think about how the functionality relates to HTML, CSS, and JavaScript:

    * **HTML:**  The link highlight is triggered by interaction with anchor tags (`<a>`). The `Node* node_` member points to the HTML element.

    * **CSS:**  The highlight color comes from the `-webkit-tap-highlight-color` CSS property. This is a direct link between CSS styling and the highlight's appearance.

    * **JavaScript:** While this specific file doesn't directly *execute* JavaScript, JavaScript interactions (like `touchstart` or `mousedown` on a link) are the *triggers* that eventually lead to the creation and display of the link highlight.

6. **Logic and Assumptions:**  Examine the code for conditional logic and assumptions:

    * **Animation Start/Stop Conditions:** When does the animation start?  When does it stop?  What happens if the element isn't composited?

    * **Fragment Handling:** How does the code handle links that span multiple lines or are broken into fragments?

    * **Rounded Rectangles:**  The logic for when to use rounded rectangles versus simple rectangles is a specific decision point.

7. **Potential Errors and User Mistakes:** Think about what could go wrong or how a developer might misuse the feature:

    * **Performance:**  Excessive or poorly implemented highlights could impact performance.

    * **Unexpected Behavior:** If the `-webkit-tap-highlight-color` is set to `transparent`, the highlight might not be visible, confusing the user.

    * **Overlapping Highlights:**  If multiple interactive elements are close together, the highlights might overlap in unintended ways.

8. **Tracing User Interaction:**  Imagine a user tapping a link on a touch device. Trace the sequence of events that would lead to this code being executed:

    * User touches the screen.
    * Browser identifies the touch target as a link.
    * Event handlers trigger (potentially JavaScript).
    * Blink's event handling mechanism initiates the link highlight.
    * `LinkHighlightImpl` is created or updated.
    * Painting occurs, driven by the methods in this file.
    * Compositor animations manage the fade effect.

9. **Structuring the Explanation:** Organize the findings logically:

    * Start with a concise summary of the file's purpose.
    * Detail the core functionalities.
    * Explain the relationships with web technologies with concrete examples.
    * Provide a logical inference scenario with input and output.
    * Describe potential errors and user mistakes.
    * Outline the user interaction flow as a debugging aid.

10. **Refinement and Clarity:**  Review the explanation for clarity and accuracy. Ensure that technical terms are explained or are understandable in context. Use clear examples and avoid jargon where possible. For instance, explicitly stating the trigger for the highlight (touch/click) is helpful.

By following these steps, breaking down the code into manageable parts, and thinking about the broader context of web development, you can effectively analyze and explain the functionality of a complex source code file like `link_highlight_impl.cc`.
好的，让我们来详细分析一下 `blink/renderer/core/paint/link_highlight_impl.cc` 这个文件。

**文件功能概览**

`link_highlight_impl.cc` 文件的主要功能是**实现链接（`<a>` 标签）在用户交互时的视觉高亮效果**。  这种高亮通常是在用户点击或触摸链接时短暂出现的，用于提供即时反馈，表明链接已被激活。

更具体地说，这个文件负责：

* **创建和管理高亮效果的图形表示:**  它使用 Blink 的渲染引擎提供的绘图 API 来生成高亮形状，通常是矩形或圆角矩形。
* **控制高亮效果的显示和消失:**  它通过动画（淡入和淡出）来平滑地显示和隐藏高亮，而不是突然出现或消失。
* **处理链接在不同渲染情况下的高亮:**  它需要处理链接可能跨越多行、包含内联元素等复杂布局情况。
* **与 Blink 的合成器（Compositor）交互:** 为了实现流畅的动画，它使用 Blink 的合成器框架来在独立的合成线程上执行动画，避免阻塞主线程。

**与 JavaScript, HTML, CSS 的关系**

这个文件虽然是用 C++ 编写的，位于 Blink 渲染引擎的核心，但它直接服务于 HTML、CSS 和 JavaScript 的功能。

* **HTML:**
    * **关联元素:** `LinkHighlightImpl` 对象与 HTML 中的 `<a>` 元素（通过 `Node* node_` 成员）关联。当用户与一个链接交互时，就会创建或更新对应的 `LinkHighlightImpl` 对象。
    * **触发条件:**  用户在 HTML 页面上点击或触摸一个链接是触发高亮效果的直接原因。

* **CSS:**
    * **高亮颜色:**  `object->StyleRef().VisitedDependentColor(GetCSSPropertyWebkitTapHighlightColor())` 这行代码表明，高亮的颜色来源于 CSS 属性 `-webkit-tap-highlight-color`。开发者可以通过 CSS 自定义链接被点击时的高亮颜色。
    * **高亮形状（间接影响）:** 虽然这个文件主要负责绘制，但链接的布局（例如，是块级元素还是内联元素，是否跨越多行）会影响高亮形状的生成。这些布局属性是由 CSS 控制的。

* **JavaScript:**
    * **事件触发:** 虽然 `link_highlight_impl.cc` 本身不执行 JavaScript，但用户的交互（如 `touchstart`、`mousedown` 等事件）首先由浏览器的事件系统捕获，然后可能触发 JavaScript 代码。在没有被阻止的情况下，这些事件最终会导致 Blink 渲染引擎创建或更新链接的高亮效果。
    * **间接影响:**  JavaScript 可以通过修改 DOM 结构或 CSS 样式来间接地影响链接的布局和渲染，从而影响高亮效果的绘制。例如，JavaScript 动态地改变链接的位置或大小。

**举例说明**

**HTML 示例:**

```html
<a href="https://example.com">这是一个链接</a>
```

**CSS 示例:**

```css
a {
  color: blue;
}

/* 自定义链接被点击时的高亮颜色 */
a:active, a:focus { /* 传统的鼠标点击和键盘焦点 */
  background-color: lightblue;
}

/* 针对触摸设备的点击高亮颜色 */
-webkit-tap-highlight-color: rgba(0, 0, 255, 0.3); /* 半透明蓝色 */
```

**JavaScript 示例（可能会影响高亮）：**

```javascript
const link = document.querySelector('a');
link.addEventListener('touchstart', (event) => {
  // 阻止默认的触摸高亮
  // event.preventDefault();
  console.log('链接被触摸了');
});
```

**逻辑推理 (假设输入与输出)**

**假设输入:**

1. 用户在触摸设备上点击了 HTML 中的一个 `<a>` 链接元素。
2. 该链接的 `-webkit-tap-highlight-color` CSS 属性设置为 `rgba(255, 0, 0, 0.5)` (半透明红色)。
3. 链接文字跨越两行。

**输出:**

1. `LinkHighlightImpl` 对象被创建并与该链接的 DOM 节点关联。
2. 计算出覆盖链接文本两行的矩形区域。
3. 创建一个半透明红色的图形层（`cc::PictureLayer`）。
4. 使用圆角矩形（如果 `GetMockGestureTapHighlightsEnabled()` 为 false 且链接没有被分割成多个独立的渲染片段）或普通矩形填充这个区域。
5. 启动一个淡入动画，使高亮层逐渐显示出来，初始透明度为 1。
6. 在短暂停留后，启动一个淡出动画，使高亮层逐渐消失，最终透明度为 0。
7. 整个动画过程在合成器线程上进行，以保证主线程的流畅性。

**用户或编程常见的使用错误**

1. **CSS 设置了 `transparent` 的 `-webkit-tap-highlight-color`:**  用户交互时不会看到任何高亮效果，可能会感到困惑，不知道是否点击成功。

   ```css
   a {
     -webkit-tap-highlight-color: transparent; /* 错误：设置透明 */
   }
   ```

2. **JavaScript 中错误地阻止了默认行为:**  如果 JavaScript 代码中调用了 `event.preventDefault()` 并且没有提供替代的视觉反馈，用户可能看不到任何高亮，也不知道链接是否被激活。

   ```javascript
   link.addEventListener('touchstart', (event) => {
     event.preventDefault(); // 阻止了默认的触摸高亮
     // ... 但没有提供其他高亮效果
   });
   ```

3. **性能问题：过度复杂的布局导致高亮计算开销过大:**  在非常复杂的页面布局中，计算高亮区域可能会消耗一定的计算资源，如果过度使用或布局过于复杂，可能会导致轻微的性能问题。

4. **Blink 内部错误（不太常见）：**  虽然不太常见，但 Blink 渲染引擎的 bug 也可能导致高亮效果出现异常，例如高亮位置不正确、动画不流畅等。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户操作:** 用户用鼠标点击或在触摸设备上触摸一个页面上的链接（`<a>` 标签）。

2. **浏览器事件捕获:**
   * **触摸设备:** 浏览器捕获 `touchstart` 和 `touchend` (或 `click` 的模拟事件) 等触摸事件。
   * **桌面设备:** 浏览器捕获 `mousedown` 和 `mouseup` (或 `click`) 等鼠标事件。

3. **事件分发与处理:**  浏览器将这些事件分发到渲染进程（Blink 的所在地）。

4. **目标元素识别:**  Blink 的事件处理机制确定哪个 DOM 元素是事件的目标（通常是 `<a>` 元素）。

5. **触发高亮逻辑:**
   * Blink 的相关代码（可能在 `EventHandler` 或类似的模块中）会检查目标元素是否是链接，以及是否需要显示高亮。
   * 这会涉及到检查 `-webkit-tap-highlight-color` CSS 属性的值。

6. **创建或更新 `LinkHighlightImpl`:**
   * 如果该链接还没有对应的 `LinkHighlightImpl` 对象，则创建一个新的。
   * 如果已经存在，则可能需要更新其状态（例如，重新计算高亮区域）。

7. **计算高亮区域 (`CollectOutlineRectsAndAdvance`):**  Blink 的布局引擎会根据链接的渲染信息（位置、大小、是否跨行等）计算出需要高亮的区域。

8. **创建图形层 (`cc::PictureLayer`):**  `LinkHighlightImpl` 创建一个用于绘制高亮的图形层。

9. **绘制高亮 (`PaintContentsToDisplayList`):**  在该图形层的上下文中，使用指定的颜色和形状（矩形或圆角矩形）绘制高亮。

10. **启动合成器动画 (`StartCompositorAnimation`):**  为了实现平滑的淡入和淡出效果，将动画任务提交给 Blink 的合成器线程。

11. **合成与显示:**  合成器线程独立地执行动画，更新高亮层的透明度，并将最终的渲染结果提交给 GPU 进行显示。

12. **动画结束 (`NotifyAnimationFinished`):**  动画完成后，`LinkHighlightImpl` 可能会释放相关资源。

**调试线索:**

* **断点:** 在 `LinkHighlightImpl` 的构造函数、`Paint` 方法、`StartCompositorAnimation` 方法等关键位置设置断点，可以观察高亮效果的创建、绘制和动画过程。
* **日志输出:** 在相关代码中添加日志输出，记录关键变量的值（例如，高亮区域的坐标、颜色、动画状态），有助于理解代码的执行流程。
* **Blink 开发者工具:** 使用 Blink 提供的开发者工具（例如，`--enable-blink-features=PaintTiming` 或其他与渲染相关的标志）可以更深入地了解渲染过程。
* **Layout Tree 和 Paint Tree 观察:**  观察 Blink 的布局树和绘制树，可以了解链接的布局信息以及高亮层在渲染管道中的位置。
* **合成器帧查看器:**  Blink 提供了查看合成器帧的工具，可以帮助理解合成器动画的执行情况。

希望以上分析能够帮助你理解 `blink/renderer/core/paint/link_highlight_impl.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/paint/link_highlight_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/paint/link_highlight_impl.h"

#include <memory>
#include <utility>

#include "base/debug/stack_trace.h"
#include "base/memory/ptr_util.h"
#include "cc/animation/animation_id_provider.h"
#include "cc/animation/keyframe_model.h"
#include "cc/layers/picture_layer.h"
#include "cc/paint/display_item_list.h"
#include "cc/trees/target_property.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/paint/fragment_data_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/animation/timing_function.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_display_item_fragment.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/animation/keyframe/keyframed_animation_curve.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

static constexpr float kStartOpacity = 1;

namespace {

float GetTargetOpacity() {
  return WebTestSupport::IsRunningWebTest() ? kStartOpacity : 0;
}

EffectPaintPropertyNode::State LinkHighlightEffectNodeState(
    float opacity,
    CompositorElementId element_id) {
  EffectPaintPropertyNode::State state;
  state.opacity = opacity;
  state.local_transform_space = &TransformPaintPropertyNode::Root();
  state.compositor_element_id = element_id;
  // EffectPaintPropertyNode::Update does not pay attention to changes in
  // direct_compositing_reasons so we assume that the effect node is always
  // animating.
  state.direct_compositing_reasons = CompositingReason::kActiveOpacityAnimation;
  return state;
}

}  // namespace

static CompositorElementId NewElementId() {
  return CompositorElementIdFromUniqueObjectId(
      NewUniqueObjectId(), CompositorElementIdNamespace::kPrimaryEffect);
}

LinkHighlightImpl::LinkHighlightImpl(Node* node)
    : node_(node),
      start_time_(base::TimeTicks::Now()),
      element_id_(NewElementId()) {
  DCHECK(node_);
  fragments_.push_back(std::make_unique<LinkHighlightFragment>());

  compositor_animation_ = CompositorAnimation::Create();
  DCHECK(compositor_animation_);
  compositor_animation_->SetAnimationDelegate(this);
  compositor_animation_->AttachElement(element_id_);

  effect_ = EffectPaintPropertyNode::Create(
      EffectPaintPropertyNode::Root(),
      LinkHighlightEffectNodeState(kStartOpacity, element_id_));

  DCHECK(GetLayoutObject());
  GetLayoutObject()->SetNeedsPaintPropertyUpdate();
  SetNeedsRepaintAndCompositingUpdate();

#if DCHECK_IS_ON()
  effect_->SetDebugName("LinkHighlightEffect");
#endif
}

LinkHighlightImpl::~LinkHighlightImpl() {
  ReleaseResources();

  if (compositor_animation_->IsElementAttached())
    compositor_animation_->DetachElement();
  compositor_animation_->SetAnimationDelegate(nullptr);
  compositor_animation_.reset();
}

void LinkHighlightImpl::ReleaseResources() {
  StopCompositorAnimation();

  if (!node_)
    return;

  if (auto* layout_object = GetLayoutObject())
    layout_object->SetNeedsPaintPropertyUpdate();

  SetNeedsRepaintAndCompositingUpdate();

  node_.Clear();
}

void LinkHighlightImpl::StartCompositorAnimation() {
  is_animating_on_compositor_ = true;
  // FIXME: Should duration be configurable?
  constexpr auto kFadeDuration = base::Milliseconds(100);
  constexpr auto kMinPreFadeDuration = base::Milliseconds(100);

  auto curve = gfx::KeyframedFloatAnimationCurve::Create();

  const auto& timing_function = *CubicBezierTimingFunction::Preset(
      CubicBezierTimingFunction::EaseType::EASE);

  curve->AddKeyframe(gfx::FloatKeyframe::Create(base::Seconds(0), kStartOpacity,
                                                timing_function.CloneToCC()));
  // Make sure we have displayed for at least minPreFadeDuration before starting
  // to fade out.
  base::TimeDelta extra_duration_required =
      std::max(base::TimeDelta(),
               kMinPreFadeDuration - (base::TimeTicks::Now() - start_time_));
  if (!extra_duration_required.is_zero()) {
    curve->AddKeyframe(gfx::FloatKeyframe::Create(
        extra_duration_required, kStartOpacity, timing_function.CloneToCC()));
  }
  curve->AddKeyframe(gfx::FloatKeyframe::Create(
      kFadeDuration + extra_duration_required, GetTargetOpacity(),
      timing_function.CloneToCC()));

  auto keyframe_model = cc::KeyframeModel::Create(
      std::move(curve), cc::AnimationIdProvider::NextKeyframeModelId(),
      cc::AnimationIdProvider::NextGroupId(),
      cc::KeyframeModel::TargetPropertyId(cc::TargetProperty::OPACITY));

  compositor_keyframe_model_id_ = keyframe_model->id();
  compositor_animation_->AddKeyframeModel(std::move(keyframe_model));
}

void LinkHighlightImpl::StopCompositorAnimation() {
  if (!is_animating_on_compositor_)
    return;

  is_animating_on_compositor_ = false;
  compositor_animation_->RemoveKeyframeModel(compositor_keyframe_model_id_);
  compositor_keyframe_model_id_ = 0;
}

LinkHighlightImpl::LinkHighlightFragment::LinkHighlightFragment() {
  layer_ = cc::PictureLayer::Create(this);
  layer_->SetIsDrawable(true);
  layer_->SetOpacity(kStartOpacity);
}

LinkHighlightImpl::LinkHighlightFragment::~LinkHighlightFragment() {
  layer_->ClearClient();
}

scoped_refptr<cc::DisplayItemList>
LinkHighlightImpl::LinkHighlightFragment::PaintContentsToDisplayList() {
  auto display_list = base::MakeRefCounted<cc::DisplayItemList>();

  PaintRecorder recorder;
  gfx::Rect record_bounds(layer_->bounds());
  cc::PaintCanvas* canvas = recorder.beginRecording();

  cc::PaintFlags flags;
  flags.setStyle(cc::PaintFlags::kFill_Style);
  flags.setAntiAlias(true);
  flags.setColor(color_.Rgb());
  canvas->drawPath(path_.GetSkPath(), flags);

  display_list->StartPaint();
  display_list->push<cc::DrawRecordOp>(recorder.finishRecordingAsPicture());
  display_list->EndPaintOfUnpaired(record_bounds);

  display_list->Finalize();
  return display_list;
}

void LinkHighlightImpl::UpdateOpacityAndRequestAnimation() {
  if (!node_ || is_animating_on_compositor_ || start_compositor_animation_)
    return;

  // Since the notification about the animation finishing may not arrive in
  // time to remove the link highlight before it's drawn without an animation
  // we set the opacity to the final target opacity to avoid a flash of the
  // initial opacity. https://crbug.com/974160.
  // Note it's also possible we may skip the animation if the property node
  // has not been composited in which case we immediately use the target
  // opacity.
  UpdateOpacity(GetTargetOpacity());

  // We request a compositing update after which UpdateAfterPaint will start
  // the composited animation at the same time as PendingAnimations::Update
  // starts composited web animations.
  SetNeedsRepaintAndCompositingUpdate();
  start_compositor_animation_ = true;
}

void LinkHighlightImpl::NotifyAnimationFinished(base::TimeDelta, int) {
  // Since WebViewImpl may hang on to us for a while, make sure we
  // release resources as soon as possible.
  ReleaseResources();

  // Reset the link highlight opacity to clean up after the animation now that
  // we have removed the node and it won't be displayed.
  UpdateOpacity(kStartOpacity);
}

void LinkHighlightImpl::UpdateBeforePrePaint() {
  auto* object = GetLayoutObject();
  if (!object || object->GetFrameView()->ShouldThrottleRendering())
    ReleaseResources();
}

void LinkHighlightImpl::UpdateAfterPrePaint() {
  auto* object = GetLayoutObject();
  if (!object)
    return;
  DCHECK(!object->GetFrameView()->ShouldThrottleRendering());

  wtf_size_t fragment_count = object->FragmentList().size();
  if (fragment_count != fragments_.size()) {
    wtf_size_t i = fragments_.size();
    fragments_.resize(fragment_count);
    for (; i < fragment_count; ++i) {
      fragments_[i] = std::make_unique<LinkHighlightFragment>();
    }
    SetNeedsRepaintAndCompositingUpdate();
  }
}

CompositorAnimation* LinkHighlightImpl::GetCompositorAnimation() const {
  return compositor_animation_.get();
}

void LinkHighlightImpl::Paint(GraphicsContext& context) {
  auto* object = GetLayoutObject();
  if (!object)
    return;

  DCHECK(object->GetFrameView());
  DCHECK(!object->GetFrameView()->ShouldThrottleRendering());

  auto color = object->StyleRef().VisitedDependentColor(
      GetCSSPropertyWebkitTapHighlightColor());

  // For now, we'll only use rounded rects if we have a single rect because
  // otherwise we may sometimes get a chain of adjacent boxes (e.g. for text
  // nodes) which end up looking like sausage links: these should ideally be
  // merged into a single rect before creating the path.
  bool use_rounded_rects = !node_->GetDocument()
                                .GetSettings()
                                ->GetMockGestureTapHighlightsEnabled() &&
                           !object->IsFragmented();

  wtf_size_t index = 0;
  for (AccompaniedFragmentIterator iterator(*object); !iterator.IsDone();
       index++) {
    const auto* fragment = iterator.GetFragmentData();
    ScopedDisplayItemFragment scoped_fragment(context, index);
    Vector<PhysicalRect> rects = object->CollectOutlineRectsAndAdvance(
        OutlineType::kIncludeBlockInkOverflow, iterator);
    if (rects.size() > 1)
      use_rounded_rects = false;

    // TODO(yosin): We should remove following if-statement once we release
    // FragmentItem to renderer rounded rect even if nested inline, e.g.
    // <a>ABC<b>DEF</b>GHI</a>.
    // See gesture-tapHighlight-simple-nested.html
    if (use_rounded_rects && object->IsLayoutInline() &&
        object->IsInLayoutNGInlineFormattingContext()) {
      InlineCursor cursor;
      cursor.MoveTo(*object);
      // When |LayoutInline| has more than one children, we render square
      // rectangle as |NGPaintFragment|.
      if (cursor && cursor.CurrentItem()->DescendantsCount() > 2)
        use_rounded_rects = false;
    }

    Path new_path;
    for (auto& rect : rects) {
      gfx::RectF snapped_rect(ToPixelSnappedRect(rect));
      if (use_rounded_rects) {
        constexpr float kRadius = 3;
        new_path.AddRoundedRect(FloatRoundedRect(snapped_rect, kRadius));
      } else {
        new_path.AddRect(snapped_rect);
      }
    }

    DCHECK_LT(index, fragments_.size());
    auto& link_highlight_fragment = *fragments_[index];
    link_highlight_fragment.SetColor(color);

    auto bounding_rect = gfx::ToEnclosingRect(new_path.BoundingRect());
    new_path.Translate(-gfx::Vector2dF(bounding_rect.OffsetFromOrigin()));

    cc::PictureLayer* layer = link_highlight_fragment.Layer();
    CHECK(layer);
    CHECK_EQ(&link_highlight_fragment, layer->client());
    if (link_highlight_fragment.GetPath() != new_path) {
      link_highlight_fragment.SetPath(new_path);
      layer->SetBounds(bounding_rect.size());
      layer->SetNeedsDisplay();
    }

    DEFINE_STATIC_DISPLAY_ITEM_CLIENT(client, "LinkHighlight");
    auto property_tree_state = fragment->LocalBorderBoxProperties().Unalias();
    property_tree_state.SetEffect(Effect());
    RecordForeignLayer(context, *client,
                       DisplayItem::kForeignLayerLinkHighlight, layer,
                       bounding_rect.origin(), &property_tree_state);
  }

  DCHECK_EQ(index, fragments_.size());
}

void LinkHighlightImpl::UpdateAfterPaint(
    const PaintArtifactCompositor* paint_artifact_compositor) {
  bool should_start_animation =
      !is_animating_on_compositor_ && start_compositor_animation_;
  start_compositor_animation_ = false;
  if (!is_animating_on_compositor_ && !should_start_animation)
    return;

  bool is_composited = paint_artifact_compositor->HasComposited(element_id_);
  // If the animating node has not been composited, remove the highlight
  // animation.
  if (is_animating_on_compositor_ && !is_composited)
    StopCompositorAnimation();

  // Skip starting the link highlight animation if the target effect node has
  // not been composited.
  if (!should_start_animation || !is_composited)
    return;

  StartCompositorAnimation();
}

void LinkHighlightImpl::SetNeedsRepaintAndCompositingUpdate() {
  DCHECK(node_);
  if (auto* frame_view = node_->GetDocument().View()) {
    frame_view->SetVisualViewportOrOverlayNeedsRepaint();
    frame_view->SetPaintArtifactCompositorNeedsUpdate();
  }
}

void LinkHighlightImpl::UpdateOpacity(float opacity) {
  auto change =
      effect_->Update(EffectPaintPropertyNode::Root(),
                      LinkHighlightEffectNodeState(opacity, element_id_));
  // If there is no |node_|, |ReleaseResources| has already handled the call to
  // |SetNeedsRepaintAndCompositingUpdate|.
  if (!node_)
    return;
  if (change > PaintPropertyChangeType::kChangedOnlyCompositedValues)
    SetNeedsRepaintAndCompositingUpdate();
}

}  // namespace blink
```