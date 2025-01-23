Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Core Purpose:** The filename `compositing_reason_finder.cc` immediately suggests this code is about determining *why* an element in the browser is being composited. Compositing is a key optimization technique where parts of the webpage are rendered on the GPU.

2. **Identify Key Data Structures and Concepts:**  Scanning the includes reveals fundamental web concepts:
    * `LayoutObject`: Represents the layout of an HTML element.
    * `PaintLayer`: Represents a layer used for painting, often associated with compositing.
    * `ComputedStyle`:  The final CSS properties applied to an element after cascading and inheritance.
    * `CompositingReason`: An enum representing different reasons for compositing.
    * `Document`, `Node`, `Element`:  DOM-related structures.
    * `Frame`, `LocalFrame`, `LocalFrameView`: Structures related to browser frames (iframes).
    * `Page`: Represents the entire web page.
    * `gfx::Transform`:  Represents CSS transformations (translate, rotate, scale, etc.).
    * `UseCounter`:  For tracking usage of certain features.

3. **Analyze the Functions:**  Go through each function and understand its role:
    * `ShouldPreferCompositingForLayoutView`: Deals with specific cases for the main `LayoutView` (the root of the layout).
    * `BackfaceInvisibility3DAncestorReason`: Checks for the `backface-visibility: hidden` property on an ancestor in a 3D context.
    * `CompositingReasonsForWillChange`: Handles the `will-change` CSS property, which hints at future changes.
    * `CompositingReasonsFor3DTransform`: Identifies compositing due to 3D transformations.
    * `CompositingReasonsFor3DSceneLeaf`:  Handles a specific scenario related to 3D scenes where an element doesn't preserve 3D itself but is within a 3D context.
    * `DirectReasonsForSVGChildPaintProperties`: Specific logic for SVG elements.
    * `CompositingReasonsForViewportScrollEffect`: Deals with fixed-position elements in the main viewport.
    * `CompositingReasonsForScrollDependentPosition`:  Handles `fixed` and `sticky` positioning.
    * `ObjectTypeSupportsCompositedTransformAnimation`: Checks if an element type can have composited transform animations.
    * `IsEligibleForElementCapture`: Related to a newer feature about capturing specific elements (not directly related to basic HTML/CSS/JS).
    * `DirectReasonsForPaintProperties`: The main function that aggregates direct reasons for compositing.
    * `ShouldForcePreferCompositingToLCDText`:  A secondary check, possibly for performance or visual quality related to text rendering.
    * `PotentialCompositingReasonsFor3DTransform`: Extracts potential 3D transform reasons from styles.
    * `CompositingReasonsForAnimation`: Handles compositing due to active CSS animations.
    * `RequiresCompositingForRootScroller`: Ensures the root scroll container is composited.

4. **Relate to HTML, CSS, and JavaScript:** For each function, think about how it connects to web technologies:
    * **CSS Properties:**  Directly link functions to CSS properties like `transform`, `opacity`, `filter`, `backface-visibility`, `will-change`, `position: fixed`, `position: sticky`, etc.
    * **HTML Structure:**  Consider how the DOM tree and parent-child relationships affect compositing (e.g., 3D contexts).
    * **JavaScript Interaction:** While this code isn't directly *executed* by JavaScript, JavaScript often *triggers* changes that lead to compositing. Think about animations controlled by JavaScript, dynamic style changes, and scrolling behavior.

5. **Logical Reasoning and Examples:**  For each compositing reason:
    * **Hypothesize an Input (HTML/CSS):**  Create a simple example demonstrating the CSS property or situation.
    * **Predict the Output (CompositingReason):** Determine which `CompositingReason` enum value would be set.

6. **User/Programming Errors:** Consider common mistakes developers might make:
    * **Overusing `will-change`:**  Explain why it's not a magic performance bullet.
    * **Forgetting browser compatibility:**  Mention vendor prefixes or newer properties.
    * **Misunderstanding 3D contexts:**  Explain the implications of `transform-style: preserve-3d`.

7. **Debugging and User Actions:**  Think about how a user interacts with a webpage and how that leads to this code being involved:
    * **Initial Page Load:** The browser needs to determine which elements to composite initially.
    * **Scrolling:**  Fixed and sticky elements require compositing during scroll.
    * **CSS Animations/Transitions:** Trigger compositing.
    * **JavaScript-Driven Changes:**  Modifying styles, adding/removing elements.
    * **Developer Tools:** Explain how the "Layers" panel can reveal compositing information.

8. **Structure the Answer:** Organize the information logically:
    * **Overview of Functionality:** Start with a high-level summary.
    * **Detailed Function Breakdown:**  Explain each function's purpose.
    * **Relationship to Web Technologies:**  Provide clear examples linking to HTML, CSS, and JavaScript.
    * **Logical Reasoning Examples:** Use the hypothesized input/output.
    * **Common Errors:** Highlight potential pitfalls.
    * **Debugging:** Explain how a user might trigger this code path.

9. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation.

**Self-Correction Example During the Process:**

Initially, I might just list the functions and their names. Then, I'd realize that's not enough. The prompt asks for *functionality*. So, I'd go back and add a concise description of *what each function does*. Then, I'd think, "How does this relate to the user?" and add the debugging section and user action examples. I might also initially miss some of the more subtle compositing reasons (like the 3D scene leaf) and have to revisit the code to understand those nuances better.
这个C++源代码文件 `compositing_reason_finder.cc` 位于 Chromium Blink 引擎中，其核心功能是**确定一个 HTML 元素为什么会被提升为自己的合成层（composited layer）**。换句话说，它负责找出导致浏览器将某个元素绘制到一个独立的 GPU 图层上的原因。

**主要功能列举:**

1. **检查并记录导致元素合成的各种原因:** 该文件定义了一系列函数，用于检查一个元素的各种属性和状态，以判断是否需要将其放置在独立的合成层上。这些原因涵盖了 CSS 属性、动画、变换、滚动行为等。

2. **提供 `DirectReasonsForPaintProperties` 函数:** 这是该文件的核心函数，它接收一个 `LayoutObject` (代表一个渲染对象) 作为输入，并返回一个 `CompositingReasons` 枚举值，其中包含了导致该对象直接合成的所有原因。

3. **处理各种 CSS 属性引起的合成:** 文件中包含了针对不同 CSS 属性的检查逻辑，例如：
    * `transform` (2D 和 3D 变换)
    * `opacity`
    * `filter`
    * `backdrop-filter`
    * `will-change`
    * `backface-visibility`
    * `position: fixed` 和 `position: sticky`
    * `-webkit-overflow-scrolling: touch` (通过 `RequiresCompositingForRootScroller`间接处理)

4. **处理动画和过渡引起的合成:**  检查元素上是否有正在进行的变换、缩放、旋转、平移、透明度、滤镜或背景滤镜动画。

5. **处理 3D 场景相关的合成:**  识别元素是否处于 3D 变换上下文中，并根据是否需要进行 3D 扁平化（flattening）来决定是否合成。

6. **处理滚动相关的合成:** 确定元素是否是根滚动器（root scroller），或者是否具有固定定位或粘性定位，这些都可能触发合成。

7. **处理 SVG 元素特有的合成原因:**  SVG 元素在某些情况下也会被合成。

8. **处理 View Transitions API 相关的合成:**  当使用 View Transitions API 时，相关的伪元素和参与元素会被合成。

9. **提供辅助函数:**  例如 `ShouldPreferCompositingForLayoutView` 用于判断根布局视图是否应该被合成，以及 `ShouldForcePreferCompositingToLCDText` 用于在某些情况下强制合成以优化 LCD 文本渲染。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

这个文件是 Blink 渲染引擎的一部分，它直接响应 HTML 结构和 CSS 样式，并可能受到 JavaScript 的动态修改影响。

* **HTML:**  HTML 结构决定了元素的父子关系和渲染树的构建，这会影响到 3D 变换上下文的判断。例如，一个设置了 `transform-style: preserve-3d` 的父元素会影响其子元素的合成。

   ```html
   <!-- HTML 结构 -->
   <div style="transform-style: preserve-3d;">
     <div style="transform: rotateY(45deg);">子元素</div>
   </div>
   ```
   在这种情况下，`compositing_reason_finder.cc` 会识别出父元素创建了一个 3D 上下文，并可能因此将子元素合成。

* **CSS:**  CSS 属性是触发合成的最主要因素。

   * **`transform`:**  任何非 `none` 的 `transform` 值都可能导致合成。
     ```css
     .element {
       transform: translateZ(10px); /* 3D 变换 */
     }
     ```
     `CompositingReasonsFor3DTransform` 函数会识别出这个属性并返回 `CompositingReason::k3DTransform`。

   * **`opacity`:**  小于 1 的 `opacity` 值通常会触发合成。
     ```css
     .element {
       opacity: 0.8;
     }
     ```
     虽然代码中没有直接列出 `opacity` 的判断，但它通常通过其他机制（例如，需要应用效果）触发合成。`CompositingReasonsForWillChange` 会检查 `will-change: opacity`。

   * **`filter`:**  应用任何滤镜效果都会导致合成。
     ```css
     .element {
       filter: blur(5px);
     }
     ```
     `DirectReasonsForPaintProperties` 函数会检查 `style.HasBackdropFilter()` 和 `CompositingReasonsForWillChange` 中与 filter 相关的属性。

   * **`will-change`:**  声明了 `will-change` 属性暗示了元素未来可能发生变化，浏览器可能会提前将其合成。
     ```css
     .element {
       will-change: transform, opacity;
     }
     ```
     `CompositingReasonsForWillChange` 函数会根据 `will-change` 的值设置相应的 `CompositingReason`。

   * **`position: fixed`:**  固定定位的元素通常会被合成，以便在滚动时保持在屏幕上的位置。
     ```css
     .element {
       position: fixed;
       top: 0;
     }
     ```
     `CompositingReasonsForScrollDependentPosition` 和 `CompositingReasonsForViewportScrollEffect` 会处理这种情况。

   * **`position: sticky`:**  粘性定位的元素在滚动到特定位置时会固定，这也可能触发合成。
     ```css
     .element {
       position: sticky;
       top: 10px;
     }
     ```
     `CompositingReasonsForScrollDependentPosition` 会处理粘性定位的情况。

* **JavaScript:** JavaScript 可以动态地修改元素的样式，从而间接地触发合成。例如，通过 JavaScript 改变元素的 `transform` 属性，会导致 `compositing_reason_finder.cc` 在后续的渲染过程中判断该元素需要合成。

   ```javascript
   // JavaScript 修改样式
   const element = document.querySelector('.element');
   element.style.transform = 'rotate(90deg)';
   ```
   当这段 JavaScript 代码执行后，浏览器的渲染引擎会重新计算样式和布局，`compositing_reason_finder.cc` 会检查更新后的样式，发现 `transform` 属性已改变，从而可能将该元素标记为需要合成。

**逻辑推理的假设输入与输出:**

假设输入一个 `LayoutObject`，该对象对应于以下 HTML 和 CSS：

```html
<div id="target" style="transform: translateZ(50px); will-change: opacity;">内容</div>
```

**假设输入:**  一个指向 `#target` 元素的 `LayoutObject` 实例。

**逻辑推理过程:**

1. `DirectReasonsForPaintProperties` 函数被调用。
2. `CompositingReasonsFor3DSceneLeaf` 检查 3D 场景叶子节点，假设父元素没有 `preserve-3d`，则返回 `kNone`。
3. `CompositingReasonsForWillChange` 检查 `will-change: opacity;`，返回 `CompositingReason::kWillChangeOpacity`。
4. `CompositingReasonsFor3DTransform` 检查 `transform: translateZ(50px);`，返回 `CompositingReason::k3DTranslate`。
5. 其他检查，如滚动相关的、背景滤镜等，假设都不满足，返回 `kNone`。
6. `DirectReasonsForPaintProperties` 将所有非 `kNone` 的原因合并。

**假设输出:** `CompositingReason::kWillChangeOpacity | CompositingReason::k3DTranslate`

**用户或编程常见的使用错误举例:**

1. **过度使用 `will-change`:**  开发者可能会为了“优化”性能而对很多元素都设置 `will-change`，但这可能会导致浏览器提前分配过多的内存和 GPU 资源，反而降低性能。只有在确定元素即将发生变化时才应该使用 `will-change`。

   ```css
   /* 错误用法 */
   .all-elements {
     will-change: transform, opacity, scroll-position;
   }
   ```
   `compositing_reason_finder.cc` 会忠实地记录因为 `will-change` 导致的合成原因，但开发者需要理解其背后的性能含义。

2. **不理解 3D 上下文的影响:**  开发者可能在一个父元素上意外地设置了 `transform-style: preserve-3d`，导致其所有子元素都进入了 3D 合成上下文，即使子元素本身并没有 3D 变换，也可能因为需要参与 3D 排序而被合成。

   ```css
   /* 可能导致意外合成 */
   .parent {
     transform-style: preserve-3d;
   }

   .child {
     /* 没有 3D 变换，但可能因为父元素而被合成 */
   }
   ```
   调试时，开发者可能会惊讶地发现 `.child` 元素被合成了，需要检查其祖先元素的样式。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问网页:** 当用户在浏览器中打开一个网页时，Blink 渲染引擎开始解析 HTML、CSS 并构建 DOM 树和渲染树。

2. **样式计算和布局:** 浏览器计算每个元素的最终样式，并进行布局计算，确定元素在页面上的位置和大小。

3. **构建 Paint Tree 和 Layer Tree:** 基于布局结果，渲染引擎会构建 Paint Tree (绘制树) 和 Layer Tree (图层树)。Layer Tree 的构建过程中，`compositing_reason_finder.cc` 就发挥了关键作用。

4. **遍历渲染对象并检查合成原因:**  对于渲染树中的每个 `LayoutObject`，渲染引擎会调用 `CompositingReasonFinder::DirectReasonsForPaintProperties` 函数。

5. **检查 CSS 属性、动画状态等:**  在 `DirectReasonsForPaintProperties` 内部，会调用各种辅助函数，例如 `CompositingReasonsForWillChange`、`CompositingReasonsFor3DTransform` 等，来检查该元素是否满足任何合成条件。

6. **记录合成原因:** 如果找到任何导致合成的原因，对应的 `CompositingReason` 枚举值会被记录下来。

7. **创建合成层:**  对于被标记为需要合成的元素，浏览器会为其创建一个独立的合成层，以便在 GPU 上进行绘制。

8. **用户交互触发重新渲染:**  当用户进行操作，例如滚动页面、鼠标悬停、点击元素（可能触发 JavaScript 动画或样式更改）时，渲染引擎可能会重新执行上述步骤，`compositing_reason_finder.cc` 也会被再次调用，以确定哪些元素需要重新合成或取消合成。

**作为调试线索:**

* **使用开发者工具的 "Layers" 面板:** Chrome 开发者工具的 "Layers" 面板可以可视化页面的合成层结构。当你发现某个元素意外地被合成了，或者本应该合成的元素没有被合成时，可以查看该面板。

* **查看 "Compositing Reasons":** 在 "Layers" 面板中，选中一个合成层后，通常会显示该层被合成的原因。这些原因正是由 `compositing_reason_finder.cc` 中的逻辑确定的。

* **检查元素的 CSS 属性:**  根据 `compositing_reason_finder.cc` 的功能，重点检查元素的 `transform`、`opacity`、`filter`、`will-change`、`position` 等与合成相关的 CSS 属性。

* **检查祖先元素的样式:**  特别是当涉及到 3D 上下文时，需要检查父元素及其祖先元素的 `transform-style` 和 `perspective` 属性。

* **分析 JavaScript 代码:**  查看是否有 JavaScript 代码动态修改了元素的样式，导致了合成状态的变化。

* **性能分析工具:**  使用 Chrome 的 Performance 面板可以分析渲染性能，合成层的创建和管理对性能有重要影响。

总而言之，`compositing_reason_finder.cc` 是 Blink 渲染引擎中一个关键的组件，它负责识别触发元素合成的各种因素，理解其工作原理对于优化网页性能和调试渲染问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/paint/compositing/compositing_reason_finder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/compositing/compositing_reason_finder.h"

#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_transformable_container.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/sticky_position_scrolling_constraints.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/transform_utils.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"

namespace blink {

namespace {

bool ShouldPreferCompositingForLayoutView(const LayoutView& layout_view) {
  if (layout_view.GetFrame()->IsLocalRoot()) {
    return true;
  }

  auto has_direct_compositing_reasons = [](const LayoutObject* object) -> bool {
    return object && CompositingReasonFinder::DirectReasonsForPaintProperties(
                         *object) != CompositingReason::kNone;
  };
  if (has_direct_compositing_reasons(
          layout_view.GetFrame()->OwnerLayoutObject()))
    return true;
  if (auto* document_element = layout_view.GetDocument().documentElement()) {
    if (has_direct_compositing_reasons(document_element->GetLayoutObject()))
      return true;
  }
  if (auto* body = layout_view.GetDocument().FirstBodyElement()) {
    if (has_direct_compositing_reasons(body->GetLayoutObject()))
      return true;
  }
  return false;
}

CompositingReasons BackfaceInvisibility3DAncestorReason(
    const PaintLayer& layer) {
  if (RuntimeEnabledFeatures::BackfaceVisibilityInteropEnabled()) {
    if (auto* compositing_container = layer.CompositingContainer()) {
      if (compositing_container->GetLayoutObject()
              .StyleRef()
              .BackfaceVisibility() == EBackfaceVisibility::kHidden)
        return CompositingReason::kBackfaceInvisibility3DAncestor;
    }
  }
  return CompositingReason::kNone;
}

CompositingReasons CompositingReasonsForWillChange(const ComputedStyle& style) {
  CompositingReasons reasons = CompositingReason::kNone;
  if (style.SubtreeWillChangeContents())
    return reasons;

  if (style.HasWillChangeTransformHint())
    reasons |= CompositingReason::kWillChangeTransform;
  if (style.HasWillChangeScaleHint())
    reasons |= CompositingReason::kWillChangeScale;
  if (style.HasWillChangeRotateHint())
    reasons |= CompositingReason::kWillChangeRotate;
  if (style.HasWillChangeTranslateHint())
    reasons |= CompositingReason::kWillChangeTranslate;
  if (style.HasWillChangeOpacityHint())
    reasons |= CompositingReason::kWillChangeOpacity;
  if (style.HasWillChangeFilterHint())
    reasons |= CompositingReason::kWillChangeFilter;
  if (style.HasWillChangeBackdropFilterHint())
    reasons |= CompositingReason::kWillChangeBackdropFilter;

  // kWillChangeOther is needed only when none of the explicit kWillChange*
  // reasons are set.
  if (reasons == CompositingReason::kNone &&
      style.HasWillChangeCompositingHint())
    reasons |= CompositingReason::kWillChangeOther;

  return reasons;
}

CompositingReasons CompositingReasonsFor3DTransform(
    const LayoutObject& layout_object) {
  // Note that we ask the layoutObject if it has a transform, because the style
  // may have transforms, but the layoutObject may be an inline that doesn't
  // support them.
  if (!layout_object.HasTransformRelatedProperty())
    return CompositingReason::kNone;

  const ComputedStyle& style = layout_object.StyleRef();
  CompositingReasons reasons =
      CompositingReasonFinder::PotentialCompositingReasonsFor3DTransform(style);
  if (reasons != CompositingReason::kNone && layout_object.IsBox()) {
    // In theory this should operate on fragment sizes, but using the box size
    // is probably good enough for a use counter.
    auto& box = To<LayoutBox>(layout_object);
    const PhysicalRect reference_box = ComputeReferenceBox(box);
    gfx::Transform matrix;
    style.ApplyTransform(matrix, &box, reference_box,
                         ComputedStyle::kIncludeTransformOperations,
                         ComputedStyle::kExcludeTransformOrigin,
                         ComputedStyle::kExcludeMotionPath,
                         ComputedStyle::kIncludeIndependentTransformProperties);

    // We want to track whether (a) this element is in a preserve-3d scene and
    // (b) has a matrix that puts it into the third dimension in some way.
    if (matrix.Creates3d()) {
      LayoutObject* parent_for_element =
          layout_object.NearestAncestorForElement();
      if (parent_for_element && parent_for_element->Preserves3D()) {
        UseCounter::Count(layout_object.GetDocument(),
                          WebFeature::kTransform3dScene);
      }
    }
  }
  return reasons;
}

CompositingReasons CompositingReasonsFor3DSceneLeaf(
    const LayoutObject& layout_object) {
  // An effect node (and, eventually, a render pass created due to
  // cc::RenderSurfaceReason::k3dTransformFlattening) is required for an
  // element that doesn't preserve 3D but is treated as a 3D object by its
  // parent.  See
  // https://bugs.chromium.org/p/chromium/issues/detail?id=1256990#c2 for some
  // notes on why this is needed.  Briefly, we need to ensure that we don't
  // output quads with a 3d sorting_context of 0 in the middle of the quads
  // that need to be 3D sorted; this is needed to contain any such quads in a
  // separate render pass.
  //
  // Note that this is done even on elements that don't create a stacking
  // context, and this appears to work.
  //
  // This could be improved by skipping this if we know that the descendants
  // won't produce any quads in the render pass's quad list.
  if (layout_object.IsText()) {
    // A LayoutBR is both IsText() and IsForElement(), but we shouldn't
    // produce compositing reasons if IsText() is true.  Since we only need
    // this for objects that have interesting descendants, we can just return.
    return CompositingReason::kNone;
  }

  if (!layout_object.IsAnonymous() && !layout_object.StyleRef().Preserves3D()) {
    const LayoutObject* parent_object =
        layout_object.NearestAncestorForElement();
    if (parent_object && parent_object->StyleRef().Preserves3D()) {
      return CompositingReason::kTransform3DSceneLeaf;
    }
  }

  return CompositingReason::kNone;
}

CompositingReasons DirectReasonsForSVGChildPaintProperties(
    const LayoutObject& object) {
  DCHECK(object.IsSVGChild());
  if (object.IsText())
    return CompositingReason::kNone;

  // Even though SVG doesn't support 3D transforms, it might be the leaf of a 3D
  // scene that contains it.
  auto reasons = CompositingReasonsFor3DSceneLeaf(object);

  const ComputedStyle& style = object.StyleRef();
  reasons |= CompositingReasonFinder::CompositingReasonsForAnimation(object);
  reasons |= CompositingReasonsForWillChange(style);
  // Exclude will-change for other properties some of which don't apply to SVG
  // children, e.g. 'top'.
  reasons &= ~CompositingReason::kWillChangeOther;
  if (style.HasBackdropFilter())
    reasons |= CompositingReason::kBackdropFilter;
  // Though SVG doesn't support 3D transforms, they are frequently used as a
  // compositing trigger for historical reasons.
  reasons |= CompositingReasonsFor3DTransform(object);
  return reasons;
}

CompositingReasons CompositingReasonsForViewportScrollEffect(
    const LayoutObject& layout_object,
    const LayoutObject* container_for_fixed_position) {
  if (!layout_object.IsBox())
    return CompositingReason::kNone;

  // The viewport scroll effect should never apply to objects inside an
  // embedded frame tree.
  const LocalFrame* frame = layout_object.GetFrame();
  if (!frame->Tree().Top().IsOutermostMainFrame())
    return CompositingReason::kNone;

  DCHECK_EQ(frame->IsMainFrame(), frame->IsOutermostMainFrame());

  // Objects inside an iframe that's the root scroller should get the same
  // "pushed by top controls" behavior as for the main frame.
  auto& controller = frame->GetPage()->GlobalRootScrollerController();
  if (!frame->IsMainFrame() &&
      frame->GetDocument() != controller.GlobalRootScroller()) {
    return CompositingReason::kNone;
  }

  if (!To<LayoutBox>(layout_object).IsFixedToView(container_for_fixed_position))
    return CompositingReason::kNone;

  CompositingReasons reasons = CompositingReason::kNone;
  // This ensures that the scroll_translation_for_fixed will be initialized in
  // FragmentPaintPropertyTreeBuilder::UpdatePaintOffsetTranslation which in
  // turn ensures that a TransformNode is created (for fixed elements) in cc.
  if (frame->GetPage()->GetVisualViewport().GetOverscrollType() ==
      OverscrollType::kTransform) {
    reasons |= CompositingReason::kFixedPosition;
    if (!To<LayoutBox>(layout_object)
             .AnchorPositionScrollAdjustmentAfectedByViewportScrolling()) {
      reasons |= CompositingReason::kUndoOverscroll;
    }
  }

  if (layout_object.StyleRef().IsFixedToBottom()) {
    reasons |= CompositingReason::kFixedPosition |
               CompositingReason::kAffectedByOuterViewportBoundsDelta;
  }

  return reasons;
}

CompositingReasons CompositingReasonsForScrollDependentPosition(
    const PaintLayer& layer,
    const LayoutObject* container_for_fixed_position) {
  CompositingReasons reasons = CompositingReason::kNone;
  // Don't promote fixed position elements that are descendants of a non-view
  // container, e.g. transformed elements.  They will stay fixed wrt the
  // container rather than the enclosing frame.
  if (const auto* box = layer.GetLayoutBox()) {
    if (box->IsFixedToView(container_for_fixed_position)) {
      // We check for |HasOverflow| instead of |ScrollsOverflow| to ensure fixed
      // position elements are composited under overflow: hidden, which can
      // still have smooth scroll animations.
      LocalFrameView* frame_view = layer.GetLayoutObject().GetFrameView();
      if (frame_view->LayoutViewport()->HasOverflow())
        reasons |= CompositingReason::kFixedPosition;
    }

    if (box->NeedsAnchorPositionScrollAdjustment()) {
      reasons |= CompositingReason::kAnchorPosition;
    }
  }

  // Don't promote sticky position elements that cannot move with scrolls.
  // We check for |HasOverflow| instead of |ScrollsOverflow| to ensure sticky
  // position elements are composited under overflow: hidden, which can still
  // have smooth scroll animations.
  if (const auto* constraints = layer.GetLayoutObject().StickyConstraints()) {
    if (!constraints->is_fixed_to_view &&
        constraints->containing_scroll_container_layer->GetScrollableArea()
            ->HasOverflow())
      reasons |= CompositingReason::kStickyPosition;
  }

  return reasons;
}

bool ObjectTypeSupportsCompositedTransformAnimation(
    const LayoutObject& object) {
  if (object.IsSVGChild()) {
    // Transforms are not supported on hidden containers, inlines, text, or
    // filter primitives.
    return !object.IsSVGHiddenContainer() && !object.IsLayoutInline() &&
           !object.IsText() && !object.IsSVGFilterPrimitive();
  }
  // Transforms don't apply on non-replaced inline elements.
  return object.IsBox();
}

// Defined by the Element Capture specification:
// https://screen-share.github.io/element-capture/#elements-eligible-for-restriction
bool IsEligibleForElementCapture(const LayoutObject& object) {
  // The element forms a stacking context.
  if (!object.IsStackingContext()) {
    return false;
  }

  // The element is flattened in 3D.
  if (!object.CreatesGroup()) {
    return false;
  }

  // The element forms a backdrop root.
  // See ViewTransitionUtils::IsViewTransitionParticipant and
  // NeedsEffectIgnoringClipPath for how View Transitions meets this
  // requirement.
  // TODO(https://issuetracker.google.com/291602746): handle backdrop root case.

  // The element has exactly one box fragment.
  if (object.IsBox() && To<LayoutBox>(object).PhysicalFragmentCount() > 1) {
    return false;
  }

  // Meets all of the conditions for element capture.
  return true;
}

}  // anonymous namespace

CompositingReasons CompositingReasonFinder::DirectReasonsForPaintProperties(
    const LayoutObject& object,
    const LayoutObject* container_for_fixed_position) {
  if (object.GetDocument().Printing())
    return CompositingReason::kNone;

  auto reasons = CompositingReasonsFor3DSceneLeaf(object);

  if (object.CanHaveAdditionalCompositingReasons())
    reasons |= object.AdditionalCompositingReasons();

  if (!object.HasLayer()) {
    if (object.IsSVGChild())
      reasons |= DirectReasonsForSVGChildPaintProperties(object);
    return reasons;
  }

  const ComputedStyle& style = object.StyleRef();
  reasons |= CompositingReasonsForAnimation(object) |
             CompositingReasonsForWillChange(style);

  reasons |= CompositingReasonsFor3DTransform(object);

  auto* layer = To<LayoutBoxModelObject>(object).Layer();
  if (layer->Has3DTransformedDescendant()) {
    // Perspective (specified either by perspective or transform properties)
    // with 3d descendants need a render surface for flattening purposes.
    if (style.HasPerspective() || style.Transform().HasPerspective())
      reasons |= CompositingReason::kPerspectiveWith3DDescendants;
    if (style.Preserves3D())
      reasons |= CompositingReason::kPreserve3DWith3DDescendants;
  }

  if (RequiresCompositingForRootScroller(object)) {
    reasons |= CompositingReason::kRootScroller;
  }

  reasons |= CompositingReasonsForScrollDependentPosition(
      *layer, container_for_fixed_position);

  reasons |= CompositingReasonsForViewportScrollEffect(
      object, container_for_fixed_position);

  if (style.HasBackdropFilter())
    reasons |= CompositingReason::kBackdropFilter;

  reasons |= BackfaceInvisibility3DAncestorReason(*layer);

  switch (style.StyleType()) {
    case kPseudoIdViewTransition:
    case kPseudoIdViewTransitionGroup:
    case kPseudoIdViewTransitionImagePair:
    case kPseudoIdViewTransitionNew:
    case kPseudoIdViewTransitionOld:
      reasons |= CompositingReason::kViewTransitionPseudoElement;
      break;
    default:
      break;
  }

  if (auto* transition =
          ViewTransitionUtils::GetTransition(object.GetDocument())) {
    // Note that `NeedsViewTransitionEffectNode` returns true for values that
    // are in the non-transition-pseudo tree DOM. That is, things like layout
    // view or the view transition elements that we are transitioning.
    if (transition->NeedsViewTransitionEffectNode(object)) {
      reasons |= CompositingReason::kViewTransitionElement;
    }
  }

  auto* element = DynamicTo<Element>(object.GetNode());
  if (element && element->GetRestrictionTargetId()) {
    const bool is_eligible = IsEligibleForElementCapture(object);
    element->SetIsEligibleForElementCapture(is_eligible);
    if (is_eligible) {
      reasons |= CompositingReason::kElementCapture;
    }
  }

  return reasons;
}

bool CompositingReasonFinder::ShouldForcePreferCompositingToLCDText(
    const LayoutObject& object,
    CompositingReasons reasons) {
  DCHECK_EQ(reasons, DirectReasonsForPaintProperties(object));
  if (reasons != CompositingReason::kNone) {
    return true;
  }

  if (object.StyleRef().WillChangeScrollPosition())
    return true;

  // Though we don't treat hidden backface as a direct compositing reason, it's
  // very likely that the object will be composited, and it also indicates
  // preference of compositing, so we prefer composited scrolling here.
  if (object.StyleRef().BackfaceVisibility() == EBackfaceVisibility::kHidden)
    return true;

  if (auto* layout_view = DynamicTo<LayoutView>(object))
    return ShouldPreferCompositingForLayoutView(*layout_view);

  return false;
}

CompositingReasons
CompositingReasonFinder::PotentialCompositingReasonsFor3DTransform(
    const ComputedStyle& style) {
  CompositingReasons reasons = CompositingReason::kNone;

  if (style.Transform().HasNonPerspective3DOperation()) {
    if (style.Transform().HasNonTrivial3DComponent()) {
      reasons |= CompositingReason::k3DTransform;
    } else {
      // This reason is not used in TransformPaintPropertyNode for low-end
      // devices. See PaintPropertyTreeBuilder.
      reasons |= CompositingReason::kTrivial3DTransform;
    }
  }

  if (style.Translate() && style.Translate()->Z() != 0)
    reasons |= CompositingReason::k3DTranslate;

  if (style.Rotate() &&
      (style.Rotate()->X() != 0 || style.Rotate()->Y() != 0)) {
    reasons |= CompositingReason::k3DRotate;
  }

  if (style.Scale() && style.Scale()->Z() != 1)
    reasons |= CompositingReason::k3DScale;

  return reasons;
}

CompositingReasons CompositingReasonFinder::CompositingReasonsForAnimation(
    const LayoutObject& object) {
  CompositingReasons reasons = CompositingReason::kNone;
  const auto& style = object.StyleRef();
  if (style.SubtreeWillChangeContents())
    return reasons;

  if (style.HasCurrentTransformAnimation() &&
      ObjectTypeSupportsCompositedTransformAnimation(object))
    reasons |= CompositingReason::kActiveTransformAnimation;
  if (style.HasCurrentScaleAnimation() &&
      ObjectTypeSupportsCompositedTransformAnimation(object))
    reasons |= CompositingReason::kActiveScaleAnimation;
  if (style.HasCurrentRotateAnimation() &&
      ObjectTypeSupportsCompositedTransformAnimation(object))
    reasons |= CompositingReason::kActiveRotateAnimation;
  if (style.HasCurrentTranslateAnimation() &&
      ObjectTypeSupportsCompositedTransformAnimation(object))
    reasons |= CompositingReason::kActiveTranslateAnimation;
  if (style.HasCurrentOpacityAnimation())
    reasons |= CompositingReason::kActiveOpacityAnimation;
  if (style.HasCurrentFilterAnimation())
    reasons |= CompositingReason::kActiveFilterAnimation;
  if (style.HasCurrentBackdropFilterAnimation())
    reasons |= CompositingReason::kActiveBackdropFilterAnimation;
  return reasons;
}

bool CompositingReasonFinder::RequiresCompositingForRootScroller(
    const LayoutObject& object) {
  // The root scroller needs composited scrolling layers even if it doesn't
  // actually have scrolling since CC has these assumptions baked in for the
  // viewport. Because this is only needed for CC, we can skip it if
  // compositing is not enabled.
  if (!object.GetFrame()->GetSettings()->GetAcceleratedCompositingEnabled()) {
    return false;
  }

  return object.IsGlobalRootScroller();
}

}  // namespace blink
```