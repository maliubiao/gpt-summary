Response:
My thought process for analyzing the provided C++ code snippet goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the `out_of_flow_layout_part.cc` file within the Chromium Blink rendering engine. They've specifically asked for its purpose, connections to web technologies (HTML, CSS, JavaScript), logical inferences with input/output examples, common usage errors, and a general summary of this first part of the file.

2. **Initial Scan for Keywords and Concepts:** I quickly scan the included headers and the namespace. Keywords like `out_of_flow`, `layout`, `absolute`, `fixed`, `position`, `fragmentation`, `grid`, `anchor`, `containing block`, and `style` immediately jump out. These suggest the file is heavily involved in the layout of elements that don't follow the normal document flow (like absolutely or fixed positioned elements).

3. **Identify Core Responsibilities:** Based on the initial scan, I deduce the core responsibilities likely involve:
    * **Handling Out-of-Flow Elements:** This is the most obvious one. The file name itself confirms this.
    * **Determining Containing Blocks:**  Out-of-flow elements are positioned relative to a containing block. The numerous mentions of "containing block" reinforce this.
    * **Calculating Positions and Sizes:**  The code likely calculates the final position and size of these elements based on CSS properties like `top`, `left`, `right`, `bottom`, `width`, and `height`.
    * **Handling Fragmentation:** The inclusion of `fragmentation` suggests the file deals with how out-of-flow elements are handled when the layout is broken into fragments (e.g., for printing or multi-column layouts).
    * **Anchor Positioning:** The presence of `anchor` related classes indicates support for the CSS anchor positioning specification.
    * **Position Visibility:**  This is a feature tied to anchor positioning, allowing control over the visibility of elements based on their anchor's visibility.
    * **`position-try-fallbacks`:**  This is a newer CSS feature, and its inclusion indicates the file handles the logic for trying different positioning strategies.

4. **Examine Key Classes and Functions:** I start looking at the defined classes and functions, even in this first part.
    * `OutOfFlowLayoutPart`: This is the main class. Its constructor and `Run()` method are crucial entry points.
    * `OOFCandidateStyleIterator`: This class seems related to handling the `position-try-fallbacks` logic.
    * `GetPositionAnchorElement`, `GetPositionAnchorObject`, `GetAnchorOffset`: These functions clearly deal with anchor positioning.
    * `UpdatePositionVisibilityAfterLayout`: This function is responsible for the `position-visibility` feature.
    * `InitialContainingBlockFixedSize`:  This seems to handle the size of the initial containing block for fixed-position elements.
    * `HandleFragmentation`, `PropagateOOFsFromPageAreas`: These functions deal with layout in fragmented contexts.
    * `GetContainingBlockInfo`: A central function for determining the containing block for out-of-flow elements.

5. **Infer Relationships to Web Technologies:**
    * **CSS:** The file directly manipulates CSS properties (`top`, `left`, `position`, `anchor-position`, `position-try-fallbacks`, `position-visibility`, grid layout properties).
    * **HTML:** The code interacts with the DOM (`Element`, `Node`) to get styling information and determine relationships between elements.
    * **JavaScript:** While this specific file is C++, the layout it performs is triggered by browser rendering processes initiated by parsing HTML, CSS, and JavaScript. Changes made by JavaScript that affect styling or DOM structure will lead to this code being executed.

6. **Consider Logical Inferences and Examples:** I think about specific scenarios and try to infer how the code would behave. For example:
    * **Input:** An absolutely positioned `div` with `top: 10px; left: 20px;` inside a relatively positioned container.
    * **Output:** The `OutOfFlowLayoutPart` would calculate the final position of the `div` relative to the edges of the relatively positioned container.
    * **Input:** A fixed positioned element.
    * **Output:** The `OutOfFlowLayoutPart` would calculate its position relative to the viewport.
    * **Input:** An element using CSS anchor positioning.
    * **Output:** The code would find the anchor element, calculate the offset based on the anchor's position, and position the element accordingly.

7. **Identify Potential Usage Errors:**  I think about common mistakes developers make when working with out-of-flow elements:
    * Forgetting to set a containing block for absolutely positioned elements, causing them to be positioned relative to the initial containing block (viewport).
    * Incorrectly calculating offsets when using fixed positioning, potentially leading to elements being placed outside the viewport.
    * Misunderstanding how anchor positioning works, especially with fallback mechanisms.

8. **Synthesize a Summary:** Finally, I combine all the information gathered into a concise summary of the file's purpose. I focus on the core responsibilities and the overarching goal of managing the layout of out-of-flow elements.

9. **Structure the Response:** I organize the information into the categories requested by the user: functionality, relationship to web technologies, logical inferences, common usage errors, and a summary. This makes the answer clear and easy to understand.

By following this process of breaking down the code, identifying key concepts, and inferring functionality, I can effectively analyze and explain the purpose of even complex source code files like this one. The iterative process of scanning, identifying, and then diving deeper into specific parts is key.
这是 `blink/renderer/core/layout/out_of_flow_layout_part.cc` 文件的第一部分，其主要功能是处理**脱离正常文档流（out-of-flow）**元素的布局。这些元素通常是使用 CSS 的 `position: absolute` 或 `position: fixed` 属性进行定位的。

**功能归纳：**

1. **管理 Out-of-Flow 元素的布局过程：**  这个文件包含了处理绝对定位和固定定位元素布局的核心逻辑。它负责计算这些元素在页面上的最终位置和尺寸。

2. **处理包含块（Containing Block）：**  Out-of-flow 元素的定位依赖于其包含块。这个文件中的代码负责确定和处理不同类型的包含块，包括初始包含块、最近的定位祖先等。

3. **处理 CSS Anchor Positioning (锚点定位)：** 文件中包含了与 CSS 锚点定位相关的逻辑，这是一种允许元素相对于另一个元素（锚点）进行定位的新特性。

4. **处理 `position-try-fallbacks`：**  这个文件支持 CSS 的 `position-try-fallbacks` 属性，该属性允许定义多个定位尝试方案，浏览器会尝试不同的方案直到找到合适的。

5. **处理布局碎片（Fragmentation）：**  该文件还涉及到在布局被分割成碎片（例如，打印或多列布局）时如何处理 out-of-flow 元素。

6. **处理 `position-visibility`：**  支持 CSS 的 `position-visibility` 属性，该属性可以根据元素相对于其锚点是否可见来控制元素的可见性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS：** 这是该文件最直接相关的部分。
    * **`position: absolute; top: 10px; left: 20px;`**:  这段 CSS 代码声明了一个绝对定位的元素。`OutOfFlowLayoutPart` 的代码会解析这些属性，并计算出元素相对于其包含块左上角偏移 10px 和 20px 的位置。
    * **`position: fixed; bottom: 0; right: 0;`**:  这段 CSS 代码声明了一个固定定位的元素。`OutOfFlowLayoutPart` 会将其定位到视口的右下角。
    * **`position-anchor: --my-anchor; anchor-name: --my-target; top: anchor(--my-target top);`**:  这段 CSS 代码使用了锚点定位。`OutOfFlowLayoutPart` 会查找名为 `--my-target` 的锚点元素，并将当前元素的顶部边缘与锚点元素的顶部边缘对齐。
    * **`position-try-fallbacks: try(top left) try(bottom right);`**:  这段 CSS 代码使用了 `position-try-fallbacks`。如果按照 `top left` 定位不成功，`OutOfFlowLayoutPart` 会尝试按照 `bottom right` 定位。
    * **`position-visibility: no-overflow;`**: 这段 CSS 代码使用了 `position-visibility`。`OutOfFlowLayoutPart` 会根据元素是否溢出其包含块来设置元素的可见性。

* **HTML：** HTML 结构定义了元素的包含关系，这对于确定 out-of-flow 元素的包含块至关重要。
    *  如果一个 `<div>` 元素设置了 `position: absolute;`，那么 `OutOfFlowLayoutPart` 会向上遍历 DOM 树，找到最近的设置了 `position: relative`, `absolute`, `fixed` 或 `sticky` 的祖先元素作为其包含块。

* **JavaScript：** JavaScript 可以动态地修改元素的 CSS 样式，包括 `position` 属性以及相关的定位属性。当 JavaScript 修改这些属性时，会触发布局的重新计算，`OutOfFlowLayoutPart` 的代码会被执行以重新定位 out-of-flow 元素。
    *  例如，一个 JavaScript 动画可能会不断修改一个绝对定位元素的 `top` 和 `left` 值，`OutOfFlowLayoutPart` 会在每次修改后更新元素的位置。

**逻辑推理的假设输入与输出：**

假设输入一个 HTML 结构如下：

```html
<div style="position: relative; width: 200px; height: 100px;">
  <div id="absolute-element" style="position: absolute; top: 10px; left: 20px; width: 50px; height: 30px;"></div>
</div>
```

**假设输入：**  布局引擎开始处理 `id="absolute-element"` 的元素。

**逻辑推理：**

1. **确定包含块：** `absolute-element` 的最近定位祖先是外层的 `div`，因此外层 `div` 是其包含块。
2. **解析定位属性：**  `top: 10px; left: 20px;` 指示元素相对于包含块的左上角偏移。
3. **计算最终位置：**  `OutOfFlowLayoutPart` 会计算出 `absolute-element` 的左上角相对于外层 `div` 的左上角位于 (20px, 10px) 的位置。
4. **考虑元素尺寸：** `width: 50px; height: 30px;` 定义了元素的尺寸。

**假设输出：** `OutOfFlowLayoutPart` 计算出 `absolute-element` 在页面上的最终布局位置和尺寸信息，以便后续的渲染过程。例如，可能会输出一个包含左上角坐标 (20, 10) 和尺寸 (50, 30) 的矩形信息。

**涉及用户或编程常见的使用错误及举例说明：**

1. **忘记设置包含块的 `position` 属性：**
   * **错误示例：**

     ```html
     <div>
       <div style="position: absolute; top: 10px; left: 20px;">This is absolute.</div>
     </div>
     ```

   * **说明：**  由于外层 `div` 没有设置 `position` 属性 (默认为 `static`)，`absolute-element` 的包含块会是初始包含块（通常是 `<html>` 元素或视口），而不是外层的 `div`。这会导致 `absolute-element` 相对于整个页面进行定位，而不是相对于其父元素。

2. **误解 `position: fixed` 的行为：**
   * **错误示例：**  期望一个固定定位的元素相对于某个特定的父元素固定，但实际上它是相对于视口固定的。
   * **说明：**  `position: fixed` 的元素总是相对于视口进行定位，忽略其祖先元素的 `position` 属性。

3. **在 `position-try-fallbacks` 中定义了不存在的 `@position-try` 规则：**
   * **错误示例：**

     ```css
     #my-element {
       position-try-fallbacks: try(named-position);
     }

     /* 没有定义 @position-try named-position */
     ```

   * **说明：** 如果引用的 `@position-try` 规则不存在，浏览器将无法应用该回退策略。

4. **过度依赖或滥用 out-of-flow 定位：**
   * **说明：**  过度使用 `position: absolute` 或 `position: fixed` 可能会使布局难以维护和理解，尤其是在复杂的页面结构中。合理使用 Flexbox 或 Grid 等现代布局技术可以避免许多使用 out-of-flow 定位的需求。

**总结：**

`OutOfFlowLayoutPart` 是 Blink 渲染引擎中负责处理 `position: absolute` 和 `position: fixed` 元素布局的关键模块。它涉及到 CSS 属性的解析、包含块的确定、元素位置和尺寸的计算，以及对 CSS 锚点定位和 `position-try-fallbacks` 等新特性的支持。理解这个模块的功能有助于开发者更好地理解浏览器如何渲染 out-of-flow 元素，并避免常见的布局错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/out_of_flow_layout_part.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/out_of_flow_layout_part.h"

#include <math.h>

#include <algorithm>

#include "base/memory/values_equivalent.h"
#include "base/not_fatal_until.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/out_of_flow_data.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/absolute_utils.h"
#include "third_party/blink/renderer/core/layout/anchor_position_scroll_data.h"
#include "third_party/blink/renderer/core/layout/anchor_position_visibility_observer.h"
#include "third_party/blink/renderer/core/layout/anchor_query_map.h"
#include "third_party/blink/renderer/core/layout/column_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/grid/grid_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/grid/grid_placement.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_box_utils.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/logical_fragment.h"
#include "third_party/blink/renderer/core/layout/oof_positioned_node.h"
#include "third_party/blink/renderer/core/layout/paginated_root_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/pagination_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_fragment.h"
#include "third_party/blink/renderer/core/layout/simplified_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/simplified_oof_layout_algorithm.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"

namespace blink {

namespace {

// `margin_box_start`/`margin_box_end` and `imcb_inset_start`/`imcb_inset_end`
// are relative to the IMCB.
bool CalculateNonOverflowingRangeInOneAxis(
    LayoutUnit margin_box_start,
    LayoutUnit margin_box_end,
    LayoutUnit imcb_inset_start,
    LayoutUnit imcb_inset_end,
    LayoutUnit position_area_start,
    LayoutUnit position_area_end,
    bool has_non_auto_inset_start,
    bool has_non_auto_inset_end,
    std::optional<LayoutUnit>* out_scroll_min,
    std::optional<LayoutUnit>* out_scroll_max) {
  const LayoutUnit start_available_space = margin_box_start - imcb_inset_start;
  if (has_non_auto_inset_start) {
    // If the start inset is non-auto, then the start edges of both the
    // scroll-adjusted inset-modified containing block and the scroll-shifted
    // margin box always move by the same amount on scrolling. Then it overflows
    // if and only if it overflows at the initial scroll location.
    if (start_available_space < 0) {
      return false;
    }
  } else {
    // Otherwise, the start edge of the scroll-adjusted inset-modified
    // containing block is always at the same location, while that of the
    // scroll-shifted margin box can move by at most `start_available_space`
    // before overflowing.
    *out_scroll_max = position_area_start + start_available_space;
  }
  // Calculation for the end edge is symmetric.
  const LayoutUnit end_available_space = imcb_inset_end - margin_box_end;
  if (has_non_auto_inset_end) {
    if (end_available_space < 0) {
      return false;
    }
  } else {
    *out_scroll_min = -(position_area_end + end_available_space);
  }
  if (*out_scroll_min && *out_scroll_max &&
      out_scroll_min->value() > out_scroll_max->value()) {
    return false;
  }
  return true;
}

// Helper class to enumerate all the candidate styles to be passed to
// `TryCalculateOffset()`. The class should iterate through:
// - The base style, if no `position-try-fallbacks` is specified
// - The `@position-try` rule styles and try tactics if `position-try-fallbacks`
//   is specified
class OOFCandidateStyleIterator {
  STACK_ALLOCATED();

 public:
  explicit OOFCandidateStyleIterator(const LayoutObject& object,
                                     AnchorEvaluatorImpl& anchor_evaluator)
      : element_(DynamicTo<Element>(object.GetNode())),
        style_(object.Style()),
        anchor_evaluator_(anchor_evaluator) {
    Initialize();
  }

  bool HasPositionTryFallbacks() const {
    return position_try_fallbacks_ != nullptr;
  }

  // https://drafts.csswg.org/css-anchor-position-1/#propdef-position-try-order
  EPositionTryOrder PositionTryOrder() const { return position_try_order_; }

  // The current index into the position-try-fallbacks list. If nullopt, then
  // we're currently at the regular style, i.e. the one without any try fallback
  // included.
  std::optional<wtf_size_t> TryFallbackIndex() const {
    return try_fallback_index_;
  }

  const ComputedStyle& GetStyle() const { return *style_; }

  const ComputedStyle& GetBaseStyle() const {
    if (HasPositionTryFallbacks()) {
      return *GetStyle().GetBaseComputedStyleOrThis();
    }
    return GetStyle();
  }

  const ComputedStyle& ActivateBaseStyleForTryAttempt() {
    if (!HasPositionTryFallbacks()) {
      return GetStyle();
    }
    const ComputedStyle& base_style = GetBaseStyle();
    if (&base_style != &GetStyle()) {
      element_->GetLayoutObject()->SetStyle(
          &base_style, LayoutObject::ApplyStyleChanges::kNo);
    }
    return base_style;
  }

  const ComputedStyle& ActivateStyleForChosenFallback() {
    const ComputedStyle& style = GetStyle();
    element_->GetLayoutObject()->SetStyle(&style,
                                          LayoutObject::ApplyStyleChanges::kNo);
    return style;
  }

  bool MoveToNextStyle() {
    CHECK(position_try_fallbacks_);
    CHECK(element_);
    if (!try_fallback_index_.has_value()) {
      try_fallback_index_ = 0;
    } else {
      ++*try_fallback_index_;
    }
    // Need to loop in case a @position-try fallback does not exist.
    for (;
         *try_fallback_index_ < position_try_fallbacks_->GetFallbacks().size();
         ++*try_fallback_index_) {
      if (const ComputedStyle* style = UpdateStyle(*try_fallback_index_)) {
        style_ = style;
        return true;
      }
      // @position-try fallback does not exist.
    }
    return false;
  }

  void MoveToLastSuccessfulOrStyleWithoutFallbacks() {
    CHECK(element_);
    const CSSPropertyValueSet* try_set = nullptr;
    TryTacticList try_tactics = kNoTryTactics;
    if (OutOfFlowData* out_of_flow_data = element_->GetOutOfFlowData()) {
      // No successful fallbacks for this pass. Clear out the new successful
      // fallback candidate.
      out_of_flow_data->ClearPendingSuccessfulPositionFallback();
      if (out_of_flow_data->HasLastSuccessfulPositionFallback()) {
        try_set = out_of_flow_data->GetLastSuccessfulTrySet();
        try_tactics = out_of_flow_data->GetLastSuccessfulTryTactics();
      }
    }
    style_ = UpdateStyle(try_set, try_tactics);
  }

  std::optional<const CSSPropertyValueSet*> TrySetFromFallback(
      const PositionTryFallback& fallback) {
    if (!fallback.GetPositionArea().IsNone()) {
      // This fallback is an position-area(). Create a declaration block
      // with an equivalent position-area declaration.
      CSSPropertyValue declaration(
          CSSPropertyName(CSSPropertyID::kPositionArea),
          *ComputedStyleUtils::ValueForPositionArea(
              fallback.GetPositionArea()));
      return ImmutableCSSPropertyValueSet::Create(
          base::span_from_ref(declaration), kHTMLStandardMode);
    } else if (const ScopedCSSName* name = fallback.GetPositionTryName()) {
      if (const StyleRulePositionTry* rule = GetPositionTryRule(*name)) {
        return &rule->Properties();
      }
      return std::nullopt;
    }
    return nullptr;
  }

  void MoveToChosenTryFallbackIndex(std::optional<wtf_size_t> index) {
    CHECK(element_);
    const CSSPropertyValueSet* try_set = nullptr;
    TryTacticList try_tactics = kNoTryTactics;
    bool may_invalidate_last_successful = false;
    if (index.has_value()) {
      CHECK(position_try_fallbacks_);
      CHECK_LE(index.value(), position_try_fallbacks_->GetFallbacks().size());
      const PositionTryFallback& fallback =
          position_try_fallbacks_->GetFallbacks()[*index];
      try_tactics = fallback.GetTryTactic();
      std::optional<const CSSPropertyValueSet*> opt_try_set =
          TrySetFromFallback(fallback);
      CHECK(opt_try_set.has_value());
      try_set = opt_try_set.value();
      may_invalidate_last_successful =
          element_->EnsureOutOfFlowData().SetPendingSuccessfulPositionFallback(
              position_try_fallbacks_, try_set, try_tactics, index);
    } else if (OutOfFlowData* out_of_flow_data = element_->GetOutOfFlowData()) {
      may_invalidate_last_successful =
          out_of_flow_data->SetPendingSuccessfulPositionFallback(
              position_try_fallbacks_,
              /* try_set */ nullptr, kNoTryTactics, /* index */ std::nullopt);
    }
    if (may_invalidate_last_successful) {
      element_->GetDocument()
          .GetStyleEngine()
          .MarkLastSuccessfulPositionFallbackDirtyForElement(*element_);
    }
    if (index == try_fallback_index_) {
      // We're already at this position.
      return;
    }
    style_ = UpdateStyle(try_set, try_tactics);
  }

 private:
  void Initialize() {
    if (element_) {
      position_try_fallbacks_ = style_->GetPositionTryFallbacks();
      position_try_order_ = style_->PositionTryOrder();

      // If the base styles contain anchor*() queries, or depend on other
      // information produced by the AnchorEvaluator, then the ComputedStyle
      // produced by the main style recalc pass (which has no AnchorEvaluator)
      // is incorrect. For example, all anchor() queries would have evaluated
      // to their fallback value. Now that we have an AnchorEvaluator, we can
      // fix this by updating the style.
      //
      // Note that it's important to avoid the expensive call to UpdateStyle
      // here if we *don't* depend on anchor*(), since every out-of-flow will
      // reach this function, regardless of whether or not anchor positioning
      // is actually used.
      if (ElementStyleDependsOnAnchor(*element_, *style_)) {
        style_ = UpdateStyle(/* try_set */ nullptr, kNoTryTactics);
      }
    }
  }

  bool ElementStyleDependsOnAnchor(const Element& element,
                                   const ComputedStyle& style) {
    if (style.PositionAnchor() || element.ImplicitAnchorElement()) {
      // anchor-center offsets may need to be updated since the layout of the
      // anchor may have changed. anchor-center offsets are computed when a
      // default anchor is present.
      return true;
    }
    if (style.HasAnchorFunctions()) {
      return true;
    }
    return false;
  }

  const StyleRulePositionTry* GetPositionTryRule(
      const ScopedCSSName& scoped_name) {
    CHECK(element_);
    return element_->GetDocument().GetStyleEngine().GetPositionTryRule(
        scoped_name);
  }

  // Update the style using the specified index into `position_try_fallbacks_`
  // (which must exist), and return that updated style. Returns nullptr if
  // the fallback references a @position-try rule which doesn't exist.
  const ComputedStyle* UpdateStyle(wtf_size_t try_fallback_index) {
    // Previously evaluated anchor is not relevant if another position fallback
    // is applied.
    anchor_evaluator_.ClearAccessibilityAnchor();
    CHECK(position_try_fallbacks_);
    CHECK_LE(try_fallback_index,
             position_try_fallbacks_->GetFallbacks().size());
    const PositionTryFallback& fallback =
        position_try_fallbacks_->GetFallbacks()[try_fallback_index];
    std::optional<const CSSPropertyValueSet*> try_set =
        TrySetFromFallback(fallback);
    if (!try_set.has_value()) {
      // @position-try fallback does not exist.
      return nullptr;
    }
    return UpdateStyle(try_set.value(), fallback.GetTryTactic());
  }

  const ComputedStyle* UpdateStyle(const CSSPropertyValueSet* try_set,
                                   const TryTacticList& tactic_list) {
    CHECK(element_);
    element_->GetDocument().GetStyleEngine().UpdateStyleForOutOfFlow(
        *element_, try_set, tactic_list, &anchor_evaluator_);
    CHECK(element_->GetLayoutObject());
    // Returns LayoutObject ComputedStyle instead of element style for layout
    // purposes. The style may be different, in particular for body -> html
    // propagation of writing modes.
    return element_->GetLayoutObject()->Style();
  }

  Element* element_ = nullptr;

  // The current candidate style if no auto anchor fallback is triggered.
  // Otherwise, the base style for generating auto anchor fallbacks.
  const ComputedStyle* style_ = nullptr;

  // This evaluator is passed to StyleEngine::UpdateStyleForOutOfFlow to
  // evaluate anchor queries on the computed style.
  AnchorEvaluatorImpl& anchor_evaluator_;

  // If the current style is applying a `position-try-fallbacks` fallback, this
  // holds the list of fallbacks. Otherwise nullptr.
  const PositionTryFallbacks* position_try_fallbacks_ = nullptr;

  EPositionTryOrder position_try_order_ = EPositionTryOrder::kNormal;

  // If the current style is created using `position-try-fallbacks`, an index
  // into the list of fallbacks; otherwise nullopt.
  std::optional<wtf_size_t> try_fallback_index_;
};

const Element* GetPositionAnchorElement(
    const BlockNode& node,
    const ComputedStyle& style,
    const LogicalAnchorQuery* anchor_query) {
  if (!anchor_query) {
    return nullptr;
  }
  if (const ScopedCSSName* specifier = style.PositionAnchor()) {
    if (const LogicalAnchorReference* reference =
            anchor_query->AnchorReference(*node.GetLayoutBox(), specifier);
        reference && reference->layout_object) {
      return DynamicTo<Element>(reference->layout_object->GetNode());
    }
    return nullptr;
  }
  if (auto* element = DynamicTo<Element>(node.GetDOMNode())) {
    return element->ImplicitAnchorElement();
  }
  return nullptr;
}

const LayoutObject* GetPositionAnchorObject(
    const BlockNode& node,
    const ComputedStyle& style,
    const LogicalAnchorQuery* anchor_query) {
  if (const Element* element =
          GetPositionAnchorElement(node, style, anchor_query)) {
    return element->GetLayoutObject();
  }
  return nullptr;
}

gfx::Vector2dF GetAnchorOffset(const BlockNode& node,
                               const ComputedStyle& style,
                               const LogicalAnchorQuery* anchor_query) {
  if (const LayoutObject* anchor_object =
          GetPositionAnchorObject(node, style, anchor_query)) {
    if (const AnchorPositionScrollData* data =
            To<Element>(node.GetDOMNode())->GetAnchorPositionScrollData()) {
      return data->TotalOffset(*anchor_object);
    }
  }
  return gfx::Vector2dF();
}

// Updates `node`'s associated `PaintLayer` for `position-visibility`. See:
// https://drafts.csswg.org/css-anchor-position-1/#position-visibility. The
// values of `no-overflow` and `anchors-valid` are computed and directly update
// the `PaintLayer` in this function. The remaining value of `anchors-visible`
// is computed via an intersection observer set up in this function, and the
// `PaintLayer` is updated later during the post-layout intersection observer
// step.
void UpdatePositionVisibilityAfterLayout(
    const OutOfFlowLayoutPart::OffsetInfo& offset_info,
    const BlockNode& node,
    const LogicalAnchorQuery* anchor_query) {
  if (!anchor_query) {
    return;
  }

  // TODO(crbug.com/332933527): Support anchors-valid.

  PaintLayer* layer = node.GetLayoutBox()->Layer();
  CHECK(layer);
  bool has_no_overflow_visibility =
      node.Style().HasPositionVisibility(PositionVisibility::kNoOverflow);
  layer->SetInvisibleForPositionVisibility(
      LayerPositionVisibility::kNoOverflow,
      has_no_overflow_visibility && offset_info.overflows_containing_block);

  // TODO(wangxianzhu): We may be anchored in cases where we do not need scroll
  // adjustment, such as when the anchor and anchored have the same containing
  // block. For now though, these flags are true in this case.
  bool is_anchor_positioned = offset_info.needs_scroll_adjustment_in_x ||
                              offset_info.needs_scroll_adjustment_in_y;
  bool has_anchors_visible_visibility =
      node.Style().HasPositionVisibility(PositionVisibility::kAnchorsVisible);
  Element* anchored = DynamicTo<Element>(node.GetDOMNode());
  // https://drafts.csswg.org/css-anchor-position-1/#valdef-position-visibility-anchors-visible
  // We only need to track the default anchor for anchors-visible.
  const Element* anchor =
      anchored ? GetPositionAnchorElement(node, node.Style(), anchor_query)
               : nullptr;
  if (is_anchor_positioned && has_anchors_visible_visibility && anchor) {
    anchored->EnsureAnchorPositionScrollData()
        .EnsureAnchorPositionVisibilityObserver()
        .MonitorAnchor(anchor);
  } else if (anchored) {
    if (auto* scroll_data = anchored->GetAnchorPositionScrollData()) {
      if (auto* observer = scroll_data->GetAnchorPositionVisibilityObserver()) {
        observer->MonitorAnchor(nullptr);
      }
    }
  }
}

}  // namespace

// static
std::optional<LogicalSize> OutOfFlowLayoutPart::InitialContainingBlockFixedSize(
    BlockNode container) {
  if (!container.GetLayoutBox()->IsLayoutView() ||
      container.GetDocument().Printing())
    return std::nullopt;
  const auto* frame_view = container.GetDocument().View();
  DCHECK(frame_view);
  PhysicalSize size(
      frame_view->LayoutViewport()->ExcludeScrollbars(frame_view->Size()));
  return size.ConvertToLogical(container.Style().GetWritingMode());
}

OutOfFlowLayoutPart::OutOfFlowLayoutPart(BoxFragmentBuilder* container_builder)
    : container_builder_(container_builder),
      is_absolute_container_(container_builder->Node().IsAbsoluteContainer()),
      is_fixed_container_(container_builder->Node().IsFixedContainer()),
      has_block_fragmentation_(
          InvolvedInBlockFragmentation(*container_builder)) {
  // If there are no OOFs inside, we can return early, except if this is the
  // root. There may be top-layer nodes still to be added. Additionally, for
  // pagination, we might not have hauled any OOFs inside the fragmentainers
  // yet. See HandleFragmentation().
  if (!container_builder->HasOutOfFlowPositionedCandidates() &&
      !container_builder->HasOutOfFlowFragmentainerDescendants() &&
      !container_builder->HasMulticolsWithPendingOOFs() &&
      !container_builder->IsRoot()) {
    return;
  }

  // Disable first tier cache for grid layouts, as grid allows for out-of-flow
  // items to be placed in grid areas, which is complex to maintain a cache for.
  const BoxStrut border_scrollbar =
      container_builder->Borders() + container_builder->Scrollbar();
  default_containing_block_info_for_absolute_.writing_direction =
      GetConstraintSpace().GetWritingDirection();
  default_containing_block_info_for_fixed_.writing_direction =
      GetConstraintSpace().GetWritingDirection();
  default_containing_block_info_for_absolute_.is_scroll_container =
      container_builder_->Node().IsScrollContainer();
  default_containing_block_info_for_fixed_.is_scroll_container =
      container_builder_->Node().IsScrollContainer();
  if (container_builder_->HasBlockSize()) {
    default_containing_block_info_for_absolute_.rect.size =
        ShrinkLogicalSize(container_builder_->Size(), border_scrollbar);
    default_containing_block_info_for_fixed_.rect.size =
        InitialContainingBlockFixedSize(container_builder->Node())
            .value_or(default_containing_block_info_for_absolute_.rect.size);
  }
  LogicalOffset container_offset = {border_scrollbar.inline_start,
                                    border_scrollbar.block_start};
  default_containing_block_info_for_absolute_.rect.offset = container_offset;
  default_containing_block_info_for_fixed_.rect.offset = container_offset;
}

void OutOfFlowLayoutPart::Run() {
  if (container_builder_->IsPaginatedRoot()) {
    PropagateOOFsFromPageAreas();
  }

  HandleFragmentation();

  // If the container is display-locked, then we skip the layout of descendants,
  // so we can early out immediately.
  const BlockNode& node = container_builder_->Node();
  if (node.ChildLayoutBlockedByDisplayLock()) {
    return;
  }

  HeapVector<LogicalOofPositionedNode> candidates;
  ClearCollectionScope<HeapVector<LogicalOofPositionedNode>> clear_scope(
      &candidates);
  container_builder_->SwapOutOfFlowPositionedCandidates(&candidates);

  if (!candidates.empty()) {
    LayoutCandidates(&candidates);
  } else {
    container_builder_
        ->AdjustFixedposContainingBlockForFragmentainerDescendants();
    container_builder_->AdjustFixedposContainingBlockForInnerMulticols();
  }

  // If this is for the root fragment, now process top-layer elements.
  // We do this last as:
  //  - Additions/removals may occur while processing normal out-of-flow
  //    positioned elements (e.g. via a container-query).
  //  - They correctly reference any anchor()s from preceding elements.
  if (!container_builder_->IsRoot()) {
    return;
  }

  for (LayoutInputNode child = node.FirstChild(); child;
       child = child.NextSibling()) {
    if (!child.IsBlock()) {
      continue;
    }
    BlockNode block_child = To<BlockNode>(child);
    if (!block_child.IsInTopOrViewTransitionLayer() ||
        !block_child.IsOutOfFlowPositioned()) {
      continue;
    }

    // https://drafts.csswg.org/css-position-4/#top-styling
    // The static position for top-layer elements is just 0x0.
    container_builder_->AddOutOfFlowChildCandidate(
        block_child, LogicalOffset(),
        LogicalStaticPosition::InlineEdge::kInlineStart,
        LogicalStaticPosition::BlockEdge::kBlockStart,
        /*is_hidden_for_paint=*/false,
        /*allow_top_layer_nodes=*/true);

    // With one top-layer node added, run through the machinery again. Note that
    // we need to do this separately for each node, as laying out a node may
    // cause top-layer nodes to be added or removed.
    HandleFragmentation();
    container_builder_->SwapOutOfFlowPositionedCandidates(&candidates);
    LayoutCandidates(&candidates);
  }
}

void OutOfFlowLayoutPart::PropagateOOFsFromPageAreas() {
  DCHECK(container_builder_->IsPaginatedRoot());
  LogicalOffset offset_adjustment;
  for (wtf_size_t i = 0; i < ChildCount(); i++) {
    // Propagation from children stopped at the fragmentainers (the page area
    // fragments). Now collect any pending OOFs, and lay them out.
    const PhysicalBoxFragment& fragmentainer = GetChildFragment(i);
    if (fragmentainer.NeedsOOFPositionedInfoPropagation()) {
      container_builder_->PropagateOOFPositionedInfo(
          fragmentainer, LogicalOffset(), LogicalOffset(), offset_adjustment);
    }
    if (const auto* break_token = fragmentainer.GetBreakToken()) {
      offset_adjustment.block_offset = break_token->ConsumedBlockSize();
    }
  }
}

void OutOfFlowLayoutPart::HandleFragmentation() {
  // OOF fragmentation depends on LayoutBox data being up-to-date, which isn't
  // the case if side-effects are disabled. So we cannot safely do anything
  // here.
  if (DisableLayoutSideEffectsScope::IsDisabled()) {
    return;
  }

  if (!column_balancing_info_ &&
      (!container_builder_->IsBlockFragmentationContextRoot() ||
       has_block_fragmentation_)) {
    return;
  }

  if (container_builder_->Node().IsPaginatedRoot()) {
    HeapVector<LogicalOofPositionedNode> candidates;
    ClearCollectionScope<HeapVector<LogicalOofPositionedNode>> scope(
        &candidates);
    container_builder_->SwapOutOfFlowPositionedCandidates(&candidates);
    // Catch everything for paged layout. We want to fragment everything. If the
    // containing block is the initial containing block, it should be fragmented
    // now, and not bubble further to the viewport (where we'd end up with
    // non-fragmented layout). Note that we're not setting a containing block
    // fragment for the candidates, as that would confuse
    // GetContainingBlockInfo(), which expects a containing block fragment to
    // also have a LayoutObject, which fragmentainers don't. Fixing that is
    // possible, but requires special-code there. This approach seems easier.
    for (LogicalOofPositionedNode candidate : candidates) {
      container_builder_->AddOutOfFlowFragmentainerDescendant(candidate);
    }
  }

  DCHECK(!child_fragment_storage_ || !child_fragment_storage_->empty());
  DCHECK(
      !column_balancing_info_ ||
      !column_balancing_info_->out_of_flow_fragmentainer_descendants.empty());

  auto ShouldContinue = [&]() -> bool {
    if (column_balancing_info_)
      return column_balancing_info_->HasOutOfFlowFragmentainerDescendants();
    return container_builder_->HasOutOfFlowFragmentainerDescendants() ||
           container_builder_->HasMulticolsWithPendingOOFs();
  };

  while (ShouldContinue()) {
    HeapVector<LogicalOofNodeForFragmentation> fragmentainer_descendants;
    ClearCollectionScope<HeapVector<LogicalOofNodeForFragmentation>> scope(
        &fragmentainer_descendants);
    if (column_balancing_info_) {
      column_balancing_info_->SwapOutOfFlowFragmentainerDescendants(
          &fragmentainer_descendants);
      DCHECK(!fragmentainer_descendants.empty());
    } else {
      HandleMulticolsWithPendingOOFs(container_builder_);
      if (container_builder_->HasOutOfFlowFragmentainerDescendants()) {
        container_builder_->SwapOutOfFlowFragmentainerDescendants(
            &fragmentainer_descendants);
        DCHECK(!fragmentainer_descendants.empty());
      }
    }
    if (!fragmentainer_descendants.empty()) {
      LogicalOffset fragmentainer_progression = GetFragmentainerProgression(
          *container_builder_, GetFragmentainerType());
      LayoutFragmentainerDescendants(&fragmentainer_descendants,
                                     fragmentainer_progression);
    }
  }
  if (!column_balancing_info_) {
    for (auto& descendant : delayed_descendants_)
      container_builder_->AddOutOfFlowFragmentainerDescendant(descendant);
  }
}

OutOfFlowLayoutPart::ContainingBlockInfo
OutOfFlowLayoutPart::ApplyPositionAreaOffsets(
    const PositionAreaOffsets& offsets,
    const OutOfFlowLayoutPart::ContainingBlockInfo& container_info) const {
  ContainingBlockInfo adjusted_container_info(container_info);
  PhysicalToLogical converter(container_info.writing_direction,
                              offsets.top.value_or(LayoutUnit()),
                              offsets.right.value_or(LayoutUnit()),
                              offsets.bottom.value_or(LayoutUnit()),
                              offsets.left.value_or(LayoutUnit()));

  // Reduce the container size and adjust the offset based on the position-area.
  adjusted_container_info.rect.ContractEdges(
      converter.BlockStart(), converter.InlineEnd(), converter.BlockEnd(),
      converter.InlineStart());

  // For 'center' values (aligned with start and end anchor sides), the
  // containing block is aligned and sized with the anchor, regardless of
  // whether it's inside the original containing block or not. Otherwise,
  // ContractEdges above might have created a negative size if the position-area
  // is aligned with an anchor side outside the containing block.
  if (adjusted_container_info.rect.size.inline_size < LayoutUnit()) {
    DCHECK(converter.InlineStart() == LayoutUnit() ||
           converter.InlineEnd() == LayoutUnit())
        << "If aligned to both anchor edges, the size should never be "
           "negative.";
    // Collapse the inline size to 0 and align with the single anchor edge
    // defined by the position-area.
    if (converter.InlineStart() == LayoutUnit()) {
      DCHECK(converter.InlineEnd() != LayoutUnit());
      adjusted_container_info.rect.offset.inline_offset +=
          adjusted_container_info.rect.size.inline_size;
    }
    adjusted_container_info.rect.size.inline_size = LayoutUnit();
  }
  if (adjusted_container_info.rect.size.block_size < LayoutUnit()) {
    DCHECK(converter.BlockStart() == LayoutUnit() ||
           converter.BlockEnd() == LayoutUnit())
        << "If aligned to both anchor edges, the size should never be "
           "negative.";
    // Collapse the block size to 0 and align with the single anchor edge
    // defined by the position-area.
    if (converter.BlockStart() == LayoutUnit()) {
      DCHECK(converter.BlockEnd() != LayoutUnit());
      adjusted_container_info.rect.offset.block_offset +=
          adjusted_container_info.rect.size.block_size;
    }
    adjusted_container_info.rect.size.block_size = LayoutUnit();
  }
  return adjusted_container_info;
}

// Retrieve the stored ContainingBlockInfo needed for placing positioned nodes.
// When fragmenting, the ContainingBlockInfo is not stored ahead of time and
// must be generated on demand. The reason being that during fragmentation, we
// wait to place positioned nodes until they've reached the fragmentation
// context root. In such cases, we cannot use default |ContainingBlockInfo|
// since the fragmentation root is not the containing block of the positioned
// nodes. Rather, we must generate their ContainingBlockInfo based on the
// |candidate.containing_block.fragment|.
const OutOfFlowLayoutPart::ContainingBlockInfo
OutOfFlowLayoutPart::GetContainingBlockInfo(
    const LogicalOofPositionedNode& candidate) {
  const auto* container_object = container_builder_->GetLayoutObject();
  const auto& node_style = candidate.Node().Style();

  auto IsPlacedWithinGridArea = [&](const auto* containing_block) {
    if (!containing_block->IsLayoutGrid()) {
      return false;
    }

    return !node_style.GridColumnStart().IsAuto() ||
           !node_style.GridColumnEnd().IsAuto() ||
           !node_style.GridRowStart().IsAuto() ||
           !node_style.GridRowEnd().IsAuto();
  };

  auto GridAreaContainingBlockInfo =
      [&](const LayoutGrid& containing_grid, const GridLayoutData& layout_data,
          const BoxStrut& borders,
          const LogicalSize& size) -> OutOfFlowLayoutPart::ContainingBlockInfo {
    const auto& grid_style = containing_grid.StyleRef();
    GridItemData grid_item(candidate.Node(), grid_style);

    return {.writing_direction = grid_style.GetWritingDirection(),
            .rect = GridLayoutAlgorithm::ComputeOutOfFlowItemContainingRect(
                containing_grid.CachedPlacementData(), layout_data, grid_style,
                borders, size, &grid_item)};
  };

  if (candidate.inline_container.container) {
    const auto it =
        containing_blocks_map_.find(candidate.inline_container.container);
    CHECK(it != containing_blocks_map_.end(), base::NotFatalUntil::M130);
    return it->value;
  }

  if (candidate.is_for_fragmentation) {
    LogicalOofNodeForFragmentation fragmentainer_descendant =
        To<LogicalOofNodeForFragmentation>(candidate);
    if (fragmentainer_descendant.containing_block.Fragment()) {
      DCHECK(container_builder_->IsBlockFragmentationContextRoot());

      const PhysicalFragment* containing_block_fragment =
          fragmentain
"""


```