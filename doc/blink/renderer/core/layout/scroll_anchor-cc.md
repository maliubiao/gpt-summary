Response:
Let's break down the thought process for analyzing the `scroll_anchor.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (JS, HTML, CSS), logical reasoning examples, and common usage errors.

2. **Initial Scan for Keywords and Structure:**  A quick skim reveals terms like "scroll," "anchor," "layout," "element," "selector," "offset," "scroller," and functions like `FindAnchor`, `ComputeAdjustment`, `RestoreAnchor`. The `#include` statements suggest dependencies on layout, DOM, CSS, and platform-level utilities. The namespace `blink` confirms it's part of the Blink rendering engine.

3. **Identify Core Functionality:** The name `scroll_anchor.cc` strongly suggests it's responsible for managing scroll anchoring. This means it tries to keep a specific point within the viewport visible when content above it changes size, preventing the user's view from jumping.

4. **Dissect Key Classes and Methods:**

   * **`ScrollAnchor` class:** This is likely the main class. It holds the state of the current scroll anchor.
   * **`FindAnchor()`:**  Crucial for selecting the best element to anchor to. This likely involves heuristics and checks.
   * **`ComputeAdjustment()`:** Calculates the scroll offset adjustment needed to keep the anchor in place.
   * **`Adjust()`:**  Applies the calculated scroll adjustment.
   * **`RestoreAnchor()`:**  Handles restoring a scroll anchor based on a serialized representation (useful for navigating back/forward).
   * **`GetSerializedAnchor()`:**  Creates a string representation of the current anchor.
   * **`Examine()` and `ExaminePriorityCandidate()`:**  Likely involved in evaluating potential anchor candidates.
   * **`ComputeRelativeOffset()`:** Determines the position of an element relative to the scroller.
   * **`UniqueSimpleSelectorAmongSiblings()` and `ComputeUniqueSelector()`:** Generate CSS selectors to identify anchor elements.

5. **Map Functionality to Web Technologies:**

   * **HTML:** Scroll anchoring is about maintaining the user's view within the *content* of the HTML document. The selectors generated directly target HTML elements.
   * **CSS:**
      * The `overflow-anchor` CSS property is explicitly mentioned, indicating a direct relationship. This property controls whether an element can be a scroll anchor.
      * The calculations involve element dimensions and positions, which are heavily influenced by CSS styling.
      * Selectors are a fundamental part of CSS.
   * **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, its functionality affects the user experience when JavaScript dynamically modifies the DOM (e.g., adding images, loading content). The scroll anchoring mechanism tries to mitigate the visual disruption caused by such changes.

6. **Infer Logical Reasoning and Examples:**

   * **Input/Output of `FindAnchor()`:**  The input is a scrollable area, and the output is the "best" anchor element within that area. The selection logic is based on heuristics (visibility, priority candidates).
   * **Input/Output of `ComputeAdjustment()`:**  The input is the current anchor element and the scrollable area. The output is the calculated scroll adjustment (a vector). The logic considers the relative position change of the anchor.
   * **Input/Output of `RestoreAnchor()`:**  The input is a serialized anchor string and the scrollable area. The output is a boolean indicating success or failure. The logic involves querying the DOM using the stored selector and potentially adjusting the scroll position.

7. **Identify Potential User/Programming Errors:**

   * **Incorrect `overflow-anchor` usage:** Setting it to `none` when the user *does* want scroll anchoring to work for that element.
   * **Creating overly complex selectors:**  While the code tries to generate robust selectors, highly dynamic or deeply nested structures might make accurate identification difficult, although the code has safeguards.
   * **Assuming immediate anchor restoration:**  The `RestoreAnchor` method might fail if the DOM structure has significantly changed since the anchor was serialized.

8. **Structure the Response:** Organize the findings into the requested categories: functionality, relationship to web technologies, logical reasoning examples, and common errors. Use clear and concise language. Provide code snippets and HTML/CSS examples where helpful.

9. **Review and Refine:**  Read through the analysis to ensure accuracy, clarity, and completeness. Double-check the connection between the code's actions and the user's experience on a webpage. Make sure the examples are illustrative and easy to understand. For instance, initially, I might have just said "it uses selectors," but refining it to show *how* it uses selectors and what kind of selectors it generates makes the explanation much better.

By following this systematic approach, which involves code examination, conceptual understanding of web technologies, and logical deduction, it's possible to create a comprehensive and accurate analysis of the `scroll_anchor.cc` file.
好的，让我们来分析一下 `blink/renderer/core/layout/scroll_anchor.cc` 文件的功能。

**文件功能概览:**

`scroll_anchor.cc` 文件的核心功能是实现浏览器的**滚动锚定 (Scroll Anchoring)** 机制。滚动锚定是一种浏览器特性，旨在改善用户体验，特别是当网页内容动态变化时，防止用户当前阅读的位置发生意外的跳跃。

**具体功能分解:**

1. **识别和选择锚点 (Anchor Point):**
   - 文件包含逻辑来判断页面中的哪个元素应该作为滚动锚点。
   - 它会考虑元素的可见性、大小、是否占据空间、是否可移动（例如，非固定定位元素）等因素。
   - 优先级会赋予某些特定的元素，例如当前获得焦点的元素或查找功能 (find-in-page) 匹配的元素。
   - `FindAnchor()` 函数及其相关的 `Examine()` 和 `ExaminePriorityCandidate()` 函数负责执行此过程。

2. **计算相对偏移 (Relative Offset):**
   - 一旦确定了锚点元素，代码会计算锚点元素相对于滚动容器的特定角（例如，左上角）的偏移量。
   - `ComputeRelativeOffset()` 函数执行此计算。

3. **计算滚动调整量 (Scroll Adjustment):**
   - 当页面内容发生变化，导致锚点元素的位置也发生变化时，代码会计算需要调整的滚动量，以保持锚点元素在视口中的相对位置不变。
   - `ComputeAdjustment()` 函数负责计算这个调整量。
   - 它会考虑锚点元素的移动距离，并只在块布局轴上进行调整，以避免水平滚动发生意外变化。

4. **应用滚动调整 (Apply Scroll Adjustment):**
   - 计算出调整量后，代码会将这个调整量应用到滚动容器上，从而更新滚动位置。
   - `Adjust()` 函数执行此操作。

5. **序列化和反序列化锚点 (Serialize and Deserialize Anchor):**
   - 为了在页面导航（例如，前进/后退）或在不同会话之间恢复滚动位置，代码可以序列化当前锚点的信息（例如，CSS 选择器和相对偏移）。
   - `GetSerializedAnchor()` 函数负责序列化。
   - `RestoreAnchor()` 函数则负责根据序列化的信息重新找到锚点并恢复滚动位置。

6. **处理 `overflow-anchor` CSS 属性:**
   - 代码会检查元素的 `overflow-anchor` CSS 属性值。如果设置为 `none`，则该元素不会被视为滚动锚点的候选者。

7. **处理内容可见性 `content-visibility: auto`:**
   - 代码会特别处理 `content-visibility: auto` 属性的元素，如果一个这样的元素在初始布局时尚未布局，但在后续布局中可能成为更好的锚点，则会重新选择锚点。

8. **避免循环调整:**
   - 代码中包含逻辑来避免因滚动调整本身触发新的布局和再次调整，从而陷入无限循环。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    - **关系:**  滚动锚定直接作用于 HTML 元素。代码通过遍历 DOM 树来寻找合适的锚点元素。
    - **举例:**  假设一个包含大量图片的网页，图片加载后会撑开页面高度。滚动锚定会尝试保持用户当前阅读的文本段落在屏幕上的位置不变，即使上面的图片加载完成。

* **CSS:**
    - **关系:**
        - `overflow-anchor` CSS 属性直接控制元素是否参与滚动锚定。
        - 代码在计算锚点元素的相对偏移时，会考虑元素的盒模型 (box model)，这受到 CSS 的影响（例如，`padding`, `border`）。
        - `content-visibility: auto` 属性也会影响滚动锚定的行为。
    - **举例:**
        ```html
        <div style="overflow-y: scroll; height: 200px;">
          <p>一些初始内容</p>
          <div id="anchor-point">这是锚点</div>
          <p>更多内容</p>
        </div>
        <button onclick="addMoreContent()">添加更多内容</button>
        <script>
          function addMoreContent() {
            const container = document.querySelector('div');
            for (let i = 0; i < 10; i++) {
              const p = document.createElement('p');
              p.textContent = '新添加的内容';
              container.insertBefore(p, container.firstChild);
            }
          }
        </script>
        ```
        在这个例子中，如果滚动条在“这是锚点”附近，点击按钮添加内容后，滚动锚定会尝试保持“这是锚点”在视口中的相对位置。

* **JavaScript:**
    - **关系:**  虽然 `scroll_anchor.cc` 是 C++ 代码，但它处理的是 JavaScript 动态修改 DOM 带来的滚动位置变化。当 JavaScript 代码添加、删除或修改页面内容时，滚动锚定机制会介入。
    - **举例:**  考虑一个无限滚动的列表，当 JavaScript 加载更多条目并添加到列表顶部时，如果没有滚动锚定，用户当前浏览的内容可能会被推到屏幕下方。滚动锚定会尝试调整滚动位置来避免这种情况。

**逻辑推理的假设输入与输出:**

**场景 1:  页面加载后，用户滚动到某个位置。然后，JavaScript 在页面顶部动态插入一个大的元素（例如，一个广告）。**

* **假设输入:**
    * 初始滚动位置: `scrollTop: 500px`
    * 锚点元素 (假设为用户当前阅读的段落):  在插入元素之前，其顶部距离滚动容器顶部 `700px`。
    * 插入的元素高度: `300px`
* **逻辑推理:**
    1. 在插入元素之前，锚点元素的相对偏移（例如，左上角相对于滚动容器的左上角）会被记录。
    2. 插入元素后，锚点元素的顶部距离滚动容器顶部变为 `700px + 300px = 1000px`。
    3. `ComputeAdjustment()` 会计算出需要调整的滚动量，大致为 `300px`。
* **预期输出:**
    * 调整后的滚动位置: `scrollTop: 500px + 300px = 800px`。
    * 这样锚点元素在视口中的相对位置大致保持不变。

**场景 2:  页面包含一个 `overflow-anchor: none` 的元素，该元素本可能成为一个好的锚点。**

* **假设输入:**
    * 页面结构包含一个 `div` 元素，其 CSS 样式为 `overflow-anchor: none;`。
    * 该 `div` 元素在视口中且占据一定空间。
* **逻辑推理:**
    1. `Examine()` 函数会检查元素的 `overflow-anchor` 属性。
    2. 由于 `overflow-anchor` 为 `none`，`Examine()` 会返回 `kSkip`，表示跳过该元素，不将其作为锚点考虑。
* **预期输出:**
    * 该 `div` 元素不会被选为滚动锚点。浏览器会选择其他合适的元素作为锚点，或者如果没有其他合适的，可能不会进行滚动锚定。

**用户或编程常见的使用错误:**

1. **过度依赖滚动锚定，而不是优化内容加载:**  虽然滚动锚定可以缓解内容动态加载带来的问题，但开发者不应该完全依赖它来解决所有布局跳跃问题。优化图片加载、使用占位符等技术仍然很重要。

2. **错误地使用 `overflow-anchor: none`:**  如果开发者错误地将关键内容的父元素设置为 `overflow-anchor: none`，可能会导致这些内容在动态更新时发生意外的跳跃，因为这些元素不会被考虑作为锚点。

   ```html
   <div style="overflow-y: scroll; height: 200px;">
     <div style="overflow-anchor: none;"> <!-- 错误地禁用了锚定 -->
       <p>一些初始内容</p>
       <div id="important-content">重要内容</div>
     </div>
     <button onclick="addContentBefore()">在前面添加内容</button>
   </div>

   <script>
     function addContentBefore() {
       const container = document.querySelector('div > div');
       const newP = document.createElement('p');
       newP.textContent = '新内容';
       container.insertBefore(newP, container.firstChild);
     }
   </script>
   ```
   在这个例子中，由于外部 `div` 设置了 `overflow-anchor: none`，即使内部的 `#important-content` 很重要，滚动锚定也可能不会起作用，导致点击按钮后 `#important-content` 可能会跳动。

3. **假设滚动锚定总是完美工作:**  滚动锚定是一项复杂的特性，在某些边缘情况下可能无法完美地保持滚动位置。例如，当锚点元素自身的大小或形状发生剧烈变化时，或者在复杂的布局场景中，锚定效果可能不如预期。

4. **不理解锚点的选择逻辑:** 开发者可能不清楚浏览器是如何选择锚点的，导致对滚动锚定的行为感到困惑。例如，他们可能期望某个特定的元素作为锚点，但浏览器由于其内部逻辑选择了另一个元素。

总而言之，`scroll_anchor.cc` 文件是 Chromium Blink 引擎中实现关键的滚动锚定特性的核心组件。它涉及到复杂的布局计算和 DOM 操作，旨在为用户提供更流畅的网页浏览体验，尤其是在内容动态变化的情况下。理解其功能和与 Web 技术的关系有助于开发者更好地利用和调试相关问题。

### 提示词
```
这是目录为blink/renderer/core/layout/scroll_anchor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/scroll_anchor.h"

#include <algorithm>
#include <memory>

#include "base/trace_event/typed_macros.h"
#include "third_party/blink/public/platform/web_scroll_anchor_data.h"
#include "third_party/blink/renderer/core/css/css_markup.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/nth_index_cache.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/bloom_filter.h"

namespace blink {

namespace {

bool IsNGBlockFragmentationRoot(const LayoutBlockFlow* block_flow) {
  return block_flow && block_flow->IsFragmentationContextRoot() &&
         block_flow->IsLayoutNGObject();
}

gfx::Vector2d ToRoundedVector2d(const LogicalOffset& o) {
  return {o.inline_offset.Round(), o.block_offset.Round()};
}

LayoutBox* ScrollerLayoutBox(const ScrollableArea* scroller) {
  LayoutBox* box = scroller->GetLayoutBox();
  DCHECK(box);
  return box;
}

LogicalOffset ToLogicalOffset(const gfx::PointF& point,
                              const ScrollableArea& scroller) {
  return ScrollerLayoutBox(&scroller)->IsHorizontalWritingMode()
             ? LogicalOffset(LayoutUnit(point.x()), LayoutUnit(point.y()))
             : LogicalOffset(LayoutUnit(point.y()), LayoutUnit(point.x()));
}

}  // anonymous namespace

// With 100 unique strings, a 2^12 slot table has a false positive rate of ~2%.
using ClassnameFilter = CountingBloomFilter<12>;
using Corner = ScrollAnchor::Corner;

SerializedAnchor::SerializedAnchor(const ScrollAnchorData& data,
                                   const ScrollableArea& scroller)
    : selector(data.selector_),
      relative_offset(ToLogicalOffset(data.offset_, scroller)),
      simhash(data.simhash_) {}

ScrollOffset SerializedAnchor::GetScrollOffset(
    const ScrollableArea& scroller) const {
  ScrollOffset offset = ToRoundedVector2d(relative_offset);
  if (!ScrollerLayoutBox(&scroller)->IsHorizontalWritingMode()) {
    offset.Transpose();
  }
  return offset;
}

ScrollAnchor::ScrollAnchor()
    : anchor_object_(nullptr),
      corner_(Corner::kTopLeft),
      scroll_anchor_disabling_style_changed_(false),
      queued_(false) {}

ScrollAnchor::ScrollAnchor(ScrollableArea* scroller) : ScrollAnchor() {
  SetScroller(scroller);
}

ScrollAnchor::~ScrollAnchor() = default;

void ScrollAnchor::Trace(Visitor* visitor) const {
  visitor->Trace(scroller_);
  visitor->Trace(anchor_object_);
}

void ScrollAnchor::SetScroller(ScrollableArea* scroller) {
  DCHECK_NE(scroller_, scroller);
  DCHECK(scroller);
  DCHECK(scroller->IsRootFrameViewport() ||
         scroller->IsPaintLayerScrollableArea());
  scroller_ = scroller;
  ClearSelf();
}

// TODO(skobes): Storing a "corner" doesn't make much sense anymore since we
// adjust only on the block flow axis.  This could probably be refactored to
// simply measure the movement of the block-start edge.
static Corner CornerToAnchor(const ScrollableArea* scroller) {
  auto writing_mode = ScrollerLayoutBox(scroller)->Style()->GetWritingMode();
  if (IsFlippedBlocksWritingMode(writing_mode)) {
    return Corner::kTopRight;
  }
  if (writing_mode == WritingMode::kSidewaysLr) {
    return Corner::kBottomLeft;
  }
  return Corner::kTopLeft;
}

static PhysicalOffset CornerPointOfRect(const PhysicalRect& rect,
                                        Corner which_corner) {
  switch (which_corner) {
    case Corner::kTopLeft:
      return rect.MinXMinYCorner();
    case Corner::kBottomLeft:
      return rect.MinXMaxYCorner();
    case Corner::kTopRight:
      return rect.MaxXMinYCorner();
  }
  NOTREACHED();
}

// Bounds of the LayoutObject relative to the scroller's visible content rect.
static PhysicalRect RelativeBounds(const LayoutObject* layout_object,
                                   const ScrollableArea* scroller) {
  PhysicalRect local_bounds;
  if (const auto* box = DynamicTo<LayoutBox>(layout_object)) {
    local_bounds = box->PhysicalBorderBoxRect();
    // If we clip overflow then we can use the `PhysicalBorderBoxRect()`
    // as our bounds. If not, we expand the bounds by the scrollable overflow.
    if (!layout_object->ShouldClipOverflowAlongEitherAxis()) {
      // BorderBoxRect doesn't include overflow content and floats.
      LayoutUnit max_y = std::max(local_bounds.Bottom(),
                                  box->ScrollableOverflowRect().Bottom());
      local_bounds.ShiftBottomEdgeTo(max_y);
    }
  } else if (layout_object->IsText()) {
    const auto* text = To<LayoutText>(layout_object);
    // TODO(kojii): |PhysicalLinesBoundingBox()| cannot compute, and thus
    // returns (0, 0) when changes are made that |DeleteLineBoxes()| or clear
    // |SetPaintFragment()|, e.g., |SplitFlow()|. crbug.com/965352
    local_bounds.Unite(text->PhysicalLinesBoundingBox());
  } else {
    // Only LayoutBox and LayoutText are supported.
    NOTREACHED();
  }

  gfx::RectF relative_bounds =
      scroller
          ->LocalToVisibleContentQuad(gfx::QuadF(gfx::RectF(local_bounds)),
                                      layout_object)
          .BoundingBox();

  return PhysicalRect::FastAndLossyFromRectF(relative_bounds);
}

static LogicalOffset ComputeRelativeOffset(const LayoutObject* layout_object,
                                           const ScrollableArea* scroller,
                                           Corner corner) {
  PhysicalOffset offset =
      CornerPointOfRect(RelativeBounds(layout_object, scroller), corner);
  const LayoutBox* scroller_box = ScrollerLayoutBox(scroller);
  return scroller_box->CreateWritingModeConverter().ToLogical(offset, {});
}

static bool CandidateMayMoveWithScroller(const LayoutObject* candidate,
                                         const ScrollableArea* scroller) {
  if (candidate->IsFixedPositioned() ||
      candidate->StyleRef().HasStickyConstrainedPosition())
    return false;

  LayoutObject::AncestorSkipInfo skip_info(ScrollerLayoutBox(scroller));
  candidate->Container(&skip_info);
  return !skip_info.AncestorSkipped();
}

static bool IsOnlySiblingWithTagName(Element* element) {
  DCHECK(element);
  return (1U == NthIndexCache::NthOfTypeIndex(*element)) &&
         (1U == NthIndexCache::NthLastOfTypeIndex(*element));
}

static const AtomicString UniqueClassnameAmongSiblings(Element* element) {
  DCHECK(element);

  auto classname_filter = std::make_unique<ClassnameFilter>();

  Element* parent_element = ElementTraversal::FirstAncestor(*element);
  Element* sibling_element =
      parent_element ? ElementTraversal::FirstChild(*parent_element) : element;
  // Add every classname of every sibling to our bloom filter, starting from the
  // leftmost sibling, but skipping |element|.
  for (; sibling_element;
       sibling_element = ElementTraversal::NextSibling(*sibling_element)) {
    if (sibling_element->HasClass() && sibling_element != element) {
      const SpaceSplitString& class_names = sibling_element->ClassNames();
      for (wtf_size_t i = 0; i < class_names.size(); ++i) {
        classname_filter->Add(class_names[i].Hash());
      }
    }
  }

  const SpaceSplitString& class_names = element->ClassNames();
  for (wtf_size_t i = 0; i < class_names.size(); ++i) {
    // MayContain allows for false positives, but a false positive is relatively
    // harmless; it just means we have to choose a different classname, or in
    // the worst case a different selector.
    if (!classname_filter->MayContain(class_names[i].Hash())) {
      return class_names[i];
    }
  }

  return AtomicString();
}

// Calculate a simple selector for |element| that uniquely identifies it among
// its siblings. If present, the element's id will be used; otherwise, less
// specific selectors are preferred to more specific ones. The ordering of
// selector preference is:
// 1. ID
// 2. Tag name
// 3. Class name
// 4. nth-child
static const String UniqueSimpleSelectorAmongSiblings(Element* element) {
  DCHECK(element);

  if (element->HasID() &&
      !element->GetDocument().ContainsMultipleElementsWithId(
          element->GetIdAttribute())) {
    StringBuilder builder;
    builder.Append("#");
    SerializeIdentifier(element->GetIdAttribute(), builder);
    return builder.ToAtomicString();
  }

  if (IsOnlySiblingWithTagName(element)) {
    StringBuilder builder;
    SerializeIdentifier(element->TagQName().ToString(), builder);
    return builder.ToAtomicString();
  }

  if (element->HasClass()) {
    AtomicString unique_classname = UniqueClassnameAmongSiblings(element);
    if (!unique_classname.empty()) {
      return AtomicString(".") + unique_classname;
    }
  }

  return ":nth-child(" +
         String::Number(NthIndexCache::NthChildIndex(
             *element, /*filter=*/nullptr, /*selector_checker=*/nullptr,
             /*context=*/nullptr)) +
         ")";
}

// Computes a selector that uniquely identifies |anchor_node|. This is done
// by computing a selector that uniquely identifies each ancestor among its
// sibling elements, terminating at a definitively unique ancestor. The
// definitively unique ancestor is either the first ancestor with an id or
// the root of the document. The computed selectors are chained together with
// the child combinator(>) to produce a compound selector that is
// effectively a path through the DOM tree to |anchor_node|.
static const String ComputeUniqueSelector(Node* anchor_node) {
  DCHECK(anchor_node);
  // The scroll anchor can be a pseudo element, but pseudo elements aren't part
  // of the DOM and can't be used as part of a selector. We fail in this case;
  // success isn't possible.
  if (anchor_node->IsPseudoElement()) {
    return String();
  }

  // When the scroll anchor is a shadow DOM element, the selector may be applied
  // to the top document. We fail in this case.
  if (anchor_node->IsInShadowTree()) {
    return String();
  }

  TRACE_EVENT0("blink", "ScrollAnchor::SerializeAnchor");

  Vector<String> selector_list;
  for (Element* element = ElementTraversal::FirstAncestorOrSelf(*anchor_node);
       element; element = ElementTraversal::FirstAncestor(*element)) {
    selector_list.push_back(UniqueSimpleSelectorAmongSiblings(element));
    if (element->HasID() &&
        !element->GetDocument().ContainsMultipleElementsWithId(
            element->GetIdAttribute())) {
      break;
    }
  }

  StringBuilder builder;
  size_t i = 0;
  // We added the selectors tree-upward order from left to right, but css
  // selectors are written tree-downward from left to right. We reverse the
  // order of iteration to get a properly ordered compound selector.
  for (auto reverse_iterator = selector_list.rbegin();
       reverse_iterator != selector_list.rend(); ++reverse_iterator, ++i) {
    if (i)
      builder.Append(">");
    builder.Append(*reverse_iterator);
  }

  if (builder.length() > kMaxSerializedSelectorLength) {
    return String();
  }

  return builder.ToString();
}

static PhysicalRect GetVisibleRect(ScrollableArea* scroller) {
  auto visible_rect =
      ScrollerLayoutBox(scroller)->OverflowClipRect(PhysicalOffset());

  const ComputedStyle* style = ScrollerLayoutBox(scroller)->Style();
  visible_rect.ContractEdges(
      MinimumValueForLength(style->ScrollPaddingTop(), visible_rect.Height()),
      MinimumValueForLength(style->ScrollPaddingRight(), visible_rect.Width()),
      MinimumValueForLength(style->ScrollPaddingBottom(),
                            visible_rect.Height()),
      MinimumValueForLength(style->ScrollPaddingLeft(), visible_rect.Width()));
  return visible_rect;
}

ScrollAnchor::ExamineResult ScrollAnchor::Examine(
    const LayoutObject* candidate) const {
  if (candidate == ScrollerLayoutBox(scroller_))
    return ExamineResult(kContinue);

  if (candidate->StyleRef().OverflowAnchor() == EOverflowAnchor::kNone)
    return ExamineResult(kSkip);

  if (candidate->IsLayoutInline())
    return ExamineResult(kContinue);

  // Anonymous blocks are not in the DOM tree and it may be hard for
  // developers to reason about the anchor node.
  if (candidate->IsAnonymous())
    return ExamineResult(kContinue);

  if (!candidate->IsText() && !candidate->IsBox())
    return ExamineResult(kSkip);

  if (!CandidateMayMoveWithScroller(candidate, scroller_))
    return ExamineResult(kSkip);

  PhysicalRect candidate_rect = RelativeBounds(candidate, scroller_);
  PhysicalRect visible_rect = GetVisibleRect(scroller_);

  bool occupies_space =
      candidate_rect.Width() > 0 && candidate_rect.Height() > 0;
  if (occupies_space && visible_rect.Intersects(candidate_rect)) {
    return ExamineResult(
        visible_rect.Contains(candidate_rect) ? kReturn : kConstrain,
        CornerToAnchor(scroller_));
  } else {
    return ExamineResult(kSkip);
  }
}

void ScrollAnchor::FindAnchor() {
  TRACE_EVENT0("blink", "ScrollAnchor::FindAnchor");

  bool found_priority_anchor = FindAnchorInPriorityCandidates();
  if (!found_priority_anchor)
    FindAnchorRecursive(ScrollerLayoutBox(scroller_));

  if (anchor_object_) {
    anchor_object_->SetIsScrollAnchorObject();
    saved_relative_offset_ =
        ComputeRelativeOffset(anchor_object_, scroller_, corner_);
    TRACE_EVENT_INSTANT(TRACE_DISABLED_BY_DEFAULT("blink.debug"), "FindAnchor",
                        "anchor_object_", anchor_object_->DebugName());
    TRACE_EVENT_INSTANT(TRACE_DISABLED_BY_DEFAULT("blink.debug"), "FindAnchor",
                        "saved_relative_offset_",
                        saved_relative_offset_.ToString());
    anchor_is_cv_auto_without_layout_ =
        DisplayLockUtilities::IsAutoWithoutLayout(*anchor_object_);
  }
}

bool ScrollAnchor::FindAnchorInPriorityCandidates() {
  auto* scroller_box = ScrollerLayoutBox(scroller_);
  if (!scroller_box)
    return false;

  auto& document = scroller_box->GetDocument();

  // Focused area.
  LayoutObject* candidate = nullptr;
  ExamineResult result{kSkip};
  auto* focused_element = document.FocusedElement();
  if (focused_element && IsEditable(*focused_element)) {
    candidate = PriorityCandidateFromNode(focused_element);
    if (candidate) {
      result = ExaminePriorityCandidate(candidate);
      if (IsViable(result.status)) {
        anchor_object_ = candidate;
        corner_ = result.corner;
        return true;
      }
    }
  }

  // Active find-in-page match.
  candidate =
      PriorityCandidateFromNode(document.GetFindInPageActiveMatchNode());
  result = ExaminePriorityCandidate(candidate);
  if (IsViable(result.status)) {
    anchor_object_ = candidate;
    corner_ = result.corner;
    return true;
  }
  return false;
}

LayoutObject* ScrollAnchor::PriorityCandidateFromNode(const Node* node) const {
  while (node) {
    if (auto* layout_object = node->GetLayoutObject()) {
      if (!layout_object->IsAnonymous() &&
          (!layout_object->IsInline() ||
           layout_object->IsAtomicInlineLevel())) {
        return layout_object;
      }
    }
    node = FlatTreeTraversal::Parent(*node);
  }
  return nullptr;
}

ScrollAnchor::ExamineResult ScrollAnchor::ExaminePriorityCandidate(
    const LayoutObject* candidate) const {
  auto* ancestor = candidate;
  auto* scroller_box = ScrollerLayoutBox(scroller_);
  while (ancestor && ancestor != scroller_box) {
    if (ancestor->StyleRef().OverflowAnchor() == EOverflowAnchor::kNone)
      return ExamineResult(kSkip);

    if (!CandidateMayMoveWithScroller(ancestor, scroller_))
      return ExamineResult(kSkip);

    ancestor = ancestor->Parent();
  }
  return ancestor ? Examine(candidate) : ExamineResult(kSkip);
}

ScrollAnchor::WalkStatus ScrollAnchor::FindAnchorRecursive(
    LayoutObject* candidate) {
  if (!candidate->EverHadLayout()) {
    return kSkip;
  }
  ExamineResult result = Examine(candidate);
  WalkStatus status = result.status;
  if (IsViable(status)) {
    anchor_object_ = candidate;
    corner_ = result.corner;
  }

  if (status == kReturn || status == kSkip)
    return status;

  bool is_block_fragmentation_context_root =
      IsNGBlockFragmentationRoot(DynamicTo<LayoutBlockFlow>(candidate));

  for (LayoutObject* child = candidate->SlowFirstChild(); child;
       child = child->NextSibling()) {
    WalkStatus child_status = FindAnchorRecursive(child);
    if (child_status == kReturn)
      return child_status;
    if (child_status == kConstrain) {
      // We have found an anchor, but it's not fully contained within the
      // viewport. If this is an NG block fragmentation context root, break now
      // to search for OOFs inside the fragmentainers, which may provide a
      // better anchor.
      if (is_block_fragmentation_context_root) {
        status = child_status;
        break;
      }
      return child_status;
    }
  }

  // Make a separate pass to catch positioned descendants with a static DOM
  // parent that we skipped over (crbug.com/692701).
  WalkStatus oof_status = FindAnchorInOOFs(candidate);
  if (IsViable(oof_status))
    return oof_status;

  return status;
}

ScrollAnchor::WalkStatus ScrollAnchor::FindAnchorInOOFs(
    LayoutObject* candidate) {
  auto* layout_block = DynamicTo<LayoutBlock>(candidate);
  if (!layout_block)
    return kSkip;

  // Look for OOF child fragments. If we're at a fragmentation context root,
  // this means that we need to look for them inside the fragmentainers (which
  // are children of fragmentation context root fragments), because then an OOF
  // is normally a direct child of a fragmentainer, not its actual containing
  // block.
  //
  // Be aware that the scroll anchor machinery often operates on a dirty layout
  // tree, which means that the LayoutObject that once generated the fragment
  // may have been deleted (but the fragment may still be around). In such cases
  // the LayoutObject associated with the fragment will be set to nullptr, so we
  // need to check for that.
  bool is_block_fragmentation_context_root =
      IsNGBlockFragmentationRoot(DynamicTo<LayoutBlockFlow>(layout_block));
  for (const PhysicalBoxFragment& fragment :
       layout_block->PhysicalFragments()) {
    if (!fragment.HasOutOfFlowFragmentChild() &&
        !is_block_fragmentation_context_root)
      continue;

    for (const PhysicalFragmentLink& child : fragment.Children()) {
      if (child->IsOutOfFlowPositioned()) {
        LayoutObject* layout_object = child->GetMutableLayoutObject();
        if (layout_object && layout_object->Parent() != candidate) {
          WalkStatus status = FindAnchorRecursive(layout_object);
          if (IsViable(status))
            return status;
        }
        continue;
      }
      if (!is_block_fragmentation_context_root ||
          !child->IsFragmentainerBox() || !child->HasOutOfFlowFragmentChild())
        continue;

      // Look for OOFs inside a fragmentainer.
      for (const PhysicalFragmentLink& grandchild : child->Children()) {
        if (!grandchild->IsOutOfFlowPositioned())
          continue;
        LayoutObject* layout_object = grandchild->GetMutableLayoutObject();
        if (layout_object) {
          WalkStatus status = FindAnchorRecursive(layout_object);
          if (IsViable(status))
            return status;
        }
      }
    }
  }

  return kSkip;
}

bool ScrollAnchor::ComputeScrollAnchorDisablingStyleChanged() {
  LayoutObject* current = AnchorObject();
  if (!current)
    return false;

  LayoutObject* scroller_box = ScrollerLayoutBox(scroller_);
  while (true) {
    DCHECK(current);
    if (current->ScrollAnchorDisablingStyleChanged())
      return true;
    if (current == scroller_box)
      return false;
    current = current->Parent();
  }
}

void ScrollAnchor::NotifyBeforeLayout() {
  if (queued_) {
    scroll_anchor_disabling_style_changed_ |=
        ComputeScrollAnchorDisablingStyleChanged();
    return;
  }
  DCHECK(scroller_);
  ScrollOffset scroll_offset = scroller_->GetScrollOffset();
  float block_direction_scroll_offset =
      ScrollerLayoutBox(scroller_)->IsHorizontalWritingMode()
          ? scroll_offset.y()
          : scroll_offset.x();
  if (block_direction_scroll_offset == 0) {
    ClearSelf();
    return;
  }

  if (!anchor_object_) {
    // FindAnchor() and ComputeRelativeOffset() query a box's borders as part of
    // its geometry. But when collapsed, table borders can depend on internal
    // parts, which get sorted during a layout pass. When a table with dirty
    // internal structure is checked as an anchor candidate, a DCHECK was hit.
    FindAnchor();
    if (!anchor_object_)
      return;
  }

  scroll_anchor_disabling_style_changed_ =
      ComputeScrollAnchorDisablingStyleChanged();

  LocalFrameView* frame_view = ScrollerLayoutBox(scroller_)->GetFrameView();
  auto* root_frame_viewport = DynamicTo<RootFrameViewport>(scroller_.Get());
  ScrollableArea* owning_scroller = root_frame_viewport
                                        ? &root_frame_viewport->LayoutViewport()
                                        : scroller_.Get();
  frame_view->EnqueueScrollAnchoringAdjustment(owning_scroller);
  queued_ = true;
}

gfx::Vector2d ScrollAnchor::ComputeAdjustment() const {
  // The anchor node can report fractional positions, but it is DIP-snapped when
  // painting (crbug.com/610805), so we must round the offsets to determine the
  // visual delta. If we scroll by the delta in LayoutUnits, the snapping of the
  // anchor node may round differently from the snapping of the scroll position.
  // (For example, anchor moving from 2.4px -> 2.6px is really 2px -> 3px, so we
  // should scroll by 1px instead of 0.2px.) This is true regardless of whether
  // the ScrollableArea actually uses fractional scroll positions.
  gfx::Vector2d delta = ToRoundedVector2d(ComputeRelativeOffset(
                            anchor_object_, scroller_, corner_)) -
                        ToRoundedVector2d(saved_relative_offset_);

  PhysicalRect anchor_rect = RelativeBounds(anchor_object_, scroller_);
  TRACE_EVENT_INSTANT(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
                      "ComputeAdjustment", "anchor_object_",
                      anchor_object_->DebugName());
  TRACE_EVENT_INSTANT(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
                      "ComputeAdjustment", "delta", delta.ToString());

  // Only adjust on the block layout axis.
  const LayoutBox* scroller_box = ScrollerLayoutBox(scroller_);
  delta.set_x(0);
  if (!scroller_box->IsHorizontalWritingMode()) {
    delta.Transpose();
  }

  if (anchor_is_cv_auto_without_layout_) {
    // See the effect delta would have on the anchor rect.
    // If the anchor is now off-screen (in block direction) then make sure it's
    // just at the edge.
    anchor_rect.Move(-PhysicalOffset(delta));
    if (scroller_box->IsHorizontalWritingMode()) {
      if (anchor_rect.Bottom() < 0) {
        delta.set_y(delta.y() + anchor_rect.Bottom().ToInt());
      }
    } else {
      // For the flipped blocks writing mode, we need to adjust the offset to
      // align the opposite edge of the block (MaxX edge instead of X edge).
      if (scroller_box->HasFlippedBlocksWritingMode()) {
        auto visible_rect = GetVisibleRect(scroller_);
        if (anchor_rect.X() > visible_rect.Right()) {
          delta.set_x(delta.x() -
                      (anchor_rect.X().ToInt() - visible_rect.Right().ToInt()));
        }
      } else if (anchor_rect.Right() < 0) {
        delta.set_x(delta.x() + anchor_rect.Right().ToInt());
      }
    }
  }

  // If block direction is flipped, delta is a logical value, so flip it to
  // make it physical.
  if (!scroller_box->IsHorizontalWritingMode() &&
      scroller_box->HasFlippedBlocksWritingMode()) {
    delta.set_x(-delta.x());
  }
  return delta;
}

void ScrollAnchor::Adjust() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
               "ScrollAnchor::Adjust");
  if (!queued_)
    return;
  queued_ = false;
  DCHECK(scroller_);
  if (!anchor_object_)
    return;
  gfx::Vector2d adjustment = ComputeAdjustment();
  TRACE_EVENT_INSTANT(TRACE_DISABLED_BY_DEFAULT("blink.debug"), "Adjust",
                      "adjustment", adjustment.ToString());

  // We should pick a new anchor if we had an unlaid-out content-visibility
  // auto. It should have been laid out, so if it is still the best candidate,
  // we will select it without this boolean set.
  if (anchor_is_cv_auto_without_layout_)
    ClearSelf();

  if (adjustment.IsZero())
    return;

  if (scroll_anchor_disabling_style_changed_) {
    // Note that we only clear if the adjustment would have been non-zero.
    // This minimizes redundant calls to findAnchor.
    ClearSelf();
    return;
  }

  ScrollOffset new_offset =
      scroller_->GetScrollOffset() + ScrollOffset(adjustment);

  TRACE_EVENT_INSTANT(TRACE_DISABLED_BY_DEFAULT("blink.debug"), "Adjust",
                      "new_offset", new_offset.ToString());

  scroller_->SetScrollOffset(new_offset, mojom::blink::ScrollType::kAnchoring);

  UseCounter::Count(ScrollerLayoutBox(scroller_)->GetDocument(),
                    WebFeature::kScrollAnchored);
}

bool ScrollAnchor::RestoreAnchor(const SerializedAnchor& serialized_anchor) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
               "ScrollAnchor::RestoreAnchor");
  if (!scroller_ || !serialized_anchor.IsValid()) {
    return false;
  }

  if (anchor_object_ && serialized_anchor.selector == saved_selector_) {
    return true;
  }

  if (anchor_object_) {
    return false;
  }

  Document* document = &(ScrollerLayoutBox(scroller_)->GetDocument());

  // This is a considered and deliberate usage of DummyExceptionStateForTesting.
  // We really do want to always swallow it. Here's why:
  // 1) We have no one to propagate an exception to.
  // 2) We don't want to rely on having an isolate(which normal ExceptionState
  // does), as this requires setting up and using javascript/v8. This is
  // undesirable since it needlessly prevents us from running when javascript is
  // disabled, and causes proxy objects to be prematurely
  // initialized(crbug.com/810897).
  DummyExceptionStateForTesting exception_state;
  StaticElementList* found_elements = document->QuerySelectorAll(
      AtomicString(serialized_anchor.selector), exception_state);

  if (exception_state.HadException()) {
    return false;
  }

  if (found_elements->length() < 1) {
    return false;
  }

  TRACE_EVENT_INSTANT(TRACE_DISABLED_BY_DEFAULT("blink.debug"), "RestoreAnchor",
                      "found_elements_length", found_elements->length());

  for (unsigned index = 0; index < found_elements->length(); index++) {
    Element* anchor_element = found_elements->item(index);
    LayoutObject* anchor_object = anchor_element->GetLayoutObject();

    if (!anchor_object) {
      continue;
    }

    // There are scenarios where the layout object we find is non-box and
    // non-text; this can happen, e.g., if the original anchor object was a text
    // element of a non-box element like <code>. The generated selector can't
    // directly locate the text object, resulting in a loss of precision.
    // Instead we scroll the object we do find into the same relative position
    // and attempt to re-find the anchor. The user-visible effect should end up
    // roughly the same.
    ScrollOffset current_offset = scroller_->GetScrollOffset();
    gfx::RectF bounding_box = anchor_object->AbsoluteBoundingBoxRectF();
    WritingMode writing_mode = anchor_object->Style()->GetWritingMode();
    gfx::PointF location_point =
        IsFlippedBlocksWritingMode(writing_mode)   ? bounding_box.top_right()
        : writing_mode == WritingMode::kSidewaysLr ? bounding_box.bottom_left()
                                                   : bounding_box.origin();
    gfx::PointF desired_point = location_point + current_offset;

    ScrollOffset desired_offset = desired_point.OffsetFromOrigin();
    ScrollOffset delta = serialized_anchor.GetScrollOffset(*scroller_);
    desired_offset -= delta;
    TRACE_EVENT_INSTANT(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
                        "RestoreAnchor", "anchor_object",
                        anchor_object->DebugName());
    scroller_->SetScrollOffset(desired_offset,
                               mojom::blink::ScrollType::kAnchoring);
    FindAnchor();

    // If the above FindAnchor call failed, reset the scroll position and try
    // again with the next found element.
    if (!anchor_object_) {
      scroller_->SetScrollOffset(current_offset,
                                 mojom::blink::ScrollType::kAnchoring);
      continue;
    }

    saved_selector_ = serialized_anchor.selector;
    return true;
  }

  return false;
}

const SerializedAnchor ScrollAnchor::GetSerializedAnchor() {
  if (auto* scroller_box = ScrollerLayoutBox(scroller_)) {
    // This method may be called to find a serialized anchor on a document which
    // needs a lifecycle update. Computing offsets below may currently compute
    // style for ::first-line. If that is done with dirty active stylesheets, we
    // may have null pointer crash as style computation assumes active sheets
    // are up to date. Update active style if necessary here.
    scroller_box->GetDocument().GetStyleEngine().UpdateActiveStyle();
  }

  // It's safe to return saved_selector_ before checking anchor_object_, since
  // clearing anchor_object_ also clears saved_selector_.
  if (!saved_selector_.empty()) {
    DCHECK(anchor_object_);
    return SerializedAnchor(
        saved_selector_,
        ComputeRelativeOffset(anchor_object_, scroller_, corner_));
  }

  if (!anchor_object_) {
    FindAnchor();
    if (!anchor_object_)
      return SerializedAnchor();
  }

  DCHECK(anchor_object_->GetNode());
  SerializedAnchor new_anchor(
      ComputeUniqueSelector(anchor_object_->GetNode()),
      ComputeRelativeOffset(anchor_object_, scroller_, corner_));

  if (new_anchor.IsValid()) {
    saved_selector_ = new_anchor.selector;
  }

  return new_anchor;
}

void ScrollAnchor::ClearSelf() {
  LayoutObject* anchor_object = anchor_object_;
  anchor_object_ = nullptr;
  saved_selector_ = String();

  if (anchor_object)
    anchor_object->MaybeClearIsScrollAnchorObject();
}

void ScrollAnchor::Dispose() {
  if (scroller_) {
    LocalFrameView* frame_view = ScrollerLayoutBox(scroller_)->GetFrameView();
    auto* root_frame_viewport = DynamicTo<RootFrameViewport>(scroller_.Get());
    ScrollableArea* owning_scroller =
        root_frame_viewport ? &root_frame_viewport->LayoutViewport()
                            : scroller_.Get();
    frame_view->DequeueScrollAnchoringAdjustment(owning_scroller);
    scroller_.Clear();
  }
  anchor_object_ = nullptr;
  saved_selector_ = String();
}

void ScrollAnchor::Clear() {
  LayoutObject* layout_object =
      anchor_object_ ? anchor_object_ : ScrollerLayoutBox(scroller_);
  PaintLayer* layer = nullptr;
  if (LayoutObject* parent = layout_object->Parent())
    layer = parent->EnclosingLayer();

  // Walk up the layer tree to clear any scroll anchors.
  while (layer) {
    if (PaintLayerScrollableArea* scrollable_area =
            layer->GetScrollableArea()) {
      ScrollAnchor* anchor = scrollable_area->GetScrollAnchor();
      DCHECK(anchor);
      anchor->ClearSelf();
    }
    layer = layer->Parent();
  }
}

bool ScrollAnchor::RefersTo(const LayoutObject* layout_object) const {
  return anchor_object_ == layout_object;
}

void ScrollAnchor::NotifyRemoved(LayoutObject* layout_object) {
  if (anchor_object_ == layout_object)
    ClearSelf();
}

}  // namespace blink
```