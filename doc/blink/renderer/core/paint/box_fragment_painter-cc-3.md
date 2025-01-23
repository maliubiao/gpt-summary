Response:
The user is asking for a summary of the `BoxFragmentPainter::HitTest*` methods in the provided code snippet, which is the last part of the file. The focus should be on the functionality related to hit testing.

**Plan:**

1. **Identify the primary function:** The main purpose of these methods is to determine if a given point intersects with elements rendered within a `BoxFragment`. This is part of the hit testing process in Blink.
2. **Categorize the different `HitTest*` methods:** Notice there are methods for different types of children (inline, block, floats), different phases of hit testing, and specific scenarios like clipped content or overflow controls.
3. **Explain the relationship to web technologies:** Connect the concepts of `BoxFragment`, layout, and hit testing to user interactions in HTML, CSS, and JavaScript (e.g., clicking, hovering).
4. **Infer logic and provide examples:** Based on the code, deduce how the hit testing is performed (e.g., checking bounding boxes, recursive descent) and create simple scenarios with input and expected output.
5. **Identify potential user errors:**  Consider how incorrect styling or JavaScript handling could lead to unexpected hit testing behavior.
6. **Describe the user journey:** Explain how user actions trigger the hit testing process, leading to the execution of this code.
7. **Summarize the overall functionality.**

**Detailed Breakdown:**

* **`HitTestAllPhasesInFragment`:**  This seems like a recursive call to perform hit testing within a fragment for all phases.
* **`NodeAtPointInFragment`:** This is likely the core function that orchestrates hit testing within a `BoxFragment`.
* **`HitTestInlineChildBoxFragment`:** Handles hit testing for inline elements. It differentiates between floats and non-floats and considers atomic painting.
* **`HitTestChildBoxItem`:** Deals with `FragmentItem` of type `kBox`. It has special handling for SVG inline elements.
* **`HitTestChildren` (multiple overloads):**  This method recursively traverses the children of a `BoxFragment` to perform hit testing. It handles both inline and block children.
* **`HitTestBlockChildren`:** Specifically for block-level children.
* **`ShouldHitTestCulledInlineAncestors`:**  Determines if culled (not visible) inline ancestors should be considered during hit testing, potentially for events like `ondragenter`.
* **`HitTestItemsChildren`:**  Handles hit testing of children represented by `FragmentItem`s.
* **`HitTestFloatingChildren` / `HitTestFloatingChildItems`:** Specifically for floating elements.
* **`HitTestClippedOutByBorder`:** Checks if the hit point is within the visible area after considering borders.
* **`HitTestOverflowControl`:** Handles hit testing for scrollbars and other overflow controls.
* **`VisualRect`:**  Calculates the visual rectangle of the fragment.

By following this plan, I can generate a comprehensive and accurate summary that addresses all aspects of the user's request.
这是对 `blink/renderer/core/paint/box_fragment_painter.cc` 文件内容的第 4 部分的总结，主要关注的是 `HitTest` 相关的功能。结合之前几部分的内容，我们可以归纳出 `BoxFragmentPainter` 的主要职责是负责渲染盒模型片段（`BoxFragment`）以及处理与这些片段的交互，而 `HitTest` 功能则是交互的核心部分，用于确定用户在屏幕上的点击位置对应到哪个渲染对象。

**BoxFragmentPainter 的 HitTest 功能归纳：**

这部分代码主要实现了 `BoxFragmentPainter` 中用于命中测试（Hit Testing）的相关方法。命中测试是指当用户在浏览器窗口中进行点击操作时，浏览器需要判断用户点击到了哪个页面元素。`BoxFragmentPainter` 在这个过程中负责判断点击位置是否在当前 `BoxFragment` 所代表的渲染盒子的范围内，以及递归地检查其子元素。

**核心功能点：**

1. **`HitTestAllPhasesInFragment`:**  这是一个通用的方法，用于在一个 `PhysicalFragment` 上执行所有阶段的命中测试。这意味着它会检查背景、边框、内容、前景等各个部分。

2. **`NodeAtPointInFragment`:**  这个方法是进行命中测试的核心。它接收一个 `PhysicalFragment`、一个点击位置 `HitTestLocation`、一个偏移量 `accumulated_offset`、一个命中测试阶段 `HitTestPhase` 和一个命中测试结果 `HitTestResult`。它的作用是判断给定的点击位置是否在这个 `Fragment` 内，并将其包含的节点信息添加到 `HitTestResult` 中。

3. **`HitTestInlineChildBoxFragment`:**  专门用于命中测试内联盒子的子片段。它会区分浮动元素和非浮动元素，并且会考虑是否处于原子绘制阶段。

4. **`HitTestChildBoxItem`:**  用于命中测试作为 `FragmentItem` 存在的子盒子。它特别处理了 SVG 内联元素的情况。对于 SVG `<text>` 元素，由于其 `kBox` 类型的 `FragmentItem` 没有最终的几何信息，所以需要特殊处理，直接使用布局对象的边界框进行命中测试。

5. **`HitTestChildren` (多个重载版本):**  用于递归地命中测试当前 `BoxFragment` 的子元素。它区分了内联盒子和块级盒子，并使用了 `InlineCursor` 来遍历内联子元素。

6. **`HitTestBlockChildren`:**  专门用于命中测试块级子元素。它会跳过具有独立绘制层或浮动的子元素。

7. **`ShouldHitTestCulledInlineAncestors`:**  判断是否应该命中测试被裁剪掉的内联祖先元素。这对于某些事件（如 `ondragenter`）来说很重要，即使元素不可见也可能需要触发事件。

8. **`HitTestItemsChildren`:**  用于命中测试由 `FragmentItem` 表示的子元素。它会遍历 `InlineCursor` 指向的子元素列表，并根据 `FragmentItem` 的类型（文本、行框、盒子）调用相应的命中测试方法。

9. **`HitTestFloatingChildren` 和 `HitTestFloatingChildItems`:**  专门用于命中测试浮动子元素。因为浮动元素可能会散落在整个内联格式化上下文中，所以需要单独处理。

10. **`HitTestClippedOutByBorder`:**  判断点击位置是否被元素的边框裁剪掉。

11. **`HitTestOverflowControl`:**  用于命中测试溢出控制条（如滚动条）。

12. **`VisualRect`:**  计算 `BoxFragment` 的可视矩形区域。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** `BoxFragmentPainter` 处理的是 HTML 元素渲染后的片段。当用户在 HTML 页面上点击时，浏览器会使用这些 `HitTest` 方法来确定点击发生在哪个 HTML 元素上。
* **CSS:** CSS 样式决定了元素的布局和渲染方式，包括元素的尺寸、位置、是否浮动等。这些样式信息会影响 `BoxFragment` 的生成以及 `HitTest` 方法的执行逻辑。例如，元素的 `overflow` 属性会影响是否需要命中测试溢出控制条。
* **JavaScript:** 当用户点击页面元素时，浏览器会触发相应的 JavaScript 事件（如 `click` 事件）。`BoxFragmentPainter` 的 `HitTest` 功能是确定触发哪个元素的事件的关键步骤。例如，如果一个按钮元素被点击，`HitTest` 过程会找到这个按钮对应的 `BoxFragment`，然后浏览器会将点击事件传递给该按钮的 JavaScript 事件处理程序。

**举例说明：**

**假设输入：** 用户点击屏幕坐标 (100, 150)。

**场景 1： 简单的块级元素**

* **HTML:** `<div style="width: 200px; height: 100px; position: absolute; top: 100px; left: 50px;"></div>`
* **`BoxFragment`:**  `BoxFragmentPainter` 针对这个 `div` 创建了一个 `BoxFragment`，其边界为 (50, 100) 到 (250, 200)。
* **`HitTest` 过程:** `NodeAtPointInFragment` 会检查点击坐标 (100, 150) 是否在这个 `BoxFragment` 的边界内。因为 50 <= 100 <= 250 且 100 <= 150 <= 200，所以命中测试成功，该 `div` 元素会被认为是点击目标。

**场景 2： 内联元素和浮动元素**

* **HTML:** `<span>Text <div style="float: left; width: 50px; height: 50px;">Float</div> more text</span>`
* **`BoxFragment`:** 会创建文本的 `BoxFragment` 和浮动 `div` 的 `BoxFragment`。
* **`HitTest` 过程:** 如果点击位置在浮动 `div` 的范围内，`HitTestInlineChildBoxFragment` 会被调用，并且由于该子片段是浮动的，会进入相应的浮动元素命中测试逻辑。

**逻辑推理：**

这些 `HitTest` 方法的核心逻辑是几何上的包含关系判断。它们会计算或获取 `BoxFragment` 的边界矩形，然后判断给定的点击位置是否在该矩形内。对于复杂的布局（如包含内联元素、浮动元素等），需要递归地遍历子元素和考虑不同的渲染特性。

**用户或编程常见的使用错误：**

1. **`z-index` 混乱导致的点击穿透:** 用户可能设置了不合理的 `z-index` 值，导致一个元素覆盖在另一个元素之上，但由于 `HitTest` 的顺序或逻辑问题，点击事件可能被错误地传递给下方的元素。
2. **`pointer-events: none;` 的滥用:**  开发者可能会错误地为元素设置 `pointer-events: none;`，导致该元素无法接收任何鼠标事件，即使该元素在视觉上是可见的且用户期望与之交互。
3. **绝对定位和层叠上下文问题:**  当元素使用绝对定位时，其层叠关系可能变得复杂，导致用户点击预期位置但实际命中的是其他元素。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中打开一个网页。**
2. **网页加载并渲染完成，`BoxFragmentPainter` 创建了页面的渲染片段。**
3. **用户移动鼠标到网页上的某个位置。** (可能触发 hover 效果，但主要针对点击)
4. **用户点击鼠标左键。**
5. **浏览器接收到点击事件，并需要确定点击发生在哪个元素上。**
6. **浏览器开始执行命中测试过程。**
7. **对于屏幕上的点击位置，浏览器会从根 `BoxFragment` 开始，递归地调用 `BoxFragmentPainter` 的 `HitTest` 相关方法。**
8. **`NodeAtPoint` 方法会被调用，并向下遍历 `BoxFragment` 树。**
9. **如果当前 `BoxFragment` 包含内联元素，可能会调用 `HitTestInlineChildBoxFragment`。**
10. **如果包含浮动元素，可能会调用 `HitTestFloatingChildren`。**
11. **最终，如果点击位置落在某个元素的 `BoxFragment` 内，该元素会被确定为命中目标。**
12. **浏览器会将相应的事件（例如 `click`）分发给该目标元素。**

**总结 `BoxFragmentPainter` 的功能（结合所有部分）：**

综合来看，`BoxFragmentPainter` 在 Blink 渲染引擎中扮演着至关重要的角色，其主要功能可以归纳如下：

1. **负责渲染盒模型片段 (`BoxFragment`)：** 它根据布局信息和样式计算，将页面元素渲染成一个个可视化的片段，管理这些片段的绘制过程。
2. **处理背景和边框的绘制：** 负责绘制盒子的背景颜色、背景图片、边框样式等视觉效果。
3. **处理盒子的内容绘制：**  虽然不是直接绘制文本或图片内容，但它负责协调这些内容的绘制过程。
4. **支持各种复杂的渲染特性：** 包括处理圆角边框、阴影、滤镜、遮罩等高级 CSS 特性。
5. **执行命中测试 (`HitTest`)：**  这是与用户交互的关键，用于确定用户在屏幕上的点击位置对应到哪个渲染对象，从而触发相应的事件。
6. **管理和遍历渲染片段树：** 通过 `PhysicalFragment` 之间的连接关系，能够遍历整个渲染树，进行绘制和命中测试。
7. **考虑不同的渲染阶段：** 命中测试会区分不同的阶段（背景、前景、浮动等），以确保所有相关的元素都能被正确命中。
8. **处理内联、块级和浮动等不同的布局模式：** 针对不同的布局方式，有专门的 `HitTest` 方法进行处理。
9. **与布局引擎紧密协作：**  `BoxFragmentPainter` 依赖布局引擎提供的布局信息来创建和定位渲染片段。
10. **作为渲染流程的一部分：**  它是 Blink 渲染流水线中的一个重要环节，负责将布局信息转化为屏幕上的像素。

总而言之，`BoxFragmentPainter` 是 Blink 渲染引擎中负责盒子模型渲染和交互的核心组件之一，其 `HitTest` 功能是实现用户与网页交互的基础。

### 提示词
```
这是目录为blink/renderer/core/paint/box_fragment_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
IsBlockInInline()) {
    // "fast/events/ondragenter.html" reaches here.
    return false;
  }

  return hit_test.AddNodeToResultWithContentOffset(
      fragment.NodeForHitTest(), box_fragment_, bounds_rect,
      physical_offset - cursor.Current().OffsetInContainerFragment());
}

bool BoxFragmentPainter::HitTestInlineChildBoxFragment(
    const HitTestContext& hit_test,
    const PhysicalBoxFragment& fragment,
    const InlineBackwardCursor& backward_cursor,
    const PhysicalOffset& physical_offset) {
  bool is_in_atomic_painting_pass;

  // Note: Floats should only be hit tested in the |kFloat| phase, so we
  // shouldn't enter a float when |phase| doesn't match. However, as floats may
  // scatter around in the entire inline formatting context, we should always
  // enter non-floating inline child boxes to search for floats in the
  // |kHitTestFloat| phase, unless the child box forms another context.
  if (fragment.IsFloating()) {
    if (hit_test.phase != HitTestPhase::kFloat)
      return false;
    is_in_atomic_painting_pass = true;
  } else {
    is_in_atomic_painting_pass = hit_test.phase == HitTestPhase::kForeground;
  }

  if (fragment.IsPaintedAtomically()) {
    if (!is_in_atomic_painting_pass) {
      return false;
    }
    return HitTestAllPhasesInFragment(fragment, hit_test.location,
                                      physical_offset, hit_test.result);
  }
  InlineCursor cursor(backward_cursor);
  const FragmentItem* item = cursor.Current().Item();
  DCHECK(item);
  DCHECK_EQ(item->BoxFragment(), &fragment);
  if (!fragment.MayIntersect(*hit_test.result, hit_test.location,
                             physical_offset)) {
    return false;
  }

  if (fragment.IsInlineBox()) {
    return BoxFragmentPainter(cursor, *item, fragment, inline_context_)
        .NodeAtPoint(hit_test, physical_offset);
  }

  DCHECK(fragment.IsBlockInInline());
  return BoxFragmentPainter(fragment).NodeAtPoint(hit_test, physical_offset);
}

bool BoxFragmentPainter::HitTestChildBoxItem(
    const HitTestContext& hit_test,
    const PhysicalBoxFragment& container,
    const FragmentItem& item,
    const InlineBackwardCursor& cursor) {
  DCHECK_EQ(&item, cursor.Current().Item());

  // Box fragments for SVG's inline boxes don't have correct geometries.
  if (!item.GetLayoutObject()->IsSVGInline()) {
    const PhysicalBoxFragment* child_fragment = item.BoxFragment();
    DCHECK(child_fragment);
    const PhysicalOffset child_offset =
        hit_test.inline_root_offset + item.OffsetInContainerFragment();
    return HitTestInlineChildBoxFragment(hit_test, *child_fragment, cursor,
                                         child_offset);
  }

  DCHECK(item.GetLayoutObject()->IsLayoutInline());
  if (InlineCursor descendants = cursor.CursorForDescendants()) {
    if (HitTestItemsChildren(hit_test, container, descendants))
      return true;
  }

  DCHECK(cursor.ContainerFragment().IsSvgText());
  if (item.Style().UsedPointerEvents() != EPointerEvents::kBoundingBox)
    return false;
  // Now hit test ourselves.
  if (hit_test.phase != HitTestPhase::kForeground ||
      !IsVisibleToHitTest(item, hit_test.result->GetHitTestRequest()))
    return false;
  // In SVG <text>, we should not refer to the geometry of kBox
  // FragmentItems because they don't have final values.
  auto bounds_rect =
      PhysicalRect::EnclosingRect(item.GetLayoutObject()->ObjectBoundingBox());
  return hit_test.location.Intersects(bounds_rect) &&
         hit_test.AddNodeToResultWithContentOffset(
             item.NodeForHitTest(), cursor.ContainerFragment(), bounds_rect,
             bounds_rect.offset);
}

bool BoxFragmentPainter::HitTestChildren(
    const HitTestContext& hit_test,
    const PhysicalOffset& accumulated_offset) {
  if (inline_box_cursor_) [[unlikely]] {
    InlineCursor descendants = inline_box_cursor_->CursorForDescendants();
    if (descendants) {
      return HitTestChildren(hit_test, GetPhysicalFragment(), descendants,
                             accumulated_offset);
    }
    return false;
  }
  if (items_) {
    const PhysicalBoxFragment& fragment = GetPhysicalFragment();
    InlineCursor cursor(fragment, *items_);
    return HitTestChildren(hit_test, fragment, cursor, accumulated_offset);
  }
  // Check descendants of this fragment because floats may be in the
  // |FragmentItems| of the descendants.
  if (hit_test.phase == HitTestPhase::kFloat) {
    return box_fragment_.HasFloatingDescendantsForPaint() &&
           HitTestFloatingChildren(hit_test, box_fragment_, accumulated_offset);
  }
  return HitTestBlockChildren(*hit_test.result, hit_test.location,
                              accumulated_offset, hit_test.phase);
}

bool BoxFragmentPainter::HitTestChildren(
    const HitTestContext& hit_test,
    const PhysicalBoxFragment& container,
    const InlineCursor& children,
    const PhysicalOffset& accumulated_offset) {
  if (children.HasRoot())
    return HitTestItemsChildren(hit_test, container, children);
  // Hits nothing if there were no children.
  return false;
}

bool BoxFragmentPainter::HitTestBlockChildren(
    HitTestResult& result,
    const HitTestLocation& hit_test_location,
    PhysicalOffset accumulated_offset,
    HitTestPhase phase) {
  if (phase == HitTestPhase::kDescendantBlockBackgrounds)
    phase = HitTestPhase::kSelfBlockBackground;
  auto children = box_fragment_.Children();
  for (const PhysicalFragmentLink& child : base::Reversed(children)) {
    const auto& block_child = To<PhysicalBoxFragment>(*child);
    if (block_child.IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
      continue;
    }
    if (block_child.HasSelfPaintingLayer() || block_child.IsFloating())
      continue;

    const PhysicalOffset child_offset = accumulated_offset + child.offset;

    if (block_child.IsPaintedAtomically()) {
      if (phase != HitTestPhase::kForeground)
        continue;
      if (!HitTestAllPhasesInFragment(block_child, hit_test_location,
                                      child_offset, &result))
        continue;
    } else {
      if (!NodeAtPointInFragment(block_child, hit_test_location, child_offset,
                                 phase, &result))
        continue;
    }

    if (result.InnerNode())
      return true;

    if (Node* node = block_child.NodeForHitTest()) {
      result.SetNodeAndPosition(node, &block_child,
                                hit_test_location.Point() - accumulated_offset);
      return true;
    }

    // Our child may have been an anonymous-block, update the hit-test node
    // to include our node if needed.
    Node* node = box_fragment_.NodeForHitTest();
    if (!node)
      return true;

    // Note: |accumulated_offset| includes container scrolled offset added
    // in |BoxFragmentPainter::NodeAtPoint()|. See http://crbug.com/1268782
    const PhysicalOffset scrolled_offset =
        box_fragment_.IsScrollContainer()
            ? PhysicalOffset(box_fragment_.PixelSnappedScrolledContentOffset())
            : PhysicalOffset();
    result.SetNodeAndPosition(
        node, &box_fragment_,
        hit_test_location.Point() - accumulated_offset - scrolled_offset);
    return true;
  }

  return false;
}

// static
bool BoxFragmentPainter::ShouldHitTestCulledInlineAncestors(
    const HitTestContext& hit_test,
    const FragmentItem& item) {
  if (hit_test.phase != HitTestPhase::kForeground)
    return false;
  if (item.Type() == FragmentItem::kLine) {
    return false;
  }
  if (hit_test.result->GetHitTestRequest().ListBased()) {
    // For list base hit test, we should include culled inline into list.
    // DocumentOrShadowRoot-prototype-elementFromPoint.html requires this.
    return true;
  }
  if (item.IsBlockInInline()) {
    // To handle, empty size <div>, we skip hit testing on culled inline box.
    // See "fast/events/ondragenter.html".
    //
    // Culled inline should be handled by item in another line for block-in-
    // inline, e.g. <span>a<div>b</div></span>.
    return false;
  }
  return true;
}

bool BoxFragmentPainter::HitTestItemsChildren(
    const HitTestContext& hit_test,
    const PhysicalBoxFragment& container,
    const InlineCursor& children) {
  DCHECK(children.HasRoot());
  for (InlineBackwardCursor cursor(children); cursor;) {
    const FragmentItem* item = cursor.Current().Item();
    DCHECK(item);
    if (item->IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
      // TODO(crbug.com/1099613): This should not happen, as long as it is
      // really layout-clean.
      NOTREACHED();
    }

    if (item->HasSelfPaintingLayer()) {
      cursor.MoveToPreviousSibling();
      continue;
    }

    if (item->IsText()) {
      if (HitTestTextItem(hit_test, *item, cursor))
        return true;
    } else if (item->Type() == FragmentItem::kLine) {
      const PhysicalLineBoxFragment* child_fragment = item->LineBoxFragment();
      if (child_fragment) {  // Top-level kLine items.
        const PhysicalOffset child_offset =
            hit_test.inline_root_offset + item->OffsetInContainerFragment();
        if (HitTestLineBoxFragment(hit_test, *child_fragment, cursor,
                                   child_offset)) {
          return true;
        }
      } else {  // Nested kLine items for ruby annotations.
        if (HitTestItemsChildren(hit_test, container,
                                 cursor.CursorForDescendants())) {
          return true;
        }
      }
    } else if (item->Type() == FragmentItem::kBox) {
      if (HitTestChildBoxItem(hit_test, container, *item, cursor))
        return true;
    } else {
      NOTREACHED();
    }

    cursor.MoveToPreviousSibling();

    if (ShouldHitTestCulledInlineAncestors(hit_test, *item)) {
      // Hit test culled inline boxes between |fragment| and its parent
      // fragment.
      const PhysicalOffset child_offset =
          hit_test.inline_root_offset + item->OffsetInContainerFragment();
      if (HitTestCulledInlineAncestors(*hit_test.result, container, children,
                                       *item, cursor.Current(),
                                       hit_test.location, child_offset))
        return true;
    }
  }

  return false;
}

bool BoxFragmentPainter::HitTestFloatingChildren(
    const HitTestContext& hit_test,
    const PhysicalFragment& container,
    const PhysicalOffset& accumulated_offset) {
  DCHECK_EQ(hit_test.phase, HitTestPhase::kFloat);
  DCHECK(container.HasFloatingDescendantsForPaint());

  if (const auto* box = DynamicTo<PhysicalBoxFragment>(&container)) {
    if (const FragmentItems* items = box->Items()) {
      InlineCursor children(*box, *items);
      if (HitTestFloatingChildItems(hit_test, children, accumulated_offset))
        return true;
      // Even if this turned out to be an inline formatting context, we need to
      // continue walking the box fragment children now. If a float is
      // block-fragmented, it is resumed as a regular box fragment child, rather
      // than becoming a fragment item.
    }
  }

  auto children = container.Children();
  for (const PhysicalFragmentLink& child : base::Reversed(children)) {
    const PhysicalFragment& child_fragment = *child.fragment;
    if (child_fragment.IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
      continue;
    }
    if (child_fragment.HasSelfPaintingLayer())
      continue;

    const PhysicalOffset child_offset = accumulated_offset + child.offset;

    if (child_fragment.IsFloating()) {
      if (HitTestAllPhasesInFragment(To<PhysicalBoxFragment>(child_fragment),
                                     hit_test.location, child_offset,
                                     hit_test.result)) {
        return true;
      }
      continue;
    }

    if (child_fragment.IsPaintedAtomically())
      continue;

    if (!child_fragment.HasFloatingDescendantsForPaint())
      continue;

    if (child_fragment.HasNonVisibleOverflow()) {
      // We need to properly visit this fragment for hit-testing, rather than
      // jumping directly to its children (which is what we normally do when
      // looking for floats), in order to set up the clip rectangle.
      if (NodeAtPointInFragment(To<PhysicalBoxFragment>(child_fragment),
                                hit_test.location, child_offset,
                                HitTestPhase::kFloat, hit_test.result)) {
        return true;
      }
      continue;
    }

    if (HitTestFloatingChildren(hit_test, child_fragment, child_offset))
      return true;
  }
  return false;
}

bool BoxFragmentPainter::HitTestFloatingChildItems(
    const HitTestContext& hit_test,
    const InlineCursor& children,
    const PhysicalOffset& accumulated_offset) {
  for (InlineBackwardCursor cursor(children); cursor;
       cursor.MoveToPreviousSibling()) {
    const FragmentItem* item = cursor.Current().Item();
    DCHECK(item);
    if (item->IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
      continue;
    }
    if (item->Type() == FragmentItem::kBox) {
      if (const PhysicalBoxFragment* child_box = item->BoxFragment()) {
        if (child_box->HasSelfPaintingLayer())
          continue;

        const PhysicalOffset child_offset =
            accumulated_offset + item->OffsetInContainerFragment();
        if (child_box->IsFloating()) {
          if (HitTestAllPhasesInFragment(*child_box, hit_test.location,
                                         child_offset, hit_test.result))
            return true;
          continue;
        }

        // Atomic inline is |IsPaintedAtomically|. |HitTestChildBoxFragment|
        // handles floating descendants in the |kHitTestForeground| phase.
        if (child_box->IsPaintedAtomically())
          continue;
        DCHECK(child_box->IsInlineBox() || child_box->IsBlockInInline());

        // If |child_box| is an inline box, look into descendants because inline
        // boxes do not have |HasFloatingDescendantsForPaint()| flag.
        if (!child_box->IsInlineBox()) {
          if (child_box->HasFloatingDescendantsForPaint()) {
            if (HitTestFloatingChildren(hit_test, *child_box, child_offset))
              return true;
          }
          continue;
        }
      }
      DCHECK(item->GetLayoutObject()->IsLayoutInline());
    } else if (item->Type() == FragmentItem::kLine) {
      const PhysicalLineBoxFragment* child_line = item->LineBoxFragment();
      if (child_line && !child_line->HasFloatingDescendantsForPaint()) {
        continue;
      }
    } else {
      continue;
    }

    InlineCursor descendants = cursor.CursorForDescendants();
    if (HitTestFloatingChildItems(hit_test, descendants, accumulated_offset))
      return true;
  }

  return false;
}

bool BoxFragmentPainter::HitTestClippedOutByBorder(
    const HitTestLocation& hit_test_location,
    const PhysicalOffset& border_box_location) const {
  const ComputedStyle& style = box_fragment_.Style();
  PhysicalRect rect(PhysicalOffset(), GetPhysicalFragment().Size());
  rect.Move(border_box_location);
  return !hit_test_location.Intersects(
      RoundedBorderGeometry::PixelSnappedRoundedBorder(
          style, rect, box_fragment_.SidesToInclude()));
}

bool BoxFragmentPainter::HitTestOverflowControl(
    const HitTestContext& hit_test,
    PhysicalOffset accumulated_offset) {
  const auto* layout_box =
      DynamicTo<LayoutBox>(box_fragment_.GetLayoutObject());
  return layout_box &&
         layout_box->HitTestOverflowControl(*hit_test.result, hit_test.location,
                                            accumulated_offset);
}

gfx::Rect BoxFragmentPainter::VisualRect(const PhysicalOffset& paint_offset) {
  if (const auto* layout_box =
          DynamicTo<LayoutBox>(box_fragment_.GetLayoutObject()))
    return BoxPainter(*layout_box).VisualRect(paint_offset);

  DCHECK(box_item_);
  PhysicalRect ink_overflow = box_item_->InkOverflowRect();
  ink_overflow.Move(paint_offset);
  return ToEnclosingRect(ink_overflow);
}

}  // namespace blink
```