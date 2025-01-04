Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the explanation.

**1. Initial Understanding and Goal:**

The first step is to understand the purpose of the request: to analyze a specific C++ file within the Chromium/Blink rendering engine. The key is to identify its functionality, its relationship to web technologies (HTML, CSS, JavaScript), potential user/developer errors, and debugging strategies.

**2. High-Level Code Review and Keyword Spotting:**

I'll quickly scan the code for prominent keywords and structures:

* **`InlinePaintContext`:** This is the central class, so its name suggests it's related to painting inline elements.
* **`DecoratingBox`:**  Appears frequently, likely related to text decorations (underline, overline, line-through).
* **`FragmentItem`, `InlineCursor`:** These suggest interaction with the layout tree and how inline content is structured.
* **`ComputedStyle`, `AppliedTextDecoration`:**  Directly related to CSS styling, particularly text decoration properties.
* **`SyncDecoratingBox`, `PushDecoratingBoxes`:** Indicate actions related to managing these `DecoratingBox` objects.
* **`ScopedInlineItem`, `ScopedLineBox`, `ScopedInlineBoxAncestors`:**  These look like RAII (Resource Acquisition Is Initialization) wrappers, suggesting they manage the lifetime and context of certain operations.
* **`ClearDecoratingBoxes`, `ClearLineBox`:**  Operations to reset or clean up state.
* **`DCHECK`:**  Assertions, useful for understanding invariants and potential error conditions during development.

**3. Deeper Dive into Key Methods:**

Now I'll focus on understanding the core functionality by examining the main methods:

* **`ClearDecoratingBoxes`:** Simple - clears a list of `DecoratingBox` objects.
* **`ScopedInlineItem` and `SyncDecoratingBox`:** This pair seems crucial. The `ScopedInlineItem` likely sets up the context for painting an inline item, and `SyncDecoratingBox` is responsible for determining and adding `DecoratingBox` objects based on the item's style and its ancestors. The logic within `SyncDecoratingBox` involving `DecorationBoxSynchronizer` is complex and requires careful examination of the different scenarios it handles (inheritance, stopping propagation, pseudo-elements, etc.).
* **`ScopedInlineBoxAncestors` and `PushDecoratingBoxAncestors`:**  These likely handle the scenario where a text decoration spans across multiple nested inline boxes. They traverse up the tree to find all relevant ancestor boxes.
* **`ScopedLineBox` and `SetLineBox`:** These focus on the context of a line of text. `SetLineBox` calculates the initial `DecoratingBox` for the line, considering block-level text decorations.
* **`PushDecoratingBoxes`:**  A simple method to add multiple `DecoratingBox` objects.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

With an understanding of the C++ code, I can now connect it to web concepts:

* **HTML:** The structure of inline elements (spans, emphasis, etc.) directly affects how `InlinePaintContext` operates.
* **CSS:** Text decoration properties (`text-decoration-line`, `text-decoration-color`, `text-decoration-style`) are the primary drivers for creating and managing `DecoratingBox` objects. Inheritance of these properties is also a key factor in the logic.
* **JavaScript:** While this C++ code doesn't directly interact with JavaScript, JavaScript manipulation of the DOM and CSS styles will indirectly trigger the execution of this code during the rendering process.

**5. Identifying Logic and Assumptions:**

Throughout the code, there are logical checks and assumptions. The `DCHECK` statements are explicit examples. For instance, the code assumes that `AppliedTextDecorations` are often shared across styles when inherited. It also handles cases where this isn't true (duplication). The logic in `DecorationBoxSynchronizer` involves complex comparisons of decoration vectors and traversing the layout tree.

**6. Considering User and Developer Errors:**

Based on the code, I can infer potential errors:

* **Confusing Text Decoration Inheritance:** Developers might misunderstand how text decorations are inherited and how changes in parent elements affect child elements.
* **Incorrectly Applying Text Decorations to Pseudo-elements:** The code explicitly handles specific cases related to pseudo-elements, suggesting these can be tricky.
* **Performance Issues with Deeply Nested Inline Elements:**  The traversal of ancestor inline boxes could potentially be a performance bottleneck in very complex layouts.

**7. Tracing User Actions and Debugging:**

To understand how a user action reaches this code, I'll trace the typical rendering pipeline:

1. **User Action:**  The user interacts with the page (e.g., types text, hovers over a link).
2. **Event Handling (JavaScript):**  JavaScript might update the DOM or CSS styles in response.
3. **Layout:** The layout engine recalculates the positions and sizes of elements, including inline elements.
4. **Paint:** The paint phase uses the layout information and computed styles to draw the elements. `InlinePaintContext` is involved in drawing inline elements and their text decorations.

Debugging involves setting breakpoints in this C++ code (if you have a Chromium development environment) and inspecting the state of variables like `decorating_boxes_`, `last_decorations_`, and the `FragmentItem` being processed. Following the execution flow through `SyncDecoratingBox` and `DecorationBoxSynchronizer` is crucial.

**8. Structuring the Explanation:**

Finally, I'll organize the information logically, addressing each point in the request:

* **Functionality:**  Provide a concise overview of the file's purpose.
* **Relationship to Web Technologies:** Give concrete examples of how HTML, CSS, and JavaScript relate to the code.
* **Logic and Assumptions:** Explain the key logical steps and assumptions within the code, providing hypothetical inputs and outputs for illustration.
* **User/Developer Errors:**  List common mistakes and provide examples.
* **User Operations and Debugging:**  Describe how user actions lead to this code and outline debugging strategies.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe the `DecoratingBox` directly maps to a CSS box. **Correction:**  Realized it's more specific to *text* decorations, not general boxes.
* **Initial thought:** The code might be simpler. **Correction:** The `DecorationBoxSynchronizer` class indicates significant complexity in handling text decoration inheritance and propagation.
* **Initial thought:**  Focusing too much on individual lines of code. **Correction:**  Shifted to understanding the overall flow and purpose of different methods and classes.

By following this thought process, iterating through the code, and connecting it to my knowledge of web technologies and the rendering pipeline, I can generate a comprehensive and accurate explanation.
这个C++源代码文件 `inline_paint_context.cc` 属于 Chromium Blink 渲染引擎，其核心功能是**管理和维护内联元素（inline elements）的文本装饰（text-decoration）绘制上下文信息**。  更具体地说，它负责跟踪哪些内联元素需要绘制文本装饰线（如下划线、删除线、上划线），并存储相关的样式和布局信息，以便在绘制阶段正确地渲染这些装饰。

下面我们详细列举它的功能，并说明其与 JavaScript, HTML, CSS 的关系，以及可能的错误和调试线索。

**主要功能:**

1. **存储和管理文本装饰盒 (Decorating Boxes):**
   - `decorating_boxes_`:  一个存储 `DecoratingBox` 对象的列表。每个 `DecoratingBox` 代表一个需要绘制文本装饰的区域，包含了位置、样式等信息。
   - 这些 `DecoratingBox` 对象并非对应于实际的 DOM 元素盒模型，而是为了处理文本装饰的特殊需求而创建的逻辑上的盒子。

2. **同步文本装饰状态 (SyncDecoratingBox):**
   - 这是核心功能。当渲染引擎遍历内联元素时，`SyncDecoratingBox` 方法负责将当前元素的文本装饰状态与父元素的装饰状态进行同步。
   - 它会检查当前元素的 `AppliedTextDecorations` (应用后的文本装饰样式)，并与之前处理的元素的装饰状态进行比较。
   - 如果当前元素引入了新的文本装饰（例如，一个 `<span>` 标签设置了下划线），或者停止了父元素的文本装饰继承，这个方法会创建或更新相应的 `DecoratingBox`。

3. **处理嵌套内联元素的文本装饰 (PushDecoratingBoxAncestors):**
   - 当文本装饰跨越多个嵌套的内联元素时（例如，一个加了下划线的 `<span>` 包含另一个 `<em>` 标签），这个方法会遍历祖先元素，确保所有相关的装饰状态都被记录。

4. **处理行盒 (Line Box) 的文本装饰 (SetLineBox):**
   - 每个文本行都被包裹在一个逻辑上的行盒中。`SetLineBox` 方法处理行盒级别的文本装饰，这通常涉及到块级元素的文本装饰如何应用于其内联内容。

5. **管理作用域 (Scoping) 和清理:**
   - `ScopedInlineItem`, `ScopedLineBox`, `ScopedInlineBoxAncestors` 等类是 RAII (Resource Acquisition Is Initialization) 风格的类，用于管理特定操作的作用域。
   - 它们在构造时执行一些操作（例如，同步装饰状态），并在析构时进行清理（例如，可能恢复之前的状态）。
   - `ClearDecoratingBoxes` 和 `ClearLineBox` 方法用于显式地清除装饰盒信息。

**与 JavaScript, HTML, CSS 的关系:**

* **CSS:**  这个文件的核心职责是处理 CSS 的 `text-decoration` 属性（`underline`, `overline`, `line-through`）。
    - 当 CSS 规则设置了元素的 `text-decoration-line` 属性时，渲染引擎会创建相应的 `AppliedTextDecoration` 对象。
    - `InlinePaintContext` 的代码会读取这些 `AppliedTextDecoration` 信息，并根据继承规则和当前元素的样式，决定是否需要创建一个新的 `DecoratingBox`。
    - **例子:**
        ```html
        <style>
          .underlined { text-decoration: underline; }
          .no-underline { text-decoration: none; }
        </style>
        <p class="underlined">
          This is <span>some text</span> with <em>emphasis</em>.
        </p>
        ```
        在这个例子中，`InlinePaintContext` 会跟踪 `<p>`, `<span>`, 和 `<em>` 元素的文本装饰状态。即使 `<span>` 和 `<em>` 没有显式设置 `text-decoration`，它们也会继承父元素 `<p>` 的下划线样式。

* **HTML:** HTML 的内联元素结构（如 `<span>`, `<a>`, `<em>`, `<strong>` 等）是 `InlinePaintContext` 处理的基础。
    - 渲染引擎需要理解 HTML 的嵌套结构，才能正确地同步和应用文本装饰。
    - **例子:** 上面的 HTML 代码片段展示了内联元素的嵌套。`InlinePaintContext` 需要处理跨越这些嵌套元素的文本装饰。

* **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式，包括 `text-decoration` 属性。
    - 当 JavaScript 修改了样式后，渲染引擎会重新布局和绘制页面。在这个过程中，`InlinePaintContext` 会根据新的 CSS 样式，更新其维护的装饰盒信息。
    - **例子:**
        ```javascript
        const element = document.querySelector('span');
        element.style.textDecoration = 'line-through red wavy';
        ```
        这段 JavaScript 代码会动态地给 `<span>` 元素添加删除线样式。渲染引擎会触发重绘，`InlinePaintContext` 将会创建或更新相应的 `DecoratingBox`，以绘制红色的波浪线删除线。

**逻辑推理 - 假设输入与输出:**

假设我们有以下 HTML 和 CSS:

```html
<style>
  .parent { text-decoration: underline; }
  .child { text-decoration: none; }
</style>
<div class="parent">
  Some <span>text</span> <em class="child">with</em> decoration.
</div>
```

**假设输入:** 渲染引擎正在处理 `<em>` 元素 (`class="child"`)。

**逻辑推理过程:**

1. `SyncDecoratingBox` 被调用，传入 `<em>` 元素的 `FragmentItem` 和当前的 `InlinePaintContext`。
2. 代码会比较 `<em>` 元素的 `AppliedTextDecorations` 和父元素 (`<div>`) 的 `AppliedTextDecorations`。
3. 由于 `.child` 类设置了 `text-decoration: none;`，它会阻止父元素的下划线装饰继承。
4. `SyncDecoratingBox` 会检测到装饰状态的变化。
5. 因为 `<em>` 明确取消了文本装饰，并且自身也没有其他文本装饰，所以可能的操作是：
   - 如果之前有来自父元素的 `DecoratingBox` 覆盖了 `<em>` 的范围，可能需要清理或标记不再需要绘制装饰。
   - 由于 `<em>` 本身没有装饰，可能不会创建新的 `DecoratingBox`。

**可能的输出 (取决于具体的实现细节):**

- 如果有保存的父元素装饰盒信息 (`saved_decorating_boxes_`)，并且其中包含了覆盖 `<em>` 区域的装饰盒，那么这个装饰盒会被移除或标记为不再需要。
- `decorating_boxes_` 列表在处理完 `<em>` 后，不会包含针对 `<em>` 自身的任何装饰盒。

**用户或编程常见的使用错误:**

1. **误解文本装饰的继承:**  开发者可能认为只需要在父元素上设置 `text-decoration`，所有子元素都会自动应用，但某些样式或显式的 `text-decoration: none` 会阻止继承。
   - **例子:** 上面的 HTML/CSS 示例就展示了如何通过 `text-decoration: none` 阻止继承。如果开发者期望 "with" 也有下划线，就会出现错误。

2. **在不希望的地方取消文本装饰:** 开发者可能在某个子元素上意外地设置了 `text-decoration: none;`，导致父元素的装饰没有应用到该子元素。

3. **与伪元素的交互不明确:**  文本装饰在与 `::first-line` 或 `::first-letter` 等伪元素交互时，其行为可能不太直观。`InlinePaintContext` 的代码中也有处理这类情况的逻辑。
   - **例子:** 如果一个段落的 `::first-line` 设置了不同的文本装饰，`InlinePaintContext` 需要正确地管理这两个装饰状态。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中加载包含内联元素的 HTML 页面。**
2. **浏览器解析 HTML，构建 DOM 树。**
3. **浏览器解析 CSS，计算每个元素的最终样式 (Computed Style)。**  这包括解析 `text-decoration` 属性。
4. **布局 (Layout) 阶段：** 浏览器根据样式信息计算元素的位置和大小，包括内联元素的排列和换行。会创建 `LayoutInline` 和 `LayoutText` 等布局对象。
5. **绘制 (Paint) 阶段：**
   - 遍历布局树，准备绘制每个元素。
   - 当遇到内联元素时，渲染引擎会创建 `InlinePaintContext` 对象来管理内联内容的绘制状态。
   - 在绘制内联文本的过程中，会遍历 `LayoutInline` 对象的 `Fragment` 列表，每个 `Fragment` 对应一部分内联内容。
   - 对于每个 `FragmentItem`，会调用 `InlinePaintContext::SyncDecoratingBox` 方法，以确定是否需要绘制文本装饰线。
   - 如果需要绘制，会使用 `decorating_boxes_` 中存储的信息来生成绘制指令。

**调试线索:**

- **查看 Computed Style:**  在浏览器的开发者工具中，检查目标元素的 Computed Style，确认 `text-decoration-line` 等属性的值是否符合预期。
- **断点调试 C++ 代码:** 如果可以访问 Chromium 的源代码，可以在 `inline_paint_context.cc` 中设置断点，例如在 `SyncDecoratingBox` 方法入口，查看 `item.Style().AppliedTextDecorations()` 的值，以及 `decorating_boxes_` 的变化。
- **Layout Tree Inspector:** 使用开发者工具的布局面板，查看内联元素的布局结构，理解 `Fragment` 的划分，有助于理解 `SyncDecoratingBox` 的工作原理。
- **Paint Profiler:**  一些浏览器提供了 Paint Profiler 工具，可以查看绘制调用的顺序和耗时，有助于理解 `InlinePaintContext` 在整个绘制过程中的作用。

总而言之，`inline_paint_context.cc` 是 Chromium Blink 渲染引擎中一个关键的文件，专门负责处理内联元素的文本装饰绘制逻辑，确保网页上的下划线、删除线等装饰能够按照 CSS 规范正确地渲染出来。理解这个文件的功能有助于深入理解浏览器渲染过程，特别是与文本相关的渲染细节。

Prompt: 
```
这是目录为blink/renderer/core/paint/inline_paint_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/inline_paint_context.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"

namespace blink {

void InlinePaintContext::ClearDecoratingBoxes(
    DecoratingBoxList* saved_decorating_boxes) {
  if (saved_decorating_boxes) {
    DCHECK(saved_decorating_boxes->empty());
    decorating_boxes_.swap(*saved_decorating_boxes);
  } else {
    decorating_boxes_.Shrink(0);
  }
}

InlinePaintContext::ScopedInlineItem::ScopedInlineItem(
    const FragmentItem& item,
    InlinePaintContext* inline_context) {
  DCHECK(inline_context);
  inline_context_ = inline_context;
  last_decorations_ = inline_context->last_decorations_;
  push_count_ =
      inline_context->SyncDecoratingBox(item, &saved_decorating_boxes_);
  DCHECK_EQ(inline_context->decorating_boxes_.size(),
            item.Style().AppliedTextDecorations().size());
}

// Synchronize |decorating_boxes_| with the |AppliedTextDecorations|, including
// culled inline boxes in the ancestor chain.
//
// This function may push multiple decorating boxes, or clear if the propagation
// was stopped. See |StopPropagateTextDecorations|.
wtf_size_t InlinePaintContext::SyncDecoratingBox(
    const FragmentItem& item,
    DecoratingBoxList* saved_decorating_boxes) {
  DCHECK(!saved_decorating_boxes || saved_decorating_boxes->empty());

  // Compare the instance addresses of |AppliedTextDecorations| because it is
  // shared across |ComputedStyle|s when it is propagated without changes.
  const ComputedStyle* style = &item.Style();
  const Vector<AppliedTextDecoration, 1>* decorations =
      &style->AppliedTextDecorations();
  DCHECK(last_decorations_);
  if (decorations == last_decorations_)
    return 0;

  // This class keeps all the context data while making recursive calls.
  class DecorationBoxSynchronizer {
    STACK_ALLOCATED();

   public:
    DecorationBoxSynchronizer(InlinePaintContext* inline_context,
                              const FragmentItem& item,
                              const Vector<AppliedTextDecoration, 1>* stop_at,
                              DecoratingBoxList* saved_decorating_boxes)
        : inline_context_(inline_context),
          stop_at_(stop_at),
          saved_decorating_boxes_(saved_decorating_boxes),
          style_variant_(ToParentStyleVariant(item.GetStyleVariant())) {
      DCHECK(inline_context_);
      DCHECK(stop_at_);
    }

    wtf_size_t Sync(const FragmentItem* item,
                    const LayoutObject* layout_object,
                    const ComputedStyle* style,
                    const Vector<AppliedTextDecoration, 1>* decorations) {
      for (;;) {
        DCHECK(!item || item->GetLayoutObject() == layout_object);
        DCHECK_EQ(&layout_object->EffectiveStyle(style_variant_), style);
        DCHECK_EQ(&style->AppliedTextDecorations(), decorations);
        DCHECK_NE(decorations, stop_at_);
        const LayoutObject* parent = layout_object->Parent();
        DCHECK(parent);
        const ComputedStyle& parent_style =
            parent->EffectiveStyle(style_variant_);
        const Vector<AppliedTextDecoration, 1>& parent_decorations =
            parent_style.AppliedTextDecorations();

        if (decorations != &parent_decorations) {
          // It's a decorating box if it has more decorations than its parent.
          if (decorations->size() > parent_decorations.size()) {
            // Ensure the parent is in sync. Ancestors are pushed first.
            wtf_size_t num_pushes = 0;
            if (&parent_decorations != stop_at_) {
              num_pushes = Sync(/* item */ nullptr, parent, &parent_style,
                                &parent_decorations);
            }

            num_pushes += PushDecoratingBoxesUntilParent(
                item, *layout_object, *style, *decorations, parent_decorations);
            return num_pushes;
          }

          // Rare but sometimes |AppliedTextDecorations| is duplicated instead
          // of being shared. If duplicated, skip it.
          // e.g., fast/css/first-letter.html
          //       tables/mozilla/bugs/bug126742.html
          if (decorations->size() == parent_decorations.size() &&
              (style->GetTextDecorationLine() == TextDecorationLine::kNone ||
               // Conceptually text nodes don't have styles, but |LayoutText|
               // has a style of its parent. Ignore |GetTextDecorationLine| for
               // |LayoutText|.
               // http/tests/devtools/service-workers/service-workers-view.js
               IsA<LayoutText>(layout_object))) {
            if (&parent_decorations == stop_at_)
              return 0;
            return Sync(/* item */ nullptr, parent, &parent_style,
                        &parent_decorations);
          }

          // If the number of this node's decorations is equal to or less than
          // the parent's, this node stopped the propagation. Reset the
          // decorating boxes. In this case, this node has 0 or 1 decorations.
          if (decorations->size() <= 1) {
            inline_context_->ClearDecoratingBoxes(saved_decorating_boxes_);
            if (decorations->empty())
              return 0;
            DCHECK_NE(style->GetTextDecorationLine(),
                      TextDecorationLine::kNone);
            PushDecoratingBox(item, *layout_object, *style, *decorations);
            return 1;
          }

          // There are some edge cases where a style doesn't propagate
          // decorations from its parent. One known such case is a pseudo
          // element in a parent with a first-line style, but there can be more.
          // If this happens, consider it stopped the propagation.
          const Vector<AppliedTextDecoration, 1>* base_decorations =
              style->BaseAppliedTextDecorations();
          if (base_decorations != &parent_decorations) {
            inline_context_->ClearDecoratingBoxes(saved_decorating_boxes_);
            const wtf_size_t size =
                std::min(saved_decorating_boxes_->size(), decorations->size());
            inline_context_->PushDecoratingBoxes(
                base::span(*saved_decorating_boxes_).first(size));
            return size;
          }

#if DCHECK_IS_ON()
          ShowLayoutTree(layout_object);
#endif
          NOTREACHED() << "size=" << decorations->size()
                       << ", parent=" << parent_decorations.size()
                       << ", TextDecorationLine="
                       << static_cast<int>(style->GetTextDecorationLine());
        }

        if (!IsA<LayoutInline>(parent)) [[unlikely]] {
          // This shouldn't happen, indicating text-decoration isn't propagated
          // as expected, but the logs indicate it does, though not too often.
          // Just abort the sync.
          return 0;
        }

#if DCHECK_IS_ON()
        // All non-culled inline boxes should have called |SyncDecoratingBox|,
        // so the loop should have stopped before seeing non-culled inline
        // boxes.
        const auto* layout_inline = To<LayoutInline>(parent);
        // Except when |AppliedTextDecorations| is duplicated instead of
        // shared, see above.
        if (!(parent_decorations.size() == parent->Parent()
                                               ->StyleRef()
                                               .AppliedTextDecorations()
                                               .size() &&
              parent_style.GetTextDecorationLine() ==
                  TextDecorationLine::kNone) &&
            !IsA<LayoutText>(layout_object)) {
          DCHECK(!layout_inline->ShouldCreateBoxFragment());
          DCHECK(!layout_inline->HasInlineFragments());
        }
#endif
        item = nullptr;
        layout_object = parent;
        style = &parent_style;
      }
    }

    wtf_size_t PushDecoratingBoxesUntilParent(
        const FragmentItem* item,
        const LayoutObject& layout_object,
        const ComputedStyle& style,
        const Vector<AppliedTextDecoration, 1>& decorations,
        const Vector<AppliedTextDecoration, 1>& parent_decorations) {
      const Vector<AppliedTextDecoration, 1>* base_decorations =
          style.BaseAppliedTextDecorations();
      if (base_decorations == &parent_decorations) {
        DCHECK_EQ(decorations.size(), parent_decorations.size() + 1);
        DCHECK_NE(style.GetTextDecorationLine(), TextDecorationLine::kNone);
        PushDecoratingBox(item, layout_object, style, decorations);
        return 1;
      }

      if (base_decorations && base_decorations != &decorations &&
          decorations.size() == parent_decorations.size() + 2) {
        // When the normal style and `::first-line` have different decorations,
        // the normal style inherits from the parent, and the `:first-line`
        // inherits from the normal style, resulting two decorating boxes.
        DCHECK_NE(style.GetTextDecorationLine(), TextDecorationLine::kNone);
        PushDecoratingBox(item, layout_object, style, *base_decorations);
        PushDecoratingBox(item, layout_object, style, decorations);
        return 2;
      }

      // The style engine may create a clone, not an inherited decorations,
      // such as a `<span>` in `::first-line`.
      DCHECK_EQ(decorations.size(), parent_decorations.size() + 1);
      PushDecoratingBox(item, layout_object, style, decorations);
      return 1;
    }

    void PushDecoratingBox(
        const FragmentItem* item,
        const LayoutObject& layout_object,
        const ComputedStyle& style,
        const Vector<AppliedTextDecoration, 1>& decorations) {
      DCHECK(!item || item->GetLayoutObject() == &layout_object);
      if (!item) {
        // If the item is not known, it is either a culled inline or it is found
        // while traversing the tree. Find the offset of the first fragment of
        // the |LayoutObject| in the current line.
        if (!line_cursor_)
          line_cursor_ = inline_context_->CursorForDescendantsOfLine();
        line_cursor_->MoveToIncludingCulledInline(layout_object);
        DCHECK(*line_cursor_);
        item = line_cursor_->Current().Item();
      }
      DCHECK(item);
      inline_context_->PushDecoratingBox(
          item->ContentOffsetInContainerFragment(), style, &decorations);
    }

    InlinePaintContext* inline_context_;
    const Vector<AppliedTextDecoration, 1>* stop_at_;
    std::optional<InlineCursor> line_cursor_;
    DecoratingBoxList* saved_decorating_boxes_;
    StyleVariant style_variant_;
  };

  const wtf_size_t push_count =
      DecorationBoxSynchronizer(this, item, last_decorations_,
                                saved_decorating_boxes)
          .Sync(&item, item.GetLayoutObject(), style, decorations);
  last_decorations_ = decorations;
  return push_count;
}

InlinePaintContext::ScopedInlineBoxAncestors::ScopedInlineBoxAncestors(
    const InlineCursor& inline_box,
    InlinePaintContext* inline_context) {
  DCHECK(inline_context);
  inline_context_ = inline_context;
  inline_context->PushDecoratingBoxAncestors(inline_box);
}

void InlinePaintContext::PushDecoratingBoxAncestors(
    const InlineCursor& inline_box) {
  DCHECK(inline_box.Current());
  DCHECK(inline_box.Current().IsInlineBox());
  DCHECK(decorating_boxes_.empty());

  Vector<const FragmentItem*, 16> ancestor_items;
  for (InlineCursor cursor = inline_box;;) {
    cursor.MoveToParent();
    const InlineCursorPosition& current = cursor.Current();
    DCHECK(current);

    if (current.IsLineBox()) {
      SetLineBox(cursor);
      for (const FragmentItem* item : base::Reversed(ancestor_items)) {
        SyncDecoratingBox(*item);
      }
      return;
    }

    DCHECK(current.IsInlineBox());
    ancestor_items.push_back(current.Item());
  }
}

void InlinePaintContext::PushDecoratingBoxes(
    const base::span<DecoratingBox>& boxes) {
  decorating_boxes_.AppendRange(boxes.begin(), boxes.end());
}

InlinePaintContext::ScopedLineBox::ScopedLineBox(
    const InlineCursor& line_cursor,
    InlinePaintContext* inline_context) {
  DCHECK(inline_context);
  inline_context_ = inline_context;
  inline_context->SetLineBox(line_cursor);
}

void InlinePaintContext::SetLineBox(const InlineCursor& line_cursor) {
  DCHECK_EQ(line_cursor.Current()->Type(), FragmentItem::kLine);
  line_cursor_ = line_cursor;
  DCHECK(decorating_boxes_.empty());

  const FragmentItem& line_item = *line_cursor.Current();
  const ComputedStyle& style = line_item.Style();
  const Vector<AppliedTextDecoration, 1>& applied_text_decorations =
      style.AppliedTextDecorations();
  line_decorations_ = last_decorations_ = &applied_text_decorations;
  if (applied_text_decorations.empty())
    return;

  // The decorating box of a block container is an anonymous inline box that
  // wraps all children of the block container.
  // https://drafts.csswg.org/css-text-decor-3/#decorating-box
  //
  // Compute the offset of the non-existent anonymous inline box.
  PhysicalOffset offset = line_item.OffsetInContainerFragment();
  if (const PhysicalLineBoxFragment* fragment = line_item.LineBoxFragment()) {
    if (const SimpleFontData* font = style.GetFont().PrimaryFont()) {
      offset.top += fragment->Metrics().ascent;
      offset.top -= font->GetFontMetrics().FixedAscent();
    }
  }

  // If the block has multiple decorations, all decorations have the same
  // decorating box, which is a non-existent anonymous inline box that wraps all
  // the in-flow children. See
  // https://drafts.csswg.org/css-text-decor-3/#line-decoration, EXAMPLE 1 in
  // the spec, and crbug.com/855589.
  for (wtf_size_t i = 0; i < applied_text_decorations.size(); ++i)
    decorating_boxes_.emplace_back(offset, style, &applied_text_decorations);
}

void InlinePaintContext::ClearLineBox() {
  last_decorations_ = nullptr;
  line_decorations_ = nullptr;
  line_cursor_.reset();
  decorating_boxes_.Shrink(0);
}

}  // namespace blink

"""

```