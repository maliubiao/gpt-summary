Response:
My goal is to analyze the provided C++ code snippet from `inline_node_test.cc` and explain its functionality, its relation to web technologies, and potential usage errors, adhering to the decomposed instructions.

**Plan:**

1. **Overall Function:**  Recognize that this is a test file for the `InlineNode` class in the Blink rendering engine. The primary function is to verify the behavior of `InlineNode` in various scenarios, especially regarding how it handles changes to the DOM and their impact on layout and inline content.

2. **Break Down Tests:** Analyze each `TEST_F` function. Identify the specific DOM manipulation or style change being tested. Focus on the `EXPECT_*` assertions to understand what the test is verifying.

3. **Relate to Web Technologies:** Connect the test scenarios to HTML, CSS, and JavaScript concepts. For example, inserting/removing elements relates to DOM manipulation via JavaScript, while changing styles directly connects to CSS.

4. **Logic and Assumptions:**  For tests involving `NeedsCollectInlines` and layout updates, infer the expected behavior based on how Blink's layout engine should react to DOM changes. Consider the assumptions about how inline layout works.

5. **Common Errors:** Think about what mistakes developers might make when working with inline elements and layout, and see if the tests expose those potential errors.

6. **Specific Instructions (Part 2 Focus):** Concentrate on summarizing the functionality of *this specific part* of the file. Avoid repeating information already covered in Part 1 (if I had access to it) and anticipate what Part 3 might contain.

**Pre-computation/Analysis:**

* **`NeedsCollectInlines`:** Recognize this flag as a key mechanism in Blink for invalidating inline layout when necessary. Changes that affect inline flow should trigger this.
* **Layout Lifecycle:**  Understand the basics of Blink's layout lifecycle (style update, layout tree construction, layout). The `UpdateStyleAndLayoutTree()` calls are crucial.
* **Inline Items:** Recall that `InlineNode` is responsible for collecting and managing inline items (text, inline elements, etc.) within a line.
* **Out-of-flow elements (absolute/fixed):** Understand that these elements generally don't participate in the normal inline flow and might have different implications for `NeedsCollectInlines`.
* **Bidi (Bidirectional Text):** Recognize tests related to text direction and how changes affect layout.
* **SVG:** Note the tests specific to SVG elements and their handling within inline layout.
* **Whitespace and Line Breaks:** Pay attention to tests involving `<br>`, newlines, and `white-space` CSS properties.
* **Ligatures and Shaping:**  Understand that text rendering can involve ligatures and complex shaping, and these tests verify that Blink correctly handles re-shaping when necessary.
* **Initial Letters:** Be aware of the `::first-letter` pseudo-element and how it impacts inline layout.
* **Text Combine:**  Recognize the `text-combine-upright` property and its implications.
* **Shape Caching:** Understand that Blink might cache shaping results for performance, and these tests verify when the cache is used or invalidated.

**Constraint Checklist & Confidence:**

* List the functions: Yes.
* Relationship with JS/HTML/CSS: Yes.
* Examples for JS/HTML/CSS: Yes.
* Logical reasoning: Yes.
* Hypothesis Input/Output: Yes (implicitly through the test setup and assertions).
* Common user/programming errors: Yes.
* Examples for errors: Yes.
* Part 2 Summary: Yes.

Confidence: 5/5 - I am confident I can address all the instructions effectively.

**Mental Walkthrough of Key Tests (Illustrative):**

* **`NeedsCollectInlinesOnInsert`:**  The assumption is that inserting an inline element into another inline container should mark the ancestors as needing inline collection. The `EXPECT_TRUE` assertions confirm this.
* **`NeedsCollectInlinesOnRemove`:**  Similar to insertion, removing an inline element should also trigger `NeedsCollectInlines`. The test verifies this for various types of removed elements.
* **`InvalidateAddSpan`:**  This test checks if adding a `<span>` element correctly invalidates the inline layout, leading to the creation of new inline items (open/close tags).
* **`InvalidateSetText`:** Changing the text content of a node should also invalidate the inline layout.
* **`SegmentRanges`:**  This test focuses on how Blink segments inline content for efficient handling, especially for bidirectional text. The `EXPECT_EQ` calls verify the correct offsets for these segments.

By following this process, I can systematically analyze the code and generate a comprehensive response that addresses all the requirements.
这是 `blink/renderer/core/layout/inline/inline_node_test.cc` 文件的第二部分，主要包含了一系列针对 `InlineNode` 类的单元测试，用于验证在各种 DOM 操作和样式更改后，`InlineNode` 及其相关的布局行为是否符合预期。

**主要功能归纳 (基于提供的代码片段):**

1. **验证 `NeedsCollectInlines()` 标记的正确性：**
   - 测试了在插入和删除不同类型的节点（包括文本节点、span、absolute 定位元素、float 元素、inline-block 元素、img 元素等）后，父元素和容器元素的 `NeedsCollectInlines()` 标记是否被正确设置。这个标记用于指示是否需要重新收集和处理元素的内联内容。
   - 特别关注了插入到 out-of-flow 的 button 元素中的情况，验证在这种特殊情况下 `NeedsCollectInlines()` 不应该被设置。

2. **验证 `CollectInlines()` 方法的行为：**
   - 测试了调用 `CollectInlines()` 后，是否会正确保留第一个内联片段 (`FirstInlineFragment`)，避免不必要的数据丢失。

3. **验证双向文本 (Bidi) 变化的处理：**
   - 测试了当内联元素中的文本双向性发生变化时（例如，插入 RTL 字符），是否会正确地设置 `NeedsLayout` 标记，触发必要的布局更新。

4. **验证 DOM 结构变化对内联布局的影响：**
   - 测试了添加和删除 `span` 元素（包括嵌套的 `span` 元素）后，是否会触发 `NeedsCollectInlines()`，并导致内联项 (inline items) 的正确增减。

5. **验证文本内容变化对内联布局的影响：**
   - 测试了通过 `SetTextIfNeeded()` 修改文本内容后，是否会触发 `NeedsCollectInlines()`。

6. **验证定位和浮动元素对内联布局的影响：**
   - 测试了添加、删除以及更改元素的定位方式 (absolute) 和浮动属性 (float) 后，是否会正确触发 `NeedsCollectInlines()`，并导致内联项（例如，OOF item）的正确增减。

7. **验证空格处理的正确性：**
   - 测试了在特定情况下（例如，插入单词）空格是否会被正确恢复。

8. **验证当块级元素变为空或包含块级子元素时，内联节点数据的清理：**
   - 测试了当一个包含内联内容的块级元素变为空（通过移除子元素或设置 `innerHTML` 为空）或添加了块级子元素后，是否会正确地清除相关的内联节点数据 (`InlineNodeData`)。

9. **验证 `SplitFlow()` 操作后内联对象的初始化：**
   - 测试了当由于 `SplitFlow()` 导致内联对象移动后，是否会正确地初始化内联片段。

10. **验证在 SVG 根元素中添加子元素的情况：**
    - 测试了在 SVG 根元素中添加子元素后，容器元素是否不需要收集内联内容 (`NeedsCollectInlines` 为 false)。

11. **验证换行符和双向文本的相互作用：**
    - 测试了在包含双向文本的 `<pre>` 元素中，添加或移除双向属性后，换行符是否被正确处理，Bidi 控制字符是否被正确保留或移除。

12. **验证 `<wbr>` 元素对换行符的影响：**
    - 测试了插入 `<wbr>` 元素后，是否能够正确地折叠相邻的换行符。

13. **验证 `white-space` 属性对空格和换行符的影响：**
    - 测试了 `white-space: pre` 属性如何影响空格和换行符的处理，以及移除该属性后的变化。

14. **(针对启用了 East Asian Width 特性的构建) 验证日语文本中分段符的移除：**
    - 测试了在日语文本中，由于布局重排，分段符是否被正确移除。

15. **验证内联项分段 (Inline Item Segments) 的范围计算：**
    - 测试了 `InlineItemSegments` 类提供的 `Ranges()` 方法，用于获取指定范围内内联项的边界偏移量，涵盖了不同起始和结束位置的情况。

16. **验证在不同 `white-space` 属性下，内联项的重用和保留：**
    - 测试了在 `white-space: pre-wrap` 等属性下，删除 `<br>` 元素后，内联项是否被正确重用，以及空格和控制字符是否被正确处理。

17. **验证浮动元素与内联项的交互：**
    - 测试了包含浮动元素的场景下，内联项的重用情况。

18. **验证 RTL 文本变为 LTR 文本的处理：**
    - 测试了当元素的 `dir` 属性从 `rtl` 变为没有设置时，内联项的数量和偏移方向是否被正确更新。

19. **验证首个非安全重用项 (ReuseFirstNonSafe)：**
    - 测试了在特定字体渲染场景下，即使样式没有改变，某些内联项（例如，包含字距调整的文本片段）也不能被安全重用。

20. **验证不应重用连字 (ShouldNotResueLigature)：**
    - 测试了包含连字的文本片段在 DOM 结构变化后，是否会重新进行 shaping，而不是重用之前的 shaping 结果。

21. **验证首字下沉 (Initial Letter) 的处理：**
    - 测试了当元素应用了 `initial-letter` 样式时，`InlineNode` 是否能正确识别并处理首字下沉盒子。

22. **验证 `text-combine-upright` 属性的缩放行为：**
    - 测试了当使用 `text-combine-upright` 属性时，对于不同长度的文本，是否会采用不同的缩放策略 (`UsesScaleX`)。

23. **验证 `text-combine-upright` 属性下的字间距 (word-spacing)：**
    - 测试了 `text-combine-upright` 属性是否会重置字间距。

24. **验证 SVG 文本处理的稳定性：**
    - 提供了多个针对 SVG 文本的测试用例，用于防止在处理特定 SVG 结构时发生崩溃或断言失败。

25. **验证是否禁用 Shape 缓存：**
    - 测试了当显式禁用 LayoutNG Shape 缓存时，`IsNGShapeCacheAllowed` 方法返回 false。

26. **验证 Shape 缓存对于长字符串和多内联项的情况：**
    - 测试了 Shape 缓存对于长文本字符串和包含多个内联项的场景是否被禁用。

27. **验证需要额外间距 (spacing) 的情况下的 Shape 缓存：**
    - 测试了当需要额外的字母间距时，Shape 缓存是否被禁用。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:** 代码中通过 `SetBodyInnerHTML()` 方法设置 HTML 结构，例如创建包含 `div`, `span`, `button`, `img`, `<pre>`, `<br>`, `<svg>`, `<text>`, `<tspan>` 等元素的 DOM 树。测试验证了在这些 HTML 结构发生变化时，内联布局的更新机制。
    ```html
    <div id="container">
      <span id="parent"></span>
    </div>
    ```
* **CSS:** 代码中通过内联样式 (`style` 属性) 或 `<style>` 标签来设置 CSS 样式，例如 `position: absolute`, `float: left`, `display: inline-block`, `white-space: pre`, `unicode-bidi: isolate`, `direction: rtl`, `letter-spacing`, `text-combine-upright`, `initial-letter` 等。测试验证了这些 CSS 属性的变化如何影响内联布局和 `NeedsCollectInlines()` 标记。
    ```css
    <style>
    #xflex { display: flex; }
    </style>
    ```
* **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的内部逻辑，但测试场景模拟了 JavaScript 对 DOM 的操作，例如 `appendChild()`, `remove()`, `setTextContent()`, `removeAttribute()`, `insertBefore()` 等。这些操作通常由 JavaScript 代码在浏览器中执行，测试验证了引擎在响应这些操作时的行为。
    ```c++
    parent->appendChild(insert); // 模拟 JavaScript 的 appendChild
    target->remove();          // 模拟 JavaScript 的 remove
    ```

**逻辑推理的假设输入与输出举例:**

**假设输入:**
```html
<div id="container">
  <span>text</span>
</div>
```
然后执行 JavaScript 代码:
```javascript
document.getElementById('container').appendChild(document.createElement('b'));
```

**逻辑推理:**
在 `NeedsCollectInlinesOnInsert` 测试中，我们期望当向包含内联元素的容器中插入一个新的内联元素（这里是 `<b>`）时，容器的布局对象应该被标记为需要重新收集内联内容。

**预期输出:**
在执行 `GetDocument().UpdateStyleAndLayoutTree()` 后，`container` 元素的布局对象 (`GetElementById("container")->GetLayoutObject()`) 的 `NeedsCollectInlines()` 方法应该返回 `true`。

**用户或编程常见的使用错误举例说明:**

1. **错误地认为修改非内联相关的 CSS 属性不需要重新布局内联内容:** 开发者可能会认为只修改了块级元素的某个属性，而忽略了内联元素的布局可能也受到了影响。例如，修改一个父元素的 `padding` 或 `border` 可能会影响其内联子元素的布局，因此需要重新收集内联内容。测试用例如 `NeedsCollectInlinesOnInsert` 和 `NeedsCollectInlinesOnRemove` 验证了即使是简单的 DOM 结构变化也可能触发内联内容的重新收集。

2. **在 JavaScript 中频繁操作 DOM 结构，但没有意识到这会导致频繁的布局计算:**  开发者可能会在短时间内多次添加或删除内联元素，导致浏览器频繁地进行内联布局计算，影响性能。测试用例如 `InvalidateAddSpan` 和 `InvalidateRemoveSpan` 展示了添加/删除元素会触发内联布局的更新。

3. **不理解 `white-space` 属性对空格和换行符的影响:** 开发者可能不清楚不同的 `white-space` 属性值（如 `normal`, `pre`, `nowrap`, `pre-wrap`, `pre-line`）如何影响文本中的空格和换行符的渲染，导致意外的文本显示效果。测试用例如 `CollapsibleSpaceFollowingBRWithNoWrapStyle` 和 `CollapsibleSpaceFollowingNewlineWithPreStyle` 验证了这些属性的行为。

4. **在处理双向文本时，没有正确使用或理解 `unicode-bidi` 和 `direction` 属性:**  开发者可能没有正确设置或理解这些属性，导致双向文本的显示顺序错误。测试用例如 `PreservedNewlineWithBidiAndRelayout` 和 `PreservedNewlineWithRemovedBidiAndRelayout` 验证了这些属性在不同场景下的作用。

总而言之，这部分测试代码覆盖了 `InlineNode` 类在处理各种 DOM 结构、样式变化以及特定文本渲染场景下的核心功能，确保了 Blink 引擎能够正确地管理和更新内联布局。这些测试对于保证浏览器的渲染准确性和性能至关重要。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/inline_node_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
<div id="container">
      <span id="previous"></span>
      <span id="parent"></span>
      <span id="next"></span>
    </div>
  )HTML");

  Element* container = GetElementById("container");
  Element* parent = GetElementById("parent");
  EXPECT_FALSE(parent->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(container->GetLayoutObject()->NeedsCollectInlines());

  Node* insert = (*GetParam())(GetDocument());
  parent->appendChild(insert);
  GetDocument().UpdateStyleAndLayoutTree();

  // Ancestors up to the container should be marked.
  EXPECT_TRUE(parent->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_TRUE(container->GetLayoutObject()->NeedsCollectInlines());

  // Siblings of |parent| should stay clean.
  Element* previous = GetElementById("previous");
  Element* next = GetElementById("next");
  EXPECT_FALSE(previous->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(next->GetLayoutObject()->NeedsCollectInlines());
}

TEST_F(InlineNodeTest, NeedsCollectInlinesOnInsertToOutOfFlowButton) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #xflex { display: flex; }
    </style>
    <div id="container">
      <button id="flex" style="position: absolute"></button>
    </div>
  )HTML");

  Element* container = GetElementById("container");
  Element* parent = ElementTraversal::FirstChild(*container);
  Element* child = GetDocument().CreateRawElement(html_names::kDivTag);
  parent->appendChild(child);
  GetDocument().UpdateStyleAndLayoutTree();

  EXPECT_FALSE(container->GetLayoutObject()->NeedsCollectInlines());
}

class NodeRemoveTest : public InlineNodeTest,
                       public testing::WithParamInterface<const char*> {};

INSTANTIATE_TEST_SUITE_P(
    InlineNodeTest,
    NodeRemoveTest,
    testing::Values(nullptr, "span", "abspos", "float", "inline-block", "img"));

TEST_P(NodeRemoveTest, NeedsCollectInlinesOnRemove) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .abspos { position: absolute; }
    .float { float: left; }
    .inline-block { display: inline-block; }
    </style>
    <div id="container">
      <span id="previous"></span>
      <span id="parent">
        text
        <span id="span">span</span>
        <span id="abspos">abspos</span>
        <span id="float">float</span>
        <span id="inline-block">inline-block</span>
        <img id="img">
      </span>
      <span id="next"></span>
    </div>
  )HTML");

  Element* container = GetElementById("container");
  Element* parent = GetElementById("parent");
  EXPECT_FALSE(parent->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(container->GetLayoutObject()->NeedsCollectInlines());

  const char* id = GetParam();
  if (id) {
    Element* target = GetElementById(GetParam());
    target->remove();
  } else {
    Node* target = parent->firstChild();
    target->remove();
  }
  GetDocument().UpdateStyleAndLayoutTree();

  // Ancestors up to the container should be marked.
  EXPECT_TRUE(parent->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_TRUE(container->GetLayoutObject()->NeedsCollectInlines());

  // Siblings of |parent| should stay clean.
  Element* previous = GetElementById("previous");
  Element* next = GetElementById("next");
  EXPECT_FALSE(previous->GetLayoutObject()->NeedsCollectInlines());
  EXPECT_FALSE(next->GetLayoutObject()->NeedsCollectInlines());
}

TEST_F(InlineNodeTest, CollectInlinesShouldNotClearFirstInlineFragment) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      text
    </div>
  )HTML");

  // Appending a child should set |NeedsCollectInlines|.
  Element* container = GetElementById("container");
  container->appendChild(GetDocument().createTextNode("add"));
  auto* block_flow = To<LayoutBlockFlow>(container->GetLayoutObject());
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(block_flow->NeedsCollectInlines());

  // |IsBlockLevel| should run |CollectInlines|.
  InlineNode node(block_flow);
  node.IsBlockLevel();
  EXPECT_FALSE(block_flow->NeedsCollectInlines());

  // Running |CollectInlines| should not clear |FirstInlineFragment|.
  LayoutObject* first_child = container->firstChild()->GetLayoutObject();
  EXPECT_TRUE(first_child->HasInlineFragments());
}

TEST_F(InlineNodeTest, SegmentBidiChangeSetsNeedsLayout) {
  SetBodyInnerHTML(R"HTML(
    <div id="container" dir="rtl">
      abc-<span id="span">xyz</span>
    </div>
  )HTML");

  // Because "-" is a neutral character, changing the following character to RTL
  // will change its bidi level.
  Element* span = GetElementById("span");
  span->setTextContent(u"\u05D1");

  // |InlineNode::SegmentBidiRuns| sets |NeedsLayout|. Run the lifecycle only
  // up to |PrepareLayout|.
  GetDocument().UpdateStyleAndLayoutTree();
  LayoutBlockFlow* container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  InlineNode node(container);
  node.PrepareLayoutIfNeeded();

  LayoutText* abc = To<LayoutText>(container->FirstChild());
  EXPECT_TRUE(abc->NeedsLayout());
}

TEST_F(InlineNodeTest, InvalidateAddSpan) {
  SetupHtml("t", "<div id=t>before</div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());
  unsigned item_count_before = Items().size();

  auto* parent = To<Element>(layout_block_flow_->GetNode());
  Element* span = GetDocument().CreateRawElement(html_names::kSpanTag);
  parent->appendChild(span);

  // NeedsCollectInlines() is marked during the layout.
  // By re-collecting inlines, open/close items should be added.
  ForceLayout();
  EXPECT_EQ(item_count_before + 2, Items().size());
}

TEST_F(InlineNodeTest, InvalidateRemoveSpan) {
  SetupHtml("t", "<div id=t><span id=x></span></div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());

  Element* span = GetElementById("x");
  ASSERT_TRUE(span);
  span->remove();
  EXPECT_TRUE(layout_block_flow_->NeedsCollectInlines());
}

TEST_F(InlineNodeTest, InvalidateAddInnerSpan) {
  SetupHtml("t", "<div id=t><span id=x></span></div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());
  unsigned item_count_before = Items().size();

  Element* parent = GetElementById("x");
  ASSERT_TRUE(parent);
  Element* span = GetDocument().CreateRawElement(html_names::kSpanTag);
  parent->appendChild(span);

  // NeedsCollectInlines() is marked during the layout.
  // By re-collecting inlines, open/close items should be added.
  ForceLayout();
  EXPECT_EQ(item_count_before + 2, Items().size());
}

TEST_F(InlineNodeTest, InvalidateRemoveInnerSpan) {
  SetupHtml("t", "<div id=t><span><span id=x></span></span></div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());

  Element* span = GetElementById("x");
  ASSERT_TRUE(span);
  span->remove();
  EXPECT_TRUE(layout_block_flow_->NeedsCollectInlines());
}

TEST_F(InlineNodeTest, InvalidateSetText) {
  SetupHtml("t", "<div id=t>before</div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());

  auto* text = To<LayoutText>(layout_block_flow_->FirstChild());
  text->SetTextIfNeeded(String("after").Impl());
  EXPECT_TRUE(layout_block_flow_->NeedsCollectInlines());
}

TEST_F(InlineNodeTest, InvalidateAddAbsolute) {
  SetupHtml("t",
            "<style>span { position: absolute; }</style>"
            "<div id=t>before</div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());
  unsigned item_count_before = Items().size();

  auto* parent = To<Element>(layout_block_flow_->GetNode());
  Element* span = GetDocument().CreateRawElement(html_names::kSpanTag);
  parent->appendChild(span);

  // NeedsCollectInlines() is marked during the layout.
  // By re-collecting inlines, an OOF item should be added.
  ForceLayout();
  EXPECT_EQ(item_count_before + 1, Items().size());
}

TEST_F(InlineNodeTest, InvalidateRemoveAbsolute) {
  SetupHtml("t",
            "<style>span { position: absolute; }</style>"
            "<div id=t>before<span id=x></span></div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());

  Element* span = GetElementById("x");
  ASSERT_TRUE(span);
  span->remove();
  EXPECT_TRUE(layout_block_flow_->NeedsCollectInlines());
}

TEST_F(InlineNodeTest, InvalidateChangeToAbsolute) {
  SetupHtml("t",
            "<style>#y { position: absolute; }</style>"
            "<div id=t>before<span id=x></span></div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());
  unsigned item_count_before = Items().size();

  Element* span = GetElementById("x");
  ASSERT_TRUE(span);
  span->SetIdAttribute(AtomicString("y"));

  // NeedsCollectInlines() is marked during the layout.
  // By re-collecting inlines, an open/close items should be replaced with an
  // OOF item.
  ForceLayout();
  EXPECT_EQ(item_count_before - 1, Items().size());
}

TEST_F(InlineNodeTest, InvalidateChangeFromAbsolute) {
  SetupHtml("t",
            "<style>#x { position: absolute; }</style>"
            "<div id=t>before<span id=x></span></div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());
  unsigned item_count_before = Items().size();

  Element* span = GetElementById("x");
  ASSERT_TRUE(span);
  span->SetIdAttribute(AtomicString("y"));

  // NeedsCollectInlines() is marked during the layout.
  // By re-collecting inlines, an OOF item should be replaced with open/close
  // items..
  ForceLayout();
  EXPECT_EQ(item_count_before + 1, Items().size());
}

TEST_F(InlineNodeTest, InvalidateAddFloat) {
  SetupHtml("t",
            "<style>span { float: left; }</style>"
            "<div id=t>before</div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());
  unsigned item_count_before = Items().size();

  auto* parent = To<Element>(layout_block_flow_->GetNode());
  Element* span = GetDocument().CreateRawElement(html_names::kSpanTag);
  parent->appendChild(span);

  // NeedsCollectInlines() is marked during the layout.
  // By re-collecting inlines, an float item should be added.
  ForceLayout();
  EXPECT_EQ(item_count_before + 1, Items().size());
}

TEST_F(InlineNodeTest, InvalidateRemoveFloat) {
  SetupHtml("t",
            "<style>span { float: left; }</style>"
            "<div id=t>before<span id=x></span></div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());

  Element* span = GetElementById("x");
  ASSERT_TRUE(span);
  span->remove();
  EXPECT_TRUE(layout_block_flow_->NeedsCollectInlines());
}

TEST_F(InlineNodeTest, SpaceRestoredByInsertingWord) {
  SetupHtml("t", "<div id=t>before <span id=x></span> after</div>");
  EXPECT_FALSE(layout_block_flow_->NeedsCollectInlines());
  EXPECT_EQ(String("before after"), GetText());

  Element* span = GetElementById("x");
  ASSERT_TRUE(span);
  Text* text = Text::Create(GetDocument(), "mid");
  span->appendChild(text);
  // EXPECT_TRUE(layout_block_flow_->NeedsCollectInlines());

  ForceLayout();
  EXPECT_EQ(String("before mid after"), GetText());
}

TEST_F(InlineNodeTest, RemoveInlineNodeDataIfBlockBecomesEmpty1) {
  SetupHtml("container", "<div id=container><b id=remove><i>foo</i></b></div>");
  ASSERT_TRUE(layout_block_flow_->GetInlineNodeData());

  Element* to_remove = GetElementById("remove");
  to_remove->remove();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(layout_block_flow_->GetInlineNodeData());
}

TEST_F(InlineNodeTest, RemoveInlineNodeDataIfBlockBecomesEmpty2) {
  SetupHtml("container", "<div id=container><b><i>foo</i></b></div>");
  ASSERT_TRUE(layout_block_flow_->GetInlineNodeData());

  GetElementById("container")->setInnerHTML("");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(layout_block_flow_->GetInlineNodeData());
}

TEST_F(InlineNodeTest, RemoveInlineNodeDataIfBlockObtainsBlockChild) {
  SetupHtml("container",
            "<div id=container><b id=blockify><i>foo</i></b></div>");
  ASSERT_TRUE(layout_block_flow_->GetInlineNodeData());

  GetElementById("blockify")
      ->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kBlock);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(layout_block_flow_->GetInlineNodeData());
}

// Test inline objects are initialized when |SplitFlow()| moves them.
TEST_F(InlineNodeTest, ClearFirstInlineFragmentOnSplitFlow) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      <span id=outer_span>
        <span id=inner_span>1234</span>
      </span>
    </div>
  )HTML");

  // Keep the text fragment to compare later.
  Element* inner_span = GetElementById("inner_span");
  Node* text = inner_span->firstChild();
  InlineCursor before_split;
  before_split.MoveTo(*text->GetLayoutObject());
  EXPECT_TRUE(before_split);

  // Append <div> to <span>. causing SplitFlow().
  Element* outer_span = GetElementById("outer_span");
  Element* div = GetDocument().CreateRawElement(html_names::kDivTag);
  outer_span->appendChild(div);

  // Update tree but do NOT update layout. At this point, there's no guarantee,
  // but there are some clients (e.g., Scroll Anchor) who try to read
  // associated fragments.
  //
  // NGPaintFragment is owned by LayoutBlockFlow. Because the original owner
  // no longer has an inline formatting context, the NGPaintFragment subtree is
  // destroyed, and should not be accessible.
  GetDocument().UpdateStyleAndLayoutTree();
  const LayoutObject* layout_text = text->GetLayoutObject();
  EXPECT_TRUE(layout_text->IsInLayoutNGInlineFormattingContext());
  EXPECT_TRUE(layout_text->HasInlineFragments());

  // Update layout. There should be a different instance of the text fragment.
  UpdateAllLifecyclePhasesForTest();
  InlineCursor after_layout;
  after_layout.MoveTo(*text->GetLayoutObject());
  EXPECT_TRUE(after_layout);

  // Check it is the one owned by the new root inline formatting context.
  LayoutBlock* inner_span_cb = inner_span->GetLayoutObject()->ContainingBlock();
  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_EQ(inner_span_cb, container);
  InlineCursor inner_span_cb_cursor(*To<LayoutBlockFlow>(inner_span_cb));
  inner_span_cb_cursor.MoveToFirstLine();
  inner_span_cb_cursor.MoveToFirstChild();
  EXPECT_TRUE(inner_span_cb_cursor);
  EXPECT_EQ(inner_span_cb_cursor.Current().GetLayoutObject(),
            outer_span->GetLayoutObject());
}

TEST_F(InlineNodeTest, AddChildToSVGRoot) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      text
      <svg id="svg"></svg>
    </div>
  )HTML");

  Element* svg = GetElementById("svg");
  svg->appendChild(GetDocument().CreateRawElement(svg_names::kTextTag));
  GetDocument().UpdateStyleAndLayoutTree();

  LayoutObject* container = GetLayoutObjectByElementId("container");
  EXPECT_FALSE(container->NeedsCollectInlines());
}

// https://crbug.com/911220
TEST_F(InlineNodeTest, PreservedNewlineWithBidiAndRelayout) {
  SetupHtml("container",
            "<style>span{unicode-bidi:isolate}</style>"
            "<pre id=container>foo<span>\n</span>bar<br></pre>");
  EXPECT_EQ(String(u"foo\u2066\u2069\n\u2066\u2069bar\n"), GetText());

  Node* new_text = Text::Create(GetDocument(), "baz");
  GetElementById("container")->appendChild(new_text);
  UpdateAllLifecyclePhasesForTest();

  // The bidi context popping and re-entering should be preserved around '\n'.
  EXPECT_EQ(String(u"foo\u2066\u2069\n\u2066\u2069bar\nbaz"), GetText());
}

TEST_F(InlineNodeTest, PreservedNewlineWithRemovedBidiAndRelayout) {
  SetupHtml("container",
            "<pre id=container>foo<span dir=rtl>\nbar</span></pre>");
  EXPECT_EQ(String(u"foo\u2067\u2069\n\u2067bar\u2069"), GetText());

  GetDocument()
      .QuerySelector(AtomicString("span"))
      ->removeAttribute(html_names::kDirAttr);
  UpdateAllLifecyclePhasesForTest();

  // The bidi control characters around '\n' should not preserve
  EXPECT_EQ("foo\nbar", GetText());
}

TEST_F(InlineNodeTest, PreservedNewlineWithRemovedLtrDirAndRelayout) {
  SetupHtml("container",
            "<pre id=container>foo<span dir=ltr>\nbar</span></pre>");
  EXPECT_EQ(String(u"foo\u2066\u2069\n\u2066bar\u2069"), GetText());

  GetDocument()
      .QuerySelector(AtomicString("span"))
      ->removeAttribute(html_names::kDirAttr);
  UpdateAllLifecyclePhasesForTest();

  // The bidi control characters around '\n' should not preserve
  EXPECT_EQ("foo\nbar", GetText());
}

// https://crbug.com/969089
TEST_F(InlineNodeTest, InsertedWBRWithLineBreakInRelayout) {
  SetupHtml("container", "<div id=container><span>foo</span>\nbar</div>");
  EXPECT_EQ("foo bar", GetText());

  Element* div = GetElementById("container");
  Element* wbr = GetDocument().CreateElementForBinding(AtomicString("wbr"));
  div->insertBefore(wbr, div->lastChild());
  UpdateAllLifecyclePhasesForTest();

  // The '\n' should be collapsed by the inserted <wbr>
  EXPECT_EQ(String(u"foo\u200Bbar"), GetText());
}

TEST_F(InlineNodeTest, CollapsibleSpaceFollowingBRWithNoWrapStyle) {
  SetupHtml("t", "<div id=t><span style=white-space:pre><br></span> </div>");
  EXPECT_EQ("\n", GetText());

  GetDocument()
      .QuerySelector(AtomicString("span"))
      ->removeAttribute(html_names::kStyleAttr);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("\n", GetText());
}

TEST_F(InlineNodeTest, CollapsibleSpaceFollowingNewlineWithPreStyle) {
  SetupHtml("t", "<div id=t><span style=white-space:pre>\n</span> </div>");
  EXPECT_EQ("\n", GetText());

  GetDocument()
      .QuerySelector(AtomicString("span"))
      ->removeAttribute(html_names::kStyleAttr);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("", GetText());
}

#if SEGMENT_BREAK_TRANSFORMATION_FOR_EAST_ASIAN_WIDTH
// https://crbug.com/879088
TEST_F(InlineNodeTest, RemoveSegmentBreakFromJapaneseInRelayout) {
  SetupHtml("container",
            u"<div id=container>"
            u"<span>\u30ED\u30B0\u30A4\u30F3</span>"
            u"\n"
            u"<span>\u767B\u9332</span>"
            u"<br></div>");
  EXPECT_EQ(String(u"\u30ED\u30B0\u30A4\u30F3\u767B\u9332\n"), GetText());

  Node* new_text = Text::Create(GetDocument(), "foo");
  GetElementById("container")->appendChild(new_text);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(String(u"\u30ED\u30B0\u30A4\u30F3\u767B\u9332\nfoo"), GetText());
}

// https://crbug.com/879088
TEST_F(InlineNodeTest, RemoveSegmentBreakFromJapaneseInRelayout2) {
  SetupHtml("container",
            u"<div id=container>"
            u"<span>\u30ED\u30B0\u30A4\u30F3</span>"
            u"\n"
            u"<span> \u767B\u9332</span>"
            u"<br></div>");
  EXPECT_EQ(String(u"\u30ED\u30B0\u30A4\u30F3\u767B\u9332\n"), GetText());

  Node* new_text = Text::Create(GetDocument(), "foo");
  GetElementById("container")->appendChild(new_text);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(String(u"\u30ED\u30B0\u30A4\u30F3\u767B\u9332\nfoo"), GetText());
}
#endif

TEST_F(InlineNodeTest, SegmentRanges) {
  SetupHtml("container",
            "<div id=container>"
            u"\u306Forange\u304C"
            "<span>text</span>"
            "</div>");

  InlineItemsData* items_data = layout_block_flow_->GetInlineNodeData();
  ASSERT_TRUE(items_data);
  InlineItemSegments* segments = items_data->segments.get();
  ASSERT_TRUE(segments);

  // Test EndOffset for the full text. All segment boundaries including the end
  // of the text content should be returned.
  Vector<unsigned> expect_0_12 = {1u, 7u, 8u, 12u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(0, 12, 0)), expect_0_12);

  // Test ranges for each segment that start with 1st item.
  Vector<unsigned> expect_0_1 = {1u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(0, 1, 0)), expect_0_1);
  Vector<unsigned> expect_2_3 = {3u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(2, 3, 0)), expect_2_3);
  Vector<unsigned> expect_7_8 = {8u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(7, 8, 0)), expect_7_8);

  // Test ranges that acrosses multiple segments.
  Vector<unsigned> expect_0_8 = {1u, 7u, 8u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(0, 8, 0)), expect_0_8);
  Vector<unsigned> expect_2_8 = {7u, 8u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(2, 8, 0)), expect_2_8);
  Vector<unsigned> expect_2_10 = {7u, 8u, 10u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(2, 10, 0)), expect_2_10);
  Vector<unsigned> expect_7_10 = {8u, 10u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(7, 10, 0)), expect_7_10);

  // Test ranges that starts with 2nd item.
  Vector<unsigned> expect_8_9 = {9u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(8, 9, 1)), expect_8_9);
  Vector<unsigned> expect_8_10 = {10u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(8, 10, 1)), expect_8_10);
  Vector<unsigned> expect_9_12 = {12u};
  EXPECT_EQ(ToEndOffsetList(segments->Ranges(9, 12, 1)), expect_9_12);
}

// https://crbug.com/1275383
TEST_F(InlineNodeTest, ReusingWithPreservedCase1) {
  SetupHtml("container",
            "<div id=container>"
            "a"
            "<br id='remove'>"
            "<span style='white-space: pre-wrap'> ijkl </span>"
            "</div>");
  EXPECT_EQ(String(u"a\n \u200Bijkl "), GetText());
  GetElementById("remove")->remove();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(String(u"a ijkl "), GetText());
}

// https://crbug.com/1275383
TEST_F(InlineNodeTest, ReusingWithPreservedCase2) {
  SetupHtml("container",
            "<div id=container style='white-space: pre-wrap'>"
            "a "
            "<br id='remove'>"
            "<span> ijkl </span>"
            "</div>");
  EXPECT_EQ(String(u"a \n \u200Bijkl "), GetText());
  GetElementById("remove")->remove();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(String(u"a  ijkl "), GetText());
}

// https://crbug.com/1275383
TEST_F(InlineNodeTest, ReusingWithPreservedCase3) {
  SetupHtml("container",
            "<div id=container style='white-space: pre-wrap'>"
            " "
            "<br id='remove'>"
            "<span> ijkl </span>"
            "</div>");
  EXPECT_EQ(String(u" \u200B\n \u200Bijkl "), GetText());
  GetElementById("remove")->remove();
  UpdateAllLifecyclePhasesForTest();
  // TODO(jfernandez): This should be "  \u200Bijkl ", but there is clearly a
  // bug that causes the first control item to be preserved, while the second is
  // ignored (due to the presence of the previous control break).
  // https://crbug.com/1276358
  EXPECT_EQ(String(u" \u200B ijkl "), GetText());
}

// https://crbug.com/1021677
TEST_F(InlineNodeTest, ReusingWithCollapsed) {
  SetupHtml("container",
            "<div id=container>"
            "abc "
            "<img style='float:right'>"
            "<br id='remove'>"
            "<b style='white-space:pre'>x</b>"
            "</div>");
  GetElementById("remove")->remove();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(String(u"abc \uFFFCx"), GetText());
}

// https://crbug.com/109654
TEST_F(InlineNodeTest, ReusingRTLAsLTR) {
  SetupHtml("container",
            "<div id=container>"
            "<span id='text' dir=rtl>"
            "[Text]text"
            "</span>"
            "</div>");
  EXPECT_EQ(String(u"\u2067[Text]text\u2069"), GetText());
  EXPECT_EQ(Items().size(), 8u);
  TEST_ITEM_OFFSET_DIR(Items()[0], 0u, 1u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(Items()[1], 1u, 1u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(Items()[2], 1u, 2u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(Items()[3], 2u, 6u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(Items()[4], 6u, 7u, TextDirection::kRtl);
  TEST_ITEM_OFFSET_DIR(Items()[5], 7u, 11u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(Items()[6], 11u, 11u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(Items()[7], 11u, 12u, TextDirection::kLtr);
  GetElementById("text")->removeAttribute(html_names::kDirAttr);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(String("[Text]text"), GetText());
  EXPECT_EQ(Items().size(), 3u);
  TEST_ITEM_OFFSET_DIR(Items()[0], 0u, 0u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(Items()[1], 0u, 10u, TextDirection::kLtr);
  TEST_ITEM_OFFSET_DIR(Items()[2], 10u, 10u, TextDirection::kLtr);
}

TEST_F(InlineNodeTest, ReuseFirstNonSafe) {
  SetBodyInnerHTML(R"HTML(
    <style>
    p {
      font-size: 50px;
    }
    </style>
    <p id="p">
      <span>A</span>V
    </p>
  )HTML");
  auto* block_flow = To<LayoutBlockFlow>(GetLayoutObjectByElementId("p"));
  const InlineNodeData* data = block_flow->GetInlineNodeData();
  ASSERT_TRUE(data);
  const auto& items = data->items;

  // We shape "AV" together, which usually has kerning between "A" and "V", then
  // split the |ShapeResult| to two |InlineItem|s. The |InlineItem| for "V"
  // is not safe to reuse even if its style does not change.
  const InlineItem& item_v = items[3];
  EXPECT_EQ(item_v.Type(), InlineItem::kText);
  EXPECT_EQ(
      StringView(data->text_content, item_v.StartOffset(), item_v.Length()),
      "V");
  EXPECT_TRUE(InlineNode::NeedsShapingForTesting(item_v));
}

TEST_F(InlineNodeTest, ReuseFirstNonSafeRtl) {
  SetBodyInnerHTML(R"HTML(
    <style>
    p {
      font-size: 50px;
      unicode-bidi: bidi-override;
      direction: rtl;
    }
    </style>
    <p id="p">
      <span>A</span>V
    </p>
  )HTML");
  auto* block_flow = To<LayoutBlockFlow>(GetLayoutObjectByElementId("p"));
  const InlineNodeData* data = block_flow->GetInlineNodeData();
  ASSERT_TRUE(data);
  const auto& items = data->items;
  const InlineItem& item_v = items[4];
  EXPECT_EQ(item_v.Type(), InlineItem::kText);
  EXPECT_EQ(
      StringView(data->text_content, item_v.StartOffset(), item_v.Length()),
      "V");
  EXPECT_TRUE(InlineNode::NeedsShapingForTesting(item_v));
}

// http://crbug.com/1409702
TEST_F(InlineNodeTest, ShouldNotResueLigature) {
  LoadGoogleSans();
  InsertStyleElement("#sample { font-family: 'Google Sans'; }");
  SetBodyContent("<div id=sample>abf<span>i</span></div>");
  Element& sample = *GetElementById("sample");

  // `shape_result_before` has a ligature "fi".
  const LayoutText& layout_text =
      *To<Text>(sample.firstChild())->GetLayoutObject();
  const ShapeResult& shape_result_before =
      *layout_text.InlineItems().begin()->TextShapeResult();
  ASSERT_EQ(3u, shape_result_before.NumGlyphs());

  const LayoutText& layout_text_i =
      *To<Text>(sample.lastChild()->firstChild())->GetLayoutObject();
  const ShapeResult& shape_result_i =
      *layout_text_i.InlineItems().begin()->TextShapeResult();
  ASSERT_EQ(0u, shape_result_i.NumGlyphs());

  // To <div id=sample>abf</div>
  sample.lastChild()->remove();
  UpdateAllLifecyclePhasesForTest();

  const ShapeResult& shape_result_after =
      *layout_text.InlineItems().begin()->TextShapeResult();
  EXPECT_NE(&shape_result_before, &shape_result_after);
}

TEST_F(InlineNodeTest, InitialLetter) {
  LoadAhem();
  InsertStyleElement(
      "p { font: 20px/24px Ahem; }"
      "p::first-letter { initial-letter: 3 }");
  SetBodyContent("<p id=sample>This paragraph has an initial letter.</p>");
  auto& sample = *GetElementById("sample");
  auto& block_flow = *To<LayoutBlockFlow>(sample.GetLayoutObject());
  auto& initial_letter_box = *To<LayoutBlockFlow>(
      sample.GetPseudoElement(kPseudoIdFirstLetter)->GetLayoutObject());

  EXPECT_TRUE(InlineNode(&block_flow).HasInitialLetterBox());
  EXPECT_TRUE(BlockNode(&initial_letter_box).IsInitialLetterBox());
  EXPECT_TRUE(InlineNode(&initial_letter_box).IsInitialLetterBox());
  EXPECT_TRUE(initial_letter_box.GetPhysicalFragment(0)->IsInitialLetterBox());

  const InlineNodeData& data = *block_flow.GetInlineNodeData();
  const InlineItem& initial_letter_item = data.items[0];
  EXPECT_EQ(InlineItem::kInitialLetterBox, initial_letter_item.Type());
}

TEST_F(InlineNodeTest, TextCombineUsesScalingX) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "  font: 10px/20px Ahem;"
      "  text-combine-upright: all;"
      "  writing-mode: vertical-rl;"
      "}");
  SetBodyInnerHTML("<div id=t1>0123456789</div><div id=t2>0</div>");

  EXPECT_TRUE(
      To<LayoutTextCombine>(GetLayoutObjectByElementId("t1")->SlowFirstChild())
          ->UsesScaleX())
      << "We paint combined text '0123456789' with scaling in X-axis.";
  EXPECT_FALSE(
      To<LayoutTextCombine>(GetLayoutObjectByElementId("t2")->SlowFirstChild())
          ->UsesScaleX())
      << "We paint combined text '0' without scaling in X-axis.";
}

// http://crbug.com/1226930
TEST_F(InlineNodeTest, TextCombineWordSpacing) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "  font: 10px/20px Ahem;"
      "  letter-spacing: 1px;"
      "  text-combine-upright: all;"
      "  word-spacing: 1px;"
      "  writing-mode: vertical-rl;"
      "}");
  SetBodyInnerHTML("<div id=t1>ab</div>");
  const auto& text =
      *To<Text>(GetElementById("t1")->firstChild())->GetLayoutObject();
  const auto& font_description = text.StyleRef().GetFont().GetFontDescription();

  EXPECT_EQ(0, font_description.LetterSpacing());
  EXPECT_EQ(0, font_description.WordSpacing());
}

// crbug.com/1034464 bad.svg
TEST_F(InlineNodeTest, FindSvgTextChunksCrash1) {
  SetBodyInnerHTML(
      "<svg><text id='text' xml:space='preserve'>"
      "<tspan unicode-bidi='embed' x='0'>(</tspan>"
      "<tspan y='-2' unicode-bidi='embed' x='3'>)</tspan>"
      "<tspan y='-2' x='6'>&#x05d2;</tspan>"
      "<tspan y='-2' unicode-bidi='embed' x='10'>(</tspan>"
      "</text></svg>");

  auto* block_flow = To<LayoutSVGText>(GetLayoutObjectByElementId("text"));
  const InlineNodeData* data = block_flow->GetInlineNodeData();
  EXPECT_TRUE(data);
  // Pass if no null pointer dereferences.
}

// crbug.com/1034464 good.svg
TEST_F(InlineNodeTest, FindSvgTextChunksCrash2) {
  SetBodyInnerHTML(
      "<svg><text id='text' xml:space='preserve'>\n"
      "<tspan unicode-bidi='embed' x='0'>(</tspan>\n"
      "<tspan y='-2' unicode-bidi='embed' x='3'>)</tspan>\n"
      "<tspan y='-2' x='6'>&#x05d2;</tspan>\n"
      "<tspan y='-2' unicode-bidi='embed' x='10'>(</tspan>\n"
      "</text></svg>");

  auto* block_flow = To<LayoutSVGText>(GetLayoutObjectByElementId("text"));
  const InlineNodeData* data = block_flow->GetInlineNodeData();
  EXPECT_TRUE(data);
  // Pass if no DCHECK() failures.
}

// crbug.com/1403838
TEST_F(InlineNodeTest, FindSvgTextChunksCrash3) {
  SetBodyInnerHTML(R"SVG(
      <svg><text id='text'>
      <tspan x='0' id='target'>PA</tspan>
      <tspan x='0' y='24'>PASS</tspan>
      </text></svg>)SVG");
  auto* tspan = GetElementById("target");
  // A trail surrogate, then a lead surrogate.
  constexpr UChar kText[2] = {0xDE48, 0xD864};
  const String text{base::span(kText)};
  tspan->appendChild(GetDocument().createTextNode(text));
  tspan->appendChild(GetDocument().createTextNode(text));
  tspan->appendChild(GetDocument().createTextNode(text));
  tspan->appendChild(GetDocument().createTextNode(text));
  tspan->appendChild(GetDocument().createTextNode(text));
  tspan->appendChild(GetDocument().createTextNode(text));
  UpdateAllLifecyclePhasesForTest();
  // Pass if no CHECK() failures in FindSvgTextChunks().
}

TEST_F(InlineNodeTest, ShapeCacheDisabled) {
  ScopedLayoutNGShapeCacheForTest scoped_feature(false);

  SetupHtml("t",
            "<style>div { font-family: serif; }</style>"
            "<div id=t>abc</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();
  EXPECT_EQ("abc", node.Text());

  const String& text_content(node.Text().c_str());
  HeapVector<InlineItem>& items = node.Items();
  ShapeResultSpacing<String> spacing(text_content, node.IsSvgText());

  EXPECT_FALSE(
      node.IsNGShapeCacheAllowed(text_content, nullptr, items, spacing));
}

TEST_F(InlineNodeTest, ShapeCacheLongString) {
  ScopedLayoutNGShapeCacheForTest scoped_feature(true);

  SetupHtml("t", "<div id=t>abcdefghijklmnopqrstuvwxyz</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();

  const String& text_content(node.Text().c_str());
  HeapVector<InlineItem>& items = node.Items();
  ShapeResultSpacing<String> spacing(text_content, node.IsSvgText());

  EXPECT_FALSE(
      node.IsNGShapeCacheAllowed(text_content, nullptr, items, spacing));
}

TEST_F(InlineNodeTest, ShapeCacheMultiItems) {
  ScopedLayoutNGShapeCacheForTest scoped_feature(true);

  SetupHtml("t", "<div id=t>abc<span>def</span>ghi</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();

  const String& text_content(node.Text().c_str());
  HeapVector<InlineItem>& items = node.Items();
  EXPECT_EQ(5u, items.size());
  ShapeResultSpacing<String> spacing(text_content, node.IsSvgText());

  EXPECT_FALSE(
      node.IsNGShapeCacheAllowed(text_content, nullptr, items, spacing));
}

TEST_F(InlineNodeTest, ShapeCacheSpacingRequired) {
  ScopedLayoutNGShapeCacheForTest scoped_feature(true);

  SetupHtml("t",
            "<style>div { letter-spacing: 5px; }</style>"
            "<div id=t>abc</div>");
  InlineNodeForTest node = CreateInlineNode();
  node.CollectInlines();

  const String& text_content(node.Text().c_str());
  HeapVector<InlineItem>& items = node.Items();
  ShapeResultSpacing<String> spacing(text_content, node.IsSvgText());

  EXPECT_FALSE(
      node.IsNGShapeCacheAllowed(text_content, nullpt
```