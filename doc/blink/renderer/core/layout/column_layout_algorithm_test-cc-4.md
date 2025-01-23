Response:
The user wants a summary of the functionalities of the C++ source code file `blink/renderer/core/layout/column_layout_algorithm_test.cc`.

The file seems to contain unit tests for the column layout algorithm in the Blink rendering engine. These tests verify how elements are laid out within multi-column containers, specifically focusing on the behavior of spanning elements (`column-span: all`).

To summarize the functionalities, I will go through each test case and describe what aspect of column layout it is testing.

Key concepts involved:
- Multi-column layout (`columns` CSS property)
- Column gaps (`column-gap`)
- Spanning elements (`column-span: all`)
- Fragmentation of content across columns
- Handling of breaks (`break-before`, `break-after`, `break-inside`)
- Margins and borders of spanning elements
- Nested multi-column layouts

Based on the test names and the provided HTML snippets, the file tests:

- Basic multi-column layout with content flowing into columns.
- The behavior of a spanning element in the middle of other content.
- A spanning element at the beginning of the content.
- A spanning element at the end of the content.
- A spanning element as the only child.
- A spanning element nested within other elements but in the same formatting context.
- A spanning element with siblings within a block.
- A spanning element within a block that has siblings.
- Margins on spanning elements.
- Margins on spanning elements in right-to-left direction.
- Spanning element in a fixed-size multi-column container.
- Spanning element with top margin and border.
- Breaking inside a spanning element that is itself inside a multi-column.
- Handling of invalid spanning elements (inside new formatting contexts).
- Breaking inside nested spanning elements.
- Breaking inside a spanning element with content within it.
- Forced breaks between spanning elements.
- Soft breaks (automatic breaks due to lack of space) between spanning elements.
- Avoidance of soft breaks between spanning elements.
- Interactions between breaks and orphan/widow properties.
- Soft break between regular column content and a spanning element.
这是对Blink引擎中负责多列布局算法进行测试的C++代码文件。 具体来说，它测试了当多列布局中存在跨列元素（使用 `column-span: all`）时的布局行为。

这个文件通过一系列的单元测试，模拟了各种HTML结构和CSS样式，然后断言生成的布局树（Fragment Tree）是否符合预期。布局树描述了元素在页面上的位置和尺寸。

**与 Javascript, HTML, CSS 的关系：**

这个测试文件直接测试了CSS `columns` 和 `column-span` 属性对HTML元素布局的影响。当浏览器解析HTML和CSS时，会使用类似的布局算法来确定最终的页面渲染结果。

**举例说明：**

例如，在测试用例 `SpannerInMiddle` 中，它创建了一个包含多个 `div.content` 元素和一个 `column-span:all` 的 `div` 的多列容器。

**HTML:**

```html
<div id="container">
  <div id="parent">
    <div class="content"></div>
    <div class="content"></div>
    <div class="content"></div>
    <div class="content"></div>
    <div style="column-span:all; height:44px;"></div>
    <div class="content"></div>
    <div class="content"></div>
    <div class="content"></div>
    <div class="content"></div>
    <div class="content"></div>
  </div>
</div>
```

**CSS (在测试用例中定义):**

```css
#parent {
  columns: 3;
  column-gap: 10px;
  width: 320px;
  border: 1px solid;
}
.content { break-inside:avoid; height:20px; }
```

这个测试的目标是验证 `column-span:all` 的 `div` 是否正确地跨越了所有三列，并且其前后的内容是否正确地排列在列中。 布局算法需要计算出每个 `div` 元素在多列容器中的正确位置和尺寸。

**逻辑推理，假设输入与输出：**

**假设输入 (基于 `SpannerInMiddle` 测试用例):**

- 一个宽度为 320px 的多列容器 (`#parent`)，分为 3 列，列间距为 10px。
- 前面有 4 个高度为 20px 的 `div.content` 元素。
- 中间有一个设置了 `column-span:all` 和 `height: 44px` 的 `div` 元素。
- 后面有 5 个高度为 20px 的 `div.content` 元素。

**预期输出 (布局树片段):**

```
offset:0,0 size:322x202  // 多列容器的尺寸
  offset:1,1 size:100x40  // 前两个 content 在第一列
    offset:0,0 size:100x20
    offset:0,20 size:100x20
  offset:111,1 size:100x40 // 中间两个 content 在第二列
    offset:0,0 size:100x20
    offset:0,20 size:100x20
  offset:221,1 size:100x40 // 最后一个 content 在第三列
    offset:0,0 size:100x20
  offset:1,41 size:320x44 // span all 的元素跨越所有列
  offset:1,85 size:100x116 // 后面的 content 从第一列开始排列
    offset:0,0 size:100x20
    offset:0,20 size:100x20
    offset:0,40 size:100x20
    offset:0,60 size:100x20
    offset:0,80 size:100x20
```

**用户或编程常见的使用错误：**

1. **误解 `column-span` 的作用域：**  `column-span` 只能应用于多列容器的直接子元素。 如果将 `column-span` 应用于非直接子元素，它将被视为普通属性，不起跨列作用。

   ```html
   <div style="columns: 2;">
     <div>
       <p style="column-span: all;">This will not span columns.</p>
     </div>
   </div>
   ```

2. **在非块级元素上使用 `column-span`：**  `column-span` 主要用于块级元素。  虽然某些浏览器可能允许在其他类型的元素上使用，但其行为可能不一致或不符合预期。

3. **与浮动元素或绝对定位元素混合使用：**  跨列元素与浮动元素或绝对定位元素的交互可能很复杂，可能导致意外的布局结果。 建议谨慎使用，并进行充分测试。

4. **忘记考虑 `break-inside: avoid`：**  如果多列容器的内容设置了 `break-inside: avoid`，浏览器会尽量避免在元素内部断列，这可能会影响跨列元素的布局以及其他列的填充。

**归纳一下它的功能 (作为第5部分):**

到目前为止（前5部分），这个测试文件已经覆盖了多列布局算法中关于跨列元素的基本和一些更复杂的场景，包括：

- 跨列元素在不同位置（开始、中间、结尾）的表现。
- 跨列元素作为唯一子元素的情况。
- 跨列元素在嵌套元素中的行为（但仍然在相同的格式化上下文中）。
- 跨列元素与兄弟元素之间的相互影响。
- 跨列元素的边距 (margin) 处理，包括在 RTL (从右到左) 布局中的情况。
- 跨列元素在固定高度的多列容器中的布局。
- 跨列元素与外边距叠加 (margin collapsing) 的交互。
- 在嵌套的多列布局中，跨列元素内部的断行控制 (`break-inside`)。
- 错误使用 `column-span` 的情况 (例如在新的格式化上下文中)。
- 更复杂的嵌套多列布局中，跨列元素的断行行为。
- 跨列元素自身包含内容的情况。
- 通过 `break-before` 和 `break-after` 强制在跨列元素之间断列。
- 由于空间不足而导致的自动断列 (soft break) 在跨列元素间的处理。
- 避免在特定的跨列元素前发生自动断列。
- 在跨列元素之间，为了满足 `orphans` 和 `widows` 属性，可能违反避免断列的请求。
- 跨列元素与普通列内容之间的自动断列。

总之，到目前为止，测试的重点是验证布局引擎如何正确地放置和调整跨列元素，以及这些元素如何影响其他列中内容的布局和断行行为。

### 提示词
```
这是目录为blink/renderer/core/layout/column_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
ontent"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div style="column-span:all; height:44px;"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x202
    offset:0,0 size:322x202
      offset:1,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,1 size:100x40
        offset:0,0 size:100x20
      offset:1,41 size:320x44
      offset:1,85 size:100x116
        offset:0,0 size:100x20
        offset:0,20 size:100x20
        offset:0,40 size:100x20
        offset:0,60 size:100x20
        offset:0,80 size:100x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerAtStart) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        border: 1px solid;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="column-span:all; height:44px;"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x86
    offset:0,0 size:322x86
      offset:1,1 size:100x0
      offset:1,1 size:320x44
      offset:1,45 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,45 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,45 size:100x40
        offset:0,0 size:100x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerAtEnd) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        border: 1px solid;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div style="column-span:all; height:44px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x86
    offset:0,0 size:322x86
      offset:1,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,1 size:100x40
        offset:0,0 size:100x20
      offset:1,41 size:320x44
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerAlone) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        border: 1px solid;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="column-span:all; height:44px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x46
    offset:0,0 size:322x46
      offset:1,1 size:100x0
      offset:1,1 size:320x44
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerInBlock) {
  // Spanners don't have to be direct children of the multicol container, but
  // have to be defined in the same block formatting context as the one
  // established by the multicol container.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        border: 1px solid;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:11px;">
          <div style="column-span:all; height:44px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x46
    offset:0,0 size:322x46
      offset:1,1 size:100x0
        offset:0,0 size:11x0
      offset:1,1 size:320x44
      offset:1,45 size:100x0
        offset:0,0 size:11x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerWithSiblingsInBlock) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        border: 1px solid;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:11px;">
          <div style="column-span:all; height:44px;"></div>
          <div class="content"></div>
          <div class="content"></div>
          <div class="content"></div>
          <div class="content"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x86
    offset:0,0 size:322x86
      offset:1,1 size:100x0
        offset:0,0 size:11x0
      offset:1,1 size:320x44
      offset:1,45 size:100x40
        offset:0,0 size:11x40
          offset:0,0 size:11x20
          offset:0,20 size:11x20
      offset:111,45 size:100x40
        offset:0,0 size:11x40
          offset:0,0 size:11x20
          offset:0,20 size:11x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerInBlockWithSiblings) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        border: 1px solid;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:11px;">
          <div style="column-span:all; height:44px;"></div>
        </div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
        <div class="content"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x86
    offset:0,0 size:322x86
      offset:1,1 size:100x0
        offset:0,0 size:11x0
      offset:1,1 size:320x44
      offset:1,45 size:100x40
        offset:0,0 size:11x0
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,45 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerMargins) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="column-span:all; margin:10px; width:33px; height:10px;"></div>
        <div class="content"></div>
        <div style="column-span:all; margin:10px auto; width:44px; height:10px;"></div>
        <div style="column-span:all; margin:20px; width:55px;"></div>
        <div style="column-span:all; margin:10px; width:66px; height:10px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x130
    offset:0,0 size:320x130
      offset:0,0 size:100x0
      offset:10,10 size:33x10
      offset:0,30 size:100x20
        offset:0,0 size:100x20
      offset:138,60 size:44x10
      offset:20,90 size:55x0
      offset:10,110 size:66x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerMarginsRtl) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        direction: rtl;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="column-span:all; margin:10px; width:33px; height:10px;"></div>
        <div class="content"></div>
        <div style="column-span:all; margin:10px auto; width:44px; height:10px;"></div>
        <div style="column-span:all; margin:20px; width:55px;"></div>
        <div style="column-span:all; margin:10px; width:66px; height:10px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x130
    offset:0,0 size:320x130
      offset:220,0 size:100x0
      offset:277,10 size:33x10
      offset:220,30 size:100x20
        offset:0,0 size:100x20
      offset:138,60 size:44x10
      offset:245,90 size:55x0
      offset:244,110 size:66x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FixedSizeMulticolWithSpanner) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 300px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:33px; height:300px;"></div>
        <div style="column-span:all; width:44px; height:50px;"></div>
        <div style="width:55px; height:450px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x300
    offset:0,0 size:320x300
      offset:0,0 size:100x100
        offset:0,0 size:33x100
      offset:110,0 size:100x100
        offset:0,0 size:33x100
      offset:220,0 size:100x100
        offset:0,0 size:33x100
      offset:0,100 size:44x50
      offset:0,150 size:100x150
        offset:0,0 size:55x150
      offset:110,150 size:100x150
        offset:0,0 size:55x150
      offset:220,150 size:100x150
        offset:0,0 size:55x150
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, MarginAndBorderTopWithSpanner) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:22px; margin-top:200px; border-top:100px solid;">
          <div style="column-span:all; width:33px; height:100px;"></div>
          <div style="width:44px; height:300px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x500
    offset:0,0 size:320x500
      offset:0,0 size:100x300
        offset:0,200 size:22x100
      offset:0,300 size:33x100
      offset:0,400 size:100x100
        offset:0,0 size:22x100
          offset:0,0 size:44x100
      offset:110,400 size:100x100
        offset:0,0 size:22x100
          offset:0,0 size:44x100
      offset:220,400 size:100x100
        offset:0,0 size:22x100
          offset:0,0 size:44x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideSpannerWithMargins) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        column-fill: auto;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="columns:2; column-gap:0;">
          <div style="column-span:all; margin-top:10px; margin-bottom:20px; width:33px; height:100px;"></div>
          <div style="column-span:all; width:44px; height:10px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,10 size:33x90
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:33x10
          offset:0,30 size:44x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, InvalidSpanners) {
  // Spanners cannot exist inside new formatting context roots. They will just
  // be treated as normal column content then.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        border: 1px solid;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="float:left; width:10px;">
          <div style="column-span:all; height:30px;"></div>
        </div>
        <div style="display:flow-root;">
          <div style="column-span:all; height:30px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x12
    offset:0,0 size:322x12
      offset:1,1 size:100x10
        offset:0,0 size:10x10
          offset:0,0 size:10x10
        offset:10,0 size:90x10
          offset:0,0 size:90x10
      offset:111,1 size:100x10
        offset:0,0 size:10x10
          offset:0,0 size:10x10
        offset:10,0 size:90x10
          offset:0,0 size:90x10
      offset:221,1 size:100x10
        offset:0,0 size:10x10
          offset:0,0 size:10x10
        offset:10,0 size:90x10
          offset:0,0 size:90x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideSpanner) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:50px; column-fill:auto; width:320px; }
      .inner { columns:2; height:100px; column-fill:auto; padding:1px; }
      .outer, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="content"></div>
        <div class="inner">
          <div class="content"></div>
          <div class="content"></div>
          <div style="column-span:all; height:35px;"></div>
          <div class="content" style="width:7px;"></div>
          <div class="content" style="width:8px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:100x20
        offset:0,20 size:100x30
          offset:1,1 size:44x20
            offset:0,0 size:44x20
          offset:55,1 size:44x20
            offset:0,0 size:44x20
          offset:1,21 size:98x9
      offset:110,0 size:100x50
        offset:0,0 size:100x50
          offset:1,0 size:98x26
          offset:1,26 size:44x24
            offset:0,0 size:7x20
          offset:55,26 size:44x24
            offset:0,0 size:8x20
      offset:220,0 size:100x50
        offset:0,0 size:100x22
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideSpannerTwice) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:50px; column-fill:auto; width:320px; }
      .inner { columns:2; height:150px; column-fill:auto; padding:1px; }
      .outer, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="content"></div>
        <div class="inner">
          <div class="content"></div>
          <div class="content"></div>
          <div style="column-span:all; height:85px;"></div>
          <div class="content" style="width:7px;"></div>
          <div class="content" style="width:8px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:100x20
        offset:0,20 size:100x30
          offset:1,1 size:44x20
            offset:0,0 size:44x20
          offset:55,1 size:44x20
            offset:0,0 size:44x20
          offset:1,21 size:98x9
      offset:110,0 size:100x50
        offset:0,0 size:100x50
          offset:1,0 size:98x50
      offset:220,0 size:100x50
        offset:0,0 size:100x50
          offset:1,0 size:98x26
          offset:1,26 size:44x24
            offset:0,0 size:7x20
          offset:55,26 size:44x24
            offset:0,0 size:8x20
      offset:330,0 size:100x50
        offset:0,0 size:100x22
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideSpannerWithContent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:50px; column-fill:auto; width:320px; }
      .inner { columns:2; height:98px; column-fill:auto; padding:1px; }
      .outer, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div class="content"></div>
          <div class="content"></div>
          <div style="column-span:all;">
            <div style="width:3px;" class="content"></div>
            <div style="width:4px;" class="content"></div>
          </div>
          <div class="content" style="width:7px;"></div>
          <div class="content" style="width:8px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:100x50
          offset:1,1 size:44x20
            offset:0,0 size:44x20
          offset:55,1 size:44x20
            offset:0,0 size:44x20
          offset:1,21 size:98x29
            offset:0,0 size:3x20
      offset:110,0 size:100x50
        offset:0,0 size:100x50
          offset:1,0 size:98x20
            offset:0,0 size:4x20
          offset:1,20 size:44x29
            offset:0,0 size:7x20
          offset:55,20 size:44x29
            offset:0,0 size:8x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedBreakBetweenSpanners) {
  // There are two spanners in a nested multicol. They could fit in the same
  // outer column, but there's a forced break between them.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; break-inside:avoid; width:55px; height:40px;"></div>
          <div style="column-span:all; break-before:column; break-inside:avoid; width:66px; height:40px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:55x40
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:66x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedBreakBetweenSpanners2) {
  // There are two spanners in a nested multicol. They could fit in the same
  // outer column, but there's a forced break between them.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; break-after:column; break-inside:avoid; width:55px; height:40px;"></div>
          <div style="column-span:all; break-inside:avoid; width:66px; height:40px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:55x40
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:66x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedBreakBetweenSpanners3) {
  // There are two spanners in a nested multicol. They could fit in the same
  // outer column, but there's a forced break after the last child of the first
  // spanner.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; break-inside:avoid; width:55px; height:40px;">
            <div style="width:33px; height:10px;"></div>
            <div style="break-after:column; width:44px; height:10px;"></div>
          </div>
          <div style="column-span:all; break-inside:avoid; width:66px; height:40px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:55x40
            offset:0,0 size:33x10
            offset:0,10 size:44x10
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:66x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedBreakBetweenSpanners4) {
  // There are two spanners in a nested multicol. They could fit in the same
  // outer column, but there's a forced break before the first child of the
  // last spanner.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; break-inside:avoid; width:55px; height:40px;"></div>
          <div style="column-span:all; break-inside:avoid; width:66px; height:40px;">
            <div style="break-before:column; width:33px; height:10px;"></div>
            <div style="width:44px; height:10px;"></div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:55x40
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:66x40
            offset:0,0 size:33x10
            offset:0,10 size:44x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedBreakBetweenSpanners5) {
  // There are two spanners in a nested multicol. They could fit in the same
  // outer column, but there's a forced break between them. The second spanner
  // has a top margin, which should be retained, due to the forced break.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; break-inside:avoid; width:55px; height:40px;"></div>
          <div style="column-span:all; break-before:column; break-inside:avoid; width:66px; height:40px; margin-top:10px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:55x40
      offset:110,0 size:100x100
        offset:0,0 size:100x50
          offset:0,10 size:66x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SoftBreakBetweenSpanners) {
  // There are two spanners in a nested multicol. They won't fit in the same
  // outer column, and we don't want to break inside. So we should break between
  // them.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; break-inside:avoid; width:55px; height:60px;"></div>
          <div style="column-span:all; break-inside:avoid; width:66px; height:60px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:55x60
      offset:110,0 size:100x100
        offset:0,0 size:100x60
          offset:0,0 size:66x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SoftBreakBetweenSpanners2) {
  // There are two spanners in a nested multicol. They won't fit in the same
  // outer column, and we don't want to break inside. So we should break between
  // them. The second spanner has a top margin, but it should be truncated since
  // it's at a soft break.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; break-inside:avoid; width:55px; height:60px;"></div>
          <div style="column-span:all; break-inside:avoid; width:66px; height:60px; margin-top:10px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:55x60
      offset:110,0 size:100x100
        offset:0,0 size:100x60
          offset:0,0 size:66x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidSoftBreakBetweenSpanners) {
  // There are three spanners in a nested multicol. The first two could fit in
  // the same outer column, but the third one is too tall, and we also don't
  // want to break before that one.So we should break between the two first
  // spanners.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; break-inside:avoid; width:55px; height:40px;"></div>
          <div style="column-span:all; break-inside:avoid; width:66px; height:40px;"></div>
          <div style="column-span:all; break-inside:avoid; break-before:avoid; width:77px; height:60px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:55x40
      offset:110,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:66x40
          offset:0,40 size:77x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidSoftBreakBetweenSpanners2) {
  // There are two spanners in a nested multicol. They won't fit in the same
  // outer column, but we don't want to break inside the second one, and also
  // not between the spanners. The first spanner is breakable, so we should
  // break at the most appealing breakpoint there, i.e. before its last child.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; column-fill:auto; column-gap:10px; width:320px; }
      .inner { columns:2; column-gap:0; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; width:11px;">
            <div class="content" style="width:22px;"></div>
            <div class="content" style="width:33px;"></div>
            <div class="content" style="width:44px;"></div>
          </div>
          <div style="column-span:all; break-inside:avoid; break-before:avoid; width:55px; height:60px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:11x100
            offset:0,0 size:22x20
            offset:0,20 size:33x20
      offset:110,0 size:100x100
        offset:0,0 size:100x80
          offset:0,0 size:11x20
            offset:0,0 size:44x20
          offset:0,20 size:55x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidSoftBreakBetweenSpanners3) {
  // Violate orphans and widows requests rather than break-between avoidance
  // requests.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer {
        columns:3;
        height:100px;
        column-fill:auto;
        column-gap:10px;
        width:320px;
        line-height: 20px;
        orphans: 3;
        widows: 3;
      }
      .inner { columns:2; column-gap:0; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; width:11px;">
            <br>
            <br>
            <br>
          </div>
          <div style="column-span:all; break-inside:avoid; break-before:avoid; width:55px; height:60px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:50x0
          offset:0,0 size:11x100
            offset:0,0 size:0x20
            offset:0,20 size:0x20
      offset:110,0 size:100x100
        offset:0,0 size:100x80
          offset:0,0 size:11x20
            offset:0,0 size:0x20
          offset:0,20 size:55x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SoftBreakBetweenRowAndSpanner) {
  // We have a nested multicol with some column cont
```