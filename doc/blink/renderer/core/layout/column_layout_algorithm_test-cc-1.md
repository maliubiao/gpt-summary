Response:
The user wants me to summarize the functionality of the provided C++ test file snippet. The file seems to be testing the column layout algorithm in the Chromium Blink engine. Specifically, it appears to be verifying how different CSS properties like `column-fill`, `column-gap`, `break-inside`, `margin-top`, `margin-bottom`, `line-height`, `orphans`, `widows`, and floats interact within a multi-column layout.

For each `TEST_F` function, I need to:
1. **Identify the core CSS property being tested.**
2. **Understand the expected layout behavior based on the HTML and CSS.** This often involves interpreting how the column layout algorithm should distribute content across columns.
3. **Relate the test to HTML, CSS, and potentially JavaScript concepts.** While this is a C++ test, the underlying behavior is driven by CSS and HTML structure.
4. **Infer the logic being tested.**  This often involves considering edge cases and boundary conditions, like elements that almost fit or elements with specific break requirements.
5. **Summarize the functionality of the provided snippet.**
这是 `column_layout_algorithm_test.cc` 文件的第 2 部分，主要功能是测试 Blink 引擎在处理多列布局时对于各种 CSS 属性和特殊情况的布局计算是否正确。这部分着重测试了以下几个方面：

**功能归纳:**

1. **`break-inside: avoid` 的嵌套和边界情况:**  测试了当设置了 `break-inside: avoid` 的元素嵌套在多列容器中时，布局引擎如何避免在这些元素内部进行分列，以及在接近列边界时的处理方式。
2. **元素 margin 在列边界的处理:** 测试了当元素的 `margin-top` 或 `margin-bottom` 导致元素跨越列边界时，布局引擎如何处理这些 margin，尤其是在元素紧贴或超出列尾部时的行为。
3. **多列布局中的行框（line box）处理:** 测试了在多列布局中，当内容为多行文本时，布局引擎如何分配行框到不同的列，包括剩余空间的处理、精确匹配的情况以及子元素包含多行文本的情况。
4. **多列布局中 `orphans` 和 `widows` 属性的影响:** 测试了 `orphans` 和 `widows` 属性如何影响多列布局中的分页行为，即避免在列的开头或结尾出现过少的行。包括可满足条件和无法满足条件的情况。
5. **多列布局中浮动元素（float）的处理:** 测试了浮动元素在多列布局中的定位和分布，以及 `orphans` 和 `widows` 属性如何影响包含浮动元素的块级元素的分布。
6. **多列布局中 border 和 padding 的影响:** 测试了 border 和 padding 如何影响多列容器和其子元素的布局计算。
7. **避免在设置了 `break-before: avoid` 的元素前分页:** 测试了在多列布局中，布局引擎优先避免在设置了 `break-before: avoid` 的元素前分页，即使这可能违反 `orphans` 或 `widows` 的规则。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **HTML 结构:**  每个 `TEST_F` 函数都通过 `SetBodyInnerHTML` 方法设置了特定的 HTML 结构，这是测试的基础。例如，创建包含多层 `div` 元素的结构来测试 `break-inside: avoid` 的嵌套效果。
*   **CSS 样式:**  通过 `<style>` 标签定义 CSS 样式，这些样式直接控制了多列布局的行为，如 `columns`, `column-gap`, `column-fill`, `height`, `width`, `break-inside`, `margin-top`, `margin-bottom`, `line-height`, `orphans`, `widows`, `float`, `border`, `padding` 等。
*   **CSS 分页属性:**  测试重点在于 CSS 的分页属性，例如 `break-inside: avoid`，`orphans`，`widows`，以及隐式的分页行为。
*   **JavaScript (间接关系):** 虽然测试代码是 C++，但它验证的是 Blink 引擎的布局能力，而这种布局能力最终会影响到 JavaScript 操作 DOM 元素后的渲染结果。开发者可以通过 JavaScript 修改元素的样式，从而触发不同的布局行为。

**逻辑推理的假设输入与输出:**

**示例 1: `NestedBreakInsideAvoidTall` 测试**

*   **假设输入 (HTML/CSS):**
    ```html
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:10px; height:50px;"></div>
        <div style="break-inside:avoid; width:30px;">
          <div style="width:21px; height:30px;"></div>
          <div style="break-inside:avoid; width:22px; height:80px;"></div>
        </div>
      </div>
    </div>
    ```
*   **逻辑推理:**
    *   父元素 `#parent` 分为 3 列，每列宽度约为 100px (320px / 3 - 2 \* 10px / 3)。
    *   第一个子 `div` (10x50) 可以放入第一列。
    *   第二个子 `div` 设置了 `break-inside:avoid`，其高度为内部两个 `div` 的高度之和，即 30px + 80px = 110px。
    *   由于第二个子 `div` 设置了 `break-inside:avoid`，且高度超过了第一列剩余空间，它会被整体移动到下一列。
    *   虽然第二个子 `div` 可以放入第二列，但其内部第二个子 `div` 也设置了 `break-inside:avoid` 且高度为 80px，超过了第二列的剩余空间。因此，内部第二个子 `div` 会被移动到第三列。
*   **预期输出 (DumpFragmentTree):**
    ```
    .:: LayoutNG Physical Fragment Tree ::.
    offset:unplaced size:1000x100
      offset:0,0 size:320x100
        offset:0,0 size:100x100
          offset:0,0 size:10x50
        offset:110,0 size:100x100
          offset:0,0 size:30x100
            offset:0,0 size:21x30
        offset:220,0 size:100x100
          offset:0,0 size:30x80
            offset:0,0 size:22x80
    ```

**用户或编程常见的使用错误举例说明:**

1. **误解 `break-inside: avoid` 的作用域:**  开发者可能认为给一个父元素设置了 `break-inside: avoid` 就能阻止其所有子元素被分页，但实际上，`break-inside: avoid` 主要阻止的是元素自身内部的分页。如果子元素也设置了 `break-inside: avoid` 且自身过高，仍然会被整体移动到下一列。
2. **忽略 `orphans` 和 `widows` 对布局的影响:** 开发者可能没有考虑到 `orphans` 和 `widows` 属性，导致在多列布局中出现单行或少量行在列的开头或结尾的情况，影响阅读体验。
3. **过度依赖 `break-inside: avoid` 导致布局混乱:**  大量使用 `break-inside: avoid` 可能会导致某些元素无法放入当前列，而被强制推到后续列，造成列的高度不一致或内容分布不均匀。
4. **对 margin 在列边界的行为不熟悉:**  开发者可能不清楚当元素的 margin 导致其超出列边界时，浏览器会如何处理这些 margin，可能导致意料之外的空白或元素位置偏移。例如，错误地认为一个设置了很大 `margin-top` 的元素会直接从下一列的顶部开始，而没有考虑到 margin 的折叠或截断。

总而言之，这部分测试用例旨在覆盖多列布局中各种复杂的场景和 CSS 属性交互，确保 Blink 引擎能够按照 CSS 规范正确地进行布局计算。

Prompt: 
```
这是目录为blink/renderer/core/layout/column_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:10px; height:50px;"></div>
        <div style="break-inside:avoid; width:20px; height:170px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:10x50
      offset:110,0 size:100x100
        offset:0,0 size:20x100
      offset:220,0 size:100x100
        offset:0,0 size:20x70
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedBreakInsideAvoid) {
  // If there were no break-inside:avoid on the outer DIV here, there'd be a
  // break between the two inner ones, since they wouldn't both fit in the first
  // column. However, since the outer DIV does have such a declaration,
  // everything is supposed to be pushed to the second column, with no space
  // between the children.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:10px; height:50px;"></div>
        <div style="break-inside:avoid; width:30px;">
          <div style="break-inside:avoid; width:21px; height:30px;"></div>
          <div style="break-inside:avoid; width:22px; height:30px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:10x50
      offset:110,0 size:100x100
        offset:0,0 size:30x60
          offset:0,0 size:21x30
          offset:0,30 size:22x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedBreakInsideAvoidTall) {
  // Here the outer DIV with break-inside:avoid is too tall to fit where it
  // occurs naturally, so it needs to be pushed to the second column. It's not
  // going to fit fully there either, though, since its two children don't fit
  // together. Its second child wants to avoid breaks inside, so it will be
  // moved to the third column.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:10px; height:50px;"></div>
        <div style="break-inside:avoid; width:30px;">
          <div style="width:21px; height:30px;"></div>
          <div style="break-inside:avoid; width:22px; height:80px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:10x50
      offset:110,0 size:100x100
        offset:0,0 size:30x100
          offset:0,0 size:21x30
      offset:220,0 size:100x100
        offset:0,0 size:30x80
          offset:0,0 size:22x80
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideAvoidAtColumnBoundary) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:90px;"></div>
        <div>
          <div style="break-inside:avoid; width:20px; height:20px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x90
      offset:110,0 size:100x100
        offset:0,0 size:100x20
          offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, MarginTopPastEndOfFragmentainer) {
  // A block whose border box would start past the end of the current
  // fragmentainer should start exactly at the start of the next fragmentainer,
  // discarding what's left of the margin.
  // https://www.w3.org/TR/css-break-3/#break-margins
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:90px;"></div>
        <div style="margin-top:20px; width:20px; height:20px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x90
      offset:110,0 size:100x100
        offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, MarginBottomPastEndOfFragmentainer) {
  // A block whose border box would start past the end of the current
  // fragmentainer should start exactly at the start of the next fragmentainer,
  // discarding what's left of the margin.
  // https://www.w3.org/TR/css-break-3/#break-margins
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="margin-bottom:20px; height:90px;"></div>
        <div style="width:20px; height:20px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x90
      offset:110,0 size:100x100
        offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, MarginTopAtEndOfFragmentainer) {
  // A block whose border box is flush with the end of the fragmentainer
  // shouldn't produce an empty fragment there - only one fragment in the next
  // fragmentainer.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:90px;"></div>
        <div style="margin-top:10px; width:20px; height:20px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x90
      offset:110,0 size:100x100
        offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, MarginBottomAtEndOfFragmentainer) {
  // A block whose border box is flush with the end of the fragmentainer
  // shouldn't produce an empty fragment there - only one fragment in the next
  // fragmentainer.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="margin-bottom:10px; height:90px;"></div>
        <div style="width:20px; height:20px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x90
      offset:110,0 size:100x100
        offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, LinesInMulticolExtraSpace) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 50px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:100x50
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:110,0 size:100x50
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, LinesInMulticolExactFit) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 40px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:320x40
      offset:0,0 size:100x40
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:110,0 size:100x40
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, LinesInMulticolChildExtraSpace) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 50px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:77px;">
          <br>
          <br>
          <br>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:77x50
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:110,0 size:100x50
        offset:0,0 size:77x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, LinesInMulticolChildExactFit) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 40px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:77px;">
          <br>
          <br>
          <br>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x40
    offset:0,0 size:320x40
      offset:0,0 size:100x40
        offset:0,0 size:77x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:110,0 size:100x40
        offset:0,0 size:77x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, LinesInMulticolChildNoSpaceForFirst) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 50px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:50px;"></div>
        <div style="width:77px;">
          <br>
          <br>
          <br>
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
      offset:110,0 size:100x50
        offset:0,0 size:77x50
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:220,0 size:100x50
        offset:0,0 size:77x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest,
       LinesInMulticolChildInsufficientSpaceForFirst) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 50px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:40px;"></div>
        <div style="width:77px;">
          <br>
          <br>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:100x40
      offset:110,0 size:100x50
        offset:0,0 size:77x50
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:220,0 size:100x50
        offset:0,0 size:77x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, LineAtColumnBoundaryInFirstBlock) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 50px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:66px; padding-top:40px;">
          <br>
        </div>
      </div>
    </div>
  )HTML");

  // It's not ideal to break before a first child that's flush with the content
  // edge of its container, but if there are no earlier break opportunities, we
  // may still have to do that. There's no class A, B or C break point [1]
  // between the DIV and the line established for the BR, but since a line is
  // monolithic content [1], we really have to try to avoid breaking inside it.
  //
  // [1] https://www.w3.org/TR/css-break-3/#possible-breaks

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:66x50
      offset:110,0 size:100x50
        offset:0,0 size:66x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, LinesAndFloatsMulticol) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 70px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <div style="float:left; width:10px; height:120px;"></div>
        <br>
        <div style="float:left; width:11px; height:120px;"></div>
        <br>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x70
    offset:0,0 size:320x70
      offset:0,0 size:100x70
        offset:0,0 size:100x70
          offset:0,0 size:0x20
          offset:10,20 size:0x20
          offset:21,40 size:0x20
      offset:110,0 size:100x70
        offset:0,0 size:100x40
          offset:0,0 size:0x0
          offset:0,0 size:0x0
          offset:21,0 size:0x20
          offset:21,20 size:0x20
      offset:220,0 size:100x70
        offset:0,0 size:100x0
          offset:0,0 size:0x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatBelowLastLineInColumn) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 70px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <div style="float:left; width:11px; height:120px;"></div>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x70
    offset:0,0 size:320x70
      offset:0,0 size:100x70
        offset:0,0 size:100x70
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
      offset:110,0 size:100x70
        offset:0,0 size:100x40
          offset:11,0 size:0x20
          offset:11,20 size:0x20
      offset:220,0 size:100x70
        offset:0,0 size:100x0
          offset:0,0 size:0x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, Orphans) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 90px;
        line-height: 20px;
        orphans: 3;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:40px;"></div>
        <div style="width:77px;">
          <br>
          <br>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x90
    offset:0,0 size:320x90
      offset:0,0 size:100x90
        offset:0,0 size:100x40
      offset:110,0 size:100x90
        offset:0,0 size:77x60
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, OrphansUnsatisfiable) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 90px;
        line-height: 20px;
        orphans: 100;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x90
    offset:0,0 size:320x90
      offset:0,0 size:100x90
        offset:0,0 size:100x90
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
          offset:0,60 size:0x20
      offset:110,0 size:100x90
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, Widows) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 110px;
        line-height: 20px;
        orphans: 1;
        widows: 3;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x110
    offset:0,0 size:320x110
      offset:0,0 size:100x110
        offset:0,0 size:100x110
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
          offset:0,60 size:0x20
      offset:110,0 size:100x110
        offset:0,0 size:100x60
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, WidowsUnsatisfiable) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 90px;
        line-height: 20px;
        orphans: 1;
        widows: 100;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x90
    offset:0,0 size:320x90
      offset:0,0 size:100x90
        offset:0,0 size:100x90
          offset:0,0 size:0x20
      offset:110,0 size:100x90
        offset:0,0 size:100x90
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
          offset:0,60 size:0x20
      offset:220,0 size:100x90
        offset:0,0 size:100x90
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
          offset:0,60 size:0x20
      offset:330,0 size:100x90
        offset:0,0 size:100x90
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
          offset:0,60 size:0x20
      offset:440,0 size:100x90
        offset:0,0 size:100x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, OrphansAndUnsatisfiableWidows) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 70px;
        line-height: 20px;
        orphans: 2;
        widows: 3;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x70
    offset:0,0 size:320x70
      offset:0,0 size:100x70
        offset:0,0 size:100x70
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:110,0 size:100x70
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, UnsatisfiableOrphansAndWidows) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 70px;
        line-height: 20px;
        orphans: 4;
        widows: 4;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x70
    offset:0,0 size:320x70
      offset:0,0 size:100x70
        offset:0,0 size:100x70
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
      offset:110,0 size:100x70
        offset:0,0 size:100x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, WidowsAndAbspos) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 70px;
        line-height: 20px;
        orphans: 1;
        widows: 3;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="position:relative;">
          <br>
          <br>
          <br>
          <br>
          <div style="position:absolute; width:33px; height:33px;"></div>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x70
    offset:0,0 size:320x70
      offset:0,0 size:100x70
        offset:0,0 size:100x70
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:110,0 size:100x70
        offset:0,0 size:100x60
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
        offset:0,40 size:33x30
      offset:220,0 size:100x70
        offset:0,0 size:33x3
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakBetweenLinesNotBefore) {
  // Just breaking where we run out of space is perfect, since it won't violate
  // the orphans/widows requirement, since there'll be two lines both before and
  // after the break.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 2;
        widows: 2;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:44px; height:60px;"></div>
        <div style="width:55px;">
          <br>
          <br>
          <br>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:44x60
        offset:0,60 size:55x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:110,0 size:100x100
        offset:0,0 size:55x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakBetweenLinesNotBefore2) {
  // Prefer breaking between lines and violate an orphans requirement, rather
  // than violating break-before:avoid.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 2;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:44px; height:80px;"></div>
        <div style="break-before:avoid; width:55px;">
          <br>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:44x80
        offset:0,80 size:55x20
          offset:0,0 size:0x20
      offset:110,0 size:100x100
        offset:0,0 size:55x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakBetweenLinesNotBefore3) {
  // Prefer breaking between lines and violate a widows requirement, rather than
  // violating break-before:avoid.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 1;
        widows: 2;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:44px; height:80px;"></div>
        <div style="break-before:avoid; width:55px;">
          <br>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:44x80
        offset:0,80 size:55x20
          offset:0,0 size:0x20
      offset:110,0 size:100x100
        offset:0,0 size:55x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatInBlockMovedByOrphans) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 70px;
        line-height: 20px;
        orphans: 2;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:11px; height:40px;"></div>
        <div style="width:77px;">
          <br>
          <div style="float:left; width:10px; height:10px;"></div>
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x70
    offset:0,0 size:320x70
      offset:0,0 size:100x70
        offset:0,0 size:11x40
      offset:110,0 size:100x70
        offset:0,0 size:77x40
          offset:0,0 size:0x20
          offset:10,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, FloatMovedWithWidows) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 90px;
        line-height: 20px;
        orphans: 1;
        widows: 4;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <div style="float:left; width:10px; height:10px;"></div>
        <br>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x90
    offset:0,0 size:320x90
      offset:0,0 size:100x90
        offset:0,0 size:100x90
          offset:0,0 size:0x20
      offset:110,0 size:100x90
        offset:0,0 size:100x80
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:10,40 size:0x20
          offset:0,60 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BorderAndPadding) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent" style="border:3px solid; padding:2px;">
        <div style="width:30px; height:150px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x110
    offset:0,0 size:330x110
      offset:5,5 size:100x100
        offset:0,0 size:30x100
      offset:115,5 size:100x100
        offset:0,0 size:30x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, BreakInsideWithBorder) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-fill: auto;
        column-gap: 10px;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:85px;"
"""


```