Response:
The user wants me to analyze a C++ source code file related to the Blink rendering engine, specifically the `column_layout_algorithm_test.cc` file. They want to know its functionality and how it relates to web technologies like JavaScript, HTML, and CSS. They also want examples of assumptions, inputs, outputs, and common usage errors. Finally, they want a summary of the file's function.

Here's a plan:

1. **Identify the core purpose of the file:** Given the name `column_layout_algorithm_test.cc`, the primary function is likely testing the column layout algorithm in Blink.
2. **Analyze the provided code snippets:** The code consists of various test cases using the `TEST_F` macro. Each test case sets up an HTML structure and then uses `DumpFragmentTree` to capture the output of the layout algorithm. This output represents the physical layout of the elements.
3. **Relate to web technologies:** The test cases directly use HTML and CSS properties related to multi-column layouts (e.g., `columns`, `column-gap`, `break-inside`, `column-span`). JavaScript might be indirectly related if the layout algorithm is influenced by JavaScript manipulations of the DOM or styles, but the provided snippets don't show direct interaction.
4. **Identify assumptions, inputs, and outputs:** Each test case implies an assumption about how the column layout algorithm should behave given specific HTML and CSS inputs. The HTML and CSS are the inputs, and the `DumpFragmentTree` output is the expected output.
5. **Consider common usage errors:**  Common errors might involve incorrect CSS syntax for multi-column properties or misunderstandings about how `break-inside`, `column-span`, and other related properties work.
6. **Summarize the functionality:** The file serves as a suite of unit tests to ensure the correctness of Blink's column layout algorithm.
这是 `blink/renderer/core/layout/column_layout_algorithm_test.cc` 文件的第 4 部分，它延续了前几部分的功能，主要用于测试 Blink 渲染引擎中**多列布局算法 (Column Layout Algorithm)** 的正确性。

**本部分的功能归纳:**

本部分继续测试了各种复杂场景下的多列布局算法，主要关注以下方面：

* **避免在元素内部打断 (`break-inside: avoid`) 的行为:** 验证了当元素设置了 `break-inside: avoid` 时，布局算法如何处理跨列的情况，以及与其它属性（如 `line-height`）的交互。
* **列平衡 (`column-fill: auto`) 的场景:**  测试了当列高不足以容纳所有内容时，列平衡算法如何工作，特别是在出现负 margin 和 `break-inside: avoid` 的情况下。
* **与浮动元素 (`float`) 的交互:**  验证了多列布局中浮动元素的存在如何影响后续元素的布局和断点，包括是否会产生强制断点 (Class C Break Point)。
* **强制断列 (`break-before: column`) 的效果:**  测试了使用 `break-before: column` 强制元素开始于新列的效果。
* **嵌套多列容器 (`Nested`) 的布局:**  这是本部分测试的重点，涵盖了多种嵌套场景，包括：
    * 嵌套容器的尺寸限制和内容分配。
    * 嵌套容器中 `break-inside: avoid` 的行为。
    * 嵌套容器的边距折叠 (`edible margin`)。
    * 嵌套容器在外部容器边界的情况。
    * 嵌套容器的内边距 (`padding`) 和边框 (`border`) 的影响。
    * 嵌套容器中包含 `column-span: all` 元素的行为。
* **绝对定位元素 (`position: absolute`) 在多列布局中的处理:** 测试了绝对定位元素如何放置在多列容器中。
* **跨列元素 (`column-span: all`) 的布局:** 验证了跨列元素的正确渲染，包括与内容共存的情况，以及百分比宽度跨列元素。
* **跨列元素对列平衡的影响:**  测试了跨列元素如何影响其前面内容的列平衡。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接测试了 CSS 中关于多列布局的特性，因此与 HTML 和 CSS 的关系非常密切。

* **HTML:** 测试用例通过 `SetBodyInnerHTML` 方法设置 HTML 结构，模拟了各种包含多列布局的 HTML 场景。例如，`<div id="parent">` 元素被设置为多列容器。
* **CSS:** 测试用例中的 `<style>` 标签内定义了 CSS 规则，这些规则直接控制了多列布局的行为，如 `columns`, `column-gap`, `column-fill`, `break-inside`, `break-before`, `column-span` 等属性。
* **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，主要测试渲染引擎的底层逻辑，但其测试的 CSS 属性经常被 JavaScript 操作。例如，JavaScript 可以动态地修改元素的 `style` 属性来改变多列布局的参数。

**举例说明：**

1. **`break-inside: avoid`:**
   * **HTML:** `<div style="break-inside:avoid;">This content should not be split across columns.</div>`
   * **CSS:** `#parent { columns: 2; width: 200px; }`
   * **功能关系:** 当 `#parent` 是一个两列的容器，且上述 `div` 的宽度大于单列宽度时，布局算法会尝试将整个 `div` 放在一个列中，可能导致该列高度超出预期，或者如果空间不足，可能将其推到下一列。

2. **`column-span: all`:**
   * **HTML:** `<div style="column-span:all;">This element spans across all columns.</div>`
   * **CSS:** `#parent { columns: 3; width: 300px; }`
   * **功能关系:** 带有 `column-span: all` 的 `div` 会横跨 `#parent` 元素的所有三列，其宽度会等于 `#parent` 的内容宽度，并打断正常的列布局流程。

3. **嵌套多列容器:**
   * **HTML:**
     ```html
     <div class="outer" style="columns: 2; width: 200px;">
       <div class="inner" style="columns: 3;">
         <div>Content in inner columns</div>
       </div>
     </div>
     ```
   * **CSS:**  定义 `.outer` 和 `.inner` 的其他样式。
   * **功能关系:**  布局算法需要处理嵌套的多列容器，确保内部列的布局受限于外部列的约束，并正确计算元素的尺寸和位置。

**逻辑推理、假设输入与输出：**

以 `TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingLinesAvoidBreakInside2)` 为例：

* **假设输入 (HTML & CSS):**
  ```html
  <style>
    #parent {
      columns: 3;
      column-gap: 10px;
      width: 320px;
      line-height: 20px;
      orphans: 1;
      widows: 1;
    }
  </style>
  <div id="container">
    <div id="parent">
      <br>
      <div style="break-inside:avoid;">
         <br><br><br>
      </div>
      <br>
    </div>
  </div>
  ```
* **逻辑推理:**  容器 `#parent` 有 5 行内容（3 个 `<br>` 元素各自占一行，中间的 `div` 包含 3 个 `<br>` 标签），被分成 3 列。中间的 `div` 设置了 `break-inside:avoid`，因此不能被分割到不同的列中。布局算法需要决定如何分配这些行，并确保中间的 `div` 完整地处于一个列中。考虑到列的高度限制和 `break-inside: avoid` 的约束，中间的 `div` 占据了第二列的全部高度。
* **预期输出 (DumpFragmentTree):**
  ```DUMP
  .:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x60
    offset:0,0 size:320x60
      offset:0,0 size:100x60
        offset:0,0 size:100x20
          offset:0,0 size:0x20
      offset:110,0 size:100x60
        offset:0,0 size:100x60
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
      offset:220,0 size:100x60
        offset:0,0 size:100x20
          offset:0,0 size:0x20
  )DUMP
  ```

**用户或编程常见的使用错误：**

1. **忘记设置多列容器的宽度：** 如果没有明确设置多列容器的 `width`，浏览器可能无法正确计算列的宽度，导致布局混乱。
   * **错误示例：**
     ```html
     <div style="columns: 3;">
       <div>Column 1</div>
       <div>Column 2</div>
       <div>Column 3</div>
     </div>
     ```

2. **错误理解 `break-inside: avoid` 的作用范围：**  `break-inside: avoid` 只阻止元素自身被分割到不同的列中，但不会阻止元素内的内容（例如文本行）被分割。
   * **错误理解示例：**  认为设置了 `break-inside: avoid` 的段落内的长文本永远不会换行显示在下一列。

3. **不恰当使用 `column-span: all`：**  过度使用或在不必要的地方使用 `column-span: all` 会破坏多列布局的结构。
   * **错误示例：**  在一个只需要部分宽度横跨的元素上使用了 `column-span: all`。

4. **混淆 `column-width` 和 `columns` 属性：** `column-width` 指定理想的列宽，浏览器会根据可用空间创建尽可能多的列，而 `columns` 直接指定要创建的列数。混淆使用可能导致非预期的列布局。

总而言之，`blink/renderer/core/layout/column_layout_algorithm_test.cc` 的这一部分是一个详尽的测试套件，旨在验证 Blink 渲染引擎在处理各种复杂的多列布局场景时的正确性和稳定性。它通过模拟不同的 HTML 结构和 CSS 样式，并断言布局结果是否符合预期来完成测试。

### 提示词
```
这是目录为blink/renderer/core/layout/column_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
d size:1000x60
    offset:0,0 size:320x60
      offset:0,0 size:100x60
        offset:0,0 size:100x20
          offset:0,0 size:0x20
      offset:110,0 size:100x60
        offset:0,0 size:100x60
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
      offset:220,0 size:100x60
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingLinesAvoidBreakInside2) {
  // We have 5 lines and 3 columns. If we make the columns tall enough to hold 2
  // lines each, it should all fit. But then there's a block with 3 lines and
  // break-inside:avoid...
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <div style="break-inside:avoid;">
           <br><br><br>
        </div>
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x60
    offset:0,0 size:320x60
      offset:0,0 size:100x60
        offset:0,0 size:100x20
          offset:0,0 size:0x20
      offset:110,0 size:100x60
        offset:0,0 size:100x60
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
      offset:220,0 size:100x60
        offset:0,0 size:100x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingUnderflow) {
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
        <div style="break-inside:avoid; margin-top:-100px; width:55px; height:110px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x10
    offset:0,0 size:320x10
      offset:0,0 size:100x10
        offset:0,-100 size:55x110
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ClassCBreakPointBeforeBfc) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height:100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:50px;"></div>
        <div style="float:left; width:100%; height:40px;"></div>
        <div style="width:55px;">
          <div style="display:flow-root; break-inside:avoid; width:44px; height:60px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:50x50
        offset:0,50 size:100x40
        offset:0,50 size:55x50
      offset:110,0 size:100x100
        offset:0,0 size:55x60
          offset:0,0 size:44x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NoClassCBreakPointBeforeBfc) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height:100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:50px;"></div>
        <div style="float:left; width:100%; height:40px;"></div>
        <div id="container" style="clear:both; width:55px;">
          <div style="display:flow-root; break-inside:avoid; width:44px; height:60px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:50x50
        offset:0,50 size:100x40
      offset:110,0 size:100x100
        offset:0,0 size:55x60
          offset:0,0 size:44x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ClassCBreakPointBeforeBfcWithClearance) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height:100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:50px;"></div>
        <div style="float:left; width:1px; height:40px;"></div>
        <div style="width:55px;">
          <div style="clear:both; display:flow-root; break-inside:avoid; width:44px; height:60px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:50x50
        offset:0,50 size:1x40
        offset:0,50 size:55x50
      offset:110,0 size:100x100
        offset:0,0 size:55x60
          offset:0,0 size:44x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ClassCBreakPointBeforeBfcWithMargin) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height:100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:50px;"></div>
        <div style="float:left; width:100%; height:40px;"></div>
        <div style="width:55px;">
          <div style="margin-top:39px; display:flow-root; break-inside:avoid; width:44px; height:60px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:50x50
        offset:0,50 size:100x40
        offset:0,50 size:55x50
      offset:110,0 size:100x100
        offset:0,0 size:55x60
          offset:0,0 size:44x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ClassCBreakPointBeforeBlockMarginCollapsing) {
  // We get a class C break point here, because we get clearance, because the
  // (collapsed) margin isn't large enough to take the block below the float on
  // its own.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height:100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:70px;"></div>
        <div style="float:left; width:100%; height:20px;"></div>
        <div style="border:1px solid; width:55px;">
          <div style="clear:left; width:44px; margin-top:10px;">
            <div style="margin-top:18px; break-inside:avoid; width:33px; height:20px;"></div>
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
        offset:0,0 size:50x70
        offset:0,70 size:100x20
        offset:0,70 size:57x30
      offset:110,0 size:100x100
        offset:0,0 size:57x21
          offset:1,0 size:44x20
            offset:0,0 size:33x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest,
       NoClassCBreakPointBeforeBlockMarginCollapsing) {
  // No class C break point here, because there's no clearance, because the
  // (collapsed) margin is large enough to take the block below the float on its
  // own.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height:100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:70px;"></div>
        <div style="float:left; width:100%; height:20px;"></div>
        <div style="border:1px solid; width:55px;">
          <div style="clear:left; width:44px; margin-top:10px;">
            <div style="margin-top:19px; break-inside:avoid; width:33px; height:20px;"></div>
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
        offset:0,0 size:50x70
        offset:0,70 size:100x20
      offset:110,0 size:100x100
        offset:0,0 size:57x41
          offset:1,20 size:44x20
            offset:0,0 size:33x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ClassCBreakPointBeforeLine) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height:100px;
        line-height: 20px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:70px;"></div>
        <div style="float:left; width:100%; height:20px;"></div>
        <div style="width:55px;">
          <div style="display:inline-block; width:33px; height:11px; vertical-align:top;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:50x70
        offset:0,70 size:100x20
        offset:0,70 size:55x30
      offset:110,0 size:100x100
        offset:0,0 size:55x20
          offset:0,0 size:33x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedBreakAtClassCBreakPoint) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height:100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:50px; height:50px;"></div>
        <div style="float:left; width:100%; height:40px;"></div>
        <div style="width:55px;">
          <div style="display:flow-root; break-before:column; width:44px; height:20px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:50x50
        offset:0,50 size:100x40
        offset:0,50 size:55x50
      offset:110,0 size:100x100
        offset:0,0 size:55x20
          offset:0,0 size:44x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, Nested) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:50px; column-fill:auto; width:320px; }
      .inner { columns:2; height:100px; column-fill:auto; padding:1px; }
      .outer, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="content" style="width:5px;"></div>
        <div class="inner">
          <div class="content" style="width:10px;"></div>
          <div class="content" style="width:20px;"></div>
          <div class="content" style="width:30px;"></div>
          <div class="content" style="width:40px;"></div>
          <div class="content" style="width:50px;"></div>
          <div class="content" style="width:60px;"></div>
          <div class="content" style="width:70px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:5x20
        offset:0,20 size:100x30
          offset:1,1 size:44x29
            offset:0,0 size:10x20
          offset:55,1 size:44x29
            offset:0,0 size:20x20
      offset:110,0 size:100x50
        offset:0,0 size:100x50
          offset:1,0 size:44x50
            offset:0,0 size:30x20
            offset:0,20 size:40x20
          offset:55,0 size:44x50
            offset:0,0 size:50x20
            offset:0,20 size:60x20
      offset:220,0 size:100x50
        offset:0,0 size:100x22
          offset:1,0 size:44x21
            offset:0,0 size:70x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedWithEdibleMargin) {
  // There's a block-start margin after an unforced break. It should be eaten by
  // the fragmentainer boundary.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:50px; column-fill:auto; width:320px; }
      .inner { columns:2; height:100px; column-fill:auto; }
      .outer, .inner { column-gap:10px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="width:5px; height:80px;"></div>
          <div style="break-inside:avoid; margin-top:30px; width:10px; height:10px;"></div>
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
          offset:0,0 size:45x50
            offset:0,0 size:5x50
          offset:55,0 size:45x50
            offset:0,0 size:5x30
      offset:110,0 size:100x50
        offset:0,0 size:100x50
          offset:0,0 size:45x50
            offset:0,0 size:10x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedNoInnerContent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:50px; column-fill:auto; width:320px; }
      .inner { columns:2; height:100px; column-fill:auto; padding:1px; }
      .outer, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="content" style="width:5px;"></div>
        <div class="inner"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:5x20
        offset:0,20 size:100x30
          offset:1,1 size:44x29
      offset:110,0 size:100x50
        offset:0,0 size:100x50
      offset:220,0 size:100x50
        offset:0,0 size:100x22
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedSomeInnerContent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:50px; column-fill:auto; width:320px; }
      .inner { columns:2; height:100px; column-fill:auto; padding:1px; }
      .outer, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="content" style="width:5px;"></div>
        <div class="inner">
          <div class="content" style="width:6px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:320x50
      offset:0,0 size:100x50
        offset:0,0 size:5x20
        offset:0,20 size:100x30
          offset:1,1 size:44x29
            offset:0,0 size:6x20
      offset:110,0 size:100x50
        offset:0,0 size:100x50
      offset:220,0 size:100x50
        offset:0,0 size:100x22
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedLimitedHeight) {
  // This tests that we don't advance to the next outer fragmentainer when we've
  // reached the bottom of an inner multicol container. We should create inner
  // columns that overflow in the inline direction in that case.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:2; height:50px; column-fill:auto; width:210px; }
      .inner { columns:2; height:80px; column-fill:auto; }
      .outer, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="content" style="width:5px;"></div>
        <div class="inner">
          <div class="content" style="width:10px;"></div>
          <div class="content" style="width:20px;"></div>
          <div class="content" style="width:30px;"></div>
          <div class="content" style="width:40px;"></div>
          <div class="content" style="width:50px;"></div>
          <div class="content" style="width:60px;"></div>
          <div class="content" style="width:70px;"></div>
          <div class="content" style="width:80px;"></div>
          <div class="content" style="width:90px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:210x50
      offset:0,0 size:100x50
        offset:0,0 size:5x20
        offset:0,20 size:100x30
          offset:0,0 size:45x30
            offset:0,0 size:10x20
          offset:55,0 size:45x30
            offset:0,0 size:20x20
      offset:110,0 size:100x50
        offset:0,0 size:100x50
          offset:0,0 size:45x50
            offset:0,0 size:30x20
            offset:0,20 size:40x20
          offset:55,0 size:45x50
            offset:0,0 size:50x20
            offset:0,20 size:60x20
          offset:110,0 size:45x50
            offset:0,0 size:70x20
            offset:0,20 size:80x20
          offset:165,0 size:45x50
            offset:0,0 size:90x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedLimitedHeightWithPadding) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; width:320px; height:100px; }
      .inner { columns:2; height:100px; padding-top:50px; }
      .outer, .inner { column-gap:10px; column-fill:auto; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="width:22px; height:200px;"></div>
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
          offset:0,50 size:45x50
            offset:0,0 size:22x50
          offset:55,50 size:45x50
            offset:0,0 size:22x50
      offset:110,0 size:100x100
        offset:0,0 size:100x50
          offset:0,0 size:45x50
            offset:0,0 size:22x50
          offset:55,0 size:45x50
            offset:0,0 size:22x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedUnbalancedInnerAutoHeight) {
  // The fragments generated by an inner multicol are block-size constrained by
  // the outer multicol, so if column-fill is auto, we shouldn't forcefully
  // balance.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:2; height:50px; column-fill:auto; width:210px; }
      .inner { columns:2; column-fill:auto; }
      .outer, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div class="content"></div>
          <div class="content"></div>
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
  offset:unplaced size:1000x50
    offset:0,0 size:210x50
      offset:0,0 size:100x50
        offset:0,0 size:100x50
          offset:0,0 size:45x50
            offset:0,0 size:45x20
            offset:0,20 size:45x20
          offset:55,0 size:45x50
            offset:0,0 size:45x20
            offset:0,20 size:45x20
      offset:110,0 size:100x50
        offset:0,0 size:100x40
          offset:0,0 size:45x50
            offset:0,0 size:45x20
            offset:0,20 size:45x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedAtOuterBoundary) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; width:320px; }
      .inner { columns:2; height:50px; }
      .outer, .inner { column-gap:10px; column-fill:auto; }
    </style>
    <div id="container">
      <div class="outer">
        <div style="width:11px; height:100px;"></div>
        <div class="inner">
          <div style="width:22px; height:70px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:11x100
      offset:110,0 size:100x100
        offset:0,0 size:100x50
          offset:0,0 size:45x50
            offset:0,0 size:22x50
          offset:55,0 size:45x50
            offset:0,0 size:22x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedZeroHeightAtOuterBoundary) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; width:320px; }
      .inner { columns:2; }
      .outer, .inner { column-gap:10px; column-fill:auto; }
    </style>
    <div id="container">
      <div class="outer">
        <div style="width:11px; height:100px;"></div>
        <div class="inner">
          <div style="width:22px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:11x100
        offset:0,100 size:100x0
          offset:0,0 size:45x0
            offset:0,0 size:22x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedWithMarginAtOuterBoundary) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; width:320px; }
      .inner { columns:2; height:50px; margin-top:20px; }
      .outer, .inner { column-gap:10px; column-fill:auto; }
    </style>
    <div id="container">
      <div class="outer">
        <div style="width:11px; height:90px;"></div>
        <div class="inner">
          <div style="width:22px; height:70px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:11x90
      offset:110,0 size:100x100
        offset:0,0 size:100x50
          offset:0,0 size:45x50
            offset:0,0 size:22x50
          offset:55,0 size:45x50
            offset:0,0 size:22x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedWithTallBorder) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; width:320px; }
      .inner { columns:2; height:50px; border-top:100px solid; }
      .outer, .inner { column-gap:10px; column-fill:auto; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="width:22px; height:70px;"></div>
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
      offset:110,0 size:100x100
        offset:0,0 size:100x50
          offset:0,0 size:45x50
            offset:0,0 size:22x50
          offset:55,0 size:45x50
            offset:0,0 size:22x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NestedWithTallSpanner) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:100px; width:320px; column-fill:auto; }
      .inner { columns:2; }
      .outer, .inner { column-gap:10px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div style="column-span:all; width:22px; height:100px;"></div>
          <div style="width:22px; height:70px;"></div>
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
          offset:0,0 size:45x0
          offset:0,0 size:22x100
      offset:110,0 size:100x100
        offset:0,0 size:100x35
          offset:0,0 size:45x35
            offset:0,0 size:22x35
          offset:55,0 size:45x35
            offset:0,0 size:22x35
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AbsposFitsInOneColumn) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div style="columns:3; width:320px; height:100px; column-gap:10px; column-fill:auto;">
        <div style="position:relative; width:222px; height:250px;">
          <div style="position:absolute; width:111px; height:50px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:222x100
        offset:0,0 size:111x50
      offset:110,0 size:100x100
        offset:0,0 size:222x100
      offset:220,0 size:100x100
        offset:0,0 size:222x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, Spanner) {
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
  offset:unplaced size:1000x126
    offset:0,0 size:322x126
      offset:1,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,1 size:100x40
        offset:0,0 size:100x20
      offset:1,41 size:320x44
      offset:1,85 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,85 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,85 size:100x40
        offset:0,0 size:100x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerWithContent) {
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
        <div style="column-span:all; padding:1px;">
          <div class="content"></div>
          <div class="content"></div>
          <div class="content"></div>
        </div>
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
  offset:unplaced size:1000x144
    offset:0,0 size:322x144
      offset:1,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,1 size:100x40
        offset:0,0 size:100x20
      offset:1,41 size:320x62
        offset:1,1 size:318x20
        offset:1,21 size:318x20
        offset:1,41 size:318x20
      offset:1,103 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,103 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,103 size:100x40
        offset:0,0 size:100x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, TwoSpannersPercentWidth) {
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
        <div style="column-span:all; width:50%; height:44px;"></div>
        <div style="column-span:all; width:50%; height:1px;"></div>
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
  offset:unplaced size:1000x127
    offset:0,0 size:322x127
      offset:1,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,1 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,1 size:100x40
        offset:0,0 size:100x20
      offset:1,41 size:160x44
      offset:1,85 size:160x1
      offset:1,86 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:111,86 size:100x40
        offset:0,0 size:100x20
        offset:0,20 size:100x20
      offset:221,86 size:100x40
        offset:0,0 size:100x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerNoBalancing) {
  // Even if column-fill is auto and block-size is restricted, we have to
  // balance column contents in front of a spanner (but not after).
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        height: 200px;
        width: 320px;
        border: 1px solid;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div class="content"></div>
        <div class="c
```