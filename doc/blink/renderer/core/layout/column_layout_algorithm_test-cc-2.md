Response:
The user is asking for a summary of the functionality of the provided C++ code, which is a test file for the column layout algorithm in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename `column_layout_algorithm_test.cc` immediately suggests that the file contains tests for the column layout functionality.

2. **Analyze the test structure:**  The code consists of multiple `TEST_F` blocks. Each `TEST_F` function focuses on testing a specific aspect of the column layout. The setup involves:
    * Setting up an HTML structure within the test environment using `SetBodyInnerHTML`.
    * Getting a specific element from the HTML.
    * Running the layout algorithm (implicitly, by interacting with the test environment).
    * Dumping the generated fragment tree using `DumpFragmentTree`.
    * Comparing the actual fragment tree with an expected output string (`expectation`) using `EXPECT_EQ`.

3. **Infer the tested features from test names and HTML:**  By looking at the names of the test functions (e.g., `Basic`, `InlineElements`, `Floats`, `ForcedBreaks`, `ColumnBalancing`, etc.) and the HTML snippets within each test, we can deduce what specific column layout features are being tested. For example:
    * `Basic`: Simple multi-column layout.
    * `InlineElements`: How inline elements are handled in columns.
    * `Floats`: Interaction of floats with column layout.
    * `ForcedBreaks`:  The `break-before` and `break-after` CSS properties for columns.
    * `ColumnBalancing`:  How content is distributed across columns to achieve balance.
    * The presence of `MinMax` suggests testing `column-width` and `column-count` interactions.

4. **Connect to web technologies (JavaScript, HTML, CSS):**  Column layout is a CSS feature. The tests directly manipulate HTML and implicitly rely on CSS styling to trigger the column layout algorithm. JavaScript isn't directly involved in *this specific test file*, but the layout engine itself is used by the browser to render web pages, which often include JavaScript for dynamic behavior.

5. **Identify assumptions and outputs:**  Each test makes an implicit assumption about how the layout algorithm *should* behave for a given input (the HTML/CSS). The output is the generated fragment tree, which describes the physical layout of the elements. The `expectation` string represents the *expected* output.

6. **Look for common errors:** The tests involving forced breaks (`ForcedBreaks`, `ForcedBreakInSecondChild`, etc.) hint at potential errors related to how the engine handles these breaks. The `ColumnBalancing` tests might reveal errors in how content is distributed across columns.

7. **Synthesize the information into a summary:** Combine the observations from the previous steps into a concise description of the file's functionality. Group related tests under broader categories (e.g., forced breaks, column balancing).

8. **Address the specific questions:**  Explicitly answer the questions about relationships to JavaScript, HTML, and CSS, provide examples based on the test cases, and address potential usage errors based on the tested scenarios.

9. **Refine and organize:**  Ensure the summary is clear, well-organized, and uses appropriate technical terminology. For example, use terms like "fragment tree," "forced breaks," "column balancing," and "formatting context."

Self-Correction/Refinement during the thought process:

* **Initial thought:** "This file tests column layout."  **Refinement:** Be more specific about *what aspects* of column layout are tested.
* **Overlook JavaScript:** Initially, I might focus only on HTML and CSS. **Correction:** Acknowledge that while this specific file doesn't use JavaScript, the layout engine is part of a larger system that interacts with JavaScript.
* **Generic error identification:**  Simply stating "errors in column layout" is too vague. **Refinement:** Point to specific types of errors the tests are designed to catch, like incorrect handling of forced breaks or unbalanced columns.
* **Output description:**  Just saying "the output is compared" is insufficient. **Refinement:** Explain that the output is a "fragment tree" and what that represents.
好的，根据你提供的代码片段，`blink/renderer/core/layout/column_layout_algorithm_test.cc` 文件的第 3 部分主要测试了以下与多列布局相关的特性：

**核心功能归纳：**

这部分代码专注于测试**分列布局中的各种断点行为和新的格式化上下文 (Formatting Context) 的处理**，以及**计算多列容器的最小和最大尺寸**。 具体来说，它验证了以下方面：

1. **强制断点 (Forced Breaks):**
   - 测试 `break-before: column` 和 `break-after: column` 样式是否能够正确地强制内容分到下一列。
   - 验证强制断点只在合法的 A 类断点（例如，块级兄弟元素之间）生效。
   - 测试在同一个边界同时存在强制断点和非强制断点时，边距的处理方式（强制断点不截断边距，非强制断点截断）。

2. **格式化上下文 (Formatting Context):**
   - 测试在分列布局中遇到新的格式化上下文根（例如，`display: flow-root` 的元素）时的布局行为，包括：
     - 如何在列边界处启动新的格式化上下文。
     - 带有 margin 的新格式化上下文如何影响列的布局。
     - 浮动元素后出现新的格式化上下文时的布局。
     - margin 超出列边界的新格式化上下文的布局。

3. **最小和最大尺寸 (Min/Max Sizes):**
   - 测试当同时设置 `column-count` 和 `column-width` 时，多列容器的最小和最大内联尺寸的计算方式。
   - 分别测试只设置 `column-count` 或只设置 `column-width` 时的最小和最大内联尺寸计算。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关联了 HTML 和 CSS 的功能，因为它通过构建 HTML 结构，并隐式地依赖 CSS 样式来触发浏览器的分列布局算法。

* **HTML:** 测试用例使用 HTML 元素（如 `<div>`, `<span>`, `<br>`) 来构建需要进行分列布局的内容结构。例如，`SetBodyInnerHTML` 函数中定义的 HTML 代码片段。
* **CSS:** 测试用例依赖 CSS 属性（如 `columns`, `column-gap`, `column-fill`, `width`, `height`, `break-before`, `break-after`, `margin-top`, `display: flow-root`, `line-height`, `orphans`, `widows`, `break-inside`) 来控制分列布局的行为。例如，`#parent` 元素的样式定义。
* **JavaScript:**  这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎的布局算法。  它**不直接**包含 JavaScript 代码。 然而，浏览器中的 JavaScript 可以动态地修改 HTML 结构和 CSS 样式，从而间接地影响到这里的测试所覆盖的分列布局行为。 例如，JavaScript 可以动态添加带有 `break-before: column` 样式的元素来触发分列。

**逻辑推理、假设输入与输出：**

每个 `TEST_F` 函数都包含一个假设的输入（HTML 和 CSS），并通过 `DumpFragmentTree` 函数生成实际的布局树片段，然后与预期的输出（`expectation` 字符串）进行比较。

**示例（`ForcedBreaks` 测试）：**

* **假设输入 (HTML/CSS):**
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
      <div style="float:left; width:1px; height:1px;"></div>
      <div style="break-before:column; break-after:column;">
        <div style="float:left; width:1px; height:1px;"></div>
        <div style="break-after:column; width:50px; height:10px;"></div>
        <div style="break-before:column; width:60px; height:10px;"></div>
        <div>
          <div>
            <div style="break-after:column; width:70px; height:10px;"></div>
          </div>
        </div>
        <div style="width:80px; height:10px;"></div>
      </div>
    </div>
  </div>
  ```
* **逻辑推理:**  该测试预期 `break-before: column` 和 `break-after: column` 会强制内容在列之间断开。注意强制断点只在块级兄弟元素之间有效，因此内联元素上的断点可能不会立即生效。
* **预期输出 (Fragment Tree):**  （对应 `expectation` 字符串）描述了元素在不同列中的位置和尺寸。例如，你会看到不同的 `offset` 值，表示元素被放置在不同的列中。

**用户或编程常见的使用错误：**

基于这部分测试的内容，常见的使用错误可能包括：

1. **错误地假设内联元素上的强制断点会立即生效:** 用户可能会期望在 `<span>` 元素上设置 `break-before: column` 就能让其换列，但实际上强制断点通常只在块级元素之间有效。
2. **不理解强制断点只在 A 类断点生效:** 可能会在不合适的位置使用强制断点，例如在浮动元素内部，导致断点没有生效。
3. **对新的格式化上下文在分列布局中的行为不熟悉:**  可能会错误地预期 `display: flow-root` 的元素会像普通块级元素一样被简单地分列，而忽略了它会创建一个独立的布局上下文。
4. **混淆 `column-count` 和 `column-width` 的优先级:**  当同时设置这两个属性时，最小和最大尺寸的计算方式可能会让人困惑。用户可能不清楚浏览器在不同情况下的计算逻辑。

**总结一下它的功能（基于第 3 部分）：**

这部分 `column_layout_algorithm_test.cc` 文件的主要功能是**详尽地测试 Blink 引擎在处理 CSS 分列布局时，关于强制断点和新的格式化上下文的各种场景，并验证其最小和最大尺寸的计算逻辑**。 它旨在确保引擎能够正确地解析和应用相关的 CSS 属性，并生成符合预期的布局结果。 通过这些测试，可以有效地发现和修复引擎在处理复杂分列布局时的潜在 bug。

### 提示词
```
这是目录为blink/renderer/core/layout/column_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
></div>
        <div style="border:10px solid;">
          <div style="height:10px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x85
        offset:0,85 size:100x15
          offset:10,10 size:80x5
      offset:110,0 size:100x100
        offset:0,0 size:100x15
          offset:10,0 size:80x5
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedBreaks) {
  // This tests that forced breaks are honored, but only at valid class A break
  // points (i.e. *between* in-flow block siblings).
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
        <div style="float:left; width:1px; height:1px;"></div>
        <div style="break-before:column; break-after:column;">
          <div style="float:left; width:1px; height:1px;"></div>
          <div style="break-after:column; width:50px; height:10px;"></div>
          <div style="break-before:column; width:60px; height:10px;"></div>
          <div>
            <div>
              <div style="break-after:column; width:70px; height:10px;"></div>
            </div>
          </div>
          <div style="width:80px; height:10px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:1x1
        offset:0,0 size:100x100
          offset:1,0 size:1x1
          offset:0,0 size:50x10
      offset:110,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:60x10
          offset:0,10 size:100x10
            offset:0,0 size:100x10
              offset:0,0 size:70x10
      offset:220,0 size:100x100
        offset:0,0 size:100x10
          offset:0,0 size:80x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedBreakInSecondChild) {
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
        <div style="width:33px; height:20px;"></div>
        <div style="width:34px;">
          <div style="width:35px; height:20px;"></div>
          <div style="break-before:column; width:36px; height:20px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:33x20
        offset:0,20 size:34x80
          offset:0,0 size:35x20
      offset:110,0 size:100x100
        offset:0,0 size:34x20
          offset:0,0 size:36x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ForcedAndUnforcedBreaksAtSameBoundary) {
  // We have two parallel flows, one with a forced break inside and one with an
  // unforced break. Check that we handle the block-start margins correctly
  // (i.e. truncate at unforced breaks but not at forced breaks).
  //
  // Note about the #blockchildifier DIV in the test: it's there to force block
  // layout, as our fragmentation support for floats inside an inline formatting
  // context is borked; see crbug.com/915929
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
        <div id="blockchildifier"></div>
        <div style="float:left; width:33px;">
          <div style="width:10px; height:70px;"></div>
          <div style="break-before:column; margin-top:50px; width:20px; height:20px;"></div>
       </div>
       <div style="float:left; width:34px;">
         <div style="width:10px; height:70px;"></div>
        <div style="margin-top:50px; width:20px; height:20px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x0
        offset:0,0 size:33x100
          offset:0,0 size:10x70
        offset:33,0 size:34x100
          offset:0,0 size:10x70
      offset:110,0 size:100x100
        offset:0,0 size:33x70
          offset:0,50 size:20x20
        offset:33,0 size:34x20
          offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ResumeInsideFormattingContextRoot) {
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
        <div style="display:flow-root; width:33px;">
          <div style="width:10px; height:70px;"></div>
          <div style="margin-top:50px; width:20px; height:20px;"></div>
       </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:33x100
          offset:0,0 size:10x70
      offset:110,0 size:100x100
        offset:0,0 size:33x20
          offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NewFcAtColumnBoundary) {
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
        <div style="width:22px; height:100px;"></div>
        <div style="display:flow-root; width:33px; height:50px;"></div>
       </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:22x100
      offset:110,0 size:100x100
        offset:0,0 size:33x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NewFcWithMargin) {
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
        <div style="width:22px; height:50px;"></div>
        <div style="display:flow-root; margin-top:30px; width:33px; height:50px;"></div>
       </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:22x50
        offset:0,80 size:33x20
      offset:110,0 size:100x100
        offset:0,0 size:33x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NewFcBelowFloat) {
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
        <div style="float:left; width:22px; height:50px;"></div>
        <div style="display:flow-root; margin-top:40px; width:88px; height:70px;"></div>
       </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:22x50
        offset:0,50 size:88x50
      offset:110,0 size:100x100
        offset:0,0 size:88x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, NewFcWithMarginPastColumnBoundary) {
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
        <div style="width:22px; height:80px;"></div>
        <div style="display:flow-root; margin-top:30px; width:33px; height:50px;"></div>
       </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:22x80
      offset:110,0 size:100x100
        offset:0,0 size:33x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, MinMax) {
  // The multicol container here contains two inline-blocks with a line break
  // opportunity between them. We'll test what min/max values we get for the
  // multicol container when specifying both column-count and column-width, only
  // column-count, and only column-width.
  SetBodyInnerHTML(R"HTML(
    <style>
      #multicol {
        column-gap: 10px;
        width: fit-content;
      }
      #multicol span { display:inline-block; width:50px; height:50px; }
    </style>
    <div id="container">
      <div id="multicol">
        <div>
          <span></span><wbr><span></span>
        </div>
      </div>
    </div>
  )HTML");

  LayoutObject* layout_object = GetLayoutObjectByElementId("multicol");
  ASSERT_TRUE(layout_object);
  BlockNode node = BlockNode(To<LayoutBox>(layout_object));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize));
  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, node, /* break_token */ nullptr);
  ColumnLayoutAlgorithm algorithm({node, fragment_geometry, space});
  std::optional<MinMaxSizes> sizes;

  // Both column-count and column-width set. See
  // https://www.w3.org/TR/2016/WD-css-sizing-3-20160510/#multicol-intrinsic
  // (which is the only thing resembling spec that we currently have); in
  // particular, if column-width is non-auto, we ignore column-count for min
  // inline-size, and also clamp it down to the specified column-width.
  ComputedStyleBuilder builder(layout_object->StyleRef());
  builder.SetColumnCount(3);
  builder.SetColumnWidth(80);
  layout_object->SetStyle(builder.TakeStyle(),
                          LayoutObject::ApplyStyleChanges::kNo);
  sizes = algorithm.ComputeMinMaxSizes(MinMaxSizesFloatInput()).sizes;
  ASSERT_TRUE(sizes.has_value());
  EXPECT_EQ(LayoutUnit(50), sizes->min_size);
  EXPECT_EQ(LayoutUnit(320), sizes->max_size);

  // Only column-count set.
  builder = ComputedStyleBuilder(layout_object->StyleRef());
  builder.SetHasAutoColumnWidth();
  layout_object->SetStyle(builder.TakeStyle(),
                          LayoutObject::ApplyStyleChanges::kNo);
  sizes = algorithm.ComputeMinMaxSizes(MinMaxSizesFloatInput()).sizes;
  ASSERT_TRUE(sizes.has_value());
  EXPECT_EQ(LayoutUnit(170), sizes->min_size);
  EXPECT_EQ(LayoutUnit(320), sizes->max_size);

  // Only column-width set.
  builder = ComputedStyleBuilder(layout_object->StyleRef());
  builder.SetColumnWidth(80);
  builder.SetHasAutoColumnCount();
  layout_object->SetStyle(builder.TakeStyle(),
                          LayoutObject::ApplyStyleChanges::kNo);
  sizes = algorithm.ComputeMinMaxSizes(MinMaxSizesFloatInput()).sizes;
  ASSERT_TRUE(sizes.has_value());
  EXPECT_EQ(LayoutUnit(50), sizes->min_size);
  EXPECT_EQ(LayoutUnit(100), sizes->max_size);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancing) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
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
  offset:unplaced size:1000x60
    offset:0,0 size:330x60
      offset:5,5 size:100x50
        offset:0,0 size:30x50
      offset:115,5 size:100x50
        offset:0,0 size:30x50
      offset:225,5 size:100x50
        offset:0,0 size:30x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingFixedHeightExactMatch) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        height: 50px;
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
  offset:unplaced size:1000x60
    offset:0,0 size:330x60
      offset:5,5 size:100x50
        offset:0,0 size:30x50
      offset:115,5 size:100x50
        offset:0,0 size:30x50
      offset:225,5 size:100x50
        offset:0,0 size:30x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingFixedHeightLessContent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
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
      offset:5,5 size:100x50
        offset:0,0 size:30x50
      offset:115,5 size:100x50
        offset:0,0 size:30x50
      offset:225,5 size:100x50
        offset:0,0 size:30x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest,
       ColumnBalancingFixedHeightOverflowingContent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        height: 35px;
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
  offset:unplaced size:1000x45
    offset:0,0 size:330x45
      offset:5,5 size:100x35
        offset:0,0 size:30x35
      offset:115,5 size:100x35
        offset:0,0 size:30x35
      offset:225,5 size:100x35
        offset:0,0 size:30x35
      offset:335,5 size:100x35
        offset:0,0 size:30x35
      offset:445,5 size:100x35
        offset:0,0 size:30x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingMinHeight) {
  // Min-height has no effect on the columns, only on the multicol
  // container. Balanced columns should never be taller than they have to be.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        min-height:70px;
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
  offset:unplaced size:1000x80
    offset:0,0 size:330x80
      offset:5,5 size:100x50
        offset:0,0 size:30x50
      offset:115,5 size:100x50
        offset:0,0 size:30x50
      offset:225,5 size:100x50
        offset:0,0 size:30x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingMaxHeight) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        max-height:40px;
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
  offset:unplaced size:1000x50
    offset:0,0 size:330x50
      offset:5,5 size:100x40
        offset:0,0 size:30x40
      offset:115,5 size:100x40
        offset:0,0 size:30x40
      offset:225,5 size:100x40
        offset:0,0 size:30x40
      offset:335,5 size:100x40
        offset:0,0 size:30x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingMinHeightLargerThanMaxHeight) {
  // Min-height has no effect on the columns, only on the multicol
  // container. Balanced columns should never be taller than they have to be.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        min-height:70px;
        max-height:50px;
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
  offset:unplaced size:1000x80
    offset:0,0 size:330x80
      offset:5,5 size:100x50
        offset:0,0 size:30x50
      offset:115,5 size:100x50
        offset:0,0 size:30x50
      offset:225,5 size:100x50
        offset:0,0 size:30x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingFixedHeightMinHeight) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        height:40px;
        max-height:30px;
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
  offset:unplaced size:1000x40
    offset:0,0 size:330x40
      offset:5,5 size:100x30
        offset:0,0 size:30x30
      offset:115,5 size:100x30
        offset:0,0 size:30x30
      offset:225,5 size:100x30
        offset:0,0 size:30x30
      offset:335,5 size:100x30
        offset:0,0 size:30x30
      offset:445,5 size:100x30
        offset:0,0 size:30x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancing100By3) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent { columns: 3; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:100px;"></div>
      </div>
    </div>
  )HTML");

  const PhysicalBoxFragment* parent_fragment =
      RunBlockLayoutAlgorithm(GetElementById("container"));

  FragmentChildIterator iterator(parent_fragment);
  const auto* multicol = iterator.NextChild();
  ASSERT_TRUE(multicol);

  // Actual column-count should be 3. I.e. no overflow columns.
  EXPECT_EQ(3U, multicol->Children().size());
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingEmpty) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
      }
    </style>
    <div id="container">
      <div id="parent"></div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x0
    offset:0,0 size:320x0
      offset:0,0 size:100x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingEmptyBlock) {
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
        <div style="width:20px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x0
    offset:0,0 size:320x0
      offset:0,0 size:100x0
        offset:0,0 size:20x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingSingleLine) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        line-height: 20px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x20
    offset:0,0 size:320x20
      offset:0,0 size:100x20
        offset:0,0 size:100x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingSingleLineInNested) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        line-height: 20px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="columns:2; column-gap:10px;">
          <br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x20
    offset:0,0 size:320x20
      offset:0,0 size:100x20
        offset:0,0 size:100x20
          offset:0,0 size:45x20
            offset:0,0 size:45x20
              offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingSingleLineInNestedSpanner) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        width: 320px;
        line-height: 20px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="columns:2; column-gap:0;">
          <div style="column-span:all;">
            <br>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x20
    offset:0,0 size:320x20
      offset:0,0 size:100x20
        offset:0,0 size:100x20
          offset:0,0 size:50x0
          offset:0,0 size:100x20
            offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingOverflow) {
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
        <div style="width:30px; height:20px;">
          <div style="width:33px; height:300px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:30x20
          offset:0,0 size:33x100
      offset:110,0 size:100x100
        offset:0,0 size:30x0
          offset:0,0 size:33x100
      offset:220,0 size:100x100
        offset:0,0 size:30x0
          offset:0,0 size:33x100
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingLines) {
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
        <br><br><br><br><br>
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
      offset:220,0 size:100x40
        offset:0,0 size:100x20
          offset:0,0 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingLinesOrphans) {
  // We have 6 lines and 3 columns. If we make the columns tall enough to hold 2
  // lines each, it should all fit. But then there's an orphans request that 3
  // lines be placed together in the same column...
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
        <div style="orphans:3;">
           <br><br><br>
        </div>
        <br><br>
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
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingLinesForcedBreak) {
  // We have 6 lines and 3 columns. If we make the columns tall enough to hold 2
  // lines each, it should all fit. But then there's a forced break after the
  // first line, so that the remaining 5 lines have to be distributed into the 2
  // remaining columns...
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
        <div style="break-before:column;">
           <br><br><br><br><br>
        </div>
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
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingLinesForcedBreak2) {
  // We have 7+5 lines and 3 columns. There's a forced break after 7 lines, then
  // 5 more lines. There will be another implicit break among the first 7 lines,
  // while the columns will have to fit 5 lines, because of the 5 lines after
  // the forced break. The first column will have 5 lines. The second one will
  // have 2. The third one (after the break) will have 5.
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
        <br><br><br><br><br><br><br>
        <div style="width:99px; break-before:column;"></div>
        <br><br><br><br><br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
          offset:0,60 size:0x20
          offset:0,80 size:0x20
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:220,0 size:100x100
        offset:0,0 size:99x0
        offset:0,0 size:100x100
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
          offset:0,60 size:0x20
          offset:0,80 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingLinesForcedBreak3) {
  // We have 7+5 lines and 3 columns. There's a forced break after 7 lines, then
  // 5 more lines. There will be another implicit break among the first 7 lines,
  // while the columns will have to fit 5 lines, because of the 5 lines after
  // the forced break. The first column will have 5 lines. The second one will
  // have 2. The third one (after the break) will have 5. The lines are wrapped
  // inside a block child of the multicol container.
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
        <div style="width:66px;">
          <br><br><br><br><br><br><br>
          <div style="width:99px; break-before:column;"></div>
          <br><br><br><br><br>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:66x100
          offset:0,0 size:66x100
            offset:0,0 size:0x20
            offset:0,20 size:0x20
            offset:0,40 size:0x20
            offset:0,60 size:0x20
            offset:0,80 size:0x20
      offset:110,0 size:100x100
        offset:0,0 size:66x100
          offset:0,0 size:66x40
            offset:0,0 size:0x20
            offset:0,20 size:0x20
      offset:220,0 size:100x100
        offset:0,0 size:66x100
          offset:0,0 size:99x0
          offset:0,0 size:66x100
            offset:0,0 size:0x20
            offset:0,20 size:0x20
            offset:0,40 size:0x20
            offset:0,60 size:0x20
            offset:0,80 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, ColumnBalancingLinesAvoidBreakInside) {
  // We have 6 lines and 3 columns. If we make the columns tall enough to hold 2
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
        <br><br>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplace
```