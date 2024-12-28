Response:
The user wants to understand the functionality of the `column_layout_algorithm_test.cc` file in the Chromium Blink engine. The request has several constraints:

1. **List Functionality:** Describe what the code does.
2. **Relate to Web Technologies:** Explain any connection to JavaScript, HTML, and CSS, providing examples.
3. **Illustrate Logic:** If the code involves logical reasoning, give examples with assumed input and output.
4. **Highlight Common Errors:** Point out potential mistakes users or programmers might make related to this code.
5. **Summarize Purpose:** Provide a concise overview of the file's goal.
6. **Context:** This is part 6 of 6, suggesting this is the concluding summary.

Let's analyze the code:

- It's a C++ file (`.cc`) within the Blink rendering engine.
- The filename strongly suggests it contains tests for a column layout algorithm.
- The `TEST_F` macros indicate these are Google Test framework tests.
- Each test case sets up HTML and CSS (`SetBodyInnerHTML`), then uses `DumpFragmentTree` to capture the layout result and compares it to an expected `DUMP`.
- The tests cover various scenarios involving CSS column layout properties like `columns`, `column-gap`, `column-fill`, `column-span`, and break-related properties like `break-before`, `break-after`, and `break-inside`.

**Plan:**

1. **General Functionality:** State that the file contains unit tests for the column layout algorithm in Blink.
2. **Web Technology Relationship:**  Explain how the tests directly relate to CSS multi-column layout. Provide examples of the CSS properties being tested and how they affect HTML elements.
3. **Logical Reasoning (Implicit):** The tests implicitly demonstrate the logic of the column layout algorithm. For the "assumed input and output," use one of the test cases. The HTML/CSS is the input, and the `DUMP` string is the expected output, representing the layout tree structure.
4. **Common Errors:**  Focus on common CSS multi-column layout errors that these tests implicitly validate correct behavior for, such as incorrect break settings or unexpected interactions between column properties and break properties.
5. **Summary:**  Reiterate that the file's purpose is to ensure the correctness of the Blink column layout implementation.
这是 `blink/renderer/core/layout/column_layout_algorithm_test.cc` 文件的功能归纳，作为第 6 部分，它主要的功能是**对 Blink 渲染引擎中负责多列布局（CSS Columns）的算法进行全面的单元测试**。

更具体地说，这个文件通过一系列独立的测试用例，验证了多列布局算法在各种复杂场景下的正确性。 这些场景涵盖了：

1. **基本多列布局：** 验证元素被正确地分配到不同的列中，并考虑了 `columns` 和 `column-gap` 属性。
2. **`column-span: all` 的元素（Spanner）：**  测试跨越多列的元素如何影响布局，以及与其他列中内容的交互。
3. **嵌套多列布局：**  验证在多列容器内部嵌套另一个多列容器时的布局行为。
4. **断点控制属性 (`break-before`, `break-after`, `break-inside`)：**  重点测试了这些属性如何影响元素在列间的断裂，以及算法如何处理 `avoid` 和 `force` 类型的断点规则。
5. **浮动元素与多列布局的交互：**  验证浮动元素在多列容器中的布局行为，以及它们是否影响列的断裂。
6. **`orphans` 和 `widows` 属性：** 测试这些属性如何防止列尾或列首出现孤立的行。
7. **不可断裂的内容（例如，替换元素）：** 验证像图片这样的不可断裂元素在多列布局中的处理方式。
8. **复杂的断点规则组合：**  测试当存在多种冲突或复杂的断点规则时，算法如何选择最优的断裂位置。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关联到 HTML 和 CSS 的功能，特别是 CSS 的多列布局模块。 它并不直接涉及 JavaScript 的功能，而是验证了浏览器引擎在解析和应用 CSS 样式到 HTML 元素时产生的布局结果是否符合预期。

**举例说明：**

* **CSS `columns` 和 `column-gap`:**
   测试用例 `Basic` 验证了当设置了 `columns: 3; column-gap: 10px;` 时，内容会被正确地分配到三个宽度相等的列中，并且列之间有 10px 的间距。

   ```html
   <style>
     #parent { columns: 3; column-gap: 10px; width: 320px; }
   </style>
   <div id="parent">
     <div>Content 1</div>
     <div>Content 2</div>
     <div>Content 3</div>
     <div>Content 4</div>
   </div>
   ```
   该测试会验证 `Content 1` 和 `Content 2` 在第一列，`Content 3` 在第二列，`Content 4` 在第三列。

* **CSS `column-span: all` 和 `break-inside: avoid`:**
   测试用例 `SpannerNotBroken` 验证了当一个元素设置了 `column-span: all` 和 `break-inside: avoid` 时，它不会在其内部被断开，并且会作为一个整体跨越所有列。

   ```html
   <style>
     .outer { columns:3; height:100px; }
     .spanner { column-span:all; break-inside:avoid; height:70px; }
   </style>
   <div class="outer">
     <div>Column content</div>
     <div class="spanner">Spanning content</div>
   </div>
   ```
   该测试会验证 "Spanning content" 这个 div 元素会占据整行，跨越所有三列。

* **CSS 断点控制属性 (`break-before: avoid`)：**
   测试用例 `AvoidBreakBetween` 验证了当一个元素设置了 `break-before: avoid;` 时，算法会避免在该元素之前断开列。

   ```html
   <style>
     #parent { columns: 3; height: 100px; }
     .content { height:30px; }
     .no-break { break-before:avoid; }
   </style>
   <div id="parent">
     <div class="content">Content 1</div>
     <div class="content">Content 2</div>
     <div class="content no-break">Content 3 (no break before)</div>
   </div>
   ```
   如果前两块内容刚好填满第一列，且没有 `break-before: avoid;`，则 "Content 3" 会出现在第二列。但由于设置了 `break-before: avoid;`，算法会尝试将 "Content 2" 放在第一列，如果放不下，可能会将 "Content 1" 也移动到下一列，以避免在 "Content 3" 之前断开。

**假设输入与输出 (逻辑推理)：**

以 `AvoidBreakBetween` 测试用例为例：

**假设输入 (HTML/CSS):**

```html
<style>
  #parent {
    columns: 3;
    column-gap: 10px;
    column-fill: auto;
    width: 320px;
    height: 100px;
  }
  .content { break-inside:avoid; height:30px; }
</style>
<div id="container">
  <div id="parent">
    <div class="content" style="width:81px;"></div>
    <div class="content" style="width:82px;"></div>
    <div class="content" style="width:83px;"></div>
    <div class="content" style="width:84px; break-before:avoid;"></div>
  </div>
</div>
```

**预期输出 (DumpFragmentTree):**

```
.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:81x30
        offset:0,30 size:82x30
      offset:110,0 size:100x100
        offset:0,0 size:83x30
        offset:0,30 size:84x30
```

这个输出表示前两个 `content` div 在第一列，后两个 `content` div 在第二列。 因为如果第三个 `content` 在第一列，第四个 `content` 由于 `break-before:avoid;` 将无法放在第二列的开头，所以算法选择在第三个 `content` 之前断开。

**涉及用户或者编程常见的使用错误：**

* **不理解断点属性的优先级：** 用户可能会错误地认为 `break-inside: avoid` 会阻止元素内部的所有断裂，但实际上 `break-before` 和 `break-after` 可能会具有更高的优先级。 例如，一个元素设置了 `break-inside: avoid`，但其子元素设置了 `break-before: always`，仍然会发生断裂。
* **混淆 `break-inside: avoid` 和 `column-span: all`：** 用户可能希望一个元素保持完整不被断开，但错误地使用了 `break-inside: avoid`，而实际上应该使用 `column-span: all` 来让元素跨越所有列。
* **忽略 `orphans` 和 `widows` 的影响：** 开发者可能没有考虑到 `orphans` 和 `widows` 属性，导致在列的开头或结尾出现不期望的孤立文本行。
* **在复杂的嵌套多列布局中难以预测断点：**  当多列布局嵌套很深时，各种断点属性的组合可能会导致难以预测的断裂行为。开发者需要仔细测试和理解各种属性的交互。

**功能归纳：**

总而言之，`blink/renderer/core/layout/column_layout_algorithm_test.cc` 作为一个测试文件，其核心功能是**确保 Blink 渲染引擎能够正确地实现 CSS 多列布局规范，处理各种布局场景和断点规则，并为开发者提供符合预期的多列布局效果。** 它通过大量的测试用例，覆盖了多列布局的各种特性和边缘情况，有效地验证了算法的健壮性和正确性。

Prompt: 
```
这是目录为blink/renderer/core/layout/column_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能

"""
ent, followed by a
  // spanner. Everything won't fit in the same outer column, and we don't want
  // to break inside the spanner. Break between the row of columns and the
  // spanner.
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer {
        columns:3;
        height:100px;
        column-fill:auto;
        column-gap:10px;
        width:320px;
      }
      .inner { columns:2; column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="inner">
          <div class="content" style="width:11px;"></div>
          <div class="content" style="width:22px;"></div>
          <div class="content" style="width:33px;"></div>
          <div style="column-span:all; break-inside:avoid; width:44px; height:70px;"></div>
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
          offset:0,0 size:45x40
            offset:0,0 size:11x20
            offset:0,20 size:22x20
          offset:55,0 size:45x40
            offset:0,0 size:33x20
      offset:110,0 size:100x100
        offset:0,0 size:100x70
          offset:0,0 size:44x70
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, SpannerAsMulticol) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .outer { columns:3; height:50px; column-fill:auto; width:320px; }
      .middle { columns:2; height:140px; column-fill:auto; }
      .inner { column-span:all; columns:2; height:80px; column-fill:auto; }
      .outer, .middle, .inner { column-gap:10px; }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div class="outer">
        <div class="middle">
          <div class="inner">
            <div class="content" style="width:131px;"></div>
            <div class="content" style="width:132px;"></div>
            <div class="content" style="width:133px;"></div>
            <div class="content" style="width:134px;"></div>
            <div class="content" style="width:135px;"></div>
            <div class="content" style="width:136px;"></div>
          </div>
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
          offset:0,0 size:45x0
          offset:0,0 size:100x50
            offset:0,0 size:45x50
              offset:0,0 size:131x20
              offset:0,20 size:132x20
            offset:55,0 size:45x50
              offset:0,0 size:133x20
              offset:0,20 size:134x20
      offset:110,0 size:100x50
        offset:0,0 size:100x50
          offset:0,0 size:100x30
            offset:0,0 size:45x30
              offset:0,0 size:135x20
            offset:55,0 size:45x30
              offset:0,0 size:136x20
      offset:220,0 size:100x50
        offset:0,0 size:100x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetween) {
  // Breaking exactly where we run out of space would violate a
  // break-before:avoid rule. There's a perfect break opportunity before the
  // previous sibling, so use that one instead.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:30px; }
    </style>
    <div id="container">
      <div id="parent">
        <div class="content" style="width:81px;"></div>
        <div class="content" style="width:82px;"></div>
        <div class="content" style="width:83px;"></div>
        <div class="content" style="width:84px; break-before:avoid;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:81x30
        offset:0,30 size:82x30
      offset:110,0 size:100x100
        offset:0,0 size:83x30
        offset:0,30 size:84x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidAndForceBreakBetween) {
  // If we're both told to avoid and force breaking at a breakpoint, forcing
  // always wins.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:30px; }
    </style>
    <div id="container">
      <div id="parent">
        <div class="content" style="width:81px;"></div>
        <div class="content" style="width:82px;"></div>
        <div class="content" style="width:83px; break-after:column;"></div>
        <div class="content" style="width:84px; break-before:avoid;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:81x30
        offset:0,30 size:82x30
        offset:0,60 size:83x30
      offset:110,0 size:100x100
        offset:0,0 size:84x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenInFloat) {
  // There are two parallel flows here; one for the float, and one for its
  // sibling. They don't affect each other as far as breaking is concerned.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:30px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="float:left; width:100%;">
          <div class="content" style="width:81px;"></div>
          <div class="content" style="width:82px;"></div>
          <div class="content" style="width:83px;"></div>
          <div class="content" style="width:84px; break-before:avoid;"></div>
        </div>
        <div style="height:150px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x100
          offset:0,0 size:81x30
          offset:0,30 size:82x30
        offset:0,0 size:100x100
      offset:110,0 size:100x100
        offset:0,0 size:100x60
          offset:0,0 size:83x30
          offset:0,30 size:84x30
        offset:0,0 size:100x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest,
       IgnoreBreakInsideAvoidBecauseBreakBetweenAvoid) {
  // We want to avoid breaks between all the children, and at the same time
  // avoid breaks inside of them. This is impossible to honor in this test,
  // since the content is taller than one column. There are no ideal
  // breakpoints; all are equally bad. The spec is explicit about the fact that
  // it "does not suggest a precise algorithm" when it comes to picking which
  // breaking rule to violate before others, so whether we should drop
  // break-before or break-inside first is undefined. However, the spec does
  // also mention that we should break as few times as possible, which suggests
  // that we should favor whatever gives more progression.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:30px; }
    </style>
    <div id="container">
      <div id="parent">
        <div class="content" style="width:81px;"></div>
        <div class="content" style="width:82px; break-before:avoid;"></div>
        <div class="content" style="width:83px; break-before:avoid;"></div>
        <div class="content" style="width:84px; break-before:avoid;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:81x30
        offset:0,30 size:82x30
        offset:0,60 size:83x30
        offset:0,90 size:84x10
      offset:110,0 size:100x100
        offset:0,0 size:84x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenAndInsideIgnoreInside) {
  // This one isn't obvious, spec-wise, since it's not defined which rules to
  // disregard first (break-inside vs. break-before, and break-inside on a child
  // vs. on its container), but it seems right to disregard break-inside:avoid
  // on the container, and at the same time honor break avoidance specified
  // further within (smaller pieces, more progression), rather than e.g. giving
  // up on everything and breaking wherever.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:30px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="break-inside:avoid;">
          <div style="width:80px; height:20px;"></div>
          <div class="content" style="width:81px;"></div>
          <div class="content" style="width:82px;"></div>
          <div class="content" style="width:83px; break-before:avoid;"></div>
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
          offset:0,0 size:80x20
          offset:0,20 size:81x30
      offset:110,0 size:100x100
        offset:0,0 size:100x60
          offset:0,0 size:82x30
          offset:0,30 size:83x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenAndInside) {
  // When looking for possible breaks inside #middle, we need to take into
  // account that we're supposed to avoid breaking inside. The only breakpoint
  // that doesn't violate any rules in this test is *before* #middle.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div class="content" style="width:32px;"></div>
        <div id="middle" style="break-inside:avoid; break-after:avoid;">
          <div class="content" style="width:33px;"></div>
          <div class="content" style="width:34px;"></div>
          <div class="content" style="width:35px;"></div>
          <div class="content" style="width:36px;"></div>
        </div>
        <div class="content" style="width:37px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:32x20
      offset:110,0 size:100x100
        offset:0,0 size:100x80
          offset:0,0 size:33x20
          offset:0,20 size:34x20
          offset:0,40 size:35x20
          offset:0,60 size:36x20
        offset:0,80 size:37x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenInsideBreakableParent) {
  // There's a perfect breakpoint between the two direct children of the
  // multicol container - i.e. between #first and #second. We should avoid
  // breaking between between any of the children of #second (we run out of
  // space between the third and the fourth child). There are no restrictions on
  // breaking between the children inside #first, but we should progress as much
  // as possible, so the correct thing to do is to break between #first and
  // #second.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div id="#first">
          <div class="content" style="width:33px;"></div>
          <div class="content" style="width:34px;"></div>
        </div>
        <div id="#second">
          <div class="content" style="width:35px;"></div>
          <div class="content" style="width:36px; break-before:avoid;"></div>
          <div class="content" style="width:37px; break-before:avoid;"></div>
          <div class="content" style="width:38px; break-before:avoid;"></div>
        </div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:33x20
          offset:0,20 size:34x20
      offset:110,0 size:100x100
        offset:0,0 size:100x80
          offset:0,0 size:35x20
          offset:0,20 size:36x20
          offset:0,40 size:37x20
          offset:0,60 size:38x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenAfterBreakableSibling) {
  // We should avoid breaking between the two direct children of the multicol
  // container - i.e. between #first and #second. We should also avoid breaking
  // between between the children of #second (we run out of space before its
  // second child). The only restriction inside #first is between the third and
  // fourth child, while there are perfect breakpoints between the first and the
  // second, and between the second and the third. We should progress as much as
  // possible, so the correct thing to do is to break between the second and
  // third child of #first.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="break-after:avoid;">
          <div class="content" style="width:33px;"></div>
          <div class="content" style="width:34px;"></div>
          <div class="content" style="width:35px;"></div>
          <div class="content" style="width:36px; break-before:avoid;"></div>
        </div>
        <div>
          <div class="content" style="width:37px;"></div>
          <div class="content" style="width:38px; break-before:avoid;"></div>
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
          offset:0,0 size:33x20
          offset:0,20 size:34x20
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:35x20
          offset:0,20 size:36x20
        offset:0,40 size:100x40
          offset:0,0 size:37x20
          offset:0,20 size:38x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenBreakInsidePreviousSibling) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div class="content" style="width:32px;"></div>
        <div style="break-after:avoid;">
          <div class="content" style="width:33px;"></div>
          <div class="content" style="width:34px;"></div>
          <div class="content" style="width:35px;"></div>
          <div class="content" style="width:36px;"></div>
        </div>
        <div class="content" style="width:37px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:32x20
        offset:0,20 size:100x80
          offset:0,0 size:33x20
          offset:0,20 size:34x20
          offset:0,40 size:35x20
      offset:110,0 size:100x100
        offset:0,0 size:100x20
          offset:0,0 size:36x20
        offset:0,20 size:37x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenHonorOrphansWidows) {
  // We run out of space at .content, but this isn't a good location, because of
  // break-before:avoid. Break between the lines. Honor orphans and widows, so
  // that two of the four lines will be pushed to the second column.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 2;
        widows: 2;
      }
      .content { break-inside:avoid; height:30px; }
    </style>
    <div id="container">
      <div id="parent">
        <br>
        <br>
        <br>
        <br>
        <div class="content" style="break-before:avoid;"></div>
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
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
        offset:0,40 size:100x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenHonorOrphansWidows2) {
  // We run out of space at .content, but this isn't a good location, because of
  // break-before:avoid. Break between the first block and the two lines, in
  // order to honor orphans and widows.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 2;
        widows: 2;
      }
      .content { break-inside:avoid; height:30px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:40px;"></div>
        <br>
        <br>
        <div class="content" style="break-before:avoid;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x40
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
        offset:0,40 size:100x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenHonorOrphansWidows3) {
  // We run out of space between the first and the second line in the second
  // container, but this isn't a good location, because of the orphans and
  // widows requirement. Break between the second and third line inside the
  // first container instead. We should not break between the two containers,
  // because of break-before:avoid.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 2;
        widows: 2;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div>
          <br>
          <br>
          <br>
          <br>
        </div>
        <div style="break-before:avoid;">
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
        offset:0,0 size:100x100
          offset:0,0 size:0x20
          offset:0,20 size:0x20
      offset:110,0 size:100x100
        offset:0,0 size:100x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
        offset:0,40 size:100x60
          offset:0,0 size:0x20
          offset:0,20 size:0x20
          offset:0,40 size:0x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenIgnoreOrphansWidows) {
  // We run out of space at .content, but this isn't a good location, because of
  // break-before:avoid. Break between the two lines, even if that will violate
  // the orphans and widows requirement. According to the spec, this is better
  // then ignoring the the break-after:avoid declaration on the first child.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 2;
        widows: 2;
      }
      .content { break-inside:avoid; height:30px; }
    </style>
    <div id="container">
      <div id="parent">
        <div style="height:40px; break-after:avoid;"></div>
        <br>
        <br>
        <div class="content" style="break-before:avoid;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:100x40
        offset:0,40 size:100x60
          offset:0,0 size:0x20
      offset:110,0 size:100x100
        offset:0,0 size:100x20
          offset:0,0 size:0x20
        offset:0,20 size:100x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenLinesInsideBreakAvoid) {
  // We run out of space at the second line inside the last container, and we're
  // not supposed to break inside it. We're also not supposed to break between
  // the lines in the previous container (since it has break-inside:avoid,
  // albeit no orphans/widows restrictions). Breaking before that container
  // instead is as far as we get without breaking any rules.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
        line-height: 20px;
        orphans: 1;
        widows: 1;
      }
      .content { break-inside:avoid; height:20px; }
    </style>
    <div id="container">
      <div id="parent">
        <div class="content" style="width:33px;"></div>
        <div class="content" style="width:34px;"></div>
        <div style="break-inside:avoid; width:35px;">
          <br>
          <br>
        </div>
        <div class="content" style="break-before:avoid; width:36px; height:30px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:33x20
        offset:0,20 size:34x20
      offset:110,0 size:100x100
        offset:0,0 size:35x40
          offset:0,0 size:0x20
          offset:0,20 size:0x20
        offset:0,40 size:36x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBetweenBreakAtEarlyClassC) {
  // The early break is a class C breakpoint, and this is also exactly where the
  // BFC block-offset is resolved. There are no possible breaks as long as we
  // don't know our BFC offset, but breaking just before the box that resolves
  // the BFC block-offset should be allowed.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:22px;">
          <div style="float:left; width:100%; width:33px; height:20px;"></div>
          <div style="display:flow-root; width:44px; height:20px;"></div>
        </div>
        <div style="break-before:avoid; break-inside:avoid; width:55px; height:70px;"></div>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:22x100
          offset:0,0 size:33x20
      offset:110,0 size:100x100
        offset:0,0 size:22x20
          offset:0,0 size:44x20
        offset:0,20 size:55x70
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, AvoidBreakBeforeBlockReplacedContent) {
  // Replaced content is unbreakable. Don't break right before it if we have
  // break-before:avoid, though.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <div style="width:22px; height:40px;"></div>
        <div style="width:33px; height:50px; break-inside:avoid;"></div>
        <img style="break-before:avoid; display:block; width:44px; height:50px;">
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:22x40
      offset:110,0 size:100x100
        offset:0,0 size:33x50
        offset:0,50 size:44x50
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(ColumnLayoutAlgorithmTest, TallReplacedContent) {
  // Replaced content is unbreakable. Let it overflow the column.
  SetBodyInnerHTML(R"HTML(
    <style>
      #parent {
        columns: 3;
        column-gap: 10px;
        column-fill: auto;
        width: 320px;
        height: 100px;
      }
    </style>
    <div id="container">
      <div id="parent">
        <img style="display:block; width:44px; height:150px;">
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:320x100
      offset:0,0 size:100x100
        offset:0,0 size:44x150
)DUMP";
  EXPECT_EQ(expectation, dump);
}

}  // anonymous namespace
}  // namespace blink

"""


```