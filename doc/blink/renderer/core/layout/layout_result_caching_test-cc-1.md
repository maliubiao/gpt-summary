Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This snippet is part of a test file for the Blink rendering engine, specifically testing the layout result caching mechanism.

The goal is to understand what aspects of layout result caching are being tested in this particular section of the file.

Each `TEST_F` function represents an individual test case. By examining the HTML and CSS used in each test, along with the `EXPECT_EQ` and `EXPECT_NE` assertions, we can deduce the functionality being tested.

Here's a breakdown of each test case in the provided snippet:

- **`TEST_F(LayoutResultCachingTest, MissFixedBlockSizeIndefinitePercentageChild)`**:  Tests a scenario where a fixed block size becomes indefinite due to a percentage-based child, causing a cache miss.
- **`TEST_F(LayoutResultCachingTest, HitQuirksModePercentageBasedParentAndChild)`**: Tests caching in quirks mode with percentage-based height for both parent and child. It checks if the cache hits when the child's height, though percentage-based, resolves to the same value.
- **`TEST_F(LayoutResultCachingTest, HitStandardsModePercentageBasedChild)`**: Tests caching in standards mode with a percentage-based height for a child.
- **`TEST_F(LayoutResultCachingTest, ChangeTableCellBlockSizeConstrainedness)`**: Tests how changes in table cell height constraints affect caching for its children with different height properties (fixed, percentage with overflow).
- **`TEST_F(LayoutResultCachingTest, OptimisticFloatPlacementNoRelayout)`**:  Checks if the layout result cache correctly handles float placement without forcing a block formatting context (BFC) offset.
- **`TEST_F(LayoutResultCachingTest, SelfCollapsingShifting)`**: Examines how the movement of self-collapsing blocks due to preceding floats affects layout result caching, considering adjoining out-of-flow elements.
- **`TEST_F(LayoutResultCachingTest, ClearancePastAdjoiningFloatsMovement)`**: Tests caching for elements with `clear` property when adjacent floats change height.
- **`TEST_F(LayoutResultCachingTest, MarginStrutMovementSelfCollapsing)`**: Tests how changes in margins that contribute to the margin strut of a self-collapsing block affect caching.
- **`TEST_F(LayoutResultCachingTest, MarginStrutMovementInFlow)`**: Tests how changes in margins within a normal flow that affect the margin strut impact caching.
- **`TEST_F(LayoutResultCachingTest, MarginStrutMovementPercentage)`**:  Tests caching when percentage-based margins contribute to the margin strut.
- **`TEST_F(LayoutResultCachingTest, HitIsFixedBlockSizeIndefinite)`**: Tests caching when a fixed block size becomes indefinite but there are no percentage-based children.
- **`TEST_F(LayoutResultCachingTest, MissIsFixedBlockSizeIndefinite)`**: Tests caching when a fixed block size becomes indefinite and there are percentage-based children.
- **`TEST_F(LayoutResultCachingTest, HitColumnFlexBoxMeasureAndLayout)`**: Tests caching of measure and layout results in a column flexbox scenario.
- **`TEST_F(LayoutResultCachingTest, HitRowFlexBoxMeasureAndLayout)`**: Tests caching of measure and layout results in a row flexbox scenario.
- **`TEST_F(LayoutResultCachingTest, HitFlexLegacyImg)`**: Tests caching within a flex container containing a legacy image.
- **`TEST_F(LayoutResultCachingTest, HitFlexLegacyGrid)`**: Tests caching within a flex container containing a legacy grid.
- **`TEST_F(LayoutResultCachingTest, HitFlexDefiniteChange)`**: Checks if the cache is hit when a flex item has a definite size.
- **`TEST_F(LayoutResultCachingTest, HitOrthogonalRoot)`**: Tests caching with orthogonal writing modes.
- **`TEST_F(LayoutResultCachingTest, SimpleTable)`**: Tests basic table layout result caching.
- **`TEST_F(LayoutResultCachingTest, MissTableCellMiddleAlignment)`**: Tests caching for table cells with middle vertical alignment.
- **`TEST_F(LayoutResultCachingTest, MissTableCellBottomAlignment)`**: Tests caching for table cells with bottom vertical alignment.
- **`TEST_F(LayoutResultCachingTest, HitTableCellBaselineAlignment)`**: Tests caching for table cells with baseline vertical alignment when baselines match.
- **`TEST_F(LayoutResultCachingTest, MissTableCellBaselineAlignment)`**: Tests caching for table cells with baseline vertical alignment when baselines don't match.
- **`TEST_F(LayoutResultCachingTest, MissTablePercent)`**: Tests caching for tables with percentage-based heights.
- **`TEST_F(LayoutResultCachingTest, HitTableRowAdd)`**: Tests caching when a table row is added.
- **`TEST_F(LayoutResultCachingTest, MissTableRowAdd)`**: Tests caching when a table row with potentially wider content is added.
这个代码片段是 Chromium Blink 引擎中 `layout_result_caching_test.cc` 文件的一部分，专门用于测试布局结果缓存机制的功能。 它的主要目的是验证在各种不同的布局场景下，布局结果能否被正确地缓存和重用，从而优化渲染性能。

**归纳一下它的功能：**

这个代码片段的功能是 **测试布局结果缓存机制在各种复杂的布局场景下的正确性。**  它通过创建特定的 HTML 和 CSS 结构，模拟不同的布局情况，然后断言布局结果缓存的状态（命中、未命中、需要简化布局）是否符合预期。这些测试覆盖了以下几个主要方面：

* **块级元素的尺寸变化和依赖关系：** 包括固定尺寸、百分比尺寸、`min-height` 等属性对缓存的影响。
* **排版模式的影响：** 包括标准模式和 Quirks 模式下的不同行为。
* **包含块的约束：** 例如父元素的高度变化如何影响子元素的缓存。
* **表格布局的特性：** 包括表格单元格的高度约束、垂直对齐方式对缓存的影响。
* **Flexbox 布局的特性：** 包括 `flex-grow`、`align-items` 等属性对缓存的影响，以及 measure 和 layout 两个阶段的缓存。
* **浮动元素的影响：**  包括浮动元素的存在和高度变化如何影响后续元素的缓存。
* **外边距合并 (Margin Collapsing) 的影响：** 包括外边距突出的变化对缓存的影响。
* **包含绝对定位元素的场景。**
* **Orthogonal flows (正交流)。**
* **是否需要完整的布局或简化布局。**

**与 javascript, html, css 的功能的关系：**

这个测试文件直接关联了 HTML 和 CSS 的功能，因为它使用 HTML 来构建测试的 DOM 结构，并使用 CSS 来定义元素的样式和布局属性。测试的目标就是验证 Blink 引擎如何根据 HTML 和 CSS 的定义进行布局计算，并利用缓存来避免重复计算。

**举例说明：**

* **HTML:**  例如，在 `TEST_F(LayoutResultCachingTest, HitQuirksModePercentageBasedParentAndChild)` 中，HTML 代码定义了嵌套的 `div` 元素，并赋予了特定的 `id` 和 `class`。这些 `id` 用于在 C++ 代码中获取对应的布局对象。
* **CSS:**  同样在上面的例子中，CSS 代码定义了 `.bfc`、`.parent` 和 `.child` 的样式，包括 `display: flow-root`、`height: 50%`、`min-height` 等属性。这些 CSS 属性直接影响了元素的布局方式和尺寸计算。
* **JavaScript:**  虽然这个特定的测试文件没有直接执行 JavaScript 代码，但布局引擎的行为会受到 JavaScript 的影响。例如，JavaScript 可以动态修改元素的样式或内容，从而触发重新布局。布局结果缓存机制需要能够正确地处理这些动态变化。

**逻辑推理，假设输入与输出:**

让我们以 `TEST_F(LayoutResultCachingTest, MissFixedBlockSizeIndefinitePercentageChild)` 为例：

**假设输入：**

1. **初始布局:** 一个 `display: flex` 的父元素，具有固定的宽度和高度 (100px)。
2. **目标
Prompt: 
```
这是目录为blink/renderer/core/layout/layout_result_caching_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
utCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitQuirksModePercentageBasedParentAndChild) {
  // Quirks-mode %-block-size parent *and* child. Here we mark the parent as
  // depending on %-block-size changes, however itself doesn't change in
  // height.
  // We are able to hit the cache as we detect that the height for the child
  // *isn't* indefinite, and results in the same height as before.
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .parent { height: 50%; min-height: 200px; }
      .child { height: 50%; }
    </style>
    <div class="bfc">
      <div id="test" class="parent">
        <div class="child"></div>
      </div>
    </div>
    <div class="bfc" style="height: 200px;">
      <div id="src" class="parent">
        <div class="child"></div>
      </div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitStandardsModePercentageBasedChild) {
  // Standards-mode %-block-size child.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .child { height: 50%; }
    </style>
    <div class="bfc">
      <div id="test">
        <div class="child"></div>
      </div>
    </div>
    <div class="bfc" style="height: 200px;">
      <div id="src">
        <div class="child"></div>
      </div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, ChangeTableCellBlockSizeConstrainedness) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .table { display: table; width: 300px; }
      .cell { display: table-cell; }
      .child1 { height: 100px; }
      .child2, .child3 { overflow:auto; height:10%; }
    </style>
    <div class="table">
      <div class="cell">
        <div class="child1" id="test1"></div>
        <div class="child2" id="test2">
          <div style="height:30px;"></div>
        </div>
        <div class="child3" id="test3"></div>
      </div>
    </div>
    <div class="table" style="height:300px;">
      <div class="cell">
        <div class="child1" id="src1"></div>
        <div class="child2" id="src2">
          <div style="height:30px;"></div>
        </div>
        <div class="child3" id="src3"></div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* test2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test2"));
  auto* test3 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test3"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));
  auto* src2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src2"));
  auto* src3 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src3"));

  LayoutCacheStatus cache_status;
  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);
  // The first child has a fixed height, and shouldn't be affected by the cell
  // height.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test2, space, &cache_status);
  // The second child has overflow:auto and a percentage height, but its
  // intrinsic height is identical to its extrinsic height (when the cell has a
  // height). So it won't need layout, either.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  space = src3->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test3, space, &cache_status);
  // The third child has overflow:auto and a percentage height, and its
  // intrinsic height is 0 (no children), so it matters whether the cell has a
  // height or not. We're only going to need simplified layout, though, since no
  // children will be affected by its height change.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsSimplifiedLayout);
}

TEST_F(LayoutResultCachingTest, OptimisticFloatPlacementNoRelayout) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .root { display: flow-root; width: 300px; }
      .float { float: left; width: 10px; height: 10px; }
    </style>
    <div class="root">
      <div id="empty">
        <div class="float"></div>
      </div>
    </div>
  )HTML");

  auto* empty = To<LayoutBlockFlow>(GetLayoutObjectByElementId("empty"));

  ConstraintSpace space =
      empty->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();

  // We shouldn't have a "forced" BFC block-offset, as the "empty"
  // self-collapsing block should have its "expected" BFC block-offset at the
  // correct place.
  EXPECT_EQ(space.ForcedBfcBlockOffset(), std::nullopt);
}

TEST_F(LayoutResultCachingTest, SelfCollapsingShifting) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 10px; height: 10px; }
      .adjoining-oof { position: absolute; display: inline; }
    </style>
    <div class="bfc">
      <div class="float"></div>
      <div id="test1"></div>
    </div>
    <div class="bfc">
      <div class="float" style="height; 20px;"></div>
      <div id="src1"></div>
    </div>
    <div class="bfc">
      <div class="float"></div>
      <div id="test2">
        <div class="adjoining-oof"></div>
      </div>
    </div>
    <div class="bfc">
      <div class="float" style="height; 20px;"></div>
      <div id="src2">
        <div class="adjoining-oof"></div>
      </div>
    </div>
    <div class="bfc">
      <div class="float"></div>
      <div style="height: 30px;"></div>
      <div id="test3">
        <div class="adjoining-oof"></div>
      </div>
    </div>
    <div class="bfc">
      <div class="float" style="height; 20px;"></div>
      <div style="height: 30px;"></div>
      <div id="src3">
        <div class="adjoining-oof"></div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* test2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test2"));
  auto* test3 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test3"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));
  auto* src2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src2"));
  auto* src3 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src3"));

  LayoutCacheStatus cache_status;

  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  // Case 1: We have a different set of constraints, but as the child has no
  // adjoining descendants it can be shifted anywhere.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test2, space, &cache_status);

  // Case 2: We have a different set of constraints, but the child has an
  // adjoining object and isn't "past" the floats - it can't be reused.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);

  space = src3->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test3, space, &cache_status);

  // Case 3: We have a different set of constraints, and adjoining descendants,
  // but have a position past where they might affect us.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, ClearancePastAdjoiningFloatsMovement) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float-left { float: left; width: 10px; height: 10px; }
      .float-right { float: right; width: 10px; height: 20px; }
    </style>
    <div class="bfc">
      <div>
        <div class="float-left"></div>
        <div class="float-right"></div>
        <div id="test1" style="clear: both;">text</div>
      </div>
    </div>
    <div class="bfc">
      <div>
        <div class="float-left" style="height; 20px;"></div>
        <div class="float-right"></div>
        <div id="src1" style="clear: both;">text</div>
      </div>
    </div>
    <div class="bfc">
      <div>
        <div class="float-left"></div>
        <div class="float-right"></div>
        <div id="test2" style="clear: left;">text</div>
      </div>
    </div>
    <div class="bfc">
      <div>
        <div class="float-left" style="height; 20px;"></div>
        <div class="float-right"></div>
        <div id="src2" style="clear: left;">text</div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* test2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test2"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));
  auto* src2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src2"));

  LayoutCacheStatus cache_status;

  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  // Case 1: We have forced clearance, but floats won't impact our children.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test2, space, &cache_status);

  // Case 2: We have forced clearance, and floats will impact our children.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MarginStrutMovementSelfCollapsing) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
    </style>
    <div class="bfc">
      <div style="margin-top: 10px;">
        <div id="test1">
          <div></div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 5px;">
        <div id="src1">
          <div></div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 10px;">
        <div id="test2">
          <div style="margin-bottom: 8px;"></div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 5px;">
        <div id="src2">
          <div style="margin-bottom: 8px;"></div>
        </div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* test2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test2"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));
  auto* src2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src2"));

  LayoutCacheStatus cache_status;

  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  // Case 1: We can safely re-use this fragment as it doesn't append anything
  // to the margin-strut within the sub-tree.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  // The "end" margin-strut should be updated.
  MarginStrut expected_margin_strut;
  expected_margin_strut.Append(LayoutUnit(5), false /* is_quirky */);
  EXPECT_EQ(expected_margin_strut, result->EndMarginStrut());

  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test2, space, &cache_status);

  // Case 2: We can't re-use this fragment as it appended a non-zero value to
  // the margin-strut within the sub-tree.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MarginStrutMovementInFlow) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
    </style>
    <div class="bfc">
      <div style="margin-top: 10px;">
        <div id="test1">
          <div>text</div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 5px;">
        <div id="src1">
          <div>text</div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 10px;">
        <div id="test2">
          <div style="margin-top: 8px;">text</div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 5px;">
        <div id="src2">
          <div style="margin-top: 8px;">text</div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 10px;">
        <div id="test3">
          <div>
            <div style="margin-top: 8px;"></div>
          </div>
          <div>text</div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 5px;">
        <div id="src3">
          <div>
            <div style="margin-top: 8px;"></div>
          </div>
          <div>text</div>
        </div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* test2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test2"));
  auto* test3 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test3"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));
  auto* src2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src2"));
  auto* src3 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src3"));

  LayoutCacheStatus cache_status;

  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  // Case 1: We can safely re-use this fragment as it doesn't append anything
  // to the margin-strut within the sub-tree.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test2, space, &cache_status);

  // Case 2: We can't re-use this fragment as it appended a non-zero value to
  // the margin-strut within the sub-tree.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);

  space = src3->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test3, space, &cache_status);

  // Case 3: We can't re-use this fragment as a (inner) self-collapsing block
  // appended a non-zero value to the margin-strut within the sub-tree.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MarginStrutMovementPercentage) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
    </style>
    <div class="bfc">
      <div style="margin-top: 10px;">
        <div id="test1" style="width: 0px;">
          <div style="margin-top: 50%;">text</div>
        </div>
      </div>
    </div>
    <div class="bfc">
      <div style="margin-top: 5px;">
        <div id="src1" style="width: 0px;">
          <div style="margin-top: 50%;">text</div>
        </div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));

  LayoutCacheStatus cache_status;

  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  // We can't re-use this fragment as it appended a non-zero value (50%) to the
  // margin-strut within the sub-tree.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitIsFixedBlockSizeIndefinite) {
  SetBodyInnerHTML(R"HTML(
    <div style="display: flex; width: 100px; height: 100px;">
      <div id="test1" style="flex-grow: 1; min-height: 100px;">
        <div style="height: 50px;">text</div>
      </div>
    </div>
    <div style="display: flex; width: 100px; height: 100px; align-items: stretch;">
      <div id="src1" style="flex-grow: 1; min-height: 100px;">
        <div style="height: 50px;">text</div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));

  LayoutCacheStatus cache_status;

  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  // Even though the "align-items: stretch" will make the final fixed
  // block-size indefinite, we don't have any %-block-size children, so we can
  // hit the cache.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MissIsFixedBlockSizeIndefinite) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div style="display: flex; width: 100px; height: 100px; align-items: start;">
      <div id="src1" style="flex-grow: 1; min-height: 100px;">
        <div style="height: 50%;">text</div>
      </div>
    </div>
    <div style="display: flex; width: 100px; height: 100px; align-items: stretch;">
      <div id="test1" style="flex-grow: 1; min-height: 100px;">
        <div style="height: 50%;">text</div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));

  LayoutCacheStatus cache_status;

  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  // The "align-items: stretch" will make the final fixed block-size
  // indefinite, and we have a %-block-size child, so we need to miss the
  // cache.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitColumnFlexBoxMeasureAndLayout) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      .bfc { display: flex; flex-direction: column; width: 100px; height: 100px; }
    </style>
    <div class="bfc">
      <div id="src1" style="flex-grow: 0;">
        <div style="height: 50px;"></div>
      </div>
    </div>
    <div class="bfc">
      <div id="src2" style="flex-grow: 1;">
        <div style="height: 50px;"></div>
      </div>
    </div>
    <div class="bfc">
      <div id="test1" style="flex-grow: 2;">
        <div style="height: 50px;"></div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));
  auto* src2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src2"));

  LayoutCacheStatus cache_status;

  // "src1" only had one "measure" pass performed, and should hit the "measure"
  // cache-slot for "test1".
  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  EXPECT_EQ(space.CacheSlot(), LayoutResultCacheSlot::kMeasure);
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  // "src2" had both a "measure" and "layout" pass performed, and should hit
  // the "layout" cache-slot for "test1".
  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test1, space, &cache_status);

  EXPECT_EQ(space.CacheSlot(), LayoutResultCacheSlot::kLayout);
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitRowFlexBoxMeasureAndLayout) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      .bfc { display: flex; width: 100px; }
    </style>
    <div class="bfc">
      <div id="src1">
        <div style="height: 50px;"></div>
      </div>
    </div>
    <div class="bfc">
      <div id="src2">
        <div style="height: 70px;"></div>
      </div>
      <div style="width: 0px; height: 100px;"></div>
    </div>
    <div class="bfc">
      <div id="test1">
        <div style="height: 50px;"></div>
      </div>
      <div style="width: 0px; height: 100px;"></div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));
  auto* src2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src2"));

  LayoutCacheStatus cache_status;

  // "src1" only had one "measure" pass performed, and should hit the "measure"
  // cache-slot for "test1".
  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);

  EXPECT_EQ(space.CacheSlot(), LayoutResultCacheSlot::kMeasure);
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  // "src2" had both a "measure" and "layout" pass performed, and should hit
  // the "layout" cache-slot for "test1".
  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test1, space, &cache_status);

  EXPECT_EQ(space.CacheSlot(), LayoutResultCacheSlot::kLayout);
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitFlexLegacyImg) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flex; flex-direction: column; width: 300px; }
      .bfc > * { display: flex; }
    </style>
    <div class="bfc">
      <div id="test">
        <img />
      </div>
    </div>
    <div class="bfc" style="height: 200px;">
      <div id="src">
        <img />
      </div>
    </div>
  )HTML");

  auto* test = To<LayoutBlock>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlock>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitFlexLegacyGrid) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flex; flex-direction: column; width: 300px; }
      .bfc > * { display: flex; }
      .grid { display: grid; }
    </style>
    <div class="bfc">
      <div id="test">
        <div class="grid"></div>
      </div>
    </div>
    <div class="bfc" style="height: 200px;">
      <div id="src">
        <div class="grid"></div>
      </div>
    </div>
  )HTML");

  auto* test = To<LayoutBlock>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlock>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitFlexDefiniteChange) {
  SetBodyInnerHTML(R"HTML(
    <div style="display: flex; flex-direction: column;">
      <div style="height: 200px;" id=target1>
        <div style="height: 100px"></div>
      </div>
    </div>
  )HTML");

  auto* target1 = To<LayoutBlock>(GetLayoutObjectByElementId("target1"));

  const LayoutResult* result1 = target1->GetSingleCachedLayoutResult();
  const LayoutResult* measure1 =
      target1->GetSingleCachedMeasureResultForTesting();
  EXPECT_EQ(measure1->IntrinsicBlockSize(), 100);
  EXPECT_EQ(result1->GetPhysicalFragment().Size().height, 200);

  EXPECT_EQ(result1->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kMeasure);
  EXPECT_EQ(result1, measure1);
}

TEST_F(LayoutResultCachingTest, HitOrthogonalRoot) {
  SetBodyInnerHTML(R"HTML(
    <style>
      span { display: inline-block; width: 20px; height: 250px }
    </style>
    <div id="target" style="display: flex;">
      <div style="writing-mode: vertical-rl; line-height: 0;">
        <span></span><span></span>
      </div>
    </div>
  )HTML");

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      target->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(target, space, &cache_status);

  // We should hit the cache using the same constraint space.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, SimpleTable) {
  SetBodyInnerHTML(R"HTML(
    <table>
      <td id="target1">abc</td>
      <td id="target2">abc</td>
    </table>
  )HTML");

  auto* target1 = To<LayoutBlock>(GetLayoutObjectByElementId("target1"));
  auto* target2 = To<LayoutBlock>(GetLayoutObjectByElementId("target2"));

  // Both "target1", and "target1" should have  only had one "measure" pass
  // performed.
  const LayoutResult* result1 = target1->GetSingleCachedLayoutResult();
  const LayoutResult* measure1 =
      target1->GetSingleCachedMeasureResultForTesting();
  EXPECT_EQ(result1->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kMeasure);
  EXPECT_NE(result1, nullptr);
  EXPECT_EQ(result1, measure1);

  const LayoutResult* result2 = target2->GetSingleCachedLayoutResult();
  const LayoutResult* measure2 =
      target2->GetSingleCachedMeasureResultForTesting();
  EXPECT_EQ(result2->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kMeasure);
  EXPECT_NE(result2, nullptr);
  EXPECT_EQ(result2, measure2);
}

TEST_F(LayoutResultCachingTest, MissTableCellMiddleAlignment) {
  SetBodyInnerHTML(R"HTML(
    <table>
      <td id="target" style="vertical-align: middle;">abc</td>
      <td>abc<br>abc</td>
    </table>
  )HTML");

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));

  // "target" should be stretched, and miss the measure cache.
  const LayoutResult* result = target->GetSingleCachedLayoutResult();
  const LayoutResult* measure =
      target->GetSingleCachedMeasureResultForTesting();
  EXPECT_NE(measure, nullptr);
  EXPECT_NE(result, nullptr);
  EXPECT_EQ(measure->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kMeasure);
  EXPECT_EQ(result->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kLayout);
  EXPECT_NE(result, measure);
}

TEST_F(LayoutResultCachingTest, MissTableCellBottomAlignment) {
  SetBodyInnerHTML(R"HTML(
    <table>
      <td id="target" style="vertical-align: bottom;">abc</td>
      <td>abc<br>abc</td>
    </table>
  )HTML");

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));

  // "target" should be stretched, and miss the measure cache.
  const LayoutResult* result = target->GetSingleCachedLayoutResult();
  const LayoutResult* measure =
      target->GetSingleCachedMeasureResultForTesting();
  EXPECT_NE(measure, nullptr);
  EXPECT_NE(result, nullptr);
  EXPECT_EQ(measure->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kMeasure);
  EXPECT_EQ(result->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kLayout);
  EXPECT_NE(result, measure);
}

TEST_F(LayoutResultCachingTest, HitTableCellBaselineAlignment) {
  SetBodyInnerHTML(R"HTML(
    <style>
      td { vertical-align: baseline; }
    </style>
    <table>
      <td id="target">abc</td>
      <td>def</td>
    </table>
  )HTML");

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));

  // "target" should align to the baseline, but hit the cache.
  const LayoutResult* result = target->GetSingleCachedLayoutResult();
  const LayoutResult* measure =
      target->GetSingleCachedMeasureResultForTesting();
  EXPECT_EQ(result->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kMeasure);
  EXPECT_NE(result, nullptr);
  EXPECT_EQ(result, measure);
}

TEST_F(LayoutResultCachingTest, MissTableCellBaselineAlignment) {
  SetBodyInnerHTML(R"HTML(
    <style>
      td { vertical-align: baseline; }
    </style>
    <table>
      <td id="target">abc</td>
      <td><span style="font-size: 32px">def</span></td>
    </table>
  )HTML");

  auto* target = To<LayoutBlock>(GetLayoutObjectByElementId("target"));

  // "target" should align to the baseline, but miss the cache.
  const LayoutResult* result = target->GetSingleCachedLayoutResult();
  const LayoutResult* measure =
      target->GetSingleCachedMeasureResultForTesting();
  EXPECT_NE(measure, nullptr);
  EXPECT_NE(result, nullptr);
  EXPECT_EQ(measure->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kMeasure);
  EXPECT_EQ(result->GetConstraintSpaceForCaching().CacheSlot(),
            LayoutResultCacheSlot::kLayout);
  EXPECT_NE(result, measure);
}

TEST_F(LayoutResultCachingTest, MissTablePercent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 100px; }
      table { height: 100%; }
      caption { height: 50px; }
    </style>
    <div class="bfc" style="height: 50px;">
      <table id="test">
        <caption></caption>
        <td></td>
      </table>
    </div>
    <div class="bfc" style="height: 100px;">
      <table id="src">
        <caption></caption>
        <td></td>
      </table>
    </div>
  )HTML");

  auto* test = To<LayoutBlock>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlock>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitTableRowAdd) {
  SetBodyInnerHTML(R"HTML(
    <table>
      <tr><td>a</td><td>b</td></tr>
      <tr id="test"><td>text</td><td>more text</td></tr>
    </table>
    <table>
      <tr id="src"><td>text</td><td>more text</td></tr>
    </table>
  )HTML");

  auto* test = To<LayoutBlock>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlock>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MissTableRowAdd) {
  SetBodyInnerHTML(R"HTML(
    <table>
      <tr><td>longwordhere</td><td>b</td></tr>
      <tr id="test"><td>text</td><td>more text</td></tr>
    </table>
    <table>
      <tr id="src"><td>text</td><td>more text</td></tr>
    </table>
  )HTML");

  auto* test = To<LayoutBlock>(GetLayoutObjectByElementId(
"""


```