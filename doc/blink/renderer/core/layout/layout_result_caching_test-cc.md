Response:
My thought process for analyzing the provided code snippet goes like this:

1. **Understand the Goal:** The file name `layout_result_caching_test.cc` and the initial comments clearly indicate this file is dedicated to testing the caching mechanism of `LayoutResult` objects within the Blink rendering engine. The core purpose is to verify when layout results can be reused (cache hit) and when a new layout is required (cache miss).

2. **Identify Key Classes and Concepts:**
    * `LayoutResult`: This is the central object being tested. It holds the results of the layout process for a given element.
    * `ConstraintSpace`: This represents the input conditions or constraints under which layout is performed (e.g., available width, BFC offset, exclusion areas). The caching mechanism heavily relies on comparing `ConstraintSpace` objects.
    * `LayoutBox`:  Represents a layout object in the render tree. The `CachedLayoutResult` method is called on instances of `LayoutBox`.
    * `LayoutCacheStatus`: An enum indicating whether a cache hit or miss occurred.
    * `BlockBreakToken`:  Likely related to handling page breaks or column breaks.
    * `FragmentGeometry`: Information about the geometry of a layout fragment, potentially relevant for multi-column layouts or fragmentation.
    * `RenderingTest`:  A base class for setting up and running rendering-related tests within Blink.
    * BFC (Block Formatting Context):  A key concept in CSS layout, influencing how elements are positioned.

3. **Analyze the Test Structure:**
    * The code defines a test fixture `LayoutResultCachingTest` inheriting from `RenderingTest`. This provides the necessary infrastructure for creating and manipulating DOM elements and layout objects.
    * Helper methods like `TestCachedLayoutResultWithBreakToken` and `TestCachedLayoutResult` are provided to simplify the process of invoking the caching logic and checking the result.
    * Numerous `TEST_F` macros define individual test cases. Each test case sets up a specific HTML structure and then calls `TestCachedLayoutResult` with different scenarios to check for cache hits or misses.

4. **Examine Individual Test Cases (and generalize):**  While I won't go through every single test in detail in my thought process, I'll look for patterns and the *kinds* of scenarios being tested:
    * **Varying BFC Offsets:** Tests like `HitDifferentBFCOffset` investigate how changes in the containing BFC's position affect caching.
    * **Varying Exclusion Spaces (Floats):** Tests like `HitDifferentExclusionSpace`, `MissFloatInitiallyIntruding`, `MissFloatWillIntrude` focus on how the presence and dimensions of floating elements (and their impact on the available space) influence caching.
    * **Descendants Affecting Layout:** Tests like `MissDescendantAboveBlockStart1` and `HitOOFDescendantAboveBlockStart` explore how the properties and positioning of an element's descendants can trigger a cache miss or hit. The distinction between in-flow and out-of-flow descendants is important here.
    * **Margin Collapsing and Struts:** `HitDifferentBFCOffsetSameMarginStrut` checks if differences in margins that don't affect the final layout prevent caching.
    * **`clear` Property:**  `HitPushedByFloats1`, `MissPushedByFloats1` examine how the `clear` property, used to position elements below floats, interacts with caching.
    * **Percentage and Fixed Dimensions:** Tests involving `min-width` (`HitPercentageMinWidth`, `HitFixedMinWidth`) explore how different ways of specifying dimensions affect caching.
    * **`width: fit-content` (Shrink-to-Fit):**  `HitShrinkToFit`, `MissShrinkToFit`, `HitShrinkToFitSameIntrinsicSizes`, `HitShrinkToFitDifferentParent` delve into the complexities of caching for elements with `width: fit-content`, considering factors like available space, intrinsic sizes, and parent element properties.
    * **Quirks Mode:** `MissQuirksModePercentageBasedChild` highlights how compatibility modes can impact layout and therefore caching.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The tests directly manipulate HTML structures using `SetBodyInnerHTML`. The structure of the HTML, the elements used, and their attributes are the basis for the layout process.
    * **CSS:** CSS properties like `display`, `width`, `height`, `float`, `clear`, `position`, `margin`, `min-width`, and `width: fit-content` are heavily used to create the different layout scenarios being tested. The behavior of these properties is what the caching mechanism aims to optimize.
    * **JavaScript (Indirectly):** While this specific file doesn't contain JavaScript, layout is often triggered by JavaScript manipulations of the DOM or CSS styles. The correctness of layout caching is crucial for efficient rendering in web applications that use JavaScript for dynamic updates.

6. **Identify Potential Usage Errors (from a developer's perspective):** Although these are *tests*, thinking about what could go wrong when *using* layout in a real web page is helpful:
    * **Unexpected Cache Misses:** Developers might make changes (e.g., to CSS or DOM structure via JavaScript) that unintentionally invalidate the layout cache, leading to performance issues. Understanding the factors that cause cache misses (as explored in these tests) is important for optimization.
    * **Performance Bottlenecks:** If layout is being recalculated unnecessarily due to poor caching, it can become a performance bottleneck, especially on complex pages or during animations.

7. **Synthesize the Summary:** Based on the above analysis, I can now create a concise summary of the file's functionality, its relation to web technologies, and the types of scenarios it covers. The key is to focus on the core purpose of testing the `LayoutResult` caching mechanism and the different layout properties and conditions being examined.
这是名为 `layout_result_caching_test.cc` 的 Chromium Blink 引擎源代码文件的第一部分，其主要功能是**测试 `LayoutResult` 对象的缓存逻辑**。

更具体地说，它旨在验证在不同的布局约束条件下，`LayoutBox` 对象是否能正确地利用已缓存的 `LayoutResult`，从而避免不必要的重复布局计算。该文件通过创建包含两个主要子元素 ("test" 和 "src") 的渲染测试用例，模拟不同的 `ConstraintSpace`（布局约束空间），并断言缓存命中（cache hit）或缓存未命中（cache miss）是否符合预期。

以下是该文件功能的归纳总结：

1. **测试 `LayoutResult` 的缓存命中和未命中:**  核心目标是验证 `LayoutBox::CachedLayoutResult` 方法的正确性，判断在给定特定 `ConstraintSpace` 和 `BlockBreakToken` 的情况下，是否能返回已缓存的 `LayoutResult`，或者需要进行新的布局计算。

2. **模拟不同的布局约束 (`ConstraintSpace`):**  测试用例通过设置不同的 HTML 结构和 CSS 样式，特别是针对 "src" 元素，来创建不同的 `ConstraintSpace`。然后，将 "src" 元素的 `ConstraintSpace` 应用到 "test" 元素，并检查是否发生缓存命中。

3. **关注影响缓存的布局属性和场景:**  该文件涵盖了多种可能影响布局结果和缓存的 CSS 属性和布局场景，例如：
    * **块格式化上下文 (BFC) 的偏移量:**  测试了 BFC 偏移量不同但排除空间相同时的缓存行为。
    * **排除空间 (Exclusion Space):** 测试了排除空间不同但 BFC 偏移量相同时的缓存行为，这通常与浮动元素 (`float`) 有关。
    * **后代元素的影响:**  测试了后代元素是否超出父元素的起始边界，以及这对缓存的影响。区分了普通流后代和绝对定位 (OOF) 后代。
    * **行盒 (Line Box) 后代:**  测试了行盒后代是否超出父元素的起始边界，以及这对缓存的影响。
    * **浮动元素 (Float) 的影响:**  测试了浮动元素是否会初始侵入或后续侵入，以及这对缓存的影响。
    * **被浮动元素推送 (Pushed by Floats):**  测试了元素是否因为浮动元素而被向下推送，以及不同的推送高度对缓存的影响。
    * **其他特殊数据 (Rare Data):**  测试了绝对定位元素的布局约束。
    * **百分比最小宽度 (`min-width`):** 测试了百分比最小宽度计算值不同但最终尺寸不变的情况。
    * **固定最小宽度 (`min-width`):** 测试了固定最小宽度大于可用空间的情况。
    * **收缩到适应内容 (Shrink-to-Fit):** 测试了 `width: fit-content` 场景下的缓存行为，包括最大内容尺寸和最小内容尺寸的情况。
    * **Quirks 模式:**  （将在后续部分涉及）测试了 Quirks 模式下百分比块大小子元素的缓存行为。

4. **使用 `RenderingTest` 框架:**  该文件继承了 `RenderingTest` 类，利用其提供的便利方法来设置 HTML 内容 (`SetBodyInnerHTML`) 和获取布局对象 (`GetLayoutObjectByElementId`)。

5. **使用断言 (`EXPECT_EQ`, `EXPECT_NE`):**  测试用例使用 gtest 框架的断言来验证缓存状态 (`LayoutCacheStatus`) 和布局结果 (`LayoutResult`) 是否符合预期。

总而言之，`layout_result_caching_test.cc` (第一部分) 的核心功能是**构建和执行各种测试用例，以验证 Blink 引擎中 `LayoutResult` 缓存机制的正确性和效率**，特别关注不同布局约束条件下的缓存命中和未命中情况。它通过模拟不同的 HTML 和 CSS 场景，确保引擎能够有效地重用已计算的布局结果，从而提高渲染性能。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** 测试用例通过 `SetBodyInnerHTML` 设置不同的 HTML 结构，这些结构定义了布局树的基本元素和关系。例如，测试中创建了包含 "test" 和 "src" 两个 `div` 元素的结构。
* **CSS:** 测试用例使用 CSS 样式来定义元素的布局属性，如 `display: flow-root`, `width`, `height`, `float`, `clear`, `position`, `padding`, `margin`, `min-width` 等。这些 CSS 属性直接影响元素的布局方式和 `ConstraintSpace`。例如，`float: left` 会影响排除空间，而 `display: flow-root` 会创建新的 BFC。
* **JavaScript:** 虽然此代码文件是 C++ 代码，用于测试 Blink 引擎的核心功能，但布局缓存的正确性直接影响到 JavaScript 操作 DOM 和 CSS 后页面的渲染性能。如果缓存机制工作正常，当 JavaScript 修改样式或结构后，引擎可以尽可能地重用之前的布局结果，避免不必要的重排（reflow）。

**逻辑推理 (假设输入与输出):**

以 `TEST_F(LayoutResultCachingTest, HitDifferentExclusionSpace)` 为例：

* **假设输入:**
    * "test" 元素和 "src" 元素都位于独立的 BFC 中。
    * 它们的 BFC 偏移量相同（垂直位置相同）。
    * 影响它们布局的浮动元素的高度不同，导致它们的排除空间不同。
    * 第一次对 "src" 元素进行布局并缓存了结果。
    * 尝试使用 "src" 的 `ConstraintSpace` 对 "test" 元素进行缓存布局检查。
* **预期输出:**
    * `cache_status` 为 `LayoutCacheStatus::kHit`，表示缓存命中。
    * `result` 不为 `nullptr`，表示返回了缓存的 `LayoutResult`。
    * 缓存的 `LayoutResult` 中的 `BfcBlockOffset` 匹配预期的值（在本例中是 50px，因为浮动元素的高度影响了 "test" 元素在其 BFC 中的起始位置）。
    * 缓存的 `LayoutResult` 中的 `BfcLineOffset` 为 0。

**用户或编程常见的使用错误 (举例说明):**

虽然这是引擎内部的测试，但理解这些测试用例有助于避免开发者在使用 CSS 时可能遇到的与布局缓存相关的问题：

* **过度依赖行内样式导致缓存失效:** 如果频繁使用 JavaScript 修改元素的行内样式，即使是很小的改动，也可能导致布局缓存失效，因为行内样式优先级高，会覆盖 CSS 规则。
* **不必要的 DOM 操作触发重排:**  在动画或频繁更新的场景中，不必要的 DOM 读写操作（例如，先读取元素的某些属性，然后立即修改其样式）会强制浏览器进行重排，即使逻辑上某些元素的布局结果可能可以缓存。
* **对影响布局的属性进行微小变动:**  即使是很小的尺寸或位置变化，如果涉及到影响布局计算的关键属性（例如 `width`, `height`, `float`, `position` 等），都可能导致缓存失效。开发者应该尽量合并或批量处理这些变化，以减少重排次数。
* **不理解 BFC 的影响:**  开发者可能没有意识到 BFC 对内部元素布局的隔离作用，以及不同 BFC 之间的相互影响。了解 BFC 如何影响布局和缓存是优化性能的关键。例如，在测试用例中，将 "test" 和 "src" 放在不同的 BFC 中，允许测试在不同排除空间但相同 BFC 偏移量的情况下进行缓存。

总而言之，`layout_result_caching_test.cc` 的第一部分通过细致的测试用例，确保了 Blink 引擎能够智能地管理布局缓存，从而提升网页的渲染性能和用户体验。开发者理解这些测试背后的原理，有助于编写更高效的 CSS 和 JavaScript 代码。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_result_caching_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/geometry/fragment_geometry.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_utils.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {
namespace {

// These tests exercise the caching logic of |LayoutResult|s. They are
// rendering tests which contain two children: "test" and "src".
//
// Both have layout initially performed on them, however the "src" will have a
// different |ConstraintSpace| which is then used to test either a cache hit
// or miss.
class LayoutResultCachingTest : public RenderingTest {
 protected:
  LayoutResultCachingTest() {}

  const LayoutResult* TestCachedLayoutResultWithBreakToken(
      LayoutBox* box,
      const ConstraintSpace& constraint_space,
      const BlockBreakToken* break_token) {
    std::optional<FragmentGeometry> fragment_geometry;
    LayoutCacheStatus cache_status;
    return box->CachedLayoutResult(constraint_space, break_token, nullptr,
                                   nullptr, &fragment_geometry, &cache_status);
  }

  const LayoutResult* TestCachedLayoutResult(
      LayoutBox* box,
      const ConstraintSpace& constraint_space,
      LayoutCacheStatus* out_cache_status = nullptr) {
    std::optional<FragmentGeometry> fragment_geometry;
    LayoutCacheStatus cache_status;
    const LayoutResult* result =
        box->CachedLayoutResult(constraint_space, nullptr, nullptr, nullptr,
                                &fragment_geometry, &cache_status);
    if (out_cache_status) {
      *out_cache_status = cache_status;
    }
    return result;
  }
};

TEST_F(LayoutResultCachingTest, HitDifferentExclusionSpace) {
  // Same BFC offset, different exclusion space.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="test" style="height: 20px;"></div>
    </div>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 30px;"></div>
      </div>
      <div id="src" style="height: 20px;"></div>
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
  EXPECT_EQ(result->BfcBlockOffset().value(), LayoutUnit(50));
  EXPECT_EQ(result->BfcLineOffset(), LayoutUnit());
}

TEST_F(LayoutResultCachingTest, HitDifferentBFCOffset) {
  // Different BFC offset, same exclusion space.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="test" style="height: 20px; padding-top: 5px;">
        <div class="float" style="height: 20px;"></div>
      </div>
    </div>
    <div class="bfc">
      <div style="height: 40px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="src" style="height: 20px; padding-top: 5px;">
        <div class="float" style="height: 20px;"></div>
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
  EXPECT_EQ(result->BfcBlockOffset().value(), LayoutUnit(40));
  EXPECT_EQ(result->BfcLineOffset(), LayoutUnit());

  // Also check that the exclusion(s) got moved correctly.
  LayoutOpportunityVector opportunities =
      result->GetExclusionSpace().AllLayoutOpportunities(
          /* offset */ {LayoutUnit(), LayoutUnit()},
          /* available_inline_size */ LayoutUnit(100));

  EXPECT_EQ(opportunities.size(), 3u);

  EXPECT_EQ(opportunities[0].rect.start_offset,
            BfcOffset(LayoutUnit(50), LayoutUnit()));
  EXPECT_EQ(opportunities[0].rect.end_offset,
            BfcOffset(LayoutUnit(100), LayoutUnit::Max()));

  EXPECT_EQ(opportunities[1].rect.start_offset,
            BfcOffset(LayoutUnit(), LayoutUnit(20)));
  EXPECT_EQ(opportunities[1].rect.end_offset,
            BfcOffset(LayoutUnit(100), LayoutUnit(45)));

  EXPECT_EQ(opportunities[2].rect.start_offset,
            BfcOffset(LayoutUnit(), LayoutUnit(65)));
  EXPECT_EQ(opportunities[2].rect.end_offset,
            BfcOffset(LayoutUnit(100), LayoutUnit::Max()));
}

TEST_F(LayoutResultCachingTest, HitDifferentBFCOffsetSameMarginStrut) {
  // Different BFC offset, same margin-strut.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
    </style>
    <div class="bfc">
      <div style="height: 50px; margin-bottom: 20px;"></div>
      <div id="test" style="height: 20px;"></div>
    </div>
    <div class="bfc">
      <div style="height: 40px; margin-bottom: 20px;"></div>
      <div id="src" style="height: 20px;"></div>
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

TEST_F(LayoutResultCachingTest, MissDescendantAboveBlockStart1) {
  // Same BFC offset, different exclusion space, descendant above
  // block start.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="test" style="height: 20px; padding-top: 5px;">
        <div style="height: 10px; margin-top: -10px;"></div>
      </div>
    </div>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 30px;"></div>
      </div>
      <div id="src" style="height: 20px;"></div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MissDescendantAboveBlockStart2) {
  // Different BFC offset, same exclusion space, descendant above
  // block start.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="test" style="height: 20px; padding-top: 5px;">
        <div style="height: 10px; margin-top: -10px;"></div>
      </div>
    </div>
    <div class="bfc">
      <div style="height: 40px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="src" style="height: 20px;"></div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitOOFDescendantAboveBlockStart) {
  // Different BFC offset, same exclusion space, OOF-descendant above
  // block start.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="test" style="position: relative; height: 20px; padding-top: 5px;">
        <div style="position: absolute; height: 10px; top: -10px;"></div>
      </div>
    </div>
    <div class="bfc">
      <div style="height: 40px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="src" style="height: 20px;"></div>
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

TEST_F(LayoutResultCachingTest, HitLineBoxDescendantAboveBlockStart) {
  // Different BFC offset, same exclusion space, line-box descendant above
  // block start.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="test" style="font-size: 12px;">
        text
        <span style="margin: 0 1px;">
          <span style="display: inline-block; vertical-align: text-bottom; width: 16px; height: 16px;"></span>
        </span>
      </div>
    </div>
    <div class="bfc">
      <div style="height: 40px;">
        <div class="float" style="height: 20px;"></div>
      </div>
      <div id="src" style="font-size: 12px;">
        text
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

TEST_F(LayoutResultCachingTest, MissFloatInitiallyIntruding1) {
  // Same BFC offset, different exclusion space, float initially
  // intruding.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="test" style="height: 20px;"></div>
    </div>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 30px;"></div>
      </div>
      <div id="src" style="height: 20px;"></div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MissFloatInitiallyIntruding2) {
  // Different BFC offset, same exclusion space, float initially
  // intruding.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="test" style="height: 60px;"></div>
    </div>
    <div class="bfc">
      <div style="height: 70px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="src" style="height: 20px;"></div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MissFloatWillIntrude1) {
  // Same BFC offset, different exclusion space, float will intrude.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 40px;"></div>
      </div>
      <div id="test" style="height: 20px;"></div>
    </div>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="src" style="height: 20px;"></div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MissFloatWillIntrude2) {
  // Different BFC offset, same exclusion space, float will intrude.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 40px;"></div>
      </div>
      <div id="test" style="height: 60px;"></div>
    </div>
    <div class="bfc">
      <div style="height: 30px;">
        <div class="float" style="height: 40px;"></div>
      </div>
      <div id="src" style="height: 20px;"></div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitPushedByFloats1) {
  // Same BFC offset, different exclusion space, pushed by floats.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="test" style="height: 20px; clear: left;"></div>
    </div>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 70px;"></div>
      </div>
      <div id="src" style="height: 20px; clear: left;"></div>
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

TEST_F(LayoutResultCachingTest, HitPushedByFloats2) {
  // Different BFC offset, same exclusion space, pushed by floats.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="test" style="height: 20px; clear: left;"></div>
    </div>
    <div class="bfc">
      <div style="height: 30px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="src" style="height: 20px; clear: left;"></div>
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

TEST_F(LayoutResultCachingTest, MissPushedByFloats1) {
  // Same BFC offset, different exclusion space, pushed by floats.
  // Miss due to shrinking offset.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 70px;"></div>
      </div>
      <div id="test" style="height: 20px; clear: left;"></div>
    </div>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="src" style="height: 20px; clear: left;"></div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MissPushedByFloats2) {
  // Different BFC offset, same exclusion space, pushed by floats.
  // Miss due to shrinking offset.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .float { float: left; width: 50px; }
    </style>
    <div class="bfc">
      <div style="height: 30px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="test" style="height: 20px; clear: left;"></div>
    </div>
    <div class="bfc">
      <div style="height: 50px;">
        <div class="float" style="height: 60px;"></div>
      </div>
      <div id="src" style="height: 20px; clear: left;"></div>
    </div>
  )HTML");

  auto* test = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test"));
  auto* src = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src"));

  LayoutCacheStatus cache_status;
  const ConstraintSpace& space =
      src->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test, space, &cache_status);

  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitDifferentRareData) {
  // Same absolute fixed constraints.
  SetBodyInnerHTML(R"HTML(
    <style>
      .container { position: relative; width: 100px; height: 100px; }
      .abs { position: absolute; width: 100px; height: 100px; top: 0; left: 0; }
    </style>
    <div class="container">
      <div id="test" class="abs"></div>
    </div>
    <div class="container" style="width: 200px; height: 200px;">
      <div id="src" class="abs"></div>
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

TEST_F(LayoutResultCachingTest, HitPercentageMinWidth) {
  // min-width calculates to different values, but doesn't change size.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .inflow { width: 100px; min-width: 25%; }
    </style>
    <div class="bfc">
      <div id="test" class="inflow"></div>
    </div>
    <div class="bfc" style="width: 200px; height: 200px;">
      <div id="src" class="inflow"></div>
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

TEST_F(LayoutResultCachingTest, HitFixedMinWidth) {
  // min-width is always larger than the available size.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .inflow { min-width: 300px; }
    </style>
    <div class="bfc">
      <div id="test" class="inflow"></div>
    </div>
    <div class="bfc" style="width: 200px; height: 200px;">
      <div id="src" class="inflow"></div>
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

TEST_F(LayoutResultCachingTest, HitShrinkToFit) {
  SetBodyInnerHTML(R"HTML(
    <div style="display: flow-root; width: 300px; height: 100px;">
      <div id="test1" style="float: left;">
        <div style="display: inline-block; width: 150px;"></div>
        <div style="display: inline-block; width: 50px;"></div>
      </div>
      <div id="test2" style="float: left;">
        <div style="display: inline-block; width: 350px;"></div>
        <div style="display: inline-block; width: 250px;"></div>
      </div>
    </div>
    <div style="display: flow-root; width: 400px; height: 100px;">
      <div id="src1" style="float: left;">
        <div style="display: inline-block; width: 150px;"></div>
        <div style="display: inline-block; width: 50px;"></div>
      </div>
    </div>
    <div style="display: flow-root; width: 200px; height: 100px;">
      <div id="src2" style="float: left;">
        <div style="display: inline-block; width: 350px;"></div>
        <div style="display: inline-block; width: 250px;"></div>
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
  // test1 was sized to its max-content size, passing an available size larger
  // than the fragment should hit the cache.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);

  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test2, space, &cache_status);
  // test2 was sized to its min-content size in, passing an available size
  // smaller than the fragment should hit the cache.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kHit);
  EXPECT_NE(result, nullptr);
}

TEST_F(LayoutResultCachingTest, MissShrinkToFit) {
  SetBodyInnerHTML(R"HTML(
    <div style="display: flow-root; width: 300px; height: 100px;">
      <div id="test1" style="float: left;">
        <div style="display: inline-block; width: 150px;"></div>
        <div style="display: inline-block; width: 50px;"></div>
      </div>
      <div id="test2" style="float: left;">
        <div style="display: inline-block; width: 350px;"></div>
        <div style="display: inline-block; width: 250px;"></div>
      </div>
      <div id="test3" style="float: left; min-width: 80%;">
        <div style="display: inline-block; width: 150px;"></div>
        <div style="display: inline-block; width: 250px;"></div>
      </div>
      <div id="test4" style="float: left; margin-left: 75px;">
        <div style="display: inline-block; width: 150px;"></div>
        <div style="display: inline-block; width: 50px;"></div>
      </div>
    </div>
    <div style="display: flow-root; width: 100px; height: 100px;">
      <div id="src1" style="float: left;">
        <div style="display: inline-block; width: 150px;"></div>
        <div style="display: inline-block; width: 50px;"></div>
      </div>
    </div>
    <div style="display: flow-root; width: 400px; height: 100px;">
      <div id="src2" style="float: left;">
        <div style="display: inline-block; width: 350px;"></div>
        <div style="display: inline-block; width: 250px;"></div>
      </div>
      <div id="src3" style="float: left; min-width: 80%;">
        <div style="display: inline-block; width: 150px;"></div>
        <div style="display: inline-block; width: 250px;"></div>
      </div>
    </div>
    <div style="display: flow-root; width: 250px; height: 100px;">
      <div id="src4" style="float: left; margin-left: 75px;">
        <div style="display: inline-block; width: 150px;"></div>
        <div style="display: inline-block; width: 50px;"></div>
      </div>
    </div>
  )HTML");

  auto* test1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test1"));
  auto* test2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test2"));
  auto* test3 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test3"));
  auto* test4 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("test4"));
  auto* src1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src1"));
  auto* src2 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src2"));
  auto* src3 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src3"));
  auto* src4 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("src4"));

  LayoutCacheStatus cache_status;
  ConstraintSpace space =
      src1->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  const LayoutResult* result =
      TestCachedLayoutResult(test1, space, &cache_status);
  // test1 was sized to its max-content size, passing an available size smaller
  // than the fragment should miss the cache.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);

  space = src2->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test2, space, &cache_status);
  // test2 was sized to its min-content size, passing an available size
  // larger than the fragment should miss the cache.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);

  space = src3->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test3, space, &cache_status);
  // test3 was sized to its min-content size, however it should miss the cache
  // as it has a %-min-size.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);

  space = src4->GetSingleCachedLayoutResult()->GetConstraintSpaceForCaching();
  result = TestCachedLayoutResult(test4, space, &cache_status);
  // test4 was sized to its max-content size, however it should miss the cache
  // due to its margin.
  EXPECT_EQ(cache_status, LayoutCacheStatus::kNeedsLayout);
  EXPECT_EQ(result, nullptr);
}

TEST_F(LayoutResultCachingTest, HitShrinkToFitSameIntrinsicSizes) {
  // We have a shrink-to-fit node, with the min, and max intrinsic sizes being
  // equal (the available size doesn't affect the final size).
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; width: 300px; height: 300px; }
      .shrink { width: fit-content; }
      .child { width: 250px; }
    </style>
    <div class="bfc">
      <div id="test" class="shrink">
        <div class="child"></div>
      </div>
    </div>
    <div class="bfc" style="width: 200px; height: 200px;">
      <div id="src" class="shrink">
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

TEST_F(LayoutResultCachingTest, HitShrinkToFitDifferentParent) {
  // The parent "bfc" node changes from shrink-to-fit, to a fixed width. But
  // these calculate as the same available space to the "test" element.
  SetBodyInnerHTML(R"HTML(
    <style>
      .bfc { display: flow-root; }
      .child { width: 250px; }
    </style>
    <div class="bfc" style="width: fit-content; height: 100px;">
      <div id="test">
        <div class="child"></div>
      </div>
    </div>
    <div class="bfc" style="width: 250px; height: 100px;">
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

TEST_F(LayoutResultCachingTest, MissQuirksModePercentageBasedChild) {
  // Quirks-mode %-block-size child.
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
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

  Layo
```