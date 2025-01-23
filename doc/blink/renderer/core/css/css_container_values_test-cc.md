Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the given C++ file (`css_container_values_test.cc`), its relation to web technologies, and insights into its usage and debugging.

2. **Identify the Core Class Under Test:** The file name itself, `css_container_values_test.cc`, strongly suggests that it tests the `CSSContainerValues` class. The `#include "third_party/blink/renderer/core/css/css_container_values.h"` confirms this.

3. **Analyze the Test Structure:** The file uses the `TEST_F` macro, which is a standard pattern in C++ unit testing frameworks (likely Google Test, given the Chromium context). This indicates that `CSSContainerValuesTest` is the test fixture class, inheriting from `PageTestBase`.

4. **Decipher the Test Fixture:**
    * `PageTestBase`:  This immediately tells us the tests are performed in a simulated web page environment. It provides the necessary infrastructure to manipulate DOM elements and CSS.
    * `SetUp()`: This method is called before each test. It initializes the testing environment by setting up a basic HTML structure with a `div` element having the ID "container". This is the primary element the tests will interact with.
    * Helper Methods (`SetContainerWritingDirection`, `CreateStickyValues`, `CreateSnappedValues`, `CreateOverflowingValues`): These functions are crucial for setting up different scenarios for testing `CSSContainerValues`. They encapsulate the creation of `CSSContainerValues` objects with specific configurations. The naming of these methods is very descriptive, giving strong hints about the properties being tested (sticky positioning, scroll snapping, overflow).

5. **Examine Individual Tests:** Each `TEST_F` block focuses on a specific aspect of `CSSContainerValues`. We need to analyze what each test does:
    * **Sticky Tests (`StickyHorizontalTbLtr`, `StickyHorizontalTbRtl`, etc.):** These tests manipulate the `writing-mode` and `direction` CSS properties of the container and then create `CSSContainerValues` with different physical sticky values (`kRight`, `kTop`). The `EXPECT_EQ` assertions then verify the logical sticky values (`kStart`, `kEnd`) based on the writing mode and direction. This immediately connects to the CSS `position: sticky` property and how its behavior is affected by text direction.
    * **Snapped Tests (`SnappedNone`, `SnappedX`, `SnappedY`, etc.):** These tests create `CSSContainerValues` with different `ContainerSnappedFlags` and assert the boolean properties (`SnappedBlock`, `SnappedInline`, `Snapped`). This relates to CSS scroll snapping features.
    * **Overflowing Tests (`OverflowingHorizontalTbLtr`, `OverflowingHorizontalTbRtl`, etc.):**  Similar to the sticky tests, these manipulate writing mode and direction and check the logical overflow directions (`OverflowingInline`, `OverflowingBlock`) based on the physical overflow flags. This relates to how overflow is handled in different writing modes.

6. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The `SetUp` method directly manipulates the HTML DOM by setting the `innerHTML` of the `body`. The tests target a specific `div` element using its ID.
    * **CSS:** The tests directly interact with CSS concepts like `writing-mode`, `direction`, `position: sticky`, and scroll snapping. The helper functions manipulate these properties indirectly through the `ComputedStyleBuilder`. The assertions verify the logical interpretation of physical sticky and overflow values, which are core CSS concepts.
    * **JavaScript:** While this specific test file doesn't directly involve JavaScript *code*, the functionality being tested (how CSS properties are interpreted and used) directly impacts how JavaScript interacts with the layout and scrolling behavior of web pages. For instance, JavaScript might need to determine if an element is stuck or snapped.

7. **Infer Functionality of `CSSContainerValues`:** Based on the tests, we can deduce that `CSSContainerValues` is a class that likely holds computed or derived values related to the container element's state, particularly concerning:
    * Sticky positioning (whether an element is stuck at the start or end of its container in the inline or block direction).
    * Scroll snapping (whether the container snaps to specific points along the X or Y axis).
    * Overflow (whether the container is overflowing in the inline or block direction, and at which end).

8. **Consider User/Programming Errors:** The tests themselves don't directly expose user errors. However, they validate the *correctness* of the `CSSContainerValues` logic. Incorrect implementations in this class *could* lead to user-visible issues like sticky elements not sticking as expected or scroll snapping behaving erratically. Programmers implementing CSS features or related JavaScript would rely on the correctness of classes like `CSSContainerValues`.

9. **Trace User Operations (Debugging):**  Think about how a user might trigger the logic tested in this file. A user scrolling a container with `position: sticky` elements or a container with scroll snapping enabled would indirectly rely on the calculations performed by `CSSContainerValues`. If a bug is suspected in sticky positioning or scroll snapping, a developer might set breakpoints in the `CSSContainerValues` class or related code to examine the computed values and understand why the behavior is incorrect. The tests in this file provide a controlled environment to isolate and verify the logic.

10. **Structure the Output:** Organize the findings into the requested sections: Functionality, Relationship to Web Technologies (with examples), Logical Reasoning (with assumed input/output), Common Errors, and User Operation/Debugging. Use clear and concise language.

By following this structured approach, analyzing the code, and making logical connections, we can effectively understand the purpose and context of this C++ test file within the larger Chromium project.
好的，让我们来分析一下 `blink/renderer/core/css/css_container_values_test.cc` 这个文件。

**文件功能:**

这个文件是一个 C++ 的单元测试文件，专门用于测试 `CSSContainerValues` 类的功能。`CSSContainerValues` 类很可能负责存储和计算与 CSS 容器查询 (Container Queries) 相关的值。这些值包括但不限于：

* **滚动吸附 (Scroll Snapping):**  指示容器是否在水平或垂直方向上进行了滚动吸附。
* **粘性定位 (Sticky Positioning):**  指示容器的边缘是否被粘住（例如，`position: sticky` 的效果）。
* **溢出 (Overflow):** 指示容器在水平或垂直方向上是否发生了溢出。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联到 CSS 的容器查询功能，而容器查询本身就是为了解决在不同容器尺寸下应用不同 CSS 样式的需求。

1. **CSS:**
   * **容器查询 (Container Queries):**  `CSSContainerValues` 的存在是为了支持容器查询。容器查询允许我们根据父容器的尺寸或其他特性来应用样式，而不是像媒体查询那样根据视口尺寸。
   * **`container-type` 和 `container-name`:**  为了使一个元素成为查询容器，我们需要在 CSS 中使用 `container-type` (例如 `size`, `inline-size`) 和可选的 `container-name` 属性。
   * **`@container` 规则:**  容器查询是通过 `@container` 规则来实现的，这个规则内部的样式只会在满足容器条件时应用。
   * **`position: sticky`:**  测试中涉及到 `ContainerStuckPhysical` 和 `ContainerStuckLogical`，这与 `position: sticky` 的行为密切相关。容器的滚动行为会影响粘性元素的粘滞状态。
   * **滚动吸附 (Scroll Snapping):** 测试中的 `ContainerSnappedFlags` 与 CSS 的滚动吸附属性如 `scroll-snap-type`, `scroll-snap-align` 等相关。

   **例子:**

   ```html
   <div id="container" style="container-type: inline-size;">
     <div id="item" style="@container (min-width: 300px) { color: red; }">
       这段文字会根据容器宽度改变颜色。
     </div>
   </div>
   ```

   在这个例子中，`#container` 是一个查询容器。当 `#container` 的 `inline-size` (通常是宽度) 大于等于 300px 时，`#item` 的文字颜色会变成红色。`CSSContainerValues` 可能会存储关于 `#container` 的尺寸信息，以便 `@container` 规则可以正确评估。

2. **HTML:**
   * HTML 结构定义了容器和被查询的元素。测试文件中的 `SetUp` 方法就创建了一个简单的 HTML 结构 `<div id="container"></div>` 来进行测试。

3. **JavaScript:**
   * 虽然这个测试文件本身是 C++ 的，但 `CSSContainerValues` 的计算结果会被渲染引擎使用，而 JavaScript 可以读取和操作与布局相关的属性，从而间接地受到其影响。
   * 例如，JavaScript 可以使用 `getBoundingClientRect()` 获取容器的尺寸，这与容器查询的评估有关。
   * 某些复杂的布局或动画可能需要 JavaScript 来配合容器查询的效果。

**逻辑推理 (假设输入与输出):**

让我们以 `StickyHorizontalTbLtr` 这个测试为例进行逻辑推理：

* **假设输入:**
    * 容器的 `writing-mode` 设置为 `horizontal-tb` (水平方向，从上到下)。
    * 容器的 `direction` 设置为 `ltr` (从左到右)。
    * 创建 `CSSContainerValues` 对象时，`horizontal` 参数设置为 `ContainerStuckPhysical::kRight` (物理上的右侧被粘住)，`vertical` 参数设置为 `ContainerStuckPhysical::kTop` (物理上的顶部被粘住)。

* **逻辑推理:**
    * 在水平书写模式且从左到右的布局中：
        * 物理上的 "右侧" 对应于逻辑上的 "结束 (end)" 侧 (inline方向)。
        * 物理上的 "顶部" 对应于逻辑上的 "开始 (start)" 侧 (block方向)。

* **预期输出:**
    * `values->StuckInline()` 应该返回 `ContainerStuckLogical::kEnd`。
    * `values->StuckBlock()` 应该返回 `ContainerStuckLogical::kStart`。

**用户或编程常见的使用错误及举例说明:**

虽然这个文件是测试代码，但它可以帮助我们理解与容器查询相关的潜在错误：

1. **CSS 中未正确设置容器属性:**  用户可能忘记在容器元素上设置 `container-type` 或 `container-name`，导致 `@container` 规则无法生效。

   **例子:**

   ```html
   <!-- 缺少 container-type -->
   <div id="container">
     <div style="@container (min-width: 300px) { color: red; }">...</div>
   </div>
   ```

2. **`@container` 规则的语法错误:**  用户可能在 `@container` 规则内部使用了错误的语法，例如错误的条件判断。

   **例子:**

   ```css
   @container my-container(min-width: 300) { /* 缺少 px 单位 */
     color: red;
   }
   ```

3. **逻辑上混淆物理和逻辑方向:**  在处理不同的 `writing-mode` 和 `direction` 时，开发者可能会混淆物理上的 top/right/bottom/left 和逻辑上的 start/end。测试文件中的 `StickyHorizontalTbRtl` 等测试就是为了验证在这种情况下逻辑方向的正确性。

   **例子:**  假设开发者错误地认为在 `direction: rtl` 的情况下，物理上的 "右侧" 仍然对应逻辑上的 "结束"，这会导致粘性定位行为不符合预期。

4. **滚动吸附配置错误:** 用户可能配置了相互冲突的滚动吸附属性，例如在同一个轴上同时设置了 `start` 和 `end` 的对齐方式。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户在浏览器中浏览一个使用了容器查询的网页时，浏览器渲染引擎会执行以下步骤，其中就可能涉及到 `CSSContainerValues` 的计算：

1. **解析 HTML 和 CSS:** 浏览器首先解析 HTML 结构和 CSS 样式表。
2. **构建渲染树:**  根据 HTML 和 CSS 构建渲染树，这个过程中会确定元素的盒模型和样式。
3. **确定容器关系:**  对于设置了 `container-type` 的元素，浏览器会识别它们作为查询容器。
4. **评估 `@container` 规则:** 当遇到 `@container` 规则时，浏览器需要评估容器的尺寸和其他相关属性是否满足规则的条件。
5. **计算 `CSSContainerValues`:**  为了评估 `@container` 规则，浏览器会计算容器的相关值，这些值很可能存储在 `CSSContainerValues` 对象中。例如，容器的 `inline-size` (宽度) 会被获取。
6. **应用样式:**  如果容器满足 `@container` 规则的条件，则应用规则内部的样式。
7. **布局和绘制:**  根据最终的样式进行布局和绘制。

**作为调试线索:**

如果开发者在调试与容器查询相关的 bug (例如，样式没有在预期的情况下应用)，他们可能会：

1. **检查 CSS 语法:**  首先确认 `@container` 规则的语法是否正确，容器属性是否已设置。
2. **使用浏览器开发者工具:**  查看元素的计算样式，确认容器查询是否生效。
3. **断点调试 C++ 代码:**  如果怀疑是渲染引擎的计算逻辑有问题，开发者可能会在 `blink/renderer/core/css/css_container_values.cc` 或相关的代码中设置断点，例如在 `CSSContainerValues` 的构造函数或相关计算方法中，来检查容器属性的计算过程和值。
4. **查看测试用例:**  查看像 `css_container_values_test.cc` 这样的测试文件，可以帮助理解 `CSSContainerValues` 的预期行为和各种场景下的逻辑。如果测试用例覆盖了相关的场景，并且测试通过，则问题可能出在其他地方。如果测试用例失败，则表明 `CSSContainerValues` 的实现存在 bug。

总而言之，`blink/renderer/core/css/css_container_values_test.cc` 是 Blink 引擎中用于测试容器查询核心数据结构 `CSSContainerValues` 的关键文件。它确保了容器查询功能的正确性，并与 HTML、CSS 和 JavaScript 共同构建了现代 Web 页面的布局和样式能力。理解这个文件及其测试的场景，有助于开发者理解容器查询的工作原理，并排查相关的问题。

### 提示词
```
这是目录为blink/renderer/core/css/css_container_values_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/css_container_values.h"

#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class CSSContainerValuesTest : public PageTestBase {
 public:
  void SetUp() override {
    PageTestBase::SetUp();
    GetDocument().body()->setInnerHTML(R"HTML(
      <div id="container"></div>
    )HTML");
  }

  void SetContainerWritingDirection(WritingMode writing_mode,
                                    TextDirection direction) {
    ComputedStyleBuilder builder(
        *GetDocument().GetStyleResolver().InitialStyleForElement());
    builder.SetWritingMode(writing_mode);
    builder.SetDirection(direction);
    ContainerElement().SetComputedStyle(builder.TakeStyle());
  }

  CSSContainerValues* CreateStickyValues(ContainerStuckPhysical horizontal,
                                         ContainerStuckPhysical vertical) {
    return MakeGarbageCollected<CSSContainerValues>(
        GetDocument(), ContainerElement(), std::nullopt, std::nullopt,
        horizontal, vertical,
        static_cast<ContainerSnappedFlags>(ContainerSnapped::kNone),
        static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kNone),
        static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kNone));
  }

  CSSContainerValues* CreateSnappedValues(ContainerSnappedFlags snapped) {
    return MakeGarbageCollected<CSSContainerValues>(
        GetDocument(), ContainerElement(), std::nullopt, std::nullopt,
        ContainerStuckPhysical::kNo, ContainerStuckPhysical::kNo, snapped,
        static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kNone),
        static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kNone));
  }

  CSSContainerValues* CreateOverflowingValues(
      ContainerOverflowingFlags horizontal,
      ContainerOverflowingFlags vertical) {
    return MakeGarbageCollected<CSSContainerValues>(
        GetDocument(), ContainerElement(), std::nullopt, std::nullopt,
        ContainerStuckPhysical::kNo, ContainerStuckPhysical::kNo,
        static_cast<ContainerSnappedFlags>(ContainerSnapped::kNone), horizontal,
        vertical);
  }

 private:
  Element& ContainerElement() {
    return *GetDocument().getElementById(AtomicString("container"));
  }
};

TEST_F(CSSContainerValuesTest, StickyHorizontalTbLtr) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kLtr);
  MediaValues* values = CreateStickyValues(ContainerStuckPhysical::kRight,
                                           ContainerStuckPhysical::kTop);
  EXPECT_EQ(values->StuckInline(), ContainerStuckLogical::kEnd);
  EXPECT_EQ(values->StuckBlock(), ContainerStuckLogical::kStart);
}

TEST_F(CSSContainerValuesTest, StickyHorizontalTbRtl) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kRtl);
  MediaValues* values = CreateStickyValues(ContainerStuckPhysical::kRight,
                                           ContainerStuckPhysical::kTop);
  EXPECT_EQ(values->StuckInline(), ContainerStuckLogical::kStart);
  EXPECT_EQ(values->StuckBlock(), ContainerStuckLogical::kStart);
}

TEST_F(CSSContainerValuesTest, StickyVerticalLrLtr) {
  SetContainerWritingDirection(WritingMode::kVerticalLr, TextDirection::kLtr);
  MediaValues* values = CreateStickyValues(ContainerStuckPhysical::kRight,
                                           ContainerStuckPhysical::kTop);
  EXPECT_EQ(values->StuckInline(), ContainerStuckLogical::kStart);
  EXPECT_EQ(values->StuckBlock(), ContainerStuckLogical::kEnd);
}

TEST_F(CSSContainerValuesTest, StickyVerticalLrRtl) {
  SetContainerWritingDirection(WritingMode::kVerticalLr, TextDirection::kRtl);
  MediaValues* values = CreateStickyValues(ContainerStuckPhysical::kRight,
                                           ContainerStuckPhysical::kTop);
  EXPECT_EQ(values->StuckInline(), ContainerStuckLogical::kEnd);
  EXPECT_EQ(values->StuckBlock(), ContainerStuckLogical::kEnd);
}

TEST_F(CSSContainerValuesTest, StickyVerticalRlLtr) {
  SetContainerWritingDirection(WritingMode::kVerticalRl, TextDirection::kLtr);
  MediaValues* values = CreateStickyValues(ContainerStuckPhysical::kRight,
                                           ContainerStuckPhysical::kTop);
  EXPECT_EQ(values->StuckInline(), ContainerStuckLogical::kStart);
  EXPECT_EQ(values->StuckBlock(), ContainerStuckLogical::kStart);
}

TEST_F(CSSContainerValuesTest, StickyVerticalRlRtl) {
  SetContainerWritingDirection(WritingMode::kVerticalRl, TextDirection::kRtl);
  MediaValues* values = CreateStickyValues(ContainerStuckPhysical::kRight,
                                           ContainerStuckPhysical::kTop);
  EXPECT_EQ(values->StuckInline(), ContainerStuckLogical::kEnd);
  EXPECT_EQ(values->StuckBlock(), ContainerStuckLogical::kStart);
}

TEST_F(CSSContainerValuesTest, SnappedNone) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kLtr);
  MediaValues* values = CreateSnappedValues(
      static_cast<ContainerSnappedFlags>(ContainerSnapped::kNone));
  EXPECT_FALSE(values->SnappedBlock());
  EXPECT_FALSE(values->SnappedInline());
  EXPECT_FALSE(values->Snapped());
}

TEST_F(CSSContainerValuesTest, SnappedX) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kLtr);
  MediaValues* values = CreateSnappedValues(
      static_cast<ContainerSnappedFlags>(ContainerSnapped::kX));
  EXPECT_TRUE(values->SnappedX());
  EXPECT_FALSE(values->SnappedY());
  EXPECT_TRUE(values->Snapped());
}

TEST_F(CSSContainerValuesTest, SnappedY) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kLtr);
  MediaValues* values = CreateSnappedValues(
      static_cast<ContainerSnappedFlags>(ContainerSnapped::kY));
  EXPECT_FALSE(values->SnappedX());
  EXPECT_TRUE(values->SnappedY());
  EXPECT_TRUE(values->Snapped());
}

TEST_F(CSSContainerValuesTest, SnappedBlock) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kLtr);
  MediaValues* values = CreateSnappedValues(
      static_cast<ContainerSnappedFlags>(ContainerSnapped::kY));
  EXPECT_TRUE(values->SnappedBlock());
  EXPECT_FALSE(values->SnappedInline());
  EXPECT_TRUE(values->Snapped());
}

TEST_F(CSSContainerValuesTest, SnappedInline) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kLtr);
  MediaValues* values = CreateSnappedValues(
      static_cast<ContainerSnappedFlags>(ContainerSnapped::kX));
  EXPECT_FALSE(values->SnappedBlock());
  EXPECT_TRUE(values->SnappedInline());
  EXPECT_TRUE(values->Snapped());
}

TEST_F(CSSContainerValuesTest, SnappedBoth) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kLtr);
  MediaValues* values = CreateSnappedValues(
      static_cast<ContainerSnappedFlags>(ContainerSnapped::kX) |
      static_cast<ContainerSnappedFlags>(ContainerSnapped::kY));
  EXPECT_TRUE(values->SnappedBlock());
  EXPECT_TRUE(values->SnappedInline());
  EXPECT_TRUE(values->Snapped());
}

TEST_F(CSSContainerValuesTest, OverflowingHorizontalTbLtr) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kLtr);
  MediaValues* values = CreateOverflowingValues(
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd),
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingInline(),
            static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd));
  EXPECT_EQ(values->OverflowingBlock(), static_cast<ContainerOverflowingFlags>(
                                            ContainerOverflowing::kStart));
}

TEST_F(CSSContainerValuesTest, OverflowingHorizontalTbRtl) {
  SetContainerWritingDirection(WritingMode::kHorizontalTb, TextDirection::kRtl);
  MediaValues* values = CreateOverflowingValues(
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd),
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingInline(), static_cast<ContainerOverflowingFlags>(
                                             ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingBlock(), static_cast<ContainerOverflowingFlags>(
                                            ContainerOverflowing::kStart));
}

TEST_F(CSSContainerValuesTest, OverflowingVerticalLrLtr) {
  SetContainerWritingDirection(WritingMode::kVerticalLr, TextDirection::kLtr);
  MediaValues* values = CreateOverflowingValues(
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd),
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingInline(), static_cast<ContainerOverflowingFlags>(
                                             ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingBlock(),
            static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd));
}

TEST_F(CSSContainerValuesTest, OverflowingVerticalLrRtl) {
  SetContainerWritingDirection(WritingMode::kVerticalLr, TextDirection::kRtl);
  MediaValues* values = CreateOverflowingValues(
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd),
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingInline(),
            static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd));
  EXPECT_EQ(values->OverflowingBlock(),
            static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd));
}

TEST_F(CSSContainerValuesTest, OverflowingVerticalRlLtr) {
  SetContainerWritingDirection(WritingMode::kVerticalRl, TextDirection::kLtr);
  MediaValues* values = CreateOverflowingValues(
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd),
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingInline(), static_cast<ContainerOverflowingFlags>(
                                             ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingBlock(), static_cast<ContainerOverflowingFlags>(
                                            ContainerOverflowing::kStart));
}

TEST_F(CSSContainerValuesTest, OverflowingVerticalRlRtl) {
  SetContainerWritingDirection(WritingMode::kVerticalRl, TextDirection::kRtl);
  MediaValues* values = CreateOverflowingValues(
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd),
      static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kStart));
  EXPECT_EQ(values->OverflowingInline(),
            static_cast<ContainerOverflowingFlags>(ContainerOverflowing::kEnd));
  EXPECT_EQ(values->OverflowingBlock(), static_cast<ContainerOverflowingFlags>(
                                            ContainerOverflowing::kStart));
}

}  // namespace blink
```