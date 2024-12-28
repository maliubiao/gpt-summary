Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The first step is to recognize that this is a *test file*. Test files in software development are designed to verify the correctness of specific units of code. The filename `static_position_test.cc` strongly suggests it's testing functionality related to "static positions".

2. **Identify the Core Tested Class/Functionality:** Scan the `#include` directives. The presence of `#include "third_party/blink/renderer/core/layout/geometry/static_position.h"` immediately points to the main subject of the tests: the `StaticPosition` class (and potentially related classes like `LogicalStaticPosition` and `PhysicalStaticPosition`).

3. **Recognize the Testing Framework:** The include `#include "testing/gtest/include/gtest/gtest.h"` indicates that the Google Test framework is being used. This is a common C++ testing framework. Knowing this helps understand the structure of the tests (e.g., `TEST_P`, `EXPECT_EQ`).

4. **Analyze the Test Structure:** Look for the `namespace` declarations. The code is within `namespace blink { namespace { ... } }`. This tells us the context of the code. The anonymous namespace `namespace { ... }` is common in C++ to limit the scope of symbols.

5. **Examine the Test Data:** The `ng_static_position_test_data` array is crucial. It's an array of structs. Each struct contains:
    * `LogicalStaticPosition`: Represents a position using "logical" coordinates and edges (inline/block).
    * `PhysicalStaticPosition`: Represents a position using "physical" coordinates and edges (horizontal/vertical).
    * `WritingMode`: Specifies the direction of text flow (e.g., horizontal, vertical).
    * `TextDirection`: Specifies the direction of text within a line (left-to-right or right-to-left).

   This structure strongly suggests the tests are about converting between these two representations of position based on writing mode and text direction. The data itself provides concrete examples of these conversions.

6. **Understand the `StaticPositionTestData` Structure:** This struct clarifies the relationship between logical and physical positions and the factors that influence the conversion.

7. **Analyze the `StaticPositionTest` Class:** This class inherits from `testing::Test` and `testing::WithParamInterface<StaticPositionTestData>`. `WithParamInterface` is a Google Test feature for parameterized testing, meaning the same test logic will be executed with different inputs (the data from `ng_static_position_test_data`).

8. **Dissect the `TEST_P` Function:**  The `TEST_P(StaticPositionTest, Convert)` is the core test function.
    * `GetParam()`:  Retrieves the current `StaticPositionTestData` instance for the current iteration of the parameterized test.
    * `WritingModeConverter`: This suggests a class responsible for performing the conversion. It's initialized with writing mode, text direction, and the size of a reference rectangle.
    * `data.logical.ConvertToPhysical(converter)`:  Performs the logical-to-physical conversion.
    * `EXPECT_EQ(...)`: Asserts that the result of the conversion matches the expected `data.physical` values.
    * `data.physical.ConvertToLogical(converter)`: Performs the physical-to-logical conversion.
    * `EXPECT_EQ(...)`: Asserts that the reverse conversion also yields the expected `data.logical` values.

9. **Infer the Functionality:** Based on the data and the test logic, the core functionality being tested is the correct conversion between logical and physical static positions, taking into account writing mode and text direction.

10. **Relate to Web Technologies (HTML, CSS, JavaScript):**

    * **CSS:**  The `writing-mode` and `direction` CSS properties directly correspond to the `WritingMode` and `TextDirection` enums used in the test. These CSS properties control how text flows on a webpage. The test is essentially verifying that Blink's layout engine correctly interprets these properties when determining the physical position of elements.
    * **HTML:** The structure of HTML elements and their content is what the layout engine works with. The static positioning concepts relate to how elements are initially placed on the page before other positioning schemes (like `position: absolute` or `position: fixed`) are applied.
    * **JavaScript:** While this specific test file doesn't directly interact with JavaScript, JavaScript can manipulate the CSS properties (`writing-mode`, `direction`) that influence the layout. Therefore, the correctness of the underlying layout calculations tested here is crucial for JavaScript's ability to interact with and modify the visual presentation of the page.

11. **Consider Logical Reasoning and Examples:** The test data provides the "if this input (logical position, writing mode, direction), then this output (physical position)" logic. We can use specific examples from the `ng_static_position_test_data` array to illustrate this.

12. **Think about User/Programming Errors:**  The most common error would be misunderstanding how `writing-mode` and `direction` interact to affect the layout. Developers might assume a simple left-to-right or top-to-bottom flow and not account for scenarios like right-to-left languages or vertical text.

By following these steps, we can systematically analyze the C++ test file and derive a comprehensive understanding of its purpose, functionality, and relevance to web technologies. The key is to start with the overall goal (testing), identify the core subject, analyze the structure and data, and then connect it to the broader context.
这个C++文件 `static_position_test.cc` 的主要功能是**测试 `StaticPosition` 相关的类和方法在 Blink 渲染引擎中的正确性**。 更具体地说，它测试了 `LogicalStaticPosition` 和 `PhysicalStaticPosition` 之间互相转换的功能，并验证了在不同书写模式（`WritingMode`）和文本方向（`TextDirection`）下的转换结果是否符合预期。

**与 JavaScript, HTML, CSS 的功能关系：**

这个测试文件直接关系到 CSS 的 `writing-mode` 和 `direction` 属性如何影响网页元素的布局。

* **CSS 的 `writing-mode` 属性：**  该属性定义了文本在块级元素中的排布方向是水平的还是垂直的。测试用例中包含了 `WritingMode::kHorizontalTb` (水平从上到下), `WritingMode::kVerticalRl` (垂直从右到左), `WritingMode::kVerticalLr` (垂直从左到右), 和 `WritingMode::kSidewaysLr` (侧向左到右) 等不同的书写模式。  `static_position_test.cc` 确保了 Blink 引擎在这些不同的书写模式下正确地计算和转换元素的位置。

    **例子 (CSS):**
    ```css
    .vertical-rl {
      writing-mode: vertical-rl;
    }
    ```
    这个 CSS 规则会使得元素内的文本垂直排列，从右向左阅读。`static_position_test.cc` 中的相关测试用例（例如，包含 `WritingMode::kVerticalRl` 的那些）正是为了验证 Blink 引擎如何处理这种情况下的元素定位。

* **CSS 的 `direction` 属性：** 该属性指定了文本的书写方向，可以是 `ltr` (从左到右) 或 `rtl` (从右到左)。测试用例中包含了 `TextDirection::kLtr` 和 `TextDirection::kRtl` 两种情况。`static_position_test.cc` 确保了 Blink 引擎在不同的文本方向下正确地计算和转换元素的位置。

    **例子 (CSS):**
    ```css
    .rtl-text {
      direction: rtl;
    }
    ```
    这个 CSS 规则会使得元素内的文本从右向左排列。`static_position_test.cc` 中包含 `TextDirection::kRtl` 的测试用例会验证 Blink 引擎如何处理这种文本方向对元素定位的影响。

* **HTML (间接关系):**  虽然这个测试文件不直接操作 HTML 元素，但它测试的是布局引擎的核心逻辑，而布局引擎正是根据 HTML 结构和 CSS 样式来渲染网页的。 `StaticPosition` 概念与元素的初始静态位置有关，这在各种布局场景中都是一个基础概念。

* **JavaScript (间接关系):** JavaScript 可以动态地修改元素的 CSS 样式，包括 `writing-mode` 和 `direction`。  `static_position_test.cc` 保证了当 JavaScript 修改这些属性时，Blink 引擎能够正确地重新计算和应用元素的位置。

**逻辑推理和假设输入与输出：**

`static_position_test.cc` 使用了参数化测试 (`testing::WithParamInterface`)，这意味着它使用一组预定义的输入数据来运行相同的测试逻辑。 `ng_static_position_test_data` 数组就是这组输入数据。

每个 `StaticPositionTestData` 结构体包含：

* **`logical` (LogicalStaticPosition):**  表示逻辑上的静态位置，使用 `InlineEdge` (内联边缘，例如 `kInlineStart`, `kInlineEnd`, `kInlineCenter`) 和 `BlockEdge` (块级边缘，例如 `kBlockStart`, `kBlockEnd`, `kBlockCenter`) 来描述位置相对于容器的边缘。
* **`physical` (PhysicalStaticPosition):** 表示物理上的静态位置，使用 `HorizontalEdge` (水平边缘，例如 `kLeft`, `kRight`, `kHorizontalCenter`) 和 `VerticalEdge` (垂直边缘，例如 `kTop`, `kBottom`, `kVerticalCenter`) 以及偏移量来描述位置。
* **`writing_mode` (WritingMode):**  书写模式。
* **`direction` (TextDirection):** 文本方向。

**假设输入与输出示例：**

假设我们取 `ng_static_position_test_data` 数组中的第一个元素：

**输入:**

* `logical`: `{{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart}}`
* `writing_mode`: `WritingMode::kHorizontalTb`
* `direction`: `TextDirection::kLtr`
* `container_size`: `100x100` (在测试代码中硬编码)

**逻辑推理:**

当书写模式是水平从上到下 (`kHorizontalTb`)，文本方向是从左到右 (`kLtr`) 时：

* `InlineEdge::kInlineStart` 对应物理上的左边缘 (`HorizontalEdge::kLeft`)。
* `BlockEdge::kBlockStart` 对应物理上的上边缘 (`VerticalEdge::kTop`).
* 逻辑偏移量 (20, 30) 直接映射到物理偏移量 (20, 30)。

**预期输出:**

* `physical`: `{{PhysicalOffset(20, 30), HorizontalEdge::kLeft, VerticalEdge::kTop}}`

测试代码中的 `TEST_P(StaticPositionTest, Convert)` 函数正是验证了这种转换关系。它会将逻辑位置转换为物理位置，并断言转换结果与预期的物理位置一致，反之亦然。

**用户或编程常见的使用错误举例：**

开发者在使用 CSS 的 `writing-mode` 和 `direction` 属性时，可能会遇到以下常见错误：

1. **混淆 `writing-mode` 和 `direction` 的作用:**  可能会认为只需要设置 `direction` 就能实现垂直排版，而忽略了 `writing-mode` 的作用。例如，期望使用 `direction: rtl` 来使文本垂直排列，但实际上 `direction` 主要影响的是行内元素的排列顺序和文本的阅读方向，而 `writing-mode` 才决定了块级元素的文本流方向。

    **错误示例 (CSS):**
    ```css
    .my-element {
      direction: rtl; /* 期望垂直排列，但实际效果可能不是预期的 */
    }
    ```

2. **忽略 `writing-mode` 对位置的影响:** 在使用绝对定位或固定定位时，开发者可能会忘记 `writing-mode` 会改变元素的坐标轴方向。例如，在垂直书写模式下，元素的 "top" 可能会对应到物理上的右侧或左侧，而不是上侧。

    **错误示例 (CSS & 期望):**
    假设一个元素设置了 `writing-mode: vertical-rl;` 和 `top: 10px;`。 开发者可能期望元素距离容器顶部 10px，但实际上，由于是垂直从右到左的书写模式，`top` 可能会对应到元素距离容器右侧 10px 的位置。

3. **在 JavaScript 中错误地计算位置:**  当需要使用 JavaScript 来获取或设置元素的位置时，开发者如果没有考虑到 `writing-mode` 和 `direction` 的影响，可能会得到错误的结果。 例如，使用 `element.offsetLeft` 和 `element.offsetTop` 在不同的书写模式下可能需要不同的理解和处理。

4. **不理解逻辑属性和物理属性的映射关系:** 开发者可能不清楚 `inline-start` 和 `block-start` 等逻辑属性在不同的 `writing-mode` 和 `direction` 下会映射到哪个物理方向（`top`, `bottom`, `left`, `right`）。 `static_position_test.cc` 正是为了确保这种映射关系的正确性。

总而言之，`static_position_test.cc` 是 Blink 引擎中一个重要的测试文件，它专注于验证在不同文本排布和方向设置下，元素静态位置计算的正确性，这直接关系到网页的布局和渲染是否符合预期。

Prompt: 
```
这是目录为blink/renderer/core/layout/geometry/static_position_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/geometry/static_position.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {
namespace {

using InlineEdge = LogicalStaticPosition::InlineEdge;
using BlockEdge = LogicalStaticPosition::BlockEdge;
using HorizontalEdge = PhysicalStaticPosition::HorizontalEdge;
using VerticalEdge = PhysicalStaticPosition::VerticalEdge;

struct StaticPositionTestData {
  LogicalStaticPosition logical;
  PhysicalStaticPosition physical;
  WritingMode writing_mode;
  TextDirection direction;

} ng_static_position_test_data[] = {
    // |WritingMode::kHorizontalTb|, |TextDirection::kLtr|
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart},
     {PhysicalOffset(20, 30), HorizontalEdge::kLeft, VerticalEdge::kTop},
     WritingMode::kHorizontalTb,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockStart},
     {PhysicalOffset(20, 30), HorizontalEdge::kRight, VerticalEdge::kTop},
     WritingMode::kHorizontalTb,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockEnd},
     {PhysicalOffset(20, 30), HorizontalEdge::kLeft, VerticalEdge::kBottom},
     WritingMode::kHorizontalTb,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockEnd},
     {PhysicalOffset(20, 30), HorizontalEdge::kRight, VerticalEdge::kBottom},
     WritingMode::kHorizontalTb,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineCenter, BlockEdge::kBlockStart},
     {PhysicalOffset(20, 30), HorizontalEdge::kHorizontalCenter,
      VerticalEdge::kTop},
     WritingMode::kHorizontalTb,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockCenter},
     {PhysicalOffset(20, 30), HorizontalEdge::kLeft,
      VerticalEdge::kVerticalCenter},
     WritingMode::kHorizontalTb,
     TextDirection::kLtr},
    // |WritingMode::kHorizontalTb|, |TextDirection::kRtl|
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart},
     {PhysicalOffset(80, 30), HorizontalEdge::kRight, VerticalEdge::kTop},
     WritingMode::kHorizontalTb,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockStart},
     {PhysicalOffset(80, 30), HorizontalEdge::kLeft, VerticalEdge::kTop},
     WritingMode::kHorizontalTb,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockEnd},
     {PhysicalOffset(80, 30), HorizontalEdge::kRight, VerticalEdge::kBottom},
     WritingMode::kHorizontalTb,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockEnd},
     {PhysicalOffset(80, 30), HorizontalEdge::kLeft, VerticalEdge::kBottom},
     WritingMode::kHorizontalTb,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineCenter, BlockEdge::kBlockStart},
     {PhysicalOffset(80, 30), HorizontalEdge::kHorizontalCenter,
      VerticalEdge::kTop},
     WritingMode::kHorizontalTb,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockCenter},
     {PhysicalOffset(80, 30), HorizontalEdge::kRight,
      VerticalEdge::kVerticalCenter},
     WritingMode::kHorizontalTb,
     TextDirection::kRtl},
    // |WritingMode::kVerticalRl|, |TextDirection::kLtr|
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart},
     {PhysicalOffset(70, 20), HorizontalEdge::kRight, VerticalEdge::kTop},
     WritingMode::kVerticalRl,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockStart},
     {PhysicalOffset(70, 20), HorizontalEdge::kRight, VerticalEdge::kBottom},
     WritingMode::kVerticalRl,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockEnd},
     {PhysicalOffset(70, 20), HorizontalEdge::kLeft, VerticalEdge::kTop},
     WritingMode::kVerticalRl,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockEnd},
     {PhysicalOffset(70, 20), HorizontalEdge::kLeft, VerticalEdge::kBottom},
     WritingMode::kVerticalRl,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineCenter, BlockEdge::kBlockStart},
     {PhysicalOffset(70, 20), HorizontalEdge::kRight,
      VerticalEdge::kVerticalCenter},
     WritingMode::kVerticalRl,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockCenter},
     {PhysicalOffset(70, 20), HorizontalEdge::kHorizontalCenter,
      VerticalEdge::kTop},
     WritingMode::kVerticalRl,
     TextDirection::kLtr},
    // |WritingMode::kVerticalRl|, |TextDirection::kRtl|
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart},
     {PhysicalOffset(70, 80), HorizontalEdge::kRight, VerticalEdge::kBottom},
     WritingMode::kVerticalRl,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockStart},
     {PhysicalOffset(70, 80), HorizontalEdge::kRight, VerticalEdge::kTop},
     WritingMode::kVerticalRl,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockEnd},
     {PhysicalOffset(70, 80), HorizontalEdge::kLeft, VerticalEdge::kBottom},
     WritingMode::kVerticalRl,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockEnd},
     {PhysicalOffset(70, 80), HorizontalEdge::kLeft, VerticalEdge::kTop},
     WritingMode::kVerticalRl,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineCenter, BlockEdge::kBlockStart},
     {PhysicalOffset(70, 80), HorizontalEdge::kRight,
      VerticalEdge::kVerticalCenter},
     WritingMode::kVerticalRl,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockCenter},
     {PhysicalOffset(70, 80), HorizontalEdge::kHorizontalCenter,
      VerticalEdge::kBottom},
     WritingMode::kVerticalRl,
     TextDirection::kRtl},
    // |WritingMode::kVerticalLr|, |TextDirection::kLtr|
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 20), HorizontalEdge::kLeft, VerticalEdge::kTop},
     WritingMode::kVerticalLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 20), HorizontalEdge::kLeft, VerticalEdge::kBottom},
     WritingMode::kVerticalLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockEnd},
     {PhysicalOffset(30, 20), HorizontalEdge::kRight, VerticalEdge::kTop},
     WritingMode::kVerticalLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockEnd},
     {PhysicalOffset(30, 20), HorizontalEdge::kRight, VerticalEdge::kBottom},
     WritingMode::kVerticalLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineCenter, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 20), HorizontalEdge::kLeft,
      VerticalEdge::kVerticalCenter},
     WritingMode::kVerticalLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockCenter},
     {PhysicalOffset(30, 20), HorizontalEdge::kHorizontalCenter,
      VerticalEdge::kTop},
     WritingMode::kVerticalLr,
     TextDirection::kLtr},
    // |WritingMode::kVerticalLr|, |TextDirection::kRtl|
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 80), HorizontalEdge::kLeft, VerticalEdge::kBottom},
     WritingMode::kVerticalLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 80), HorizontalEdge::kLeft, VerticalEdge::kTop},
     WritingMode::kVerticalLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockEnd},
     {PhysicalOffset(30, 80), HorizontalEdge::kRight, VerticalEdge::kBottom},
     WritingMode::kVerticalLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockEnd},
     {PhysicalOffset(30, 80), HorizontalEdge::kRight, VerticalEdge::kTop},
     WritingMode::kVerticalLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineCenter, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 80), HorizontalEdge::kLeft,
      VerticalEdge::kVerticalCenter},
     WritingMode::kVerticalLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockCenter},
     {PhysicalOffset(30, 80), HorizontalEdge::kHorizontalCenter,
      VerticalEdge::kBottom},
     WritingMode::kVerticalLr,
     TextDirection::kRtl},
    // |WritingMode::kSidewaysLr|, |TextDirection::kLtr|
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 80), HorizontalEdge::kLeft, VerticalEdge::kBottom},
     WritingMode::kSidewaysLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 80), HorizontalEdge::kLeft, VerticalEdge::kTop},
     WritingMode::kSidewaysLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockEnd},
     {PhysicalOffset(30, 80), HorizontalEdge::kRight, VerticalEdge::kBottom},
     WritingMode::kSidewaysLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockEnd},
     {PhysicalOffset(30, 80), HorizontalEdge::kRight, VerticalEdge::kTop},
     WritingMode::kSidewaysLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineCenter, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 80), HorizontalEdge::kLeft,
      VerticalEdge::kVerticalCenter},
     WritingMode::kSidewaysLr,
     TextDirection::kLtr},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockCenter},
     {PhysicalOffset(30, 80), HorizontalEdge::kHorizontalCenter,
      VerticalEdge::kBottom},
     WritingMode::kSidewaysLr,
     TextDirection::kLtr},
    // |WritingMode::kSidewaysLr|, |TextDirection::kRtl|
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 20), HorizontalEdge::kLeft, VerticalEdge::kTop},
     WritingMode::kSidewaysLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 20), HorizontalEdge::kLeft, VerticalEdge::kBottom},
     WritingMode::kSidewaysLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockEnd},
     {PhysicalOffset(30, 20), HorizontalEdge::kRight, VerticalEdge::kTop},
     WritingMode::kSidewaysLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineEnd, BlockEdge::kBlockEnd},
     {PhysicalOffset(30, 20), HorizontalEdge::kRight, VerticalEdge::kBottom},
     WritingMode::kSidewaysLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineCenter, BlockEdge::kBlockStart},
     {PhysicalOffset(30, 20), HorizontalEdge::kLeft,
      VerticalEdge::kVerticalCenter},
     WritingMode::kSidewaysLr,
     TextDirection::kRtl},
    {{LogicalOffset(20, 30), InlineEdge::kInlineStart, BlockEdge::kBlockCenter},
     {PhysicalOffset(30, 20), HorizontalEdge::kHorizontalCenter,
      VerticalEdge::kTop},
     WritingMode::kSidewaysLr,
     TextDirection::kRtl},
};

class StaticPositionTest
    : public testing::Test,
      public testing::WithParamInterface<StaticPositionTestData> {};

TEST_P(StaticPositionTest, Convert) {
  const auto& data = GetParam();

  // These tests take the logical static-position, and convert it to a physical
  // static-position with a 100x100 rect.
  //
  // It asserts that it is the same as the expected physical static-position,
  // then performs the same operation in reverse.

  const WritingModeConverter converter({data.writing_mode, data.direction},
                                       PhysicalSize(100, 100));
  PhysicalStaticPosition physical_result =
      data.logical.ConvertToPhysical(converter);
  EXPECT_EQ(physical_result.offset, data.physical.offset);
  EXPECT_EQ(physical_result.horizontal_edge, data.physical.horizontal_edge);
  EXPECT_EQ(physical_result.vertical_edge, data.physical.vertical_edge);

  LogicalStaticPosition logical_result =
      data.physical.ConvertToLogical(converter);
  EXPECT_EQ(logical_result.offset, data.logical.offset);
  EXPECT_EQ(logical_result.inline_edge, data.logical.inline_edge);
  EXPECT_EQ(logical_result.block_edge, data.logical.block_edge);
}

INSTANTIATE_TEST_SUITE_P(StaticPositionTest,
                         StaticPositionTest,
                         testing::ValuesIn(ng_static_position_test_data));

}  // namespace
}  // namespace blink

"""

```