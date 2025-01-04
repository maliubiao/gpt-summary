Response:
Let's break down the thought process for analyzing the given C++ test file.

**1. Understanding the Goal:**

The initial request is to understand the purpose of the `writing_mode_utils_test.cc` file within the Chromium Blink rendering engine. Specifically, I need to identify its functionality, its relationship to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning with inputs/outputs, and highlight potential user/programming errors.

**2. Initial Code Scan and Keywords:**

I'll quickly scan the code for relevant keywords and structures:

* **`#include`:**  This immediately tells me it's C++ code and includes headers for testing (`gtest`) and the code being tested (`writing_mode_utils.h`).
* **`namespace blink`:** This confirms it's part of the Blink rendering engine.
* **`TEST(WritingModeUtilsTest, ...)`:**  These are Google Test test cases. This is a strong indication that the file's purpose is to test the functionality of something related to `WritingModeUtils`.
* **`PhysicalToLogical` and `LogicalToPhysical`:** These are the core concepts being tested. They suggest a conversion between physical (top, right, bottom, left) and logical (inline-start, inline-end, block-start, block-end) dimensions.
* **`WritingMode::kHorizontalTb`, `WritingMode::kVerticalLr`, `WritingMode::kSidewaysRl`:** These enums clearly relate to different text writing modes (horizontal top-to-bottom, vertical left-to-right, sideways right-to-left).
* **`TextDirection::kLtr`, `TextDirection::kRtl`:**  These enums represent left-to-right and right-to-left text directions.
* **`EXPECT_EQ(...)`:** This is a Google Test assertion, indicating that the tests are verifying expected outputs.

**3. Deeper Analysis of Test Cases:**

Now, I'll examine the individual test cases to understand the specific scenarios being tested:

* **`PhysicalToLogicalHorizontalLtr` and similar:** These tests take physical values (kTop, kRight, kBottom, kLeft) and convert them to logical values based on the writing mode and text direction. I notice a pattern:
    * Horizontal LTR: Left maps to InlineStart, Right to InlineEnd, Top to BlockStart, Bottom to BlockEnd.
    * Horizontal RTL: Right maps to InlineStart, Left to InlineEnd, Top to BlockStart, Bottom to BlockEnd.
    * Vertical LTR/RTL/RLT/RLR: The mappings change, involving swaps between horizontal and vertical physical/logical properties.

* **`LogicalToPhysicalHorizontalLtr` and similar:** These tests perform the reverse conversion – from logical to physical values. The patterns observed in the `PhysicalToLogical` tests are mirrored here.

* **`PhysicalToLogicalGetter` and `LogicalToPhysicalSetter`:** These tests introduce a `PhysicalValues` class and test the `PhysicalToLogicalGetter` and `LogicalToPhysicalSetter` templates. This suggests these templates provide a way to access and modify physical values based on logical concepts.

* **`LogicalToPhysicalGetter` (with `LogicalValues`):** Similar to the previous getter test, but this time operating on a `LogicalValues` class.

**4. Connecting to Web Technologies (HTML, CSS, JavaScript):**

Based on the understanding of writing modes and text direction, I can connect this to web technologies:

* **CSS:** The `writing-mode` and `direction` CSS properties directly influence how text is laid out. `writing-mode` controls whether text flows horizontally or vertically, and `direction` handles left-to-right or right-to-left flow. The tests directly correspond to the different combinations of these properties.
* **HTML:**  HTML elements are styled using CSS. The `dir` attribute can also influence text direction.
* **JavaScript:** JavaScript can manipulate the CSS styles of elements, including `writing-mode` and `direction`. This allows for dynamic changes to text layout.

**5. Logical Reasoning Examples (Input/Output):**

I'll pick a few test cases and explicitly state the input and expected output:

* **`PhysicalToLogicalHorizontalRtl`:**
    * Input: `WritingMode::kHorizontalTb`, `TextDirection::kRtl`, kTop, kRight, kBottom, kLeft.
    * Expected Output: InlineStart = kRight, InlineEnd = kLeft, BlockStart = kTop, BlockEnd = kBottom.

* **`LogicalToPhysicalVlrLtr`:**
    * Input: `WritingMode::kVerticalLr`, `TextDirection::kLtr`, kInlineStart, kInlineEnd, kBlockStart, kBlockEnd.
    * Expected Output: Left = kBlockStart, Right = kBlockEnd, Top = kInlineStart, Bottom = kInlineEnd.

**6. Identifying Potential Errors:**

I'll think about common mistakes developers might make when dealing with writing modes and directions:

* **Incorrectly assuming LTR:**  Developers might hardcode styles or logic assuming left-to-right flow, neglecting the need for right-to-left support.
* **Misunderstanding logical vs. physical properties:**  Forgetting that `left` and `right` don't always correspond to the visual left and right edges in vertical or RTL layouts can lead to errors.
* **Forgetting to update both logical and physical properties:** When manipulating layout, developers need to ensure they're correctly updating both logical (inline/block) and physical (top/left/bottom/right) properties when necessary.

**7. Structuring the Answer:**

Finally, I'll organize the information into the requested categories: functionality, relation to web technologies, logical reasoning examples, and common errors. I'll use clear and concise language and provide specific code examples where relevant. I'll make sure to explain the purpose of the test file within the larger context of the Blink rendering engine.
This C++ file, `writing_mode_utils_test.cc`, located within the Chromium Blink engine, is a **unit test file**. Its primary function is to **test the correctness and functionality of the `writing_mode_utils.h` header file**. This header file likely contains utility functions and classes for handling different writing modes and text directions in web page rendering.

Let's break down its functionalities and connections to web technologies:

**Functionality of `writing_mode_utils_test.cc`:**

The file uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`) to define various test cases. These test cases focus on verifying the behavior of two key concepts related to writing modes:

1. **`PhysicalToLogical` conversion:** This likely involves converting physical dimensions (top, right, bottom, left) to logical dimensions (inline-start, inline-end, block-start, block-end) based on the current writing mode and text direction.

2. **`LogicalToPhysical` conversion:** This is the reverse of the above, converting logical dimensions back to physical dimensions.

3. **Getter and Setter implementations:** The tests also examine how to access and modify physical and logical values using getter and setter classes (`PhysicalToLogicalGetter`, `LogicalToPhysicalSetter`, `LogicalToPhysicalGetter`).

**Relationship to JavaScript, HTML, and CSS:**

This C++ code directly relates to how web pages are rendered, and thus has connections to HTML, CSS, and indirectly to JavaScript:

* **CSS `writing-mode` property:**  The `writing-mode` CSS property (e.g., `horizontal-tb`, `vertical-lr`, `vertical-rl`, `sideways-lr`, `sideways-rl`) directly influences the layout of text. The test cases in this file directly correspond to different values of this property. For example:
    * `WritingMode::kHorizontalTb` corresponds to `writing-mode: horizontal-tb;`
    * `WritingMode::kVerticalLr` corresponds to `writing-mode: vertical-lr;`

* **CSS `direction` property:** The `direction` CSS property (e.g., `ltr`, `rtl`) determines the direction of inline text flow. The test cases consider both `TextDirection::kLtr` (left-to-right) and `TextDirection::kRtl` (right-to-left).

* **HTML `dir` attribute:** The `dir` attribute on HTML elements can also influence text direction.

* **JavaScript:** JavaScript can dynamically manipulate the `writing-mode` and `direction` CSS properties of HTML elements, leading to changes in text layout that these utility functions handle.

**Examples with JavaScript, HTML, and CSS:**

1. **CSS and `PhysicalToLogical`:**
   ```html
   <div style="writing-mode: vertical-rl; direction: rtl; position: absolute; top: 10px; right: 20px; bottom: 30px; left: 40px;">
     Text
   </div>
   ```
   In the rendering engine, when processing this CSS, the `PhysicalToLogical` converter would take the physical values (top=10, right=20, bottom=30, left=40) and the writing mode (`kVerticalRl`) and direction (`kRtl`) to determine the logical positions:
   * `InlineStart` would correspond to `bottom` (30).
   * `InlineEnd` would correspond to `top` (10).
   * `BlockStart` would correspond to `right` (20).
   * `BlockEnd` would correspond to `left` (40).

2. **CSS and `LogicalToPhysical`:**
   ```css
   .vertical-lr {
     writing-mode: vertical-lr;
   }
   .rtl {
     direction: rtl;
   }
   ```
   When laying out an element with `class="vertical-lr rtl"`, the rendering engine might have determined the logical positioning (e.g., `InlineStart: 100px`, `InlineEnd: 200px`, `BlockStart: 50px`, `BlockEnd: 150px`). The `LogicalToPhysical` converter would then use the `WritingMode::kVerticalLr` and `TextDirection::kRtl` to calculate the physical positions:
   * `Left` would correspond to `BlockStart` (50).
   * `Right` would correspond to `BlockEnd` (150).
   * `Top` would correspond to `InlineEnd` (200).
   * `Bottom` would correspond to `InlineStart` (100).

3. **JavaScript manipulation:**
   ```javascript
   const element = document.getElementById('myElement');
   element.style.writingMode = 'vertical-lr';
   element.style.direction = 'rtl';
   // ... later, the rendering engine uses the utility functions to layout 'myElement'
   ```
   When JavaScript changes the writing mode and direction, the underlying rendering engine relies on functions like those tested in `writing_mode_utils_test.cc` to correctly interpret these changes and position the content.

**Logical Reasoning Examples (Hypothetical Input & Output):**

Let's consider the `PhysicalToLogicalHorizontalRtl` test case:

* **Hypothetical Input:**
    * `WritingMode`: `kHorizontalTb` (horizontal top-to-bottom)
    * `TextDirection`: `kRtl` (right-to-left)
    * `physical_top`: 10
    * `physical_right`: 20
    * `physical_bottom`: 30
    * `physical_left`: 40

* **Logical Reasoning:**
    * In horizontal top-to-bottom writing mode with right-to-left direction:
        * The inline direction goes from right to left. Therefore, the physical `right` corresponds to the logical `InlineStart`, and the physical `left` corresponds to the logical `InlineEnd`.
        * The block direction goes from top to bottom. Therefore, the physical `top` corresponds to the logical `BlockStart`, and the physical `bottom` corresponds to the logical `BlockEnd`.

* **Expected Output:**
    * `logical_inline_start`: 20 (from `physical_right`)
    * `logical_inline_end`: 40 (from `physical_left`)
    * `logical_block_start`: 10 (from `physical_top`)
    * `logical_block_end`: 30 (from `physical_bottom`)

Similarly, for the `LogicalToPhysicalVlrLtr` test:

* **Hypothetical Input:**
    * `WritingMode`: `kVerticalLr` (vertical left-to-right)
    * `TextDirection`: `kLtr` (left-to-right)
    * `logical_inline_start`: 100
    * `logical_inline_end`: 200
    * `logical_block_start`: 50
    * `logical_block_end`: 150

* **Logical Reasoning:**
    * In vertical left-to-right writing mode with left-to-right direction:
        * The inline direction goes from top to bottom. Therefore, the logical `InlineStart` corresponds to the physical `Top`, and the logical `InlineEnd` corresponds to the physical `Bottom`.
        * The block direction goes from left to right. Therefore, the logical `BlockStart` corresponds to the physical `Left`, and the logical `BlockEnd` corresponds to the physical `Right`.

* **Expected Output:**
    * `physical_top`: 100 (from `logical_inline_start`)
    * `physical_right`: 150 (from `logical_block_end`)
    * `physical_bottom`: 200 (from `logical_inline_end`)
    * `physical_left`: 50 (from `logical_block_start`)

**User or Programming Common Usage Errors:**

1. **Assuming left-to-right always:** A common error is to hardcode layout logic assuming text always flows from left to right. This will break when dealing with right-to-left languages or vertical writing modes. Developers might incorrectly use physical `left` and `right` properties without considering the current writing mode and direction.

   * **Example:**  A developer might calculate the position of an element to the right of another by simply adding to the `left` property. This will not work correctly in RTL layouts where "to the right" actually means decreasing the `left` value or increasing the `right` value.

2. **Mixing logical and physical properties incorrectly:**  Developers might get confused about when to use logical properties (inline-start, block-start) and when to use physical properties (top, left). Using the wrong set of properties can lead to incorrect layout.

   * **Example:** When trying to position something at the beginning of a line of text, they might incorrectly use `left: 0` even in a vertical writing mode where the starting position is determined by the `top` property.

3. **Forgetting to update both logical and physical properties when needed:**  Sometimes, when manipulating layout, developers need to update both the logical and physical properties to achieve the desired effect, especially when transitions or animations are involved. Failing to update both can lead to inconsistencies.

   * **Example:** When animating the movement of an element in a vertical writing mode, the developer might only update the `top` and `bottom` properties, forgetting to adjust the `left` or `right` if the inline progression is also involved.

4. **Not considering the impact of `writing-mode` and `direction` together:** The behavior is a combination of both properties. Developers might test their layout with only one or two combinations and assume it works for all, neglecting edge cases.

   * **Example:**  Testing a component only in `writing-mode: horizontal-tb; direction: ltr;` and assuming it will work flawlessly in `writing-mode: vertical-rl; direction: rtl;` without specific adjustments.

In summary, `writing_mode_utils_test.cc` plays a crucial role in ensuring the Chromium rendering engine correctly handles the complexities of different writing modes and text directions, which are fundamental for supporting internationalization and diverse layout options on the web. The tests verify the core logic that translates between physical and logical dimensions based on these properties.

Prompt: 
```
这是目录为blink/renderer/platform/text/writing_mode_utils_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/text/writing_mode_utils.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"

namespace blink {

namespace {

enum { kTop, kRight, kBottom, kLeft };

TEST(WritingModeUtilsTest, PhysicalToLogicalHorizontalLtr) {
  PhysicalToLogical<int> converter(
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, kTop, kRight, kBottom,
      kLeft);
  EXPECT_EQ(kLeft, converter.InlineStart());
  EXPECT_EQ(kRight, converter.InlineEnd());
  EXPECT_EQ(kTop, converter.BlockStart());
  EXPECT_EQ(kBottom, converter.BlockEnd());
}

TEST(WritingModeUtilsTest, PhysicalToLogicalHorizontalRtl) {
  PhysicalToLogical<int> converter(
      {WritingMode::kHorizontalTb, TextDirection::kRtl}, kTop, kRight, kBottom,
      kLeft);
  EXPECT_EQ(kRight, converter.InlineStart());
  EXPECT_EQ(kLeft, converter.InlineEnd());
  EXPECT_EQ(kTop, converter.BlockStart());
  EXPECT_EQ(kBottom, converter.BlockEnd());
}

TEST(WritingModeUtilsTest, PhysicalToLogicalVlrLtr) {
  PhysicalToLogical<int> converter(
      {WritingMode::kVerticalLr, TextDirection::kLtr}, kTop, kRight, kBottom,
      kLeft);
  EXPECT_EQ(kTop, converter.InlineStart());
  EXPECT_EQ(kBottom, converter.InlineEnd());
  EXPECT_EQ(kLeft, converter.BlockStart());
  EXPECT_EQ(kRight, converter.BlockEnd());
}

TEST(WritingModeUtilsTest, PhysicalToLogicalVlrRtl) {
  PhysicalToLogical<int> converter(
      {WritingMode::kVerticalLr, TextDirection::kRtl}, kTop, kRight, kBottom,
      kLeft);
  EXPECT_EQ(kBottom, converter.InlineStart());
  EXPECT_EQ(kTop, converter.InlineEnd());
  EXPECT_EQ(kLeft, converter.BlockStart());
  EXPECT_EQ(kRight, converter.BlockEnd());
}

TEST(WritingModeUtilsTest, PhysicalToLogicalVrlLtr) {
  PhysicalToLogical<int> converter(
      {WritingMode::kVerticalRl, TextDirection::kLtr}, kTop, kRight, kBottom,
      kLeft);
  EXPECT_EQ(kTop, converter.InlineStart());
  EXPECT_EQ(kBottom, converter.InlineEnd());
  EXPECT_EQ(kRight, converter.BlockStart());
  EXPECT_EQ(kLeft, converter.BlockEnd());
}

TEST(WritingModeUtilsTest, PhysicalToLogicalVrlRtl) {
  PhysicalToLogical<int> converter(
      {WritingMode::kVerticalRl, TextDirection::kRtl}, kTop, kRight, kBottom,
      kLeft);
  EXPECT_EQ(kBottom, converter.InlineStart());
  EXPECT_EQ(kTop, converter.InlineEnd());
  EXPECT_EQ(kRight, converter.BlockStart());
  EXPECT_EQ(kLeft, converter.BlockEnd());
}

enum { kInlineStart = 1000, kInlineEnd, kBlockStart, kBlockEnd };

TEST(WritingModeUtilsTest, LogicalToPhysicalHorizontalLtr) {
  LogicalToPhysical<int> converter(
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, kInlineStart,
      kInlineEnd, kBlockStart, kBlockEnd);
  EXPECT_EQ(kInlineStart, converter.Left());
  EXPECT_EQ(kInlineEnd, converter.Right());
  EXPECT_EQ(kBlockStart, converter.Top());
  EXPECT_EQ(kBlockEnd, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalHorizontalRtl) {
  LogicalToPhysical<int> converter(
      {WritingMode::kHorizontalTb, TextDirection::kRtl}, kInlineStart,
      kInlineEnd, kBlockStart, kBlockEnd);
  EXPECT_EQ(kInlineEnd, converter.Left());
  EXPECT_EQ(kInlineStart, converter.Right());
  EXPECT_EQ(kBlockStart, converter.Top());
  EXPECT_EQ(kBlockEnd, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalVlrLtr) {
  LogicalToPhysical<int> converter(
      {WritingMode::kVerticalLr, TextDirection::kLtr}, kInlineStart, kInlineEnd,
      kBlockStart, kBlockEnd);
  EXPECT_EQ(kBlockStart, converter.Left());
  EXPECT_EQ(kBlockEnd, converter.Right());
  EXPECT_EQ(kInlineStart, converter.Top());
  EXPECT_EQ(kInlineEnd, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalVlrRtl) {
  LogicalToPhysical<int> converter(
      {WritingMode::kVerticalLr, TextDirection::kRtl}, kInlineStart, kInlineEnd,
      kBlockStart, kBlockEnd);
  EXPECT_EQ(kBlockStart, converter.Left());
  EXPECT_EQ(kBlockEnd, converter.Right());
  EXPECT_EQ(kInlineEnd, converter.Top());
  EXPECT_EQ(kInlineStart, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalVrlLtr) {
  LogicalToPhysical<int> converter(
      {WritingMode::kVerticalRl, TextDirection::kLtr}, kInlineStart, kInlineEnd,
      kBlockStart, kBlockEnd);
  EXPECT_EQ(kBlockEnd, converter.Left());
  EXPECT_EQ(kBlockStart, converter.Right());
  EXPECT_EQ(kInlineStart, converter.Top());
  EXPECT_EQ(kInlineEnd, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalVrlRtl) {
  LogicalToPhysical<int> converter(
      {WritingMode::kVerticalRl, TextDirection::kRtl}, kInlineStart, kInlineEnd,
      kBlockStart, kBlockEnd);
  EXPECT_EQ(kBlockEnd, converter.Left());
  EXPECT_EQ(kBlockStart, converter.Right());
  EXPECT_EQ(kInlineEnd, converter.Top());
  EXPECT_EQ(kInlineStart, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalSlrLtr) {
  LogicalToPhysical<int> converter(
      {WritingMode::kSidewaysLr, TextDirection::kLtr}, kInlineStart, kInlineEnd,
      kBlockStart, kBlockEnd);
  EXPECT_EQ(kBlockStart, converter.Left());
  EXPECT_EQ(kBlockEnd, converter.Right());
  EXPECT_EQ(kInlineEnd, converter.Top());
  EXPECT_EQ(kInlineStart, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalSlrRtl) {
  LogicalToPhysical<int> converter(
      {WritingMode::kSidewaysLr, TextDirection::kRtl}, kInlineStart, kInlineEnd,
      kBlockStart, kBlockEnd);
  EXPECT_EQ(kBlockStart, converter.Left());
  EXPECT_EQ(kBlockEnd, converter.Right());
  EXPECT_EQ(kInlineStart, converter.Top());
  EXPECT_EQ(kInlineEnd, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalSrlLtr) {
  LogicalToPhysical<int> converter(
      {WritingMode::kSidewaysRl, TextDirection::kLtr}, kInlineStart, kInlineEnd,
      kBlockStart, kBlockEnd);
  EXPECT_EQ(kBlockEnd, converter.Left());
  EXPECT_EQ(kBlockStart, converter.Right());
  EXPECT_EQ(kInlineStart, converter.Top());
  EXPECT_EQ(kInlineEnd, converter.Bottom());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalSrlRtl) {
  LogicalToPhysical<int> converter(
      {WritingMode::kSidewaysRl, TextDirection::kRtl}, kInlineStart, kInlineEnd,
      kBlockStart, kBlockEnd);
  EXPECT_EQ(kBlockEnd, converter.Left());
  EXPECT_EQ(kBlockStart, converter.Right());
  EXPECT_EQ(kInlineEnd, converter.Top());
  EXPECT_EQ(kInlineStart, converter.Bottom());
}

class PhysicalValues {
  STACK_ALLOCATED();

 public:
  int Top() const { return top_; }
  int Right() const { return right_; }
  int Bottom() const { return bottom_; }
  int Left() const { return left_; }
  void SetTop(int top) { top_ = top; }
  void SetRight(int right) { right_ = right; }
  void SetBottom(int bottom) { bottom_ = bottom; }
  void SetLeft(int left) { left_ = left; }

 private:
  int top_ = kTop;
  int right_ = kRight;
  int bottom_ = kBottom;
  int left_ = kLeft;
};

TEST(WritingModeUtilsTest, PhysicalToLogicalGetter) {
  PhysicalValues physical_values;
  PhysicalToLogicalGetter<int, PhysicalValues> getter(
      {WritingMode::kVerticalRl, TextDirection::kRtl}, physical_values,
      &PhysicalValues::Top, &PhysicalValues::Right, &PhysicalValues::Bottom,
      &PhysicalValues::Left);

  EXPECT_EQ(kBottom, getter.InlineStart());
  EXPECT_EQ(kTop, getter.InlineEnd());
  EXPECT_EQ(kRight, getter.BlockStart());
  EXPECT_EQ(kLeft, getter.BlockEnd());
}

TEST(WritingModeUtilsTest, LogicalToPhysicalSetter) {
  PhysicalValues physical_values;
  LogicalToPhysicalSetter<int, PhysicalValues> setter(
      {WritingMode::kVerticalRl, TextDirection::kRtl}, physical_values,
      &PhysicalValues::SetTop, &PhysicalValues::SetRight,
      &PhysicalValues::SetBottom, &PhysicalValues::SetLeft);
  setter.SetInlineStart(kInlineStart);
  setter.SetInlineEnd(kInlineEnd);
  setter.SetBlockStart(kBlockStart);
  setter.SetBlockEnd(kBlockEnd);

  EXPECT_EQ(kBlockEnd, physical_values.Left());
  EXPECT_EQ(kBlockStart, physical_values.Right());
  EXPECT_EQ(kInlineEnd, physical_values.Top());
  EXPECT_EQ(kInlineStart, physical_values.Bottom());
}

class LogicalValues {
  STACK_ALLOCATED();

 public:
  int InlineStart() const { return inline_start_; }
  int InlineEnd() const { return inline_end_; }
  int BlockStart() const { return block_start_; }
  int BlockEnd() const { return block_end_; }
  void SetInlineStart(int inline_start) { inline_start_ = inline_start; }
  void SetInlineEnd(int inline_end) { inline_end_ = inline_end; }
  void SetBlockStart(int block_start) { block_start_ = block_start; }
  void SetBlockEnd(int block_end) { block_end_ = block_end; }

 private:
  int inline_start_ = kInlineStart;
  int inline_end_ = kInlineEnd;
  int block_start_ = kBlockStart;
  int block_end_ = kBlockEnd;
};

TEST(WritingModeUtilsTest, LogicalToPhysicalGetter) {
  LogicalValues logical_values;
  LogicalToPhysicalGetter<int, LogicalValues> getter(
      {WritingMode::kVerticalRl, TextDirection::kRtl}, logical_values,
      &LogicalValues::InlineStart, &LogicalValues::InlineEnd,
      &LogicalValues::BlockStart, &LogicalValues::BlockEnd);

  EXPECT_EQ(kBlockEnd, getter.Left());
  EXPECT_EQ(kBlockStart, getter.Right());
  EXPECT_EQ(kInlineEnd, getter.Top());
  EXPECT_EQ(kInlineStart, getter.Bottom());
}

}  // namespace

}  // namespace blink

"""

```