Response:
The user wants to understand the functionality of the `line_relative_rect_test.cc` file in the Chromium Blink engine. This file contains unit tests for the `LineRelativeRect` class.

Here's a breakdown of how to address each part of the request:

1. **Functionality:** Describe the purpose of the test file and the `LineRelativeRect` class itself. The tests cover various operations on `LineRelativeRect` objects.

2. **Relationship to JavaScript/HTML/CSS:**  Explain how `LineRelativeRect` is related to the rendering process driven by these web technologies. Focus on how it represents the dimensions and position of elements during layout and paint. Provide concrete examples.

3. **Logical Reasoning (Hypothetical Input/Output):**  Select specific test cases and demonstrate the input (`LineRelativeRect` or `PhysicalRect` data) and expected output (`LineRelativeRect` or `AffineTransform` data).

4. **Common Usage Errors:**  Identify potential mistakes developers might make when using or reasoning about `LineRelativeRect`, especially concerning coordinate systems and transformations.

5. **User Operation to Reach the Code:**  Describe the sequence of user actions that could trigger the code related to `LineRelativeRect`, focusing on text selection as a key use case for highlighting.

**Mental Sandbox Simulation:**

* **Functionality:** I'll state that it tests `LineRelativeRect`. I need to explain *what* `LineRelativeRect` does. It represents a rectangle relative to a line of text, taking into account writing modes.

* **JavaScript/HTML/CSS Connection:** Think about how a user selecting text in a web page would lead to the need for such a representation. The browser needs to calculate the bounding box of the selection. How does writing mode affect this?  For vertical text, the box will be oriented differently. I can use text selection highlighting as an example.

* **Logical Reasoning:** I'll pick a couple of the simpler tests, like `EnclosingRect` and the basic `ComputeRelativeToPhysicalTransform`. I'll extract the input values and the expected output and present them clearly.

* **Common Errors:**  Mixing up physical and logical coordinates seems like a common mistake. Also, forgetting about writing mode transformations.

* **User Operation:**  Text selection is the most direct path. Clicking and dragging the mouse.

**Constraint Checklist & Confidence Score:**

*列举一下它的功能: Yes
*与javascript, html, css的功能有关系: Yes
*做出对应的举例说明: Yes
*做了逻辑推理: Yes
*给出假设输入与输出: Yes
*涉及用户或者编程常见的使用错误: Yes
*举例说明: Yes
*说明用户操作是如何一步步的到达这里: Yes

Confidence Score: 5/5

Strategizing complete. I will now generate the response based on these steps.

好的，我们来分析一下 `blink/renderer/core/paint/line_relative_rect_test.cc` 这个测试文件的功能。

**功能概述:**

这个 C++ 文件是 Chromium Blink 渲染引擎的一部分，专门用于测试 `LineRelativeRect` 类的功能。`LineRelativeRect` 类用于表示一个相对于文本行的矩形。它与普通的屏幕坐标矩形不同，它使用 **逻辑坐标**，即与文本行的书写方向相关的坐标。这对于处理不同书写模式（例如，水平从左到右、垂直从上到下、垂直从右到左等）的文本布局非常重要。

测试文件 `line_relative_rect_test.cc` 包含了多个单元测试，用于验证 `LineRelativeRect` 类的各种方法是否按预期工作，例如：

* **`EnclosingRect`:**  测试根据给定的物理矩形计算包含它的 `LineRelativeRect` 的功能，并验证是否正确地将坐标和尺寸转换为逻辑坐标，并处理精度限制。
* **`CreateFromLineBox`:** 测试从 `PhysicalRect`（物理坐标矩形）创建 `LineRelativeRect` 的功能，并根据是否是水平书写模式正确地设置逻辑坐标的偏移和尺寸。
* **`ComputeRelativeToPhysicalTransform`:** 测试计算将 `LineRelativeRect` 转换为物理坐标所需的仿射变换的功能，这对于在屏幕上绘制与文本行相关的元素至关重要。
* **`Create`:** 测试根据给定的物理矩形和仿射变换创建 `LineRelativeRect` 的功能，这用于处理已经过变换的矩形。
* **`EnclosingLineRelativeRect`:** 测试获取包含给定 `LineRelativeRect` 的最小整数边界 `LineRelativeRect` 的功能。
* **`Inflate`:** 测试扩展 `LineRelativeRect` 的功能。
* **`Unite`:** 测试合并两个 `LineRelativeRect` 以得到包含两者的最小 `LineRelativeRect` 的功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`LineRelativeRect` 类在 Blink 渲染引擎中扮演着关键角色，它使得浏览器能够正确地渲染和处理具有不同书写方向的文本和相关元素。 它与 JavaScript、HTML 和 CSS 的交互体现在以下方面：

1. **文本高亮显示 (Text Selection Highlight):**
   - **用户操作:** 用户在浏览器中选中一段文本（HTML 内容）。
   - **内部过程:** 浏览器引擎需要确定选中文本的边界，并在屏幕上绘制高亮背景。
   - **`LineRelativeRect` 的作用:**  对于水平文本，计算高亮区域的物理矩形可能比较直接。但对于垂直书写模式的文本，就需要使用 `LineRelativeRect` 来表示相对于每一行文本的选区，然后再通过 `ComputeRelativeToPhysicalTransform` 将其转换为屏幕上的物理坐标进行绘制。
   - **示例:** 考虑一个垂直书写的日语网页。当用户选中几个垂直排列的字符时，Blink 引擎会使用 `LineRelativeRect` 来描述每个选中的字符相对于其所在文本行的位置和大小，然后将这些逻辑矩形转换成屏幕上的物理矩形来绘制高亮效果。

2. **光标定位 (Caret Positioning):**
   - **用户操作:** 用户在可编辑的 HTML 元素（例如 `<textarea>` 或设置了 `contenteditable` 属性的元素）中点击鼠标或使用键盘导航。
   - **内部过程:** 浏览器需要确定光标应该显示的位置。
   - **`LineRelativeRect` 的作用:** 确定光标的正确位置需要考虑文本的行高、字符的宽度以及书写方向。`LineRelativeRect` 可以用于表示光标所在文本行的相关信息，辅助计算光标在屏幕上的物理坐标。
   - **示例:** 在一个垂直书写的文本框中，光标的移动是沿着垂直方向的。`LineRelativeRect` 可以帮助确定光标在每一行中的垂直偏移。

3. **CSS 布局和渲染 (CSS Layout and Rendering):**
   - **内部过程:** 当浏览器解析 HTML 和 CSS 时，Blink 引擎会进行布局计算，确定每个元素在页面上的位置和大小。对于包含文本的元素，书写模式会影响布局。
   - **`LineRelativeRect` 的作用:** 在渲染阶段，需要将布局计算得到的逻辑尺寸和位置转换为屏幕上的物理坐标进行绘制。`LineRelativeRect` 及其相关的转换机制确保了在不同书写模式下，文本和装饰（如下划线、删除线等）能够正确渲染。
   - **示例:**  一个设置了 `writing-mode: vertical-rl;` 的 `<div>` 元素，其内部文本是从上到下、从右到左排列的。在绘制下划线时，Blink 引擎会使用 `LineRelativeRect` 来确定下划线相对于每一行文本的位置，并进行相应的旋转和偏移，以保证下划线在视觉上正确地位于文本下方。

**逻辑推理 (假设输入与输出):**

让我们看一个 `ComputeRelativeToPhysicalTransformNotAtOrigin` 的测试用例：

**假设输入:**

* `LineRelativeRect r_origin`:
    * `offset.line_left = 1000`
    * `offset.line_over = 10000`
    * `size.inline_size = 10`
    * `size.block_size = 100`
* `WritingMode writing_mode = WritingMode::kVerticalRl;`

**逻辑推理:**

当书写模式为 `kVerticalRl`（垂直从右到左）时，逻辑上的 "inline" 方向对应物理上的 "block" 方向（高度），逻辑上的 "block" 方向对应物理上的反向 "inline" 方向（宽度）。  变换包括一个旋转和偏移。

* 旋转 90 度 (将水平方向变为垂直方向)。
* `line_left` (逻辑水平偏移) 对应物理上的垂直偏移，但由于是 `kVerticalRl`，所以需要加上原始矩形的高度 `100`。
* `line_over` (逻辑垂直偏移) 对应物理上的水平偏移，但由于是 `kVerticalRl`，方向相反，需要减去原始矩形的宽度 `10`。

**预期输出:**

`AffineTransform(0, 1, -1, 0, 11010, 9000)`

* `0, 1, -1, 0`:  表示旋转 90 度的矩阵。
* `11010`:  物理水平偏移 = 原始 `line_over` (10000) + 原始矩形的 `block_size` (100) + 原始矩形的 `inline_size` (10) = 11010
* `9000`:  物理垂直偏移 = 原始 `line_left` (1000) - 0 = 9000  *(更正：应该直接是原始的 line_left)*

**更正后的逻辑推理和预期输出:**

当书写模式为 `kVerticalRl` 时：

* 逻辑上的 `line_left` 对应物理上的 `y` 坐标。
* 逻辑上的 `line_over` 对应物理上的 `x` 坐标的反向。
* 逻辑上的 `inline_size` 对应物理上的 `height`。
* 逻辑上的 `block_size` 对应物理上的 `width`。

变换矩阵会将逻辑坐标 `(x, y)` 转换为物理坐标 `(new_x, new_y)`：

* `new_x = scaleX * x + skewY * y + translateX`
* `new_y = skewX * x + scaleY * y + translateY`

对于 `kVerticalRl`，变换大致是旋转 90 度并平移。

* `new_x = y + translateX`
* `new_y = -x + translateY`

其中，平移量需要考虑原始矩形的位置和大小。

* `translateX`:  原始的 `line_over` (10000) 加上原始矩形的 `block_size` (100)  => 10100  *(再次思考，应该是 `line_over` + `block_size`)*. 实际上，这里的平移是为了将原点移动到正确的位置进行旋转，需要更仔细考虑。

让我们直接看代码中的期望值： `AffineTransform(0, 1, -1, 0, 11100, 9000)`

* `0, 1, -1, 0`:  旋转 90 度。
* `11100`:  物理 `x` 偏移。  考虑原始矩形的右上角在物理坐标系中的位置。 原始逻辑矩形的右上角是 `(1000 + 10, 10000)`。 经过 `kVerticalRl` 变换后，它应该对应物理坐标系的某个点。
* `9000`:  物理 `y` 偏移。

更精确的推导需要理解仿射变换的含义和 `LineRelativeRect` 到物理坐标的转换过程。  关键在于理解旋转和平移的顺序和参考点。

**简化理解:**

对于 `kVerticalRl`，逻辑上的矩形 `(line_left, line_over, inline_size, block_size)` 大致对应物理上的矩形，但进行了旋转和平移：

* 物理 `x` 坐标与逻辑 `line_over` 相关，加上 `block_size` 进行调整。
* 物理 `y` 坐标与逻辑 `line_left` 相关。

**常见的使用错误及举例说明:**

1. **混淆逻辑坐标和物理坐标:**
   - **错误示例:**  开发者可能会直接使用 `LineRelativeRect` 的 `offset.line_left` 和 `offset.line_over` 作为屏幕上的像素坐标，而没有考虑到书写模式的影响。
   - **情景:** 在处理垂直书写的文本时，如果直接将 `line_left` 作为水平偏移，会导致元素定位错误。

2. **忽略书写模式的影响:**
   - **错误示例:** 在计算文本高亮区域时，开发者可能只考虑水平书写模式的情况，直接使用文本行的物理边界。
   - **情景:**  当网页包含不同书写模式的文本时，这种假设会导致高亮区域绘制不正确。例如，在垂直文本中，高亮区域的宽度和高度会与水平文本相反。

3. **不正确地应用仿射变换:**
   - **错误示例:**  开发者可能尝试手动计算坐标变换，而不是使用 `ComputeRelativeToPhysicalTransform` 提供的方法，导致计算错误。
   - **情景:**  在自定义绘制与文本相关的装饰时，如果仿射变换应用不当，会导致装饰元素的位置、旋转或缩放不正确。

**用户操作如何一步步到达这里 (作为调试线索):**

假设开发者正在调试一个与文本高亮显示相关的问题，特别是当涉及到非水平书写模式的文本时，可能会进入到 `line_relative_rect_test.cc` 进行调试或查看相关代码。以下是可能的操作步骤：

1. **用户在浏览器中打开一个包含垂直书写文本的网页。** 例如，一个日语或中文竖排古籍的网页。
2. **用户尝试选中这段垂直排列的文本。**
3. **观察到高亮显示不正确。** 例如，高亮区域没有覆盖选中的文本，或者位置偏移了。
4. **开发者开始调查渲染过程。** 他们可能会使用 Chrome 的开发者工具来查看元素的样式和布局信息。
5. **开发者怀疑问题可能与书写模式的处理有关。** 他们可能会查看与文本渲染相关的 Blink 代码。
6. **开发者可能会搜索或浏览 Blink 渲染引擎中与矩形和坐标转换相关的代码。** `LineRelativeRect` 和 `paint` 目录下的文件可能会引起他们的注意。
7. **开发者查看 `line_relative_rect_test.cc`，了解 `LineRelativeRect` 的功能和预期行为。** 通过阅读测试用例，他们可以更好地理解如何正确地使用 `LineRelativeRect` 以及如何进行坐标转换。
8. **开发者可能会在 `LineRelativeRect` 的相关代码中设置断点，例如在 `ComputeRelativeToPhysicalTransform` 或 `CreateFromLineBox` 等方法中，来跟踪当用户选择文本时，这些方法的输入和输出值，从而定位问题所在。**

总而言之，`line_relative_rect_test.cc` 是 Blink 渲染引擎中一个重要的测试文件，它确保了 `LineRelativeRect` 类的正确性，这对于处理各种书写模式下的文本布局和渲染至关重要。理解这个文件的功能有助于开发者理解 Blink 引擎是如何处理文本和相关元素的几何信息的。

### 提示词
```
这是目录为blink/renderer/core/paint/line_relative_rect_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/paint/line_relative_rect.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

class LineRelativeRectTest : public testing::Test {};

TEST(LineRelativeRectTest, EnclosingRect) {
  test::TaskEnvironment task_environment;
  gfx::RectF r(1000, 10000, 10, 100);
  LineRelativeRect lor = LineRelativeRect::EnclosingRect(r);
  EXPECT_EQ(lor.offset.line_left, 1000) << "offset X";
  EXPECT_EQ(lor.offset.line_over, 10000) << "offset Y";
  EXPECT_EQ(lor.size.inline_size, 10) << "inline size";
  EXPECT_EQ(lor.size.block_size, 100) << "block size";

  // All values are clamped to 1/64, enclosing the rect.
  gfx::RectF r2(1000.005625, 10000.005625, 10.005625, 100.005625);
  LineRelativeRect lor2 = LineRelativeRect::EnclosingRect(r2);
  EXPECT_EQ(lor2.offset.line_left, 1000) << "offset X clamped to 0";
  EXPECT_EQ(lor2.offset.line_over, 10000) << "offset Y clamped to 0";
  EXPECT_EQ(lor2.size.inline_size, LayoutUnit(10.015625))
      << "inline size clamped to 20 and 1/64";
  EXPECT_EQ(lor2.size.block_size, LayoutUnit(100.015625))
      << "block size clamped to 30 and 1/64";
}

TEST(LineRelativeRectTest, CreateFromLineBox) {
  test::TaskEnvironment task_environment;
  PhysicalRect r(1000, 10000, 10, 100);
  LineRelativeRect lor = LineRelativeRect::CreateFromLineBox(r, true);
  EXPECT_EQ(lor.offset.line_left, 1000) << "offset X, no rotation";
  EXPECT_EQ(lor.offset.line_over, 10000) << "offset Y, no rotation";
  EXPECT_EQ(lor.size.inline_size, 10) << "inline size, no rotation";
  EXPECT_EQ(lor.size.block_size, 100) << "block size, no rotation";

  LineRelativeRect lor_veritcal = LineRelativeRect::CreateFromLineBox(r, false);
  EXPECT_EQ(lor_veritcal.offset.line_left, 1000) << "offset X, with rotation";
  EXPECT_EQ(lor_veritcal.offset.line_over, 10000) << "offset Y, with rotation";
  EXPECT_EQ(lor_veritcal.size.inline_size, 100) << "inline size, with rotation";
  EXPECT_EQ(lor_veritcal.size.block_size, 10) << "block size, with rotation";
}

TEST(LineRelativeRectTest, ComputeRelativeToPhysicalTransformAtOrigin) {
  test::TaskEnvironment task_environment;
  LineRelativeRect r_origin = {{LayoutUnit(), LayoutUnit()},
                               {LayoutUnit(20), LayoutUnit(30)}};

  WritingMode writing_mode = WritingMode::kHorizontalTb;
  std::optional<AffineTransform> rotation =
      r_origin.ComputeRelativeToPhysicalTransform(writing_mode);
  EXPECT_EQ(rotation, AffineTransform());

  writing_mode = WritingMode::kVerticalRl;
  rotation = r_origin.ComputeRelativeToPhysicalTransform(writing_mode);
  EXPECT_EQ(rotation, AffineTransform(0, 1, -1, 0, 30, 0)) << "kVerticalRl";

  writing_mode = WritingMode::kSidewaysLr;
  rotation = r_origin.ComputeRelativeToPhysicalTransform(writing_mode);
  EXPECT_EQ(rotation, AffineTransform(0, -1, 1, 0, 0, 20)) << "kSidewaysLr";
}

TEST(LineRelativeRectTest, ComputeRelativeToPhysicalTransformNotAtOrigin) {
  test::TaskEnvironment task_environment;
  LineRelativeRect r_origin = {{LayoutUnit(1000), LayoutUnit(10000)},
                               {LayoutUnit(10), LayoutUnit(100)}};

  WritingMode writing_mode = WritingMode::kHorizontalTb;
  std::optional<AffineTransform> rotation =
      r_origin.ComputeRelativeToPhysicalTransform(writing_mode);
  EXPECT_EQ(rotation, AffineTransform());

  writing_mode = WritingMode::kVerticalRl;
  rotation = r_origin.ComputeRelativeToPhysicalTransform(writing_mode);
  EXPECT_EQ(rotation, AffineTransform(0, 1, -1, 0, 11100, 9000))
      << "kVerticalRl";

  writing_mode = WritingMode::kSidewaysLr;
  rotation = r_origin.ComputeRelativeToPhysicalTransform(writing_mode);
  EXPECT_EQ(rotation, AffineTransform(0, -1, 1, 0, -9000, 11010))
      << "kSidewaysLr";
}

TEST(LineRelativeRectTest, Create_kHorizontalTB) {
  test::TaskEnvironment task_environment;
  PhysicalRect r(1000, 10000, 10, 100);

  const WritingMode writing_mode = WritingMode::kHorizontalTb;
  const bool is_horizontal = IsHorizontalWritingMode(writing_mode);

  const LineRelativeRect rotated_box =
      LineRelativeRect::CreateFromLineBox(r, is_horizontal);
  std::optional<AffineTransform> rotation =
      rotated_box.ComputeRelativeToPhysicalTransform(writing_mode);

  EXPECT_EQ(rotation, AffineTransform());

  // First half of original box r
  PhysicalRect highlight(1000, 10000, 5, 100);
  LineRelativeRect rotated = LineRelativeRect::Create(highlight, rotation);
  EXPECT_EQ(rotated.offset.line_left, 1000) << "first half x, no rotation";
  EXPECT_EQ(rotated.offset.line_over, 10000) << "first half y, no rotation";
  EXPECT_EQ(rotated.size.inline_size, 5)
      << "first half inline_size, no rotation";
  EXPECT_EQ(rotated.size.block_size, 100)
      << "first half block_size, no rotation";

  // Second half of original box r
  PhysicalRect highlight2(1005, 10000, 5, 100);
  LineRelativeRect rotated2 = LineRelativeRect::Create(highlight2, rotation);
  EXPECT_EQ(rotated2.offset.line_left, 1005) << "second half x, no rotation";
  EXPECT_EQ(rotated2.offset.line_over, 10000) << "second half y, no rotation";
  EXPECT_EQ(rotated2.size.inline_size, 5)
      << "second half inline_size, no rotation";
  EXPECT_EQ(rotated2.size.block_size, 100)
      << "second half block_size, no rotation";
}

TEST(LineRelativeRectTest, Create_kSidewaysLr) {
  test::TaskEnvironment task_environment;
  PhysicalRect r(1000, 10000, 10, 100);

  const WritingMode writing_mode = WritingMode::kSidewaysLr;
  const bool is_horizontal = IsHorizontalWritingMode(writing_mode);
  EXPECT_FALSE(is_horizontal);
  const LineRelativeRect rotated_box =
      LineRelativeRect::CreateFromLineBox(r, is_horizontal);
  std::optional<AffineTransform> rotation =
      rotated_box.ComputeRelativeToPhysicalTransform(writing_mode);

  // AffineTransform ("translation(-9000,11100), scale(1,1), angle(-90deg),
  // skewxy(0)")
  EXPECT_EQ(rotation, AffineTransform(0, -1, 1, 0, -9000, 11100));

  // Top half of original box r
  PhysicalRect highlight(1000, 10000, 10, 50);
  LineRelativeRect rotated = LineRelativeRect::Create(highlight, rotation);
  EXPECT_EQ(rotated.offset.line_left, 1050) << "Top half, x";
  EXPECT_EQ(rotated.offset.line_over, 10000) << "Top half, y";
  EXPECT_EQ(rotated.size.inline_size, 50) << "Top half, inline_size";
  EXPECT_EQ(rotated.size.block_size, 10) << "Top half, block_size";

  // Bottom half of original box r
  PhysicalRect highlight2(1000, 10050, 10, 50);
  LineRelativeRect rotated2 = LineRelativeRect::Create(highlight2, rotation);
  EXPECT_EQ(rotated2.offset.line_left, 1000) << "Bottom half, x";
  EXPECT_EQ(rotated2.offset.line_over, 10000) << "Bottom half, y";
  EXPECT_EQ(rotated2.size.inline_size, 50) << "Bottom half, inline_size";
  EXPECT_EQ(rotated2.size.block_size, 10) << "Bottom half, block_size";

  // The whole thing.
  PhysicalRect highlight3(1000, 10000, 10, 100);
  LineRelativeRect rotated3 = LineRelativeRect::Create(highlight3, rotation);
  EXPECT_EQ(rotated3.offset.line_left, 1000) << "whole box, x";
  EXPECT_EQ(rotated3.offset.line_over, 10000) << "whole box, y";
  EXPECT_EQ(rotated3.size.inline_size, 100) << "whole box, inline_size";
  EXPECT_EQ(rotated3.size.block_size, 10) << "whole box, block_size";
}

TEST(LineRelativeRectTest, Create_kVerticalRl) {
  test::TaskEnvironment task_environment;
  PhysicalRect r(1000, 10000, 10, 100);

  const WritingMode writing_mode = WritingMode::kVerticalRl;
  const bool is_horizontal = IsHorizontalWritingMode(writing_mode);
  EXPECT_FALSE(is_horizontal);
  const LineRelativeRect rotated_box =
      LineRelativeRect::CreateFromLineBox(r, is_horizontal);
  std::optional<AffineTransform> rotation =
      rotated_box.ComputeRelativeToPhysicalTransform(writing_mode);

  // AffineTransform ("translation(11010,9000), scale(1,1), angle(90deg),
  // skewxy(0)")
  EXPECT_EQ(rotation, AffineTransform(0, 1, -1, 0, 11010, 9000));

  // Top half of original box r
  PhysicalRect highlight(1000, 10000, 10, 50);
  LineRelativeRect rotated = LineRelativeRect::Create(highlight, rotation);
  EXPECT_EQ(rotated.offset.line_left, 1000) << "top half, x";
  EXPECT_EQ(rotated.offset.line_over, 10000) << "top half, y";
  EXPECT_EQ(rotated.size.inline_size, 50) << "top half, inline_size";
  EXPECT_EQ(rotated.size.block_size, 10) << "top half, block_size";

  // Bottom half of original box r
  PhysicalRect highlight2(1000, 10050, 10, 50);
  LineRelativeRect rotated2 = LineRelativeRect::Create(highlight2, rotation);
  EXPECT_EQ(rotated2.offset.line_left, 1050) << "bottom half, x";
  EXPECT_EQ(rotated2.offset.line_over, 10000) << "bottom half, y";
  EXPECT_EQ(rotated2.size.inline_size, 50) << "bottom half, inline_size";
  EXPECT_EQ(rotated2.size.block_size, 10) << "bottom half, block_size";
}

TEST(LineRelativeRectTest, EnclosingLineRelativeRect) {
  test::TaskEnvironment task_environment;

  // Nothing should change
  LineRelativeRect rect_1 = {{LayoutUnit(10), LayoutUnit(0)},
                             {LayoutUnit(20), LayoutUnit(30)}};
  LineRelativeRect snapped_1 = rect_1.EnclosingLineRelativeRect();
  EXPECT_EQ(snapped_1.offset.line_left, 10);
  EXPECT_EQ(snapped_1.offset.line_over, 0);
  EXPECT_EQ(snapped_1.size.inline_size, 20);
  EXPECT_EQ(snapped_1.size.block_size, 30);

  // Size needs to increase size by 1 pixel, version a.
  LineRelativeRect rect_2 = {{LayoutUnit(10.25), LayoutUnit(0.25)},
                             {LayoutUnit(20.5), LayoutUnit(30.5)}};
  LineRelativeRect snapped_2 = rect_2.EnclosingLineRelativeRect();
  EXPECT_EQ(snapped_2.offset.line_left, 10);
  EXPECT_EQ(snapped_2.offset.line_over, 0);
  EXPECT_EQ(snapped_2.size.inline_size, 21);
  EXPECT_EQ(snapped_2.size.block_size, 31);

  // Size needs to increase size by 1 pixel, version b.
  LineRelativeRect rect_3 = {{LayoutUnit(10.75), LayoutUnit(0.75)},
                             {LayoutUnit(20.25), LayoutUnit(30.25)}};
  LineRelativeRect snapped_3 = rect_3.EnclosingLineRelativeRect();
  EXPECT_EQ(snapped_3.offset.line_left, 10);
  EXPECT_EQ(snapped_3.offset.line_over, 0);
  EXPECT_EQ(snapped_3.size.inline_size, 21);
  EXPECT_EQ(snapped_3.size.block_size, 31);

  // Size needs to increase size by more than 1 pixel.
  LineRelativeRect rect_4 = {{LayoutUnit(10.75), LayoutUnit(0.75)},
                             {LayoutUnit(20.5), LayoutUnit(30.5)}};
  LineRelativeRect snapped_4 = rect_4.EnclosingLineRelativeRect();
  EXPECT_EQ(snapped_4.offset.line_left, 10);
  EXPECT_EQ(snapped_4.offset.line_over, 0);
  EXPECT_EQ(snapped_4.size.inline_size, 22);
  EXPECT_EQ(snapped_4.size.block_size, 32);
}

TEST(LineRelativeRectTest, Inflate) {
  test::TaskEnvironment task_environment;

  // Nothing should change
  LineRelativeRect rect_1 = {{LayoutUnit(10), LayoutUnit(0)},
                             {LayoutUnit(20), LayoutUnit(30)}};
  rect_1.Inflate(LayoutUnit(1));
  EXPECT_EQ(rect_1.offset.line_left, 9);
  EXPECT_EQ(rect_1.offset.line_over, -1);
  EXPECT_EQ(rect_1.size.inline_size, 22);
  EXPECT_EQ(rect_1.size.block_size, 32);
}

TEST(LineRelativeRectTest, Unite) {
  test::TaskEnvironment task_environment;

  // Nothing should change
  LineRelativeRect rect_1 = {{LayoutUnit(10), LayoutUnit(0)},
                             {LayoutUnit(20), LayoutUnit(40)}};
  LineRelativeRect rect_2 = {{LayoutUnit(0), LayoutUnit(10)},
                             {LayoutUnit(40), LayoutUnit(20)}};
  LineRelativeRect rect_1a = rect_1;
  LineRelativeRect rect_2a = rect_2;

  rect_1.Unite(rect_2a);
  EXPECT_EQ(rect_1.offset.line_left, 0);
  EXPECT_EQ(rect_1.offset.line_over, 0);
  EXPECT_EQ(rect_1.size.inline_size, 40);
  EXPECT_EQ(rect_1.size.block_size, 40);

  rect_2.Unite(rect_1a);
  EXPECT_EQ(rect_2.offset.line_left, 0);
  EXPECT_EQ(rect_2.offset.line_over, 0);
  EXPECT_EQ(rect_2.size.inline_size, 40);
  EXPECT_EQ(rect_2.size.block_size, 40);
}

}  // namespace blink
```