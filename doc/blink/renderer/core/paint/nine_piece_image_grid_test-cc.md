Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `nine_piece_image_grid_test.cc` immediately suggests the file tests the `NinePieceImageGrid` class. The directory `blink/renderer/core/paint/` indicates it's related to rendering and painting within the Blink engine.

2. **Understand the Purpose of Unit Tests:** Unit tests verify the behavior of individual components or units of code in isolation. They aim to catch bugs early in the development process. Key aspects of unit tests are setting up scenarios (inputs), executing the code under test, and asserting the expected outcomes (outputs).

3. **Examine the Includes:**  The `#include` statements provide crucial context:
    * `"third_party/blink/renderer/core/paint/nine_piece_image_grid.h"`: Confirms the class being tested.
    * `"testing/gtest/include/gtest/gtest.h"`:  Indicates the use of Google Test framework for writing tests.
    * `"third_party/blink/renderer/core/css/css_gradient_value.h"`: Suggests interaction with CSS gradient values.
    * `"third_party/blink/renderer/core/style/nine_piece_image.h"`: Points to the related `NinePieceImage` class, likely containing the data model for nine-piece images.
    * `"third_party/blink/renderer/core/style/style_generated_image.h"`: Indicates the use of generated images in the tests.
    * `"third_party/blink/renderer/core/testing/core_unit_test_helper.h"`:  A helper for Blink unit tests.
    * `"ui/gfx/geometry/outsets.h"` and others from `ui/gfx/geometry`:  Show usage of graphics primitives like rectangles, sizes, and insets.

4. **Analyze the Test Structure:**
    * **Namespace:** The code is within `namespace blink { namespace { ... } }`, which is typical for Blink. The anonymous namespace is common for test files to avoid symbol collisions.
    * **Test Fixture:** `class NinePieceImageGridTest : public RenderingTest { ... }` establishes a test fixture. This allows setting up common resources or helper functions (`GeneratedImage()` in this case) that can be used across multiple tests. Inheriting from `RenderingTest` likely provides necessary infrastructure for rendering-related tests.
    * **Individual Tests:**  `TEST_F(NinePieceImageGridTest, ...)` defines individual test cases. The test names are descriptive, hinting at the specific scenarios being tested (e.g., `NinePieceImagePainting_NoDrawables`, `NinePieceImagePainting_AllDrawable`).

5. **Deconstruct Individual Tests:** For each test:
    * **Setup:**  Look for initialization of `NinePieceImage` and setting its properties (image, slices, fill, border slices, rules). Also, note the creation of `gfx::SizeF`, `gfx::Rect`, and `gfx::Outsets` which define the context for the image grid.
    * **Action:** The core action is the creation of a `NinePieceImageGrid` object with specific parameters. The key method being tested is `GetNinePieceDrawInfo(piece)`.
    * **Assertions:**  `EXPECT_...` macros from Google Test are used to verify expectations. These checks focus on properties of the `NinePieceDrawInfo` struct (e.g., `is_drawable`, `destination`, `source`, `tile_scale`, `tile_rule`).

6. **Identify Relationships with Web Technologies:**
    * **CSS `border-image`:** The concept of a nine-piece image grid directly corresponds to the CSS `border-image` property. The `image-slice`, `border-width`, `border-image-repeat`, and `border-image-source` properties are all reflected in the test scenarios.
    * **HTML Elements:** While not directly manipulating HTML elements, the tests simulate how a rendered HTML element with a `border-image` would be processed.
    * **JavaScript:**  JavaScript could manipulate the CSS `border-image` properties of an element, indirectly affecting the behavior tested by this code.

7. **Infer Logic and Assumptions:**
    * **`NinePieceImage`:**  This class likely holds the image source and slicing information.
    * **`NinePieceImageGrid`:** This class takes the `NinePieceImage` and rendering context (size, area, border widths, zoom) and calculates how the nine pieces of the image should be drawn. The core logic involves determining which pieces are drawable and their destination and source rectangles.
    * **`NinePieceDrawInfo`:**  This struct likely contains the information needed to draw a single piece of the nine-piece image.

8. **Consider Potential User Errors:**  Think about how developers might misuse the `border-image` property in CSS:
    * Incorrectly specified `border-image-slice` values.
    * Mismatched `border-width` and `border-image-slice`.
    * Not understanding the `border-image-repeat` values (`stretch`, `repeat`, `round`, `space`).
    * Issues with image size and scaling.

9. **Trace User Operations (Debugging Clues):** Consider how a user's actions could lead to the code being executed:
    * A user loads a webpage containing an element with a `border-image` style.
    * The browser's rendering engine processes the CSS and creates a `NinePieceImage` object.
    * During the paint phase, the `NinePieceImageGrid` is used to determine how to draw the border image.
    * If the border image is not rendered correctly, a developer might inspect the element's styles and the calculated layout to find the issue. They might then look at the `NinePieceImageGrid` logic to understand why a particular piece is not being drawn as expected.

10. **Review and Refine:** Go back through the analysis, ensuring accuracy and completeness. Look for any missing links or areas that could be explained more clearly. For example,  explicitly mentioning the `kMinPiece` and `kMaxPiece` enum and how it iterates through the nine pieces adds clarity.

By following these steps, you can systematically analyze the C++ test file and extract the requested information. The process involves understanding the code's purpose, its structure, its interactions with other parts of the system, and its relationship to web technologies.
这个文件 `nine_piece_image_grid_test.cc` 是 Chromium Blink 引擎中用于测试 `NinePieceImageGrid` 类的单元测试文件。 `NinePieceImageGrid` 类负责处理和绘制九宫格图片，这是一种常见的用于实现可伸缩的用户界面元素的技术，例如按钮、窗口边框等。

以下是该文件的功能列表，以及它与 JavaScript、HTML、CSS 的关系，逻辑推理、常见错误和调试线索的说明：

**功能列表:**

1. **测试 `NinePieceImageGrid` 类的各种场景:** 该文件包含多个以 `TEST_F` 宏定义的测试用例，每个测试用例都针对 `NinePieceImageGrid` 类的特定功能或边缘情况。
2. **验证九宫格图片不同部分的绘制信息:**  测试用例会创建 `NinePieceImageGrid` 对象，并使用 `GetNinePieceDrawInfo` 方法来获取九宫格图片的九个部分（四个角、四条边和一个中心）的绘制信息。
3. **检查绘制信息的准确性:**  测试用例使用 `EXPECT_TRUE`、`EXPECT_FALSE`、`EXPECT_EQ`、`EXPECT_FLOAT_EQ` 等宏来断言获取到的绘制信息是否符合预期，例如是否可绘制、目标和源矩形的大小和位置、平铺缩放比例和规则等。
4. **覆盖不同的配置和参数:** 测试用例会设置不同的 `NinePieceImage` 属性（例如图片源、切片大小、填充模式、平铺规则）和 `NinePieceImageGrid` 的参数（例如图片大小、边框区域、边框宽度、缩放比例），以确保该类在各种情况下都能正确工作。

**与 JavaScript, HTML, CSS 的关系:**

`NinePieceImageGrid` 类是渲染引擎内部的实现细节，直接与 JavaScript、HTML 和 CSS 没有直接的 API 交互。但是，它背后支撑着 CSS 的 `border-image` 属性的功能。

* **CSS `border-image`:**  `border-image` 属性允许开发者使用一张图片来绘制元素的边框。这张图片可以被切割成九个部分（四个角，四条边和一个中心），并根据 `border-image-slice`、`border-image-width`、`border-image-repeat` 和 `border-image-outset` 等 CSS 属性进行缩放、平铺或拉伸。
* **HTML 元素:**  `border-image` 属性应用于 HTML 元素，例如 `<div>`、`<button>` 等。当浏览器渲染这些元素时，会使用 `NinePieceImageGrid` 类来计算如何绘制边框图像。
* **JavaScript:** JavaScript 可以动态地修改 HTML 元素的 CSS 样式，包括 `border-image` 相关的属性。这会间接地影响 `NinePieceImageGrid` 类的行为。

**举例说明:**

假设以下 CSS 样式应用于一个 `<div>` 元素：

```css
div {
  border-image-source: url("border.png");
  border-image-slice: 10 20 30 40 fill;
  border-image-width: 10px 20px 30px 40px;
  border-image-repeat: stretch;
  border-width: 10px 20px 30px 40px;
  width: 200px;
  height: 100px;
}
```

当浏览器渲染这个 `<div>` 元素时，`NinePieceImageGrid` 类会使用 `border.png` 图片，并根据 `border-image-slice` 的值 (上 10px, 右 20px, 下 30px, 左 40px) 将其切割成九个部分。然后，根据 `border-image-width` 和 `border-image-repeat` 的设置，计算出每个部分应该如何绘制到元素的边框区域。

`nine_piece_image_grid_test.cc` 中的测试用例会模拟这种场景，创建 `NinePieceImage` 对象并设置相应的切片、宽度和重复规则，然后创建 `NinePieceImageGrid` 对象并验证其计算出的绘制信息是否正确。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `NinePieceImage` 对象，其 `image_slices` 设置为 `LengthBox(10, 10, 10, 10)` (上、右、下、左切片均为 10 像素)。
* `image_size` 为 `100x100` 像素。
* `border_image_area` 为 `0, 0, 100, 100`。
* `border_widths` 为 `Outsets(10)` (所有边框宽度均为 10 像素)。
* `fill` 设置为 `false` (不填充中心区域)。

**预期输出 (基于 `NinePieceImagePainting_NoFillMiddleNotDrawable` 测试用例):**

对于 `GetNinePieceDrawInfo(piece)` 方法：

* 除 `kMiddlePiece` 外，其他八个部分的 `draw_info.is_drawable` 应该为 `true`。
* `kMiddlePiece` 的 `draw_info.is_drawable` 应该为 `false`。

**用户或编程常见的使用错误:**

1. **`border-image-slice` 的值不合理:**  例如，切片值大于图片的尺寸，导致无法正确切割图片。测试用例会覆盖这种情况，确保 `NinePieceImageGrid` 能正确处理。
2. **`border-image-width` 与 `border-width` 不一致:** 可能导致边框图像绘制超出或小于预期的边框区域。测试用例通过设置不同的 `border_widths` 来验证这种情况。
3. **不理解 `border-image-repeat` 的含义:**  错误地使用了 `repeat`、`round` 或 `stretch`，导致边框图像的平铺效果不符合预期。测试用例中包含了对不同平铺规则的测试。
4. **忘记设置 `border-image-source`:**  这将导致边框图像不显示。虽然 `nine_piece_image_grid_test.cc` 不直接测试 CSS 解析，但它创建的 `NinePieceImage` 对象需要有有效的图像源。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 HTML 文件中定义了一个带有 `border-image` 样式的元素。** 例如：
   ```html
   <div style="border-image: url('my-border.png') 10 20 30 40 stretch;">Content</div>
   ```
2. **浏览器加载 HTML 文件并解析 CSS。**  渲染引擎会解析 `border-image` 属性及其相关子属性。
3. **渲染引擎创建 `NinePieceImage` 对象。**  基于解析后的 CSS 属性，渲染引擎会创建一个 `NinePieceImage` 对象来存储边框图像的信息，包括图像源、切片大小、重复规则等。
4. **在布局和绘制阶段，渲染引擎需要绘制元素的边框。**  对于使用了 `border-image` 的元素，渲染引擎会使用 `NinePieceImageGrid` 类。
5. **`NinePieceImageGrid` 的实例被创建，并传入 `NinePieceImage` 对象以及元素的尺寸、边框宽度等信息。**
6. **`GetNinePieceDrawInfo` 方法被调用，针对九宫格的每个部分，计算其绘制所需的源矩形、目标矩形、平铺规则等信息。**
7. **如果边框图像没有按预期显示，开发者可以使用浏览器的开发者工具进行检查。**  他们可能会看到元素的样式信息、计算后的样式信息，甚至可以断点调试渲染引擎的代码。
8. **在调试渲染引擎的过程中，开发者可能会进入 `NinePieceImageGrid::GetNinePieceDrawInfo` 等方法，查看其内部的计算逻辑。**  `nine_piece_image_grid_test.cc` 中的测试用例可以帮助开发者理解这些计算逻辑在不同情况下的行为，从而找到问题所在。

总而言之，`nine_piece_image_grid_test.cc` 是 Blink 渲染引擎中一个重要的测试文件，它确保了用于实现 CSS `border-image` 功能的核心类 `NinePieceImageGrid` 的正确性和稳定性。 通过阅读和理解这些测试用例，开发者可以更好地了解 `border-image` 的工作原理以及可能出现的问题。

### 提示词
```
这是目录为blink/renderer/core/paint/nine_piece_image_grid_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/nine_piece_image_grid.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_gradient_value.h"
#include "third_party/blink/renderer/core/style/nine_piece_image.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "ui/gfx/geometry/outsets.h"

namespace blink {
namespace {

class NinePieceImageGridTest : public RenderingTest {
 public:
  NinePieceImageGridTest() = default;

  StyleImage* GeneratedImage() {
    auto* gradient = MakeGarbageCollected<cssvalue::

                                              CSSLinearGradientValue>(
        nullptr, nullptr, nullptr, nullptr, nullptr, cssvalue::kRepeating);
    return MakeGarbageCollected<StyleGeneratedImage>(
        *gradient, StyleGeneratedImage::ContainerSizes());
  }
};

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_NoDrawables) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());

  gfx::SizeF image_size(100, 100);
  gfx::Rect border_image_area(0, 0, 100, 100);
  gfx::Outsets border_widths(0);

  NinePieceImageGrid grid =
      NinePieceImageGrid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                         border_image_area, border_widths);
  for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
    NinePieceImageGrid::NinePieceDrawInfo draw_info =
        grid.GetNinePieceDrawInfo(piece);
    EXPECT_FALSE(draw_info.is_drawable);
  }
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_AllDrawable) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  nine_piece.SetImageSlices(LengthBox(10, 10, 10, 10));
  nine_piece.SetFill(true);

  gfx::SizeF image_size(100, 100);
  gfx::Rect border_image_area(0, 0, 100, 100);
  gfx::Outsets border_widths(10);

  NinePieceImageGrid grid =
      NinePieceImageGrid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                         border_image_area, border_widths);
  for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
    NinePieceImageGrid::NinePieceDrawInfo draw_info =
        grid.GetNinePieceDrawInfo(piece);
    EXPECT_TRUE(draw_info.is_drawable);
  }
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_NoFillMiddleNotDrawable) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  nine_piece.SetImageSlices(LengthBox(10, 10, 10, 10));
  nine_piece.SetFill(false);  // default

  gfx::SizeF image_size(100, 100);
  gfx::Rect border_image_area(0, 0, 100, 100);
  gfx::Outsets border_widths(10);

  NinePieceImageGrid grid =
      NinePieceImageGrid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                         border_image_area, border_widths);
  for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
    NinePieceImageGrid::NinePieceDrawInfo draw_info =
        grid.GetNinePieceDrawInfo(piece);
    if (piece != kMiddlePiece)
      EXPECT_TRUE(draw_info.is_drawable);
    else
      EXPECT_FALSE(draw_info.is_drawable);
  }
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_EmptySidesNotDrawable) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  nine_piece.SetImageSlices(LengthBox(Length::Percent(49), Length::Percent(49),
                                      Length::Percent(49),
                                      Length::Percent(49)));

  gfx::SizeF image_size(6, 6);
  gfx::Rect border_image_area(0, 0, 6, 6);
  gfx::Outsets border_widths(3);

  NinePieceImageGrid grid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                          border_image_area, border_widths);
  for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
    auto draw_info = grid.GetNinePieceDrawInfo(piece);
    if (piece == kLeftPiece || piece == kRightPiece || piece == kTopPiece ||
        piece == kBottomPiece || piece == kMiddlePiece)
      EXPECT_FALSE(draw_info.is_drawable);
    else
      EXPECT_TRUE(draw_info.is_drawable);
  }
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_TopLeftDrawable) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  nine_piece.SetImageSlices(LengthBox(10, 10, 10, 10));

  gfx::SizeF image_size(100, 100);
  gfx::Rect border_image_area(0, 0, 100, 100);

  const struct {
    gfx::Outsets border_widths;
    bool expected_is_drawable;
  } test_cases[] = {
      {gfx::Outsets(), false},
      {gfx::Outsets().set_top(10), false},
      {gfx::Outsets().set_left(10), false},
      {gfx::Outsets().set_top(10).set_left(10), true},
  };

  for (const auto& test_case : test_cases) {
    NinePieceImageGrid grid =
        NinePieceImageGrid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                           border_image_area, test_case.border_widths);
    for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
      NinePieceImageGrid::NinePieceDrawInfo draw_info =
          grid.GetNinePieceDrawInfo(piece);
      if (piece == kTopLeftPiece)
        EXPECT_EQ(draw_info.is_drawable, test_case.expected_is_drawable);
    }
  }
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_ScaleDownBorder) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  nine_piece.SetImageSlices(LengthBox(10, 10, 10, 10));

  gfx::SizeF image_size(100, 100);
  gfx::Rect border_image_area(0, 0, 100, 100);
  gfx::Outsets border_widths(10);

  // Set border slices wide enough so that the widths are scaled
  // down and corner pieces cover the entire border image area.
  nine_piece.SetBorderSlices(BorderImageLengthBox(6));

  NinePieceImageGrid grid =
      NinePieceImageGrid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                         border_image_area, border_widths);
  for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
    NinePieceImageGrid::NinePieceDrawInfo draw_info =
        grid.GetNinePieceDrawInfo(piece);
    if (draw_info.is_corner_piece)
      EXPECT_EQ(draw_info.destination.size(), gfx::SizeF(50, 50));
    else
      EXPECT_TRUE(draw_info.destination.size().IsEmpty());
  }

  // Like above, but also make sure to get a scale-down factor that requires
  // rounding to pick the larger value on one of the edges. (A 1:3, 2:3 split.)
  BorderImageLength top_left(10);
  BorderImageLength bottom_right(20);
  nine_piece.SetBorderSlices(
      BorderImageLengthBox(top_left, bottom_right, bottom_right, top_left));
  grid = NinePieceImageGrid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                            border_image_area, border_widths);
  NinePieceImageGrid::NinePieceDrawInfo draw_info =
      grid.GetNinePieceDrawInfo(kTopLeftPiece);
  EXPECT_EQ(draw_info.destination.size(), gfx::SizeF(33, 33));
  draw_info = grid.GetNinePieceDrawInfo(kTopRightPiece);
  EXPECT_EQ(draw_info.destination.size(), gfx::SizeF(67, 33));
  draw_info = grid.GetNinePieceDrawInfo(kBottomLeftPiece);
  EXPECT_EQ(draw_info.destination.size(), gfx::SizeF(33, 67));
  draw_info = grid.GetNinePieceDrawInfo(kBottomRightPiece);
  EXPECT_EQ(draw_info.destination.size(), gfx::SizeF(67, 67));

  // Set border slices that overlap in one dimension but not in the other, and
  // where the resulting width in the non-overlapping dimension will round to a
  // larger width.
  BorderImageLength top_bottom(10);
  BorderImageLength left_right(Length::Fixed(11));
  nine_piece.SetBorderSlices(
      BorderImageLengthBox(top_bottom, left_right, top_bottom, left_right));
  grid = NinePieceImageGrid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                            border_image_area, border_widths);
  NinePieceImageGrid::NinePieceDrawInfo tl_info =
      grid.GetNinePieceDrawInfo(kTopLeftPiece);
  EXPECT_EQ(tl_info.destination.size(), gfx::SizeF(5, 50));
  // The top-right, bottom-left and bottom-right pieces are the same size as
  // the top-left piece.
  draw_info = grid.GetNinePieceDrawInfo(kTopRightPiece);
  EXPECT_EQ(tl_info.destination.size(), draw_info.destination.size());
  draw_info = grid.GetNinePieceDrawInfo(kBottomLeftPiece);
  EXPECT_EQ(tl_info.destination.size(), draw_info.destination.size());
  draw_info = grid.GetNinePieceDrawInfo(kBottomRightPiece);
  EXPECT_EQ(tl_info.destination.size(), draw_info.destination.size());
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_AbuttingEdges) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  nine_piece.SetImageSlices(
      LengthBox(Length::Percent(56.1f), Length::Percent(12.5f),
                Length::Percent(43.9f), Length::Percent(37.5f)));
  BorderImageLength auto_width(Length::Auto());
  nine_piece.SetBorderSlices(
      BorderImageLengthBox(auto_width, auto_width, auto_width, auto_width));

  const gfx::SizeF image_size(200, 35);
  const gfx::Rect border_image_area(0, 0, 250, 35);
  const int kExpectedTileWidth = border_image_area.width() -
                                 0.125f * image_size.width() -
                                 0.375f * image_size.width();
  const gfx::Outsets border_widths(0);
  const NinePieceImageGrid grid =
      NinePieceImageGrid(nine_piece, image_size, gfx::Vector2dF(1, 1), 1,
                         border_image_area, border_widths);

  const NinePieceImageGrid::NinePieceDrawInfo top_info =
      grid.GetNinePieceDrawInfo(kTopPiece);
  EXPECT_EQ(top_info.destination.size(), gfx::SizeF(kExpectedTileWidth, 20));

  const NinePieceImageGrid::NinePieceDrawInfo middle_info =
      grid.GetNinePieceDrawInfo(kMiddlePiece);
  EXPECT_FALSE(middle_info.is_drawable);

  const NinePieceImageGrid::NinePieceDrawInfo bottom_info =
      grid.GetNinePieceDrawInfo(kBottomPiece);
  EXPECT_EQ(bottom_info.destination.size(), gfx::SizeF(kExpectedTileWidth, 15));
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting) {
  const struct {
    gfx::SizeF image_size;
    gfx::Rect border_image_area;
    gfx::Outsets border_widths;
    bool fill;
    LengthBox image_slices;
    ENinePieceImageRule horizontal_rule;
    ENinePieceImageRule vertical_rule;
    struct Piece {
      bool is_drawable;
      bool is_corner_piece;
      gfx::RectF destination;
      gfx::RectF source;
      float tile_scale_horizontal;
      float tile_scale_vertical;
      ENinePieceImageRule horizontal_rule;
      ENinePieceImageRule vertical_rule;
    };
    std::array<Piece, 9> pieces;
  } test_cases[] = {
      {// Empty border and slices but with fill
       gfx::SizeF(100, 100),
       gfx::Rect(0, 0, 100, 100),
       gfx::Outsets(0),
       true,
       LengthBox(Length::Fixed(0), Length::Fixed(0), Length::Fixed(0),
                 Length::Fixed(0)),
       kStretchImageRule,
       kStretchImageRule,
       {{
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kStretchImageRule},
           {true, false, gfx::RectF(0, 0, 100, 100), gfx::RectF(0, 0, 100, 100),
            1, 1, kStretchImageRule, kStretchImageRule},
       }}},
      {// Single border and fill
       gfx::SizeF(100, 100),
       gfx::Rect(0, 0, 100, 100),
       gfx::Outsets().set_bottom(10),
       true,
       LengthBox(Length::Percent(20), Length::Percent(20), Length::Percent(20),
                 Length::Percent(20)),
       kStretchImageRule,
       kStretchImageRule,
       {{
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kStretchImageRule},
           {true, false, gfx::RectF(0, 90, 100, 10), gfx::RectF(20, 80, 60, 20),
            0.5, 0.5, kStretchImageRule, kStretchImageRule},
           {true, false, gfx::RectF(0, 0, 100, 90), gfx::RectF(20, 20, 60, 60),
            1.666667, 1.5, kStretchImageRule, kStretchImageRule},
       }}},
      {// All borders, no fill
       gfx::SizeF(100, 100),
       gfx::Rect(0, 0, 100, 100),
       gfx::Outsets(10),
       false,
       LengthBox(Length::Percent(20), Length::Percent(20), Length::Percent(20),
                 Length::Percent(20)),
       kStretchImageRule,
       kStretchImageRule,
       {{
           {true, true, gfx::RectF(0, 0, 10, 10), gfx::RectF(0, 0, 20, 20), 1,
            1, kStretchImageRule, kStretchImageRule},
           {true, true, gfx::RectF(0, 90, 10, 10), gfx::RectF(0, 80, 20, 20), 1,
            1, kStretchImageRule, kStretchImageRule},
           {true, false, gfx::RectF(0, 10, 10, 80), gfx::RectF(0, 20, 20, 60),
            0.5, 0.5, kStretchImageRule, kStretchImageRule},
           {true, true, gfx::RectF(90, 0, 10, 10), gfx::RectF(80, 0, 20, 20), 1,
            1, kStretchImageRule, kStretchImageRule},
           {true, true, gfx::RectF(90, 90, 10, 10), gfx::RectF(80, 80, 20, 20),
            1, 1, kStretchImageRule, kStretchImageRule},
           {true, false, gfx::RectF(90, 10, 10, 80), gfx::RectF(80, 20, 20, 60),
            0.5, 0.5, kStretchImageRule, kStretchImageRule},
           {true, false, gfx::RectF(10, 0, 80, 10), gfx::RectF(20, 0, 60, 20),
            0.5, 0.5, kStretchImageRule, kStretchImageRule},
           {true, false, gfx::RectF(10, 90, 80, 10), gfx::RectF(20, 80, 60, 20),
            0.5, 0.5, kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kStretchImageRule},
       }}},
      {// Single border, no fill
       gfx::SizeF(100, 100),
       gfx::Rect(0, 0, 100, 100),
       gfx::Outsets().set_left(10),
       false,
       LengthBox(Length::Percent(20), Length::Percent(20), Length::Percent(20),
                 Length::Percent(20)),
       kStretchImageRule,
       kRoundImageRule,
       {{
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {true, false, gfx::RectF(0, 0, 10, 100), gfx::RectF(0, 20, 20, 60),
            0.5, 0.5, kStretchImageRule, kRoundImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kRoundImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kRoundImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kRoundImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kRoundImageRule},
       }}},
      {// All borders but no slices, with fill (stretch horizontally, space
       // vertically)
       gfx::SizeF(100, 100),
       gfx::Rect(0, 0, 100, 100),
       gfx::Outsets(10),
       true,
       LengthBox(Length::Fixed(0), Length::Fixed(0), Length::Fixed(0),
                 Length::Fixed(0)),
       kStretchImageRule,
       kSpaceImageRule,
       {{
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kSpaceImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, true, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 1, 1,
            kStretchImageRule, kStretchImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kSpaceImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kSpaceImageRule},
           {false, false, gfx::RectF(0, 0, 0, 0), gfx::RectF(0, 0, 0, 0), 0, 0,
            kStretchImageRule, kSpaceImageRule},
           {true, false, gfx::RectF(10, 10, 80, 80), gfx::RectF(0, 0, 100, 100),
            0.800000, 1, kStretchImageRule, kSpaceImageRule},
       }}},
  };

  for (auto& test_case : test_cases) {
    NinePieceImage nine_piece;
    nine_piece.SetImage(GeneratedImage());
    nine_piece.SetFill(test_case.fill);
    nine_piece.SetImageSlices(test_case.image_slices);
    nine_piece.SetHorizontalRule(
        (ENinePieceImageRule)test_case.horizontal_rule);
    nine_piece.SetVerticalRule((ENinePieceImageRule)test_case.vertical_rule);

    NinePieceImageGrid grid = NinePieceImageGrid(
        nine_piece, test_case.image_size, gfx::Vector2dF(1, 1), 1,
        test_case.border_image_area, test_case.border_widths);
    for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
      NinePieceImageGrid::NinePieceDrawInfo draw_info =
          grid.GetNinePieceDrawInfo(piece);
      EXPECT_EQ(test_case.pieces[piece].is_drawable, draw_info.is_drawable);
      if (!test_case.pieces[piece].is_drawable)
        continue;

      EXPECT_EQ(test_case.pieces[piece].destination.x(),
                draw_info.destination.x());
      EXPECT_EQ(test_case.pieces[piece].destination.y(),
                draw_info.destination.y());
      EXPECT_EQ(test_case.pieces[piece].destination.width(),
                draw_info.destination.width());
      EXPECT_EQ(test_case.pieces[piece].destination.height(),
                draw_info.destination.height());
      EXPECT_EQ(test_case.pieces[piece].source.x(), draw_info.source.x());
      EXPECT_EQ(test_case.pieces[piece].source.y(), draw_info.source.y());
      EXPECT_EQ(test_case.pieces[piece].source.width(),
                draw_info.source.width());
      EXPECT_EQ(test_case.pieces[piece].source.height(),
                draw_info.source.height());

      if (test_case.pieces[piece].is_corner_piece)
        continue;

      EXPECT_FLOAT_EQ(test_case.pieces[piece].tile_scale_horizontal,
                      draw_info.tile_scale.x());
      EXPECT_FLOAT_EQ(test_case.pieces[piece].tile_scale_vertical,
                      draw_info.tile_scale.y());
      EXPECT_EQ(test_case.pieces[piece].horizontal_rule,
                draw_info.tile_rule.horizontal);
      EXPECT_EQ(test_case.pieces[piece].vertical_rule,
                draw_info.tile_rule.vertical);
    }
  }
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_Zoomed) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  // Image slices are specified in CSS pixels.
  nine_piece.SetImageSlices(LengthBox(10, 10, 10, 10));
  nine_piece.SetFill(true);

  gfx::SizeF image_size(50, 50);
  gfx::Rect border_image_area(0, 0, 200, 200);
  gfx::Outsets border_widths(20);

  NinePieceImageGrid grid(nine_piece, image_size, gfx::Vector2dF(2, 2), 2,
                          border_image_area, border_widths);

  struct ExpectedPiece {
    bool is_drawable;
    bool is_corner_piece;
    gfx::RectF destination;
    gfx::RectF source;
    float tile_scale_horizontal;
    float tile_scale_vertical;
    ENinePieceImageRule horizontal_rule;
    ENinePieceImageRule vertical_rule;
  };
  std::array<ExpectedPiece, kMaxPiece> expected_pieces = {{
      {true, true, gfx::RectF(0, 0, 20, 20), gfx::RectF(0, 0, 20, 20), 0, 0,
       kStretchImageRule, kStretchImageRule},
      {true, true, gfx::RectF(0, 180, 20, 20), gfx::RectF(0, 30, 20, 20), 0, 0,
       kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(0, 20, 20, 160), gfx::RectF(0, 20, 20, 10), 1, 1,
       kStretchImageRule, kStretchImageRule},
      {true, true, gfx::RectF(180, 0, 20, 20), gfx::RectF(30, 0, 20, 20), 0, 0,
       kStretchImageRule, kStretchImageRule},
      {true, true, gfx::RectF(180, 180, 20, 20), gfx::RectF(30, 30, 20, 20), 0,
       0, kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(180, 20, 20, 160), gfx::RectF(30, 20, 20, 10), 1,
       1, kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(20, 0, 160, 20), gfx::RectF(20, 0, 10, 20), 1, 1,
       kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(20, 180, 160, 20), gfx::RectF(20, 30, 10, 20), 1,
       1, kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(20, 20, 160, 160), gfx::RectF(20, 20, 10, 10),
       16, 16, kStretchImageRule, kStretchImageRule},
  }};

  for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
    NinePieceImageGrid::NinePieceDrawInfo draw_info =
        grid.GetNinePieceDrawInfo(piece);
    EXPECT_TRUE(draw_info.is_drawable);

    const auto& expected = expected_pieces[piece];
    EXPECT_EQ(draw_info.destination, expected.destination);
    EXPECT_EQ(draw_info.source, expected.source);

    if (expected.is_corner_piece)
      continue;

    EXPECT_FLOAT_EQ(draw_info.tile_scale.x(), expected.tile_scale_horizontal);
    EXPECT_FLOAT_EQ(draw_info.tile_scale.y(), expected.tile_scale_vertical);
    EXPECT_EQ(draw_info.tile_rule.vertical, expected.vertical_rule);
    EXPECT_EQ(draw_info.tile_rule.horizontal, expected.horizontal_rule);
  }
}

TEST_F(NinePieceImageGridTest, NinePieceImagePainting_ZoomedNarrowSlices) {
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  // Image slices are specified in CSS pixels.
  nine_piece.SetImageSlices(LengthBox(1, 1, 1, 1));
  nine_piece.SetFill(true);

  constexpr float zoom = 2.2f;
  const gfx::SizeF image_size(3 * zoom, 3 * zoom);
  const gfx::Rect border_image_area(0, 0, 220, 220);
  const gfx::Outsets border_widths(33);

  const float kSliceWidth = 2.203125f;  // 2.2f rounded to nearest LayoutUnit
  const float kSliceMiddleWidth =
      image_size.width() - kSliceWidth - kSliceWidth;
  // Relative locations of the "inside" of a certain edge.
  const float kSliceTop = kSliceWidth;
  const float kSliceRight = image_size.width() - kSliceWidth;
  const float kSliceBottom = image_size.height() - kSliceWidth;
  const float kSliceLeft = kSliceWidth;

  const float kTileScaleX = border_widths.left() / kSliceWidth;
  const float kTileScaleY = border_widths.top() / kSliceWidth;
  const float kTileMiddleScale =
      (border_image_area.width() - border_widths.left() -
       border_widths.right()) /
      kSliceMiddleWidth;

  NinePieceImageGrid grid(nine_piece, image_size, gfx::Vector2dF(zoom, zoom),
                          zoom, border_image_area, border_widths);

  struct ExpectedPiece {
    bool is_drawable;
    bool is_corner_piece;
    gfx::RectF destination;
    gfx::RectF source;
    float tile_scale_horizontal;
    float tile_scale_vertical;
    ENinePieceImageRule horizontal_rule;
    ENinePieceImageRule vertical_rule;
  };
  std::array<ExpectedPiece, kMaxPiece> expected_pieces = {{
      {true, true, gfx::RectF(0, 0, 33, 33),
       gfx::RectF(0, 0, kSliceWidth, kSliceWidth), 0, 0, kStretchImageRule,
       kStretchImageRule},
      {true, true, gfx::RectF(0, 187, 33, 33),
       gfx::RectF(0, kSliceBottom, kSliceWidth, kSliceWidth), 0, 0,
       kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(0, 33, 33, 154),
       gfx::RectF(0, kSliceTop, kSliceWidth, kSliceMiddleWidth), kTileScaleX,
       kTileScaleY, kStretchImageRule, kStretchImageRule},
      {true, true, gfx::RectF(187, 0, 33, 33),
       gfx::RectF(kSliceRight, 0, kSliceWidth, kSliceWidth), 0, 0,
       kStretchImageRule, kStretchImageRule},
      {true, true, gfx::RectF(187, 187, 33, 33),
       gfx::RectF(kSliceRight, kSliceBottom, kSliceWidth, kSliceWidth), 0, 0,
       kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(187, 33, 33, 154),
       gfx::RectF(kSliceRight, kSliceTop, kSliceWidth, kSliceMiddleWidth),
       kTileScaleX, kTileScaleY, kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(33, 0, 154, 33),
       gfx::RectF(kSliceLeft, 0, kSliceMiddleWidth, kSliceWidth), kTileScaleX,
       kTileScaleY, kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(33, 187, 154, 33),
       gfx::RectF(kSliceLeft, kSliceBottom, kSliceMiddleWidth, kSliceWidth),
       kTileScaleX, kTileScaleY, kStretchImageRule, kStretchImageRule},
      {true, false, gfx::RectF(33, 33, 154, 154),
       gfx::RectF(kSliceLeft, kSliceTop, kSliceMiddleWidth, kSliceMiddleWidth),
       kTileMiddleScale, kTileMiddleScale, kStretchImageRule,
       kStretchImageRule},
  }};

  for (NinePiece piece = kMinPiece; piece < kMaxPiece; ++piece) {
    NinePieceImageGrid::NinePieceDrawInfo draw_info =
        grid.GetNinePieceDrawInfo(piece);
    EXPECT_TRUE(draw_info.is_drawable);

    const auto& expected = expected_pieces[piece];
    EXPECT_FLOAT_EQ(draw_info.destination.x(), expected.destination.x());
    EXPECT_FLOAT_EQ(draw_info.destination.y(), expected.destination.y());
    EXPECT_FLOAT_EQ(draw_info.destination.width(),
                    expected.destination.width());
    EXPECT_FLOAT_EQ(draw_info.destination.height(),
                    expected.destination.height());
    EXPECT_FLOAT_EQ(draw_info.source.x(), expected.source.x());
    EXPECT_FLOAT_EQ(draw_info.source.y(), expected.source.y());
    EXPECT_FLOAT_EQ(draw_info.source.width(), expected.source.width());
    EXPECT_FLOAT_EQ(draw_info.source.height(), expected.source.height());

    if (expected.is_corner_piece)
      continue;

    EXPECT_FLOAT_EQ(draw_info.tile_scale.x(), expected.tile_scale_horizontal);
    EXPECT_FLOAT_EQ(draw_info.tile_scale.y(), expected.tile_scale_vertical);
    EXPECT_EQ(draw_info.tile_rule.vertical, expected.vertical_rule);
    EXPECT_EQ(draw_info.tile_rule.horizontal, expected.horizontal_rule);
  }
}

TEST_F(NinePieceImageGridTest,
       NinePieceImagePainting_ZoomedMiddleNoLeftRightEdge) {
  constexpr float zoom = 2;
  // A border-image where the left and right edges are collapsed (zero-width),
  // and thus not drawable, as well as zoomed.
  NinePieceImage nine_piece;
  nine_piece.SetImage(GeneratedImage());
  nine_piece.SetImageSlices(LengthBox(32, 0, 32, 0));
  nine_piece.SetBorderSlices(BorderImageLengthBox(32 * zoom, 0, 32 * zoom, 0));
  nine_piece.SetHorizontalRule(kStretchImageRule);
  nine_piece.SetVerticalRule(kRepeatImageRule);
  nine_piece.SetFill(true);

  gfx::SizeF image_size(32, 96);
  gfx::Rect border_image_area(24, 8, 128, 464);
  gfx::Outsets border_widths(0);

  NinePieceImageGrid grid(nine_piece, image_size, gfx::Vector2dF(1, 1), zoom,
                          border_image_area, border_widths);
  NinePieceImageGrid::NinePieceDrawInfo draw_info =
      grid.GetNinePieceDrawInfo(kMiddlePiece);
  EXPECT_TRUE(draw_info.is_drawable);
  // border-image-area-width / image-width (128 / 32)
  EXPECT_FLOAT_EQ(draw_info.tile_scale.x(), 4);
  // zoom (because no edges available to derive scale from)
  EXPECT_FLOAT_EQ(draw_info.tile_scale.y(), zoom);
}

}  // namespace
}  // namespace blink
```