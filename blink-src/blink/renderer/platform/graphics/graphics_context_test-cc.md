Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The request asks for the functionality of the `graphics_context_test.cc` file, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common usage errors.

**2. Initial Scan for Keywords and Structure:**

I'd start by quickly skimming the code for recognizable keywords:

* `#include`: Indicates dependencies on other files. This gives clues about what the file interacts with. Specifically, `graphics_context.h`, `gtest/gtest.h`, `bitmap_image.h`, `paint/...`, `path.h`, `text_run.h`, and `skia/...` stand out.
* `namespace blink`:  Confirms this is part of the Blink rendering engine.
* `TEST(...)`:  Clearly indicates this is a unit test file using the Google Test framework.
* `EXPECT_EQ(...)`, `EXPECT_OPAQUE_PIXELS...`:  These are assertion macros, confirming the testing nature.
* Function names like `Recording`, `UnboundedDrawsAreClipped`, and `GraphicsContextDarkModeTest`:  Suggest the specific functionalities being tested.
* `FillRect`, `Clip`, `DrawPath`: These point to drawing operations, likely related to rendering.
* `Color`, `AutoDarkMode`:  Related to visual properties.
* `SkBitmap`, `SkCanvas`:  Indicates the use of the Skia graphics library, Blink's rendering backend.

**3. Identifying Core Functionality (Purpose of the Tests):**

Based on the test names and the included headers, I can infer that this file tests the `GraphicsContext` class. Specifically, it checks:

* **Recording and playback of drawing operations:** The `Recording` test clearly demonstrates this.
* **Clipping:** The `UnboundedDrawsAreClipped` test verifies that drawing operations are constrained by clip regions.
* **Dark mode functionality:** The `GraphicsContextDarkModeTest` suite is dedicated to this. The different `DarkModeInversionAlgorithm` settings are important here.

**4. Connecting to Web Technologies:**

Now I need to link the `GraphicsContext` to JavaScript, HTML, and CSS:

* **`GraphicsContext` is the drawing API for the browser.**  When JavaScript code uses the `<canvas>` API, or when the browser renders HTML elements with CSS styles that involve drawing (e.g., backgrounds, borders, shadows), it internally uses the `GraphicsContext` (or an abstraction of it) to perform the actual drawing.
* **HTML:** The `<canvas>` element is the most direct link. The test's drawing of rectangles and paths mirrors what the `<canvas>` API allows.
* **CSS:**  CSS properties like `background-color`, `border`, `box-shadow`, `clip-path`, and filters all eventually translate into `GraphicsContext` operations. Dark mode itself is often triggered or controlled via CSS media queries or JavaScript logic.
* **JavaScript:**  The `<canvas>` API in JavaScript directly exposes methods that correspond to `GraphicsContext` operations (e.g., `fillRect`, `beginPath`, `lineTo`, `stroke`).

**5. Developing Examples and Logical Reasoning:**

For the logical reasoning, I need to pick a specific test case and show how it works. The `Recording` test is a good example.

* **Hypothesis:** If drawing commands are recorded and played back, the final output should be the combination of the recorded operations.
* **Input (Implicit):** The test sets up a `GraphicsContext`, starts recording, draws a red rectangle, stops recording, and then draws the recorded operations onto a bitmap. It then repeats this with a larger rectangle.
* **Output (Expected):** The pixels in the bitmap should reflect the drawings. The assertions (`EXPECT_OPAQUE_PIXELS_ONLY_IN_RECT`) verify this.

For the dark mode tests, the reasoning is about how different inversion algorithms affect colors. The examples show how black, white, red, and gray are transformed under different `DarkModeInversionAlgorithm` settings.

**6. Identifying Common Usage Errors:**

Think about how a web developer might misuse drawing APIs:

* **Forgetting to call `beginPath()`:**  This is a classic `<canvas>` mistake, leading to unexpected connected paths. While this test doesn't *directly* show this, it tests the underlying `GraphicsContext` which *could* be used incorrectly by a higher-level API.
* **Incorrect clipping:**  Drawing outside the intended area due to faulty clipping logic is a common issue. The `UnboundedDrawsAreClipped` test implicitly touches on this.
* **Misunderstanding blend modes:**  Not knowing how different blend modes interact can lead to unexpected visual results. While the test uses `SkBlendMode::kSrcOver` and `kSrcOut`, it hints at the complexity of blending.
* **Dark mode inconsistencies:** Applying dark mode incorrectly or inconsistently across elements can cause visual glitches. The dark mode tests specifically address the correctness of the underlying dark mode implementation.

**7. Structuring the Answer:**

Organize the information clearly:

* Start with a concise summary of the file's purpose.
* Detail the key functionalities it tests.
* Explain the connections to JavaScript, HTML, and CSS with concrete examples.
* Provide a logical reasoning example using one of the tests.
* List common usage errors related to the concepts tested in the file.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on the Skia details. I need to remember the request asks about *Blink's* `GraphicsContext` and its relation to web technologies. Skia is an implementation detail.
* I might initially forget to explicitly mention the `<canvas>` element as the primary HTML connection.
* I need to ensure my "logical reasoning" examples are clear and have explicit inputs and expected outputs.
* My "common errors" should relate to the *concepts* tested, even if the test doesn't directly show the error occurring.

By following this structured approach and thinking about the connections between the C++ code and the higher-level web technologies, I can arrive at a comprehensive and accurate answer.
这个文件 `graphics_context_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件，它专门用于测试 `blink::GraphicsContext` 类的功能。`GraphicsContext` 是 Blink 中用于执行各种绘图操作的核心类。

**主要功能:**

1. **测试 `GraphicsContext` 的绘图能力:**  该文件通过编写各种测试用例，来验证 `GraphicsContext` 是否能够正确地执行各种绘图操作，例如：
    * **填充矩形 (`FillRect`)**: 测试能否用指定的颜色填充一个矩形区域。
    * **裁剪 (`Clip`)**: 测试能否将后续的绘图操作限制在指定的区域内。
    * **绘制路径 (`DrawPath`)**: 测试能否按照指定的路径和样式进行绘制。
    * **记录和回放绘图操作 (`BeginRecording`, `EndRecording`)**: 测试能否将一系列绘图操作记录下来，并在之后重新执行。这对于性能优化和重绘机制非常重要。
    * **暗黑模式支持 (`GraphicsContextDarkModeTest`)**: 测试 `GraphicsContext` 在启用暗黑模式时的颜色转换和渲染行为。

2. **验证绘图操作的正确性:** 测试用例会绘制一些特定的图形，然后检查渲染结果是否符合预期。这通常涉及到检查目标区域的像素颜色值。

3. **确保在不同场景下的稳定性和可靠性:**  通过各种边界条件和异常情况的测试，确保 `GraphicsContext` 在各种情况下都能正常工作。

**与 JavaScript, HTML, CSS 的关系:**

`GraphicsContext` 是浏览器渲染引擎的核心组件，它直接参与将 HTML 结构和 CSS 样式转化为用户可见的图像。

* **HTML:** 当浏览器解析 HTML 页面时，会构建 DOM 树。对于需要渲染的内容，例如 `<div>` 元素的背景色、边框，或者 `<canvas>` 元素上的绘图操作，都会通过 `GraphicsContext` 来实现。
* **CSS:** CSS 样式定义了元素的视觉外观，例如颜色、大小、边框、背景等。这些样式信息最终会被传递给 `GraphicsContext`，由它来执行相应的绘图操作。例如，CSS 的 `background-color: red;` 会导致 `GraphicsContext` 调用填充矩形的操作，并将颜色设置为红色。
* **JavaScript:** JavaScript 可以通过 Canvas API 直接操作 `GraphicsContext` (或者它的封装)。`<canvas>` 元素提供了一个可以通过 JavaScript 访问的绘图表面。JavaScript 代码可以使用 Canvas API 的方法 (例如 `fillRect()`, `beginPath()`, `lineTo()`, `stroke()`) 来指示 `GraphicsContext` 执行特定的绘图操作。

**举例说明:**

1. **HTML 和 CSS 的关系:**
   假设有以下 HTML 和 CSS 代码：

   ```html
   <div id="box"></div>
   ```

   ```css
   #box {
     width: 100px;
     height: 50px;
     background-color: blue;
   }
   ```

   当浏览器渲染这个 `div` 元素时，渲染引擎会将 CSS 样式转化为 `GraphicsContext` 的操作，大致相当于调用 `context.FillRect(gfx::RectF(x, y, 100, 50), Color::kBlue, ...)`。

2. **JavaScript 和 Canvas 的关系:**
   假设有以下 HTML 和 JavaScript 代码：

   ```html
   <canvas id="myCanvas" width="200" height="100"></canvas>
   ```

   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');
   ctx.fillStyle = 'green';
   ctx.fillRect(10, 10, 80, 30);
   ```

   这段 JavaScript 代码会获取 Canvas 的 2D 渲染上下文，然后调用 `fillRect()` 方法。这个方法最终会调用 Blink 内部的 `GraphicsContext` 的相应方法来填充一个绿色的矩形。

**逻辑推理和假设输入/输出:**

以下以 `TEST(GraphicsContextTest, Recording)` 这个测试用例为例进行说明：

* **假设输入:**
    * 创建一个 100x100 的黑色位图 (`bitmap.eraseColor(0);`)。
    * 创建一个 `GraphicsContext` 对象。
    * 开始记录绘图操作 (`context.BeginRecording();`)。
    * 绘制一个红色的 50x50 矩形 (`context.FillRect(gfx::RectF(0, 0, 50, 50), opaque, ...);`)。
    * 结束记录 (`context.EndRecording();`)，得到一个记录对象。
    * 将记录对象绘制到之前的位图上 (`canvas.drawPicture(...)`)。
    * 再次开始记录。
    * 绘制一个红色的 100x100 矩形。
    * 结束记录。
    * 将第二次记录绘制到位图上。

* **逻辑推理:**  记录功能应该允许我们先将一系列绘图操作缓存起来，然后在需要的时候一次性执行。第一次记录绘制了一个小矩形，第二次绘制了一个大矩形。因此，最终的位图上应该只显示最后一次绘制的大矩形，因为它覆盖了之前的绘制。然而，测试用例中先绘制了第一次记录，再绘制了第二次。

* **预期输出:**
    * 在第一次调用 `canvas.drawPicture(context.EndRecording());` 后，位图的左上角 50x50 区域应该是红色（不透明像素）。
    * 在第二次调用 `canvas.drawPicture(context.EndRecording());` 后，整个 100x100 的位图都应该是红色（不透明像素）。测试用例中通过 `EXPECT_OPAQUE_PIXELS_ONLY_IN_RECT` 宏来验证像素的透明度。

**用户或编程常见的使用错误:**

1. **Canvas 上下文获取失败:** 在 JavaScript 中使用 Canvas API 时，如果尝试获取不支持的上下文类型 (例如 `"webgl"` 在不支持的浏览器上)，或者 Canvas 元素本身不存在，`getContext()` 方法会返回 `null`，导致后续的绘图操作失败。

   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('invalid-context'); // 常见错误：使用无效的上下文
   if (!ctx) {
     console.error('无法获取 Canvas 上下文');
     return;
   }
   ctx.fillStyle = 'red'; // 如果 ctx 为 null，这里会报错
   ```

2. **忘记调用 `beginPath()`:** 在 Canvas 中绘制复杂图形时，经常需要使用路径。如果忘记在开始绘制新的子路径之前调用 `beginPath()`，新的路径可能会连接到之前的路径上，导致意外的绘制结果。

   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');

   ctx.rect(10, 10, 50, 50);
   ctx.stroke(); // 绘制第一个矩形

   // 忘记调用 beginPath()
   ctx.rect(70, 10, 50, 50); // 错误：可能会连接到第一个矩形
   ctx.stroke(); // 绘制第二个矩形
   ```

3. **不理解坐标系统和变换:** Canvas 的坐标系统和变换 (例如 `translate()`, `rotate()`, `scale()`) 如果使用不当，会导致绘制的元素出现在错误的位置或具有错误的尺寸和方向。

   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');

   ctx.translate(50, 50); // 将原点移动到 (50, 50)
   ctx.fillRect(0, 0, 20, 20); // 实际上绘制在 (50, 50) 到 (70, 70) 的位置

   // 忘记重置变换可能导致后续绘制错乱
   ```

4. **暗黑模式处理不当:** 在涉及暗黑模式的开发中，如果开发者没有正确处理颜色反转或调整，可能会导致在暗黑模式下颜色显示异常，对比度不足，或者某些元素不可见。`GraphicsContextDarkModeTest` 就是为了确保 Blink 内部的暗黑模式处理是正确的。开发者需要确保他们的 CSS 样式和 JavaScript 代码也能正确适配暗黑模式，例如使用 CSS 媒体查询 `prefers-color-scheme: dark`。

总之，`graphics_context_test.cc` 是 Blink 渲染引擎中一个至关重要的测试文件，它确保了核心绘图功能的正确性和稳定性，这直接关系到网页在浏览器中的正确渲染。 理解它的功能有助于开发者更好地理解浏览器的工作原理以及如何避免常见的绘图错误。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/graphics_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/platform/graphics/graphics_context.h"

#include <memory>

#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/text/text_run.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkShader.h"

namespace blink {
namespace {

#define EXPECT_EQ_RECT(a, b)       \
  EXPECT_EQ(a.x(), b.x());         \
  EXPECT_EQ(a.y(), b.y());         \
  EXPECT_EQ(a.width(), b.width()); \
  EXPECT_EQ(a.height(), b.height());

#define EXPECT_OPAQUE_PIXELS_IN_RECT(bitmap, opaqueRect)          \
  {                                                               \
    for (int y = opaqueRect.y(); y < opaqueRect.bottom(); ++y)    \
      for (int x = opaqueRect.x(); x < opaqueRect.right(); ++x) { \
        int alpha = *bitmap.getAddr32(x, y) >> 24;                \
        EXPECT_EQ(255, alpha);                                    \
      }                                                           \
  }

#define EXPECT_OPAQUE_PIXELS_ONLY_IN_RECT(bitmap, opaqueRect) \
  {                                                           \
    for (int y = 0; y < bitmap.height(); ++y)                 \
      for (int x = 0; x < bitmap.width(); ++x) {              \
        int alpha = *bitmap.getAddr32(x, y) >> 24;            \
        bool is_opaque = opaqueRect.Contains(x, y);           \
        EXPECT_EQ(is_opaque, alpha == 255);                   \
      }                                                       \
  }

AutoDarkMode AutoDarkModeDisabled() {
  return AutoDarkMode(DarkModeFilter::ElementRole::kBackground, false);
}

TEST(GraphicsContextTest, Recording) {
  SkBitmap bitmap;
  bitmap.allocN32Pixels(100, 100);
  bitmap.eraseColor(0);
  SkiaPaintCanvas canvas(bitmap);

  PaintController paint_controller;
  GraphicsContext context(paint_controller);

  Color opaque = Color::FromRGBA(255, 0, 0, 255);

  context.BeginRecording();
  context.FillRect(gfx::RectF(0, 0, 50, 50), opaque, AutoDarkModeDisabled(),
                   SkBlendMode::kSrcOver);
  canvas.drawPicture(context.EndRecording());
  EXPECT_OPAQUE_PIXELS_ONLY_IN_RECT(bitmap, gfx::Rect(0, 0, 50, 50))

  context.BeginRecording();
  context.FillRect(gfx::RectF(0, 0, 100, 100), opaque, AutoDarkModeDisabled(),
                   SkBlendMode::kSrcOver);
  // Make sure the opaque region was unaffected by the rect drawn during
  // recording.
  EXPECT_OPAQUE_PIXELS_ONLY_IN_RECT(bitmap, gfx::Rect(0, 0, 50, 50))

  canvas.drawPicture(context.EndRecording());
  EXPECT_OPAQUE_PIXELS_ONLY_IN_RECT(bitmap, gfx::Rect(0, 0, 100, 100))
}

TEST(GraphicsContextTest, UnboundedDrawsAreClipped) {
  SkBitmap bitmap;
  bitmap.allocN32Pixels(400, 400);
  bitmap.eraseColor(0);
  SkiaPaintCanvas canvas(bitmap);

  Color opaque = Color::FromRGBA(255, 0, 0, 255);
  Color transparent = Color::kTransparent;

  PaintController paint_controller;
  GraphicsContext context(paint_controller);
  context.BeginRecording();

  context.SetShouldAntialias(false);

  // Make the device opaque in 10,10 40x40.
  context.FillRect(gfx::RectF(10, 10, 40, 40), opaque, AutoDarkModeDisabled(),
                   SkBlendMode::kSrcOver);
  canvas.drawPicture(context.EndRecording());
  EXPECT_OPAQUE_PIXELS_ONLY_IN_RECT(bitmap, gfx::Rect(10, 10, 40, 40));

  context.BeginRecording();
  // Clip to the left edge of the opaque area.
  context.Clip(gfx::Rect(10, 10, 10, 40));

  // Draw a path that gets clipped. This should destroy the opaque area, but
  // only inside the clip.
  Path path;
  path.MoveTo(gfx::PointF(10, 10));
  path.AddLineTo(gfx::PointF(40, 40));
  cc::PaintFlags flags;
  flags.setColor(transparent.Rgb());
  flags.setBlendMode(SkBlendMode::kSrcOut);
  context.DrawPath(path.GetSkPath(), flags, AutoDarkModeDisabled());

  canvas.drawPicture(context.EndRecording());
  EXPECT_OPAQUE_PIXELS_IN_RECT(bitmap, gfx::Rect(20, 10, 30, 40));
}

class GraphicsContextDarkModeTest : public testing::Test {
 protected:
  void SetUp() override {
    bitmap_.allocN32Pixels(4, 1);
    bitmap_.eraseColor(0);
    canvas_ = std::make_unique<SkiaPaintCanvas>(bitmap_);
  }

  void DrawColorsToContext(bool is_dark_mode_on,
                           const DarkModeSettings& settings) {
    PaintController paint_controller;
    GraphicsContext context(paint_controller);
    if (is_dark_mode_on)
      context.UpdateDarkModeSettingsForTest(settings);
    context.BeginRecording();
    context.FillRect(gfx::RectF(0, 0, 1, 1), Color::kBlack,
                     AutoDarkMode(DarkModeFilter::ElementRole::kBackground,
                                  is_dark_mode_on));
    context.FillRect(gfx::RectF(1, 0, 1, 1), Color::kWhite,
                     AutoDarkMode(DarkModeFilter::ElementRole::kBackground,
                                  is_dark_mode_on));
    context.FillRect(gfx::RectF(2, 0, 1, 1), Color::FromSkColor(SK_ColorRED),
                     AutoDarkMode(DarkModeFilter::ElementRole::kBackground,
                                  is_dark_mode_on));
    context.FillRect(gfx::RectF(3, 0, 1, 1), Color::FromSkColor(SK_ColorGRAY),
                     AutoDarkMode(DarkModeFilter::ElementRole::kBackground,
                                  is_dark_mode_on));
    // Capture the result in the bitmap.
    canvas_->drawPicture(context.EndRecording());
  }

  SkBitmap bitmap_;
  std::unique_ptr<SkiaPaintCanvas> canvas_;
};

// This is a baseline test where dark mode is turned off. Compare other variants
// of the test where dark mode is enabled.
TEST_F(GraphicsContextDarkModeTest, DarkModeOff) {
  DarkModeSettings settings;

  DrawColorsToContext(false, settings);

  EXPECT_EQ(SK_ColorBLACK, bitmap_.getColor(0, 0));
  EXPECT_EQ(SK_ColorWHITE, bitmap_.getColor(1, 0));
  EXPECT_EQ(SK_ColorRED, bitmap_.getColor(2, 0));
  EXPECT_EQ(SK_ColorGRAY, bitmap_.getColor(3, 0));
}

// Simple invert for testing. Each color component |c|
// is replaced with |255 - c| for easy testing.
TEST_F(GraphicsContextDarkModeTest, SimpleInvertForTesting) {
  DarkModeSettings settings;
  settings.mode = DarkModeInversionAlgorithm::kSimpleInvertForTesting;
  settings.contrast = 0;

  DrawColorsToContext(true, settings);

  EXPECT_EQ(SK_ColorWHITE, bitmap_.getColor(0, 0));
  EXPECT_EQ(SK_ColorBLACK, bitmap_.getColor(1, 0));
  EXPECT_EQ(SK_ColorCYAN, bitmap_.getColor(2, 0));
  EXPECT_EQ(0xff777777, bitmap_.getColor(3, 0));
}

// Invert brightness (with gamma correction).
TEST_F(GraphicsContextDarkModeTest, InvertBrightness) {
  DarkModeSettings settings;
  settings.mode = DarkModeInversionAlgorithm::kInvertBrightness;
  settings.contrast = 0;

  DrawColorsToContext(true, settings);

  EXPECT_EQ(SK_ColorWHITE, bitmap_.getColor(0, 0));
  EXPECT_EQ(SK_ColorBLACK, bitmap_.getColor(1, 0));
  EXPECT_EQ(SK_ColorCYAN, bitmap_.getColor(2, 0));
  EXPECT_EQ(0xffe1e1e1, bitmap_.getColor(3, 0));
}

// Invert lightness (in HSL space).
TEST_F(GraphicsContextDarkModeTest, InvertLightness) {
  DarkModeSettings settings;
  settings.mode = DarkModeInversionAlgorithm::kInvertLightness;
  settings.contrast = 0;

  DrawColorsToContext(true, settings);

  EXPECT_EQ(SK_ColorWHITE, bitmap_.getColor(0, 0));
  EXPECT_EQ(SK_ColorBLACK, bitmap_.getColor(1, 0));
  EXPECT_EQ(SK_ColorRED, bitmap_.getColor(2, 0));
  EXPECT_EQ(0xffe1e1e1, bitmap_.getColor(3, 0));
}

TEST_F(GraphicsContextDarkModeTest, InvertLightnessPlusContrast) {
  DarkModeSettings settings;
  settings.mode = DarkModeInversionAlgorithm::kInvertLightness;
  settings.contrast = 0.2;

  DrawColorsToContext(true, settings);

  EXPECT_EQ(SK_ColorWHITE, bitmap_.getColor(0, 0));
  EXPECT_EQ(SK_ColorBLACK, bitmap_.getColor(1, 0));
  EXPECT_EQ(SK_ColorRED, bitmap_.getColor(2, 0));
  EXPECT_EQ(0xfff1f1f1, bitmap_.getColor(3, 0));
}

}  // namespace
}  // namespace blink

"""

```