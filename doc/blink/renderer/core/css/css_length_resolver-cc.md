Response:
Let's break down the thought process for analyzing the `css_length_resolver.cc` file.

1. **Understanding the Goal:** The request asks for a comprehensive analysis of the provided C++ code. This includes its function, its relationship to web technologies, examples of its use, common errors, and debugging information.

2. **Initial Code Scan:** The first step is to quickly read through the code to get a general idea of what it does. Keywords like "Viewport," "Container," "Percent," and the presence of various `UnitType` cases in the `ZoomedComputedPixels` function immediately suggest that this code is involved in calculating CSS length values. The filename `css_length_resolver.cc` reinforces this idea.

3. **Identifying Core Functionality:**  Focusing on the individual functions, we see a clear pattern. There are groups of functions calculating percentages of different viewport sizes (normal, small, large, dynamic) and container sizes. The `ZoomedComputedPixels` function is clearly the core logic, taking a value and a unit type and returning a calculated pixel value, considering zoom.

4. **Relating to Web Technologies:** Now, the goal is to connect this C++ code to the world of web development.

    * **CSS:**  The function names like `ViewportWidthPercent`, `ContainerHeightPercent`, and the handling of CSS `UnitType` constants directly link to CSS length units (vw, vh, container queries, px, cm, etc.). This forms the basis of the "Relationship to CSS" section.

    * **JavaScript:**  JavaScript interacts with CSS styles. When JavaScript manipulates element styles (e.g., using `element.style.width = '50vw'`), the browser needs to resolve these CSS length values into concrete pixel values. This resolution process is where `CSSLengthResolver` comes into play. This leads to the "Relationship to JavaScript" section.

    * **HTML:** HTML provides the structure to which CSS is applied. The size of the viewport and the dimensions of containing elements, which are crucial inputs for `CSSLengthResolver`, are ultimately determined by the HTML structure and the browser window size. This justifies the "Relationship to HTML" section.

5. **Creating Examples and Scenarios:** To illustrate the functionality, concrete examples are needed.

    * **Simple Viewport Units:**  Using `vw` and `vh` is a straightforward way to demonstrate the viewport-related functions. The example clarifies how these units respond to browser window resizing.

    * **Container Queries:** Demonstrating container queries requires defining a container element and then styling a child element using container units (`cqw`, `cqh`). This shows the code's role in resolving lengths relative to specific container dimensions.

    * **`ZoomedComputedPixels`:**  To show how this function works, choose a few different unit types (like `px`, `cm`, `vw`) and demonstrate the calculation. Make sure to include the zoom factor in the calculation.

6. **Identifying Potential Errors:** Think about what could go wrong when using CSS length units.

    * **Typos:**  Incorrectly typing CSS units is a very common mistake.

    * **Incorrect Container Context:**  Container queries won't work if the parent element isn't explicitly set as a container.

    * **Unexpected Zoom Levels:**  Users might have their browser zoomed in or out, which can affect layout if not considered.

7. **Debugging Scenarios:** Consider how a developer might end up investigating this code.

    * **Layout Issues:**  If elements aren't sized correctly, developers might start inspecting the computed styles. This would eventually lead to the length resolution logic.

    * **Responsiveness Problems:**  Issues with how layouts adapt to different screen sizes or orientations could involve debugging how viewport units are being calculated.

    * **Container Query Problems:** When container queries don't behave as expected, understanding how the container dimensions are being determined becomes crucial.

8. **Structuring the Answer:** Organize the information logically with clear headings. Start with the core function, then move to the relationships with web technologies, followed by examples, potential errors, and debugging information.

9. **Refinement and Detail:**  Go back through the answer and add more detail and clarity. For instance, explicitly mention that `CSSLengthResolver` is a *helper class*. In the debugging section, describe the typical steps a developer would take. Ensure the examples are clear and concise.

10. **Self-Correction/Review:**  Read through the generated answer as if you were someone else trying to understand the code. Are there any ambiguities? Is anything unclear?  For example, initially, I might not have explicitly mentioned that the `IsHorizontalWritingMode()` function influences the inline and block size calculations. Realizing this is important, I would add it to the explanation.

By following this methodical approach, combining code analysis with knowledge of web technologies and debugging practices, you can generate a comprehensive and accurate explanation of the `css_length_resolver.cc` file.
好的，让我们来分析一下 `blink/renderer/core/css/css_length_resolver.cc` 文件的功能。

**文件功能总览**

`CSSLengthResolver` 类是 Blink 渲染引擎中负责解析和计算 CSS 长度值的核心组件。它的主要职责是将各种 CSS 长度单位（例如像素、百分比、视口单位、容器单位等）转换为最终的像素值，以便渲染引擎可以正确地布局和绘制页面元素。

**具体功能分解**

1. **提供各种上下文信息:** `CSSLengthResolver` 类持有一些重要的上下文信息，这些信息对于解析 CSS 长度至关重要。虽然代码片段中没有直接显示这些成员变量，但从函数名可以推断出它能够访问：
    * **视口尺寸:**  `ViewportWidth()`, `ViewportHeight()`, `SmallViewportWidth()`, `SmallViewportHeight()`, `LargeViewportWidth()`, `LargeViewportHeight()`, `DynamicViewportWidth()`, `DynamicViewportHeight()` 等方法表明它可以获取不同类型的视口尺寸。这些尺寸用于解析视口相关的长度单位 (vw, vh, svw, svh, lvw, lvh, dvw, dvh 等)。
    * **书写模式:** `IsHorizontalWritingMode()` 方法表明它可以知道当前的文本书写方向（水平或垂直），这影响到内联尺寸 (inline-size) 和块状尺寸 (block-size) 的计算。
    * **容器尺寸:** `ContainerWidth()`, `ContainerHeight()` 方法表明它可以获取 CSS 容器查询 (Container Queries) 中定义的容器元素的尺寸，用于解析容器相关的长度单位 (cqw, cqh, cqi, cqb 等)。
    * **缩放比例:** `Zoom()` 方法表明它能获取当前的页面缩放比例，用于调整像素相关的长度值。
    * **字体相关信息:**  `EmFontSize()`, `ExFontSize()`, `RexFontSize()`, `RemFontSize()`, `ChFontSize()`, `RchFontSize()`, `IcFontSize()`, `RicFontSize()`, `LineHeight()`, `RootLineHeight()`, `CapFontSize()`, `RcapFontSize()` 等方法表明它可以获取与字体相关的尺寸信息，用于解析 em, ex, rem, ch, lh 等字体相对单位。

2. **计算百分比值:**  文件中定义了一系列返回百分比值的函数，例如 `ViewportWidthPercent()`, `ViewportHeightPercent()`, `ContainerWidthPercent()`, `ContainerHeightPercent()` 等。这些函数将实际的尺寸除以 100，得到一个 1% 对应的像素值。这为后续基于百分比的长度计算提供了基础。

3. **`ZoomedComputedPixels` 函数:**  这是核心函数，它接收一个数值和一个 CSS 单位类型，并返回经过缩放调整后的最终像素值。
    * **处理绝对长度单位:**  对于像素 (`kPixels`, `kUserUnits`) 和其他绝对长度单位 (cm, mm, in, pt, pc)，它会将数值乘以相应的像素转换系数，并应用当前的缩放比例。
    * **处理视口相对单位:** 对于视口相关的单位 (vw, vh, vmin, vmax, svw, svh, lvmin, lvmax, dvw, dvh 等)，它会调用相应的百分比计算函数，并将结果乘以数值和缩放比例。
    * **处理容器相对单位:** 对于容器相关的单位 (cqw, cqh, cqi, cqb, cqmin, cqmax)，它会调用相应的容器百分比计算函数，并将结果乘以数值和缩放比例。
    * **处理字体相对单位:** 对于字体相对单位 (em, ex, rem, ch, lh 等)，它会调用相应的字体尺寸获取函数，这些函数通常已经考虑了缩放因素，因此 `ZoomedComputedPixels` 函数只需要将结果乘以数值。
    * **处理书写模式:**  对于内联尺寸和块状尺寸的计算 (vi, vb, svi, svb, lvi, lvb, dvi, dvb, cqi, cqb)，它会根据当前的 `IsHorizontalWritingMode()` 决定使用宽度还是高度进行计算。

**与 JavaScript, HTML, CSS 的关系**

`CSSLengthResolver` 处于渲染引擎的核心位置，直接参与了浏览器将 HTML、CSS 代码转化为用户可见页面的过程。

* **CSS:** `CSSLengthResolver` 的主要任务就是解析 CSS 中声明的各种长度值。例如，当 CSS 规则中出现 `width: 50vw;` 时，渲染引擎会调用 `CSSLengthResolver` 的相关方法（例如 `ViewportWidthPercent()` 和 `ZoomedComputedPixels()`）来计算出 `50vw` 对应的实际像素值。

   **举例:**
   ```css
   .element {
     width: 100px;
     height: 50vh;
     font-size: 1.2em;
   }
   ```
   在这个例子中，`CSSLengthResolver` 会参与计算 `100px` 的实际像素值（可能需要考虑缩放），计算 `50vh` 对应的高度（依赖于视口高度），以及计算 `1.2em` 对应的字体大小（依赖于当前元素的字体大小）。

* **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式。当 JavaScript 代码修改元素的长度属性时，例如：
   ```javascript
   element.style.width = '75%';
   ```
   浏览器仍然需要使用 `CSSLengthResolver` 来解析这个百分比值。在这种情况下，`CSSLengthResolver` 需要知道这个元素的包含块 (containing block) 的尺寸，才能计算出 `75%` 对应的像素值。

   **举例:**
   ```javascript
   const div = document.getElementById('myDiv');
   div.style.width = '50vw'; // JavaScript 设置宽度为视口宽度的一半
   ```
   当执行这段 JavaScript 代码后，渲染引擎会调用 `CSSLengthResolver`，获取当前的视口宽度，计算出 `50vw` 的像素值，并最终应用到 `div` 元素的宽度上。

* **HTML:** HTML 结构定义了页面的元素以及它们的层级关系，这会影响到 CSS 长度单位的解析。例如，百分比单位的计算依赖于父元素的尺寸，而视口单位依赖于浏览器窗口的尺寸。HTML 结构为 `CSSLengthResolver` 提供了计算上下文。

   **举例:**
   ```html
   <div style="width: 200px;">
     <p style="width: 50%;">This is a paragraph.</p>
   </div>
   ```
   在这个例子中，`p` 元素的宽度是其父元素 `div` 宽度的 50%。`CSSLengthResolver` 需要知道 `div` 元素的实际宽度（可能也是通过 `CSSLengthResolver` 计算得到的），才能计算出 `p` 元素的宽度。

**逻辑推理的假设输入与输出**

假设我们有以下 CSS 规则：

```css
.box {
  width: 50vw;
  height: 100px;
  font-size: 16px; /* 假设默认字体大小 */
}
```

并且假设：
* 浏览器窗口宽度 (ViewportWidth) 为 1000px
* 页面缩放比例 (Zoom) 为 1.0
* 书写模式为水平

**对于 `width: 50vw;`:**

* **输入到 `CSSLengthResolver`:**
    * `value`: 50
    * `type`: `CSSPrimitiveValue::UnitType::kViewportWidth`
    * 当前的 `CSSLengthResolver` 对象，其中包含视口宽度 1000px 和缩放比例 1.0。
* **`CSSLengthResolver` 内部逻辑:**
    1. `ViewportWidthPercent()` 返回 `1000 / 100 = 10`。
    2. `ZoomedComputedPixels(50, kViewportWidth)` 计算 `50 * 10 * 1.0 = 500`。
* **输出:** 宽度将被解析为 `500px`。

**对于 `height: 100px;`:**

* **输入到 `CSSLengthResolver`:**
    * `value`: 100
    * `type`: `CSSPrimitiveValue::UnitType::kPixels`
    * 当前的 `CSSLengthResolver` 对象，其中包含缩放比例 1.0。
* **`CSSLengthResolver` 内部逻辑:**
    1. `ZoomedComputedPixels(100, kPixels)` 计算 `100 * 1.0 = 100`。
* **输出:** 高度将被解析为 `100px`。

**用户或编程常见的使用错误**

1. **拼写错误的 CSS 单位:**  用户可能会错误地输入 CSS 单位，例如 `widht: 100px;` 或 `height: 50vhx;`。虽然 `CSSLengthResolver` 不负责语法检查，但后续的解析过程会因为无法识别单位而可能导致默认值或其他错误行为。

2. **容器查询上下文错误:**  在使用容器查询单位 (cqw, cqh 等) 时，如果父元素没有正确设置 `container-type` 或 `container-name`，`CSSLengthResolver` 可能无法找到正确的容器尺寸，导致容器相关的长度单位无法正确解析。

   **举例:**
   ```html
   <div class="container">
     <div style="width: 50cqw;"></div>
   </div>
   ```
   如果 `.container` 类没有设置 `container-type: inline-size;` 或其他容器属性，`50cqw` 将无法正确解析。

3. **对百分比单位理解不足:** 开发者可能会忘记百分比单位是相对于其包含块的尺寸计算的。如果一个元素的父元素没有明确的尺寸，那么该元素的百分比尺寸可能无法按预期工作。

   **举例:**
   ```html
   <div style="display: flex;">
     <div style="width: 50%;"></div>
   </div>
   ```
   在这个例子中，子 `div` 的宽度是相对于父 `div` 的，而父 `div` 的宽度由其内容决定，除非显式设置。这可能导致对 `50%` 的理解偏差。

4. **缩放影响的考虑不周:**  开发者可能没有意识到浏览器的页面缩放会影响到像素等绝对单位的实际显示大小。虽然 `CSSLengthResolver` 会考虑缩放，但开发者在布局时需要考虑到这种情况，特别是在处理像素精度要求较高的场景。

**用户操作如何一步步到达这里，作为调试线索**

假设用户在浏览网页时发现某个元素的尺寸不正确。以下是调试过程可能涉及 `css_length_resolver.cc` 的步骤：

1. **用户加载网页:** 用户在浏览器中输入网址或点击链接，浏览器开始解析 HTML、CSS 和 JavaScript。
2. **渲染引擎构建渲染树:** Blink 渲染引擎解析 HTML 和 CSS，构建渲染树，确定每个元素的大小、位置等样式属性。
3. **遇到需要解析的 CSS 长度值:**  在计算某个元素的样式时，渲染引擎遇到了一个需要解析的 CSS 长度值，例如 `width: 70vw;`。
4. **调用 `CSSLengthResolver`:** 渲染引擎会创建或获取一个 `CSSLengthResolver` 实例，并调用其相关方法来解析这个长度值。例如，会调用 `ViewportWidthPercent()` 获取当前视口宽度百分比，然后调用 `ZoomedComputedPixels()` 计算最终的像素值。
5. **尺寸计算错误或不符合预期:** 如果计算出的尺寸与预期不符，开发者可能会开始调试。
6. **开发者工具检查:** 开发者通常会打开浏览器的开发者工具，检查 "Elements" 面板中的 "Styles" 或 "Computed" 标签。
7. **查看计算后的样式:** 在 "Computed" 标签中，开发者可以看到元素最终计算出的像素值。如果这个值不正确，可能是 CSS 规则有问题，也可能是 `CSSLengthResolver` 在特定情况下的计算逻辑有问题。
8. **Blink 源码调试 (高级):**  如果开发者怀疑是 Blink 引擎本身的 bug，他们可能会下载 Chromium 源码，并尝试在 `css_length_resolver.cc` 文件中设置断点，来跟踪长度解析的具体过程。他们可能会关注：
    * **传入 `ZoomedComputedPixels` 的参数是否正确。**
    * **`ViewportWidth()`, `ContainerWidth()` 等方法返回的值是否符合预期。**
    * **`IsHorizontalWritingMode()` 的状态是否正确。**
    * **缩放比例 `Zoom()` 是否正确。**
9. **模拟不同的用户场景:** 开发者可能会尝试调整浏览器窗口大小、更改页面缩放比例、修改元素的包含块样式等，来观察 `CSSLengthResolver` 在不同场景下的行为。

总而言之，`css_length_resolver.cc` 文件是 Blink 渲染引擎中一个关键的组件，它负责将抽象的 CSS 长度单位转换为具体的像素值，是连接 CSS 样式定义和最终页面渲染的桥梁。理解它的功能对于深入理解浏览器渲染原理和调试 CSS 布局问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/css_length_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/css_length_resolver.h"

#include "third_party/blink/renderer/core/css/css_resolution_units.h"

namespace blink {

double CSSLengthResolver::ViewportWidthPercent() const {
  return ViewportWidth() / 100;
}

double CSSLengthResolver::ViewportHeightPercent() const {
  return ViewportHeight() / 100;
}

double CSSLengthResolver::ViewportInlineSizePercent() const {
  return (IsHorizontalWritingMode() ? ViewportWidth() : ViewportHeight()) / 100;
}

double CSSLengthResolver::ViewportBlockSizePercent() const {
  return (IsHorizontalWritingMode() ? ViewportHeight() : ViewportWidth()) / 100;
}

double CSSLengthResolver::ViewportMinPercent() const {
  return std::min(ViewportWidth(), ViewportHeight()) / 100;
}

double CSSLengthResolver::ViewportMaxPercent() const {
  return std::max(ViewportWidth(), ViewportHeight()) / 100;
}

double CSSLengthResolver::SmallViewportWidthPercent() const {
  return SmallViewportWidth() / 100;
}

double CSSLengthResolver::SmallViewportHeightPercent() const {
  return SmallViewportHeight() / 100;
}

double CSSLengthResolver::SmallViewportInlineSizePercent() const {
  return (IsHorizontalWritingMode() ? SmallViewportWidth()
                                    : SmallViewportHeight()) /
         100;
}

double CSSLengthResolver::SmallViewportBlockSizePercent() const {
  return (IsHorizontalWritingMode() ? SmallViewportHeight()
                                    : SmallViewportWidth()) /
         100;
}

double CSSLengthResolver::SmallViewportMinPercent() const {
  return std::min(SmallViewportWidth(), SmallViewportHeight()) / 100;
}

double CSSLengthResolver::SmallViewportMaxPercent() const {
  return std::max(SmallViewportWidth(), SmallViewportHeight()) / 100;
}

double CSSLengthResolver::LargeViewportWidthPercent() const {
  return LargeViewportWidth() / 100;
}

double CSSLengthResolver::LargeViewportHeightPercent() const {
  return LargeViewportHeight() / 100;
}

double CSSLengthResolver::LargeViewportInlineSizePercent() const {
  return (IsHorizontalWritingMode() ? LargeViewportWidth()
                                    : LargeViewportHeight()) /
         100;
}

double CSSLengthResolver::LargeViewportBlockSizePercent() const {
  return (IsHorizontalWritingMode() ? LargeViewportHeight()
                                    : LargeViewportWidth()) /
         100;
}

double CSSLengthResolver::LargeViewportMinPercent() const {
  return std::min(LargeViewportWidth(), LargeViewportHeight()) / 100;
}

double CSSLengthResolver::LargeViewportMaxPercent() const {
  return std::max(LargeViewportWidth(), LargeViewportHeight()) / 100;
}

double CSSLengthResolver::DynamicViewportWidthPercent() const {
  return DynamicViewportWidth() / 100;
}

double CSSLengthResolver::DynamicViewportHeightPercent() const {
  return DynamicViewportHeight() / 100;
}

double CSSLengthResolver::DynamicViewportInlineSizePercent() const {
  return (IsHorizontalWritingMode() ? DynamicViewportWidth()
                                    : DynamicViewportHeight()) /
         100;
}

double CSSLengthResolver::DynamicViewportBlockSizePercent() const {
  return (IsHorizontalWritingMode() ? DynamicViewportHeight()
                                    : DynamicViewportWidth()) /
         100;
}

double CSSLengthResolver::DynamicViewportMinPercent() const {
  return std::min(DynamicViewportWidth(), DynamicViewportHeight()) / 100;
}

double CSSLengthResolver::DynamicViewportMaxPercent() const {
  return std::max(DynamicViewportWidth(), DynamicViewportHeight()) / 100;
}

double CSSLengthResolver::ContainerWidthPercent() const {
  return ContainerWidth() / 100;
}

double CSSLengthResolver::ContainerHeightPercent() const {
  return ContainerHeight() / 100;
}

double CSSLengthResolver::ContainerInlineSizePercent() const {
  return IsHorizontalWritingMode() ? ContainerWidthPercent()
                                   : ContainerHeightPercent();
}

double CSSLengthResolver::ContainerBlockSizePercent() const {
  return IsHorizontalWritingMode() ? ContainerHeightPercent()
                                   : ContainerWidthPercent();
}

double CSSLengthResolver::ContainerMinPercent() const {
  return std::min(ContainerWidthPercent(), ContainerHeightPercent());
}

double CSSLengthResolver::ContainerMaxPercent() const {
  return std::max(ContainerWidthPercent(), ContainerHeightPercent());
}

double CSSLengthResolver::ZoomedComputedPixels(
    double value,
    CSSPrimitiveValue::UnitType type) const {
  switch (type) {
    case CSSPrimitiveValue::UnitType::kPixels:
    case CSSPrimitiveValue::UnitType::kUserUnits:
      return value * Zoom();

    case CSSPrimitiveValue::UnitType::kCentimeters:
      return value * kCssPixelsPerCentimeter * Zoom();

    case CSSPrimitiveValue::UnitType::kMillimeters:
      return value * kCssPixelsPerMillimeter * Zoom();

    case CSSPrimitiveValue::UnitType::kQuarterMillimeters:
      return value * kCssPixelsPerQuarterMillimeter * Zoom();

    case CSSPrimitiveValue::UnitType::kInches:
      return value * kCssPixelsPerInch * Zoom();

    case CSSPrimitiveValue::UnitType::kPoints:
      return value * kCssPixelsPerPoint * Zoom();

    case CSSPrimitiveValue::UnitType::kPicas:
      return value * kCssPixelsPerPica * Zoom();

    case CSSPrimitiveValue::UnitType::kViewportWidth:
      return value * ViewportWidthPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kViewportHeight:
      return value * ViewportHeightPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kViewportInlineSize:
      return value * ViewportInlineSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kViewportBlockSize:
      return value * ViewportBlockSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kViewportMin:
      return value * ViewportMinPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kViewportMax:
      return value * ViewportMaxPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kSmallViewportWidth:
      return value * SmallViewportWidthPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kSmallViewportHeight:
      return value * SmallViewportHeightPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kSmallViewportInlineSize:
      return value * SmallViewportInlineSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kSmallViewportBlockSize:
      return value * SmallViewportBlockSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kSmallViewportMin:
      return value * SmallViewportMinPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kSmallViewportMax:
      return value * SmallViewportMaxPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kLargeViewportWidth:
      return value * LargeViewportWidthPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kLargeViewportHeight:
      return value * LargeViewportHeightPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kLargeViewportInlineSize:
      return value * LargeViewportInlineSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kLargeViewportBlockSize:
      return value * LargeViewportBlockSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kLargeViewportMin:
      return value * LargeViewportMinPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kLargeViewportMax:
      return value * LargeViewportMaxPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kDynamicViewportWidth:
      return value * DynamicViewportWidthPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kDynamicViewportHeight:
      return value * DynamicViewportHeightPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kDynamicViewportInlineSize:
      return value * DynamicViewportInlineSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kDynamicViewportBlockSize:
      return value * DynamicViewportBlockSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kDynamicViewportMin:
      return value * DynamicViewportMinPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kDynamicViewportMax:
      return value * DynamicViewportMaxPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kContainerWidth:
      return value * ContainerWidthPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kContainerHeight:
      return value * ContainerHeightPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kContainerInlineSize:
      return value * ContainerInlineSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kContainerBlockSize:
      return value * ContainerBlockSizePercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kContainerMin:
      return value * ContainerMinPercent() * Zoom();

    case CSSPrimitiveValue::UnitType::kContainerMax:
      return value * ContainerMaxPercent() * Zoom();

    // Note that functions for font-relative units already account for the
    // zoom factor.
    case CSSPrimitiveValue::UnitType::kEms:
    case CSSPrimitiveValue::UnitType::kQuirkyEms:
      return value * EmFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kExs:
      return value * ExFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kRexs:
      return value * RexFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kRems:
      return value * RemFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kChs:
      return value * ChFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kRchs:
      return value * RchFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kIcs:
      return value * IcFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kRics:
      return value * RicFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kLhs:
      return value * LineHeight(Zoom());

    case CSSPrimitiveValue::UnitType::kRlhs:
      return value * RootLineHeight(Zoom());

    case CSSPrimitiveValue::UnitType::kCaps:
      return value * CapFontSize(Zoom());

    case CSSPrimitiveValue::UnitType::kRcaps:
      return value * RcapFontSize(Zoom());

    default:
      NOTREACHED();
  }
}

}  // namespace blink
```