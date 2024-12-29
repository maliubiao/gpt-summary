Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Understanding the Goal:**

The request asks for an analysis of the `css_to_length_conversion_data_test.cc` file. Specifically, it wants to know:

* **Functionality:** What does this file *do*?
* **Relation to Web Technologies:** How does it connect to JavaScript, HTML, and CSS?
* **Logic and Examples:** Can we infer the logic through examples of inputs and outputs?
* **User Errors:** What common mistakes might users make that relate to this code?
* **Debugging Context:** How does a user end up here during debugging?

**2. Initial Scan and Keyword Identification:**

I quickly scanned the code, looking for keywords and patterns. Key things that jumped out were:

* `#include`: Indicates dependencies and core functionality. `css_to_length_conversion_data.h`, `css_primitive_value.h`, `computed_style.h`, `element.h`, etc., all point to CSS and layout concepts.
* `namespace blink`:  Confirms it's part of the Blink rendering engine.
* `class CSSToLengthConversionDataTest`: Clearly a test file.
* `TEST_F`:  Indicates Google Test framework usage. Each `TEST_F` is an individual test case.
* `ConvertPx`, `ConvertLength`: Functions suggesting the core purpose is converting CSS length values to pixels.
* Specific CSS units mentioned: `px`, `em`, `rem`, `ex`, `ch`, `vw`, `vh`, `cqw`, `cqh`, `lh`, `rlh`, `cap`, `rcap`, `anchor()`, `anchor-size()`.
* `Zoom`:  Appears frequently, suggesting handling of page zoom.
* `Flags`: Hints at tracking which CSS units are used in a given value.
* `AnchorEvaluator`:  Indicates testing of CSS anchor positioning features.
* `SetLineHeightSize`, `SetFontSizes`:  Methods suggesting setting up the context for length conversions.

**3. Deducing Core Functionality:**

Based on the keywords and structure, I deduced the primary function: **This file tests the `CSSToLengthConversionData` class, which is responsible for converting CSS length values (like "1em", "10px", "50vh") into pixel values.**  This conversion is crucial for the browser's layout engine to determine the actual dimensions of elements on the page.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **CSS:** The file directly deals with CSS units and properties. The tests parse CSS values and verify their pixel equivalents. Examples like "1em", "10px", and the `anchor()` function are directly from CSS.
* **HTML:** The tests create simple HTML structures (`<div>`, `documentElement`) to set up the context for CSS calculations. The `ComputedStyle` is derived from HTML elements.
* **JavaScript:** While this specific test file doesn't have direct JavaScript, the functionality it tests is *essential* for JavaScript interactions. JavaScript often reads and manipulates CSS styles. When JavaScript gets the dimensions of an element (e.g., `element.offsetWidth`), the underlying calculation likely involves the `CSSToLengthConversionData` logic.

**5. Logic Inference and Examples:**

I looked at individual `TEST_F` blocks to understand the specific logic being tested. For instance:

* `TEST_F(CSSToLengthConversionDataTest, Normal)`: Tests basic unit conversions without any zoom. Input: CSS length string (e.g., "1em"). Output: Expected pixel value (e.g., 20.0f).
* `TEST_F(CSSToLengthConversionDataTest, Zoomed)`: Tests how `css_zoom` affects conversions. Input: CSS length string. Output: Scaled pixel value.
* `TEST_F(CSSToLengthConversionDataTest, AnchorFunction)`: Tests the `anchor()` CSS function. Input: `anchor()` CSS string. Output: Pixel value based on the `AnchorEvaluator`.
* `TEST_F(CSSToLengthConversionDataTest, Flags)`: Tests which CSS units trigger specific flags. Input: CSS length string. Output: A bitmask of flags.

By analyzing these tests, I could infer the underlying conversion logic for different CSS units and scenarios (like zoom and anchor positioning).

**6. Identifying Potential User Errors:**

I considered how a developer or user might interact with CSS and potentially cause issues related to length conversions:

* **Incorrect Units:** Using a unit that isn't supported or makes no sense in the context.
* **Typographical Errors:** Misspelling CSS units.
* **Incorrect `calc()` Syntax:** Errors in complex calculations.
* **Unexpected Zoom:** Not accounting for browser or page zoom.
* **Overriding Styles:** Conflicting CSS rules leading to unexpected computed values.
* **Misunderstanding Relative Units:** Not grasping how `em`, `rem`, `vh`, `vw`, etc., are calculated.

**7. Debugging Scenario:**

I thought about how a developer might end up investigating this code:

* **Layout Issues:** Elements not being the expected size or position.
* **Unexpected JavaScript Behavior:** JavaScript code that relies on element dimensions behaving strangely.
* **CSS Functionality Problems:** Issues with newer CSS features like container queries or anchor positioning.
* **Performance Issues:**  Inefficient or incorrect length conversions impacting rendering speed (though less directly visible in this *test* file).

The debugging process would involve inspecting the computed styles of elements, potentially stepping through the rendering engine's code, and examining the values used in length calculations.

**8. Structuring the Answer:**

Finally, I organized the findings into a clear and logical structure, addressing each part of the original request with specific examples and explanations. I used headings and bullet points to improve readability. I focused on providing concrete examples for each point, making the explanation more understandable.
这个文件 `css_to_length_conversion_data_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件。它的主要功能是 **测试 `CSSToLengthConversionData` 类的各种功能**。 `CSSToLengthConversionData` 类负责在 CSS 样式计算过程中，将 CSS 的长度值（例如 `10px`, `2em`, `50vh`）转换为具体的像素值。

更具体地说，这个测试文件会创建不同的测试场景，并使用 `CSSToLengthConversionData` 类来转换各种 CSS 长度值，然后验证转换结果是否符合预期。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关系到 **CSS** 的功能，因为它测试的是 CSS 长度值的转换。虽然它本身是用 C++ 写的，但它验证了浏览器对 CSS 的解析和计算是否正确，这直接影响了网页的渲染效果，而网页的结构和样式通常是由 **HTML** 和 **CSS** 定义的。**JavaScript** 可以读取和修改元素的 CSS 样式，因此 CSS 长度值的正确转换对于 JavaScript 与页面元素的交互至关重要。

**举例说明:**

1. **CSS 单位转换:**
   - **假设输入 CSS:**  `width: 1em; font-size: 20px;` (应用于一个 `<div>` 元素)
   - `CSSToLengthConversionData` 的功能是将 `1em` 转换为像素值。在这种情况下，`1em` 等于当前元素的 `font-size`，即 `20px`。测试会验证转换结果是否为 `20.0f`。
   - **测试用例:** `EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1em"));`

2. **相对单位转换 (rem):**
   - **假设输入 CSS:** `:root { font-size: 10px; } div { width: 1rem; }`
   - `CSSToLengthConversionData` 需要访问根元素 (`:root`) 的 `font-size` 来计算 `1rem` 的像素值。在这种情况下，`1rem` 等于根元素的 `font-size`，即 `10px`。
   - **测试用例:** `EXPECT_FLOAT_EQ(10.0f, ConvertPx(data, "1rem"));`

3. **视口单位转换 (vw, vh):**
   - **假设输入 CSS:** `div { height: 50vh; }`，假设视口高度为 `800px`。
   - `CSSToLengthConversionData` 需要知道当前视口的大小来计算 `50vh` 的像素值。在这种情况下，`50vh` 等于视口高度的 50%，即 `400px`。
   - **测试用例:** `EXPECT_EQ(sv, ConversionFlags("1svh"));` (这个测试用例验证了 `svh` 单位会设置 `kStaticViewport` 标志，表明它依赖于视口大小)。

4. **`calc()` 函数:**
   - **假设输入 CSS:** `width: calc(1em + 10px); font-size: 20px;`
   - `CSSToLengthConversionData` 需要先将 `1em` 转换为 `20px`，然后与 `10px` 相加，最终结果为 `30px`。
   - **测试用例:** `EXPECT_FLOAT_EQ(30.0f, ConvertPx(data, "calc(1em + 10px)"));`

5. **`anchor()` 和 `anchor-size()` 函数 (CSS Anchor Positioning):**
   - **假设输入 CSS:** `position: absolute; left: anchor(--my-anchor right);`
   - `CSSToLengthConversionData` 需要使用 `AnchorEvaluator` 来评估 `--my-anchor` 元素的 `right` 边缘的位置，并将其转换为像素值。
   - **测试用例:** `EXPECT_FLOAT_EQ(60.0f, ConvertPx(data, "anchor(--a left)", right));` (假设 `AnchorEvaluator` 返回了 `60px` 的结果)。

**逻辑推理和假设输入与输出:**

文件中的每个 `TEST_F` 都是一个独立的测试用例，用于验证 `CSSToLengthConversionData` 类的特定功能。

**假设输入与输出示例:**

| 测试用例                                   | 假设输入 CSS 长度值 | 假设上下文 (font-size, 视口大小等) | 预期输出像素值 |
|--------------------------------------------|----------------------|-----------------------------------|-------------|
| `TEST_F(CSSToLengthConversionDataTest, Normal)` | `"1px"`              | 无特殊上下文                        | `1.0f`      |
| `TEST_F(CSSToLengthConversionDataTest, Normal)` | `"1em"`              | 父元素 `font-size: 20px`           | `20.0f`     |
| `TEST_F(CSSToLengthConversionDataTest, Zoomed)` | `"1px"`              | `css_zoom = 2.0f`                   | `2.0f`      |
| `TEST_F(CSSToLengthConversionDataTest, AdjustedZoom)` | `"1em"`              | 父元素 `font-size: 20px`, adjusted zoom = `2.0f` | `40.0f`     |
| `TEST_F(CSSToLengthConversionDataTest, AnchorFunction)` | `"anchor(--a left)"` | `AnchorEvaluator` 返回 `60px`      | `60.0f`     |
| `TEST_F(CSSToLengthConversionDataTest, AnchorFunctionFallback)` | `"anchor(--a left, 42px)"` | `AnchorEvaluator` 返回 `null`      | `42.0f`     |

**涉及用户或者编程常见的使用错误，举例说明:**

1. **使用了错误的单位:** 用户可能会错误地使用不支持的 CSS 长度单位，或者在不适用的上下文中使用相对单位，导致计算结果不符合预期。例如，在一个没有设置 `font-size` 的元素上使用 `em` 单位，其计算结果可能会依赖于浏览器的默认字体大小，而不是用户的预期。

2. **`calc()` 函数语法错误:** 用户可能会在 `calc()` 函数中犯语法错误，例如缺少运算符或者使用了不兼容的单位进行计算，导致解析失败或计算错误。

3. **缩放 (Zoom) 的影响未考虑:** 用户可能没有意识到浏览器或页面缩放会影响像素值的计算，导致在不同缩放级别下看到不同的布局效果。

4. **相对单位的上下文理解错误:** 用户可能没有正确理解 `em`, `rem`, `vh`, `vw` 等相对单位的计算方式，例如混淆了 `em` 和 `rem` 的区别，或者没有考虑到视口大小的变化。

5. **CSS 属性的继承和层叠:**  用户可能会忽略 CSS 属性的继承和层叠规则，导致元素最终的样式值与预期不符，从而影响长度转换的结果。例如，父元素设置了 `font-size: 16px;`，子元素没有设置，则子元素的 `1em` 将会基于父元素的 `font-size` 计算。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

当开发者在调试网页布局或样式问题时，可能会遇到以下情况，从而需要查看或理解 `CSSToLengthConversionData` 的工作原理：

1. **页面元素大小或位置不符合预期:** 开发者可能会发现某个 HTML 元素的大小或位置与 CSS 中设置的值不一致。例如，一个设置了 `width: 50%` 的 `div` 元素，在不同的屏幕尺寸下显示的宽度可能与预期不同。

2. **JavaScript 获取元素尺寸错误:**  JavaScript 代码使用 `element.offsetWidth` 或 `element.getBoundingClientRect()` 等方法获取元素的尺寸时，得到的值与预期不符。这可能是因为 CSS 长度值转换过程中出现了问题。

3. **使用开发者工具检查元素样式:**  开发者可以使用浏览器的开发者工具（通常通过 F12 键打开）检查元素的“计算后样式 (Computed Style)”。如果发现计算后的像素值与预期的 CSS 值不一致，就可能需要深入了解长度转换的细节。

4. **调试 CSS 函数 (例如 `calc()`, `anchor()`):** 当使用了复杂的 CSS 函数时，开发者可能会遇到计算错误。例如，`calc(100% - 20px)` 的结果可能在某些情况下不符合预期。对于 `anchor()` 等新特性，如果定位不准确，开发者需要理解其计算过程。

5. **性能问题排查:** 虽然不常见，但理论上，复杂的 CSS 长度计算可能会影响页面渲染性能。如果怀疑是这方面的问题，开发者可能会查看 Blink 渲染引擎的相关代码。

**调试线索:**

当开发者遇到上述问题时，可能会通过以下步骤进行调试，最终可能需要理解 `CSSToLengthConversionData` 的作用：

1. **检查 CSS 样式:**  首先，开发者会检查应用于该元素的 CSS 规则，确认 CSS 值是否正确。

2. **检查计算后样式:** 使用开发者工具查看元素的“计算后样式”，确认浏览器最终计算出的像素值。

3. **尝试修改 CSS 值:**  开发者可能会尝试修改 CSS 值，观察页面变化，以缩小问题范围。

4. **使用开发者工具断点调试:**  如果问题比较复杂，开发者可能会在 JavaScript 代码中设置断点，检查获取到的元素尺寸，或者在 Blink 渲染引擎的源代码中设置断点（如果具备相关知识和环境）。

5. **查阅文档和资料:** 开发者可能会查阅 CSS 规范、浏览器文档以及相关的技术博客，了解 CSS 长度单位和计算的细节。

6. **搜索错误信息或相关问题:**  如果在开发者工具中看到错误或警告信息，或者在网上搜索到类似的问题，可能会引导开发者了解 `CSSToLengthConversionData` 负责的功能，因为它直接参与了 CSS 长度值到像素值的转换过程。

总而言之，`css_to_length_conversion_data_test.cc` 文件是 Blink 渲染引擎中用于确保 CSS 长度值正确转换的关键测试文件。理解其功能有助于开发者更好地理解浏览器如何处理 CSS 样式，并在遇到布局或样式问题时提供调试线索。

Prompt: 
```
这是目录为blink/renderer/core/css/css_to_length_conversion_data_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"

#include <optional>

#include "third_party/blink/renderer/core/css/anchor_evaluator.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/geometry/calculation_value.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

namespace {

// Evaluates any query to `result`.
class TestAnchorEvaluator : public AnchorEvaluator {
  STACK_ALLOCATED();

 public:
  explicit TestAnchorEvaluator(std::optional<LayoutUnit> result)
      : result_(result) {}

  std::optional<LayoutUnit> Evaluate(
      const AnchorQuery&,
      const ScopedCSSName* position_anchor,
      const std::optional<PositionAreaOffsets>&) override {
    return result_;
  }
  std::optional<PositionAreaOffsets> ComputePositionAreaOffsetsForLayout(
      const ScopedCSSName*,
      PositionArea) override {
    return PositionAreaOffsets();
  }
  std::optional<PhysicalOffset> ComputeAnchorCenterOffsets(
      const ComputedStyleBuilder&) override {
    return std::nullopt;
  }

 private:
  std::optional<LayoutUnit> result_;
};

}  // namespace

class CSSToLengthConversionDataTest : public PageTestBase {
 public:
  void SetUp() override {
    PageTestBase::SetUp();
    LoadAhem();
  }

  struct DataOptions {
    // The zoom to apply to :root.
    std::optional<float> css_zoom;
    // The zoom to pass to the CSSToLengthConversionData constructor.
    std::optional<float> data_zoom;
    // Used to evaluate anchor() and anchor-size() queries.
    AnchorEvaluator* anchor_evaluator = nullptr;
    // Any flags set by conversion is stored here.
    // See CSSToLengthConversionData::Flag.
    CSSToLengthConversionData::Flags* flags = nullptr;
  };

  // Set up a page with "Ahem 10px" as :root, and "Ahem 20px" at some <div>,
  // then return a CSSToLengthConversionData constructed from that.
  CSSToLengthConversionData ConversionData(DataOptions options) {
    Element* root = GetDocument().documentElement();
    DCHECK(root);
    if (options.css_zoom.has_value()) {
      root->SetInlineStyleProperty(CSSPropertyID::kZoom,
                                   String::Format("%f", *options.css_zoom));
    }
    root->SetInlineStyleProperty(CSSPropertyID::kFontSize, "10px");
    root->SetInlineStyleProperty(CSSPropertyID::kFontFamily, "Ahem");
    root->SetInlineStyleProperty(CSSPropertyID::kLineHeight, "5");
    auto* div = MakeGarbageCollected<HTMLDivElement>(GetDocument());
    div->SetInlineStyleProperty(CSSPropertyID::kFontSize, "20px");
    div->SetIdAttribute(AtomicString("div"));
    GetDocument().body()->AppendChild(div);
    GetDocument().body()->SetInlineStyleProperty(CSSPropertyID::kLineHeight,
                                                 "10");
    UpdateAllLifecyclePhasesForTest();

    return CSSToLengthConversionData(
        div->ComputedStyleRef(), GetDocument().body()->GetComputedStyle(),
        GetDocument().documentElement()->GetComputedStyle(),
        CSSToLengthConversionData::ViewportSize(GetDocument().GetLayoutView()),
        CSSToLengthConversionData::ContainerSizes(),
        CSSToLengthConversionData::AnchorData(
            options.anchor_evaluator,
            /* position_anchor */ nullptr,
            /* position_area_offsets */ std::nullopt),
        options.data_zoom.value_or(div->GetComputedStyle()->EffectiveZoom()),
        options.flags ? *options.flags : ignored_flags_, /*element=*/nullptr);
  }

  CSSToLengthConversionData ConversionData() {
    return ConversionData(DataOptions{});
  }

  // Parses the given string a <length>, and converts the result to a Length.
  //
  // A property may be specified to invoke the parsing behavior of that
  // specific property.
  Length ConvertLength(const CSSToLengthConversionData& data,
                       String value,
                       CSSPropertyID property_id = CSSPropertyID::kLeft) {
    const CSSValue* result = css_test_helpers::ParseLonghand(
        GetDocument(), CSSProperty::Get(property_id), value);
    CHECK(result);
    // Any tree-scoped references within `result` need to be populated with
    // their TreeScope. This is normally done by StyleCascade before length
    // conversion, and we're simulating that here.
    result = &result->EnsureScopedValue(&GetDocument());

    auto* primitive_value = DynamicTo<CSSPrimitiveValue>(result);
    DCHECK(primitive_value);

    return primitive_value->ConvertToLength(data);
  }

  float ConvertPx(const CSSToLengthConversionData& data,
                  String value,
                  CSSPropertyID property_id = CSSPropertyID::kLeft) {
    return ConvertLength(data, value, property_id).Pixels();
  }

  CSSToLengthConversionData::Flags ConversionFlags(String value) {
    CSSToLengthConversionData::Flags flags = 0;
    CSSToLengthConversionData data = ConversionData({.flags = &flags});
    ConvertPx(data, value);
    return flags;
  }

  void SetLineHeightSize(Element& element, CSSToLengthConversionData& data) {
    data.SetLineHeightSize(CSSToLengthConversionData::LineHeightSize(
        element.ComputedStyleRef().GetFontSizeStyle(),
        element.GetDocument().documentElement()->GetComputedStyle()));
  }

 private:
  CSSToLengthConversionData::Flags ignored_flags_ = 0;
};

TEST_F(CSSToLengthConversionDataTest, Normal) {
  CSSToLengthConversionData data = ConversionData();
  EXPECT_FLOAT_EQ(1.0f, ConvertPx(data, "1px"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1em"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1ex"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1ch"));
  EXPECT_FLOAT_EQ(10.0f, ConvertPx(data, "1rem"));
  EXPECT_FLOAT_EQ(8.0f, ConvertPx(data, "1rex"));
  EXPECT_FLOAT_EQ(10.0f, ConvertPx(data, "1rch"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1ic"));
  EXPECT_FLOAT_EQ(10.0f, ConvertPx(data, "1ric"));
  EXPECT_FLOAT_EQ(36.0f, ConvertPx(data, "calc(1em + 1ex)"));
  EXPECT_FLOAT_EQ(100.0f, ConvertPx(data, "1lh"));
  EXPECT_FLOAT_EQ(50.0f, ConvertPx(data, "1rlh"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1cap"));
  EXPECT_FLOAT_EQ(8.0f, ConvertPx(data, "1rcap"));
}

TEST_F(CSSToLengthConversionDataTest, Zoomed) {
  CSSToLengthConversionData data = ConversionData({.css_zoom = 2.0f});
  EXPECT_FLOAT_EQ(2.0f, ConvertPx(data, "1px"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1em"));
  EXPECT_FLOAT_EQ(32.0f, ConvertPx(data, "1ex"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1ch"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1rem"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1rex"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1rch"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1ic"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1ric"));
  EXPECT_FLOAT_EQ(72.0f, ConvertPx(data, "calc(1em + 1ex)"));
  EXPECT_FLOAT_EQ(200.0f, ConvertPx(data, "1lh"));
  EXPECT_FLOAT_EQ(100.0f, ConvertPx(data, "1rlh"));
  EXPECT_FLOAT_EQ(32.0f, ConvertPx(data, "1cap"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1rcap"));
}

TEST_F(CSSToLengthConversionDataTest, AdjustedZoom) {
  CSSToLengthConversionData data = ConversionData().CopyWithAdjustedZoom(2.0f);
  EXPECT_FLOAT_EQ(2.0f, ConvertPx(data, "1px"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1em"));
  EXPECT_FLOAT_EQ(32.0f, ConvertPx(data, "1ex"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1ch"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1rem"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1rex"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1rch"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1ic"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1ric"));
  EXPECT_FLOAT_EQ(72.0f, ConvertPx(data, "calc(1em + 1ex)"));
  EXPECT_FLOAT_EQ(200.0f, ConvertPx(data, "1lh"));
  EXPECT_FLOAT_EQ(100.0f, ConvertPx(data, "1rlh"));
  EXPECT_FLOAT_EQ(32.0f, ConvertPx(data, "1cap"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1rcap"));
}

TEST_F(CSSToLengthConversionDataTest, DifferentZoom) {
  // The zoom used to calculate fonts is different from the requested
  // zoom in the CSSToLengthConversionData constructor.
  CSSToLengthConversionData data =
      ConversionData({.css_zoom = 1.0f, .data_zoom = 2.0f});
  EXPECT_FLOAT_EQ(2.0f, ConvertPx(data, "1px"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1em"));
  EXPECT_FLOAT_EQ(32.0f, ConvertPx(data, "1ex"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1ch"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1rem"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1rex"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1rch"));
  EXPECT_FLOAT_EQ(40.0f, ConvertPx(data, "1ic"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1ric"));
  EXPECT_FLOAT_EQ(72.0f, ConvertPx(data, "calc(1em + 1ex)"));
  EXPECT_FLOAT_EQ(200.0f, ConvertPx(data, "1lh"));
  EXPECT_FLOAT_EQ(100.0f, ConvertPx(data, "1rlh"));
  EXPECT_FLOAT_EQ(32.0f, ConvertPx(data, "1cap"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1rcap"));
}

TEST_F(CSSToLengthConversionDataTest, Unzoomed) {
  CSSToLengthConversionData data =
      ConversionData({.css_zoom = 2.0f}).Unzoomed();
  EXPECT_FLOAT_EQ(1.0f, ConvertPx(data, "1px"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1em"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1ex"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1ch"));
  EXPECT_FLOAT_EQ(10.0f, ConvertPx(data, "1rem"));
  EXPECT_FLOAT_EQ(8.0f, ConvertPx(data, "1rex"));
  EXPECT_FLOAT_EQ(10.0f, ConvertPx(data, "1rch"));
  EXPECT_FLOAT_EQ(20.0f, ConvertPx(data, "1ic"));
  EXPECT_FLOAT_EQ(10.0f, ConvertPx(data, "1ric"));
  EXPECT_FLOAT_EQ(36.0f, ConvertPx(data, "calc(1em + 1ex)"));
  EXPECT_FLOAT_EQ(100.0f, ConvertPx(data, "1lh"));
  EXPECT_FLOAT_EQ(50.0f, ConvertPx(data, "1rlh"));
  EXPECT_FLOAT_EQ(16.0f, ConvertPx(data, "1cap"));
  EXPECT_FLOAT_EQ(8.0f, ConvertPx(data, "1rcap"));
}

TEST_F(CSSToLengthConversionDataTest, StyleLessContainerUnitConversion) {
  // No ComputedStyle associated.
  CSSToLengthConversionData data(/*element=*/nullptr);

  // Don't crash:
  ConvertPx(data, "1cqw");
  ConvertPx(data, "1cqh");
}

TEST_F(CSSToLengthConversionDataTest, SetLineHeightSize) {
  CSSToLengthConversionData data = ConversionData();
  EXPECT_FLOAT_EQ(100.0f, ConvertPx(data, "1lh"));
  Element* div = GetDocument().getElementById(AtomicString("div"));
  ASSERT_TRUE(div);
  SetLineHeightSize(*div, data);
  EXPECT_FLOAT_EQ(200.0f, ConvertPx(data, "1lh"));
}

TEST_F(CSSToLengthConversionDataTest, Flags) {
  using Flag = CSSToLengthConversionData::Flag;
  using Flags = CSSToLengthConversionData::Flags;

  Flags em = static_cast<Flags>(Flag::kEm);
  Flags rem = static_cast<Flags>(Flag::kRootFontRelative);
  Flags glyph = static_cast<Flags>(Flag::kGlyphRelative);
  Flags rex = rem | glyph | static_cast<Flags>(Flag::kRexRelative);
  Flags ch = glyph | static_cast<Flags>(Flag::kChRelative);
  Flags rch = rem | glyph | static_cast<Flags>(Flag::kRchRelative);
  Flags ic = glyph | static_cast<Flags>(Flag::kIcRelative);
  Flags ric = rem | glyph | static_cast<Flags>(Flag::kRicRelative);
  Flags cap = glyph | static_cast<Flags>(Flag::kCapRelative);
  Flags rcap = glyph | rem | static_cast<Flags>(Flag::kRcapRelative);
  Flags lh = glyph | static_cast<Flags>(Flag::kLhRelative);
  Flags rlh = glyph | rem | static_cast<Flags>(Flag::kRlhRelative);
  Flags sv = static_cast<Flags>(Flag::kStaticViewport);
  Flags dv = static_cast<Flags>(Flag::kDynamicViewport);
  Flags cq = static_cast<Flags>(Flag::kContainerRelative);
  Flags ldr = static_cast<Flags>(Flag::kLogicalDirectionRelative);

  EXPECT_EQ(0u, ConversionFlags("1px"));

  EXPECT_EQ(em, ConversionFlags("1em"));
  EXPECT_EQ(cap, ConversionFlags("1cap"));

  EXPECT_EQ(rem, ConversionFlags("1rem"));
  EXPECT_EQ(rex, ConversionFlags("1rex"));
  EXPECT_EQ(rch, ConversionFlags("1rch"));
  EXPECT_EQ(ric, ConversionFlags("1ric"));
  EXPECT_EQ(rcap, ConversionFlags("1rcap"));

  EXPECT_EQ(glyph, ConversionFlags("1ex"));
  EXPECT_EQ(ch, ConversionFlags("1ch"));
  EXPECT_EQ(ic, ConversionFlags("1ic"));

  EXPECT_EQ(lh, ConversionFlags("1lh"));
  EXPECT_EQ(rlh, ConversionFlags("1rlh"));

  EXPECT_EQ(sv, ConversionFlags("1svw"));
  EXPECT_EQ(sv, ConversionFlags("1svh"));
  EXPECT_EQ(sv | ldr, ConversionFlags("1svi"));
  EXPECT_EQ(sv | ldr, ConversionFlags("1svb"));
  EXPECT_EQ(sv, ConversionFlags("1svmin"));
  EXPECT_EQ(sv, ConversionFlags("1svmax"));

  EXPECT_EQ(sv, ConversionFlags("1lvw"));
  EXPECT_EQ(sv, ConversionFlags("1lvh"));
  EXPECT_EQ(sv | ldr, ConversionFlags("1lvi"));
  EXPECT_EQ(sv | ldr, ConversionFlags("1lvb"));
  EXPECT_EQ(sv, ConversionFlags("1lvmin"));
  EXPECT_EQ(sv, ConversionFlags("1lvmax"));

  EXPECT_EQ(sv, ConversionFlags("1vw"));
  EXPECT_EQ(sv, ConversionFlags("1vh"));
  EXPECT_EQ(sv | ldr, ConversionFlags("1vi"));
  EXPECT_EQ(sv | ldr, ConversionFlags("1vb"));
  EXPECT_EQ(sv, ConversionFlags("1vmin"));
  EXPECT_EQ(sv, ConversionFlags("1vmax"));

  EXPECT_EQ(dv, ConversionFlags("1dvw"));
  EXPECT_EQ(dv, ConversionFlags("1dvh"));
  EXPECT_EQ(dv | ldr, ConversionFlags("1dvi"));
  EXPECT_EQ(dv | ldr, ConversionFlags("1dvb"));
  EXPECT_EQ(dv, ConversionFlags("1dvmin"));
  EXPECT_EQ(dv, ConversionFlags("1dvmax"));

  // Since there is no container, these units fall back to the small viewport.
  EXPECT_EQ(cq | sv, ConversionFlags("1cqh"));
  EXPECT_EQ(cq | sv, ConversionFlags("1cqw"));
  EXPECT_EQ(cq | sv | ldr, ConversionFlags("1cqi"));
  EXPECT_EQ(cq | sv | ldr, ConversionFlags("1cqb"));
  EXPECT_EQ(cq | sv, ConversionFlags("1cqmin"));
  EXPECT_EQ(cq | sv, ConversionFlags("1cqmax"));

  EXPECT_EQ(em | glyph, ConversionFlags("calc(1em + 1ex)"));
}

TEST_F(CSSToLengthConversionDataTest, ConversionWithoutPrimaryFont) {
  FontDescription font_description;
  Font font(font_description);
  font.NullifyPrimaryFontForTesting();

  ASSERT_FALSE(font.PrimaryFont());

  CSSToLengthConversionData data(/*element=*/nullptr);
  CSSToLengthConversionData::FontSizes font_sizes(
      /* em */ 16.0f, /* rem */ 16.0f, &font, /* font_zoom */ 1.0f);
  CSSToLengthConversionData::LineHeightSize line_height_size(
      Length::Fixed(16.0f), &font, /* font_zoom */ 1.0f);
  data.SetFontSizes(font_sizes);
  data.SetLineHeightSize(line_height_size);

  // Don't crash:
  ConvertPx(data, "1em");
  ConvertPx(data, "1rem");
  ConvertPx(data, "1ex");
  ConvertPx(data, "1rex");
  ConvertPx(data, "1ch");
  ConvertPx(data, "1rch");
  ConvertPx(data, "1ic");
  ConvertPx(data, "1ric");
  ConvertPx(data, "1lh");
  ConvertPx(data, "1rlh");
}

TEST_F(CSSToLengthConversionDataTest, AnchorFunction) {
  TestAnchorEvaluator anchor_evaluator(/* result */ LayoutUnit(60.0));
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = &anchor_evaluator});

  CSSPropertyID right = CSSPropertyID::kRight;

  EXPECT_FLOAT_EQ(60.0f, ConvertPx(data, "anchor(--a left)", right));
  EXPECT_FLOAT_EQ(2.0f, ConvertPx(data, "calc(anchor(--a left) / 30)", right));
}

TEST_F(CSSToLengthConversionDataTest, AnchorFunctionFallback) {
  TestAnchorEvaluator anchor_evaluator(/* result */ std::nullopt);
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = &anchor_evaluator});

  CSSPropertyID right = CSSPropertyID::kRight;

  EXPECT_FLOAT_EQ(42.0f, ConvertPx(data, "anchor(--a left, 42px)", right));
  EXPECT_FLOAT_EQ(
      52.0f, ConvertPx(data, "anchor(--a left, calc(42px + 10px))", right));
  EXPECT_FLOAT_EQ(10.0f,
                  ConvertPx(data, "anchor(--a left, min(42px, 10px))", right));
}

TEST_F(CSSToLengthConversionDataTest, AnchorSizeFunction) {
  TestAnchorEvaluator anchor_evaluator(/* result */ LayoutUnit(60.0));
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = &anchor_evaluator});

  CSSPropertyID width = CSSPropertyID::kWidth;

  EXPECT_FLOAT_EQ(60.0f, ConvertPx(data, "anchor-size(width)", width));
  EXPECT_FLOAT_EQ(60.0f, ConvertPx(data, "anchor-size(--a width)", width));
  EXPECT_FLOAT_EQ(2.0f,
                  ConvertPx(data, "calc(anchor-size(--a width) / 30)", width));
}

TEST_F(CSSToLengthConversionDataTest, AnchorSizeFunctionFallback) {
  TestAnchorEvaluator anchor_evaluator(/* result */ std::nullopt);
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = &anchor_evaluator});

  CSSPropertyID width = CSSPropertyID::kWidth;

  EXPECT_FLOAT_EQ(42.0f,
                  ConvertPx(data, "anchor-size(--a width, 42px)", width));
  EXPECT_FLOAT_EQ(
      52.0f,
      ConvertPx(data, "anchor-size(--a width, calc(42px + 10px))", width));
  EXPECT_FLOAT_EQ(
      10.0f, ConvertPx(data, "anchor-size(--a width, min(42px, 10px))", width));
}

TEST_F(CSSToLengthConversionDataTest, AnchorWithinOtherFunction) {
  TestAnchorEvaluator anchor_evaluator(/* result */ std::nullopt);
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = &anchor_evaluator});

  CSSPropertyID right = CSSPropertyID::kRight;

  EXPECT_FLOAT_EQ(
      42.0f, ConvertPx(data, "calc(anchor(--a left, 10px) + 32px)", right));
  EXPECT_EQ(ConvertLength(data, "calc(10px + 42%)", right),
            ConvertLength(data, "calc(anchor(--a left, 10px) + 42%)", right));
  EXPECT_EQ(ConvertLength(data, "calc(0px + 42%)", right),
            ConvertLength(data, "calc(anchor(--a left, 0px) + 42%)", right));
  EXPECT_EQ(ConvertLength(data, "min(10px, 42%)", right),
            ConvertLength(data, "min(anchor(--a left, 10px), 42%)", right));
  EXPECT_EQ(ConvertLength(data, "min(10px, 42%)", right),
            ConvertLength(data, "min(anchor(--a left, 10px), 42%)", right));
  EXPECT_FLOAT_EQ(
      10.0f,
      ConvertLength(data, "min(anchor(--a left, 10px), 42px)", right).Pixels());
  // TODO(crbug.com/326088870): This result is to be expected from the current
  // implementation, but it's not consistent with what you get if you specify
  // min(10%, 42%) directly (52%).
  EXPECT_EQ("min(10%, 42%)",
            CSSPrimitiveValue::CreateFromLength(
                ConvertLength(data, "min(anchor(--a left, 10%), 42%)", right),
                /* zoom */ 1.0f)
                ->CssText());
}

TEST_F(CSSToLengthConversionDataTest, AnchorFunctionPercentageFallback) {
  TestAnchorEvaluator anchor_evaluator(/* result */ std::nullopt);
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = &anchor_evaluator});

  CSSPropertyID right = CSSPropertyID::kRight;

  EXPECT_EQ("42%", CSSPrimitiveValue::CreateFromLength(
                       ConvertLength(data, "anchor(--a left, 42%)", right),
                       /* zoom */ 1.0f)
                       ->CssText());
  EXPECT_EQ("52%",
            CSSPrimitiveValue::CreateFromLength(
                ConvertLength(data, "anchor(--a left, calc(42% + 10%))", right),
                /* zoom */ 1.0f)
                ->CssText());
  EXPECT_EQ("10%",
            CSSPrimitiveValue::CreateFromLength(
                ConvertLength(data, "anchor(--a left, min(42%, 10%))", right),
                /* zoom */ 1.0f)
                ->CssText());
}

TEST_F(CSSToLengthConversionDataTest,
       AnchorFunctionPercentageFallbackNotTaken) {
  TestAnchorEvaluator anchor_evaluator(/* result */ LayoutUnit(60.0));
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = &anchor_evaluator});

  CSSPropertyID right = CSSPropertyID::kRight;

  // TODO(crbug.com/326088870): This result is probably not what we want.
  EXPECT_EQ("calc(60px)",
            CSSPrimitiveValue::CreateFromLength(
                ConvertLength(data, "anchor(--a left, 42%)", right),
                /* zoom */ 1.0f)
                ->CssText());
}

TEST_F(CSSToLengthConversionDataTest, AnchorFunctionFallbackNullEvaluator) {
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = nullptr});

  CSSPropertyID right = CSSPropertyID::kRight;

  EXPECT_FLOAT_EQ(42.0f, ConvertPx(data, "anchor(--a right, 42px)", right));
}

TEST_F(CSSToLengthConversionDataTest, AnchorFunctionLengthPercentageFallback) {
  TestAnchorEvaluator anchor_evaluator(/* result */ std::nullopt);
  CSSToLengthConversionData data =
      ConversionData({.anchor_evaluator = &anchor_evaluator});

  CSSPropertyID right = CSSPropertyID::kRight;

  EXPECT_EQ(ConvertLength(data, "calc(10px + 42%)", right),
            ConvertLength(data, "anchor(--a left, calc(10px + 42%))", right));
  EXPECT_EQ(ConvertLength(data, "min(10px, 42%)", right),
            ConvertLength(data, "anchor(--a left, min(10px, 42%))", right));
}

TEST_F(CSSToLengthConversionDataTest, ContainerUnitsWithContainerName) {
  auto* container = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  container->SetInlineStyleProperty(CSSPropertyID::kWidth, "322px");
  container->SetInlineStyleProperty(CSSPropertyID::kHeight, "228px");
  container->SetInlineStyleProperty(CSSPropertyID::kContainerName,
                                    "root_container");
  container->SetInlineStyleProperty(CSSPropertyID::kContainerType, "size");
  auto* child = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  GetDocument().body()->AppendChild(container);
  container->AppendChild(child);
  UpdateAllLifecyclePhasesForTest();

  CSSToLengthConversionData::Flags flags = 0;
  CSSToLengthConversionData length_resolver(
      child->ComputedStyleRef(), GetDocument().body()->GetComputedStyle(),
      GetDocument().documentElement()->GetComputedStyle(),
      CSSToLengthConversionData::ViewportSize(GetDocument().GetLayoutView()),
      CSSToLengthConversionData::ContainerSizes(child),
      CSSToLengthConversionData::AnchorData(
          nullptr,
          /* position_anchor */ nullptr,
          /* position_area_offsets */ std::nullopt),
      child->GetComputedStyle()->EffectiveZoom(), flags, /*element=*/nullptr);

  ScopedCSSName* name = MakeGarbageCollected<ScopedCSSName>(
      AtomicString("root_container"), nullptr);
  EXPECT_EQ(length_resolver.ContainerWidth(*name), 322);
  EXPECT_EQ(length_resolver.ContainerHeight(*name), 228);
}

}  // namespace blink

"""

```