Response:
The user is asking for a summary of the functionality of the `text_autosizer_test.cc` file in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file name strongly suggests it's a test file for the `TextAutosizer` functionality. The `#include "third_party/blink/renderer/core/layout/text_autosizer.h"` confirms this.

2. **Recognize the testing framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of the Google Test framework. This means the file contains various test cases (`TEST_P`) to verify the behavior of the `TextAutosizer`.

3. **Analyze the test structure:** The tests generally follow a pattern:
    * Setting up the HTML content using `SetBodyInnerHTML`.
    * Optionally modifying settings or attributes.
    * Getting a reference to a specific element using `GetElementById` or `GetLayoutObjectByElementId`.
    * Making assertions about the computed or specified font size using `EXPECT_FLOAT_EQ`.

4. **Identify key features being tested:** By examining the names of the test cases (e.g., `SimpleParagraph`, `TextSizeAdjustDisablesAutosizing`, `AccessibilityFontScaleFactor`),  we can infer the functionalities being tested:
    * Basic text autosizing.
    * The interaction of `text-size-adjust` CSS property with autosizing.
    * Handling of accessibility font scale factors.
    * Device scale adjustments and viewport settings.
    * Behavior in "supercluster" scenarios (likely related to how autosizing behaves in more complex layouts).

5. **Relate to web technologies:** Consider how the tested features connect to JavaScript, HTML, and CSS:
    * **HTML:** The tests manipulate the HTML structure to create different scenarios for autosizing.
    * **CSS:** The `text-size-adjust` property is explicitly tested, and the overall font size is influenced by CSS.
    * **JavaScript:** While not directly tested in this file, the underlying `TextAutosizer` functionality is used by the rendering engine when processing web pages, which can be dynamically manipulated by JavaScript.

6. **Look for logical reasoning:**  The tests often involve calculations based on viewport width, window width, and specified font sizes. The expected output is often derived from a formula or rule.

7. **Consider potential user errors:** Think about common mistakes developers might make when dealing with text sizing and responsiveness, such as incorrect usage of `text-size-adjust` or misunderstanding how accessibility settings affect font sizes.

8. **Structure the answer:** Organize the findings into logical categories like core functionality, relationship to web technologies, logical reasoning, and potential errors.

9. **Acknowledge the "Part 1" instruction:** Explicitly state that the summary is for the first part of the file and focus on the functionalities covered in the provided code snippet.

**Self-Correction/Refinement:**

* **Initial thought:** Focus solely on the test cases.
* **Correction:** Broaden the scope to include the purpose of the file and its context within the Blink engine.
* **Initial thought:** List each test case individually.
* **Correction:** Group related test cases to identify the underlying features being tested.
* **Initial thought:** Only mention direct relationships with HTML, CSS, and JavaScript.
* **Correction:**  Explain that although JavaScript isn't directly *in* the test, the tested functionality *affects* how JavaScript-manipulated content is rendered.
* **Initial thought:**  Only describe the tests.
* **Correction:**  Include a higher-level summary of the `TextAutosizer`'s overall goal.
这个文件 `text_autosizer_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `TextAutosizer` 类的功能。 `TextAutosizer` 的主要目的是**自动调整网页上的文本大小**，以提高在不同屏幕尺寸和分辨率下的可读性。

**核心功能归纳：**

1. **测试基本的文本自动缩放功能:** 验证在默认情况下，当启用文本自动缩放时，文本的计算字体大小会根据视口宽度和窗口宽度进行调整。
2. **测试 `text-size-adjust` CSS 属性的影响:** 验证 `text-size-adjust` 属性的不同值（`auto`, `none`, 百分比值）如何影响文本自动缩放的行为。例如，设置为 `none` 或特定的百分比值应该禁用或覆盖自动缩放。
3. **测试动态修改 `text-size-adjust` 属性:** 验证在运行时通过 JavaScript 修改元素的 `text-size-adjust` 属性后，文本的计算字体大小是否会相应更新。
4. **测试 `text-size-adjust` 属性的边界情况:** 验证当 `text-size-adjust` 设置为 0%、负值或非百分比单位时，系统的处理方式（通常会将这些情况视为 `auto` 或禁用自动缩放）。
5. **测试嵌套的 `text-size-adjust` 属性:** 验证在嵌套元素上设置 `text-size-adjust` 时，各自属性的影响。
6. **测试 `-webkit-text-size-adjust` 前缀属性:** 验证带有浏览器前缀的 `text-size-adjust` 属性是否作为别名起作用。
7. **测试辅助功能字体缩放系数的影响:** 验证辅助功能设置中的字体缩放系数是否会与文本自动缩放共同作用，进一步调整文本大小。
8. **测试辅助功能字体缩放系数与 `text-size-adjust: none` 的交互:**  验证当 `text-size-adjust` 设置为 `none` 时，辅助功能字体缩放系数是否会被禁用（在启用 `TextSizeAdjustImprovementsEnabled` 特性后）。
9. **测试动态修改辅助功能字体缩放系数:** 验证在运行时修改辅助功能字体缩放系数后，文本的计算字体大小是否会相应更新。
10. **测试 `text-size-adjust` 在不需要自动缩放时的行为:**  验证即使在视口宽度和窗口宽度相同，不需要进行自动缩放时，`text-size-adjust` 属性仍然能生效。
11. **测试设备像素比调整与视口 `meta` 标签的交互:** 验证当同时存在设备像素比调整和视口 `meta` 标签时，文本自动缩放的行为。通常，视口 `meta` 标签会优先。
12. **测试在 "supercluster" 布局中的文本自动缩放:** 验证在特定布局模式下，当元素的文本内容发生变化或添加新元素时，文本自动缩放的行为是否正确。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**  测试用例通过 `SetBodyInnerHTML` 设置 HTML 结构，创建包含不同文本内容的 `div` 元素，并设置相应的 `id` 或 `class`，以便后续通过 `GetElementById` 获取元素进行测试。

   ```html
   <div id='autosized'>
       这段文字会被自动调整大小。
   </div>
   ```

* **CSS:** 测试用例使用内联样式或 `<style>` 标签来设置 CSS 属性，例如 `font-size`、`width`、`margin` 和关键的 `text-size-adjust`。

   ```html
   <style>
       html { font-size: 16px; }
       body { width: 800px; margin: 0; overflow-y: hidden; }
   </style>
   <div id='textSizeAdjustNone' style='text-size-adjust: none;'>
       这段文字的自动缩放被禁用。
   </div>
   ```

* **JavaScript:** 虽然这个测试文件本身不直接执行 JavaScript 代码，但它测试的功能是当浏览器引擎处理包含特定 CSS 属性的 HTML 时所发生的行为。开发者可以使用 JavaScript 来动态修改元素的 `text-size-adjust` 属性，这个测试覆盖了这种情况。

   **假设输入:** 一个 HTML 页面加载后，JavaScript 代码执行以下操作：
   ```javascript
   const element = document.getElementById('autosized');
   element.style.textSizeAdjust = '50%';
   ```
   **预期输出:**  `TextAutosizer` 的测试会验证，在这种情况下，元素的计算字体大小将变为其指定字体大小的 50%。

**逻辑推理的假设输入与输出：**

* **假设输入:**  一个 `div` 元素，其 CSS 设置为 `font-size: 16px;`，并且页面视口宽度为 800px，模拟窗口宽度设置为 320px。文本自动缩放已启用。
* **预期输出:**  该 `div` 元素的计算字体大小应该是 `16px * 800px / 320px = 40px`。  这就是 `TEST_P(TextAutosizerTest, SimpleParagraph)` 测试用例所验证的逻辑。

* **假设输入:**  一个 `div` 元素，其 CSS 设置为 `font-size: 16px; text-size-adjust: none;`，页面视口宽度为 800px，模拟窗口宽度设置为 320px。
* **预期输出:** 该 `div` 元素的计算字体大小应该保持其指定的字体大小 `16px`，因为 `text-size-adjust: none;` 禁用了自动缩放。这是 `TEST_P(TextAutosizerTest, TextSizeAdjustDisablesAutosizing)` 测试用例的一部分。

**涉及用户或编程常见的使用错误：**

1. **误解 `text-size-adjust: auto` 的作用:** 开发者可能认为 `text-size-adjust: auto` 会启用某种特定的缩放策略，但实际上它表示允许浏览器进行默认的文本自动缩放。

2. **错误地使用非百分比值作为 `text-size-adjust` 的值:** 开发者可能会尝试使用像素或其他单位作为 `text-size-adjust` 的值，例如 `text-size-adjust: 10px;`，这在大多数浏览器中会被忽略或视为 `auto`。 测试用例 `TEST_P(TextAutosizerTest, TextSizeAdjustmentPixelUnits)` 验证了这种行为。

3. **不理解 `text-size-adjust: none` 会禁用自动缩放:** 开发者可能希望微调缩放比例，但错误地使用了 `text-size-adjust: none;`，导致在需要自动缩放的场景下文本过小。

4. **忘记考虑辅助功能字体缩放系数的影响:** 开发者可能只关注视口宽度和窗口宽度，而忽略了用户的辅助功能设置也会影响最终的文本大小。 测试用例 `TEST_P(TextAutosizerTest, AccessibilityFontScaleFactor)` 和相关测试覆盖了这一点。

**总结第 1 部分的功能:**

总而言之，`text_autosizer_test.cc` 的第 1 部分主要集中在测试 `TextAutosizer` 类的**基本文本自动缩放功能**以及 **`text-size-adjust` CSS 属性** 对自动缩放行为的各种影响，包括启用、禁用、动态修改和处理各种取值情况。此外，它还初步涉及了**辅助功能字体缩放系数**与文本自动缩放的交互。 这个文件的目的是确保 Blink 引擎能够正确地根据各种条件调整网页上的文本大小，提供更好的用户体验。

### 提示词
```
这是目录为blink/renderer/core/layout/text_autosizer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/text_autosizer.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {
class TextAutosizerClient : public RenderingTestChromeClient {
 public:
  float WindowToViewportScalar(LocalFrame*, const float value) const override {
    return value * device_scale_factor_;
  }
  gfx::Rect LocalRootToScreenDIPs(const gfx::Rect& rect,
                                  const LocalFrameView*) const override {
    return gfx::ScaleToRoundedRect(rect, 1 / device_scale_factor_);
  }

  void set_device_scale_factor(float device_scale_factor) {
    device_scale_factor_ = device_scale_factor;
  }

 private:
  float device_scale_factor_;
};

class TextAutosizerTest : public RenderingTest,
                          public testing::WithParamInterface<bool>,
                          private ScopedTextSizeAdjustImprovementsForTest {
 public:
  TextAutosizerTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()),
        ScopedTextSizeAdjustImprovementsForTest(GetParam()) {}

  RenderingTestChromeClient& GetChromeClient() const override {
    return GetTextAutosizerClient();
  }
  TextAutosizerClient& GetTextAutosizerClient() const {
    DEFINE_STATIC_LOCAL(Persistent<TextAutosizerClient>, client,
                        (MakeGarbageCollected<TextAutosizerClient>()));
    return *client;
  }
  void set_device_scale_factor(float device_scale_factor) {
    GetTextAutosizerClient().set_device_scale_factor(device_scale_factor);

    // This fake ChromeClient cannot update device scale factor (DSF). We apply
    // DSF to the zoom factor manually.
    GetDocument().GetFrame()->SetLayoutZoomFactor(device_scale_factor);
  }

 private:
  void SetUp() override {
    GetTextAutosizerClient().set_device_scale_factor(1.f);
    RenderingTest::SetUp();
    GetDocument().GetSettings()->SetTextAutosizingEnabled(true);
    GetDocument().GetSettings()->SetTextAutosizingWindowSizeOverride(
        gfx::Size(320, 480));
  }
};

INSTANTIATE_TEST_SUITE_P(All, TextAutosizerTest, testing::Bool());

TEST_P(TextAutosizerTest, SimpleParagraph) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='autosized'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  Element* autosized = GetElementById("autosized");
  EXPECT_FLOAT_EQ(16.f,
                  autosized->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 40px.
  EXPECT_FLOAT_EQ(40.f,
                  autosized->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, TextSizeAdjustDisablesAutosizing) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='textSizeAdjustAuto' style='text-size-adjust: auto;'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
    <div id='textSizeAdjustNone' style='text-size-adjust: none;'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
    <div id='textSizeAdjust100' style='text-size-adjust: 100%;'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  LayoutObject* text_size_adjust_auto =
      GetLayoutObjectByElementId("textSizeAdjustAuto");
  EXPECT_FLOAT_EQ(16.f, text_size_adjust_auto->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(40.f, text_size_adjust_auto->StyleRef().ComputedFontSize());
  LayoutObject* text_size_adjust_none =
      GetLayoutObjectByElementId("textSizeAdjustNone");
  EXPECT_FLOAT_EQ(16.f, text_size_adjust_none->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(16.f, text_size_adjust_none->StyleRef().ComputedFontSize());
  LayoutObject* text_size_adjust100 =
      GetLayoutObjectByElementId("textSizeAdjust100");
  EXPECT_FLOAT_EQ(16.f, text_size_adjust100->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(16.f, text_size_adjust100->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ParagraphWithChangingTextSizeAdjustment) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
      .none { text-size-adjust: none; }
      .small { text-size-adjust: 50%; }
      .large { text-size-adjust: 150%; }
    </style>
    <div id='autosized'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  Element* autosized_div = GetElementById("autosized");
  EXPECT_FLOAT_EQ(
      16.f, autosized_div->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(
      40.f, autosized_div->GetLayoutObject()->StyleRef().ComputedFontSize());

  autosized_div->setAttribute(html_names::kClassAttr, AtomicString("none"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(
      16.f, autosized_div->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(
      16.f, autosized_div->GetLayoutObject()->StyleRef().ComputedFontSize());

  autosized_div->setAttribute(html_names::kClassAttr, AtomicString("small"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(
      16.f, autosized_div->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(
      8.f, autosized_div->GetLayoutObject()->StyleRef().ComputedFontSize());

  autosized_div->setAttribute(html_names::kClassAttr, AtomicString("large"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(
      16.f, autosized_div->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(
      24.f, autosized_div->GetLayoutObject()->StyleRef().ComputedFontSize());

  autosized_div->removeAttribute(html_names::kClassAttr);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FLOAT_EQ(
      16.f, autosized_div->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(
      40.f, autosized_div->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ZeroTextSizeAdjustment) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='textSizeAdjustZero' style='text-size-adjust: 0%;'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  LayoutObject* text_size_adjust_zero =
      GetElementById("textSizeAdjustZero")->GetLayoutObject();
  EXPECT_FLOAT_EQ(16.f, text_size_adjust_zero->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(0.f, text_size_adjust_zero->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, NegativeTextSizeAdjustment) {
  SetBodyInnerHTML(
      "<style>"
      "  html { font-size: 16px; }"
      "  body { width: 800px; margin: 0; overflow-y: hidden; }"
      "</style>"
      // Negative values should be treated as auto.
      "<div id='textSizeAdjustNegative' style='text-size-adjust: -10%;'>"
      "  Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do"
      "  eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim"
      "  ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut"
      "  aliquip ex ea commodo consequat. Duis aute irure dolor in"
      "  reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla"
      "  pariatur. Excepteur sint occaecat cupidatat non proident, sunt in"
      "  culpa qui officia deserunt mollit anim id est laborum."
      "</div>");
  LayoutObject* text_size_adjust_negative =
      GetLayoutObjectByElementId("textSizeAdjustNegative");
  EXPECT_FLOAT_EQ(16.f,
                  text_size_adjust_negative->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(40.f,
                  text_size_adjust_negative->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, TextSizeAdjustmentPixelUnits) {
  SetBodyInnerHTML(
      "<style>"
      "  html { font-size: 16px; }"
      "  body { width: 800px; margin: 0; overflow-y: hidden; }"
      "</style>"
      // Non-percentage values should be treated as auto.
      "<div id='textSizeAdjustPixels' style='text-size-adjust: 0.1px;'>"
      "  Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do"
      "  eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim"
      "  ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut"
      "  aliquip ex ea commodo consequat. Duis aute irure dolor in"
      "  reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla"
      "  pariatur. Excepteur sint occaecat cupidatat non proident, sunt in"
      "  culpa qui officia deserunt mollit anim id est laborum."
      "</div>");
  LayoutObject* text_size_adjust_pixels =
      GetLayoutObjectByElementId("textSizeAdjustPixels");
  EXPECT_FLOAT_EQ(16.f,
                  text_size_adjust_pixels->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(40.f, text_size_adjust_pixels->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, NestedTextSizeAdjust) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='textSizeAdjustA' style='text-size-adjust: 47%;'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
      <div id='textSizeAdjustB' style='text-size-adjust: 53%;'>
        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
        eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
        ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
        aliquip ex ea commodo consequat. Duis aute irure dolor in
        reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
        pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
        culpa qui officia deserunt mollit anim id est laborum.
      </div>
    </div>
  )HTML");
  LayoutObject* text_size_adjust_a =
      GetLayoutObjectByElementId("textSizeAdjustA");
  EXPECT_FLOAT_EQ(16.f, text_size_adjust_a->StyleRef().SpecifiedFontSize());
  // 16px * 47% = 7.52
  EXPECT_FLOAT_EQ(7.52f, text_size_adjust_a->StyleRef().ComputedFontSize());
  LayoutObject* text_size_adjust_b =
      GetLayoutObjectByElementId("textSizeAdjustB");
  EXPECT_FLOAT_EQ(16.f, text_size_adjust_b->StyleRef().SpecifiedFontSize());
  // 16px * 53% = 8.48
  EXPECT_FLOAT_EQ(8.48f, text_size_adjust_b->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, PrefixedTextSizeAdjustIsAlias) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='textSizeAdjust' style='-webkit-text-size-adjust: 50%;'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  LayoutObject* text_size_adjust = GetLayoutObjectByElementId("textSizeAdjust");
  EXPECT_FLOAT_EQ(16.f, text_size_adjust->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(8.f, text_size_adjust->StyleRef().ComputedFontSize());
  EXPECT_FLOAT_EQ(
      .5f, text_size_adjust->StyleRef().GetTextSizeAdjust().Multiplier());
}

TEST_P(TextAutosizerTest, AccessibilityFontScaleFactor) {
  GetDocument().GetSettings()->SetAccessibilityFontScaleFactor(1.5);
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='autosized'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  Element* autosized = GetElementById("autosized");
  EXPECT_FLOAT_EQ(16.f,
                  autosized->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // 1.5 * (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 60px.
  EXPECT_FLOAT_EQ(60.f,
                  autosized->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, AccessibilityFontScaleFactorWithTextSizeAdjustNone) {
  if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
    // Non-auto values of text-size-adjust should disable all automatic font
    // scale adjustment.
    return;
  }

  GetDocument().GetSettings()->SetAccessibilityFontScaleFactor(1.5);
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
      #autosized { width: 400px; text-size-adjust: 100%; }
      #notAutosized { width: 100px; text-size-adjust: 100%; }
    </style>
    <div id='autosized'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
    <div id='notAutosized'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  Element* autosized = GetElementById("autosized");
  EXPECT_FLOAT_EQ(16.f,
                  autosized->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // 1.5 * (specified font-size = 16px) = 24px.
  EXPECT_FLOAT_EQ(24.f,
                  autosized->GetLayoutObject()->StyleRef().ComputedFontSize());

  // Because this does not autosize (due to the width), no accessibility font
  // scale factor should be applied.
  Element* not_autosized = GetElementById("notAutosized");
  EXPECT_FLOAT_EQ(
      16.f, not_autosized->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // specified font-size = 16px.
  EXPECT_FLOAT_EQ(
      16.f, not_autosized->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ChangingAccessibilityFontScaleFactor) {
  GetDocument().GetSettings()->SetAccessibilityFontScaleFactor(1);
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='autosized'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  Element* autosized = GetElementById("autosized");
  EXPECT_FLOAT_EQ(16.f,
                  autosized->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // 1.0 * (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 40px.
  EXPECT_FLOAT_EQ(40.f,
                  autosized->GetLayoutObject()->StyleRef().ComputedFontSize());

  GetDocument().GetSettings()->SetAccessibilityFontScaleFactor(2);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FLOAT_EQ(16.f,
                  autosized->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // 2.0 * (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 80px.
  EXPECT_FLOAT_EQ(80.f,
                  autosized->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, TextSizeAdjustDoesNotDisableAccessibility) {
  if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
    // Non-auto values of text-size-adjust should disable all automatic font
    // scale adjustment.
    return;
  }

  GetDocument().GetSettings()->SetAccessibilityFontScaleFactor(1.5);
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='textSizeAdjustNone' style='text-size-adjust: none;'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
    <div id='textSizeAdjustDouble' style='text-size-adjust: 200%;'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");
  Element* text_size_adjust_none = GetElementById("textSizeAdjustNone");
  EXPECT_FLOAT_EQ(
      16.f,
      text_size_adjust_none->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // 1.5 * (specified font-size = 16px) = 24px.
  EXPECT_FLOAT_EQ(
      24.f,
      text_size_adjust_none->GetLayoutObject()->StyleRef().ComputedFontSize());

  Element* text_size_adjust_double = GetElementById("textSizeAdjustDouble");
  EXPECT_FLOAT_EQ(16.f, text_size_adjust_double->GetLayoutObject()
                            ->StyleRef()
                            .SpecifiedFontSize());
  // 1.5 * (specified font-size = 16px) * (text size adjustment = 2) = 48px.
  EXPECT_FLOAT_EQ(48.f, text_size_adjust_double->GetLayoutObject()
                            ->StyleRef()
                            .ComputedFontSize());

  // Changing the accessibility font scale factor should change the adjusted
  // size.
  GetDocument().GetSettings()->SetAccessibilityFontScaleFactor(2);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FLOAT_EQ(
      16.f,
      text_size_adjust_none->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // 2.0 * (specified font-size = 16px) = 32px.
  EXPECT_FLOAT_EQ(
      32.f,
      text_size_adjust_none->GetLayoutObject()->StyleRef().ComputedFontSize());

  EXPECT_FLOAT_EQ(16.f, text_size_adjust_double->GetLayoutObject()
                            ->StyleRef()
                            .SpecifiedFontSize());
  // 2.0 * (specified font-size = 16px) * (text size adjustment = 2) = 64px.
  EXPECT_FLOAT_EQ(64.f, text_size_adjust_double->GetLayoutObject()
                            ->StyleRef()
                            .ComputedFontSize());
}

// https://crbug.com/646237
TEST_P(TextAutosizerTest, DISABLED_TextSizeAdjustWithoutNeedingAutosizing) {
  GetDocument().GetSettings()->SetTextAutosizingWindowSizeOverride(
      gfx::Size(800, 600));
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='textSizeAdjust' style='text-size-adjust: 150%;'>
      Text
    </div>
  )HTML");

  LayoutObject* text_size_adjust = GetLayoutObjectByElementId("textSizeAdjust");
  EXPECT_FLOAT_EQ(16.f, text_size_adjust->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(24.f, text_size_adjust->StyleRef().ComputedFontSize());
  EXPECT_FLOAT_EQ(
      1.5f, text_size_adjust->StyleRef().GetTextSizeAdjust().Multiplier());
}

TEST_P(TextAutosizerTest, DeviceScaleAdjustmentWithViewport) {
  SetBodyInnerHTML(R"HTML(
    <meta name='viewport' content='width=800'>
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='autosized'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");

  GetDocument().GetSettings()->SetViewportMetaEnabled(true);
  GetDocument().GetSettings()->SetDeviceScaleAdjustment(1.5f);
  UpdateAllLifecyclePhasesForTest();

  Element* autosized = GetElementById("autosized");
  EXPECT_FLOAT_EQ(16.f,
                  autosized->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 40px.
  // The device scale adjustment of 1.5 is ignored.
  EXPECT_FLOAT_EQ(40.f,
                  autosized->GetLayoutObject()->StyleRef().ComputedFontSize());

  GetDocument().GetSettings()->SetViewportMetaEnabled(false);
  UpdateAllLifecyclePhasesForTest();

  autosized = GetElementById("autosized");
  EXPECT_FLOAT_EQ(16.f,
                  autosized->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // (device scale adjustment = 1.5) * (specified font-size = 16px) *
  // (viewport width = 800px) / (window width = 320px) = 60px.
  EXPECT_FLOAT_EQ(60.f,
                  autosized->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ChangingSuperClusterFirstText) {
  SetBodyInnerHTML(R"HTML(
    <meta name='viewport' content='width=800'>
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
      .supercluster { width:560px; }
    </style>
    <div class='supercluster'>
      <div id='longText'>short blah blah</div>
    </div>
    <div class='supercluster'>
      <div id='shortText'>short blah blah</div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* long_text_element = GetElementById("longText");
  long_text_element->setInnerHTML(
      "    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed "
      "do eiusmod tempor"
      "    incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
      "veniam, quis nostrud"
      "    exercitation ullamco laboris nisi ut aliquip ex ea commodo "
      "consequat. Duis aute irure"
      "    dolor in reprehenderit in voluptate velit esse cillum dolore eu "
      "fugiat nulla pariatur."
      "    Excepteur sint occaecat cupidatat non proident, sunt in culpa "
      "qui officia deserunt"
      "    mollit anim id est laborum.",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  LayoutObject* long_text = GetLayoutObjectByElementId("longText");
  EXPECT_FLOAT_EQ(16.f, long_text->StyleRef().SpecifiedFontSize());
  //(specified font-size = 16px) * (block width = 560px) /
  // (window width = 320px) = 28px.
  EXPECT_FLOAT_EQ(28.f, long_text->StyleRef().ComputedFontSize());
  LayoutObject* short_text = GetLayoutObjectByElementId("shortText");
  EXPECT_FLOAT_EQ(16.f, short_text->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(28.f, short_text->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ChangingSuperClusterSecondText) {
  SetBodyInnerHTML(R"HTML(
    <meta name='viewport' content='width=800'>
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
      .supercluster { width:560px; }
    </style>
    <div class='supercluster'>
      <div id='shortText'>short blah blah</div>
    </div>
    <div class='supercluster'>
      <div id='longText'>short blah blah</div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* long_text_element = GetElementById("longText");
  long_text_element->setInnerHTML(
      "    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed "
      "do eiusmod tempor"
      "    incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
      "veniam, quis nostrud"
      "    exercitation ullamco laboris nisi ut aliquip ex ea commodo "
      "consequat. Duis aute irure"
      "    dolor in reprehenderit in voluptate velit esse cillum dolore eu "
      "fugiat nulla pariatur."
      "    Excepteur sint occaecat cupidatat non proident, sunt in culpa "
      "qui officia deserunt"
      "    mollit anim id est laborum.",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  LayoutObject* long_text = GetLayoutObjectByElementId("longText");
  EXPECT_FLOAT_EQ(16.f, long_text->StyleRef().SpecifiedFontSize());
  //(specified font-size = 16px) * (block width = 560px) /
  // (window width = 320px) = 28px.
  EXPECT_FLOAT_EQ(28.f, long_text->StyleRef().ComputedFontSize());
  LayoutObject* short_text = GetLayoutObjectByElementId("shortText");
  EXPECT_FLOAT_EQ(16.f, short_text->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(28.f, short_text->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, AddingSuperCluster) {
  SetBodyInnerHTML(R"HTML(
    <meta name='viewport' content='width=800'>
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
      .supercluster { width:560px; }
    </style>
    <div>
      <div class='supercluster' id='shortText'>
          short blah blah
      </div>
    </div>
    <div id='container'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* container = GetElementById("container");
  container->setInnerHTML(
      "<div class='supercluster' id='longText'>"
      "    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed "
      "do eiusmod tempor"
      "    incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
      "veniam, quis nostrud"
      "    exercitation ullamco laboris nisi ut aliquip ex ea commodo "
      "consequat. Duis aute irure"
      "    dolor in reprehenderit in voluptate velit esse cillum dolore eu "
      "fugiat nulla pariatur."
      "    Excepteur sint occaecat cupidatat non proident, sunt in culpa "
      "qui officia deserunt"
      "    mollit anim id est laborum."
      "</div>",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  LayoutObject* long_text = GetLayoutObjectByElementId("longText");
  EXPECT_FLOAT_EQ(16.f, long_text->StyleRef().SpecifiedFontSize());
  //(specified font-size = 16px) * (block width = 560px) /
  // (window width = 320px) = 28px.
  EXPECT_FLOAT_EQ(28.f, long_text->StyleRef().ComputedFontSize());
  LayoutObject* short_text = GetLayoutObjectByElementId("shortText");
  EXPECT_FLOAT_EQ(16.f, short_text->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(28.f, short_text->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ChangingInheritedClusterTextInsideSuperCluster) {
  SetBodyInnerHTML(R"HTML(
    <meta name='viewport' content='width=800'>
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
      .supercluster { width:560px; }
      .cluster{width:560px;}
    </style>
    <div class='supercluster'>
      <div class='cluster' id='longText'>short blah blah</div>
    </div>
    <div class='supercluster'>
      <div class='cluster' id='shortText'>short blah blah</div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* long_text_element = GetElementById("longText");
  long_text_element->setInnerHTML(
      "    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed "
      "do eiusmod tempor"
      "    incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
      "veniam, quis nostrud"
      "    exercitation ullamco laboris nisi ut aliquip ex ea commodo "
      "consequat. Duis aute irure"
      "
```