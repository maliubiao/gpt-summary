Response:
My thinking process to answer the request about `media_query_evaluator_test.cc` went like this:

1. **Understand the Core Function:** The filename itself gives a strong hint: "media_query_evaluator_test". This immediately tells me the file is about *testing* the functionality of a `MediaQueryEvaluator`.

2. **Examine Includes:**  The `#include` statements are crucial for understanding dependencies and the context of the code. I look for key classes and concepts:
    * `media_query_evaluator.h`:  Confirms the testing target.
    * `testing/gtest/include/gtest/gtest.h`: Indicates this is a unit test file using the Google Test framework.
    * `third_party/blink/public/common/css/...`:  Points to CSS-related data structures and enums.
    * `third_party/blink/renderer/core/css/...`:  More core CSS classes like `MediaList`, `MediaValues`, `MediaQueryParser`.
    * `third_party/blink/renderer/core/dom/document.h`: Suggests interaction with the DOM.
    * `third_party/blink/renderer/core/frame/...`:  Indicates involvement with the browser frame structure.

3. **Analyze Test Cases:** The code defines several arrays of `MediaQueryEvaluatorTestCase`. Each test case has an `input` (a media query string) and an `output` (a boolean indicating whether the evaluator should consider the query to match). This is the heart of the testing strategy.

4. **Identify Tested Features:** I go through the different test case arrays (`g_screen_test_cases`, `g_viewport_test_cases`, `g_print_test_cases`, etc.). The names of these arrays clearly indicate the media query features being tested: `screen`, viewport dimensions (`width`, `height`), `print` media type, `update` frequency, `forced-colors`, `prefers-contrast`, and many more.

5. **Connect to Web Technologies:** I link the tested media query features back to their counterparts in web development:
    * **CSS:** Media queries are a fundamental part of CSS for responsive design.
    * **HTML:** Media queries influence which stylesheets are applied to an HTML document.
    * **JavaScript:** While this specific file isn't directly JavaScript, JavaScript can interact with and query the results of media query evaluations.

6. **Look for Logic and Examples:** The test cases themselves *are* the logical examples. For instance, `{"(min-width: 500px)", true}` and `{"(min-width: 501px)", false}` (assuming a viewport width of 500px) demonstrates the evaluator's handling of `min-width`.

7. **Consider User/Programming Errors:**  The test cases that evaluate to `false` can often highlight potential errors. For example, incorrect syntax in a media query string (`"(orientation: url(portrait))"`) will be flagged as false.

8. **Infer Debugging Information:** The tests show how different media features are evaluated based on underlying browser state (screen size, device capabilities, user preferences). This provides clues for debugging why a particular stylesheet might be applied or not. Stepping through the `MediaQueryEvaluator::Eval` function with these test cases as input would be a debugging approach.

9. **Synthesize a Summary:**  Based on the above analysis, I formulate a concise summary of the file's purpose, highlighting its role in testing media query evaluation and its relevance to CSS, HTML, and JavaScript.

10. **Address the "Part 1" Request:**  I explicitly state that the provided code is primarily about *testing* and that the subsequent parts will likely contain more test cases and potentially the implementation of the evaluator itself.

**Self-Correction/Refinement:**

* **Initial thought:**  Might the file contain the actual implementation of the media query evaluator?
* **Correction:** The presence of `TEST(...)` macros and the clear separation of input and expected output strongly suggest this is solely a *test* file. The implementation would likely be in `media_query_evaluator.cc`.

* **Initial thought:** Focus heavily on the C++ code details.
* **Refinement:** While understanding the C++ structure is important, the request emphasizes the *functionality* and its connection to web technologies. Therefore, I shifted focus to explaining the *what* and *why* of the tests in relation to CSS, HTML, and JavaScript.

By following these steps, I could systematically analyze the provided code snippet and generate a comprehensive answer that addresses all aspects of the request.
好的，根据你提供的 blink 引擎源代码文件 `media_query_evaluator_test.cc` 的内容，以下是其功能的归纳：

**文件功能归纳：**

`media_query_evaluator_test.cc` 文件是 Chromium Blink 引擎中用于测试 `MediaQueryEvaluator` 类功能的单元测试文件。它的主要目的是验证 `MediaQueryEvaluator` 能否正确地评估各种 CSS 媒体查询在不同设备和浏览器状态下的匹配结果。

**更详细的功能点：**

1. **测试 `MediaQueryEvaluator::Eval()` 方法:** 该文件通过大量的测试用例来验证 `MediaQueryEvaluator` 类的 `Eval()` 方法是否能够准确判断给定的媒体查询是否与当前的浏览器环境和设备状态相匹配。

2. **覆盖多种媒体特性:** 测试用例涵盖了各种各样的 CSS 媒体特性，例如：
    * **设备特性:** `screen`, `print`, `color`, `monochrome`, `resolution`, `orientation`, `device-aspect-ratio`, `pointer`, `hover`, `update`, `grid` 等。
    * **视口特性:** `width`, `height`, `min-width`, `max-width`, `min-height`, `max-height`, `aspect-ratio`, `device-pixel-ratio` 等。
    * **显示模式:** `display-mode` (fullscreen, standalone, browser 等)。
    * **显示状态:** `display-state` (fullscreen, minimized, maximized, normal)。
    * **可调整大小:** `resizable`。
    * **用户偏好:** `forced-colors`, `prefers-contrast`, `prefers-reduced-transparency`。
    * **分段视口:** `horizontal-viewport-segments`, `vertical-viewport-segments`。
    * **设备姿态:** `device-posture`。
    * **动态范围:** `dynamic-range`, `video-dynamic-range`。
    * **溢出:** `overflow-inline`, `overflow-block`。
    * **反色:** `inverted-colors`。
    * **脚本:** `scripting`。

3. **模拟不同的浏览器和设备状态:**  测试用例通过设置不同的 `MediaValues` 对象来模拟不同的浏览器和设备状态，例如：
    * 不同的屏幕尺寸和分辨率。
    * 不同的设备类型（屏幕、打印机等）。
    * 是否支持彩色或单色。
    * 鼠标指针的精度和悬停能力。
    * 不同的显示模式（例如，全屏、独立应用）。
    * 用户的对比度偏好。
    * 设备是否支持 HDR。

4. **使用 Google Test 框架:** 该文件使用 Google Test 框架来组织和执行测试用例，方便编写、运行和管理测试。

5. **提供清晰的测试断言:**  每个测试用例都使用 `EXPECT_EQ` 宏来断言 `MediaQueryEvaluator::Eval()` 方法的返回值是否与预期的结果一致。

**与 Javascript, HTML, CSS 的关系：**

* **CSS:** 该文件直接测试的是 CSS 媒体查询的评估逻辑。媒体查询是 CSS 的核心功能之一，用于根据不同的设备和环境应用不同的样式规则，实现响应式设计。
    * **举例:** 测试用例 `{"screen and (min-width: 500px)", true}` 验证了当设备类型为 `screen` 且视口宽度大于等于 `500px` 时，媒体查询应该匹配成功。

* **HTML:**  媒体查询通常在 HTML 文档的 `<link>` 标签或 `<style>` 标签中使用，以决定是否应用相应的 CSS 样式表。
    * **举例:**  如果 HTML 中有 `<link rel="stylesheet" href="style.css" media="screen and (min-width: 500px)">`，那么该测试文件中的相关测试用例就验证了浏览器是否会正确判断当前环境是否满足 `screen and (min-width: 500px)` 这个条件，从而决定是否加载 `style.css`。

* **Javascript:** 虽然这个测试文件本身不是 JavaScript 代码，但 JavaScript 可以通过 `window.matchMedia()` 方法来查询媒体查询的匹配结果。 `MediaQueryEvaluator` 的正确性直接影响到 `window.matchMedia()` 的行为。
    * **举例:** JavaScript 代码 `window.matchMedia('(min-width: 500px)').matches` 会调用 Blink 引擎的底层逻辑进行媒体查询评估，而 `media_query_evaluator_test.cc` 中的测试用例就保证了这部分底层逻辑的正确性。如果测试用例 `{"(min-width: 500px)", true}` 通过，则意味着当视口宽度为 500px 时，JavaScript 代码会正确地得到 `true` 的结果。

**逻辑推理与假设输入输出：**

假设我们有以下测试用例：

* **假设输入 (Media Query String):** `screen and (orientation: portrait)`
* **当前环境假设:** 设备类型为 `screen`，屏幕方向为 `portrait`。

**逻辑推理:**

1. `MediaQueryParser` 会解析媒体查询字符串，生成一个表示该查询的内部结构。
2. `MediaQueryEvaluator` 接收该内部结构和当前的 `MediaValues` 对象（包含了当前设备和浏览器的状态）。
3. `MediaQueryEvaluator` 首先检查设备类型是否为 `screen`，这取决于 `MediaValues` 中的 `media_type`。
4. 然后，它检查 `orientation` 特性是否为 `portrait`，这取决于 `MediaValues` 中的屏幕方向信息。
5. 由于两个条件都满足，`Eval()` 方法会返回 `true`。

* **预期输出:** `true`

假设当前环境屏幕方向为 `landscape`，则上述逻辑推理的第 4 步会失败，`Eval()` 方法会返回 `false`。

**用户或编程常见的使用错误举例：**

1. **媒体查询语法错误:** 用户在编写 CSS 或 JavaScript 时，可能会写出不符合 CSS 媒体查询规范的字符串。
    * **错误示例 (假设输入):** `(min-width: 500)`  // 缺少单位 `px`
    * **结果:** `MediaQueryParser` 可能无法正确解析，或者 `MediaQueryEvaluator` 的行为可能不符合预期。测试用例中会包含一些解析失败或评估为 `false` 的情况来覆盖这类错误。

2. **对媒体特性理解不足:**  开发者可能错误地使用了某些媒体特性，或者对它们的行为有误解。
    * **错误示例:**  认为 `(color)` 始终为真，而没有考虑到单色设备的情况。
    * **结果:** 测试用例 `{"(color)", false}` (在单色设备模拟下) 可以帮助发现这种误解。

3. **在 JavaScript 中使用 `window.matchMedia()` 时传入错误的查询字符串:** 这会导致 JavaScript 代码的行为与预期不符。
    * **错误示例 (JavaScript):** `window.matchMedia('min-width: 500px').matches;` // 缺少括号
    * **结果:**  `window.matchMedia()` 可能会抛出错误或者返回不正确的结果，而 `media_query_evaluator_test.cc` 保证了即使传入正确的查询字符串，底层的评估逻辑也是可靠的。

**用户操作如何一步步到达这里 (调试线索)：**

假设用户发现一个使用了媒体查询的网页在特定尺寸的屏幕上样式不正确：

1. **用户调整浏览器窗口大小:**  用户拖动浏览器窗口的边缘，改变了视口的宽度和高度。
2. **浏览器触发媒体查询重新评估:** 浏览器监听到窗口大小变化，会触发对当前页面所有媒体查询的重新评估。
3. **Blink 引擎调用 `MediaQueryEvaluator`:**  当需要评估媒体查询时，Blink 引擎会创建或使用一个 `MediaQueryEvaluator` 实例。
4. **`MediaQueryEvaluator::Eval()` 被调用:**  对于页面中使用的每个媒体查询，`Eval()` 方法会被调用，传入该查询的内部结构和当前的 `MediaValues`。
5. **测试文件中的逻辑被执行 (间接):**  虽然用户操作不会直接执行测试文件中的代码，但测试文件保证了 `Eval()` 方法的内部逻辑是正确的。如果测试文件中的 `{"(min-width: 800px)", true}` 在视口宽度为 800px 时通过，那么用户在将窗口调整到 800px 时，浏览器也应该能够正确地评估相应的媒体查询。
6. **样式更新:** 根据 `Eval()` 方法的返回结果，浏览器会决定是否应用与该媒体查询关联的 CSS 规则，从而更新页面的样式。

如果用户发现样式没有按预期更新，开发者可能会：

1. **使用开发者工具检查媒体查询:**  在 Chrome 开发者工具的 "Elements" 面板中，可以查看当前应用的样式规则以及匹配的媒体查询。
2. **断点调试 Blink 引擎 (更深入):**  如果开发者怀疑是 Blink 引擎的媒体查询评估逻辑有问题，他们可能会下载 Chromium 源代码，设置断点在 `MediaQueryEvaluator::Eval()` 函数中，并逐步执行代码，查看在特定的用户操作和浏览器状态下，媒体查询是如何被评估的。`media_query_evaluator_test.cc` 文件中的测试用例可以帮助开发者理解 `Eval()` 函数的预期行为，并作为调试的参考。

**总结 (针对第 1 部分):**

总而言之，`blink/renderer/core/css/media_query_evaluator_test.cc` 的主要功能是 **系统地测试 Blink 引擎中 `MediaQueryEvaluator` 类的媒体查询评估功能，确保其在各种场景下都能正确地判断媒体查询的匹配结果。** 这对于保证浏览器正确地应用 CSS 样式，实现响应式网页设计至关重要。 该文件通过大量的测试用例覆盖了各种媒体特性和浏览器状态，并使用 Google Test 框架进行组织和断言。

Prompt: 
```
这是目录为blink/renderer/core/css/media_query_evaluator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/media_query_evaluator.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/css/forced_colors.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_sample_test_utils.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token.h"
#include "third_party/blink/public/common/privacy_budget/scoped_identifiability_test_sample_collector.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/media_query_parser.h"
#include "third_party/blink/renderer/core/css/resolver/media_query_result.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/media_type_names.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/base/mojom/window_show_state.mojom-blink.h"
#include "ui/gfx/display_color_spaces.h"

namespace blink {

namespace {

const CSSNumericLiteralValue& WrapDouble(
    double value,
    CSSPrimitiveValue::UnitType unit_type =
        CSSPrimitiveValue::UnitType::kNumber) {
  return *CSSNumericLiteralValue::Create(value, unit_type);
}

MediaQueryExpValue PxValue(double value) {
  return MediaQueryExpValue(
      WrapDouble(value, CSSPrimitiveValue::UnitType::kPixels));
}

MediaQueryExpValue RatioValue(unsigned numerator, unsigned denominator) {
  return MediaQueryExpValue(WrapDouble(numerator), WrapDouble(denominator));
}

}  // namespace

struct MediaQueryEvaluatorTestCase {
  const char* input;
  const bool output;
};

MediaQueryEvaluatorTestCase g_screen_test_cases[] = {
    {"", true},
    {" ", true},
    {"screen", true},
    {"screen and (color)", true},
    {"not screen and (color)", false},
    {"screen and (device-aspect-ratio: 16/9)", false},
    {"screen and (device-aspect-ratio: 0.5/0.5)", true},
    {"screen and (device-aspect-ratio: 1.5)", false},
    {"screen and (device-aspect-ratio: 1/1)", true},
    {"screen and (device-aspect-ratio: calc(1/1))", true},
    {"all and (min-color: 2)", true},
    {"all and (min-color: 32)", false},
    {"all and (min-color-index: 0)", true},
    {"all and (min-color-index: 1)", false},
    {"all and (monochrome)", false},
    {"all and (min-monochrome: 0)", true},
    {"all and (grid: 0)", true},
    {"(resolution: 2dppx)", true},
    {"(resolution: 1dppx)", false},
    {"(resolution: calc(2x))", true},
    {"(resolution: calc(1x))", false},
    {"(resolution: calc(1x + 1x))", true},
    {"(resolution: calc(1x + 0x))", false},
    {"(resolution: calc(1x + 96dpi))", true},
    {"(resolution: calc(0x + 37.79532dpcm))", false},
    {"(resolution: calc(3x - 1x))", true},
    {"(resolution: calc(3x - 2x))", false},
    {"(resolution: calc(3x - 96dpi))", true},
    {"(resolution: calc(2x - 37.79532dpcm))", false},
    {"(resolution: calc(1x * 2))", true},
    {"(resolution: calc(0.5x * 2))", false},
    {"(resolution: calc(4x / 2))", true},
    {"(resolution: calc(2x / 2))", false},
    {"(orientation: portrait)", true},
    {"(orientation: landscape)", false},
    {"(orientation: url(portrait))", false},
    {"(orientation: #portrait)", false},
    {"(orientation: @portrait)", false},
    {"(orientation: 'portrait')", false},
    {"(orientation: @junk portrait)", false},
    {"screen and (orientation: @portrait) and (max-width: 1000px)", false},
    {"screen and (orientation: @portrait), (max-width: 1000px)", true},
    {"tv and (scan: progressive)", false},
    {"(pointer: coarse)", false},
    {"(pointer: fine)", true},
    {"(hover: hover)", true},
    {"(hover: on-demand)", false},
    {"(hover: none)", false},
    {"(display-mode)", true},
    {"(display-mode: fullscreen)", false},
    {"(display-mode: standalone)", false},
    {"(display-mode: minimal-ui)", false},
    {"(display-mode: window-controls-overlay)", false},
    {"(display-mode: borderless)", false},
    {"(display-mode: browser)", true},
    {"(display-mode: min-browser)", false},
    {"(display-mode: url(browser))", false},
    {"(display-mode: #browser)", false},
    {"(display-mode: @browser)", false},
    {"(display-mode: 'browser')", false},
    {"(display-mode: @junk browser)", false},
    {"(display-mode: tabbed)", false},
    {"(display-mode: picture-in-picture)", false},
    {"(max-device-aspect-ratio: 4294967295/1)", true},
    {"(min-device-aspect-ratio: 1/4294967296)", true},
    {"(max-device-aspect-ratio: 0.5)", false},
    {"(max-device-aspect-ratio: 0.6/0.5)", true},
    {"(min-device-aspect-ratio: 1/2)", true},
    {"(max-device-aspect-ratio: 1.5)", true},
};

MediaQueryEvaluatorTestCase g_display_state_test_cases[] = {
    {"(display-state)", true},
    {"(display-state: fullscreen)", false},
    {"(display-state: minimized)", false},
    {"(display-state: maximized)", false},
    {"(display-state: normal)", true},
    {"(display-state: #normal)", false},
    {"(display-state: @normal)", false},
    {"(display-state: 'normal')", false},
    {"(display-state: @junk normal)", false},
};

MediaQueryEvaluatorTestCase g_resizable_test_cases[] = {
    {"(resizable)", true},
    {"(resizable: true)", true},
    {"(resizable: false)", false},
    {"(resizable: #true)", false},
    {"(resizable: @true)", false},
    {"(resizable: 'true')", false},
    {"(resizable: \"true\")", false},
    {"(resizable: @junk true)", false},
};

MediaQueryEvaluatorTestCase g_monochrome_test_cases[] = {
    {"(color)", false},
    {"(monochrome)", true},
};

MediaQueryEvaluatorTestCase g_viewport_test_cases[] = {
    {"all and (min-width: 500px)", true},
    {"(min-width: 500px)", true},
    {"(min-width: 501px)", false},
    {"(max-width: 500px)", true},
    {"(max-width: 499px)", false},
    {"(width: 500px)", true},
    {"(width: 501px)", false},
    {"(min-height: 500px)", true},
    {"(min-height: 501px)", false},
    {"(min-height: 500.02px)", false},
    {"(max-height: 500px)", true},
    {"(max-height: calc(500px))", true},
    {"(max-height: 499.98px)", false},
    {"(max-height: 499px)", false},
    {"(height: 500px)", true},
    {"(height: calc(500px))", true},
    {"(height: 500.001px)", true},
    {"(height: 499.999px)", true},
    {"(height: 500.02px)", false},
    {"(height: 499.98px)", false},
    {"(height: 501px)", false},
    {"(height)", true},
    {"(width)", true},
    {"(width: whatisthis)", false},
    {"screen and (min-width: 400px) and (max-width: 700px)", true},
    {"(max-aspect-ratio: 4294967296/1)", true},
    {"(max-aspect-ratio: calc(4294967296) / calc(1)", true},
    {"(min-aspect-ratio: 1/4294967295)", true},
};

MediaQueryEvaluatorTestCase g_float_viewport_test_cases[] = {
    {"all and (min-width: 600.5px)", true},
    {"(min-width: 600px)", true},
    {"(min-width: 600.5px)", true},
    {"(min-width: 601px)", false},
    {"(max-width: 600px)", false},
    {"(max-width: 600.5px)", true},
    {"(max-width: 601px)", true},
    {"(width: 600.5px)", true},
    {"(width: 601px)", false},
    {"(min-height: 700px)", true},
    {"(min-height: 700.125px)", true},
    {"(min-height: 701px)", false},
    {"(min-height: 700.141px)", false},
    {"(max-height: 701px)", true},
    {"(max-height: 700.125px)", true},
    {"(max-height: 700px)", false},
    {"(height: 700.125px)", true},
    {"(height: 700.141px)", false},
    {"(height: 700.109px)", false},
    {"(height: 701px)", false},
};

MediaQueryEvaluatorTestCase g_float_non_friendly_viewport_test_cases[] = {
    {"(min-width: 821px)", true},  {"(max-width: 821px)", true},
    {"(width: 821px)", true},      {"(min-height: 821px)", true},
    {"(max-height: 821px)", true}, {"(height: 821px)", true},
    {"(width: 100vw)", true},      {"(height: 100vh)", true},
};

MediaQueryEvaluatorTestCase g_print_test_cases[] = {
    {"print and (min-resolution: 1dppx)", true},
    {"print and (min-resolution: calc(100dpi - 4dpi))", true},
    {"print and (min-resolution: 118dpcm)", true},
    {"print and (min-resolution: 119dpcm)", false},
};

// Tests when the output device is print.
MediaQueryEvaluatorTestCase g_update_with_print_device_test_cases[] = {
    {"(update)", false},       {"(update: none)", true},
    {"(update: slow)", false}, {"(update: fast)", false},
    {"update: fast", false},   {"(update: ?)", false},
};

// Tests when the output device is slow.
MediaQueryEvaluatorTestCase g_update_with_slow_device_test_cases[] = {
    {"(update)", true},       {"(update: none)", false},
    {"(update: slow)", true}, {"(update: fast)", false},
    {"update: fast", false},  {"(update: ?)", false},
};

// Tests when the output device is slow.
MediaQueryEvaluatorTestCase g_update_with_fast_device_test_cases[] = {
    {"(update)", true},        {"(update: none)", false},
    {"(update: slow)", false}, {"(update: fast)", true},
    {"update: fast", false},   {"(update: ?)", false},
};

MediaQueryEvaluatorTestCase g_forcedcolors_active_cases[] = {
    {"(forced-colors: active)", true},
    {"(forced-colors: none)", false},
};

MediaQueryEvaluatorTestCase g_forcedcolors_none_cases[] = {
    {"(forced-colors: active)", false},
    {"(forced-colors: none)", true},
};

MediaQueryEvaluatorTestCase g_preferscontrast_nopreference_cases[] = {
    {"(prefers-contrast)", false},
    {"(prefers-contrast: more)", false},
    {"(prefers-contrast: less)", false},
    {"(prefers-contrast: no-preference)", true},
    {"(prefers-contrast: custom)", false},
};

MediaQueryEvaluatorTestCase g_preferscontrast_more_cases[] = {
    {"(prefers-contrast)", true},
    {"(prefers-contrast: more)", true},
    {"(prefers-contrast: less)", false},
    {"(prefers-contrast: no-preference)", false},
    {"(prefers-contrast: custom)", false},
};

MediaQueryEvaluatorTestCase g_preferscontrast_less_cases[] = {
    {"(prefers-contrast)", true},
    {"(prefers-contrast: more)", false},
    {"(prefers-contrast: less)", true},
    {"(prefers-contrast: no-preference)", false},
    {"(prefers-contrast: custom)", false},
};

MediaQueryEvaluatorTestCase g_preferscontrast_custom_cases[] = {
    {"(prefers-contrast)", true},
    {"(prefers-contrast: more)", false},
    {"(prefers-contrast: less)", false},
    {"(prefers-contrast: no-preference)", false},
    {"(prefers-contrast: custom)", true},
};

MediaQueryEvaluatorTestCase g_prefersreducedtransparency_nopreference_cases[] =
    {
        {"(prefers-reduced-transparency)", false},
        {"(prefers-reduced-transparency: reduce)", false},
        {"(prefers-reduced-transparency: no-preference)", true},
};

MediaQueryEvaluatorTestCase g_prefersreducedtransparency_reduce_cases[] = {
    {"(prefers-reduced-transparency)", true},
    {"(prefers-reduced-transparency: reduce)", true},
    {"(prefers-reduced-transparency: no-preference)", false},
};

MediaQueryEvaluatorTestCase g_navigationcontrols_back_button_cases[] = {
    {"(navigation-controls: back-button)", true},
    {"(navigation-controls: none)", false},
};

MediaQueryEvaluatorTestCase g_navigationcontrols_none_cases[] = {
    {"(navigation-controls: back-button)", false},
    {"(navigation-controls: none)", true},
};

MediaQueryEvaluatorTestCase g_single_horizontal_viewport_segment_cases[] = {
    {"(horizontal-viewport-segments)", true},
    {"(horizontal-viewport-segments: 1)", true},
    {"(horizontal-viewport-segments > 1)", false},
    {"(horizontal-viewport-segments: 2)", false},
    {"(horizontal-viewport-segments: none)", false},
    {"(horizontal-viewport-segments: 1px)", false},
    {"(horizontal-viewport-segments: 16/9)", false},
};

MediaQueryEvaluatorTestCase g_double_horizontal_viewport_segment_cases[] = {
    {"(horizontal-viewport-segments)", true},
    {"(horizontal-viewport-segments: 1)", false},
    {"(horizontal-viewport-segments: 2)", true},
    {"(horizontal-viewport-segments: 3)", false},
};

MediaQueryEvaluatorTestCase g_single_vertical_viewport_segment_cases[] = {
    {"(vertical-viewport-segments)", true},
    {"(vertical-viewport-segments: 1)", true},
    {"(vertical-viewport-segments: 2)", false},
    {"(vertical-viewport-segments: none)", false},
    {"(vertical-viewport-segments: 1px)", false},
    {"(vertical-viewport-segments: 16/9)", false},
};

MediaQueryEvaluatorTestCase g_double_vertical_viewport_segment_cases[] = {
    {"(vertical-viewport-segments)", true},
    {"(vertical-viewport-segments: 1)", false},
    {"(vertical-viewport-segments: 2)", true},
    {"(vertical-viewport-segments: 3)", false},
};

MediaQueryEvaluatorTestCase g_device_posture_none_cases[] = {
    {"(device-posture)", true},          {"(device-posture: continuous)", true},
    {"(device-posture: folded)", false}, {"(device-posture: 15)", false},
    {"(device-posture: 2px)", false},    {"(device-posture: 16/9)", false},
};

MediaQueryEvaluatorTestCase g_device_posture_folded_cases[] = {
    {"(device-posture)", true},
    {"(device-posture: continuous)", false},
    {"(device-posture: folded)", true},
};

MediaQueryEvaluatorTestCase g_device_posture_folded_over_cases[] = {
    {"(device-posture)", true},
    {"(device-posture: continuous)", false},
    {"(device-posture: folded)", false},
};

MediaQueryEvaluatorTestCase g_dynamic_range_standard_cases[] = {
    {"(dynamic-range: standard)", true},
    {"(dynamic-range: high)", false},
    {"(dynamic-range: invalid)", false},
};

MediaQueryEvaluatorTestCase g_dynamic_range_high_cases[] = {
    {"(dynamic-range: standard)", true},
    {"(dynamic-range: high)", true},
    {"(dynamic-range: invalid)", false},
};

MediaQueryEvaluatorTestCase g_dynamic_range_feature_disabled_cases[] = {
    {"(dynamic-range: standard)", false},
    {"(dynamic-range: high)", false},
    {"(dynamic-range: invalid)", false},
};

MediaQueryEvaluatorTestCase g_video_dynamic_range_standard_cases[] = {
    {"(video-dynamic-range: standard)", true},
    {"(video-dynamic-range: high)", false},
    {"(video-dynamic-range: invalid)", false},
};

MediaQueryEvaluatorTestCase g_video_dynamic_range_high_cases[] = {
    {"(video-dynamic-range: standard)", true},
    {"(video-dynamic-range: high)", true},
    {"(video-dynamic-range: invalid)", false},
};

MediaQueryEvaluatorTestCase g_video_dynamic_range_feature_disabled_cases[] = {
    {"(video-dynamic-range: standard)", false},
    {"(video-dynamic-range: high)", false},
    {"(video-dynamic-range: invalid)", false},
};

// Tests when the output device is print.
MediaQueryEvaluatorTestCase g_overflow_with_print_device_test_cases[] = {
    {"(overflow-inline)", false},        {"(overflow-block)", true},
    {"(overflow-inline: none)", true},   {"(overflow-block: none)", false},
    {"(overflow-block: paged)", true},   {"(overflow-inline: scroll)", false},
    {"(overflow-block: scroll)", false},
};

// Tests when the output device is scrollable.
MediaQueryEvaluatorTestCase g_overflow_with_scrollable_device_test_cases[] = {
    {"(overflow-inline)", true},        {"(overflow-block)", true},
    {"(overflow-inline: none)", false}, {"(overflow-block: none)", false},
    {"(overflow-block: paged)", false}, {"(overflow-inline: scroll)", true},
    {"(overflow-block: scroll)", true},
};

MediaQueryEvaluatorTestCase g_invertedcolors_none_cases[] = {
    {"(inverted-colors)", false},
    {"(inverted-colors: inverted)", false},
    {"(inverted-colors: none)", true},
};

MediaQueryEvaluatorTestCase g_invertedcolors_inverted_cases[] = {
    {"(inverted-colors)", true},
    {"(inverted-colors: inverted)", true},
    {"(inverted-colors: none)", false},
};

MediaQueryEvaluatorTestCase g_scripting_none_cases[] = {
    {"(scripting)", false},
    {"(scripting: none)", true},
    {"(scripting: initial-only)", false},
    {"(scripting: enabled)", false},
};

MediaQueryEvaluatorTestCase g_scripting_initial_only_cases[] = {
    {"(scripting)", false},
    {"(scripting: none)", false},
    {"(scripting: initial-only)", true},
    {"(scripting: enabled)", false},
};

MediaQueryEvaluatorTestCase g_scripting_enabled_cases[] = {
    {"(scripting)", true},
    {"(scripting: none)", false},
    {"(scripting: initial-only)", false},
    {"(scripting: enabled)", true},
};

void TestMQEvaluator(base::span<MediaQueryEvaluatorTestCase> test_cases,
                     const MediaQueryEvaluator* media_query_evaluator,
                     CSSParserMode mode) {
  MediaQuerySet* query_set = nullptr;
  for (const MediaQueryEvaluatorTestCase& test_case : test_cases) {
    if (String(test_case.input).empty()) {
      query_set = MediaQuerySet::Create();
    } else {
      StringView str(test_case.input);
      CSSParserTokenStream stream(str);
      query_set =
          MediaQueryParser::ParseMediaQuerySetInMode(stream, mode, nullptr);
    }
    EXPECT_EQ(test_case.output, media_query_evaluator->Eval(*query_set))
        << "Query: " << test_case.input;
  }
}

void TestMQEvaluator(base::span<MediaQueryEvaluatorTestCase> test_cases,
                     const MediaQueryEvaluator* media_query_evaluator) {
  TestMQEvaluator(test_cases, media_query_evaluator, kHTMLStandardMode);
}

TEST(MediaQueryEvaluatorTest, Cached) {
  MediaValuesCached::MediaValuesCachedData data;
  data.viewport_width = 500;
  data.viewport_height = 500;
  data.device_width = 500;
  data.device_height = 500;
  data.device_pixel_ratio = 2.0;
  data.color_bits_per_component = 24;
  data.monochrome_bits_per_component = 0;
  data.primary_pointer_type = mojom::blink::PointerType::kPointerFineType;
  data.primary_hover_type = mojom::blink::HoverType::kHoverHoverType;
  data.output_device_update_ability_type =
      mojom::blink::OutputDeviceUpdateAbilityType::kFastType;
  data.three_d_enabled = true;
  data.media_type = media_type_names::kScreen;
  data.strict_mode = true;
  data.display_mode = blink::mojom::DisplayMode::kBrowser;

  // Default values.
  {
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_screen_test_cases, media_query_evaluator);
    TestMQEvaluator(g_viewport_test_cases, media_query_evaluator);
  }

  // Default display-state values.
  {
    data.window_show_state = ui::mojom::blink::WindowShowState::kDefault;
    ScopedDesktopPWAsAdditionalWindowingControlsForTest scoped_feature(true);
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_display_state_test_cases, media_query_evaluator);
  }

  // Default resizable values.
  {
    ScopedDesktopPWAsAdditionalWindowingControlsForTest scoped_feature(true);
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_resizable_test_cases, media_query_evaluator);
  }

  // Print values.
  {
    data.media_type = media_type_names::kPrint;
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_print_test_cases, media_query_evaluator);
    data.media_type = media_type_names::kScreen;
  }

  // Update values with print device.
  {
    data.media_type = media_type_names::kPrint;
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_update_with_print_device_test_cases,
                    media_query_evaluator);
    data.media_type = media_type_names::kScreen;
  }

  // Update values with slow device.
  {
    data.output_device_update_ability_type =
        mojom::blink::OutputDeviceUpdateAbilityType::kSlowType;
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_update_with_slow_device_test_cases,
                    media_query_evaluator);
  }

  // Update values with fast device.
  {
    data.output_device_update_ability_type =
        mojom::blink::OutputDeviceUpdateAbilityType::kFastType;
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_update_with_fast_device_test_cases,
                    media_query_evaluator);
  }

  // Monochrome values.
  {
    data.color_bits_per_component = 0;
    data.monochrome_bits_per_component = 8;
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_monochrome_test_cases, media_query_evaluator);
    data.color_bits_per_component = 24;
    data.monochrome_bits_per_component = 0;
  }

  // Overflow values with printing.
  {
    data.media_type = media_type_names::kPrint;
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_overflow_with_print_device_test_cases,
                    media_query_evaluator);
    data.media_type = media_type_names::kScreen;
  }

  // Overflow values with scrolling.
  {
    auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_overflow_with_scrollable_device_test_cases,
                    media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, Dynamic) {
  test::TaskEnvironment task_environment;
  auto page_holder = std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
  page_holder->GetFrameView().SetMediaType(media_type_names::kScreen);

  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(&page_holder->GetFrame());
  TestMQEvaluator(g_viewport_test_cases, media_query_evaluator);
  TestMQEvaluator(g_overflow_with_scrollable_device_test_cases,
                  media_query_evaluator);
  TestMQEvaluator(g_update_with_fast_device_test_cases, media_query_evaluator);
  page_holder->GetFrame().GetSettings()->SetOutputDeviceUpdateAbilityType(
      mojom::blink::OutputDeviceUpdateAbilityType::kSlowType);
  TestMQEvaluator(g_update_with_slow_device_test_cases, media_query_evaluator);
  page_holder->GetFrameView().SetMediaType(media_type_names::kPrint);
  TestMQEvaluator(g_print_test_cases, media_query_evaluator);
  TestMQEvaluator(g_overflow_with_print_device_test_cases,
                  media_query_evaluator);
  TestMQEvaluator(g_update_with_print_device_test_cases, media_query_evaluator);
}

TEST(MediaQueryEvaluatorTest, DynamicNoView) {
  test::TaskEnvironment task_environment;
  auto page_holder = std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
  LocalFrame* frame = &page_holder->GetFrame();
  page_holder.reset();
  ASSERT_EQ(nullptr, frame->View());
  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(frame);
  MediaQuerySet* query_set = MediaQuerySet::Create("foobar", nullptr);
  EXPECT_FALSE(media_query_evaluator->Eval(*query_set));
}

TEST(MediaQueryEvaluatorTest, CachedFloatViewport) {
  MediaValuesCached::MediaValuesCachedData data;
  data.viewport_width = 600.5;
  data.viewport_height = 700.125;
  auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);

  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(media_values);
  TestMQEvaluator(g_float_viewport_test_cases, media_query_evaluator);
}

TEST(MediaQueryEvaluatorTest, CachedFloatViewportNonFloatFriendly) {
  MediaValuesCached::MediaValuesCachedData data;
  data.viewport_width = 821;
  data.viewport_height = 821;
  auto* media_values = MakeGarbageCollected<MediaValuesCached>(data);

  MediaQueryEvaluator* media_query_evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(media_values);
  TestMQEvaluator(g_float_non_friendly_viewport_test_cases,
                  media_query_evaluator);
}

TEST(MediaQueryEvaluatorTest, CachedForcedColors) {
  ScopedForcedColorsForTest scoped_feature(true);

  MediaValuesCached::MediaValuesCachedData data;

  // Forced colors - none.
  {
    data.forced_colors = ForcedColors::kNone;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_forcedcolors_none_cases, media_query_evaluator);
  }

  // Forced colors - active.
  {
    data.forced_colors = ForcedColors::kActive;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_forcedcolors_active_cases, media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, CachedPrefersContrast) {
  ScopedForcedColorsForTest forced_scoped_feature(true);

  MediaValuesCached::MediaValuesCachedData data;
  data.forced_colors = ForcedColors::kNone;

  // Prefers-contrast - no-preference.
  {
    data.preferred_contrast = mojom::blink::PreferredContrast::kNoPreference;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_preferscontrast_nopreference_cases,
                    media_query_evaluator);
  }

  // Prefers-contrast - more.
  {
    data.preferred_contrast = mojom::blink::PreferredContrast::kMore;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_preferscontrast_more_cases, media_query_evaluator);
  }

  // Prefers-contrast - less.
  {
    data.preferred_contrast = mojom::blink::PreferredContrast::kLess;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_preferscontrast_less_cases, media_query_evaluator);
  }

  // Prefers-contrast - custom.
  {
    data.preferred_contrast = mojom::blink::PreferredContrast::kCustom;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_preferscontrast_custom_cases, media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, CachedPrefersReducedTransparency) {
  MediaValuesCached::MediaValuesCachedData data;

  // Prefers-reduced-transparency - no-preference.
  {
    data.prefers_reduced_transparency = false;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_prefersreducedtransparency_nopreference_cases,
                    media_query_evaluator);
  }

  // Prefers-reduced-transparency - reduce.
  {
    data.prefers_reduced_transparency = true;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_prefersreducedtransparency_reduce_cases,
                    media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, CachedViewportSegments) {
  ScopedViewportSegmentsForTest scoped_feature(true);

  MediaValuesCached::MediaValuesCachedData data;
  {
    data.horizontal_viewport_segments = 1;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);

    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_single_horizontal_viewport_segment_cases,
                    media_query_evaluator);
  }

  {
    data.horizontal_viewport_segments = 2;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_double_horizontal_viewport_segment_cases,
                    media_query_evaluator);
  }

  {
    data.vertical_viewport_segments = 1;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);

    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_single_vertical_viewport_segment_cases,
                    media_query_evaluator);
  }

  {
    data.vertical_viewport_segments = 2;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_double_vertical_viewport_segment_cases,
                    media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, CachedDevicePosture) {
  ScopedDevicePostureForTest scoped_feature(true);

  MediaValuesCached::MediaValuesCachedData data;
  {
    data.device_posture = mojom::blink::DevicePostureType::kContinuous;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_device_posture_none_cases, media_query_evaluator);
  }

  {
    data.device_posture = mojom::blink::DevicePostureType::kFolded;
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_device_posture_folded_cases, media_query_evaluator);
  }
}

TEST(MediaQueryEvaluatorTest, CachedDynamicRange) {
  MediaValuesCached::MediaValuesCachedData data;

  // Test with color spaces supporting standard dynamic range
  {
    data.device_supports_hdr = gfx::DisplayColorSpaces().SupportsHDR();
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_dynamic_range_standard_cases, media_query_evaluator);
    TestMQEvaluator(g_video_dynamic_range_standard_cases,
                    media_query_evaluator);

    // Test again with the feature disabled
    ScopedCSSVideoDynamicRangeMediaQueriesForTest const disable_video_feature{
        false};
    TestMQEvaluator(g_video_dynamic_range_feature_disabled_cases,
                    media_query_evaluator);
  }
  {
    data.device_supports_hdr =
        gfx::DisplayColorSpaces(gfx::ColorSpace::CreateDisplayP3D65())
            .SupportsHDR();
    MediaValues* media_values = MakeGarbageCollected<MediaValuesCached>(data);
    MediaQueryEvaluator* media_query_evaluator =
        MakeGarbageCollected<MediaQueryEvaluator>(media_values);
    TestMQEvaluator(g_dynamic_range_standard_cases
"""


```