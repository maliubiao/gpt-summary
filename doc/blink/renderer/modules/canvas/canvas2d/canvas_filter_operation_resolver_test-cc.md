Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Skim and Keyword Identification:**

The first step is a quick read-through, looking for recurring keywords and structural elements. Keywords like `TEST_P`, `TEST`, `INSTANTIATE_TEST_SUITE_P`, `EXPECT_THAT`, `EXPECT_FALSE`, `ShadowData`, `BlurFilterOperation`, `CreateFilterOperationsFromList`, `CreateFilterOperationsFromCSSFilter`, `V8TestingScope`, `ScriptValue`, and namespace names (`blink`) immediately jump out. These provide clues about the file's purpose.

**2. Understanding the Core Functionality:**

The presence of "filter" and operations related to it (`DropShadowFilterOperation`, `BlurFilterOperation`) strongly suggests the code deals with visual filters. The functions `CreateFilterOperationsFromList` and `CreateFilterOperationsFromCSSFilter` suggest two different ways these filters are being created or parsed.

**3. Recognizing the Test Structure:**

The `TEST_P` and `INSTANTIATE_TEST_SUITE_P` patterns are standard Google Test constructs for parameterized tests. This means the same test logic is being run with different sets of input data (the `FilterTestParams`). The `TEST` macro indicates regular, non-parameterized tests.

**4. Analyzing `FilterTestParams`:**

The `FilterTestParams` struct is crucial. It holds `testcase_name`, `filter`, and `expected_ops`. This clearly defines the input (the `filter` string) and the expected output (a vector of `FilterOperation` matchers). The `testcase_name` provides context.

**5. Focusing on the Tested Functions:**

The core functions being tested are:

* `CanvasFilterOperationResolver::CreateFilterOperationsFromList`: This function takes a list of `ScriptValue` (likely representing JavaScript objects) and converts them into a list of internal `FilterOperation` objects.
* `CanvasFilterOperationResolver::CreateFilterOperationsFromCSSFilter`: This function takes a CSS filter string (like "blur(5px)") and does the same conversion.

**6. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The `ScriptValue` type and the structure of the filter strings within the test cases (e.g., `{'name': 'dropShadow', ...}`) strongly indicate that these filters are being defined using JavaScript objects, likely mirroring the Canvas API's filter property.
* **CSS:**  The `CreateFilterOperationsFromCSSFilter` function explicitly deals with CSS filter syntax. This connects directly to the `filter` CSS property.
* **HTML:** The test involving `HTMLCanvasElement` shows how these filters are used in the context of the `<canvas>` element.

**7. Inferring Functionality and Logic:**

Based on the test cases, we can deduce the logic within the tested functions:

* **Parsing:**  The resolver needs to parse the input strings (both JavaScript objects and CSS strings) to extract the filter type and its parameters.
* **Validation:** The tests with `ESErrorType::kTypeError` indicate that the resolver performs input validation to ensure parameters have the correct types and values.
* **Object Creation:**  The resolver creates concrete `FilterOperation` objects (like `DropShadowFilterOperation` and `BlurFilterOperation`) based on the parsed input.
* **Parameter Handling:**  The tests demonstrate how different parameters (e.g., `dx`, `dy`, `stdDeviation`, `floodColor`, `floodOpacity`) are parsed and used to configure the `FilterOperation` objects.
* **Unit Conversion:** The CSS filter tests show how CSS units like `px` and `em` are handled, especially with and without style resolution.

**8. Considering User Errors and Debugging:**

The tests that check for exceptions (like `ESErrorType::kTypeError`) directly relate to potential user errors in JavaScript when defining canvas filters. The file itself serves as a debugging aid by providing concrete examples of valid and invalid filter definitions. Understanding the flow – user interacts with the canvas API, which then triggers the filter resolution logic – helps in tracing issues.

**9. Structuring the Explanation:**

Finally, the information needs to be organized logically. Start with a high-level summary of the file's purpose. Then, delve into the details of the tested functions, their relationship to web technologies, the logic inferred from the tests, potential user errors, and the debugging perspective. Use examples from the code to illustrate the points.

**Self-Correction/Refinement During the Process:**

* Initially, I might just think "it tests filter creation."  But further examination reveals the two distinct paths: from JavaScript objects and from CSS strings.
* Seeing the `V8TestingScope` clarifies that the JavaScript interaction is being simulated within the test environment.
*  The inclusion of `HTMLCanvasElement` and font resolution details adds another layer of understanding about the context in which these filters operate.
* Noticing the specific error codes helps refine the understanding of the validation logic being tested.

By following this structured approach, combining keyword recognition, pattern analysis, and careful examination of the test cases, we can effectively understand the functionality of the given C++ test file and its relevance to web development.
这个文件 `canvas_filter_operation_resolver_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `CanvasFilterOperationResolver` 类的功能**。

`CanvasFilterOperationResolver` 类的职责是将 Canvas 2D API 中用于定义滤镜效果的各种输入形式（例如 JavaScript 对象、CSS 滤镜字符串）转换为 Blink 引擎内部使用的 `FilterOperation` 对象。这些 `FilterOperation` 对象最终会被用于渲染 Canvas 上的内容，实现各种视觉效果，如模糊、阴影等。

让我们更详细地分解一下它的功能以及与 JavaScript, HTML, CSS 的关系：

**1. 功能：测试 `CanvasFilterOperationResolver` 的滤镜解析能力**

这个测试文件主要验证 `CanvasFilterOperationResolver` 类能够正确地将不同格式的滤镜定义解析成内部的 `FilterOperation` 对象。它包含了多个测试用例，分别针对不同的滤镜类型和参数组合。

* **从 JavaScript 对象解析滤镜:**  测试用例模拟了 JavaScript 中通过 Canvas 2D API 设置 `filter` 属性时传入的对象。例如，一个表示 drop-shadow 滤镜的 JavaScript 对象。
* **从 CSS 滤镜字符串解析滤镜:** 测试用例模拟了 CSS `filter` 属性的值，例如 `blur(5px)` 或 `drop-shadow(2px 2px 2px black)`。
* **处理不同类型的滤镜:** 测试用例覆盖了 `dropShadow` (阴影) 和 `gaussianBlur` (高斯模糊) 等滤镜类型。
* **处理滤镜参数:** 测试用例验证了对各种滤镜参数（如阴影的偏移量、模糊半径、颜色等）的正确解析。
* **处理参数的各种有效和无效值:** 测试用例不仅测试了有效的参数值，还测试了无效的参数值，并验证了是否会抛出预期的异常。
* **考虑样式解析:** 测试用例还考虑了 CSS 单位（如 `em`）的解析，这可能涉及到对元素的字体大小等样式信息的查询。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明**

* **JavaScript:**
    * **功能关系:** Canvas 2D API 允许开发者通过 JavaScript 代码来设置 Canvas 元素的滤镜效果。例如，可以使用 `canvasContext.filter = "blur(5px)";` 或者 `canvasContext.filter = [{ name: 'dropShadow', dx: 2, dy: 2, stdDeviation: 2 }];`。
    * **举例说明:**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');

        // 使用 CSS 滤镜字符串
        ctx.filter = 'blur(10px)';
        ctx.fillRect(10, 10, 100, 100);

        // 使用 JavaScript 对象数组定义滤镜
        ctx.filter = [
          { name: 'dropShadow', dx: 5, dy: 5, stdDeviation: 3, floodColor: 'rgba(0,0,0,0.5)' }
        ];
        ctx.fillStyle = 'red';
        ctx.fillRect(150, 10, 100, 100);
        ```
        `canvas_filter_operation_resolver_test.cc` 中的 `CreatesFilterOperationsFromObject` 和 `CreatesFilterOperationsFromObjectArray` 测试用例就是模拟解析上述 JavaScript 对象或对象数组的过程。

* **HTML:**
    * **功能关系:**  Canvas 元素本身在 HTML 中定义，而滤镜效果最终会渲染在 Canvas 上。
    * **举例说明:**
        ```html
        <canvas id="myCanvas" width="300" height="200"></canvas>
        ```
        虽然 HTML 本身不直接参与滤镜的解析过程，但 `HTMLCanvasElement` 对象在测试中被用来提供上下文信息，例如进行样式解析时需要访问 Document 和 Frame。

* **CSS:**
    * **功能关系:** Canvas 2D API 的 `filter` 属性也接受 CSS 滤镜函数作为字符串值。
    * **举例说明:**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.filter = 'grayscale(1) contrast(1.5)';
        ctx.drawImage(image, 0, 0);
        ```
        `canvas_filter_operation_resolver_test.cc` 中的 `CreatesFilterOperationsFromCSSFilter` 测试用例就是模拟解析这样的 CSS 滤镜字符串。

**3. 逻辑推理、假设输入与输出**

以 `DropShadowTests` 中的一个测试用例为例：

* **假设输入 (JavaScript 对象):**
  ```javascript
  ({
    "name": "dropShadow",
    "dx": 15,
    "dy": 10,
    "stdDeviation": 5,
    "floodColor": "purple",
    "floodOpacity": 0.7
  })
  ```

* **逻辑推理:** `CanvasFilterOperationResolver` 会解析这个 JavaScript 对象，提取出滤镜类型 (`dropShadow`) 和参数 (`dx`, `dy`, `stdDeviation`, `floodColor`, `floodOpacity`)。它会将颜色字符串 "purple" 解析为对应的颜色值，并将其他参数转换为数值。

* **预期输出 (`FilterOperation` 对象):**  一个 `DropShadowFilterOperation` 对象，其内部的 `ShadowData` 应该包含以下信息：
    * `offset`: `{15, 10}`
    * `blur`: `{5, 5}`
    * `spread`: `0` (默认值)
    * `color`: `StyleColor(Color::FromRGBA(128, 0, 128, 255))` (purple 的 RGBA 值)
    * `opacity`: `0.7`

**4. 用户或编程常见的使用错误及举例说明**

* **错误的滤镜名称:**
    * **错误示例 (JavaScript):**  `ctx.filter = [{ name: 'dropshadow', dx: 2, dy: 2 }];`  (注意 `dropshadow` 拼写错误)
    * **测试中的体现:**  测试文件可能会包含一些测试用例，尝试使用未知的滤镜名称，并验证是否会产生错误或被忽略。

* **错误的参数类型或值:**
    * **错误示例 (JavaScript):** `ctx.filter = [{ name: 'dropShadow', dx: 'abc', dy: 2 }];` ( `dx` 应该是数字) 或者 `ctx.filter = [{ name: 'gaussianBlur', stdDeviation: -5 }];` (模糊半径不能为负数，会被限制为 0)。
    * **测试中的体现:**  `FilterApiTest` 系列的测试用例专门用于测试各种参数的有效和无效类型/值，并验证是否会抛出 `TypeError` 等异常。例如，测试 `dropShadow` 的 `dx` 参数是否可以接受字符串、NaN、Infinity 等非法值。

* **CSS 滤镜语法错误:**
    * **错误示例 (CSS):** `ctx.filter = 'blur(10 px)';` (单位和数值之间有空格)
    * **测试中的体现:**  虽然这个测试文件主要关注 JavaScript 对象形式的滤镜，但解析 CSS 滤镜字符串的测试也会覆盖一些基本的语法错误情况。

**5. 用户操作如何一步步到达这里，作为调试线索**

当开发者在网页中使用 Canvas 2D API 设置滤镜时，会经历以下步骤，最终可能会触发 `CanvasFilterOperationResolver` 的代码：

1. **用户编写 JavaScript 代码:** 开发者使用 JavaScript 获取 Canvas 上下文，并设置 `filter` 属性。
2. **浏览器执行 JavaScript 代码:**  当浏览器执行到设置 `filter` 属性的代码时。
3. **Blink 引擎接收滤镜信息:** Blink 引擎的 JavaScript 绑定层会接收到开发者设置的滤镜信息 (可以是 JavaScript 对象或 CSS 字符串)。
4. **调用 `CanvasFilterOperationResolver`:** Blink 引擎内部会调用 `CanvasFilterOperationResolver` 的相关方法，将接收到的滤镜信息转换为内部的 `FilterOperation` 对象。
5. **滤镜应用和渲染:** 生成的 `FilterOperation` 对象会被传递到渲染流水线，最终用于绘制 Canvas 内容，实现滤镜效果。

**调试线索:**

* 如果用户看到的 Canvas 滤镜效果不符合预期，或者出现错误，可以考虑从以下几个方面进行调试：
    * **检查 JavaScript 代码:** 确保传递给 `filter` 属性的 JavaScript 对象或 CSS 字符串格式正确，参数值有效。
    * **查看浏览器控制台错误信息:** 如果滤镜参数无效，浏览器可能会抛出错误。
    * **断点调试 Blink 引擎代码:** 如果需要深入了解 Blink 引擎的解析过程，可以在 `CanvasFilterOperationResolver` 相关的代码中设置断点，例如在 `CreateFilterOperationsFromList` 或 `CreateFilterOperationsFromCSSFilter` 方法中。查看接收到的输入和生成的 `FilterOperation` 对象是否符合预期。
    * **参考测试用例:** `canvas_filter_operation_resolver_test.cc` 中的测试用例可以作为参考，了解各种滤镜参数的正确用法和预期行为。

总而言之，`canvas_filter_operation_resolver_test.cc` 是确保 Blink 引擎能够正确解析和处理 Canvas 2D API 滤镜功能的重要组成部分。它通过大量的测试用例覆盖了各种场景，帮助开发者避免在使用 Canvas 滤镜时遇到问题。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_filter_operation_resolver_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_filter_operation_resolver.h"

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/check_deref.h"
#include "base/functional/callback.h"  // IWYU pragma: keep (needed by GarbageCollectedIs)
#include "base/strings/stringprintf.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_object_objectarray_string.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"  // IWYU pragma: keep (https://github.com/clangd/clangd/issues/2044)
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/resolver/font_style_resolver.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/style/filter_operation.h"
#include "third_party/blink/renderer/core/style/shadow_data.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_filter_test_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/vector2d_f.h"

namespace blink {
namespace {

using ::blink_testing::GarbageCollectedIs;
using ::blink_testing::ParseFilter;
using ::testing::Combine;
using ::testing::ElementsAreArray;
using ::testing::Matcher;
using ::testing::SizeIs;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::Values;
using ::testing::ValuesIn;

struct FilterTestParams {
  std::string testcase_name;
  std::string filter;
  std::vector<Matcher<FilterOperation*>> expected_ops;
};

using FilterTest = TestWithParam<FilterTestParams>;

TEST_P(FilterTest, CreatesFilterOperationsFromObject) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  HeapVector<ScriptValue> filters = {
      CHECK_DEREF(ParseFilter(scope, GetParam().filter)).GetAsObject()};
  EXPECT_THAT(CanvasFilterOperationResolver::CreateFilterOperationsFromList(
                  filters, CHECK_DEREF(scope.GetExecutionContext()),
                  scope.GetExceptionState())
                  .Operations(),
              ElementsAreArray(GetParam().expected_ops));
  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

INSTANTIATE_TEST_SUITE_P(
    DropShadowTests,
    FilterTest,
    ValuesIn<FilterTestParams>({
        {.testcase_name = "DefaultParams",
         .filter = "({'name': 'dropShadow'})",
         .expected_ops = {GarbageCollectedIs<DropShadowFilterOperation>(
             ShadowData(
                 /*offset=*/{2, 2},
                 /*blur=*/{2, 2},
                 /*spread=*/0,
                 ShadowStyle::kNormal,
                 StyleColor(Color::kBlack),
                 /*opacity=*/1))}},

        {.testcase_name = "AllParamsSpecified",
         .filter = R"js(({
                     "name": "dropShadow",
                     "dx": 15,
                     "dy": 10,
                     "stdDeviation": 5,
                     "floodColor": "purple",
                     "floodOpacity": 0.7
                    }))js",
         .expected_ops = {GarbageCollectedIs<DropShadowFilterOperation>(
             ShadowData(
                 /*offset=*/{15, 10},
                 /*blur=*/{5, 5},
                 /*spread=*/0,
                 ShadowStyle::kNormal,
                 StyleColor(Color::FromRGBA(128, 0, 128, 255)),
                 /*opacity=*/0.7))}},

        {.testcase_name = "XYBlur",
         .filter = R"js(({
                     "name": "dropShadow",
                     "stdDeviation": [5, 10],
                    }))js",
         .expected_ops = {GarbageCollectedIs<DropShadowFilterOperation>(
             ShadowData(
                 /*offset=*/{2, 2},
                 /*blur=*/{5, 10},
                 /*spread=*/0,
                 ShadowStyle::kNormal,
                 StyleColor(Color::kBlack),
                 /*opacity=*/1.0))}},

        {.testcase_name = "NegativeBlur",
         .filter = R"js(({
                     "name": "dropShadow",
                     "stdDeviation": [-5, -10],
                    }))js",
         .expected_ops = {GarbageCollectedIs<DropShadowFilterOperation>(
             ShadowData(
                 /*offset=*/{2, 2},
                 /*blur=*/{0, 0},
                 /*spread=*/0,
                 ShadowStyle::kNormal,
                 StyleColor(Color::kBlack),
                 /*opacity=*/1.0))}},
    }),
    [](const TestParamInfo<FilterTestParams>& info) {
      return info.param.testcase_name;
    });

INSTANTIATE_TEST_SUITE_P(
    BlurFilterTests,
    FilterTest,
    ValuesIn<FilterTestParams>({
        {.testcase_name = "SingleValue",
         .filter = R"js(({
                     "name": "gaussianBlur",
                     "stdDeviation": 42,
                    }))js",
         .expected_ops = {GarbageCollectedIs<BlurFilterOperation>(
             Length::Fixed(42))}},
        {.testcase_name = "XYValues",
         .filter = R"js(({
                     "name": "gaussianBlur",
                     "stdDeviation": [123, 456],
                    }))js",
         .expected_ops = {GarbageCollectedIs<BlurFilterOperation>(
             Length::Fixed(123),
             Length::Fixed(456))}},
        {.testcase_name = "NegativeValue",
         .filter = R"js(({
                     "name": "gaussianBlur",
                     "stdDeviation": [-1234],
                    }))js",
         .expected_ops = {GarbageCollectedIs<BlurFilterOperation>(
             Length::Fixed(0))}},
        {.testcase_name = "NegativeValueX",
         .filter = R"js(({
                     "name": "gaussianBlur",
                     "stdDeviation": [-123, 456],
                    }))js",
         .expected_ops = {GarbageCollectedIs<BlurFilterOperation>(
             Length::Fixed(0),
             Length::Fixed(456))}},
        {.testcase_name = "NegativeValueY",
         .filter = R"js(({
                     "name": "gaussianBlur",
                     "stdDeviation": [123, -456],
                    }))js",
         .expected_ops = {GarbageCollectedIs<BlurFilterOperation>(
             Length::Fixed(123),
             Length::Fixed(0))}},
        {.testcase_name = "NegativeValueXY",
         .filter = R"js(({
                     "name": "gaussianBlur",
                     "stdDeviation": [-123, -456],
                    }))js",
         .expected_ops = {GarbageCollectedIs<BlurFilterOperation>(
             Length::Fixed(0),
             Length::Fixed(0))}},
    }),
    [](const TestParamInfo<FilterTestParams>& info) {
      return info.param.testcase_name;
    });

using FilterArrayTest = TestWithParam<FilterTestParams>;

TEST_P(FilterArrayTest, CreatesFilterOperationsFromObjectArray) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  CHECK(scope.GetExecutionContext());
  HeapVector<ScriptValue> filters =
      CHECK_DEREF(ParseFilter(scope, GetParam().filter)).GetAsObjectArray();
  EXPECT_THAT(CanvasFilterOperationResolver::CreateFilterOperationsFromList(
                  filters, CHECK_DEREF(scope.GetExecutionContext()),
                  scope.GetExceptionState())
                  .Operations(),
              ElementsAreArray(GetParam().expected_ops));
  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

INSTANTIATE_TEST_SUITE_P(
    FilterArrayTests,
    FilterArrayTest,
    ValuesIn<FilterTestParams>({
        {.testcase_name = "MultipleShadows",
         .filter = R"js(([
                    {
                        "name": "dropShadow",
                        "dx": 5,
                        "dy": 5,
                        "stdDeviation": 5,
                        "floodColor": "blue",
                        "floodOpacity": 0.5
                    },
                    {
                        "name": "dropShadow",
                        "dx": 10,
                        "dy": 10,
                        "stdDeviation": 10,
                        "floodColor": "red",
                        "floodOpacity": 0.7
                    }
                    ]))js",
         .expected_ops =
             {GarbageCollectedIs<DropShadowFilterOperation>(ShadowData(
                  /*offset=*/{5, 5},
                  /*blur=*/{5, 5},
                  /*spread=*/0,
                  ShadowStyle::kNormal,
                  StyleColor(Color::FromRGBA(0, 0, 255, 255)),
                  /*opacity=*/0.5)),
              GarbageCollectedIs<DropShadowFilterOperation>(ShadowData(
                  /*offset=*/{10, 10},
                  /*blur=*/{10, 10},
                  /*spread=*/0,
                  ShadowStyle::kNormal,
                  StyleColor(Color::FromRGBA(255, 0, 0, 255)),
                  /*opacity=*/0.7))}},
        {.testcase_name = "ShadowAndBlur",
         .filter = R"js(([
                    {
                        "name": "dropShadow",
                        "dx": 5,
                        "dy": 5,
                        "stdDeviation": 5,
                        "floodColor": "blue",
                        "floodOpacity": 0.5
                    },
                    {
                        "name": "gaussianBlur",
                        "stdDeviation": 12
                    }
                    ]))js",
         .expected_ops =
             {GarbageCollectedIs<DropShadowFilterOperation>(ShadowData(
                  /*offset=*/{5, 5},
                  /*blur=*/{5, 5},
                  /*spread=*/0,
                  ShadowStyle::kNormal,
                  StyleColor(Color::FromRGBA(0, 0, 255, 255)),
                  /*opacity=*/0.5)),
              GarbageCollectedIs<BlurFilterOperation>(
                  /*std_deviation=*/Length(12.0f, Length::Type::kFixed))}},
    }),
    [](const TestParamInfo<FilterTestParams>& info) {
      return info.param.testcase_name;
    });

using CSSFilterTest = TestWithParam<FilterTestParams>;

TEST_P(CSSFilterTest, CreatesFilterOperationsFromCSSFilter) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  EXPECT_THAT(
      CanvasFilterOperationResolver::CreateFilterOperationsFromCSSFilter(
          String(GetParam().filter), CHECK_DEREF(scope.GetExecutionContext()),
          /*style_resolution_host=*/nullptr, Font())
          .Operations(),
      ElementsAreArray(GetParam().expected_ops));
  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

INSTANTIATE_TEST_SUITE_P(
    CSSFilterParamTests,
    CSSFilterTest,
    ValuesIn<FilterTestParams>({
        {.testcase_name = "dropShadow",
         .filter = "drop-shadow(20px 25px 10px cyan)",
         .expected_ops = {GarbageCollectedIs<DropShadowFilterOperation>(
             ShadowData(
                 /*offset=*/{20, 25},
                 /*blur=*/{10, 10},
                 /*spread=*/0,
                 ShadowStyle::kNormal,
                 StyleColor(Color::FromRGBA(0, 255, 255, 255)),
                 /*opacity=*/1.0))}},

        {.testcase_name = "blur",
         .filter = "blur(12px)",
         .expected_ops = {GarbageCollectedIs<BlurFilterOperation>(
             /*std_deviation=*/Length(12.0f, Length::Type::kFixed))}},
    }),
    [](const TestParamInfo<FilterTestParams>& info) {
      return info.param.testcase_name;
    });

TEST(CSSResolutionTest,
     CreatesFilterOperationsFromCSSFilterWithStyleResolution) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  HTMLCanvasElement* canvas =
      MakeGarbageCollected<HTMLCanvasElement>(scope.GetDocument());
  // Pre-condition for using style resolution for fonts.
  ASSERT_NE(canvas->GetDocument().GetFrame(), nullptr);
  Font font(FontStyleResolver::ComputeFont(
      *CSSParser::ParseFont("10px sans-serif", scope.GetExecutionContext()),
      canvas->GetFontSelector()));
  EXPECT_THAT(
      CanvasFilterOperationResolver::CreateFilterOperationsFromCSSFilter(
          String("drop-shadow(1em 1em 0 black)"),
          CHECK_DEREF(scope.GetExecutionContext()), canvas, font)
          .Operations(),
      ElementsAreArray(
          {GarbageCollectedIs<DropShadowFilterOperation>(ShadowData(
              /*offset=*/{10, 10},
              /*blur=*/{0, 0},
              /*spread=*/0, ShadowStyle::kNormal, StyleColor(Color::kBlack),
              /*opacity=*/1.0))}));
  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

TEST(CSSResolutionTest,
     CreatesFilterOperationsFromCSSFilterWithNoStyleResolution) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  EXPECT_THAT(
      CanvasFilterOperationResolver::CreateFilterOperationsFromCSSFilter(
          String("drop-shadow(1em 1em 0 black)"),
          CHECK_DEREF(scope.GetExecutionContext()),
          /*style_resolution_host=*/nullptr, Font())
          .Operations(),
      // Font sized is assumed to be 16px when no style resolution is available.
      ElementsAreArray(
          {GarbageCollectedIs<DropShadowFilterOperation>(ShadowData(
              /*offset=*/{16, 16},
              /*blur=*/{0, 0},
              /*spread=*/0, ShadowStyle::kNormal, StyleColor(Color::kBlack),
              /*opacity=*/1.0))}));
  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

using FilterApiTest = TestWithParam<
    std::tuple<std::string, std::string, std::string, ExceptionCode>>;

TEST_P(FilterApiTest, RaisesExceptionForInvalidType) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  const auto& [filter_name, param_key, param_value, expected_error] =
      GetParam();
  HeapVector<ScriptValue> filters = {
      CHECK_DEREF(
          ParseFilter(scope, base::StringPrintf(
                                 "({name: '%s', %s: %s})", filter_name.c_str(),
                                 param_key.c_str(), param_value.c_str())))
          .GetAsObject()};

  EXPECT_THAT(
      CanvasFilterOperationResolver::CreateFilterOperationsFromList(
          filters, CHECK_DEREF(scope.GetExecutionContext()),
          scope.GetExceptionState())
          .Operations(),
      SizeIs(expected_error == ToExceptionCode(DOMExceptionCode::kNoError)
                 ? 1
                 : 0));
  EXPECT_EQ(scope.GetExceptionState().Code(), expected_error);
}

INSTANTIATE_TEST_SUITE_P(
    DropShadowValidParamTests,
    FilterApiTest,
    Combine(Values("dropShadow"),
            Values("dx", "dy", "floodOpacity"),
            Values("10",
                   "-1",
                   "0.5",
                   "null",
                   "true",
                   "false",
                   "[]",
                   "[20]",
                   "'30'"),
            Values(ToExceptionCode(DOMExceptionCode::kNoError))));

INSTANTIATE_TEST_SUITE_P(
    DropShadowInvalidParamTests,
    FilterApiTest,
    Combine(Values("dropShadow"),
            Values("dx", "dy", "floodOpacity"),
            Values("NaN",
                   "Infinity",
                   "-Infinity",
                   "undefined",
                   "'asdf'",
                   "{}",
                   "[1,2]"),
            Values(ToExceptionCode(ESErrorType::kTypeError))));

INSTANTIATE_TEST_SUITE_P(
    ValidStdDeviationTests,
    FilterApiTest,
    Combine(Values("dropShadow", "gaussianBlur"),
            Values("stdDeviation"),
            Values("10",
                   "-1",
                   "0.5",
                   "null",
                   "true",
                   "false",
                   "[]",
                   "[20]",
                   "'30'",
                   "[1,2]",
                   "[[1],'2']",
                   "[null,[]]"),
            Values(ToExceptionCode(DOMExceptionCode::kNoError))));

INSTANTIATE_TEST_SUITE_P(
    InvalidStdDeviationTests,
    FilterApiTest,
    Combine(Values("dropShadow", "gaussianBlur"),
            Values("stdDeviation"),
            Values("NaN",
                   "Infinity",
                   "-Infinity",
                   "undefined",
                   "'asdf'",
                   "{}",
                   "[1,2,3]",
                   "[1,'asdf']",
                   "[1,'undefined']"),
            Values(ToExceptionCode(ESErrorType::kTypeError))));

INSTANTIATE_TEST_SUITE_P(
    DropShadowValidFloodColorTests,
    FilterApiTest,
    Combine(Values("dropShadow"),
            Values("floodColor"),
            Values("'red'",
                   "'canvas'",
                   "'rgba(4,-3,0.5,1)'",
                   "'#aabbccdd'",
                   "'#abcd'"),
            Values(ToExceptionCode(DOMExceptionCode::kNoError))));

INSTANTIATE_TEST_SUITE_P(
    DropShadowInvalidFloodColorTests,
    FilterApiTest,
    Combine(
        Values("dropShadow"),
        Values("floodColor"),
        Values("'asdf'", "'rgba(NaN,3,2,1)'", "10", "undefined", "null", "NaN"),
        Values(ToExceptionCode(ESErrorType::kTypeError))));

}  // namespace
}  // namespace blink

"""

```