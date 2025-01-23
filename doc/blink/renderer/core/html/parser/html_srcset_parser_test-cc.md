Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Functionality:** The file name `html_srcset_parser_test.cc` immediately suggests this code tests the functionality of parsing the `srcset` attribute in HTML. The presence of `HTMLSrcsetParser` in the includes confirms this.

2. **Look for Test Structures:** The file uses `TEST` macros from the `gtest` framework. This is the primary way to define and organize tests in Chromium. We see `TEST(ImageCandidateTest, Basic)` and `TEST(HTMLSrcsetParserTest, Basic)`, `TEST(HTMLSrcsetParserTest, SaveDataEnabledBasic)`, and `TEST(HTMLSrcsetParserTest, MaxDensityEnabled)`. This tells us there are tests for both the `ImageCandidate` class and the `HTMLSrcsetParser` itself.

3. **Analyze the Test Cases:**  The heart of the file lies within the `SrcsetParserTestCase` structure and the arrays of these structures used within the `HTMLSrcsetParserTest` tests.

    * **`SrcsetParserTestCase`:**  This struct clearly defines the inputs and expected outputs of the parser. We see fields for:
        * `device_scale_factor`:  Simulates different screen densities.
        * `effective_size`:  Represents the available width for the image (important for `w` descriptors).
        * `src_input`:  The value of the `src` attribute (fallback image).
        * `srcset_input`:  The actual `srcset` string being tested.
        * `output_url`:  The expected URL chosen by the parser.
        * `output_density`: The expected pixel density of the chosen image.
        * `output_resource_width`: The expected intrinsic width of the chosen image (from `w` descriptors).

    * **Test Array Iteration:** The tests iterate through these arrays, calling `BestFitSourceForImageAttributes`. This function is the key under test. It takes the inputs from the test case and returns an `ImageCandidate`.

    * **Assertions:**  The `ASSERT_EQ` calls verify that the `ImageCandidate` returned by the parser matches the expected outputs in the test case.

4. **Infer the Functionality of `BestFitSourceForImageAttributes`:** Based on the test cases and the field names, we can infer that `BestFitSourceForImageAttributes` does the following:

    * **Parses the `srcset` string:** It breaks down the `srcset` attribute into individual image candidate entries.
    * **Interprets descriptors:** It understands the `w` (width), `x` (pixel density), and potentially other descriptors (like the invalid `q`, `h`, `z`, `pw`, `ex` descriptors the tests try).
    * **Selects the best candidate:** Based on the `device_scale_factor`, `effective_size`, and the descriptors, it chooses the most appropriate image URL from the `srcset`.
    * **Handles fallback `src`:** If `srcset` is empty or doesn't contain a suitable image, it falls back to the `src` attribute.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**

    * **HTML:**  The `srcset` attribute is a core HTML feature for responsive images. The tests directly relate to how browsers should interpret this attribute. The `src` attribute is also a fundamental HTML image attribute.
    * **CSS:**  While this specific code doesn't directly interact with CSS parsing, the *purpose* of `srcset` is tightly linked to CSS media queries. `srcset` provides image options, and CSS media queries often trigger the browser to select from these options based on viewport size or device characteristics.
    * **JavaScript:**  JavaScript can read and sometimes manipulate the `srcset` attribute. Understanding how the browser parses `srcset` is important for JavaScript developers who work with images.

6. **Identify Logic and Assumptions:** The tests are based on the assumption that the `BestFitSourceForImageAttributes` function correctly implements the `srcset` parsing logic according to web standards. The logic involves:

    * **Prioritizing candidates:**  There's a logic for choosing between `x` and `w` descriptors, and for selecting the best match based on device pixel ratio and available width.
    * **Handling invalid syntax:** The tests include cases with invalid descriptors (like negative values, incorrect units) to verify the parser's robustness.
    * **Edge cases:** The tests cover cases with empty `srcset`, `src` only, and various combinations of valid and invalid syntax.

7. **Identify Common Usage Errors:** The test cases themselves reveal potential user errors:

    * **Incorrect descriptor syntax:**  Using invalid units (`q`, `px`, `ex`), negative values, or missing spaces.
    * **Typos:**  Simple spelling errors in URLs or descriptors.
    * **Misunderstanding `w` descriptors:** Not providing accurate image widths or not understanding how `effective_size` influences the selection.
    * **Over-complicating `srcset`:**  Creating overly long or confusing `srcset` strings that are hard to debug.

8. **Specific Test Cases and Their Significance:**

    * **Basic tests:**  Cover the most common scenarios with `x` and `w` descriptors.
    * **Empty/whitespace tests:** Ensure the parser handles whitespace and empty strings correctly.
    * **Data URLs:** Test support for inline images.
    * **SVG with fragments:** Check how URL fragments are handled.
    * **`SaveDataEnabledBasic`:**  This test specifically checks the behavior when the browser's "Save Data" mode is enabled, suggesting a potential optimization or change in behavior in that scenario.
    * **`MaxDensityEnabled`:**  This test indicates a feature flag that might limit the maximum pixel density considered.

9. **Structure and Boilerplate:**  Recognize the standard Google Test setup (`#include`, `namespace blink`, `typedef struct`, `TEST`, `ASSERT_EQ`). The `test::TaskEnvironment` is common in Blink tests for managing asynchronous operations (though not heavily used in this particular file).

By following these steps, you can systematically analyze the C++ test file and understand its purpose, functionality, relationship to web technologies, underlying logic, and potential user errors it helps to prevent.
这个C++源代码文件 `html_srcset_parser_test.cc` 的主要功能是**测试 Blink 渲染引擎中用于解析 HTML `srcset` 属性的 `HTMLSrcsetParser` 类及其相关功能。**

具体来说，它通过一系列的单元测试用例来验证 `HTMLSrcsetParser` 是否能正确地解析 `srcset` 字符串，并根据给定的设备像素比（device scale factor）和有效尺寸（effective size）选择最合适的图像资源。

以下是更详细的功能分解和与 Web 技术的关系：

**1. 功能：解析 `srcset` 属性**

   - `srcset` 属性允许 HTML `<img>` 元素指定一组不同的图像资源，浏览器可以根据屏幕尺寸、像素密度等因素选择最合适的图像进行显示，从而实现响应式图片。
   - `HTMLSrcsetParser` 负责将这个字符串解析成浏览器可以理解的图像候选项列表，每个候选项包含图像的 URL 和描述符（如像素密度 `x` 和宽度 `w`）。

**2. 功能：选择最佳图像候选项**

   -  `BestFitSourceForImageAttributes` 函数（从测试用例中可以看出）是核心的测试对象。它模拟了浏览器根据设备像素比和有效尺寸从解析后的图像候选项中选择最佳图像的过程。
   -  **假设输入：**
      - `device_scale_factor`:  模拟不同的屏幕像素密度（例如 1.0, 2.0, 3.0）。
      - `effective_size`: 模拟图像的可用宽度（对于使用 `w` 描述符的情况）。
      - `src_input`:  `<img>` 标签的 `src` 属性值，作为备用图像。
      - `srcset_input`:  `<img>` 标签的 `srcset` 属性值，包含一组图像候选项。
   -  **假设输出：**
      - `output_url`:  选择的最佳图像的 URL。
      - `output_density`: 选择的图像的像素密度。
      - `output_resource_width`: 选择的图像的固有宽度（仅当使用了 `w` 描述符时）。

**3. 与 JavaScript、HTML、CSS 的关系**

   - **HTML:**  `srcset` 属性是 HTML5 的一部分，这个测试文件直接关系到浏览器如何解析和处理 HTML 结构中的这一属性。
      - **举例说明：**  当 HTML 中有如下代码时：
         ```html
         <img src="image-100.jpg"
              srcset="image-200.jpg 2x, image-300.jpg 3x"
              alt="A responsive image">
         ```
         `HTMLSrcsetParser` 的作用就是解析 `srcset="image-200.jpg 2x, image-300.jpg 3x"` 这个字符串。
   - **CSS:**  虽然这个测试文件本身不直接涉及 CSS，但 `srcset` 的目标是与 CSS Media Queries 结合使用，提供更精细的响应式图像控制。CSS 可以根据不同的屏幕尺寸应用不同的样式，而 `srcset` 可以根据屏幕像素密度提供不同的图像分辨率。
      - **举例说明：**  CSS Media Queries 可以检测屏幕宽度，然后浏览器会根据 `srcset` 选择合适的图像：
         ```css
         @media (max-width: 600px) {
           /* 应用于小屏幕 */
         }
         ```
   - **JavaScript:**  JavaScript 可以读取和操作 `srcset` 属性。了解 `srcset` 的解析规则对于编写处理图像的 JavaScript 代码非常重要。
      - **举例说明：**  JavaScript 可以获取 `srcset` 属性的值，或者在某些情况下动态修改它。

**4. 逻辑推理与假设输入输出**

   测试用例中的 `SrcsetParserTestCase` 结构定义了各种假设的输入和预期的输出。例如：

   - **假设输入：** `device_scale_factor = 2.0`, `effective_size = -1`, `srcset_input = "1x.gif 1x, 2x.gif 2x"`
   - **逻辑推理：** 当设备像素比为 2.0 时，应该选择像素密度为 2x 的图像，即 `2x.gif`。
   - **假设输出：** `output_url = "2x.gif"`, `output_density = 2.0`

   - **假设输入：** `device_scale_factor = 1.0`, `effective_size = 400`, `srcset_input = "400.gif 400w, 6000.gif 6000w"`
   - **逻辑推理：** 当有效尺寸为 400px 时，应该选择宽度接近但不超过 400px 的图像，即 `400.gif`。
   - **假设输出：** `output_url = "400.gif"`, `output_density = 1.0`, `output_resource_width = 400`

**5. 用户或编程常见的使用错误举例**

   测试用例也间接反映了一些用户或编程中常见的 `srcset` 使用错误：

   - **错误的描述符语法：**
      - `neg.gif -2x` (负的像素密度)
      - `2x.gif 2q` (使用了未知的描述符 `q`)
      - `2x.gif 2px` (像素单位 `px` 不应用于像素密度描述符)
      - `2x.gif 2ex` (长度单位 `ex` 不应用于像素密度描述符)
      - `2x.gif +2x` (像素密度描述符前不应有 `+`)
      - `data:,a 1 w` (宽度描述符 `w` 前后应该有空格分隔 URL 和描述符)
   - **`srcset` 字符串格式错误：**
      - `1x,,  ,   x    ,2x  ` (多个连续的逗号或空格)
   - **混淆像素密度和宽度描述符：** 没有理解 `x` 和 `w` 描述符的区别和使用场景。
   - **在 `srcset` 中使用无效的 URL：**  虽然测试用例中大多使用简单的文件名，但在实际使用中可能会遇到格式错误的 URL。

**总结**

`html_srcset_parser_test.cc` 是一个关键的测试文件，它确保了 Blink 渲染引擎能够正确地解析和使用 HTML `srcset` 属性，这是实现响应式图片、提升用户体验和优化网络资源加载的重要组成部分。 通过大量的测试用例，它涵盖了各种可能的输入情况和潜在的错误，保证了 `HTMLSrcsetParser` 的健壮性和正确性。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_srcset_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/parser/html_srcset_parser.h"

#include <limits.h>

#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/web_network_state_notifier.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

typedef struct {
  float device_scale_factor;
  float effective_size;
  const char* src_input;
  const char* srcset_input;
  const char* output_url;
  float output_density;
  int output_resource_width;
} SrcsetParserTestCase;

TEST(ImageCandidateTest, Basic) {
  test::TaskEnvironment task_environment;
  ImageCandidate candidate;
  ASSERT_EQ(candidate.Density(), 1);
  ASSERT_EQ(candidate.GetResourceWidth(), -1);
  ASSERT_EQ(candidate.SrcOrigin(), false);
}

TEST(HTMLSrcsetParserTest, Basic) {
  test::TaskEnvironment task_environment;
  SrcsetParserTestCase test_cases[] = {
      {2.0, 0.5, "", "data:,a 1w, data:,b 2x", "data:,a", 2.0, 1},
      {2.0, 1, "", "data:,a 2w, data:,b 2x", "data:,a", 2.0, 2},
      {2.0, -1, "", "1x.gif 1x, 2x.gif 2x", "2x.gif", 2.0, -1},
      {2.0, -1, "", "1x.gif 1q, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "", "1x.gif 1q, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "", "1x.gif 1x 100h, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "", "1x.gif 1x 100w, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "", "1x.gif 1x 100h 100w, 2x.gif 2x", "2x.gif", 2.0, -1},
      {2.0, -1, "", "1x.gif 1x, 2x.gif -2x", "1x.gif", 1.0, -1},
      {2.0, -1, "", "0x.gif 0x", "0x.gif", 0.0, -1},
      {2.0, -1, "", "0x.gif -0x", "0x.gif", 0.0, -1},
      {2.0, -1, "", "neg.gif -2x", "", 1.0, -1},
      {2.0, -1, "", "1x.gif 1x, 2x.gif 2q", "1x.gif", 1.0, -1},
      {2.0, -1, "", "1x.gif, 2x.gif 2q", "1x.gif", 1.0, -1},
      {2.0, -1, "", "1x.gif  , 2x.gif 2q", "1x.gif", 1.0, -1},
      {2.0, -1, "1x.gif 1x, 2x.gif 2x", "1x.gif 1x, 2x.gif 2x", "2x.gif", 2.0,
       -1},
      {1.0, -1, "1x.gif 1x, 2x.gif 2x", "1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0,
       -1},
      {1.0, -1, "1x.gif 1x, 2x.gif 2x", "", "1x.gif 1x, 2x.gif 2x", 1.0, -1},
      {2.0, -1, "src.gif", "1x.gif 1x, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "src.gif", "1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0, -1},
      {1.0, -1, "src.gif", "2x.gif 2x", "src.gif", 1.0, -1},
      {2.0, -1, "src.gif", "2x.gif 2x", "2x.gif", 2.0, -1},
      {2.0, -1, "src.gif", "2x.gif 2px", "src.gif", 1.0, -1},
      {2.0, -1, "src.gif", "2x.gif 2ex", "src.gif", 1.0, -1},
      {10.0, -1, "src.gif", "2x.gif 2e1x", "2x.gif", 20.0, -1},
      {2.0, -1, "src.gif", "2x.gif 2e1x", "src.gif", 1.0, -1},
      {2.0, -1, "src.gif", "2x.gif +2x", "src.gif", 1.0, -1},
      {1.5, -1, "src.gif", "2x.gif 2x", "2x.gif", 2.0, -1},
      {2.5, -1, "src.gif", "2x.gif 2x", "2x.gif", 2.0, -1},
      {2.5, -1, "src.gif", "2x.gif 2x, 3x.gif 3x", "3x.gif", 3.0, -1},
      {2.0, -1, "", "1x,,  ,   x    ,2x  ", "1x", 1.0, -1},
      {2.0, -1, "", "1x,,  ,   x    ,2x  ", "1x", 1.0, -1},
      {2.0, -1, "", ",,1x,,  ,   x    ,2x  ", "1x", 1.0, -1},
      {2.0, -1, "", ",,1x,,", "1x", 1.0, -1},
      {2.0, -1, "", ",1x,", "1x", 1.0, -1},
      {2.0, -1, "",
       "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg 1x, 2x.gif 2x", "2x.gif",
       2.0, -1},
      {2.0, -1, "",
       "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg 2x, 1x.gif 1x",
       "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg", 2.0, -1},
      {2.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100z, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "2x.gif", 2.0, -1},
      {4.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100h, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "2x.gif", 2.0, -1},
      {4.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100z, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "2x.gif", 2.0, -1},
      {1.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100z, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "1x", 1.0, -1},
      {5.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100z, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "2x.gif", 2.0, -1},
      {2.0, -1, "",
       "1x.gif 1x, "
       "data:image/"
       "svg+xml;base64,"
       "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGh"
       "laWdodD0iMTAwIj4KCTxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSJncm"
       "VlbiIvPgo8L3N2Zz4K 2x",
       "data:image/"
       "svg+xml;base64,"
       "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGh"
       "laWdodD0iMTAwIj4KCTxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSJncm"
       "VlbiIvPgo8L3N2Zz4K",
       2.0, -1},
      {2.0, -1, "1x.gif",
       "data:image/"
       "svg+xml;base64,"
       "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGh"
       "laWdodD0iMTAwIj4KCTxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSJncm"
       "VlbiIvPgo8L3N2Zz4K 2x",
       "data:image/"
       "svg+xml;base64,"
       "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGh"
       "laWdodD0iMTAwIj4KCTxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSJncm"
       "VlbiIvPgo8L3N2Zz4K",
       2.0, -1},
      {2.0, -1, "1x.svg#red", "1x.svg#green 2x", "1x.svg#green", 2.0, -1},
      {2.0, -1, "", "1x.svg#red 1x, 1x.svg#green 2x", "1x.svg#green", 2.0, -1},
      {1.0, 400, "", "400.gif 400w, 6000.gif 6000w", "400.gif", 1.0, 400},
      {1.0, 400, "", "400.gif 400pw, 6000.gif 6000w", "6000.gif", 15.0, 6000},
      {1.0, 400, "fallback.gif", "400.gif 400pw", "fallback.gif", 1.0, -1},
      {1.0, 400, "fallback.gif", "400.gif +400w", "fallback.gif", 1.0, -1},
      {1.0, 400, "", "400.gif 400w 400h, 6000.gif 6000w", "400.gif", 1.0, 400},
      {4.0, 400, "", "400.gif 400w, 6000.gif 6000w", "6000.gif", 15.0, 6000},
      {3.8, 400, "", "400.gif 400w, 6000.gif 6000w", "400.gif", 1.0, 400},
      {0.9, 800, "src.gif", "400.gif 400w", "400.gif", 0.5, 400},
      {0.9, 800, "src.gif", "1x.gif 1x, 400.gif 400w", "1x.gif", 1.0, -1},
      {0.9, 800, "src.gif", "1x.gif 0.6x, 400.gif 400w", "1x.gif", 0.6, -1},
      {0.9, 800, "src.gif", "1x.gif 1x, 400.gif 720w", "400.gif", 0.9, 720},
      {0.9, 800, "src.gif", "1x.gif 1x, 400.gif 719w", "1x.gif", 1.0, -1},
      {2.0, 800, "src.gif", "400.gif 400w", "400.gif", 0.5, 400},
      {1.0, 400, "src.gif", "800.gif 800w", "800.gif", 2.0, 800},
      {1.0, 400, "src.gif", "0.gif 0w, 800.gif 800w", "800.gif", 2.0, 800},
      {1.0, 400, "src.gif", "0.gif 0w, 2x.gif 2x", "src.gif", 1.0, -1},
      {1.0, 400, "src.gif", "800.gif 2x, 1600.gif 1600w", "800.gif", 2.0, -1},
      {1.0, 400, "", "400.gif 400w, 2x.gif 2x", "400.gif", 1.0, 400},
      {2.0, 400, "", "400.gif 400w, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, 0, "", "400.gif 400w, 6000.gif 6000w", "400.gif",
       std::numeric_limits<float>::infinity(), 400},
      {2.0, -1, "", ", 1x.gif 1x, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "", ",1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0, -1},
      {1.0, -1, "", ",1x.gif 1.x , 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.2, -1, "", ",1x.gif 1x, 1.4x.gif 1.4x, 2x.gif 2x", "1.4x.gif", 1.4,
       -1},
      {1.0, -1, "", "inf.gif 0.00000000001x", "inf.gif", 1e-11, -1},
      {1.0, -1, "", "data:,a ( , data:,b 1x, ), data:,c", "data:,c", 1.0, -1},
      {1.0, 1, "", "data:,a 1w 1h", "data:,a", 1.0, 1},
      {1.0, -1, "", ",1x.gif 1x future-descriptor(3x, 4h, whatever), 2x.gif 2x",
       "2x.gif", 2.0, -1},
      {2.0, -1, "", ",1x.gif 1x future-descriptor(3x, 4h, whatever), 2x.gif 2x",
       "2x.gif", 2.0, -1},
      {1.0, -1, "", "data:,a 1 w", "", 1.0, -1},
      {1.0, -1, "", "data:,a 1  w", "", 1.0, -1},
      {1.0, -1, "", "data:,a +1x", "", 1.0, -1},
      {1.0, -1, "", "data:,a   +1x", "", 1.0, -1},
      {1.0, -1, "", "data:,a 1.0x", "data:,a", 1.0, -1},
      {1.0, -1, "", "1%20and%202.gif 1x", "1%20and%202.gif", 1.0, -1},
      {1.0, 700, "", "data:,a 0.5x, data:,b 1400w", "data:,b", 2.0, 1400},
      {0, 0, nullptr, nullptr, nullptr,
       0}  // Do not remove the terminator line.
  };

  for (unsigned i = 0; test_cases[i].src_input; ++i) {
    SrcsetParserTestCase test = test_cases[i];
    ImageCandidate candidate = BestFitSourceForImageAttributes(
        test.device_scale_factor, test.effective_size, test.src_input,
        test.srcset_input);
    ASSERT_EQ(test.output_density, candidate.Density());
    ASSERT_EQ(test.output_resource_width, candidate.GetResourceWidth());
    ASSERT_EQ(test.output_url, candidate.ToString().Ascii());
  }
}

#if (BUILDFLAG(IS_ANDROID) && defined(ADDRESS_SANITIZER))
// https://crbug.com/1189511
#define MAYBE_SaveDataEnabledBasic DISABLED_SaveDataEnabledBasic
#else
#define MAYBE_SaveDataEnabledBasic SaveDataEnabledBasic
#endif
TEST(HTMLSrcsetParserTest, MAYBE_SaveDataEnabledBasic) {
  test::TaskEnvironment task_environment;
  SrcsetParserTestCase test_cases[] = {
      // 0
      {2.0, 0.5, "", "data:,a 1w, data:,b 2x", "data:,a", 2.0, 1},
      {2.0, 1, "", "data:,a 2w, data:,b 2x", "data:,a", 2.0, 2},
      {2.0, -1, "", "1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0, -1},
      {2.0, -1, "", "1x.gif 1q, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "", "1x.gif 1q, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "", "1x.gif 1x 100h, 2x.gif 2x", "2x.gif", 2.0, -1},  // 5
      {1.0, -1, "", "1x.gif 1x 100w, 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.0, -1, "", "1x.gif 1x 100h 100w, 2x.gif 2x", "2x.gif", 2.0, -1},
      {2.0, -1, "", "1x.gif 1x, 2x.gif -2x", "1x.gif", 1.0, -1},
      {2.0, -1, "", "0x.gif 0x", "0x.gif", 0.0, -1},
      {2.0, -1, "", "0x.gif -0x", "0x.gif", 0.0, -1},  // 10
      {2.0, -1, "", "neg.gif -2x", "", 1.0, -1},
      {2.0, -1, "", "1x.gif 1x, 2x.gif 2q", "1x.gif", 1.0, -1},
      {2.0, -1, "", "1x.gif, 2x.gif 2q", "1x.gif", 1.0, -1},
      {2.0, -1, "", "1x.gif  , 2x.gif 2q", "1x.gif", 1.0, -1},
      {2.0, -1, "1x.gif 1x, 2x.gif 2x", "1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0,
       -1},  // 15
      {1.0, -1, "1x.gif 1x, 2x.gif 2x", "1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0,
       -1},
      {1.0, -1, "1x.gif 1x, 2x.gif 2x", "", "1x.gif 1x, 2x.gif 2x", 1.0, -1},
      {2.0, -1, "src.gif", "1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0, -1},
      {1.0, -1, "src.gif", "1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0, -1},
      {1.0, -1, "src.gif", "2x.gif 2x", "src.gif", 1.0, -1},  // 20
      {2.0, -1, "src.gif", "2x.gif 2x", "src.gif", 1.0, -1},
      {2.0, -1, "src.gif", "2x.gif 2px", "src.gif", 1.0, -1},
      {2.0, -1, "src.gif", "2x.gif 2ex", "src.gif", 1.0, -1},
      {10.0, -1, "src.gif", "2x.gif 2e1x", "src.gif", 1.0, -1},
      {2.0, -1, "src.gif", "2x.gif 2e1x", "src.gif", 1.0, -1},  // 25
      {2.0, -1, "src.gif", "2x.gif +2x", "src.gif", 1.0, -1},
      {1.5, -1, "src.gif", "2x.gif 2x", "src.gif", 1.0, -1},
      {2.5, -1, "src.gif", "2x.gif 2x", "src.gif", 1.0, -1},
      {2.5, -1, "src.gif", "2x.gif 2x, 3x.gif 3x", "src.gif", 1.0, -1},
      {2.0, -1, "", "1x,,  ,   x    ,2x  ", "1x", 1.0, -1},  // 30
      {2.0, -1, "", "1x,,  ,   x    ,2x  ", "1x", 1.0, -1},
      {2.0, -1, "", ",,1x,,  ,   x    ,2x  ", "1x", 1.0, -1},
      {2.0, -1, "", ",,1x,,", "1x", 1.0, -1},
      {2.0, -1, "", ",1x,", "1x", 1.0, -1},
      {2.0, -1, "",
       "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg 1x, 2x.gif 2x",
       "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg", 1.0, -1},  // 35
      {2.0, -1, "",
       "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg 2x, 1x.gif 1x", "1x.gif",
       1.0, -1},
      {2.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100z, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "1x", 1.0, -1},
      {4.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100h, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "1x", 1.0, -1},
      {4.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100z, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "1x", 1.0, -1},
      {1.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100z, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "1x", 1.0, -1},  // 40
      {5.0, -1, "",
       "1x,,  ,   x    ,2x  , 1x.gif, 3x, 4x.gif 4x 100z, 5x.gif 5, dx.gif dx, "
       "2x.gif   2x ,",
       "1x", 1.0, -1},
      {2.0, -1, "",
       "1x.gif 1x, "
       "data:image/"
       "svg+xml;base64,"
       "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGh"
       "laWdodD0iMTAwIj4KCTxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSJncm"
       "VlbiIvPgo8L3N2Zz4K 2x",
       "1x.gif", 1.0, -1},
      {2.0, -1, "1x.gif",
       "data:image/"
       "svg+xml;base64,"
       "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGh"
       "laWdodD0iMTAwIj4KCTxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSJncm"
       "VlbiIvPgo8L3N2Zz4K 2x",
       "1x.gif", 1.0, -1},
      {2.0, -1, "1x.svg#red", "1x.svg#green 2x", "1x.svg#red", 1.0, -1},
      {2.0, -1, "", "1x.svg#red 1x, 1x.svg#green 2x", "1x.svg#red", 1.0,
       -1},  // 45
      {1.0, 400, "", "400.gif 400w, 6000.gif 6000w", "400.gif", 1.0, 400},
      {1.0, 400, "", "400.gif 400pw, 6000.gif 6000w", "6000.gif", 15.0, 6000},
      {1.0, 400, "fallback.gif", "400.gif 400pw", "fallback.gif", 1.0, -1},
      {1.0, 400, "fallback.gif", "400.gif +400w", "fallback.gif", 1.0, -1},
      {1.0, 400, "", "400.gif 400w 400h, 6000.gif 6000w", "400.gif", 1.0,
       400},  // 50
      {4.0, 400, "", "400.gif 400w, 6000.gif 6000w", "400.gif", 1.0, 400},
      {3.8, 400, "", "400.gif 400w, 6000.gif 6000w", "400.gif", 1.0, 400},
      {0.9, 800, "src.gif", "400.gif 400w", "400.gif", 0.5, 400},
      {0.9, 800, "src.gif", "1x.gif 1x, 400.gif 400w", "400.gif", 0.5, 400},
      {0.9, 800, "src.gif", "1x.gif 0.6x, 400.gif 400w", "400.gif", 0.5,
       400},  // 55
      {0.9, 800, "src.gif", "1x.gif 1x, 400.gif 720w", "400.gif", 0.9, 720},
      {0.9, 800, "src.gif", "1x.gif 1x, 400.gif 719w", "400.gif", 719.0 / 800.0,
       719},
      {2.0, 800, "src.gif", "400.gif 400w", "400.gif", 0.5, 400},
      {1.0, 400, "src.gif", "800.gif 800w", "800.gif", 2.0, 800},
      {1.0, 400, "src.gif", "0.gif 0w, 800.gif 800w", "800.gif", 2.0,
       800},  // 60
      {1.0, 400, "src.gif", "0.gif 0w, 2x.gif 2x", "src.gif", 1.0, -1},
      {1.0, 400, "src.gif", "800.gif 2x, 1600.gif 1600w", "800.gif", 2.0, -1},
      {1.0, 400, "", "400.gif 400w, 2x.gif 2x", "400.gif", 1.0, 400},
      {2.0, 400, "", "400.gif 400w, 2x.gif 2x", "400.gif", 1.0, 400},
      {1.0, 0, "", "400.gif 400w, 6000.gif 6000w", "400.gif",
       std::numeric_limits<float>::infinity(), 400},  // 65
      {2.0, -1, "", ", 1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0, -1},
      {1.0, -1, "", ",1x.gif 1x, 2x.gif 2x", "1x.gif", 1.0, -1},
      {1.0, -1, "", ",1x.gif 1.x , 2x.gif 2x", "2x.gif", 2.0, -1},
      {1.2, -1, "", ",1x.gif 1x, 1.4x.gif 1.4x, 2x.gif 2x", "1x.gif", 1.0, -1},
      {1.0, -1, "", "inf.gif 0.00000000001x", "inf.gif", 1e-11, -1},  // 70
      {1.0, -1, "", "data:,a ( , data:,b 1x, ), data:,c", "data:,c", 1.0, -1},
      {1.0, 1, "", "data:,a 1w 1h", "data:,a", 1.0, 1},
      {1.0, -1, "", ",1x.gif 1x future-descriptor(3x, 4h, whatever), 2x.gif 2x",
       "2x.gif", 2.0, -1},
      {2.0, -1, "", ",1x.gif 1x future-descriptor(3x, 4h, whatever), 2x.gif 2x",
       "2x.gif", 2.0, -1},
      {1.0, -1, "", "data:,a 1 w", "", 1.0, -1},  // 75
      {1.0, -1, "", "data:,a 1  w", "", 1.0, -1},
      {1.0, -1, "", "data:,a +1x", "", 1.0, -1},
      {1.0, -1, "", "data:,a   +1x", "", 1.0, -1},
      {1.0, -1, "", "data:,a 1.0x", "data:,a", 1.0, -1},
      {1.0, -1, "", "1%20and%202.gif 1x", "1%20and%202.gif", 1.0, -1},  // 80
      {1.0, 700, "", "data:,a 0.5x, data:,b 1400w", "data:,a", 0.5, -1},
      {0, 0, nullptr, nullptr, nullptr,
       0}  // Do not remove the terminator line.
  };

  blink::WebNetworkStateNotifier::SetSaveDataEnabled(true);
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({blink::features::kSaveDataImgSrcset},
                                       {});
  for (unsigned i = 0; test_cases[i].src_input; ++i) {
    SrcsetParserTestCase test = test_cases[i];
    ImageCandidate candidate = BestFitSourceForImageAttributes(
        test.device_scale_factor, test.effective_size, test.src_input,
        test.srcset_input);
    ASSERT_EQ(test.output_density, candidate.Density());
    ASSERT_EQ(test.output_resource_width, candidate.GetResourceWidth());
    ASSERT_EQ(test.output_url, candidate.ToString().Ascii());
  }
}

TEST(HTMLSrcsetParserTest, MaxDensityEnabled) {
  test::TaskEnvironment task_environment;
  ScopedSrcsetMaxDensityForTest srcset_max_density(true);
  SrcsetParserTestCase test_cases[] = {
      {10.0, -1, "src.gif", "2x.gif 2e1x", "src.gif", 1.0, -1},
      {2.5, -1, "src.gif", "1.5x.gif 1.5x, 3x.gif 3x", "3x.gif", 3.0, -1},
      {4.0, 400, "", "400.gif 400w, 1000.gif 1000w", "1000.gif", 2.5, 1000},
      {0, 0, nullptr, nullptr, nullptr,
       0}  // Do not remove the terminator line.
  };

  for (unsigned i = 0; test_cases[i].src_input; ++i) {
    SrcsetParserTestCase test = test_cases[i];
    ImageCandidate candidate = BestFitSourceForImageAttributes(
        test.device_scale_factor, test.effective_size, test.src_input,
        test.srcset_input);
    ASSERT_EQ(test.output_density, candidate.Density());
    ASSERT_EQ(test.output_resource_width, candidate.GetResourceWidth());
    ASSERT_EQ(test.output_url, candidate.ToString().Ascii());
  }
}

}  // namespace blink
```