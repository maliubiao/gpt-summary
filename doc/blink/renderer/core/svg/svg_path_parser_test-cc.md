Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to understand what the `svg_path_parser_test.cc` file does and how it relates to the broader context of web development (JavaScript, HTML, CSS).

2. **Identify the Core Functionality:**  The filename itself, "svg_path_parser_test.cc," strongly suggests it's a test file for an SVG path parser. The `#include "third_party/blink/renderer/core/svg/svg_path_parser.h"` confirms this. The code then proceeds to define helper functions and test cases.

3. **Analyze the Helper Functions:**
    * `ParsePath(const char* input, String& output)`: This function takes a string representing an SVG path, parses it using `svg_path_parser::ParsePath`, and builds a normalized output string using `SVGPathStringBuilder`. The `had_error` return value is also important.
    * `#define VALID(input, expected)` and `#define MALFORMED(input, expected)`: These macros are clearly for defining test cases. `VALID` asserts that parsing succeeds and the output matches the `expected` string. `MALFORMED` asserts that parsing *fails* (returns `false`) and the output matches the `expected` (likely a prefix of the path up to the error).
    * `ParsePathWithError(const char* input)`: This function is specifically for testing error reporting. It calls the parser and then returns the `SVGParsingError` object.
    * `#define EXPECT_ERROR(input, expectedLocus, expectedError)`: This macro asserts the type of error and the location where the error occurred.

4. **Examine the Test Cases:** The `TEST(SVGPathParserTest, ...)` blocks contain the actual test cases. Look for patterns and categories of tests:
    * **Simple Cases:** Tests basic SVG path commands (M, L, H, V, Z, C, S, Q, T, A) in both absolute and relative forms. Pay attention to variations in spacing and comma usage.
    * **Malformed Cases:** Tests invalid path strings, like incorrect command usage, missing values, or invalid characters.
    * **Arc Command Variations:** Specifically tests different combinations of arc flags.
    * **Chained Commands:** Tests sequences of the same command (e.g., multiple 'h' or 'H' commands).
    * **Scientific Notation:** Tests how the parser handles numbers in scientific notation.
    * **Error Reporting:**  Tests specific error scenarios and checks that the parser correctly identifies the error type and location.

5. **Relate to Web Technologies:**  Now connect the functionality to JavaScript, HTML, and CSS:
    * **HTML:** The `<svg>` element in HTML uses the `d` attribute to define path data. This is the direct input to the parser being tested.
    * **CSS:**  CSS can also use SVG paths in features like `clip-path` and `mask`. The parsing logic is the same.
    * **JavaScript:** JavaScript can manipulate SVG elements and their attributes, including the `d` attribute. Libraries might use similar parsing logic or interact with the browser's built-in SVG rendering engine, which relies on a parser like this.

6. **Illustrate with Examples:** Provide concrete examples of how the tested functionality manifests in web development:
    * Show an `<svg>` tag with a `path` element and the `d` attribute.
    * Show a CSS rule using `clip-path` with an SVG path.
    * Show a JavaScript snippet that gets or sets the `d` attribute of an SVG path.

7. **Consider User Errors and Debugging:** Think about common mistakes developers might make when writing SVG paths and how this test file helps catch those errors:
    * Typos in command names.
    * Incorrect number of arguments for a command.
    * Invalid characters.
    * Incorrect arc flag values.
    * Missing the initial 'M' (moveto).

8. **Trace User Actions:**  Describe the sequence of user actions that might lead to this code being executed during debugging:
    * A developer creating or editing an SVG in a text editor.
    * A tool generating SVG code.
    * A web page loading with an SVG.
    * The browser's rendering engine encountering the SVG path and needing to parse it.

9. **Formulate Assumptions and Outputs:**  For the logical reasoning aspect, select a few interesting test cases and explicitly state the input and expected output (or error). This demonstrates understanding of the parsing rules.

10. **Structure the Answer:** Organize the findings into logical sections (Functionality, Relationship to Web Technologies, Examples, User Errors, Debugging, Assumptions/Outputs). Use clear and concise language.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  "It just parses SVG paths."  **Refinement:** "It parses SVG path *strings* and validates them, normalizing the output."
* **Initial thought:** "It's only used internally." **Refinement:** "While internal to the rendering engine, understanding its purpose is crucial for web developers to avoid common SVG path errors."
* **Missing connection:**  Initially, I might forget to explicitly link the parsing to the browser's rendering process. **Correction:** Add the step where the browser encounters the SVG and needs to parse the path data to draw it.

By following this structured approach and continually refining understanding, a comprehensive and accurate analysis of the test file can be achieved.
好的，让我们来详细分析一下 `blink/renderer/core/svg/svg_path_parser_test.cc` 这个文件。

**文件功能：**

这个 `svg_path_parser_test.cc` 文件的主要功能是**测试 blink 引擎中 SVG 路径解析器 (`SVGPathParser`) 的正确性**。它包含了大量的单元测试用例，用于验证解析器在处理各种合法的和非法的 SVG 路径字符串时的行为是否符合预期。

具体来说，它测试了：

1. **解析合法路径字符串：** 验证解析器能否正确解析各种 SVG 路径命令（如 `M`, `L`, `H`, `V`, `C`, `S`, `Q`, `T`, `A`, `Z`）及其大小写形式，以及不同的参数格式（空格、逗号分隔，正负号，小数，科学计数法等）。
2. **处理非法路径字符串：** 验证解析器能否正确识别并报告各种格式错误的路径字符串，并输出预期部分的结果。
3. **错误报告：**  验证解析器在遇到错误时能否提供准确的错误类型和错误发生的位置。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件虽然是 C++ 代码，但它直接关系到浏览器如何解析和渲染网页中使用的 SVG 路径，而 SVG 路径通常被用在 HTML 和 CSS 中，并且可以通过 JavaScript 进行操作。

1. **HTML：** SVG 路径最常见的用法是在 HTML 的 `<svg>` 元素中的 `<path>` 标签的 `d` 属性中定义。

   ```html
   <svg width="100" height="100">
     <path d="M 10 10 L 90 90" stroke="black" />
   </svg>
   ```

   在这个例子中，`d="M 10 10 L 90 90"` 就是一个 SVG 路径字符串。`svg_path_parser_test.cc` 中的测试用例就是用来验证 blink 引擎能否正确解析像这样的字符串。例如，测试用例 `VALID("M10,20 L30,40", "M 10 20 L 30 40")` 验证了对类似路径的解析和标准化输出。

2. **CSS：** SVG 路径也可以用在 CSS 的 `clip-path` 属性中来定义元素的裁剪区域，或者用在 `mask` 属性中定义遮罩。

   ```css
   .clipped {
     clip-path: path("M 0 0 L 100 0 L 100 100 Z");
   }
   ```

   同样，blink 引擎需要解析这个 CSS 属性值中的 SVG 路径字符串。`svg_path_parser_test.cc` 中测试了各种路径格式，确保了 CSS 中使用的路径也能被正确解析。

3. **JavaScript：** JavaScript 可以动态地创建、修改 SVG 元素及其属性，包括 `path` 元素的 `d` 属性。

   ```javascript
   const pathElement = document.createElementNS('http://www.w3.org/2000/svg', 'path');
   pathElement.setAttribute('d', 'M 50 50 C 75 0 75 100 100 50 Z');
   document.querySelector('svg').appendChild(pathElement);
   ```

   当 JavaScript 设置或修改 `d` 属性时，blink 引擎同样会调用路径解析器来处理新的路径字符串。测试用例覆盖了各种可能的路径字符串格式，有助于确保 JavaScript 操作的 SVG 路径能够被正确渲染。

**逻辑推理、假设输入与输出：**

测试文件中的 `VALID` 和 `MALFORMED` 宏就体现了逻辑推理和假设输入输出的过程。

**`VALID` 宏（预期解析成功）：**

* **假设输入：** `"M1,2"`
* **逻辑推理：**  这是一个合法的绝对移动命令，移动到坐标 (1, 2)。解析器应该能够正确识别 'M' 命令和参数 1 和 2。
* **预期输出：** `"M 1 2"` (解析器会将路径标准化，例如在命令和参数之间添加空格)

* **假设输入：** `"m100,200 c3,4,5,6,7,8"`
* **逻辑推理：**  先是一个绝对移动命令 `M 100 200`，然后是一个相对三次贝塞尔曲线命令 `c 3 4 5 6 7 8`。解析器需要正确识别这两个命令和它们的参数。
* **预期输出：** `"M 100 200 c 3 4 5 6 7 8"`

**`MALFORMED` 宏（预期解析失败）：**

* **假设输入：** `"L1,2"`
* **逻辑推理：**  路径字符串以 'L' 命令开始，但根据 SVG 规范，路径必须以 'M'（或 'm'）命令开始。因此，这是一个格式错误的路径。
* **预期输出：** `""` (表示解析失败，可能返回空字符串或者解析到错误发生前的部分)

* **假设输入：** `"M1,1c2,3 4,5 6,7 8"`
* **逻辑推理：**  三次贝塞尔曲线命令 'c' 需要 6 个参数，这里只提供了 7 个数值，但没有足够的参数组成完整的命令序列。
* **预期输出：** `"M 1 1 c 2 3 4 5 6 7"` (解析器可能解析到遇到错误的地方)

**用户或编程常见的使用错误举例：**

1. **忘记起始的 `M` 或 `m` 命令：**  用户在定义路径时，可能直接从画线命令开始，忘记了移动到起始点的命令。
   * **错误示例：** `"L 10 20"`
   * **`svg_path_parser_test.cc` 中的对应测试用例：** `MALFORMED("L1,2", "")` 和 `EXPECT_ERROR("L 10 10", 0u, SVGParseStatus::kExpectedMoveToCommand);`

2. **命令参数数量错误：**  用户可能为某个命令提供了错误数量的参数。例如，`L` 命令需要两个参数（x, y），而 `C` 命令需要六个参数。
   * **错误示例：** `"M 10 10 L 20"` (缺少 L 命令的 y 坐标)
   * **`svg_path_parser_test.cc` 中的对应测试用例：** `MALFORMED("M1,1c2,3 4,5 6,7 8", "M 1 1 c 2 3 4 5 6 7")` 和 `EXPECT_ERROR("M 10 10 L100 ", 13u, SVGParseStatus::kExpectedNumber);`

3. **无效的命令字母：**  用户可能输入了不存在或错误的命令字母。
   * **错误示例：** `"X 10 20"`
   * **`svg_path_parser_test.cc` 中的对应测试用例：** `MALFORMED("xM1,2", "")` 和 `EXPECT_ERROR("M 10 10 #", 8u, SVGParseStatus::kExpectedPathCommand);`

4. **错误的数值格式：**  用户可能使用了非法的数值格式，例如缺少小数点后的数字或使用了非法字符。
   * **错误示例：** `"M 10. 20"` 或 `"M 10a 20"`
   * **`svg_path_parser_test.cc` 中的对应测试用例：** `MALFORMED("M 0.6.5", "M 0.6")` 和 类似 `EXPECT_ERROR` 的用例检查 `kExpectedNumber` 错误。

5. **Arc 命令参数错误：**  `A` 或 `a` 命令有多个参数，包括弧形的半径、角度、标志位等，很容易出错。
   * **错误示例：** `"M 0 0 A 10 10 0 2 0 20 20"` (弧形标志位只能是 0 或 1)
   * **`svg_path_parser_test.cc` 中的对应测试用例：** `MALFORMED("M100,200 a3,4,5,2,1,6,7", "M 100 200")` 和 `EXPECT_ERROR` 系列针对 arc flag 的测试。

**用户操作如何一步步到达这里作为调试线索：**

当开发者在浏览器中遇到 SVG 路径渲染问题时，他们可能会采取以下步骤进行调试，而这些步骤最终会涉及到 `svg_path_parser_test.cc` 中测试的代码：

1. **开发者创建或修改了包含 SVG 路径的 HTML 文件。**  例如，他们可能手动编写了 `<path>` 元素的 `d` 属性，或者使用图形编辑器生成了 SVG 代码。
2. **浏览器加载该 HTML 文件。**
3. **浏览器的渲染引擎开始解析 HTML 和 CSS。** 当遇到 `<svg>` 元素和其中的 `<path>` 元素时，渲染引擎会获取 `d` 属性的值。
4. **渲染引擎调用 SVG 路径解析器 (`SVGPathParser`) 来解析 `d` 属性中的字符串。** 这是 `blink/renderer/core/svg/svg_path_parser.h` 和 `.cc` 文件中定义的代码发挥作用的时刻。
5. **如果路径字符串格式正确，解析器会生成路径的内部表示，用于后续的渲染。**
6. **如果路径字符串格式错误，解析器会报告错误。** 这可能会导致 SVG 图形无法正确显示，或者在开发者工具中显示错误信息。
7. **开发者可能会打开浏览器的开发者工具 (通常按 F12)。**
8. **在 "Elements" 或 "检查器" 面板中，开发者可以查看 SVG 元素的属性，包括 `d` 属性的值。**
9. **在 "Console" 面板中，如果解析过程中发生了错误，浏览器可能会输出相关的错误信息，**  这些错误信息可能间接来源于 `SVGPathParser` 内部的错误报告机制。
10. **开发者可能会尝试修改 `d` 属性的值，然后刷新页面查看效果。**  每次修改都会触发路径解析器重新解析。
11. **如果开发者怀疑是浏览器的 SVG 解析器本身有问题 (尽管这种情况比较少见)，或者他们正在开发 blink 引擎，那么他们可能会查看 `svg_path_parser_test.cc` 文件，运行其中的测试用例，来验证解析器的行为是否符合预期。**  如果某个测试用例失败，那么就说明解析器在处理特定类型的路径字符串时存在 bug。
12. **开发者可能会使用调试器 (例如 gdb 或 lldb) 来单步执行 `SVGPathParser` 的代码，查看解析过程中的变量值，以便更深入地理解问题所在。**

因此，`svg_path_parser_test.cc` 文件中的测试用例，实际上是模拟了浏览器在解析和渲染网页中 SVG 路径时可能遇到的各种情况，确保了浏览器的 SVG 渲染功能的稳定性和正确性。当用户看到错误的 SVG 图形时，背后很可能就是路径解析器在处理某个特定格式的路径字符串时出现了问题，而 `svg_path_parser_test.cc` 就是用来预防和排查这类问题的关键工具。

### 提示词
```
这是目录为blink/renderer/core/svg/svg_path_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/svg/svg_path_parser.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/svg/svg_path_string_builder.h"
#include "third_party/blink/renderer/core/svg/svg_path_string_source.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

bool ParsePath(const char* input, String& output) {
  String input_string(input);
  SVGPathStringSource source(input_string);
  SVGPathStringBuilder builder;
  bool had_error = svg_path_parser::ParsePath(source, builder);
  output = builder.Result();
  // Coerce a null result to empty.
  if (output.IsNull())
    output = g_empty_string;
  return had_error;
}

#define VALID(input, expected)             \
  {                                        \
    String output;                         \
    EXPECT_TRUE(ParsePath(input, output)); \
    EXPECT_EQ(expected, output);           \
  }

#define MALFORMED(input, expected)          \
  {                                         \
    String output;                          \
    EXPECT_FALSE(ParsePath(input, output)); \
    EXPECT_EQ(expected, output);            \
  }

TEST(SVGPathParserTest, Simple) {
  test::TaskEnvironment task_environment;
  VALID("M1,2", "M 1 2");
  VALID("m1,2", "m 1 2");
  VALID("M100,200 m3,4", "M 100 200 m 3 4");
  VALID("M100,200 L3,4", "M 100 200 L 3 4");
  VALID("M100,200 l3,4", "M 100 200 l 3 4");
  VALID("M100,200 H3", "M 100 200 H 3");
  VALID("M100,200 h3", "M 100 200 h 3");
  VALID("M100,200 V3", "M 100 200 V 3");
  VALID("M100,200 v3", "M 100 200 v 3");
  VALID("M100,200 Z", "M 100 200 Z");
  VALID("M100,200 z", "M 100 200 Z");
  VALID("M100,200 C3,4,5,6,7,8", "M 100 200 C 3 4 5 6 7 8");
  VALID("M100,200 c3,4,5,6,7,8", "M 100 200 c 3 4 5 6 7 8");
  VALID("M100,200 S3,4,5,6", "M 100 200 S 3 4 5 6");
  VALID("M100,200 s3,4,5,6", "M 100 200 s 3 4 5 6");
  VALID("M100,200 Q3,4,5,6", "M 100 200 Q 3 4 5 6");
  VALID("M100,200 q3,4,5,6", "M 100 200 q 3 4 5 6");
  VALID("M100,200 T3,4", "M 100 200 T 3 4");
  VALID("M100,200 t3,4", "M 100 200 t 3 4");
  VALID("M100,200 A3,4,5,0,0,6,7", "M 100 200 A 3 4 5 0 0 6 7");
  VALID("M100,200 A3,4,5,1,0,6,7", "M 100 200 A 3 4 5 1 0 6 7");
  VALID("M100,200 A3,4,5,0,1,6,7", "M 100 200 A 3 4 5 0 1 6 7");
  VALID("M100,200 A3,4,5,1,1,6,7", "M 100 200 A 3 4 5 1 1 6 7");
  VALID("M100,200 a3,4,5,0,0,6,7", "M 100 200 a 3 4 5 0 0 6 7");
  VALID("M100,200 a3,4,5,0,1,6,7", "M 100 200 a 3 4 5 0 1 6 7");
  VALID("M100,200 a3,4,5,1,0,6,7", "M 100 200 a 3 4 5 1 0 6 7");
  VALID("M100,200 a3,4,5,1,1,6,7", "M 100 200 a 3 4 5 1 1 6 7");
  VALID("M100,200 a3,4,5,006,7", "M 100 200 a 3 4 5 0 0 6 7");
  VALID("M100,200 a3,4,5,016,7", "M 100 200 a 3 4 5 0 1 6 7");
  VALID("M100,200 a3,4,5,106,7", "M 100 200 a 3 4 5 1 0 6 7");
  VALID("M100,200 a3,4,5,116,7", "M 100 200 a 3 4 5 1 1 6 7");
  MALFORMED("M100,200 a3,4,5,2,1,6,7", "M 100 200");
  MALFORMED("M100,200 a3,4,5,1,2,6,7", "M 100 200");

  VALID("M100,200 a0,4,5,0,0,10,0 a4,0,5,0,0,0,10 a0,0,5,0,0,-10,0 z",
        "M 100 200 a 0 4 5 0 0 10 0 a 4 0 5 0 0 0 10 a 0 0 5 0 0 -10 0 Z");

  VALID("M1,2,3,4", "M 1 2 L 3 4");
  VALID("m100,200,3,4", "m 100 200 l 3 4");

  VALID("M 100-200", "M 100 -200");
  VALID("M 0.6.5", "M 0.6 0.5");

  VALID(" M1,2", "M 1 2");
  VALID("  M1,2", "M 1 2");
  VALID("\tM1,2", "M 1 2");
  VALID("\nM1,2", "M 1 2");
  VALID("\rM1,2", "M 1 2");
  MALFORMED("\vM1,2", "");
  MALFORMED("xM1,2", "");
  VALID("M1,2 ", "M 1 2");
  VALID("M1,2\t", "M 1 2");
  VALID("M1,2\n", "M 1 2");
  VALID("M1,2\r", "M 1 2");
  MALFORMED("M1,2\v", "M 1 2");
  MALFORMED("M1,2x", "M 1 2");
  MALFORMED("M1,2 L40,0#90", "M 1 2 L 40 0");

  VALID("", "");
  VALID(" ", "");
  MALFORMED("x", "");
  MALFORMED("L1,2", "");
  VALID("M.1 .2 L.3 .4 .5 .6", "M 0.1 0.2 L 0.3 0.4 L 0.5 0.6");

  MALFORMED("M", "");
  MALFORMED("M\0", "");

  MALFORMED("M1,1Z0", "M 1 1 Z");
  MALFORMED("M1,1z0", "M 1 1 Z");

  VALID("M1,1h2,3", "M 1 1 h 2 h 3");
  VALID("M1,1H2,3", "M 1 1 H 2 H 3");
  VALID("M1,1v2,3", "M 1 1 v 2 v 3");
  VALID("M1,1V2,3", "M 1 1 V 2 V 3");

  MALFORMED("M1,1c2,3 4,5 6,7 8", "M 1 1 c 2 3 4 5 6 7");
  VALID("M1,1c2,3 4,5 6,7 8,9 10,11 12,13",
        "M 1 1 c 2 3 4 5 6 7 c 8 9 10 11 12 13");
  MALFORMED("M1,1C2,3 4,5 6,7 8", "M 1 1 C 2 3 4 5 6 7");
  VALID("M1,1C2,3 4,5 6,7 8,9 10,11 12,13",
        "M 1 1 C 2 3 4 5 6 7 C 8 9 10 11 12 13");
  MALFORMED("M1,1s2,3 4,5 6", "M 1 1 s 2 3 4 5");
  VALID("M1,1s2,3 4,5 6,7 8,9", "M 1 1 s 2 3 4 5 s 6 7 8 9");
  MALFORMED("M1,1S2,3 4,5 6", "M 1 1 S 2 3 4 5");
  VALID("M1,1S2,3 4,5 6,7 8,9", "M 1 1 S 2 3 4 5 S 6 7 8 9");
  MALFORMED("M1,1q2,3 4,5 6", "M 1 1 q 2 3 4 5");
  VALID("M1,1q2,3 4,5 6,7 8,9", "M 1 1 q 2 3 4 5 q 6 7 8 9");
  MALFORMED("M1,1Q2,3 4,5 6", "M 1 1 Q 2 3 4 5");
  VALID("M1,1Q2,3 4,5 6,7 8,9", "M 1 1 Q 2 3 4 5 Q 6 7 8 9");
  MALFORMED("M1,1t2,3 4", "M 1 1 t 2 3");
  VALID("M1,1t2,3 4,5", "M 1 1 t 2 3 t 4 5");
  MALFORMED("M1,1T2,3 4", "M 1 1 T 2 3");
  VALID("M1,1T2,3 4,5", "M 1 1 T 2 3 T 4 5");
  MALFORMED("M1,1a2,3,4,0,0,5,6 7", "M 1 1 a 2 3 4 0 0 5 6");
  VALID("M1,1a2,3,4,0,0,5,6 7,8,9,0,0,10,11",
        "M 1 1 a 2 3 4 0 0 5 6 a 7 8 9 0 0 10 11");
  MALFORMED("M1,1A2,3,4,0,0,5,6 7", "M 1 1 A 2 3 4 0 0 5 6");
  VALID("M1,1A2,3,4,0,0,5,6 7,8,9,0,0,10,11",
        "M 1 1 A 2 3 4 0 0 5 6 A 7 8 9 0 0 10 11");

  // Scientific notation.
  VALID("M1e2,10e1", "M 100 100");
  VALID("M100e0,100", "M 100 100");
  VALID("M1e+2,1000e-1", "M 100 100");
  VALID("M1e2.5", "M 100 0.5");
  VALID("M0.00000001e10 100", "M 100 100");
  VALID("M1e-46,50 h1e38", "M 0 50 h 1.00000e+38");
  VALID("M0,50 h1e-123456789123456789123", "M 0 50 h 0");
  MALFORMED("M0,50 h1e39", "M 0 50");
  MALFORMED("M0,50 h1e123456789123456789123", "M 0 50");
  MALFORMED("M0,50 h1e-.5", "M 0 50");
  MALFORMED("M0,50 h1e+.5", "M 0 50");
}

#undef MALFORMED
#undef VALID

SVGParsingError ParsePathWithError(const char* input) {
  String input_string(input);
  SVGPathStringSource source(input_string);
  SVGPathStringBuilder builder;
  svg_path_parser::ParsePath(source, builder);
  return source.ParseError();
}

#define EXPECT_ERROR(input, expectedLocus, expectedError) \
  {                                                       \
    SVGParsingError error = ParsePathWithError(input);    \
    EXPECT_EQ(expectedError, error.Status());             \
    EXPECT_TRUE(error.HasLocus());                        \
    EXPECT_EQ(expectedLocus, error.Locus());              \
  }

TEST(SVGPathParserTest, ErrorReporting) {
  test::TaskEnvironment task_environment;
  // Missing initial moveto.
  EXPECT_ERROR(" 10 10", 1u, SVGParseStatus::kExpectedMoveToCommand);
  EXPECT_ERROR("L 10 10", 0u, SVGParseStatus::kExpectedMoveToCommand);
  // Invalid command letter.
  EXPECT_ERROR("M 10 10 #", 8u, SVGParseStatus::kExpectedPathCommand);
  EXPECT_ERROR("M 10 10 E 100 100", 8u, SVGParseStatus::kExpectedPathCommand);
  // Invalid number.
  EXPECT_ERROR("M 10 10 L100 ", 13u, SVGParseStatus::kExpectedNumber);
  EXPECT_ERROR("M 10 10 L100 #", 13u, SVGParseStatus::kExpectedNumber);
  EXPECT_ERROR("M 10 10 L100#100", 12u, SVGParseStatus::kExpectedNumber);
  EXPECT_ERROR("M0,0 A#,10 0 0,0 20,20", 6u, SVGParseStatus::kExpectedNumber);
  EXPECT_ERROR("M0,0 A10,# 0 0,0 20,20", 9u, SVGParseStatus::kExpectedNumber);
  EXPECT_ERROR("M0,0 A10,10 # 0,0 20,20", 12u, SVGParseStatus::kExpectedNumber);
  EXPECT_ERROR("M0,0 A10,10 0 0,0 #,20", 18u, SVGParseStatus::kExpectedNumber);
  EXPECT_ERROR("M0,0 A10,10 0 0,0 20,#", 21u, SVGParseStatus::kExpectedNumber);
  // Invalid arc-flag.
  EXPECT_ERROR("M0,0 A10,10 0 #,0 20,20", 14u,
               SVGParseStatus::kExpectedArcFlag);
  EXPECT_ERROR("M0,0 A10,10 0 0,# 20,20", 16u,
               SVGParseStatus::kExpectedArcFlag);
  EXPECT_ERROR("M0,0 A10,10 0 0,2 20,20", 16u,
               SVGParseStatus::kExpectedArcFlag);
}

#undef EXPECT_ERROR

}  // namespace

}  // namespace blink
```