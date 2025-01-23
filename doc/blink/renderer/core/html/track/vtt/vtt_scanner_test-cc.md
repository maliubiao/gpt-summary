Response:
Let's break down the thought process for analyzing the `vtt_scanner_test.cc` file.

1. **Understand the Goal:** The core request is to analyze a C++ test file in the Chromium Blink engine. The goal isn't just to list functions, but to explain what the file *does*, how it relates to web technologies, potential errors, and even how a user might indirectly trigger its execution.

2. **Initial Examination (Header):** The initial comments are crucial. They immediately tell us this is part of the Blink renderer, specifically dealing with VTT (WebVTT) scanning. The copyright notice indicates it originated with Opera Software. This gives us context: this is about processing subtitle/caption data for `<video>` and `<audio>` elements.

3. **Include Directives:** The `#include` statements are the next important clues:
    * `"third_party/blink/renderer/core/html/track/vtt/vtt_scanner.h"`: This confirms that the test file is specifically for the `VTTScanner` class.
    * `"testing/gtest/include/gtest/gtest.h"`:  This reveals it's using the Google Test framework for unit testing. We can expect `TEST()` macros.
    * `"third_party/blink/renderer/platform/testing/task_environment.h"`: This suggests the tests might involve some form of asynchronous operations or environment setup, although in this specific file, it appears mainly for setup.
    * `"third_party/blink/renderer/platform/wtf/text/wtf_string.h"`:  Indicates the use of Blink's string class (`WTF::String`).

4. **Namespace:** The `namespace blink { ... }` block clarifies the scope of the code.

5. **Test Structure:** The `TEST(VTTScannerTest, ...)` macros are the heart of the file. Each `TEST` case focuses on testing a specific aspect of the `VTTScanner` class. The first step in analysis is to identify these test cases and their names.

6. **Analyzing Individual Test Cases:**  This is the bulk of the work. For each test case:
    * **Purpose:** What functionality is being tested? Look at the function name (e.g., `Constructor`, `BasicOperations1`, `PredicateScanning`).
    * **Setup:**  What input data is being used?  Are there helper functions?
    * **Assertions:** What `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ` statements are present? These are the checks that verify the `VTTScanner` is working correctly.
    * **Helper Functions:** Notice the `ScanSequenceHelper1`, `ScanSequenceHelper2`, etc. These simplify the tests by encapsulating common sequences of `VTTScanner` operations. Analyze what these helpers do.
    * **Macros:** The `TEST_WITH` macro is interesting. It indicates the tests are run with both 8-bit and 16-bit string encodings. This is important for understanding how Blink handles different character sets.
    * **Specific `VTTScanner` Methods:** Identify which methods of the `VTTScanner` class are being called in each test case (e.g., `Match`, `Scan`, `SkipWhile`, `CountWhile`, `ExtractString`, `RestOfInputAsString`, `ScanDigits`, `ScanDouble`).
    * **Data Types:** Pay attention to the data types being passed to and returned from the `VTTScanner` methods (e.g., `UChar`, `String`, `size_t`, `unsigned`, `double`).

7. **Connecting to Web Technologies (HTML, CSS, JavaScript):** This requires understanding the role of VTT in web development.
    * **HTML:**  The `<track>` element is the direct link. The `src` attribute of `<track>` points to VTT files.
    * **JavaScript:**  The WebVTT API allows JavaScript to interact with and manipulate track data. The parsing done by `VTTScanner` is a crucial first step.
    * **CSS:**  While less direct, CSS can style the appearance of captions/subtitles rendered from VTT data.

8. **Hypothetical Inputs and Outputs:** For the more complex tests, try to mentally trace the execution with specific input strings. Predict what the `EXPECT` statements should evaluate to. This solidifies understanding.

9. **Common User/Programming Errors:** Think about how incorrect VTT files might lead to issues. Typos in timestamps, malformed cues, and incorrect formatting are common problems. The `VTTScanner` is designed to handle some of these robustly, but errors can still occur.

10. **User Operations:**  This requires linking the low-level C++ code to user actions in a web browser. Think about the steps a user takes to play a video with subtitles.

11. **Refinement and Organization:**  After the initial analysis, organize the findings into logical categories (functionality, relationships to web tech, errors, user interaction). Use clear and concise language. Provide concrete examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just tests basic string scanning."
* **Correction:** "Wait, it's specifically for *VTT* scanning. That means it's dealing with timed cues and specific formatting rules."
* **Initial thought:** "The `TaskEnvironment` is for complex asynchronous testing."
* **Correction:** "In *this* file, it seems primarily for setting up the basic testing environment. The tests themselves look synchronous."
* **Initial thought:** "The `TEST_WITH` macro is just for convenience."
* **Correction:** "No, it's explicitly testing both 8-bit and 16-bit string handling, which is important for internationalization."

By continually asking "why?" and connecting the code to its higher-level purpose, a deeper understanding emerges. The process involves a combination of code reading, domain knowledge (WebVTT), and logical reasoning.
好的，让我们来详细分析一下 `blink/renderer/core/html/track/vtt/vtt_scanner_test.cc` 这个文件。

**文件功能总览**

`vtt_scanner_test.cc` 文件是 Chromium Blink 引擎中用于测试 `VTTScanner` 类的单元测试文件。`VTTScanner` 类的主要功能是**解析 WebVTT (Web Video Text Tracks) 格式的文本数据**。WebVTT 是一种用于显示视频字幕、标题、描述、章节等的文本格式。

简单来说，`vtt_scanner_test.cc` 的作用就是**确保 `VTTScanner` 类能够正确地读取和识别 WebVTT 文件的各种语法元素**，例如：

*   基本的字符匹配和扫描。
*   匹配和扫描特定的字符串。
*   基于特定条件的字符扫描（例如，扫描所有小写字母）。
*   提取子字符串。
*   扫描数字和浮点数。

**与 JavaScript, HTML, CSS 的关系**

`VTTScanner` 位于 Blink 引擎的底层，负责解析 VTT 文件内容，这与前端的 JavaScript, HTML, CSS 有着密切的关系：

1. **HTML `<track>` 元素:**
    *   **功能关系:** HTML 的 `<track>` 元素用于指定视频或音频的外部文本轨道（例如字幕）。`src` 属性指向 VTT 文件。
    *   **用户操作到达此处的路径:**
        1. 用户在 HTML 中添加一个 `<video>` 或 `<audio>` 元素。
        2. 用户在该元素中添加一个 `<track>` 子元素，并设置 `src` 属性指向一个 `.vtt` 文件。
        3. 当浏览器加载该页面或用户开始播放媒体时，Blink 引擎会请求并下载该 VTT 文件。
        4. Blink 引擎会使用 `VTTScanner` 来解析下载的 VTT 文件内容，提取字幕、时间戳等信息。

    *   **举例说明:**

        ```html
        <video controls>
          <source src="my-video.mp4" type="video/mp4">
          <track src="subtitles.vtt" kind="subtitles" srclang="en" label="English">
        </video>
        ```

        在这个例子中，当浏览器加载这段 HTML 并开始播放 `my-video.mp4` 时，Blink 引擎会使用 `VTTScanner` 来解析 `subtitles.vtt` 文件，从而显示英文字幕。

2. **JavaScript WebVTT API:**
    *   **功能关系:** JavaScript 提供了 WebVTT API，允许开发者通过脚本与 `<track>` 元素及其加载的 VTT 数据进行交互。`VTTScanner` 的解析结果会被用于构建 JavaScript 可以操作的 `TextTrack` 对象。
    *   **用户操作到达此处的路径:**  与上述 HTML 示例类似，一旦 VTT 文件被 `<track>` 元素引用并加载，`VTTScanner` 就会参与解析。 JavaScript 可以通过 `video.textTracks` 访问解析后的字幕数据。

    *   **举例说明:**

        ```javascript
        const video = document.querySelector('video');
        const textTracks = video.textTracks;
        const englishSubtitles = textTracks.getTrackById('english-subtitles'); // 假设 track 元素有 id="english-subtitles"

        englishSubtitles.oncuechange = () => {
          if (englishSubtitles.activeCues.length > 0) {
            console.log('当前字幕：', englishSubtitles.activeCues[0].text);
          }
        };
        ```

        这段 JavaScript 代码监听字幕的切换事件，并打印当前显示的字幕内容。这依赖于 `VTTScanner` 正确解析 VTT 文件并创建 `VTTCue` 对象。

3. **CSS 样式:**
    *   **功能关系:** 虽然 `VTTScanner` 本身不直接处理 CSS，但它解析的 VTT 数据最终会以某种形式呈现出来（通常是字幕）。CSS 可以用来控制字幕的样式，例如字体、颜色、位置等。
    *   **用户操作到达此处的路径:**  用户通过 HTML 的 `<track>` 元素引入 VTT 文件，`VTTScanner` 解析文件后，浏览器会渲染字幕。开发者可以使用 CSS 来定制这些字幕的显示效果。

    *   **举例说明:**

        ```css
        ::cue {
          background-color: rgba(0, 0, 0, 0.8);
          color: white;
          font-size: 1.2em;
          text-align: center;
        }
        ```

        这段 CSS 代码定义了字幕的背景颜色、文字颜色、字体大小和对齐方式。这些样式会应用到 `VTTScanner` 解析出的字幕内容上。

**逻辑推理 (假设输入与输出)**

让我们以 `ScanSequenceHelper1` 这个测试辅助函数为例进行逻辑推理：

**假设输入:** 字符串 "foe"

**代码分析:**

```c++
void ScanSequenceHelper1(const String& input) {
  VTTScanner scanner(input);
  EXPECT_FALSE(scanner.IsAtEnd()); // 检查扫描器是否不在字符串末尾 (True)
  EXPECT_TRUE(scanner.Match('f'));  // 检查当前字符是否为 'f' (True)
  EXPECT_FALSE(scanner.Match('o')); // 检查当前字符是否为 'o' (False)

  EXPECT_TRUE(scanner.Scan('f'));   // 扫描 'f'，扫描器前进到下一个字符 (True)
  EXPECT_FALSE(scanner.Match('f')); // 检查当前字符是否为 'f' (False，因为已经扫描过了)
  EXPECT_TRUE(scanner.Match('o'));  // 检查当前字符是否为 'o' (True)

  EXPECT_FALSE(scanner.Scan('e'));  // 尝试扫描 'e'，但当前字符是 'o'，所以失败 (False)
  EXPECT_TRUE(scanner.Scan('o'));   // 扫描 'o'，扫描器前进到下一个字符 (True)

  EXPECT_TRUE(scanner.Scan('e'));   // 扫描 'e'，扫描器到达字符串末尾 (True)
  EXPECT_FALSE(scanner.Match('e')); // 检查当前字符是否为 'e' (False，因为已经到达末尾)

  EXPECT_TRUE(scanner.IsAtEnd());  // 检查扫描器是否在字符串末尾 (True)
}
```

**预期输出:**

根据 `EXPECT_*` 断言，我们期望所有断言都为真，测试通过。

**假设输入:** 字符串 "bar"

**预期输出:**

大部分断言会失败，例如 `EXPECT_TRUE(scanner.Match('f'))` 将会是 `False`，因为字符串的第一个字符是 'b' 而不是 'f'。

**用户或编程常见的使用错误**

虽然 `vtt_scanner_test.cc` 是测试代码，但它可以帮助我们理解 `VTTScanner` 的使用方式，从而避免一些编程错误，例如：

1. **假设 `Scan()` 会跳过不匹配的字符:** `Scan('x')` 只会在当前位置的字符是 'x' 时才成功并移动扫描位置。如果当前字符不是 'x'，它会返回 `false`，并且扫描位置不会改变。初学者可能会误以为 `Scan()` 会像正则表达式的某些匹配操作一样，跳过不匹配的字符继续寻找。

    **示例 (基于 `ScanSequenceHelper1`):**

    如果程序员错误地认为 `scanner.Scan('e')` 会在 "foe" 中找到 'e'，他们可能会写出依赖于这种错误行为的代码。但实际上，在扫描完 'f' 和 'o' 之后，`scanner.Scan('e')` 会返回 `false`。

2. **混淆 `Match()` 和 `Scan()`:**
    *   `Match('x')` 只是检查当前字符是否为 'x'，**不会移动扫描位置**。
    *   `Scan('x')` 检查当前字符是否为 'x'，**如果匹配则移动扫描位置**。

    **示例 (基于 `ScanSequenceHelper1`):**

    如果程序员连续使用 `Match()` 而不使用 `Scan()`，扫描位置将不会前进，导致无限循环或逻辑错误。

3. **未正确处理字符串末尾:**  在扫描过程中没有检查 `IsAtEnd()`，可能导致越界访问或不可预测的行为。`VTTScanner` 提供了 `IsAtEnd()` 方法来检查是否到达字符串末尾，这是防止此类错误的关键。

    **示例:**  如果代码在一个循环中调用 `scanner.Scan(n)` 但没有检查 `scanner.IsAtEnd()`，当扫描到字符串末尾时，可能会尝试读取不存在的字符。

**总结**

`vtt_scanner_test.cc` 通过一系列的单元测试，详尽地验证了 `VTTScanner` 类的各种功能。理解这个测试文件不仅有助于理解 `VTTScanner` 的工作原理，还能帮助开发者避免在使用相关 WebVTT 功能时可能遇到的错误。它也清晰地展示了 Blink 引擎如何确保其 VTT 解析功能的正确性和鲁棒性，从而为用户提供可靠的字幕和文本轨道体验。

### 提示词
```
这是目录为blink/renderer/core/html/track/vtt/vtt_scanner_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
/*
 * Copyright (c) 2013, Opera Software ASA. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Opera Software ASA nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/track/vtt/vtt_scanner.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

TEST(VTTScannerTest, Constructor) {
  test::TaskEnvironment task_environment;
  String data8("foo");
  EXPECT_TRUE(data8.Is8Bit());
  VTTScanner scanner8(data8);
  EXPECT_FALSE(scanner8.IsAtEnd());

  String data16(data8);
  data16.Ensure16Bit();
  EXPECT_FALSE(data16.Is8Bit());
  VTTScanner scanner16(data16);
  EXPECT_FALSE(scanner16.IsAtEnd());

  VTTScanner scanner_empty(g_empty_string);
  EXPECT_TRUE(scanner_empty.IsAtEnd());
}

void ScanSequenceHelper1(const String& input) {
  VTTScanner scanner(input);
  EXPECT_FALSE(scanner.IsAtEnd());
  EXPECT_TRUE(scanner.Match('f'));
  EXPECT_FALSE(scanner.Match('o'));

  EXPECT_TRUE(scanner.Scan('f'));
  EXPECT_FALSE(scanner.Match('f'));
  EXPECT_TRUE(scanner.Match('o'));

  EXPECT_FALSE(scanner.Scan('e'));
  EXPECT_TRUE(scanner.Scan('o'));

  EXPECT_TRUE(scanner.Scan('e'));
  EXPECT_FALSE(scanner.Match('e'));

  EXPECT_TRUE(scanner.IsAtEnd());
}

// Run TESTFUNC with DATA in Latin and then UTF-16. (Requires DATA being Latin.)
#define TEST_WITH(TESTFUNC, DATA)  \
  do {                             \
    String data8(DATA);            \
    EXPECT_TRUE(data8.Is8Bit());   \
    TESTFUNC(data8);               \
                                   \
    String data16(data8);          \
    data16.Ensure16Bit();          \
    EXPECT_FALSE(data16.Is8Bit()); \
    TESTFUNC(data16);              \
  } while (false)

// Exercises match(c) and scan(c).
TEST(VTTScannerTest, BasicOperations1) {
  test::TaskEnvironment task_environment;
  TEST_WITH(ScanSequenceHelper1, "foe");
}

void ScanSequenceHelper2(const String& input) {
  VTTScanner scanner(input);
  EXPECT_FALSE(scanner.IsAtEnd());
  EXPECT_FALSE(scanner.Scan("fe"));

  EXPECT_TRUE(scanner.Scan("fo"));
  EXPECT_FALSE(scanner.IsAtEnd());

  EXPECT_FALSE(scanner.Scan("ee"));

  EXPECT_TRUE(scanner.Scan('e'));
  EXPECT_TRUE(scanner.IsAtEnd());
}

// Exercises scan(<literal>[, length]).
TEST(VTTScannerTest, BasicOperations2) {
  test::TaskEnvironment task_environment;
  TEST_WITH(ScanSequenceHelper2, "foe");
}

bool LowerCaseAlpha(UChar c) {
  return c >= 'a' && c <= 'z';
}

void ScanWithPredicate(const String& input) {
  VTTScanner scanner(input);
  EXPECT_FALSE(scanner.IsAtEnd());
  // Collect "bad".
  size_t lc_run_length = scanner.CountWhile<LowerCaseAlpha>();
  // CountWhile doesn't move the scan position.
  EXPECT_TRUE(scanner.Match('b'));

  size_t length_before = scanner.Remaining();
  // Consume "bad".
  scanner.SkipWhile<LowerCaseAlpha>();
  EXPECT_TRUE(scanner.Match('A'));
  EXPECT_EQ(scanner.Remaining(), length_before - lc_run_length);

  // Consume "A".
  EXPECT_TRUE(scanner.Scan('A'));

  // Collect "bing".
  lc_run_length = scanner.CountWhile<LowerCaseAlpha>();
  // CountWhile doesn't move the scan position.
  EXPECT_FALSE(scanner.IsAtEnd());

  length_before = scanner.Remaining();
  // Consume "bing".
  scanner.SkipWhile<LowerCaseAlpha>();
  EXPECT_EQ(scanner.Remaining(), length_before - lc_run_length);
  EXPECT_TRUE(scanner.IsAtEnd());
}

// Tests SkipWhile() and CountWhile().
TEST(VTTScannerTest, PredicateScanning) {
  test::TaskEnvironment task_environment;
  TEST_WITH(ScanWithPredicate, "badAbing");
}

void ScanWithInvPredicate(const String& input) {
  VTTScanner scanner(input);
  EXPECT_FALSE(scanner.IsAtEnd());
  // Collect "BAD".
  size_t uc_run_length = scanner.CountUntil<LowerCaseAlpha>();
  // CountUntil doesn't move the scan position.
  EXPECT_TRUE(scanner.Match('B'));

  size_t length_before = scanner.Remaining();
  // Consume "BAD".
  scanner.SkipUntil<LowerCaseAlpha>();
  EXPECT_TRUE(scanner.Match('a'));
  EXPECT_EQ(scanner.Remaining(), length_before - uc_run_length);

  // Consume "a".
  EXPECT_TRUE(scanner.Scan('a'));

  // Collect "BING".
  uc_run_length = scanner.CountUntil<LowerCaseAlpha>();
  // CountUntil doesn't move the scan position.
  EXPECT_FALSE(scanner.IsAtEnd());

  length_before = scanner.Remaining();
  // Consume "BING".
  scanner.SkipUntil<LowerCaseAlpha>();
  EXPECT_EQ(scanner.Remaining(), length_before - uc_run_length);
  EXPECT_TRUE(scanner.IsAtEnd());
}

// Tests SkipUntil() and CountUntil().
TEST(VTTScannerTest, InversePredicateScanning) {
  test::TaskEnvironment task_environment;
  TEST_WITH(ScanWithInvPredicate, "BADaBING");
}

void ScanRuns(const String& input) {
  String foo_string("foo");
  String bar_string("bar");
  VTTScanner scanner(input);
  EXPECT_FALSE(scanner.IsAtEnd());
  VTTScanner foo_scanner = scanner.SubrangeWhile<LowerCaseAlpha>();
  EXPECT_FALSE(foo_scanner.Scan(bar_string));
  EXPECT_TRUE(foo_scanner.Scan(foo_string));
  EXPECT_TRUE(foo_scanner.IsAtEnd());

  EXPECT_TRUE(scanner.Match(':'));
  EXPECT_TRUE(scanner.Scan(':'));

  // Skip 'baz'.
  scanner.SubrangeWhile<LowerCaseAlpha>();

  EXPECT_TRUE(scanner.Match(':'));
  EXPECT_TRUE(scanner.Scan(':'));

  VTTScanner bar_scanner = scanner.SubrangeWhile<LowerCaseAlpha>();
  EXPECT_FALSE(bar_scanner.Scan(foo_string));
  EXPECT_TRUE(bar_scanner.Scan(bar_string));
  EXPECT_TRUE(bar_scanner.IsAtEnd());
  EXPECT_TRUE(scanner.IsAtEnd());
}

// Tests scanRun/skipRun.
TEST(VTTScannerTest, RunScanning) {
  test::TaskEnvironment task_environment;
  TEST_WITH(ScanRuns, "foo:baz:bar");
}

void ScanRunsToStrings(const String& input) {
  VTTScanner scanner(input);
  EXPECT_FALSE(scanner.IsAtEnd());

  size_t word_length = scanner.CountWhile<LowerCaseAlpha>();
  size_t length_before = scanner.Remaining();
  String foo_string = scanner.ExtractString(word_length);
  EXPECT_EQ(foo_string, "foo");
  EXPECT_EQ(scanner.Remaining(), length_before - word_length);

  EXPECT_TRUE(scanner.Match(':'));
  EXPECT_TRUE(scanner.Scan(':'));

  word_length = scanner.CountWhile<LowerCaseAlpha>();
  length_before = scanner.Remaining();
  String bar_string = scanner.ExtractString(word_length);
  EXPECT_EQ(bar_string, "bar");
  EXPECT_EQ(scanner.Remaining(), length_before - word_length);
  EXPECT_TRUE(scanner.IsAtEnd());
}

// Tests extractString.
TEST(VTTScannerTest, ExtractString) {
  test::TaskEnvironment task_environment;
  TEST_WITH(ScanRunsToStrings, "foo:bar");
}

void TailStringExtract(const String& input) {
  VTTScanner scanner(input);
  EXPECT_TRUE(scanner.Scan("foo"));
  EXPECT_TRUE(scanner.Scan(':'));
  String bar_suffix = scanner.RestOfInputAsString();
  EXPECT_EQ(bar_suffix, "bar");

  EXPECT_TRUE(scanner.IsAtEnd());
}

// Tests restOfInputAsString().
TEST(VTTScannerTest, ExtractRestAsString) {
  test::TaskEnvironment task_environment;
  TEST_WITH(TailStringExtract, "foo:bar");
}

void ScanDigits1(const String& input) {
  VTTScanner scanner(input);
  EXPECT_TRUE(scanner.Scan("foo"));
  unsigned number;

  EXPECT_EQ(scanner.ScanDigits(number), 0u);
  EXPECT_EQ(number, 0u);

  EXPECT_TRUE(scanner.Scan(' '));
  EXPECT_EQ(scanner.ScanDigits(number), 3u);
  EXPECT_TRUE(scanner.Match(' '));
  EXPECT_EQ(number, 123u);

  EXPECT_TRUE(scanner.Scan(' '));
  EXPECT_TRUE(scanner.Scan("bar"));
  EXPECT_TRUE(scanner.Scan(' '));

  EXPECT_EQ(scanner.ScanDigits(number), 5u);
  EXPECT_EQ(number, 45678u);

  EXPECT_TRUE(scanner.IsAtEnd());
}

void ScanDigits2(const String& input) {
  VTTScanner scanner(input);
  unsigned number;
  EXPECT_EQ(scanner.ScanDigits(number), 0u);
  EXPECT_EQ(number, 0u);
  EXPECT_TRUE(scanner.Scan('-'));
  EXPECT_EQ(scanner.ScanDigits(number), 3u);
  EXPECT_EQ(number, 654u);

  EXPECT_TRUE(scanner.Scan(' '));

  EXPECT_EQ(scanner.ScanDigits(number), 19u);
  EXPECT_EQ(number, std::numeric_limits<unsigned>::max());

  EXPECT_TRUE(scanner.IsAtEnd());
}

// Tests scanDigits().
TEST(VTTScannerTest, ScanDigits) {
  test::TaskEnvironment task_environment;
  TEST_WITH(ScanDigits1, "foo 123 bar 45678");
  TEST_WITH(ScanDigits2, "-654 1000000000000000000");
}

void ScanDoubleValue(const String& input) {
  VTTScanner scanner(input);
  double value;
  // "1."
  EXPECT_TRUE(scanner.ScanDouble(value));
  EXPECT_EQ(value, 1.0);
  EXPECT_TRUE(scanner.Scan(' '));

  // "1.0"
  EXPECT_TRUE(scanner.ScanDouble(value));
  EXPECT_EQ(value, 1.0);
  EXPECT_TRUE(scanner.Scan(' '));

  // ".0"
  EXPECT_TRUE(scanner.ScanDouble(value));
  EXPECT_EQ(value, 0.0);
  EXPECT_TRUE(scanner.Scan(' '));

  // "." (invalid)
  EXPECT_FALSE(scanner.ScanDouble(value));
  EXPECT_TRUE(scanner.Match('.'));
  EXPECT_TRUE(scanner.Scan('.'));
  EXPECT_TRUE(scanner.Scan(' '));

  // "1.0000"
  EXPECT_TRUE(scanner.ScanDouble(value));
  EXPECT_EQ(value, 1.0);
  EXPECT_TRUE(scanner.Scan(' '));

  // "01.000"
  EXPECT_TRUE(scanner.ScanDouble(value));
  EXPECT_EQ(value, 1.0);

  EXPECT_TRUE(scanner.IsAtEnd());
}

// Tests ScanDouble().
TEST(VTTScannerTest, ScanDouble) {
  test::TaskEnvironment task_environment;
  TEST_WITH(ScanDoubleValue, "1. 1.0 .0 . 1.0000 01.000");
}

#undef TEST_WITH

}  // namespace blink
```