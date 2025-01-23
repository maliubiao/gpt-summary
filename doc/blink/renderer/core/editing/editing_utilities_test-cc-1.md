Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file in the Chromium Blink engine. The code focuses on testing grapheme boundary detection and text editing functionalities, particularly the `PreviousGraphemeBoundaryOf` and `NextGraphemeBoundaryOf` functions, as well as the `PreviousPositionOf` function for backspace operations.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the Core Functionality:** The code primarily consists of `TEST_F` blocks, which are standard Google Test framework constructs. Each `TEST_F` focuses on a specific aspect of text manipulation. The names of the tests give strong hints about their purpose: `graphemeBoundary`, `previousPositionOf_Backspace`, `IsTabHTMLSpanElementOnDisplayNone`, `IsRenderedAsNonInlineTableImageOrHR`.

2. **Analyze `graphemeBoundary` Test:** This test extensively uses `SetBodyContent` to set up various HTML structures, followed by assertions using `EXPECT_EQ` with `PreviousGraphemeBoundaryOf` and `NextGraphemeBoundaryOf`. This clearly indicates testing of grapheme boundary detection logic under different Unicode scenarios.

3. **Examine Unicode Scenarios:** The comments within the `graphemeBoundary` test explicitly mention various Unicode rules (GB1 to GB999) and specific Unicode characters. This reveals that the test aims to verify correct boundary identification for different character types and combinations, including:
    * Basic ASCII
    * Surrogate pairs (emojis)
    * Combining characters
    * Regional indicator symbols (flags)
    * Zero-width joiners (ZWJ)
    * Spacing marks
    * Thai characters
    * Half-width Katakana
    * Indic characters (Virama)

4. **Analyze `previousPositionOf_Backspace` Tests:** These tests focus on the `PreviousPositionOf` function when simulating a backspace. The scenarios involve:
    * Basic BMP characters
    * Elements with `::first-letter` pseudo-element
    * Text transformations (e.g., uppercase)
    * Surrogate pairs, including broken pairs

5. **Analyze `IsTabHTMLSpanElementOnDisplayNone` Test:** This test checks a specific edge case related to tab characters within spans with `display: none`.

6. **Analyze `IsRenderedAsNonInlineTableImageOrHR` Test:** This test, although simpler, checks for a specific rendering condition. The comment "Pass if no crash" suggests it might be testing for potential crashes in specific rendering scenarios.

7. **Connect to Web Technologies:**  Consider how these tests relate to web technologies:
    * **JavaScript:**  While the test is in C++, the grapheme boundary logic is crucial for correct cursor movement and text selection in JavaScript within a web page. JavaScript's string manipulation relies on understanding grapheme boundaries.
    * **HTML:** The tests directly manipulate the HTML content using `SetBodyContent`. The different HTML structures (paragraphs, spans) are the context for the tests.
    * **CSS:** The `previousPositionOf_Backspace_FirstLetter` and `previousPositionOf_Backspace_TextTransform` tests explicitly involve CSS styling and its impact on text manipulation.

8. **Identify Potential User/Programming Errors:** The tests implicitly highlight potential errors:
    * Incorrect handling of surrogate pairs can lead to unexpected character deletion.
    * Not considering combining characters or ZWJ can result in incorrect cursor positioning.
    * Failing to account for text transformations can lead to unexpected backspace behavior.

9. **Consider User Actions and Debugging:**  Think about how a user might encounter these issues and how developers might debug them:
    * Typing and deleting text, especially with emojis or complex scripts.
    * Selecting text with the mouse or keyboard.
    * Observing unexpected cursor movements or character deletions.
    * Developers would use debugging tools to step through the code and understand how the browser handles text input and manipulation.

10. **Synthesize the Summary:** Combine the above observations into a concise summary, addressing the specific points requested by the user (functionality, relation to web technologies, logical reasoning, user/programming errors, user actions/debugging, and the final request for summarization of the provided snippet).

By following these steps, the generated summary accurately reflects the functionality of the provided code and its relevance to web technologies and potential user issues.
这是对`blink/renderer/core/editing/editing_utilities_test.cc`文件第二部分的分析，延续了第一部分对该文件功能的描述。

**功能归纳（基于提供的第二部分代码）：**

这部分代码主要集中在测试 Blink 引擎中关于文本编辑的实用工具函数，特别是以下几个方面：

1. **复杂文本中字形簇（Grapheme）边界的判断：**
   - 继续测试 `PreviousGraphemeBoundaryOf` 和 `NextGraphemeBoundaryOf` 函数在处理各种复杂 Unicode 字符组合时的正确性。
   - 覆盖了包括但不限于：
     - 偶数和奇数个 Regional Indicator Symbols (用于表示国旗)。
     - Combining characters (扩展字符)。
     - Zero-Width Joiner (ZWJ)。
     - Spacing Marks。
     - Prepend 字符（尽管代码中注释提到需要 Unicode 9.0 支持）。
     - 泰语字符。
     - 日语半角片假名浊音符号。
     - Indic 字符的 Virama 属性。
     - Emoji modifier (尽管 Unicode 11 后已部分合并到 Extend 属性)。
     - ZWJ 连接的 Emoji 序列。
     - 韩文音节。
     - 单独的 Extended 或 ZWJ 字符。

2. **退格键（Backspace）操作时光标位置的正确回退：**
   - 测试 `PreviousPositionOf` 函数在模拟退格键操作时，光标位置回退到正确的前一个位置。
   - 覆盖了不同场景：
     - BMP (Basic Multilingual Plane) 字符。
     - 带有 `::first-letter` 伪元素的情况。
     - 文本转换 (text-transform) 的影响。
     - 代理对 (Surrogate Pairs) 表示的 Unicode 字符（例如 Emoji）。
     - 错误的代理对 (Broken Surrogate Pairs) 的处理。

3. **特定 HTML 元素属性的判断：**
   - 测试 `IsTabHTMLSpanElement` 函数在 `display: none` 的 `<span>` 元素中包含制表符时的行为。

4. **判断元素是否以非内联方式渲染：**
   - 测试 `IsRenderedAsNonInlineTableImageOrHR` 函数，尽管这部分只有一个简单的测试用例，但暗示了该函数用于判断元素是否像表格、图片或 `<hr>` 标签那样以非内联的方式渲染。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:** 这些测试直接影响到 JavaScript 中与文本编辑相关的 API 的行为，例如 `Selection` 和 `Range` 对象的操作。当 JavaScript 代码需要移动光标、删除字符或选择文本时，依赖于引擎内部对字形簇和字符边界的正确理解。
    * **举例：** 当用户在 `contenteditable` 的 `<div>` 中输入 Emoji 表情，然后按下退格键时，JavaScript 的文本处理逻辑会调用引擎的 `PreviousPositionOf` 函数来确定光标应该回退到哪里。如果引擎的实现有问题，可能会导致退格键删除半个 Emoji，而不是整个表情。

* **HTML:** 测试使用 `SetBodyContent` 设置 HTML 结构，这是测试用例的基础。不同的 HTML 结构会影响文本的布局和渲染，从而影响到字形簇的判断。
    * **举例：** 测试用例中使用了 `<p>` 标签来包含文本内容。字形簇的判断需要在 HTML 元素的上下文中进行，例如考虑了元素间的空格等。

* **CSS:**  测试中明确包含了 CSS 样式的影响，例如 `::first-letter` 伪元素和 `text-transform` 属性。这些 CSS 属性会改变文本的渲染方式，进而影响到光标的定位和字符的删除。
    * **举例：** 当一个段落使用了 `text-transform: uppercase` 将小写字母转换为大写时，一个像 "ß" 这样的字符可能会被渲染成 "SS"。退格键操作需要正确处理这种情况，删除 "SS" 整体而不是只删除 "S"。`previousPositionOf_Backspace_TextTransform` 这个测试就是验证这种情况。

**逻辑推理、假设输入与输出：**

这部分代码的核心是单元测试，其逻辑推理体现在对各种边界情况的覆盖和验证。

* **假设输入（以字形簇边界测试为例）：**
    * 输入一个包含多个 Regional Indicator Symbols 的字符串，例如 "🇦🇺🇧🇷🇨🇳"。
    * 调用 `PreviousGraphemeBoundaryOf` 函数，并指定一个字符串中的索引位置。
* **预期输出：**
    * 函数应该返回前一个字形簇的起始索引位置。例如，如果输入 "🇦🇺🇧🇷🇨🇳" 和索引 6（在 "🇧" 的中间），函数应该返回 4（"🇦🇺" 之后，"🇧" 之前的索引）。

* **假设输入（以退格键测试为例）：**
    * 输入一个包含代理对字符的字符串，例如 "😄abc"。
    * 模拟光标位于字符串末尾，执行退格操作。
* **预期输出：**
    * `PreviousPositionOf` 函数应该返回 Emoji 表情 "😄" 的起始位置，意味着退格键会删除整个 Emoji 表情。

**用户或编程常见的使用错误：**

* **用户错误：**
    * 在不支持某些复杂 Unicode 字符（例如最新的 Emoji）的系统中输入文本，可能会导致显示或编辑问题。
    * 在文本编辑器中错误地删除了代理对字符的一部分，导致显示乱码。
* **编程错误：**
    * 在 JavaScript 中使用错误的字符串索引方法来操作包含复杂 Unicode 字符的字符串，可能会导致意外的结果。例如，使用基于码点的索引而不是基于字形簇的索引来删除字符。
    * 在处理用户输入时，没有考虑到各种 Unicode 规范和边界情况，导致文本处理逻辑错误。

**用户操作如何一步步到达这里作为调试线索：**

假设用户在使用 Chrome 浏览器编辑一个富文本编辑器：

1. **输入复杂文本：** 用户输入了一个包含 Emoji 表情、组合字符或者国旗 Emoji 的文本。
2. **移动光标：** 用户使用键盘方向键或者鼠标点击来移动光标到文本的不同位置。
3. **执行退格或删除操作：** 用户按下退格键或者 Delete 键来删除文本。
4. **文本选择：** 用户可能尝试使用鼠标拖拽或者 Shift + 方向键来选择文本。

如果在这个过程中，用户发现光标移动不符合预期（例如跳过了某些字符），或者退格键没有按预期删除整个 Emoji 表情，或者文本选择出现异常，那么开发者可能会怀疑是字形簇边界判断或光标位置计算出现了问题。

为了调试，开发者可能会：

* **查看控制台输出：**  如果相关的 JavaScript 代码有日志输出，可以帮助定位问题。
* **使用开发者工具断点调试 JavaScript 代码：**  查看 JavaScript 中与文本编辑相关的逻辑是如何调用 Blink 引擎的接口的。
* **检查 Blink 引擎的日志：** 如果问题很底层，可能需要查看 Blink 引擎的内部日志。
* **运行相关的单元测试：**  例如 `editing_utilities_test.cc` 中的测试用例，来验证引擎的文本处理逻辑是否正确。如果某个测试用例失败了，就说明引擎在该特定场景下存在 Bug。

**总结提供的第二部分代码的功能：**

总而言之，提供的第二部分代码延续了第一部分的思路，专注于测试 Blink 引擎中处理复杂文本和编辑操作的关键实用工具函数。它深入测试了在各种 Unicode 场景下字形簇边界判断的正确性，以及在退格键操作时光标位置回退的准确性。此外，还包含了一些针对特定 HTML 元素属性和渲染状态的测试。这些测试对于确保 Blink 引擎能够正确处理各种语言和字符，并提供一致和可靠的文本编辑体验至关重要。 这部分代码通过详尽的测试用例，力求覆盖各种边界情况和潜在的错误，从而保证了浏览器在文本编辑功能上的健壮性。

### 提示词
```
这是目录为blink/renderer/core/editing/editing_utilities_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
eBoundaryOf(*node, 17));

  // GB8c: Break if there is an odd number of regional indicator symbols before.
  SetBodyContent("<p id='target'>a" + flag + flag + flag + flag +
                 "&#x1F1F8;b</p>");  // RI ÷ RI
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(19, PreviousGraphemeBoundaryOf(*node, 20));
  EXPECT_EQ(17, PreviousGraphemeBoundaryOf(*node, 19));
  EXPECT_EQ(13, PreviousGraphemeBoundaryOf(*node, 17));
  EXPECT_EQ(9, PreviousGraphemeBoundaryOf(*node, 13));
  EXPECT_EQ(5, PreviousGraphemeBoundaryOf(*node, 9));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(5, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(9, NextGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(13, NextGraphemeBoundaryOf(*node, 9));
  EXPECT_EQ(17, NextGraphemeBoundaryOf(*node, 13));
  EXPECT_EQ(19, NextGraphemeBoundaryOf(*node, 17));
  EXPECT_EQ(20, NextGraphemeBoundaryOf(*node, 19));

  // GB9: Do not break before extending characters or ZWJ.
  // U+0300(COMBINING GRAVE ACCENT) has Extend property.
  SetBodyContent("<p id='target'>a&#x0300;b</p>");  // x Extend
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 2));
  // U+200D is ZERO WIDTH JOINER.
  SetBodyContent("<p id='target'>a&#x200D;b</p>");  // x ZWJ
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 2));

  // GB9a: Do not break before SpacingMarks.
  // U+0903(DEVANAGARI SIGN VISARGA) has SpacingMark property.
  SetBodyContent("<p id='target'>a&#x0903;b</p>");  // x SpacingMark
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 2));

  // GB9b: Do not break after Prepend.
  // TODO(nona): Introduce Prepend test case once ICU grabs Unicode 9.0.

  // For https://bugs.webkit.org/show_bug.cgi?id=24342
  // The break should happens after Thai character.
  SetBodyContent("<p id='target'>a&#x0E40;b</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(2, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(2, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 2));

  // Blink customization: Don't break before Japanese half-width katakana voiced
  // marks.
  SetBodyContent("<p id='target'>a&#xFF76;&#xFF9E;b</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));

  // Additional rule for IndicSyllabicCategory=Virama: Do not break after that.
  // See
  // http://www.unicode.org/Public/9.0.0/ucd/IndicSyllabicCategory-9.0.0d2.txt
  // U+0905 is DEVANAGARI LETTER A. This has Extend property.
  // U+094D is DEVANAGARI SIGN VIRAMA. This has Virama property.
  // U+0915 is DEVANAGARI LETTER KA.
  SetBodyContent("<p id='target'>a&#x0905;&#x094D;&#x0915;b</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(4, PreviousGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(5, NextGraphemeBoundaryOf(*node, 4));
  // U+0E01 is THAI CHARACTER KO KAI
  // U+0E3A is THAI CHARACTER PHINTHU
  // Should break after U+0E3A since U+0E3A has Virama property but not listed
  // in IndicSyllabicCategory=Virama.
  SetBodyContent("<p id='target'>a&#x0E01;&#x0E3A;&#x0E01;b</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(4, PreviousGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(5, NextGraphemeBoundaryOf(*node, 4));

  // GB10: Do not break within emoji modifier.
  // GB10 is deleted in Unicode 11, but it's subsumed by GB9 by
  // extending the definition of Extend to include E_Base, E_Modifier,
  // etc. E_Base, E_Modifier and E_Base_GAZ are obsolete.
  // U+1F385(FATHER CHRISTMAS) used to have E_Base property.
  // U+1F3FB(EMOJI MODIFIER FITZPATRICK TYPE-1-2) used to have
  // E_Modifier property.
  SetBodyContent(
      "<p id='target'>a&#x1F385;&#x1F3FB;b</p>");  // E_Base x E_Modifier
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(5, PreviousGraphemeBoundaryOf(*node, 6));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(5, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(6, NextGraphemeBoundaryOf(*node, 5));
  // U+1F466(BOY) used to have EBG property, but now has Extend property.
  SetBodyContent(
      "<p id='target'>a&#x1F466;&#x1F3FB;b</p>");  // EBG x E_Modifier
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(5, PreviousGraphemeBoundaryOf(*node, 6));
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(5, NextGraphemeBoundaryOf(*node, 1));
  EXPECT_EQ(6, NextGraphemeBoundaryOf(*node, 5));

  // GB11: Do not break within ZWJ emoji sequence.
  // U+2764(HEAVY BLACK HEART) has Extended_Pictographic=True.
  // So does U+1F466.
  SetBodyContent(
      "<p id='target'>a&#x200D;&#x2764;b</p>");  // ZWJ x Glue_After_Zwj
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(3, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 3));
  SetBodyContent("<p id='target'>a&#x200D;&#x1F466;b</p>");  // ZWJ x EBG
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(4, PreviousGraphemeBoundaryOf(*node, 5));
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 0));
  EXPECT_EQ(5, NextGraphemeBoundaryOf(*node, 4));

  // U+1F5FA(World Map) has Extended_Pictographic=True.
  SetBodyContent("<p id='target'>&#x200D;&#x1F5FA;</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 0));

  // GB999: Otherwise break everywhere.
  // Breaks between Hangul syllable except for GB6, GB7, GB8.
  SetBodyContent("<p id='target'>" + l + t + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + v + l + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + v + lv + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + v + lvt + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + lv + l + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + lv + lv + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + lv + lvt + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + lvt + l + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + lvt + v + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + lvt + lv + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + lvt + lvt + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + t + l + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + t + v + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + t + lv + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>" + t + lvt + "</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));

  // Per GB8, do not break before Extended|ZWJ. E_Modifier is obsolete
  // in Unicode 11 and is now a part of Extended.
  SetBodyContent("<p id='target'>a&#x1F3FB;</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 3));
  EXPECT_EQ(3, NextGraphemeBoundaryOf(*node, 0));
  SetBodyContent("<p id='target'>&#x1F5FA;&#x1F3FB;</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(0, PreviousGraphemeBoundaryOf(*node, 4));
  EXPECT_EQ(4, NextGraphemeBoundaryOf(*node, 0));

  // For GB11, if trailing character is not Glue_After_Zwj or EBG, break happens
  // after ZWJ.
  // U+1F5FA(WORLD MAP) doesn't have either Glue_After_Zwj or EBG.
  SetBodyContent("<p id='target'>&#x200D;a</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(1, PreviousGraphemeBoundaryOf(*node, 2));
  EXPECT_EQ(1, NextGraphemeBoundaryOf(*node, 0));
}

TEST_F(EditingUtilitiesTest, previousPositionOf_Backspace) {
  // BMP characters. Only one code point should be deleted.
  SetBodyContent("<p id='target'>abc</p>");
  Node* node =
      GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 1),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));
}

TEST_F(EditingUtilitiesTest, previousPositionOf_Backspace_FirstLetter) {
  SetBodyContent(
      "<style>p::first-letter {color:red;}</style><p id='target'>abc</p>");
  Node* node =
      GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 1),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));

  SetBodyContent(
      "<style>p::first-letter {color:red;}</style><p id='target'>(a)bc</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 4),
            PreviousPositionOf(Position(node, 5),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 3),
            PreviousPositionOf(Position(node, 4),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 1),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));
}

TEST_F(EditingUtilitiesTest, previousPositionOf_Backspace_TextTransform) {
  // Uppercase of &#x00DF; will be transformed to SS.
  SetBodyContent(
      "<style>p {text-transform:uppercase}</style><p "
      "id='target'>&#x00DF;abc</p>");
  Node* node =
      GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 3),
            PreviousPositionOf(Position(node, 4),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 1),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));
}

TEST_F(EditingUtilitiesTest, IsTabHTMLSpanElementOnDisplayNone) {
  SetBodyContent("<span style=\"display:none\">\t</span>");
  const Node* const node = GetDocument().QuerySelector(AtomicString("span"));
  EXPECT_EQ(false, IsTabHTMLSpanElement(node));
}

TEST_F(EditingUtilitiesTest, previousPositionOf_Backspace_SurrogatePairs) {
  // Supplementary plane characters. Only one code point should be deleted.
  // &#x1F441; is EYE.
  SetBodyContent("<p id='target'>&#x1F441;&#x1F441;&#x1F441;</p>");
  Node* node =
      GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 4),
            PreviousPositionOf(Position(node, 6),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 4),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));

  // BMP and Supplementary plane case.
  SetBodyContent("<p id='target'>&#x1F441;a&#x1F441;a</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 5),
            PreviousPositionOf(Position(node, 6),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 3),
            PreviousPositionOf(Position(node, 5),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));

  // Edge case: broken surrogate pairs.
  SetBodyContent(
      "<p id='target'>&#xD83D;</p>");  // &#xD83D; is unpaired lead surrogate.
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));

  // &#xD83D; is unpaired lead surrogate.
  SetBodyContent("<p id='target'>&#x1F441;&#xD83D;&#x1F441;</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 3),
            PreviousPositionOf(Position(node, 5),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));

  SetBodyContent(
      "<p id='target'>a&#xD83D;a</p>");  // &#xD83D; is unpaired lead surrogate.
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 1),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));

  SetBodyContent(
      "<p id='target'>&#xDC41;</p>");  // &#xDC41; is unpaired trail surrogate.
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));

  // &#xDC41; is unpaired trail surrogate.
  SetBodyContent("<p id='target'>&#x1F441;&#xDC41;&#x1F441;</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 3),
            PreviousPositionOf(Position(node, 5),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));

  // &#xDC41; is unpaired trail surrogate.
  SetBodyContent("<p id='target'>a&#xDC41;a</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 1),
            PreviousPositionOf(Position(node, 2),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));

  // Edge case: specify middle of surrogate pairs.
  SetBodyContent("<p id='target'>&#x1F441;&#x1F441;&#x1F441</p>");
  node = GetDocument().getElementById(AtomicString("target"))->firstChild();
  EXPECT_EQ(Position(node, 4),
            PreviousPositionOf(Position(node, 5),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 2),
            PreviousPositionOf(Position(node, 3),
                               PositionMoveType::kBackwardDeletion));
  EXPECT_EQ(Position(node, 0),
            PreviousPositionOf(Position(node, 1),
                               PositionMoveType::kBackwardDeletion));
}

// crbug.com/1503530
TEST_F(EditingUtilitiesTest, IsRenderedAsNonInlineTableImageOrHR) {
  SetBodyContent("<p id='target' hidden></p>");
  IsRenderedAsNonInlineTableImageOrHR(GetElementById("target"));
  // Pass if no crash.
}

}  // namespace blink
```