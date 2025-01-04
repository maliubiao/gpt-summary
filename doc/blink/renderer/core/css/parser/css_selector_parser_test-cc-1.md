Response:
Let's break down the thought process for analyzing the provided code snippet and generating the desired output.

**1. Understanding the Goal:**

The core request is to analyze a specific C++ test file (`css_selector_parser_test.cc`) from the Chromium Blink engine and describe its functionality, its relationship with web technologies (HTML, CSS, JavaScript), potential usage errors, debugging approaches, and finally, summarize its overall purpose as the second part of a larger analysis.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code and identify key elements and patterns. Keywords like `TEST`, `EXPECT_TRUE`, `EXPECT_FALSE`, `IsCounted`, `WebFeature`, `CSSSelectorParser`, `ParseSelector`, and various CSS pseudo-elements (e.g., `::cue`, `::-webkit-`) immediately jump out. This signals that the code is about testing the parsing of CSS selectors.

**3. Deconstructing the Tests:**

The code is organized into several `TEST` blocks. Each block seems to focus on a specific aspect of CSS selector parsing:

* **`UseCountShadowPseudo`:** This test checks if specific shadow DOM pseudo-elements are correctly associated with `WebFeature` flags. The `ExpectCount` lambda suggests it's verifying that these features are being counted or tracked when these selectors are encountered.

* **`IsWhereUseCount`:** This test specifically examines the `:is()` and `:where()` pseudo-classes and whether their usage is tracked as `WebFeature`s. The negative and positive `EXPECT_FALSE`/`EXPECT_TRUE` calls are crucial for understanding what conditions trigger the feature tracking.

* **`ImplicitShadowCrossingCombinators`:** This test delves into how the parser handles selectors that implicitly cross shadow DOM boundaries (e.g., `*::placeholder`, `div::slotted(*)`). The `ShadowCombinatorTest` struct and the loop processing `test_cases` indicate that it's comparing the parsed representation of these selectors against expected relationships (`kUAShadow`, `kShadowSlot`, `kSubSelector`).

* **Tests related to `:has()`:** The sections with `invalid_pseudo_has_arguments_data` and `has_nesting_data` are clearly testing the constraints and limitations of the `:has()` pseudo-class. They verify which pseudo-elements and nesting scenarios are considered invalid within `:has()`.

* **Tests related to Nesting (`NestingTypeImpliedDescendant`):** This section introduces the concept of CSS nesting and how the parser handles different nesting types (`kNesting`, `kScope`, `kNone`). The `GetImplicitlyAddedPseudo` function and the `EXPECT_EQ` calls suggest it's checking for implicitly added selectors (like `&` or `:scope`) during parsing based on the nesting context.

* **Tests related to `:scope` (`IsScopeContainingTest`):** This complex section focuses on the `:scope` pseudo-class and the concept of "scope containment." The `CreateReferenceSelectorForScopeContaining`, `FlattenSelector`, and `IsScopeContainingComparison` functions, along with the `IsScopeContainingData` struct, point to a mechanism for verifying whether certain selectors are correctly flagged as "scope containing."

**4. Identifying Relationships with Web Technologies:**

Based on the understanding of the tests, the connections to HTML, CSS, and JavaScript become clear:

* **CSS:** The primary focus is on CSS selectors, including pseudo-classes (e.g., `:is`, `:where`, `:has`) and pseudo-elements (e.g., `::cue`, `::-webkit-*`). The tests ensure the parser correctly interprets the syntax and semantics of these selectors. The shadow DOM specific pseudo-elements highlight the interaction with Shadow DOM in web components.

* **HTML:**  CSS selectors target HTML elements. The examples use tag names like `div`, `span`, `video`, and attributes/classes implied by selectors like `.a`. The concept of Shadow DOM is deeply tied to HTML's component model.

* **JavaScript:** While this specific test file doesn't directly involve JavaScript code, the functionality it tests is crucial for the browser's style engine, which *is* often interacted with by JavaScript (e.g., dynamically changing styles, querying elements). JavaScript might use methods like `querySelectorAll` which rely on the correct parsing of CSS selectors.

**5. Inferring Functionality and Purpose:**

Combining the analysis of the individual tests, the overall functionality of the file is to *rigorously test the CSS selector parser in the Blink rendering engine*. It ensures that the parser correctly handles a wide range of valid and invalid CSS selector syntax, including features like shadow DOM, nesting, and advanced pseudo-classes. The use of `WebFeature` flags suggests that the parser is also responsible for tracking the usage of certain CSS features, likely for metrics or compatibility purposes.

**6. Generating Examples and Error Scenarios:**

Based on the test cases, it's possible to construct examples of how the tested features are used in HTML and CSS, and also identify potential developer errors (like incorrectly nesting `:has()` or using pseudo-elements within it).

**7. Constructing the Debugging Narrative:**

The file path (`blink/renderer/core/css/parser/css_selector_parser_test.cc`) gives a strong indication of where to start debugging issues related to CSS selector parsing. The process involves:

* **User Action:**  A user interacts with a webpage.
* **Browser Processing:** The browser receives HTML and CSS.
* **Style Calculation:** The CSS is parsed by the `CSSSelectorParser`.
* **Potential Issue:** If there's a bug in the parser, it might misinterpret a selector, leading to incorrect styling.
* **Debugging:**  A developer might look at this test file to understand how the parser *should* behave for a particular selector and then step through the parser code to find the discrepancy.

**8. Summarizing the Functionality (Part 2):**

For the second part summary, the key is to concisely reiterate the core purpose identified earlier, emphasizing the testing and validation aspect.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `WebFeature` flags are about enabling/disabling features.
* **Correction:**  The tests seem to be *counting* or *tracking* the usage of these features, not necessarily enabling/disabling them. The `IsCounted` function name reinforces this.

* **Initial thought:**  Focus heavily on the low-level C++ details.
* **Correction:** While it's a C++ file, the prompt asks about the *functionality* and its relation to web technologies. The explanation should be geared towards that, not just the C++ implementation.

By following these steps, analyzing the code structure, keywords, and test cases, and connecting them to the broader context of web development, one can arrive at a comprehensive understanding of the `css_selector_parser_test.cc` file and generate the requested detailed explanation.
这是对`blink/renderer/core/css/parser/css_selector_parser_test.cc` 文件第二部分的分析和归纳。 基于您提供的第一部分（未提供，但根据第二部分内容可以推断），我们可以推断出第一部分可能侧重于 `CSSSelectorParser` 的基础功能测试，例如基本选择器的解析、组合器、属性选择器等等。

**第二部分的功能归纳：**

这第二部分的 `css_selector_parser_test.cc` 文件主要集中在以下几个方面对 CSS 选择器解析器进行更深入和特定的测试：

1. **Web Feature 使用计数 (Use Counting):**
   - **目的:**  验证特定的 CSS 伪元素（主要是 Shadow DOM 相关的以及一些 WebKit 前缀的）在使用时是否会被正确地标记和计数。这对于跟踪 Web 平台特性的使用情况，以及在未来版本中决定是否继续支持或移除某些特性至关重要。
   - **测试对象:**  大量的以 `::` 或 `::-webkit-` 开头的伪元素选择器，例如 `::cue`，`::-webkit-calendar-picker-indicator` 等。
   - **机制:**  使用 `IsCounted` 函数来检查给定的选择器在标准模式下是否会触发特定 `WebFeature` 的计数。

2. **`:is()` 和 `:where()` 伪类的使用计数:**
   - **目的:**  专门测试 `:is()` 和 `:where()` 这两个逻辑组合伪类的使用计数。
   - **区别:**  强调了 `:is()` 和 `:where()` 在 UA 样式表模式下不会进行计数，但在 HTML 标准模式下会进行计数。

3. **隐式 Shadow Crossing 组合器:**
   - **目的:**  测试解析器如何处理隐式跨越 Shadow DOM 边界的选择器。
   - **示例:**  例如 `*::placeholder`，`div::slotted(*)`，`span::part(my-part)` 等。
   - **验证:**  检查解析后的选择器链中的 `RelationType` 是否正确地被识别为 `kUAShadow`（用户代理 Shadow）或 `kShadowSlot`（Shadow 插槽），以及相应的选择器值是否正确。

4. **`:has()` 伪类的限制和嵌套:**
   - **目的:**  测试 `:has()` 伪类的一些语法限制，特别是关于嵌套使用和内部包含伪元素的限制。
   - **限制:**
     - 不允许嵌套 `:has()`。
     - 不允许 `:has()` 内部直接包含伪元素（例如 `::before`，`::-webkit-progress-bar` 等）。
     - 空的 `:has()` 或包含无效参数的 `:has()` 会被丢弃。
   - **测试用例:**  `invalid_pseudo_has_arguments_data` 和 `has_nesting_data` 包含了各种无效的 `:has()` 用法。

5. **CSS 嵌套 (`&` 和 `:scope`) 的处理:**
   - **目的:**  测试在 CSS 嵌套规则中，解析器如何处理 `&` 符号和 `:scope` 伪类，以及它们如何影响选择器的结构。
   - **隐式祖先选择器:**  验证在 `kNesting` 模式下，以非 `&` 开头的选择器是否会被隐式地添加一个引用父选择器的伪类 (`:parent`)。
   - **`:scope` 的作用:**  验证 `:scope` 伪类在 `kScope` 模式下的作用，以及它如何使选择器成为 "scope-containing"。
   - **不同嵌套类型的影响:**  比较 `kNesting`、`kScope` 和 `kNone` 三种嵌套类型对选择器解析结果的影响。

6. **"IsScopeContaining" 标志:**
   - **目的:**  深入测试选择器是否被标记为 "scope-containing"。这个标志对于某些优化和特定场景下的样式应用非常重要。
   - **触发条件:**  明确地使用 `:scope` 或 `&` 符号会使选择器成为 "scope-containing"。
   - **测试方法:**  通过 `CreateReferenceSelectorForScopeContaining` 创建预期结果，然后与实际解析结果进行比较。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **CSS:**  这部分测试直接关系到 CSS 的语法解析，特别是对新的伪类（如 `:is()`, `:where()`, `:has()`）和 Shadow DOM 相关伪元素的支持和正确解析。
    * **例子:**  `ExpectCount("::cue", WebFeature::kCSSSelectorCue);` 测试了当 CSS 中出现 `::cue` 选择器时，解析器是否正确识别并将其与 `kCSSSelectorCue` 特性关联起来。
    * **例子:**  对于无效的 `:has()` 用法，例如 `:has(::before)`，解析器会拒绝该选择器，防止 CSS 样式规则被错误地应用。

* **HTML:**  CSS 选择器用于选取 HTML 元素。这部分测试确保解析器能够正确理解针对 HTML 结构（包括 Shadow DOM 结构）的选择器。
    * **例子:**  `div::slotted(*)` 选择器用于选取被 slot 插入到 `div` 元素 Shadow DOM 中的所有元素。测试确保解析器正确理解 `::slotted` 的含义。

* **JavaScript:**  虽然测试代码本身是 C++，但它验证的 CSS 解析功能直接影响 JavaScript 操作 DOM 和样式的能力。
    * **例子:**  如果 JavaScript 使用 `document.querySelectorAll('video::-webkit-media-controls-play-button')` 来选取视频播放按钮，那么这里的测试确保了 CSS 解析器能够正确理解这个选择器，从而使 JavaScript 能够正确地操作该元素。

**逻辑推理的假设输入与输出:**

* **假设输入 (对于 `UseCountShadowPseudo`):**  在 CSS 样式表中使用了 `::-webkit-slider-thumb` 选择器。
* **输出:**  `IsCounted("::-webkit-slider-thumb", kHTMLStandardMode, WebFeature::kCSSSelectorWebkitSliderThumb)` 将返回 `true`，表明该特性的使用被计数了。

* **假设输入 (对于 `:has()` 限制):**  在 CSS 样式表中使用了 `:has(::before)`。
* **输出:**  解析器会认为该选择器无效，不会生成有效的 CSS 规则。相关的测试用例 `{"has(::before)", ""}` 验证了这一点。

* **假设输入 (对于 CSS 嵌套):**  在 CSS 嵌套规则中使用了 `.foo` (假设父选择器为 `div`)，并且 `nesting_type` 为 `kNesting`。
* **输出:**  解析器会将其解析为类似于 `div :parent .foo` 的结构，其中 `:parent` 是隐式添加的。

**涉及用户或编程常见的使用错误举例说明:**

* **错误使用 `:has()`:**
    * **用户操作:** 开发者尝试编写 CSS 规则，例如 `div:has(span::after) { ... }`。
    * **问题:**  这是不允许的，因为 `:has()` 内部不能直接包含伪元素。解析器会拒绝这个选择器，样式不会生效。
    * **调试线索:**  开发者可能会在浏览器的开发者工具中看到该 CSS 规则被标记为无效，或者样式没有按预期应用。查看 `css_selector_parser_test.cc` 中关于 `:has()` 限制的测试用例可以帮助理解为什么这个写法是错误的。

* **错误理解 CSS 嵌套:**
    * **用户操作:** 开发者期望 `.foo` 在嵌套规则中直接作用于当前元素，而没有理解 `&` 的作用。
    * **问题:**  在 `kNesting` 模式下，如果写了 `.foo`，会被解析为选择父元素的后代 `.foo`。开发者可能需要使用 `& .foo` 来明确表示当前元素的后代。
    * **调试线索:**  样式应用不符合预期。查看 `CSSSelectorParserTest, NestingTypeImpliedDescendant` 测试用例可以帮助理解不同嵌套类型下选择器的解析方式。

**用户操作如何一步步的到达这里作为调试线索:**

1. **用户编写或修改 CSS 代码:**  开发者在他们的项目 CSS 文件中编写了包含特定 CSS 选择器的样式规则，例如使用了 Shadow DOM 的伪元素，或者使用了 `:has()` 伪类。
2. **浏览器加载和解析 CSS:**  当用户访问网页时，浏览器会加载并解析 CSS 文件。
3. **CSS 解析器工作:**  `blink/renderer/core/css/parser/css_selector_parser.cc` 文件中的代码会被调用来解析这些 CSS 选择器。
4. **测试失败或行为异常:**  如果 CSS 解析器存在 bug，或者开发者使用了不被支持的语法，可能会导致以下情况：
    * **样式没有按预期应用:**  元素没有被正确选中，导致样式规则没有生效。
    * **浏览器开发者工具报错:**  解析器可能抛出错误或警告，指出 CSS 语法不正确。
    * **性能问题:**  复杂的或错误的 CSS 选择器可能导致样式计算性能下降。
5. **开发者开始调试:**  开发者会使用浏览器开发者工具检查元素的样式，查看哪些 CSS 规则生效了，哪些没有生效。他们可能会注意到某些选择器没有按预期工作。
6. **查看 Blink 源代码:**  为了深入理解问题，开发者（通常是 Chromium 的贡献者或理解 Blink 内部机制的高级开发者）可能会查看 Blink 的源代码，特别是 `blink/renderer/core/css/parser/css_selector_parser.cc` 和相关的测试文件 `blink/renderer/core/css/parser/css_selector_parser_test.cc`。
7. **定位测试用例:**  开发者会在测试文件中寻找与他们遇到的问题相关的测试用例。例如，如果他们在使用 `:has()` 时遇到问题，他们会查看 `InvalidPseudoHasArguments` 和 `NestedHasSelectorValidity` 这两个测试套件。
8. **理解解析器行为:**  通过阅读测试用例，开发者可以了解 CSS 解析器对于特定语法的预期行为，从而判断是他们的 CSS 代码有问题，还是解析器本身存在 bug。
9. **修改代码或报告 Bug:**  根据分析结果，开发者可能会修改他们的 CSS 代码以符合规范，或者如果确认是解析器的问题，他们会报告一个 Bug，并可能提交修复代码。

**总结第二部分的功能:**

总而言之，`blink/renderer/core/css/parser/css_selector_parser_test.cc` 的第二部分专注于对 CSS 选择器解析器进行**更精细化和特定场景的测试**，涵盖了 Web Feature 的使用计数、特定伪类的行为和限制、Shadow DOM 的处理以及 CSS 嵌套等高级特性。这部分测试旨在确保解析器能够准确、可靠地处理各种复杂的 CSS 选择器语法，保证浏览器能够正确地解释和应用网页的样式。它对于维护 Blink 引擎的 CSS 兼容性和稳定性至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_selector_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ParserTest, UseCountShadowPseudo) {
  test::TaskEnvironment task_environment;
  auto ExpectCount = [](const char* selector, WebFeature feature) {
    SCOPED_TRACE(selector);
    EXPECT_TRUE(IsCounted(selector, kHTMLStandardMode, feature));
  };

  ExpectCount("::cue", WebFeature::kCSSSelectorCue);
  ExpectCount("::-internal-media-controls-overlay-cast-button",
              WebFeature::kCSSSelectorInternalMediaControlsOverlayCastButton);
  ExpectCount("::-webkit-calendar-picker-indicator",
              WebFeature::kCSSSelectorWebkitCalendarPickerIndicator);
  ExpectCount("::-webkit-clear-button",
              WebFeature::kCSSSelectorWebkitClearButton);
  ExpectCount("::-webkit-color-swatch",
              WebFeature::kCSSSelectorWebkitColorSwatch);
  ExpectCount("::-webkit-color-swatch-wrapper",
              WebFeature::kCSSSelectorWebkitColorSwatchWrapper);
  ExpectCount("::-webkit-date-and-time-value",
              WebFeature::kCSSSelectorWebkitDateAndTimeValue);
  ExpectCount("::-webkit-datetime-edit",
              WebFeature::kCSSSelectorWebkitDatetimeEdit);
  ExpectCount("::-webkit-datetime-edit-ampm-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditAmpmField);
  ExpectCount("::-webkit-datetime-edit-day-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditDayField);
  ExpectCount("::-webkit-datetime-edit-fields-wrapper",
              WebFeature::kCSSSelectorWebkitDatetimeEditFieldsWrapper);
  ExpectCount("::-webkit-datetime-edit-hour-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditHourField);
  ExpectCount("::-webkit-datetime-edit-millisecond-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditMillisecondField);
  ExpectCount("::-webkit-datetime-edit-minute-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditMinuteField);
  ExpectCount("::-webkit-datetime-edit-month-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditMonthField);
  ExpectCount("::-webkit-datetime-edit-second-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditSecondField);
  ExpectCount("::-webkit-datetime-edit-text",
              WebFeature::kCSSSelectorWebkitDatetimeEditText);
  ExpectCount("::-webkit-datetime-edit-week-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditWeekField);
  ExpectCount("::-webkit-datetime-edit-year-field",
              WebFeature::kCSSSelectorWebkitDatetimeEditYearField);
  ExpectCount("::-webkit-file-upload-button",
              WebFeature::kCSSSelectorWebkitFileUploadButton);
  ExpectCount("::-webkit-inner-spin-button",
              WebFeature::kCSSSelectorWebkitInnerSpinButton);
  ExpectCount("::-webkit-input-placeholder",
              WebFeature::kCSSSelectorWebkitInputPlaceholder);
  ExpectCount("::-webkit-media-controls",
              WebFeature::kCSSSelectorWebkitMediaControls);
  ExpectCount("::-webkit-media-controls-current-time-display",
              WebFeature::kCSSSelectorWebkitMediaControlsCurrentTimeDisplay);
  ExpectCount("::-webkit-media-controls-enclosure",
              WebFeature::kCSSSelectorWebkitMediaControlsEnclosure);
  ExpectCount("::-webkit-media-controls-fullscreen-button",
              WebFeature::kCSSSelectorWebkitMediaControlsFullscreenButton);
  ExpectCount("::-webkit-media-controls-mute-button",
              WebFeature::kCSSSelectorWebkitMediaControlsMuteButton);
  ExpectCount("::-webkit-media-controls-overlay-enclosure",
              WebFeature::kCSSSelectorWebkitMediaControlsOverlayEnclosure);
  ExpectCount("::-webkit-media-controls-overlay-play-button",
              WebFeature::kCSSSelectorWebkitMediaControlsOverlayPlayButton);
  ExpectCount("::-webkit-media-controls-panel",
              WebFeature::kCSSSelectorWebkitMediaControlsPanel);
  ExpectCount("::-webkit-media-controls-play-button",
              WebFeature::kCSSSelectorWebkitMediaControlsPlayButton);
  ExpectCount("::-webkit-media-controls-timeline",
              WebFeature::kCSSSelectorWebkitMediaControlsTimeline);
  ExpectCount("::-webkit-media-controls-timeline-container",
              WebFeature::kCSSSelectorWebkitMediaControlsTimelineContainer);
  ExpectCount("::-webkit-media-controls-time-remaining-display",
              WebFeature::kCSSSelectorWebkitMediaControlsTimeRemainingDisplay);
  ExpectCount(
      "::-webkit-media-controls-toggle-closed-captions-button",
      WebFeature::kCSSSelectorWebkitMediaControlsToggleClosedCaptionsButton);
  ExpectCount("::-webkit-media-controls-volume-slider",
              WebFeature::kCSSSelectorWebkitMediaControlsVolumeSlider);
  ExpectCount("::-webkit-media-slider-container",
              WebFeature::kCSSSelectorWebkitMediaSliderContainer);
  ExpectCount("::-webkit-media-slider-thumb",
              WebFeature::kCSSSelectorWebkitMediaSliderThumb);
  ExpectCount("::-webkit-media-text-track-container",
              WebFeature::kCSSSelectorWebkitMediaTextTrackContainer);
  ExpectCount("::-webkit-media-text-track-display",
              WebFeature::kCSSSelectorWebkitMediaTextTrackDisplay);
  ExpectCount("::-webkit-media-text-track-region",
              WebFeature::kCSSSelectorWebkitMediaTextTrackRegion);
  ExpectCount("::-webkit-media-text-track-region-container",
              WebFeature::kCSSSelectorWebkitMediaTextTrackRegionContainer);
  ExpectCount("::-webkit-meter-bar", WebFeature::kCSSSelectorWebkitMeterBar);
  ExpectCount("::-webkit-meter-even-less-good-value",
              WebFeature::kCSSSelectorWebkitMeterEvenLessGoodValue);
  ExpectCount("::-webkit-meter-inner-element",
              WebFeature::kCSSSelectorWebkitMeterInnerElement);
  ExpectCount("::-webkit-meter-optimum-value",
              WebFeature::kCSSSelectorWebkitMeterOptimumValue);
  ExpectCount("::-webkit-meter-suboptimum-value",
              WebFeature::kCSSSelectorWebkitMeterSuboptimumValue);
  ExpectCount("::-webkit-progress-bar",
              WebFeature::kCSSSelectorWebkitProgressBar);
  ExpectCount("::-webkit-progress-inner-element",
              WebFeature::kCSSSelectorWebkitProgressInnerElement);
  ExpectCount("::-webkit-progress-value",
              WebFeature::kCSSSelectorWebkitProgressValue);
  ExpectCount("::-webkit-search-cancel-button",
              WebFeature::kCSSSelectorWebkitSearchCancelButton);
  ExpectCount("::-webkit-slider-container",
              WebFeature::kCSSSelectorWebkitSliderContainer);
  ExpectCount("::-webkit-slider-runnable-track",
              WebFeature::kCSSSelectorWebkitSliderRunnableTrack);
  ExpectCount("::-webkit-slider-thumb",
              WebFeature::kCSSSelectorWebkitSliderThumb);
  ExpectCount("::-webkit-textfield-decoration-container",
              WebFeature::kCSSSelectorWebkitTextfieldDecorationContainer);
  ExpectCount("::-webkit-unrecognized",
              WebFeature::kCSSSelectorWebkitUnknownPseudo);
}

TEST(CSSSelectorParserTest, IsWhereUseCount) {
  test::TaskEnvironment task_environment;
  const auto is_feature = WebFeature::kCSSSelectorPseudoIs;
  EXPECT_FALSE(IsCounted(".a", kHTMLStandardMode, is_feature));
  EXPECT_FALSE(IsCounted(":not(.a)", kHTMLStandardMode, is_feature));
  EXPECT_FALSE(IsCounted(":where(.a)", kHTMLStandardMode, is_feature));
  EXPECT_TRUE(IsCounted(":is()", kHTMLStandardMode, is_feature));
  EXPECT_TRUE(IsCounted(":is(.a)", kHTMLStandardMode, is_feature));
  EXPECT_TRUE(IsCounted(":not(:is(.a))", kHTMLStandardMode, is_feature));
  EXPECT_TRUE(IsCounted(".a:is(.b)", kHTMLStandardMode, is_feature));
  EXPECT_TRUE(IsCounted(":is(.a).b", kHTMLStandardMode, is_feature));
  EXPECT_FALSE(IsCounted(":is(.a)", kUASheetMode, is_feature));

  const auto where_feature = WebFeature::kCSSSelectorPseudoWhere;
  EXPECT_FALSE(IsCounted(".a", kHTMLStandardMode, where_feature));
  EXPECT_FALSE(IsCounted(":not(.a)", kHTMLStandardMode, where_feature));
  EXPECT_FALSE(IsCounted(":is(.a)", kHTMLStandardMode, where_feature));
  EXPECT_TRUE(IsCounted(":where()", kHTMLStandardMode, where_feature));
  EXPECT_TRUE(IsCounted(":where(.a)", kHTMLStandardMode, where_feature));
  EXPECT_TRUE(IsCounted(":not(:where(.a))", kHTMLStandardMode, where_feature));
  EXPECT_TRUE(IsCounted(".a:where(.b)", kHTMLStandardMode, where_feature));
  EXPECT_TRUE(IsCounted(":where(.a).b", kHTMLStandardMode, where_feature));
  EXPECT_FALSE(IsCounted(":where(.a)", kUASheetMode, where_feature));
}

TEST(CSSSelectorParserTest, ImplicitShadowCrossingCombinators) {
  test::TaskEnvironment task_environment;
  struct ShadowCombinatorTest {
    const char* input;
    Vector<std::pair<AtomicString, CSSSelector::RelationType>> expectation;
  };

  const ShadowCombinatorTest test_cases[] = {
      {
          "*::placeholder",
          {
              {AtomicString("placeholder"), CSSSelector::kUAShadow},
              {g_null_atom, CSSSelector::kSubSelector},
          },
      },
      {
          "div::slotted(*)",
          {
              {AtomicString("slotted"), CSSSelector::kShadowSlot},
              {AtomicString("div"), CSSSelector::kSubSelector},
          },
      },
      {
          "::slotted(*)::placeholder",
          {
              {AtomicString("placeholder"), CSSSelector::kUAShadow},
              {AtomicString("slotted"), CSSSelector::kShadowSlot},
              {g_null_atom, CSSSelector::kSubSelector},
          },
      },
      {
          "span::part(my-part)",
          {
              {AtomicString("part"), CSSSelector::kShadowPart},
              {AtomicString("span"), CSSSelector::kSubSelector},
          },
      },
      {
          "video::-webkit-media-controls",
          {
              {AtomicString("-webkit-media-controls"), CSSSelector::kUAShadow},
              {AtomicString("video"), CSSSelector::kSubSelector},
          },
      },
  };

  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);

  HeapVector<CSSSelector> arena;
  for (auto test_case : test_cases) {
    SCOPED_TRACE(test_case.input);
    CSSParserTokenStream stream(test_case.input);
    base::span<CSSSelector> vector = CSSSelectorParser::ParseSelector(
        stream, context, CSSNestingType::kNone,
        /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
        /*semicolon_aborts_nested_selector=*/false, sheet, arena);
    CSSSelectorList* list = CSSSelectorList::AdoptSelectorVector(vector);
    EXPECT_TRUE(list->IsValid());
    const CSSSelector* selector = list->First();
    for (auto sub_expectation : test_case.expectation) {
      ASSERT_TRUE(selector);
      AtomicString selector_value = selector->Match() == CSSSelector::kTag
                                        ? selector->TagQName().LocalName()
                                        : selector->Value();
      EXPECT_EQ(sub_expectation.first, selector_value);
      EXPECT_EQ(sub_expectation.second, selector->Relation());
      selector = selector->NextSimpleSelector();
    }
    EXPECT_FALSE(selector);
  }
}

static const SelectorTestCase invalid_pseudo_has_arguments_data[] = {
    // clang-format off
    // restrict use of nested :has()
    {":has(:has(.a))", ""},
    {":has(.a, :has(.b), .c)", ""},
    {":has(.a, :has(.b))", ""},
    {":has(:has(.a), .b)", ""},
    {":has(:is(:has(.a)))", ":has(:is())"},

    // restrict use of pseudo element inside :has()
    {":has(::-webkit-progress-bar)", ""},
    {":has(::-webkit-progress-value)", ""},
    {":has(::-webkit-slider-runnable-track)", ""},
    {":has(::-webkit-slider-thumb)", ""},
    {":has(::after)", ""},
    {":has(::backdrop)", ""},
    {":has(::before)", ""},
    {":has(::cue)", ""},
    {":has(::first-letter)", ""},
    {":has(::first-line)", ""},
    {":has(::grammar-error)", ""},
    {":has(::marker)", ""},
    {":has(::placeholder)", ""},
    {":has(::selection)", ""},
    {":has(::slotted(*))", ""},
    {":has(::part(foo))", ""},
    {":has(::spelling-error)", ""},
    {":has(:after)", ""},
    {":has(:before)", ""},
    {":has(:cue)", ""},
    {":has(:first-letter)", ""},
    {":has(:first-line)", ""},

    // drops empty :has()
    {":has()", ""},
    {":has(,,  ,, )", ""},

    // drops :has() when it contains invalid argument
    {":has(.a,,,,)", ""},
    {":has(,,.a,,)", ""},
    {":has(,,,,.a)", ""},
    {":has(@x {,.b,}, .a)", ""},
    {":has({,.b,} @x, .a)", ""},
    {":has((@x), .a)", ""},
    {":has((.b), .a)", ""},

    // clang-format on
};

INSTANTIATE_TEST_SUITE_P(InvalidPseudoHasArguments,
                         SelectorParseTest,
                         testing::ValuesIn(invalid_pseudo_has_arguments_data));

static const SelectorTestCase has_nesting_data[] = {
    // clang-format off
    // :has() is not allowed in the pseudos accepting only compound selectors:
    {"::slotted(:has(.a))", ""},
    {":host(:has(.a))", ""},
    {":host-context(:has(.a))", ""},
    {"::cue(:has(.a))", ""},
    // :has() is not allowed after pseudo elements:
    {"::part(foo):has(:hover)", ""},
    {"::part(foo):has(:hover:focus)", ""},
    {"::part(foo):has(:focus, :hover)", ""},
    {"::part(foo):has(:focus)", ""},
    {"::part(foo):has(:focus, :state(bar))", ""},
    {"::part(foo):has(.a)", ""},
    {"::part(foo):has(.a:hover)", ""},
    {"::part(foo):has(:hover.a)", ""},
    {"::part(foo):has(:hover + .a)", ""},
    {"::part(foo):has(.a + :hover)", ""},
    {"::part(foo):has(:hover:enabled)", ""},
    {"::part(foo):has(:enabled:hover)", ""},
    {"::part(foo):has(:hover, :where(.a))", ""},
    {"::part(foo):has(:hover, .a)", ""},
    {"::part(foo):has(:state(bar), .a)", ""},
    {"::part(foo):has(:enabled)", ""},
    {"::-webkit-scrollbar:has(:enabled)", ""},
    {"::selection:has(:window-inactive)", ""},
    {"::-webkit-input-placeholder:has(:hover)", ""},
    // clang-format on
};

INSTANTIATE_TEST_SUITE_P(NestedHasSelectorValidity,
                         SelectorParseTest,
                         testing::ValuesIn(has_nesting_data));

static CSSSelectorList* ParseNested(String inner_rule,
                                    CSSNestingType nesting_type) {
  auto dummy_holder = std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
  Document& document = dummy_holder->GetDocument();

  auto* parent_rule_for_nesting =
      nesting_type == CSSNestingType::kNone
          ? nullptr
          : DynamicTo<StyleRule>(
                css_test_helpers::ParseRule(document, "div {}"));
  bool is_within_scope = nesting_type == CSSNestingType::kScope;
  CSSSelectorList* list = css_test_helpers::ParseSelectorList(
      inner_rule, nesting_type, parent_rule_for_nesting, is_within_scope);
  if (!list || !list->First()) {
    return nullptr;
  }
  return list;
}

static std::optional<CSSSelector> GetImplicitlyAddedSelector(
    String inner_rule,
    CSSNestingType nesting_type) {
  CSSSelectorList* list = ParseNested(inner_rule, nesting_type);
  if (!list) {
    return std::nullopt;
  }

  Vector<const CSSSelector*> selectors;
  for (const CSSSelector* selector = list->First(); selector;
       selector = selector->NextSimpleSelector()) {
    selectors.push_back(selector);
  }
  // The back of `selectors` now contains the leftmost simple CSSSelector.

  const CSSSelector* back = !selectors.empty() ? selectors.back() : nullptr;
  if (!back || back->Match() != CSSSelector::kPseudoClass ||
      !back->IsImplicit()) {
    return std::nullopt;
  }
  return *back;
}

static std::optional<CSSSelector::PseudoType> GetImplicitlyAddedPseudo(
    String inner_rule,
    CSSNestingType nesting_type) {
  std::optional<CSSSelector> implicit_selector =
      GetImplicitlyAddedSelector(inner_rule, nesting_type);
  if (!implicit_selector.has_value()) {
    return std::nullopt;
  }
  return implicit_selector->GetPseudoType();
}

TEST(CSSSelectorParserTest, NestingTypeImpliedDescendant) {
  test::TaskEnvironment task_environment;
  // Nesting selector (&)
  EXPECT_EQ(CSSSelector::kPseudoParent,
            GetImplicitlyAddedPseudo(".foo", CSSNestingType::kNesting));
  EXPECT_EQ(
      CSSSelector::kPseudoParent,
      GetImplicitlyAddedPseudo(".foo:is(.bar)", CSSNestingType::kNesting));
  EXPECT_EQ(CSSSelector::kPseudoParent,
            GetImplicitlyAddedPseudo("> .foo", CSSNestingType::kNesting));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(".foo > &", CSSNestingType::kNesting));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, &)",
                                                   CSSNestingType::kNesting));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo("& .foo", CSSNestingType::kNesting));

  // :scope
  EXPECT_EQ(CSSSelector::kPseudoScope,
            GetImplicitlyAddedPseudo(".foo", CSSNestingType::kScope));
  EXPECT_EQ(CSSSelector::kPseudoScope,
            GetImplicitlyAddedPseudo(".foo:is(.bar)", CSSNestingType::kScope));
  EXPECT_EQ(CSSSelector::kPseudoScope,
            GetImplicitlyAddedPseudo("> .foo", CSSNestingType::kScope));
  // :scope makes a selector :scope-containing:
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(".foo > :scope", CSSNestingType::kScope));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, :scope)",
                                                   CSSNestingType::kScope));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(":scope .foo", CSSNestingType::kScope));
  // '&' also makes a selector :scope-containing:
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(".foo > &", CSSNestingType::kScope));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, &)",
                                                   CSSNestingType::kScope));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, !&)",
                                                   CSSNestingType::kScope));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, :scope)",
                                                   CSSNestingType::kScope));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, :SCOPE)",
                                                   CSSNestingType::kScope));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, !:scope)",
                                                   CSSNestingType::kScope));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo("& .foo", CSSNestingType::kScope));

  // kNone
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(".foo", CSSNestingType::kNone));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(".foo:is(.bar)", CSSNestingType::kNone));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo("> .foo", CSSNestingType::kNone));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(".foo > &", CSSNestingType::kNone));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, &)",
                                                   CSSNestingType::kNone));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo("& .foo", CSSNestingType::kNone));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(".foo > :scope", CSSNestingType::kNone));
  EXPECT_EQ(std::nullopt, GetImplicitlyAddedPseudo(".foo > :is(.b, :scope)",
                                                   CSSNestingType::kNone));
  EXPECT_EQ(std::nullopt,
            GetImplicitlyAddedPseudo(":scope .foo", CSSNestingType::kNone));
}

// See IsScopeContainingData.
//
// Creates a selector equivalent to to `selector_text`, except inserting
// an empty :where() at each point indicated by `arrows`. The empty :where()
// selectors are used by IsScopeContainingComparison as signals for when
// IsScopeContaining==true is expected.
static String CreateReferenceSelectorForScopeContaining(String selector_text,
                                                        String arrows) {
  CHECK_EQ(selector_text.length(), arrows.length());
  StringBuilder builder;
  for (wtf_size_t i = 0; i < selector_text.length(); ++i) {
    if (arrows[i] == '^') {
      builder.Append(":where()");
    }
    builder.Append(selector_text[i]);
  }
  return builder.ToString();
}

static HeapVector<CSSSelector> FlattenSelector(const CSSSelector* selector) {
  HeapVector<CSSSelector> result;
  while (selector) {
    result.push_back(*selector);
    if (const CSSSelectorList* list = selector->SelectorList()) {
      for (const CSSSelector* s = list->First(); s;
           s = CSSSelectorList::Next(*s)) {
        result.AppendVector(FlattenSelector(s));
      }
    }
    selector = selector->NextSimpleSelector();
  }
  return result;
}

static bool IsScopeContainingComparison(HeapVector<CSSSelector> actual,
                                        HeapVector<CSSSelector> ref) {
  actual.Reverse();
  ref.Reverse();
  // [actual,ref].back() now holds the first CSSSelector produced
  // by FlattenSelector.

  while (!actual.empty()) {
    bool at_arrow = (ref.back().GetPseudoType() == CSSSelector::kPseudoWhere) &&
                    !ref.back().SelectorList()->IsValid();
    if (at_arrow) {
      ref.pop_back();
      CHECK(!ref.empty());
    }
    if (actual.back().IsScopeContaining() != at_arrow) {
      DLOG(ERROR) << "Unexpected value for IsScopeContaining:" << " expected="
                  << at_arrow << " actual=" << actual.back().IsScopeContaining()
                  << " selector=" << actual.back().SimpleSelectorTextForDebug();
      return false;
    }
    actual.pop_back();
    ref.pop_back();
  }

  return ref.empty();
}

struct IsScopeContainingData {
  // The selector text, e.g. ".a .b > .c".
  const char* selector_text;
  // A string of the same length as `selector_text`, where each '^' indicates
  // a simple selector which has the IsScopeContaining flag set.
  const char* arrows;
};

IsScopeContainingData scope_containing_data[] = {
    // No IsScopeContaining flags set:
    {
        ".a",
        "  ",
    },
    {
        "div > .a",
        "        ",
    },
    {
        "div > :is(.b, main) ~ .a",
        "                        ",
    },

    // Explicit :scope top-level:
    {
        ":scope",
        "^     ",
    },
    {
        ".a :scope",
        "   ^     ",
    },
    {
        ".a > :scope > .b",
        "     ^          ",
    },
    {
        ":scope > :scope",
        "^        ^     ",
    },
    {
        ":scope > .a > :scope",
        "^             ^     ",
    },

    // :scope in inner selector lists:
    {
        ".a > :is(.b, :scope, .c) .d",
        "     ^       ^             ",
    },
    {
        ".a > :not(.b, :scope, .c) .d",
        "     ^        ^             ",
    },
    {
        ".a > :is(.b, :scope, .c):scope .d",
        "     ^       ^          ^        ",
    },
    {
        ".a > :is(.b, :scope, .c):scope .d:scope",
        "     ^       ^          ^        ^     ",
    },
    {
        ".a > :is(.b, :scope, :scope, .c):scope .d:scope",
        "     ^       ^       ^          ^        ^     ",
    },
    {
        ".a > :has(> :scope):scope > .b",
        "     ^      ^      ^          ",
    },

    // As the previous section, but using '&' instead of :scope.
    {
        ".a > :is(.b, &, .c) .d",
        "     ^       ^        ",
    },
    {
        ".a > :not(.b, &, .c) .d",
        "     ^        ^        ",
    },
    {
        ".a > :is(.b, &, .c)& .d",
        "     ^       ^     ^   ",
    },
    {
        ".a > :is(.b, &, .c)& .d&",
        "     ^       ^     ^   ^",
    },
    {
        ".a > :is(.b, &, &, .c)& .d&",
        "     ^       ^  ^     ^   ^",
    },
    {
        ".a > :has(> &)& > .b",
        "     ^      ^ ^     ",
    },
};

class IsScopeContainingTest
    : public ::testing::TestWithParam<IsScopeContainingData> {
 private:
  test::TaskEnvironment task_environment_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         IsScopeContainingTest,
                         testing::ValuesIn(scope_containing_data));

TEST_P(IsScopeContainingTest, RefTest) {
  IsScopeContainingData param = GetParam();
  SCOPED_TRACE(param.arrows);
  SCOPED_TRACE(param.selector_text);
  SCOPED_TRACE("'^' indicates where IsScopeContaining==true was expected");
  ASSERT_EQ(strlen(param.selector_text), strlen(param.arrows));

  String ref = CreateReferenceSelectorForScopeContaining(param.selector_text,
                                                         param.arrows);
  CSSSelectorList* actual_list =
      ParseNested(param.selector_text, CSSNestingType::kNone);
  CSSSelectorList* ref_list = ParseNested(ref, CSSNestingType::kNone);
  ASSERT_TRUE(actual_list);
  ASSERT_TRUE(actual_list->First());
  ASSERT_TRUE(ref_list);
  ASSERT_TRUE(ref_list->First());
  EXPECT_TRUE(IsScopeContainingComparison(FlattenSelector(actual_list->First()),
                                          FlattenSelector(ref_list->First())));
}

TEST(CSSSelectorParserTest, ImplicitSelectorIsScopeContaining) {
  test::TaskEnvironment task_environment;
  EXPECT_TRUE(GetImplicitlyAddedSelector("> .a", CSSNestingType::kNesting)
                  .value_or(CSSSelector())
                  .IsScopeContaining());
  EXPECT_TRUE(GetImplicitlyAddedSelector(".a", CSSNestingType::kNesting)
                  .value_or(CSSSelector())
                  .IsScopeContaining());
  EXPECT_TRUE(GetImplicitlyAddedSelector("> .a", CSSNestingType::kScope)
                  .value_or(CSSSelector())
                  .IsScopeContaining());
  EXPECT_TRUE(GetImplicitlyAddedSelector(".a", CSSNestingType::kScope)
                  .value_or(CSSSelector())
                  .IsScopeContaining());
}

}  // namespace blink

"""


```