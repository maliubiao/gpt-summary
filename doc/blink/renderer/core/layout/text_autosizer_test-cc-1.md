Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. This file seems to be a test suite for a feature called "TextAutosizer". The request has several parts:

1. **List the functionalities of the code:** This requires analyzing the test cases to understand what aspects of text autosizing are being tested.
2. **Relate to JavaScript, HTML, CSS:**  Since it's a rendering engine test, there's a high likelihood of interaction with these web technologies. I need to identify how the tests exercise these interactions.
3. **Provide examples for the relationship:** Concrete examples showcasing the interplay between the tested functionality and web technologies are needed.
4. **Logic and assumptions:** Some tests might involve logical calculations. I need to identify these, the inputs, and the expected outputs.
5. **User/programming errors:**  Tests can sometimes reveal potential pitfalls for developers or unexpected behavior for users. I should point these out if present.
6. **Summarize the functionality (Part 2 of 2):**  This will be a concise overview of the entire file's purpose based on the analysis of this snippet and the information gleaned from the previous part (which I don't have access to, so I'll focus on what this snippet reveals).

**Mental Sandbox:**

* **Keyword Identification:**  `TextAutosizer`, `FontSize`, `ComputedFontSize`, `SpecifiedFontSize`, `viewport`, `width`, `ruby`, `MultiColumns`, `device_scale_factor`, `print`, `iframe`, `UseCounter`. These keywords point to core aspects of the functionality being tested.
* **Test Structure:** The code uses the `TEST_P` macro, indicating parameterized tests. This means the same test logic is run with different parameter values (though these specific parameters aren't in this snippet).
* **HTML Structure:**  The tests set up HTML using `SetBodyInnerHTML` or `setInnerHTML`. This is how the scenarios for text autosizing are created.
* **CSS Styling:** CSS is used within the HTML to define initial font sizes, widths, and other layout properties. The tests then check how text autosizing modifies the `ComputedFontSize`.
* **JavaScript Interaction (Likely Indirect):** While no explicit JavaScript is present in this snippet, the underlying text autosizing functionality likely interacts with the browser's layout and rendering engines, which are influenced by JavaScript. The tests implicitly cover these interactions by manipulating the DOM and checking the resulting layout.
* **Calculations:** Several `EXPECT_FLOAT_EQ` calls compare expected computed font sizes with actual values. The comments often provide the formula used for the expected value, involving factors like specified font size, viewport width, and window width.
* **Viewport Influence:**  The `<meta name='viewport' ...>` tag appears frequently, indicating that the viewport configuration is a significant factor in text autosizing.
* **Device Scale Factor:** Tests involving `device_scale_factor` show how the autosizing mechanism adapts to different screen densities.
* **Iframes:** The `UsedDeviceScaleAdjustmentUseCounter` tests involve iframes, suggesting that the scope and context of the document are considered.

**Plan of Action:**

1. Go through each `TEST_P` function and identify the specific scenario being tested.
2. For each test, identify:
    * The HTML and CSS setup.
    * The input (e.g., specified font size, viewport width).
    * The expected output (computed font size).
    * The formula or logic behind the expected output.
    * Connections to HTML, CSS, and potentially JavaScript concepts.
    * Potential user errors or programming mistakes the test might reveal.
3. Based on the individual tests, synthesize the overall functionality of `TextAutosizer`.
4. Summarize the functionality in a concise manner.
这是对 `blink/renderer/core/layout/text_autosizer_test.cc` 文件第二部分的分析，延续了第一部分对文本自动调整大小功能的测试。

**归纳其功能 (基于提供的第二部分代码):**

这部分测试用例主要集中在以下几个方面，以验证 Blink 引擎中文本自动调整大小 (Text Autosizer) 功能的正确性：

1. **考虑容器宽度和视口宽度的文本自动缩放：**
   - 测试了当容器宽度大于视口宽度时，文本自动调整大小以适应视口的情况。
   - 验证了长文本和短文本在相同容器和视口条件下，字体大小被调整到相同大小。

2. **对 Ruby 元素内容进行自动缩放：**
   - 测试了对 `<ruby>` 标签内的文本内容（包括基准文本 `<rb>` 和注音 `<rt>`）进行自动缩放的能力。
   - 分别测试了行内 (inline) 和块级 (block) 的 Ruby 元素的自动缩放行为。

3. **窗口大小改变和字形溢出变化时的处理：**
   - 测试了在窗口大小改变后，文本自动调整大小功能是否能正确更新字体大小。
   - 虽然代码注释中提到了字形溢出 (Glyph Overflow)，但具体的测试逻辑更侧重于窗口尺寸变化的触发。

4. **嵌套的宽容器中窄内容的处理：**
   - 测试了当内容位于多层嵌套的宽容器中，但自身宽度较窄时，文本自动调整大小的行为。
   - 验证了在这种情况下，文本是否会基于其自身有效宽度进行调整，而不是外层容器的宽度。

5. **布局视图宽度提供者的影响：**
   - 测试了当页面元素布局发生变化（例如插入新的元素）时，文本自动调整大小功能是否能正确响应并更新字体大小。

6. **多列布局中的文本自动缩放：**
   - 测试了在 CSS 多列布局 (Multi-Columns) 中，文本自动调整大小是否会考虑列的宽度，而不是整个容器的宽度。
   - 验证了在不同列中的文本字体大小是否一致。

7. **设备像素比 (Device Scale Factor, DSF) 的影响：**
   - 测试了在高设备像素比的屏幕上，文本自动调整大小是否会考虑 DSF 进行字体大小的调整，以保证在不同设备上的可读性。

8. **文本长度对自动缩放的影响：**
   - 测试了当文本内容长度不足以触发自动缩放机制时，字体大小是否保持不变。
   - 区分了在高 DSF 下，长文本是否能触发基于辅助功能字体缩放因子 (accessibility font scale factor) 的调整。

9. **打印后的状态恢复：**
   - 测试了在进入和退出打印模式后，文本自动调整大小功能是否能正确恢复到之前的字体大小。

10. **处理极小宽度的情况：**
    - 测试了当容器宽度非常小（例如 `calc(1px)`）时，文本自动调整大小功能是否能正常工作，避免崩溃或断言失败。

11. **`kUsedDeviceScaleAdjustment` 使用计数器的测试：**
    - 测试了在存在和不存在用户指定的视口 (meta viewport) 的情况下，是否正确记录了使用设备比例调整的次数。
    - 涉及到主框架和子框架 (iframe) 的场景，验证了视口设置的继承和影响范围。

12. **跨站点 iframe 的使用计数器：**
    - 测试了在跨站点的 iframe 中是否正确记录了文本自动调整大小的使用情况。

13. **视口变化更新自动缩放：**
    - 测试了在运行时通过 JavaScript 修改 `<meta name="viewport">` 标签内容后，文本自动调整大小功能是否会相应地更新字体大小。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

- **HTML:** 测试用例通过 `SetBodyInnerHTML` 和 `setInnerHTML`  创建和修改 HTML 结构，这是文本内容和布局的基础。例如：
  ```html
  <div id='longText' style='width: 560px;'>
    Lorem ipsum dolor sit amet...
  </div>
  ```
  这个 HTML 代码片段定义了一个 `div` 元素，其 `id` 为 `longText`，并设置了宽度，用于测试文本自动调整大小在特定宽度容器中的行为。

- **CSS:** 测试用例通过内联样式或 `<style>` 标签来设置 CSS 属性，这些属性会影响文本的布局和字体大小，从而触发文本自动调整大小功能。例如：
  ```css
  <style>
    html { font-size: 16px; }
    body { width: 800px; margin: 0; overflow-y: hidden; }
    #mc {columns: 3; column-gap: 0;}
  </style>
  ```
  这段 CSS 代码设置了 `html` 元素的默认字体大小，`body` 的宽度，以及一个多列布局容器 `#mc`。文本自动调整大小功能会根据这些 CSS 属性以及视口大小来调整文本的最终显示大小。

- **JavaScript (间接关系):** 虽然这段测试代码本身不包含 JavaScript，但文本自动调整大小功能是浏览器渲染引擎的一部分，它会响应 JavaScript 对 DOM 和 CSSOM 的修改。例如，在 `ViewportChangesUpdateAutosizing` 测试中，通过 JavaScript 修改 `meta` 标签的 `content` 属性，触发了文本自动调整大小的重新计算。

**逻辑推理及假设输入与输出:**

1. **测试 `AutosizeWithBlockWidthLargerThanViewportWidth`:**
   - **假设输入:**
     - 视口宽度 (窗口宽度): 320px (由测试框架设置，例如 `gfx::Size(320, 640)`)
     - 块级元素 `#longText` 的 `width` CSS 属性: 560px
     - 块级元素 `#longText` 的 `font-size` CSS 属性: 16px
   - **逻辑:** 文本自动调整大小会根据以下公式计算： `computedFontSize = specifiedFontSize * (blockWidth / windowWidth)`。 由于块宽度大于窗口宽度，字体大小会被放大。
   - **预期输出:**  `#longText` 和 `#shortText` 的 `ComputedFontSize` 都为 `16 * (560 / 320) = 28px`。

2. **测试 `AutosizeInnerContentOfRuby`:**
   - **假设输入:**
     - 视口宽度: 800px (通过 `<meta name='viewport' content='width=800'>` 设置)
     - 窗口宽度: 320px (由测试框架设置)
     - Ruby 元素内部文本的默认 `font-size`: 16px
   - **逻辑:** 文本自动调整大小会根据视口宽度和窗口宽度来调整字体大小。
   - **预期输出:** 行内 Ruby 元素 (`#rubyInline`) 和块级 Ruby 元素 (`#rubyBlock`) 的 `ComputedFontSize` 都为 `16 * (800 / 320) = 40px`。

3. **测试 `MultiColumns`:**
   - **假设输入:**
     - 视口宽度: 800px
     - 窗口宽度: 320px
     - 多列容器 `#mc` 的列数: 3
     - 目标元素 `#target` 的默认 `font-size`: 16px
   - **逻辑:**  在多列布局中，文本自动调整大小会考虑每列的宽度，而不是整个容器的宽度。每列的宽度大约为 `800px / 3`。
   - **预期输出:** 目标元素 `#target` 的 `ComputedFontSize` 将是 `16 * ((800/3) / 320)`，但由于通常有最小字体大小限制，预计为 `16px`。

**用户或者编程常见的使用错误举例说明:**

1. **未设置视口 meta 标签导致意外的缩放:**
   - **错误:** 开发者忘记在移动设备上设置 `<meta name="viewport" content="width=device-width, initial-scale=1.0">`。
   - **结果:**  浏览器可能会使用其默认的视口宽度，导致文本自动调整大小功能过度放大字体，使得页面布局错乱。

2. **过度依赖文本自动调整大小而忽略响应式设计:**
   - **错误:** 开发者没有使用媒体查询 (Media Queries) 或其他响应式设计技术来适配不同屏幕尺寸，而是期望文本自动调整大小功能解决所有问题。
   - **结果:**  虽然文本大小可能被调整，但其他布局元素可能无法很好地适应小屏幕，导致用户体验不佳。

3. **在不希望自动缩放的元素上设置了继承的字体大小:**
   - **错误:** 开发者可能在父元素上设置了一个较大的 `font-size`，导致子元素也继承了这个大小，并被文本自动调整大小进一步放大，即使子元素的内容并不需要这么大的字体。
   - **结果:**  某些特定区域的文本可能显得过大。

4. **在 iframe 中对视口设置理解不足:**
   - **错误:**  开发者可能认为主文档的视口设置会自动应用于所有 iframe，但事实并非如此。每个 iframe 都有自己的文档和视口。
   - **结果:**  iframe 中的文本自动调整大小行为可能与主文档不同，导致不一致的显示效果。

总结来说，这部分测试代码覆盖了 Blink 引擎文本自动调整大小功能的多个核心场景，包括对不同布局模式、容器尺寸、视口配置以及设备特性的处理。通过这些测试，可以确保该功能在各种情况下都能按照预期工作，提升网页在不同设备上的可读性和用户体验。

### 提示词
```
这是目录为blink/renderer/core/layout/text_autosizer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
dolor in reprehenderit in voluptate velit esse cillum dolore eu "
      "fugiat nulla pariatur."
      "    Excepteur sint occaecat cupidatat non proident, sunt in culpa "
      "qui officia deserunt"
      "    mollit anim id est laborum.",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  LayoutObject* long_text = GetLayoutObjectByElementId("longText");
  ;
  EXPECT_FLOAT_EQ(16.f, long_text->StyleRef().SpecifiedFontSize());
  //(specified font-size = 16px) * (block width = 560px) /
  // (window width = 320px) = 28px.
  EXPECT_FLOAT_EQ(28.f, long_text->StyleRef().ComputedFontSize());
  LayoutObject* short_text = GetLayoutObjectByElementId("shortText");
  EXPECT_FLOAT_EQ(16.f, short_text->StyleRef().SpecifiedFontSize());
  EXPECT_FLOAT_EQ(28.f, short_text->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, AutosizeInnerContentOfRuby) {
  SetBodyInnerHTML(R"HTML(
    <meta name='viewport' content='width=800'>
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
    </style>
    <div id='autosized'>
      東京特許許可局許可局長　今日
      <ruby>
        <rb id='rubyInline'>急遽</rb>
        <rp>(</rp>
        <rt>きゅうきょ</rt>
        <rp>)</rp>
      </ruby>
      許可却下、<br><br>
      <span>
          Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec
          sed diam facilisis, elementum elit at, elementum sem. Aliquam
          consectetur leo at nisi fermentum, vitae maximus libero
    sodales. Sed
          laoreet congue ipsum, at tincidunt ante tempor sed. Cras eget
    erat
          mattis urna vestibulum porta. Sed tempus vitae dui et suscipit.
          Curabitur laoreet accumsan pharetra. Nunc facilisis, elit sit
    amet
          sollicitudin condimentum, ipsum velit ultricies mi, eget
    dapibus nunc
          nulla nec sapien. Fusce dictum imperdiet aliquet.
      </span>
      <ruby style='display:block'>
        <rb id='rubyBlock'>拼音</rb>
        <rt>pin yin</rt>
      </ruby>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* ruby_inline = GetElementById("rubyInline");
  EXPECT_FLOAT_EQ(
      16.f, ruby_inline->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 40px.
  EXPECT_FLOAT_EQ(
      40.f, ruby_inline->GetLayoutObject()->StyleRef().ComputedFontSize());

  Element* ruby_block = GetElementById("rubyBlock");
  EXPECT_FLOAT_EQ(
      16.f, ruby_block->GetLayoutObject()->StyleRef().SpecifiedFontSize());
  // (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 40px.
  EXPECT_FLOAT_EQ(40.f,
                  ruby_block->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ResizeAndGlyphOverflowChanged) {
  GetDocument().GetSettings()->SetTextAutosizingWindowSizeOverride(
      gfx::Size(360, 640));
  Element* html = GetDocument().body()->parentElement();
  html->setInnerHTML(
      "<head>"
      "  <meta name='viewport' content='width=800'>"
      "  <style>"
      "    html { font-size:16px; font-family:'Times New Roman';}"
      "  </style>"
      "</head>"
      "<body>"
      "  <span id='autosized' style='font-size:10px'>"
      "    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do"
      "    eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim"
      "    ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut"
      "    aliquip ex ea commodo consequat. Duis aute irure dolor in"
      "    reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla"
      "    pariatur. Excepteur sint occaecat cupidatat non proident, sunt in"
      "    culpa qui officia deserunt mollit anim id est laborum."
      "  </span>"
      "  <span style='font-size:8px'>n</span>"
      "  <span style='font-size:9px'>n</span>"
      "  <span style='font-size:10px'>n</span>"
      "  <span style='font-size:11px'>n</span>"
      "  <span style='font-size:12px'>n</span>"
      "  <span style='font-size:13px'>n</span>"
      "  <span style='font-size:14px'>n</span>"
      "  <span style='font-size:15px'>n</span>"
      "</body>",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  GetDocument().GetSettings()->SetTextAutosizingWindowSizeOverride(
      gfx::Size(640, 360));
  UpdateAllLifecyclePhasesForTest();

  GetDocument().GetSettings()->SetTextAutosizingWindowSizeOverride(
      gfx::Size(360, 640));
  UpdateAllLifecyclePhasesForTest();
}

TEST_P(TextAutosizerTest, narrowContentInsideNestedWideBlock) {
  Element* html = GetDocument().body()->parentElement();
  html->setInnerHTML(
      "<head>"
      "  <meta name='viewport' content='width=800'>"
      "  <style>"
      "    html { font-size:16px;}"
      "  </style>"
      "</head>"
      "<body>"
      "  <div style='width:800px'>"
      "    <div style='width:800px'>"
      "      <div style='width:200px' id='content'>"
      "        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed "
      "        do eiusmod tempor incididunt ut labore et dolore magna aliqua."
      "        Ut enim ad minim veniam, quis nostrud exercitation ullamco "
      "        laboris nisi ut aliquip ex ea commodo consequat. Duis aute "
      "        irure dolor in reprehenderit in voluptate velit esse cillum "
      "        dolore eu fugiat nulla pariatur. Excepteur sint occaecat "
      "        cupidatat non proident, sunt in culpa qui officia deserunt "
      "        mollit anim id est laborum."
      "      </div>"
      "    </div>"
      "    Content belong to first wide block."
      "  </div>"
      "</body>",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  Element* content = GetElementById("content");
  //(content width = 200px) / (window width = 320px) < 1.0f, multiplier = 1.0,
  // font-size = 16px;
  EXPECT_FLOAT_EQ(16.f,
                  content->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, LayoutViewWidthProvider) {
  Element* html = GetDocument().body()->parentElement();
  html->setInnerHTML(
      "<head>"
      "  <meta name='viewport' content='width=800'>"
      "  <style>"
      "    html { font-size:16px;}"
      "    #content {margin-left: 140px;}"
      "  </style>"
      "</head>"
      "<body>"
      "  <div id='content'>"
      "    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do"
      "    eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim"
      "    ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut"
      "    aliquip ex ea commodo consequat. Duis aute irure dolor in"
      "    reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla"
      "    pariatur. Excepteur sint occaecat cupidatat non proident, sunt in"
      "    culpa qui officia deserunt mollit anim id est laborum."
      "  </div>"
      "  <div id='panel'></div>"
      "</body>",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  Element* content = GetElementById("content");
  // (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 40px.
  EXPECT_FLOAT_EQ(40.f,
                  content->GetLayoutObject()->StyleRef().ComputedFontSize());

  GetElementById("panel")->setInnerHTML("insert text");
  content->setInnerHTML(content->innerHTML());
  UpdateAllLifecyclePhasesForTest();

  // (specified font-size = 16px) * (viewport width = 800px) /
  // (window width = 320px) = 40px.
  EXPECT_FLOAT_EQ(40.f,
                  content->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, MultiColumns) {
  Element* html = GetDocument().body()->parentElement();
  html->setInnerHTML(
      "<head>"
      "  <meta name='viewport' content='width=800'>"
      "  <style>"
      "    html { font-size:16px;}"
      "    #mc {columns: 3;}"
      "  </style>"
      "</head>"
      "<body>"
      "  <div id='mc'>"
      "    <div id='target'>"
      "      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed "
      "      do eiusmod tempor incididunt ut labore et dolore magna aliqua."
      "      Ut enim ad minim veniam, quis nostrud exercitation ullamco "
      "      laboris nisi ut aliquip ex ea commodo consequat. Duis aute "
      "      irure dolor in reprehenderit in voluptate velit esse cillum "
      "      dolore eu fugiat nulla pariatur. Excepteur sint occaecat "
      "      cupidatat non proident, sunt in culpa qui officia deserunt "
      "    </div>"
      "  </div>"
      "  <div> hello </div>"
      "</body>",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  Element* target = GetElementById("target");
  // (specified font-size = 16px) * ( thread flow layout width = 800px / 3) /
  // (window width = 320px) < 16px.
  EXPECT_FLOAT_EQ(16.f,
                  target->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, MultiColumns2) {
  Element* html = GetDocument().body()->parentElement();
  html->setInnerHTML(
      "<head>"
      "  <meta name='viewport' content='width=800'>"
      "  <style>"
      "    html { font-size:16px;}"
      "    #mc {columns: 3; column-gap: 0;}"
      "  </style>"
      "</head>"
      "<body>"
      "  <div id='mc'>"
      "    <div id='target1'>"
      "      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed "
      "      do eiusmod tempor incididunt ut labore et dolore magna aliqua."
      "      Ut enim ad minim veniam, quis nostrud exercitation ullamco "
      "      laboris nisi ut aliquip ex ea commodo consequat. Duis aute "
      "      irure dolor in reprehenderit in voluptate velit esse cillum "
      "      dolore eu fugiat nulla pariatur. Excepteur sint occaecat "
      "      cupidatat non proident, sunt in culpa qui officia deserunt "
      "    </div>"
      "    <div id='target2'>"
      "      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed "
      "      do eiusmod tempor incididunt ut labore et dolore magna aliqua."
      "      Ut enim ad minim veniam, quis nostrud exercitation ullamco "
      "      laboris nisi ut aliquip ex ea commodo consequat. Duis aute "
      "      irure dolor in reprehenderit in voluptate velit esse cillum "
      "      dolore eu fugiat nulla pariatur. Excepteur sint occaecat "
      "      cupidatat non proident, sunt in culpa qui officia deserunt "
      "    </div>"
      "  </div>"
      "  <div> hello </div>"
      "</body>",
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  Element* target1 = GetElementById("target1");
  Element* target2 = GetElementById("target2");
  // (specified font-size = 16px) * ( column width = 800px / 3) /
  // (window width = 320px) < 16px.
  EXPECT_FLOAT_EQ(16.f,
                  target1->GetLayoutObject()->StyleRef().ComputedFontSize());
  EXPECT_FLOAT_EQ(16.f,
                  target2->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ScaledbyDSF) {
  const float device_scale = 3;
  set_device_scale_factor(device_scale);
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 16px; }
      body { width: 800px; margin: 0; overflow-y: hidden; }
      .target { width: 560px; }
    </style>
    <body>
      <div id='target'>
        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed
        do eiusmod tempor incididunt ut labore et dolore magna aliqua.
        Ut enim ad minim veniam, quis nostrud exercitation ullamco
        laboris nisi ut aliquip ex ea commodo consequat. Duis aute
        irure dolor in reprehenderit in voluptate velit esse cillum
        dolore eu fugiat nulla pariatur. Excepteur sint occaecat
        cupidatat non proident, sunt in culpa qui officia deserunt
      </div>
    </body>
  )HTML");
  Element* target = GetElementById("target");
  // (specified font-size = 16px) * (thread flow layout width = 800px) /
  // (window width = 320px) * (device scale factor) = 40px * device_scale.
  EXPECT_FLOAT_EQ(40.0f * device_scale,
                  target->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, ClusterHasNotEnoughTextToAutosizeForZoomDSF) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 8px; }
    </style>
    <body>
      <div id='target'>
        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed
        do eiusmod tempor incididunt ut labore et dolore magna aliqua.
        Ut enim ad minim veniam, quis nostrud exercitation ullamco
        laboris nisi ut aliquip ex ea commodo consequat.
      </div>
    </body>
  )HTML");
  Element* target = GetElementById("target");
  // ClusterHasEnoughTextToAutosize() returns false because
  // minimum_text_length_to_autosize < length. Thus, ClusterMultiplier()
  // returns 1 (not multiplied by the accessibility font scale factor).
  // computed font-size = specified font-size = 8px.
  EXPECT_FLOAT_EQ(8.0f,
                  target->GetLayoutObject()->StyleRef().ComputedFontSize());
}

// TODO(jaebaek): Unit tests ClusterHasNotEnoughTextToAutosizeForZoomDSF and
// ClusterHasEnoughTextToAutosizeForZoomDSF must be updated.
// The return value of TextAutosizer::ClusterHasEnoughTextToAutosize() must not
// be the same regardless of DSF. In real world
// TextAutosizer::ClusterHasEnoughTextToAutosize(),
// minimum_text_length_to_autosize is in physical pixel scale. However, in
// these unit tests, it is in DIP scale, which makes
// ClusterHasEnoughTextToAutosizeForZoomDSF not fail. We need a trick to update
// the minimum_text_length_to_autosize in these unit test and check the return
// value change of TextAutosizer::ClusterHasEnoughTextToAutosize() depending on
// the length of text even when DSF is not 1 (e.g., letting DummyPageHolder
// update the view size according to the change of DSF).
TEST_P(TextAutosizerTest, ClusterHasEnoughTextToAutosizeForZoomDSF) {
  const float device_scale = 3;
  set_device_scale_factor(device_scale);
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 8px; }
    </style>
    <body>
      <div id='target'>
        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed
        do eiusmod tempor incididunt ut labore et dolore magna aliqua.
        Ut enim ad minim veniam, quis nostrud exercitation ullamco
        laboris nisi ut aliquip ex ea commodo consequat.
      </div>
    </body>
  )HTML");
  Element* target = GetElementById("target");
  // (specified font-size = 8px) * (thread flow layout width = 800px) /
  // (window width = 320px) * (device scale factor) = 20px * device_scale.
  // ClusterHasEnoughTextToAutosize() returns true and both accessibility font
  // scale factor and device scale factor are multiplied.
  EXPECT_FLOAT_EQ(20.0f * device_scale,
                  target->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, AfterPrint) {
  const float device_scale = 3;
  gfx::SizeF print_size(160, 240);
  set_device_scale_factor(device_scale);
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 8px; }
    </style>
    <body>
      <div id='target'>
        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed
        do eiusmod tempor incididunt ut labore et dolore magna aliqua.
        Ut enim ad minim veniam, quis nostrud exercitation ullamco
        laboris nisi ut aliquip ex ea commodo consequat.
      </div>
    </body>
  )HTML");
  Element* target = GetElementById("target");
  EXPECT_FLOAT_EQ(20.0f * device_scale,
                  target->GetLayoutObject()->StyleRef().ComputedFontSize());
  GetDocument().GetFrame()->StartPrinting(WebPrintParams(print_size));
  EXPECT_FLOAT_EQ(8.0f,
                  target->GetLayoutObject()->StyleRef().ComputedFontSize());
  GetDocument().GetFrame()->EndPrinting();
  EXPECT_FLOAT_EQ(20.0f * device_scale,
                  target->GetLayoutObject()->StyleRef().ComputedFontSize());
}

TEST_P(TextAutosizerTest, FingerprintWidth) {
  SetBodyInnerHTML(R"HTML(
    <style>
      html { font-size: 8px; }
      #target { width: calc(1px); }
    </style>
    <body>
      <div id='target'>
        Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed
        do eiusmod tempor incididunt ut labore et dolore magna aliqua.
        Ut enim ad minim veniam, quis nostrud exercitation ullamco
        laboris nisi ut aliquip ex ea commodo consequat.
      </div>
    </body>
  )HTML");
  // The test pass if it doesn't crash nor hit DCHECK.
}

// Test that `kUsedDeviceScaleAdjustment` is not recorded when a user-specified
// meta viewport is present on the outermost main frame.
TEST_P(TextAutosizerTest, UsedDeviceScaleAdjustmentUseCounterWithViewport) {
  SetBodyInnerHTML(R"HTML(
    <meta name="viewport" content="width=device-width">
    <div style="font-size: 20px">
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
      tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
      veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea
      commodo consequat.
    </div>
    <iframe></iframe>
  )HTML");
  GetDocument().GetSettings()->SetViewportMetaEnabled(true);
  GetDocument().GetSettings()->SetDeviceScaleAdjustment(1.5f);
  // Do not specify a meta viewport in the subframe. If the subframe's lack of a
  // meta viewport were used, it would incorrectly cause the device scale
  // adjustment to be used.
  SetChildFrameHTML(R"HTML(
    <div style="font-size: 20px">
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
      tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
      veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea
      commodo consequat.
    </div>
  )HTML");
  ASSERT_TRUE(ChildDocument().GetSettings()->GetViewportMetaEnabled());
  ASSERT_EQ(1.5f, ChildDocument().GetSettings()->GetDeviceScaleAdjustment());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kUsedDeviceScaleAdjustment));
  EXPECT_FALSE(
      ChildDocument().IsUseCounted(WebFeature::kUsedDeviceScaleAdjustment));
}

// Test that `kUsedDeviceScaleAdjustment` is recorded when a user-specified meta
// viewport is not specified on the outermost main frame.
TEST_P(TextAutosizerTest, UsedDeviceScaleAdjustmentUseCounterWithoutViewport) {
  SetBodyInnerHTML(R"HTML(
    <div style="font-size: 20px">
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
      tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
      veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea
      commodo consequat.
    </div>
    <iframe></iframe>
  )HTML");
  // We should not record the metric before setting the viewport settings.
  ASSERT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kUsedDeviceScaleAdjustment));
  GetDocument().GetSettings()->SetViewportMetaEnabled(true);
  GetDocument().GetSettings()->SetDeviceScaleAdjustment(1.5f);
  // Specify a meta viewport in the subframe. If the subframe's meta viewport
  // were used, it would incorrectly prevent the device scale adjustment from
  // being used.
  SetChildFrameHTML(R"HTML(
    <meta name="viewport" content="width=device-width">
    <div style="font-size: 20px">
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
      tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
      veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea
      commodo consequat.
    </div>
  )HTML");
  ASSERT_TRUE(ChildDocument().GetSettings()->GetViewportMetaEnabled());
  ASSERT_EQ(1.5f, ChildDocument().GetSettings()->GetDeviceScaleAdjustment());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kUsedDeviceScaleAdjustment));
  EXPECT_TRUE(
      ChildDocument().IsUseCounted(WebFeature::kUsedDeviceScaleAdjustment));
}

class TextAutosizerSimTest : public SimTest,
                             public testing::WithParamInterface<bool>,
                             private ScopedTextSizeAdjustImprovementsForTest {
 public:
  TextAutosizerSimTest()
      : ScopedTextSizeAdjustImprovementsForTest(GetParam()) {}

 private:
  void SetUp() override {
    SimTest::SetUp();

    WebSettings* web_settings = WebView().GetSettings();
    web_settings->SetViewportEnabled(true);
    web_settings->SetViewportMetaEnabled(true);

    Settings& settings = WebView().GetPage()->GetSettings();
    settings.SetTextAutosizingEnabled(true);
    settings.SetTextAutosizingWindowSizeOverride(gfx::Size(400, 400));
    settings.SetDeviceScaleAdjustment(1.5f);
  }
};

INSTANTIATE_TEST_SUITE_P(All, TextAutosizerSimTest, testing::Bool());

TEST_P(TextAutosizerSimTest, CrossSiteUseCounter) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 800));

  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_resource("https://crosssite.com/", "text/html");

  LoadURL("https://example.com/");
  main_resource.Complete(
      "<iframe width=700 src='https://crosssite.com/'></iframe>");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_resource.Complete(R"HTML(
    <body style='font-size: 20px'>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed
      do eiusmod tempor incididunt ut labore et dolore magna aliqua.
      Ut enim ad minim veniam, quis nostrud exercitation ullamco
      laboris nisi ut aliquip ex ea commodo consequat.
    </body>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  auto* child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto* child_doc = child_frame->GetFrame()->GetDocument();

  EXPECT_TRUE(
      child_doc->IsUseCounted(WebFeature::kTextAutosizedCrossSiteIframe));
}

TEST_P(TextAutosizerSimTest, ViewportChangesUpdateAutosizing) {
  if (!RuntimeEnabledFeatures::ViewportChangesUpdateTextAutosizingEnabled()) {
    GTEST_SKIP();
  }

  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <meta>
    <style>
      html { font-size: 16px; }
      body { width: 320px; margin: 0; overflow-y: hidden; }
    </style>
    <div>
      Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
      eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim
      ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
      aliquip ex ea commodo consequat. Duis aute irure dolor in
      reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
      pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
      culpa qui officia deserunt mollit anim id est laborum.
    </div>
  )HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(GetDocument()
                   .GetViewportData()
                   .GetViewportDescription()
                   .IsSpecifiedByAuthor());

  // The page should autosize because a meta viewport is not specified.
  auto* div = GetDocument().QuerySelector(AtomicString("div"));
  EXPECT_FLOAT_EQ(18.f, div->GetLayoutObject()->StyleRef().ComputedFontSize());

  Element* meta = GetDocument().QuerySelector(AtomicString("meta"));
  meta->setAttribute(html_names::kNameAttr, AtomicString("viewport"));
  meta->setAttribute(html_names::kContentAttr,
                     AtomicString("width=device-width"));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // The page should no longer autosize because a meta viewport is specified.
  EXPECT_FLOAT_EQ(16.f, div->GetLayoutObject()->StyleRef().ComputedFontSize());
}

}  // namespace blink
```