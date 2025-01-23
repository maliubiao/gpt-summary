Response:
The user wants a summary of the provided C++ code, specifically focusing on its functionality within the Chromium Blink engine. I need to identify what aspects of web technologies (HTML, CSS, Javascript) it interacts with and provide illustrative examples. If the code demonstrates logical operations, I should infer input and output scenarios. Finally, I need to point out potential user or programming errors related to the tested features.

**Plan:**

1. **Overall Function:** Determine the primary goal of the test file. It seems to be testing the `text-combine-upright` CSS property in various scenarios.
2. **HTML Interaction:** Identify how the tests manipulate the DOM using `SetBodyInnerHTML`.
3. **CSS Interaction:**  Pinpoint the CSS properties being tested (`text-combine-upright`, `writing-mode`).
4. **Javascript Interaction:** Note the use of Javascript-related APIs like `remove()`, `replaceChild()`, `setData()`, and `splitText()`.
5. **Logical Inference:** For each test case, analyze the initial state, the performed action, and the expected outcome. This will help infer the logic being tested.
6. **Common Errors:** Based on the tests, identify potential mistakes developers might make when using `text-combine-upright`.
7. **Categorize and Summarize:** Group the test cases by the functionality they cover (e.g., adding/removing elements, manipulating text content, changing styles).
8. **Structure the Output:**  Organize the findings into clear sections for functionality, HTML/CSS/JS relationships with examples, logical inference, and common errors.
这是对`blink/renderer/core/layout/layout_text_combine_test.cc` 文件中剩余测试用例的分析和总结。这些测试用例主要关注在使用了 `text-combine-upright` CSS 属性的元素内部进行各种 DOM 操作和样式更改后，布局树的结构是否符合预期。

**文件功能归纳（第 2 部分）：**

这部分测试用例主要验证当元素应用了 `text-combine-upright` 属性（通常与垂直书写模式 `writing-mode: vertical-rl` 配合使用）后，对其子节点进行动态修改（例如添加、删除、替换子节点，修改文本内容，拆分文本节点）或者修改自身及父元素的样式时，布局树的正确生成和维护。

**与 Javascript, HTML, CSS 的关系及举例说明：**

* **HTML:**  测试用例通过 `SetBodyInnerHTML()` 方法设置 HTML 结构，这是测试的基础。例如：
    ```c++
    SetBodyInnerHTML("<div id=root><c>a<b id=t>x</b>z</c></div>");
    ```
    这里定义了一个包含嵌套元素的 HTML 结构，`c` 元素后续会被应用 `text-combine-upright` 样式。

* **CSS:** 测试用例通过 `InsertStyleElement()` 方法插入 CSS 样式，来激活 `text-combine-upright` 属性和 `writing-mode` 属性。例如：
    ```c++
    InsertStyleElement(
        "c { text-combine-upright: all; }"
        "div { writing-mode: vertical-rl; }");
    ```
    这段 CSS 将会使得 `<c>` 元素内的文本按照组合文本的方式垂直排列。

* **Javascript:**  测试用例模拟了 Javascript 对 DOM 的操作，并验证布局树的更新是否正确。涉及的 Javascript API 包括：
    * **`remove()`:** 删除节点。
        ```c++
        GetElementById("t")->remove();
        ```
        这个操作会删除 id 为 `t` 的元素，测试确保删除后组合文本的布局结构仍然正确。
    * **`replaceChild()`:** 替换节点。
        ```c++
        target.parentNode()->replaceChild(&new_text, &target);
        ```
        这个操作会将 id 为 `t` 的元素替换为一个新的文本节点，测试验证替换后组合文本的布局结构。
    * **`setData()`:** 修改文本节点的内容。
        ```c++
        To<Text>(GetElementById("combine")->firstChild())->setData("");
        ```
        这个操作将组合文本元素的文本内容设置为空，测试验证当组合文本的文本内容为空时，是否会生成不必要的包装元素。
    * **`splitText()`:** 分割文本节点。
        ```c++
        To<Text>(GetElementById("combine")->firstChild())->splitText(1, ASSERT_NO_EXCEPTION);
        ```
        这个操作会将组合文本元素的文本节点在指定位置分割，测试验证分割后是否会生成新的组合文本布局结构。
    * **`setAttribute()`:** 修改元素的 HTML 属性，可以用来动态改变元素的样式。
        ```c++
        GetElementById("combine")->setAttribute(
            html_names::kStyleAttr, AtomicString("text-combine-upright: all"));
        ```
        这个操作动态地给元素添加或修改 `text-combine-upright` 样式，测试验证样式改变后布局树的更新。

**逻辑推理（假设输入与输出）：**

* **`RemoveChildToOneCombinedText`:**
    * **假设输入:**  HTML `<div id=root><c>a<b id=t>x</b>z</c></div>`，CSS 规则使得 `<c>` 元素应用 `text-combine-upright: all;` 和父元素应用 `writing-mode: vertical-rl;`。
    * **操作:**  通过 Javascript 删除 id 为 `t` 的 `<b>` 元素。
    * **预期输出:**  `<c>` 元素内部的文本节点 "a" 和 "z" 会被组合在一个 `LayoutTextCombine` 布局对象中。

* **`ReplaceChildToOneCombinedText`:**
    * **假设输入:**  与上例相同。
    * **操作:**  通过 Javascript 将 id 为 `t` 的 `<b>` 元素替换为文本节点 "X"。
    * **预期输出:**  `<c>` 元素内部的文本节点 "a"、"X" 和 "z" 会被组合在一个 `LayoutTextCombine` 布局对象中。

* **`SetDataToEmpty`:**
    * **假设输入:** HTML `<div id=root>ab<c id=combine>XY</c>de</div>`，CSS 规则使得 `<c>` 元素应用 `text-combine-upright: all;` 和父元素应用 `writing-mode: vertical-rl;`。
    * **操作:**  通过 Javascript 将 id 为 `combine` 的 `<c>` 元素内的文本内容设置为空字符串 `""`。
    * **预期输出:**  应用了 `text-combine-upright` 的元素如果内部没有文本内容，则不应该生成 `LayoutTextCombine` 布局对象。

* **`SplitText`:**
    * **假设输入:** 与 `SetDataToEmpty` 相同。
    * **操作:**  通过 Javascript 将 id 为 `combine` 的 `<c>` 元素内的文本节点 "XY" 在索引 1 的位置分割成两个文本节点 "X" 和 "Y"。
    * **预期输出:**  `<c>` 元素内部的两个文本节点 "X" 和 "Y" 会分别被组合在同一个 `LayoutTextCombine` 布局对象中。

* **`StyleToTextCombineUprightAll` / `StyleToTextCombineUprightNone`:**
    * **假设输入:** HTML `<div id=root>ab<c id=combine><b>XY</b></c>de</div>`，初始状态 `<c>` 元素没有 `text-combine-upright` 样式。父元素应用 `writing-mode: vertical-rl;`。
    * **操作:**  通过 Javascript 动态设置或移除 `<c>` 元素的 `text-combine-upright` 样式。
    * **预期输出:**  当设置 `text-combine-upright: all` 时，`<b>` 元素内的文本 "XY" 会被组合在一个 `LayoutTextCombine` 布局对象中。当设置为 `none` 或移除时，则不会有 `LayoutTextCombine` 对象。

* **`StyleToHorizontalWritingMode` / `StyleToVerticalWritingMode`:**
    * **假设输入:** HTML `<div id=root>ab<c id=combine><b>XY</b></c>de</div>`，初始状态 `<c>` 元素应用 `text-combine-upright: all;`，父元素应用或不应用 `writing-mode: vertical-rl;`。
    * **操作:**  通过 Javascript 动态修改父元素的 `writing-mode` 样式。
    * **预期输出:**  只有当 `writing-mode` 为垂直模式（如 `vertical-rl`）时，并且元素本身有 `text-combine-upright` 样式时，才会生成 `LayoutTextCombine` 布局对象。

**涉及用户或者编程常见的使用错误：**

* **错误地认为 `text-combine-upright` 在水平书写模式下有效:**  测试用例 `InHorizontal` 和 `InVertical` 明确指出，`text-combine-upright` 主要用于垂直书写模式。在水平书写模式下，即使设置了该属性，也不会生成 `LayoutTextCombine` 对象，文本会像正常内联元素一样排列。用户可能会错误地期望在水平模式下也能使用该属性来压缩文本。

* **忘记配合 `writing-mode` 使用:**  `text-combine-upright` 通常与 `writing-mode: vertical-rl` 或 `writing-mode: vertical-lr` 配合使用才能看到效果。如果只设置了 `text-combine-upright` 而没有设置垂直书写模式，那么文本不会被组合排列。开发者可能会忘记设置 `writing-mode` 导致 `text-combine-upright` 没有生效。

* **在动态修改 DOM 后，没有触发布局更新:**  虽然测试代码使用了 `RunDocumentLifecycle()` 来显式触发布局更新，但在实际开发中，开发者可能在修改 DOM 后忘记触发布局更新，导致页面显示不符合预期。

* **错误地假设空文本节点会生成 `LayoutTextCombine` 对象:**  `SetDataToEmpty` 测试用例表明，当应用了 `text-combine-upright` 的元素内部文本为空时，不会生成 `LayoutTextCombine` 对象。开发者可能错误地认为即使文本为空也会有对应的布局对象。

* **对包含子元素的元素应用 `text-combine-upright` 的行为理解不准确:**  例如 `StyleToTextCombineUprightAll` 测试用例显示，即使组合文本内部包含其他内联元素（如 `<b>`），`text-combine-upright` 仍然会作用于该内联元素内的文本节点。开发者需要理解 `text-combine-upright` 对文本节点的影响范围。

总而言之，这部分测试用例覆盖了在使用 `text-combine-upright` 属性时，进行各种常见的 DOM 操作和样式更改的场景，确保 Blink 引擎能够正确地处理这些情况并生成符合预期的布局树。这有助于开发者避免在使用该特性时遇到意外的布局问题。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_text_combine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
bug.com/1227066
TEST_F(LayoutTextCombineTest, RemoveChildToOneCombinedText) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root><c>a<b id=t>x</b>z</c></div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutInline C
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "a"
  |  +--LayoutInline B id="t"
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "x"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "z"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  GetElementById("t")->remove();
  RunDocumentLifecycle();

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutInline C
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "a"
  |  |  +--LayoutText #text "z"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1227066
TEST_F(LayoutTextCombineTest, ReplaceChildToOneCombinedText) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root><c>a<b id=t>x</b>z</c></div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutInline C
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "a"
  |  +--LayoutInline B id="t"
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "x"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "z"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  auto& target = *GetElementById("t");
  auto& new_text = *Text::Create(GetDocument(), "X");
  target.parentNode()->replaceChild(&new_text, &target);
  RunDocumentLifecycle();

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutInline C
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "a"
  |  |  +--LayoutText #text "X"
  |  |  +--LayoutText #text "z"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, SetDataToEmpty) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  To<Text>(GetElementById("combine")->firstChild())->setData("");
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object))
      << "We should not have a wrapper.";
}

TEST_F(LayoutTextCombineTest, SplitText) {
  V8TestingScope scope;

  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  To<Text>(GetElementById("combine")->firstChild())
      ->splitText(1, ASSERT_NO_EXCEPTION);
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "X"
  |  |  +--LayoutText #text "Y"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, SplitTextAtZero) {
  V8TestingScope scope;

  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  To<Text>(GetElementById("combine")->firstChild())
      ->splitText(0, ASSERT_NO_EXCEPTION);
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object))
      << "There are no empty LayoutText.";
}

TEST_F(LayoutTextCombineTest, SplitTextBeforeBox) {
  V8TestingScope scope;

  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY<b>Z</b></c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  |  +--LayoutInline B
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "Z"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  To<Text>(GetElementById("combine")->firstChild())
      ->splitText(1, ASSERT_NO_EXCEPTION);
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "X"
  |  |  +--LayoutText #text "Y"
  |  +--LayoutInline B
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "Z"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, StyleToTextCombineUprightAll) {
  InsertStyleElement("div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine><b>XY</b></c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutInline B
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object))
      << "There are no wrapper.";

  GetElementById("combine")->setAttribute(
      html_names::kStyleAttr, AtomicString("text-combine-upright: all"));
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine" style="text-combine-upright: all"
  |  +--LayoutInline B
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object))
      << "There are no wrapper.";
}

TEST_F(LayoutTextCombineTest, StyleToTextCombineUprightNone) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine><b>XY</b></c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutInline B
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  GetElementById("combine")->setAttribute(
      html_names::kStyleAttr, AtomicString("text-combine-upright: none"));
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine" style="text-combine-upright: none"
  |  +--LayoutInline B
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object))
      << "There are no wrapper.";
}

TEST_F(LayoutTextCombineTest, StyleToHorizontalWritingMode) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine><b>XY</b></c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutInline B
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  root.setAttribute(html_names::kStyleAttr,
                    AtomicString("writing-mode: horizontal-tb"));
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root" style="writing-mode: horizontal-tb"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutInline B
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object))
      << "There are no wrapper.";
}

TEST_F(LayoutTextCombineTest, StyleToHorizontalWritingModeWithWordBreak) {
  InsertStyleElement(
      "wbr { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root><wbr></div>");
  auto& root = *GetElementById("root");

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutTextCombine (anonymous)
  |  +--LayoutWordBreak WBR
)DUMP",
            ToSimpleLayoutTree(*root.GetLayoutObject()));

  root.setAttribute(html_names::kStyleAttr,
                    AtomicString("writing-mode: horizontal-tb"));
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root" style="writing-mode: horizontal-tb"
  +--LayoutWordBreak WBR
)DUMP",
            ToSimpleLayoutTree(*root.GetLayoutObject()));
}

TEST_F(LayoutTextCombineTest, StyleToVerticalWritingMode) {
  InsertStyleElement("c { text-combine-upright: all; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine><b>XY</b></c>de</div>");
  auto& root = *GetElementById("root");
  const auto& root_layout_object = *To<LayoutBlockFlow>(root.GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutInline B
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));

  root.setAttribute(html_names::kStyleAttr,
                    AtomicString("writing-mode: vertical-rl"));
  RunDocumentLifecycle();
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root" style="writing-mode: vertical-rl"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutInline B
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1222121
TEST_F(LayoutTextCombineTest, VerticalWritingModeByBR) {
  InsertStyleElement(
      "#sample {  text-combine-upright: all; writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<br id=sample>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetDocument().body()->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow BODY
  +--LayoutBR BR id="sample"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1222121
TEST_F(LayoutTextCombineTest, VerticalWritingModeByWBR) {
  InsertStyleElement(
      "#sample {  text-combine-upright: all; writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<wbr id=sample>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetDocument().body()->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow BODY
  +--LayoutWordBreak WBR id="sample"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1222069
TEST_F(LayoutTextCombineTest, WithBidiControl) {
  InsertStyleElement(
      "c { text-combine-upright: all; -webkit-rtl-ordering: visual; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY</c>de</div>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, WithBR) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY<br>Z</c>de</div>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  |  |  +--LayoutBR BR
  |  |  +--LayoutText #text "Z"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1060007
TEST_F(LayoutTextCombineTest, WithMarker) {
  InsertStyleElement(
      "li { text-combine-upright: all; }"
      "p {"
      "  counter-increment: my-counter;"
      "  display: list-item;"
      "  writing-mode: vertical-rl;"
      "}"
      "p::marker {"
      "  content: '<' counter(my-counter) '>';"
      "  text-combine-upright: all;"
      "}");
  SetBodyInnerHTML("<p id=root>ab</p>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());
  EXPECT_EQ(R"DUMP(
LayoutListItem P id="root"
  +--LayoutOutsideListMarker ::marker
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutTextFragment (anonymous) ("<")
  |  |  +--LayoutCounter (anonymous) "1"
  |  |  +--LayoutTextFragment (anonymous) (">")
  +--LayoutText #text "ab"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, WithOrderedList) {
  InsertStyleElement(
      "li { text-combine-upright: all; }"
      "ol { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<ol id=root><li>ab</li></ol>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow OL id="root"
  +--LayoutListItem LI
  |  +--LayoutOutsideListMarker ::marker
  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  +--LayoutTextFragment (anonymous) ("1. ")
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "ab"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

TEST_F(LayoutTextCombineTest, WithQuote) {
  InsertStyleElement(
      "q { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root><q>XY</q></div>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutInline Q
  |  +--LayoutInline ::before
  |  |  +--LayoutQuote (anonymous)
  |  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  |  +--LayoutTextFragment (anonymous) ("\u201C")
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  |  +--LayoutInline ::after
  |  |  +--LayoutQuote (anonymous)
  |  |  |  +--LayoutTextCombine (anonymous)
  |  |  |  |  +--LayoutTextFragment (anonymous) ("\u201D")
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1223423
TEST_F(LayoutTextCombineTest, WithTab) {
  InsertStyleElement(
      "c { text-combine-upright: all; white-space: pre; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>X\tY</c>de</div>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "X\tY"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// http://crbug.com/1242755
TEST_F(LayoutTextCombineTest, WithTextIndent) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 20px/30px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }"
      "#root { text-indent: 100px; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XYZ</c>de</div>");
  const auto& text_xyz = *To<Text>(GetElementById("combine")->firstChild());

  InlineCursor cursor;
  cursor.MoveTo(*text_xyz.GetLayoutObject());

  EXPECT_EQ(PhysicalRect(0, 0, 60, 20),
            cursor.Current().RectInContainerFragment());
}

TEST_F(LayoutTextCombineTest, WithWordBreak) {
  InsertStyleElement(
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>ab<c id=combine>XY<wbr>Z</c>de</div>");
  const auto& root_layout_object =
      *To<LayoutBlockFlow>(GetElementById("root")->GetLayoutObject());

  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root"
  +--LayoutText #text "ab"
  +--LayoutInline C id="combine"
  |  +--LayoutTextCombine (anonymous)
  |  |  +--LayoutText #text "XY"
  |  |  +--LayoutWordBreak WBR
  |  |  +--LayoutText #text "Z"
  +--LayoutText #text "de"
)DUMP",
            ToSimpleLayoutTree(root_layout_object));
}

// crbug.com/1430617
TEST_F(LayoutTextCombineTest, ShouldBeParentOfSvg) {
  SetBodyInnerHTML(R"HTML(
    <div id="root" style="text-combine-upright: all;">
    <svg>
    <text style="writing-mode: vertical-rl;">Text)HTML");

  // Should have no LayoutTextCombine.
  EXPECT_EQ(R"DUMP(
LayoutBlockFlow DIV id="root" style="text-combine-upright: all;"
  +--LayoutSVGRoot svg
  |  +--LayoutSVGText text style="writing-mode: vertical-rl;"
  |  |  +--LayoutSVGInlineText #text "Text"
)DUMP",
            ToSimpleLayoutTree(*GetLayoutObjectByElementId("root")));
}

TEST_F(LayoutTextCombineTest, InHorizontal) {
  InsertStyleElement(
      "div { writing-mode: horizontal-tb; }"
      "tcy { text-combine-upright: all; }");
  SetBodyInnerHTML("<div><tcy id=sample>ab</tcy></div>");
  const auto& sample_layout_object = *GetLayoutObjectByElementId("sample");

  EXPECT_EQ(R"DUMP(
LayoutInline TCY id="sample"
  +--LayoutText #text "ab"
)DUMP",
            ToSimpleLayoutTree(sample_layout_object));
}

TEST_F(LayoutTextCombineTest, InVertical) {
  InsertStyleElement(
      "div { writing-mode: vertical-rl; }"
      "tcy { text-combine-upright: all; }");
  SetBodyInnerHTML("<div><tcy id=sample>ab</tcy></div>");
  const auto& sample_layout_object = *GetLayoutObjectByElementId("sample");

  EXPECT_EQ(R"DUMP(
LayoutInline TCY id="sample"
  +--LayoutTextCombine (anonymous)
  |  +--LayoutText #text "ab"
)DUMP",
            ToSimpleLayoutTree(sample_layout_object));
}

}  // namespace blink
```