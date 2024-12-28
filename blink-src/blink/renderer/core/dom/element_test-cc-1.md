Response:
The user wants a summary of the provided C++ code snippet, which is the second part of a test file for `blink::Element`. I need to analyze the test cases and identify the main functionalities being tested.

The tests primarily focus on the `focusgroup` attribute and its related behaviors, and the creation and management of pseudo-elements.

**Plan:**
1. Summarize the functionality related to the `focusgroup` attribute.
2. Summarize the functionality related to pseudo-elements.
3. Explain the relation to JavaScript, HTML, and CSS.
4. Provide examples for each functionality, including potential user errors and debugging steps.
这是`blink/renderer/core/dom/element_test.cc`文件的第二部分，延续了第一部分的内容，主要功能是测试`blink::Element`类中关于焦点组（focusgroup）属性和伪元素（pseudo-element）的相关功能。

**主要功能归纳：**

1. **焦点组属性 (focusgroup attribute) 的解析和继承:**
    *   测试了 `focusgroup` 属性的不同取值（例如：`inline`, `block`, `wrap`, `extend`, `grid`, `row-wrap`, `col-wrap`, `row-flow`, `col-flow`）如何被解析并设置到元素的 `FocusgroupFlags` 中。
    *   验证了焦点组属性在 DOM 树中的继承规则，特别是 `extend` 关键字的作用，以及不同轴向（inline/block）的焦点组属性如何影响子元素。
    *   测试了当 DOM 结构发生变化（例如，移动节点）时，焦点组属性的重新计算和更新。
    *   测试了当节点被移除时，焦点组属性是否被正确清除。

2. **伪元素 (pseudo-element) 的创建和获取:**
    *   测试了 `GetPseudoElement()` 方法能否正确获取元素的 `::before`, `::after`, `::marker` 伪元素，这依赖于 CSS 样式计算。
    *   测试了 `CreateColumnPseudoElementIfNeeded()` 方法能否为元素创建 `::column` 伪元素，并验证了这些伪元素的样式属性（例如 `opacity`）是否正确设置。同时测试了 `::column::scroll-marker` 伪元素的创建。
    *   测试了特定伪元素（例如 `::check`, `::select-arrow`）是否只为特定类型的元素创建（例如，`::check` 针对 `option` 元素， `::select-arrow` 针对 `select` 元素）。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

*   **HTML:** `focusgroup` 属性直接在 HTML 元素上使用，用于定义焦点导航的行为。例如：
    ```html
    <div id="myFocusGroup" focusgroup="wrap">
      <button>Item 1</button>
      <button>Item 2</button>
    </div>
    ```
    这个例子中，`focusgroup="wrap"` 表示在这个 div 内的焦点导航到达最后一个元素后，会循环回到第一个元素。

*   **CSS:** CSS 用于定义伪元素的内容和样式。例如：
    ```css
    #myElement::before {
      content: "前缀";
      color: blue;
    }
    ```
    这段 CSS 会在 ID 为 `myElement` 的元素前插入内容 "前缀" 并设置为蓝色。测试代码中验证了当 CSS 规则存在时，`GetPseudoElement()` 可以正确获取到这些伪元素。

*   **JavaScript:** JavaScript 可以用来动态地修改元素的属性，包括 `focusgroup` 属性，以及检查元素是否拥有特定的伪元素。例如：
    ```javascript
    const element = document.getElementById('myElement');
    element.setAttribute('focusgroup', 'inline'); // 使用 JavaScript 修改 focusgroup 属性

    const beforePseudo = element.GetPseudoElement(kPseudoIdBefore); // JavaScript 中获取伪元素 (这里的 kPseudoIdBefore 是 C++ 中的常量，在 JavaScript 中不会直接使用)
    ```
    虽然 JavaScript 不能直接调用 `GetPseudoElement` (这是 Blink 内部的 C++ 方法)，但是 JavaScript 可以通过 `window.getComputedStyle(element, '::before')` 来获取伪元素的样式信息，从而间接验证伪元素的存在。

**逻辑推理、假设输入与输出:**

以下是一个基于代码片段中 `ParseFocusgroupAttrDoesntWrapInExtendingFocusgroupOnly` 测试的逻辑推理示例：

**假设输入:**  以下 HTML 结构被加载到浏览器中：

```html
<div id=fg1 focusgroup>
  <div id=fg2 focusgroup="extend inline wrap"></div>
</div>
```

**逻辑推理:**

1. `fg1` 元素设置了 `focusgroup` 属性，但没有指定具体的类型，默认会启用焦点组行为，但不会有 `wrap` 行为。
2. `fg2` 元素设置了 `focusgroup="extend inline wrap"`。
3. 由于 `fg2` 的 `focusgroup` 包含 `extend` 关键字，它会继承父元素 `fg1` 的焦点组行为。
4. `fg2` 明确指定了 `inline wrap`，因此在 inline 轴上会有 wrap 行为。

**预期输出:**

*   `fg1` 的 `FocusgroupFlags` 不包含 `kWrapInline` 和 `kWrapBlock`。
*   `fg2` 的 `FocusgroupFlags` 不包含 `kWrapInline` 和 `kWrapBlock`，因为 `extend` 会阻止 `wrap` 属性的继承。

**用户或编程常见的使用错误举例说明:**

1. **错误地期望 `extend` 会继承所有 `wrap` 属性:**  正如 `ParseFocusgroupAttrDoesntWrapInExtendingFocusgroupOnly` 测试所展示的，`extend` 只会继承焦点组的启用状态，而不会继承 `wrap` 属性，除非两个焦点组有共同的轴向。用户可能会错误地认为设置了 `extend` 后，子元素会自动拥有父元素的 `wrap` 行为，导致焦点导航不符合预期。

    **调试线索和用户操作:** 用户可能会发现在一个设置了 `focusgroup="wrap"` 的父元素中，设置了 `focusgroup="extend"` 的子元素并没有实现环绕焦点导航。用户可能会通过浏览器的开发者工具查看元素的属性，或者尝试用键盘导航来观察焦点行为。

2. **在不支持伪元素的元素上尝试使用伪元素选择器:** 例如，尝试为 `<div>` 元素创建 `::check` 伪元素样式。浏览器会忽略这些样式，因为 `::check` 仅适用于特定的表单元素。

    **调试线索和用户操作:** 用户可能会在 CSS 中定义了 `div::check { ... }` 样式，但发现这些样式没有任何效果。通过浏览器的开发者工具查看元素的样式时，会发现该伪元素选择器下的样式没有被应用。

**用户操作是如何一步步的到达这里，作为调试线索:**

以焦点组属性为例：

1. **用户在 HTML 中添加了 `focusgroup` 属性到某个或某些元素上。** 例如 `<div focusgroup="wrap">...</div>`。
2. **用户可能使用键盘（Tab 键）在页面元素之间导航。**
3. **如果焦点导航的行为不符合预期（例如，没有环绕，或者焦点跳跃不正确），用户可能会怀疑 `focusgroup` 属性的设置有问题。**
4. **用户可能会打开浏览器的开发者工具。**
5. **在 "Elements" 面板中，用户会选中设置了 `focusgroup` 属性的元素。**
6. **用户可能会查看 "Properties" 或 "Attributes" 面板，但通常 `FocusgroupFlags` 这样的内部状态不会直接显示在这里。**
7. **更高级的用户可能会查看 "Event Listeners" 面板，看看是否有与焦点相关的事件监听器。**
8. **如果用户是 Web 开发者，并且怀疑 Blink 引擎的实现有问题，他们可能会深入到 Blink 的源代码进行调试，这时就会涉及到 `element_test.cc` 这样的测试文件。**  开发者可能会尝试运行相关的测试用例，例如 `ParseFocusgroupAttrWrap` 或 `ParseFocusgroupAttrInheritance`，来验证焦点组的行为是否符合预期。
9. **在调试过程中，开发者可能会在 `Element::GetFocusgroupFlags()` 方法或者与焦点处理相关的代码中设置断点，来观察代码的执行流程和变量的值。**  `element_test.cc` 中的测试用例可以作为很好的起点，帮助开发者理解 `focusgroup` 属性的工作原理。

总之，`element_test.cc` 的这部分代码主要负责测试 `blink::Element` 类中关于焦点组属性的解析、继承和动态更新，以及各种伪元素的创建和管理机制，确保这些核心功能在不同的 HTML 和 CSS 场景下都能正常工作。这些测试对于保证 Chromium 浏览器的焦点管理和渲染功能的正确性至关重要。

Prompt: 
```
这是目录为blink/renderer/core/dom/element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
s, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg4_flags & FocusgroupFlags::kWrapInline);
  ASSERT_TRUE(fg4_flags & FocusgroupFlags::kWrapBlock);

  // 5. The ancestor focusgroup's wrap properties shouldn't be inherited since
  // the two focusgroups have no axis in common.
  auto* fg5 = document.getElementById(AtomicString("fg5"));
  ASSERT_TRUE(fg5);

  FocusgroupFlags fg5_flags = fg5->GetFocusgroupFlags();
  ASSERT_NE(fg5_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg5_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg5_flags & FocusgroupFlags::kWrapBlock);
}

TEST_F(ElementTest, ParseFocusgroupAttrDoesntWrapInExtendingFocusgroupOnly) {
  Document& document = GetDocument();
  SetBodyContent(R"HTML(
    <div id=fg1 focusgroup>
      <div id=fg2 focusgroup="extend inline wrap"></div>
      <div id=fg3 focusgroup="extend block wrap"></div>
      <div id=fg4 focusgroup="extend wrap"></div>
    </div>
    <div id=fg5 focusgroup=inline>
      <div id=fg6 focusgroup="extend inline wrap"></div>
      <div id=fg7 focusgroup="extend block wrap"></div>
      <div id=fg8 focusgroup="extend wrap"></div>
    </div>
    <div id=fg9 focusgroup=block>
      <div id=fg10 focusgroup="extend inline wrap"></div>
      <div id=fg11 focusgroup="extend block wrap"></div>
      <div id=fg12 focusgroup="extend wrap"></div>
    </div>
  )HTML");

  auto* fg1 = document.getElementById(AtomicString("fg1"));
  auto* fg2 = document.getElementById(AtomicString("fg2"));
  auto* fg3 = document.getElementById(AtomicString("fg3"));
  auto* fg4 = document.getElementById(AtomicString("fg4"));
  auto* fg5 = document.getElementById(AtomicString("fg5"));
  auto* fg6 = document.getElementById(AtomicString("fg6"));
  auto* fg7 = document.getElementById(AtomicString("fg7"));
  auto* fg8 = document.getElementById(AtomicString("fg8"));
  auto* fg9 = document.getElementById(AtomicString("fg9"));
  auto* fg10 = document.getElementById(AtomicString("fg10"));
  auto* fg11 = document.getElementById(AtomicString("fg11"));
  auto* fg12 = document.getElementById(AtomicString("fg12"));
  ASSERT_TRUE(fg1);
  ASSERT_TRUE(fg2);
  ASSERT_TRUE(fg3);
  ASSERT_TRUE(fg4);
  ASSERT_TRUE(fg5);
  ASSERT_TRUE(fg6);
  ASSERT_TRUE(fg7);
  ASSERT_TRUE(fg8);
  ASSERT_TRUE(fg9);
  ASSERT_TRUE(fg10);
  ASSERT_TRUE(fg11);
  ASSERT_TRUE(fg12);

  FocusgroupFlags fg1_flags = fg1->GetFocusgroupFlags();
  ASSERT_NE(fg1_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg1_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg1_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg2_flags = fg2->GetFocusgroupFlags();
  ASSERT_NE(fg2_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg2_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg2_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg3_flags = fg3->GetFocusgroupFlags();
  ASSERT_NE(fg3_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg3_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg3_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg4_flags = fg4->GetFocusgroupFlags();
  ASSERT_NE(fg4_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg4_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg4_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg5_flags = fg5->GetFocusgroupFlags();
  ASSERT_NE(fg5_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg5_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg5_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg6_flags = fg6->GetFocusgroupFlags();
  ASSERT_NE(fg6_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg6_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg6_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg7_flags = fg7->GetFocusgroupFlags();
  ASSERT_NE(fg7_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg7_flags & FocusgroupFlags::kWrapInline);
  ASSERT_TRUE(fg7_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg8_flags = fg8->GetFocusgroupFlags();
  ASSERT_NE(fg8_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg8_flags & FocusgroupFlags::kWrapInline);
  ASSERT_TRUE(fg8_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg9_flags = fg9->GetFocusgroupFlags();
  ASSERT_NE(fg9_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg9_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg9_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg10_flags = fg10->GetFocusgroupFlags();
  ASSERT_NE(fg10_flags, FocusgroupFlags::kNone);
  ASSERT_TRUE(fg10_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg10_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg11_flags = fg11->GetFocusgroupFlags();
  ASSERT_NE(fg11_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg11_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg11_flags & FocusgroupFlags::kWrapBlock);

  FocusgroupFlags fg12_flags = fg12->GetFocusgroupFlags();
  ASSERT_NE(fg12_flags, FocusgroupFlags::kNone);
  ASSERT_TRUE(fg12_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg12_flags & FocusgroupFlags::kWrapBlock);
}

TEST_F(ElementTest, ParseFocusgroupAttrGrid) {
  Document& document = GetDocument();
  SetBodyContent(R"HTML(
    <!-- Not an error, since an author might provide the table structure in CSS. -->
    <div id=e1 focusgroup=grid></div>
    <table id=e2 focusgroup=grid></table>
    <table id=e3 focusgroup="grid wrap"></table>
    <table id=e4 focusgroup="grid row-wrap"></table>
    <table id=e5 focusgroup="grid col-wrap"></table>
    <table id=e6 focusgroup="grid row-wrap col-wrap"></table>
    <table id=e7 focusgroup="grid flow"></table>
    <table id=e8 focusgroup="grid row-flow"></table>
    <table id=e9 focusgroup="grid col-flow"></table>
    <table id=e10 focusgroup="grid row-flow col-flow"></table>
    <table id=e11 focusgroup="grid row-wrap row-flow"></table>
    <table id=e12 focusgroup="grid row-wrap col-flow"></table>
    <table id=e13 focusgroup="grid col-wrap col-flow"></table>
    <table id=e14 focusgroup="grid col-wrap row-flow"></table>
    <table focusgroup=grid>
      <tbody id=e15 focusgroup=extend></tbody> <!-- Error -->
    </table>
    <div id=e16 focusgroup="flow"></div> <!-- Error -->
  )HTML");

  auto* e1 = document.getElementById(AtomicString("e1"));
  auto* e2 = document.getElementById(AtomicString("e2"));
  auto* e3 = document.getElementById(AtomicString("e3"));
  auto* e4 = document.getElementById(AtomicString("e4"));
  auto* e5 = document.getElementById(AtomicString("e5"));
  auto* e6 = document.getElementById(AtomicString("e6"));
  auto* e7 = document.getElementById(AtomicString("e7"));
  auto* e8 = document.getElementById(AtomicString("e8"));
  auto* e9 = document.getElementById(AtomicString("e9"));
  auto* e10 = document.getElementById(AtomicString("e10"));
  auto* e11 = document.getElementById(AtomicString("e11"));
  auto* e12 = document.getElementById(AtomicString("e12"));
  auto* e13 = document.getElementById(AtomicString("e13"));
  auto* e14 = document.getElementById(AtomicString("e14"));
  auto* e15 = document.getElementById(AtomicString("e15"));
  auto* e16 = document.getElementById(AtomicString("e16"));
  ASSERT_TRUE(e1);
  ASSERT_TRUE(e2);
  ASSERT_TRUE(e3);
  ASSERT_TRUE(e4);
  ASSERT_TRUE(e5);
  ASSERT_TRUE(e6);
  ASSERT_TRUE(e7);
  ASSERT_TRUE(e8);
  ASSERT_TRUE(e9);
  ASSERT_TRUE(e10);
  ASSERT_TRUE(e11);
  ASSERT_TRUE(e12);
  ASSERT_TRUE(e13);
  ASSERT_TRUE(e14);
  ASSERT_TRUE(e15);
  ASSERT_TRUE(e16);

  FocusgroupFlags e1_flags = e1->GetFocusgroupFlags();
  FocusgroupFlags e2_flags = e2->GetFocusgroupFlags();
  FocusgroupFlags e3_flags = e3->GetFocusgroupFlags();
  FocusgroupFlags e4_flags = e4->GetFocusgroupFlags();
  FocusgroupFlags e5_flags = e5->GetFocusgroupFlags();
  FocusgroupFlags e6_flags = e6->GetFocusgroupFlags();
  FocusgroupFlags e7_flags = e7->GetFocusgroupFlags();
  FocusgroupFlags e8_flags = e8->GetFocusgroupFlags();
  FocusgroupFlags e9_flags = e9->GetFocusgroupFlags();
  FocusgroupFlags e10_flags = e10->GetFocusgroupFlags();
  FocusgroupFlags e11_flags = e11->GetFocusgroupFlags();
  FocusgroupFlags e12_flags = e12->GetFocusgroupFlags();
  FocusgroupFlags e13_flags = e13->GetFocusgroupFlags();
  FocusgroupFlags e14_flags = e14->GetFocusgroupFlags();
  FocusgroupFlags e15_flags = e15->GetFocusgroupFlags();
  FocusgroupFlags e16_flags = e16->GetFocusgroupFlags();

  ASSERT_EQ(e1_flags, FocusgroupFlags::kGrid);
  ASSERT_EQ(e2_flags, FocusgroupFlags::kGrid);
  ASSERT_EQ(e3_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kWrapInline |
                       FocusgroupFlags::kWrapBlock));
  ASSERT_EQ(e4_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kWrapInline));
  ASSERT_EQ(e5_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kWrapBlock));
  ASSERT_EQ(e6_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kWrapInline |
                       FocusgroupFlags::kWrapBlock));
  ASSERT_EQ(e7_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kRowFlow |
                       FocusgroupFlags::kColFlow));
  ASSERT_EQ(e8_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kRowFlow));
  ASSERT_EQ(e9_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kColFlow));
  ASSERT_EQ(e10_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kRowFlow |
                        FocusgroupFlags::kColFlow));
  ASSERT_EQ(e11_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kWrapInline));
  ASSERT_EQ(e12_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kWrapInline |
                        FocusgroupFlags::kColFlow));
  ASSERT_EQ(e13_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kWrapBlock));
  ASSERT_EQ(e14_flags, (FocusgroupFlags::kGrid | FocusgroupFlags::kWrapBlock |
                        FocusgroupFlags::kRowFlow));
  ASSERT_EQ(e15_flags, FocusgroupFlags::kNone);
  ASSERT_EQ(e16_flags, (FocusgroupFlags::kInline | FocusgroupFlags::kBlock));
}

TEST_F(ElementTest, ParseFocusgroupAttrValueRecomputedAfterDOMStructureChange) {
  Document& document = GetDocument();
  SetBodyContent(R"HTML(
    <div id=fg1 focusgroup=wrap>
      <div id=fg2 focusgroup=extend>
          <div>
            <div id=fg3 focusgroup=extend></div>
          </div>
      </div>
    </div>
    <div id=not-fg></div>
  )HTML");

  // 1. Validate that the |fg2| and |fg3| focusgroup properties were set
  // correctly initially.
  auto* fg2 = document.getElementById(AtomicString("fg2"));
  ASSERT_TRUE(fg2);

  FocusgroupFlags fg2_flags = fg2->GetFocusgroupFlags();
  ASSERT_NE(fg2_flags, FocusgroupFlags::kNone);
  ASSERT_TRUE(fg2_flags & FocusgroupFlags::kExtend);
  ASSERT_TRUE(fg2_flags & FocusgroupFlags::kWrapInline);
  ASSERT_TRUE(fg2_flags & FocusgroupFlags::kWrapBlock);

  auto* fg3 = document.getElementById(AtomicString("fg3"));
  ASSERT_TRUE(fg3);

  FocusgroupFlags fg3_flags = fg3->GetFocusgroupFlags();
  ASSERT_NE(fg3_flags, FocusgroupFlags::kNone);
  ASSERT_TRUE(fg3_flags & FocusgroupFlags::kExtend);
  ASSERT_TRUE(fg3_flags & FocusgroupFlags::kWrapInline);
  ASSERT_TRUE(fg3_flags & FocusgroupFlags::kWrapBlock);

  // 2. Move |fg2| from |fg1| to |not-fg|.
  auto* not_fg = document.getElementById(AtomicString("not-fg"));
  ASSERT_TRUE(not_fg);

  not_fg->AppendChild(fg2);

  // 3. Validate that the focusgroup properties were updated correctly on |fg2|
  // and |fg3| after they moved to a different ancestor.
  fg2_flags = fg2->GetFocusgroupFlags();
  ASSERT_NE(fg2_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg2_flags & FocusgroupFlags::kExtend);
  ASSERT_FALSE(fg2_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg2_flags & FocusgroupFlags::kWrapBlock);

  fg3_flags = fg3->GetFocusgroupFlags();
  ASSERT_NE(fg3_flags, FocusgroupFlags::kNone);
  ASSERT_TRUE(fg3_flags & FocusgroupFlags::kExtend);
  ASSERT_FALSE(fg3_flags & FocusgroupFlags::kWrapInline);
  ASSERT_FALSE(fg3_flags & FocusgroupFlags::kWrapBlock);
}

TEST_F(ElementTest, ParseFocusgroupAttrValueClearedAfterNodeRemoved) {
  Document& document = GetDocument();
  SetBodyContent(R"HTML(
    <div id=fg1 focusgroup>
      <div id=fg2 focusgroup=extend></div>
    </div>
  )HTML");

  // 1. Validate that the |fg1| and |fg1| focusgroup properties were set
  // correctly initially.
  auto* fg1 = document.getElementById(AtomicString("fg1"));
  ASSERT_TRUE(fg1);

  FocusgroupFlags fg1_flags = fg1->GetFocusgroupFlags();
  ASSERT_NE(fg1_flags, FocusgroupFlags::kNone);
  ASSERT_FALSE(fg1_flags & FocusgroupFlags::kExtend);

  auto* fg2 = document.getElementById(AtomicString("fg2"));
  ASSERT_TRUE(fg2);

  FocusgroupFlags fg2_flags = fg2->GetFocusgroupFlags();
  ASSERT_NE(fg2_flags, FocusgroupFlags::kNone);
  ASSERT_TRUE(fg2_flags & FocusgroupFlags::kExtend);

  // 2. Remove |fg1| from the DOM.
  fg1->remove();

  // 3. Validate that the focusgroup properties were cleared from both
  // focusgroups.
  fg1_flags = fg1->GetFocusgroupFlags();
  ASSERT_EQ(fg1_flags, FocusgroupFlags::kNone);

  fg2_flags = fg2->GetFocusgroupFlags();
  ASSERT_EQ(fg2_flags, FocusgroupFlags::kNone);
}

TEST_F(ElementTest, MixStyleAttributeAndCSSOMChanges) {
  Document& document = GetDocument();
  SetBodyContent(R"HTML(
    <div id="elmt" style="color: green;"></div>
  )HTML");

  Element* elmt = document.getElementById(AtomicString("elmt"));
  elmt->style()->setProperty(GetDocument().GetExecutionContext(), "color",
                             "red", String(), ASSERT_NO_EXCEPTION);

  // Verify that setting the style attribute back to its initial value is not
  // mistakenly considered as a no-op attribute change and ignored. It would be
  // without proper synchronization of attributes.
  elmt->setAttribute(html_names::kStyleAttr, AtomicString("color: green;"));

  EXPECT_EQ(elmt->getAttribute(html_names::kStyleAttr), "color: green;");
  EXPECT_EQ(elmt->style()->getPropertyValue("color"), "green");
}

TEST_F(ElementTest, GetPseudoElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
    #before::before { content:"a"; }
    #after::after { content:"a"; }
    #marker1 { display: list-item; }
    #marker2 { display: flow-root list-item; }
    #marker3 { display: inline flow list-item; }
    #marker4 { display: inline flow-root list-item; }
    </style>
    <div id="before"></div>
    <div id="after">flow</div>
    <div id="marker1"></div>
    <div id="marker2"></div>
    <div id="marker3"></div>
    <div id="marker4"></div>
    )HTML");
  // GetPseudoElement() relies on style recalc.
  GetDocument().UpdateStyleAndLayoutTree();
  struct {
    const char* id_name;
    bool has_before;
    bool has_after;
    bool has_marker;
  } kExpectations[] = {
      {"before", true, false, false},  {"after", false, true, false},
      {"marker1", false, false, true}, {"marker2", false, false, true},
      {"marker3", false, false, true}, {"marker4", false, false, true},
  };
  for (const auto& e : kExpectations) {
    SCOPED_TRACE(e.id_name);
    Element* element = GetElementById(e.id_name);
    EXPECT_EQ(e.has_before, !!element->GetPseudoElement(kPseudoIdBefore));
    EXPECT_EQ(e.has_after, !!element->GetPseudoElement(kPseudoIdAfter));
    EXPECT_EQ(e.has_marker, !!element->GetPseudoElement(kPseudoIdMarker));
  }
}

TEST_F(ElementTest, ColumnPseudoElements) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style id="test-style">
    #test::column { content: "*"; opacity: 0.5; }
    #test::column::scroll-marker { content: "+"; opacity: 0.3; }
    </style>
    <div id="test"></div>
    )HTML");
  // GetPseudoElement() relies on style recalc.
  GetDocument().UpdateStyleAndLayoutTree();

  Element* element = GetElementById("test");

  PhysicalRect dummy_column_rect;
  PseudoElement* first_column_pseudo_element =
      element->CreateColumnPseudoElementIfNeeded(0u, dummy_column_rect);
  ASSERT_TRUE(first_column_pseudo_element);
  EXPECT_EQ(first_column_pseudo_element->GetComputedStyle()->Opacity(), 0.5f);
  ASSERT_TRUE(
      first_column_pseudo_element->GetPseudoElement(kPseudoIdScrollMarker));
  EXPECT_EQ(first_column_pseudo_element->GetPseudoElement(kPseudoIdScrollMarker)
                ->GetComputedStyle()
                ->Opacity(),
            0.3f);

  PseudoElement* second_column_pseudo_element =
      element->CreateColumnPseudoElementIfNeeded(1u, dummy_column_rect);
  ASSERT_TRUE(second_column_pseudo_element);
  EXPECT_EQ(second_column_pseudo_element->GetComputedStyle()->Opacity(), 0.5f);
  ASSERT_TRUE(
      second_column_pseudo_element->GetPseudoElement(kPseudoIdScrollMarker));
  EXPECT_EQ(
      second_column_pseudo_element->GetPseudoElement(kPseudoIdScrollMarker)
          ->GetComputedStyle()
          ->Opacity(),
      0.3f);

  PseudoElement* third_column_pseudo_element =
      element->CreateColumnPseudoElementIfNeeded(2u, dummy_column_rect);
  ASSERT_TRUE(third_column_pseudo_element);
  EXPECT_EQ(third_column_pseudo_element->GetComputedStyle()->Opacity(), 0.5f);
  ASSERT_TRUE(
      third_column_pseudo_element->GetPseudoElement(kPseudoIdScrollMarker));
  EXPECT_EQ(third_column_pseudo_element->GetPseudoElement(kPseudoIdScrollMarker)
                ->GetComputedStyle()
                ->Opacity(),
            0.3f);

  ASSERT_TRUE(element->GetColumnPseudoElements());
  EXPECT_EQ(element->GetColumnPseudoElements()->size(), 3u);

  Element* style = GetElementById("test-style");
  style->setInnerHTML("");
  GetDocument().UpdateStyleAndLayoutTree();

  EXPECT_EQ(element->GetColumnPseudoElements()->size(), 0u);
}

TEST_F(ElementTest, TheCheckPseudoElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #a-div::check {
        content: "*";
      }

      #target::check {
        content: "*";
      }
    </style>

    <div id="a-div"></div>

    <select id="target">
      <option id="target-option" value="the only option"></option>
    </select>
    )HTML");

  // GetPseudoElement() relies on style recalc.
  GetDocument().UpdateStyleAndLayoutTree();

  Element* div = GetElementById("a-div");
  EXPECT_EQ(nullptr, div->GetPseudoElement(kPseudoIdCheck));

  Element* target = GetElementById("target");
  EXPECT_EQ(nullptr, target->GetPseudoElement(kPseudoIdCheck));

  // The `::check` pseudo element should only be created for option elements.
  Element* target_option = GetElementById("target-option");
  EXPECT_NE(nullptr, target_option->GetPseudoElement(kPseudoIdCheck));
}

TEST_F(ElementTest, TheSelectArrowPseudoElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #a-div::select-arrow {
        content: "*";
      }

      #target::select-arrow {
        content: "*";
      }
    </style>

    <div id="a-div"></div>

    <select id="target">
      <option id="target-option" value="the only option"></option>
    </select>
    )HTML");

  // GetPseudoElement() relies on style recalc.
  GetDocument().UpdateStyleAndLayoutTree();

  Element* div = GetElementById("a-div");
  EXPECT_EQ(nullptr, div->GetPseudoElement(kPseudoIdSelectArrow));

  // The `::select-arrow` pseudo element should only be created for select
  // elements.
  Element* target = GetElementById("target");
  EXPECT_NE(nullptr, target->GetPseudoElement(kPseudoIdSelectArrow));

  Element* target_option = GetElementById("target-option");
  EXPECT_EQ(nullptr, target_option->GetPseudoElement(kPseudoIdSelectArrow));
}

}  // namespace blink

"""


```