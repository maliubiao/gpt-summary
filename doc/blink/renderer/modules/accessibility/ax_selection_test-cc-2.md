Response:
My thinking process to analyze the provided C++ code and fulfill the user's request involved several steps:

1. **Understand the Core Purpose:** I first scanned the file name (`ax_selection_test.cc`) and the test fixture name (`AccessibilitySelectionTest`). This immediately told me the file is about testing the accessibility selection functionality within the Chromium Blink engine. The `ax_` prefix likely refers to the Accessibility Tree.

2. **Identify Key Classes and Concepts:**  I looked for recurring types and methods. `AXSelection`, `AXPosition`, `AXObject`, `SelectionInDOMTree`, `TextControlElement`, `Element`, `Document` all appeared frequently. This indicated the code focuses on:
    * Representing and manipulating accessibility selections (`AXSelection`, `AXPosition`).
    * Interacting with accessibility objects in the tree (`AXObject`).
    * Relating accessibility selections to the DOM (`SelectionInDOMTree`, `Element`, `Document`).
    * Handling selections in text input fields (`TextControlElement`).

3. **Analyze Individual Test Cases:**  I then examined each `TEST_F` block to understand the specific scenario being tested. I looked for:
    * **Setup (`SetBodyInnerHTML`):** What HTML structure is being created for the test?  This is crucial for understanding the context.
    * **Actions:** What methods are being called on `AXSelection` or other accessibility-related objects?  Common actions include `Select()`, `IsValid()`, and building selections using `AXSelection::Builder`.
    * **Assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_NE`):** What conditions are being checked? These assertions define the expected behavior of the accessibility selection logic.

4. **Identify Connections to Web Technologies (HTML, CSS, JavaScript):**  As I analyzed the test cases, I noted how they relate to web technologies:
    * **HTML:** The `SetBodyInnerHTML` calls directly create HTML structures. The tests often target specific HTML elements like `textarea`, `div` with `contenteditable`, `p`, `select`, and elements within shadow DOM.
    * **CSS (indirectly):**  Styles are sometimes applied (`style="font-family: monospace; width: 15ch;"`, `style="max-width: 5px; overflow-wrap: normal;"`). While not directly testing CSS parsing, these styles influence layout and how text is rendered, which can impact accessibility.
    * **JavaScript (in one test):** The `InvalidSelectionOnAShadowRoot` test uses JavaScript to create a shadow DOM. This highlights the interaction between accessibility and dynamic DOM manipulation.

5. **Infer Functionality from Test Names and Assertions:** The test names often provide clear clues about the functionality being tested, like `SelectTextarea`, `SelectEachConsecutiveCharacterInTextarea`, `InvalidSelectionInTextarea`, `FromCurrentSelectionInContenteditableWithAffinity`. The assertions then confirm the expected behavior in these scenarios.

6. **Look for Logic and Edge Cases:** I paid attention to loops (`for` loops in the character selection tests), conditional checks (like checking for `nullptr`), and tests for invalid selections. This revealed how the code handles different selection ranges and potential errors.

7. **Consider User and Developer Implications:** I thought about how these tests relate to real-world usage:
    * **User actions:**  Selecting text in text fields, contenteditable areas. The "SelectEachConsecutiveCharacter" tests simulate fine-grained selection.
    * **Developer errors:**  Creating invalid selections (e.g., crossing shadow DOM boundaries).

8. **Trace User Steps (Debugging):**  For debugging scenarios, I considered how a user might reach a state that triggers these tests. Interacting with form fields, selecting text with the mouse or keyboard, and using assistive technologies could all lead to the accessibility selection code being invoked.

9. **Synthesize and Summarize:** Finally, I organized my observations into a coherent summary, addressing each point of the user's request:

    * **Functionality:**  Aimed at testing the `AXSelection` class, focusing on creating, manipulating, and validating accessibility selections.
    * **Relationship to Web Technologies:** Providing concrete examples of how the tests interact with HTML elements, how CSS (indirectly) influences the tests, and how JavaScript is used in one specific test case.
    * **Logic and Examples:**  Explaining the character selection logic with hypothetical inputs and outputs.
    * **User/Developer Errors:**  Illustrating the "invalid selection across shadow DOM" as a common mistake.
    * **User Operations (Debugging):** Describing the steps a user might take to reach the tested code.
    * **Overall Function:**  Providing a concise summary of the file's purpose within the larger accessibility framework.

By following these steps, I could systematically break down the C++ code, understand its purpose, and connect it to the broader context of web development and accessibility. The iterative process of examining test cases and relating them to core concepts was key to forming a comprehensive understanding.
Based on the provided C++ code snippet from `blink/renderer/modules/accessibility/ax_selection_test.cc`, here's a breakdown of its functionality, its relationship to web technologies, logical reasoning, potential errors, and user operation tracing:

**功能归纳 (Summary of Functionality):**

This code file (`ax_selection_test.cc`) contains unit tests for the `AXSelection` class within the Chromium Blink rendering engine. The primary goal of these tests is to ensure that accessibility selections are correctly created, manipulated, and validated in various scenarios. These scenarios involve different HTML structures, including:

* **Textareas:** Testing selection within form fields.
* **Contenteditable elements:** Testing selection in editable rich text areas.
* **Elements with specific ARIA roles:**  Testing how ARIA attributes influence accessibility selections.
* **Elements within Shadow DOM:** Testing selection across shadow boundaries.
* **General HTML elements:** Testing basic selection scenarios.

The tests verify that:

* **Selections can be created and applied:**  Using `AXSelection::Builder` to define the anchor and focus points of a selection.
* **Selections correctly update the DOM selection:**  When an accessibility selection is applied, the underlying DOM selection (the user-visible selection) is updated accordingly.
* **Selections handle different selection directions:**  Forward and backward selections are tested.
* **Invalid selections are detected:**  Selections that cross certain boundaries (like shadow DOM boundaries) are identified as invalid.
* **Selections respect accessibility tree structure:**  Selections are made based on the accessibility tree representation of the DOM, which might differ from the raw DOM structure (e.g., due to ARIA attributes).
* **Selections can be created from the current DOM selection:**  Testing the conversion from the browser's native selection to an `AXSelection` object.

**与 JavaScript, HTML, CSS 的关系 (Relationship to JavaScript, HTML, CSS):**

This C++ code directly interacts with the underlying representation of HTML elements and their accessibility properties, which are often manipulated by JavaScript and styled by CSS.

* **HTML:** The tests heavily rely on setting up specific HTML structures using `SetBodyInnerHTML()`. The structure of the HTML dictates how the accessibility tree is built and how selections behave. For example, tests examine selections within `<textarea>`, `<div>` with `contenteditable`, and elements with specific IDs.
    * **Example:** The test `SelectTextarea` creates a `<textarea>` element and verifies that setting an `AXSelection` within it updates the `selectionStart` and `selectionEnd` properties of the textarea.

* **JavaScript:** While this specific C++ file doesn't execute JavaScript directly, the functionality it tests is crucial for how JavaScript interacts with accessibility. JavaScript code might:
    * **Set or get the selection:** JavaScript can use the `window.getSelection()` API to access and manipulate the current selection. The tests in this file ensure that the accessibility representation of that selection is accurate.
    * **Modify the DOM:** JavaScript can dynamically add, remove, or modify HTML elements and their attributes, which will affect the accessibility tree and how selections are made. The `InvalidSelectionOnAShadowRoot` test explicitly uses JavaScript to create a shadow DOM.
    * **Handle user input:** JavaScript event listeners might react to selection changes.

* **CSS:** CSS styles can indirectly affect accessibility selections by influencing the layout and rendering of elements. While the tests don't directly test CSS parsing, the structure and content of the elements (which CSS styles) impact the text flow and how selections are logically made within the accessibility tree.
    * **Example:** The `SelectEachConsecutiveCharacterInContenteditable` test uses CSS (`style="max-width: 5px; overflow-wrap: normal;"`) to force text wrapping, which can influence how character-by-character selection behaves in the accessibility tree.

**逻辑推理 (Logical Reasoning):**

Many tests involve setting up a specific HTML structure and then creating an `AXSelection` with defined anchor and focus points. The tests then reason about:

* **Expected DOM selection:** Based on the `AXSelection`, what should the `selectionStart`, `selectionEnd`, and `selectionDirection` of a `<textarea>` or the selection within a `contenteditable` be?
    * **假设输入 (Hypothetical Input):** A `<textarea>` with the content "Hello World", and an `AXSelection` is created with an anchor at the beginning of "World" and a focus at the end of "Hello".
    * **输出 (Output):** The `selectionStart` of the textarea should be 6, the `selectionEnd` should be 5 (indicating a backward selection), and the `selectionDirection` should be "backward".

* **Validity of the `AXSelection`:**  Does the created `AXSelection` span across invalid boundaries (like shadow roots)?
    * **假设输入 (Hypothetical Input):** An `AXSelection` is created with the anchor in the light DOM and the focus inside a shadow DOM.
    * **输出 (Output):** The `ax_selection.IsValid()` method should return `false`.

* **Mapping between AX tree positions and DOM positions:** The tests verify the correct translation between positions within the accessibility tree and corresponding positions within the DOM tree. This is particularly relevant for `contenteditable` elements where whitespace might be handled differently in the accessibility tree.

**用户或编程常见的使用错误 (Common User or Programming Errors):**

* **Creating selections that cross shadow DOM boundaries:** Developers might unintentionally create selections that start in the main document and end within a shadow root, or vice-versa. The `InvalidSelectionOnAShadowRoot` test specifically checks for this. This can lead to unexpected behavior and inconsistencies.
    * **Example:** A user tries to programmatically select text that spans across the boundary of a custom HTML element using shadow DOM. This might fail or produce an unexpected selection range.

* **Assuming a direct one-to-one mapping between DOM positions and accessibility tree positions:**  Whitespace collapsing and other accessibility transformations can lead to differences. Developers need to be aware of these differences when working with accessibility APIs. The `SelectEachConsecutiveCharacterInContenteditable` test highlights this discrepancy.

* **Incorrectly setting anchor and focus positions:**  Providing invalid or out-of-bounds positions for the anchor and focus of an `AXSelection` can lead to errors or unexpected selection behavior.

**用户操作如何一步步的到达这里 (How User Operations Lead Here - Debugging Clues):**

This code is part of the browser's internal implementation, so users don't directly interact with these C++ classes. However, user actions in the browser trigger the code being tested here. Here's a breakdown of how a user's actions can lead to this code being executed:

1. **User Selects Text:** When a user selects text using their mouse or keyboard in a web page, the browser's rendering engine needs to represent this selection internally.

2. **DOM Selection Update:** The browser updates the DOM selection, which includes the anchor node, anchor offset, focus node, and focus offset.

3. **Accessibility Tree Update:** The accessibility tree, which provides an alternative representation of the DOM for assistive technologies, needs to be informed about the selection change.

4. **`AXSelection` Creation:**  The browser might create or update an `AXSelection` object based on the DOM selection. This involves determining the corresponding positions within the accessibility tree. The `AXSelection::FromCurrentSelection()` method tested here is part of this process.

5. **Applying Accessibility Selection:**  If an assistive technology or browser extension wants to programmatically set the selection, it might use accessibility APIs, potentially leading to the creation and application of an `AXSelection`.

6. **Testing and Development:** During the development of the Blink rendering engine, engineers write unit tests like the ones in this file to ensure the `AXSelection` class works correctly in various scenarios. When a bug related to text selection or accessibility arises, developers might investigate this code to understand how selections are being handled.

**Example User Action and Debugging Trace:**

1. **User Action:** A user selects the word "textarea" within the `<textarea>` element on a web page.
2. **DOM State:** The browser's DOM selection now has the start and end points corresponding to the selected word.
3. **Accessibility Code Path:** The browser's accessibility code might create an `AXSelection` object representing this selection.
4. **Potential Issue:** If the user reports that their screen reader isn't correctly announcing the selected text in the textarea, a developer might investigate the `AXSelection` logic for textareas in this test file (`AccessibilitySelectionTest::SelectTextarea`). They might run this test to see if the basic selection within a textarea is working as expected. If the test fails, it indicates a bug in the `AXSelection` implementation for textareas.

**这是第3部分，共3部分，请归纳一下它的功能 (Part 3 of 3 - Summary of its Functionality):**

As the final part of the analysis, this code file (`ax_selection_test.cc`) comprehensively tests the `AXSelection` class, ensuring its correctness and robustness in handling various selection scenarios across different HTML elements and accessibility contexts. It acts as a crucial validation point for the accessibility selection mechanism within the Blink rendering engine, directly impacting how assistive technologies interact with web content and how programmatic selection manipulation behaves. The tests cover basic selection within text fields and rich text areas, handling of ARIA attributes, and the crucial aspect of preventing invalid selections across shadow DOM boundaries. They also ensure that the accessibility representation of the selection aligns with the underlying DOM selection.

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_selection_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
de());
  EXPECT_EQ(GetElementById("after"),
            dom_selection.Focus().ComputeNodeAfterPosition());

  // The selection in the textarea field should remain unchanged because the
  // field is not focused.
  EXPECT_EQ(3u, ToTextControl(*textarea).selectionStart());
  EXPECT_EQ(10u, ToTextControl(*textarea).selectionEnd());
  EXPECT_EQ("backward", ToTextControl(*textarea).selectionDirection());
}

TEST_F(AccessibilitySelectionTest, SelectEachConsecutiveCharacterInTextarea) {
  SetBodyInnerHTML(R"HTML(
      <textarea id="textarea">
        Inside
        textarea
        field.
      </textarea>
      )HTML");

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));
  TextControlElement& text_control = ToTextControl(*textarea);
  ASSERT_LE(1u, text_control.Value().length());

  const AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());

  for (unsigned int i = 0; i < text_control.Value().length() - 1; ++i) {
    GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder
            .SetAnchor(AXPosition::CreatePositionInTextObject(*ax_textarea, i))
            .SetFocus(
                AXPosition::CreatePositionInTextObject(*ax_textarea, i + 1))
            .Build();

    testing::Message message;
    message << "While selecting forward character "
            << static_cast<char>(text_control.Value()[i]) << " at position "
            << i << " in textarea.";
    SCOPED_TRACE(message);
    EXPECT_TRUE(ax_selection.Select());

    EXPECT_EQ(i, text_control.selectionStart());
    EXPECT_EQ(i + 1, text_control.selectionEnd());
    EXPECT_EQ("forward", text_control.selectionDirection());
  }

  for (unsigned int i = text_control.Value().length(); i > 0; --i) {
    GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder
            .SetAnchor(AXPosition::CreatePositionInTextObject(*ax_textarea, i))
            .SetFocus(
                AXPosition::CreatePositionInTextObject(*ax_textarea, i - 1))
            .Build();

    testing::Message message;
    message << "While selecting backward character "
            << static_cast<char>(text_control.Value()[i]) << " at position "
            << i << " in textarea.";
    SCOPED_TRACE(message);
    EXPECT_TRUE(ax_selection.Select());

    EXPECT_EQ(i - 1, text_control.selectionStart());
    EXPECT_EQ(i, text_control.selectionEnd());
    EXPECT_EQ("backward", text_control.selectionDirection());
  }
}

TEST_F(AccessibilitySelectionTest, InvalidSelectionInTextarea) {
  SetBodyInnerHTML(R"HTML(
      <p id="before">Before textarea field.</p>
      <textarea id="textarea">
        Inside
        textarea
        field.
      </textarea>
      <p id="after">After textarea field.</p>
      )HTML");

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));
  ASSERT_TRUE(ToTextControl(*textarea).SetSelectionRange(
      3u, 10u, kSelectionHasBackwardDirection));

  const AXObject* ax_before = GetAXObjectByElementId("before");
  ASSERT_NE(nullptr, ax_before);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_before->RoleValue());
  const AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());
  const AXObject* ax_after = GetAXObjectByElementId("after");
  ASSERT_NE(nullptr, ax_after);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_after->RoleValue());

  {
    // Light tree only selection. Selects the whole of the textarea field.
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder.SetAnchor(AXPosition::CreatePositionBeforeObject(*ax_before))
            .SetFocus(AXPosition::CreatePositionAfterObject(*ax_textarea))
            .Build();
    ax_selection.Select();
  }

  // Invalid selection because it crosses a user agent shadow tree boundary.
  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(AXPosition::CreatePositionInTextObject(*ax_textarea, 0))
          .SetFocus(AXPosition::CreatePositionBeforeObject(*ax_after))
          .Build();

  EXPECT_FALSE(ax_selection.IsValid());

  // The selection in the light DOM should remain unchanged.
  const SelectionInDOMTree dom_selection = Selection().GetSelectionInDOMTree();
  EXPECT_EQ(GetDocument().body(), dom_selection.Anchor().AnchorNode());
  EXPECT_EQ(1, dom_selection.Anchor().OffsetInContainerNode());
  EXPECT_EQ(GetElementById("before"),
            dom_selection.Anchor().ComputeNodeAfterPosition());
  EXPECT_EQ(GetDocument().body(), dom_selection.Focus().AnchorNode());
  EXPECT_EQ(5, dom_selection.Focus().OffsetInContainerNode());
  EXPECT_EQ(GetElementById("after"),
            dom_selection.Focus().ComputeNodeAfterPosition());

  // The selection in the textarea field should remain unchanged because the
  // field is not focused.
  EXPECT_EQ(3u, ToTextControl(*textarea).selectionStart());
  EXPECT_EQ(10u, ToTextControl(*textarea).selectionEnd());
  EXPECT_EQ("backward", ToTextControl(*textarea).selectionDirection());
}

TEST_F(AccessibilitySelectionTest,
       FromCurrentSelectionInContenteditableWithAffinity) {
  SetBodyInnerHTML(R"HTML(
      <div role="textbox" contenteditable id="contenteditable"
          style="font-family: monospace; width: 15ch;">
        InsideContenteditableTextboxField.
      </div>
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  Element* const contenteditable =
      GetDocument().QuerySelector(AtomicString("div[role=textbox]"));
  ASSERT_NE(nullptr, contenteditable);

  // This test should only be testing accessibility code. Ordinarily we should
  // be setting up the test using Javascript in order to avoid depending on the
  // internal implementation of DOM selection. However, the only way I found to
  // get an upstream affinity is to send the "end" key which might be unreliable
  // on certain platforms, so we modify the selection using Blink internal
  // functions instead.
  contenteditable->Focus();
  Selection().Modify(SelectionModifyAlteration::kMove,
                     SelectionModifyDirection::kBackward,
                     TextGranularity::kDocumentBoundary, SetSelectionBy::kUser);
  Selection().Modify(SelectionModifyAlteration::kMove,
                     SelectionModifyDirection::kForward,
                     TextGranularity::kLineBoundary, SetSelectionBy::kUser);
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(TextAffinity::kUpstream,
            Selection().GetSelectionInDOMTree().Affinity());

  const AXObject* ax_contenteditable =
      GetAXObjectByElementId("contenteditable");
  ASSERT_NE(nullptr, ax_contenteditable);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_contenteditable->RoleValue());
  const AXObject* ax_text = ax_contenteditable->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text->RoleValue());

  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  const auto ax_selection = AXSelection::FromCurrentSelection(GetDocument());
  ASSERT_TRUE(ax_selection.IsValid());

  EXPECT_TRUE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_text, ax_selection.Anchor().ContainerObject());
  EXPECT_LE(15, ax_selection.Anchor().TextOffset());
  EXPECT_GT(static_cast<int>(ax_text->ComputedName().length()),
            ax_selection.Anchor().TextOffset());
  EXPECT_EQ(TextAffinity::kUpstream, ax_selection.Anchor().Affinity());
  EXPECT_TRUE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_text, ax_selection.Focus().ContainerObject());
  EXPECT_LE(15, ax_selection.Focus().TextOffset());
  EXPECT_GT(static_cast<int>(ax_text->ComputedName().length()),
            ax_selection.Focus().TextOffset());
  EXPECT_EQ(TextAffinity::kUpstream, ax_selection.Focus().Affinity());
}

TEST_F(AccessibilitySelectionTest,
       SelectEachConsecutiveCharacterInContenteditable) {
  // The text should wrap after each word.
  SetBodyInnerHTML(R"HTML(
      <div id="contenteditable" contenteditable role="textbox"
          style="max-width: 5px; overflow-wrap: normal;">
        This is a test.
      </div>
      )HTML");

  const Element* contenteditable =
      GetDocument().QuerySelector(AtomicString("div[contenteditable]"));
  ASSERT_NE(nullptr, contenteditable);
  const Node* text = contenteditable->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());

  const AXObject* ax_contenteditable =
      GetAXObjectByElementId("contenteditable");
  ASSERT_NE(nullptr, ax_contenteditable);
  ASSERT_EQ(1, ax_contenteditable->ChildCountIncludingIgnored());
  const AXObject* ax_static_text =
      ax_contenteditable->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());
  String computed_name = ax_static_text->ComputedName();
  ASSERT_LE(1u, computed_name.length());

  for (unsigned int i = 0; i < computed_name.length() - 1; ++i) {
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder
            .SetAnchor(
                AXPosition::CreatePositionInTextObject(*ax_static_text, i))
            .SetFocus(
                AXPosition::CreatePositionInTextObject(*ax_static_text, i + 1))
            .Build();

    testing::Message message;
    message << "While selecting forward character "
            << std::u16string(1, computed_name[i]) << " at position " << i
            << " in contenteditable.";
    SCOPED_TRACE(message);
    EXPECT_TRUE(ax_selection.Select());

    const SelectionInDOMTree dom_selection =
        Selection().GetSelectionInDOMTree();
    EXPECT_EQ(text, dom_selection.Anchor().AnchorNode());
    EXPECT_EQ(text, dom_selection.Focus().AnchorNode());
    // The discrepancy between DOM and AX text offsets is due to the fact that
    // there is some white space in the DOM that is compressed in the
    // accessibility tree.
    EXPECT_EQ(static_cast<int>(i + 9),
              dom_selection.Anchor().OffsetInContainerNode());
    EXPECT_EQ(static_cast<int>(i + 10),
              dom_selection.Focus().OffsetInContainerNode());
  }

  for (unsigned int i = computed_name.length(); i > 0; --i) {
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder
            .SetAnchor(
                AXPosition::CreatePositionInTextObject(*ax_static_text, i))
            .SetFocus(
                AXPosition::CreatePositionInTextObject(*ax_static_text, i - 1))
            .Build();

    testing::Message message;
    message << "While selecting backward character "
            << std::u16string(1, computed_name[i]) << " at position " << i
            << " in contenteditable.";
    SCOPED_TRACE(message);
    EXPECT_TRUE(ax_selection.Select());

    const SelectionInDOMTree dom_selection =
        Selection().GetSelectionInDOMTree();
    EXPECT_EQ(text, dom_selection.Anchor().AnchorNode());
    EXPECT_EQ(text, dom_selection.Focus().AnchorNode());
    // The discrepancy between DOM and AX text offsets is due to the fact that
    // there is some white space in the DOM that is compressed in the
    // accessibility tree.
    EXPECT_EQ(static_cast<int>(i + 9),
              dom_selection.Anchor().OffsetInContainerNode());
    EXPECT_EQ(static_cast<int>(i + 8),
              dom_selection.Focus().OffsetInContainerNode());
  }
}

TEST_F(AccessibilitySelectionTest, SelectionWithEqualBaseAndExtent) {
  SetBodyInnerHTML(R"HTML(
      <select id="sel"><option>1</option></select>
      )HTML");
  AXObject* ax_sel =
      GetAXObjectByElementId("sel")->FirstChildIncludingIgnored();
  AXPosition ax_position = AXPosition::CreatePositionBeforeObject(*ax_sel);
  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(ax_position).SetFocus(ax_position).Build();
}

TEST_F(AccessibilitySelectionTest, InvalidSelectionOnAShadowRoot) {
  GetPage().GetSettings().SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
		<div id="container">
		</div>
	)HTML");
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  script_element->setTextContent(R"SCRIPT(
      var container = document.getElementById("container");
			var shadow = container.attachShadow({mode: 'open'});
			var button = document.createElement("button");
			button.id = "button";
			shadow.appendChild(button);
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  Node* shadow_root = GetElementById("container")->GetShadowRoot();
  const Position base = Position::EditingPositionOf(shadow_root, 0);
  const Position extent = Position::EditingPositionOf(shadow_root, 1);

  const auto selection =
      SelectionInDOMTree::Builder().SetBaseAndExtent(base, extent).Build();
  EXPECT_FALSE(AXSelection::FromSelection(selection).IsValid());
}

//
// Declarative tests.
//

TEST_F(AccessibilitySelectionTest, ARIAHidden) {
  RunSelectionTest("aria-hidden");
}

TEST_F(AccessibilitySelectionTest, List) {
  RunSelectionTest("list");
}

TEST_F(AccessibilitySelectionTest, ParagraphPresentational) {
  // The focus of the selection is an "after children" position on a paragraph
  // with role="presentation" and in which the last child is an empty div. In
  // other words, both the paragraph and its last child are ignored in the
  // accessibility tree. In order to become valid, the focus should move to
  // before the next unignored child of the presentational paragraph's unignored
  // parent, which in this case is another paragraph that comes after the
  // presentational one.
  RunSelectionTest("paragraph-presentational");
}

TEST_F(AccessibilitySelectionTest, SVG) {
  RunSelectionTest("svg");
}

TEST_F(AccessibilitySelectionTest, Table) {
  RunSelectionTest("table");
}

}  // namespace test
}  // namespace blink
```