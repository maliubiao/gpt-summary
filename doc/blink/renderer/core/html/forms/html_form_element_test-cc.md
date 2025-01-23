Response:
My thought process for analyzing the `html_form_element_test.cc` file goes like this:

1. **Understand the Goal:** The primary goal of any `*_test.cc` file is to test the functionality of a corresponding source code file. In this case, it's testing `html_form_element.h` and potentially related implementations.

2. **Identify the Target Class:** The test class name `HTMLFormElementTest` immediately tells me the core focus is on the `HTMLFormElement` class in Blink.

3. **Look for Setup and Helper Functions:** The `SetUp()` method is crucial. It initializes the testing environment, setting the document's MIME type to "text/html". The helper functions `GetFormElement()` and `GetListedElement()` are for conveniently retrieving specific elements within the test setup. The `GetFormElement` function demonstrates handling of shadow DOM.

4. **Analyze Individual Test Cases (TEST_F macros):**  Each `TEST_F` block represents a specific scenario being tested. I'll go through each one, trying to understand what aspect of `HTMLFormElement`'s functionality it's verifying.

    * **`ListedElementsNestedForms`:** This clearly tests how `ListedElements()` behaves when forms are nested. The manual tree construction highlights that the HTML parser's behavior of removing nested forms needs a manual workaround for testing this specific scenario. The assertion checks that the outer form has no listed elements and the inner form has the input element.

    * **`ListedElementsDetachedForm`:**  This checks if `ListedElements()` correctly identifies elements even after the form is detached from the DOM. This is important for ensuring the internal list of elements is maintained correctly.

    * **`ListedElementsIncludeShadowTrees`:** This is a big one. It meticulously tests the behavior of `ListedElements()` when dealing with Shadow DOM. The code constructs a complex nested structure with shadow roots and moves an input element around, verifying that `ListedElements()` (without `include_shadow_trees=true`) doesn't include elements within shadow trees, while subsequent tests with `include_shadow_trees=true` (in later tests) *do*.

    * **`ListedElementsAfterIncludeShadowTrees`:**  This confirms that `ListedElements(true)` correctly finds elements within shadow DOM after the elements are parsed from HTML. It contrasts this with the default behavior of `ListedElements()`.

    * **`ListedElementsIncludesOnlyDescendants`:** This is a crucial test for preventing over-collection of form elements. It ensures that elements in *separate* shadow trees are not incorrectly included in a form's listed elements, even if they have a `form` attribute pointing to that form.

    * **`ListedElementsInNestedForms`:** This focuses on the interaction between nested forms and the `form` attribute for associating elements. It confirms that elements within nested shadow DOM and elements explicitly associated with the nested form are included when `include_shadow_trees=true`.

    * **`ListedElementsInDeepNestedForms`:** This tests the cache invalidation mechanism for `ListedElements()` when elements are added or removed within deeply nested shadow DOM structures. This is about performance and correctness – ensuring the cached list updates when the DOM changes.

    * **`ListedElementsInDeepNestedFormsLightDom`:** Similar to the previous test, but focuses on nested forms within the regular (light) DOM, again checking cache invalidation.

    * **`ShadowDomTreesMustBeDescendantsOfForm`:** Reinforces that only shadow trees that are *descendants* of the form are considered when listing elements, preventing accidental inclusion of elements in unrelated shadow trees.

    * **`FormInsertionsInvalidateFormCaches` and `FormRemovalsInvalidateFormCaches`:** These tests specifically focus on the cache invalidation when forms themselves are dynamically added or removed. This is critical for maintaining an accurate `ListedElements()` result.

    * **`ElementsAssociateWithNestedForms`:** This confirms that elements outside a form can be associated with a nested form using the `form` attribute and that these associations are respected when `include_shadow_trees=true`.

    * **`NestedFormsAssociatedByParserMalformedHtml` and `NestedFormsAssociatedByParserMalformedHtml_Large` (SimTest):** These tests use `SimTest` to load and parse HTML, including *malformed* HTML. This is important for testing how Blink handles unusual or incorrect HTML structures, particularly how the parser establishes form associations in such cases. The focus is on verifying that `ListedElements(true)` correctly identifies elements associated with nested forms even when the HTML is malformed.

5. **Identify Relationships to Web Technologies:**

    * **HTML:** The tests directly manipulate HTML form elements, input elements, and the `form` attribute. The use of `setHTMLUnsafe` and the SimTest loading of HTML clearly demonstrate the connection to HTML structure.
    * **JavaScript:** While this is a C++ test file, the underlying functionality of `HTMLFormElement` is heavily used by JavaScript. JavaScript can access form elements, submit forms, and interact with form controls. The correct behavior tested here ensures that JavaScript interactions with forms work as expected.
    * **CSS:** While not directly tested in this file, the *rendering* of form elements is influenced by CSS. The correct functionality of the underlying `HTMLFormElement` is a prerequisite for CSS styling to work correctly. The tests implicitly ensure that the core logic is sound before CSS comes into play.
    * **Shadow DOM:** A significant portion of the tests deal with Shadow DOM, verifying that `HTMLFormElement` correctly handles form controls within shadow trees.

6. **Infer Logic and Assumptions:** The tests often make assumptions about how the HTML parser works (especially in the malformed HTML cases). The logic revolves around traversing the DOM tree to find form controls that belong to a specific form. The `include_shadow_trees` flag adds complexity to this traversal.

7. **Identify Potential User/Programming Errors:** The tests implicitly highlight common errors:

    * **Incorrectly assuming nested forms behave like independent forms in all contexts.** The tests show that by default, nested forms don't contribute to the parent form's listed elements.
    * **Forgetting to consider Shadow DOM when working with form controls.** If a developer isn't aware of Shadow DOM, they might be surprised that elements inside shadow trees aren't automatically included in a form's elements.
    * **Malformed HTML can lead to unexpected form associations.** The SimTest cases demonstrate this, showing how parser behavior can result in elements being associated with different forms than intended.

8. **Trace User Actions:** While the tests are programmatic, we can infer user actions that lead to the code being executed:

    * **A user loads a web page containing HTML forms.**
    * **The HTML parser processes the HTML, creating `HTMLFormElement` objects.**
    * **JavaScript code might interact with the form, accessing its elements.**
    * **The user might submit the form.**  (Though submission logic isn't directly tested here, the foundation for it is being verified).
    * **Dynamic changes to the DOM (via JavaScript) might add or remove form elements or even entire forms.**

By following these steps, I can systematically analyze the test file and extract the required information about its functionality, relationships to web technologies, logic, potential errors, and user actions.
这个文件 `html_form_element_test.cc` 是 Chromium Blink 引擎中用于测试 `blink/renderer/core/html/forms/html_form_element.h` 中定义的 `HTMLFormElement` 类的功能的单元测试文件。

以下是它的主要功能以及与 Javascript, HTML, CSS 的关系、逻辑推理、用户错误和用户操作路径的说明：

**功能列表:**

1. **测试 `HTMLFormElement` 的 `ListedElements()` 方法:**  该方法用于返回表单中所有可列出的表单控件元素（例如 `<input>`, `<select>`, `<textarea>`, `<button>` 等）。测试会验证在各种场景下，该方法是否返回了正确的元素列表。
2. **测试嵌套表单的处理:**  HTML 规范不允许嵌套的 `<form>` 元素。测试会验证 Blink 在遇到嵌套表单时的行为，以及 `ListedElements()` 如何处理这种情况。
3. **测试包含 Shadow DOM 的表单元素的处理:** 测试验证当表单控件存在于 Shadow DOM 中时，`ListedElements()` 方法是否能正确地包含或排除这些元素，取决于是否设置了 `include_shadow_trees` 参数。
4. **测试动态添加和删除表单元素对 `ListedElements()` 结果的影响:** 测试验证当通过 JavaScript 动态地向表单中添加或删除表单控件元素时，`ListedElements()` 方法返回的结果是否会相应更新。
5. **测试通过 `form` 属性关联的表单控件的处理:**  HTML 允许表单控件通过 `form` 属性与不在其父表单内的表单关联。测试验证 `ListedElements()` 方法是否能正确处理这种关联。
6. **测试在解析畸形 HTML 时表单控件的关联:** 测试使用 `SimTest` 来加载包含不规范 HTML 的页面，并验证 Blink 的 HTML 解析器如何处理嵌套表单以及表单控件的关联，并确保 `ListedElements()` 能正确反映这种关联。
7. **测试表单的插入和移除对 `ListedElements()` 缓存的影响:** 测试验证动态插入或移除嵌套表单时，父表单的 `ListedElements()` 结果是否会正确地失效和更新。

**与 Javascript, HTML, CSS 的关系:**

* **HTML:**  这个测试文件直接测试了与 HTML `<form>` 元素相关的核心逻辑。它验证了如何识别表单内的各种 HTML 表单控件元素，以及如何处理嵌套表单和通过 `form` 属性关联的元素。例如，测试用例中会创建 `<form>` 和 `<input>` 等 HTML 元素，并断言 `ListedElements()` 是否返回了预期的 `<input>` 元素。

    ```c++
    // 例子：创建 HTMLFormElement 和 HTMLInputElement
    HTMLFormElement* form = MakeGarbageCollected<HTMLFormElement>(GetDocument());
    HTMLInputElement* input = MakeGarbageCollected<HTMLInputElement>(GetDocument());
    form->AppendChild(input);
    ```

* **Javascript:** 虽然这个测试文件是 C++ 代码，但它测试的 `HTMLFormElement` 的功能是 JavaScript 可以直接访问和操作的。JavaScript 可以通过 DOM API 获取表单元素，访问其控件，以及监听表单事件。例如，JavaScript 代码可以使用 `document.getElementById()` 获取表单，然后访问其 `elements` 属性（对应于 `ListedElements()` 的行为）。这个测试确保了 Blink 引擎提供的这些 JavaScript API 的底层实现是正确的。

    * **假设输入 (HTML):**
      ```html
      <form id="myForm">
        <input type="text" name="username">
      </form>
      <script>
        const form = document.getElementById('myForm');
        console.log(form.elements.length); // 输出应该为 1
      </script>
      ```
    * **输出 (JavaScript 行为):**  JavaScript 代码会获取表单，并且 `form.elements.length` 会返回 1，因为表单内有一个输入元素。这个测试文件中的 `ListedElements()` 方法就是验证了 Blink 引擎在底层是否正确地识别并返回了这个输入元素。

* **CSS:**  虽然 CSS 主要负责样式控制，与表单元素的逻辑功能关联较少，但 CSS 选择器可以根据表单元素的状态或属性来应用样式。例如，可以使用 CSS 选择器来针对表单中被禁用的输入框进行样式设置。 这个测试文件保证了表单元素的基本结构和属性是正确的，这为 CSS 的正确应用奠定了基础。

**逻辑推理与假设输入输出:**

* **假设输入 (C++ 测试代码):** 创建一个包含嵌套表单和输入元素的 DOM 树：
    ```c++
    HTMLBodyElement* body = GetDocument().FirstBodyElement();
    HTMLFormElement* form1 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
    body->AppendChild(form1);
    HTMLFormElement* form2 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
    form1->AppendChild(form2);
    HTMLInputElement* input = MakeGarbageCollected<HTMLInputElement>(GetDocument());
    form2->AppendChild(input);
    ```
* **输出 (测试断言):**  断言 `form1->ListedElements()` 返回一个空列表，而 `form2->ListedElements()` 返回包含 `input` 元素的列表。
    ```c++
    EXPECT_EQ(form1elements.size(), 0u);
    ASSERT_EQ(form2elements.size(), 1u);
    EXPECT_EQ(form2elements.at(0)->ToHTMLElement(), input);
    ```
* **逻辑推理:**  HTML 规范通常不允许嵌套表单，并且 `ListedElements()` 默认只考虑直接子代的表单控件。因此，外部表单 `form1` 不会包含内部表单 `form2` 的控件。

**用户或编程常见的使用错误:**

1. **误以为嵌套表单会合并其控件列表:**  开发者可能会错误地认为，访问父表单的控件列表会包含嵌套子表单的控件。测试用例 `ListedElementsNestedForms` 明确地测试了这种情况，指出父表单的 `ListedElements()` 不会包含子表单的控件。
2. **忽略 Shadow DOM 中的表单控件:**  在使用 Web Components 和 Shadow DOM 时，开发者可能会忘记 `ListedElements()` 默认情况下不包含 Shadow DOM 内部的表单控件。测试用例 `ListedElementsIncludeShadowTrees` 强调了这一点，并展示了如何使用 `include_shadow_trees=true` 来包含这些元素。
3. **动态修改 DOM 后未考虑到表单控件列表的更新:**  当通过 JavaScript 动态地添加或删除表单控件时，开发者需要意识到表单的控件列表也会随之改变。测试用例如 `ListedElementsInDeepNestedForms` 验证了 Blink 引擎在这种情况下是否正确更新了内部的控件列表。
4. **错误地假设通过 `form` 属性关联的元素必须是表单的直接子元素:**  HTML 允许通过 `form` 属性将元素关联到任何同一文档中的表单。测试用例 `ElementsAssociateWithNestedForms` 验证了 `ListedElements()` 能正确识别这种关联，即使关联的元素不在表单的直接子树中。

**用户操作到达此处的步骤:**

虽然开发者通常不会直接与这个 C++ 测试文件交互，但可以推断出用户操作最终会触发相关代码的执行：

1. **用户在浏览器中加载一个包含 HTML 表单的网页。**
2. **Blink 引擎的 HTML 解析器会解析 HTML 代码，创建 `HTMLFormElement` 和其他相关的 DOM 元素。**  在解析过程中，会处理嵌套表单和通过 `form` 属性关联的元素，这些逻辑正是 `html_form_element_test.cc` 所测试的关键点。
3. **用户的 JavaScript 代码可能会与表单进行交互，例如访问表单的 `elements` 属性，尝试提交表单，或者动态地添加/删除表单控件。** 这些 JavaScript 操作最终会调用 Blink 引擎中 `HTMLFormElement` 类的相关方法，例如 `ListedElements()`。
4. **开发者在开发或调试 Chromium 浏览器引擎时，会运行这些单元测试来确保 `HTMLFormElement` 的功能符合预期。**  这些测试覆盖了各种边缘情况和潜在的错误场景，帮助开发者尽早发现和修复 bug。

总而言之，`html_form_element_test.cc` 是一个至关重要的测试文件，用于确保 Blink 引擎中 `HTMLFormElement` 类的核心功能（特别是关于表单控件列表的管理）的正确性和健壮性。它直接关联到 HTML 表单的结构和行为，并间接影响到 JavaScript 与表单的交互以及 CSS 样式的应用。

### 提示词
```
这是目录为blink/renderer/core/html/forms/html_form_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/forms/html_form_element.h"

#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/googletest/src/googlemock/include/gmock/gmock-matchers.h"

namespace blink {

using ::testing::ElementsAre;
using ::testing::IsEmpty;

class HTMLFormElementTest : public PageTestBase {
 protected:
  void SetUp() override;

  HTMLFormElement* GetFormElement(const char* id,
                                  ShadowRoot* shadow_root = nullptr) {
    return DynamicTo<HTMLFormElement>(
        shadow_root ? shadow_root->getElementById(AtomicString(id))
                    : GetElementById(id));
  }

  ListedElement* GetListedElement(const char* id,
                                  ShadowRoot* shadow_root = nullptr) {
    if (Element* element = shadow_root
                               ? shadow_root->getElementById(AtomicString(id))
                               : GetElementById(id)) {
      return ListedElement::From(*element);
    }
    return nullptr;
  }
};

void HTMLFormElementTest::SetUp() {
  PageTestBase::SetUp();
  GetDocument().SetMimeType(AtomicString("text/html"));
}

// This tree is created manually because the HTML parser removes nested forms.
// The created tree looks like this:
// <body>
//   <form id=form1>
//     <form id=form2>
//       <input>
TEST_F(HTMLFormElementTest, ListedElementsNestedForms) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();

  HTMLFormElement* form1 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  body->AppendChild(form1);

  HTMLFormElement* form2 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  form1->AppendChild(form2);

  HTMLInputElement* input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());
  form2->AppendChild(input);

  ListedElement::List form1elements = form1->ListedElements();
  ListedElement::List form2elements = form2->ListedElements();
  EXPECT_EQ(form1elements.size(), 0u);
  ASSERT_EQ(form2elements.size(), 1u);
  EXPECT_EQ(form2elements.at(0)->ToHTMLElement(), input);
}

TEST_F(HTMLFormElementTest, ListedElementsDetachedForm) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();

  HTMLFormElement* form = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  body->AppendChild(form);

  HTMLInputElement* input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());
  form->AppendChild(input);

  ListedElement::List listed_elements = form->ListedElements();
  ASSERT_EQ(listed_elements.size(), 1u);
  EXPECT_EQ(listed_elements.at(0)->ToHTMLElement(), input);

  form->remove();
  listed_elements = form->ListedElements();
  ASSERT_EQ(listed_elements.size(), 1u);
  EXPECT_EQ(listed_elements.at(0)->ToHTMLElement(), input);
}

// This tree is created manually because the HTML parser removes nested forms.
// The created tree looks like this:
// <body>
//   <form id=form1>
//     <div id=form1div>
//       <template shadowrootmode=open>
//         <form id=form2>
//           <form id=form3>
//             <div id=form3div>
//               <template shadowrootmode=open>
//
// An <input> element is appended at the bottom and moved up one node at a time
// in this tree, and each step of the way, ListedElements is checked on all
// forms.
TEST_F(HTMLFormElementTest, ListedElementsIncludeShadowTrees) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();

  HTMLFormElement* form1 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  body->AppendChild(form1);

  HTMLDivElement* form1div =
      MakeGarbageCollected<HTMLDivElement>(GetDocument());
  form1->AppendChild(form1div);
  ShadowRoot& form1root =
      form1div->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  HTMLFormElement* form2 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  form1root.AppendChild(form2);

  HTMLFormElement* form3 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  form2->AppendChild(form3);

  HTMLDivElement* form3div =
      MakeGarbageCollected<HTMLDivElement>(GetDocument());
  form3->AppendChild(form3div);
  ShadowRoot& form3root =
      form3div->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  HTMLInputElement* input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());

  form3root.AppendChild(input);
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  input->remove();
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  form3div->AppendChild(input);
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{input});

  form3->AppendChild(input);
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{input});

  input->remove();
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  form2->AppendChild(input);
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{input});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  input->remove();
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  form1root.AppendChild(input);
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  input->remove();
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  form1div->AppendChild(input);
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{input});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  form1->AppendChild(input);
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{input});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});

  input->remove();
  EXPECT_EQ(form1->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form2->ListedElements(), ListedElement::List{});
  EXPECT_EQ(form3->ListedElements(), ListedElement::List{});
}

TEST_F(HTMLFormElementTest, ListedElementsAfterIncludeShadowTrees) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  body->setHTMLUnsafe(R"HTML(
    <form id=form1>
      <input id=input1>
      <div id=div1>
        <template shadowrootmode=open>
          <input id=input2>
        </template>
      </div>
    </form>
  )HTML");

  HTMLFormElement* form1 = GetFormElement("form1");
  ASSERT_NE(form1, nullptr);
  EXPECT_THAT(
      form1->ListedElements(/*include_shadow_trees=*/true),
      ElementsAre(
          GetListedElement("input1"),
          GetListedElement("input2", GetElementById("div1")->GetShadowRoot())));
  EXPECT_THAT(form1->ListedElements(), ElementsAre(GetListedElement("input1")));
}

// Regression test for crbug.com/349121116: If there are no "form" attributes,
// the traversal in CollectListedElements() must only collect descendants of the
// form element.
TEST_F(HTMLFormElementTest, ListedElementsIncludesOnlyDescendants) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  body->setHTMLUnsafe(R"HTML(
    <form id=form1>
      <div id=div1>
        <template shadowrootmode=open>
          <input id=input1>
        </template>
      </div>
    </form>
    <div id=div2>
      <template shadowrootmode=open>
        <input id=input2>
      </template>
    </div>
  )HTML");

  HTMLFormElement* form1 = GetFormElement("form1");
  ASSERT_NE(form1, nullptr);
  EXPECT_THAT(form1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(GetListedElement(
                  "input1", GetElementById("div1")->GetShadowRoot())));
}

// Tests that form control elements inside nested forms are extracted and
// included in `ListedElements` if `include_shadow_trees` is true.
TEST_F(HTMLFormElementTest, ListedElementsInNestedForms) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  body->setHTMLUnsafe(R"HTML(
    <form id=f1>
      <div id=shadowhost>
        <template shadowrootmode=open>
          <input id=i1>
          <form id=f2>
            <input id=i2>
          </form>
          <input id=i3 form=f2>
        </template>
      </div>
    </form>
  )HTML");

  ShadowRoot* shadow_root = GetElementById("shadowhost")->GetShadowRoot();
  ASSERT_NE(shadow_root, nullptr);
  HTMLFormElement* f1 = GetFormElement("f1");
  ASSERT_NE(f1, nullptr);

  EXPECT_THAT(f1->ListedElements(), IsEmpty());
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(GetListedElement("i1", shadow_root),
                          GetListedElement("i2", shadow_root),
                          GetListedElement("i3", shadow_root)));
}

// Tests that dynamic addition and removal of an element inside Shadow DOM
// properly invalidates the caches of all ancestors.
TEST_F(HTMLFormElementTest, ListedElementsInDeepNestedForms) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  body->setHTMLUnsafe(R"HTML(
    <form id=f1>
      <div id=shadowhost1>
        <template shadowrootmode=open>
          <form id=f2>
            <input id=i1>
            <div id=shadowhost2>
              <template shadowrootmode=open>
                <div id=d1>
                  <input id=i2>
                </div>
              </template>
            </div>
          </form>
        </template>
      </div>
    </form>
  )HTML");

  ShadowRoot* shadow_root1 = GetElementById("shadowhost1")->GetShadowRoot();
  ASSERT_NE(shadow_root1, nullptr);
  ShadowRoot* shadow_root2 =
      shadow_root1->getElementById(AtomicString("shadowhost2"))
          ->GetShadowRoot();
  ASSERT_NE(shadow_root2, nullptr);
  HTMLFormElement* f1 = GetFormElement("f1");
  HTMLFormElement* f2 = GetFormElement("f2", shadow_root1);
  ListedElement* i1 = GetListedElement("i1", shadow_root1);
  ListedElement* i2 = GetListedElement("i2", shadow_root2);
  ASSERT_NE(f1, nullptr);
  ASSERT_NE(f2, nullptr);
  Element* d1 = shadow_root2->getElementById(AtomicString("d1"));
  ASSERT_NE(d1, nullptr);

  EXPECT_THAT(f1->ListedElements(), IsEmpty());
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(i1, i2));

  // Test that cache invalidation happens for all ancestor forms when an input
  // field is added and removed.
  HTMLInputElement* input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());
  d1->AppendChild(input);
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(i1, i2, input));
  input->remove();
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(i1, i2));

  // Test that that is also true for adding and removing forms.
  HTMLFormElement* f3 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  f3->AppendChild(input);
  d1->AppendChild(f3);
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(i1, i2, input));
  f3->remove();
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(i1, i2));
}

// Tests that changes inside nested forms inside light DOM properly invalidate
// the cache for listed elements.
TEST_F(HTMLFormElementTest, ListedElementsInDeepNestedFormsLightDom) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  HTMLFormElement* f1 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  body->AppendChild(f1);
  HTMLFormElement* f2 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  f1->AppendChild(f2);
  HTMLFormElement* f3 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  f2->AppendChild(f3);
  HTMLInputElement* input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());

  // Prior to attaching `input`, no form has a listed element.
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true), IsEmpty());
  EXPECT_THAT(f2->ListedElements(/*include_shadow_trees=*/true), IsEmpty());
  EXPECT_THAT(f3->ListedElements(/*include_shadow_trees=*/true), IsEmpty());

  // If input is attached to a form, all parent forms should also have this
  // element.
  f1->AppendChild(input);
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(input));
  EXPECT_THAT(f2->ListedElements(/*include_shadow_trees=*/true), IsEmpty());
  EXPECT_THAT(f3->ListedElements(/*include_shadow_trees=*/true), IsEmpty());

  input->remove();
  f2->AppendChild(input);
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(input));
  EXPECT_THAT(f2->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(input));
  EXPECT_THAT(f3->ListedElements(/*include_shadow_trees=*/true), IsEmpty());

  input->remove();
  f3->AppendChild(input);
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(input));
  EXPECT_THAT(f2->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(input));
  EXPECT_THAT(f3->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(input));
}

// Tests that the listed elements of a form `f` only include elements inside
// shadow DOM whose shadow hosts are descendants of `f`.
TEST_F(HTMLFormElementTest, ShadowDomTreesMustBeDescendantsOfForm) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  body->setHTMLUnsafe(R"HTML(
    <form id=f1>
      <input id=i1>
    </form>
    <input id=i2 form=f1>
    <div id=shadowhost>
        <template shadowrootmode=open>
          <input id=i3>
        </template>
    </div>
  )HTML");

  HTMLFormElement* f1 = GetFormElement("f1");
  ASSERT_NE(f1, nullptr);

  EXPECT_THAT(f1->ListedElements(),
              ElementsAre(GetListedElement("i1"), GetListedElement("i2")));
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(GetListedElement("i1"), GetListedElement("i2")));
}

// Tests that dynamic nested form insertions properly invalidate the cache of
// listed elements.
TEST_F(HTMLFormElementTest, FormInsertionsInvalidateFormCaches) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  HTMLFormElement* f1 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  body->AppendChild(f1);
  EXPECT_THAT(f1->ListedElements(), IsEmpty());
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true), IsEmpty());

  HTMLFormElement* f2 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  f1->AppendChild(f2);
  EXPECT_THAT(f1->ListedElements(), IsEmpty());
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true), IsEmpty());
  EXPECT_THAT(f2->ListedElements(), IsEmpty());
  EXPECT_THAT(f2->ListedElements(/*include_shadow_trees=*/true), IsEmpty());

  HTMLFormElement* f3 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  HTMLInputElement* t = MakeGarbageCollected<HTMLInputElement>(GetDocument());
  f3->AppendChild(t);
  f2->AppendChild(f3);

  // Input fields in child forms are included iff `include_shadow_trees` is
  // true.
  EXPECT_THAT(f1->ListedElements(), IsEmpty());
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t));
  EXPECT_THAT(f2->ListedElements(), IsEmpty());
  EXPECT_THAT(f2->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t));
  EXPECT_THAT(f3->ListedElements(), ElementsAre(t));
  EXPECT_THAT(f3->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t));
}

// Tests that dynamic nested form removals properly invalidate the cache of
// listed elements.
TEST_F(HTMLFormElementTest, FormRemovalsInvalidateFormCaches) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  HTMLFormElement* f1 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  HTMLFormElement* f2 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  HTMLFormElement* f3 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  HTMLInputElement* t = MakeGarbageCollected<HTMLInputElement>(GetDocument());
  body->AppendChild(f1);
  f1->AppendChild(f2);
  f2->AppendChild(f3);
  f3->AppendChild(t);

  // Input fields in child forms are included iff `include_shadow_trees` is
  // true.
  EXPECT_THAT(f1->ListedElements(), IsEmpty());
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t));
  EXPECT_THAT(f2->ListedElements(), IsEmpty());
  EXPECT_THAT(f2->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t));
  EXPECT_THAT(f3->ListedElements(), ElementsAre(t));
  EXPECT_THAT(f3->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t));

  f2->RemoveChild(f3);

  EXPECT_THAT(f1->ListedElements(), IsEmpty());
  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true), IsEmpty());
  EXPECT_THAT(f2->ListedElements(), IsEmpty());
  EXPECT_THAT(f2->ListedElements(/*include_shadow_trees=*/true), IsEmpty());
}

// Tests that `include_shadow_trees=true` also includes form control elements
// that are associated via form-attribute with forms nested inside the form
// whose listed elements we are examining.
TEST_F(HTMLFormElementTest, ElementsAssociateWithNestedForms) {
  HTMLBodyElement* body = GetDocument().FirstBodyElement();
  HTMLFormElement* f1 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  HTMLFormElement* f2 = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  HTMLInputElement* t1 = MakeGarbageCollected<HTMLInputElement>(GetDocument());
  HTMLInputElement* t2 = MakeGarbageCollected<HTMLInputElement>(GetDocument());

  body->AppendChild(f1);
  f2->SetIdAttribute(AtomicString("f2"));
  f1->AppendChild(f2);
  f2->AppendChild(t1);
  t2->setAttribute(html_names::kFormAttr, AtomicString("f2"));
  body->AppendChild(t2);

  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t1, t2));
}

class HTMLFormElementSimTest : public SimTest {
 public:
  void LoadHTML(const String& html) {
    SimRequest main_resource("https://example.com", "text/html");
    LoadURL("https://example.com");
    main_resource.Complete(html);
  }
};

// Tests that `include_shadow_trees=true` also includes form control elements
// that are associated by the HTML parser.
// Regression test for crbug.com/347059988#comment40.
TEST_F(HTMLFormElementSimTest, NestedFormsAssociatedByParserMalformedHtml) {
  // From the following invalid HTML, Blink produces a DOM where
  // - f2 is nested in f1
  // - t2 is associated with f2.
  //
  // By closing f1 before opening f2, the parser's form element pointer is set
  // to f2 and therefore all following elements are associated with f2.
  // https://html.spec.whatwg.org/multipage/parsing.html#form-element-pointer
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <div>
      <form id=f1>
        <div>
          </form>  <!-- This is roughly ignored by the parser. -->
          <form id=f2>
        </div>
    </div>
    <input id=t>  <!-- This is associated with the unclosed form f2. -->
  )HTML");

  Document& doc = GetDocument();
  auto* f1 = To<HTMLFormElement>(doc.getElementById(AtomicString("f1")));
  auto* f2 = To<HTMLFormElement>(doc.getElementById(AtomicString("f2")));
  auto* t = To<HTMLInputElement>(doc.getElementById(AtomicString("t")));

  ASSERT_EQ(NodeTraversal::CommonAncestor(*f1, *f2), f1);
  ASSERT_EQ(NodeTraversal::CommonAncestor(*f2, *t), doc.body());
  ASSERT_EQ(t->Form(), f2);

  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t));
}

// This is a beefed-up version of the above test case
// `NestedFormsAssociatedByParserMalformedHtml` with additional form controls to
// test that ListedElements() does not include too many form controls.
TEST_F(HTMLFormElementSimTest,
       NestedFormsAssociatedByParserMalformedHtml_Large) {
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <div>
      <input id=t1>
      <form id=f1>
        <div>
          <input id=t2>
          </form>  <!-- This is roughly ignored by the parser. -->
          <form id=f2>
            <input id=t3>
        </div>
    </div>
    <input id=t4>  <!-- This is associated with the unclosed form f2. -->
    </form>
    <input id=t5>
  )HTML");

  Document& doc = GetDocument();
  auto* f1 = To<HTMLFormElement>(doc.getElementById(AtomicString("f1")));
  auto* f2 = To<HTMLFormElement>(doc.getElementById(AtomicString("f2")));
  auto* t1 = To<HTMLInputElement>(doc.getElementById(AtomicString("t1")));
  auto* t2 = To<HTMLInputElement>(doc.getElementById(AtomicString("t2")));
  auto* t3 = To<HTMLInputElement>(doc.getElementById(AtomicString("t3")));
  auto* t4 = To<HTMLInputElement>(doc.getElementById(AtomicString("t4")));
  auto* t5 = To<HTMLInputElement>(doc.getElementById(AtomicString("t5")));

  ASSERT_EQ(NodeTraversal::CommonAncestor(*f1, *f2), f1);
  ASSERT_EQ(NodeTraversal::CommonAncestor(*f2, *t4), doc.body());
  ASSERT_EQ(NodeTraversal::CommonAncestor(*f2, *t5), doc.body());
  ASSERT_EQ(t1->Form(), nullptr);
  ASSERT_EQ(t2->Form(), f1);
  ASSERT_EQ(t3->Form(), f2);
  ASSERT_EQ(t4->Form(), f2);
  ASSERT_EQ(t5->Form(), nullptr);

  EXPECT_THAT(f1->ListedElements(/*include_shadow_trees=*/true),
              ElementsAre(t2, t3, t4));
}

}  // namespace blink
```