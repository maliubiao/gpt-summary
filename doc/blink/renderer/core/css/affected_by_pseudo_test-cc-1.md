Response:
The user wants to understand the functionality of the provided C++ code snippet from `affected_by_pseudo_test.cc`. This is part 2 of 8, suggesting the user is going through a larger file. I need to summarize the functionality of this specific chunk of code and relate it to web technologies (HTML, CSS, JavaScript) where applicable. I also need to identify potential user errors and describe how a user might reach this code during debugging.

**Plan:**

1. **Identify the core functionality:** This code seems to be testing how changes in the DOM (like adding/removing classes or hovering) affect the styling of elements, particularly when CSS `:has()` pseudo-class is involved. The `CheckAffectedByFlagsForHas` function suggests it's verifying internal flags related to how the `:has()` selector influences style invalidation.

2. **Relate to web technologies:**
    * **HTML:** The code manipulates HTML elements by setting attributes (`setAttribute`) and triggering hover states (`SetHovered`).
    * **CSS:** The tests use CSS selectors, including the `:has()` pseudo-class, to define styles. The tests verify how these styles are applied or invalidated based on DOM changes.
    * **JavaScript:** While not directly present, these tests are simulating scenarios that could be triggered by JavaScript manipulating the DOM or user interactions.

3. **Provide examples:**
    * For CSS, show how the `:has()` selector works and how changes in the subject of `:has()` or elements inside `:has()` can trigger style recalculations.
    * For HTML, demonstrate the basic structure used in the tests.
    * For potential user errors, consider common mistakes when using `:has()`.

4. **Explain logical reasoning (with input/output):**
    * Focus on how the tests assert the number of elements that need restyling after a DOM change. The input is the DOM change, and the output is the assertion about `element_count`.

5. **Identify user/programming errors:**  Consider common mistakes when using the `:has()` selector.

6. **Describe user operations leading here:**  Think about scenarios where a developer might be debugging style invalidation issues related to `:has()`.

7. **Summarize the functionality of this part.**
```cpp
ne().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div6")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div7")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div7")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div9")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div9")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div10")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div10")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div12")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div12")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div13")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div13")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(AffectedByPseudoTest,
       AffectedByNonSubjectHasHasAndAncestorsOrAncestorSiblingsAffectedByHas) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(.b) .c { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3>
          <div id=div4>
            <div id=div5></div>
          </div>
          <div id=div6 class='b'></div>
        </div>
        <div id=div7></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div7")->setAttribute(html_names::kClassAttr,
                                       AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div5")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
}

TEST_F(AffectedByPseudoTest,
       AffectedByNonSubjectHasHasAndSiblingsAffectedByHas) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(~ .b) .c { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
      </div>
      <div id=div4></div>
      <div id=div5 class='b'></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->setAttribute(html_names::kClassAttr,
                                       AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div5")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(AffectedByPseudoTest, AffectedBySubjectHasComplexCase1) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(.b ~ .c) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
        <div id=div4>
          <div id=div5></div>
          <div id=div6 class='b'></div>
          <div id=div7></div>
          <div id=div8 class='c'></div>
          <div id=div9></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div8")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div3",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedBySubjectHasComplexCase2) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(~ .b .c) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
      </div>
      <div id=div4>
        <div id=div5></div>
      </div>
      <div id=div6 class='b'>
        <div id=div7></div>
        <div id=div8>
          <div id=div9></div>
          <div id=div10 class='c'></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, true},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div10",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, true},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div10",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedBySubjectHasComplexCase3) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(.b ~ .c .d) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
        <div id=div4>
          <div id=div5></div>
          <div id=div6 class='b'></div>
          <div id=div7></div>
          <div id=div8 class='c'>
            <div id=div9></div>
            <div id=div10>
              <div id=div11></div>
              <div id=div12 class='d'></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div3",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div10",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div12",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div8")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div3",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas,
### 提示词
```
这是目录为blink/renderer/core/css/affected_by_pseudo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ne().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByPseudoInHas, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByPseudoInHas, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div6")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div7")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div7")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div9")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div9")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div10")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
  GetElementById("div10")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div12")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div12")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div13")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div13")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(AffectedByPseudoTest,
       AffectedByNonSubjectHasHasAndAncestorsOrAncestorSiblingsAffectedByHas) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(.b) .c { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3>
          <div id=div4>
            <div id=div5></div>
          </div>
          <div id=div6 class='b'></div>
        </div>
        <div id=div7></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div7")->setAttribute(html_names::kClassAttr,
                                       AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div5")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, true}});
}

TEST_F(AffectedByPseudoTest,
       AffectedByNonSubjectHasHasAndSiblingsAffectedByHas) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(~ .b) .c { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
      </div>
      <div id=div4></div>
      <div id=div5 class='b'></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->setAttribute(html_names::kClassAttr,
                                       AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, true},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div5")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);
}

TEST_F(AffectedByPseudoTest, AffectedBySubjectHasComplexCase1) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(.b ~ .c) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
        <div id=div4>
          <div id=div5></div>
          <div id=div6 class='b'></div>
          <div id=div7></div>
          <div id=div8 class='c'></div>
          <div id=div9></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div8")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div3",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedBySubjectHasComplexCase2) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(~ .b .c) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
      </div>
      <div id=div4>
        <div id=div5></div>
      </div>
      <div id=div6 class='b'>
        <div id=div7></div>
        <div id=div8>
          <div id=div9></div>
          <div id=div10 class='c'></div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, true},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div7", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div9", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div10",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div6")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, true},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div6", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, true}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div10",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedBySubjectHasComplexCase3) {
  SetHtmlInnerHTML(R"HTML(
    <style>.a:has(.b ~ .c .d) { background-color: lime; }</style>
    <div id=div1>
      <div id=div2 class='a'>
        <div id=div3></div>
        <div id=div4>
          <div id=div5></div>
          <div id=div6 class='b'></div>
          <div id=div7></div>
          <div id=div8 class='c'>
            <div id=div9></div>
            <div id=div10>
              <div id=div11></div>
              <div id=div12 class='d'></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div3",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div10",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div12",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div8")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div3",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div6",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div7",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div8",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div9",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div10",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div12",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
```