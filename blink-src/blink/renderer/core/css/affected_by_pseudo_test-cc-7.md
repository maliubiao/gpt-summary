Response:
The user is asking for a summary of the provided C++ code file. The file seems to be testing the behavior of the `:has()` CSS pseudo-class in the Blink rendering engine.

Here's a breakdown of how to address the user's request:

1. **Identify the core functionality:** The tests revolve around how changes in the DOM (Document Object Model) affect the styling of elements when the `:has()` pseudo-class is used in CSS rules. Specifically, it's testing which elements need to have their styles recalculated when the conditions of the `:has()` selector change.

2. **Relate to web technologies:**  The `:has()` pseudo-class is a CSS feature. The tests demonstrate how CSS interacts with the DOM (HTML structure) and how the browser's rendering engine (Blink) handles these interactions. JavaScript is implicitly involved as it's the language used to manipulate the DOM in these tests.

3. **Analyze the test structure:** Each `TEST_F` function sets up an HTML structure, applies CSS rules using `:has()`, performs DOM manipulations, and then uses `CheckAffectedByFlagsForHas` to verify which elements are expected to have their styles recalculated. The `ASSERT_EQ` calls confirm the number of style recalculations.

4. **Infer logical reasoning and examples:** The tests often involve adding or removing elements, or changing attributes. The expected output is the number of elements whose styles need recalculating.

5. **Consider user errors:** Common user errors involve misunderstanding how `:has()` works, especially with complex selectors or when the target element is removed or modified.

6. **Trace user operations:**  The tests mimic user interactions by modifying the DOM. A user could trigger these code paths by interacting with a webpage, causing the DOM to update.

7. **Synthesize a concise summary:** Combine the identified functionalities into a high-level description.
```cpp
#include "third_party/blink/renderer/core/css/affected_by_pseudo_test.h"

#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/style/style_engine.h"

namespace blink {

TEST_F(AffectedByPseudoTest, AffectedByHasAfterRemoval5) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      #div1:has(#div12 > #div121) { color: green }
      #div1:has(#div14 > #div141) { color: red }
      #div1:has(#div14 > #div143) { color: blue }
      #div15:has(#div151) { color: yellow }
    </style>
    <div id=div1>
      <div id=div11></div>
      <div id=div12>
        <div id=div121></div>
      </div>
      <div id=div13></div>
      <div id=div14>
        <div id=div141></div>
        <div id=div142></div>
        <div id=div143></div>
      </div>
    </div>
    <div id=div15></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div121",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div14",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div141",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div142",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div143",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div15",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div14"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div142")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterRemoval6) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(+ .b > .c) { color: green }
    </style>
    <div id=div1>
      <div id=div11 class='a'></div>
      <div id=div12 class='b'>
        <div id=div121></div>
        <div id=div122 class='c'>
          <div id=div1221 class='c'></div>
        </div>
      </div>
      <div id=div13 class='b'>
        <div id=div131></div>
        <div id=div132 class='c'></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div121",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div122",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1221",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div131",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div132",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div122"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div1221")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div12")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div131",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div132",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasWithoutNth) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      #root:has(.foo) { background-color: green }
      :nth-child(1000) * { background-color: red }
    </style>
    <div id="root">
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div id="foo"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  CheckAffectedByFlagsForHas(
      "root",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  Element* foo = GetElementById("foo");
  foo->setAttribute(html_names::kClassAttr, AtomicString("foo"));

  UpdateAllLifecyclePhasesForTest();

  ASSERT_EQ(GetStyleEngine().StyleForElementCount() - start_count, 1U);
}

TEST_F(AffectedByPseudoTest, AffectedByPseudoInHasWithNestingParent) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .b:hover {
        .a:has(~ &) { background-color: green; }
      }
    </style>
    <div id=div1></div>
    <div id=div2 class='a'></div>
    <div id=div3></div>
    <div id=div4 class='b'></div>
    <div id=div5></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, true},
               {kAffectedByPseudoInHas, true},
               {kSiblingsAffectedByHasForSiblingRelationship, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div3")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(2U, element_count);
  GetElementById("div4")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(AffectedByPseudoTest, AffectedByPseudoInHasWithNestingComplexParent) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .b .c {
        .a:has(> &) { background-color: green; }
      }
    </style>
    <div id=div1></div>
    <div id=div2>
      <div id=div3></div>
      <div id=div4 class='a'>
        <div id=div5 class='c'></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kAffectedByLogicalCombinationsInHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kAffectedByLogicalCombinationsInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kAffectedByLogicalCombinationsInHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByPseudoInHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kAffectedByLogicalCombinationsInHas, true}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByPseudoInHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kAffectedByLogicalCombinationsInHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div1")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div2")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(2U, element_count);
}

TEST_F(AffectedByPseudoTest,
       ShadowHostAffectedByNonSubjectHasInShadowTreeStyle) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id="div1">
      <div id="div11">
        <template shadowrootmode="open">
          <style>
            :host:has(.a) .b { background-color: lime; }
            :host:has(~ .a) .c { background-color: lime; }
          </style>
          <div id="div111">
            <div id="div1111">
              <div id="div11111"></div>
            </div>
            <div id="div1112" class="a"></div>
          </div>
          <div id="div112"></div>
        </template>
        <div id="div113">
          <div id="div1131"></div>
          <div id="div1132" class="a"></div>
        </div>
      </div>
      <div id="div12" class="a"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div112")
      ->setAttribute(html_names::kClassAttr, AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedByNonSubjectHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div1111")
      ->setAttribute(html_names::kClassAttr, AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedByNonSubjectHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div111")
      ->setAttribute(html_names::kClassAttr, AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedByNonSubjectHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div1112")
      ->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(3U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedByNonSubjectHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedBy
Prompt: 
```
这是目录为blink/renderer/core/css/affected_by_pseudo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共8部分，请归纳一下它的功能

"""
estorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div143",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div15",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div14"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div142")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterRemoval6) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(+ .b > .c) { color: green }
    </style>
    <div id=div1>
      <div id=div11 class='a'></div>
      <div id=div12 class='b'>
        <div id=div121></div>
        <div id=div122 class='c'>
          <div id=div1221 class='c'></div>
        </div>
      </div>
      <div id=div13 class='b'>
        <div id=div131></div>
        <div id=div132 class='c'></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div121",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div122",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1221",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div131",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div132",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div122"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div1221")));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("div12")));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, true}});
  CheckAffectedByFlagsForHas(
      "div131",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div132",
      {{kAffectedBySubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasWithoutNth) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      #root:has(.foo) { background-color: green }
      :nth-child(1000) * { background-color: red }
    </style>
    <div id="root">
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div id="foo"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  CheckAffectedByFlagsForHas(
      "root",
      {{kAffectedBySubjectHas, true},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  Element* foo = GetElementById("foo");
  foo->setAttribute(html_names::kClassAttr, AtomicString("foo"));

  UpdateAllLifecyclePhasesForTest();

  ASSERT_EQ(GetStyleEngine().StyleForElementCount() - start_count, 1U);
}

TEST_F(AffectedByPseudoTest, AffectedByPseudoInHasWithNestingParent) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .b:hover {
        .a:has(~ &) { background-color: green; }
      }
    </style>
    <div id=div1></div>
    <div id=div2 class='a'></div>
    <div id=div3></div>
    <div id=div4 class='b'></div>
    <div id=div5></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, false},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, true},
               {kAffectedByPseudoInHas, true},
               {kSiblingsAffectedByHasForSiblingRelationship, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});
  CheckAffectedByFlagsForHas(
      "div4", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, true}});
  CheckAffectedByFlagsForHas(
      "div5", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kSiblingsAffectedByHasForSiblingRelationship, true},
               {kAncestorsOrSiblingsAffectedByHoverInHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
  GetElementById("div3")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div4")->SetHovered(true);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(2U, element_count);
  GetElementById("div4")->SetHovered(false);
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(AffectedByPseudoTest, AffectedByPseudoInHasWithNestingComplexParent) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .b .c {
        .a:has(> &) { background-color: green; }
      }
    </style>
    <div id=div1></div>
    <div id=div2>
      <div id=div3></div>
      <div id=div4 class='a'>
        <div id=div5 class='c'></div>
      </div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kAffectedByLogicalCombinationsInHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kAffectedByLogicalCombinationsInHas, false}});
  CheckAffectedByFlagsForHas(
      "div3", {{kAffectedBySubjectHas, false},
               {kAffectedByPseudoInHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kAffectedByLogicalCombinationsInHas, false}});
  CheckAffectedByFlagsForHas("div4",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByPseudoInHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kAffectedByLogicalCombinationsInHas, true}});
  CheckAffectedByFlagsForHas("div5",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByPseudoInHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kAffectedByLogicalCombinationsInHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div1")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div3")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div2")->setAttribute(html_names::kClassAttr,
                                       AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(2U, element_count);
}

TEST_F(AffectedByPseudoTest,
       ShadowHostAffectedByNonSubjectHasInShadowTreeStyle) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id="div1">
      <div id="div11">
        <template shadowrootmode="open">
          <style>
            :host:has(.a) .b { background-color: lime; }
            :host:has(~ .a) .c { background-color: lime; }
          </style>
          <div id="div111">
            <div id="div1111">
              <div id="div11111"></div>
            </div>
            <div id="div1112" class="a"></div>
          </div>
          <div id="div112"></div>
        </template>
        <div id="div113">
          <div id="div1131"></div>
          <div id="div1132" class="a"></div>
        </div>
      </div>
      <div id="div12" class="a"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div112")
      ->setAttribute(html_names::kClassAttr, AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  unsigned element_count =
      GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedByNonSubjectHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div1111")
      ->setAttribute(html_names::kClassAttr, AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedByNonSubjectHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div111")
      ->setAttribute(html_names::kClassAttr, AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedByNonSubjectHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div1112")
      ->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(3U, element_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedByNonSubjectHas, true},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div11111",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div1112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHasInShadowTree(
      "div11", "div112",
      {{kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, true},
       {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div113", {{kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1131", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1132", {{kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12", {{kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div1111")
      ->setAttribute(html_names::kClassAttr, AtomicString("b"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(1U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetShadowTreeElementById("div11", "div111")
      ->setAttribute(html_names::kClassAttr, AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(3U, element_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div12")->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_count = GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);
}

}  // namespace blink

"""


```