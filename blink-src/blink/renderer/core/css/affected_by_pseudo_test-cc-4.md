Response:
The user wants to understand the functionality of the `affected_by_pseudo_test.cc` file in the Chromium Blink engine. They are particularly interested in how it relates to HTML, CSS, and JavaScript, and want to understand the debugging context.

Here's a breakdown of how to approach this:

1. **Identify the core purpose of the file:** The filename suggests it's about testing how changes in the DOM and CSS affect elements due to pseudo-classes, specifically `:has()`.

2. **Analyze the code snippets:** The provided code consists of several test cases using `TEST_F`. Each test case sets up an HTML structure, potentially with some CSS, and then performs actions (like adding attributes or elements) and verifies the state using `CheckAffectedByFlagsForHas`.

3. **Explain the functionality:** Based on the code, the file tests the correctness of how Blink determines if an element is affected by the `:has()` pseudo-class after various DOM manipulations. It checks different scenarios involving nesting, sibling relationships, and insertion of elements.

4. **Connect to HTML, CSS, and JavaScript:**
    - **HTML:** The tests manipulate the HTML structure using methods like `SetHtmlInnerHTML`, `setAttribute`, `setInnerHTML`, `AppendChild`, and `InsertBefore`.
    - **CSS:** The tests define CSS rules using the `:has()` pseudo-class to style elements based on the presence of other elements.
    - **JavaScript:** While the tests themselves are in C++, the behavior they are testing is crucial for JavaScript interactions that modify the DOM and expect CSS to update accordingly.

5. **Provide examples:**  Illustrate the interaction with concrete examples of HTML, CSS, and how JavaScript might trigger these scenarios.

6. **Explain the logic and reasoning:** Focus on the `:has()` pseudo-class and how the tests verify that the "affected by" flags are correctly set after DOM changes. Explain the meaning of the different flags (`kAffectedBySubjectHas`, `kAffectedByNonSubjectHas`, etc.).

7. **Address potential user errors:**  Think about common mistakes developers make when using `:has()` and how these tests might help catch related bugs in Blink.

8. **Explain the debugging context:** Describe how a developer might end up examining this code, likely when investigating issues related to styling and the `:has()` pseudo-class after dynamic DOM updates.

9. **Summarize the function of this specific part:** Since the user specified this is part 5 of 8, focus on the specific aspect covered in the provided snippet, which seems to be focused on DOM manipulations *after* initial rendering.

**Self-Correction/Refinement:** Initially, I might focus solely on the C++ testing framework. However, the user's request explicitly asks for connections to web technologies. Therefore, it's crucial to bridge the gap and explain how these low-level tests relate to the high-level behavior seen in web browsers. Also, the explicit mention of "part 5 of 8" implies the need for a summary that aligns with the *specific* tests within this snippet, likely focusing on post-insertion scenarios.
```
这是目录为blink/renderer/core/css/affected_by_pseudo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共8部分，请归纳一下它的功能

"""
</div>
      <div id=div22></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div211", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2111", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21111", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div212", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div21")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div21",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div211",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21111", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div212",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div11")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div111 class='b'>
          <div id=div1111>
            <div id=div11111></div>
          </div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(4U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas("div111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div1111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // There can be some inefficiency for fixed depth :has() argument
  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div11111")
      ->setAttribute(html_names::kClassAttr, AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div21111")
      ->setInnerHTML(String::FromUTF8(
          R"HTML(
        <div id=div211111>
          <div id=div2111111></div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div211111", {{kAffectedBySubjectHas, false},
                    {kAffectedByNonSubjectHas, false},
                    {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                    {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2111111", {{kAffectedBySubjectHas, false},
                     {kAffectedByNonSubjectHas, false},
                     {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                     {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div212")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div2121>
          <div id=div21211>
            <div id=div212111></div>
          </div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas("div2121",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div21211",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div212111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterInsertion3) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(~ .b) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'>
        <div id=div111></div>
      </div>
    </div>
    <div id=div2>
      <div id=div21></div>
      <div id=div22></div>
      <div id=div23></div>
      <div id=div24 class='b'></div>
      <div id=div25></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div111", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div23", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div24", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div25", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div22")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div111", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div23",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div24",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div25",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div111")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div1111>
          <div id=div11112 class='b'></div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1111", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11112", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  auto* subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div12"));
  subtree_root->setInnerHTML(String::FromUTF8(R"HTML(
      <div id=div121>
        <div id=div1211></div>
        <div id=div1212 class='a'>
          <div id=div12121></div>
        </div>
        <div id=div1213></div>
        <div id=div1214 class='b'></div>
        <div id=div1215></div>
      </div>
  )HTML"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(subtree_root);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(8U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1211", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1212",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div12121", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1213",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1214",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1215",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterInsertion4) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(+ .b + .c) { color: green; }
    </style>
    <div id=div1>
      <div id=div11></div>
      <div id=div13 class='b'></div>
      <div id=div14></div>
      <div id=div17></div>
      <div id=div18></div>
      <div id=div19></div>
    </div>
    <div id=div2>
      <div id=div21></div>
      <div id=div22></div>
      <div id=div23 class='b'>
        <div id=div231></div>
      </div>
      <div id=div24 class='c'></div>
      <div id=div25></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div14", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div17", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div18", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div19", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div23", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div24", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div25", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  element->setAttribute(html_names::kIdAttr, AtomicString("div12"));
  element->setAttribute(html_names::kClassAttr, AtomicString("a"));
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->InsertBefore(element,
                     GetDocument().getElementById(AtomicString("div13")));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div14",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div17",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div12")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // There can be some inefficiency for fixed adjacent distance :has() argument
  start_count = GetStyleEngine().StyleForElementCount();
  element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  element->setAttribute(html_names::kIdAttr, AtomicString("div16"));
  element->setAttribute(html_names::kClassAttr, AtomicString("b c"));
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->InsertBefore(element,
                     GetDocument().getElementById(AtomicString("div17")));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div12")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  CheckAffectedByFlagsForHas(
      "div16",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div17",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div14")->setAttribute(html_names::kClassAttr,
                                        AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetElementById("div12")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  CheckAffectedByFlagsForHas(
      "div16",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div17",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start
Prompt: 
```
这是目录为blink/renderer/core/css/affected_by_pseudo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共8部分，请归纳一下它的功能

"""
</div>
      <div id=div22></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div211", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2111", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21111", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div212", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div21")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div21",
                             {{kAffectedBySubjectHas, true},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div211",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div2111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21111", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div212",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div11")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div111 class='b'>
          <div id=div1111>
            <div id=div11111></div>
          </div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(4U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas("div111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div1111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div11111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // There can be some inefficiency for fixed depth :has() argument
  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div11111")
      ->setAttribute(html_names::kClassAttr, AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div11")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div21111")
      ->setInnerHTML(String::FromUTF8(
          R"HTML(
        <div id=div211111>
          <div id=div2111111></div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div211111", {{kAffectedBySubjectHas, false},
                    {kAffectedByNonSubjectHas, false},
                    {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                    {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2111111", {{kAffectedBySubjectHas, false},
                     {kAffectedByNonSubjectHas, false},
                     {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                     {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div212")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div2121>
          <div id=div21211>
            <div id=div212111></div>
          </div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas("div2121",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div21211",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas("div212111",
                             {{kAffectedBySubjectHas, false},
                              {kAffectedByNonSubjectHas, false},
                              {kAncestorsOrAncestorSiblingsAffectedByHas, true},
                              {kSiblingsAffectedByHas, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterInsertion3) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(~ .b) { color: green; }
    </style>
    <div id=div1>
      <div id=div11 class='a'>
        <div id=div111></div>
      </div>
    </div>
    <div id=div2>
      <div id=div21></div>
      <div id=div22></div>
      <div id=div23></div>
      <div id=div24 class='b'></div>
      <div id=div25></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div111", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div23", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div24", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div25", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div22")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div111", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div23",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div24",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div25",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div111")->setInnerHTML(String::FromUTF8(
      R"HTML(
        <div id=div1111>
          <div id=div11112 class='b'></div>
        </div>
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div1111", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11112", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  auto* subtree_root = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  subtree_root->setAttribute(html_names::kIdAttr, AtomicString("div12"));
  subtree_root->setInnerHTML(String::FromUTF8(R"HTML(
      <div id=div121>
        <div id=div1211></div>
        <div id=div1212 class='a'>
          <div id=div12121></div>
        </div>
        <div id=div1213></div>
        <div id=div1214 class='b'></div>
        <div id=div1215></div>
      </div>
  )HTML"));
  GetDocument().getElementById(AtomicString("div1"))->AppendChild(subtree_root);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(8U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div121", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
                 {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                 {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1211", {{kAffectedBySubjectHas, false},
                  {kAffectedByNonSubjectHas, false},
                  {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                  {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1212",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div12121", {{kAffectedBySubjectHas, false},
                   {kAffectedByNonSubjectHas, false},
                   {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                   {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div1213",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1214",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div1215",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
}

TEST_F(AffectedByPseudoTest, AffectedByHasAfterInsertion4) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .a:has(+ .b + .c) { color: green; }
    </style>
    <div id=div1>
      <div id=div11></div>
      <div id=div13 class='b'></div>
      <div id=div14></div>
      <div id=div17></div>
      <div id=div18></div>
      <div id=div19></div>
    </div>
    <div id=div2>
      <div id=div21></div>
      <div id=div22></div>
      <div id=div23 class='b'>
        <div id=div231></div>
      </div>
      <div id=div24 class='c'></div>
      <div id=div25></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  CheckAffectedByFlagsForHas(
      "div1", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div13", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div14", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div17", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div18", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div19", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div23", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div24", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div25", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  auto* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  element->setAttribute(html_names::kIdAttr, AtomicString("div12"));
  element->setAttribute(html_names::kClassAttr, AtomicString("a"));
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->InsertBefore(element,
                     GetDocument().getElementById(AtomicString("div13")));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div11", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div13",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div14",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div17",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div12")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // There can be some inefficiency for fixed adjacent distance :has() argument
  start_count = GetStyleEngine().StyleForElementCount();
  element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  element->setAttribute(html_names::kIdAttr, AtomicString("div16"));
  element->setAttribute(html_names::kClassAttr, AtomicString("b c"));
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->InsertBefore(element,
                     GetDocument().getElementById(AtomicString("div17")));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetElementById("div12")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  CheckAffectedByFlagsForHas(
      "div16",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div17",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div14")->setAttribute(html_names::kClassAttr,
                                        AtomicString("c"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetElementById("div12")->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  CheckAffectedByFlagsForHas(
      "div16",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div17",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  element->setAttribute(html_names::kIdAttr, AtomicString("div15"));
  element->setAttribute(html_names::kClassAttr, AtomicString("a"));
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->InsertBefore(element,
                     GetDocument().getElementById(AtomicString("div16")));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(2U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div15",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div16",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div17",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div18",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, false},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  element->setAttribute(html_names::kIdAttr, AtomicString("div15.5"));
  GetDocument()
      .getElementById(AtomicString("div1"))
      ->InsertBefore(element,
                     GetDocument().getElementById(AtomicString("div16")));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(3U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div12",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div15",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div15.5",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});

  start_count = GetStyleEngine().StyleForElementCount();
  GetElementById("div22")->setAttribute(html_names::kClassAttr,
                                        AtomicString("a"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, GetStyleEngine().StyleForElementCount() - start_count);

  CheckAffectedByFlagsForHas(
      "div2", {{kAffectedBySubjectHas, false},
               {kAffectedByNonSubjectHas, false},
               {kAncestorsOrAncestorSiblingsAffectedByHas, false},
               {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div21", {{kAffectedBySubjectHas, false},
                {kAffectedByNonSubjectHas, false},
                {kAncestorsOrAncestorSiblingsAffectedByHas, false},
                {kSiblingsAffectedByHas, false}});
  CheckAffectedByFlagsForHas(
      "div22",
      {{kAffectedBySubjectHas, true},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div23",
      {{kAffectedBySubjectHas, false},
       {kAffectedByNonSubjectHas, false},
       {kAncestorsOrAncestorSiblingsAffectedByHas, false},
       {kSiblingsAffectedByHasForSiblingRelationship, true},
       {kSiblingsAffectedByHasForSiblingDescendantRelationship, false}});
  CheckAffectedByFlagsForHas(
      "div231", {{kAffectedBySubjectHas, false},
                 {kAffectedByNonSubjectHas, false},
         
"""


```