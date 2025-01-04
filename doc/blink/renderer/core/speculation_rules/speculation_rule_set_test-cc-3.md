Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a test file for the speculation rules feature in the Chromium Blink engine.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The file name `speculation_rule_set_test.cc` immediately suggests it's about testing the `SpeculationRuleSet` class or related logic. The tests focus on how speculation rules defined in HTML (using `<script type="speculationrules">`) are parsed and applied.

2. **Analyze Test Cases:** Each `TEST_F` function represents a specific scenario being tested. Look for patterns and keywords in the test names and the code within each test.

3. **Relate to Web Technologies:**  The tests frequently manipulate DOM elements (anchors, meta tags, base URLs), and the speculation rules involve matching URLs and CSS selectors. This connects the code to HTML, CSS, and to a lesser extent, JavaScript (since the rules are embedded in `<script>` tags).

4. **Infer Logic and Data Flow:**  Follow how the tests set up the environment (`DummyPageHolder`, `StubSpeculationHost`), define speculation rules, manipulate the DOM, and then assert the expected outcomes (e.g., which URLs are considered candidates, what referrer policies are applied).

5. **Consider User Actions:**  Think about how a user's browsing actions might lead to the execution of this code. For example, a page loading and encountering speculation rules in its HTML.

6. **Identify Potential Errors:** Look for tests that explicitly check for invalid inputs or situations that might cause unexpected behavior.

7. **Address the "Part 4 of 6" Constraint:** Acknowledge the context and ensure the summary focuses on the provided snippet, not the entirety of the speculation rules implementation.
```cpp
ferrer"));

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"href_matches": "https://foo.com/*"},
      "referrer_policy": "strict-origin"
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ::testing::Each(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kStrictOrigin)));
}

// Tests that a link's referrer-policy value is used if one is not specified
// in the document rule.
TEST_F(DocumentRulesTest, LinkReferrerPolicy) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();
  page_holder.GetFrame().DomWindow()->SetReferrerPolicy(
      network::mojom::ReferrerPolicy::kStrictOrigin);

  auto* link_with_referrer = AddAnchor(*document.body(), "https://foo.com/abc");
  link_with_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                   AtomicString("same-origin"));
  auto* link_with_no_referrer =
      AddAnchor(*document.body(), "https://foo.com/xyz");
  auto* link_with_rel_noreferrer =
      AddAnchor(*document.body(), "https://foo.com/mno");
  link_with_rel_noreferrer->setAttribute(html_names::kRelAttr,
                                         AtomicString("noreferrer"));
  auto* link_with_invalid_referrer =
      AddAnchor(*document.body(), "https://foo.com/pqr");
  link_with_invalid_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                           AtomicString("invalid"));
  auto* link_with_disallowed_referrer =
      AddAnchor(*document.body(), "https://foo.com/aaa");
  link_with_disallowed_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                              AtomicString("unsafe-url"));

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(
      candidates,
      ::testing::UnorderedElementsAre(
          ::testing::AllOf(
              HasURL(link_with_referrer->HrefURL()),
              HasReferrerPolicy(network::mojom::ReferrerPolicy::kSameOrigin)),
          ::testing::AllOf(
              HasURL(link_with_rel_noreferrer->HrefURL()),
              HasReferrerPolicy(network::mojom::ReferrerPolicy::kNever)),
          ::testing::AllOf(
              HasURL(link_with_no_referrer->HrefURL()),
              HasReferrerPolicy(network::mojom::ReferrerPolicy::kStrictOrigin)),
          ::testing::AllOf(
              HasURL(link_with_invalid_referrer->HrefURL()),
              HasReferrerPolicy(
                  network::mojom::ReferrerPolicy::kStrictOrigin))));

  // Console message should have been logged for
  // |link_with_disallowed_referrer|.
  const auto& console_message_storage =
      page_holder.GetPage().GetConsoleMessageStorage();
  EXPECT_EQ(console_message_storage.size(), 1u);
  EXPECT_THAT(console_message_storage.at(0)->Nodes(),
              testing::Contains(link_with_disallowed_referrer->GetDomNodeId()));
}

// Tests that changing the "referrerpolicy" attribute results in the
// corresponding speculation candidate updating.
TEST_F(DocumentRulesTest, ReferrerPolicyAttributeChangeCausesLinkInvalidation) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* link_with_referrer = AddAnchor(*document.body(), "https://foo.com/abc");
  link_with_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                   AtomicString("same-origin"));
  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kSameOrigin)));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link_with_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                     AtomicString("strict-origin"));
  });
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kStrictOrigin)));
}

// Tests that changing the "rel" attribute results in the corresponding
// speculation candidate updating. Also tests that "rel=noreferrer" overrides
// the referrerpolicy attribute.
TEST_F(DocumentRulesTest, RelAttributeChangeCausesLinkInvalidation) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* link = AddAnchor(*document.body(), "https://foo.com/abc");
  link->setAttribute(html_names::kReferrerpolicyAttr,
                     AtomicString("same-origin"));

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kSameOrigin)));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link->setAttribute(html_names::kRelAttr, AtomicString("noreferrer"));
  });
  EXPECT_THAT(
      candidates,
      ElementsAre(HasReferrerPolicy(network::mojom::ReferrerPolicy::kNever)));
}

TEST_F(DocumentRulesTest, ReferrerMetaChangeShouldInvalidateCandidates) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  AddAnchor(*document.body(), "https://foo.com/abc");
  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(
      candidates,
      ElementsAre(HasReferrerPolicy(
          network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin)));

  auto* meta =
      MakeGarbageCollected<HTMLMetaElement>(document, CreateElementFlags());
  meta->setAttribute(html_names::kNameAttr, AtomicString("referrer"));
  meta->setAttribute(html_names::kContentAttr, AtomicString("strict-origin"));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    document.head()->appendChild(meta);
  });
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kStrictOrigin)));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    meta->setAttribute(html_names::kContentAttr, AtomicString("same-origin"));
  });
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kSameOrigin)));
}

TEST_F(DocumentRulesTest, BaseURLChanged) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();
  document.SetBaseURLOverride(KURL("https://foo.com"));

  AddAnchor(*document.body(), "https://foo.com/bar");
  AddAnchor(*document.body(), "/bart");

  HTMLScriptElement* speculation_script;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    speculation_script = InsertSpeculationRules(page_holder.GetDocument(),
                                                R"(
      {"prefetch": [
        {"source": "document", "where": {"href_matches": "/bar*"}}
      ]}
    )");
  });
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar"),
                                  KURL("https://foo.com/bart")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    document.SetBaseURLOverride(KURL("https://bar.com"));
  });
  // After the base URL changes, "https://foo.com/bar" is matched against
  // "https://bar.com/bar*" and doesn't match. "/bart" is resolved to
  // "https://bar.com/bart" and matches with "https://bar.com/bar*".
  EXPECT_THAT(candidates, HasURLs("https://bar.com/bart"));

  // Test that removing the script causes the candidates to be removed.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      [&]() { speculation_script->remove(); });
  EXPECT_EQ(candidates.size(), 0u);
}

TEST_F(DocumentRulesTest, TargetHintFromLink) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* anchor_1 = AddAnchor(*document.body(), "https://foo.com/bar");
  anchor_1->setAttribute(html_names::kTargetAttr, AtomicString("_blank"));
  auto* anchor_2 = AddAnchor(*document.body(), "https://fizz.com/buzz");
  anchor_2->setAttribute(html_names::kTargetAttr, AtomicString("_self"));
  AddAnchor(*document.body(), "https://hello.com/world");

  String speculation_script = R"(
    {
      "prefetch": [{
        "source": "document",
        "where": {"href_matches": "https://foo.com/bar"}
      }],
      "prerender": [{"source": "document"}]
    }
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(
      candidates,
      ::testing::UnorderedElementsAre(
          ::testing::AllOf(
              HasAction(mojom::blink::SpeculationAction::kPrefetch),
              HasTargetHint(mojom::blink::SpeculationTargetHint::kNoHint)),
          ::testing::AllOf(
              HasURL(KURL("https://foo.com/bar")),
              HasAction(mojom::blink::SpeculationAction::kPrerender),
              HasTargetHint(mojom::blink::SpeculationTargetHint::kBlank)),
          ::testing::AllOf(
              HasURL(KURL("https://fizz.com/buzz")),
              HasAction(mojom::blink::SpeculationAction::kPrerender),
              HasTargetHint(mojom::blink::SpeculationTargetHint::kSelf)),
          ::testing::AllOf(
              HasURL(KURL("https://hello.com/world")),
              HasAction(mojom::blink::SpeculationAction::kPrerender),
              HasTargetHint(mojom::blink::SpeculationTargetHint::kNoHint))));
}

TEST_F(DocumentRulesTest, TargetHintFromSpeculationRuleOverridesLinkTarget) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* anchor = AddAnchor(*document.body(), "https://foo.com/bar");
  anchor->setAttribute(html_names::kTargetAttr, AtomicString("_blank"));

  String speculation_script = R"(
    {"prerender": [{"source": "document", "target_hint": "_self"}]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ::testing::ElementsAre(HasTargetHint(
                              mojom::blink::SpeculationTargetHint::kSelf)));
}

TEST_F(DocumentRulesTest, TargetHintFromLinkDynamic) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* anchor = AddAnchor(*document.body(), "https://foo.com/bar");

  String speculation_script = R"({"prerender": [{"source": "document"}]})";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ::testing::ElementsAre(HasTargetHint(
                              mojom::blink::SpeculationTargetHint::kNoHint)));

  HTMLBaseElement* base_element;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    base_element = MakeGarbageCollected<HTMLBaseElement>(document);
    base_element->setAttribute(html_names::kTargetAttr, AtomicString("_self"));
    document.head()->appendChild(base_element);
  });
  EXPECT_THAT(candidates, ::testing::ElementsAre(HasTargetHint(
                              mojom::blink::SpeculationTargetHint::kSelf)));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    anchor->setAttribute(html_names::kTargetAttr, AtomicString("_blank"));
  });
  EXPECT_THAT(candidates, ::testing::ElementsAre(HasTargetHint(
                              mojom::blink::SpeculationTargetHint::kBlank)));
}

TEST_F(DocumentRulesTest, ParseSelectorMatches) {
  auto* simple_selector_matches = CreatePredicate(R"(
    "selector_matches": ".valid"
  )");
  EXPECT_THAT(simple_selector_matches,
              Selector({StyleRuleWithSelectorText(".valid")}));

  auto* simple_selector_matches_list = CreatePredicate(R"(
    "selector_matches": [".one", "#two"]
  )");
  EXPECT_THAT(simple_selector_matches_list,
              Selector({StyleRuleWithSelectorText(".one"),
                        StyleRuleWithSelectorText("#two")}));

  auto* selector_matches_with_compound_selector = CreatePredicate(R"(
    "selector_matches": ".interesting-section > a"
  )");
  EXPECT_THAT(
      selector_matches_with_compound_selector,
      Selector({StyleRuleWithSelectorText(".interesting-section > a")}));
}

TEST_F(DocumentRulesTest, GetStyleRules) {
  auto* predicate = CreatePredicate(R"(
    "and": [
      {"or": [
        {"not": {"selector_matches": "span.fizz > a"}},
        {"selector_matches": "#bar a"}
      ]},
      {"selector_matches": "a.foo"}
    ]
  )");
  EXPECT_THAT(
      predicate,
      And({Or({Neg(Selector({StyleRuleWithSelectorText("span.fizz > a")})),
               Selector({StyleRuleWithSelectorText("#bar a")})}),
           Selector({StyleRuleWithSelectorText("a.foo")})}));
  EXPECT_THAT(predicate->GetStyleRules(),
              UnorderedElementsAre(StyleRuleWithSelectorText("span.fizz > a"),
                                   StyleRuleWithSelectorText("#bar a"),
                                   StyleRuleWithSelectorText("a.foo")));
}

TEST_F(DocumentRulesTest, SelectorMatchesAddsCandidates) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/foo");
  AddAnchor(*unimportant_section, "https://foo.com/bar");
  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/foo"),
                                  KURL("https://foo.com/fizz")));
}

TEST_F(DocumentRulesTest, SelectorMatchesIsDynamic) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"or": [
        {"selector_matches": "#important-section > a"},
        {"selector_matches": ".important-link"}
      ]}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_TRUE(candidates.empty());

  HTMLAnchorElement* second_anchor = nullptr;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    AddAnchor(*important_section, "https://foo.com/fizz");
    second_anchor = AddAnchor(*unimportant_section, "https://foo.com/buzz");
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    second_anchor->setAttribute(html_names::kClassAttr,
                                AtomicString("important-link"));
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz"),
                                  KURL("https://foo.com/buzz")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->SetIdAttribute(AtomicString("random-section"));
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/buzz")));
}

TEST_F(DocumentRulesTest, AddingDocumentRulesInvalidatesStyle) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
  page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
  ASSERT_FALSE(document.NeedsLayoutTreeUpdate());

  auto* script_without_selector_matches = InsertSpeculationRules(document, R"(
    {"prefetch": [{"source": "document", "where": {"href_matches": "/foo"}}]}
  )");
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());

  auto* script_with_irrelevant_selector_matches =
      InsertSpeculationRules(document, R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#irrelevant a"}
    }]}
  )");
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());

  auto* script_with_selector_matches = InsertSpeculationRules(document, R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )");
  EXPECT_TRUE(important_section->ChildNeedsStyleRecalc());

  page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());

  // Test removing SpeculationRuleSets, removing a ruleset should also cause
  // invalidations.
  script_with_selector_matches->remove();
  EXPECT_TRUE(important_section->ChildNeedsStyleRecalc());
  page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();

  script_without_selector_matches->remove();
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());

  script_with_irrelevant_selector_matches->remove();
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());
}

TEST_F(DocumentRulesTest, BasicStyleInvalidation) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);

  EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
  unimportant_section->SetIdAttribute(AtomicString("random-section"));
  EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
  unimportant_section->SetIdAttribute(AtomicString("important-section"));
  EXPECT_TRUE(document.NeedsLayoutTreeUpdate());
}

TEST_F(DocumentRulesTest, IrrelevantDOMChangeShouldNotInvalidateCandidateList) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz")));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        unimportant_section->SetIdAttribute(AtomicString("random-section"));
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));
}

TEST_F(DocumentRulesTest, SelectorMatchesInsideShadowTree) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  ShadowRoot& shadow_root =
      document.body()->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      shadow_root.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      shadow_root.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz")));
}

TEST_F(DocumentRulesTest, SelectorMatchesWithScopePseudoSelector) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setAttribute(html_names::kClassAttr, AtomicString("foo"));
  document.body()->setInnerHTML(R"HTML(
    <a href="https://foo.com/fizz"></a>
    <div class="foo">
      <a href="https://foo.com/buzz"></a>
    </div>
  )HTML");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": ":scope > .foo > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz")));
}

// Basic test to check that we wait for UpdateStyle before sending a list of
// updated candidates to the browser process when "selector_matches" is
// enabled.
TEST_F(DocumentRulesTest, UpdateQueueingWithSelectorMatches_1) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"href_matches": "https://bar.com/*"}
    }]}
  )";
  // No update should be sent before running a style update after inserting
  // the rules.
  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
        InsertSpeculationRules(document, speculation_script);
      },
      IncludesStyleUpdate{false}));
  ASSERT_TRUE(document.NeedsLayoutTreeUpdate());
  // The list of candidates is updated after a style update.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, []() {});
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs());

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() { AddAnchor(*document.body(), "https://bar.com/fizz.html"); },
      IncludesStyleUpdate{false}));
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, []() {});
  EXPECT_THAT(candidates, HasURLs(KURL("https://bar.com/fizz.html")));

  String speculation_script_with_selector_matches = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  // Insert a speculation ruleset with "selector_matches". This will not require
  // a style update, as adding the ruleset itself will not cause any
  // invalidations (there are no existing elements that match the selector in
  // the new ruleset).
  PropagateRulesToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        InsertSpeculationRules(document,
                               speculation_script_with_selector_matches);
      },
      IncludesStyleUpdate{false});
  ASSERT_FALSE(document.NeedsLayoutTreeUpdate());
  EXPECT_THAT(candidates, HasURLs(KURL("https://bar.com/fizz.html")));

  // Add two new links. We should not update speculation candidates until we run
  // UpdateStyle.
  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        AddAnchor(*important_section, "https://foo.com/fizz.html");
        AddAnchor(*unimportant_section, "https://foo.com/buzz.html");
      },
      IncludesStyleUpdate{false}));
  ASSERT_TRUE(document.NeedsLayoutTreeUpdate());
  // Runs UpdateStyle; new speculation candidates should be sent.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, []() {});
  EXPECT_THAT(candidates, HasURLs(KURL("https://bar.com/fizz.html"),
                                  KURL("https://foo.com/fizz.html")));
}

// This tests that we don't need to wait for a style update if an operation
// does not invalidate style.
TEST_F(DocumentRulesTest, UpdateQueueingWithSelectorMatches_2) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  AddAnchor(*important_section, "https://foo.com/bar");
  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  // We shouldn't have to wait for UpdateStyle if the update doesn't cause
  // style invalidation.
  PropagateRulesToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
        auto* referrer_meta = MakeGarbageCollected<HTMLMetaElement>(
            document
Prompt: 
```
这是目录为blink/renderer/core/speculation_rules/speculation_rule_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
ferrer"));

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"href_matches": "https://foo.com/*"},
      "referrer_policy": "strict-origin"
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ::testing::Each(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kStrictOrigin)));
}

// Tests that a link's referrer-policy value is used if one is not specified
// in the document rule.
TEST_F(DocumentRulesTest, LinkReferrerPolicy) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();
  page_holder.GetFrame().DomWindow()->SetReferrerPolicy(
      network::mojom::ReferrerPolicy::kStrictOrigin);

  auto* link_with_referrer = AddAnchor(*document.body(), "https://foo.com/abc");
  link_with_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                   AtomicString("same-origin"));
  auto* link_with_no_referrer =
      AddAnchor(*document.body(), "https://foo.com/xyz");
  auto* link_with_rel_noreferrer =
      AddAnchor(*document.body(), "https://foo.com/mno");
  link_with_rel_noreferrer->setAttribute(html_names::kRelAttr,
                                         AtomicString("noreferrer"));
  auto* link_with_invalid_referrer =
      AddAnchor(*document.body(), "https://foo.com/pqr");
  link_with_invalid_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                           AtomicString("invalid"));
  auto* link_with_disallowed_referrer =
      AddAnchor(*document.body(), "https://foo.com/aaa");
  link_with_disallowed_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                              AtomicString("unsafe-url"));

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(
      candidates,
      ::testing::UnorderedElementsAre(
          ::testing::AllOf(
              HasURL(link_with_referrer->HrefURL()),
              HasReferrerPolicy(network::mojom::ReferrerPolicy::kSameOrigin)),
          ::testing::AllOf(
              HasURL(link_with_rel_noreferrer->HrefURL()),
              HasReferrerPolicy(network::mojom::ReferrerPolicy::kNever)),
          ::testing::AllOf(
              HasURL(link_with_no_referrer->HrefURL()),
              HasReferrerPolicy(network::mojom::ReferrerPolicy::kStrictOrigin)),
          ::testing::AllOf(
              HasURL(link_with_invalid_referrer->HrefURL()),
              HasReferrerPolicy(
                  network::mojom::ReferrerPolicy::kStrictOrigin))));

  // Console message should have been logged for
  // |link_with_disallowed_referrer|.
  const auto& console_message_storage =
      page_holder.GetPage().GetConsoleMessageStorage();
  EXPECT_EQ(console_message_storage.size(), 1u);
  EXPECT_THAT(console_message_storage.at(0)->Nodes(),
              testing::Contains(link_with_disallowed_referrer->GetDomNodeId()));
}

// Tests that changing the "referrerpolicy" attribute results in the
// corresponding speculation candidate updating.
TEST_F(DocumentRulesTest, ReferrerPolicyAttributeChangeCausesLinkInvalidation) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* link_with_referrer = AddAnchor(*document.body(), "https://foo.com/abc");
  link_with_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                   AtomicString("same-origin"));
  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kSameOrigin)));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link_with_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                     AtomicString("strict-origin"));
  });
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kStrictOrigin)));
}

// Tests that changing the "rel" attribute results in the corresponding
// speculation candidate updating. Also tests that "rel=noreferrer" overrides
// the referrerpolicy attribute.
TEST_F(DocumentRulesTest, RelAttributeChangeCausesLinkInvalidation) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* link = AddAnchor(*document.body(), "https://foo.com/abc");
  link->setAttribute(html_names::kReferrerpolicyAttr,
                     AtomicString("same-origin"));

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kSameOrigin)));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link->setAttribute(html_names::kRelAttr, AtomicString("noreferrer"));
  });
  EXPECT_THAT(
      candidates,
      ElementsAre(HasReferrerPolicy(network::mojom::ReferrerPolicy::kNever)));
}

TEST_F(DocumentRulesTest, ReferrerMetaChangeShouldInvalidateCandidates) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  AddAnchor(*document.body(), "https://foo.com/abc");
  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(
      candidates,
      ElementsAre(HasReferrerPolicy(
          network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin)));

  auto* meta =
      MakeGarbageCollected<HTMLMetaElement>(document, CreateElementFlags());
  meta->setAttribute(html_names::kNameAttr, AtomicString("referrer"));
  meta->setAttribute(html_names::kContentAttr, AtomicString("strict-origin"));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    document.head()->appendChild(meta);
  });
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kStrictOrigin)));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    meta->setAttribute(html_names::kContentAttr, AtomicString("same-origin"));
  });
  EXPECT_THAT(candidates, ElementsAre(HasReferrerPolicy(
                              network::mojom::ReferrerPolicy::kSameOrigin)));
}

TEST_F(DocumentRulesTest, BaseURLChanged) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();
  document.SetBaseURLOverride(KURL("https://foo.com"));

  AddAnchor(*document.body(), "https://foo.com/bar");
  AddAnchor(*document.body(), "/bart");

  HTMLScriptElement* speculation_script;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    speculation_script = InsertSpeculationRules(page_holder.GetDocument(),
                                                R"(
      {"prefetch": [
        {"source": "document", "where": {"href_matches": "/bar*"}}
      ]}
    )");
  });
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar"),
                                  KURL("https://foo.com/bart")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    document.SetBaseURLOverride(KURL("https://bar.com"));
  });
  // After the base URL changes, "https://foo.com/bar" is matched against
  // "https://bar.com/bar*" and doesn't match. "/bart" is resolved to
  // "https://bar.com/bart" and matches with "https://bar.com/bar*".
  EXPECT_THAT(candidates, HasURLs("https://bar.com/bart"));

  // Test that removing the script causes the candidates to be removed.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      [&]() { speculation_script->remove(); });
  EXPECT_EQ(candidates.size(), 0u);
}

TEST_F(DocumentRulesTest, TargetHintFromLink) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* anchor_1 = AddAnchor(*document.body(), "https://foo.com/bar");
  anchor_1->setAttribute(html_names::kTargetAttr, AtomicString("_blank"));
  auto* anchor_2 = AddAnchor(*document.body(), "https://fizz.com/buzz");
  anchor_2->setAttribute(html_names::kTargetAttr, AtomicString("_self"));
  AddAnchor(*document.body(), "https://hello.com/world");

  String speculation_script = R"(
    {
      "prefetch": [{
        "source": "document",
        "where": {"href_matches": "https://foo.com/bar"}
      }],
      "prerender": [{"source": "document"}]
    }
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(
      candidates,
      ::testing::UnorderedElementsAre(
          ::testing::AllOf(
              HasAction(mojom::blink::SpeculationAction::kPrefetch),
              HasTargetHint(mojom::blink::SpeculationTargetHint::kNoHint)),
          ::testing::AllOf(
              HasURL(KURL("https://foo.com/bar")),
              HasAction(mojom::blink::SpeculationAction::kPrerender),
              HasTargetHint(mojom::blink::SpeculationTargetHint::kBlank)),
          ::testing::AllOf(
              HasURL(KURL("https://fizz.com/buzz")),
              HasAction(mojom::blink::SpeculationAction::kPrerender),
              HasTargetHint(mojom::blink::SpeculationTargetHint::kSelf)),
          ::testing::AllOf(
              HasURL(KURL("https://hello.com/world")),
              HasAction(mojom::blink::SpeculationAction::kPrerender),
              HasTargetHint(mojom::blink::SpeculationTargetHint::kNoHint))));
}

TEST_F(DocumentRulesTest, TargetHintFromSpeculationRuleOverridesLinkTarget) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* anchor = AddAnchor(*document.body(), "https://foo.com/bar");
  anchor->setAttribute(html_names::kTargetAttr, AtomicString("_blank"));

  String speculation_script = R"(
    {"prerender": [{"source": "document", "target_hint": "_self"}]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ::testing::ElementsAre(HasTargetHint(
                              mojom::blink::SpeculationTargetHint::kSelf)));
}

TEST_F(DocumentRulesTest, TargetHintFromLinkDynamic) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* anchor = AddAnchor(*document.body(), "https://foo.com/bar");

  String speculation_script = R"({"prerender": [{"source": "document"}]})";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, ::testing::ElementsAre(HasTargetHint(
                              mojom::blink::SpeculationTargetHint::kNoHint)));

  HTMLBaseElement* base_element;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    base_element = MakeGarbageCollected<HTMLBaseElement>(document);
    base_element->setAttribute(html_names::kTargetAttr, AtomicString("_self"));
    document.head()->appendChild(base_element);
  });
  EXPECT_THAT(candidates, ::testing::ElementsAre(HasTargetHint(
                              mojom::blink::SpeculationTargetHint::kSelf)));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    anchor->setAttribute(html_names::kTargetAttr, AtomicString("_blank"));
  });
  EXPECT_THAT(candidates, ::testing::ElementsAre(HasTargetHint(
                              mojom::blink::SpeculationTargetHint::kBlank)));
}

TEST_F(DocumentRulesTest, ParseSelectorMatches) {
  auto* simple_selector_matches = CreatePredicate(R"(
    "selector_matches": ".valid"
  )");
  EXPECT_THAT(simple_selector_matches,
              Selector({StyleRuleWithSelectorText(".valid")}));

  auto* simple_selector_matches_list = CreatePredicate(R"(
    "selector_matches": [".one", "#two"]
  )");
  EXPECT_THAT(simple_selector_matches_list,
              Selector({StyleRuleWithSelectorText(".one"),
                        StyleRuleWithSelectorText("#two")}));

  auto* selector_matches_with_compound_selector = CreatePredicate(R"(
    "selector_matches": ".interesting-section > a"
  )");
  EXPECT_THAT(
      selector_matches_with_compound_selector,
      Selector({StyleRuleWithSelectorText(".interesting-section > a")}));
}

TEST_F(DocumentRulesTest, GetStyleRules) {
  auto* predicate = CreatePredicate(R"(
    "and": [
      {"or": [
        {"not": {"selector_matches": "span.fizz > a"}},
        {"selector_matches": "#bar a"}
      ]},
      {"selector_matches": "a.foo"}
    ]
  )");
  EXPECT_THAT(
      predicate,
      And({Or({Neg(Selector({StyleRuleWithSelectorText("span.fizz > a")})),
               Selector({StyleRuleWithSelectorText("#bar a")})}),
           Selector({StyleRuleWithSelectorText("a.foo")})}));
  EXPECT_THAT(predicate->GetStyleRules(),
              UnorderedElementsAre(StyleRuleWithSelectorText("span.fizz > a"),
                                   StyleRuleWithSelectorText("#bar a"),
                                   StyleRuleWithSelectorText("a.foo")));
}

TEST_F(DocumentRulesTest, SelectorMatchesAddsCandidates) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/foo");
  AddAnchor(*unimportant_section, "https://foo.com/bar");
  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/foo"),
                                  KURL("https://foo.com/fizz")));
}

TEST_F(DocumentRulesTest, SelectorMatchesIsDynamic) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"or": [
        {"selector_matches": "#important-section > a"},
        {"selector_matches": ".important-link"}
      ]}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_TRUE(candidates.empty());

  HTMLAnchorElement* second_anchor = nullptr;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    AddAnchor(*important_section, "https://foo.com/fizz");
    second_anchor = AddAnchor(*unimportant_section, "https://foo.com/buzz");
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    second_anchor->setAttribute(html_names::kClassAttr,
                                AtomicString("important-link"));
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz"),
                                  KURL("https://foo.com/buzz")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->SetIdAttribute(AtomicString("random-section"));
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/buzz")));
}

TEST_F(DocumentRulesTest, AddingDocumentRulesInvalidatesStyle) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
  page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
  ASSERT_FALSE(document.NeedsLayoutTreeUpdate());

  auto* script_without_selector_matches = InsertSpeculationRules(document, R"(
    {"prefetch": [{"source": "document", "where": {"href_matches": "/foo"}}]}
  )");
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());

  auto* script_with_irrelevant_selector_matches =
      InsertSpeculationRules(document, R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#irrelevant a"}
    }]}
  )");
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());

  auto* script_with_selector_matches = InsertSpeculationRules(document, R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )");
  EXPECT_TRUE(important_section->ChildNeedsStyleRecalc());

  page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());

  // Test removing SpeculationRuleSets, removing a ruleset should also cause
  // invalidations.
  script_with_selector_matches->remove();
  EXPECT_TRUE(important_section->ChildNeedsStyleRecalc());
  page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();

  script_without_selector_matches->remove();
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());

  script_with_irrelevant_selector_matches->remove();
  ASSERT_FALSE(important_section->ChildNeedsStyleRecalc());
}

TEST_F(DocumentRulesTest, BasicStyleInvalidation) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);

  EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
  unimportant_section->SetIdAttribute(AtomicString("random-section"));
  EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
  unimportant_section->SetIdAttribute(AtomicString("important-section"));
  EXPECT_TRUE(document.NeedsLayoutTreeUpdate());
}

TEST_F(DocumentRulesTest, IrrelevantDOMChangeShouldNotInvalidateCandidateList) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz")));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        unimportant_section->SetIdAttribute(AtomicString("random-section"));
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));
}

TEST_F(DocumentRulesTest, SelectorMatchesInsideShadowTree) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  ShadowRoot& shadow_root =
      document.body()->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      shadow_root.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      shadow_root.getElementById(AtomicString("unimportant-section"));

  AddAnchor(*important_section, "https://foo.com/fizz");
  AddAnchor(*unimportant_section, "https://foo.com/buzz");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz")));
}

TEST_F(DocumentRulesTest, SelectorMatchesWithScopePseudoSelector) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setAttribute(html_names::kClassAttr, AtomicString("foo"));
  document.body()->setInnerHTML(R"HTML(
    <a href="https://foo.com/fizz"></a>
    <div class="foo">
      <a href="https://foo.com/buzz"></a>
    </div>
  )HTML");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": ":scope > .foo > a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz")));
}

// Basic test to check that we wait for UpdateStyle before sending a list of
// updated candidates to the browser process when "selector_matches" is
// enabled.
TEST_F(DocumentRulesTest, UpdateQueueingWithSelectorMatches_1) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="unimportant-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* unimportant_section =
      document.getElementById(AtomicString("unimportant-section"));

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"href_matches": "https://bar.com/*"}
    }]}
  )";
  // No update should be sent before running a style update after inserting
  // the rules.
  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
        InsertSpeculationRules(document, speculation_script);
      },
      IncludesStyleUpdate{false}));
  ASSERT_TRUE(document.NeedsLayoutTreeUpdate());
  // The list of candidates is updated after a style update.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, []() {});
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs());

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() { AddAnchor(*document.body(), "https://bar.com/fizz.html"); },
      IncludesStyleUpdate{false}));
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, []() {});
  EXPECT_THAT(candidates, HasURLs(KURL("https://bar.com/fizz.html")));

  String speculation_script_with_selector_matches = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  // Insert a speculation ruleset with "selector_matches". This will not require
  // a style update, as adding the ruleset itself will not cause any
  // invalidations (there are no existing elements that match the selector in
  // the new ruleset).
  PropagateRulesToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        InsertSpeculationRules(document,
                               speculation_script_with_selector_matches);
      },
      IncludesStyleUpdate{false});
  ASSERT_FALSE(document.NeedsLayoutTreeUpdate());
  EXPECT_THAT(candidates, HasURLs(KURL("https://bar.com/fizz.html")));

  // Add two new links. We should not update speculation candidates until we run
  // UpdateStyle.
  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        AddAnchor(*important_section, "https://foo.com/fizz.html");
        AddAnchor(*unimportant_section, "https://foo.com/buzz.html");
      },
      IncludesStyleUpdate{false}));
  ASSERT_TRUE(document.NeedsLayoutTreeUpdate());
  // Runs UpdateStyle; new speculation candidates should be sent.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, []() {});
  EXPECT_THAT(candidates, HasURLs(KURL("https://bar.com/fizz.html"),
                                  KURL("https://foo.com/fizz.html")));
}

// This tests that we don't need to wait for a style update if an operation
// does not invalidate style.
TEST_F(DocumentRulesTest, UpdateQueueingWithSelectorMatches_2) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  AddAnchor(*important_section, "https://foo.com/bar");
  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  // We shouldn't have to wait for UpdateStyle if the update doesn't cause
  // style invalidation.
  PropagateRulesToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
        auto* referrer_meta = MakeGarbageCollected<HTMLMetaElement>(
            document, CreateElementFlags());
        referrer_meta->setAttribute(html_names::kNameAttr,
                                    AtomicString("referrer"));
        referrer_meta->setAttribute(html_names::kContentAttr,
                                    AtomicString("strict-origin"));
        document.head()->appendChild(referrer_meta);
        EXPECT_FALSE(document.NeedsLayoutTreeUpdate());
      },
      IncludesStyleUpdate{false});
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));
}

// This tests a scenario where we queue an update microtask, invalidate style,
// update style, and then run the microtask.
TEST_F(DocumentRulesTest, UpdateQueueingWithSelectorMatches_3) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs());

  // Note: AddAnchor below will queue a microtask before invalidating style
  // (Node::InsertedInto is called before style invalidation).
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    AddAnchor(*important_section, "https://foo.com/bar.html");
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar.html")));
}

// This tests a scenario where we queue a microtask update, invalidate style,
// and then run the microtask.
TEST_F(DocumentRulesTest, UpdateQueueingWithSelectorMatches_4) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs());

  // A microtask will be queued and run before a style update - but no list of
  // candidates should be sent as style isn't clean. Note: AddAnchor below will
  // queue a microtask before invalidating style (Node::InsertedInto is called
  // before style invalidation).
  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() { AddAnchor(*important_section, "https://foo.com/bar"); },
      IncludesStyleUpdate{false}));
  ASSERT_TRUE(document.NeedsLayoutTreeUpdate());
  // Updating style should trigger UpdateSpeculationCandidates.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, []() {});
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));
}

// Tests update queueing after making a DOM modification that doesn't directly
// affect a link.
TEST_F(DocumentRulesTest, UpdateQueueingWithSelectorMatches_5) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* impor
"""


```