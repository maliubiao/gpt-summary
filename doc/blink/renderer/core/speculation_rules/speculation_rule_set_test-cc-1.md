Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the Chromium Blink engine. This file seems to be a test suite (`speculation_rule_set_test.cc`) for the `SpeculationRuleSet` functionality.

Here's a breakdown of the code's features:

1. **Parsing and Processing Speculation Rules:** The code tests how the engine parses and processes speculation rules defined in `<script type="speculationrules">` tags.
2. **Propagation to Browser:** It verifies that valid speculation rules are correctly propagated to the browser process (through Mojo interfaces).
3. **Filtering and Exclusion:** The tests confirm that certain URLs (like the current document's URL) are excluded from the speculation candidates.
4. **Handling Additions and Removals:** The code checks how the system handles the addition and removal of speculation rule scripts, even within the same task or across microtasks.
5. **Error Handling and Console Warnings:** It includes tests for how parsing errors and invalid rules are handled, ensuring that warnings are logged to the console.
6. **Use Counters:** The presence of speculation rules is tracked using use counters for telemetry.
7. **Document-based Rules (`where` clause):** The code also tests the parsing and processing of document-based rules, where the application of speculation rules is conditional based on the current document's properties (like URL or CSS selectors).

Based on this understanding, I can now provide a summary of the functionality in the context of part 2 of 6.
这是`blink/renderer/core/speculation_rules/speculation_rule_set_test.cc`文件的第二部分，主要功能是 **测试 `SpeculationRuleSet` 在以下方面的行为：向浏览器进程传播有效的推测规则，并处理推测规则的添加、移除以及可能出现的错误和警告。**

具体来说，这部分代码主要测试了：

1. **正确的推测规则传播:**
    *   当页面中插入包含有效推测规则的 `<script type="speculationrules">` 标签时，这些规则会被解析并传递给浏览器进程 (通过 Mojo 接口 `SpeculationHost`)。
    *   测试用例验证了不同类型的推测行为（如 `prefetch` 和 `prerender`）以及相关的配置项（如 `requires`）能够正确地被解析和传递。
    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **HTML:** 通过插入 `<script>` 标签将推测规则嵌入到 HTML 页面中。
        *   **JavaScript:** 虽然不是直接的 JavaScript 代码，但 `<script>` 标签的内容是 JSON 格式的推测规则，可以被 JavaScript 操作或动态生成。
        *   **CSS:**  在后续部分中，会涉及到通过 CSS 选择器来定义推测规则的应用条件。

    *   **假设输入与输出:**
        *   **假设输入:** 一个包含有效的 "prefetch" 和 "prerender" 规则的 JSON 字符串，例如：
            ```json
            {
              "prefetch": [
                { "source": "list", "urls": ["https://example.com/foo"] }
              ],
              "prerender": [
                { "source": "list", "urls": ["https://example.com/bar"] }
              ]
            }
            ```
        *   **预期输出:** `StubSpeculationHost` (一个测试用的模拟对象) 的 `candidates()` 方法会返回包含两个 `SpeculationCandidate` 对象的向量，分别对应 "prefetch" 和 "prerender" 规则，并且包含相应的 URL 和行为类型。

2. **规则的忽略 (基于 Flag):**
    *   测试了在特定功能 Flag 未启用的情况下，某些类型的推测规则会被忽略。例如，在 `SpeculationRulesPrefetchProxy` 未启用时，`prefetch_with_subresources` 规则会被忽略。
    *   这体现了 Chromium 的 Feature Flag 机制，用于控制新功能的启用和实验。

3. **Use Counter 记录:**
    *   验证了当页面中存在 `<script type="speculationrules">` 标签时，会记录相应的 Use Counter (`WebFeature::kSpeculationRules`)，用于统计功能的使用情况。
    *   也测试了 No-Vary-Search hint 的 Use Counter (`WebFeature::kSpeculationRulesNoVarySearchHint`) 的记录。

4. **排除当前页面 URL:**
    *   测试用例确保了当前页面的 URL 不会被添加到推测候选项中，避免不必要的自我推测。
    *   即使页面 URL 的 Hash 部分发生变化，也不会影响这个排除机制。
    *   `base` 标签的存在也不会影响对当前页面 URL 的排除。

5. **动态添加和移除规则:**
    *   测试了在同一个任务中添加和移除推测规则 `<script>` 标签的情况，验证了最终只会上报仍然存在的规则。
    *   也测试了先添加规则并上报，然后再移除规则的情况，确保移除操作也会被正确地传递给浏览器。
    *   特别测试了在微任务中移除规则的情况，确保了移除操作能够被异步处理。

6. **错误和警告处理:**
    *   测试了当推测规则的 JSON 格式不正确时，会在控制台输出警告信息。
    *   测试了当规则中的某个条目无效时（例如，URLs 不是字符串），也会在控制台输出警告。
    *   测试了使用 `innerHTML` 来设置 `<script type="speculationrules">` 标签的内容时，会输出警告，因为这种方式可能不会按预期工作。
    *   测试了修改已存在的 `<script type="speculationrules">` 标签的文本内容时，会输出警告，提示修改可能无效。
    *   测试了 JSON 中存在重复的 Key 时，会输出警告信息。
    *   测试了规则集或规则的格式不正确（例如，`prefetch` 不是数组，或者规则不是对象）时，会生成相应的错误信息。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **开发者在 HTML 页面中添加了 `<script type="speculationrules">` 标签。**
2. **开发者在 `<script>` 标签中编写了 JSON 格式的推测规则。** 可能是手动编写，也可能是通过 JavaScript 代码动态生成并插入。
3. **浏览器加载并解析 HTML 页面。**
4. **Blink 引擎识别到 `type="speculationrules"` 的 `<script>` 标签。**
5. **`SpeculationRuleSet` 相关代码开始解析 JSON 内容。** 如果 JSON 格式正确，规则会被提取出来。
6. **提取出的规则会通过 Mojo 接口传递给浏览器进程。** `PropagateRulesToStubSpeculationHost` 函数模拟了这个过程。
7. **如果 JSON 格式有误或者规则不符合规范，会触发相应的错误处理逻辑，并在控制台输出警告信息。**

在调试过程中，如果推测预加载或预渲染没有按预期工作，可以按照以下步骤排查：

1. **检查 HTML 源代码，确认 `<script type="speculationrules">` 标签是否存在并且 `type` 属性拼写正确。**
2. **打开浏览器的开发者工具 (Console 面板)，查看是否有关于推测规则的错误或警告信息。** 这些信息可以帮助定位 JSON 格式或规则本身的问题。
3. **检查 Network 面板，查看是否有预加载或预渲染的请求发出。** 这可以验证推测规则是否被成功解析和应用。
4. **使用 `chrome://net-internals/#prerender` 或 `chrome://net-internals/#events` 等内部页面来查看更详细的推测状态和事件。**
5. **如果怀疑是动态添加/删除规则的问题，可以在 JavaScript 代码中设置断点，观察规则的添加和删除时机，以及是否触发了预期的规则更新。**

总而言之，这部分测试代码集中验证了 `SpeculationRuleSet` 核心的解析和传播功能，以及对各种异常情况的处理机制，确保了推测规则能够正确地被识别、处理并传递给浏览器，从而实现预加载和预渲染等优化。

Prompt: 
```
这是目录为blink/renderer/core/speculation_rules/speculation_rule_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
"SpEcUlAtIoNrUlEs"));
  script->setText(
      R"({"prefetch": [
           {"source": "list", "urls": ["https://example.com/foo"]}
         ],
         "prerender": [
           {"source": "list", "urls": ["https://example.com/bar"]}
         ]
         })");
  document.head()->appendChild(script);

  auto* supplement = DocumentSpeculationRules::FromIfExists(document);
  ASSERT_TRUE(supplement);
  ASSERT_EQ(supplement->rule_sets().size(), 1u);
  SpeculationRuleSet* rule_set = supplement->rule_sets()[0];
  EXPECT_THAT(rule_set->prefetch_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/foo")));
  EXPECT_THAT(rule_set->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/bar")));
}

HTMLScriptElement* InsertSpeculationRules(Document& document,
                                          const String& speculation_script) {
  HTMLScriptElement* script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script->setAttribute(html_names::kTypeAttr, AtomicString("SpEcUlAtIoNrUlEs"));
  script->setText(speculation_script);
  document.head()->appendChild(script);
  return script;
}

using IncludesStyleUpdate =
    base::StrongAlias<class IncludesStyleUpdateTag, bool>;

// This runs the functor while observing any speculation rules sent by it.
// Since updates may be queued in a microtask or be blocked by style update,
// those are also awaited.
// At least one update is expected.
template <typename F>
void PropagateRulesToStubSpeculationHost(
    DummyPageHolder& page_holder,
    StubSpeculationHost& speculation_host,
    const F& functor,
    IncludesStyleUpdate includes_style_update = IncludesStyleUpdate{true}) {
  // A <script> with a case-insensitive type match should be propagated to the
  // browser via Mojo.
  // TODO(jbroman): Should we need to enable script? Should that be bypassed?
  LocalFrame& frame = page_holder.GetFrame();
  frame.GetSettings()->SetScriptEnabled(true);

  auto& broker = frame.DomWindow()->GetBrowserInterfaceBroker();
  broker.SetBinderForTesting(
      mojom::blink::SpeculationHost::Name_,
      WTF::BindRepeating(&StubSpeculationHost::BindUnsafe,
                         WTF::Unretained(&speculation_host)));

  base::RunLoop run_loop;
  speculation_host.SetDoneClosure(run_loop.QuitClosure());
  {
    auto* script_state = ToScriptStateForMainWorld(&frame);
    v8::MicrotasksScope microtasks_scope(script_state->GetIsolate(),
                                         ToMicrotaskQueue(script_state),
                                         v8::MicrotasksScope::kRunMicrotasks);
    functor();
    if (includes_style_update) {
      page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
    }
  }
  run_loop.Run();

  broker.SetBinderForTesting(mojom::blink::SpeculationHost::Name_, {});
}

void PropagateRulesToStubSpeculationHost(DummyPageHolder& page_holder,
                                         StubSpeculationHost& speculation_host,
                                         const String& speculation_script) {
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    InsertSpeculationRules(page_holder.GetDocument(), speculation_script);
  });
}

template <typename F>
testing::AssertionResult NoRulesPropagatedToStubSpeculationHost(
    DummyPageHolder& page_holder,
    StubSpeculationHost& speculation_host,
    const F& functor,
    IncludesStyleUpdate includes_style_update = IncludesStyleUpdate{true}) {
  LocalFrame& frame = page_holder.GetFrame();
  auto& broker = frame.DomWindow()->GetBrowserInterfaceBroker();
  broker.SetBinderForTesting(
      mojom::blink::SpeculationHost::Name_,
      WTF::BindRepeating(&StubSpeculationHost::BindUnsafe,
                         WTF::Unretained(&speculation_host)));

  bool done_was_called = false;

  base::RunLoop run_loop;
  speculation_host.SetDoneClosure(base::BindLambdaForTesting(
      [&done_was_called] { done_was_called = true; }));
  {
    auto* script_state = ToScriptStateForMainWorld(&frame);
    v8::MicrotasksScope microtasks_scope(script_state->GetIsolate(),
                                         ToMicrotaskQueue(script_state),
                                         v8::MicrotasksScope::kRunMicrotasks);
    functor();
    if (includes_style_update) {
      page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
    }
  }
  run_loop.RunUntilIdle();

  broker.SetBinderForTesting(mojom::blink::SpeculationHost::Name_, {});
  return done_was_called ? testing::AssertionFailure()
                         : testing::AssertionSuccess();
}

TEST_F(SpeculationRuleSetTest, PropagatesAllRulesToBrowser) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  const String speculation_script =
      R"({"prefetch": [
           {"source": "list",
            "urls": ["https://example.com/foo", "https://example.com/bar"],
            "requires": ["anonymous-client-ip-when-cross-origin"]}
         ],
          "prerender": [
           {"source": "list", "urls": ["https://example.com/prerender"]}
         ]
         })";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);

  const auto& candidates = speculation_host.candidates();
  ASSERT_EQ(candidates.size(), 3u);
  {
    const auto& candidate = candidates[0];
    EXPECT_EQ(candidate->action, mojom::blink::SpeculationAction::kPrefetch);
    EXPECT_EQ(candidate->url, "https://example.com/foo");
    EXPECT_TRUE(candidate->requires_anonymous_client_ip_when_cross_origin);
  }
  {
    const auto& candidate = candidates[1];
    EXPECT_EQ(candidate->action, mojom::blink::SpeculationAction::kPrefetch);
    EXPECT_EQ(candidate->url, "https://example.com/bar");
    EXPECT_TRUE(candidate->requires_anonymous_client_ip_when_cross_origin);
  }
  {
    const auto& candidate = candidates[2];
    EXPECT_EQ(candidate->action, mojom::blink::SpeculationAction::kPrerender);
    EXPECT_EQ(candidate->url, "https://example.com/prerender");
  }
}

// Tests that prefetch rules are ignored unless SpeculationRulesPrefetchProxy
// is enabled.
TEST_F(SpeculationRuleSetTest, PrerenderIgnorePrefetchRules) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  const String speculation_script =
      R"({"prefetch_with_subresources": [
           {"source": "list",
            "urls": ["https://example.com/foo", "https://example.com/bar"],
            "requires": ["anonymous-client-ip-when-cross-origin"]}
         ],
          "prerender": [
           {"source": "list", "urls": ["https://example.com/prerender"]}
         ]
         })";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);

  const auto& candidates = speculation_host.candidates();
  EXPECT_EQ(candidates.size(), 1u);
  EXPECT_FALSE(base::ranges::any_of(candidates, [](const auto& candidate) {
    return candidate->action ==
           mojom::blink::SpeculationAction::kPrefetchWithSubresources;
  }));
}

// Tests that prerender rules are ignored unless Prerender2 is enabled.
TEST_F(SpeculationRuleSetTest, PrefetchIgnorePrerenderRules) {
  // Overwrite the kPrerender2 flag.
  ScopedPrerender2ForTest enable_prerender{false};

  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  const String speculation_script =
      R"({"prefetch": [
           {"source": "list",
            "urls": ["https://example.com/foo", "https://example.com/bar"],
            "requires": ["anonymous-client-ip-when-cross-origin"]}
         ],
          "prerender": [
           {"source": "list", "urls": ["https://example.com/prerender"]}
         ]
         })";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);

  const auto& candidates = speculation_host.candidates();
  EXPECT_EQ(candidates.size(), 2u);
  EXPECT_FALSE(base::ranges::any_of(candidates, [](const auto& candidate) {
    return candidate->action == mojom::blink::SpeculationAction::kPrerender;
  }));
}

// Tests that the presence of a speculationrules script is recorded.
TEST_F(SpeculationRuleSetTest, UseCounter) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
  EXPECT_FALSE(
      page_holder.GetDocument().IsUseCounted(WebFeature::kSpeculationRules));

  const String speculation_script =
      R"({"prefetch": [{"source": "list", "urls": ["/foo"]}]})";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  EXPECT_TRUE(
      page_holder.GetDocument().IsUseCounted(WebFeature::kSpeculationRules));
}

// Tests that the presence of a speculationrules No-Vary-Search hint is
// recorded.
TEST_F(SpeculationRuleSetTest, NoVarySearchHintUseCounter) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
  EXPECT_FALSE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesNoVarySearchHint));

  const String speculation_script =
      R"nvs({"prefetch": [{
        "source": "list",
        "urls": ["/foo"],
        "expects_no_vary_search": "params=(\"a\")"
      }]})nvs";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  EXPECT_TRUE(page_holder.GetDocument().IsUseCounted(
      WebFeature::kSpeculationRulesNoVarySearchHint))
      << "No-Vary-Search hint functionality is counted";
}

// Tests that the document's URL is excluded from candidates.
TEST_F(SpeculationRuleSetTest, ExcludesFragmentLinks) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  page_holder.GetDocument().SetURL(KURL("https://example.com/"));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      String(R"({"prefetch": [
           {"source": "list", "urls":
              ["https://example.com/", "#foo", "/b#bar"]}]})"));
  EXPECT_THAT(
      speculation_host.candidates(),
      HasURLs(KURL("https://example.com"), KURL("https://example.com/b#bar")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&] {
    page_holder.GetDocument().SetURL(KURL("https://example.com/b"));
  });
  EXPECT_THAT(speculation_host.candidates(),
              HasURLs(KURL("https://example.com")));
}

// Tests that the document's URL is excluded from candidates, even when its
// changes do not affect the base URL.
TEST_F(SpeculationRuleSetTest, ExcludesFragmentLinksWithBase) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  page_holder.GetDocument().SetURL(KURL("https://example.com/"));
  page_holder.GetDocument().head()->setInnerHTML(
      "<base href=\"https://not-example.com/\">");

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      String(R"({"prefetch": [
           {"source": "list", "urls":
              ["https://example.com/#baz", "#foo", "/b#bar"]}]})"));
  EXPECT_THAT(speculation_host.candidates(),
              HasURLs(KURL("https://not-example.com/#foo"),
                      KURL("https://not-example.com/b#bar")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&] {
    page_holder.GetDocument().SetURL(KURL("https://example.com/b"));
  });
  EXPECT_THAT(speculation_host.candidates(),
              HasURLs(KURL("https://example.com/#baz"),
                      KURL("https://not-example.com/#foo"),
                      KURL("https://not-example.com/b#bar")));
}

// Tests that rules removed before the task to update speculation candidates
// runs are not reported.
TEST_F(SpeculationRuleSetTest, AddAndRemoveInSameTask) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    InsertSpeculationRules(page_holder.GetDocument(),
                           R"({"prefetch": [
             {"source": "list", "urls": ["https://example.com/foo"]}]})");
    HTMLScriptElement* to_remove =
        InsertSpeculationRules(page_holder.GetDocument(),
                               R"({"prefetch": [
             {"source": "list", "urls": ["https://example.com/bar"]}]})");
    InsertSpeculationRules(page_holder.GetDocument(),
                           R"({"prefetch": [
             {"source": "list", "urls": ["https://example.com/baz"]}]})");
    to_remove->remove();
  });

  const auto& candidates = speculation_host.candidates();
  ASSERT_EQ(candidates.size(), 2u);
  EXPECT_EQ(candidates[0]->url, "https://example.com/foo");
  EXPECT_EQ(candidates[1]->url, "https://example.com/baz");
}

// Tests that rules removed after being previously reported are reported as
// removed.
TEST_F(SpeculationRuleSetTest, AddAndRemoveAfterReport) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  HTMLScriptElement* to_remove = nullptr;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    InsertSpeculationRules(page_holder.GetDocument(),
                           R"({"prefetch": [
             {"source": "list", "urls": ["https://example.com/foo"]}]})");
    to_remove = InsertSpeculationRules(page_holder.GetDocument(),
                                       R"({"prefetch": [
             {"source": "list", "urls": ["https://example.com/bar"]}]})");
    InsertSpeculationRules(page_holder.GetDocument(),
                           R"({"prefetch": [
             {"source": "list", "urls": ["https://example.com/baz"]}]})");
  });

  {
    const auto& candidates = speculation_host.candidates();
    ASSERT_EQ(candidates.size(), 3u);
    EXPECT_EQ(candidates[0]->url, "https://example.com/foo");
    EXPECT_EQ(candidates[1]->url, "https://example.com/bar");
    EXPECT_EQ(candidates[2]->url, "https://example.com/baz");
  }

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      [&]() { to_remove->remove(); });

  {
    const auto& candidates = speculation_host.candidates();
    ASSERT_EQ(candidates.size(), 2u);
    EXPECT_EQ(candidates[0]->url, "https://example.com/foo");
    EXPECT_EQ(candidates[1]->url, "https://example.com/baz");
  }
}

// Tests that removed candidates are reported in a microtask.
// This is somewhat difficult to observe in practice, but most sharply visible
// if a removal occurs and then in a subsequent microtask an addition occurs.
TEST_F(SpeculationRuleSetTest, RemoveInMicrotask) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  base::RunLoop run_loop;
  base::MockCallback<base::RepeatingCallback<void(
      const Vector<mojom::blink::SpeculationCandidatePtr>&)>>
      mock_callback;
  {
    ::testing::InSequence sequence;
    EXPECT_CALL(mock_callback, Run(::testing::SizeIs(2)));
    EXPECT_CALL(mock_callback, Run(::testing::SizeIs(1)));
    EXPECT_CALL(mock_callback, Run(::testing::SizeIs(2)))
        .WillOnce(::testing::Invoke([&]() { run_loop.Quit(); }));
  }
  speculation_host.SetCandidatesUpdatedCallback(mock_callback.Get());

  LocalFrame& frame = page_holder.GetFrame();
  frame.GetSettings()->SetScriptEnabled(true);
  auto& broker = frame.DomWindow()->GetBrowserInterfaceBroker();
  broker.SetBinderForTesting(
      mojom::blink::SpeculationHost::Name_,
      WTF::BindRepeating(&StubSpeculationHost::BindUnsafe,
                         WTF::Unretained(&speculation_host)));

  // First simulated task adds the rule sets.
  InsertSpeculationRules(page_holder.GetDocument(),
                         R"({"prefetch": [
           {"source": "list", "urls": ["https://example.com/foo"]}]})");
  HTMLScriptElement* to_remove =
      InsertSpeculationRules(page_holder.GetDocument(),
                             R"({"prefetch": [
             {"source": "list", "urls": ["https://example.com/bar"]}]})");
  scoped_refptr<scheduler::EventLoop> event_loop =
      frame.DomWindow()->GetAgent()->event_loop();
  event_loop->PerformMicrotaskCheckpoint();
  frame.View()->UpdateAllLifecyclePhasesForTest();

  // Second simulated task removes the rule sets, then adds another one in a
  // microtask which is queued later than any queued during the removal.
  to_remove->remove();
  event_loop->EnqueueMicrotask(base::BindLambdaForTesting([&] {
    InsertSpeculationRules(page_holder.GetDocument(),
                           R"({"prefetch": [
           {"source": "list", "urls": ["https://example.com/baz"]}]})");
  }));
  event_loop->PerformMicrotaskCheckpoint();

  run_loop.Run();
  broker.SetBinderForTesting(mojom::blink::SpeculationHost::Name_, {});
}

class ConsoleCapturingChromeClient : public EmptyChromeClient {
 public:
  void AddMessageToConsole(LocalFrame*,
                           mojom::ConsoleMessageSource,
                           mojom::ConsoleMessageLevel,
                           const String& message,
                           unsigned line_number,
                           const String& source_id,
                           const String& stack_trace) override {
    messages_.push_back(message);
  }

  const Vector<String>& ConsoleMessages() const { return messages_; }

 private:
  Vector<String> messages_;
};

// Tests that parse errors are logged to the console.
TEST_F(SpeculationRuleSetTest, ConsoleWarning) {
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);

  Document& document = page_holder.GetDocument();
  HTMLScriptElement* script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script->setAttribute(html_names::kTypeAttr, AtomicString("speculationrules"));
  script->setText("[invalid]");
  document.head()->appendChild(script);

  EXPECT_TRUE(base::ranges::any_of(
      chrome_client->ConsoleMessages(),
      [](const String& message) { return message.Contains("Syntax error"); }));
}

// Tests that errors of individual rules which cause them to be ignored are
// logged to the console.
TEST_F(SpeculationRuleSetTest, ConsoleWarningForInvalidRule) {
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);

  Document& document = page_holder.GetDocument();
  HTMLScriptElement* script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script->setAttribute(html_names::kTypeAttr, AtomicString("speculationrules"));
  script->setText(
      R"({
        "prefetch": [{
          "source": "list",
          "urls": [["a", ".", "c", "o", "m"]]
        }]
      })");
  document.head()->appendChild(script);

  EXPECT_TRUE(base::ranges::any_of(
      chrome_client->ConsoleMessages(), [](const String& message) {
        return message.Contains("URLs must be given as strings");
      }));
}

// Tests that a warning is shown when speculation rules are added using the
// innerHTML setter, which doesn't currently do what the author meant.
TEST_F(SpeculationRuleSetTest, ConsoleWarningForSetInnerHTML) {
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);

  Document& document = page_holder.GetDocument();
  document.head()->setInnerHTML("<script type=speculationrules>{}</script>");

  EXPECT_TRUE(base::ranges::any_of(
      chrome_client->ConsoleMessages(), [](const String& message) {
        return message.Contains("speculation rule") &&
               message.Contains("will be ignored");
      }));
}

// Tests that a console warning mentions that child modifications are
// ineffective.
TEST_F(SpeculationRuleSetTest, ConsoleWarningForChildModification) {
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);

  Document& document = page_holder.GetDocument();
  HTMLScriptElement* script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script->setAttribute(html_names::kTypeAttr, AtomicString("speculationrules"));
  script->setText("{}");
  document.head()->appendChild(script);

  script->setText(R"({"prefetch": [{"urls": "/2"}]})");

  EXPECT_TRUE(base::ranges::any_of(
      chrome_client->ConsoleMessages(), [](const String& message) {
        return message.Contains("speculation rule") &&
               message.Contains("modified");
      }));
}

// Tests that a console warning mentions duplicate keys.
TEST_F(SpeculationRuleSetTest, ConsoleWarningForDuplicateKey) {
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);

  Document& document = page_holder.GetDocument();
  HTMLScriptElement* script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script->setAttribute(html_names::kTypeAttr, AtomicString("speculationrules"));
  script->setText(
      R"({
        "prefetch": [{"urls": ["a.html"]}],
        "prefetch": [{"urls": ["b.html"]}]
      })");
  document.head()->appendChild(script);

  EXPECT_TRUE(base::ranges::any_of(
      chrome_client->ConsoleMessages(), [](const String& message) {
        return message.Contains("speculation rule") &&
               message.Contains("more than one") &&
               message.Contains("prefetch");
      }));
}
TEST_F(SpeculationRuleSetTest, DropNotArrayAtRuleSetPosition) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": "invalid"
      })",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains(
      "A rule set for a key must be an array: path = [\"prefetch\"]"))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, DropNotObjectAtRulePosition) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": ["invalid"]
      })",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains(
      "A rule must be an object: path = [\"prefetch\"][0]"))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
}

MATCHER_P(MatchesPredicate,
          matcher,
          ::testing::DescribeMatcher<DocumentRulePredicate*>(matcher)) {
  if (!arg->predicate()) {
    *result_listener << "does not have a predicate";
    return false;
  }
  return ExplainMatchResult(matcher, arg->predicate(), result_listener);
}

String GetTypeString(DocumentRulePredicate::Type type) {
  switch (type) {
    case DocumentRulePredicate::Type::kAnd:
      return "And";
    case DocumentRulePredicate::Type::kOr:
      return "Or";
    case DocumentRulePredicate::Type::kNot:
      return "Not";
    case DocumentRulePredicate::Type::kURLPatterns:
      return "Href";
    case DocumentRulePredicate::Type::kCSSSelectors:
      return "Selector";
  }
}

template <typename ItemType>
class PredicateMatcher {
 public:
  using DocumentRulePredicateGetter =
      HeapVector<Member<ItemType>> (DocumentRulePredicate::*)() const;

  explicit PredicateMatcher(Vector<::testing::Matcher<ItemType*>> matchers,
                            DocumentRulePredicate::Type type,
                            DocumentRulePredicateGetter getter)
      : matchers_(std::move(matchers)), type_(type), getter_(getter) {}

  bool MatchAndExplain(DocumentRulePredicate* predicate,
                       ::testing::MatchResultListener* listener) const {
    if (!predicate) {
      return false;
    }

    if (predicate->GetTypeForTesting() != type_) {
      *listener << predicate->ToString();
      return false;
    }

    HeapVector<Member<ItemType>> items = ((*predicate).*(getter_))();
    if (items.size() != matchers_.size()) {
      *listener << predicate->ToString();
      return false;
    }

    ::testing::StringMatchResultListener inner_listener;
    for (wtf_size_t i = 0; i < matchers_.size(); i++) {
      if (!matchers_[i].MatchAndExplain(items[i], &inner_listener)) {
        *listener << predicate->ToString();
        return false;
      }
    }
    return true;
  }

  void DescribeTo(::std::ostream* os) const {
    *os << GetTypeString(type_) << "([";
    for (wtf_size_t i = 0; i < matchers_.size(); i++) {
      matchers_[i].DescribeTo(os);
      if (i != matchers_.size() - 1) {
        *os << ", ";
      }
    }
    *os << "])";
  }

  void DescribeNegationTo(::std::ostream* os) const { DescribeTo(os); }

 private:
  Vector<::testing::Matcher<ItemType*>> matchers_;
  DocumentRulePredicate::Type type_;
  DocumentRulePredicateGetter getter_;
};

template <typename ItemType>
auto MakePredicateMatcher(
    Vector<::testing::Matcher<ItemType*>> matchers,
    DocumentRulePredicate::Type type,
    typename PredicateMatcher<ItemType>::DocumentRulePredicateGetter getter) {
  return testing::MakePolymorphicMatcher(
      PredicateMatcher<ItemType>(std::move(matchers), type, getter));
}

auto MakeConditionMatcher(
    Vector<::testing::Matcher<DocumentRulePredicate*>> matchers,
    DocumentRulePredicate::Type type) {
  return MakePredicateMatcher(
      std::move(matchers), type,
      &DocumentRulePredicate::GetSubPredicatesForTesting);
}

auto And(Vector<::testing::Matcher<DocumentRulePredicate*>> matchers = {}) {
  return MakeConditionMatcher(std::move(matchers),
                              DocumentRulePredicate::Type::kAnd);
}

auto Or(Vector<::testing::Matcher<DocumentRulePredicate*>> matchers = {}) {
  return MakeConditionMatcher(std::move(matchers),
                              DocumentRulePredicate::Type::kOr);
}

auto Neg(::testing::Matcher<DocumentRulePredicate*> matcher) {
  return MakeConditionMatcher({matcher}, DocumentRulePredicate::Type::kNot);
}

auto Href(Vector<::testing::Matcher<URLPattern*>> pattern_matchers = {}) {
  return MakePredicateMatcher(std::move(pattern_matchers),
                              DocumentRulePredicate::Type::kURLPatterns,
                              &DocumentRulePredicate::GetURLPatternsForTesting);
}

auto Selector(Vector<::testing::Matcher<StyleRule*>> style_rule_matchers = {}) {
  return MakePredicateMatcher(std::move(style_rule_matchers),
                              DocumentRulePredicate::Type::kCSSSelectors,
                              &DocumentRulePredicate::GetStyleRulesForTesting);
}

class StyleRuleMatcher {
 public:
  explicit StyleRuleMatcher(String selector_text)
      : selector_text_(std::move(selector_text)) {}

  bool MatchAndExplain(StyleRule* style_rule,
                       ::testing::MatchResultListener* listener) const {
    if (!style_rule) {
      return false;
    }
    return style_rule->SelectorsText() == selector_text_;
  }

  void DescribeTo(::std::ostream* os) const { *os << selector_text_; }

  void DescribeNegationTo(::std::ostream* os) const { DescribeTo(os); }

 private:
  String selector_text_;
};

auto StyleRuleWithSelectorText(String selector_text) {
  return ::testing::MakePolymorphicMatcher(StyleRuleMatcher(selector_text));
}

class DocumentRulesTest : public SpeculationRuleSetTest {
 public:
  ~DocumentRulesTest() override = default;

  DocumentRulePredicate* CreatePredicate(
      String where_text,
      KURL base_url = KURL("https://example.com/")) {
    auto* rule_set = CreateRuleSetWithPredicate(where_text, base_url);
    DCHECK(!rule_set->prefetch_rules().empty())
        << "Invalid predicate: " << rule_set->error_message();
    return rule_set->prefetch_rules()[0]->predicate();
  }

  String CreateInvalidPredicate(String where_text) {
    auto* rule_set =
        CreateRuleSetWithPredicate(where_text, KURL("https://example.com"));
    EXPECT_TRUE(!rule_set || rule_set->prefetch_rules().empty())
        << "Rule set is valid.";
    return rule_set->error_message();
  }

 private:
  SpeculationRuleSet* CreateRuleSetWithPredicate(String where_text,
                                                 KURL base_url) {
    // clang-format off
    auto* rule_set =
        CreateRuleSet(
          String::Format(
            R"({
              "prefetch": [{
                "source": "document",
                "where": {%s}
              }]
            })",
            where_text.Latin1().c_str()),
          base_url, execution_context());
    // clang-format on
    return rule_set;
  }
};

TEST_F(DocumentRulesTest, ParseAnd) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "document",
          "where": { "and": [] }
        }, {
          "source": "document",
          "where": {"and": [{"and": []}, {"and": []}]}
        }]
      })",
      KURL("https://example.com/"), execution_context());
  EXPECT_THAT(rule_set->prefetch_rules(),
              ElementsAre(MatchesPredicate(And()),
                          MatchesPredicate(And({And(), And()}))));
}

TEST_F(DocumentRulesTest, ParseOr) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "document",
          "where": { "or": [] }
        }, {
          "source": "document",
          "where": {"or": [{"and": []}, {"or": []}]}
        }]
      })",
      KURL("https://example.com/"), execution_context());
  EXPECT_THAT(
      rule_set->prefetch_rules(),
      ElementsAre(MatchesPredicate(Or()), MatchesPredicate(Or({And(), Or()}))));
}

TEST_F(DocumentRulesTest, ParseNot) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "document",
          "where": {"not": {"and": []}}
        }, {
          "source": "document",
          "where": {"not": {"or": [{"and": []}, {"or": []}]}}
        }]
      })",
      KURL("https://example.com/"), execution_context());
  EXPECT_THAT(rule_set->prefetch_rules(),
              ElementsAre(MatchesPredicate(Neg(And())),
                          MatchesPredicate(Neg(Or({And(), Or()})))));
}

TEST_F(DocumentRulesTest, ParseHref) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "document",
          "where": {"href_matches": "/foo#bar"}
        }, {
          "source": "document",
          "where": {"href_matches": {"pathname": "/foo"}}
        }, {
          "source": "document",
          "where": {"href_matches": [
            {"pathname": "/buzz"},
            "/fizz",
            {"hostname": "bar.com"}
          ]}
        }, {
          "source": "document",
          "where": {"or": [
            {"href_matches": {"hostname": "foo.com"}},
            {"not": {"href_matches": {"protocol": "http", "hostname": "*"}}}
          ]}
        }]
      })",
      KURL("https://example.com/"), execution_context());
  EXPECT_THAT(
      rule_set->prefetch_rules(),
      ElementsAre(
          MatchesPredicate(Href({URLPattern("/foo#bar")})),
          MatchesPredicate(Href({URLPattern("/foo")})),
          MatchesPredicate(Href({URLPattern("/buzz"), URLPattern("/fizz"),
                                 URLPattern("https://bar.com:*")})),
          MatchesPredicate(Or({Href({URLPattern("https://foo.com:*")}),
                               Neg(Href({URLPattern("http://*:*")}))}))));
}

TEST_F(DocumentRulesTest, ParseHref_AllUrlPatternKeys) {
  auto* href_matches = CreatePredicate(R"("href_matches": {
    "username": "",
    "password": "",
    "port": "*",
    "pathname": "/*",
    "search": "*",
    "hash": "",
    "protocol": "https",
    "hostname": "abc.xyz",
    "baseURL": "https://example.com"
  })");
  EXPECT_THAT(href_matches, Href({URLPattern("https://:@abc.xyz:*/*\\?*#")}));
}

TEST_F(DocumentRulesTest, HrefMatchesWithBaseURL) {
  auto* without_base_specified = CreatePredicate(
      R"("href_matches": {"pathname": "/hello"}
"""


```