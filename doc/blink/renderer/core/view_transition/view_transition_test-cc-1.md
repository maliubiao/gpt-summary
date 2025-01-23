Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger test file for the View Transitions feature in the Chromium Blink rendering engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose of the code:** The code consists of several `TEST_P` blocks, indicating these are parameterized tests. Each test focuses on a specific aspect of the View Transitions functionality.

2. **Analyze each test case individually:** For each `TEST_P` block, determine what it's testing. Look for setup (`SetHtmlInnerHTML`), actions (like calling `startViewTransition`), and assertions (`EXPECT_*`, `ASSERT_*`).

3. **Relate to web technologies (JavaScript, HTML, CSS):**  View Transitions are triggered and controlled via JavaScript, and they manipulate the rendering of HTML elements based on CSS properties. Identify these connections in each test.

4. **Infer logical reasoning:**  Some tests involve setting up specific conditions (e.g., adding a class) and then checking the resulting state. This demonstrates a logical flow. Try to articulate the "if this input, then this output" for such cases.

5. **Identify potential user/programming errors:** Consider scenarios where a developer might misuse the View Transition API or CSS properties, and how the tests might be validating against those errors.

6. **Synthesize a high-level summary:** Combine the insights from the individual test cases into a concise description of the overall functionality being tested by this code snippet.

**Mental Walkthrough of the Code:**

* **`ViewTransitionNameResolution`**: Tests how `view-transition-name` is resolved for regular and pseudo-elements, including cases with and without the "root" name and tag-based names.
* **`VirtualKeyboardDoesntAffectSnapshotSize`**: Checks if the appearance of a virtual keyboard, which resizes the viewport, affects the size of the view transition snapshot. This is important for maintaining visual consistency.
* **`DocumentWithNoDocumentElementHasNullTransition`**:  Verifies that starting a view transition on a document without a `documentElement` (which is an unusual state) results in a null transition object, indicating a graceful failure.
* **`RootEffectLifetime`**:  Focuses on the lifecycle of the view transition effect applied to the root element. It checks if the necessary paint updates are triggered.
* **`PseudoAwareChildTraversal`**: Examines how the tree traversal methods (`PseudoAwareFirstChild`, `PseudoAwareLastChild`) work with the pseudo-elements created during a view transition. This is crucial for internal rendering logic.
* **`PseudoAwareSiblingTraversal`**: Similar to the above, but focuses on sibling traversal (`PseudoAwareNextSibling`, `PseudoAwarePreviousSibling`).
* **`IncludingPseudoTraversal`**: Tests the traversal methods that *include* pseudo-elements in the traversal, ensuring all relevant nodes are visited.
* **`GetAnimationsCrashTest`**: This is a specific regression test to prevent crashes related to sorting animations involving view transition pseudo-elements.
* **`ScriptCallAfterNavigationTransition`**:  Verifies that JavaScript callbacks associated with a view transition are executed correctly even after a navigation (page load).
* **`NoEffectOnIframe`**: Checks that view transitions initiated within an iframe don't have an effect on the parent document. View transitions are typically scoped to the current document.
* **`SubframeSnapshotLayer`**:  Tests the creation and behavior of the snapshot layer used for iframes during a view transition, including how it handles live content.

**Summarization:**

Based on the individual test analyses, the code snippet appears to be testing various edge cases and specific aspects of the View Transitions implementation, including:

* Correct resolution of `view-transition-name` styles.
* How viewport resizing (like due to a virtual keyboard) interacts with snapshots.
* Handling of invalid document states.
* Correct tree and sibling traversal including pseudo-elements.
* Prevention of crashes in animation handling.
* Interaction with navigation events.
* Scoping of view transitions to the current document (not affecting iframes).
* Snapshotting behavior for subframes.
好的，让我们归纳一下 `blink/renderer/core/view_transition/view_transition_test.cc` 这个文件的第 2 部分的功能。

**总而言之，这部分代码延续了第 1 部分的主题，即对 Blink 引擎中 View Transitions 功能进行全面的单元测试。它涵盖了更多特定的场景和边缘情况，以确保 View Transitions 功能的稳定性和正确性。**

具体来说，这部分代码着重测试了以下几个方面：

1. **`view-transition-name` 属性的解析和应用：**
   - 验证了在存在伪元素的情况下，`view-transition-name` 的正确解析逻辑。
   - 测试了当 CSS 规则中包含 `root` 关键字时，对根元素的 `view-transition-name` 处理。
   - 验证了标签选择器是否会影响伪元素的 `view-transition-name` 的匹配。

   **与 CSS 的关系：** 这些测试直接验证了 CSS 属性 `view-transition-name` 的行为和解析规则。

   **举例说明：**  `TEST_P(ViewTransitionTest, ViewTransitionNameResolution)`  测试用例通过定义不同的 HTML 结构和 CSS 规则，断言在不同情况下伪元素的 `view-transition-name` 是否被正确解析。例如，它会测试当一个伪元素同时匹配到通用规则和特定规则时，哪个规则会生效。

2. **虚拟键盘对快照大小的影响：**
   - 确认了虚拟键盘的出现和消失导致的视口大小变化，不会影响 View Transition 快照的尺寸。这确保了过渡效果不会因为虚拟键盘而产生不期望的变化。

   **与用户使用错误的关系：**  开发者可能担心虚拟键盘的出现会破坏 View Transitions 的视觉效果。这个测试表明 Blink 引擎已经考虑并处理了这种情况。

   **假设输入与输出：** 假设用户在页面中有一个设置了 `view-transition-name` 的元素，并且虚拟键盘出现导致视口高度缩小。测试验证了 View Transition 的快照大小仍然保持虚拟键盘出现之前的尺寸。

3. **在没有 `documentElement` 的文档上启动 View Transition 的处理：**
   - 测试了在一个没有 `documentElement` 的特殊文档对象上尝试启动 View Transition 的行为，预期会返回空值，避免程序崩溃或出现未定义行为。

   **与编程常见的使用错误的关系：** 开发者可能会在一些特殊情况下（例如，创建临时的、不完整的文档对象）错误地尝试启动 View Transition。这个测试验证了引擎的健壮性。

4. **根元素 View Transition Effect 的生命周期：**
   - 验证了对根元素应用 `view-transition-name: root;` 后，是否正确触发了布局和绘制更新，确保 View Transition 的效果能够正确应用。

   **与 CSS 的关系：**  直接关系到 CSS 属性 `view-transition-name` 在根元素上的应用。

5. **包含伪元素的子元素和兄弟元素遍历：**
   - 测试了在 View Transition 过程中创建的伪元素（例如 `::view-transition`, `::view-transition-group`, `::view-transition-image-pair` 等）在 DOM 树遍历中的行为，包括 `firstChild`, `lastChild`, `nextSibling`, `previousSibling` 等方法。
   - 验证了这些遍历方法能够正确地处理这些由 View Transition 产生的特殊伪元素。

   **与 JavaScript 和 HTML 的关系：** 这些测试验证了 JavaScript 中用于 DOM 遍历的 API (例如 `Node.firstChild`, `Node.nextSibling`)  在涉及到 View Transition 创建的伪元素时的行为是否符合预期。

   **假设输入与输出：**  假设一个包含了设置了 `view-transition-name` 的元素的 HTML 结构，启动 View Transition 后，测试会验证使用 `firstChild` 和 `lastChild` 能否正确访问到 `::view-transition-group` 伪元素。

6. **包含伪元素的完整节点树遍历：**
   - 使用 `NodeTraversal::NextIncludingPseudo` 和 `NodeTraversal::PreviousIncludingPseudo` 测试了包含所有伪元素的正向和反向节点树遍历，确保在 View Transition 期间能够完整地遍历整个 DOM 树。

7. **`getAnimations()` 方法的兼容性测试：**
   - 这是一个特殊的回归测试，旨在防止在调用 `getAnimations()` 方法时，由于涉及到 View Transition 的伪元素而导致程序崩溃。

   **与 JavaScript 的关系：**  `getAnimations()` 是 JavaScript 中用于获取元素动画的 API。这个测试确保了 View Transition 的伪元素不会干扰这个 API 的正常使用。

8. **导航后调用 View Transition 的脚本回调：**
   - 验证了在页面导航（例如 `pushState`）后，即使之前的 View Transition 仍在进行中，新的 View Transition 的脚本回调仍然能够被正确执行。

   **与 JavaScript 的关系：**  直接测试了 JavaScript 中启动 View Transition 的 API 以及其回调函数的执行时机。

9. **iframe 中不应用 View Transition 效果：**
   - 确认了在一个 iframe 内部启动的 View Transition 不会影响到主文档。View Transitions 的作用域通常限定在当前文档内。

   **与 HTML 的关系：**  涉及到 HTML 的 iframe 元素以及 View Transitions 在跨文档场景下的行为。

10. **iframe 快照图层的处理：**
    - 测试了在 iframe 上启动 View Transition 时，会创建快照图层，并且这个图层可以正确地在渲染过程中使用。
    - 验证了在提交新的合成器帧后，会创建一个新的快照图层。

**总结来说，这部分测试用例更加关注 View Transitions 功能的细节实现和与其他 Web 技术（如 CSS, JavaScript, HTML）的交互。它通过模拟各种场景和边缘情况，确保了 View Transitions 功能的健壮性、稳定性和与现有 Web 标准的兼容性。**

### 提示词
```
这是目录为blink/renderer/core/view_transition/view_transition_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
->pseudo_id != test_case.pseudo_id)
        continue;
      if (matched_rules->view_transition_name == "root") {
        EXPECT_FALSE(found_rule_for_root);
        found_rule_for_root = true;
        continue;
      }

      EXPECT_FALSE(matched_rules_for_pseudo);
      matched_rules_for_pseudo = matched_rules;
    }

    ASSERT_TRUE(matched_rules_for_pseudo);
    // Pseudo elements which are generated for each tag should include the root
    // by default.
    EXPECT_EQ(found_rule_for_root, test_case.uses_tags);
    EXPECT_EQ(matched_rules_for_pseudo->view_transition_name,
              test_case.uses_tags ? AtomicString("foo") : g_null_atom);

    auto pseudo_element_rules = matched_rules_for_pseudo->matched_rules;
    // The resolver collects developer and UA rules.
    EXPECT_GT(pseudo_element_rules->size(), 1u);
    EXPECT_EQ(pseudo_element_rules->back().first->cssText(),
              test_case.user_rule);
  }

  FinishTransition();
  UpdateAllLifecyclePhasesAndFinishDirectives();
}

TEST_P(ViewTransitionTest, VirtualKeyboardDoesntAffectSnapshotSize) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .target {
        contain: layout;
        width: 100px;
        height: 100px;
        view-transition-name: target;
      }
    </style>
    <div class="target">
    </div>
  )HTML");

  // Simulate a content-resizing virtual keyboard appearing.
  const int kVirtualKeyboardHeight = 50;
  gfx::Size original_size = web_view_helper_->GetWebView()->Size();

  ASSERT_GT(original_size.height(), kVirtualKeyboardHeight);
  gfx::Size new_size = gfx::Size(
      original_size.width(), original_size.height() - kVirtualKeyboardHeight);

  web_view_helper_->Resize(new_size);
  web_view_helper_->LocalMainFrame()
      ->FrameWidgetImpl()
      ->SetVirtualKeyboardResizeHeightForTesting(kVirtualKeyboardHeight);

  UpdateAllLifecyclePhasesForTest();

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesForTest();

  // The snapshot rect should not have been shrunk by the virtual keyboard, even
  // though it shrinks the WebView.
  EXPECT_EQ(transition->GetViewTransitionForTest()->GetSnapshotRootSize(),
            original_size);

  // The height of the ::view-transition should come from the snapshot root
  // rect.
  {
    auto* transition_pseudo = GetDocument().documentElement()->GetPseudoElement(
        kPseudoIdViewTransition);
    int height = To<LayoutBox>(transition_pseudo->GetLayoutObject())
                     ->GetPhysicalFragment(0)
                     ->Size()
                     .height.ToInt();
    EXPECT_EQ(height, original_size.height());
  }

  // Finish the prepare phase, mutate the DOM and start the animation.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  // Simulate hiding the virtual keyboard.
  web_view_helper_->Resize(original_size);
  web_view_helper_->LocalMainFrame()
      ->FrameWidgetImpl()
      ->SetVirtualKeyboardResizeHeightForTesting(0);

  // The snapshot rect should remain the same size.
  EXPECT_EQ(transition->GetViewTransitionForTest()->GetSnapshotRootSize(),
            original_size);

  // The start phase should generate pseudo elements for rendering new live
  // content.
  UpdateAllLifecyclePhasesAndFinishDirectives();

  // Finish the animations which should remove the pseudo element tree.
  FinishTransition();

  UpdateAllLifecyclePhasesAndFinishDirectives();
}

TEST_P(ViewTransitionTest, DocumentWithNoDocumentElementHasNullTransition) {
  auto* document =
      Document::CreateForTest(*GetDocument().GetExecutionContext());
  ASSERT_FALSE(document->documentElement());

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  DOMViewTransition* transition = ViewTransitionSupplement::startViewTransition(
      script_state, *document,
      V8ViewTransitionCallback::Create(start_setup_callback),
      IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_FALSE(transition);
}

TEST_P(ViewTransitionTest, RootEffectLifetime) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
    </style>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  EXPECT_TRUE(GetDocument().GetLayoutView()->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(
      transition->GetViewTransitionForTest()->NeedsViewTransitionEffectNode(
          *GetDocument().GetLayoutView()));
}

TEST_P(ViewTransitionTest, PseudoAwareChildTraversal) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      :root {
        view-transition-name: none;
      }
      :root.transitioned {
        view-transition-name: root;
      }
      #foo {
        view-transition-name: foo;
      }
      #bar {
        view-transition-name: bar;
      }
      .transitioned #bar {
        view-transition-name: none;
      }
    </style>
    <div id="foo"></div>
    <div id="bar"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        auto* document =
            static_cast<Document*>(info.Data().As<v8::External>()->Value());
        document->documentElement()->classList().Add(
            AtomicString("transitioned"));
      };

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(
          script_state->GetContext(), start_setup_lambda,
          v8::External::New(script_state->GetIsolate(), &GetDocument()))
          .ToLocalChecked();

  ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();

  auto* transition_pseudo = GetDocument().documentElement()->GetPseudoElement(
      kPseudoIdViewTransition);
  ASSERT_TRUE(transition_pseudo);

  EXPECT_EQ(GetDocument().documentElement()->PseudoAwareFirstChild(),
            static_cast<Node*>(GetDocument().head()));
  EXPECT_EQ(GetDocument().documentElement()->PseudoAwareLastChild(),
            transition_pseudo);

  // Root is last since it doesn't appear until encountered in the new view.
  auto* foo_group_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("foo"));
  auto* bar_group_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("bar"));
  auto* root_group_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("root"));

  EXPECT_EQ(transition_pseudo->PseudoAwareFirstChild(), foo_group_pseudo);
  EXPECT_EQ(transition_pseudo->PseudoAwareLastChild(), root_group_pseudo);

  auto* root_image_pair_pseudo = root_group_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionImagePair, AtomicString("root"));
  auto* foo_image_pair_pseudo = foo_group_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionImagePair, AtomicString("foo"));
  auto* bar_image_pair_pseudo = bar_group_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionImagePair, AtomicString("bar"));

  EXPECT_EQ(foo_group_pseudo->PseudoAwareFirstChild(), foo_image_pair_pseudo);
  EXPECT_EQ(foo_group_pseudo->PseudoAwareLastChild(), foo_image_pair_pseudo);

  auto* foo_old_pseudo = foo_image_pair_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionOld, AtomicString("foo"));
  auto* foo_new_pseudo = foo_image_pair_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionNew, AtomicString("foo"));

  EXPECT_EQ(foo_image_pair_pseudo->PseudoAwareFirstChild(), foo_old_pseudo);
  EXPECT_EQ(foo_image_pair_pseudo->PseudoAwareLastChild(), foo_new_pseudo);

  auto* bar_old_pseudo = bar_image_pair_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionOld, AtomicString("bar"));
  EXPECT_EQ(bar_image_pair_pseudo->PseudoAwareFirstChild(), bar_old_pseudo);
  EXPECT_EQ(bar_image_pair_pseudo->PseudoAwareLastChild(), bar_old_pseudo);

  auto* root_new_pseudo = root_image_pair_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionNew, AtomicString("root"));
  EXPECT_EQ(root_image_pair_pseudo->PseudoAwareFirstChild(), root_new_pseudo);
  EXPECT_EQ(root_image_pair_pseudo->PseudoAwareLastChild(), root_new_pseudo);
}

TEST_P(ViewTransitionTest, PseudoAwareSiblingTraversal) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      #foo {
        view-transition-name: foo;
      }
      #bar {
        view-transition-name: bar;
      }
    </style>
    <div id="foo"></div>
    <div id="bar"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();

  auto* transition_pseudo = GetDocument().documentElement()->GetPseudoElement(
      kPseudoIdViewTransition);
  ASSERT_TRUE(transition_pseudo);

  EXPECT_FALSE(transition_pseudo->PseudoAwareNextSibling());
  EXPECT_EQ(transition_pseudo->PseudoAwarePreviousSibling(),
            GetDocument().QuerySelector(AtomicString("body")));

  auto* foo_group_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("foo"));
  auto* bar_group_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("bar"));
  auto* root_group_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("root"));

  EXPECT_EQ(root_group_pseudo->PseudoAwareNextSibling(), foo_group_pseudo);
  EXPECT_EQ(root_group_pseudo->PseudoAwarePreviousSibling(), nullptr);

  EXPECT_EQ(foo_group_pseudo->PseudoAwareNextSibling(), bar_group_pseudo);
  EXPECT_EQ(foo_group_pseudo->PseudoAwarePreviousSibling(), root_group_pseudo);

  EXPECT_EQ(bar_group_pseudo->PseudoAwareNextSibling(), nullptr);
  EXPECT_EQ(bar_group_pseudo->PseudoAwarePreviousSibling(), foo_group_pseudo);

  auto* foo_image_pair_pseudo = foo_group_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionImagePair, AtomicString("foo"));
  auto* bar_image_pair_pseudo = bar_group_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionImagePair, AtomicString("bar"));

  EXPECT_FALSE(foo_image_pair_pseudo->PseudoAwareNextSibling());
  EXPECT_FALSE(foo_image_pair_pseudo->PseudoAwarePreviousSibling());
  EXPECT_FALSE(bar_image_pair_pseudo->PseudoAwareNextSibling());
  EXPECT_FALSE(bar_image_pair_pseudo->PseudoAwarePreviousSibling());

  auto* foo_old_pseudo = foo_image_pair_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionOld, AtomicString("foo"));
  auto* foo_new_pseudo = foo_image_pair_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionNew, AtomicString("foo"));

  EXPECT_EQ(foo_old_pseudo->PseudoAwareNextSibling(), foo_new_pseudo);
  EXPECT_EQ(foo_old_pseudo->PseudoAwarePreviousSibling(), nullptr);
  EXPECT_EQ(foo_new_pseudo->PseudoAwareNextSibling(), nullptr);
  EXPECT_EQ(foo_new_pseudo->PseudoAwarePreviousSibling(), foo_old_pseudo);
}

TEST_P(ViewTransitionTest, IncludingPseudoTraversal) {
  SetHtmlInnerHTML(R"HTML(
  <style>
    html { display: list-item; }
    html::marker {}
    html::before { content: ''}
    html::after { content: '' }
  </style>
  <div id="foo"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();

  Node* root = &GetDocument();
  Element* html = GetDocument().QuerySelector(AtomicString("html"));
  PseudoElement* vt = html->GetPseudoElement(kPseudoIdViewTransition);
  PseudoElement* vt_group =
      vt->GetPseudoElement(kPseudoIdViewTransitionGroup, AtomicString("root"));
  PseudoElement* vt_image_pair = vt_group->GetPseudoElement(
      kPseudoIdViewTransitionImagePair, AtomicString("root"));
  PseudoElement* vt_old = vt_image_pair->GetPseudoElement(
      kPseudoIdViewTransitionOld, AtomicString("root"));
  PseudoElement* vt_new = vt_image_pair->GetPseudoElement(
      kPseudoIdViewTransitionNew, AtomicString("root"));

  PseudoElement* marker = html->GetPseudoElement(kPseudoIdMarker);
  PseudoElement* before = html->GetPseudoElement(kPseudoIdBefore);
  PseudoElement* after = html->GetPseudoElement(kPseudoIdAfter);

  Element* head = GetDocument().QuerySelector(AtomicString("head"));
  Element* style = GetDocument().QuerySelector(AtomicString("style"));
  Element* body = GetDocument().QuerySelector(AtomicString("body"));
  Element* foo = GetDocument().QuerySelector(AtomicString("#foo"));

  HeapVector<Member<Node>> preorder_traversal = {
      root, html,  marker, before,   head,          body,   style,
      foo,  after, vt,     vt_group, vt_image_pair, vt_old, vt_new};

  HeapVector<Member<Node>> forward_traversal;
  for (Node* cur = preorder_traversal.front(); cur;
       cur = NodeTraversal::NextIncludingPseudo(*cur)) {
    // Simplify the test by ignoring whitespace.
    if (cur->IsTextNode()) {
      continue;
    }
    forward_traversal.push_back(cur);
  }
  EXPECT_EQ(preorder_traversal, forward_traversal);

  HeapVector<Member<Node>> backward_traversal;
  for (Node* cur = preorder_traversal.back(); cur;
       cur = NodeTraversal::PreviousIncludingPseudo(*cur)) {
    if (cur->IsTextNode()) {
      continue;
    }
    backward_traversal.push_back(cur);
  }

  preorder_traversal.Reverse();
  EXPECT_EQ(preorder_traversal, backward_traversal);
}

// This test was added because of a crash in getAnimations. The crash would
// occur because getAnimations attempts to sort the animations into compositing
// order. The comparator used uses tree order in some situations which requires
// pseudo elements to implement tree traversal methods. The crash occurred only
// on Android, probably due to differences in the std::sort implementation.
TEST_P(ViewTransitionTest, GetAnimationsCrashTest) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      #a {
        view-transition-name: a;
      }
      #b {
        view-transition-name: b;
      }
      #c {
        view-transition-name: c;
      }
      #d {
        view-transition-name: d;
      }
      #e {
        view-transition-name: e;
      }
      #f {
        view-transition-name: f;
      }
    </style>
    <div id="a"></div>
    <div id="b"></div>
    <div id="c"></div>
    <div id="d"></div>
    <div id="e"></div>
    <div id="f"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();

  // This test passes if getAnimations() doesn't crash while trying to sort the
  // view-transitions animations.
  ASSERT_GT(GetDocument().getAnimations().size(), 0ul);
}

TEST_P(ViewTransitionTest, ScriptCallAfterNavigationTransition) {
  GetDocument().domWindow()->GetSecurityContext().SetSecurityOriginForTesting(
      SecurityOrigin::Create(KURL("http://test.com")));
  GetDocument()
      .domWindow()
      ->GetFrame()
      ->Loader()
      .SetIsNotOnInitialEmptyDocument();

  auto* current_item = MakeGarbageCollected<HistoryItem>();
  current_item->SetURL(KURL("http://test.com"));
  GetDocument().domWindow()->navigation()->UpdateCurrentEntryForTesting(
      *current_item);

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto page_swap_params = mojom::blink::PageSwapEventParams::New();
  page_swap_params->url = KURL("http://test.com");
  page_swap_params->navigation_type =
      mojom::blink::NavigationTypeForNavigationApi::kPush;
  ViewTransitionSupplement::SnapshotDocumentForNavigation(
      GetDocument(), blink::ViewTransitionToken(), std::move(page_swap_params),
      base::BindOnce([](const ViewTransitionState&) {}));

  ASSERT_TRUE(ViewTransitionSupplement::From(GetDocument())->GetTransition());

  bool callback_issued = false;

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        auto* callback_issued =
            static_cast<bool*>(info.Data().As<v8::External>()->Value());
        *callback_issued = true;
      };
  auto start_setup_callback =
      v8::Function::New(
          script_state->GetContext(), start_setup_lambda,
          v8::External::New(script_state->GetIsolate(), &callback_issued))
          .ToLocalChecked();
  DOMViewTransition* script_transition =
      ViewTransitionSupplement::startViewTransition(
          script_state, GetDocument(),
          V8ViewTransitionCallback::Create(start_setup_callback),
          IGNORE_EXCEPTION_FOR_TESTING);

  EXPECT_TRUE(script_transition);

  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();

  EXPECT_TRUE(callback_issued);
}

TEST_P(ViewTransitionTest, NoEffectOnIframe) {
  SetHtmlInnerHTML(R"HTML(
    <iframe id=frame srcdoc="<html></html>"></iframe>
  )HTML");
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  auto& child_document =
      *To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild())
           ->GetDocument();
  ViewTransitionSupplement::startViewTransition(
      script_state, child_document,
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesForTest();
  auto* paint_properties =
      child_document.GetLayoutView()->FirstFragment().PaintProperties();
  EXPECT_TRUE(!paint_properties || !paint_properties->Effect());
}

TEST_P(ViewTransitionTest, SubframeSnapshotLayer) {
  SetHtmlInnerHTML(R"HTML(
    <iframe id=frame srcdoc="<html></html>"></iframe>
  )HTML");
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesForTest();

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  auto& child_document =
      *To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild())
           ->GetDocument();
  ViewTransitionSupplement::startViewTransition(
      script_state, child_document,
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);
  auto* transition = ViewTransitionUtils::GetTransition(child_document);
  ASSERT_TRUE(transition);

  UpdateAllLifecyclePhasesForTest();
  auto layer = transition->GetSubframeSnapshotLayer();
  ASSERT_TRUE(layer);
  EXPECT_TRUE(layer->is_live_content_layer_for_testing());

  child_document.GetPage()->GetChromeClient().WillCommitCompositorFrame();
  auto new_layer = transition->GetSubframeSnapshotLayer();
  ASSERT_TRUE(new_layer);
  EXPECT_NE(layer, new_layer);
  EXPECT_FALSE(new_layer->is_live_content_layer_for_testing());
}

}  // namespace blink
```