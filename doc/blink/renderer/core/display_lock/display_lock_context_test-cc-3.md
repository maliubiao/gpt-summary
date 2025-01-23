Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a test file for the `DisplayLockContext` in the Chromium Blink engine.

Here's a plan to summarize the code:

1. **Identify the core purpose of the file:** It tests the `DisplayLockContext` class.
2. **Analyze the individual test cases:** Each test case focuses on a specific aspect of the `DisplayLockContext`'s behavior.
3. **Group related test cases:**  Look for common themes or functionalities being tested.
4. **Summarize each group of tests:** Describe the functionality being verified by the group.
5. **Identify interactions with web technologies (HTML, CSS, JavaScript):**  Note how the tests use HTML and CSS properties to trigger different `DisplayLockContext` behaviors.
6. **Look for examples of logical reasoning and assumptions:** Analyze test cases that involve conditional behavior based on input or state.
7. **Identify potential user or programming errors:** Note test cases that demonstrate how incorrect usage or edge cases are handled.
8. **Organize the summary into functional categories.**

Based on the test names and the code itself, I can identify the following functionalities being tested:

* **Basic Locking/Unlocking:**  How `content-visibility: hidden` and other factors affect the lock state.
* **Nested Locks:** How nested `content-visibility` properties interact.
* **Layout and Rendering:** How display locks affect layout, paint, and visibility.
* **Lifecycle Observation:** How `DisplayLockContext` observes and reacts to document lifecycle events.
* **Offscreen Visibility:** How offscreen elements with display locks are handled.
* **Focusability:** How display locks interact with focus.
* **Forced Updates:**  How forced updates bypass display locks.
* **Use Counters:** Tracking usage of `content-visibility`.
* **Intersection Observers:** How intersection with the viewport affects locking/unlocking (especially for `content-visibility: auto`).
* **Printing:** How printing affects display locks.
* **Cull Rects:** How display locks interact with culling.
* **Element Connection/Disconnection:** How connection and disconnection from the DOM affect display lock state.
* **Selection:** How display locks affect selection within the locked content.
* **Reattachment:** How display locks prevent reattachment of parts of the DOM (shadow DOM, slotted content, pseudo-elements).

Now I can proceed with generating the summary.
这是对 Chromium Blink 引擎中 `blink/renderer/core/display_lock/display_lock_context_test.cc` 文件功能进行的总结，基于提供的代码片段，它是该文件的第 4 部分，共 5 部分。

**功能归纳：**

这部分测试文件主要专注于测试 `DisplayLockContext` 在渲染流程中的行为，特别是涉及到嵌套的 display lock、元素是否在视口内、强制更新以及元素连接和断开连接时的状态变化。

具体来说，这部分测试验证了以下功能：

1. **嵌套的 Display Lock 的行为：**
   - 验证了当外层元素应用 `content-visibility: hidden` 导致 display lock 时，内层元素（即使设置了 `content-visibility: auto`）也会被有效地隐藏。
   - 确认了当外层 display lock 解除后，内层元素会根据其自身的 `content-visibility` 属性（例如 `auto`）继续进行生命周期观察和可能的解锁。
   - 测试了当嵌套的 `content-visibility: auto` 元素由于父元素被隐藏而不在视口内时，它不会观察生命周期。

2. **元素是否在视口内的影响（针对 `content-visibility: auto`）：**
   - 测试了当 `content-visibility: auto` 的元素不在视口内时，它会保持锁定状态。
   - 验证了当 `content-visibility: auto` 的元素滚动进入视口后，它会被解锁。
   - 强调了 intersection observer 的作用，解锁会在下一个生命周期中发生。

3. **强制更新（Forced Update）如何绕过 Display Lock：**
   - 证明了即使元素被 display lock 锁定，通过 `GetScopedForcedUpdate` 创建的强制更新作用域可以强制进行布局和绘制。
   - 验证了在强制更新作用域内，被锁定的子树可以被更新。

4. **Display Lock 对布局的影响：**
   - 确认了当祖先元素被 display lock 锁定时，子元素的布局不会被处理，除非进行强制更新。
   - 验证了在锁定的子树中进行 reparent 操作，即使会导致布局失效，也不会立即触发布局计算，直到解锁或进行强制更新。

5. **Display Lock 的簿记和状态管理：**
   - 测试了当元素被 display lock 锁定时，文档状态会记录锁定的 display lock 数量。
   - 验证了通过修改样式（例如 `display: inline`）强制解锁元素后，文档状态中的锁定计数会相应减少。
   - 确认了断开连接的元素会自动解锁。

6. **Display Lock 与打印预览的交互：**
   - 验证了在打印预览模式下，`content-visibility: auto` 的元素会被解锁，以便在打印输出中显示。

7. **Display Lock 对 Cull Rect 的影响：**
   - 测试了 display lock 状态变化时，cull rect 的更新行为。

8. **元素连接和断开连接时的行为：**
   - 验证了断开连接的元素会被解锁。
   - 测试了元素重新连接到 DOM 时，是否会重新进行 subtree checks。

9. **Display Lock 如何阻止某些操作：**
    - 阻止了 slotted 元素在父元素被锁定时重新附加布局树。
    - 阻止了 shadow tree 在 host 元素被锁定时重新附加布局树。
    - 阻止了伪元素在宿主元素被锁定时重新附加布局树。
    - 阻止了与锁定的元素相邻的空白节点重新附加布局树。

**与 JavaScript, HTML, CSS 的关系及举例：**

- **CSS:** `content-visibility: hidden` 和 `content-visibility: auto` 是触发 display lock 的关键 CSS 属性。测试用例通过设置元素的 class 属性来添加或移除这些属性，从而控制 display lock 的状态。例如：
  ```html
  <div id="target" class="hidden"></div>
  ```
  对应的 CSS：
  ```css
  .hidden { content-visibility: hidden; }
  ```
- **HTML:** 测试用例使用 HTML 结构来模拟不同的场景，例如嵌套元素、包含可聚焦元素的 canvas 等。通过 JavaScript 获取 HTML 元素并修改其属性来触发不同的 display lock 行为。例如：
  ```javascript
  auto* outer_element = GetDocument().getElementById(AtomicString("outer"));
  outer_element->setAttribute(html_names::kClassAttr, AtomicString("hidden"));
  ```
- **JavaScript:** 虽然测试文件是用 C++ 编写的，但它模拟了 JavaScript 可能触发的操作，例如修改元素属性、添加/删除子节点、滚动视口等，这些操作会间接影响 display lock 的状态和行为。例如，通过 `scroller->setScrollTop(2600);` 模拟滚动操作来测试 `content-visibility: auto` 的解锁机制。

**逻辑推理及假设输入与输出：**

例如，在测试嵌套 display lock 的场景中：

**假设输入:**

```html
<div id="outer" class="hidden">
  <div id="inner" class="auto">Content</div>
</div>
```

**逻辑推理:**  当外层元素 `outer` 应用了 `content-visibility: hidden` 时，它会被锁定，并且其子树（包括 `inner`）也会被隐式锁定，即使 `inner` 设置了 `content-visibility: auto`。

**预期输出:**  `inner_context->IsLocked()` 应该为 `true`，并且 `IsObservingLifecycle(inner_context)` 应该为 `false`（因为被外层隐藏）。当移除 `outer` 的 `hidden` class 后，`inner` 会根据其 `auto` 属性重新观察生命周期。

**用户或编程常见的使用错误：**

- **错误地认为 `content-visibility: auto` 的元素始终会立即渲染：** 用户可能会期望设置了 `content-visibility: auto` 的元素在初始加载时就完全渲染，但实际上，它会先处于锁定状态，直到进入视口后才解锁。
- **不理解嵌套 `content-visibility` 的影响：** 开发者可能会错误地认为内层元素的 `content-visibility: auto` 会使其独立于外层元素的 `content-visibility: hidden`，但实际上，外层的隐藏会覆盖内层的自动行为。
- **在锁定的元素上执行需要布局的操作并期望立即生效：**  如果开发者在 JavaScript 中对一个被 display lock 锁定的元素进行了修改，例如添加了子节点，他们可能会期望立即看到布局变化，但这只有在解锁或进行强制更新后才会发生。

总而言之，这部分测试代码旨在全面验证 `DisplayLockContext` 在各种渲染场景下的正确性和预期行为，确保其能够有效地控制元素的渲染和布局生命周期。

### 提示词
```
这是目录为blink/renderer/core/display_lock/display_lock_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ould be observing
  // lifecycle.
  for (int i = 0; i < 3; ++i) {
    // It shouldn't change the fact that we're layout clean.
    EXPECT_FALSE(outer_element->GetLayoutObject()->NeedsLayout());
    EXPECT_FALSE(outer_element->GetLayoutObject()->SelfNeedsFullLayout());
    EXPECT_FALSE(unrelated_element->GetLayoutObject()->NeedsLayout());
    EXPECT_FALSE(unrelated_element->GetLayoutObject()->SelfNeedsFullLayout());
    EXPECT_FALSE(inner_element->GetLayoutObject()->NeedsLayout());
    EXPECT_FALSE(inner_element->GetLayoutObject()->SelfNeedsFullLayout());

    // Because we skipped hiding the element, inner_context should be observing
    // lifecycle.
    EXPECT_TRUE(IsObservingLifecycle(inner_context));

    UpdateAllLifecyclePhasesForTest();
  }

  // Unlock outer.
  outer_element->setAttribute(html_names::kClassAttr, g_empty_atom);
  // Ensure the lock processes (but don't run intersection observation tasks
  // yet).
  UpdateAllLifecyclePhasesForTest();

  // Note that although we're not nested, we're still observing the lifecycle
  // because we don't yet know whether we should or should not hide and we only
  // make this decision _before_ the lifecycle actually unlocked outer.
  EXPECT_TRUE(IsObservingLifecycle(inner_context));

  // Verify the lock is gone.
  EXPECT_FALSE(outer_context->IsLocked());

  // Everything should be layout clean.
  EXPECT_FALSE(outer_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(outer_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->SelfNeedsFullLayout());

  // Process visibility changes.
  RunStartOfLifecycleTasks();

  // We now should know we're visible and so we're not observing the lifecycle.
  EXPECT_FALSE(IsObservingLifecycle(inner_context));

  // Also we should still be activated and unlocked.
  EXPECT_FALSE(inner_context->IsLocked());

  // Everything should be layout clean.
  EXPECT_FALSE(outer_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(outer_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->SelfNeedsFullLayout());
}

TEST_F(DisplayLockContextRenderingTest, NestedLockDoesHideWhenItIsOffscreen) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .auto { content-visibility: auto; }
      .hidden { content-visibility: hidden; }
      .item { height: 10px; }
      /* this is important to not invalidate layout when we hide the element! */
      #outer { contain: style layout; }
      .spacer { height: 10000px; }
    </style>
    <div id=future_spacer></div>
    <div id=outer>
      <div id=unrelated>
        <div id=inner class=auto>Content</div>
      </div>
    </div>
  )HTML");

  auto* inner_element = GetDocument().getElementById(AtomicString("inner"));
  auto* unrelated_element =
      GetDocument().getElementById(AtomicString("unrelated"));
  auto* outer_element = GetDocument().getElementById(AtomicString("outer"));

  // Ensure that the visibility switch happens. This would also clear the
  // layout.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(outer_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(outer_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->SelfNeedsFullLayout());

  // Verify lock state.
  auto* inner_context = inner_element->GetDisplayLockContext();
  ASSERT_TRUE(inner_context);
  EXPECT_FALSE(inner_context->IsLocked());

  // Lock outer.
  outer_element->setAttribute(html_names::kClassAttr, AtomicString("hidden"));
  // Ensure the lock processes (but don't run intersection observation tasks
  // yet).
  UpdateAllLifecyclePhasesForTest();

  // Verify the lock exists.
  auto* outer_context = outer_element->GetDisplayLockContext();
  ASSERT_TRUE(outer_context);
  EXPECT_TRUE(outer_context->IsLocked());

  // Everything should be layout clean.
  EXPECT_FALSE(outer_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(outer_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->SelfNeedsFullLayout());

  // Inner context should not be observing the lifecycle.
  EXPECT_FALSE(IsObservingLifecycle(inner_context));

  // Process any visibility changes.
  RunStartOfLifecycleTasks();

  // It shouldn't change the fact that we're layout clean.
  EXPECT_FALSE(outer_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(outer_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->SelfNeedsFullLayout());

  // Let future spacer become a real spacer!
  GetDocument()
      .getElementById(AtomicString("future_spacer"))
      ->setAttribute(html_names::kClassAttr, AtomicString("spacer"));

  UpdateAllLifecyclePhasesForTest();

  // Because we skipped hiding the element, inner_context should be observing
  // lifecycle.
  EXPECT_TRUE(IsObservingLifecycle(inner_context));

  // Unlock outer.
  outer_element->setAttribute(html_names::kClassAttr, g_empty_atom);
  // Ensure the lock processes (but don't run intersection observation tasks
  // yet).
  UpdateAllLifecyclePhasesForTest();

  // Note that although we're not nested, we're still observing the lifecycle
  // because we don't yet know whether we should or should not hide and we only
  // make this decision _before_ the lifecycle actually unlocked outer.
  EXPECT_TRUE(IsObservingLifecycle(inner_context));

  // Verify the lock is gone.
  EXPECT_FALSE(outer_context->IsLocked());

  // Everything should be layout clean.
  EXPECT_FALSE(outer_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(outer_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->SelfNeedsFullLayout());

  // Process any visibility changes.
  RunStartOfLifecycleTasks();

  // We're still invisible, and we don't know that we're not nested so we're
  // still observing the lifecycle.
  EXPECT_TRUE(IsObservingLifecycle(inner_context));

  // We're unlocked for now.
  EXPECT_FALSE(inner_context->IsLocked());

  // Everything should be layout clean.
  EXPECT_FALSE(outer_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(outer_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(unrelated_element->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(inner_element->GetLayoutObject()->SelfNeedsFullLayout());

  UpdateAllLifecyclePhasesForTest();

  // We figured out that we're actually invisible so no need to observe the
  // lifecycle.
  EXPECT_FALSE(IsObservingLifecycle(inner_context));

  // We're locked.
  EXPECT_TRUE(inner_context->IsLocked());
}

TEST_F(DisplayLockContextRenderingTest,
       LockedCanvasWithFallbackHasFocusableStyle) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .auto { content-visibility: auto; }
      .spacer { height: 3000px; }
    </style>
    <div class=spacer></div>
    <div class=auto>
      <canvas>
        <div id=target tabindex=0></div>
      </canvas>
    </div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_TRUE(target->IsFocusable());
}

TEST_F(DisplayLockContextRenderingTest, ForcedUnlockBookkeeping) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden; }
      .inline { display: inline; }
    </style>
    <div id=target class=hidden></div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* context = target->GetDisplayLockContext();

  ASSERT_TRUE(context);
  EXPECT_TRUE(context->IsLocked());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);

  target->classList().Add(AtomicString("inline"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(context->IsLocked());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
}

TEST_F(DisplayLockContextRenderingTest, LayoutRootIsSkippedIfLocked) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden; }
      .contained { contain: strict; }
      .positioned { position: absolute; top: 0; left: 0; }
    </style>
    <div id=hide>
      <div class=contained>
        <div id=new_parent class="contained positioned">
          <div>
            <div id=target></div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  // Lock an ancestor.
  auto* hide = GetDocument().getElementById(AtomicString("hide"));
  hide->classList().Add(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* new_parent = GetDocument().getElementById(AtomicString("new_parent"));

  // Reparent elements which will invalidate layout without needing to process
  // style (which is blocked by the display-lock).
  new_parent->appendChild(target);

  // Note that we don't check target here, since it doesn't have a layout object
  // after being re-parented.
  EXPECT_TRUE(new_parent->GetLayoutObject()->NeedsLayout());

  // Updating the lifecycle should not update new_parent, since it is in a
  // locked subtree.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(new_parent->GetLayoutObject()->NeedsLayout());

  // Unlocking and updating should update everything.
  hide->classList().Remove(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(hide->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(target->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(new_parent->GetLayoutObject()->NeedsLayout());
}

TEST_F(DisplayLockContextRenderingTest,
       LayoutRootIsProcessedIfLockedAndForced) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden; }
      .contained { contain: strict; }
      .positioned { position: absolute; top: 0; left: 0; }
    </style>
    <div id=hide>
      <div class=contained>
        <div id=new_parent class="contained positioned">
          <div>
            <div id=target></div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  // Lock an ancestor.
  auto* hide = GetDocument().getElementById(AtomicString("hide"));
  hide->classList().Add(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* new_parent = GetDocument().getElementById(AtomicString("new_parent"));

  // Reparent elements which will invalidate layout without needing to process
  // style (which is blocked by the display-lock).
  new_parent->appendChild(target);

  // Note that we don't check target here, since it doesn't have a layout object
  // after being re-parented.
  EXPECT_TRUE(new_parent->GetLayoutObject()->NeedsLayout());

  {
    auto scope =
        GetScopedForcedUpdate(hide, DisplayLockContext::ForcedPhase::kLayout,
                              true /* include self */);

    // Updating the lifecycle should update target and new_parent, since it is
    // in a locked but forced subtree.
    UpdateAllLifecyclePhasesForTest();
    EXPECT_FALSE(target->GetLayoutObject()->NeedsLayout());
    EXPECT_FALSE(new_parent->GetLayoutObject()->NeedsLayout());
  }

  // Unlocking and updating should update everything.
  hide->classList().Remove(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(hide->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(target->GetLayoutObject()->NeedsLayout());
  EXPECT_FALSE(new_parent->GetLayoutObject()->NeedsLayout());
}

TEST_F(DisplayLockContextRenderingTest, ContainStrictChild) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden; }
      .contained { contain: strict; }
      #target { backface-visibility: hidden; }
    </style>
    <div id=hide>
      <div id=container class=contained>
        <div id=target></div>
      </div>
    </div>
  )HTML");

  // Lock an ancestor.
  auto* hide = GetDocument().getElementById(AtomicString("hide"));
  hide->classList().Add(AtomicString("hidden"));

  // This should not DCHECK.
  UpdateAllLifecyclePhasesForTest();

  hide->classList().Remove(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(DisplayLockContextRenderingTest, UseCounter) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .auto { content-visibility: auto; }
      .hidden { content-visibility: hidden; }
    </style>
    <div id=e1></div>
    <div id=e2></div>
  )HTML");

  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kContentVisibilityAuto));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kContentVisibilityHidden));

  GetDocument()
      .getElementById(AtomicString("e1"))
      ->classList()
      .Add(AtomicString("auto"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kContentVisibilityAuto));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kContentVisibilityHidden));

  GetDocument()
      .getElementById(AtomicString("e2"))
      ->classList()
      .Add(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kContentVisibilityAuto));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kContentVisibilityHidden));
}

TEST_F(DisplayLockContextRenderingTest,
       NeedsLayoutTreeUpdateForNodeRespectsForcedLocks) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden; }
      .contained { contain: strict; }
      .backface_hidden { backface-visibility: hidden; }
    </style>
    <div id=hide>
      <div id=container class=contained>
        <div id=target></div>
      </div>
    </div>
  )HTML");

  // Lock an ancestor.
  auto* hide = GetDocument().getElementById(AtomicString("hide"));
  hide->classList().Add(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  auto* target = GetDocument().getElementById(AtomicString("target"));
  target->classList().Add(AtomicString("backface_hidden"));

  auto scope =
      GetScopedForcedUpdate(hide, DisplayLockContext::ForcedPhase::kPrePaint,
                            true /* include self */);
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdateForNode(*target));
}

TEST_F(DisplayLockContextRenderingTest, InnerScrollerAutoVisibilityMargin) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .auto { content-visibility: auto; }
      #scroller { height: 300px; overflow: scroll }
      #target { height: 10px; width: 10px; }
      .spacer { height: 3000px }
    </style>
    <div id=scroller>
      <div class=spacer></div>
      <div id=target class=auto></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  auto* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target->GetDisplayLockContext());
  EXPECT_TRUE(target->GetDisplayLockContext()->IsLocked());

  auto* scroller = GetDocument().getElementById(AtomicString("scroller"));
  // 2600 is spacer (3000) minus scroller height (300) minus 100 for some extra
  // padding.
  scroller->setScrollTop(2600);
  UpdateAllLifecyclePhasesForTest();

  // Since the intersection observation is delivered on the next frame, run
  // another lifecycle.
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(target->GetDisplayLockContext()->IsLocked());
}

TEST_F(DisplayLockContextRenderingTest,
       AutoReachesStableStateOnContentSmallerThanLockedSize) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .spacer { height: 20000px; }
      .auto {
        content-visibility: auto;
        contain-intrinsic-size: 1px 20000px;
      }
      .auto > div {
        height: 3000px;
      }
    </style>

    <div class=spacer></div>
    <div id=e1 class=auto><div>content</div></div>
    <div id=e2 class=auto><div>content</div></div>
    <div class=spacer></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  GetDocument().scrollingElement()->setScrollTop(29000);

  Element* element = GetDocument().getElementById(AtomicString("e1"));

  // Note that this test also unlock/relocks #e2 but we only care about #e1
  // settling into a steady state.

  // Initially we start with locked in the viewport.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollTop(), 29000.);

  // It gets unlocked because it's in the viewport.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollTop(), 29000.);

  // By unlocking it, it shrinks so next time it gets relocked.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollTop(), 29000.);

  // However, because c-v auto implies c-i-s auto when relocking it doesn't
  // grow anymore and this is a stable state.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollTop(), 29000.);
}

TEST_F(DisplayLockContextRenderingTest,
       AutoReachesStableStateOnContentSmallerThanLockedSizeInLtr) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      body { writing-mode: vertical-lr }
      .spacer { block-size: 20000px; }
      .auto {
        content-visibility: auto;
        contain-intrinsic-size: 20000px 1px;
      }
      .auto > div {
        block-size: 3000px;
      }
    </style>

    <div class=spacer></div>
    <div id=e1 class=auto><div>content</div></div>
    <div id=e2 class=auto><div>content</div></div>
    <div class=spacer></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  GetDocument().scrollingElement()->setScrollLeft(29000);

  Element* element = GetDocument().getElementById(AtomicString("e1"));

  // Note that this test also unlock/relocks #e2 but we only care about #e1
  // settling into a steady state.

  // Initially we start with locked in the viewport.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollLeft(), 29000.);

  // It gets unlocked because it's in the viewport.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollLeft(), 29000.);

  // By unlocking it, it shrinks so next time it gets relocked.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollLeft(), 29000.);

  // Because c-v auto implies c-i-s auto, the element doesn't grow again so this
  // is a stable state.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollLeft(), 29000.);
}

TEST_F(DisplayLockContextRenderingTest,
       AutoReachesStableStateOnContentSmallerThanLockedSizeInRtl) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      body { writing-mode: vertical-rl }
      .spacer { block-size: 20000px; }
      .auto {
        content-visibility: auto;
        contain-intrinsic-size: 20000px 1px;
      }
      .auto > div {
        block-size: 3000px;
      }
    </style>

    <div class=spacer></div>
    <div id=e1 class=auto><div>content</div></div>
    <div id=e2 class=auto><div>content</div></div>
    <div class=spacer></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  GetDocument().scrollingElement()->setScrollLeft(-29000);

  Element* element = GetDocument().getElementById(AtomicString("e1"));

  // Note that this test also unlock/relocks #e2 but we only care about #e1
  // settling into a steady state.

  // Initially we start with locked in the viewport.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollLeft(), -29000.);

  // It gets unlocked because it's in the viewport.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollLeft(), -29000.);

  // By unlocking it, it shrinks so next time it gets relocked.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollLeft(), -29000.);

  // Because c-v auto implies c-i-s auto, this is a stable state.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(element->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(GetDocument().scrollingElement()->scrollLeft(), -29000.);
}

TEST_F(DisplayLockContextRenderingTest, FirstAutoFramePaintsInViewport) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .spacer { height: 10000px }
      .auto {
        content-visibility: auto;
        contain-intrinsic-size: 1px 200px;
      }
      .auto > div { height: 100px }
    </style>

    <div id=visible><div>content</div></div>
    <div class=spacer></div>
    <div id=hidden><div>content</div></div>
  )HTML");

  auto* visible = GetDocument().getElementById(AtomicString("visible"));
  auto* hidden = GetDocument().getElementById(AtomicString("hidden"));

  visible->classList().Add(AtomicString("auto"));
  hidden->classList().Add(AtomicString("auto"));

  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(visible->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(hidden->GetDisplayLockContext()->IsLocked());

  EXPECT_FALSE(visible->GetLayoutObject()->SelfNeedsFullLayout());
  EXPECT_FALSE(hidden->GetLayoutObject()->SelfNeedsFullLayout());

  auto* visible_rect = visible->GetBoundingClientRect();
  auto* hidden_rect = hidden->GetBoundingClientRect();

  EXPECT_FLOAT_EQ(visible_rect->height(), 100);
  EXPECT_FLOAT_EQ(hidden_rect->height(), 200);
}

TEST_F(DisplayLockContextRenderingTest,
       HadIntersectionNotificationsResetsWhenConnected) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .auto { content-visibility: auto; }
    </style>
    <div id=target class=auto></div>
  )HTML");

  auto* element = GetDocument().getElementById(AtomicString("target"));
  auto* context = element->GetDisplayLockContext();
  ASSERT_TRUE(context);
  test::RunPendingTasks();

  EXPECT_TRUE(context->HadAnyViewportIntersectionNotifications());

  element->remove();
  GetDocument().body()->AppendChild(element);

  EXPECT_FALSE(context->HadAnyViewportIntersectionNotifications());

  UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();

  EXPECT_TRUE(context->HadAnyViewportIntersectionNotifications());
}

TEST_F(DisplayLockContextTest, PrintingUnlocksAutoLocks) {
  ResizeAndFocus();

  SetHtmlInnerHTML(R"HTML(
    <style>
    .spacer { height: 30000px; }
    .auto { content-visibility: auto; }
    </style>
    <div class=spacer></div>
    <div id=target class=auto>
      <div id=nested class=auto></div>
    </div>
  )HTML");

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* nested = GetDocument().getElementById(AtomicString("nested"));
  ASSERT_TRUE(target->GetDisplayLockContext());
  EXPECT_TRUE(target->GetDisplayLockContext()->IsLocked());
  // Nested should not have a display lock since we would have skipped style.
  EXPECT_FALSE(nested->GetDisplayLockContext());

  {
    // Create a paint preview scope.
    Document::PaintPreviewScope scope(GetDocument(),
                                      Document::kPaintingPreview);
    UpdateAllLifecyclePhasesForTest();

    EXPECT_FALSE(target->GetDisplayLockContext()->IsLocked());
    // Nested should have created a context...
    ASSERT_TRUE(nested->GetDisplayLockContext());
    // ... but it should be unlocked.
    EXPECT_FALSE(nested->GetDisplayLockContext()->IsLocked());
  }

  EXPECT_TRUE(target->GetDisplayLockContext()->IsLocked());
  EXPECT_TRUE(nested->GetDisplayLockContext()->IsLocked());
}

TEST_F(DisplayLockContextTest, CullRectUpdate) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #clip {
      width: 100px;
      height: 100px;
      overflow: hidden;
    }
    #container {
      width: 300px;
      height: 300px;
      contain: paint layout;
    }
    .locked {
      content-visibility: hidden;
    }
    </style>
    <div id="clip">
      <div id="container"
           style="width: 300px; height: 300px; contain: paint layout">
        <div id="target" style="position: relative"></div>
      </div>
    </div>
  )HTML");

  // Check if the result is correct if we update the contents.
  auto* container = GetDocument().getElementById(AtomicString("container"));
  auto* target =
      GetDocument().getElementById(AtomicString("target"))->GetLayoutBox();
  EXPECT_EQ(gfx::Rect(0, 0, 100, 100),
            target->FirstFragment().GetCullRect().Rect());

  container->classList().Add(AtomicString("locked"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 100, 100),
            target->FirstFragment().GetCullRect().Rect());

  GetDocument()
      .getElementById(AtomicString("clip"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("width: 200px"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 100, 100),
            target->FirstFragment().GetCullRect().Rect());

  container->classList().Remove(AtomicString("locked"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 100),
            target->FirstFragment().GetCullRect().Rect());
}

TEST_F(DisplayLockContextTest, DisconnectedElementIsUnlocked) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    .locked { content-visibility: hidden; }
    </style>
    <div id="container" class="locked"></div>
  )HTML");

  // Check if the result is correct if we update the contents.
  auto* container = GetDocument().getElementById(AtomicString("container"));
  auto* context = container->GetDisplayLockContext();
  ASSERT_TRUE(context);
  EXPECT_TRUE(context->IsLocked());
  EXPECT_EQ(context->GetState(), EContentVisibility::kHidden);

  container->remove();

  EXPECT_FALSE(container->GetComputedStyle());
  EXPECT_FALSE(context->IsLocked());
  EXPECT_EQ(context->GetState(), EContentVisibility::kVisible);
}

TEST_F(DisplayLockContextTest, ConnectedElementDefersSubtreeChecks) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    .spacer { height: 3000px; }
    .locked { content-visibility: auto; }
    </style>
    <div id="s1" class="spacer">first spacer</div>
    <div id="s2" class="spacer">second spacer</div>
    <div id="locked" class="locked">locked container</div>
  )HTML");

  auto* locked = GetDocument().getElementById(AtomicString("locked"));
  auto* context = locked->GetDisplayLockContext();
  ASSERT_TRUE(context);
  EXPECT_TRUE(context->IsLocked());

  auto* range = GetDocument().createRange();
  range->setStart(
      GetDocument().getElementById(AtomicString("s1"))->firstChild(), 0);
  range->setEnd(GetDocument().getElementById(AtomicString("s2"))->firstChild(),
                5);

  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .SetBaseAndExtent(EphemeralRange(range))
                               .Build(),
                           SetSelectionOptions());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(HasSelection(context));

  GetDocument().body()->insertBefore(
      locked, GetDocument().getElementById(AtomicString("s2")));

  EXPECT_FALSE(HasSelection(context));

  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(HasSelection(context));
}

TEST_F(DisplayLockContextTest, BlockedReattachOfSlotted) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <div id="host">
      <template shadowrootmode="open">
        <style>
          slot { display: block; }
          .locked {
            content-visibility: hidden;
          }
        </style>
        <slot id="slot"></slot>
      </template>
      <span id="slotted"></span>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* slotted = GetDocument().getElementById(AtomicString("slotted"));
  auto* slot = host->GetShadowRoot()->getElementById(AtomicString("slot"));

  EXPECT_TRUE(slot->GetLayoutObject());

  slot->classList().Add(AtomicString("locked"));
  GetDocument().documentElement()->SetForceReattachLayoutTree();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(slotted->GetLayoutObject());
}

TEST_F(DisplayLockContextTest, BlockedReattachOfShadowTree) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <style>
      .locked { content-visibility: hidden; }
    </style>
    <div id="host">
      <template shadowrootmode="open">
        <span id="span"></span>
      </template>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* span = host->GetShadowRoot()->getElementById(AtomicString("span"));

  ASSERT_TRUE(host->GetLayoutObject());
  EXPECT_TRUE(span->GetLayoutObject());

  host->classList().Add(AtomicString("locked"));
  GetDocument().documentElement()->SetForceReattachLayoutTree();
  UpdateAllLifecyclePhasesForTest();

  ASSERT_TRUE(host->GetLayoutObject());
  EXPECT_FALSE(span->GetLayoutObject());
}

TEST_F(DisplayLockContextTest, BlockedReattachOfPseudoElements) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #locked::before { content: "X"; }
      .locked { content-visibility: hidden; }
    </style>
    <div id="locked"></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* locked = GetDocument().getElementById(AtomicString("locked"));

  ASSERT_TRUE(locked->GetLayoutObject());
  ASSERT_TRUE(locked->GetPseudoElement(kPseudoIdBefore));
  EXPECT_TRUE(locked->GetPseudoElement(kPseudoIdBefore)->GetLayoutObject());

  locked->classList().Add(AtomicString("locked"));
  GetDocument().documentElement()->SetForceReattachLayoutTree();
  UpdateAllLifecyclePhasesForTest();

  ASSERT_TRUE(locked->GetLayoutObject());
  ASSERT_TRUE(locked->GetPseudoElement(kPseudoIdBefore));
  EXPECT_FALSE(locked->GetPseudoElement(kPseudoIdBefore)->GetLayoutObject());
}

TEST_F(DisplayLockContextTest, BlockedReattachWhitespaceSibling) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #locked { display: inline-block; }
      .locked { content-visibility: hidden; }
    </style>
    <span id="locked"><span>X</span></span> <span>X</span>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  auto* locked = GetDocument().getElementById(AtomicString("locked"));

  EXPECT_TRUE(locked->GetLayoutObject());
  EXPECT_TRUE(locked->firstChild()->GetLayoutObject());
  EXPECT_TRUE(locked->firstChild()->firstChild()->GetLayoutObject());
  EXPECT_TRUE(locked->nextSibling()->GetLayoutObject());
  EXPECT_TRUE(locked->nextSibling()->nextSibling()->GetLayoutObject());

  locked->classList().Add(AtomicString("locked"));
  GetDocument().documentElement()->SetForceReattachLayoutTree();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_TRUE(locked->GetLayoutObject());
  EXPECT_FALSE(locked->firstChild()->GetLayoutObject());
  EXPECT_FALSE(locked->firstChild()->firstChild()->GetLayoutObject());
  EXPECT_TRUE(locked->nextSibling()->GetLayoutObject());
  EXPECT_TRUE(locked->nextSibling()->nextSibling()->GetLayoutObject());
}

TEST_F(DisplayLockContextTest, ReattachPropagationBlockedByDisplayLock) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #locked { content-visibility: hidden; }
    </style>
    <div id=parent>
      <div id=loc
```