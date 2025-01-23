Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine test file. Specifically, they want to understand what aspects of the rendering engine this code is testing.

**Plan:**

1. **Identify the core functionality being tested:**  The code uses `DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock` and manipulates `DisplayLockContext` and `DisplayLockDocumentState`. This strongly suggests testing the "Display Lock" feature.
2. **Analyze the test cases:** Each `TEST_F` block represents a distinct test scenario. Summarize the purpose of each test.
3. **Relate to web technologies (JavaScript, HTML, CSS):**  Examine how the tests interact with or are affected by these technologies. Look for manipulation of DOM elements, CSS properties, and any implicit or explicit interactions with JavaScript-like behavior (e.g., event listeners, focus).
4. **Identify logical reasoning and assumptions:**  Look for `ASSERT_FALSE` and `ASSERT_TRUE` calls that indicate expected behavior under specific conditions. Try to infer the underlying logic being validated.
5. **Pinpoint potential usage errors:** Consider how the Display Lock API might be misused or misunderstood by developers. Think about scenarios where the expected outcome of locking or unlocking an element might not be what the developer intends.
6. **Synthesize a concise summary:** Combine the above points into a brief overview of the code's functionality.
```
这是目录为blink/renderer/core/display_lock/display_lock_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

根据提供的代码片段，这个测试文件的主要功能是测试 Blink 渲染引擎中 `DisplayLockContext` 的行为和功能。`DisplayLockContext` 是用于实现“显示锁”这一特性的核心组件。显示锁允许开发者阻止页面特定区域的更新和渲染，直到显式地解除锁定。

以下是对代码片段中测试用例功能的归纳：

**功能归纳 (基于提供的代码片段):**

* **测试 `ShouldIgnoreNodeDueToDisplayLock` 函数：**  测试在不同的显示锁状态下，特定的 DOM 节点是否应该被忽略（例如，在某些渲染或激活过程中）。涵盖了以下场景：
    * **Slotted 元素:** 测试当包含 `<slot>` 元素的容器被锁定时，slot 元素是否被忽略。
    * **Contain 属性:** 测试当包含 `contain: style layout paint;` 样式的元素被锁定时，其内部的 slotted 元素是否被忽略。
    * **Commit 过程:** 测试在锁定和提交（解锁）元素后，节点是否应该被忽略。
    * **`hidden=until-found` 属性:** 测试带有 `hidden=until-found` 属性的元素在不同 `DisplayLockActivationReason` 下是否被忽略。这涉及到与浏览器的 "Find in Page" 和用户焦点功能的交互。

* **测试锁定元素对焦点的影响:**  验证当一个元素被锁定时，其后代元素（包括 shadow DOM 中的元素）是否不再可聚焦。这包括键盘焦点和程序化焦点。

* **测试多重锁定计数:**  验证在存在多个显示锁的情况下，`LockedDisplayLockCount` 和 `DisplayLockBlockingAllActivationCount` 的计数是否正确。特别关注嵌套锁定的情况，理解内部锁定只有在外部锁定生效后才会被计入。

* **测试可激活锁定的行为:**  验证带有 `is_activatable` 标志的锁定不会被计入 `DisplayLockBlockingAllActivationCount`。这表明可激活锁定不会阻止某些类型的页面激活。

* **测试模板元素中的锁定:**  测试尝试锁定 `<template>` 元素内部的元素时的行为。验证锁定在模板内容未添加到文档之前不会生效。同时测试将模板内容添加到文档后，锁定如何生效以及与 `display: none` 和 `content-visibility: hidden` 等 CSS 属性的交互。

* **测试触摸事件处理和 `allowed-touch-action` 属性:** 测试当祖先元素或后代元素包含触摸事件监听器时，锁定元素对 `allowed-touch-action` 属性的影响。验证相关的 dirty bits 是否被正确传播。

* **测试滚轮事件处理:** 测试当祖先元素包含滚轮事件监听器时，锁定元素对滚轮事件处理的影响。验证相关的 dirty bits 是否被正确传播。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 测试用例大量使用 HTML 结构来创建不同的 DOM 树，并使用特定的 HTML 属性（如 `id`, `class`, `hidden=until-found`, `<slot>`, `<template>`）来模拟不同的场景。
    * **例:**  `<div id='container' style='contain:style layout paint;'><slot></slot></div>`  展示了如何使用 HTML 结构和 CSS 的 `contain` 属性来创建一个隔离的渲染上下文，并结合 `<slot>` 元素进行测试。
    * **例:** `<div id="nonviewport" hidden=until-found>`  展示了 HTML 的 `hidden=until-found` 属性，该属性与浏览器的内置特性相关，并在此处与显示锁进行交互测试。

* **CSS:** 测试用例使用 CSS 属性 (`contain`, `display`, `content-visibility`) 来影响元素的渲染行为，并观察显示锁与之的交互。
    * **例:** `style='contain:style layout paint;'`  指定了元素应该独立地进行样式、布局和绘制，这通常是使用显示锁的前提条件。
    * **例:** `style='display: none;'`  用于测试当锁定的元素不可见时，显示锁的行为。

* **JavaScript (隐式):** 虽然代码是 C++ 测试代码，但它测试的是 Blink 引擎的行为，而 Blink 引擎最终会影响 JavaScript API 的行为。例如，测试焦点相关的部分验证了 JavaScript 中 `element.focus()` 等 API 的行为在显示锁作用下的变化。
    * **例:**  测试 `text_field->Focus()`  验证了 JavaScript 中调用 `focus()` 方法是否能成功聚焦一个被锁定的元素。
    * **例:**  事件监听器的添加 (`handler_element->addEventListener(event_type_names::kTouchstart, callback);`) 模拟了 JavaScript 中添加事件监听器的行为，并观察显示锁如何影响事件处理。

**逻辑推理、假设输入与输出:**

* **假设输入:** 一个包含 slotted 元素的 DOM 结构，其中父元素被锁定。
* **输出:** `DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock` 函数返回 `true` (在锁定生效期间)，表明 slotted 元素应该被忽略，因为它的渲染上下文被冻结。

* **假设输入:** 一个 input 元素和一个包含 `contain` 属性的父元素，该父元素被锁定。
* **输出:** `text_field->IsKeyboardFocusable()` 和 `text_field->IsFocusable()` 返回 `false`，表明输入元素不再可聚焦。

* **假设输入:**  多个具有 `contain` 属性的 div 元素被锁定，包括嵌套的情况。
* **输出:** `GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount()` 和 `GetDocument().GetDisplayLockDocumentState().DisplayLockBlockingAllActivationCount()` 返回相应的锁定计数，并根据锁定和提交操作进行更新。嵌套锁定的生效需要外部锁定先完成。

**用户或编程常见的使用错误举例:**

* **错误地认为锁定一个元素会阻止其所有后代的所有操作：**  开发者可能错误地认为锁定一个元素会完全阻止其后代的事件处理。但测试用例表明，即使父元素被锁定，后代元素上的事件监听器仍然可以触发，虽然渲染可能被冻结。
* **在模板元素内部尝试锁定元素而期望立即生效：** 开发者可能尝试在 `<template>` 元素内部锁定一个元素，并期望该锁定在模板内容未添加到文档之前就生效。测试用例明确指出，这种情况下的锁定不会生效。
* **不理解 `is_activatable` 锁定的含义：** 开发者可能不清楚可激活锁定不会阻止某些类型的页面激活，从而在需要阻止所有激活的情况下错误地使用了可激活锁定。

**总结:**

这部分代码主要测试了 `DisplayLockContext` 在处理 slotted 元素、焦点管理、多重锁定、可激活锁定以及与模板元素交互时的核心行为。它验证了显示锁机制与 HTML 结构、CSS 属性以及 JavaScript 行为之间的预期交互，并覆盖了一些可能导致开发者误用的场景。

### 提示词
```
这是目录为blink/renderer/core/display_lock/display_lock_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *slotted, DisplayLockActivationReason::kAny));

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(
      "<div id='container' style='contain:style layout "
      "paint;'><slot></slot></div>");
  UpdateAllLifecyclePhasesForTest();

  auto* container = shadow_root.getElementById(AtomicString("container"));
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *host, DisplayLockActivationReason::kAny));
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *container, DisplayLockActivationReason::kAny));
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *slotted, DisplayLockActivationReason::kAny));

  LockElement(*container, false);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *host, DisplayLockActivationReason::kAny));
  // The container itself is locked but that doesn't mean it should be ignored.
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *container, DisplayLockActivationReason::kAny));
  ASSERT_TRUE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *slotted, DisplayLockActivationReason::kAny));

  // Ensure that we resolve the acquire callback, thus finishing the acquire
  // step.
  UpdateAllLifecyclePhasesForTest();

  CommitElement(*container);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *host, DisplayLockActivationReason::kAny));
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *container, DisplayLockActivationReason::kAny));
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *slotted, DisplayLockActivationReason::kAny));

  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *host, DisplayLockActivationReason::kAny));
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *container, DisplayLockActivationReason::kAny));
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *slotted, DisplayLockActivationReason::kAny));

  SetHtmlInnerHTML(R"HTML(
    <body>
    <div id="nonviewport" hidden=until-found>
      <div id="nonviewport-child"></div>
    </div>
    </body>
  )HTML");
  auto* non_viewport =
      GetDocument().getElementById(AtomicString("nonviewport-child"));

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *non_viewport, DisplayLockActivationReason::kAny));
  ASSERT_FALSE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *non_viewport, DisplayLockActivationReason::kFindInPage));
  ASSERT_TRUE(DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
      *non_viewport, DisplayLockActivationReason::kUserFocus));
}

TEST_F(DisplayLockContextTest,
       LockedElementAndFlatTreeDescendantsAreNotFocusable) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <body>
    <div id="shadowHost">
      <input id="textfield" type="text">
    </div>
    </body>
  )HTML");

  auto* host = GetDocument().getElementById(AtomicString("shadowHost"));
  auto* text_field = GetDocument().getElementById(AtomicString("textfield"));
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(
      "<div id='container' style='contain:style layout "
      "paint;'><slot></slot></div>");

  UpdateAllLifecyclePhasesForTest();
  ASSERT_TRUE(text_field->IsKeyboardFocusable());
  ASSERT_TRUE(text_field->IsFocusable());

  auto* element = shadow_root.getElementById(AtomicString("container"));
  LockElement(*element, false);

  // Sanity checks to ensure the element is locked.
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldStyleChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldLayoutChildren());
  EXPECT_FALSE(element->GetDisplayLockContext()->ShouldPaintChildren());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);

  // The input should not be focusable now.
  EXPECT_FALSE(text_field->IsKeyboardFocusable());
  EXPECT_FALSE(text_field->IsFocusable());

  // Calling explicit focus() should also not focus the element.
  text_field->Focus();
  EXPECT_FALSE(GetDocument().FocusedElement());
}

TEST_F(DisplayLockContextTest, LockedCountsWithMultipleLocks) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    .container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body>
    <div id="one" class="container">
      <div id="two" class="container"></div>
    </div>
    <div id="three" class="container"></div>
    </body>
  )HTML");

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  auto* one = GetDocument().getElementById(AtomicString("one"));
  auto* two = GetDocument().getElementById(AtomicString("two"));
  auto* three = GetDocument().getElementById(AtomicString("three"));

  LockElement(*one, false);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);

  LockElement(*two, false);

  // Because |two| is nested, the lock counts aren't updated since the lock
  // doesn't actually take effect until style can determine that we should lock.
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);

  LockElement(*three, false);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 2);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            2);

  // Now commit the outer lock.
  CommitElement(*one);

  // The counts remain the same since now the inner lock is determined to be
  // locked.
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 2);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            2);

  // Commit the inner lock.
  CommitElement(*two);

  // Both inner and outer locks should have committed.
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);

  // Commit the sibling lock.
  CommitElement(*three);

  // Both inner and outer locks should have committed.
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
}

TEST_F(DisplayLockContextTest, ActivatableNotCountedAsBlocking) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    .container {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <body>
    <div id="activatable" class="container"></div>
    <div id="nonActivatable" class="container"></div>
    </body>
  )HTML");

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  auto* activatable = GetDocument().getElementById(AtomicString("activatable"));
  auto* non_activatable =
      GetDocument().getElementById(AtomicString("nonActivatable"));

  // Initial display lock context should be activatable, since nothing skipped
  // activation for it.
  EXPECT_TRUE(activatable->EnsureDisplayLockContext().IsActivatable(
      DisplayLockActivationReason::kAny));

  LockElement(*activatable, true);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
  EXPECT_TRUE(activatable->GetDisplayLockContext()->IsActivatable(
      DisplayLockActivationReason::kAny));

  LockElement(*non_activatable, false);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 2);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);
  EXPECT_FALSE(non_activatable->GetDisplayLockContext()->IsActivatable(
      DisplayLockActivationReason::kAny));

  // Now commit the lock for |non_activatable|.
  CommitElement(*non_activatable);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  // Re-acquire the lock for |activatable| again with the activatable flag.
  LockElement(*activatable, true);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
  EXPECT_TRUE(activatable->GetDisplayLockContext()->IsActivatable(
      DisplayLockActivationReason::kAny));
}

TEST_F(DisplayLockContextTest, ElementInTemplate) {
  ResizeAndFocus();
  SetHtmlInnerHTML(R"HTML(
    <style>
    #child {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    #grandchild {
      color: blue;
    }
    #container {
      display: none;
    }
    </style>
    <body>
      <template id="template"><div id="child"><div id="grandchild">foo</div></div></template>
      <div id="container"></div>
    </body>
  )HTML");

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  auto* template_el = To<HTMLTemplateElement>(
      GetDocument().getElementById(AtomicString("template")));
  auto* child = To<Element>(template_el->content()->firstChild());
  EXPECT_FALSE(child->isConnected());

  // Try to lock an element in a template.
  LockElement(*child, false);

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
  EXPECT_FALSE(child->GetDisplayLockContext());

  // Commit also works, but does nothing.
  CommitElement(*child);
  EXPECT_FALSE(child->GetDisplayLockContext());

  // Try to lock an element that was moved from a template to a document.
  auto* document_child =
      To<Element>(GetDocument().adoptNode(child, ASSERT_NO_EXCEPTION));
  auto* container = GetDocument().getElementById(AtomicString("container"));
  container->appendChild(document_child);

  LockElement(*document_child, false);

  // These should be 0, since container is display: none, so locking its child
  // is not visible to style.
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);
  ASSERT_FALSE(document_child->GetDisplayLockContext());

  container->setAttribute(html_names::kStyleAttr,
                          AtomicString("display: block;"));
  EXPECT_TRUE(container->NeedsStyleRecalc());
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 1);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            1);
  ASSERT_TRUE(document_child->GetDisplayLockContext());
  EXPECT_TRUE(document_child->GetDisplayLockContext()->IsLocked());

  document_child->setAttribute(
      html_names::kStyleAttr,
      AtomicString("content-visibility: hidden; color: red;"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(document_child->NeedsStyleRecalc());

  // Commit will unlock the element and update the style.
  document_child->setAttribute(html_names::kStyleAttr,
                               AtomicString("color: red;"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(document_child->GetDisplayLockContext()->IsLocked());
  EXPECT_EQ(
      GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount(), 0);
  EXPECT_EQ(GetDocument()
                .GetDisplayLockDocumentState()
                .DisplayLockBlockingAllActivationCount(),
            0);

  EXPECT_FALSE(document_child->NeedsStyleRecalc());
  EXPECT_FALSE(document_child->ChildNeedsStyleRecalc());
  ASSERT_TRUE(document_child->GetComputedStyle());
  EXPECT_EQ(document_child->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()),
            Color::FromRGB(255, 0, 0));

  auto* grandchild = GetDocument().getElementById(AtomicString("grandchild"));
  EXPECT_FALSE(grandchild->NeedsStyleRecalc());
  EXPECT_FALSE(grandchild->ChildNeedsStyleRecalc());
  ASSERT_TRUE(grandchild->GetComputedStyle());
  EXPECT_EQ(grandchild->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()),
            Color::FromRGB(0, 0, 255));
}

TEST_F(DisplayLockContextTest, AncestorAllowedTouchAction) {
  SetHtmlInnerHTML(R"HTML(
    <style>
    #locked {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <div id="ancestor">
      <div id="handler">
        <div id="descendant">
          <div id="locked">
            <div id="lockedchild"></div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  auto* ancestor_element =
      GetDocument().getElementById(AtomicString("ancestor"));
  auto* handler_element = GetDocument().getElementById(AtomicString("handler"));
  auto* descendant_element =
      GetDocument().getElementById(AtomicString("descendant"));
  auto* locked_element = GetDocument().getElementById(AtomicString("locked"));
  auto* lockedchild_element =
      GetDocument().getElementById(AtomicString("lockedchild"));

  LockElement(*locked_element, false);
  EXPECT_TRUE(locked_element->GetDisplayLockContext()->IsLocked());

  auto* ancestor_object = ancestor_element->GetLayoutObject();
  auto* handler_object = handler_element->GetLayoutObject();
  auto* descendant_object = descendant_element->GetLayoutObject();
  auto* locked_object = locked_element->GetLayoutObject();
  auto* lockedchild_object = lockedchild_element->GetLayoutObject();

  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(lockedchild_object->EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(lockedchild_object->InsideBlockingTouchEventHandler());

  auto* callback = MakeGarbageCollected<DisplayLockEmptyEventListener>();
  handler_element->addEventListener(event_type_names::kTouchstart, callback);

  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(handler_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(lockedchild_object->EffectiveAllowedTouchActionChanged());

  EXPECT_TRUE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantEffectiveAllowedTouchActionChanged());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(lockedchild_object->EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(handler_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(lockedchild_object->InsideBlockingTouchEventHandler());

  // Manually commit the lock so that we can verify which dirty bits get
  // propagated.
  CommitElement(*locked_element, false);
  UnlockImmediate(locked_element->GetDisplayLockContext());

  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(lockedchild_object->EffectiveAllowedTouchActionChanged());

  EXPECT_TRUE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(handler_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(handler_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(lockedchild_object->InsideBlockingTouchEventHandler());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(lockedchild_object->EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(handler_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(lockedchild_object->InsideBlockingTouchEventHandler());
}

TEST_F(DisplayLockContextTest, DescendantAllowedTouchAction) {
  SetHtmlInnerHTML(R"HTML(
    <style>
    #locked {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <div id="ancestor">
      <div id="descendant">
        <div id="locked">
          <div id="handler"></div>
        </div>
      </div>
    </div>
  )HTML");

  auto* ancestor_element =
      GetDocument().getElementById(AtomicString("ancestor"));
  auto* descendant_element =
      GetDocument().getElementById(AtomicString("descendant"));
  auto* locked_element = GetDocument().getElementById(AtomicString("locked"));
  auto* handler_element = GetDocument().getElementById(AtomicString("handler"));

  LockElement(*locked_element, false);
  EXPECT_TRUE(locked_element->GetDisplayLockContext()->IsLocked());

  auto* ancestor_object = ancestor_element->GetLayoutObject();
  auto* descendant_object = descendant_element->GetLayoutObject();
  auto* locked_object = locked_element->GetLayoutObject();
  auto* handler_object = handler_element->GetLayoutObject();

  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingTouchEventHandler());

  auto* callback = MakeGarbageCollected<DisplayLockEmptyEventListener>();
  handler_element->addEventListener(event_type_names::kTouchstart, callback);

  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(handler_object->EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(handler_object->EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingTouchEventHandler());

  // Do the same check again. For now, nothing is expected to change. However,
  // when we separate self and child layout, then some flags would be different.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(handler_object->EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingTouchEventHandler());

  // Manually commit the lock so that we can verify which dirty bits get
  // propagated.
  CommitElement(*locked_element, false);
  UnlockImmediate(locked_element->GetDisplayLockContext());

  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(handler_object->EffectiveAllowedTouchActionChanged());

  EXPECT_TRUE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_TRUE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingTouchEventHandler());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(descendant_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->EffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->EffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(
      descendant_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(locked_object->DescendantEffectiveAllowedTouchActionChanged());
  EXPECT_FALSE(handler_object->DescendantEffectiveAllowedTouchActionChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingTouchEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingTouchEventHandler());
  EXPECT_TRUE(handler_object->InsideBlockingTouchEventHandler());
}

TEST_F(DisplayLockContextTest, AncestorWheelEventHandler) {
  SetHtmlInnerHTML(R"HTML(
    <style>
    #locked {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    </style>
    <div id="ancestor">
      <div id="handler">
        <div id="descendant">
          <div id="locked">
            <div id="lockedchild"></div>
          </div>
        </div>
      </div>
    </div>
  )HTML");

  auto* ancestor_element =
      GetDocument().getElementById(AtomicString("ancestor"));
  auto* handler_element = GetDocument().getElementById(AtomicString("handler"));
  auto* descendant_element =
      GetDocument().getElementById(AtomicString("descendant"));
  auto* locked_element = GetDocument().getElementById(AtomicString("locked"));
  auto* lockedchild_element =
      GetDocument().getElementById(AtomicString("lockedchild"));

  LockElement(*locked_element, false);
  EXPECT_TRUE(locked_element->GetDisplayLockContext()->IsLocked());

  auto* ancestor_object = ancestor_element->GetLayoutObject();
  auto* handler_object = handler_element->GetLayoutObject();
  auto* descendant_object = descendant_element->GetLayoutObject();
  auto* locked_object = locked_element->GetLayoutObject();
  auto* lockedchild_object = lockedchild_element->GetLayoutObject();

  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(lockedchild_object->BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(lockedchild_object->InsideBlockingWheelEventHandler());

  auto* callback = MakeGarbageCollected<DisplayLockEmptyEventListener>();
  handler_element->addEventListener(event_type_names::kWheel, callback);

  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_TRUE(handler_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(lockedchild_object->BlockingWheelEventHandlerChanged());

  EXPECT_TRUE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantBlockingWheelEventHandlerChanged());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(lockedchild_object->BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object
```