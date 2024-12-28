Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of a test file for the `DisplayLockContext` in the Chromium Blink rendering engine.

Here's a breakdown of the request and a plan to address it:

1. **Identify the Core Functionality:**  The code consists of multiple test cases within the `DisplayLockContextTest` and `DisplayLockContextRenderingTest` classes. The tests primarily revolve around verifying the behavior of the `DisplayLockContext` in various scenarios. Keywords like `LockElement`, `UnlockImmediate`, `CommitElement`, `content-visibility`, `contain`, and the checks on layout object properties like `BlockingWheelEventHandlerChanged`, `DescendantBlockingWheelEventHandlerChanged`, `InsideBlockingWheelEventHandler`, `NeedsPaintPropertyUpdate`, and `DescendantNeedsPaintPropertyUpdate` are crucial.

2. **Relate to Web Technologies:**  The code interacts with HTML elements and CSS properties. Specifically, it manipulates elements (`div`, `iframe`), styles (`content-visibility`, `contain`, `width`, `height`, `float`, `column-count`, `column-span`), and event listeners (`wheel`). The `DisplayLockContext` is related to the `content-visibility` CSS property, which controls whether an element renders its content.

3. **Logical Reasoning and Examples:** The tests often set up scenarios with nested elements, apply locks, and then check the state of various flags on the associated layout objects. I need to infer the logic behind these checks and potentially provide simplified examples. For instance, when an element with `contain: paint` is locked using `content-visibility: hidden`, its descendants might not be painted.

4. **Common Usage Errors:**  While this is a test file, I can infer potential user errors based on the scenarios being tested. For example, misunderstanding how `content-visibility` interacts with `contain` could lead to unexpected rendering behavior.

5. **Part 3 of 5:**  This indicates that the user has provided a fragment of a larger file. I should focus on the functionality demonstrated in this specific snippet and avoid making assumptions about the rest of the file.

6. **Summarization:**  The final step is to provide a concise summary of the functionality covered in this specific part of the test file.

**Mental Walkthrough and Draft Outline:**

* **Core Functionality:** Testing the `DisplayLockContext`'s behavior related to:
    * Event handling (specifically `wheel` events) and how locks affect event propagation and dirty flags.
    * Paint property updates and how locks can block or propagate these updates.
    * Rendering-related scenarios, including interactions with `content-visibility`, `contain`, floating elements, and multi-column layouts.
    * The impact of locks on layout calculations and dirty flags during layout.
    * Paint dirty bit propagation across locked boundaries.
    * Nested locks and their effect on layout invalidation.

* **Relationship to Web Technologies:**
    * **JavaScript:**  Adding event listeners (`addEventListener`).
    * **HTML:**  Creating elements (`div`, `iframe`) and manipulating attributes (`id`, `style`, `class`).
    * **CSS:** Using properties like `content-visibility`, `contain`, `width`, `height`, `float`, `column-count`, `column-span`. Example:  `content-visibility: hidden` is used to lock elements.

* **Logical Reasoning and Examples:**
    * **Wheel Event Test:**  When an ancestor is locked, wheel events on descendants might be blocked from triggering layout changes on the ancestor.
        * **Input:** HTML structure with nested divs, the middle div locked, a wheel event listener on a descendant.
        * **Output:** Verification that flags like `BlockingWheelEventHandlerChanged` and `InsideBlockingWheelEventHandler` are set correctly on different elements based on the lock.
    * **Paint Property Update Test:**  When a locked element's descendant needs a paint property update, this update might be blocked from propagating upwards until the lock is released.
        * **Input:** HTML structure with nested divs, the middle div locked, a descendant needing a paint property update.
        * **Output:** Verification that flags like `NeedsPaintPropertyUpdate` and `DescendantNeedsPaintPropertyUpdate` are set correctly based on the lock.

* **Common Usage Errors:**
    * Expecting events to propagate through elements with `content-visibility: hidden` without understanding the locking mechanism.
    * Incorrectly assuming that changes within a `contain: paint` element will always trigger repaints on its ancestors when the element is locked.

* **Summary of Part 3:** This part focuses on testing the `DisplayLockContext`'s ability to:
    * Control the propagation of wheel event-related flags.
    * Block and manage paint property updates within locked subtrees.
    * Handle various rendering scenarios, including interactions with floating elements and multi-column layouts, while locked.
    * Prevent unnecessary layout invalidation with nested locks.
    * Manage paint dirty bits across locked boundaries.

By following these steps, I can provide a comprehensive and accurate summary of the code snippet's functionality. I'll refine the language to be clear and concise in the final response.
这是 `blink/renderer/core/display_lock/display_lock_context_test.cc` 文件的第三部分，主要功能是测试 `DisplayLockContext` 在处理各种渲染场景下的行为，特别是涉及到事件处理、属性更新、布局和绘制等方面的交互。

以下是该部分功能的详细列举和说明：

**功能列举：**

1. **测试后代元素的 Wheel 事件处理:**
   - 验证当一个元素被锁定 (`content-visibility: hidden` 或 `contain: style layout paint`) 时，其后代元素上的 `wheel` 事件处理器的状态和相关标志位的变化（例如 `BlockingWheelEventHandlerChanged`, `DescendantBlockingWheelEventHandlerChanged`, `InsideBlockingWheelEventHandler`）。
   - 测试在锁定和解锁元素后，这些标志位的变化以及脏位（dirty bits）的传播。

2. **测试后代元素需要 Paint Property 更新的情况:**
   - 验证当一个元素被锁定时，其后代元素需要进行 Paint Property 更新时，相关的标志位（例如 `NeedsPaintPropertyUpdate`, `DescendantNeedsPaintPropertyUpdate`) 的变化。
   - 测试锁定状态如何阻止 Paint Property 更新向上冒泡，以及解锁后更新的传播。

3. **测试在渲染过程中 `DisplayLockContext` 的行为:**
   - **框架文档移除:** 测试在尝试获取锁定的过程中，如果关联的框架文档被移除，是否会发生崩溃。
   - **Visual Overflow 计算:** 测试当子元素是 Paint Layer 时，锁定容器元素是否会阻止视觉溢出 (Visual Overflow) 的计算，并在解锁后进行计算。
   - **浮动子元素锁定:** 测试当包含浮动子元素的容器被锁定时，视觉溢出和可滚动溢出 (Scrollable Overflow) 矩形的计算是否被阻止，并在解锁后正确计算。
   - **强制锁定的 Visual Overflow 计算:** 测试在强制锁定阶段（使用 `ScopedForcedUpdate`），子元素的 Visual Overflow 计算是否能正常进行。
   - **匿名列 Spanner 上的选择:**  测试在多列布局中，当选择发生在匿名列 Spanner 上时，是否会发生崩溃。

4. **测试 `ObjectsNeedingLayout` 在考虑锁定的情况:**
   - 验证当元素被锁定时，`GetDocument().View()->CountObjectsNeedingLayout()` 方法如何统计需要布局的对象数量。
   - 测试锁定元素如何阻止其子元素的布局脏位传播到父元素。

5. **测试 Paint 脏位不会跨越锁定边界传播:**
   - 验证当一个元素被锁定时，其后代元素的 Paint 脏位不会传播到锁定的父元素之外。
   - 测试锁定和解锁状态下，`SelfNeedsRepaint` 和 `DescendantNeedsRepaint` 标志位的变化。

6. **测试嵌套锁定不会在隐藏或显示时导致不必要的布局失效:**
   - 验证当外层元素被锁定 (`content-visibility: hidden`) 后，内层元素即使设置了 `content-visibility: auto`，也不会导致不必要的布局失效。
   - 测试嵌套锁定的场景下，`IsObservingLifecycle` 的状态。

**与 Javascript, HTML, CSS 的关系及举例说明：**

- **HTML:** 代码中大量使用了 HTML 结构来搭建测试场景，例如使用 `<div>` 元素创建嵌套结构，并通过 `id` 属性来获取特定的元素。
  ```html
  <div id="ancestor">
    <div id="descendant">
      <div id="locked">
        <div id="handler"></div>
      </div>
    </div>
  </div>
  ```
- **CSS:** 使用 CSS 属性来控制元素的渲染行为和触发 `DisplayLockContext` 的作用。
  - **`content-visibility: hidden`:** 用于主动锁定元素，阻止其内容渲染和布局。例如：
    ```css
    .hidden { content-visibility: hidden }
    ```
    在测试中，通过添加或移除 `hidden` class 来模拟锁定和解锁。
  - **`contain: style layout paint`:** 用于创建独立渲染的容器，其内部的渲染变化不会影响外部。例如：
    ```css
    #locked {
      width: 100px;
      height: 100px;
      contain: style layout paint;
    }
    ```
  - **`float`:** 测试浮动元素在锁定容器内的布局行为。
  - **`column-count`, `column-span`:** 用于测试多列布局相关的场景。
- **Javascript:** 通过 Blink 引擎的 C++ 代码模拟 JavaScript 的事件监听行为。例如，`handler_element->addEventListener(event_type_names::kWheel, callback);` 模拟了 JavaScript 中给元素添加 `wheel` 事件监听器。

**逻辑推理、假设输入与输出：**

**示例 1：Wheel 事件处理测试**

**假设输入 (HTML):**

```html
<div id="ancestor">
  <div id="descendant">
    <div id="locked">
      <div id="handler"></div>
      <div id="lockedchild"></div>
    </div>
  </div>
</div>
```

**操作:**

1. 获取所有元素 (`ancestor`, `descendant`, `locked`, `handler`, `lockedchild`) 的 LayoutObject。
2. 使用 `LockElement(*locked_element, false)` 锁定 `#locked` 元素。
3. 在 `#handler` 元素上添加 `wheel` 事件监听器。

**预期输出:**

在锁定后，未提交锁定时：
- `handler_object->BlockingWheelEventHandlerChanged()` 为 `true`，因为 `#handler` 添加了事件监听器。
- `locked_object->DescendantBlockingWheelEventHandlerChanged()` 为 `true`，因为 `#locked` 的后代有阻塞 `wheel` 事件的处理器。
- `handler_object->InsideBlockingWheelEventHandler()` 和 `locked_object->InsideBlockingWheelEventHandler()` 为 `true`，表示这些元素内部有阻塞 `wheel` 事件的处理器。

在手动提交锁定并解锁后：
- `locked_object->BlockingWheelEventHandlerChanged()` 为 `true`，因为锁定状态发生了变化。
- `ancestor_object->DescendantBlockingWheelEventHandlerChanged()`, `handler_object->DescendantBlockingWheelEventHandlerChanged()`, `descendant_object->DescendantBlockingWheelEventHandlerChanged()` 为 `true`，表示后代有影响 `wheel` 事件处理的改变。

**示例 2：Paint Property 更新测试**

**假设输入 (HTML):**

```html
<div id="ancestor">
  <div id="descendant">
    <div id="locked">
      <div id="handler"></div>
    </div>
  </div>
</div>
```

**操作:**

1. 获取所有元素的 LayoutObject。
2. 使用 `LockElement(*locked_element, false)` 锁定 `#locked` 元素。
3. 调用 `handler_object->SetNeedsPaintPropertyUpdate()` 标记 `#handler` 需要进行 Paint Property 更新。

**预期输出:**

在锁定后，未提交锁定时：
- `handler_object->NeedsPaintPropertyUpdate()` 为 `true`。
- `ancestor_object->DescendantNeedsPaintPropertyUpdate()`, `descendant_object->DescendantNeedsPaintPropertyUpdate()`, `locked_object->DescendantNeedsPaintPropertyUpdate()` 为 `true`，表示后代需要 Paint Property 更新。

在手动提交锁定并解锁后：
- `locked_object->NeedsPaintPropertyUpdate()` 为 `true`，因为锁定状态变化可能触发 Paint Property 更新。
- `handler_object->NeedsPaintPropertyUpdate()` 为 `true`，因为 `#handler` 仍然需要更新。
- `ancestor_object->DescendantNeedsPaintPropertyUpdate()`, `descendant_object->DescendantNeedsPaintPropertyUpdate()`, `locked_object->DescendantNeedsPaintPropertyUpdate()` 为 `true`。

**用户或编程常见的使用错误：**

1. **误解 `content-visibility: hidden` 的作用:** 开发者可能认为 `content-visibility: hidden` 仅仅是隐藏元素，而忽略了它还会阻止元素的渲染和交互，这可能会导致事件监听器无法正常工作或布局更新被阻止。
   - **错误示例:** 在一个 `content-visibility: hidden` 的元素上添加事件监听器，并期望在元素隐藏时事件仍然能触发。实际上，事件可能不会被触发，或者触发后不会导致预期的渲染效果。

2. **错误地组合 `content-visibility` 和 `contain`:** 开发者可能不理解 `content-visibility` 和 `contain` 的组合效果。例如，在一个 `contain: paint` 的元素上使用 `content-visibility: hidden`，可能会期望其后代元素的绘制更新能够冒泡到父元素，但实际上由于锁定，这种冒泡会被阻止。
   - **错误示例:**  在一个 `contain: paint` 的父元素和一个需要频繁重绘的子元素中，当父元素使用 `content-visibility: hidden` 锁定后，可能会错误地认为子元素的重绘仍然会影响父元素的绘制层。

**功能归纳 (第 3 部分):**

这部分测试文件主要关注 `DisplayLockContext` 在处理各种渲染更新场景下的行为，特别是当元素被锁定（使用 `content-visibility: hidden` 或 `contain` 属性）时，如何影响事件处理、Paint Property 更新、布局计算以及绘制脏位的传播。测试用例覆盖了从基本的事件监听、属性更新到复杂的渲染流程控制，旨在验证锁定机制的正确性和效率，确保在需要的时候能够有效地阻止不必要的渲染操作，并在解锁后能够正确地恢复和处理这些更新。

Prompt: 
```
这是目录为blink/renderer/core/display_lock/display_lock_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(handler_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(lockedchild_object->InsideBlockingWheelEventHandler());

  // Manually commit the lock so that we can verify which dirty bits get
  // propagated.
  CommitElement(*locked_element, false);
  UnlockImmediate(locked_element->GetDisplayLockContext());

  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_TRUE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(lockedchild_object->BlockingWheelEventHandlerChanged());

  EXPECT_TRUE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_TRUE(handler_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_TRUE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(
      lockedchild_object->DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(handler_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(lockedchild_object->InsideBlockingWheelEventHandler());

  UpdateAllLifecyclePhasesForTest();
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
  EXPECT_TRUE(handler_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(lockedchild_object->InsideBlockingWheelEventHandler());
}

TEST_F(DisplayLockContextTest, DescendantWheelEventHandler) {
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

  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingWheelEventHandler());

  auto* callback = MakeGarbageCollected<DisplayLockEmptyEventListener>();
  handler_element->addEventListener(event_type_names::kWheel, callback);

  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_TRUE(handler_object->BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_TRUE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_TRUE(handler_object->BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_TRUE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingWheelEventHandler());

  // Do the same check again. For now, nothing is expected to change. However,
  // when we separate self and child layout, then some flags would be different.
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_TRUE(handler_object->BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_TRUE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingWheelEventHandler());

  // Manually commit the lock so that we can verify which dirty bits get
  // propagated.
  CommitElement(*locked_element, false);
  UnlockImmediate(locked_element->GetDisplayLockContext());

  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_TRUE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_TRUE(handler_object->BlockingWheelEventHandlerChanged());

  EXPECT_TRUE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_TRUE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_TRUE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(handler_object->InsideBlockingWheelEventHandler());

  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(ancestor_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->BlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->BlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(descendant_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(locked_object->DescendantBlockingWheelEventHandlerChanged());
  EXPECT_FALSE(handler_object->DescendantBlockingWheelEventHandlerChanged());

  EXPECT_FALSE(ancestor_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(descendant_object->InsideBlockingWheelEventHandler());
  EXPECT_FALSE(locked_object->InsideBlockingWheelEventHandler());
  EXPECT_TRUE(handler_object->InsideBlockingWheelEventHandler());
}

TEST_F(DisplayLockContextTest, DescendantNeedsPaintPropertyUpdateBlocked) {
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

  EXPECT_FALSE(ancestor_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(locked_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(handler_object->NeedsPaintPropertyUpdate());

  EXPECT_FALSE(ancestor_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(locked_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(handler_object->DescendantNeedsPaintPropertyUpdate());

  handler_object->SetNeedsPaintPropertyUpdate();

  EXPECT_FALSE(ancestor_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(locked_object->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(handler_object->NeedsPaintPropertyUpdate());

  EXPECT_TRUE(ancestor_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_TRUE(descendant_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_TRUE(locked_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(handler_object->DescendantNeedsPaintPropertyUpdate());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(ancestor_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(locked_object->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(handler_object->NeedsPaintPropertyUpdate());

  EXPECT_FALSE(ancestor_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_TRUE(locked_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(handler_object->DescendantNeedsPaintPropertyUpdate());

  locked_object->SetShouldCheckForPaintInvalidationWithoutLayoutChange();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(ancestor_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(locked_object->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(handler_object->NeedsPaintPropertyUpdate());

  EXPECT_FALSE(ancestor_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_TRUE(locked_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(handler_object->DescendantNeedsPaintPropertyUpdate());

  // Manually commit the lock so that we can verify which dirty bits get
  // propagated.
  CommitElement(*locked_element, false);
  UnlockImmediate(locked_element->GetDisplayLockContext());

  EXPECT_FALSE(ancestor_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(locked_object->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(handler_object->NeedsPaintPropertyUpdate());

  EXPECT_TRUE(ancestor_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_TRUE(descendant_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_TRUE(locked_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(handler_object->DescendantNeedsPaintPropertyUpdate());

  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(ancestor_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(locked_object->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(handler_object->NeedsPaintPropertyUpdate());

  EXPECT_FALSE(ancestor_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(descendant_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(locked_object->DescendantNeedsPaintPropertyUpdate());
  EXPECT_FALSE(handler_object->DescendantNeedsPaintPropertyUpdate());
}

class DisplayLockContextRenderingTest : public RenderingTest {
 public:
  DisplayLockContextRenderingTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }

  bool IsObservingLifecycle(DisplayLockContext* context) const {
    return context->is_registered_for_lifecycle_notifications_;
  }
  bool DescendantDependentFlagUpdateWasBlocked(
      DisplayLockContext* context) const {
    return context->needs_compositing_dependent_flag_update_;
  }
  void LockImmediate(DisplayLockContext* context) {
    context->SetRequestedState(EContentVisibility::kHidden);
  }
  void RunStartOfLifecycleTasks() {
    auto start_of_lifecycle_tasks =
        GetDocument().View()->TakeStartOfLifecycleTasksForTest();
    for (auto& task : start_of_lifecycle_tasks)
      std::move(task).Run();
  }
  DisplayLockUtilities::ScopedForcedUpdate GetScopedForcedUpdate(
      const Node* node,
      DisplayLockContext::ForcedPhase phase,
      bool include_self = false) {
    return DisplayLockUtilities::ScopedForcedUpdate(node, phase, include_self);
  }
};

TEST_F(DisplayLockContextRenderingTest, FrameDocumentRemovedWhileAcquire) {
  SetHtmlInnerHTML(R"HTML(
    <iframe id="frame"></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      div {
        contain: style layout;
      }
    </style>
    <div id="target"></target>
  )HTML");

  auto* target = ChildDocument().getElementById(AtomicString("target"));
  GetDocument().getElementById(AtomicString("frame"))->remove();

  LockImmediate(&target->EnsureDisplayLockContext());
}

TEST_F(DisplayLockContextRenderingTest,
       VisualOverflowCalculateOnChildPaintLayer) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden }
      .paint_layer { contain: paint }
      .composited { will-change: transform }
    </style>
    <div id=lockable class=paint_layer>
      <div id=parent class=paint_layer>
        <div id=child class=paint_layer>
          <span>content</span>
          <span>content</span>
          <span>content</span>
        </div>
      </div>
    </div>
  )HTML");

  auto* parent = GetDocument().getElementById(AtomicString("parent"));
  auto* parent_box = parent->GetLayoutBoxModelObject();
  ASSERT_TRUE(parent_box);
  EXPECT_TRUE(parent_box->Layer());
  EXPECT_TRUE(parent_box->HasSelfPaintingLayer());

  // Lock the container.
  auto* lockable = GetDocument().getElementById(AtomicString("lockable"));
  lockable->classList().Add(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  auto* child_layer = GetPaintLayerByElementId("child");
  child_layer->SetNeedsVisualOverflowRecalc();
  EXPECT_TRUE(child_layer->NeedsVisualOverflowRecalc());

  // The following should not crash/DCHECK.
  UpdateAllLifecyclePhasesForTest();

  // Verify that the display lock knows that the descendant dependent flags
  // update was blocked.
  ASSERT_TRUE(lockable->GetDisplayLockContext());
  EXPECT_TRUE(DescendantDependentFlagUpdateWasBlocked(
      lockable->GetDisplayLockContext()));
  EXPECT_TRUE(child_layer->NeedsVisualOverflowRecalc());

  // After unlocking, we should process the pending visual overflow recalc.
  lockable->classList().Remove(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(child_layer->NeedsVisualOverflowRecalc());
}

TEST_F(DisplayLockContextRenderingTest, FloatChildLocked) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden }
      #floating { float: left; width: 100px; height: 100px }
    </style>
    <div id=lockable style="width: 200px; height: 50px; position: absolute">
      <div id=floating></div>
    </div>
  )HTML");

  auto* lockable = GetDocument().getElementById(AtomicString("lockable"));
  auto* lockable_box = lockable->GetLayoutBox();
  auto* floating = GetDocument().getElementById(AtomicString("floating"));
  EXPECT_EQ(PhysicalRect(0, 0, 200, 100), lockable_box->VisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 200, 100),
            lockable_box->ScrollableOverflowRect());

  lockable->classList().Add(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  // Verify that the display lock knows that the descendant dependent flags
  // update was blocked.
  ASSERT_TRUE(lockable->GetDisplayLockContext());
  EXPECT_TRUE(DescendantDependentFlagUpdateWasBlocked(
      lockable->GetDisplayLockContext()));
  EXPECT_EQ(PhysicalRect(0, 0, 200, 50), lockable_box->VisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 200, 50),
            lockable_box->ScrollableOverflowRect());

  floating->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
  // The following should not crash/DCHECK.
  UpdateAllLifecyclePhasesForTest();

  ASSERT_TRUE(lockable->GetDisplayLockContext());
  EXPECT_TRUE(DescendantDependentFlagUpdateWasBlocked(
      lockable->GetDisplayLockContext()));
  EXPECT_EQ(PhysicalRect(0, 0, 200, 50), lockable_box->VisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 200, 50),
            lockable_box->ScrollableOverflowRect());

  // After unlocking, we should process the pending visual overflow recalc.
  lockable->classList().Remove(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(PhysicalRect(0, 0, 200, 200), lockable_box->VisualOverflowRect());
  EXPECT_EQ(PhysicalRect(0, 0, 200, 200),
            lockable_box->ScrollableOverflowRect());
}

TEST_F(DisplayLockContextRenderingTest,
       VisualOverflowCalculateOnChildPaintLayerInForcedLock) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .hidden { content-visibility: hidden }
      .paint_layer { contain: paint }
      .composited { will-change: transform }
    </style>
    <div id=lockable class=paint_layer>
      <div id=parent class=paint_layer>
        <div id=child class=paint_layer>
          <span>content</span>
          <span>content</span>
          <span>content</span>
        </div>
      </div>
    </div>
  )HTML");

  auto* parent = GetDocument().getElementById(AtomicString("parent"));
  auto* parent_box = parent->GetLayoutBoxModelObject();
  ASSERT_TRUE(parent_box);
  EXPECT_TRUE(parent_box->Layer());
  EXPECT_TRUE(parent_box->HasSelfPaintingLayer());

  // Lock the container.
  auto* lockable = GetDocument().getElementById(AtomicString("lockable"));
  lockable->classList().Add(AtomicString("hidden"));
  UpdateAllLifecyclePhasesForTest();

  auto* child_layer = GetPaintLayerByElementId("child");
  child_layer->SetNeedsVisualOverflowRecalc();
  EXPECT_TRUE(child_layer->NeedsVisualOverflowRecalc());

  ASSERT_TRUE(lockable->GetDisplayLockContext());
  {
    auto scope = GetScopedForcedUpdate(
        lockable, DisplayLockContext::ForcedPhase::kPrePaint,
        true /* include self */);

    // The following should not crash/DCHECK.
    UpdateAllLifecyclePhasesForTest();
  }

  // Verify that the display lock doesn't keep extra state since the update was
  // processed.
  EXPECT_FALSE(DescendantDependentFlagUpdateWasBlocked(
      lockable->GetDisplayLockContext()));
  EXPECT_FALSE(child_layer->NeedsVisualOverflowRecalc());

  // After unlocking, we should not need to do any extra work.
  lockable->classList().Remove(AtomicString("hidden"));
  EXPECT_FALSE(child_layer->NeedsVisualOverflowRecalc());

  UpdateAllLifecyclePhasesForTest();
}
TEST_F(DisplayLockContextRenderingTest,
       SelectionOnAnonymousColumnSpannerDoesNotCrash) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      #columns {
        column-count: 5;
      }
      #spanner {
        column-span: all;
      }
    </style>
    <div id="columns">
      <div id="spanner"></div>
    </div>
  )HTML");

  auto* columns_object =
      GetDocument().getElementById(AtomicString("columns"))->GetLayoutObject();
  LayoutObject* spanner_placeholder_object = nullptr;
  for (auto* candidate = columns_object->SlowFirstChild(); candidate;
       candidate = candidate->NextSibling()) {
    if (candidate->IsLayoutMultiColumnSpannerPlaceholder()) {
      spanner_placeholder_object = candidate;
      break;
    }
  }

  ASSERT_TRUE(spanner_placeholder_object);
  EXPECT_FALSE(spanner_placeholder_object->CanBeSelectionLeaf());
}

TEST_F(DisplayLockContextRenderingTest, ObjectsNeedingLayoutConsidersLocks) {
  SetHtmlInnerHTML(R"HTML(
    <div id=a>
      <div id=b>
        <div id=c></div>
        <div id=d></div>
      </div>
      <div id=e>
        <div id=f></div>
        <div id=g></div>
      </div>
    </div>
  )HTML");

  // Dirty all of the leaf nodes.
  auto dirty_all = [this]() {
    GetDocument()
        .getElementById(AtomicString("c"))
        ->GetLayoutObject()
        ->SetNeedsLayout("test");
    GetDocument()
        .getElementById(AtomicString("d"))
        ->GetLayoutObject()
        ->SetNeedsLayout("test");
    GetDocument()
        .getElementById(AtomicString("f"))
        ->GetLayoutObject()
        ->SetNeedsLayout("test");
    GetDocument()
        .getElementById(AtomicString("g"))
        ->GetLayoutObject()
        ->SetNeedsLayout("test");
  };

  unsigned dirty_count = 0;
  unsigned total_count = 0;
  bool is_subtree = false;

  dirty_all();
  GetDocument().View()->CountObjectsNeedingLayout(dirty_count, total_count,
                                                  is_subtree);
  // 7 divs + body + html + layout view
  EXPECT_EQ(dirty_count, 10u);
  EXPECT_EQ(total_count, 10u);

  GetDocument()
      .getElementById(AtomicString("e"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("content-visibility: hidden"));
  UpdateAllLifecyclePhasesForTest();

  // Note that the dirty_all call propagate the dirty bit from the unlocked
  // subtree all the way up to the layout view, so everything on the way up is
  // dirtied.
  dirty_all();
  GetDocument().View()->CountObjectsNeedingLayout(dirty_count, total_count,
                                                  is_subtree);
  // Element with 2 children is locked, and it itself isn't dirty (just the
  // children are). So, 10 - 3 = 7
  EXPECT_EQ(dirty_count, 7u);
  // We still see the locked element, so the total is 8.
  EXPECT_EQ(total_count, 8u);

  GetDocument()
      .getElementById(AtomicString("a"))
      ->setAttribute(html_names::kStyleAttr,
                     AtomicString("content-visibility: hidden"));
  UpdateAllLifecyclePhasesForTest();

  // Note that this dirty_all call is now not propagating the dirty bits at all,
  // since they are stopped at the top level div.
  dirty_all();
  GetDocument().View()->CountObjectsNeedingLayout(dirty_count, total_count,
                                                  is_subtree);
  // Top level element is locked and the dirty bits were not propagated, so we
  // expect 0 dirty elements. The total should be 4 ('a' + body + html + layout
  // view);
  EXPECT_EQ(dirty_count, 0u);
  EXPECT_EQ(total_count, 4u);
}

TEST_F(DisplayLockContextRenderingTest,
       PaintDirtyBitsNotPropagatedAcrossBoundary) {
  SetHtmlInnerHTML(R"HTML(
    <style>
    .locked { content-visibility: hidden; }
    div { contain: paint; }
    </style>
    <div id=parent>
      <div id=lockable>
        <div id=child>
          <div id=grandchild></div>
        </div>
      </div>
    </div>
  )HTML");

  auto* parent = GetDocument().getElementById(AtomicString("parent"));
  auto* lockable = GetDocument().getElementById(AtomicString("lockable"));
  auto* child = GetDocument().getElementById(AtomicString("child"));
  auto* grandchild = GetDocument().getElementById(AtomicString("grandchild"));

  auto* parent_box = parent->GetLayoutBoxModelObject();
  auto* lockable_box = lockable->GetLayoutBoxModelObject();
  auto* child_box = child->GetLayoutBoxModelObject();
  auto* grandchild_box = grandchild->GetLayoutBoxModelObject();

  ASSERT_TRUE(parent_box);
  ASSERT_TRUE(lockable_box);
  ASSERT_TRUE(child_box);
  ASSERT_TRUE(grandchild_box);

  ASSERT_TRUE(parent_box->HasSelfPaintingLayer());
  ASSERT_TRUE(lockable_box->HasSelfPaintingLayer());
  ASSERT_TRUE(child_box->HasSelfPaintingLayer());
  ASSERT_TRUE(grandchild_box->HasSelfPaintingLayer());

  auto* parent_layer = parent_box->Layer();
  auto* lockable_layer = lockable_box->Layer();
  auto* child_layer = child_box->Layer();
  auto* grandchild_layer = grandchild_box->Layer();

  EXPECT_FALSE(parent_layer->SelfOrDescendantNeedsRepaint());
  EXPECT_FALSE(lockable_layer->SelfOrDescendantNeedsRepaint());
  EXPECT_FALSE(child_layer->SelfOrDescendantNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->SelfOrDescendantNeedsRepaint());

  lockable->classList().Add(AtomicString("locked"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // Lockable layer needs repainting after locking.
  EXPECT_FALSE(parent_layer->SelfNeedsRepaint());
  EXPECT_TRUE(lockable_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_layer->SelfNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->SelfNeedsRepaint());

  // Breadcrumbs are set from the lockable layer.
  EXPECT_TRUE(parent_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(lockable_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(child_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->DescendantNeedsRepaint());

  UpdateAllLifecyclePhasesForTest();

  // Everything is clean.
  EXPECT_FALSE(parent_layer->SelfNeedsRepaint());
  EXPECT_FALSE(lockable_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_layer->SelfNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->SelfNeedsRepaint());

  // Breadcrumbs are clean as well.
  EXPECT_FALSE(parent_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(lockable_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(child_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->DescendantNeedsRepaint());

  grandchild_layer->SetNeedsRepaint();

  // Grandchild needs repaint, so everything else should be clean.
  EXPECT_FALSE(parent_layer->SelfNeedsRepaint());
  EXPECT_FALSE(lockable_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_layer->SelfNeedsRepaint());
  EXPECT_TRUE(grandchild_layer->SelfNeedsRepaint());

  // Breadcrumbs are set from the lockable layer but are stopped at the locked
  // boundary.
  EXPECT_FALSE(parent_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(lockable_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(child_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->DescendantNeedsRepaint());

  // Updating the lifecycle does not clean the dirty bits.
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(parent_layer->SelfNeedsRepaint());
  EXPECT_FALSE(lockable_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_layer->SelfNeedsRepaint());
  EXPECT_TRUE(grandchild_layer->SelfNeedsRepaint());

  EXPECT_FALSE(parent_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(lockable_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(child_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->DescendantNeedsRepaint());

  // Unlocking causes lockable to repaint itself.
  lockable->classList().Remove(AtomicString("locked"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_FALSE(parent_layer->SelfNeedsRepaint());
  EXPECT_TRUE(lockable_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_layer->SelfNeedsRepaint());
  EXPECT_TRUE(grandchild_layer->SelfNeedsRepaint());

  EXPECT_TRUE(parent_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(lockable_layer->DescendantNeedsRepaint());
  EXPECT_TRUE(child_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->DescendantNeedsRepaint());

  UpdateAllLifecyclePhasesForTest();

  // Everything should be clean.
  EXPECT_FALSE(parent_layer->SelfNeedsRepaint());
  EXPECT_FALSE(lockable_layer->SelfNeedsRepaint());
  EXPECT_FALSE(child_layer->SelfNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->SelfNeedsRepaint());

  // Breadcrumbs are clean as well.
  EXPECT_FALSE(parent_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(lockable_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(child_layer->DescendantNeedsRepaint());
  EXPECT_FALSE(grandchild_layer->DescendantNeedsRepaint());
}

TEST_F(DisplayLockContextRenderingTest,
       NestedLockDoesNotInvalidateOnHideOrShow) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .auto { content-visibility: auto; }
      .hidden { content-visibility: hidden; }
      .item { height: 10px; }
      /* this is important to not invalidate layout when we hide the element! */
      #outer { contain: style layout; }
    </style>
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

  // Run the following checks a few times since we sh
"""


```