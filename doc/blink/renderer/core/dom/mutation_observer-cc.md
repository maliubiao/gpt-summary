Response:
Let's break down the thought process for analyzing this `mutation_observer.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relation to JavaScript/HTML/CSS, examples, logical inferences, common errors, and debugging clues.

2. **Initial Scan and Keywords:**  Start by skimming the code, looking for key terms like `MutationObserver`, `observe`, `disconnect`, `takeRecords`, `callback`, `attributes`, `childList`, `subtree`, `HTMLSlotElement`, `Document`, `Agent`, `ExecutionContext`, and JavaScript-related terms like `ScriptState`, `V8MutationCallback`, and `ExceptionState`. These keywords give immediate clues about the file's purpose.

3. **Identify Core Functionality:** The presence of methods like `observe`, `disconnect`, and `takeRecords` strongly suggests this file implements the core logic for the JavaScript `MutationObserver` API. The names suggest observing DOM changes, stopping observation, and retrieving the recorded changes.

4. **Map to JavaScript API:** Connect the identified core functionality to the corresponding JavaScript API. `observe` directly maps to the `observe()` method of a `MutationObserver` instance in JavaScript. `disconnect` and `takeRecords` have similar direct mappings.

5. **Analyze Data Structures:** Pay attention to the data structures used:
    * `MutationRecordVector`:  Likely stores the details of the changes (what changed, where, etc.).
    * `MutationObserverRegistrationSet`:  Keeps track of which nodes this observer is watching.
    * `MutationObserverInit`:  Represents the options passed to the `observe()` method in JavaScript (e.g., `attributes`, `childList`).
    * `MutationObserverAgentData`: This seems like a per-agent (likely browser process or worker) storage for active observers and slot change lists, crucial for managing and delivering mutations efficiently.

6. **Understand the Delivery Mechanism:**  The `Deliver()` method and the `MutationObserverAgentData::DeliverMutations()` method are critical. These methods handle the process of gathering the recorded mutations and invoking the JavaScript callback function. Note the sorting of observers by priority.

7. **Examine Relationships with HTML/CSS:**
    * **HTML:** The observation targets are `Node` objects, which include HTML elements. The `HTMLSlotElement` is explicitly handled, indicating its special behavior with mutation observation. Changes to attributes and child nodes directly affect the HTML structure.
    * **CSS:** While the code doesn't directly manipulate CSS, changes to HTML attributes (like `class` or `style`) that are observed by the `MutationObserver` *can* indirectly trigger CSS updates (style recalculation, layout).

8. **Logical Inference and Examples:**  Based on the understanding of the API and the code, start constructing examples.
    * **JavaScript Interaction:** Show how to create a `MutationObserver` in JavaScript and use its methods.
    * **HTML Interaction:** Demonstrate observing changes to specific HTML elements.
    * **CSS Interaction (indirect):** Show how observing attribute changes can relate to CSS classes.
    * **Input/Output (Hypothetical):**  Create scenarios with specific DOM manipulations and predict the resulting `MutationRecord` objects. This helps solidify understanding of what kinds of changes trigger notifications.

9. **Identify Common Errors:** Think about how developers might misuse the `MutationObserver` API. Incorrect option settings, forgetting to disconnect the observer, and assuming synchronous behavior are common pitfalls.

10. **Debugging Clues:**  Consider the flow of execution when a DOM change occurs. How does the system know to notify the observer? The `EnqueueMutationRecord` function is a likely entry point. The `MutationObserverAgentData` plays a crucial role in queueing and delivering notifications. User actions that lead to DOM manipulation are the starting point.

11. **Structure the Output:** Organize the findings logically into the requested categories: Functionality, JavaScript/HTML/CSS relations, logical inference, common errors, and debugging. Use clear headings and bullet points for readability.

12. **Refine and Elaborate:** Review the generated information. Are the explanations clear and concise? Are the examples relevant and easy to understand?  Add more detail where needed. For instance, explicitly explain the purpose of `attributeOldValue` and `characterDataOldValue`.

13. **Consider Edge Cases:**  Think about scenarios like observing changes within shadow DOM (hence the `HTMLSlotElement` handling). Consider the implications of observing the `subtree`.

By following this step-by-step approach, starting with high-level understanding and gradually digging deeper into the code, a comprehensive analysis of the `mutation_observer.cc` file can be produced. The key is to connect the code's implementation details back to the user-facing JavaScript API and the underlying web technologies (HTML and CSS).
好的，让我们来分析一下 `blink/renderer/core/dom/mutation_observer.cc` 这个文件。

**文件功能总览**

这个文件实现了 Chromium Blink 引擎中 `MutationObserver` API 的核心逻辑。`MutationObserver` 是一个 Web API，它允许 JavaScript 监听 DOM 树的变化，并在变化发生时异步地执行回调函数。

**具体功能列举**

1. **创建和管理 MutationObserver 对象:**
   - 提供了 `MutationObserver::Create` 方法来创建 `MutationObserver` 实例。
   - 内部维护了观察者对象的生命周期和相关数据。

2. **注册观察目标和配置:**
   - `MutationObserver::observe` 方法允许 JavaScript 指定要观察的 DOM 节点以及需要监听的变化类型（例如，子节点变化、属性变化、文本内容变化等）。
   - 它解析 JavaScript 传递的 `MutationObserverInit` 对象，提取观察选项（如 `attributes`, `childList`, `subtree`, `attributeOldValue`, `attributeFilter`, `characterData`, `characterDataOldValue`）。
   - 将观察者与目标节点以及观察配置关联起来，通过 `Node::RegisterMutationObserver` 完成注册。

3. **记录 DOM 变化:**
   - 当被观察的 DOM 节点发生变化时，相关的代码会创建 `MutationRecord` 对象来记录这些变化（例如，添加/移除的节点、修改的属性、旧值和新值等）。
   - `MutationObserver::EnqueueMutationRecord` 方法负责将这些 `MutationRecord` 对象添加到观察者的内部队列 `records_` 中。

4. **异步通知回调:**
   - `MutationObserverAgentData` 类负责管理所有活跃的 `MutationObserver` 对象，并确保回调函数在合适的时机异步执行。
   - 当有新的 `MutationRecord` 被加入时，会将相关的 `MutationObserver` 标记为活跃。
   - 通过微任务（microtask）机制，`MutationObserverAgentData::DeliverMutations` 方法会在 JavaScript 事件循环的合适时机被调用。
   - `MutationObserver::Deliver` 方法负责将累积的 `MutationRecord` 传递给 JavaScript 回调函数。

5. **断开观察:**
   - `MutationObserver::disconnect` 方法允许 JavaScript 停止观察所有关联的 DOM 节点。
   - 它会清理内部的注册信息和待处理的 `MutationRecord`。

6. **立即获取记录:**
   - `MutationObserver::takeRecords` 方法允许 JavaScript 立即获取当前累积的所有 `MutationRecord`，并清空内部队列。

7. **处理 `<slot>` 元素的变化:**
   - 特别处理了 `HTMLSlotElement` 元素的变化，通过 `MutationObserver::EnqueueSlotChange` 和 `MutationObserver::CleanSlotChangeList` 来管理 slot 的变化事件，确保在 MutationObserver 的回调之前处理 slotchange 事件。

8. **与 Inspector 的集成:**
   - 包含了 `CancelInspectorAsyncTasks` 方法，表明了与 Chrome DevTools (Inspector) 的集成，可能用于在调试时取消或管理相关的异步任务。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **JavaScript:**
    - `MutationObserver` 对象是由 JavaScript 代码创建和操作的。
    - JavaScript 代码通过 `observe()` 方法指定要观察的 DOM 节点和变化类型。
    - 当 DOM 变化发生时，会调用 JavaScript 中提供的回调函数，并传递一个 `MutationRecord` 对象数组作为参数。

    ```javascript
    // JavaScript 示例
    const targetNode = document.getElementById('myElement');
    const observer = new MutationObserver(function(mutationsList, observer) {
      for(let mutation of mutationsList) {
        if (mutation.type === 'childList') {
          console.log('A child node has been added or removed.');
        } else if (mutation.type === 'attributes') {
          console.log('The ' + mutation.attributeName + ' attribute was modified.');
        } else if (mutation.type === 'characterData') {
          console.log('The text content was modified.');
        }
      }
    });

    const config = { attributes: true, childList: true, subtree: true, characterData: true };
    observer.observe(targetNode, config);

    // ... 在 JavaScript 中修改 targetNode 的属性、子节点或文本内容 ...

    observer.disconnect(); // 停止观察
    ```

* **HTML:**
    - `MutationObserver` 观察的是 HTML 结构的变化。
    - JavaScript 中指定的观察目标通常是 HTML 元素。
    - 当 HTML 结构被修改（例如，添加、删除元素，修改属性）时，`MutationObserver` 会记录这些变化。

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>MutationObserver Example</title>
    </head>
    <body>
      <div id="myElement">
        <p>Initial text</p>
      </div>
      <script>
        // ... 上面的 JavaScript 代码 ...
        const myElement = document.getElementById('myElement');
        myElement.textContent = 'New text content'; // 触发 characterData 类型的 mutation
        const newParagraph = document.createElement('p');
        newParagraph.textContent = 'Another paragraph';
        myElement.appendChild(newParagraph); // 触发 childList 类型的 mutation
        myElement.setAttribute('class', 'highlight'); // 触发 attributes 类型的 mutation
      </script>
    </body>
    </html>
    ```

* **CSS:**
    - 虽然 `MutationObserver` 不直接观察 CSS 的变化，但它可以观察到影响 CSS 渲染的 HTML 变化。
    - 例如，当元素的 `class` 属性被修改时，CSS 规则可能会因此而应用或移除，`MutationObserver` 可以捕捉到这个属性变化。

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>MutationObserver and CSS</title>
      <style>
        .highlight {
          background-color: yellow;
        }
      </style>
    </head>
    <body>
      <div id="myElement">This is some text.</div>
      <button onclick="toggleHighlight()">Toggle Highlight</button>
      <script>
        const targetNode = document.getElementById('myElement');
        const observer = new MutationObserver(function(mutationsList) {
          for (let mutation of mutationsList) {
            if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
              console.log('Class attribute changed:', mutation.oldValue, targetNode.className);
            }
          }
        });
        observer.observe(targetNode, { attributes: true, attributeOldValue: true });

        function toggleHighlight() {
          if (targetNode.classList.contains('highlight')) {
            targetNode.classList.remove('highlight');
          } else {
            targetNode.classList.add('highlight');
          }
        }
      </script>
    </body>
    </html>
    ```

**逻辑推理和假设输入与输出**

假设我们有以下 JavaScript 代码和一个简单的 HTML 结构：

**HTML:**

```html
<div id="target">
  <span>Initial Text</span>
</div>
```

**JavaScript:**

```javascript
const targetNode = document.getElementById('target');
const observer = new MutationObserver(function(mutationsList) {
  console.log("Mutations:", mutationsList);
});
observer.observe(targetNode, { childList: true, subtree: true, characterData: true });

const spanElement = targetNode.querySelector('span');
spanElement.textContent = 'Updated Text'; // 修改文本内容
const newElement = document.createElement('p');
newElement.textContent = 'New Paragraph';
targetNode.appendChild(newElement); // 添加新元素
```

**假设输入：** 上述 JavaScript 代码执行后，DOM 结构发生变化。

**逻辑推理：**

1. 修改 `span` 元素的 `textContent` 会触发一个 `characterData` 类型的 `MutationRecord`。
2. 向 `targetNode` 添加一个新的 `p` 元素会触发一个 `childList` 类型的 `MutationRecord`。

**假设输出 (控制台打印的 `mutationsList`):**

```json
[
  {
    "type": "characterData",
    "target": { /* 指向 span 元素的 Node 对象 */ },
    "addedNodes": [],
    "removedNodes": [],
    "previousSibling": null,
    "nextSibling": null,
    "attributeName": null,
    "attributeNamespace": null,
    "oldValue": "Initial Text"
  },
  {
    "type": "childList",
    "target": { /* 指向 target div 元素的 Node 对象 */ },
    "addedNodes": [ { /* 指向新创建的 p 元素的 Node 对象 */ } ],
    "removedNodes": [],
    "previousSibling": { /* 指向 span 元素的 Node 对象 */ },
    "nextSibling": null,
    "attributeName": null,
    "attributeNamespace": null,
    "oldValue": null
  }
]
```

**用户或编程常见的使用错误及举例说明**

1. **忘记 `disconnect()` 观察者:** 如果在不需要观察时忘记调用 `observer.disconnect()`，会导致内存泄漏和不必要的性能开销，因为观察者会继续监听 DOM 变化。

   ```javascript
   const target = document.getElementById('myDiv');
   const observer = new MutationObserver(() => { /* ... */ });
   observer.observe(target, { childList: true });
   // ... 某些操作后，但忘记调用 observer.disconnect();
   ```

2. **错误的观察配置:** 配置不当可能导致没有捕获到期望的变化，或者捕获到过多的不相关的变化，影响性能。例如，只监听 `childList` 但忽略了属性变化。

   ```javascript
   const target = document.getElementById('myElement');
   const observer = new MutationObserver(() => { console.log('Child changed'); });
   observer.observe(target, { childList: true });
   target.setAttribute('class', 'new-class'); // 不会触发回调
   ```

3. **在回调函数中进行大量的同步 DOM 操作:** 这可能导致性能问题，因为每次 DOM 变化都可能触发回调，如果回调中又进行大量的 DOM 操作，可能会形成循环触发。

   ```javascript
   const target = document.getElementById('container');
   const observer = new MutationObserver((mutations) => {
     mutations.forEach(mutation => {
       if (mutation.addedNodes.length) {
         const newNode = document.createElement('p');
         newNode.textContent = 'Another paragraph';
         target.appendChild(newNode); // 可能导致无限循环触发回调
       }
     });
   });
   observer.observe(target, { childList: true });
   const initialNode = document.createElement('p');
   target.appendChild(initialNode);
   ```

4. **假设回调是同步的:** `MutationObserver` 的回调是异步的，在浏览器空闲时才会执行。依赖回调的立即执行可能会导致逻辑错误。

   ```javascript
   let isChanged = false;
   const observer = new MutationObserver(() => { isChanged = true; });
   observer.observe(document.body, { childList: true });
   document.body.appendChild(document.createElement('div'));
   console.log(isChanged); // 很可能仍然是 false，因为回调还没执行
   ```

**用户操作是如何一步步的到达这里，作为调试线索**

当你在浏览器中使用涉及到 DOM 变化的 JavaScript 代码时，最终会触发 `mutation_observer.cc` 中的逻辑。以下是一个典型的用户操作流程：

1. **用户交互或 JavaScript 执行:** 用户在网页上进行操作，例如点击按钮、输入文本，或者 JavaScript 代码通过 `setTimeout`、`setInterval` 或事件监听器执行。

2. **DOM 操作:**  这些操作导致 JavaScript 代码修改 DOM 结构或属性。例如：
   - 使用 `document.createElement` 和 `appendChild` 添加新元素。
   - 使用 `element.removeChild` 删除元素。
   - 修改元素的 `textContent` 或 `innerHTML`。
   - 使用 `element.setAttribute` 或 `element.removeAttribute` 修改或删除属性。
   - 修改元素的 `className` 或 `style` 属性。

3. **触发 Mutation Observation:** 如果有 `MutationObserver` 对象正在观察这些被修改的节点，并且观察配置包含了相应的变化类型，那么 Blink 引擎会捕获这些变化。

4. **创建 MutationRecord:**  Blink 引擎会创建 `MutationRecord` 对象来记录这些具体的 DOM 变化，包括变化类型、目标节点、添加/删除的节点、修改的属性和旧值等。这个过程发生在 C++ 代码中，包括 `mutation_observer.cc` 文件中的相关逻辑。

5. **将 MutationRecord 入队:** `MutationObserver::EnqueueMutationRecord` 方法会被调用，将 `MutationRecord` 添加到观察者的内部队列 `records_` 中。

6. **激活观察者并调度微任务:** `MutationObserverAgentData` 会管理活跃的观察者，并调度一个微任务来执行回调。

7. **JavaScript 事件循环:**  在 JavaScript 事件循环的后续迭代中，当没有其他同步任务需要执行时，之前调度的微任务会被执行。

8. **执行回调函数:** `MutationObserver::Deliver` 方法会被调用，它会将累积的 `MutationRecord` 数组传递给 JavaScript 中定义的回调函数。

9. **回调函数处理变化:** JavaScript 回调函数接收到 `MutationRecord` 数组，并根据记录的信息执行相应的逻辑。

**作为调试线索:**

* **断点:** 在 `mutation_observer.cc` 的关键方法（如 `observe`, `EnqueueMutationRecord`, `Deliver`）设置断点，可以追踪 DOM 变化发生时 Blink 引擎的处理流程。
* **日志:**  添加日志输出可以帮助理解观察者是如何注册、变化是如何记录和传递的。
* **Chrome DevTools:** 使用 Chrome DevTools 的 "Performance" 面板可以查看 MutationObserver 回调的执行时间，帮助识别性能瓶颈。 "Elements" 面板的 "Break on..." 功能可以让你在特定类型的 DOM 变化发生时暂停 JavaScript 执行。
* **理解异步性:** 意识到 `MutationObserver` 的回调是异步的，有助于理解为什么某些代码的执行顺序与预期不符。

希望以上分析能够帮助你理解 `blink/renderer/core/dom/mutation_observer.cc` 文件的功能和它在整个 Web 技术栈中的作用。

### 提示词
```
这是目录为blink/renderer/core/dom/mutation_observer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/dom/mutation_observer.h"

#include <algorithm>

#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mutation_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mutation_observer_init.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/mutation_observer_registration.h"
#include "third_party/blink/renderer/core/dom/mutation_record.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"

namespace blink {

using SlotChangeList = HeapVector<Member<HTMLSlotElement>>;

static unsigned g_observer_priority = 0;
struct MutationObserver::ObserverLessThan {
  bool operator()(const Member<MutationObserver>& lhs,
                  const Member<MutationObserver>& rhs) {
    return lhs->priority_ < rhs->priority_;
  }
};

class MutationObserverAgentData
    : public GarbageCollected<MutationObserverAgentData>,
      public Supplement<Agent> {
 public:
  constexpr static const char kSupplementName[] = "MutationObserverAgentData";

  explicit MutationObserverAgentData(Agent& agent) : Supplement<Agent>(agent) {}

  static MutationObserverAgentData& From(Agent& agent) {
    MutationObserverAgentData* supplement =
        Supplement<Agent>::From<MutationObserverAgentData>(agent);
    if (!supplement) {
      supplement = MakeGarbageCollected<MutationObserverAgentData>(agent);
      ProvideTo(agent, supplement);
    }
    return *supplement;
  }

  void Trace(Visitor* visitor) const override {
    Supplement<Agent>::Trace(visitor);
    visitor->Trace(active_mutation_observers_);
    visitor->Trace(active_slot_change_list_);
  }

  void EnqueueSlotChange(HTMLSlotElement& slot) {
    EnsureEnqueueMicrotask();
    active_slot_change_list_.push_back(&slot);
  }

  void CleanSlotChangeList(Document& document) {
    SlotChangeList kept;
    kept.reserve(active_slot_change_list_.size());
    for (auto& slot : active_slot_change_list_) {
      if (slot->GetDocument() != document)
        kept.push_back(slot);
    }
    active_slot_change_list_.swap(kept);
  }

  void ActivateObserver(MutationObserver* observer) {
    EnsureEnqueueMicrotask();
    active_mutation_observers_.insert(observer);
  }

  void ClearActiveObserver(MutationObserver* observer) {
    active_mutation_observers_.erase(observer);
  }

 private:
  void EnsureEnqueueMicrotask() {
    if (active_mutation_observers_.empty() &&
        active_slot_change_list_.empty()) {
      GetSupplementable()->event_loop()->EnqueueMicrotask(
          WTF::BindOnce(&MutationObserverAgentData::DeliverMutations,
                        WrapWeakPersistent(this)));
    }
  }

  void DeliverMutations() {
    // These steps are defined in DOM Standard's "notify mutation observers".
    // https://dom.spec.whatwg.org/#notify-mutation-observers
    DCHECK(IsMainThread());
    MutationObserverVector observers(active_mutation_observers_);
    active_mutation_observers_.clear();
    SlotChangeList slots;
    slots.swap(active_slot_change_list_);
    for (const auto& slot : slots)
      slot->ClearSlotChangeEventEnqueued();
    std::sort(observers.begin(), observers.end(),
              MutationObserver::ObserverLessThan());
    for (const auto& observer : observers)
      observer->Deliver();
    for (const auto& slot : slots)
      slot->DispatchSlotChangeEvent();
  }

 private:
  // For MutationObserver.
  MutationObserverSet active_mutation_observers_;
  SlotChangeList active_slot_change_list_;
};

class MutationObserver::V8DelegateImpl final
    : public MutationObserver::Delegate,
      public ExecutionContextClient {
 public:
  static V8DelegateImpl* Create(V8MutationCallback* callback,
                                ExecutionContext* execution_context) {
    return MakeGarbageCollected<V8DelegateImpl>(callback, execution_context);
  }

  V8DelegateImpl(V8MutationCallback* callback,
                 ExecutionContext* execution_context)
      : ExecutionContextClient(execution_context), callback_(callback) {}

  ExecutionContext* GetExecutionContext() const override {
    return ExecutionContextClient::GetExecutionContext();
  }

  void Deliver(const MutationRecordVector& records,
               MutationObserver& observer) override {
    // https://dom.spec.whatwg.org/#notify-mutation-observers
    // step 5-4. specifies that the callback this value is a MutationObserver.
    callback_->InvokeAndReportException(&observer, records, &observer);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(callback_);
    MutationObserver::Delegate::Trace(visitor);
    ExecutionContextClient::Trace(visitor);
  }

 private:
  Member<V8MutationCallback> callback_;
};

MutationObserver* MutationObserver::Create(Delegate* delegate) {
  DCHECK(IsMainThread());
  return MakeGarbageCollected<MutationObserver>(delegate->GetExecutionContext(),
                                                delegate);
}

MutationObserver* MutationObserver::Create(ScriptState* script_state,
                                           V8MutationCallback* callback) {
  DCHECK(IsMainThread());
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  return MakeGarbageCollected<MutationObserver>(
      execution_context, V8DelegateImpl::Create(callback, execution_context));
}

MutationObserver::MutationObserver(ExecutionContext* execution_context,
                                   Delegate* delegate)
    : ActiveScriptWrappable<MutationObserver>({}),
      ExecutionContextLifecycleStateObserver(execution_context),
      delegate_(delegate) {
  priority_ = g_observer_priority++;
  UpdateStateIfNeeded();
}

MutationObserver::~MutationObserver() = default;

void MutationObserver::observe(Node* node,
                               const MutationObserverInit* observer_init,
                               ExceptionState& exception_state) {
  DCHECK(node);

  MutationObserverOptions options = 0;

  if (observer_init->hasAttributeOldValue() &&
      observer_init->attributeOldValue())
    options |= kAttributeOldValue;

  HashSet<AtomicString> attribute_filter;
  if (observer_init->hasAttributeFilter()) {
    for (const auto& name : observer_init->attributeFilter())
      attribute_filter.insert(AtomicString(name));
    options |= kAttributeFilter;
  }

  bool attributes =
      observer_init->hasAttributes() && observer_init->attributes();
  if (attributes || (!observer_init->hasAttributes() &&
                     (observer_init->hasAttributeOldValue() ||
                      observer_init->hasAttributeFilter())))
    options |= kMutationTypeAttributes;

  if (observer_init->hasCharacterDataOldValue() &&
      observer_init->characterDataOldValue())
    options |= kCharacterDataOldValue;

  bool character_data =
      observer_init->hasCharacterData() && observer_init->characterData();
  if (character_data || (!observer_init->hasCharacterData() &&
                         observer_init->hasCharacterDataOldValue()))
    options |= kMutationTypeCharacterData;

  if (observer_init->childList())
    options |= kMutationTypeChildList;

  if (observer_init->subtree())
    options |= kSubtree;

  if (!(options & kMutationTypeAttributes)) {
    if (options & kAttributeOldValue) {
      exception_state.ThrowTypeError(
          "The options object may only set 'attributeOldValue' to true when "
          "'attributes' is true or not present.");
      return;
    }
    if (options & kAttributeFilter) {
      exception_state.ThrowTypeError(
          "The options object may only set 'attributeFilter' when 'attributes' "
          "is true or not present.");
      return;
    }
  }
  if (!((options & kMutationTypeCharacterData) ||
        !(options & kCharacterDataOldValue))) {
    exception_state.ThrowTypeError(
        "The options object may only set 'characterDataOldValue' to true when "
        "'characterData' is true or not present.");
    return;
  }

  if (!(options & kMutationTypeAll)) {
    exception_state.ThrowTypeError(
        "The options object must set at least one of 'attributes', "
        "'characterData', or 'childList' to true.");
    return;
  }

  node->RegisterMutationObserver(*this, options, attribute_filter);
}

MutationRecordVector MutationObserver::takeRecords() {
  MutationRecordVector records;
  CancelInspectorAsyncTasks();
  swap(records_, records);
  return records;
}

void MutationObserver::disconnect() {
  CancelInspectorAsyncTasks();
  records_.clear();
  MutationObserverRegistrationSet registrations(registrations_);
  for (auto& registration : registrations) {
    // The registration may be already unregistered while iteration.
    // Only call unregister if it is still in the original set.
    if (registrations_.Contains(registration))
      registration->Unregister();
  }
  DCHECK(registrations_.empty());
}

void MutationObserver::ObservationStarted(
    MutationObserverRegistration* registration) {
  DCHECK(!registrations_.Contains(registration));
  registrations_.insert(registration);
}

void MutationObserver::ObservationEnded(
    MutationObserverRegistration* registration) {
  DCHECK(registrations_.Contains(registration));
  registrations_.erase(registration);
}

// static
void MutationObserver::EnqueueSlotChange(HTMLSlotElement& slot) {
  DCHECK(IsMainThread());
  MutationObserverAgentData::From(slot.GetDocument().GetAgent())
      .EnqueueSlotChange(slot);
}

// static
void MutationObserver::CleanSlotChangeList(Document& document) {
  MutationObserverAgentData::From(document.GetAgent())
      .CleanSlotChangeList(document);
}

static void ActivateObserver(MutationObserver* observer) {
  if (!observer->GetExecutionContext())
    return;
  MutationObserverAgentData::From(*observer->GetExecutionContext()->GetAgent())
      .ActivateObserver(observer);
}

void MutationObserver::EnqueueMutationRecord(MutationRecord* mutation) {
  DCHECK(IsMainThread());
  records_.push_back(mutation);
  ActivateObserver(this);
  mutation->async_task_context()->Schedule(delegate_->GetExecutionContext(),
                                           mutation->type());
}

void MutationObserver::SetHasTransientRegistration() {
  DCHECK(IsMainThread());
  ActivateObserver(this);
}

HeapHashSet<Member<Node>> MutationObserver::GetObservedNodes() const {
  HeapHashSet<Member<Node>> observed_nodes;
  for (const auto& registration : registrations_)
    registration->AddRegistrationNodesToSet(observed_nodes);
  return observed_nodes;
}

void MutationObserver::ContextLifecycleStateChanged(
    mojom::FrameLifecycleState state) {
  if (state == mojom::FrameLifecycleState::kRunning)
    ActivateObserver(this);
}

void MutationObserver::ContextDestroyed() {
  // The 'DeliverMutations' micro task is *not* guaranteed to run.
  // It's necessary to clear out this observer from the list of active observers
  // in case the MutationObserverAgentData is reused across navigations.
  // Otherwise no MutationObserver for the agent can fire again.
  DCHECK(GetExecutionContext());
  MutationObserverAgentData::From(*GetExecutionContext()->GetAgent())
      .ClearActiveObserver(this);
}

void MutationObserver::CancelInspectorAsyncTasks() {
  for (auto& record : records_) {
    record->async_task_context()->Cancel();
  }
}

void MutationObserver::Deliver() {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextPaused())
    return;

  // Calling ClearTransientRegistrations() can modify registrations_, so it's
  // necessary to make a copy of the transient registrations before operating on
  // them.
  HeapVector<Member<MutationObserverRegistration>, 1> transient_registrations;
  for (auto& registration : registrations_) {
    if (registration->HasTransientRegistrations())
      transient_registrations.push_back(registration);
  }
  for (const auto& registration : transient_registrations)
    registration->ClearTransientRegistrations();

  if (records_.empty())
    return;

  MutationRecordVector records;
  swap(records_, records);

  // Report the first (earliest) stack as the async cause.
  probe::AsyncTask async_task(delegate_->GetExecutionContext(),
                              records.front()->async_task_context());
  delegate_->Deliver(records, *this);
}

void MutationObserver::Trace(Visitor* visitor) const {
  visitor->Trace(delegate_);
  visitor->Trace(records_);
  visitor->Trace(registrations_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleStateObserver::Trace(visitor);
}

}  // namespace blink
```