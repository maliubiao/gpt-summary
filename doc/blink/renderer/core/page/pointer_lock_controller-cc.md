Response:
Let's break down the request and the provided code to construct a comprehensive answer.

**1. Understanding the Goal:**

The request asks for a functional breakdown of `pointer_lock_controller.cc`, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical flow, common usage errors, and debugging steps. The key is to explain *what* this code does and *how* it fits into the larger web development picture.

**2. Initial Code Scan and Keyword Identification:**

I immediately scanned the code for key terms and concepts:

* **Pointer Lock:** The core functionality.
* **RequestPointerLock:**  Functions for initiating pointer lock.
* **ExitPointerLock:**  Functions for releasing pointer lock.
* **Element:** The target for pointer lock.
* **Events (pointerlockchange, pointerlockerror):**  Signals about the pointer lock state.
* **Promises:**  Used for asynchronous results in JavaScript.
* **DOMException:**  Error handling related to the DOM.
* **User Gesture:**  A security requirement for certain actions.
* **Sandbox:**  Security restrictions in iframes.
* **Mouse Events:** How pointer lock interacts with mouse input.
* **Frame:**  The context within a web page.
* **Widget:**  The platform-specific representation of a frame.
* **Callbacks:** Mechanisms for handling asynchronous results.
* **`mojom::blink::PointerLockResult`:**  Enumerated outcomes of pointer lock requests.
* **`PointerLockOptions`:**  Configuration options for pointer lock.
* **`unadjustedMovement`:** A specific option related to raw mouse input.

**3. Deconstructing Functionality:**

I then went through each key function and its purpose:

* **`PointerLockController` (constructor):**  Initializes the controller.
* **`RequestPointerLock(Element*, ResultCallback)`:**  The older, callback-based way to request pointer lock.
* **`RequestPointerLock(ScriptPromiseResolver*, Element*, const PointerLockOptions*)`:** The newer, promise-based way with options. This is the primary entry point from JavaScript.
* **`ChangeLockRequestCallback`:** Handles the result of changing pointer lock options.
* **`LockRequestCallback`:**  Handles the result of the initial pointer lock request. Crucially, it establishes the Mojo communication channel (`mouse_lock_context_`).
* **`ProcessResultPromise`:**  Handles the promise resolution/rejection based on the pointer lock result.
* **`ProcessResult`:** Handles the callback-based result.
* **`ConvertResultToException`:** Translates internal result codes into JavaScript `DOMException` objects. This is vital for the JavaScript API.
* **`ExitPointerLock`:**  The core logic for releasing pointer lock, dispatching the `pointerlockchange` event.
* **`ElementRemoved`:** Handles the case where the locked element is removed from the DOM.
* **`DocumentDetached`:** Handles the case where the document containing the locked element is detached.
* **`LockPending`, `IsPointerLocked`, `GetElement`:** Accessor methods to query the state of pointer lock.
* **`DidAcquirePointerLock`:** Actions taken when pointer lock is successfully acquired (e.g., dispatching `pointerlockchange`, handling mouse capture).
* **`DidNotAcquirePointerLock`:** Actions taken when pointer lock fails (dispatching `pointerlockerror`).
* **`DispatchLockedMouseEvent`:**  How mouse events are routed and handled when pointer lock is active.
* **`GetPointerLockPosition`:**  Retrieves the mouse position at the time of locking.
* **`ClearElement`:** Resets the stored element and pending state.
* **`EnqueueEvent`:** A helper function to dispatch DOM events.
* **`GetPointerLockedElement` (static):**  A utility function to get the currently locked element.

**4. Identifying Relationships with Web Technologies:**

Based on the function analysis, the connections to JavaScript, HTML, and CSS became clear:

* **JavaScript:** The primary interface. `requestPointerLock()` is a JavaScript API, and the code uses promises and dispatches events that JavaScript can listen for. The error handling with `DOMException` directly relates to JavaScript's error handling.
* **HTML:** The target element for `requestPointerLock()` is an HTML element. The state of the DOM (whether the element is connected, its document) is crucial.
* **CSS:**  While not directly manipulating CSS, pointer lock can influence how elements behave visually (e.g., the cursor disappearing).

**5. Constructing Examples and Scenarios:**

With the understanding of the code's purpose and its connections, I could then formulate:

* **Logical Flow Examples:**  Demonstrating the sequence of events for successful and failed pointer lock requests, including the role of promises and callbacks. The "Assumptions and Outputs" format helps clarify the conditional logic.
* **Common Usage Errors:** Based on the checks in the code (user gesture, sandboxing, element removal, already locked), I could identify typical mistakes developers might make.
* **Debugging Steps:**  Tracing the user interaction from a button click to the `RequestPointerLock` call, highlighting the key data points and events to observe.

**6. Refining and Structuring the Answer:**

Finally, I organized the information into clear sections with headings and bullet points to make it easily digestible. I focused on explaining the *why* and *how*, not just the *what*. I also made sure to connect the technical details back to the user experience and developer concerns.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Focus heavily on the Mojo interface.
* **Correction:**  While Mojo is important for the internal workings, the request is geared towards understanding the high-level functionality and its relation to web technologies. Shift the focus to the JavaScript API and DOM interactions.
* **Initial thought:**  Simply list the functions.
* **Correction:**  Provide a functional description of *what* each function does and *why* it exists in the context of pointer lock.
* **Initial thought:**  Assume the reader has deep knowledge of Blink internals.
* **Correction:** Explain concepts like "user gesture" and "sandboxing" briefly, as the target audience might be web developers with varying levels of browser engine knowledge.

By following this iterative process of understanding, analyzing, connecting, and structuring, I arrived at the comprehensive answer provided previously.
好的，让我们来详细分析一下 `blink/renderer/core/page/pointer_lock_controller.cc` 这个文件的功能。

**功能概述:**

`PointerLockController` 类的主要职责是管理浏览器中的指针锁定（Pointer Lock）API 的实现。这个 API 允许网页应用程序请求将鼠标光标锁定在浏览器视口内。当指针被锁定时，用户的所有鼠标移动都会被捕获，并报告给应用程序，而光标本身则可能被隐藏。这对于需要连续鼠标输入的应用场景非常有用，例如第一人称游戏、3D 建模工具等。

**核心功能点:**

1. **发起指针锁定请求 (`RequestPointerLock`)**:
   - 接收来自 JavaScript 的请求，指定需要锁定指针的 DOM 元素。
   - 检查请求是否合法（例如，目标元素是否在文档中，是否存在其他锁定请求）。
   - 与浏览器进程（通过 Mojo 接口）通信，请求执行指针锁定操作。
   - 可以处理带有选项的请求，例如 `unadjustedMovement`（是否需要原始的、未经调整的鼠标移动数据）。

2. **处理指针锁定请求的结果 (`LockRequestCallback`, `ChangeLockRequestCallback`)**:
   - 接收来自浏览器进程的指针锁定请求结果（成功或失败）。
   - 根据结果触发相应的事件 (`pointerlockchange` 或 `pointerlockerror`)。
   - 如果成功，则记录当前锁定状态和锁定的元素。
   - 如果失败，则通知 JavaScript 并清理状态。

3. **管理指针锁定状态**:
   - 维护当前是否有元素锁定了指针 (`element_`)。
   - 跟踪是否有正在进行的锁定请求 (`lock_pending_`).
   - 存储当前的指针锁定选项 (`current_unadjusted_movement_setting_`).

4. **解除指针锁定 (`ExitPointerLock`)**:
   - 响应用户操作（例如按下 Esc 键）、页面失去焦点或程序调用解除锁定。
   - 向浏览器进程发送解除锁定的请求。
   - 触发 `pointerlockchange` 事件通知 JavaScript 指针已解锁。
   - 重置内部状态。

5. **处理锁定的鼠标事件 (`DispatchLockedMouseEvent`)**:
   - 当指针被锁定时，所有的鼠标事件都会被 `PointerLockController` 拦截。
   - 将这些事件（包括 `mousemove` 等）分发到锁定的目标元素。
   - 在 `mouseup` 事件后，还会合成并分发 `click` 事件。

6. **处理元素或文档的移除 (`ElementRemoved`, `DocumentDetached`)**:
   - 当锁定的元素或其所在的文档被移除时，自动解除指针锁定并清理状态。

7. **错误处理**:
   - 将浏览器进程返回的错误代码转换为 JavaScript 可以理解的 `DOMException` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript**: `PointerLockController` 是 Pointer Lock API 在 Blink 渲染引擎中的核心实现。JavaScript 代码通过以下方式与它交互：
    * **请求锁定**: JavaScript 调用 `element.requestPointerLock(options)` 方法。这个调用最终会到达 `PointerLockController::RequestPointerLock`。
        ```javascript
        const element = document.getElementById('myCanvas');
        element.requestPointerLock(); // 简单请求
        element.requestPointerLock({ unadjustedMovement: true }); // 请求原始鼠标移动数据
        ```
        **假设输入**: JavaScript 调用 `element.requestPointerLock()`，其中 `element` 是一个 `<canvas>` 元素。
        **输出**:  `PointerLockController` 向浏览器进程发送请求，用户可能会看到浏览器提示允许指针锁定。如果成功，`pointerlockchange` 事件会在 `document` 上触发。
    * **监听事件**: JavaScript 监听 `pointerlockchange` 和 `pointerlockerror` 事件来感知指针锁定的状态变化。
        ```javascript
        document.addEventListener('pointerlockchange', () => {
          if (document.pointerLockElement === element) {
            console.log('指针已锁定');
          } else {
            console.log('指针已解锁');
          }
        });

        document.addEventListener('pointerlockerror', (error) => {
          console.error('指针锁定失败:', error);
        });
        ```
        **假设输入**:  用户按下 Esc 键或 JavaScript 调用 `document.exitPointerLock()`。
        **输出**: `PointerLockController::ExitPointerLock` 被调用，然后 `pointerlockchange` 事件被触发，`document.pointerLockElement` 变为 `null`。
    * **解除锁定**: JavaScript 调用 `document.exitPointerLock()` 方法，这会触发 `PointerLockController::ExitPointerLock`。

* **HTML**: HTML 元素是请求指针锁定的目标。只有当一个元素成功请求到指针锁定时，该元素才会接收锁定的鼠标事件。
    ```html
    <canvas id="myCanvas" width="500" height="300"></canvas>
    <script>
      const canvas = document.getElementById('myCanvas');
      canvas.onclick = () => {
        canvas.requestPointerLock();
      };
    </script>
    ```
    **用户操作**: 用户点击 `<canvas>` 元素。
    **到达 `PointerLockController` 的步骤**:
    1. 用户点击 `<canvas>` 元素。
    2. 浏览器的事件处理机制捕获到 `click` 事件。
    3. JavaScript 中注册的 `onclick` 事件处理函数被执行。
    4. `canvas.requestPointerLock()` 方法被调用。
    5. 这个调用会通过 Blink 的 JavaScript 绑定层，最终调用到 `PointerLockController::RequestPointerLock`。

* **CSS**: CSS 本身不直接参与指针锁定的核心逻辑。然而，指针锁定可能会影响到与光标相关的 CSS 属性。例如，当指针被锁定时，浏览器通常会隐藏鼠标光标，这可以看作是浏览器对指针锁定状态的一种默认样式处理。开发者无法通过 CSS 直接控制指针锁定的行为。

**逻辑推理的假设输入与输出:**

**场景 1: 成功的指针锁定**

* **假设输入**:
    1. JavaScript 调用 `element.requestPointerLock()`，并且存在用户激活（例如，在 `click` 事件处理函数中调用）。
    2. 目标元素 `element` 在文档中且未被移除。
    3. 没有其他元素已经锁定了指针。
    4. 用户允许指针锁定（如果浏览器有提示）。
* **输出**:
    1. `PointerLockController::RequestPointerLock` 返回 `true`。
    2. 浏览器进程成功获取指针锁定。
    3. `PointerLockController::LockRequestCallback` 接收到成功的通知。
    4. `pointerlockchange` 事件在 `document` 上触发，`document.pointerLockElement` 指向 `element`。
    5. 以后的鼠标移动事件（`mousemove`）会以 `movementX` 和 `movementY` 的形式发送到 `element`。

**场景 2: 因权限被拒绝的指针锁定**

* **假设输入**:
    1. JavaScript 调用 `element.requestPointerLock()`。
    2. 目标元素在一个被沙盒化的 `<iframe>` 中，并且没有 `allow-pointer-lock` 特性。
* **输出**:
    1. `PointerLockController::RequestPointerLock` 中的沙盒检查会失败。
    2. 控制台会输出一个错误消息。
    3. `pointerlockerror` 事件在 `document` 上触发。
    4. `Promise` 返回的 `reject` 回调函数被调用，并带有一个 `SecurityError` 类型的 `DOMException`。

**用户或编程常见的使用错误及举例说明:**

1. **未在用户手势中请求指针锁定**:
   - **错误代码**:
     ```javascript
     setTimeout(() => {
       document.getElementById('myCanvas').requestPointerLock(); // 错误：不在用户手势中
     }, 1000);
     ```
   - **说明**: 浏览器通常只允许在用户主动操作（例如，点击、按下键盘）触发的事件处理函数中调用 `requestPointerLock()`，以防止恶意网站滥用。
   - **调试线索**: 如果尝试在非用户手势上下文中调用，`LockRequestCallback` 可能会收到 `mojom::blink::PointerLockResult::kRequiresUserGesture`，最终导致 `pointerlockerror` 事件和 `NotAllowedError` 类型的 `DOMException`。

2. **在沙盒化的 iframe 中请求指针锁定但缺少 `allow-pointer-lock`**:
   - **错误代码**:
     ```html
     <!-- parent.html -->
     <iframe sandbox="allow-scripts" src="child.html"></iframe>

     <!-- child.html -->
     <script>
       document.addEventListener('click', () => {
         document.body.requestPointerLock();
       });
     </script>
     ```
   - **说明**: 如果一个 `<iframe>` 元素设置了 `sandbox` 属性，默认情况下会禁用指针锁定。需要在 `sandbox` 属性中显式添加 `allow-pointer-lock`。
   - **调试线索**: `PointerLockController::RequestPointerLock` 会检查沙盒标志，如果缺少 `allow-pointer-lock`，会直接触发 `pointerlockerror` 并返回 `SecurityError` 类型的 `DOMException`。

3. **尝试在已经锁定的情况下再次锁定**:
   - **错误代码**:
     ```javascript
     let isLocked = false;
     document.addEventListener('pointerlockchange', () => {
       isLocked = document.pointerLockElement !== null;
     });

     document.getElementById('element1').onclick = () => {
       document.getElementById('element1').requestPointerLock();
     };

     document.getElementById('element2').onclick = () => {
       if (!isLocked) {
         document.getElementById('element2').requestPointerLock(); // 错误：可能在已经锁定的情况下调用
       }
     };
     ```
   - **说明**: 在一个元素已经锁定了指针的情况下，尝试另一个元素锁定指针会失败。应该先解除之前的锁定。
   - **调试线索**: `PointerLockController::RequestPointerLock` 会检查 `element_` 是否已存在，如果存在，会触发 `pointerlockerror` 并返回 `InUseAttributeError` 类型的 `DOMException`。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在一个网页上与一个 `<canvas>` 元素交互，并触发了指针锁定：

1. **用户操作**: 用户点击了网页上的一个按钮或元素。
2. **事件触发**: 浏览器捕获到用户的点击事件（例如 `click` 事件）。
3. **JavaScript 处理**: 与该按钮或元素关联的 JavaScript 事件处理函数被执行。
4. **调用 `requestPointerLock()`**: 在 JavaScript 代码中，调用了某个元素的 `requestPointerLock()` 方法。
5. **Blink 绑定层**:  浏览器引擎的 JavaScript 绑定层接收到这个调用，并将它转换为对 Blink C++ 代码的调用。
6. **`PointerLockController::RequestPointerLock()`**: `blink/renderer/core/page/pointer_lock_controller.cc` 文件中的 `RequestPointerLock` 方法被调用。
7. **合法性检查**: `RequestPointerLock` 内部会进行一系列检查，例如目标元素是否存在、是否连接到文档、是否需要用户手势等。
8. **Mojo 通信**: 如果请求合法，`PointerLockController` 会通过 Mojo 接口向浏览器进程发送一个请求，要求执行指针锁定。
9. **浏览器进程处理**: 浏览器进程接收到请求，可能会显示一个提示框询问用户是否允许锁定指针。
10. **回调**: 浏览器进程处理完成后，会将结果通过 Mojo 回调发送回渲染进程。
11. **`PointerLockController::LockRequestCallback()`**: `LockRequestCallback` 方法被调用，处理来自浏览器进程的结果。
12. **事件分发**: 根据结果，`LockRequestCallback` 会触发 `pointerlockchange` 或 `pointerlockerror` 事件，通知 JavaScript 指针锁定的状态变化。

**调试线索:**

* **断点**: 在 `PointerLockController::RequestPointerLock`、`LockRequestCallback` 和 `ExitPointerLock` 等关键方法设置断点，可以跟踪指针锁定请求的生命周期。
* **控制台输出**: 在 JavaScript 中监听 `pointerlockchange` 和 `pointerlockerror` 事件，可以查看事件对象，获取错误信息。
* **Chrome 开发者工具**: 使用 Performance 面板可以查看事件的触发顺序和时间。使用 Sources 面板可以单步调试 JavaScript 代码，查看 `requestPointerLock()` 调用时的上下文。
* **`chrome://webrtc-internals`**: 虽然这个工具主要用于 WebRTC，但有时也能提供一些关于浏览器内部状态的信息。
* **查看错误消息**:  注意浏览器控制台中输出的任何与指针锁定相关的错误或警告信息。

希望以上详细的解释能够帮助你理解 `pointer_lock_controller.cc` 的功能和它在 Web 技术栈中的作用。

### 提示词
```
这是目录为blink/renderer/core/page/pointer_lock_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"

#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/public/mojom/input/pointer_lock_result.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_pointer_lock_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"

namespace blink {

PointerLockController::PointerLockController(Page* page)
    : page_(page), lock_pending_(false) {}

bool PointerLockController::RequestPointerLock(Element* target,
                                               ResultCallback callback) {
  if (!target || !target->isConnected() ||
      document_of_removed_element_while_waiting_for_unlock_ || element_) {
    return false;
  }
  LocalDOMWindow* window = To<LocalDOMWindow>(target->GetExecutionContext());
  window->GetFrame()->GetWidgetForLocalRoot()->RequestMouseLock(
      LocalFrame::HasTransientUserActivation(window->GetFrame()),
      /*unadjusted_movement_requested=*/false,
      WTF::BindOnce(&PointerLockController::LockRequestCallback,
                    WrapWeakPersistent(this), std::move(callback),
                    /*unadjusted_movement_requested=*/false));
  lock_pending_ = true;
  element_ = target;
  return true;
}

void PointerLockController::RequestPointerLock(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    Element* target,
    const PointerLockOptions* options) {
  if (!target || !target->isConnected() ||
      document_of_removed_element_while_waiting_for_unlock_) {
    EnqueueEvent(event_type_names::kPointerlockerror, target);
    resolver->RejectWithDOMException(DOMExceptionCode::kWrongDocumentError,
                                     "Target Element removed from DOM");
    return;
  }

  LocalDOMWindow* window = To<LocalDOMWindow>(target->GetExecutionContext());
  window->CountUseOnlyInCrossOriginIframe(
      WebFeature::kElementRequestPointerLockIframe);
  if (target->IsInShadowTree()) {
    UseCounter::Count(window, WebFeature::kElementRequestPointerLockInShadow);
  }
  if (options && options->unadjustedMovement()) {
    UseCounter::Count(window, WebFeature::kPointerLockUnadjustedMovement);
  }

  if (window->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kPointerLock)) {
    // FIXME: This message should be moved off the console once a solution to
    // https://bugs.webkit.org/show_bug.cgi?id=103274 exists.
    if (!window->GetFrame()->IsInFencedFrameTree()) {
      window->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kSecurity,
          mojom::blink::ConsoleMessageLevel::kError,
          "Blocked pointer lock on an element because the element's frame is "
          "sandboxed and the 'allow-pointer-lock' permission is not set."));
    }
    EnqueueEvent(event_type_names::kPointerlockerror, target);
    resolver->RejectWithSecurityError(
        window->GetFrame()->IsInFencedFrameTree()
            ? "Blocked pointer lock on an element because the element is "
              "contained "
              "in a fence frame tree."
            : "Blocked pointer lock on an element because the element's frame "
              "is "
              "sandboxed and the 'allow-pointer-lock' permission is not set.",
        "");
    return;
  }

  bool unadjusted_movement_requested =
      options ? options->unadjustedMovement() : false;
  if (element_) {
    if (element_->GetDocument() != target->GetDocument()) {
      EnqueueEvent(event_type_names::kPointerlockerror, target);
      resolver->RejectWithDOMException(
          DOMExceptionCode::kWrongDocumentError,
          "The new element is not in the same shadow-root document as the "
          "element that currently holds the lock.");
      return;
    }
    // Attempt to change options if necessary.
    if (unadjusted_movement_requested != current_unadjusted_movement_setting_) {
      if (!mouse_lock_context_.is_bound() || lock_pending_) {
        EnqueueEvent(event_type_names::kPointerlockerror, target);
        resolver->RejectWithDOMException(DOMExceptionCode::kInUseAttributeError,
                                         "Pointer lock pending.");
        return;
      }

      mouse_lock_context_->RequestMouseLockChange(
          unadjusted_movement_requested,
          WTF::BindOnce(
              &PointerLockController::ChangeLockRequestCallback,
              WrapWeakPersistent(this), WrapWeakPersistent(target),
              WTF::BindOnce(&PointerLockController::ProcessResultPromise,
                            WrapPersistent(resolver)),
              unadjusted_movement_requested));
      return;
    }

    EnqueueEvent(event_type_names::kPointerlockchange, target);
    element_ = target;
    resolver->Resolve();

    // Subsequent steps are handled in the browser process.
  } else {
    window->GetFrame()->GetWidgetForLocalRoot()->RequestMouseLock(
        LocalFrame::HasTransientUserActivation(window->GetFrame()),
        unadjusted_movement_requested,
        WTF::BindOnce(
            &PointerLockController::LockRequestCallback,
            WrapWeakPersistent(this),
            WTF::BindOnce(&PointerLockController::ProcessResultPromise,
                          WrapPersistent(resolver)),
            unadjusted_movement_requested));
    lock_pending_ = true;
    element_ = target;
  }
}

void PointerLockController::ChangeLockRequestCallback(
    Element* target,
    ResultCallback callback,
    bool unadjusted_movement_requested,
    mojom::blink::PointerLockResult result) {
  if (result == mojom::blink::PointerLockResult::kSuccess)
    element_ = target;

  ProcessResult(std::move(callback), unadjusted_movement_requested, result);
}

void PointerLockController::LockRequestCallback(
    ResultCallback callback,
    bool unadjusted_movement_requested,
    mojom::blink::PointerLockResult result,
    mojo::PendingRemote<blink::mojom::blink::PointerLockContext> context) {
  if (element_ && context) {
    mouse_lock_context_.Bind(std::move(context),
                             element_->GetExecutionContext()->GetTaskRunner(
                                 TaskType::kUserInteraction));
    // The browser might unlock the mouse for many reasons including closing
    // the tab, the user hitting esc, the page losing focus, and more.
    mouse_lock_context_.set_disconnect_handler(WTF::BindOnce(
        &PointerLockController::ExitPointerLock, WrapWeakPersistent(this)));
  }
  ProcessResult(std::move(callback), unadjusted_movement_requested, result);
  if (result == mojom::blink::PointerLockResult::kSuccess) {
    DidAcquirePointerLock();
  } else {
    DidNotAcquirePointerLock();
  }
}

void PointerLockController::ProcessResultPromise(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    mojom::blink::PointerLockResult result) {
  if (result == mojom::blink::PointerLockResult::kSuccess) {
    resolver->Resolve();
    return;
  }
  DOMException* exception = ConvertResultToException(result);
  resolver->Reject(exception);
}

void PointerLockController::ProcessResult(
    ResultCallback callback,
    bool unadjusted_movement_requested,
    mojom::blink::PointerLockResult result) {
  if (result == mojom::blink::PointerLockResult::kSuccess)
    current_unadjusted_movement_setting_ = unadjusted_movement_requested;
  std::move(callback).Run(result);
}

DOMException* PointerLockController::ConvertResultToException(
    mojom::blink::PointerLockResult result) {
  switch (result) {
    case mojom::blink::PointerLockResult::kUnsupportedOptions:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotSupportedError,
          "The options asked for in this request are not supported on this "
          "platform.");
    case mojom::blink::PointerLockResult::kRequiresUserGesture:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "A user gesture is required to request Pointer Lock.");
    case mojom::blink::PointerLockResult::kAlreadyLocked:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInUseAttributeError, "Pointer is already locked.");
    case mojom::blink::PointerLockResult::kWrongDocument:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kWrongDocumentError,
          "The root document of this element is not valid for pointer lock.");
    case mojom::blink::PointerLockResult::kPermissionDenied:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "The root document of this element is not valid for pointer lock.");
    case mojom::blink::PointerLockResult::kElementDestroyed:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kWrongDocumentError,
          "The element has been destroyed while making this request.");
    case mojom::blink::PointerLockResult::kUserRejected:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kSecurityError,
          "The user has exited the lock before this request was completed.");
    case mojom::blink::PointerLockResult::kSuccess:
    case mojom::blink::PointerLockResult::kUnknownError:
      return MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kUnknownError,
          "If you see this error we have a bug. Please report this bug to "
          "chromium.");
  }
}

void PointerLockController::ExitPointerLock() {
  Document* pointer_lock_document =
      element_ ? &element_->GetDocument()
               : document_of_removed_element_while_waiting_for_unlock_.Get();
  EnqueueEvent(event_type_names::kPointerlockchange, pointer_lock_document);

  // Set the last mouse position back the locked position.
  if (pointer_lock_document && pointer_lock_document->GetFrame()) {
    pointer_lock_document->GetFrame()
        ->GetEventHandler()
        .ResetMousePositionForPointerUnlock();
  }

  ClearElement();
  document_of_removed_element_while_waiting_for_unlock_ = nullptr;
  mouse_lock_context_.reset();
}

void PointerLockController::ElementRemoved(Element* element) {
  if (element_ == element) {
    document_of_removed_element_while_waiting_for_unlock_ =
        &element_->GetDocument();
    ExitPointerLock();
    // Set element null immediately to block any future interaction with it
    // including mouse events received before the unlock completes.
    ClearElement();
  }
}

void PointerLockController::DocumentDetached(Document* document) {
  if (element_ && element_->GetDocument() == document) {
    ExitPointerLock();
    ClearElement();
  }
}

bool PointerLockController::LockPending() const {
  return lock_pending_;
}

bool PointerLockController::IsPointerLocked() const {
  return mouse_lock_context_.is_bound();
}

Element* PointerLockController::GetElement() const {
  return element_.Get();
}

void PointerLockController::DidAcquirePointerLock() {
  EnqueueEvent(event_type_names::kPointerlockchange, element_.Get());
  lock_pending_ = false;
  if (element_) {
    LocalFrame* frame = element_->GetDocument().GetFrame();
    pointer_lock_position_ = frame->LocalFrameRoot()
                                 .GetEventHandler()
                                 .LastKnownMousePositionInRootFrame();
    pointer_lock_screen_position_ = frame->LocalFrameRoot()
                                        .GetEventHandler()
                                        .LastKnownMouseScreenPosition();
    LocalFrame* focused_frame =
        frame->GetPage()->GetFocusController().FocusedFrame();
    if (focused_frame) {
      focused_frame->GetEventHandler().ReleaseMousePointerCapture();
    }

    // Mouse Lock removes the system cursor and provides all mouse motion as
    // .movementX/Y values on events all sent to a fixed target. This requires
    // content to specifically request the mode to be entered.
    // Mouse Capture is implicitly given for the duration of a drag event, and
    // sends all mouse events to the initial target of the drag.
    // If Lock is entered it supersedes any in progress Capture.
    frame->GetWidgetForLocalRoot()->MouseCaptureLost();
  }
}

void PointerLockController::DidNotAcquirePointerLock() {
  EnqueueEvent(event_type_names::kPointerlockerror, element_.Get());
  ClearElement();
}

void PointerLockController::DispatchLockedMouseEvent(
    const WebMouseEvent& event,
    const Vector<WebMouseEvent>& coalesced_events,
    const Vector<WebMouseEvent>& predicted_events,
    const AtomicString& event_type) {
  if (!element_ || !element_->GetDocument().GetFrame())
    return;

  if (LocalFrame* frame = element_->GetDocument().GetFrame()) {
    frame->GetEventHandler().HandleTargetedMouseEvent(
        element_, event, event_type, coalesced_events, predicted_events);

    // Event handlers may remove element.
    if (!element_)
      return;

    // Create click events
    if (event_type == event_type_names::kMouseup) {
      frame->GetEventHandler().HandleTargetedMouseEvent(
          element_, event, event_type_names::kClick, Vector<WebMouseEvent>(),
          Vector<WebMouseEvent>());
    }
  }
}

void PointerLockController::GetPointerLockPosition(
    gfx::PointF* lock_position,
    gfx::PointF* lock_screen_position) {
  if (element_ && !lock_pending_) {
    DCHECK(lock_position);
    DCHECK(lock_screen_position);
    *lock_position = pointer_lock_position_;
    *lock_screen_position = pointer_lock_screen_position_;
  }
}

void PointerLockController::ClearElement() {
  lock_pending_ = false;
  element_ = nullptr;
}

void PointerLockController::EnqueueEvent(const AtomicString& type,
                                         Element* element) {
  if (element)
    EnqueueEvent(type, &element->GetDocument());
}

void PointerLockController::EnqueueEvent(const AtomicString& type,
                                         Document* document) {
  if (document && document->domWindow()) {
    document->domWindow()->EnqueueDocumentEvent(*Event::Create(type),
                                                TaskType::kUserInteraction);
  }
}

void PointerLockController::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
  visitor->Trace(element_);
  visitor->Trace(document_of_removed_element_while_waiting_for_unlock_);
  visitor->Trace(mouse_lock_context_);
}

// static
Element* PointerLockController::GetPointerLockedElement(LocalFrame* frame) {
  if (Page* p = frame->GetPage()) {
    if (!p->GetPointerLockController().LockPending())
      return p->GetPointerLockController().GetElement();
  }
  return nullptr;
}

}  // namespace blink
```