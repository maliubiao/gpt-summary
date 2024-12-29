Response:
Let's break down the thought process to analyze the provided C++ code for `clipboard_promise.cc`.

**1. Initial Understanding - What is the File About?**

The filename `clipboard_promise.cc` immediately suggests it's related to asynchronous operations (Promises) involving the clipboard in the Chromium/Blink rendering engine. The inclusion of `#include "third_party/blink/renderer/modules/clipboard/clipboard_promise.h"` confirms this.

**2. Scanning for Key Functionalities/Keywords:**

I'd quickly scan the code for prominent keywords and class names to get a high-level overview. Things like:

* `class ClipboardPromise`:  This is the core class, so focus here.
* `ScriptPromise`:  Indicates interaction with JavaScript Promises.
* `CreateForRead`, `CreateForReadText`, `CreateForWrite`, `CreateForWriteText`: These look like static factory methods for creating different types of clipboard promises (read/write, text/rich content).
* `HandleRead`, `HandleWrite`, `HandleReadText`, `HandleWriteText`:  These seem to be the core logic handlers for the different clipboard operations.
* `ClipboardItem`, `ClipboardReader`, `ClipboardWriter`: These are likely helper classes for managing clipboard data.
* `PermissionService`:  Suggests handling permissions for clipboard access.
* `ValidatePreconditions`:  Likely checks for necessary conditions before accessing the clipboard (focus, security, permissions).
* `Resolve`, `Reject`: These are standard Promise terminology for success and failure.
* `Trace`:  Indicates part of the Blink garbage collection system.
* Includes like `<memory>`, `<utility>`, `"base/functional/callback_helpers.h"`, `"mojo/public/cpp/base/big_buffer.h"`: These point to the underlying C++ infrastructure being used (smart pointers, callbacks, inter-process communication).

**3. Deconstructing the Core Functions (The "Handle" Methods):**

I'd then focus on the `Handle...` methods to understand the main workflows:

* **`HandleRead`:**  Checks for unsanitized formats, validates permissions, and then uses `SystemClipboard` to read available formats. The `OnReadAvailableFormatNames` and `ReadNextRepresentation` methods suggest an iterative process for fetching data for different formats.
* **`HandleReadText`:** Simpler, just validates permissions and reads plain text using `SystemClipboard`.
* **`HandleWrite`:** Handles writing `ClipboardItem` objects. It checks for multiple items (currently unsupported), extracts representations, and then uses `ValidatePreconditions` for permissions. The interaction with `ClipboardItemDataPromiseFulfill` and `ClipboardItemDataPromiseReject` suggests it handles asynchronous resolution of data within the `ClipboardItem`.
* **`HandleWriteText`:**  Stores the text data and validates write permissions. The actual writing happens in `HandleWriteTextWithPermission`.

**4. Identifying JavaScript/HTML/CSS Relationships:**

With the core functions understood, I'd look for how these C++ components interact with the web platform:

* **`ScriptPromise`:** This is the direct bridge to JavaScript Promises. The `CreateFor...` methods return these, which are then used in JavaScript.
* **`ClipboardItem`:** This C++ class likely corresponds to the `ClipboardItem` JavaScript API.
* **Formats (MIME types):** The code deals with different clipboard data formats (text/plain, text/html, etc.), which are relevant to web content.
* **Permissions:** The interaction with `PermissionService` directly ties into the browser's permission model for clipboard access, which JavaScript code must respect.

**5. Logical Reasoning and Assumptions:**

* **Assumption:** When `HandleWrite` receives `ClipboardItem`s, it needs to potentially fetch data asynchronously if the `ClipboardItem` contains Blobs or Promises. This explains the `ClipboardItemDataPromiseFulfill` and `Reject` classes.
* **Reasoning:** The code iterates through clipboard representations (`WriteNextRepresentation`, `ReadNextRepresentation`). This suggests the clipboard can hold data in multiple formats.
* **Assumption:** The `ValidatePreconditions` method enforces security and permission constraints before allowing clipboard access. This is a crucial security feature.

**6. Identifying Potential Errors:**

* **User Errors:**  Trying to write too many custom formats, attempting to read multiple unsanitized formats, trying to access the clipboard when the document isn't focused.
* **Programming Errors:** Incorrectly specifying MIME types, failing to handle Promise rejections properly.

**7. Tracing User Operations:**

I'd think about the steps a user takes in a web page that would trigger this code:

* User selects text/images and presses Ctrl+C (Copy).
* User presses Ctrl+V (Paste).
* JavaScript code uses the `navigator.clipboard.read()` or `navigator.clipboard.write()` APIs.

**8. Structuring the Output:**

Finally, I'd organize the information into the requested categories:

* **Functionality:** Summarize the core purpose of the file and its main classes.
* **JavaScript/HTML/CSS Relationships:** Explain how the C++ code connects to web APIs, using examples.
* **Logic and Assumptions:** Detail the reasoning behind certain code structures.
* **Common Errors:** List both user and programming errors.
* **User Operation Debugging:** Describe how a user's actions can lead to this code being executed.

**Self-Correction/Refinement:**

During the process, I might revisit earlier assumptions or interpretations. For example, initially, I might have overlooked the significance of the `ExecutionContextLifecycleObserver`. Later, realizing it handles cleanup when the document is destroyed would be an important refinement. Similarly, understanding the role of `PromiseAll` in handling multiple asynchronous data fetches within a `ClipboardItem` is crucial and might require re-examining the `HandleWrite` flow.
这个文件 `clipboard_promise.cc` 是 Chromium Blink 引擎中处理与 JavaScript Clipboard API 交互的核心组件之一。它主要负责实现与剪贴板操作相关的异步 Promise 功能。

以下是它的主要功能：

**1. 提供基于 Promise 的剪贴板操作接口:**

*   该文件定义了 `ClipboardPromise` 类，该类封装了与剪贴板交互的异步操作，并使用 JavaScript Promise 来表示这些操作的结果。
*   它提供了静态方法 `CreateForRead`, `CreateForReadText`, `CreateForWrite`, `CreateForWriteText`，这些方法用于创建不同类型的剪贴板操作 Promise 对象，供 JavaScript 调用。

**2. 处理剪贴板读取操作:**

*   **`CreateForRead`:** 用于创建读取任意格式数据的 Promise。它会检查权限，然后从系统剪贴板读取指定格式的数据，并将数据封装成 `ClipboardItem` 对象，最终 resolve Promise。
*   **`CreateForReadText`:** 用于创建读取纯文本数据的 Promise。它会检查权限，然后从系统剪贴板读取纯文本数据，并 resolve Promise。
*   **`HandleRead`:**  处理读取操作的核心逻辑。它会请求剪贴板读取权限，并根据提供的格式从系统剪贴板读取数据。
*   **`HandleReadText`:** 处理读取纯文本的核心逻辑。
*   **`OnReadAvailableFormatNames`:**  在成功获取可用的剪贴板格式后被调用，用于初始化读取流程。
*   **`ReadNextRepresentation`:** 迭代读取剪贴板中不同格式的数据。
*   **`OnRead`:**  在读取到特定格式的数据后被调用，将数据存储并继续读取下一个格式。
*   **`ResolveRead`:** 在所有数据读取完成后，将 `ClipboardItem` 列表 resolve 到 JavaScript Promise。
*   **`RejectFromReadOrDecodeFailure`:** 在读取或解码剪贴板数据失败时拒绝 Promise。

**3. 处理剪贴板写入操作:**

*   **`CreateForWrite`:** 用于创建写入多个 `ClipboardItem` 对象的 Promise。它会检查权限，并将提供的 `ClipboardItem` 数据写入系统剪贴板，最终 resolve Promise。
*   **`CreateForWriteText`:** 用于创建写入纯文本数据的 Promise。它会检查权限，并将提供的文本数据写入系统剪贴板，最终 resolve Promise。
*   **`HandleWrite`:** 处理写入多个 `ClipboardItem` 的核心逻辑。它会请求剪贴板写入权限，并将 `ClipboardItem` 中的数据写入系统剪贴板。由于 `ClipboardItem` 可能包含 Blob 或 Promise，所以需要等待这些 Promise resolve 后才能进行实际写入。
*   **`HandleWriteText`:** 处理写入纯文本的核心逻辑。
*   **`HandlePromiseWrite`:**  在 `ClipboardItem` 中包含的 Blob 或 Promise resolve 后被调用，用于收集所有待写入的数据。
*   **`WriteClipboardItemData`:**  将收集到的数据写入到系统剪贴板。
*   **`WriteNextRepresentation`:** 迭代写入剪贴板中不同格式的数据。
*   **`CompleteWriteRepresentation`:** 在写入完成特定格式的数据后被调用，准备写入下一个格式。
*   **`HandleWriteWithPermission`:** 在获得写入权限后，处理包含 Promise 的 `ClipboardItem` 数据，并使用 `PromiseAll` 等待所有 Promise 完成。
*   **`HandleWriteTextWithPermission`:** 在获得写入权限后，将纯文本数据写入系统剪贴板。

**4. 权限管理:**

*   `ClipboardPromise` 使用 `PermissionService` 来请求和验证剪贴板的读写权限 (`clipboard-read` 和 `clipboard-write`)。
*   **`ValidatePreconditions`:**  在执行剪贴板操作前，检查必要的先决条件，例如文档是否聚焦，是否是安全上下文，以及是否拥有相应的权限。

**5. 错误处理:**

*   当剪贴板操作失败时，例如权限被拒绝、读取或写入数据出错，`ClipboardPromise` 会 reject 相应的 JavaScript Promise，并将错误信息传递给 JavaScript。
*   它会抛出 `DOMException` 来表示错误。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **JavaScript:**  `ClipboardPromise` 是 JavaScript Clipboard API 的底层实现。JavaScript 代码通过 `navigator.clipboard` 对象调用 `read()`, `readText()`, `write()`, `writeText()` 方法，这些方法最终会触发 `ClipboardPromise` 中相应的方法。

    ```javascript
    // JavaScript 写入文本到剪贴板
    navigator.clipboard.writeText("Hello, clipboard!")
      .then(() => console.log("Text copied!"))
      .catch(err => console.error("Failed to copy: ", err));

    // JavaScript 读取剪贴板文本
    navigator.clipboard.readText()
      .then(text => console.log("Pasted text: ", text))
      .catch(err => console.error("Failed to read clipboard: ", err));

    // JavaScript 写入包含不同格式的 ClipboardItem 到剪贴板
    navigator.clipboard.write([
      new ClipboardItem({
        'text/plain': new Blob(['This is plain text'], {type: 'text/plain'}),
        'text/html': new Blob(['<b>This is bold text</b>'], {type: 'text/html'})
      })
    ]).then(() => console.log("Data copied!")).catch(err => console.error("Failed to copy:", err));

    // JavaScript 读取包含多种格式的剪贴板数据
    navigator.clipboard.read().then(clipboardItems => {
      clipboardItems.forEach(item => {
        for (const type of item.types) {
          item.getType(type).then(blob => {
            // 处理不同类型的数据
            if (type === 'text/plain') {
              blob.text().then(text => console.log("Plain text:", text));
            } else if (type === 'text/html') {
              blob.text().then(html => console.log("HTML:", html));
            }
          });
        }
      });
    }).catch(err => console.error("Failed to read:", err));
    ```

*   **HTML:**  用户的操作，如点击“复制”按钮或使用键盘快捷键 (Ctrl+C, Ctrl+V)，可能会触发 JavaScript 代码调用 Clipboard API。HTML 结构定义了用户交互的界面。

    ```html
    <button onclick="copyText()">复制文本</button>
    <button onclick="pasteText()">粘贴文本</button>
    <script>
      async function copyText() {
        try {
          await navigator.clipboard.writeText("要复制的文本");
          console.log('文本已复制到剪贴板');
        } catch (err) {
          console.error('无法复制文本：', err);
        }
      }

      async function pasteText() {
        try {
          const text = await navigator.clipboard.readText();
          console.log('从剪贴板粘贴的文本：', text);
        } catch (err) {
          console.error('无法从剪贴板粘贴文本：', err);
        }
      }
    </script>
    ```

*   **CSS:** CSS 样式可以影响用户界面，从而影响用户与复制粘贴功能的交互（例如，按钮的样式）。但 CSS 本身不直接参与剪贴板的读写操作。

**逻辑推理、假设输入与输出:**

**假设输入 (写入操作):**

*   JavaScript 代码调用 `navigator.clipboard.writeText("Hello")`。

**逻辑推理:**

1. JavaScript 调用会触发 `Clipboard::WriteText()` (或其他相关方法，最终会到达 `ClipboardPromise::CreateForWriteText`)。
2. `ClipboardPromise::CreateForWriteText` 创建一个新的 `ClipboardPromise` 对象。
3. `ClipboardPromise::HandleWriteText` 被调用，存储要写入的文本 "Hello"。
4. `ClipboardPromise::ValidatePreconditions` 被调用，检查权限、安全上下文、焦点等。假设检查通过。
5. `ClipboardPromise::HandleWriteTextWithPermission` 被调用。
6. `SystemClipboard::WritePlainText("Hello")` 被调用，将文本写入系统剪贴板。
7. `SystemClipboard::CommitWrite()` 被调用，提交写入操作。
8. `script_promise_resolver_->DowncastTo<IDLUndefined>()->Resolve()` 被调用，JavaScript Promise resolve。

**假设输出 (写入操作):**

*   JavaScript Promise resolve，`then()` 回调被执行。
*   系统剪贴板中现在包含文本 "Hello"。

**假设输入 (读取操作):**

*   JavaScript 代码调用 `navigator.clipboard.readText()`。

**逻辑推理:**

1. JavaScript 调用会触发 `Clipboard::ReadText()` (或其他相关方法，最终会到达 `ClipboardPromise::CreateForReadText`)。
2. `ClipboardPromise::CreateForReadText` 创建一个新的 `ClipboardPromise` 对象。
3. `ClipboardPromise::HandleReadText` 被调用。
4. `ClipboardPromise::ValidatePreconditions` 被调用，检查权限、安全上下文、焦点等。假设检查通过。
5. `ClipboardPromise::HandleReadTextWithPermission` 被调用。
6. `SystemClipboard::ReadPlainText(mojom::blink::ClipboardBuffer::kStandard)` 被调用，从系统剪贴板读取纯文本。
7. 假设系统剪贴板中有文本 "World"。
8. `script_promise_resolver_->DowncastTo<IDLString>()->Resolve("World")` 被调用，JavaScript Promise resolve 并返回读取到的文本。

**假设输出 (读取操作):**

*   JavaScript Promise resolve，`then()` 回调被执行，并接收到字符串 "World"。

**用户或编程常见的使用错误:**

1. **用户未授予权限:** JavaScript 代码尝试读写剪贴板，但用户拒绝了相应的权限请求。
    *   **现象:**  JavaScript Promise reject，并返回一个 `NotAllowedError` 类型的 `DOMException`。
    *   **代码示例:**  用户在浏览器中阻止了网站的剪贴板访问权限。

2. **文档未聚焦:** 尝试在文档失去焦点时访问剪贴板。
    *   **现象:** JavaScript Promise reject，并返回一个 `NotAllowedError` 类型的 `DOMException`，错误消息为 "Document is not focused."。
    *   **代码示例:**  在用户切换到其他标签页后，网页尝试读取剪贴板。

3. **在非安全上下文中使用:**  Clipboard API 只能在安全上下文 (HTTPS) 中使用。
    *   **现象:**  相关 API 方法不可用，或者调用时抛出错误。
    *   **代码示例:**  在 HTTP 网站上尝试调用 `navigator.clipboard.readText()`。

4. **尝试读取或写入不支持的格式:**  尝试读取或写入系统剪贴板中不存在的或浏览器不支持的格式。
    *   **现象:**  读取操作可能返回空数据或导致 Promise reject。写入操作可能失败。
    *   **代码示例:**  尝试读取自定义的二进制剪贴板格式，但浏览器没有相应的处理程序。

5. **编程错误：未正确处理 Promise 的 reject 情况:**  JavaScript 代码没有 `catch` 到 Promise 的 reject，导致错误未被捕获。
    *   **现象:**  可能在控制台看到未处理的 Promise 拒绝警告或错误。

6. **编程错误：在 `ClipboardItem` 中使用了不支持的类型:**  在 `ClipboardItem` 中尝试使用 `DOMString` (在某些浏览器版本或特性开关下可能不支持)。
    *   **现象:**  写入操作的 Promise reject，错误消息指示 `DOMString` 不被支持。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要复制网页上的一段文本：

1. **用户操作:** 用户在网页上选中一段文本。
2. **用户操作:** 用户按下 Ctrl+C 快捷键，或者右键点击并选择“复制”。
3. **浏览器事件:**  浏览器捕获到用户的复制操作。
4. **Blink 事件处理:** Blink 引擎处理复制事件，可能会触发与剪贴板相关的命令 (`ClipboardCommands::ExecuteCopy`)。
5. **JavaScript API 调用 (可选):**  如果网页上绑定了自定义的复制事件处理程序，JavaScript 代码可能会调用 `navigator.clipboard.write()` 或 `navigator.clipboard.writeText()` 方法。即使没有自定义处理程序，浏览器也会默认执行复制操作，底层也会使用 Clipboard API。
6. **`ClipboardPromise` 创建:**  当 JavaScript 调用 Clipboard API 的写入方法时（例如 `navigator.clipboard.writeText()`），Blink 会创建一个 `ClipboardPromise` 对象 (`ClipboardPromise::CreateForWriteText`)。
7. **权限检查:** `ClipboardPromise` 会调用 `ValidatePreconditions` 检查必要的先决条件，包括剪贴板写入权限。
8. **系统剪贴板交互:** 如果权限允许，`ClipboardPromise` 会调用 `SystemClipboard` 的相应方法 (`WritePlainText` 等) 将数据写入操作系统剪贴板。
9. **Promise Resolve/Reject:**  操作成功或失败后，`ClipboardPromise` 会 resolve 或 reject 相应的 JavaScript Promise。

**调试线索:**

*   **断点:** 在 `ClipboardPromise` 的 `CreateForWriteText`, `HandleWriteText`, `ValidatePreconditions`, `HandleWriteTextWithPermission` 等关键方法设置断点，可以观察代码执行流程和变量值。
*   **控制台输出:**  在 JavaScript 代码中添加 `console.log` 或 `console.error` 输出，可以追踪 Promise 的 resolve 和 reject 情况，以及错误信息。
*   **浏览器开发者工具:** 使用浏览器的开发者工具中的“网络”或“性能”标签，可以查看是否有与权限请求相关的网络活动。
*   **权限设置:**  检查浏览器的权限设置，确认网站是否被授予了剪贴板访问权限。
*   **安全上下文:** 确认网页是否运行在 HTTPS 上。
*   **焦点状态:**  确认在执行剪贴板操作时，文档是否拥有焦点。

通过以上分析，我们可以深入了解 `clipboard_promise.cc` 文件的功能，以及它在 Chromium Blink 引擎中处理剪贴板操作的关键作用。

Prompt: 
```
这是目录为blink/renderer/modules/clipboard/clipboard_promise.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/clipboard/clipboard_promise.h"

#include <memory>
#include <utility>

#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_functions.h"
#include "base/task/single_thread_task_runner.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/renderer/bindings/core/v8/promise_all.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_clipboard_unsanitized_formats.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_mime_types.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/editing/commands/clipboard_commands.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/clipboard/clipboard.h"
#include "third_party/blink/renderer/modules/clipboard/clipboard_item.h"
#include "third_party/blink/renderer/modules/clipboard/clipboard_reader.h"
#include "third_party/blink/renderer/modules/clipboard/clipboard_writer.h"
#include "third_party/blink/renderer/modules/permissions/permission_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/base/clipboard/clipboard_constants.h"

// There are 2 clipboard permissions defined in the spec:
// * clipboard-read
// * clipboard-write
// See https://w3c.github.io/clipboard-apis/#clipboard-permissions
//
// These permissions map to these ContentSettings:
// * CLIPBOARD_READ_WRITE, for sanitized read, and unsanitized read/write.
// * CLIPBOARD_SANITIZED_WRITE, for sanitized write only.

namespace blink {

using mojom::blink::PermissionService;

// This class deals with all the clipboard item promises and executes the write
// operation after all the promises have been resolved.
class ClipboardPromise::ClipboardItemDataPromiseFulfill final
    : public ThenCallable<IDLSequence<V8UnionBlobOrString>,
                          ClipboardItemDataPromiseFulfill> {
 public:
  explicit ClipboardItemDataPromiseFulfill(ClipboardPromise* clipboard_promise)
      : clipboard_promise_(clipboard_promise) {}

  void Trace(Visitor* visitor) const final {
    ThenCallable<IDLSequence<V8UnionBlobOrString>,
                 ClipboardItemDataPromiseFulfill>::Trace(visitor);
    visitor->Trace(clipboard_promise_);
  }

  void React(ScriptState* script_state,
             HeapVector<Member<V8UnionBlobOrString>> clipboard_item_list) {
    auto* list_copy =
        MakeGarbageCollected<HeapVector<Member<V8UnionBlobOrString>>>(
            std::move(clipboard_item_list));
    clipboard_promise_->HandlePromiseWrite(list_copy);
  }

 private:
  Member<ClipboardPromise> clipboard_promise_;
};

class ClipboardPromise::ClipboardItemDataPromiseReject final
    : public ThenCallable<IDLAny, ClipboardItemDataPromiseReject> {
 public:
  explicit ClipboardItemDataPromiseReject(ClipboardPromise* clipboard_promise)
      : clipboard_promise_(clipboard_promise) {}

  void Trace(Visitor* visitor) const final {
    ThenCallable<IDLAny, ClipboardItemDataPromiseReject>::Trace(visitor);
    visitor->Trace(clipboard_promise_);
  }

  void React(ScriptState* script_state, ScriptValue exception) {
    clipboard_promise_->RejectClipboardItemPromise(exception);
  }

 private:
  Member<ClipboardPromise> clipboard_promise_;
};

// static
ScriptPromise<IDLSequence<ClipboardItem>> ClipboardPromise::CreateForRead(
    ExecutionContext* context,
    ScriptState* script_state,
    ClipboardUnsanitizedFormats* formats,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    return ScriptPromise<IDLSequence<ClipboardItem>>();
  }
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<ClipboardItem>>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ClipboardPromise* clipboard_promise = MakeGarbageCollected<ClipboardPromise>(
      context, resolver, exception_state);
  clipboard_promise->HandleRead(formats);
  return promise;
}

// static
ScriptPromise<IDLString> ClipboardPromise::CreateForReadText(
    ExecutionContext* context,
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    return EmptyPromise();
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(
      script_state, exception_state.GetContext());
  ClipboardPromise* clipboard_promise = MakeGarbageCollected<ClipboardPromise>(
      context, resolver, exception_state);
  auto promise = resolver->Promise();
  clipboard_promise->HandleReadText();
  return promise;
}

// static
ScriptPromise<IDLUndefined> ClipboardPromise::CreateForWrite(
    ExecutionContext* context,
    ScriptState* script_state,
    const HeapVector<Member<ClipboardItem>>& items,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    return EmptyPromise();
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  ClipboardPromise* clipboard_promise = MakeGarbageCollected<ClipboardPromise>(
      context, resolver, exception_state);
  auto promise = resolver->Promise();
  clipboard_promise->HandleWrite(items);
  return promise;
}

// static
ScriptPromise<IDLUndefined> ClipboardPromise::CreateForWriteText(
    ExecutionContext* context,
    ScriptState* script_state,
    const String& data,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    return EmptyPromise();
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  ClipboardPromise* clipboard_promise = MakeGarbageCollected<ClipboardPromise>(
      context, resolver, exception_state);
  auto promise = resolver->Promise();
  clipboard_promise->HandleWriteText(data);
  return promise;
}

ClipboardPromise::ClipboardPromise(ExecutionContext* context,
                                   ScriptPromiseResolverBase* resolver,
                                   ExceptionState& exception_state)
    : ExecutionContextLifecycleObserver(context),
      script_promise_resolver_(resolver),
      permission_service_(context) {}

ClipboardPromise::~ClipboardPromise() = default;

void ClipboardPromise::CompleteWriteRepresentation() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  clipboard_writer_.Clear();  // The previous write is done.
  ++clipboard_representation_index_;
  WriteNextRepresentation();
}

void ClipboardPromise::WriteNextRepresentation() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!GetExecutionContext() || !GetScriptState()->ContextIsValid()) {
    return;
  }
  ScriptState::Scope scope(GetScriptState());
  LocalFrame* local_frame = GetLocalFrame();
  // Commit to system clipboard when all representations are written.
  // This is in the start flow so that a |clipboard_item_data_| with 0 items
  // will still commit gracefully.
  if (clipboard_representation_index_ == clipboard_item_data_.size()) {
    local_frame->GetSystemClipboard()->CommitWrite();
    script_promise_resolver_->DowncastTo<IDLUndefined>()->Resolve();
    return;
  }

  // We currently write the ClipboardItem type, but don't use the blob type.
  const String& type =
      clipboard_item_data_[clipboard_representation_index_].first;
  const Member<V8UnionBlobOrString>& clipboard_item_data =
      clipboard_item_data_[clipboard_representation_index_].second;

  DCHECK(!clipboard_writer_);
  clipboard_writer_ =
      ClipboardWriter::Create(local_frame->GetSystemClipboard(), type, this);
  if (!clipboard_writer_) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Type " + type + " is not supported");
    return;
  }
  clipboard_writer_->WriteToSystem(clipboard_item_data);
}

void ClipboardPromise::RejectFromReadOrDecodeFailure() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!GetExecutionContext() || !GetScriptState()->ContextIsValid()) {
    return;
  }
  ScriptState::Scope scope(GetScriptState());
  String exception_text =
      RuntimeEnabledFeatures::ClipboardItemWithDOMStringSupportEnabled()
          ? "Failed to read or decode ClipboardItemData for type "
          : "Failed to read or decode Blob for clipboard item type ";
  script_promise_resolver_->RejectWithDOMException(
      DOMExceptionCode::kDataError,
      exception_text +
          clipboard_item_data_[clipboard_representation_index_].first + ".");
}

void ClipboardPromise::HandleRead(ClipboardUnsanitizedFormats* formats) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (formats && formats->hasUnsanitized() && !formats->unsanitized().empty()) {
    Vector<String> unsanitized_formats = formats->unsanitized();
    if (unsanitized_formats.size() > 1) {
      script_promise_resolver_->RejectWithDOMException(
          DOMExceptionCode::kNotAllowedError,
          "Reading multiple unsanitized formats is not supported.");
      return;
    }
    if (unsanitized_formats[0] != kMimeTypeTextHTML) {
      script_promise_resolver_->RejectWithDOMException(
          DOMExceptionCode::kNotAllowedError, "The unsanitized type " +
                                                  unsanitized_formats[0] +
                                                  " is not supported.");
      return;
    }
    // HTML is the only standard format that can be read without any processing
    // for now.
    will_read_unprocessed_html_ = true;
  }

  ValidatePreconditions(
      mojom::blink::PermissionName::CLIPBOARD_READ,
      /*will_be_sanitized=*/false,
      WTF::BindOnce(&ClipboardPromise::HandleReadWithPermission,
                    WrapPersistent(this)));
}

void ClipboardPromise::HandleReadText() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ValidatePreconditions(
      mojom::blink::PermissionName::CLIPBOARD_READ,
      /*will_be_sanitized=*/true,
      WTF::BindOnce(&ClipboardPromise::HandleReadTextWithPermission,
                    WrapPersistent(this)));
}

void ClipboardPromise::HandleWrite(
    const HeapVector<Member<ClipboardItem>>& clipboard_items) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(GetExecutionContext());

  if (clipboard_items.size() > 1) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Support for multiple ClipboardItems is not implemented.");
    return;
  }
  if (!clipboard_items.size()) {
    // Do nothing if there are no ClipboardItems.
    script_promise_resolver_->DowncastTo<IDLUndefined>()->Resolve();
    return;
  }

  // For now, we only process the first ClipboardItem.
  ClipboardItem* clipboard_item = clipboard_items[0];
  clipboard_item_data_with_promises_ = clipboard_item->GetRepresentations();
  write_custom_format_types_ = clipboard_item->CustomFormats();

  if (static_cast<int>(write_custom_format_types_.size()) >
      ui::kMaxRegisteredClipboardFormats) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Number of custom formats exceeds the max limit which is set to 100.");
    return;
  }

  // Input in standard formats is sanitized, so the write will be sanitized
  // unless there are custom formats.
  ValidatePreconditions(
      mojom::blink::PermissionName::CLIPBOARD_WRITE,
      /*will_be_sanitized=*/write_custom_format_types_.empty(),
      WTF::BindOnce(&ClipboardPromise::HandleWriteWithPermission,
                    WrapPersistent(this)));
}

void ClipboardPromise::HandleWriteText(const String& data) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  plain_text_ = data;
  ValidatePreconditions(
      mojom::blink::PermissionName::CLIPBOARD_WRITE,
      /*will_be_sanitized=*/true,
      WTF::BindOnce(&ClipboardPromise::HandleWriteTextWithPermission,
                    WrapPersistent(this)));
}

void ClipboardPromise::HandleReadWithPermission(
    mojom::blink::PermissionStatus status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!GetExecutionContext()) {
    return;
  }
  if (status != mojom::blink::PermissionStatus::GRANTED) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError, "Read permission denied.");
    return;
  }

  SystemClipboard* system_clipboard = GetLocalFrame()->GetSystemClipboard();
  system_clipboard->ReadAvailableCustomAndStandardFormats(WTF::BindOnce(
      &ClipboardPromise::OnReadAvailableFormatNames, WrapPersistent(this)));
}

void ClipboardPromise::ResolveRead() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(GetExecutionContext());

  base::UmaHistogramCounts100("Blink.Clipboard.Read.NumberOfFormats",
                              clipboard_item_data_.size());
  ScriptState* script_state = GetScriptState();
  if (!script_state->ContextIsValid()) {
    return;
  }
  ScriptState::Scope scope(script_state);
  Vector<std::pair<String, ScriptPromise<V8UnionBlobOrString>>> items;
  items.ReserveInitialCapacity(clipboard_item_data_.size());

  for (const auto& item : clipboard_item_data_) {
    if (!item.second) {
      continue;
    }
    auto promise =
        ToResolvedPromise<V8UnionBlobOrString>(script_state, item.second);
    items.emplace_back(item.first, promise);
  }
  HeapVector<Member<ClipboardItem>> clipboard_items = {
      MakeGarbageCollected<ClipboardItem>(items)};
  script_promise_resolver_->DowncastTo<IDLSequence<ClipboardItem>>()->Resolve(
      clipboard_items);
}

void ClipboardPromise::OnReadAvailableFormatNames(
    const Vector<String>& format_names) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!GetExecutionContext()) {
    return;
  }

  clipboard_item_data_.ReserveInitialCapacity(format_names.size());
  for (const String& format_name : format_names) {
    if (ClipboardItem::supports(format_name)) {
      clipboard_item_data_.emplace_back(format_name,
                                        /* Placeholder value. */ nullptr);
    }
  }
  ReadNextRepresentation();
}

void ClipboardPromise::ReadNextRepresentation() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!GetExecutionContext())
    return;
  if (clipboard_representation_index_ == clipboard_item_data_.size()) {
    ResolveRead();
    return;
  }

  ClipboardReader* clipboard_reader = ClipboardReader::Create(
      GetLocalFrame()->GetSystemClipboard(),
      clipboard_item_data_[clipboard_representation_index_].first, this,
      /*sanitize_html=*/!will_read_unprocessed_html_);
  if (!clipboard_reader) {
    OnRead(nullptr);
    return;
  }
  clipboard_reader->Read();
}

void ClipboardPromise::OnRead(Blob* blob) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (blob) {
    clipboard_item_data_[clipboard_representation_index_].second =
        MakeGarbageCollected<V8UnionBlobOrString>(blob);
  }
  ++clipboard_representation_index_;
  ReadNextRepresentation();
}

void ClipboardPromise::HandleReadTextWithPermission(
    mojom::blink::PermissionStatus status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!GetExecutionContext()) {
    return;
  }
  if (status != mojom::blink::PermissionStatus::GRANTED) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError, "Read permission denied.");
    return;
  }

  String text = GetLocalFrame()->GetSystemClipboard()->ReadPlainText(
      mojom::blink::ClipboardBuffer::kStandard);
  script_promise_resolver_->DowncastTo<IDLString>()->Resolve(text);
}

void ClipboardPromise::HandlePromiseWrite(
    HeapVector<Member<V8UnionBlobOrString>>* clipboard_item_list) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  GetClipboardTaskRunner()->PostTask(
      FROM_HERE,
      WTF::BindOnce(&ClipboardPromise::WriteClipboardItemData,
                    WrapPersistent(this), WrapPersistent(clipboard_item_list)));
}

void ClipboardPromise::WriteClipboardItemData(
    HeapVector<Member<V8UnionBlobOrString>>* clipboard_item_list) {
  wtf_size_t clipboard_item_index = 0;
  CHECK_EQ(write_clipboard_item_types_.size(), clipboard_item_list->size());
  for (const auto& clipboard_item_data : *clipboard_item_list) {
    if (!RuntimeEnabledFeatures::ClipboardItemWithDOMStringSupportEnabled() &&
        !clipboard_item_data->IsBlob()) {
      script_promise_resolver_->RejectWithDOMException(
          DOMExceptionCode::kNotAllowedError,
          "DOMString is not supported in ClipboardItem");
      return;
    }

    const String& type = write_clipboard_item_types_[clipboard_item_index];
    if (clipboard_item_data->IsBlob()) {
      const String& type_with_args = clipboard_item_data->GetAsBlob()->type();
      // For web custom types, extract the MIME type after removing the "web "
      // prefix. For normal (not-custom) write, blobs may have a full MIME type
      // with args (ex. 'text/plain;charset=utf-8'), whereas the type must not
      // have args (ex. 'text/plain' only), so ensure that Blob->type is
      // contained in type.
      String web_custom_format = Clipboard::ParseWebCustomFormat(type);
      if ((!type_with_args.Contains(type.LowerASCII()) &&
           web_custom_format.empty()) ||
          (!web_custom_format.empty() &&
           !type_with_args.Contains(web_custom_format))) {
        script_promise_resolver_->RejectWithDOMException(
            DOMExceptionCode::kNotAllowedError,
            "Type " + type + " does not match the blob's type " +
                type_with_args);
        return;
      }
    }
    clipboard_item_data_.emplace_back(type, clipboard_item_data);
    clipboard_item_index++;
  }
  write_clipboard_item_types_.clear();

  DCHECK(!clipboard_representation_index_);
  WriteNextRepresentation();
}

void ClipboardPromise::HandleWriteWithPermission(
    mojom::blink::PermissionStatus status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!GetExecutionContext()) {
    return;
  }
  if (status != mojom::blink::PermissionStatus::GRANTED) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError, "Write permission denied.");
    return;
  }

  HeapVector<MemberScriptPromise<V8UnionBlobOrString>> promise_list;
  promise_list.ReserveInitialCapacity(
      clipboard_item_data_with_promises_.size());
  write_clipboard_item_types_.ReserveInitialCapacity(
      clipboard_item_data_with_promises_.size());
  // Check that all types are valid.
  for (const auto& type_and_promise : clipboard_item_data_with_promises_) {
    const String& type = type_and_promise.first;
    write_clipboard_item_types_.emplace_back(type);
    promise_list.emplace_back(type_and_promise.second);
    if (!ClipboardItem::supports(type)) {
      script_promise_resolver_->RejectWithDOMException(
          DOMExceptionCode::kNotAllowedError,
          "Type " + type + " not supported on write.");
      return;
    }
  }
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);
  PromiseAll<V8UnionBlobOrString>::Create(script_state, promise_list)
      .Then(script_state,
            MakeGarbageCollected<ClipboardItemDataPromiseFulfill>(this),
            MakeGarbageCollected<ClipboardItemDataPromiseReject>(this));
}

void ClipboardPromise::HandleWriteTextWithPermission(
    mojom::blink::PermissionStatus status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!GetExecutionContext()) {
    return;
  }
  if (status != mojom::blink::PermissionStatus::GRANTED) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError, "Write permission denied.");
    return;
  }

  SystemClipboard* system_clipboard = GetLocalFrame()->GetSystemClipboard();
  system_clipboard->WritePlainText(plain_text_);
  system_clipboard->CommitWrite();
  script_promise_resolver_->DowncastTo<IDLUndefined>()->Resolve();
}

void ClipboardPromise::RejectClipboardItemPromise(ScriptValue exception) {
  script_promise_resolver_->Reject(exception);
}

PermissionService* ClipboardPromise::GetPermissionService() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ExecutionContext* context = GetExecutionContext();
  DCHECK(context);
  if (!permission_service_.is_bound()) {
    ConnectToPermissionService(context,
                               permission_service_.BindNewPipeAndPassReceiver(
                                   GetClipboardTaskRunner()));
  }
  return permission_service_.get();
}

void ClipboardPromise::ValidatePreconditions(
    mojom::blink::PermissionName permission,
    bool will_be_sanitized,
    base::OnceCallback<void(mojom::blink::PermissionStatus)> callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(script_promise_resolver_);
  DCHECK(permission == mojom::blink::PermissionName::CLIPBOARD_READ ||
         permission == mojom::blink::PermissionName::CLIPBOARD_WRITE);

  ExecutionContext* context = GetExecutionContext();
  DCHECK(context);
  LocalDOMWindow& window = *To<LocalDOMWindow>(context);
  DCHECK(window.IsSecureContext());  // [SecureContext] in IDL

  if (!window.document()->hasFocus()) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError, "Document is not focused.");
    return;
  }

  constexpr char kFeaturePolicyMessage[] =
      "The Clipboard API has been blocked because of a permissions policy "
      "applied to the current document. See https://goo.gl/EuHzyv for more "
      "details.";

  if ((permission == mojom::blink::PermissionName::CLIPBOARD_READ &&
       !window.IsFeatureEnabled(
           mojom::blink::PermissionsPolicyFeature::kClipboardRead,
           ReportOptions::kReportOnFailure, kFeaturePolicyMessage)) ||
      (permission == mojom::blink::PermissionName::CLIPBOARD_WRITE &&
       !window.IsFeatureEnabled(
           mojom::blink::PermissionsPolicyFeature::kClipboardWrite,
           ReportOptions::kReportOnFailure, kFeaturePolicyMessage))) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError, kFeaturePolicyMessage);
    return;
  }

  // Grant permission by-default if extension has read/write permissions.
  if (GetLocalFrame()->GetContentSettingsClient() &&
      ((permission == mojom::blink::PermissionName::CLIPBOARD_READ &&
        GetLocalFrame()
            ->GetContentSettingsClient()
            ->AllowReadFromClipboard()) ||
       (permission == mojom::blink::PermissionName::CLIPBOARD_WRITE &&
        GetLocalFrame()
            ->GetContentSettingsClient()
            ->AllowWriteToClipboard()))) {
    GetClipboardTaskRunner()->PostTask(
        FROM_HERE, WTF::BindOnce(std::move(callback),
                                 mojom::blink::PermissionStatus::GRANTED));
    return;
  }

  if ((permission == mojom::blink::PermissionName::CLIPBOARD_WRITE &&
       ClipboardCommands::IsExecutingCutOrCopy(*context)) ||
      (permission == mojom::blink::PermissionName::CLIPBOARD_READ &&
       ClipboardCommands::IsExecutingPaste(*context))) {
    GetClipboardTaskRunner()->PostTask(
        FROM_HERE, WTF::BindOnce(std::move(callback),
                                 mojom::blink::PermissionStatus::GRANTED));
    return;
  }

  if (!GetPermissionService()) {
    script_promise_resolver_->RejectWithDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Permission Service could not connect.");
    return;
  }

  bool has_transient_user_activation =
      LocalFrame::HasTransientUserActivation(GetLocalFrame());
  auto permission_descriptor = CreateClipboardPermissionDescriptor(
      permission, /*has_user_gesture=*/has_transient_user_activation,
      /*will_be_sanitized=*/will_be_sanitized);

  // Note that extra checks are performed browser-side in
  // `ContentBrowserClient::IsClipboardPasteAllowed()`.
  permission_service_->RequestPermission(
      std::move(permission_descriptor),
      /*user_gesture=*/has_transient_user_activation, std::move(callback));
}

LocalFrame* ClipboardPromise::GetLocalFrame() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ExecutionContext* context = GetExecutionContext();
  // In case the context was destroyed and the caller didn't check for it, we
  // just return nullptr.
  if (!context) {
    return nullptr;
  }
  LocalFrame* local_frame = To<LocalDOMWindow>(context)->GetFrame();
  return local_frame;
}

ScriptState* ClipboardPromise::GetScriptState() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return script_promise_resolver_->GetScriptState();
}

scoped_refptr<base::SingleThreadTaskRunner>
ClipboardPromise::GetClipboardTaskRunner() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return GetExecutionContext()->GetTaskRunner(TaskType::kClipboard);
}

// ExecutionContextLifecycleObserver implementation.
void ClipboardPromise::ContextDestroyed() {
  // This isn't the correct way to create a DOMException, but the correct way
  // probably wouldn't work at this point, and it probably doesn't matter.
  script_promise_resolver_->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotAllowedError, "Document detached."));
  clipboard_writer_.Clear();
}

void ClipboardPromise::Trace(Visitor* visitor) const {
  visitor->Trace(script_promise_resolver_);
  visitor->Trace(clipboard_writer_);
  visitor->Trace(permission_service_);
  visitor->Trace(clipboard_item_data_);
  visitor->Trace(clipboard_item_data_with_promises_);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink

"""

```