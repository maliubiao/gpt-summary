Response:
Let's break down the thought process for analyzing this `dom_exception.cc` file.

1. **Understand the Goal:** The core request is to explain the purpose of this file, its connections to web technologies (JavaScript, HTML, CSS), provide illustrative examples, explain potential user errors, and outline debugging steps.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for key terms. "DOMException," "error," "code," "message," "JavaScript,"  "HTML," and any related terms jump out. The copyright notice also indicates this is part of a web browser engine (Chromium/Blink).

3. **Identify the Core Functionality:** The code defines a class `DOMException` and a static table `kDOMExceptionEntryTable`. This table clearly maps error codes to error names and messages. The `Create`, `GetErrorName`, and `GetErrorMessage` static methods are for creating and retrieving information about exceptions. The constructor initializes `DOMException` objects.

4. **Connect to Web Technologies:**  The name "DOMException" itself strongly suggests a connection to the Document Object Model (DOM), which is the fundamental way JavaScript interacts with HTML. Think about common JavaScript error scenarios related to the DOM. This will lead to examples like accessing non-existent elements, modifying read-only nodes, etc.

5. **Illustrate with Examples (JavaScript & HTML):**

   * **JavaScript:**  Focus on common DOM manipulation errors that throw exceptions. `getElementById` returning `null` and then trying to access properties is a classic `TypeError`, but the `dom_exception.cc` is about *specific* DOMExceptions. So, think about actions that *should* throw specific DOMExceptions. `IndexSizeError` when accessing array-like structures, `NotFoundError` when trying to remove a non-existent node, `NoModificationAllowedError` with read-only elements are good starting points.
   * **HTML:** How do user actions in the HTML context trigger these errors?  It's often indirect, through JavaScript interactions with the DOM. The HTML provides the structure that JavaScript manipulates.

6. **Consider CSS:** CSS doesn't directly throw DOMExceptions. However, invalid CSS *can* indirectly lead to situations where JavaScript tries to interact with elements in unexpected ways. For example, if CSS hides an element, JavaScript might try to get its dimensions, potentially leading to errors depending on how the element is hidden. The connection is less direct but worth noting.

7. **Reasoning and Input/Output:**  Think about how the code works internally. If a JavaScript function calls a Blink API that could fail, that API might return a specific `DOMExceptionCode`. The `dom_exception.cc` then translates that code into a human-readable error message.

   * **Hypothetical Input:**  A JavaScript call tries to remove a node that doesn't exist.
   * **Internal Process:** The Blink rendering engine detects this and raises a `DOMExceptionCode::kNotFoundError`.
   * **Output:** The `DOMException::GetErrorMessage(DOMExceptionCode::kNotFoundError)` function returns "An attempt was made to reference a Node in a context where it does not exist." This message is then likely presented to the developer in the browser's console.

8. **User/Programming Errors:**  Shift the focus to how developers or even end-users might trigger these exceptions. Incorrect JavaScript code is the primary culprit. Typos in IDs, assumptions about element existence, attempting disallowed modifications are all common programming errors. For the end-user, actions like clicking buttons that trigger error-prone JavaScript code can lead to these exceptions.

9. **Debugging Clues and User Steps:**  Think about how a developer would debug these errors. The browser's developer console is the key tool. The error message, the stack trace, and the line of code where the error occurred are vital. Trace back the user's actions that led to that point. This involves considering the sequence of events: user interaction -> JavaScript code execution -> Blink API call -> DOMException.

10. **Structure and Refinement:** Organize the information logically. Start with the core functionality, then connect it to web technologies, provide examples, explain errors, and finally, discuss debugging. Use clear headings and bullet points for better readability. Ensure the language is precise and avoids jargon where possible. Review and refine the explanations to ensure accuracy and clarity. For instance, initially I might have focused too much on `TypeError`, but the request is specifically about `DOMException`, so I adjusted the examples accordingly. Also, emphasizing the *mapping* between error codes and messages is crucial.

11. **Self-Correction Example During Analysis:**  Initially, I might think of `console.error()` as being directly related to `dom_exception.cc`. However, `dom_exception.cc` *creates* the `DOMException` object. `console.error()` is a higher-level function that *displays* errors, often including `DOMException` messages. The connection is that `dom_exception.cc` provides the error information that `console.error()` uses.

By following this structured approach, combining code analysis with knowledge of web development concepts, and thinking through concrete examples, we can generate a comprehensive and accurate explanation of the `dom_exception.cc` file.
好的，我们来详细分析一下 `blink/renderer/core/dom/dom_exception.cc` 文件的功能。

**核心功能:**

这个文件的主要功能是定义和管理 DOM 异常 (DOMException)。DOM 异常是当在 Web 浏览器中执行与文档对象模型 (DOM) 相关的操作时发生错误时抛出的特定类型的异常。该文件包含了：

1. **DOM 异常代码的定义和映射:**  它维护了一个静态的结构体数组 `kDOMExceptionEntryTable`，这个数组存储了所有可能的 DOM 异常的代码 (枚举类型 `DOMExceptionCode`)、对应的名称 (字符串，例如 "IndexSizeError") 和默认的错误消息。

2. **创建 DOMException 对象:** 提供了静态方法 `Create` 用于创建 `DOMException` 类的实例。这个方法接受错误消息和错误名称作为参数，并根据错误名称查找对应的错误代码。

3. **获取错误名称和消息:** 提供了静态方法 `GetErrorName` 和 `GetErrorMessage`，根据给定的 `DOMExceptionCode` 返回相应的错误名称和默认错误消息。

4. **DOMException 类的实现:**  定义了 `DOMException` 类本身，包含：
   - 存储错误代码 (`legacy_code_`)，错误名称 (`name_`)，以及经过清理和未清理的错误消息 (`sanitized_message_`, `unsanitized_message_`)。
   - 构造函数，用于初始化 `DOMException` 对象。
   - `ToStringForConsole` 方法，用于生成在浏览器控制台中显示的错误字符串。
   - `AddContextToMessages` 方法，用于在错误消息中添加上下文信息，例如发生错误的类名和属性名。

5. **将 DOMExceptionCode 转换为旧代码:**  提供 `ToLegacyErrorCode` 函数，用于将新的 `DOMExceptionCode` 转换为旧版本的错误代码（如果存在）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

DOM 异常是 Web 平台规范的一部分，直接与 JavaScript 和 HTML 的交互相关。当 JavaScript 代码尝试执行某些不符合规范或导致错误的 DOM 操作时，浏览器会抛出 DOM 异常。CSS 本身不会直接抛出 DOM 异常，但错误的 CSS 可能导致 JavaScript 操作 DOM 时出现问题，从而间接导致 DOM 异常。

**JavaScript 示例:**

```javascript
// 假设有一个数组
const myArray = [1, 2, 3];

// 尝试访问超出数组索引的元素，会抛出 IndexSizeError
try {
  const element = myArray[5];
} catch (e) {
  console.error(e.name); // 输出 "IndexSizeError"
  console.error(e.message); // 输出 "Index or size was negative, or greater than the allowed value."
}

// 尝试移除一个不存在的节点，会抛出 NotFoundError
try {
  document.body.removeChild(document.getElementById('nonExistentElement'));
} catch (e) {
  console.error(e.name); // 输出 "NotFoundError"
  console.error(e.message); // 输出 "An attempt was made to reference a Node in a context where it does not exist."
}

// 尝试修改一个只读的 DOM 节点，会抛出 NoModificationAllowedError
const title = document.querySelector('title');
try {
  title.textContent = 'New Title';
} catch (e) {
  console.error(e.name); // 输出 "NoModificationAllowedError"
  console.error(e.message); // 输出 "An attempt was made to modify an object where modifications are not allowed."
}
```

**HTML 示例 (间接关系):**

```html
<!DOCTYPE html>
<html>
<head>
  <title>Original Title</title>
</head>
<body>
  <div id="myDiv"></div>
  <script>
    // 假设 HTML 中没有 id 为 'missingDiv' 的元素
    try {
      const missingDiv = document.getElementById('missingDiv');
      document.body.removeChild(missingDiv); // 会在这里抛出 NotFoundError
    } catch (e) {
      console.error(e);
    }
  </script>
</body>
</html>
```

**CSS 示例 (间接关系):**

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    #hiddenElement {
      display: none;
    }
  </style>
</head>
<body>
  <div id="hiddenElement">This is hidden</div>
  <script>
    const hiddenElement = document.getElementById('hiddenElement');
    try {
      // 尝试获取隐藏元素的高度，可能会导致一些布局相关的异常，
      // 虽然不一定是直接的 DOMException，但错误的 CSS 可能导致
      // JavaScript 操作 DOM 时出现预料之外的情况。
      const height = hiddenElement.offsetHeight;
      console.log(height); // 可能输出 0 或引发其他问题
    } catch (e) {
      console.error(e);
    }
  </script>
</body>
</html>
```

**逻辑推理、假设输入与输出:**

假设 JavaScript 代码尝试访问一个 `NodeList` 中超出范围的索引：

**假设输入:**

- JavaScript 代码： `myNodeList.item(10);` （假设 `myNodeList` 的长度小于 10）

**内部逻辑推理:**

1. Blink 渲染引擎执行到 `myNodeList.item(10)`。
2. `NodeList::item()` 方法内部会检查索引是否越界。
3. 发现索引 10 超出了 `myNodeList` 的有效索引范围。
4. Blink 引擎会创建一个 `DOMException` 对象，其 `DOMExceptionCode` 为 `kIndexSizeError`。
5. `DOMException::GetErrorName(DOMExceptionCode::kIndexSizeError)` 返回 "IndexSizeError"。
6. `DOMException::GetErrorMessage(DOMExceptionCode::kIndexSizeError)` 返回 "Index or size was negative, or greater than the allowed value."

**输出 (抛出的 DOMException 对象):**

- `name`: "IndexSizeError"
- `message`: "Index or size was negative, or greater than the allowed value."
- `legacy_code`:  （对应的旧版本错误代码）

**用户或编程常见的使用错误及举例说明:**

1. **索引越界:** 访问数组、`NodeList` 等集合时，使用了超出有效范围的索引。
   ```javascript
   const elements = document.querySelectorAll('p');
   const lastElement = elements[elements.length]; // 错误，应该使用 elements.length - 1
   ```

2. **尝试操作不存在的节点:**  例如，使用 `getElementById` 获取一个不存在的元素，然后对其进行操作。
   ```javascript
   const nonExistent = document.getElementById('doesNotExist');
   nonExistent.textContent = 'New Text'; // 会抛出 TypeError，因为 nonExistent 为 null
   ```
   (虽然这里会先抛出 `TypeError`, 但如果 Blink 内部某些操作依赖于该节点的存在，则可能最终抛出 `NotFoundError`)

3. **在错误的文档中使用节点:** 尝试将一个文档中的节点插入到另一个文档中。
   ```javascript
   const iframe = document.createElement('iframe');
   document.body.appendChild(iframe);
   const otherDocument = iframe.contentDocument;
   const myElement = document.createElement('div');
   try {
     otherDocument.body.appendChild(myElement); // 错误，myElement 属于主文档
   } catch (e) {
     console.error(e.name); // 输出 "WrongDocumentError"
   }
   ```

4. **尝试修改只读属性或节点:** 例如，尝试修改 `title` 元素的 `textContent` (在某些特定情况下可能是只读的，或者操作在不被允许的时机进行)。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一个用户操作导致 `IndexSizeError` 的例子以及调试线索：

**用户操作步骤:**

1. 用户在网页上点击一个按钮。
2. 该按钮绑定了一个 JavaScript 事件监听器。
3. JavaScript 代码在事件处理函数中尝试获取一个动态生成的列表的最后一个元素。
4. 代码中使用了 `list.item(list.length)` 来访问最后一个元素（这是一个错误，因为索引是从 0 开始的，最后一个元素的索引是 `list.length - 1`）。

**调试线索:**

1. **控制台错误信息:** 浏览器控制台会显示一个类似 "Uncaught DOMException: IndexSizeError: Index or size was negative, or greater than the allowed value." 的错误信息。
2. **堆栈跟踪 (Stack Trace):**  控制台还会提供堆栈跟踪，指出哪个 JavaScript 文件、哪一行代码触发了该错误。
3. **断点调试:** 开发者可以在浏览器开发者工具中设置断点，在 JavaScript 代码执行到访问列表元素的地方暂停，检查 `list.length` 的值以及尝试访问的索引，从而发现索引越界的问题。
4. **审查元素:** 检查网页的 DOM 结构，确认列表元素的数量，从而理解为什么访问 `list.length` 索引会超出范围。

**总结:**

`blink/renderer/core/dom/dom_exception.cc` 文件在 Chromium Blink 引擎中扮演着至关重要的角色，它定义和管理了 DOM 操作中可能发生的各种错误，确保了 Web 平台的稳定性和规范性。它直接关联着 JavaScript 与 HTML 的交互，并为开发者提供了丰富的错误信息，帮助他们调试和修复 Web 应用中的 DOM 相关问题。

### 提示词
```
这是目录为blink/renderer/core/dom/dom_exception.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY GOOGLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/dom/dom_exception.h"

#include "base/notreached.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"

namespace blink {

namespace {

// Name, description, and legacy code name and value of DOMExceptions.
// https://webidl.spec.whatwg.org/#idl-DOMException-error-names
const struct DOMExceptionEntry {
  DOMExceptionCode code;
  const char* name;
  const char* message;
} kDOMExceptionEntryTable[] = {
    // DOMException defined with legacy error code in Web IDL.
    {DOMExceptionCode::kIndexSizeError, "IndexSizeError",
     "Index or size was negative, or greater than the allowed value."},
    {DOMExceptionCode::kHierarchyRequestError, "HierarchyRequestError",
     "A Node was inserted somewhere it doesn't belong."},
    {DOMExceptionCode::kWrongDocumentError, "WrongDocumentError",
     "A Node was used in a different document than the one that created it "
     "(that doesn't support it)."},
    {DOMExceptionCode::kInvalidCharacterError, "InvalidCharacterError",
     "The string contains invalid characters."},
    {DOMExceptionCode::kNoModificationAllowedError,
     "NoModificationAllowedError",
     "An attempt was made to modify an object where modifications are not "
     "allowed."},
    {DOMExceptionCode::kNotFoundError, "NotFoundError",
     "An attempt was made to reference a Node in a context where it does not "
     "exist."},
    {DOMExceptionCode::kNotSupportedError, "NotSupportedError",
     "The implementation did not support the requested type of object or "
     "operation."},
    {DOMExceptionCode::kInUseAttributeError, "InUseAttributeError",
     "An attempt was made to add an attribute that is already in use "
     "elsewhere."},
    {DOMExceptionCode::kInvalidStateError, "InvalidStateError",
     "An attempt was made to use an object that is not, or is no longer, "
     "usable."},
    {DOMExceptionCode::kSyntaxError, "SyntaxError",
     "An invalid or illegal string was specified."},
    {DOMExceptionCode::kInvalidModificationError, "InvalidModificationError",
     "The object can not be modified in this way."},
    {DOMExceptionCode::kNamespaceError, "NamespaceError",
     "An attempt was made to create or change an object in a way which is "
     "incorrect with regard to namespaces."},
    {DOMExceptionCode::kInvalidAccessError, "InvalidAccessError",
     "A parameter or an operation was not supported by the underlying object."},
    {DOMExceptionCode::kTypeMismatchError, "TypeMismatchError",
     "The type of an object was incompatible with the expected type of the "
     "parameter associated to the object."},
    {DOMExceptionCode::kSecurityError, "SecurityError",
     "An attempt was made to break through the security policy of the user "
     "agent."},
    {DOMExceptionCode::kNetworkError, "NetworkError",
     "A network error occurred."},
    {DOMExceptionCode::kAbortError, "AbortError",
     "The user aborted a request."},
    {DOMExceptionCode::kURLMismatchError, "URLMismatchError",
     "A worker global scope represented an absolute URL that is not equal to "
     "the resulting absolute URL."},
    {DOMExceptionCode::kQuotaExceededError, "QuotaExceededError",
     "An attempt was made to add something to storage that exceeded the "
     "quota."},
    {DOMExceptionCode::kTimeoutError, "TimeoutError", "A timeout occurred."},
    {DOMExceptionCode::kInvalidNodeTypeError, "InvalidNodeTypeError",
     "The supplied node is invalid or has an invalid ancestor for this "
     "operation."},
    {DOMExceptionCode::kDataCloneError, "DataCloneError",
     "An object could not be cloned."},

    // DOMException defined without legacy error code in Web IDL.
    {DOMExceptionCode::kEncodingError, "EncodingError",
     "A URI supplied to the API was malformed, or the resulting Data URL has "
     "exceeded the URL length limitations for Data URLs."},
    {DOMExceptionCode::kNotReadableError, "NotReadableError",
     "The requested file could not be read, typically due to permission "
     "problems that have occurred after a reference to a file was acquired."},
    {DOMExceptionCode::kUnknownError, "UnknownError",
     "The operation failed for an unknown transient reason "
     "(e.g. out of memory)."},
    {DOMExceptionCode::kConstraintError, "ConstraintError",
     "A mutation operation in the transaction failed because a constraint was "
     "not satisfied."},
    {DOMExceptionCode::kDataError, "DataError",
     "The data provided does not meet requirements."},
    {DOMExceptionCode::kTransactionInactiveError, "TransactionInactiveError",
     "A request was placed against a transaction which is either currently not "
     "active, or which is finished."},
    {DOMExceptionCode::kReadOnlyError, "ReadOnlyError",
     "A write operation was attempted in a read-only transaction."},
    {DOMExceptionCode::kVersionError, "VersionError",
     "An attempt was made to open a database using a lower version than the "
     "existing version."},
    {DOMExceptionCode::kOperationError, "OperationError",
     "The operation failed for an operation-specific reason"},
    {DOMExceptionCode::kNotAllowedError, "NotAllowedError",
     "The request is not allowed by the user agent or the platform in the "
     "current context."},
    {DOMExceptionCode::kOptOutError, "OptOutError",
     "The user opted out of the process."},

    // DOMError (obsolete, not DOMException) defined in File system (obsolete).
    // https://www.w3.org/TR/2012/WD-file-system-api-20120417/
    {DOMExceptionCode::kPathExistsError, "PathExistsError",
     "An attempt was made to create a file or directory where an element "
     "already exists."},

    // Push API
    //
    // PermissionDeniedError (obsolete) was replaced with NotAllowedError in the
    // standard.
    // https://github.com/WICG/BackgroundSync/issues/124
    {DOMExceptionCode::kPermissionDeniedError, "PermissionDeniedError",
     "User or security policy denied the request."},

    // Serial API - https://wicg.github.io/serial
    {DOMExceptionCode::kBreakError, "BreakError",
     "A break condition has been detected."},
    {DOMExceptionCode::kBufferOverrunError, "BufferOverrunError",
     "A buffer overrun has been detected."},
    {DOMExceptionCode::kFramingError, "FramingError",
     "A framing error has been detected."},
    {DOMExceptionCode::kParityError, "ParityError",
     "A parity error has been detected."},
    {DOMExceptionCode::kWebTransportError, "WebTransportError",
     "The WebTransport operation failed."},

    // Smart Card API
    // https://wicg.github.io/web-smart-card/#smartcarderror-interface
    {DOMExceptionCode::kSmartCardError, "SmartCardError",
     "A Smart Card operation failed."},

    // WebGPU https://www.w3.org/TR/webgpu/
    {DOMExceptionCode::kGPUPipelineError, "GPUPipelineError",
     "A WebGPU pipeline creation failed."},

    // Media Capture and Streams API
    // https://w3c.github.io/mediacapture-main/#overconstrainederror-interface
    {DOMExceptionCode::kOverconstrainedError, "OverconstrainedError",
     "The desired set of constraints/capabilities cannot be met."},

    // FedCM API
    // https://fedidcg.github.io/FedCM/#browser-api-identity-credential-error-interface
    {DOMExceptionCode::kIdentityCredentialError, "IdentityCredentialError",
     "An attempt to retrieve an IdentityCredential has failed."},

    // WebSocketStream API https://websockets.spec.whatwg.org/
    {DOMExceptionCode::kWebSocketError, "WebSocketError",
     "The WebSocket connection was closed."},

    // Extra comment to keep the end of the initializer list on its own line.
};

uint16_t ToLegacyErrorCode(DOMExceptionCode exception_code) {
  if (DOMExceptionCode::kLegacyErrorCodeMin <= exception_code &&
      exception_code <= DOMExceptionCode::kLegacyErrorCodeMax) {
    return static_cast<uint16_t>(exception_code);
  }
  return 0;
}

const DOMExceptionEntry* FindErrorEntry(DOMExceptionCode exception_code) {
  for (const auto& entry : kDOMExceptionEntryTable) {
    if (exception_code == entry.code)
      return &entry;
  }
  NOTREACHED();
}

uint16_t FindLegacyErrorCode(const String& name) {
  for (const auto& entry : kDOMExceptionEntryTable) {
    if (name == entry.name)
      return ToLegacyErrorCode(entry.code);
  }
  return 0;
}

}  // namespace

// static
DOMException* DOMException::Create(const String& message, const String& name) {
  return MakeGarbageCollected<DOMException>(FindLegacyErrorCode(name), name,
                                            message, String());
}

// static
String DOMException::GetErrorName(DOMExceptionCode exception_code) {
  const DOMExceptionEntry* entry = FindErrorEntry(exception_code);

  DCHECK(entry);
  if (!entry)
    return "UnknownError";

  return entry->name;
}

// static
String DOMException::GetErrorMessage(DOMExceptionCode exception_code) {
  const DOMExceptionEntry* entry = FindErrorEntry(exception_code);

  DCHECK(entry);
  if (!entry)
    return "Unknown error.";

  return entry->message;
}

DOMException::DOMException(DOMExceptionCode exception_code,
                           String sanitized_message,
                           String unsanitized_message) {
  // Don't delegate to another constructor to avoid calling FindErrorEntry()
  // multiple times.
  auto* error_entry = FindErrorEntry(exception_code);
  CHECK(error_entry);
  legacy_code_ = ToLegacyErrorCode(error_entry->code);
  name_ = error_entry->name;
  sanitized_message_ = sanitized_message.IsNull()
                           ? String(error_entry->message)
                           : std::move(sanitized_message);
  unsanitized_message_ = std::move(unsanitized_message);
}

DOMException::DOMException(DOMExceptionCode exception_code,
                           const char* sanitized_message,
                           const char* unsanitized_message)
    : DOMException(
          exception_code,
          sanitized_message ? String(sanitized_message) : String(),
          unsanitized_message ? String(unsanitized_message) : String()) {}

DOMException::DOMException(uint16_t legacy_code,
                           const String& name,
                           const String& sanitized_message,
                           const String& unsanitized_message)
    : legacy_code_(legacy_code),
      name_(name),
      sanitized_message_(sanitized_message),
      unsanitized_message_(unsanitized_message) {
  DCHECK(name);
}

String DOMException::ToStringForConsole() const {
  // If an unsanitized message is present, we prefer it.
  const String& message_for_console =
      !unsanitized_message_.empty() ? unsanitized_message_ : sanitized_message_;
  return message_for_console.empty()
             ? String()
             : "Uncaught " + name() + ": " + message_for_console;
}

void DOMException::AddContextToMessages(v8::ExceptionContext type,
                                        const char* class_name,
                                        const String& property_name) {
  sanitized_message_ = ExceptionMessages::AddContextToMessage(
      type, class_name, property_name, sanitized_message_);
  if (!unsanitized_message_.IsNull()) {
    unsanitized_message_ = ExceptionMessages::AddContextToMessage(
        type, class_name, property_name, unsanitized_message_);
  }
}

}  // namespace blink
```