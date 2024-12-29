Response:
Let's break down the thought process for analyzing the `global_file_system_access.cc` file.

**1. Understanding the Goal:**

The request asks for the file's functionality, its relation to web technologies (JavaScript, HTML, CSS), examples, logical reasoning, common errors, and how users reach this code.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to read through the code, looking for important keywords and patterns. This helps establish the general purpose. Keywords that immediately jump out include:

* `file_system_access` (appears in the filename, includes, and namespaces)
* `showOpenFilePicker`, `showSaveFilePicker`, `showDirectoryPicker` (function names suggest user interaction)
* `ScriptPromise` (indicates asynchronous operations, likely related to JavaScript Promises)
* `LocalDOMWindow` (points to browser window context)
* `OpenFilePickerOptions`, `SaveFilePickerOptions`, `DirectoryPickerOptions` (configuration for the file pickers)
* `FilePickerAcceptType` (deals with file type filtering)
* `FileSystemFileHandle`, `FileSystemDirectoryHandle` (represent selected files and directories)
* `mojom::blink::*` (indicates communication with the browser process, likely through Mojo)
* `ExceptionState` (error handling)
* `UserActivation` (security measure related to user interaction)

**3. Identifying Core Functionality:**

Based on the keywords and function names, it becomes clear that this file implements the core logic for the File System Access API in the Blink rendering engine. Specifically, it handles:

* **Showing file and directory pickers:**  The `showOpenFilePicker`, `showSaveFilePicker`, and `showDirectoryPicker` functions directly correspond to the JavaScript methods.
* **Handling user selections:**  The callbacks within these functions process the files or directories selected by the user.
* **Interacting with the browser process:**  The `mojom::blink::FileSystemAccessManager` is used to send requests to the browser process to actually display the native file picker dialogs.
* **Enforcing security constraints:** Checks for user activation, same-origin policy, and sandbox restrictions are present.
* **Converting JavaScript options to internal representations:**  The code translates the options passed from JavaScript (like allowed file types, starting directory, etc.) into Mojo messages.

**4. Relating to JavaScript, HTML, and CSS:**

* **JavaScript:** The file directly implements the JavaScript API. The function names match the global methods available in the browser. The use of `ScriptPromise` links directly to JavaScript's asynchronous programming model. The options objects (`OpenFilePickerOptions`, etc.) correspond to JavaScript objects passed to these methods.
* **HTML:** While this file doesn't directly *render* HTML, the functionality is triggered by JavaScript that runs within an HTML page. User interaction with HTML elements (like buttons) often leads to the execution of this JavaScript.
* **CSS:** CSS has no direct functional relationship with this code. CSS styles the elements on the page, but the file system access logic is purely functional.

**5. Constructing Examples:**

To illustrate the connection with web technologies, it's crucial to provide code examples:

* **JavaScript example:**  Demonstrate how to call the `showOpenFilePicker`, `showSaveFilePicker`, and `showDirectoryPicker` methods, showing how to pass options and handle the returned Promises.
* **HTML example:** Show a simple HTML structure with a button that triggers the JavaScript code.

**6. Logical Reasoning and Assumptions:**

The logical flow involves:

* **Input:** JavaScript calls one of the `show*Picker` methods with options.
* **Validation:** The Blink code validates the input (e.g., valid file extensions, user activation).
* **Browser Interaction:**  Blink sends a Mojo request to the browser process.
* **User Interaction:** The browser displays the native file picker dialog.
* **Output (Success):** The user selects a file/directory, and the browser sends the information back to Blink, which resolves the JavaScript Promise with `FileSystemFileHandle` or `FileSystemDirectoryHandle` objects.
* **Output (Failure):**  The user cancels, an error occurs, or validation fails, and the Promise is rejected with an error.

**7. Identifying Common Errors:**

Consider common mistakes developers might make:

* **Missing user activation:**  Calling the file picker without a recent user interaction.
* **Incorrect file type specification:**  Providing invalid file extensions or MIME types.
* **Security errors:**  Trying to use the API in a sandboxed iframe or cross-origin context without proper permissions.

**8. Tracing User Actions (Debugging Clues):**

Think about the user's journey that leads to this code being executed:

1. **User opens a web page:** The initial HTML, CSS, and JavaScript are loaded.
2. **User interacts with the page:**  Clicks a button, for instance.
3. **JavaScript is executed:** The button's event listener triggers a script that calls `showOpenFilePicker`, `showSaveFilePicker`, or `showDirectoryPicker`.
4. **Blink's File System Access code is invoked:** This is where the `global_file_system_access.cc` code comes into play.

**9. Structuring the Answer:**

Organize the information logically with clear headings:

* **Functionality:** A high-level description of what the file does.
* **Relationship to Web Technologies:** Explain how it connects to JavaScript, HTML, and CSS with examples.
* **Logical Reasoning:** Describe the input, processing, and output.
* **Common Usage Errors:** List typical developer mistakes.
* **User Actions and Debugging:** Explain the steps leading to the code's execution.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe CSS is involved in styling the file picker dialog.
* **Correction:**  The native file picker is OS-controlled and not directly styled by web page CSS. CSS's role is in the *triggering* elements on the web page.
* **Initial thought:**  Focus heavily on the Mojo communication details.
* **Refinement:** While Mojo is important, the explanation should be more focused on the user-facing functionality and the connection to the JavaScript API. Mojo is an implementation detail.
* **Ensuring clarity in examples:** Make sure the JavaScript and HTML examples are simple and easy to understand, directly illustrating the usage of the API.

By following these steps, the analysis becomes more structured, comprehensive, and accurate, leading to a helpful and informative answer.
这个文件 `global_file_system_access.cc` 是 Chromium Blink 引擎中实现 **File System Access API** 的核心部分。它提供了全局可访问的方法，允许网页上的 JavaScript 代码请求用户选择本地文件或目录，并与它们进行交互。

**主要功能:**

1. **实现 `showOpenFilePicker()` 方法:**
   - 允许网页上的 JavaScript 代码显示一个“打开文件”的对话框，让用户选择一个或多个文件。
   - 接收 `OpenFilePickerOptions` 对象作为参数，用于配置对话框的行为，例如允许选择的文件类型、是否允许多选、以及建议的起始目录等。
   - 返回一个 `Promise`，该 Promise 在用户选择文件后解析为一个包含 `FileSystemFileHandle` 对象（代表选中的文件）的数组，或者在用户取消选择时被拒绝。

2. **实现 `showSaveFilePicker()` 方法:**
   - 允许网页上的 JavaScript 代码显示一个“保存文件”的对话框，让用户指定要保存文件的位置和名称。
   - 接收 `SaveFilePickerOptions` 对象作为参数，用于配置对话框的行为，例如允许保存的文件类型、建议的文件名、以及建议的起始目录等。
   - 返回一个 `Promise`，该 Promise 在用户选择保存位置后解析为一个 `FileSystemFileHandle` 对象（代表要保存的文件），或者在用户取消选择时被拒绝。

3. **实现 `showDirectoryPicker()` 方法:**
   - 允许网页上的 JavaScript 代码显示一个“选择目录”的对话框，让用户选择一个目录。
   - 接收 `DirectoryPickerOptions` 对象作为参数，用于配置对话框的行为，例如建议的起始目录以及是否请求写入权限。
   - 返回一个 `Promise`，该 Promise 在用户选择目录后解析为一个 `FileSystemDirectoryHandle` 对象（代表选中的目录），或者在用户取消选择时被拒绝。

4. **处理用户输入和权限:**
   - 验证用户是否进行了有效的操作（例如，在用户手势之后调用）。
   - 与浏览器进程通信，显示本地操作系统的文件选择对话框。
   - 处理用户在对话框中的选择或取消操作。
   - 检查安全限制，例如是否在沙箱环境中，以及是否允许访问文件系统。

5. **参数验证和转换:**
   - 验证传递给 JavaScript 方法的选项参数是否有效（例如，文件扩展名格式）。
   - 将 JavaScript 的选项参数转换为 Blink 内部使用的 Mojo 消息格式，以便与浏览器进程通信。

6. **错误处理:**
   - 当操作失败时（例如，用户取消选择，权限不足），会拒绝返回的 Promise，并提供相应的错误信息。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:** 此文件直接实现了 JavaScript 中可用的全局方法 `showOpenFilePicker()`, `showSaveFilePicker()`, 和 `showDirectoryPicker()`。开发者在 JavaScript 代码中调用这些方法来触发文件/目录选择器。

   ```javascript
   // 打开文件选择器
   async function openFile() {
     try {
       const fileHandles = await window.showOpenFilePicker({
         types: [{
           description: 'Images',
           accept: { 'image/*': ['.png', '.gif', '.jpeg', '.jpg'] },
         }],
         multiple: false
       });
       // 处理选中的文件
       const file = await fileHandles[0].getFile();
       console.log(file.name, file.size, file.type);
     } catch (err) {
       console.error("打开文件失败:", err.name, err.message);
     }
   }

   // 保存文件选择器
   async function saveFile() {
     try {
       const fileHandle = await window.showSaveFilePicker({
         suggestedName: 'my-document.txt',
         types: [{
           description: 'Text files',
           accept: { 'text/plain': ['.txt'] },
         }],
       });
       // 处理要保存的文件
       const writable = await fileHandle.createWritable();
       await writable.write('Hello, world!');
       await writable.close();
     } catch (err) {
       console.error("保存文件失败:", err.name, err.message);
     }
   }

   // 选择目录选择器
   async function selectDirectory() {
     try {
       const directoryHandle = await window.showDirectoryPicker();
       console.log(directoryHandle.name);
     } catch (err) {
       console.error("选择目录失败:", err.name, err.message);
     }
   }
   ```

* **HTML:** HTML 中通常包含触发这些 JavaScript 代码的元素，例如按钮。

   ```html
   <button onclick="openFile()">打开文件</button>
   <button onclick="saveFile()">保存文件</button>
   <button onclick="selectDirectory()">选择目录</button>
   <script src="your-script.js"></script>
   ```

* **CSS:** CSS 用于样式化 HTML 元素，例如按钮，但它不直接参与文件系统访问 API 的核心逻辑。CSS 的作用是提供用户界面，让用户可以触发与文件系统交互的 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入 (对于 `showOpenFilePicker`):**

* 用户点击了网页上的“打开文件”按钮。
* JavaScript 代码调用 `window.showOpenFilePicker({ types: [{ accept: { 'image/*': ['.png'] } }] })`。

**逻辑推理:**

1. `GlobalFileSystemAccess::showOpenFilePicker` 被调用，接收到 `OpenFilePickerOptions` 对象，其中指定了只允许选择 PNG 图片。
2. 此函数会验证选项，例如确保文件扩展名以 "." 开头。
3. 它会检查安全上下文，例如用户是否在用户激活状态下。
4. 它会创建一个 Mojo 消息，请求浏览器进程显示文件选择对话框，并设置过滤器为 PNG 图片。
5. 浏览器进程显示对话框。
6. **假设用户选择了名为 `image.png` 的文件并点击了“打开”。**

**假设输出:**

* `showOpenFilePicker` 返回的 `Promise` 会被解析。
* `Promise` 的 `resolve` 回调函数会接收到一个包含一个 `FileSystemFileHandle` 对象的数组。
* 这个 `FileSystemFileHandle` 对象代表用户选择的 `image.png` 文件。

**假设输入 (对于 `showSaveFilePicker`):**

* 用户点击了网页上的“保存文件”按钮。
* JavaScript 代码调用 `window.showSaveFilePicker({ suggestedName: 'report.txt' })`。

**逻辑推理:**

1. `GlobalFileSystemAccess::showSaveFilePicker` 被调用，接收到 `SaveFilePickerOptions` 对象，其中建议的文件名为 `report.txt`。
2. 此函数会验证选项。
3. 它会检查安全上下文。
4. 它会创建一个 Mojo 消息，请求浏览器进程显示保存文件对话框，并预填文件名 `report.txt`。
5. 浏览器进程显示对话框。
6. **假设用户接受了建议的文件名，并选择了保存位置，点击了“保存”。**

**假设输出:**

* `showSaveFilePicker` 返回的 `Promise` 会被解析。
* `Promise` 的 `resolve` 回调函数会接收到一个 `FileSystemFileHandle` 对象。
* 这个 `FileSystemFileHandle` 对象代表用户指定保存的 `report.txt` 文件。

**涉及用户或者编程常见的使用错误举例说明:**

1. **未在用户激活时调用:**  如果 `showOpenFilePicker` 等方法在没有用户手势（例如点击按钮）的情况下被调用，浏览器会阻止显示文件选择器，并抛出一个错误。这是出于安全考虑，防止恶意网站随意访问用户的文件系统。

   ```javascript
   // 错误示例：在页面加载时尝试打开文件选择器
   window.onload = async () => {
     try {
       await window.showOpenFilePicker(); // 这很可能会失败
     } catch (error) {
       console.error("打开文件选择器失败:", error.name, error.message); // 可能会输出 SecurityError
     }
   };
   ```

2. **文件类型参数配置错误:**  `types` 选项中的 `accept` 属性需要正确的 MIME 类型和文件扩展名。如果配置不当，用户可能无法选择他们期望的文件类型。

   ```javascript
   // 错误示例：MIME 类型或扩展名不正确
   await window.showOpenFilePicker({
     types: [{
       description: 'Text Files',
       accept: { 'text/plain': ['.doc'] }, // .doc 通常不是纯文本文件
     }],
   });
   ```

3. **安全限制:** 在某些安全上下文中，例如 `<iframe>` 元素中，或者跨域请求，文件系统访问 API 可能受到限制。

   ```html
   <!-- 如果 iframe 的 sandbox 属性阻止了文件系统访问，以下代码会失败 -->
   <iframe sandbox="allow-scripts" src="..."></iframe>
   <script>
     iframe.contentWindow.showOpenFilePicker(); // 可能会抛出 SecurityError
   </script>
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **用户与网页交互:** 用户首先需要与一个包含相关 JavaScript 代码的网页进行交互。这通常意味着用户点击了一个按钮、链接或其他触发 JavaScript 事件的 HTML 元素。

2. **触发 JavaScript 代码:** 用户操作触发了与该 HTML 元素关联的 JavaScript 事件监听器（例如 `onclick`）。

3. **调用 `showOpenFilePicker` 等方法:** 在 JavaScript 事件监听器内部，代码调用了全局的 `window.showOpenFilePicker()`, `window.showSaveFilePicker()`, 或 `window.showDirectoryPicker()` 方法。

4. **Blink 引擎介入:**  当这些 JavaScript 方法被调用时，Blink 引擎会捕获这些调用，并进入到 `global_file_system_access.cc` 文件中的相应函数（例如 `GlobalFileSystemAccess::showOpenFilePicker`）。

5. **参数处理和验证:**  `global_file_system_access.cc` 中的函数会接收并处理来自 JavaScript 的参数，进行必要的验证，例如文件类型、安全上下文等。

6. **Mojo 消息发送:** 如果验证通过，Blink 引擎会创建一个 Mojo 消息，并通过 IPC (进程间通信) 将请求发送到浏览器进程。这个消息包含了要显示的文件选择器的配置信息。

7. **浏览器进程处理:** 浏览器进程接收到 Mojo 消息，并根据消息中的信息显示本地操作系统的文件选择对话框。

8. **用户与文件选择器交互:** 用户与操作系统提供的原生文件选择器进行交互，选择文件或目录，或者取消操作。

9. **结果返回:**
   - **成功:** 用户选择文件/目录并确认后，操作系统会将选择结果返回给浏览器进程。浏览器进程再通过 Mojo 消息将结果发送回 Blink 引擎。`global_file_system_access.cc` 中的 Promise 会被解析，并将 `FileSystemFileHandle` 或 `FileSystemDirectoryHandle` 对象传递给 JavaScript 的 `then` 回调函数。
   - **失败/取消:** 如果用户取消操作或发生错误，操作系统会将相应的状态返回给浏览器进程，浏览器进程再通过 Mojo 消息通知 Blink 引擎。`global_file_system_access.cc` 中的 Promise 会被拒绝，并将错误信息传递给 JavaScript 的 `catch` 回调函数。

**作为调试线索:**

当调试文件系统访问相关的代码时，可以关注以下几点：

* **断点:** 在 `global_file_system_access.cc` 中设置断点，可以观察参数的传递、验证过程以及 Mojo 消息的发送。
* **Console 输出:** 在 JavaScript 代码中添加 `console.log` 或 `console.error`，可以查看 Promise 的状态和错误信息。
* **浏览器开发者工具:** 使用浏览器的开发者工具（例如 Chrome DevTools）可以查看控制台输出、网络请求（虽然这里主要是进程间通信，但有时能观察到一些端倪）以及断点调试 JavaScript 代码。
* **用户激活状态:** 确认调用文件选择器的方法是在用户手势之后执行的。
* **文件类型配置:** 检查 `types` 选项是否配置正确。
* **安全上下文:** 确认代码运行在允许文件系统访问的安全上下文中。

通过理解用户操作的流程以及 `global_file_system_access.cc` 在其中的作用，开发者可以更有效地调试与 File System Access API 相关的错误。

Prompt: 
```
这是目录为blink/renderer/modules/file_system_access/global_file_system_access.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/file_system_access/global_file_system_access.h"

#include <utility>

#include "base/notreached.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_error.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_manager.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_manager.mojom-blink.h"
#include "third_party/blink/public/mojom/file_system_access/file_system_access_manager.mojom-shared.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_usvstring_usvstringsequence.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_directory_picker_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_picker_accept_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_open_file_picker_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_save_file_picker_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_filesystemhandle_wellknowndirectory.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_well_known_directory.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_error.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_access_manager.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_directory_handle.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_file_handle.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"

namespace blink {

namespace {

constexpr char kDefaultStartingDirectoryId[] = "";

constexpr bool IsHTTPWhitespace(UChar chr) {
  return chr == ' ' || chr == '\n' || chr == '\t' || chr == '\r';
}

bool IsValidSuffixCodePoint(UChar chr) {
  return IsASCIIAlphanumeric(chr) || chr == '+' || chr == '.';
}

bool IsValidIdCodePoint(UChar chr) {
  return IsASCIIAlphanumeric(chr) || chr == '_' || chr == '-';
}

bool VerifyIsValidExtension(const String& extension,
                            ExceptionState& exception_state) {
  if (!extension.StartsWith(".")) {
    exception_state.ThrowTypeError("Extension '" + extension +
                                   "' must start with '.'.");
    return false;
  }
  if (!extension.IsAllSpecialCharacters<IsValidSuffixCodePoint>()) {
    exception_state.ThrowTypeError("Extension '" + extension +
                                   "' contains invalid characters.");
    return false;
  }
  if (extension.EndsWith(".")) {
    exception_state.ThrowTypeError("Extension '" + extension +
                                   "' must not end with '.'.");
    return false;
  }
  if (extension.length() > 16) {
    exception_state.ThrowTypeError("Extension '" + extension +
                                   "' cannot be longer than 16 characters.");
    return false;
  }

  return true;
}

String VerifyIsValidId(const String& id, ExceptionState& exception_state) {
  if (!id.IsAllSpecialCharacters<IsValidIdCodePoint>()) {
    exception_state.ThrowTypeError("ID '" + id +
                                   "' contains invalid characters.");
    return String();
  }
  if (id.length() > 32) {
    exception_state.ThrowTypeError("ID '" + id +
                                   "' cannot be longer than 32 characters.");
    return String();
  }

  return std::move(id);
}

bool AddExtension(const String& extension,
                  Vector<String>& extensions,
                  ExceptionState& exception_state) {
  if (!VerifyIsValidExtension(extension, exception_state))
    return false;

  extensions.push_back(extension.Substring(1));
  return true;
}

Vector<mojom::blink::ChooseFileSystemEntryAcceptsOptionPtr> ConvertAccepts(
    const HeapVector<Member<FilePickerAcceptType>>& types,
    ExceptionState& exception_state) {
  Vector<mojom::blink::ChooseFileSystemEntryAcceptsOptionPtr> result;
  result.ReserveInitialCapacity(types.size());
  for (const auto& t : types) {
    if (!t->hasAccept())
      continue;
    Vector<String> mimeTypes;
    mimeTypes.ReserveInitialCapacity(t->accept().size());
    Vector<String> extensions;
    for (const auto& a : t->accept()) {
      String type = a.first.StripWhiteSpace(IsHTTPWhitespace);
      if (type.empty()) {
        exception_state.ThrowTypeError("Invalid type: " + a.first);
        return {};
      }
      Vector<String> parsed_type;
      type.Split('/', true, parsed_type);
      if (parsed_type.size() != 2) {
        exception_state.ThrowTypeError("Invalid type: " + a.first);
        return {};
      }
      if (!IsValidHTTPToken(parsed_type[0])) {
        exception_state.ThrowTypeError("Invalid type: " + a.first);
        return {};
      }
      if (!IsValidHTTPToken(parsed_type[1])) {
        exception_state.ThrowTypeError("Invalid type: " + a.first);
        return {};
      }

      mimeTypes.push_back(type);
      switch (a.second->GetContentType()) {
        case V8UnionUSVStringOrUSVStringSequence::ContentType::kUSVString:
          if (!AddExtension(a.second->GetAsUSVString(), extensions,
                            exception_state)) {
            return {};
          }
          break;
        case V8UnionUSVStringOrUSVStringSequence::ContentType::
            kUSVStringSequence:
          for (const auto& extension : a.second->GetAsUSVStringSequence()) {
            if (!AddExtension(extension, extensions, exception_state)) {
              return {};
            }
          }
          break;
      }
    }
    result.emplace_back(
        blink::mojom::blink::ChooseFileSystemEntryAcceptsOption::New(
            t->description(), std::move(mimeTypes), std::move(extensions)));
  }
  return result;
}

void VerifyIsAllowedToShowFilePicker(const LocalDOMWindow& window,
                                     ExceptionState& exception_state) {
  if (!window.IsCurrentlyDisplayedInFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kAbortError, "");
    return;
  }

  if (!window.GetSecurityOrigin()->CanAccessFileSystem()) {
    if (window.IsSandboxed(network::mojom::blink::WebSandboxFlags::kOrigin)) {
      exception_state.ThrowSecurityError(
          "Sandboxed documents aren't allowed to show a file picker.");
      return;
    } else {
      exception_state.ThrowSecurityError(
          "This document isn't allowed to show a file picker.");
      return;
    }
  }

  LocalFrame* local_frame = window.GetFrame();
  if (!local_frame || local_frame->IsCrossOriginToOutermostMainFrame()) {
    exception_state.ThrowSecurityError(
        "Cross origin sub frames aren't allowed to show a file picker.");
    return;
  }

  if (!LocalFrame::HasTransientUserActivation(local_frame) &&
      local_frame->GetSettings()
          ->GetRequireTransientActivationForShowFileOrDirectoryPicker()) {
    exception_state.ThrowSecurityError(
        "Must be handling a user gesture to show a file picker.");
    return;
  }
}

mojom::blink::WellKnownDirectory ToMojomWellKnownDirectory(
    V8WellKnownDirectory v8_well_known_directory) {
  // This assertion protects against the IDL enum changing without updating the
  // corresponding mojom interface, or vice versa. The offset of 1 accounts for
  // the zero-indexing of the mojom enum values.
  static_assert(
      V8WellKnownDirectory::kEnumSize ==
          static_cast<size_t>(mojom::blink::WellKnownDirectory::kMaxValue) + 1,
      "the number of values in the WellKnownDirectory mojom enum "
      "must match the number of values in the WellKnownDirectory blink enum");

  switch (v8_well_known_directory.AsEnum()) {
    case V8WellKnownDirectory::Enum::kDesktop:
      return mojom::blink::WellKnownDirectory::kDirDesktop;
    case V8WellKnownDirectory::Enum::kDocuments:
      return mojom::blink::WellKnownDirectory::kDirDocuments;
    case V8WellKnownDirectory::Enum::kDownloads:
      return mojom::blink::WellKnownDirectory::kDirDownloads;
    case V8WellKnownDirectory::Enum::kMusic:
      return mojom::blink::WellKnownDirectory::kDirMusic;
    case V8WellKnownDirectory::Enum::kPictures:
      return mojom::blink::WellKnownDirectory::kDirPictures;
    case V8WellKnownDirectory::Enum::kVideos:
      return mojom::blink::WellKnownDirectory::kDirVideos;
  }
}

mojom::blink::FilePickerStartInOptionsUnionPtr ToMojomStartInOptions(
    const V8UnionFileSystemHandleOrWellKnownDirectory* start_in_union) {
  switch (start_in_union->GetContentType()) {
    case V8UnionFileSystemHandleOrWellKnownDirectory::ContentType::
        kFileSystemHandle:
      return mojom::blink::FilePickerStartInOptionsUnion::NewDirectoryToken(
          start_in_union->GetAsFileSystemHandle()->Transfer());
    case V8UnionFileSystemHandleOrWellKnownDirectory::ContentType::
        kWellKnownDirectory:
      return mojom::blink::FilePickerStartInOptionsUnion::NewWellKnownDirectory(
          ToMojomWellKnownDirectory(start_in_union->GetAsWellKnownDirectory()));
  }
}

enum class ShowFilePickerType { kSequence, kHandle, kDirectory };

void ShowFilePickerImpl(ScriptPromiseResolverBase* resolver,
                        LocalDOMWindow& window,
                        mojom::blink::FilePickerOptionsPtr options,
                        ExceptionState& exception_state,
                        ShowFilePickerType type) {
  bool multiple =
      options->type_specific_options->is_open_file_picker_options() &&
      options->type_specific_options->get_open_file_picker_options()
          ->can_select_multiple_files;
  bool intercepted = false;
  probe::FileChooserOpened(window.GetFrame(), /*element=*/nullptr, multiple,
                           &intercepted);
  if (intercepted) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kAbortError,
        "Intercepted by Page.setInterceptFileChooserDialog().");
    return;
  }

  FileSystemAccessManager::From(resolver->GetExecutionContext())
      ->ChooseEntries(
          std::move(options),
          WTF::BindOnce(
              [](ScriptPromiseResolverBase* resolver, ShowFilePickerType type,
                 LocalFrame* local_frame,
                 mojom::blink::FileSystemAccessErrorPtr file_operation_result,
                 Vector<mojom::blink::FileSystemAccessEntryPtr> entries) {
                ExecutionContext* context = resolver->GetExecutionContext();
                if (!context) {
                  return;
                }
                if (file_operation_result->status !=
                    mojom::blink::FileSystemAccessStatus::kOk) {
                  file_system_access_error::Reject(resolver,
                                                   *file_operation_result);
                  return;
                }

                // While it would be better to not trust the renderer process,
                // we're doing this here to avoid potential mojo message pipe
                // ordering problems, where the frame activation state
                // reconciliation messages would compete with concurrent File
                // System Access messages to the browser.
                // TODO(https://crbug.com/1017270): Remove this after spec
                // change, or when activation moves to browser.
                LocalFrame::NotifyUserActivation(
                    local_frame, mojom::blink::UserActivationNotificationType::
                                     kFileSystemAccess);

                if (type == ShowFilePickerType::kSequence) {
                  HeapVector<Member<FileSystemFileHandle>> results;
                  results.ReserveInitialCapacity(entries.size());
                  for (auto& entry : entries) {
                    auto* handle = FileSystemHandle::CreateFromMojoEntry(
                        std::move(entry), context);
                    results.push_back(To<FileSystemFileHandle>(handle));
                  }
                  resolver->DowncastTo<IDLSequence<FileSystemFileHandle>>()
                      ->Resolve(results);
                } else {
                  DCHECK_EQ(1u, entries.size());
                  auto* handle = FileSystemHandle::CreateFromMojoEntry(
                      std::move(entries[0]), context);
                  if (type == ShowFilePickerType::kHandle) {
                    resolver->DowncastTo<FileSystemFileHandle>()->Resolve(
                        To<FileSystemFileHandle>(handle));
                  } else {
                    resolver->DowncastTo<FileSystemDirectoryHandle>()->Resolve(
                        To<FileSystemDirectoryHandle>(handle));
                  }
                }
              },
              WrapPersistent(resolver), type,
              WrapPersistent(window.GetFrame())));
}

}  // namespace

// static
ScriptPromise<IDLSequence<FileSystemFileHandle>>
GlobalFileSystemAccess::showOpenFilePicker(ScriptState* script_state,
                                           LocalDOMWindow& window,
                                           const OpenFilePickerOptions* options,
                                           ExceptionState& exception_state) {
  UseCounter::Count(window, WebFeature::kFileSystemPickerMethod);

  Vector<mojom::blink::ChooseFileSystemEntryAcceptsOptionPtr> accepts;
  if (options->hasTypes())
    accepts = ConvertAccepts(options->types(), exception_state);
  if (exception_state.HadException())
    return ScriptPromise<IDLSequence<FileSystemFileHandle>>();

  if (accepts.empty() && options->excludeAcceptAllOption()) {
    exception_state.ThrowTypeError("Need at least one accepted type");
    return ScriptPromise<IDLSequence<FileSystemFileHandle>>();
  }

  String starting_directory_id = kDefaultStartingDirectoryId;
  if (options->hasId()) {
    starting_directory_id = VerifyIsValidId(options->id(), exception_state);
    if (exception_state.HadException())
      return ScriptPromise<IDLSequence<FileSystemFileHandle>>();
  }

  mojom::blink::FilePickerStartInOptionsUnionPtr start_in_options;
  if (options->hasStartIn()) {
    start_in_options = ToMojomStartInOptions(options->startIn());
  }

  VerifyIsAllowedToShowFilePicker(window, exception_state);
  if (exception_state.HadException())
    return ScriptPromise<IDLSequence<FileSystemFileHandle>>();

  auto open_file_picker_options = mojom::blink::OpenFilePickerOptions::New(
      mojom::blink::AcceptsTypesInfo::New(std::move(accepts),
                                          !options->excludeAcceptAllOption()),
      options->multiple());

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLSequence<FileSystemFileHandle>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ShowFilePickerImpl(
      resolver, window,
      mojom::blink::FilePickerOptions::New(
          mojom::blink::TypeSpecificFilePickerOptionsUnion::
              NewOpenFilePickerOptions(std::move(open_file_picker_options)),
          std::move(starting_directory_id), std::move(start_in_options)),
      exception_state, ShowFilePickerType::kSequence);
  return promise;
}

// static
ScriptPromise<FileSystemFileHandle> GlobalFileSystemAccess::showSaveFilePicker(
    ScriptState* script_state,
    LocalDOMWindow& window,
    const SaveFilePickerOptions* options,
    ExceptionState& exception_state) {
  UseCounter::Count(window, WebFeature::kFileSystemPickerMethod);

  Vector<mojom::blink::ChooseFileSystemEntryAcceptsOptionPtr> accepts;
  if (options->hasTypes())
    accepts = ConvertAccepts(options->types(), exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  if (accepts.empty() && options->excludeAcceptAllOption()) {
    exception_state.ThrowTypeError("Need at least one accepted type");
    return EmptyPromise();
  }

  String starting_directory_id = kDefaultStartingDirectoryId;
  if (options->hasId()) {
    starting_directory_id = VerifyIsValidId(options->id(), exception_state);
    if (exception_state.HadException())
      return EmptyPromise();
  }

  mojom::blink::FilePickerStartInOptionsUnionPtr start_in_options;
  if (options->hasStartIn()) {
    start_in_options = ToMojomStartInOptions(options->startIn());
  }

  VerifyIsAllowedToShowFilePicker(window, exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  auto save_file_picker_options = mojom::blink::SaveFilePickerOptions::New(
      mojom::blink::AcceptsTypesInfo::New(std::move(accepts),
                                          !options->excludeAcceptAllOption()),
      (options->hasSuggestedName() && !options->suggestedName().IsNull())
          ? options->suggestedName()
          : g_empty_string);
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FileSystemFileHandle>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ShowFilePickerImpl(
      resolver, window,
      mojom::blink::FilePickerOptions::New(
          mojom::blink::TypeSpecificFilePickerOptionsUnion::
              NewSaveFilePickerOptions(std::move(save_file_picker_options)),
          std::move(starting_directory_id), std::move(start_in_options)),
      exception_state, ShowFilePickerType::kHandle);
  return promise;
}

// static
ScriptPromise<FileSystemDirectoryHandle>
GlobalFileSystemAccess::showDirectoryPicker(
    ScriptState* script_state,
    LocalDOMWindow& window,
    const DirectoryPickerOptions* options,
    ExceptionState& exception_state) {
  UseCounter::Count(window, WebFeature::kFileSystemPickerMethod);

  String starting_directory_id = kDefaultStartingDirectoryId;
  if (options->hasId()) {
    starting_directory_id = VerifyIsValidId(options->id(), exception_state);
    if (exception_state.HadException())
      return EmptyPromise();
  }

  mojom::blink::FilePickerStartInOptionsUnionPtr start_in_options;
  if (options->hasStartIn()) {
    start_in_options = ToMojomStartInOptions(options->startIn());
  }

  VerifyIsAllowedToShowFilePicker(window, exception_state);
  if (exception_state.HadException())
    return EmptyPromise();

  bool request_writable =
      options->mode() == V8FileSystemPermissionMode::Enum::kReadwrite;
  auto directory_picker_options =
      mojom::blink::DirectoryPickerOptions::New(request_writable);
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<FileSystemDirectoryHandle>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  ShowFilePickerImpl(
      resolver, window,
      mojom::blink::FilePickerOptions::New(
          mojom::blink::TypeSpecificFilePickerOptionsUnion::
              NewDirectoryPickerOptions(std::move(directory_picker_options)),
          std::move(starting_directory_id), std::move(start_in_options)),
      exception_state, ShowFilePickerType::kDirectory);
  return promise;
}

}  // namespace blink

"""

```