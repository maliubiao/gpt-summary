Response:
Let's break down the thought process for analyzing this C++ file and generating the response.

1. **Understand the Goal:** The request asks for the functionality of `file_error.cc`, its relationship to web technologies (JavaScript, HTML, CSS), examples, logical reasoning (input/output), and common usage errors.

2. **Initial Scan and Keyword Identification:**  I first scan the code for important keywords and structures. I see:
    * `Copyright`, `Google Inc.`, `blink`: Confirms it's a Chromium/Blink file.
    * `#include`:  Shows dependencies on other Blink components like `dom_exception.h`, `exception_state.h`, and `base/files/file.h`. This hints at the file's core purpose: handling file-related errors and converting them to DOM exceptions.
    * `namespace blink`, `namespace file_error`:  Identifies the code's organizational structure.
    * `const char k...ErrorMessage[]`:  These are clearly error message strings.
    * `enum FileErrorCode`:  An enumeration of file-specific error codes.
    * `ErrorCodeToExceptionCode`, `ErrorCodeToMessage`, `FileErrorToExceptionCode`, `FileErrorToMessage`: These are crucial functions for converting internal error codes to DOMException details.
    * `ThrowDOMException`:  The core function for actually raising DOM exceptions.
    * `CreateDOMException`:  A function to create `DOMException` objects.

3. **Core Functionality Identification:** Based on the keywords and structures, the primary function of this file is evident: **mapping internal file system errors (represented by `FileErrorCode` and `base::File::Error`) to DOMException objects that can be understood and handled by JavaScript in web pages.**

4. **Relationship to Web Technologies:**  Now, I need to connect this C++ code to the browser's user-facing aspects.

    * **JavaScript:**  JavaScript uses the File API (e.g., `FileReader`, `FileWriter`, `FileSystem API`). When these APIs encounter file system errors, the browser needs a way to report these errors to the JavaScript code. The `DOMException` is the standard mechanism for this. Therefore, this C++ code *directly supports* the JavaScript File API by providing the error reporting mechanism.

    * **HTML:** HTML provides the `<input type="file">` element, which allows users to select files. When JavaScript interacts with these files (e.g., using `FileReader`), the underlying operations can trigger file errors handled by this C++ code.

    * **CSS:** CSS itself doesn't directly interact with the file system in a way that would generate these specific file errors. While CSS might reference images or other assets, the *loading* of those assets is typically handled by other parts of the browser engine. Therefore, the connection to CSS is weaker and less direct. I need to be careful not to overstate the connection.

5. **Examples:**  To illustrate the connection to JavaScript and HTML, I need concrete examples. I consider common scenarios where file errors might occur:

    * Trying to read a non-existent file (using `FileReader`).
    * Attempting to write to a file when permissions are denied (using `FileWriter`).
    * Exceeding storage quota (using the File System API).
    * Aborting a file operation.

6. **Logical Reasoning (Input/Output):** The functions that convert error codes are perfect for demonstrating input/output. I select a few representative `FileErrorCode` and `base::File::Error` values and show how they map to `DOMExceptionCode` and error messages.

7. **Common Usage Errors:** I think about what mistakes developers might make when working with file APIs:

    * Not handling errors properly (the most common).
    * Incorrectly assuming file paths or permissions.
    * Ignoring quota limits.
    * Misunderstanding asynchronous operations and abortion.

8. **Structure and Language:** I organize the information logically, starting with the core functionality and then elaborating on the relationships and examples. I use clear and concise language, explaining technical terms where necessary. I make sure to distinguish between the C++ implementation and the JavaScript/HTML usage.

9. **Refinement and Review:**  I reread the generated response to ensure accuracy, clarity, and completeness. I check for any inconsistencies or areas where the explanation could be improved. For example, I initially might have focused too much on the internal C++ details and needed to shift the emphasis to the user-facing implications. I also double-check the mappings between error codes and DOMException codes to ensure correctness based on the source code.

This iterative process of analyzing the code, connecting it to web technologies, generating examples, and refining the explanation allows for a comprehensive and accurate answer to the prompt.
这个文件 `file_error.cc` 的主要功能是 **定义和处理 Blink 渲染引擎中与文件操作相关的错误**。它提供了一组工具和函数，用于将底层的、平台相关的错误代码转换为符合 Web 标准的 `DOMException` 对象，从而使 JavaScript 代码能够以统一的方式处理这些错误。

以下是该文件的详细功能列表：

**1. 定义文件错误相关的常量字符串消息:**

该文件定义了一系列常量字符串 (`kAbortErrorMessage`、`kEncodingErrorMessage` 等)，这些字符串用于描述不同类型的文件操作错误。这些消息会作为 `DOMException` 对象的 `message` 属性返回给 JavaScript。

**2. 定义内部文件错误枚举 `FileErrorCode` (虽然代码中没有直接定义，但被引用和使用):**

虽然这个 `.cc` 文件本身没有定义 `FileErrorCode`，但它使用了这个枚举。`FileErrorCode` 在 Blink 的其他地方定义，用于表示 Blink 内部的文件操作错误类型。

**3. 提供将内部 `FileErrorCode` 转换为 `DOMExceptionCode` 的函数 `ErrorCodeToExceptionCode`:**

这个函数接收一个 `FileErrorCode` 枚举值作为输入，并将其映射到相应的 `DOMExceptionCode` 枚举值。`DOMExceptionCode` 是 Web 标准中定义的错误类型，例如 `NotFoundError`、`SecurityError` 等。

**假设输入与输出:**

* **输入:** `FileErrorCode::kNotFoundErr`
* **输出:** `DOMExceptionCode::kNotFoundError`

* **输入:** `FileErrorCode::kSecurityErr`
* **输出:** `DOMExceptionCode::kSecurityError`

**4. 提供将内部 `FileErrorCode` 转换为错误消息字符串的函数 `ErrorCodeToMessage`:**

这个函数接收一个 `FileErrorCode` 枚举值作为输入，并返回与之对应的错误消息字符串。如果某个错误码没有特定的消息，则返回 `nullptr`，表示使用默认消息。

**假设输入与输出:**

* **输入:** `FileErrorCode::kAbortErr`
* **输出:** 指向字符串 `"An ongoing operation was aborted, typically with a call to abort()."` 的指针

* **输入:** `FileErrorCode::kInvalidModificationErr`
* **输出:** `nullptr`

**5. 提供将底层平台文件错误 `base::File::Error` 转换为 `DOMExceptionCode` 的函数 `FileErrorToExceptionCode`:**

这个函数接收一个 `base::File::Error` 枚举值（来自 Chromium 的 `base` 库，代表操作系统级别的错误）作为输入，并将其映射到相应的 `DOMExceptionCode`。

**假设输入与输出:**

* **输入:** `base::File::FILE_ERROR_NOT_FOUND`
* **输出:** `DOMExceptionCode::kNotFoundError`

* **输入:** `base::File::FILE_ERROR_ACCESS_DENIED`
* **输出:** `DOMExceptionCode::kNoModificationAllowedError`

**6. 提供将底层平台文件错误 `base::File::Error` 转换为错误消息字符串的函数 `FileErrorToMessage`:**

这个函数接收一个 `base::File::Error` 枚举值作为输入，并返回与之对应的错误消息字符串。

**假设输入与输出:**

* **输入:** `base::File::FILE_ERROR_ABORT`
* **输出:** 指向字符串 `"An ongoing operation was aborted, typically with a call to abort()."` 的指针

* **输入:** `base::File::FILE_ERROR_INVALID_OPERATION`
* **输出:** `nullptr`

**7. 提供 `ThrowDOMException` 函数，用于抛出 `DOMException`:**

该文件提供了两个重载的 `ThrowDOMException` 函数：

* **`ThrowDOMException(ExceptionState& exception_state, FileErrorCode code, String message)`:**  接收一个 `FileErrorCode`、一个可选的消息字符串和一个 `ExceptionState` 对象。它会根据 `FileErrorCode` 创建并抛出一个 `DOMException`。 特别地，对于 `FileErrorCode::kSecurityErr`，它会调用 `exception_state.ThrowSecurityError`。

* **`ThrowDOMException(ExceptionState& exception_state, base::File::Error error, String message)`:** 接收一个 `base::File::Error`、一个可选的消息字符串和一个 `ExceptionState` 对象。它会根据 `base::File::Error` 创建并抛出一个 `DOMException`。 同样，对于 `base::File::FILE_ERROR_SECURITY`，它会调用 `exception_state.ThrowSecurityError`。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接关系到 JavaScript 中与文件操作相关的 API，例如：

* **`FileReader`:** 用于读取文件内容。当 `FileReader` 操作失败时（例如，找不到文件，权限不足），此文件中的代码会将底层的错误转换为 JavaScript 可以捕获的 `DOMException`。

* **`FileWriter` (已被废弃，但概念类似):** 用于向文件写入内容。写入操作失败时，同样会使用这里的错误处理机制。

* **File System API (如 `requestFileSystem`):** 允许 Web 应用访问用户的本地文件系统（在沙箱环境下）。此 API 的各种操作（创建文件、读取目录等）都可能遇到文件系统错误，这些错误会通过此文件转换为 `DOMException`。

* **`<input type="file">` 元素:**  用户通过此元素选择文件后，JavaScript 可以访问 `File` 对象。对 `File` 对象的操作（例如，通过 `FileReader` 读取）可能会触发此文件中的错误处理。

**举例说明:**

**情景 1：使用 `FileReader` 读取不存在的文件**

**假设输入 (在 Blink 内部):**  当 JavaScript 代码尝试使用 `FileReader` 读取一个不存在的文件时，底层的文件系统操作会返回一个 `base::File::FILE_ERROR_NOT_FOUND` 错误。

**逻辑推理和输出:**

1. Blink 的文件读取相关代码捕获到 `base::File::FILE_ERROR_NOT_FOUND`。
2. 调用 `file_error::ThrowDOMException` 并传入 `base::File::FILE_ERROR_NOT_FOUND`。
3. `FileErrorToExceptionCode(base::File::FILE_ERROR_NOT_FOUND)` 返回 `DOMExceptionCode::kNotFoundError`。
4. `FileErrorToMessage(base::File::FILE_ERROR_NOT_FOUND)` 返回 `kNotFoundErrorMessage` (即 `"A requested file or directory could not be found at the time an operation was processed."`)。
5. `ThrowDOMException` 创建一个 `DOMException` 对象，其 `name` 属性为 "NotFoundError"，`message` 属性为上述错误消息。
6. JavaScript 代码中的 `FileReader.onerror` 事件会被触发，并接收到这个 `DOMException` 对象。

**JavaScript 代码示例:**

```javascript
const reader = new FileReader();
reader.onerror = function(event) {
  console.error("文件读取错误:", event.target.error.name, event.target.error.message);
  // 输出: 文件读取错误: NotFounError A requested file or directory could not be found at the time an operation was processed.
};
reader.readAsText(new File([""], "nonexistent.txt"));
```

**情景 2：使用 File System API 尝试创建已存在的文件**

**假设输入 (在 Blink 内部):** JavaScript 使用 File System API 尝试创建一个已经存在的同名文件或目录，底层文件系统操作返回一个表示文件已存在的错误（可能对应于 `base::File::FILE_ERROR_EXISTS`）。

**逻辑推理和输出:**

1. Blink 的 File System API 实现捕获到表示文件已存在的底层错误。
2. 调用 `file_error::ThrowDOMException` 并传入对应的 `base::File::Error` 代码。
3. `FileErrorToExceptionCode` 将其映射到 `DOMExceptionCode::kInvalidModificationError` (目前的代码映射，注释中提到未来可能修改为 `kPathExistsError`)。
4. `FileErrorToMessage` 返回 `kPathExistsErrorMessage` (即 `"An attempt was made to create a file or directory where an element already exists."`)。
5. `ThrowDOMException` 创建一个 `DOMException` 对象，其 `name` 属性为 "InvalidModificationError"，`message` 属性为上述错误消息。
6. JavaScript 中对应的 Promise 或回调函数会接收到这个错误。

**JavaScript 代码示例 (File System API):**

```javascript
navigator.webkitRequestFileSystem(window.TEMPORARY, 5 * 1024 * 1024, function(fs) {
  fs.root.getFile('existing_file.txt', { create: true, exclusive: true }, function(fileEntry) {
    // 文件创建成功
  }, function(fileError) {
    console.error("文件操作错误:", fileError.name, fileError.message);
    // 输出: 文件操作错误: InvalidModificationError An attempt was made to create a file or directory where an element already exists.
  });
}, function(err) {
  console.error("请求文件系统失败", err);
});
```

**用户或编程常见的使用错误举例:**

1. **未正确处理异步操作的错误:**  文件操作通常是异步的。开发者可能在操作完成前就尝试访问结果，或者没有正确地设置 `onerror` 回调或 Promise 的 reject 处理，导致错误被忽略。

   ```javascript
   const reader = new FileReader();
   reader.readAsText(someFile); // 假设 someFile 不存在
   console.log(reader.result); // 错误！在文件读取完成前尝试访问结果，如果发生错误，result 也不会被设置
   ```

2. **假设文件总是存在或可访问:**  开发者可能没有考虑到文件可能被删除、权限被更改等情况，直接进行文件操作，而没有进行必要的错误检查。

   ```javascript
   const reader = new FileReader();
   reader.onload = function() { console.log(reader.result); };
   reader.readAsText(new File(["content"], "my_file.txt")); // 如果 "my_file.txt" 不存在，将会出错，但如果没有 onerror 处理，错误可能被忽略
   ```

3. **忽略存储配额限制:**  在使用 File System API 时，开发者可能会尝试写入超出配额的数据，导致操作失败。

   ```javascript
   navigator.webkitRequestFileSystem(window.TEMPORARY, 1024, function(fs) {
     const writer = fs.root.getFile('large_file.txt', { create: true }, function(fileEntry) {
       fileEntry.createWriter(function(writer) {
         writer.onerror = function(e) { console.error("写入错误:", e.target.error.name); };
         writer.write(new Blob([new ArrayBuffer(2048)])); // 尝试写入超过配额的数据
       });
     });
   });
   ```

4. **滥用或不当使用 `abort()` 方法:**  开发者可能会在不合适的时机调用 `abort()`，导致操作意外中断，并且可能没有正确处理 `AbortError`。

   ```javascript
   const reader = new FileReader();
   reader.onloadstart = function() { reader.abort(); }; // 立即中止读取
   reader.onerror = function(event) {
     if (event.target.error.name === "AbortError") {
       console.log("操作被用户中止。");
     }
   };
   reader.readAsText(someFile);
   ```

总而言之，`file_error.cc` 是 Blink 渲染引擎中处理文件操作错误的关键组件，它确保了 Web 开发者能够以标准化的方式接收和处理文件系统相关的错误，从而构建更健壮的 Web 应用。

### 提示词
```
这是目录为blink/renderer/core/fileapi/file_error.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/fileapi/file_error.h"

#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace file_error {

const char kAbortErrorMessage[] =
    "An ongoing operation was aborted, typically with a call to abort().";
const char kEncodingErrorMessage[] =
    "A URI supplied to the API was malformed, or the resulting Data URL has "
    "exceeded the URL length limitations for Data URLs.";
const char kInvalidStateErrorMessage[] =
    "An operation that depends on state cached in an interface object was made "
    "but the state had changed since it was read from disk.";
const char kNoModificationAllowedErrorMessage[] =
    "An attempt was made to write to a file or directory which could not be "
    "modified due to the state of the underlying filesystem.";
const char kNotFoundErrorMessage[] =
    "A requested file or directory could not be found at the time an operation "
    "was processed.";
const char kNotReadableErrorMessage[] =
    "The requested file could not be read, typically due to permission "
    "problems that have occurred after a reference to a file was acquired.";
const char kPathExistsErrorMessage[] =
    "An attempt was made to create a file or directory where an element "
    "already exists.";
const char kQuotaExceededErrorMessage[] =
    "The operation failed because it would cause the application to exceed its "
    "storage quota.";
const char kSecurityErrorMessage[] =
    "It was determined that certain files are unsafe for access within a Web "
    "application, or that too many calls are being made on file resources.";
const char kSyntaxErrorMessage[] =
    "An invalid or unsupported argument was given, like an invalid line ending "
    "specifier.";
const char kTypeMismatchErrorMessage[] =
    "The path supplied exists, but was not an entry of requested type.";

namespace {

DOMExceptionCode ErrorCodeToExceptionCode(FileErrorCode code) {
  switch (code) {
    case FileErrorCode::kOK:
      return DOMExceptionCode::kNoError;
    case FileErrorCode::kNotFoundErr:
      return DOMExceptionCode::kNotFoundError;
    case FileErrorCode::kSecurityErr:
      return DOMExceptionCode::kSecurityError;
    case FileErrorCode::kAbortErr:
      return DOMExceptionCode::kAbortError;
    case FileErrorCode::kNotReadableErr:
      return DOMExceptionCode::kNotReadableError;
    case FileErrorCode::kEncodingErr:
      return DOMExceptionCode::kEncodingError;
    case FileErrorCode::kNoModificationAllowedErr:
      return DOMExceptionCode::kNoModificationAllowedError;
    case FileErrorCode::kInvalidStateErr:
      return DOMExceptionCode::kInvalidStateError;
    case FileErrorCode::kSyntaxErr:
      return DOMExceptionCode::kSyntaxError;
    case FileErrorCode::kInvalidModificationErr:
      return DOMExceptionCode::kInvalidModificationError;
    case FileErrorCode::kQuotaExceededErr:
      return DOMExceptionCode::kQuotaExceededError;
    case FileErrorCode::kTypeMismatchErr:
      return DOMExceptionCode::kTypeMismatchError;
    case FileErrorCode::kPathExistsErr:
      return DOMExceptionCode::kPathExistsError;
    default:
      NOTREACHED();
  }
}

const char* ErrorCodeToMessage(FileErrorCode code) {
  // Note that some of these do not set message. If message is 0 then the
  // default message is used.
  switch (code) {
    case FileErrorCode::kOK:
      return nullptr;
    case FileErrorCode::kSecurityErr:
      return kSecurityErrorMessage;
    case FileErrorCode::kNotFoundErr:
      return kNotFoundErrorMessage;
    case FileErrorCode::kAbortErr:
      return kAbortErrorMessage;
    case FileErrorCode::kNotReadableErr:
      return kNotReadableErrorMessage;
    case FileErrorCode::kEncodingErr:
      return kEncodingErrorMessage;
    case FileErrorCode::kNoModificationAllowedErr:
      return kNoModificationAllowedErrorMessage;
    case FileErrorCode::kInvalidStateErr:
      return kInvalidStateErrorMessage;
    case FileErrorCode::kSyntaxErr:
      return kSyntaxErrorMessage;
    case FileErrorCode::kInvalidModificationErr:
      return nullptr;
    case FileErrorCode::kQuotaExceededErr:
      return kQuotaExceededErrorMessage;
    case FileErrorCode::kTypeMismatchErr:
      return nullptr;
    case FileErrorCode::kPathExistsErr:
      return kPathExistsErrorMessage;
    default:
      NOTREACHED();
  }
}

DOMExceptionCode FileErrorToExceptionCode(base::File::Error code) {
  switch (code) {
    case base::File::FILE_OK:
      return DOMExceptionCode::kNoError;
    case base::File::FILE_ERROR_FAILED:
      return DOMExceptionCode::kInvalidStateError;
    // TODO(https://crbug.com/883062): base::File::FILE_ERROR_EXISTS should map
    // to kPathExistsError, but that currently breaks tests. Fix the test
    // expectations and make the change.
    case base::File::FILE_ERROR_EXISTS:
    case base::File::FILE_ERROR_NOT_EMPTY:
    case base::File::FILE_ERROR_INVALID_OPERATION:
      return DOMExceptionCode::kInvalidModificationError;
    case base::File::FILE_ERROR_TOO_MANY_OPENED:
    case base::File::FILE_ERROR_NO_MEMORY:
      return DOMExceptionCode::kUnknownError;
    case base::File::FILE_ERROR_NOT_FOUND:
      return DOMExceptionCode::kNotFoundError;
    case base::File::FILE_ERROR_IN_USE:
    case base::File::FILE_ERROR_ACCESS_DENIED:
      return DOMExceptionCode::kNoModificationAllowedError;
    case base::File::FILE_ERROR_NO_SPACE:
      return DOMExceptionCode::kQuotaExceededError;
    case base::File::FILE_ERROR_NOT_A_DIRECTORY:
    case base::File::FILE_ERROR_NOT_A_FILE:
      return DOMExceptionCode::kTypeMismatchError;
    case base::File::FILE_ERROR_ABORT:
      return DOMExceptionCode::kAbortError;
    case base::File::FILE_ERROR_SECURITY:
      return DOMExceptionCode::kSecurityError;
    case base::File::FILE_ERROR_INVALID_URL:
      return DOMExceptionCode::kEncodingError;
    case base::File::FILE_ERROR_IO:
      return DOMExceptionCode::kNotReadableError;
    case base::File::FILE_ERROR_MAX:
      NOTREACHED();
  }
  NOTREACHED();
}

const char* FileErrorToMessage(base::File::Error code) {
  // Note that some of these do not set message. If message is null then the
  // default message is used.
  switch (code) {
    case base::File::FILE_ERROR_NOT_FOUND:
      return kNotFoundErrorMessage;
    case base::File::FILE_ERROR_ACCESS_DENIED:
      return kNoModificationAllowedErrorMessage;
    case base::File::FILE_ERROR_FAILED:
      return kInvalidStateErrorMessage;
    case base::File::FILE_ERROR_ABORT:
      return kAbortErrorMessage;
    case base::File::FILE_ERROR_SECURITY:
      return kSecurityErrorMessage;
    case base::File::FILE_ERROR_NO_SPACE:
      return kQuotaExceededErrorMessage;
    case base::File::FILE_ERROR_INVALID_URL:
      return kEncodingErrorMessage;
    case base::File::FILE_ERROR_IO:
      return kNotReadableErrorMessage;
    case base::File::FILE_ERROR_EXISTS:
      return kPathExistsErrorMessage;
    case base::File::FILE_ERROR_NOT_A_DIRECTORY:
    case base::File::FILE_ERROR_NOT_A_FILE:
      return kTypeMismatchErrorMessage;
    case base::File::FILE_OK:
    case base::File::FILE_ERROR_INVALID_OPERATION:
    case base::File::FILE_ERROR_NOT_EMPTY:
    case base::File::FILE_ERROR_NO_MEMORY:
    case base::File::FILE_ERROR_TOO_MANY_OPENED:
    case base::File::FILE_ERROR_IN_USE:
      // TODO(mek): More specific error messages for at least some of these
      // errors.
      return nullptr;
    case base::File::FILE_ERROR_MAX:
      NOTREACHED();
  }
  NOTREACHED();
}

}  // namespace

void ThrowDOMException(ExceptionState& exception_state,
                       FileErrorCode code,
                       String message) {
  if (code == FileErrorCode::kOK)
    return;

  // SecurityError is special-cased, as we want to route those exceptions
  // through ExceptionState::ThrowSecurityError.
  if (code == FileErrorCode::kSecurityErr) {
    exception_state.ThrowSecurityError(kSecurityErrorMessage);
    return;
  }

  if (message.IsNull()) {
    message = ErrorCodeToMessage(code);
  }

  exception_state.ThrowDOMException(ErrorCodeToExceptionCode(code), message);
}

void ThrowDOMException(ExceptionState& exception_state,
                       base::File::Error error,
                       String message) {
  if (error == base::File::FILE_OK)
    return;

  // SecurityError is special-cased, as we want to route those exceptions
  // through ExceptionState::ThrowSecurityError.
  if (error == base::File::FILE_ERROR_SECURITY) {
    exception_state.ThrowSecurityError(kSecurityErrorMessage);
    return;
  }

  if (message.IsNull()) {
    message = FileErrorToMessage(error);
  }

  exception_state.ThrowDOMException(FileErrorToExceptionCode(error), message);
}

DOMException* CreateDOMException(FileErrorCode code) {
  DCHECK_NE(code, FileErrorCode::kOK);
  return MakeGarbageCollected<DOMException>(ErrorCodeToExceptionCode(code),
                                            ErrorCodeToMessage(code));
}

DOMException* CreateDOMException(base::File::Error code) {
  DCHECK_NE(code, base::File::FILE_OK);
  return MakeGarbageCollected<DOMException>(FileErrorToExceptionCode(code),
                                            FileErrorToMessage(code));
}

}  // namespace file_error

}  // namespace blink
```