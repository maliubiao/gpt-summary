Response:
Let's break down the thought process for analyzing this C++ file and generating the detailed explanation.

1. **Understand the Goal:** The primary goal is to understand the functionality of `file_system_callbacks.cc` within the Blink rendering engine and relate it to web technologies (JavaScript, HTML, CSS).

2. **Initial Scan for Keywords and Structure:**  Quickly read through the code, looking for important keywords and structural elements:
    * **Namespace:** `blink` immediately tells us this is part of the Blink engine.
    * **Includes:**  Look at the included headers. `core/dom/dom_exception.h`, `core/execution_context/execution_context.h`, `core/fileapi/file.h`, `modules/filesystem/...`, and `platform/file_metadata.h` are strong indicators that this code deals with file system operations within a web browser context.
    * **Class Names:**  The class names are very descriptive: `FileSystemCallbacksBase`, `EntryCallbacks`, `EntriesCallbacks`, `FileSystemCallbacks`, `ResolveURICallbacks`, `MetadataCallbacks`, `FileWriterCallbacks`, `SnapshotFileCallback`, `VoidCallbacks`. This suggests the file is organized around different types of asynchronous operations related to the file system.
    * **Callback Functions:**  The repeated use of `SuccessCallback` and `ErrorCallback` points to an asynchronous, event-driven nature.

3. **Identify the Core Functionality:** The class names and the presence of success/error callbacks strongly suggest that this file manages the *callbacks* for asynchronous file system operations. When a web page requests a file system operation (like reading a directory, creating a file, etc.), these callbacks are what gets invoked when the operation completes (successfully or with an error).

4. **Analyze Each Callback Class:** Go through each of the callback classes individually:

    * **`FileSystemCallbacksBase`:** This is clearly the base class, handling common setup like associating with a `DOMFileSystemBase` and managing pending callbacks. The constructor and destructor confirm this role.

    * **`EntryCallbacks`:**  Deals with single file or directory entries. It takes a `success_callback` (receiving an `Entry` object) and an `error_callback`. It differentiates between creating a `FileEntry` and a `DirectoryEntry`. The `DidSucceed` and `DidFail` methods handle the actual callback invocation. *Think: When would you need a single entry?  Getting a specific file or directory by name.*

    * **`EntriesCallbacks`:**  Handles multiple entries (likely for directory listing). It stores a vector of `Entry` objects. `DidReadDirectoryEntry` adds individual entries, and `DidReadDirectoryEntries` delivers the entire list. *Think: This is for `readEntries()` on a `DirectoryReader`.*

    * **`FileSystemCallbacks`:** Used when initially opening or requesting access to a file system. It returns a `DOMFileSystem` object on success. *Think:  `requestFileSystem()` in JavaScript.*

    * **`ResolveURICallbacks`:**  Handles resolving a URI to a file system entry. It reconstructs the `DOMFileSystem` and then locates the specific `Entry` within that file system. *Think:  `resolveLocalFileSystemURL()` in older File API versions.*

    * **`MetadataCallbacks`:** Fetches metadata (size, modification time, etc.) for a file or directory. It receives a `FileMetadata` object and wraps it in a `Metadata` object. *Think: `getMetadata()` on an `Entry`.*

    * **`FileWriterCallbacks`:**  Manages callbacks for `FileWriter` operations. It's used when creating a `FileWriter` object, providing the URL and initial length. *Think: Creating a `FileWriter` object to write to a file.*

    * **`SnapshotFileCallback`:**  Specifically used when creating a "snapshot" of a file, likely for creating `File` objects that represent the current state of a file in the file system. *Think:  The `file()` method on a `FileEntry`.*

    * **`VoidCallbacks`:**  A simple callback for operations that don't return any specific data upon success (e.g., deleting a file or directory). *Think: `remove()` or `removeRecursively()` on an `Entry`.*

5. **Relate to JavaScript, HTML, and CSS:**  Now, connect the C++ code to the web technologies users interact with:

    * **JavaScript:** The File API in JavaScript is the primary interface that triggers these callbacks. List the key JavaScript methods and interfaces that correspond to each callback class (as done in the example answer).
    * **HTML:**  Mention how HTML can initiate file system operations (e.g., `<input type="file">` or drag-and-drop).
    * **CSS:**  CSS doesn't directly interact with the file system API in the same way as JavaScript or HTML. Acknowledge this.

6. **Logical Reasoning (Input/Output):**  For each callback type, think about the *input* that would lead to that callback being used and the *output* that the callback provides:

    * **Example (EntryCallbacks):**
        * **Input:**  A JavaScript call to `getDirectory()` or `getFile()`.
        * **Output (Success):** A `DirectoryEntry` or `FileEntry` object in JavaScript.
        * **Output (Failure):** A `FileError` object in JavaScript.

7. **Common Usage Errors:** Consider the mistakes developers might make when using the File API that could lead to these error callbacks being triggered:

    * Incorrect paths.
    * Permissions issues.
    * Trying to access non-existent files/directories.
    * Quota exceeded errors.

8. **User Actions and Debugging:**  Trace back how a user action in the browser can lead to this code being executed. For example:

    * User selects a file using `<input type="file">`.
    * JavaScript uses the File API to request access to the file system.
    * The browser (Blink) translates this request into internal operations involving these callbacks.

    For debugging, highlight the key information that would be useful: error messages, file paths, the type of operation being attempted.

9. **Structure and Refine:** Organize the information logically, using clear headings and bullet points. Ensure the language is accessible to someone with a general understanding of web development concepts. Review and refine the explanation for clarity and accuracy. Add a concluding summary.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just handles errors."  **Correction:** Realize it handles both success and error scenarios via separate callbacks.
* **Considering the `FileWriterCallbacks`:** Initially, I might have thought it was directly for writing data. **Correction:**  Realize it's for the *creation* of the `FileWriter` object itself. The actual writing happens through methods on the `FileWriter` object.
* **Overlooking CSS:**  Initially, I might have forgotten to mention CSS. **Correction:**  Briefly acknowledge that CSS doesn't have direct involvement.

By following these steps, we can arrive at a comprehensive and accurate explanation of the `file_system_callbacks.cc` file. The key is to move from the code itself to the broader context of how it fits into the web browser and the web development process.

好的，让我们来分析一下 `blink/renderer/modules/filesystem/file_system_callbacks.cc` 这个文件。

**文件功能概要**

`file_system_callbacks.cc` 文件在 Chromium Blink 引擎中扮演着关键角色，它定义了一系列回调类，用于处理与文件系统操作相关的异步结果。  当 Blink 内部执行文件系统操作（例如读取目录、创建文件、获取文件元数据等）时，这些操作通常是异步的，意味着它们不会立即完成。  这些回调类提供了一种机制，当异步操作成功或失败时，通知调用者并传递相应的结果或错误信息。

**各个回调类的功能细述**

这个文件定义了多个继承自 `FileSystemCallbacksBase` 的回调类，每个类负责处理特定类型的文件系统操作的完成：

* **`FileSystemCallbacksBase`:** 这是一个基类，提供了一些通用的功能，例如持有对 `DOMFileSystemBase` 对象和 `ExecutionContext` 对象的引用，以及管理待处理的回调计数。

* **`EntryCallbacks`:**  用于处理返回单个文件或目录条目的操作。
    * **成功时:** 调用 `success_callback_`，传入一个 `Entry` 对象，该对象可能是 `DirectoryEntry` 或 `FileEntry`，具体取决于操作的目标是目录还是文件。
    * **失败时:** 调用 `error_callback_`，传入一个 `base::File::Error` 类型的错误码。

* **`EntriesCallbacks`:** 用于处理读取目录内容的操作，返回一组文件和目录条目。
    * **`DidReadDirectoryEntry`:** 当读取到一个目录条目时被调用，将新的 `Entry` (可能是 `DirectoryEntry` 或 `FileEntry`) 添加到内部的 `entries_` 列表中。
    * **`DidReadDirectoryEntries`:** 当读取完一批目录条目后被调用，将所有读取到的 `Entry` 对象组成的列表通过 `success_callback_` 返回。
    * **失败时:** 调用 `error_callback_`，传入一个 `base::File::Error` 类型的错误码。

* **`FileSystemCallbacks`:** 用于处理打开或请求文件系统访问的操作。
    * **成功时:** 调用 `success_callback_`，传入一个 `DOMFileSystem` 对象，代表成功获取的文件系统。
    * **失败时:** 调用 `error_callback_`，传入一个 `base::File::Error` 类型的错误码。

* **`ResolveURICallbacks`:** 用于处理将文件系统 URI 解析为 `Entry` 对象的操作。
    * **成功时:** 调用 `success_callback_`，传入解析后的 `Entry` 对象 (可能是 `DirectoryEntry` 或 `FileEntry`)。
    * **失败时:** 调用 `error_callback_`，传入一个 `base::File::Error` 类型的错误码。

* **`MetadataCallbacks`:** 用于处理获取文件或目录元数据的操作。
    * **成功时:** 调用 `success_callback_`，传入一个 `Metadata` 对象，其中包含了文件的元数据信息。
    * **失败时:** 调用 `error_callback_`，传入一个 `base::File::Error` 类型的错误码。

* **`FileWriterCallbacks`:** 用于处理创建 `FileWriter` 对象的操作。
    * **`DidCreateFileWriter`:** 当成功创建 `FileWriter` 对象后被调用，初始化 `FileWriterBase` 并通过 `success_callback_` 返回。
    * **失败时:** 调用 `error_callback_`，传入一个 `base::File::Error` 类型的错误码。

* **`SnapshotFileCallback`:** 用于处理创建文件快照的操作，通常用于获取 `File` 对象。
    * **`DidCreateSnapshotFile`:** 当成功创建快照文件后被调用，创建一个 `File` 对象并通过 `success_callback_` 返回。
    * **失败时:** 调用 `error_callback_`，传入一个 `base::File::Error` 类型的错误码。

* **`VoidCallbacks`:**  用于处理不需要返回特定结果的操作，例如删除文件或目录。
    * **成功时:** 调用 `success_callback_`，不传递任何参数，表示操作成功。
    * **失败时:** 调用 `error_callback_`，传入一个 `base::File::Error` 类型的错误码。

**与 JavaScript, HTML, CSS 的关系**

这个文件中的代码直接支持了 Web 应用程序中使用的 File API。JavaScript 代码可以通过 File API 来执行文件系统操作，而这些 C++ 回调类则负责处理这些操作的结果，并将结果传递回 JavaScript。

以下是一些具体的例子：

* **JavaScript 的 `requestFileSystem()` 方法:** 当 JavaScript 调用 `navigator.webkitRequestFileSystem()` 或 `navigator.requestFileSystem()` 请求访问文件系统时，Blink 内部会创建一个 `FileSystemCallbacks` 对象。如果请求成功，`FileSystemCallbacks::DidOpenFileSystem` 会被调用，并将 `DOMFileSystem` 对象传递给 JavaScript 的成功回调函数。

   ```javascript
   navigator.webkitRequestFileSystem(
       window.TEMPORARY,
       1024 * 1024,
       function(fs) {
           console.log('Opened file system: ' + fs.name);
       },
       function(err) {
           console.error('Error requesting file system:', err);
       }
   );
   ```

* **JavaScript 的 `DirectoryReader` 接口:** 当 JavaScript 使用 `createReader()` 方法创建一个 `DirectoryReader` 对象，并调用其 `readEntries()` 方法来读取目录内容时，Blink 内部会创建 `EntriesCallbacks` 对象。`EntriesCallbacks::DidReadDirectoryEntry` 会在每次读取到一个条目时被调用，最终 `EntriesCallbacks::DidReadDirectoryEntries` 会将所有条目传递回 JavaScript 的成功回调函数。

   ```javascript
   directoryEntry.createReader().readEntries(
       function(entries) {
           entries.forEach(function(entry) {
               console.log(entry.name);
           });
       },
       function(err) {
           console.error('Error reading directory:', err);
       }
   );
   ```

* **JavaScript 的 `FileEntry` 和 `DirectoryEntry` 接口的方法 (例如 `getMetadata()`, `file()`, `createWriter()`, `remove()`, `removeRecursively()`):**  这些方法在 Blink 内部会创建相应的回调对象 (`MetadataCallbacks`, `SnapshotFileCallback`, `FileWriterCallbacks`, `VoidCallbacks`) 来处理操作的结果。

* **JavaScript 的 `resolveLocalFileSystemURL()` 方法 (已废弃，但概念类似 `webkitResolveLocalFileSystemURL()`):**  这个方法尝试将一个文件系统 URL 解析为一个 `Entry` 对象。Blink 内部会使用 `ResolveURICallbacks` 来处理解析结果。

**HTML 和 CSS 的关系:**

HTML 和 CSS 本身不直接触发这个文件中的代码。然而，用户在 HTML 页面上的操作（例如，通过 `<input type="file">` 元素选择文件，或者通过拖放 API 拖放文件到页面）可能会导致 JavaScript 代码调用 File API，从而间接地触发这里定义的回调。

**逻辑推理、假设输入与输出**

让我们以 `EntryCallbacks` 为例进行逻辑推理：

**假设输入:**

1. JavaScript 代码调用 `directoryEntry.getFile('myfile.txt', {}, successCallback, errorCallback)`。
2. Blink 内部尝试在 `directoryEntry` 代表的目录下查找名为 `myfile.txt` 的文件。

**可能的输出:**

* **成功 (文件存在):**
    *   Blink 找到文件，创建一个 `FileEntry` 对象。
    *   `EntryCallbacks::DidSucceed()` 被调用。
    *   `successCallback` 在 JavaScript 中被执行，传入一个代表 `myfile.txt` 的 `FileEntry` 对象。
* **失败 (文件不存在):**
    *   Blink 找不到文件。
    *   `EntryCallbacks::DidFail(base::File::FILE_ERROR_NOT_FOUND)` 被调用。
    *   `errorCallback` 在 JavaScript 中被执行，传入一个 `FileError` 对象，其 `code` 属性可能为 `FileError.NOT_FOUND_ERR`。

**用户或编程常见的使用错误**

* **路径错误:** JavaScript 代码中提供的文件或目录路径不正确，例如拼写错误或者路径不存在。这会导致相应的 `DidFail` 回调被调用，错误码可能是 `FILE_ERROR_NOT_FOUND`。

   ```javascript
   // 假设目录 "mydir" 不存在
   fs.root.getDirectory('mydir/myfile.txt', {}, successCallback, errorCallback);
   // errorCallback 会被调用，错误信息表明目录不存在
   ```

* **权限错误:**  Web 应用程序可能没有足够的权限访问请求的文件或目录。这会导致 `DidFail` 回调被调用，错误码可能是 `FILE_ERROR_SECURITY` 或 `FILE_ERROR_NO_MODIFICATION_ALLOWED`.

   ```javascript
   // 尝试修改只读文件系统上的文件
   fileEntry.createWriter(function(fileWriter) {
       fileWriter.write(new Blob(['some data']));
       fileWriter.onerror = function(e) {
           console.error('Write failed: ' + e.toString());
       };
   });
   ```

* **超出配额:**  Web 应用程序尝试使用的文件系统空间超过了分配的配额。这会导致 `DidFail` 回调被调用，错误码可能是 `FILE_ERROR_QUOTA_EXCEEDED`.

   ```javascript
   // 尝试写入大量数据到文件，超出配额
   fileWriter.seek(fileWriter.length);
   fileWriter.write(largeBlob);
   fileWriter.onerror = function(e) {
       console.error('Write failed: ' + e.toString()); // 错误信息可能包含 QUOTA_EXCEEDED_ERR
   };
   ```

* **操作非法状态的对象:**  例如，在一个已经被删除的 `Entry` 对象上调用方法。这可能会导致程序崩溃或抛出异常，但也可能在某些异步操作中，回调会返回一个表示操作无效的错误。

**用户操作如何一步步到达这里 (调试线索)**

以下是一个用户操作导致 `EntryCallbacks` 被调用的例子以及调试线索：

1. **用户操作:** 用户在网页上点击了一个按钮，该按钮触发了一个 JavaScript 函数，该函数使用 File API 来获取一个文件对象。

2. **JavaScript 代码:**

    ```javascript
    function getMyFile() {
        navigator.webkitRequestFileSystem(window.TEMPORARY, 5 * 1024 * 1024, function(fs) {
            fs.root.getFile('my_document.txt', {}, function(fileEntry) {
                console.log('Got the file entry:', fileEntry.name);
            }, function(fileError) {
                console.error('Error getting file:', fileError);
            });
        }, function(fileError) {
            console.error('Error requesting file system:', fileError);
        });
    }
    ```

3. **Blink 引擎处理:**
    *   当 `fs.root.getFile()` 被调用时，Blink 内部会创建一个 `EntryCallbacks` 对象。
    *   Blink 会尝试在文件系统中查找名为 `my_document.txt` 的文件。

4. **调试线索:**

    *   **JavaScript 断点:** 在 JavaScript 的 `successCallback` 和 `errorCallback` 函数中设置断点，查看是否进入了回调，以及传入的参数（`fileEntry` 或 `fileError`）。
    *   **Blink 调试日志:**  Blink 引擎可能会输出与文件系统操作相关的调试信息。查找包含 "FileSystem" 或相关关键词的日志。
    *   **C++ 断点:** 如果你需要深入了解 Blink 内部的执行流程，可以在 `blink/renderer/modules/filesystem/file_system_callbacks.cc` 中 `EntryCallbacks::DidSucceed()` 和 `EntryCallbacks::DidFail()` 方法中设置断点。
    *   **检查文件系统状态:** 确认预期的文件是否存在于文件系统中（这通常是模拟的文件系统，具体取决于浏览器和配置）。
    *   **检查错误码:** 如果 `errorCallback` 被调用，检查 `FileError` 对象的 `code` 属性，它可以提供关于错误的具体信息 (例如 `FileError.NOT_FOUND_ERR`, `FileError.SECURITY_ERR` 等)。

总而言之，`file_system_callbacks.cc` 是 Blink 引擎中处理异步文件系统操作结果的关键组件，它连接了 JavaScript File API 的调用和底层的 C++ 文件系统实现。 理解这个文件及其中的回调类对于调试与文件系统相关的 Web 应用程序问题至关重要。

### 提示词
```
这是目录为blink/renderer/modules/filesystem/file_system_callbacks.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/modules/filesystem/file_system_callbacks.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/fileapi/file_error.h"
#include "third_party/blink/renderer/modules/filesystem/directory_entry.h"
#include "third_party/blink/renderer/modules/filesystem/directory_reader.h"
#include "third_party/blink/renderer/modules/filesystem/dom_file_path.h"
#include "third_party/blink/renderer/modules/filesystem/dom_file_system.h"
#include "third_party/blink/renderer/modules/filesystem/dom_file_system_base.h"
#include "third_party/blink/renderer/modules/filesystem/entry.h"
#include "third_party/blink/renderer/modules/filesystem/file_entry.h"
#include "third_party/blink/renderer/modules/filesystem/file_writer.h"
#include "third_party/blink/renderer/modules/filesystem/metadata.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

FileSystemCallbacksBase::FileSystemCallbacksBase(DOMFileSystemBase* file_system,
                                                 ExecutionContext* context)
    : file_system_(file_system), execution_context_(context) {
  DCHECK(execution_context_);

  if (file_system_)
    file_system_->AddPendingCallbacks();
}

FileSystemCallbacksBase::~FileSystemCallbacksBase() {
  if (file_system_)
    file_system_->RemovePendingCallbacks();
}

// EntryCallbacks -------------------------------------------------------------

EntryCallbacks::EntryCallbacks(SuccessCallback success_callback,
                               ErrorCallback error_callback,
                               ExecutionContext* context,
                               DOMFileSystemBase* file_system,
                               const String& expected_path,
                               bool is_directory)
    : FileSystemCallbacksBase(file_system, context),
      success_callback_(std::move(success_callback)),
      error_callback_(std::move(error_callback)),
      expected_path_(expected_path),
      is_directory_(is_directory) {}

void EntryCallbacks::DidSucceed() {
  if (!success_callback_)
    return;

  Entry* entry = is_directory_
                     ? static_cast<Entry*>(MakeGarbageCollected<DirectoryEntry>(
                           file_system_, expected_path_))
                     : static_cast<Entry*>(MakeGarbageCollected<FileEntry>(
                           file_system_, expected_path_));

  std::move(success_callback_).Run(entry);
}

void EntryCallbacks::DidFail(base::File::Error error) {
  if (!error_callback_)
    return;

  std::move(error_callback_).Run(error);
}

// EntriesCallbacks -----------------------------------------------------------

EntriesCallbacks::EntriesCallbacks(const SuccessCallback& success_callback,
                                   ErrorCallback error_callback,
                                   ExecutionContext* context,
                                   DirectoryReaderBase* directory_reader,
                                   const String& base_path)
    : FileSystemCallbacksBase(directory_reader->Filesystem(), context),
      success_callback_(success_callback),
      error_callback_(std::move(error_callback)),
      directory_reader_(directory_reader),
      base_path_(base_path),
      entries_(MakeGarbageCollected<HeapVector<Member<Entry>>>()) {
  DCHECK(directory_reader_);
}

void EntriesCallbacks::DidReadDirectoryEntry(const String& name,
                                             bool is_directory) {
  DOMFileSystemBase* filesystem = directory_reader_->Filesystem();
  const String& path = DOMFilePath::Append(base_path_, name);
  Entry* entry = is_directory
                     ? static_cast<Entry*>(MakeGarbageCollected<DirectoryEntry>(
                           filesystem, path))
                     : static_cast<Entry*>(
                           MakeGarbageCollected<FileEntry>(filesystem, path));
  entries_->push_back(entry);
}

void EntriesCallbacks::DidReadDirectoryEntries(bool has_more) {
  directory_reader_->SetHasMoreEntries(has_more);
  EntryHeapVector* entries =
      MakeGarbageCollected<EntryHeapVector>(std::move(*entries_));

  if (!success_callback_) {
    return;
  }

  success_callback_.Run(entries);
}

void EntriesCallbacks::DidFail(base::File::Error error) {
  if (!error_callback_) {
    return;
  }

  std::move(error_callback_).Run(error);
}

// FileSystemCallbacks --------------------------------------------------------

FileSystemCallbacks::FileSystemCallbacks(SuccessCallback success_callback,
                                         ErrorCallback error_callback,
                                         ExecutionContext* context,
                                         mojom::blink::FileSystemType type)
    : FileSystemCallbacksBase(
          /*file_system=*/nullptr,
          context),
      success_callback_(std::move(success_callback)),
      error_callback_(std::move(error_callback)),
      type_(type) {}

void FileSystemCallbacks::DidOpenFileSystem(const String& name,
                                            const KURL& root_url) {
  if (!success_callback_)
    return;

  auto* filesystem = MakeGarbageCollected<DOMFileSystem>(
      execution_context_.Get(), name, type_, root_url);
  std::move(success_callback_).Run(filesystem);
}

void FileSystemCallbacks::DidFail(base::File::Error error) {
  if (!error_callback_)
    return;

  std::move(error_callback_).Run(error);
}

// ResolveURICallbacks --------------------------------------------------------

ResolveURICallbacks::ResolveURICallbacks(SuccessCallback success_callback,
                                         ErrorCallback error_callback,
                                         ExecutionContext* context)
    : FileSystemCallbacksBase(
          /*file_system=*/nullptr,
          context),
      success_callback_(std::move(success_callback)),
      error_callback_(std::move(error_callback)) {
  DCHECK(success_callback_);
}

void ResolveURICallbacks::DidResolveURL(const String& name,
                                        const KURL& root_url,
                                        mojom::blink::FileSystemType type,
                                        const String& file_path,
                                        bool is_directory) {
  auto* filesystem = MakeGarbageCollected<DOMFileSystem>(
      execution_context_.Get(), name, type, root_url);
  DirectoryEntry* root = filesystem->root();

  String absolute_path;
  if (!DOMFileSystemBase::PathToAbsolutePath(type, root, file_path,
                                             absolute_path)) {
    DidFail(base::File::FILE_ERROR_INVALID_OPERATION);
    return;
  }

  Entry* entry = is_directory
                     ? static_cast<Entry*>(MakeGarbageCollected<DirectoryEntry>(
                           filesystem, absolute_path))
                     : static_cast<Entry*>(MakeGarbageCollected<FileEntry>(
                           filesystem, absolute_path));

  std::move(success_callback_).Run(entry);
}

void ResolveURICallbacks::DidFail(base::File::Error error) {
  if (!error_callback_)
    return;

  std::move(error_callback_).Run(error);
}

// MetadataCallbacks ----------------------------------------------------------

MetadataCallbacks::MetadataCallbacks(SuccessCallback success_callback,
                                     ErrorCallback error_callback,
                                     ExecutionContext* context,
                                     DOMFileSystemBase* file_system)
    : FileSystemCallbacksBase(file_system, context),
      success_callback_(std::move(success_callback)),
      error_callback_(std::move(error_callback)) {}

void MetadataCallbacks::DidReadMetadata(const FileMetadata& metadata) {
  if (!success_callback_)
    return;

  std::move(success_callback_).Run(MakeGarbageCollected<Metadata>(metadata));
}

void MetadataCallbacks::DidFail(base::File::Error error) {
  if (!error_callback_)
    return;

  std::move(error_callback_).Run(error);
}

// FileWriterCallbacks ----------------------------------------------------

FileWriterCallbacks::FileWriterCallbacks(FileWriterBase* file_writer,
                                         SuccessCallback success_callback,
                                         ErrorCallback error_callback,
                                         ExecutionContext* context)
    : FileSystemCallbacksBase(
          /*file_system =*/nullptr,
          context),
      file_writer_(file_writer),
      success_callback_(std::move(success_callback)),
      error_callback_(std::move(error_callback)) {}

void FileWriterCallbacks::DidCreateFileWriter(const KURL& path,
                                              int64_t length) {
  if (!success_callback_)
    return;

  file_writer_->Initialize(path, length);
  std::move(success_callback_).Run(file_writer_);
}

void FileWriterCallbacks::DidFail(base::File::Error error) {
  if (!error_callback_)
    return;

  std::move(error_callback_).Run(error);
}

// SnapshotFileCallback -------------------------------------------------------

SnapshotFileCallback::SnapshotFileCallback(DOMFileSystemBase* filesystem,
                                           const String& name,
                                           const KURL& url,
                                           SuccessCallback success_callback,
                                           ErrorCallback error_callback,
                                           ExecutionContext* context)
    : FileSystemCallbacksBase(filesystem, context),
      name_(name),
      url_(url),
      success_callback_(std::move(success_callback)),
      error_callback_(std::move(error_callback)) {}

void SnapshotFileCallback::DidCreateSnapshotFile(const FileMetadata& metadata) {
  if (!success_callback_)
    return;

  std::move(success_callback_)
      .Run(DOMFileSystemBase::CreateFile(execution_context_, metadata, url_,
                                         file_system_->GetType(), name_));
}

void SnapshotFileCallback::DidFail(base::File::Error error) {
  if (!error_callback_)
    return;

  std::move(error_callback_).Run(error);
}

// VoidCallbacks --------------------------------------------------------------

VoidCallbacks::VoidCallbacks(SuccessCallback success_callback,
                             ErrorCallback error_callback,
                             ExecutionContext* context,
                             DOMFileSystemBase* file_system)
    : FileSystemCallbacksBase(file_system, context),
      success_callback_(std::move(success_callback)),
      error_callback_(std::move(error_callback)) {}

void VoidCallbacks::DidSucceed() {
  if (!success_callback_)
    return;

  std::move(success_callback_).Run();
}

void VoidCallbacks::DidFail(base::File::Error error) {
  if (!error_callback_)
    return;

  std::move(error_callback_).Run(error);
}

}  // namespace blink
```