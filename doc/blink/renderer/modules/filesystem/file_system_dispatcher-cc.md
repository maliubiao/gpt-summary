Response:
Let's break down the thought process for analyzing the `FileSystemDispatcher.cc` file.

**1. Initial Skim and Identification of Core Purpose:**

The first step is to quickly read through the code, paying attention to class names, key function names, included headers, and any comments. Keywords like "FileSystem," "Dispatcher," "Open," "Read," "Write," "Move," "Copy," "Remove," "Truncate," "Blob," and "Callbacks" immediately jump out. The `#include` statements tell us it interacts with Mojo, base::File, and other Blink-specific types. The `// Copyright` indicates it's a Chromium file dealing with file system operations.

From this initial skim, the core purpose becomes clear: **This class acts as an intermediary to handle file system operations initiated by the renderer process (Blink) and delegate them to the browser process.**  It manages asynchronous operations using callbacks and Mojo interfaces.

**2. Deeper Dive into Functionality:**

Next, examine the public methods of the `FileSystemDispatcher` class. These methods directly expose the capabilities of the class. Group similar functions together (e.g., synchronous and asynchronous versions of the same operation).

* **Opening File Systems:** `OpenFileSystem`, `OpenFileSystemSync`. This suggests the ability to access different types of file systems.
* **Resolving URLs:** `ResolveURL`, `ResolveURLSync`. Indicates converting file system URLs to internal representations.
* **File/Directory Manipulation:** `Move`, `MoveSync`, `Copy`, `CopySync`, `Remove`, `RemoveSync`, `CreateFile`, `CreateFileSync`, `CreateDirectory`, `CreateDirectorySync`, `Exists`, `ExistsSync`. These are standard file system operations.
* **Reading Content:** `ReadDirectory`, `ReadDirectorySync`, `ReadMetadata`, `ReadMetadataSync`. Capabilities to retrieve directory listings and file metadata.
* **Writing Content:** `InitializeFileWriter`, `InitializeFileWriterSync`, `Truncate`, `TruncateSync`, `Write`, `WriteSync`. Methods for modifying file content.
* **Canceling Operations:** `Cancel`. Mechanism to stop in-progress asynchronous operations.
* **Snapshotting:** `CreateSnapshotFile`, `CreateSnapshotFileSync`. Likely related to creating immutable copies of files.

**3. Identifying Relationships with Web Technologies (JavaScript, HTML, CSS):**

Now, consider how these functionalities connect to web technologies. Think about the scenarios where web pages might need to interact with the file system.

* **JavaScript:**  The File System Access API (or older APIs like `requestFileSystem`) allows JavaScript code to interact with the user's local file system (with permissions). The methods in `FileSystemDispatcher` directly map to the underlying implementations needed for these APIs.
* **HTML:**  The `<input type="file">` element allows users to select local files. While not directly invoking `FileSystemDispatcher`, the subsequent processing of these files (reading contents, getting metadata) would likely involve this class. Drag-and-drop of files onto a webpage is another relevant scenario.
* **CSS:**  Direct connections to CSS are less common. However, if a CSS feature required accessing local files (which is generally restricted for security reasons), `FileSystemDispatcher` could be involved. *Initial thought:  Maybe related to custom fonts loaded from local files?  Correction: Custom fonts are usually handled differently, but conceptually, accessing local resources could involve a similar mechanism.*

**4. Logical Reasoning (Input/Output):**

For each function, consider a basic input and the expected output. This helps solidify understanding.

* **`OpenFileSystem`:**
    * Input: `SecurityOrigin` of the requesting page, `FileSystemType` (e.g., temporary, persistent).
    * Output:  Success (returns the file system's name and root URL) or failure (error code).
* **`Write`:**
    * Input: File `KURL`, `Blob` of data, `offset`.
    * Output: Success (number of bytes written, completion status) or failure (error code).

**5. Common User/Programming Errors:**

Think about how developers might misuse these APIs or encounter errors.

* **Permissions:**  Trying to access files or directories the user hasn't granted permission for.
* **File Not Found:**  Attempting to operate on a non-existent file or directory.
* **Invalid Paths:** Providing incorrect or malformed file system URLs.
* **Security Restrictions:**  Cross-origin access attempts without proper permissions.
* **Concurrency Issues:**  Multiple attempts to modify the same file concurrently without proper synchronization (though `FileSystemDispatcher` handles some of this through its asynchronous nature).

**6. Debugging Scenario (User Steps to Reach the Code):**

Trace a potential user action that would lead to `FileSystemDispatcher` being invoked.

1. User visits a website.
2. The website uses JavaScript code that leverages the File System Access API (e.g., `window.showOpenFilePicker()`).
3. The user grants permission to access a specific directory.
4. The JavaScript code then calls a method to read a file in that directory (e.g., `fileHandle.getFile()`, then reading the `File` object).
5. This JavaScript call triggers a request that goes through Blink's rendering engine.
6. The `FileSystemDispatcher` in the renderer process intercepts this request.
7. `FileSystemDispatcher` serializes the request and sends it via Mojo to the browser process's file system service.
8. The browser process performs the actual file system operation.
9. The result is sent back via Mojo to the `FileSystemDispatcher`.
10. `FileSystemDispatcher` invokes the appropriate JavaScript callback with the results.

**7. Review and Refine:**

Finally, review the generated analysis. Ensure it's clear, concise, and addresses all aspects of the prompt. Double-check for accuracy and completeness. For example, ensure the explanations of JavaScript API connections are accurate and specific. Also, confirm that the input/output examples make sense in the context of file system operations.

This systematic approach ensures that all relevant information is extracted from the code and presented in a structured and understandable way. It combines code reading with knowledge of web technologies and common development practices.
好的，让我们来分析一下 `blink/renderer/modules/filesystem/file_system_dispatcher.cc` 这个 Chromium Blink 引擎的源代码文件。

**功能概要:**

`FileSystemDispatcher` 的主要功能是作为 **渲染进程 (Renderer Process)** 中处理文件系统操作的 **调度器 (Dispatcher)**。 它充当了 JavaScript 或其他 Blink 模块发起的文件系统请求与浏览器进程中实际执行文件系统操作的服务之间的桥梁。

更具体地说，它的职责包括：

1. **管理与浏览器进程中 `FileSystemManager` 的连接:** 它使用 Mojo 接口与浏览器进程中的 `FileSystemManager` 通信，`FileSystemManager` 负责实际的文件系统操作。
2. **处理各种文件系统操作请求:**  它接收来自 Blink 内部或其他模块的文件系统操作请求，例如：
    * 打开文件系统 (`OpenFileSystem`)
    * 解析文件系统 URL (`ResolveURL`)
    * 移动、复制、删除文件或目录 (`Move`, `Copy`, `Remove`)
    * 读取文件或目录的元数据 (`ReadMetadata`)
    * 创建文件或目录 (`CreateFile`, `CreateDirectory`)
    * 检查文件或目录是否存在 (`Exists`)
    * 读取目录内容 (`ReadDirectory`)
    * 初始化文件写入器 (`InitializeFileWriter`)
    * 截断文件 (`Truncate`)
    * 写入文件 (`Write`)
    * 创建文件快照 (`CreateSnapshotFile`)
    * 取消进行中的操作 (`Cancel`)
3. **异步操作管理:** 大部分文件系统操作都是异步的。 `FileSystemDispatcher` 管理这些异步操作，使用回调函数来处理操作的成功或失败。
4. **同步操作支持:**  也支持部分同步的文件系统操作。
5. **错误处理:**  它处理从浏览器进程返回的错误，并将这些错误传递回调用方。
6. **生命周期管理:** 作为 `ExecutionContext` 的补充 (Supplement)，它的生命周期与关联的上下文一致。
7. **线程管理:** 它确保某些操作在正确的线程上执行。

**与 JavaScript, HTML, CSS 的关系：**

`FileSystemDispatcher` 是连接 Web 技术（如 JavaScript）与底层文件系统操作的关键组件。

* **JavaScript:**
    * **File System Access API:** 这是与 `FileSystemDispatcher` 关系最密切的 JavaScript API。当 JavaScript 代码使用 `window.showOpenFilePicker()`, `window.showSaveFilePicker()`, `navigator.storage.getDirectory()` 等 API 时，最终会调用到 `FileSystemDispatcher` 的相应方法。
    * **例如：**
        ```javascript
        async function openFile() {
          const [fileHandle] = await window.showOpenFilePicker();
          const file = await fileHandle.getFile();
          const contents = await file.text();
          console.log(contents);
        }
        ```
        在这个例子中，`window.showOpenFilePicker()` 的执行最终会导致浏览器进程显示文件选择对话框。当用户选择文件后，浏览器进程会将文件句柄信息传递回渲染进程。如果后续 JavaScript 代码尝试读取文件内容（如 `file.text()`），则 `FileSystemDispatcher` 会被调用，向浏览器进程请求读取文件，并将读取到的内容返回给 JavaScript。
    * **Older File API (e.g., `requestFileSystem`):** 尽管 File System Access API 是推荐的方式，但旧的 File API (如 `window.requestFileSystem`) 也会通过 `FileSystemDispatcher` 与底层文件系统交互。
    * **Blob API:** 在 `FileSystemDispatcher::Write` 方法中可以看到与 `Blob` 对象的交互。当 JavaScript 使用 `FileWriter` 或类似机制向文件写入数据时，数据通常以 `Blob` 的形式传递，`FileSystemDispatcher` 会将 `Blob` 数据传递给浏览器进程进行写入。

* **HTML:**
    * **`<input type="file">`:**  当用户通过 `<input type="file">` 元素选择文件时，虽然 `FileSystemDispatcher` 不会直接参与文件选择过程，但当 JavaScript 代码需要访问所选文件的内容或元数据时，例如读取文件大小、最后修改时间等，或者需要将文件保存到文件系统（如果使用了 File System Access API），则会调用 `FileSystemDispatcher` 的方法。
    * **Drag and Drop:**  当用户将文件拖放到网页上时，相关的 JavaScript 事件处理程序可能会调用与文件系统相关的 API，从而间接触发 `FileSystemDispatcher` 的工作。

* **CSS:**
    * **通常没有直接关系。** CSS 主要负责样式和布局，不涉及直接的文件系统操作。
    * **理论上，如果 CSS 的某些功能需要访问本地文件（这在浏览器安全模型中通常是被限制的），`FileSystemDispatcher` 可能会参与，但这非常罕见。** 例如，加载本地字体文件虽然涉及到文件系统，但通常有专门的机制处理，不一定会直接通过 `FileSystemDispatcher`。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码调用了 `navigator.storage.getDirectory()` 来获取一个持久存储的目录句柄：

**假设输入:**

* **JavaScript 调用:** `navigator.storage.getDirectory()`
* **内部参数 (可能):**  Origin of the web page, desired directory name (optional)

**逻辑推理过程 (在 `FileSystemDispatcher` 中):**

1. JavaScript 的调用会触发 Blink 内部的相应处理逻辑。
2. 这会调用到 `FileSystemDispatcher::OpenFileSystem` (或者一个类似的用于获取特定类型文件系统入口的方法)。
3. `FileSystemDispatcher` 通过 Mojo 向浏览器进程的 `FileSystemManager` 发送一个打开文件系统的请求，包含 Origin 和请求的存储类型（持久存储）。
4. 浏览器进程的 `FileSystemManager` 执行实际的文件系统操作，检查权限，创建或返回目录的句柄。
5. 浏览器进程将结果（成功或失败，以及目录的元数据或句柄信息）通过 Mojo 返回给 `FileSystemDispatcher`。
6. `FileSystemDispatcher` 将结果转换为 JavaScript 可以理解的格式，并传递给相应的 JavaScript Promise 的 resolve 或 reject 回调。

**假设输出:**

* **成功:** 返回一个 `FileSystemDirectoryHandle` 对象给 JavaScript，允许 JavaScript 代码操作该目录下的文件和子目录。
* **失败:**  JavaScript 接收到一个错误（例如，`DOMException`），表明无法获取目录句柄，可能是由于权限问题或其他错误。

**用户或编程常见的使用错误：**

1. **权限错误:**
    * **用户操作:** 用户拒绝了网站访问其文件系统的请求。
    * **编程错误:** 开发者没有正确处理权限请求的结果，或者假设用户总是会授予权限。
    * **到达 `FileSystemDispatcher` 的路径:** JavaScript 调用文件系统 API，但浏览器进程的 `FileSystemManager` 因为权限问题返回错误，`FileSystemDispatcher` 将该错误传递回 JavaScript。

2. **文件或目录不存在:**
    * **用户操作:** 尝试访问或操作一个不存在的文件或目录。
    * **编程错误:** 开发者使用了错误的路径，或者没有检查文件或目录是否存在就尝试操作。
    * **到达 `FileSystemDispatcher` 的路径:** JavaScript 调用如 `FileSystemFileHandle.getFile()` 或 `FileSystemDirectoryHandle.getDirectoryHandle()`，`FileSystemDispatcher` 将请求发送到浏览器进程，`FileSystemManager` 发现文件或目录不存在，返回相应的错误码（例如 `base::File::FILE_ERROR_NOT_FOUND`），`FileSystemDispatcher` 将此错误传递回 JavaScript。

3. **类型错误:**
    * **编程错误:**  尝试对一个文件执行目录操作，或者反之。例如，尝试将一个文件移动到另一个文件路径（而不是目录）。
    * **到达 `FileSystemDispatcher` 的路径:** JavaScript 调用 `FileSystemDirectoryHandle.getFileHandle()` 尝试获取一个已经存在的目录，或者调用 `FileSystemFileHandle.getDirectoryHandle()`。浏览器进程的 `FileSystemManager` 检测到类型不匹配，返回相应的错误码。

4. **安全限制:**
    * **用户操作/编程错误:** 尝试访问超出网站被授予访问权限范围的文件或目录。
    * **到达 `FileSystemDispatcher` 的路径:** JavaScript 调用文件系统 API 请求访问受限资源，浏览器进程的 `FileSystemManager` 根据安全策略拒绝请求，`FileSystemDispatcher` 将安全错误传递回 JavaScript。

**用户操作如何一步步的到达这里 (作为调试线索):**

以用户通过网页选择一个本地文件为例：

1. **用户操作:** 用户访问一个网页，网页上有一个按钮或者其他交互元素，点击后会触发文件选择操作。
2. **JavaScript 执行:**  点击事件触发 JavaScript 代码，该代码调用 `window.showOpenFilePicker()`。
3. **Blink 内部处理:**  Blink 接收到 `showOpenFilePicker` 的请求，开始处理。
4. **调用 `FileSystemDispatcher`:** Blink 内部的逻辑会调用 `FileSystemDispatcher::OpenFileSystem` 或一个类似的方法，以请求打开文件系统的访问权限 (如果是首次访问)。
5. **Mojo 通信:** `FileSystemDispatcher` 通过 Mojo 向浏览器进程的 `FileSystemManager` 发送请求，指示需要显示文件选择对话框。
6. **浏览器进程处理:** 浏览器进程接收到请求，显示文件选择对话框。
7. **用户选择文件:** 用户在对话框中选择一个或多个文件，然后点击“打开”。
8. **浏览器进程返回结果:** 浏览器进程将用户选择的文件信息（例如，文件路径、名称）通过 Mojo 返回给渲染进程的 `FileSystemDispatcher`。
9. **`FileSystemDispatcher` 处理回调:** `FileSystemDispatcher` 接收到来自浏览器进程的响应，并调用相应的 JavaScript Promise 的 resolve 回调，将 `FileSystemFileHandle` 对象传递给 JavaScript。
10. **后续操作 (可能):** 如果 JavaScript 代码随后调用 `fileHandle.getFile()` 来获取 `File` 对象，这将再次触发 `FileSystemDispatcher` 的调用，请求读取文件内容或元数据。

**调试线索:**

* **断点:** 在 `FileSystemDispatcher` 的关键方法（例如 `OpenFileSystem`, `ResolveURL`, `Write` 等）设置断点，可以观察参数和执行流程。
* **Mojo 日志:** 查看 Mojo 通信的日志，可以了解渲染进程和浏览器进程之间传递的消息。
* **浏览器开发者工具:** 使用 Chrome 开发者工具的 "Sources" 面板调试 JavaScript 代码，查看文件系统 API 的调用栈。
* **`chrome://file-system-internals`:** 这个 Chrome 内部页面可以提供关于文件系统 API 使用情况的更详细信息。

总而言之，`FileSystemDispatcher` 是 Blink 渲染引擎中处理文件系统操作的核心组件，它连接了 JavaScript 等 Web 技术与底层的操作系统文件系统，并负责管理异步操作和错误处理。理解它的功能对于理解浏览器如何处理网页的文件系统访问至关重要。

### 提示词
```
这是目录为blink/renderer/modules/filesystem/file_system_dispatcher.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/filesystem/file_system_dispatcher.h"

#include <utility>

#include "base/containers/contains.h"
#include "base/task/sequenced_task_runner.h"
#include "build/build_config.h"
#include "components/services/filesystem/public/mojom/types.mojom-blink.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class FileSystemDispatcher::WriteListener
    : public mojom::blink::FileSystemOperationListener {
 public:
  WriteListener(const WriteCallback& success_callback,
                StatusCallback error_callback)
      : error_callback_(std::move(error_callback)),
        write_callback_(success_callback) {}

  void ResultsRetrieved(
      Vector<filesystem::mojom::blink::DirectoryEntryPtr> entries,
      bool has_more) override {
    NOTREACHED();
  }

  void ErrorOccurred(base::File::Error error_code) override {
    std::move(error_callback_).Run(error_code);
  }

  void DidWrite(int64_t byte_count, bool complete) override {
    write_callback_.Run(byte_count, complete);
  }

 private:
  StatusCallback error_callback_;
  WriteCallback write_callback_;
};

class FileSystemDispatcher::ReadDirectoryListener
    : public mojom::blink::FileSystemOperationListener {
 public:
  explicit ReadDirectoryListener(std::unique_ptr<EntriesCallbacks> callbacks)
      : callbacks_(std::move(callbacks)) {}

  void ResultsRetrieved(
      Vector<filesystem::mojom::blink::DirectoryEntryPtr> entries,
      bool has_more) override {
    for (const auto& entry : entries) {
      callbacks_->DidReadDirectoryEntry(
          FilePathToWebString(entry->name.path()),
          entry->type == filesystem::mojom::blink::FsFileType::DIRECTORY);
    }
    callbacks_->DidReadDirectoryEntries(has_more);
  }

  void ErrorOccurred(base::File::Error error_code) override {
    callbacks_->DidFail(error_code);
  }

  void DidWrite(int64_t byte_count, bool complete) override { NOTREACHED(); }

 private:
  std::unique_ptr<EntriesCallbacks> callbacks_;
};

FileSystemDispatcher::FileSystemDispatcher(ExecutionContext& context)
    : Supplement<ExecutionContext>(context),
      file_system_manager_(&context),
      next_operation_id_(1),
      op_listeners_(&context) {}

// static
const char FileSystemDispatcher::kSupplementName[] = "FileSystemDispatcher";

// static
FileSystemDispatcher& FileSystemDispatcher::From(ExecutionContext* context) {
  DCHECK(context);
  FileSystemDispatcher* dispatcher =
      Supplement<ExecutionContext>::From<FileSystemDispatcher>(context);
  if (!dispatcher) {
    dispatcher = MakeGarbageCollected<FileSystemDispatcher>(*context);
    Supplement<ExecutionContext>::ProvideTo(*context, dispatcher);
  }
  return *dispatcher;
}

FileSystemDispatcher::~FileSystemDispatcher() = default;

mojom::blink::FileSystemManager& FileSystemDispatcher::GetFileSystemManager() {
  if (!file_system_manager_.is_bound()) {
    // See https://bit.ly/2S0zRAS for task types
    mojo::PendingReceiver<mojom::blink::FileSystemManager> receiver =
        file_system_manager_.BindNewPipeAndPassReceiver(
            GetSupplementable()->GetTaskRunner(
                blink::TaskType::kMiscPlatformAPI));

    GetSupplementable()->GetBrowserInterfaceBroker().GetInterface(
        std::move(receiver));
  }
  DCHECK(file_system_manager_.is_bound());
  return *file_system_manager_.get();
}

void FileSystemDispatcher::OpenFileSystem(
    const SecurityOrigin* origin,
    mojom::blink::FileSystemType type,
    std::unique_ptr<FileSystemCallbacks> callbacks) {
  GetFileSystemManager().Open(
      origin, type,
      WTF::BindOnce(&FileSystemDispatcher::DidOpenFileSystem,
                    WrapWeakPersistent(this), std::move(callbacks)));
}

void FileSystemDispatcher::OpenFileSystemSync(
    const SecurityOrigin* origin,
    mojom::blink::FileSystemType type,
    std::unique_ptr<FileSystemCallbacks> callbacks) {
  String name;
  KURL root_url;
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().Open(origin, type, &name, &root_url, &error_code);
  DidOpenFileSystem(std::move(callbacks), std::move(name), root_url,
                    error_code);
}

void FileSystemDispatcher::ResolveURL(
    const KURL& filesystem_url,
    std::unique_ptr<ResolveURICallbacks> callbacks) {
  GetFileSystemManager().ResolveURL(
      filesystem_url,
      WTF::BindOnce(&FileSystemDispatcher::DidResolveURL,
                    WrapWeakPersistent(this), std::move(callbacks)));
}

void FileSystemDispatcher::ResolveURLSync(
    const KURL& filesystem_url,
    std::unique_ptr<ResolveURICallbacks> callbacks) {
  mojom::blink::FileSystemInfoPtr info;
  base::FilePath file_path;
  bool is_directory;
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().ResolveURL(filesystem_url, &info, &file_path,
                                    &is_directory, &error_code);
  DidResolveURL(std::move(callbacks), std::move(info), std::move(file_path),
                is_directory, error_code);
}

void FileSystemDispatcher::Move(const KURL& src_path,
                                const KURL& dest_path,
                                std::unique_ptr<EntryCallbacks> callbacks) {
  GetFileSystemManager().Move(
      src_path, dest_path,
      WTF::BindOnce(&FileSystemDispatcher::DidFinish, WrapWeakPersistent(this),
                    std::move(callbacks)));
}

void FileSystemDispatcher::MoveSync(const KURL& src_path,
                                    const KURL& dest_path,
                                    std::unique_ptr<EntryCallbacks> callbacks) {
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().Move(src_path, dest_path, &error_code);
  DidFinish(std::move(callbacks), error_code);
}

void FileSystemDispatcher::Copy(const KURL& src_path,
                                const KURL& dest_path,
                                std::unique_ptr<EntryCallbacks> callbacks) {
  GetFileSystemManager().Copy(
      src_path, dest_path,
      WTF::BindOnce(&FileSystemDispatcher::DidFinish, WrapWeakPersistent(this),
                    std::move(callbacks)));
}

void FileSystemDispatcher::CopySync(const KURL& src_path,
                                    const KURL& dest_path,
                                    std::unique_ptr<EntryCallbacks> callbacks) {
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().Copy(src_path, dest_path, &error_code);
  DidFinish(std::move(callbacks), error_code);
}

void FileSystemDispatcher::Remove(const KURL& path,
                                  bool recursive,
                                  std::unique_ptr<VoidCallbacks> callbacks) {
  GetFileSystemManager().Remove(
      path, recursive,
      WTF::BindOnce(&FileSystemDispatcher::DidRemove, WrapWeakPersistent(this),
                    std::move(callbacks)));
}

void FileSystemDispatcher::RemoveSync(
    const KURL& path,
    bool recursive,
    std::unique_ptr<VoidCallbacks> callbacks) {
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().Remove(path, recursive, &error_code);
  DidRemove(std::move(callbacks), error_code);
}

void FileSystemDispatcher::ReadMetadata(
    const KURL& path,
    std::unique_ptr<MetadataCallbacks> callbacks) {
  GetFileSystemManager().ReadMetadata(
      path, WTF::BindOnce(&FileSystemDispatcher::DidReadMetadata,
                          WrapWeakPersistent(this), std::move(callbacks)));
}

void FileSystemDispatcher::ReadMetadataSync(
    const KURL& path,
    std::unique_ptr<MetadataCallbacks> callbacks) {
  base::File::Info file_info;
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().ReadMetadata(path, &file_info, &error_code);
  DidReadMetadata(std::move(callbacks), std::move(file_info), error_code);
}

void FileSystemDispatcher::CreateFile(
    const KURL& path,
    bool exclusive,
    std::unique_ptr<EntryCallbacks> callbacks) {
  GetFileSystemManager().Create(
      path, exclusive, /*is_directory=*/false, /*is_recursive=*/false,
      WTF::BindOnce(&FileSystemDispatcher::DidFinish, WrapWeakPersistent(this),
                    std::move(callbacks)));
}

void FileSystemDispatcher::CreateFileSync(
    const KURL& path,
    bool exclusive,
    std::unique_ptr<EntryCallbacks> callbacks) {
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().Create(path, exclusive, /*is_directory=*/false,
                                /*is_recursive=*/false, &error_code);
  DidFinish(std::move(callbacks), error_code);
}

void FileSystemDispatcher::CreateDirectory(
    const KURL& path,
    bool exclusive,
    bool recursive,
    std::unique_ptr<EntryCallbacks> callbacks) {
  GetFileSystemManager().Create(
      path, exclusive, /*is_directory=*/true, recursive,
      WTF::BindOnce(&FileSystemDispatcher::DidFinish, WrapWeakPersistent(this),
                    std::move(callbacks)));
}

void FileSystemDispatcher::CreateDirectorySync(
    const KURL& path,
    bool exclusive,
    bool recursive,
    std::unique_ptr<EntryCallbacks> callbacks) {
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().Create(path, exclusive, /*is_directory=*/true,
                                recursive, &error_code);
  DidFinish(std::move(callbacks), error_code);
}

void FileSystemDispatcher::Exists(const KURL& path,
                                  bool is_directory,
                                  std::unique_ptr<EntryCallbacks> callbacks) {
  GetFileSystemManager().Exists(
      path, is_directory,
      WTF::BindOnce(&FileSystemDispatcher::DidFinish, WrapWeakPersistent(this),
                    std::move(callbacks)));
}

void FileSystemDispatcher::ExistsSync(
    const KURL& path,
    bool is_directory,
    std::unique_ptr<EntryCallbacks> callbacks) {
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().Exists(path, is_directory, &error_code);
  DidFinish(std::move(callbacks), error_code);
}

void FileSystemDispatcher::ReadDirectory(
    const KURL& path,
    std::unique_ptr<EntriesCallbacks> callbacks) {
  mojo::PendingRemote<mojom::blink::FileSystemOperationListener> listener;
  mojo::PendingReceiver<mojom::blink::FileSystemOperationListener> receiver =
      listener.InitWithNewPipeAndPassReceiver();
  op_listeners_.Add(
      std::make_unique<ReadDirectoryListener>(std::move(callbacks)),
      std::move(receiver),
      // See https://bit.ly/2S0zRAS for task types
      GetSupplementable()->GetTaskRunner(blink::TaskType::kMiscPlatformAPI));
  GetFileSystemManager().ReadDirectory(path, std::move(listener));
}

void FileSystemDispatcher::ReadDirectorySync(
    const KURL& path,
    std::unique_ptr<EntriesCallbacks> callbacks) {
  Vector<filesystem::mojom::blink::DirectoryEntryPtr> entries;
  base::File::Error result = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().ReadDirectorySync(path, &entries, &result);
  if (result == base::File::FILE_OK) {
    DidReadDirectory(std::move(callbacks), std::move(entries),
                     std::move(result));
  }
}

void FileSystemDispatcher::InitializeFileWriter(
    const KURL& path,
    std::unique_ptr<FileWriterCallbacks> callbacks) {
  GetFileSystemManager().ReadMetadata(
      path,
      WTF::BindOnce(&FileSystemDispatcher::InitializeFileWriterCallback,
                    WrapWeakPersistent(this), path, std::move(callbacks)));
}

void FileSystemDispatcher::InitializeFileWriterSync(
    const KURL& path,
    std::unique_ptr<FileWriterCallbacks> callbacks) {
  base::File::Info file_info;
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().ReadMetadata(path, &file_info, &error_code);
  InitializeFileWriterCallback(path, std::move(callbacks), file_info,
                               error_code);
}

void FileSystemDispatcher::Truncate(const KURL& path,
                                    int64_t offset,
                                    int* request_id_out,
                                    StatusCallback callback) {
  HeapMojoRemote<mojom::blink::FileSystemCancellableOperation> op_remote(
      GetSupplementable());
  // See https://bit.ly/2S0zRAS for task types
  mojo::PendingReceiver<mojom::blink::FileSystemCancellableOperation>
      op_receiver = op_remote.BindNewPipeAndPassReceiver(
          GetSupplementable()->GetTaskRunner(
              blink::TaskType::kMiscPlatformAPI));
  int operation_id = next_operation_id_++;
  op_remote.set_disconnect_handler(
      WTF::BindOnce(&FileSystemDispatcher::RemoveOperationRemote,
                    WrapWeakPersistent(this), operation_id));
  cancellable_operations_.insert(operation_id,
                                 WrapDisallowNew(std::move(op_remote)));
  GetFileSystemManager().Truncate(
      path, offset, std::move(op_receiver),
      WTF::BindOnce(&FileSystemDispatcher::DidTruncate,
                    WrapWeakPersistent(this), operation_id,
                    std::move(callback)));

  if (request_id_out)
    *request_id_out = operation_id;
}

void FileSystemDispatcher::TruncateSync(const KURL& path,
                                        int64_t offset,
                                        StatusCallback callback) {
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().TruncateSync(path, offset, &error_code);
  std::move(callback).Run(error_code);
}

void FileSystemDispatcher::Write(const KURL& path,
                                 const Blob& blob,
                                 int64_t offset,
                                 int* request_id_out,
                                 const WriteCallback& success_callback,
                                 StatusCallback error_callback) {
  HeapMojoRemote<mojom::blink::FileSystemCancellableOperation> op_remote(
      GetSupplementable());
  // See https://bit.ly/2S0zRAS for task types
  scoped_refptr<base::SequencedTaskRunner> task_runner =
      GetSupplementable()->GetTaskRunner(blink::TaskType::kMiscPlatformAPI);
  mojo::PendingReceiver<mojom::blink::FileSystemCancellableOperation>
      op_receiver = op_remote.BindNewPipeAndPassReceiver(task_runner);
  int operation_id = next_operation_id_++;
  op_remote.set_disconnect_handler(
      WTF::BindOnce(&FileSystemDispatcher::RemoveOperationRemote,
                    WrapWeakPersistent(this), operation_id));
  cancellable_operations_.insert(operation_id,
                                 WrapDisallowNew(std::move(op_remote)));

  mojo::PendingRemote<mojom::blink::FileSystemOperationListener> listener;
  mojo::PendingReceiver<mojom::blink::FileSystemOperationListener> receiver =
      listener.InitWithNewPipeAndPassReceiver();
  op_listeners_.Add(std::make_unique<WriteListener>(
                        WTF::BindRepeating(&FileSystemDispatcher::DidWrite,
                                           WrapWeakPersistent(this),
                                           success_callback, operation_id),
                        WTF::BindOnce(&FileSystemDispatcher::WriteErrorCallback,
                                      WrapWeakPersistent(this),
                                      std::move(error_callback), operation_id)),
                    std::move(receiver), task_runner);

  GetFileSystemManager().Write(path, blob.AsMojoBlob(), offset,
                               std::move(op_receiver), std::move(listener));

  if (request_id_out)
    *request_id_out = operation_id;
}

void FileSystemDispatcher::WriteSync(const KURL& path,
                                     const Blob& blob,
                                     int64_t offset,
                                     const WriteCallback& success_callback,
                                     StatusCallback error_callback) {
  int64_t byte_count;
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  GetFileSystemManager().WriteSync(path, blob.AsMojoBlob(), offset, &byte_count,
                                   &error_code);
  if (error_code == base::File::FILE_OK)
    std::move(success_callback).Run(byte_count, /*complete=*/true);
  else
    std::move(error_callback).Run(error_code);
}

void FileSystemDispatcher::Cancel(int request_id_to_cancel,
                                  StatusCallback callback) {
  if (!base::Contains(cancellable_operations_, request_id_to_cancel)) {
    std::move(callback).Run(base::File::FILE_ERROR_INVALID_OPERATION);
    return;
  }
  auto& remote =
      cancellable_operations_.find(request_id_to_cancel)->value->Value();
  if (!remote.is_bound()) {
    RemoveOperationRemote(request_id_to_cancel);
    std::move(callback).Run(base::File::FILE_ERROR_INVALID_OPERATION);
    return;
  }
  remote->Cancel(WTF::BindOnce(&FileSystemDispatcher::DidCancel,
                               WrapWeakPersistent(this), std::move(callback),
                               request_id_to_cancel));
}

void FileSystemDispatcher::CreateSnapshotFile(
    const KURL& file_path,
    std::unique_ptr<SnapshotFileCallbackBase> callbacks) {
  GetFileSystemManager().CreateSnapshotFile(
      file_path, WTF::BindOnce(&FileSystemDispatcher::DidCreateSnapshotFile,
                               WrapWeakPersistent(this), std::move(callbacks)));
}

void FileSystemDispatcher::CreateSnapshotFileSync(
    const KURL& file_path,
    std::unique_ptr<SnapshotFileCallbackBase> callbacks) {
  base::File::Info file_info;
  base::FilePath platform_path;
  base::File::Error error_code = base::File::FILE_ERROR_FAILED;
  mojo::PendingRemote<mojom::blink::ReceivedSnapshotListener> listener;
  GetFileSystemManager().CreateSnapshotFile(
      file_path, &file_info, &platform_path, &error_code, &listener);
  DidCreateSnapshotFile(std::move(callbacks), std::move(file_info),
                        std::move(platform_path), error_code,
                        std::move(listener));
}

void FileSystemDispatcher::Trace(Visitor* visitor) const {
  visitor->Trace(file_system_manager_);
  visitor->Trace(cancellable_operations_);
  visitor->Trace(op_listeners_);
  Supplement<ExecutionContext>::Trace(visitor);
}

void FileSystemDispatcher::DidOpenFileSystem(
    std::unique_ptr<FileSystemCallbacks> callbacks,
    const String& name,
    const KURL& root,
    base::File::Error error_code) {
  if (error_code == base::File::Error::FILE_OK) {
    callbacks->DidOpenFileSystem(name, root);
  } else {
    callbacks->DidFail(error_code);
  }
}

void FileSystemDispatcher::DidResolveURL(
    std::unique_ptr<ResolveURICallbacks> callbacks,
    mojom::blink::FileSystemInfoPtr info,
    const base::FilePath& file_path,
    bool is_directory,
    base::File::Error error_code) {
  if (error_code == base::File::Error::FILE_OK) {
    DCHECK(info->root_url.IsValid());
    callbacks->DidResolveURL(info->name, info->root_url, info->mount_type,
                             FilePathToWebString(file_path), is_directory);
  } else {
    callbacks->DidFail(error_code);
  }
}

void FileSystemDispatcher::DidRemove(std::unique_ptr<VoidCallbacks> callbacks,
                                     base::File::Error error_code) {
  if (error_code == base::File::Error::FILE_OK)
    callbacks->DidSucceed();
  else
    callbacks->DidFail(error_code);
}

void FileSystemDispatcher::DidFinish(std::unique_ptr<EntryCallbacks> callbacks,
                                     base::File::Error error_code) {
  if (error_code == base::File::Error::FILE_OK)
    callbacks->DidSucceed();
  else
    callbacks->DidFail(error_code);
}

void FileSystemDispatcher::DidReadMetadata(
    std::unique_ptr<MetadataCallbacks> callbacks,
    const base::File::Info& file_info,
    base::File::Error error_code) {
  if (error_code == base::File::Error::FILE_OK) {
    callbacks->DidReadMetadata(FileMetadata::From(file_info));
  } else {
    callbacks->DidFail(error_code);
  }
}

void FileSystemDispatcher::DidReadDirectory(
    std::unique_ptr<EntriesCallbacks> callbacks,
    Vector<filesystem::mojom::blink::DirectoryEntryPtr> entries,
    base::File::Error error_code) {
  if (error_code == base::File::Error::FILE_OK) {
    for (const auto& entry : entries) {
      callbacks->DidReadDirectoryEntry(
          FilePathToWebString(entry->name.path()),
          entry->type == filesystem::mojom::blink::FsFileType::DIRECTORY);
    }
    callbacks->DidReadDirectoryEntries(false);
  } else {
    callbacks->DidFail(error_code);
  }
}

void FileSystemDispatcher::InitializeFileWriterCallback(
    const KURL& path,
    std::unique_ptr<FileWriterCallbacks> callbacks,
    const base::File::Info& file_info,
    base::File::Error error_code) {
  if (error_code == base::File::Error::FILE_OK) {
    if (file_info.is_directory || file_info.size < 0) {
      callbacks->DidFail(base::File::FILE_ERROR_FAILED);
      return;
    }
    callbacks->DidCreateFileWriter(path, file_info.size);
  } else {
    callbacks->DidFail(error_code);
  }
}

void FileSystemDispatcher::DidTruncate(int operation_id,
                                       StatusCallback callback,
                                       base::File::Error error_code) {
  if (error_code != base::File::FILE_ERROR_ABORT)
    RemoveOperationRemote(operation_id);
  std::move(callback).Run(error_code);
}

void FileSystemDispatcher::DidWrite(const WriteCallback& callback,
                                    int operation_id,
                                    int64_t bytes,
                                    bool complete) {
  callback.Run(bytes, complete);
  if (complete)
    RemoveOperationRemote(operation_id);
}

void FileSystemDispatcher::WriteErrorCallback(StatusCallback callback,
                                              int operation_id,
                                              base::File::Error error) {
  std::move(callback).Run(error);
  if (error != base::File::FILE_ERROR_ABORT)
    RemoveOperationRemote(operation_id);
}

void FileSystemDispatcher::DidCancel(StatusCallback callback,
                                     int cancelled_operation_id,
                                     base::File::Error error_code) {
  if (error_code == base::File::FILE_OK)
    RemoveOperationRemote(cancelled_operation_id);
  std::move(callback).Run(error_code);
}

void FileSystemDispatcher::DidCreateSnapshotFile(
    std::unique_ptr<SnapshotFileCallbackBase> callbacks,
    const base::File::Info& file_info,
    const base::FilePath& platform_path,
    base::File::Error error_code,
    mojo::PendingRemote<mojom::blink::ReceivedSnapshotListener> listener) {
  if (error_code == base::File::FILE_OK) {
    FileMetadata file_metadata = FileMetadata::From(file_info);
    file_metadata.platform_path = FilePathToWebString(platform_path);

    callbacks->DidCreateSnapshotFile(file_metadata);

    if (listener) {
      mojo::Remote<mojom::blink::ReceivedSnapshotListener>(std::move(listener))
          ->DidReceiveSnapshotFile();
    }
  } else {
    callbacks->DidFail(error_code);
  }
}

void FileSystemDispatcher::RemoveOperationRemote(int operation_id) {
  auto it = cancellable_operations_.find(operation_id);
  if (it == cancellable_operations_.end())
    return;
  cancellable_operations_.erase(it);
}

}  // namespace blink
```