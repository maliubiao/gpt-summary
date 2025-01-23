Response:
Let's break down the thought process to analyze the `data_object.cc` file.

1. **Understand the Goal:** The request asks for the functionality of this file, its relation to web technologies, examples, assumptions, common errors, and how users reach this code. This requires both high-level understanding and some code-level analysis.

2. **Initial Scan & Keywords:**  Immediately, I see keywords like "clipboard," "drag," "data," "file," "string," "MIME type." This tells me the file is about handling data transfer, specifically copy/paste and drag-and-drop operations in a web browser. The "blink/renderer/core" path indicates it's part of the core rendering engine, not just a platform-specific interface.

3. **Core Class Identification:** The name `DataObject` is prominent. This is likely the central class this file defines. I'll focus on its methods and how they interact.

4. **Key Functionality Areas:**  Based on the initial scan and class name, I can start categorizing the functionality:
    * **Creation:**  How `DataObject` instances are created (from clipboard, from strings, from drag data). Look for `Create` methods.
    * **Data Storage:** How data is stored within a `DataObject`. The `item_list_` member seems important, holding `DataObjectItem` instances.
    * **Data Access:**  How to get data out of a `DataObject` (by type, as a file, etc.). Look for `Get` methods.
    * **Data Modification:** How to add, remove, or modify data within a `DataObject`. Look for `Add`, `Delete`, `Clear`, `Set` methods.
    * **Clipboard Interaction:**  Functions that directly interact with the system clipboard. Look for methods mentioning `SystemClipboard`.
    * **Drag-and-Drop Interaction:** Functions that handle drag data. Look for methods mentioning `WebDragData`.
    * **Data Types:**  What types of data can be stored (strings, files, URLs, HTML).
    * **Observers:** The presence of `Observer` suggests a mechanism for notifying other parts of the system about changes to the `DataObject`.

5. **Detailed Method Analysis (Iterative):** Now I go through the code method by method, focusing on the key areas identified above. I'll simulate the code execution in my head for simple scenarios.

    * **`CreateFromClipboard`:** This confirms the clipboard interaction. It iterates through available clipboard types and populates the `DataObject`. The `PasteMode` parameter is interesting – hinting at handling plain text vs. rich text. The file handling within this method is crucial.
    * **`CreateFromString`:** Simple creation for text data.
    * **`Add`, `DeleteItem`, `Clear...`:**  These are the core data manipulation methods. I pay attention to how `DataObjectItem` is used.
    * **`Types`, `GetData`:**  These are for retrieving information. The `Types` method specifically handles the case of files being present.
    * **`UrlAndTitle`, `SetURLAndTitle`, `HtmlAndBaseURL`, `SetHTMLAndBaseURL`:** These are specific helpers for common web content types. This directly links to HTML and JavaScript concepts.
    * **`ContainsFilenames`, `Filenames`, `AddFilename`, `AddFileSharedBuffer`:** Focused on file handling in drag-and-drop.
    * **`Create(ExecutionContext*, const WebDragData&)`:** This is the core drag-and-drop data ingestion. The `absl::visit` pattern handles different types of drag items, which is a key observation.
    * **`ToWebDragData`:**  The reverse of the previous method, converting the internal representation back to the external `WebDragData` format.

6. **Relating to Web Technologies (JavaScript, HTML, CSS):** As I analyze the methods, I specifically think about how these operations relate to user actions and web APIs:
    * **JavaScript:** The `Clipboard API` (e.g., `navigator.clipboard.readText()`, `navigator.clipboard.write()`) and the `Drag and Drop API` (e.g., `dragstart`, `dragover`, `drop` events, `DataTransfer` object). The `DataObject` is the underlying representation of the `DataTransfer` object's data in Blink.
    * **HTML:** Copying/pasting text, URLs, images, dragging links, dragging files – all involve the `DataObject`. The `kMimeTypeTextHTML` handling is a direct link.
    * **CSS:** While less direct, CSS can influence the *appearance* of draggable elements or the feedback during a drag operation. It doesn't directly manipulate the `DataObject`.

7. **Examples and Scenarios:**  For each relation to web technologies, I formulate simple examples:
    * Copying text:  User selects text, presses Ctrl+C. This leads to `CreateFromClipboard` being called, reading `text/plain`.
    * Dragging a link: User drags a link. `Create(ExecutionContext*, const WebDragData&)` is called, processing the `text/uri-list`.
    * Dragging a file: User drags a file. The file-related handling in `Create` and the `FilenameItem` are involved.

8. **Assumptions and Logic:** If a method has conditional logic, I think about the inputs and outputs. For example, in `CreateFromClipboard`, the behavior differs based on `PasteMode`. I'd consider the input (`PasteMode::kPlainTextOnly`) and the output (only plain text items).

9. **Common Errors:** I consider what could go wrong from a developer's perspective:
    * Incorrect MIME types.
    * Forgetting to handle different data types in drag-and-drop.
    * Not checking for errors when accessing files.

10. **User Actions and Debugging:**  I trace back from the `DataObject` to user actions. What steps a user takes to trigger code that *uses* this class. This is crucial for debugging. The examples already generated in step 7 serve as debugging clues.

11. **Structure and Refine:**  Finally, I organize the information into the requested categories (functionality, relations, examples, assumptions, errors, debugging). I use clear language and code snippets where helpful. I review for accuracy and completeness.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about clipboard."  **Correction:**  The presence of drag-related methods and `WebDragData` clearly indicates it handles drag-and-drop as well.
* **Initial thought:** "CSS is directly involved." **Correction:** CSS influences the UI but doesn't directly manipulate the `DataObject`'s data. JavaScript through the Drag and Drop API is the primary interface.
* **Realization:** The `absl::visit` pattern is a key detail for understanding how different drag item types are handled. Highlighting this improves the explanation.

By following this structured approach, combining high-level understanding with code-level analysis, and thinking about user interactions and potential errors, I can generate a comprehensive and accurate explanation of the `data_object.cc` file.
这是 `blink/renderer/core/clipboard/data_object.cc` 文件的功能分析：

**核心功能:**

`DataObject` 类是 Blink 渲染引擎中用于表示剪贴板或拖放操作中传递的数据的中心容器。 它负责存储和管理各种类型的数据，例如文本、HTML、URL 和文件。  可以将 `DataObject` 视为一个通用的数据包，可以在不同的操作（例如复制、粘贴、拖动、释放）之间传递信息。

**主要功能点:**

1. **数据存储:**
   -  可以存储多种数据类型，每种数据类型都与一个 MIME 类型关联。
   -  内部使用 `item_list_` 存储 `DataObjectItem` 对象的列表，每个 `DataObjectItem` 代表一个数据项及其类型。
   -  支持存储字符串数据（例如纯文本、HTML）和文件数据。

2. **数据添加和删除:**
   -  提供 `Add()` 方法用于添加不同类型的数据（字符串、文件）。
   -  提供 `DeleteItem()` 方法用于删除特定索引的数据项。
   -  提供 `ClearStringItems()` 方法用于清除所有字符串类型的数据项。
   -  提供 `ClearAll()` 方法用于清除所有数据项。
   -  提供 `ClearData()` 方法用于清除特定类型（MIME 类型）的字符串数据。

3. **数据访问:**
   -  提供 `length()` 方法获取数据项的数量。
   -  提供 `Item()` 方法通过索引访问特定的 `DataObjectItem`。
   -  提供 `Types()` 方法获取所有已存储的数据类型（MIME 类型）的列表。
   -  提供 `GetData()` 方法根据 MIME 类型获取字符串数据。
   -  提供 `UrlAndTitle()` 和 `SetURLAndTitle()` 方法用于处理 URL 列表数据。
   -  提供 `HtmlAndBaseURL()` 和 `SetHTMLAndBaseURL()` 方法用于处理 HTML 数据及其基准 URL。
   -  提供 `ContainsFilenames()` 方法检查是否包含文件名。
   -  提供 `Filenames()` 方法获取所有存储的文件名列表。

4. **剪贴板交互:**
   -  提供静态方法 `CreateFromClipboard()` 从系统剪贴板读取数据并创建 `DataObject` 对象。
   -  此方法会根据 `PasteMode` 参数（例如，是否只粘贴纯文本）来决定读取哪些类型的数据。
   -  能处理 `text/uri-list` 类型，从中读取 URL 和文件名。

5. **拖放交互:**
   -  提供静态方法 `Create(ExecutionContext*, const WebDragData&)` 从 `WebDragData` 对象创建 `DataObject`，用于接收拖放的数据。
   -  提供 `ToWebDragData()` 方法将 `DataObject` 转换为 `WebDragData` 对象，用于发起拖放操作。
   -  能够处理拖放的文件，包括文件名、显示名称、文件系统 ID 以及 `FileSystemAccessDropData`。
   -  支持处理拖放的二进制数据。

6. **事件通知:**
   -  提供观察者模式，允许其他对象注册为观察者 (`AddObserver()`)，并在 `DataObject` 的数据项列表发生变化时收到通知 (`NotifyItemListChanged()`)。

**与 JavaScript, HTML, CSS 的关系及举例:**

`DataObject` 在 Web 浏览器中扮演着桥梁的角色，连接着用户操作（例如复制、粘贴、拖放）和 JavaScript 代码。

**JavaScript:**

- **Clipboard API (navigator.clipboard):** 当 JavaScript 代码使用 `navigator.clipboard.readText()` 或 `navigator.clipboard.read()` 方法读取剪贴板内容时，浏览器内部会调用 `SystemClipboard` 读取数据，最终通过 `DataObject::CreateFromClipboard()` 创建 `DataObject` 对象，并将数据传递给 JavaScript。
  ```javascript
  navigator.clipboard.readText().then(text => {
    console.log("Pasted text:", text);
  });
  ```
  **假设输入:** 用户复制了一段文本 "Hello World"。
  **输出:**  `DataObject::CreateFromClipboard()` 将创建一个包含一个类型为 `text/plain`，数据为 "Hello World" 的 `DataObject`。JavaScript 的 `then` 回调函数会接收到 "Hello World" 字符串。

- **Drag and Drop API:** 当用户开始拖动元素或释放拖动的元素时，JavaScript 的 `dragstart` 和 `drop` 事件会触发。  `DataObject` 用于在拖动源和目标之间传递数据。
  ```javascript
  const element = document.getElementById('draggable');
  element.addEventListener('dragstart', (event) => {
    event.dataTransfer.setData('text/plain', 'This is draggable data');
  });

  const dropZone = document.getElementById('dropzone');
  dropZone.addEventListener('drop', (event) => {
    const data = event.dataTransfer.getData('text/plain');
    console.log("Dropped data:", data);
  });
  ```
  **假设输入:** 用户拖动 id 为 `draggable` 的元素到 id 为 `dropzone` 的区域。
  **输出:** 在 `dragstart` 事件中，JavaScript 调用 `event.dataTransfer.setData()` 会在内部创建一个 `DataObject`，其中包含类型为 `text/plain`，数据为 "This is draggable data" 的项。在 `drop` 事件中，`DataObject::Create(ExecutionContext*, const WebDragData&)` 会被调用来创建 `DataObject`，然后 JavaScript 通过 `event.dataTransfer.getData()` 获取数据。

**HTML:**

- **复制粘贴 HTML 内容:** 当用户复制包含 HTML 格式的内容时，`DataObject` 会存储 `text/html` 类型的数据。
  ```html
  <!-- 用户复制以下 HTML 片段 -->
  <p>This is <b>bold</b> text.</p>
  ```
  **假设输入:** 用户复制了上述 HTML 代码。
  **输出:** `DataObject::CreateFromClipboard()` 将创建一个包含一个类型为 `text/html`，数据为 `<p>This is <b>bold</b> text.</p>` 的 `DataObject`。

- **拖动链接或图片:** 当用户拖动一个链接或图片时，浏览器会创建一个包含 URL 和可能的标题或文件信息的 `DataObject`。
  **假设输入:** 用户拖动一个指向 `https://example.com` 的链接。
  **输出:** `DataObject::Create(ExecutionContext*, const WebDragData&)` 将创建一个包含一个类型为 `text/uri-list`，数据为 `https://example.com` 的 `DataObject`，可能还会包含一个标题。

**CSS:**

CSS 本身不直接与 `DataObject` 交互来存储或访问数据。 然而，CSS 可以影响用户界面的交互，从而间接地影响到 `DataObject` 的使用。 例如，CSS 可以设置元素为可拖动 (`draggable="true"`)，或者定义拖放操作的视觉反馈。

**用户操作如何一步步的到达这里，作为调试线索:**

以下是一些用户操作导致 `DataObject` 代码被执行的步骤，可以作为调试线索：

1. **复制文本:**
   - 用户在网页上选择一段文本。
   - 用户按下 `Ctrl+C` (或 `Cmd+C` 在 macOS 上)，或者右键选择 "复制"。
   - 浏览器捕获到复制操作。
   - Blink 核心代码调用平台相关的剪贴板 API 将选中文本写入系统剪贴板。
   - 当 JavaScript 代码调用 `navigator.clipboard.readText()` 或某些粘贴事件触发时，Blink 会从系统剪贴板读取数据，并调用 `DataObject::CreateFromClipboard()` 创建 `DataObject`。

2. **粘贴文本:**
   - 用户按下 `Ctrl+V` (或 `Cmd+V` 在 macOS 上)，或者右键选择 "粘贴"。
   - 浏览器捕获到粘贴操作。
   - Blink 核心代码调用平台相关的剪贴板 API 从系统剪贴板读取数据。
   - `DataObject::CreateFromClipboard()` 被调用，根据剪贴板中的数据类型创建 `DataObject`。
   - 事件（例如 `paste` 事件）被触发，并将 `DataObject` 中的数据传递给相关的事件处理程序或渲染过程。

3. **拖动元素:**
   - 用户点击并按住一个设置了 `draggable="true"` 属性的 HTML 元素，或者一个浏览器默认可拖动的元素（如链接、图片）。
   - 用户开始移动鼠标，触发 `dragstart` 事件。
   - 在 `dragstart` 事件处理程序中，JavaScript 代码可以使用 `event.dataTransfer.setData()` 向 `DataObject` 中添加数据。  或者，浏览器会自动为某些元素类型设置默认的拖动数据。
   - 当拖动操作进行时，`DataObject` 中存储的数据会被用于传递拖动信息。

4. **释放拖动的元素到目标区域:**
   - 用户将拖动的元素移动到目标区域上方。
   - `dragenter` 和 `dragover` 事件在目标元素上触发。
   - 当用户释放鼠标时，`drop` 事件在目标元素上触发。
   - 浏览器会基于拖动操作中的数据创建一个 `DataObject`，并通过 `event.dataTransfer` 对象将其传递给 `drop` 事件处理程序。  在 Blink 内部，这涉及到调用 `DataObject::Create(ExecutionContext*, const WebDragData&)`。

**用户或编程常见的使用错误举例:**

1. **JavaScript 中 `dataTransfer` 对象使用错误:**
   - **错误:**  在 `dragstart` 事件中设置了错误的 MIME 类型，导致在 `drop` 事件中无法正确读取数据。
     ```javascript
     element.addEventListener('dragstart', (event) => {
       event.dataTransfer.setData('text', 'Incorrect MIME type'); // 应该使用 'text/plain'
     });
     ```
     **假设输入:** 用户拖动元素。
     **输出:**  在 `drop` 事件中，尝试使用 `event.dataTransfer.getData('text/plain')` 将返回空字符串。

   - **错误:**  在 `drop` 事件中尝试读取不存在的 MIME 类型的数据。
     ```javascript
     dropZone.addEventListener('drop', (event) => {
       const data = event.dataTransfer.getData('application/json'); // 如果拖动源没有设置这种类型的数据
       console.log(data); // 输出 null 或空字符串
     });
     ```
     **假设输入:** 用户拖动一个只设置了 `text/plain` 数据的元素。
     **输出:** `event.dataTransfer.getData('application/json')` 将返回空值或空字符串。

2. **后端处理剪贴板数据时假设了错误的数据格式:**
   - **错误:**  后端接收到粘贴操作的数据，并假设总是纯文本，但实际上用户可能复制了包含 HTML 格式的内容。
   - **假设输入:** 用户复制了包含格式的文本（例如，从 Word 文档复制）。
   - **输出:**  后端可能无法正确解析 HTML 标签，导致显示错误或数据丢失。

3. **在拖放操作中没有正确处理文件数据:**
   - **错误:**  在 `drop` 事件中，没有检查 `dataTransfer.files` 属性来处理拖放的文件。
     ```javascript
     dropZone.addEventListener('drop', (event) => {
       event.preventDefault(); // 阻止浏览器默认行为
       if (event.dataTransfer.files.length > 0) {
         // 处理文件
         const file = event.dataTransfer.files[0];
         console.log("Dropped file:", file.name);
       } else {
         const textData = event.dataTransfer.getData('text/plain');
         console.log("Dropped text:", textData);
       }
     });
     ```
     **假设输入:** 用户拖动一个文件到 `dropZone`。
     **输出:** 如果没有检查 `event.dataTransfer.files`，代码可能只会尝试读取文本数据，而忽略了拖放的文件。

**总结:**

`DataObject` 是 Blink 渲染引擎中处理剪贴板和拖放操作的核心类，负责存储和管理各种类型的数据。理解其功能和与 JavaScript、HTML 的关系，以及可能出现的使用错误，对于开发涉及数据交互的 Web 应用至关重要。  调试时，关注用户操作的步骤，检查 JavaScript 中 `dataTransfer` 对象的使用，以及后端如何处理接收到的数据，可以帮助定位问题。

### 提示词
```
这是目录为blink/renderer/core/clipboard/data_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (c) 2008, 2009, 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/clipboard/data_object.h"

#include <utility>

#include "base/functional/overloaded.h"
#include "base/notreached.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_drag_data.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_mime_types.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_utilities.h"
#include "third_party/blink/renderer/core/clipboard/dragged_isolated_file_system.h"
#include "third_party/blink/renderer/core/clipboard/paste_mode.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"

namespace blink {

// static
DataObject* DataObject::CreateFromClipboard(ExecutionContext* context,
                                            SystemClipboard* system_clipboard,
                                            PasteMode paste_mode) {
  DataObject* data_object = Create();
#if DCHECK_IS_ON()
  HashSet<String> types_seen;
#endif
  ClipboardSequenceNumberToken sequence_number =
      system_clipboard->SequenceNumber();
  for (const String& type : system_clipboard->ReadAvailableTypes()) {
    if (paste_mode == PasteMode::kPlainTextOnly && type != kMimeTypeTextPlain)
      continue;
    mojom::blink::ClipboardFilesPtr files;
    if (type == kMimeTypeTextURIList) {
      files = system_clipboard->ReadFiles();
      if (files) {
        // Ignore ReadFiles() result if clipboard sequence number has changed.
        if (system_clipboard->SequenceNumber() != sequence_number) {
          files->files.clear();
        } else {
          for (const mojom::blink::DataTransferFilePtr& file : files->files) {
            data_object->AddFilename(
                context, FilePathToString(file->path),
                FilePathToString(file->display_name), files->file_system_id,
                base::MakeRefCounted<FileSystemAccessDropData>(
                    std::move(file->file_system_access_token)));
          }
        }
      }
    }
    if (files && !files->files.empty()) {
      DraggedIsolatedFileSystem::PrepareForDataObject(data_object);
    } else {
      data_object->item_list_.push_back(DataObjectItem::CreateFromClipboard(
          system_clipboard, type, sequence_number));
    }
#if DCHECK_IS_ON()
    DCHECK(types_seen.insert(type).is_new_entry);
#endif
  }
  return data_object;
}

DataObject* DataObject::CreateFromClipboard(SystemClipboard* system_clipboard,
                                            PasteMode paste_mode) {
  return CreateFromClipboard(/*context=*/nullptr, system_clipboard, paste_mode);
}

// static
DataObject* DataObject::CreateFromString(const String& data) {
  DataObject* data_object = Create();
  data_object->Add(data, kMimeTypeTextPlain);
  return data_object;
}

// static
DataObject* DataObject::Create() {
  return MakeGarbageCollected<DataObject>();
}

DataObject::~DataObject() = default;

uint32_t DataObject::length() const {
  return item_list_.size();
}

DataObjectItem* DataObject::Item(uint32_t index) {
  if (index >= length())
    return nullptr;
  return item_list_[index].Get();
}

void DataObject::DeleteItem(uint32_t index) {
  if (index >= length())
    return;
  item_list_.EraseAt(index);
  NotifyItemListChanged();
}

void DataObject::ClearStringItems() {
  if (item_list_.empty()) {
    return;
  }

  wtf_size_t num_items_before = item_list_.size();
  item_list_.erase(std::remove_if(item_list_.begin(), item_list_.end(),
                                  [](Member<DataObjectItem> item) {
                                    return item->Kind() ==
                                           DataObjectItem::kStringKind;
                                  }),
                   item_list_.end());
  if (num_items_before != item_list_.size()) {
    NotifyItemListChanged();
  }
}

void DataObject::ClearAll() {
  if (item_list_.empty())
    return;
  item_list_.clear();
  NotifyItemListChanged();
}

DataObjectItem* DataObject::Add(const String& data, const String& type) {
  DataObjectItem* item = DataObjectItem::CreateFromString(type, data);
  if (!InternalAddStringItem(item))
    return nullptr;
  return item;
}

DataObjectItem* DataObject::Add(File* file) {
  if (!file)
    return nullptr;

  DataObjectItem* item = DataObjectItem::CreateFromFile(file);
  InternalAddFileItem(item);
  return item;
}

DataObjectItem* DataObject::Add(File* file, const String& file_system_id) {
  if (!file)
    return nullptr;

  DataObjectItem* item =
      DataObjectItem::CreateFromFileWithFileSystemId(file, file_system_id);
  InternalAddFileItem(item);
  return item;
}

void DataObject::ClearData(const String& type) {
  for (wtf_size_t i = 0; i < item_list_.size(); ++i) {
    if (item_list_[i]->Kind() == DataObjectItem::kStringKind &&
        item_list_[i]->GetType() == type) {
      // Per the spec, type must be unique among all items of kind 'string'.
      item_list_.EraseAt(i);
      NotifyItemListChanged();
      return;
    }
  }
}

Vector<String> DataObject::Types() const {
  Vector<String> results;
#if DCHECK_IS_ON()
  HashSet<String> types_seen;
#endif
  bool contains_files = false;
  for (const auto& item : item_list_) {
    switch (item->Kind()) {
      case DataObjectItem::kStringKind:
        // Per the spec, type must be unique among all items of kind 'string'.
        results.push_back(item->GetType());
#if DCHECK_IS_ON()
        DCHECK(types_seen.insert(item->GetType()).is_new_entry);
#endif
        break;
      case DataObjectItem::kFileKind:
        contains_files = true;
        break;
    }
  }
  if (contains_files) {
    results.push_back(kMimeTypeFiles);
#if DCHECK_IS_ON()
    DCHECK(types_seen.insert(kMimeTypeFiles).is_new_entry);
#endif
  }
  return results;
}

String DataObject::GetData(const String& type) const {
  for (const auto& item : item_list_) {
    if (item->Kind() == DataObjectItem::kStringKind && item->GetType() == type)
      return item->GetAsString();
  }
  return String();
}

void DataObject::SetData(const String& type, const String& data) {
  ClearData(type);
  if (!Add(data, type)) {
    NOTREACHED();
  }
}

void DataObject::UrlAndTitle(String& url, String* title) const {
  DataObjectItem* item = FindStringItem(kMimeTypeTextURIList);
  if (!item)
    return;
  url = ConvertURIListToURL(item->GetAsString());
  if (title)
    *title = item->Title();
}

void DataObject::SetURLAndTitle(const String& url, const String& title) {
  ClearData(kMimeTypeTextURIList);
  InternalAddStringItem(DataObjectItem::CreateFromURL(url, title));
}

void DataObject::HtmlAndBaseURL(String& html, KURL& base_url) const {
  DataObjectItem* item = FindStringItem(kMimeTypeTextHTML);
  if (!item)
    return;
  html = item->GetAsString();
  base_url = item->BaseURL();
}

void DataObject::SetHTMLAndBaseURL(const String& html, const KURL& base_url) {
  ClearData(kMimeTypeTextHTML);
  InternalAddStringItem(DataObjectItem::CreateFromHTML(html, base_url));
}

bool DataObject::ContainsFilenames() const {
  for (const auto& item : item_list_) {
    if (item->IsFilename())
      return true;
  }
  return false;
}

Vector<String> DataObject::Filenames() const {
  Vector<String> results;
  for (const auto& item : item_list_) {
    if (item->IsFilename())
      results.push_back(item->GetAsFile()->GetPath());
  }
  return results;
}

void DataObject::AddFilename(
    ExecutionContext* context,
    const String& filename,
    const String& display_name,
    const String& file_system_id,
    scoped_refptr<FileSystemAccessDropData> file_system_access_entry) {
  InternalAddFileItem(DataObjectItem::CreateFromFileWithFileSystemId(
      File::CreateForUserProvidedFile(context, filename, display_name),
      file_system_id, std::move(file_system_access_entry)));
}

void DataObject::AddFileSharedBuffer(scoped_refptr<SharedBuffer> buffer,
                                     bool is_image_accessible,
                                     const KURL& source_url,
                                     const String& filename_extension,
                                     const AtomicString& content_disposition) {
  InternalAddFileItem(DataObjectItem::CreateFromFileSharedBuffer(
      std::move(buffer), is_image_accessible, source_url, filename_extension,
      content_disposition));
}

DataObject::DataObject() : modifiers_(0) {}

DataObjectItem* DataObject::FindStringItem(const String& type) const {
  for (const auto& item : item_list_) {
    if (item->Kind() == DataObjectItem::kStringKind && item->GetType() == type)
      return item.Get();
  }
  return nullptr;
}

bool DataObject::InternalAddStringItem(DataObjectItem* new_item) {
  DCHECK_EQ(new_item->Kind(), DataObjectItem::kStringKind);
  for (const auto& item : item_list_) {
    if (item->Kind() == DataObjectItem::kStringKind &&
        item->GetType() == new_item->GetType())
      return false;
  }

  item_list_.push_back(new_item);
  NotifyItemListChanged();
  return true;
}

void DataObject::InternalAddFileItem(DataObjectItem* new_item) {
  DCHECK_EQ(new_item->Kind(), DataObjectItem::kFileKind);
  item_list_.push_back(new_item);
  NotifyItemListChanged();
}

void DataObject::AddObserver(Observer* observer) {
  DCHECK(!observers_.Contains(observer));
  observers_.insert(observer);
}

void DataObject::NotifyItemListChanged() const {
  for (const Member<Observer>& observer : observers_)
    observer->OnItemListChanged();
}

void DataObject::Trace(Visitor* visitor) const {
  visitor->Trace(item_list_);
  visitor->Trace(observers_);
  Supplementable<DataObject>::Trace(visitor);
}

// static
DataObject* DataObject::Create(ExecutionContext* context,
                               const WebDragData& data) {
  DataObject* data_object = Create();
  bool has_file_system = false;

  for (const WebDragData::Item& item : data.Items()) {
    absl::visit(
        base::Overloaded{
            [&](const WebDragData::StringItem& item) {
              if (String(item.type) == kMimeTypeTextURIList) {
                data_object->SetURLAndTitle(item.data, item.title);
              } else if (String(item.type) == kMimeTypeTextHTML) {
                data_object->SetHTMLAndBaseURL(item.data, item.base_url);
              } else {
                data_object->SetData(item.type, item.data);
              }
            },
            [&](const WebDragData::FilenameItem& item) {
              has_file_system = true;
              data_object->AddFilename(context, item.filename,
                                       item.display_name, data.FilesystemId(),
                                       item.file_system_access_entry);
            },
            [&](const WebDragData::BinaryDataItem& item) {
              data_object->AddFileSharedBuffer(
                  item.data, item.image_accessible, item.source_url,
                  item.filename_extension, item.content_disposition);
            },
            [&](const WebDragData::FileSystemFileItem& item) {
              // TODO(http://crbug.com/429077): The file system URL may refer a
              // user visible file.
              scoped_refptr<BlobDataHandle> blob_data_handle =
                  item.blob_info.GetBlobHandle();

              // If the browser process has provided a BlobDataHandle to use for
              // building the File object (as a result of a drop operation being
              // performed) then use it to create the file here (instead of
              // creating a File object without one and requiring a call to
              // BlobRegistry::Register in the browser process to hook up the
              // Blob remote/receiver pair). If no BlobDataHandle was provided,
              // create a BlobDataHandle to an empty blob since the File object
              // contents won't be needed (for example, because this DataObject
              // will be used for the DragEnter case where the spec only
              // indicates that basic file metadata should be retrievable via
              // the corresponding DataTransferItem).
              if (!blob_data_handle) {
                blob_data_handle = BlobDataHandle::Create();
              }
              has_file_system = true;
              FileMetadata file_metadata;
              file_metadata.length = item.size;
              data_object->Add(
                  File::CreateForFileSystemFile(item.url, file_metadata,
                                                File::kIsNotUserVisible,
                                                std::move(blob_data_handle)),
                  item.file_system_id);
            },
        },
        item);
  }

  data_object->SetFilesystemId(data.FilesystemId());

  if (has_file_system)
    DraggedIsolatedFileSystem::PrepareForDataObject(data_object);

  return data_object;
}

DataObject* DataObject::Create(const WebDragData& data) {
  return Create(/*context=*/nullptr, data);
}

WebDragData DataObject::ToWebDragData() {
  WebDragData data;
  WebVector<WebDragData::Item> item_list(length());

  for (wtf_size_t i = 0; i < length(); ++i) {
    DataObjectItem* original_item = Item(i);
    WebDragData::Item& item = item_list[i];
    switch (original_item->Kind()) {
      case DataObjectItem::kStringKind: {
        auto& string_item = item.emplace<WebDragData::StringItem>();
        string_item.type = original_item->GetType();
        string_item.data = original_item->GetAsString();
        string_item.title = original_item->Title();
        string_item.base_url = original_item->BaseURL();
        break;
      }
      case DataObjectItem::kFileKind: {
        if (original_item->GetSharedBuffer()) {
          auto& binary_data_item = item.emplace<WebDragData::BinaryDataItem>();
          binary_data_item.data = original_item->GetSharedBuffer();
          binary_data_item.image_accessible =
              original_item->IsImageAccessible();
          binary_data_item.source_url = original_item->BaseURL();
          binary_data_item.filename_extension =
              original_item->FilenameExtension();
          binary_data_item.content_disposition = original_item->Title();
        } else if (original_item->IsFilename()) {
          auto* file = original_item->GetAsFile();
          if (file->HasBackingFile()) {
            auto& filename_item =
                item_list[i].emplace<WebDragData::FilenameItem>();
            filename_item.filename = file->GetPath();
            filename_item.display_name = file->name();
          } else if (!file->FileSystemURL().IsEmpty()) {
            auto& file_system_file_item =
                item_list[i].emplace<WebDragData::FileSystemFileItem>();
            file_system_file_item.url = file->FileSystemURL();
            file_system_file_item.size = file->size();
            file_system_file_item.file_system_id =
                original_item->FileSystemId();
          } else {
            // TODO(http://crbug.com/394955): support dragging constructed
            // Files across renderers.
            auto& string_item = item_list[i].emplace<WebDragData::StringItem>();
            string_item.type = "text/plain";
            string_item.data = file->name();
          }
        } else {
          NOTREACHED();
        }
        break;
      }
    }
  }
  data.SetItems(std::move(item_list));
  return data;
}

}  // namespace blink
```