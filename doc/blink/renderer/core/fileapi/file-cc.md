Response:
Let's break down the thought process for analyzing the `File.cc` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `File.cc` file in the Chromium Blink engine. This involves:

* **Identifying its primary function:** What is the core responsibility of this code?
* **Relating it to web technologies (JavaScript, HTML, CSS):** How does this code interact with these technologies that web developers use?
* **Inferring logic and providing examples:**  Can we deduce the behavior of the code and illustrate it with hypothetical inputs and outputs?
* **Highlighting potential user/developer errors:** What mistakes could someone make when working with this functionality?

**2. Initial Skim and Keyword Recognition:**

I started by quickly skimming the code, looking for familiar keywords and patterns:

* **`File`:**  The class name itself is a huge clue. This file likely implements the `File` interface accessible in JavaScript.
* **`Blob`:**  The code frequently mentions `Blob`. This suggests a close relationship between `File` and `Blob`, which is accurate—`File` inherits from or at least uses `Blob` for its underlying data.
* **`ExecutionContext`:** This indicates the code runs within a specific browsing context, likely a tab or worker.
* **`FormData` (implied by `FormControlState`):**  The mentions of `FormControlState` and appending to it suggest how files are handled when submitting forms.
* **`ContentType`:** The code deals with determining the MIME type of files.
* **`lastModified`:** This directly corresponds to a JavaScript property.
* **`size`:**  Another core property of the `File` object in JavaScript.
* **`name`:**  The filename.
* **`path`:**  The actual path on the user's system (though often restricted for security).
* **`relative_path` (`webkitRelativePath`):**  Important for directory uploads.
* **`Create` methods:** These static methods suggest different ways to construct `File` objects.
* **`BlobDataHandle`:**  This seems to be an internal representation of the file's data.
* **`UserVisibility`:** Hints at security and privacy considerations.

**3. Identifying Core Functionalities:**

Based on the keywords and structure, I started outlining the core responsibilities:

* **File Representation:** The primary function is to represent files within the Blink rendering engine. This involves storing metadata (name, size, modification date) and a handle to the file's contents.
* **Creation:** The different `Create` methods indicate various scenarios for creating `File` objects:
    * From JavaScript `Blob` parts.
    * From `<input type="file">` form elements.
    * From the file system API.
* **Metadata Access:** Providing access to file metadata like name, size, and last modification date, mirroring the JavaScript `File` interface.
* **Content Type Determination:**  Inferring the MIME type based on the file extension.
* **Integration with Forms:**  Handling file data when submitting HTML forms.
* **Internal Data Handling:** Using `BlobDataHandle` to manage the underlying file data, likely for efficiency and potential asynchronous loading.
* **Snapshotting:** The `CaptureSnapshotIfNeeded` function suggests that file metadata might be lazily loaded or cached.

**4. Connecting to Web Technologies:**

With the core functionalities identified, I started connecting them to JavaScript, HTML, and CSS:

* **JavaScript:** The `File` object is directly accessible and manipulable in JavaScript. The code mirrors the properties and methods of the JavaScript `File` interface. I focused on properties like `name`, `size`, `lastModified`, and the concept of creating `File` objects from JavaScript.
* **HTML:** The `<input type="file">` element is the primary way users select files. The code handles the data coming from this element when a form is submitted. The `webkitRelativePath` is specifically relevant to directory uploads via `<input type="file" webkitdirectory>`.
* **CSS:**  While CSS doesn't directly interact with the *content* of files, the selection of files via `<input type="file">` can be styled with CSS. The *names* of selected files might be displayed, which could be styled. The interaction is indirect but still worth mentioning.

**5. Developing Examples and Logic:**

For logical inference and examples, I focused on:

* **Content Type Determination:**  I created a scenario showing how the file extension affects the `type` property.
* **Form Submission:** I illustrated how the `File` object's properties are used when a form is submitted.
* **`lastModified`:** I explained the behavior when the modification date is unavailable.
* **`webkitRelativePath`:** I showed how this property is populated in the context of directory uploads.

**6. Identifying Potential Errors:**

I considered common mistakes developers or users might make:

* **Assuming File Availability:**  JavaScript code might assume a `File` object always has a backing file, which isn't true for files created purely in memory (e.g., from `Blob`).
* **Incorrect Path Assumptions:**  Developers shouldn't rely on the `path` property for security reasons. Browsers restrict access to the full client-side path.
* **Lossy `lastModified` Conversion:**  The code itself notes potential lossiness when converting the `lastModified` timestamp to a double if using older APIs. This is a good example of a potential pitfall.
* **Size Limitations:**  JavaScript's number type has limitations, and very large files might cause issues with the `size` property, though the Blink code attempts to mitigate this.

**7. Structuring the Answer:**

Finally, I organized the information into clear sections:

* **Functionality:**  A high-level summary of the code's purpose.
* **Relationship with Web Technologies:**  Separate explanations for JavaScript, HTML, and CSS with concrete examples.
* **Logic Inference:**  Hypothetical input and output scenarios to illustrate behavior.
* **Common Errors:**  A list of potential mistakes and misunderstandings.

**Self-Correction/Refinement:**

During the process, I might have initially focused too heavily on internal details. I then shifted to ensure the explanation was understandable to someone familiar with web development, emphasizing the *user-facing* aspects of the `File` object. I also double-checked that my examples were clear and accurate. For instance, I made sure to distinguish between `lastModified` (number) and `lastModifiedDate` (Date object) in JavaScript.
这是一个位于 `blink/renderer/core/fileapi/file.cc` 的 Chromium Blink 引擎源代码文件，它主要负责实现 **JavaScript File API** 中的 `File` 接口。`File` 接口允许 Web 应用程序访问本地文件系统中的文件或者在内存中创建文件。

以下是该文件的功能列表，并附带与 JavaScript、HTML 和 CSS 的关系以及逻辑推理和常见错误的说明：

**功能列表：**

1. **表示文件:**  `File` 类用于在 Blink 渲染引擎中表示一个文件。这包括存储文件的元数据（名称、大小、最后修改时间）以及指向文件内容的句柄。
2. **创建 `File` 对象:** 文件中包含多种静态方法 (`Create`)，用于创建 `File` 对象的不同方式：
    * **从文件路径创建:** `CreateForUserProvidedFile`, `CreateWithRelativePath` 等方法根据文件路径和名称创建 `File` 对象。
    * **从 Blob 数据创建:** `Create` 方法允许从 `Blob` 对象片段创建新的 `File` 对象。
    * **从 `<input type="file">` 元素创建:**  `CreateFromControlState` 和 `PathFromControlState` 用于处理 HTML 表单中文件上传控件 (`<input type="file">`) 选择的文件。
    * **从文件系统 API 创建:** `CreateForFileSystemFile` 用于表示通过文件系统 API (如 `FileSystem`) 获取的文件。
3. **获取文件元数据:** 提供了方法来获取文件的基本属性：
    * `name()`: 获取文件名。
    * `size()`: 获取文件大小（字节）。
    * `lastModified()`: 获取文件最后修改时间的 Unix 时间戳（毫秒）。
    * `lastModifiedDate()`: 获取文件最后修改时间的 `Date` 对象。
4. **处理文件内容:**  虽然 `File` 对象本身不直接提供读取文件内容的方法（这是 `FileReader` 的职责），但它内部维护了一个 `BlobDataHandle`，用于管理文件的底层数据。
5. **确定 Content-Type:**  `GetContentTypeFromFileName` 函数根据文件名（主要是文件扩展名）来推断文件的 MIME 类型。
6. **与 Blob 集成:** `File` 类继承自 `Blob`，这意味着 `File` 对象也具备 `Blob` 的特性，例如可以被切片 (`slice()`)。
7. **处理表单数据:** `AppendToControlState` 方法用于将 `File` 对象的信息添加到表单数据 (`FormControlState`) 中，以便在提交表单时上传文件。
8. **快照管理:** `CaptureSnapshotIfNeeded` 方法用于延迟获取文件的元数据（大小和修改时间），这有助于提高性能，尤其是在处理大量文件时。
9. **判断文件来源:** `HasSameSource` 方法用于判断两个 `File` 对象是否指向同一个文件。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * `File` 类直接对应于 JavaScript 中的 `File` 接口。Web 开发者可以使用 JavaScript 创建、访问和操作 `File` 对象。
    * 例如，当用户通过 `<input type="file">` 选择文件后，JavaScript 可以通过 `event.target.files` 获取到一个 `FileList` 对象，其中包含了 `File` 对象。
    * 可以使用 `new File(bits, name, options)` 在 JavaScript 中创建新的 `File` 对象。
    * 可以访问 `File` 对象的 `name`, `size`, `lastModified` 等属性。
    * `File` 对象可以作为 `FormData` 的一部分用于发送 HTTP 请求。
* **HTML:**
    * `<input type="file">` 元素是用户选择本地文件的主要方式。当表单提交时，浏览器会将选择的文件信息封装成 `File` 对象。
    * `webkitRelativePath` 属性与 `<input type="file" webkitdirectory>` 属性相关，用于指示用户选择的目录结构中的相对路径。
* **CSS:**
    * CSS 本身不直接操作 `File` 对象。但是，可以使用 CSS 来样式化文件选择控件 (`<input type="file">`)。例如，可以改变按钮的样式，但 CSS 不能直接访问或修改 `File` 对象的内容或元数据。

**逻辑推理与示例：**

**假设输入：**

1. **JavaScript 代码:**
   ```javascript
   const fileInput = document.getElementById('myFile');
   const file = fileInput.files[0];

   console.log(file.name);
   console.log(file.size);
   console.log(new Date(file.lastModified));
   console.log(file.type); // 基于文件名推断的 MIME 类型
   ```
2. **HTML:**
   ```html
   <input type="file" id="myFile">
   ```
3. **用户操作:** 用户选择了一个名为 `image.png` 的文件，大小为 10240 字节，最后修改时间为 2023年10月26日 10:00:00。

**预期输出 (基于 `file.cc` 的逻辑):**

* `file.name`: "image.png"
* `file.size`: 10240
* `new Date(file.lastModified)`:  将会输出表示 2023年10月26日 10:00:00 的 Date 对象。
* `file.type`: "image/png" (因为 `GetContentTypeFromFileName` 会根据 `.png` 扩展名推断出 MIME 类型)。

**假设输入 (创建 File 对象):**

1. **JavaScript 代码:**
   ```javascript
   const blob = new Blob(['Hello, world!'], { type: 'text/plain' });
   const file = new File([blob], 'myTextFile.txt', { lastModified: Date.now() });

   console.log(file.name);
   console.log(file.size);
   console.log(new Date(file.lastModified));
   console.log(file.type);
   ```

**预期输出:**

* `file.name`: "myTextFile.txt"
* `file.size`: 13 (Blob 的大小)
* `new Date(file.lastModified)`: 将会输出表示当前时间的 Date 对象 (因为使用了 `Date.now()`)。
* `file.type`:  "" (如果 `Blob` 的 `type` 属性为空) 或者 "text/plain" (取决于 `Blob` 的 `type` 是否被设置)。 **注意：`File` 的 `type` 属性在从 `Blob` 创建时会继承 `Blob` 的 `type`。**

**用户或编程常见的使用错误：**

1. **假设 `File` 对象总是有 `path` 属性:** 实际上，出于安全考虑，Web 浏览器通常不会暴露文件的完整本地路径。`File` 对象可能没有 `path` 属性，或者该属性可能被限制访问。应该使用 `name` 属性来获取文件名。
   ```javascript
   const fileInput = document.getElementById('myFile');
   const file = fileInput.files[0];
   // 错误的做法：假设可以访问 file.path
   // 正确的做法：使用 file.name
   console.log(file.name);
   ```
2. **混淆 `lastModified` 和 `lastModifiedDate`:**  `lastModified` 返回的是 Unix 时间戳（毫秒数），而 `lastModifiedDate` 返回的是 `Date` 对象。需要根据需求选择正确的属性。
   ```javascript
   const fileInput = document.getElementById('myFile');
   const file = fileInput.files[0];

   console.log(file.lastModified); // 输出毫秒数
   console.log(file.lastModifiedDate); // 输出 Date 对象
   ```
3. **在文件上传前尝试读取文件内容:** `File` 对象本身不提供读取文件内容的方法。需要使用 `FileReader` API 来异步读取文件内容。
   ```javascript
   const fileInput = document.getElementById('myFile');
   const file = fileInput.files[0];

   // 错误的做法：直接尝试读取 file 的内容
   // console.log(file.content); // 错误！

   // 正确的做法：使用 FileReader
   const reader = new FileReader();
   reader.onload = function(event) {
       console.log(event.target.result); // 文件内容
   };
   reader.readAsText(file); // 以文本格式读取
   ```
4. **不正确地处理文件类型:**  依赖文件名扩展名来判断文件类型可能不准确。应该使用 `file.type` 属性，但这依赖于浏览器和操作系统提供的 MIME 类型信息。在需要精确判断文件类型时，可能需要读取文件内容的前几个字节（magic number）。
5. **在不支持 File API 的旧浏览器中使用:**  确保目标浏览器支持 File API。可以使用特性检测来避免在不支持的浏览器上出现错误。
   ```javascript
   if (window.File && window.FileReader && window.FileList && window.Blob) {
       // 支持 File API
       const fileInput = document.getElementById('myFile');
       // ...
   } else {
       alert('您的浏览器不支持 File API');
   }
   ```

总而言之，`blink/renderer/core/fileapi/file.cc` 文件是 Blink 引擎中实现 JavaScript `File` 接口的关键部分，它负责表示文件，管理文件元数据，并与浏览器中的文件上传机制和 JavaScript API 集成。理解其功能有助于开发者更好地使用和理解 Web 平台的文件处理能力。

### 提示词
```
这是目录为blink/renderer/core/fileapi/file.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/fileapi/file.h"

#include <memory>

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/public/mojom/filesystem/file_system.mojom-blink.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file_property_bag.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/file_backed_blob_factory_dispatcher.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

static String GetContentTypeFromFileName(const String& name,
                                         File::ContentTypeLookupPolicy policy) {
  String type;
  wtf_size_t index = name.ReverseFind('.');
  if (index != WTF::kNotFound) {
    if (policy == File::kWellKnownContentTypes) {
      type = MIMETypeRegistry::GetWellKnownMIMETypeForExtension(
          name.Substring(index + 1));
    } else {
      DCHECK_EQ(policy, File::kAllContentTypes);
      type =
          MIMETypeRegistry::GetMIMETypeForExtension(name.Substring(index + 1));
    }
  }
  return type;
}

static scoped_refptr<BlobDataHandle> CreateBlobDataHandleForFileWithType(
    ExecutionContext* context,
    const String& path,
    const String& content_type) {
  return BlobDataHandle::CreateForFile(
      FileBackedBlobFactoryDispatcher::GetFileBackedBlobFactory(context), path,
      /*offset=*/0, BlobData::kToEndOfFile,
      /*expected_modification_time=*/std::nullopt, content_type);
}

static scoped_refptr<BlobDataHandle> CreateBlobDataHandleForFile(
    ExecutionContext* context,
    const String& path,
    File::ContentTypeLookupPolicy policy) {
  if (path.empty()) {
    auto blob_data = std::make_unique<BlobData>();
    blob_data->SetContentType("application/octet-stream");
    return BlobDataHandle::Create(std::move(blob_data), /*size=*/0);
  }
  return CreateBlobDataHandleForFileWithType(
      context, path, GetContentTypeFromFileName(path, policy));
}

static scoped_refptr<BlobDataHandle> CreateBlobDataHandleForFileWithName(
    ExecutionContext* context,
    const String& path,
    const String& file_system_name,
    File::ContentTypeLookupPolicy policy) {
  return CreateBlobDataHandleForFileWithType(
      context, path, GetContentTypeFromFileName(file_system_name, policy));
}

static scoped_refptr<BlobDataHandle> CreateBlobDataHandleForFileWithMetadata(
    ExecutionContext* context,
    const String& file_system_name,
    const FileMetadata& metadata) {
  // We are creating a handle for a snapshot file. The FileSystemManager may
  // have to create a read permission needed on the browser side for this
  // operation. As the manager might revoke this permission directly after the
  // call, we have to ensure the permission is available while we create the
  // handle. So we need create a handle using the synchronous version of the
  // IPC.
  return BlobDataHandle::CreateForFileSync(
      FileBackedBlobFactoryDispatcher::GetFileBackedBlobFactory(context),
      metadata.platform_path,
      /*offset=*/0, metadata.length, metadata.modification_time,
      GetContentTypeFromFileName(file_system_name,
                                 File::kWellKnownContentTypes));
}

// static
File* File::Create(ExecutionContext* context,
                   const HeapVector<Member<V8BlobPart>>& file_bits,
                   const String& file_name,
                   const FilePropertyBag* options) {
  DCHECK(options->hasType());

  base::Time last_modified;
  if (options->hasLastModified()) {
    // We don't use base::Time::FromMillisecondsSinceUnixEpoch(double) here
    // because options->lastModified() is a 64-bit integer, and casting it to
    // double is lossy.
    last_modified =
        base::Time::UnixEpoch() + base::Milliseconds(options->lastModified());
  } else {
    last_modified = base::Time::Now();
  }
  DCHECK(options->hasEndings());
  bool normalize_line_endings_to_native = options->endings() == "native";
  if (normalize_line_endings_to_native)
    UseCounter::Count(context, WebFeature::kFileAPINativeLineEndings);

  auto blob_data = std::make_unique<BlobData>();
  blob_data->SetContentType(NormalizeType(options->type()));
  PopulateBlobData(blob_data.get(), file_bits,
                   normalize_line_endings_to_native);

  uint64_t file_size = blob_data->length();
  return MakeGarbageCollected<File>(
      file_name, last_modified,
      BlobDataHandle::Create(std::move(blob_data), file_size));
}

File* File::CreateFromControlState(ExecutionContext* context,
                                   const FormControlState& state,
                                   wtf_size_t& index) {
  if (index + 2 >= state.ValueSize()) {
    index = state.ValueSize();
    return nullptr;
  }
  String path = state[index++];
  String name = state[index++];
  String relative_path = state[index++];
  if (relative_path.empty())
    return File::CreateForUserProvidedFile(context, path, name);
  return File::CreateWithRelativePath(context, path, name, relative_path);
}

String File::PathFromControlState(const FormControlState& state,
                                  wtf_size_t& index) {
  if (index + 2 >= state.ValueSize()) {
    index = state.ValueSize();
    return String();
  }
  String path = state[index];
  index += 3;
  return path;
}

File* File::CreateWithRelativePath(ExecutionContext* context,
                                   const String& path,
                                   const String& name,
                                   const String& relative_path) {
  File* file = MakeGarbageCollected<File>(
      context, path, name, File::kAllContentTypes, File::kIsUserVisible);
  file->relative_path_ = relative_path;
  return file;
}

// static
File* File::CreateForFileSystemFile(ExecutionContext& context,
                                    const KURL& url,
                                    const FileMetadata& metadata,
                                    UserVisibility user_visibility) {
  String content_type = GetContentTypeFromFileName(
      url.GetPath().ToString(), File::kWellKnownContentTypes);
  // RegisterBlob doesn't take nullable strings.
  if (content_type.IsNull()) {
    content_type = g_empty_string;
  }

  scoped_refptr<BlobDataHandle> handle;
  CoreInitializer::GetInstance().GetFileSystemManager(&context).RegisterBlob(
      content_type, url, metadata.length, metadata.modification_time, &handle);

  return MakeGarbageCollected<File>(url, metadata, user_visibility, handle);
}

File::File(ExecutionContext* context,
           const String& path,
           ContentTypeLookupPolicy policy,
           UserVisibility user_visibility)
    : Blob(CreateBlobDataHandleForFile(context, path, policy)),
      has_backing_file_(true),
      user_visibility_(user_visibility),
      path_(path),
      name_(FilePathToWebString(WebStringToFilePath(path).BaseName())) {}

File::File(ExecutionContext* context,
           const String& path,
           const String& name,
           ContentTypeLookupPolicy policy,
           UserVisibility user_visibility)
    : Blob(CreateBlobDataHandleForFileWithName(context, path, name, policy)),
      has_backing_file_(true),
      user_visibility_(user_visibility),
      path_(path),
      name_(name) {}

File::File(const String& path,
           const String& name,
           const String& relative_path,
           UserVisibility user_visibility,
           bool has_snapshot_data,
           uint64_t size,
           const std::optional<base::Time>& last_modified,
           scoped_refptr<BlobDataHandle> blob_data_handle)
    : Blob(std::move(blob_data_handle)),
      has_backing_file_(!path.empty() || !relative_path.empty()),
      user_visibility_(user_visibility),
      path_(path),
      name_(name),
      snapshot_modification_time_(last_modified),
      relative_path_(relative_path) {
  if (has_snapshot_data)
    snapshot_size_ = size;
}

File::File(const String& name,
           const std::optional<base::Time>& modification_time,
           scoped_refptr<BlobDataHandle> blob_data_handle)
    : Blob(std::move(blob_data_handle)),
      has_backing_file_(false),
      user_visibility_(File::kIsNotUserVisible),
      name_(name),
      snapshot_modification_time_(modification_time) {
  uint64_t size = Blob::size();
  if (size != std::numeric_limits<uint64_t>::max())
    snapshot_size_ = size;
}

File::File(ExecutionContext* context,
           const String& name,
           const FileMetadata& metadata,
           UserVisibility user_visibility)
    : Blob(CreateBlobDataHandleForFileWithMetadata(context, name, metadata)),
      has_backing_file_(true),
      user_visibility_(user_visibility),
      path_(metadata.platform_path),
      name_(name),
      snapshot_modification_time_(metadata.modification_time) {
  if (metadata.length >= 0) {
    snapshot_size_ = metadata.length;
  }
}

File::File(const KURL& file_system_url,
           const FileMetadata& metadata,
           UserVisibility user_visibility,
           scoped_refptr<BlobDataHandle> blob_data_handle)
    : Blob(std::move(blob_data_handle)),
      has_backing_file_(false),
      user_visibility_(user_visibility),
      name_(DecodeURLEscapeSequences(file_system_url.LastPathComponent(),
                                     DecodeURLMode::kUTF8OrIsomorphic)),
      file_system_url_(file_system_url),
      snapshot_size_(metadata.length),
      snapshot_modification_time_(metadata.modification_time) {
  DCHECK_GE(metadata.length, 0);
}

File::File(const File& other)
    : Blob(other.GetBlobDataHandle()),
      has_backing_file_(other.has_backing_file_),
      user_visibility_(other.user_visibility_),
      path_(other.path_),
      name_(other.name_),
      file_system_url_(other.file_system_url_),
      snapshot_size_(other.snapshot_size_),
      snapshot_modification_time_(other.snapshot_modification_time_),
      relative_path_(other.relative_path_) {}

File* File::Clone(const String& name) const {
  File* file = MakeGarbageCollected<File>(*this);
  if (!name.IsNull())
    file->name_ = name;
  return file;
}

base::Time File::LastModifiedTime() const {
  CaptureSnapshotIfNeeded();

  if (HasValidSnapshotMetadata() && snapshot_modification_time_)
    return *snapshot_modification_time_;

  // lastModified / lastModifiedDate getters should return the current time
  // when the last modification time isn't known.
  return base::Time::Now();
}

int64_t File::lastModified() const {
  // lastModified returns a number, not a Date instance,
  // http://dev.w3.org/2006/webapi/FileAPI/#file-attrs
  return (LastModifiedTime() - base::Time::UnixEpoch()).InMilliseconds();
}

ScriptValue File::lastModifiedDate(ScriptState* script_state) const {
  // lastModifiedDate returns a Date instance,
  // http://www.w3.org/TR/FileAPI/#dfn-lastModifiedDate
  return ScriptValue(
      script_state->GetIsolate(),
      ToV8Traits<IDLNullable<IDLDate>>::ToV8(
          script_state, std::optional<base::Time>(LastModifiedTime())));
}

std::optional<base::Time> File::LastModifiedTimeForSerialization() const {
  CaptureSnapshotIfNeeded();

  return snapshot_modification_time_;
}

uint64_t File::size() const {
  CaptureSnapshotIfNeeded();

  // FIXME: JavaScript cannot represent sizes as large as uint64_t, we need
  // to come up with an exception to throw if file size is not representable.
  if (HasValidSnapshotMetadata())
    return *snapshot_size_;

  return 0;
}

void File::CaptureSnapshotIfNeeded() const {
  if (HasValidSnapshotMetadata() && snapshot_modification_time_)
    return;

  uint64_t snapshot_size;
  if (GetBlobDataHandle()->CaptureSnapshot(&snapshot_size,
                                           &snapshot_modification_time_)) {
    snapshot_size_ = snapshot_size;
  }
}

bool File::HasSameSource(const File& other) const {
  if (has_backing_file_ != other.has_backing_file_)
    return false;

  if (has_backing_file_)
    return path_ == other.path_;

  if (file_system_url_.IsEmpty() != other.file_system_url_.IsEmpty())
    return false;

  if (!file_system_url_.IsEmpty())
    return file_system_url_ == other.file_system_url_;

  return Uuid() == other.Uuid();
}

bool File::AppendToControlState(FormControlState& state) {
  // FIXME: handle Blob-backed File instances, see http://crbug.com/394948
  if (!HasBackingFile())
    return false;
  state.Append(GetPath());
  state.Append(name());
  state.Append(webkitRelativePath());
  return true;
}

}  // namespace blink
```