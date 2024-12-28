Response:
My thinking process to analyze the `blob_data.cc` file and answer the prompt goes like this:

1. **Understand the Goal:** The prompt asks for the functionality of `blob_data.cc`, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common usage errors.

2. **Identify the Core Abstraction:** The filename and the initial imports (`#include "third_party/blink/renderer/platform/blob/blob_data.h"`) immediately suggest that this file deals with `Blob` objects within the Blink rendering engine. `Blob` is a fundamental web API, so I know it's related to JavaScript and data handling.

3. **Scan for Key Classes/Structures:** I look for the main classes defined in the file. The presence of `BlobData` and `BlobDataHandle` is prominent. These are likely the core components for representing and managing blob data.

4. **Analyze `BlobData`:**
    * **Constructor and Destructor:**  A default constructor and destructor provide basic lifecycle management. The constructor takes `FileCompositionStatus`, hinting at how blobs are composed (potentially from files).
    * **`ReleaseElements()`:** This function suggests that a `BlobData` internally holds a collection of "elements". The return type `Vector<mojom::blink::DataElementPtr>` confirms this and points to the `mojom` interface definition, which is a way Chromium defines inter-process communication structures.
    * **`SetContentType()`:**  This directly maps to the `type` property of a JavaScript `Blob` object. The validation logic (`IsValidBlobType`) is important to note.
    * **`AppendData()`, `AppendBlob()`, `AppendText()`, `AppendBytes()`:** These are the key functions for building a `BlobData`. They reveal how different data sources (raw data, other blobs, text, byte arrays) are incorporated. The normalization of line endings in `AppendText` is an interesting detail.
    * **`length()`:**  This corresponds directly to the `size` property of a JavaScript `Blob`.
    * **`AppendDataInternal()`:** This is a private helper for efficiently adding byte data, potentially embedding small chunks directly or using a `BlobBytesProvider` for larger amounts. This optimization detail is worth noting.

5. **Analyze `BlobDataHandle`:**
    * **Creation Methods (`CreateForFile`, `CreateForFileSync`, `Create`):** These static methods illustrate different ways to create `BlobDataHandle` instances, notably from files and existing `Blob` remotes. The "sync" version suggests performance implications.
    * **Constructor Overloads:**  The various constructors indicate different initialization scenarios, including creating empty blobs, wrapping existing `BlobData`, and referencing file-backed blobs.
    * **`CloneBlobRemote()`:** This is crucial for understanding how `Blob` objects are shared and passed around, especially in a multi-process environment. Cloning ensures that different parts of the system can interact with the blob without race conditions.
    * **`AsDataPipeGetter()` and `ReadAll()`:** These methods connect `Blob` to data streaming mechanisms, likely used for efficient transfer of large amounts of data.
    * **`CaptureSnapshot()`:**  This method suggests the ability to get metadata about the blob (size and modification time) without necessarily reading all the data.
    * **`GetBlobRegistry()` and `SetBlobRegistryForTesting()`:**  These methods reveal the existence of a global or thread-local `BlobRegistry` responsible for managing `Blob` objects. The "testing" variant is important for unit tests.

6. **Connect to Web Technologies:**
    * **JavaScript:** The `Blob` API in JavaScript is the primary connection. Functions like `SetContentType`, `length`, and the methods for creating blobs directly correspond. The file highlights how the browser engine implements the JavaScript `Blob` API.
    * **HTML:**  The `<input type="file">` element and drag-and-drop APIs are the most relevant HTML connections. These provide the initial data sources for creating `Blob` objects. The `BlobDataHandle::CreateForFile` methods are directly involved in handling file inputs.
    * **CSS:** While less direct, `Blob` objects can be used in CSS, for example, as the source for `url()` for background images or in `content` properties (though this is less common for direct `Blob` usage). The file itself doesn't directly interact with CSS parsing or rendering but provides the underlying data.

7. **Identify Logical Reasoning and Assumptions:**
    * **Data Embedding:** The decision to embed small byte arrays directly (`DataElementBytes::kMaximumEmbeddedDataSize`) is a performance optimization. The assumption is that for small amounts of data, embedding is faster than managing a separate data provider.
    * **Unknown Size Files:** The handling of files with unknown sizes and the restrictions on appending other data are logical consequences of how these files are processed. The assumption is that you can't easily determine the final size if you mix unknown-size files with other data sources.
    * **Line Ending Normalization:** The `NormalizeLineEndingsToNative` function reflects the need to handle different operating system conventions for line breaks when creating text blobs.

8. **Consider Common Usage Errors:**
    * **Invalid `Blob` Type:** The `IsValidBlobType` function highlights a potential error: providing an invalid MIME type string.
    * **Appending to Unknown Size File Blobs:** The code explicitly checks for and disallows appending data to a blob that already contains a single unknown-size file without specifying a size. This is a likely usage error.
    * **Incorrect Offset/Length:** When using `AppendBlob` or creating blobs from files, providing incorrect offset or length values could lead to data corruption or unexpected behavior. While the code doesn't explicitly *detect* all such errors, understanding the parameters is crucial for correct usage.
    * **Concurrency Issues:** While the code uses mutexes (`blob_remote_lock_`), incorrect usage of `BlobDataHandle` in a multithreaded environment could lead to issues.

9. **Structure the Answer:** Finally, I organize the gathered information into the requested categories: functionality, relationship to web technologies (with examples), logical reasoning (with assumptions and I/O), and common usage errors. I use clear headings and bullet points to make the information easy to read and understand. I also include the requested input and output examples for logical reasoning.

This systematic approach, breaking down the code into smaller parts and understanding the purpose of each part, helps in comprehensively analyzing the functionality and its implications.

好的，让我们来分析一下 `blink/renderer/platform/blob/blob_data.cc` 这个文件。

**功能概述:**

`blob_data.cc` 文件是 Chromium Blink 引擎中负责管理 `Blob` (Binary Large Object) 数据表示的核心组件。它的主要功能包括：

1. **Blob 数据的创建和管理:**  它定义了 `BlobData` 类，该类用于存储构成一个 `Blob` 的数据片段，可以包含以下类型的片段：
    * **Bytes:** 直接存储的字节数据。
    * **File:**  指向文件系统中某个文件的引用（包含偏移量和长度）。
    * **Blob:**  对另一个已存在的 `Blob` 的引用（包含偏移量和长度）。
2. **Blob 元数据的管理:**  `BlobData` 存储了 `Blob` 的内容类型 (content type)。
3. **Blob 注册:**  通过 `BlobDataHandle` 类，将创建的 `Blob` 注册到全局的 `BlobRegistry` 中，使其可以通过唯一的 UUID 进行访问和共享。
4. **Blob 数据的拼接和组合:** 提供了 `AppendData`, `AppendBlob`, `AppendText`, `AppendBytes` 等方法，允许将不同来源的数据片段组合成一个新的 `Blob`。
5. **Blob 数据的克隆和共享:**  `BlobDataHandle` 允许安全地克隆 `Blob` 的引用，以便在不同的组件或进程中共享 `Blob` 数据。
6. **Blob 数据到数据管道的转换:** 提供了将 `Blob` 数据转换为 `DataPipeGetter` 的功能，用于高效地将 `Blob` 数据流式传输到其他组件。
7. **文件支持的 Blob:**  通过与 `FileBackedBlobFactory` 的交互，支持创建基于文件系统的 `Blob`，避免将整个文件内容加载到内存中。
8. **线程安全管理:** 使用锁 (`blob_remote_lock_`) 来保护 `Blob` 远程接口的访问，确保在多线程环境下的安全性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`blob_data.cc` 文件是 Web API `Blob` 的底层实现，因此与 JavaScript 和 HTML 密切相关。CSS 的关联相对间接。

* **JavaScript:**
    * **`Blob` 构造函数:** 当 JavaScript 代码中创建 `Blob` 对象时，例如 `new Blob(['hello'], {type: 'text/plain'})`，Blink 引擎会创建对应的 `BlobData` 对象来存储数据 (`'hello'`) 和元数据 (`type: 'text/plain'`)。
        * **假设输入（JavaScript）:**
          ```javascript
          const blob = new Blob(['This is text.'], { type: 'text/plain' });
          ```
        * **输出（`blob_data.cc` 相关的内部状态）:**
          * 创建一个 `BlobData` 对象。
          * `content_type_` 被设置为 "text/plain"。
          * `elements_` 包含一个 `DataElementBytes`，其中存储了 "This is text." 的 UTF-8 编码。
    * **`FileReader` API:** 当 JavaScript 使用 `FileReader` 读取 `Blob` 的内容时，Blink 引擎会通过 `BlobDataHandle` 获取 `Blob` 数据，并将其传递给 `FileReader`。
    * **`URL.createObjectURL()`:** 当 JavaScript 使用 `URL.createObjectURL(blob)` 创建一个指向 `Blob` 数据的 URL 时，Blink 引擎会使用 `BlobRegistry` 来管理这个 `Blob`，并生成一个可以访问该 `Blob` 的 URL。
    * **`FormData` API:** 当 JavaScript 使用 `FormData` 发送包含 `Blob` 的表单数据时，Blink 引擎会将 `Blob` 数据包含在请求体中。

* **HTML:**
    * **`<input type="file">` 元素:** 当用户通过 `<input type="file">` 元素选择文件时，Blink 引擎会为每个选择的文件创建一个 `Blob` 对象。`BlobDataHandle::CreateForFile` 或 `BlobDataHandle::CreateForFileSync` 等方法会被调用来创建基于文件的 `Blob`。
        * **假设输入（用户操作）：** 用户在 `<input type="file">` 元素中选择了一个名为 "image.png" 的图片文件。
        * **输出（`blob_data.cc` 相关的内部状态）:**
          * 调用 `BlobDataHandle::CreateForFile`。
          * 创建一个 `BlobDataHandle`，其中包含一个 `DataElementFile`，指向 "image.png" 文件的路径、偏移量（通常为 0）和长度。
          * `content_type_` 可能会根据文件扩展名或内容嗅探来设置。
    * **拖放 API:** 当用户将文件拖放到浏览器窗口时，Blink 引擎会为拖放的文件创建 `Blob` 对象。

* **CSS:**
    * **`url()` 函数:** 虽然 CSS 本身不直接操作 `Blob` 对象，但 JavaScript 可以使用 `URL.createObjectURL()` 创建指向 `Blob` 数据的 URL，然后在 CSS 的 `url()` 函数中使用，例如作为背景图片。
        * **假设输入（JavaScript & CSS）：**
          ```javascript
          const blob = new Blob(['<svg>...</svg>'], { type: 'image/svg+xml' });
          const url = URL.createObjectURL(blob);
          // 然后在 CSS 中使用
          // .element { background-image: url(blob:...) }
          ```
        * **输出（`blob_data.cc` 相关的内部状态）:**
          * 创建一个 `BlobData` 对象，存储 SVG 数据。
          * `BlobRegistry` 中注册了这个 `Blob`，并生成了一个 `blob:` 协议的 URL。

**逻辑推理与假设输入输出:**

* **假设输入:**  JavaScript 代码尝试创建一个由两部分组成的 `Blob`：一段文本和一个小型的字节数组。
  ```javascript
  const textPart = 'Hello, ';
  const byteArrayPart = new Uint8Array([97, 98, 99]); // a, b, c
  const blob = new Blob([textPart, byteArrayPart], { type: 'text/plain' });
  ```
* **`blob_data.cc` 中的逻辑推理:**
    * `BlobData::AppendText` 会被调用处理 `textPart`，将其编码为 UTF-8 并存储为一个 `DataElementBytes`。
    * `BlobData::AppendBytes` 会被调用处理 `byteArrayPart`，将其存储为另一个 `DataElementBytes`。
    * 由于字节数组很小，`AppendDataInternal` 可能会选择将其直接嵌入到 `DataElementBytes` 的 `embedded_data` 中，而不是创建一个单独的 `BlobBytesProvider`。
* **输出（`blob_data.cc` 相关的内部状态）:**
    * `content_type_` 被设置为 "text/plain"。
    * `elements_` 包含两个 `DataElement`：
        * 第一个 `DataElementBytes` 存储 "Hello, " 的 UTF-8 编码。
        * 第二个 `DataElementBytes` 的 `embedded_data` 中存储了字节 [97, 98, 99]。

**用户或编程常见的使用错误:**

1. **尝试修改已创建的 Blob 数据:** `Blob` 对象在创建后是不可变的。尝试修改 `Blob` 的内容是不允许的。程序员需要创建一个新的 `Blob` 来表示修改后的数据。
2. **创建具有无效 MIME 类型的 Blob:**  `BlobData::SetContentType` 中检查了 MIME 类型的有效性。如果传入无效的字符，内容类型会被设置为空字符串。
    * **举例:** `new Blob(['data'], { type: 'invalid-mime!@#$' })` 会创建一个 `Blob`，但其 `type` 属性将为空字符串。
3. **在不指定大小的情况下，将未知大小的文件 Blob 与其他数据组合:** 代码中明确指出，包含未知大小文件的 `Blob` 不能与其他数据项组合，除非该文件是唯一的组成部分。
    * **举例:** 假设从 `<input type="file">` 获取了一个大小未知的流式文件（某些特殊类型的文件可能出现这种情况），然后尝试 `new Blob([fileBlob, 'some text'])` 会导致错误或不期望的行为。
4. **错误地计算偏移量和长度:** 在使用 `AppendBlob` 或创建基于文件的 `Blob` 时，如果提供的偏移量或长度超出实际数据范围，可能会导致读取错误或数据不完整。
5. **忘记释放 `URL.createObjectURL()` 创建的 URL:** 通过 `URL.createObjectURL()` 创建的 URL 会持有对 `Blob` 数据的引用。如果不再需要这些 URL，应该使用 `URL.revokeObjectURL()` 来释放资源，否则可能导致内存泄漏。

总而言之，`blob_data.cc` 是 Blink 引擎中 `Blob` 功能的核心实现，负责 `Blob` 数据的存储、管理和与其他 Web 技术的集成。理解其功能有助于开发者更好地理解和使用 `Blob` API。

Prompt: 
```
这是目录为blink/renderer/platform/blob/blob_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
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

#include "third_party/blink/renderer/platform/blob/blob_data.h"

#include <memory>
#include <utility>

#include "base/check_is_test.h"
#include "base/containers/span.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/network/public/mojom/data_pipe_getter.mojom-blink.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/blob/blob.mojom-blink.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"
#include "third_party/blink/public/mojom/blob/data_element.mojom-blink.h"
#include "third_party/blink/public/mojom/blob/file_backed_blob_factory.mojom-blink.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/blob/blob_bytes_provider.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/line_ending.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

using mojom::blink::BytesProvider;
using mojom::blink::DataElement;
using mojom::blink::DataElementBlob;
using mojom::blink::DataElementBytes;
using mojom::blink::DataElementBytesPtr;
using mojom::blink::DataElementFile;
using mojom::blink::DataElementPtr;

namespace {

// http://dev.w3.org/2006/webapi/FileAPI/#constructorBlob
bool IsValidBlobType(const String& type) {
  for (unsigned i = 0; i < type.length(); ++i) {
    UChar c = type[i];
    if (c < 0x20 || c > 0x7E)
      return false;
  }
  return true;
}

mojom::blink::BlobRegistry* g_blob_registry_for_testing = nullptr;

mojom::blink::BlobRegistry* GetThreadSpecificRegistry() {
  if (g_blob_registry_for_testing) [[unlikely]] {
    return g_blob_registry_for_testing;
  }

  DEFINE_THREAD_SAFE_STATIC_LOCAL(
      ThreadSpecific<mojo::Remote<mojom::blink::BlobRegistry>>, registry, ());
  if (!registry.IsSet()) [[unlikely]] {
    // TODO(mek): Going through BrowserInterfaceBroker to get a
    // mojom::blink::BlobRegistry ends up going through the main thread. Ideally
    // workers wouldn't need to do that.
    Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
        (*registry).BindNewPipeAndPassReceiver());
  }
  return registry->get();
}

}  // namespace

constexpr int64_t BlobData::kToEndOfFile;

RawData::RawData() = default;

BlobData::BlobData(FileCompositionStatus composition)
    : file_composition_(composition) {}

BlobData::~BlobData() = default;

Vector<mojom::blink::DataElementPtr> BlobData::ReleaseElements() {
  if (last_bytes_provider_) {
    DCHECK(last_bytes_provider_receiver_);
    BlobBytesProvider::Bind(std::move(last_bytes_provider_),
                            std::move(last_bytes_provider_receiver_));
  }

  return std::move(elements_);
}

void BlobData::SetContentType(const String& content_type) {
  if (IsValidBlobType(content_type))
    content_type_ = content_type;
  else
    content_type_ = "";
}

void BlobData::AppendData(scoped_refptr<RawData> data) {
  AppendDataInternal(base::span(*data), data);
}

void BlobData::AppendBlob(scoped_refptr<BlobDataHandle> data_handle,
                          int64_t offset,
                          int64_t length) {
  DCHECK_EQ(file_composition_, FileCompositionStatus::kNoUnknownSizeFiles)
      << "Blobs with a unknown-size file cannot have other items.";
  DCHECK(!data_handle->IsSingleUnknownSizeFile() ||
         length != BlobData::kToEndOfFile)
      << "It is illegal to append an unknown size file blob without specifying "
         "a size.";
  // Skip zero-byte items, as they don't matter for the contents of the blob.
  if (length == 0)
    return;
  elements_.push_back(DataElement::NewBlob(
      DataElementBlob::New(data_handle->CloneBlobRemote(), offset, length)));
}

void BlobData::AppendText(const String& text,
                          bool do_normalize_line_endings_to_native) {
  DCHECK_EQ(file_composition_, FileCompositionStatus::kNoUnknownSizeFiles)
      << "Blobs with a unknown-size file cannot have other items.";
  std::string utf8_text = UTF8Encoding().Encode(text, WTF::kNoUnencodables);

  if (do_normalize_line_endings_to_native) {
    if (utf8_text.length() >
        BlobBytesProvider::kMaxConsolidatedItemSizeInBytes) {
      auto raw_data = RawData::Create();
      NormalizeLineEndingsToNative(utf8_text, *raw_data->MutableData());
      AppendDataInternal(base::span(*raw_data), raw_data);
    } else {
      Vector<char> buffer;
      NormalizeLineEndingsToNative(utf8_text, buffer);
      AppendDataInternal(base::make_span(buffer));
    }
  } else {
    AppendDataInternal(base::span(utf8_text));
  }
}

void BlobData::AppendBytes(base::span<const uint8_t> bytes) {
  AppendDataInternal(base::as_chars(bytes));
}

uint64_t BlobData::length() const {
  uint64_t length = 0;

  for (const auto& element : elements_) {
    switch (element->which()) {
      case DataElement::Tag::kBytes:
        length += element->get_bytes()->length;
        break;
      case DataElement::Tag::kFile:
        length += element->get_file()->length;
        break;
      case DataElement::Tag::kBlob:
        length += element->get_blob()->length;
        break;
    }
  }
  return length;
}

void BlobData::AppendDataInternal(base::span<const char> data,
                                  scoped_refptr<RawData> raw_data) {
  DCHECK_EQ(file_composition_, FileCompositionStatus::kNoUnknownSizeFiles)
      << "Blobs with a unknown-size file cannot have other items.";
  // Skip zero-byte items, as they don't matter for the contents of the blob.
  if (data.empty())
    return;
  bool should_embed_bytes = current_memory_population_ + data.size() <=
                            DataElementBytes::kMaximumEmbeddedDataSize;
  if (!elements_.empty() && elements_.back()->is_bytes()) {
    // Append bytes to previous element.
    DCHECK(last_bytes_provider_);
    DCHECK(last_bytes_provider_receiver_);
    const auto& bytes_element = elements_.back()->get_bytes();
    bytes_element->length += data.size();
    if (should_embed_bytes && bytes_element->embedded_data) {
      bytes_element->embedded_data->AppendSpan(data);
      current_memory_population_ += data.size();
    } else if (bytes_element->embedded_data) {
      current_memory_population_ -= bytes_element->embedded_data->size();
      bytes_element->embedded_data = std::nullopt;
    }
  } else {
    if (last_bytes_provider_) {
      // If `last_bytes_provider_` is set, but the previous element is not a
      // bytes element, a new BytesProvider will be created and we need to
      // make sure to bind the previous one first.
      DCHECK(last_bytes_provider_receiver_);
      BlobBytesProvider::Bind(std::move(last_bytes_provider_),
                              std::move(last_bytes_provider_receiver_));
    }
    mojo::PendingRemote<BytesProvider> bytes_provider_remote;
    last_bytes_provider_ = std::make_unique<BlobBytesProvider>();
    last_bytes_provider_receiver_ =
        bytes_provider_remote.InitWithNewPipeAndPassReceiver();

    auto bytes_element = DataElementBytes::New(
        data.size(), std::nullopt, std::move(bytes_provider_remote));
    if (should_embed_bytes) {
      bytes_element->embedded_data = Vector<uint8_t>();
      bytes_element->embedded_data->AppendSpan(data);
      current_memory_population_ += data.size();
    }
    elements_.push_back(DataElement::NewBytes(std::move(bytes_element)));
  }
  if (raw_data)
    last_bytes_provider_->AppendData(std::move(raw_data));
  else
    last_bytes_provider_->AppendData(std::move(data));
}

// static
scoped_refptr<BlobDataHandle> BlobDataHandle::CreateForFile(
    mojom::blink::FileBackedBlobFactory* file_backed_blob_factory,
    const String& path,
    int64_t offset,
    int64_t length,
    const std::optional<base::Time>& expected_modification_time,
    const String& content_type) {
  mojom::blink::DataElementFilePtr element = mojom::blink::DataElementFile::New(
      WebStringToFilePath(path), offset, length, expected_modification_time);
  uint64_t size = length == BlobData::kToEndOfFile
                      ? std::numeric_limits<uint64_t>::max()
                      : length;
  return base::AdoptRef(new BlobDataHandle(
      file_backed_blob_factory, std::move(element), content_type, size));
}

// static
scoped_refptr<BlobDataHandle> BlobDataHandle::CreateForFileSync(
    mojom::blink::FileBackedBlobFactory* file_backed_blob_factory,
    const String& path,
    int64_t offset,
    int64_t length,
    const std::optional<base::Time>& expected_modification_time,
    const String& content_type) {
  mojom::blink::DataElementFilePtr element = mojom::blink::DataElementFile::New(
      WebStringToFilePath(path), offset, length, expected_modification_time);
  uint64_t size = length == BlobData::kToEndOfFile
                      ? std::numeric_limits<uint64_t>::max()
                      : length;
  return base::AdoptRef(new BlobDataHandle(
      file_backed_blob_factory, std::move(element), content_type, size, true));
}

// static
scoped_refptr<BlobDataHandle> BlobDataHandle::Create(
    const String& uuid,
    const String& type,
    uint64_t size,
    mojo::PendingRemote<mojom::blink::Blob> blob_remote) {
  CHECK(blob_remote.is_valid());
  return base::AdoptRef(
      new BlobDataHandle(uuid, type, size, std::move(blob_remote)));
}

BlobDataHandle::BlobDataHandle()
    : uuid_(WTF::CreateCanonicalUUIDString()),
      size_(0),
      is_single_unknown_size_file_(false) {
  GetThreadSpecificRegistry()->Register(
      blob_remote_.InitWithNewPipeAndPassReceiver(), uuid_, "", "", {});
}

BlobDataHandle::BlobDataHandle(std::unique_ptr<BlobData> data, uint64_t size)
    : uuid_(WTF::CreateCanonicalUUIDString()),
      type_(data->ContentType()),
      size_(size),
      is_single_unknown_size_file_(data->IsSingleUnknownSizeFile()) {
  auto elements = data->ReleaseElements();
  TRACE_EVENT0("Blob", "Registry::RegisterBlob");
  GetThreadSpecificRegistry()->Register(
      blob_remote_.InitWithNewPipeAndPassReceiver(), uuid_,
      type_.IsNull() ? "" : type_, "", std::move(elements));
}

BlobDataHandle::BlobDataHandle(
    mojom::blink::FileBackedBlobFactory* file_backed_blob_factory,
    mojom::blink::DataElementFilePtr file_element,
    const String& content_type,
    uint64_t size,
    bool synchronous_register)
    : uuid_(WTF::CreateCanonicalUUIDString()),
      type_(content_type),
      size_(size),
      is_single_unknown_size_file_(size ==
                                   std::numeric_limits<uint64_t>::max()) {
  if (file_backed_blob_factory) {
    if (synchronous_register) {
      file_backed_blob_factory->RegisterBlobSync(
          blob_remote_.InitWithNewPipeAndPassReceiver(), uuid_,
          type_.IsNull() ? "" : type_, std::move(file_element));
    } else {
      file_backed_blob_factory->RegisterBlob(
          blob_remote_.InitWithNewPipeAndPassReceiver(), uuid_,
          type_.IsNull() ? "" : type_, std::move(file_element));
    }
  } else {
    // TODO(b/287417238): Temporarily fallback to the previous BlobRegistry
    // registration when new interface is disabled by its feature flag or the
    // interface is not bound to a frame.
    Vector<mojom::blink::DataElementPtr> elements;
    elements.push_back(DataElement::NewFile(std::move(file_element)));
    TRACE_EVENT0("Blob", "Registry::RegisterBlob");
    GetThreadSpecificRegistry()->Register(
        blob_remote_.InitWithNewPipeAndPassReceiver(), uuid_,
        type_.IsNull() ? "" : type_, "", std::move(elements));
  }
}

BlobDataHandle::BlobDataHandle(const String& uuid,
                               const String& type,
                               uint64_t size)
    : uuid_(uuid),
      type_(IsValidBlobType(type) ? type : ""),
      size_(size),
      is_single_unknown_size_file_(false) {
  // This is only used by unit tests that won't access `blob_remote_`.
  CHECK_IS_TEST();
}

BlobDataHandle::BlobDataHandle(
    const String& uuid,
    const String& type,
    uint64_t size,
    mojo::PendingRemote<mojom::blink::Blob> blob_remote)
    : uuid_(uuid),
      type_(IsValidBlobType(type) ? type : ""),
      size_(size),
      is_single_unknown_size_file_(false),
      blob_remote_(std::move(blob_remote)) {
  DCHECK(blob_remote_.is_valid());
}

BlobDataHandle::~BlobDataHandle() = default;

mojo::PendingRemote<mojom::blink::Blob> BlobDataHandle::CloneBlobRemote() {
  base::AutoLock locker(blob_remote_lock_);
  if (!blob_remote_.is_valid())
    return mojo::NullRemote();
  mojo::Remote<mojom::blink::Blob> blob(std::move(blob_remote_));
  mojo::PendingRemote<mojom::blink::Blob> blob_clone;
  blob->Clone(blob_clone.InitWithNewPipeAndPassReceiver());
  blob_remote_ = blob.Unbind();
  return blob_clone;
}

void BlobDataHandle::CloneBlobRemote(
    mojo::PendingReceiver<mojom::blink::Blob> receiver) {
  base::AutoLock locker(blob_remote_lock_);
  if (!blob_remote_.is_valid())
    return;
  mojo::Remote<mojom::blink::Blob> blob(std::move(blob_remote_));
  blob->Clone(std::move(receiver));
  blob_remote_ = blob.Unbind();
}

mojo::PendingRemote<network::mojom::blink::DataPipeGetter>
BlobDataHandle::AsDataPipeGetter() {
  base::AutoLock locker(blob_remote_lock_);
  if (!blob_remote_.is_valid())
    return mojo::NullRemote();
  mojo::PendingRemote<network::mojom::blink::DataPipeGetter> result;
  mojo::Remote<mojom::blink::Blob> blob(std::move(blob_remote_));
  blob->AsDataPipeGetter(result.InitWithNewPipeAndPassReceiver());
  blob_remote_ = blob.Unbind();
  return result;
}

void BlobDataHandle::ReadAll(
    mojo::ScopedDataPipeProducerHandle pipe,
    mojo::PendingRemote<mojom::blink::BlobReaderClient> client) {
  base::AutoLock locker(blob_remote_lock_);
  mojo::Remote<mojom::blink::Blob> blob(std::move(blob_remote_));
  blob->ReadAll(std::move(pipe), std::move(client));
  blob_remote_ = blob.Unbind();
}

bool BlobDataHandle::CaptureSnapshot(
    uint64_t* snapshot_size,
    std::optional<base::Time>* snapshot_modification_time) {
  // This method operates on a cloned blob remote; this lets us avoid holding
  // the |blob_remote_lock_| locked during the duration of the (synchronous)
  // CaptureSnapshot call.
  mojo::Remote<mojom::blink::Blob> remote(CloneBlobRemote());
  return remote->CaptureSnapshot(snapshot_size, snapshot_modification_time);
}

// static
mojom::blink::BlobRegistry* BlobDataHandle::GetBlobRegistry() {
  return GetThreadSpecificRegistry();
}

// static
void BlobDataHandle::SetBlobRegistryForTesting(
    mojom::blink::BlobRegistry* registry) {
  g_blob_registry_for_testing = registry;
}

}  // namespace blink

"""

```