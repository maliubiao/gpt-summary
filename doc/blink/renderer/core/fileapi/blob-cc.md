Response:
Let's break down the thought process for analyzing the `blob.cc` file and generating the comprehensive explanation.

1. **Understand the Request:** The core request is to analyze a specific Chromium Blink engine source file (`blob.cc`) and describe its functionality, its relationship with web technologies (JavaScript, HTML, CSS), provide examples with hypothetical inputs and outputs for logical inferences, and highlight potential user/programming errors.

2. **Initial File Scan (Keywords and Imports):**  The first step is to quickly scan the file for keywords and included headers. This gives a high-level overview:
    * **Keywords:** `Blob`, `FileReader`, `ArrayBuffer`, `USVString`, `slice`, `stream`, `text`, `arrayBuffer`, `ContentType`, `BlobData`, `BlobDataHandle`, `URLRegistry`. These suggest the file deals with the Blob API, reading and manipulating binary data, and potentially URLs associated with blobs.
    * **Imports:**  Headers like `v8_blob_property_bag.h`, `v8_union_arraybuffer_arraybufferview_blob_usvstring.h` strongly indicate interaction with JavaScript's Blob API and its related data types. Headers like `execution_context.h`, `file_reader_client.h`, `file_reader_loader.h` point towards the internal mechanisms for handling file/blob reading operations within Blink. The `fetch` directory imports hint at Blob's connection to network requests. `platform/blob/blob_url.h` confirms URL association.

3. **Core Functionality Identification:** Based on the keywords and imports, the primary function of `blob.cc` is to implement the `Blob` interface within the Chromium rendering engine (Blink). This involves:
    * **Creation:** Constructing `Blob` objects from various sources (other Blobs, ArrayBuffers, strings). The `Create` methods confirm this.
    * **Slicing:** Creating new `Blob` objects representing a portion of an existing `Blob` (`slice` method).
    * **Reading:** Providing methods to read the contents of a `Blob` as text (`text`), an ArrayBuffer (`arrayBuffer`), or a stream (`stream`).
    * **Internal Data Handling:**  Managing the underlying binary data of a `Blob` using `BlobDataHandle` and `BlobData`.
    * **Type Management:** Handling the `type` (MIME type) of a `Blob`.
    * **URL Association:**  Potentially managing URLs associated with Blobs (though the `NullURLRegistry` suggests this might be deprecated or handled elsewhere).

4. **Relationship with Web Technologies:** This is where the connections to JavaScript, HTML, and CSS are explored:
    * **JavaScript:**  The most direct connection. The `Blob` class is a core JavaScript API. The code directly interacts with V8 (JavaScript engine) types like `ArrayBuffer`, and uses `ScriptPromise` for asynchronous operations, which are fundamental to JavaScript's interaction with Blobs. Examples of creating, slicing, and reading blobs in JavaScript are crucial here.
    * **HTML:** Blobs are often used in conjunction with HTML elements, especially `<input type="file">` for file uploads, `<a>` tags for downloading, and `<img>` tags (via `URL.createObjectURL`). Examples showcasing these scenarios are necessary.
    * **CSS:** While less direct, Blobs can indirectly interact with CSS through techniques like using a Blob URL as the `src` of an `<img>` element, which CSS can then style.

5. **Logical Inference and Examples:**  Analyze the code for specific logic and provide illustrative examples:
    * **`IsValidBlobType` and `NormalizeType`:**  Focus on how the `type` property is validated and normalized. Provide examples of valid and invalid types and the output of the normalization.
    * **`ClampSliceOffsets`:** This function has clear logic for handling start and end offsets. Provide examples with different positive, negative, and out-of-bounds inputs and show the resulting clamped values.
    * **Asynchronous Reading (`text`, `arrayBuffer`):**  Emphasize the asynchronous nature and the use of Promises. Explain that the code initiates a read operation and resolves the Promise when the data is available.

6. **User and Programming Errors:** Think about common mistakes developers make when working with the Blob API:
    * **Incorrect `type`:** Providing invalid characters in the `type` string.
    * **Incorrect `endings`:** Misunderstanding the `endings` option for line ending normalization.
    * **Incorrect slice parameters:**  Providing `start` and `end` values that lead to unexpected results (e.g., `end` being less than `start`).
    * **Asynchronous issues:**  Not handling the Promises returned by `text` and `arrayBuffer` correctly, leading to race conditions or unhandled rejections.
    * **Memory Management (though less obvious from this code snippet):**  While not directly evident here, developers might forget to revoke Blob URLs created with `URL.createObjectURL`, leading to memory leaks. (Though this file doesn't handle URL creation).

7. **Structure and Refinement:**  Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Detail the core functionalities.
    * Explain the relationships with web technologies with clear examples.
    * Provide specific examples of logical inferences with hypothetical inputs and outputs.
    * List common user/programming errors.
    * Use clear and precise language.

8. **Review and Verification:**  Read through the explanation to ensure accuracy and completeness. Check that the examples are correct and easy to understand. Ensure all parts of the request have been addressed. For instance, initially, I might have focused too much on the internal data structures. Reviewing the request would remind me to emphasize the web technology connections.

By following these steps, one can systematically analyze the given source code and generate a comprehensive and helpful explanation like the example provided in the initial prompt. The key is to combine code understanding with knowledge of the relevant web technologies and common developer practices.
这是 `blink/renderer/core/fileapi/blob.cc` 文件的分析，它主要负责实现 Chromium Blink 引擎中 `Blob` 接口的功能。`Blob` (Binary Large Object) 在 Web 开发中用于表示不可变的原始数据。

**文件功能列表:**

1. **`Blob` 对象的创建:**
   - 提供了多种静态方法 (`Create`) 来创建 `Blob` 对象，可以从以下来源创建：
     - 由 `ArrayBuffer`, `ArrayBufferView`, 其他 `Blob` 对象, 和字符串组成的 `V8BlobPart` 列表。
     - 原始字节数据 (`base::span<const uint8_t>`)。
   - 在创建过程中，可以设置 `Blob` 的 `type` (MIME 类型) 和 `endings` (行尾符规范化)。

2. **`Blob` 数据的管理:**
   - 使用 `BlobDataHandle` 和 `BlobData` 内部类来管理 `Blob` 对象的实际二进制数据。
   - `BlobDataHandle` 负责持有数据的引用，可能是一个内存中的缓冲区，也可能是一个指向文件或其他数据源的句柄。
   - `BlobData` 负责组织和操作这些数据片段。

3. **`Blob` 对象的切片 (slicing):**
   - 实现了 `slice` 方法，允许创建一个新的 `Blob` 对象，它是原始 `Blob` 对象的一个子集。
   - 允许指定起始和结束的字节偏移量，以及新的 `Blob` 的 `type`。
   - 内部实现了对偏移量的规范化处理，例如处理负数偏移量和超出范围的偏移量。

4. **读取 `Blob` 内容:**
   - 提供了异步方法来读取 `Blob` 的内容：
     - `text(ScriptState*)`: 将 `Blob` 的内容读取为文本字符串 (UTF-8 编码)。返回一个 `Promise`，最终会 resolve 为字符串。
     - `arrayBuffer(ScriptState*)`: 将 `Blob` 的内容读取为 `ArrayBuffer`。返回一个 `Promise`，最终会 resolve 为 `ArrayBuffer` 对象。
     - `stream(ScriptState*)`: 将 `Blob` 的内容作为 `ReadableStream` 返回，允许逐步读取数据。

5. **内部数据追加 (`AppendTo`):**
   - 提供了 `AppendTo` 方法，允许将当前 `Blob` 的数据追加到另一个 `BlobData` 对象中。这在创建新的 `Blob` 时用于组合多个数据片段。

6. **类型规范化 (`NormalizeType`):**
   - 提供了 `NormalizeType` 静态方法，用于规范化 `Blob` 的 `type` 属性，例如将其转换为小写并移除无效字符。

7. **Mojo 集成:**
   - 包含了与 Mojo 相关的代码，允许将 `Blob` 对象作为 Mojo 接口进行传递和克隆。这对于跨进程通信非常重要。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **JavaScript:** `Blob` 对象是 JavaScript File API 的一部分，该文件实现了 Blink 引擎中 `Blob` 接口的底层逻辑。
   - **创建 `Blob`:**
     ```javascript
     const text = "Hello, world!";
     const blob = new Blob([text], { type: 'text/plain' });
     ```
     `blob.cc` 中的 `Blob::Create` 方法会被调用来创建这个 `Blob` 对象。
   - **切片 `Blob`:**
     ```javascript
     const slicedBlob = blob.slice(0, 5, 'text/plain');
     ```
     `blob.cc` 中的 `Blob::slice` 方法会被调用。
   - **读取 `Blob` 内容:**
     ```javascript
     blob.text().then(content => console.log(content));
     blob.arrayBuffer().then(buffer => console.log(buffer));
     ```
     分别对应 `blob.cc` 中的 `Blob::text` 和 `Blob::arrayBuffer` 方法。
   - **创建可下载链接:**
     ```javascript
     const url = URL.createObjectURL(blob);
     const link = document.createElement('a');
     link.href = url;
     link.download = 'my-file.txt';
     document.body.appendChild(link);
     ```
     虽然 `blob.cc` 不直接处理 URL 的创建，但它负责提供 `Blob` 对象，`URL.createObjectURL` 内部会使用 `Blob` 的数据。

2. **HTML:** `Blob` 对象经常与 HTML 元素一起使用。
   - **文件上传 (`<input type="file">`):**
     ```html
     <input type="file" id="fileInput">
     <script>
       document.getElementById('fileInput').addEventListener('change', function() {
         const file = this.files[0]; // file 对象继承自 Blob
         console.log(file.type);
         file.text().then(content => console.log(content));
       });
     </script>
     ```
     用户选择的文件会以 `File` 对象的形式提供，而 `File` 继承自 `Blob`。
   - **创建可下载链接 (`<a>` 标签):** (见 JavaScript 例子)

3. **CSS:** `Blob` 与 CSS 的关系相对间接，通常通过 JavaScript 作为桥梁。
   - **使用 `Blob` URL 作为图像源:**
     ```javascript
     const imageBlob = new Blob([ /* 图像数据 */ ], { type: 'image/png' });
     const imageUrl = URL.createObjectURL(imageBlob);
     const img = document.createElement('img');
     img.src = imageUrl;
     document.body.appendChild(img);
     ```
     CSS 可以对这个 `<img>` 元素进行样式设置。

**逻辑推理及假设输入与输出:**

**假设输入:** 创建一个包含字符串 "abc\ndef" 的 `Blob`，并设置 `endings` 为 "native"。

**逻辑:** `PopulateBlobData` 方法会根据 `endings` 的值来规范化行尾符。如果 `endings` 是 "native"，在 Windows 上会将 "\n" 转换为 "\r\n"，在其他平台上保持不变。

**假设平台:** Windows

**输入:**
```javascript
const text = "abc\ndef";
const blob = new Blob([text], { type: 'text/plain', endings: 'native' });
```

**`blob.cc` 内部处理逻辑 (简化):**
- `Blob::Create` 被调用。
- `PopulateBlobData` 被调用。
- 检测到 `endings` 为 "native"。
- 在 Windows 平台上，"\n" 被替换为 "\r\n"。

**假设输出 (内部 `BlobData` 的内容):** `"abc\r\ndef"`

**用户或编程常见的使用错误及举例说明:**

1. **`Blob` 的 `type` 设置不正确或包含非法字符:**
   - **错误示例:**
     ```javascript
     const blob = new Blob(['data'], { type: 'text/plain;charset=utf-8;' }); // 末尾分号
     ```
   - **`blob.cc` 的处理:** `NormalizeType` 方法会移除末尾的分号，但更严格的验证可能会在其他地方进行。理想情况下，开发者应该避免创建包含非法字符的 `type`。

2. **切片时 `start` 和 `end` 参数使用错误:**
   - **错误示例:**
     ```javascript
     const blob = new Blob(['abcdefg']);
     const slice = blob.slice(5, 2); // start 大于 end
     ```
   - **`blob.cc` 的处理:** `ClampSliceOffsets` 方法会将 `end` 调整为等于 `start`，最终切片会得到一个空 `Blob`。开发者应该确保 `start` 小于或等于 `end`。

3. **忘记处理异步读取 `Blob` 内容的 Promise 错误:**
   - **错误示例:**
     ```javascript
     const blob = new Blob(['data']);
     blob.text(); // 缺少 .then() 或 .catch() 来处理结果或错误
     ```
   - **可能导致的问题:** 如果读取过程中发生错误（例如，底层文件读取失败），Promise 会被 reject，如果没有 `catch` 处理，可能会导致 unhandled rejection 错误。

4. **过度依赖 `Blob` URL 而不及时释放:**
   - **错误示例:**
     ```javascript
     const blob = new Blob(['large data']);
     const url = URL.createObjectURL(blob);
     // ... 使用 url
     // 忘记调用 URL.revokeObjectURL(url);
     ```
   - **可能导致的问题:** `Blob` URL 会持有对底层 `Blob` 数据的引用，如果不及时释放，可能会导致内存泄漏。虽然 `blob.cc` 不直接负责 URL 的创建和释放，但它是 `Blob` 对象的提供者，开发者需要了解 `Blob` 的生命周期管理。

5. **假设 `Blob` 的大小在创建后保持不变:**
   - `Blob` 对象是不可变的。一旦创建，其内容和大小不会改变。尝试修改 `Blob` 的内容是无效的，需要创建新的 `Blob` 对象。

总而言之，`blink/renderer/core/fileapi/blob.cc` 是 Chromium Blink 引擎中实现 `Blob` 接口核心功能的关键文件，它处理 `Blob` 对象的创建、数据管理、切片和读取等操作，并与 JavaScript File API 紧密相连。理解其内部机制有助于更好地理解和使用 Web 平台的 `Blob` 功能。

### 提示词
```
这是目录为blink/renderer/core/fileapi/blob.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
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

#include "third_party/blink/renderer/core/fileapi/blob.h"

#include <memory>
#include <utility>

#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob_property_bag.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_blob_usvstring.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fileapi/file_read_type.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_client.h"
#include "third_party/blink/renderer/core/fileapi/file_reader_loader.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/url/dom_url.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/blob/blob_url.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/self_keep_alive.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

// http://dev.w3.org/2006/webapi/FileAPI/#constructorBlob
bool IsValidBlobType(const String& type) {
  for (unsigned i = 0; i < type.length(); ++i) {
    UChar c = type[i];
    if (c < 0x20 || c > 0x7E) {
      return false;
    }
  }
  return true;
}

}  // namespace

// TODO(https://crbug.com/989876): This is not used any more, refactor
// PublicURLManager to deprecate this.
class NullURLRegistry final : public URLRegistry {
 public:
  void RegisterURL(const KURL&, URLRegistrable*) override {}
  void UnregisterURL(const KURL&) override {}
};

// Helper class to asynchronously read from a Blob using a FileReaderLoader.
// Each client is only good for one Blob read operation.
// This class is not thread-safe.
class BlobFileReaderClient : public GarbageCollected<BlobFileReaderClient>,
                             public FileReaderAccumulator {
 public:
  BlobFileReaderClient(
      const scoped_refptr<BlobDataHandle> blob_data_handle,
      const scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      const FileReadType read_type,
      ScriptPromiseResolverBase* resolver)
      : loader_(MakeGarbageCollected<FileReaderLoader>(this,
                                                       std::move(task_runner))),
        resolver_(resolver),
        read_type_(read_type),
        keep_alive_(this) {
    loader_->Start(std::move(blob_data_handle));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(loader_);
    visitor->Trace(resolver_);
    FileReaderAccumulator::Trace(visitor);
  }

  ~BlobFileReaderClient() override = default;
  void DidFail(FileErrorCode error_code) override {
    FileReaderAccumulator::DidFail(error_code);
    resolver_->Reject(file_error::CreateDOMException(error_code));
    Done();
  }

  void DidFinishLoading(FileReaderData contents) override {
    if (read_type_ == FileReadType::kReadAsText) {
      String result = std::move(contents).AsText("UTF-8");
      resolver_->DowncastTo<IDLUSVString>()->Resolve(result);
    } else if (read_type_ == FileReadType::kReadAsArrayBuffer) {
      DOMArrayBuffer* result = std::move(contents).AsDOMArrayBuffer();
      resolver_->DowncastTo<DOMArrayBuffer>()->Resolve(result);
    } else {
      NOTREACHED() << "Unknown ReadType supplied to BlobFileReaderClient";
    }
    Done();
  }

 private:
  void Done() {
    keep_alive_.Clear();
    loader_ = nullptr;
  }
  Member<FileReaderLoader> loader_;
  Member<ScriptPromiseResolverBase> resolver_;
  const FileReadType read_type_;
  SelfKeepAlive<BlobFileReaderClient> keep_alive_;
};

Blob::Blob(scoped_refptr<BlobDataHandle> data_handle)
    : blob_data_handle_(std::move(data_handle)) {}

Blob::~Blob() = default;

// static
Blob* Blob::Create(ExecutionContext* context,
                   const HeapVector<Member<V8BlobPart>>& blob_parts,
                   const BlobPropertyBag* options) {
  DCHECK(options->hasType());
  DCHECK(options->hasEndings());
  bool normalize_line_endings_to_native = (options->endings() == "native");
  if (normalize_line_endings_to_native)
    UseCounter::Count(context, WebFeature::kFileAPINativeLineEndings);
  UseCounter::Count(context, WebFeature::kCreateObjectBlob);

  auto blob_data = std::make_unique<BlobData>();
  blob_data->SetContentType(NormalizeType(options->type()));

  PopulateBlobData(blob_data.get(), blob_parts,
                   normalize_line_endings_to_native);

  uint64_t blob_size = blob_data->length();
  return MakeGarbageCollected<Blob>(
      BlobDataHandle::Create(std::move(blob_data), blob_size));
}

Blob* Blob::Create(base::span<const uint8_t> data, const String& content_type) {
  auto blob_data = std::make_unique<BlobData>();
  blob_data->SetContentType(content_type);
  blob_data->AppendBytes(data);
  uint64_t blob_size = blob_data->length();

  return MakeGarbageCollected<Blob>(
      BlobDataHandle::Create(std::move(blob_data), blob_size));
}

// static
void Blob::PopulateBlobData(BlobData* blob_data,
                            const HeapVector<Member<V8BlobPart>>& parts,
                            bool normalize_line_endings_to_native) {
  for (const auto& item : parts) {
    switch (item->GetContentType()) {
      case V8BlobPart::ContentType::kArrayBuffer: {
        DOMArrayBuffer* array_buffer = item->GetAsArrayBuffer();
        blob_data->AppendBytes(array_buffer->ByteSpan());
        break;
      }
      case V8BlobPart::ContentType::kArrayBufferView: {
        auto&& array_buffer_view = item->GetAsArrayBufferView();
        blob_data->AppendBytes(array_buffer_view->ByteSpan());
        break;
      }
      case V8BlobPart::ContentType::kBlob: {
        item->GetAsBlob()->AppendTo(*blob_data);
        break;
      }
      case V8BlobPart::ContentType::kUSVString: {
        blob_data->AppendText(item->GetAsUSVString(),
                              normalize_line_endings_to_native);
        break;
      }
    }
  }
}

// static
void Blob::ClampSliceOffsets(uint64_t size, int64_t& start, int64_t& end) {
  DCHECK_NE(size, std::numeric_limits<uint64_t>::max());

  // Convert the negative value that is used to select from the end.
  if (start < 0)
    start = start + size;
  if (end < 0)
    end = end + size;

  // Clamp the range if it exceeds the size limit.
  if (start < 0)
    start = 0;
  if (end < 0)
    end = 0;
  if (static_cast<uint64_t>(start) >= size) {
    start = 0;
    end = 0;
  } else if (end < start) {
    end = start;
  } else if (static_cast<uint64_t>(end) > size) {
    end = size;
  }
}

Blob* Blob::slice(int64_t start,
                  int64_t end,
                  const String& content_type,
                  ExceptionState& exception_state) const {
  uint64_t size = this->size();
  ClampSliceOffsets(size, start, end);

  uint64_t length = end - start;
  auto blob_data = std::make_unique<BlobData>();
  blob_data->SetContentType(NormalizeType(content_type));
  blob_data->AppendBlob(blob_data_handle_, start, length);
  return MakeGarbageCollected<Blob>(
      BlobDataHandle::Create(std::move(blob_data), length));
}

ReadableStream* Blob::stream(ScriptState* script_state) const {
  BodyStreamBuffer* body_buffer = BodyStreamBuffer::Create(
      script_state,
      MakeGarbageCollected<BlobBytesConsumer>(
          ExecutionContext::From(script_state), blob_data_handle_),
      /*signal=*/nullptr, /*cached_metadata_handler=*/nullptr);

  return body_buffer->Stream();
}

ScriptPromise<IDLUSVString> Blob::text(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUSVString>>(script_state);
  auto promise = resolver->Promise();
  MakeGarbageCollected<BlobFileReaderClient>(
      blob_data_handle_,
      ExecutionContext::From(script_state)
          ->GetTaskRunner(TaskType::kFileReading),
      FileReadType::kReadAsText, resolver);
  return promise;
}

ScriptPromise<DOMArrayBuffer> Blob::arrayBuffer(ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<DOMArrayBuffer>>(script_state);
  auto promise = resolver->Promise();
  MakeGarbageCollected<BlobFileReaderClient>(
      blob_data_handle_,
      ExecutionContext::From(script_state)
          ->GetTaskRunner(TaskType::kFileReading),
      FileReadType::kReadAsArrayBuffer, resolver);
  return promise;
}

scoped_refptr<BlobDataHandle> Blob::GetBlobDataHandleWithKnownSize() const {
  if (!blob_data_handle_->IsSingleUnknownSizeFile()) {
    return blob_data_handle_;
  }
  return BlobDataHandle::Create(blob_data_handle_->Uuid(),
                                blob_data_handle_->GetType(), size(),
                                blob_data_handle_->CloneBlobRemote());
}

void Blob::AppendTo(BlobData& blob_data) const {
  blob_data.AppendBlob(blob_data_handle_, 0, size());
}

URLRegistry& Blob::Registry() const {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(NullURLRegistry, instance, ());
  return instance;
}

bool Blob::IsMojoBlob() {
  return true;
}

void Blob::CloneMojoBlob(mojo::PendingReceiver<mojom::blink::Blob> receiver) {
  blob_data_handle_->CloneBlobRemote(std::move(receiver));
}

mojo::PendingRemote<mojom::blink::Blob> Blob::AsMojoBlob() const {
  return blob_data_handle_->CloneBlobRemote();
}

// static
String Blob::NormalizeType(const String& type) {
  if (type.IsNull()) {
    return g_empty_string;
  }
  if (type.length() > 65535) {
    return g_empty_string;
  }
  if (!IsValidBlobType(type)) {
    return g_empty_string;
  }
  return type.DeprecatedLower();
}

}  // namespace blink
```