Response:
Let's break down the thought process for analyzing this C++ code. The request asks for functionality, relationships to web technologies, logical reasoning, common errors, and debugging context. Here's a potential step-by-step approach:

1. **Initial Scan and Class Identification:**  First, I'd quickly scan the code to identify the main classes and their inheritance. I see `FetchDataLoader` as a base class and several derived classes: `FetchDataLoaderAsBlobHandle`, `FetchDataLoaderAsArrayBuffer`, `FetchDataLoaderAsFailure`, `FetchDataLoaderAsFormData`, `FetchDataLoaderAsString`, and `FetchDataLoaderAsDataPipe`. This immediately suggests different ways of handling fetched data.

2. **Focus on Individual Class Functionality:**  I'd go through each derived class and analyze its `Start` and `OnStateChange` methods (and `FinishedCreatingFromDataPipe` for `FetchDataLoaderAsBlobHandle`). These methods seem crucial for understanding the core logic of each loader.

    * **`FetchDataLoaderAsBlobHandle`:**  The name suggests handling data as a Blob. The code attempts to get a `BlobDataHandle` directly. If not available, it uses a `DataPipe`. The `FinishedCreatingFromDataPipe` method confirms this. Keywords: `Blob`, `DataPipe`, `mime_type`.

    * **`FetchDataLoaderAsArrayBuffer`:**  The name clearly indicates handling as an ArrayBuffer. The code accumulates data in a `SharedBuffer` and then converts it to a `DOMArrayBuffer`. Keywords: `ArrayBuffer`, `SharedBuffer`.

    * **`FetchDataLoaderAsFailure`:** This seems straightforward – it simply consumes the data and then signals a failure. Keywords: `Failure`.

    * **`FetchDataLoaderAsFormData`:**  The name points to handling `multipart/form-data`. The code uses a `MultipartParser` to process the data and populate a `FormData` object. Keywords: `FormData`, `MultipartParser`, `Content-Disposition`.

    * **`FetchDataLoaderAsString`:**  This class decodes the fetched data into a string using a `TextResourceDecoder`. Keywords: `String`, `TextResourceDecoder`.

    * **`FetchDataLoaderAsDataPipe`:** This class focuses on directly passing the data through a `DataPipe`. Keywords: `DataPipe`.

3. **Identify Common Patterns and Interfaces:** I notice all derived classes implement the `FetchDataLoader` interface with a `Start` and `Cancel` method. They also interact with a `BytesConsumer` and a `FetchDataLoader::Client`. This suggests a common framework for data loading. The `BytesConsumer` seems responsible for providing the raw data, and the `FetchDataLoader::Client` handles the callbacks when loading is complete or fails.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** Now, I'd connect the identified functionalities to web technologies.

    * **JavaScript:** `Blob` and `ArrayBuffer` are fundamental JavaScript types for handling binary data. `FormData` is directly used in JavaScript for submitting forms. String encoding is relevant to how JavaScript interprets text. The `fetch()` API in JavaScript is the primary way these loaders would be used.

    * **HTML:**  The `<form>` element with `enctype="multipart/form-data"` directly relates to `FetchDataLoaderAsFormData`. `<img>`, `<video>`, and `<audio>` tags might use Blobs or ArrayBuffers behind the scenes when fetching resources. `<script>` and `<style>` tags involve fetching and decoding text (relevant to `FetchDataLoaderAsString`).

    * **CSS:** While CSS itself doesn't directly interact with these loaders, resources fetched by CSS (like background images or fonts) could use these mechanisms.

5. **Logical Reasoning (Assumptions and Outputs):** For each loader, I'd think about simple scenarios:

    * **Blob:** Input: Raw bytes, mime type. Output: `BlobDataHandle`.
    * **ArrayBuffer:** Input: Raw bytes. Output: `DOMArrayBuffer`.
    * **FormData:** Input: `multipart/form-data` bytes, boundary. Output: `FormData` object.
    * **String:** Input: Raw bytes, encoding. Output: Decoded string.
    * **DataPipe:** Input: Raw bytes. Output: `DataPipe` handle.
    * **Failure:** Input: Any raw bytes. Output: Failure signal.

6. **Common User/Programming Errors:**  I'd consider potential mistakes:

    * **Mismatched Mime Types:** Providing an incorrect mime type for a Blob.
    * **Invalid Multipart Data:**  Incorrect boundary, malformed headers.
    * **Encoding Issues:**  Not specifying the correct encoding for text.
    * **Large Data:**  Potentially causing memory issues with `ArrayBuffer` if not handled carefully.
    * **Incorrect API Usage:**  Not handling the asynchronous nature of fetching correctly.

7. **Debugging Context (User Actions):**  I'd trace back how a user action could lead to this code being executed.

    * **Navigating to a webpage:**  Fetching HTML, CSS, JavaScript.
    * **Submitting a form:** Especially forms with file uploads.
    * **JavaScript `fetch()` calls:**  Explicitly requesting data.
    * **Loading images/media:**  Implicit fetching by the browser.

8. **Code Structure and Details:**  Finally, I'd look at the code's structure, use of smart pointers (`scoped_refptr`, `Member`), and the asynchronous nature of operations using callbacks and Mojo data pipes. The use of `DCHECK` indicates internal consistency checks during development.

**Self-Correction/Refinement during the Process:**

* **Initially, I might focus too much on the technical details of Mojo pipes.** I need to remember to connect these low-level mechanisms back to the higher-level concepts of web technologies.
* **I need to ensure the examples are clear and concrete.**  Vague explanations are less helpful.
* **It's important to distinguish between *user* errors and *programmer* errors.**  For instance, a user might upload a corrupted file, while a programmer might incorrectly implement a `fetch()` request.
* **The debugging section needs to be actionable.** Listing potential entry points is more useful than just saying "a fetch happened."

By following these steps, and iterating and refining the analysis, I can produce a comprehensive explanation like the example provided in the prompt. The key is to start with the code, understand its core functions, and then connect it to the broader context of web development.
好的，我们来分析一下 `blink/renderer/core/fetch/fetch_data_loader.cc` 这个文件。

**文件功能总览**

`fetch_data_loader.cc` 文件的主要职责是根据不同的需求，将通过网络或本地获取的数据（由 `BytesConsumer` 提供）转换成不同的数据格式，并通知相应的客户端。 它定义了多种 `FetchDataLoader` 的实现子类，每种实现都负责将数据转换为特定的类型。

**各个子类的功能详解**

* **`FetchDataLoaderAsBlobHandle`**:
    * **功能**: 将获取的数据转换为 `BlobDataHandle` 对象。 `Blob` 是一个表示原始二进制数据的不透明对象。
    * **与 Web 技术的关系**:
        * **JavaScript**:  JavaScript 中可以使用 `Blob` 对象来处理二进制数据，例如，从 `<input type="file">` 获取的文件内容，或者通过 `fetch()` API 获取的二进制响应。
        * **HTML**:  `<img>` 标签的 `src` 属性可以使用 `blob:` URL 来显示 `Blob` 对象代表的图片。`<a>` 标签的 `download` 属性可以配合 `blob:` URL 来下载文件。
    * **逻辑推理**:
        * **假设输入**: `BytesConsumer` 提供了一段 MIME 类型为 "image/png" 的 PNG 图片数据。
        * **输出**:  `DidFetchDataLoadedBlobHandle` 回调被调用，传递一个 `BlobDataHandle`，其 MIME 类型为 "image/png"，内容是 PNG 图片数据。
    * **用户/编程常见错误**:
        * **用户错误**:  用户尝试加载一个损坏的图片文件，导致 `BytesConsumer` 提供的数据不完整或无效，最终可能导致 `DidFetchDataLoadFailed` 被调用。
        * **编程错误**:  开发者错误地指定了 `Blob` 的 MIME 类型，导致后续使用该 `Blob` 的操作出现问题。例如，将一个 PNG 图片的 `Blob` 的 MIME 类型错误地设置为 "text/plain"。
    * **调试线索**:  当需要将网络资源作为 `Blob` 处理时，例如使用 `response.blob()`，会使用此加载器。

* **`FetchDataLoaderAsArrayBuffer`**:
    * **功能**: 将获取的数据转换为 `DOMArrayBuffer` 对象。 `ArrayBuffer` 是 JavaScript 中用于表示通用的、固定长度的原始二进制数据缓冲区。
    * **与 Web 技术的关系**:
        * **JavaScript**:  JavaScript 可以使用 `ArrayBuffer` 进行底层的二进制数据操作，例如处理音频、视频数据，或者使用 WebGL 进行图形渲染。
    * **逻辑推理**:
        * **假设输入**: `BytesConsumer` 提供了一段表示 32 位整型数组的二进制数据。
        * **输出**: `DidFetchDataLoadedArrayBuffer` 回调被调用，传递一个包含该整型数组的 `DOMArrayBuffer` 对象。
    * **用户/编程常见错误**:
        * **编程错误**:  开发者在处理 `ArrayBuffer` 时，可能会出现字节偏移或类型错误，导致数据解析错误。
    * **调试线索**: 当 JavaScript 代码调用 `response.arrayBuffer()` 时，会使用此加载器。

* **`FetchDataLoaderAsFailure`**:
    * **功能**:  简单地消费所有数据，然后通知加载失败。 这通常用于处理已知会失败的加载场景。
    * **与 Web 技术的关系**:  当请求的资源不存在或服务器返回错误状态码时，可能会使用此加载器来清理资源并通知失败。
    * **逻辑推理**:
        * **假设输入**: `BytesConsumer` 提供了任何数据。
        * **输出**:  无论输入是什么，都会调用 `DidFetchDataLoadFailed`。
    * **用户/编程常见错误**:  不常见用户错误，更可能是内部错误处理机制。
    * **调试线索**:  当预期加载会失败时，或者作为错误处理路径的一部分。

* **`FetchDataLoaderAsFormData`**:
    * **功能**: 将 `multipart/form-data` 格式的数据解析成 `FormData` 对象。 `FormData` 用于表示 HTML 表单数据。
    * **与 Web 技术的关系**:
        * **JavaScript**: JavaScript 中可以使用 `FormData` 对象来构建表单数据，并通过 `fetch()` API 或传统的表单提交发送到服务器。
        * **HTML**:  当 HTML `<form>` 元素的 `enctype` 属性设置为 `"multipart/form-data"` 时，提交的表单数据会使用这种格式。
    * **逻辑推理**:
        * **假设输入**: `BytesConsumer` 提供了一段 `multipart/form-data` 格式的数据，其中包含一个名为 "name" 的文本字段和一个名为 "avatar" 的文件字段。
        * **输出**: `DidFetchDataLoadedFormData` 回调被调用，传递一个 `FormData` 对象，该对象包含 "name" 字段的文本值和 "avatar" 字段对应的 `File` 对象。
    * **用户/编程常见错误**:
        * **用户错误**:  用户上传的文件损坏或格式不正确，可能导致解析失败。
        * **编程错误**:  服务器端返回的 `multipart/form-data` 数据格式不正确，例如缺少 boundary，或者 part 的头部格式错误。
    * **调试线索**:  当处理 `multipart/form-data` 类型的响应时，例如通过 `fetch()` API 获取表单提交的响应，或者在 Service Worker 中处理表单提交时。

* **`FetchDataLoaderAsString`**:
    * **功能**: 使用指定的文本解码器将获取的数据解码成字符串。
    * **与 Web 技术的关系**:
        * **JavaScript**:  JavaScript 中的字符串类型。
        * **HTML**:  HTML 文档的内容是字符串。
        * **CSS**:  CSS 样式表的内容是字符串。
    * **逻辑推理**:
        * **假设输入**: `BytesConsumer` 提供了一段 UTF-8 编码的 HTML 代码。
        * **输出**: `DidFetchDataLoadedString` 回调被调用，传递一个包含该 HTML 代码的字符串。
    * **用户/编程常见错误**:
        * **用户错误**:  服务器返回的文本数据使用了错误的编码，而浏览器没有正确识别，导致乱码。
        * **编程错误**:  开发者在创建 `FetchDataLoaderAsString` 时，使用了错误的 `TextResourceDecoderOptions`，例如指定了错误的字符编码。
    * **调试线索**:  当需要将响应作为文本处理时，例如使用 `response.text()`，或者加载 HTML、CSS、JavaScript 文件时。

* **`FetchDataLoaderAsDataPipe`**:
    * **功能**: 将获取的数据直接通过 Mojo 数据管道传递。 这通常用于在不同的进程或线程之间高效地传输数据。
    * **与 Web 技术的关系**:  Mojo 数据管道是 Chromium 内部用于进程间通信的机制，对于 Web 开发者来说是底层的实现细节，通常不需要直接关心。但是，例如在 Service Worker 中处理流式响应时，可能会涉及到数据管道的概念。
    * **逻辑推理**:
        * **假设输入**: `BytesConsumer` 提供了任意数据。
        * **输出**: `DidFetchDataStartedDataPipe` 回调被调用，传递一个可以读取该数据的 Mojo 数据管道消费者句柄。当数据完全读取完毕时，调用 `DidFetchDataLoadedDataPipe`，或者在发生错误时调用 `DidFetchDataLoadFailed`。
    * **用户/编程常见错误**:  用户或开发者通常不会直接与此加载器交互，错误更可能发生在底层的 Mojo 管道配置或使用上。
    * **调试线索**:  当需要以流的方式处理数据，并且需要在不同的 Blink 组件之间传递数据时。

**用户操作如何一步步到达这里 (调试线索)**

假设用户访问一个包含表单的网页，并上传了一个图片作为头像，然后提交表单。以下是可能涉及 `FetchDataLoaderAsFormData` 的步骤：

1. **用户操作**: 用户在网页上填写表单，并选择一个图片文件。
2. **表单提交**: 用户点击提交按钮。
3. **网络请求**: 浏览器创建一个网络请求，该请求的 `Content-Type` 头部设置为 `multipart/form-data`，包含表单字段和上传的文件数据。
4. **网络接收**: Chromium 的网络栈接收到服务器的响应。
5. **响应处理**: Blink 渲染引擎开始处理服务器的响应。
6. **判断数据类型**:  根据响应的 `Content-Type` 头部，判断数据类型为 `multipart/form-data`。
7. **创建 `FetchDataLoader`**: 创建一个 `FetchDataLoaderAsFormData` 实例，并将 `multipart` boundary 传递给它。
8. **数据传递**:  将 `BytesConsumer` (从网络栈获取响应体数据) 传递给 `FetchDataLoaderAsFormData` 的 `Start` 方法。
9. **数据解析**: `FetchDataLoaderAsFormData` 使用 `MultipartParser` 逐步解析 `BytesConsumer` 提供的数据。
10. **回调通知**:  当解析完成时，`MultipartParser` 通知 `FetchDataLoaderAsFormData`，然后 `FetchDataLoaderAsFormData` 调用客户端的 `DidFetchDataLoadedFormData` 方法，传递解析后的 `FormData` 对象。
11. **JavaScript 处理**:  网页上的 JavaScript 代码可以访问该 `FormData` 对象，例如用于显示上传的图片或进一步处理表单数据。

**用户或编程常见的使用错误举例**

* **MIME 类型错误 (与 `FetchDataLoaderAsBlobHandle` 相关)**:  一个网站可能错误地将一个 JPEG 图片的 `Content-Type` 设置为 `text/plain`。当 JavaScript 代码尝试使用 `response.blob()` 获取该图片时，`FetchDataLoaderAsBlobHandle` 会创建一个 MIME 类型为 `text/plain` 的 `Blob` 对象。如果后续尝试将该 `Blob` 作为图片显示，可能会失败，因为浏览器期望的 MIME 类型是 `image/jpeg`。

* **`multipart/form-data` 格式错误 (与 `FetchDataLoaderAsFormData` 相关)**:  一个服务器端程序在生成 `multipart/form-data` 响应时，错误地使用了不匹配的 boundary，或者没有正确地分隔各个 part。当浏览器使用 `FetchDataLoaderAsFormData` 解析该响应时，`MultipartParser` 会遇到错误，并最终调用 `DidFetchDataLoadFailed`。这会导致 JavaScript 代码无法正确获取表单数据。

* **字符编码问题 (与 `FetchDataLoaderAsString` 相关)**:  一个网页的 HTML 文件使用了 GBK 编码，但服务器返回的响应头部中 `Content-Type` 错误地声明为 `charset=UTF-8`。当浏览器使用 `FetchDataLoaderAsString` 并使用 UTF-8 解码时，页面上的中文字符会显示为乱码。

希望这个详细的解释能够帮助你理解 `fetch_data_loader.cc` 文件的功能和它在 Chromium 中的作用。

Prompt: 
```
这是目录为blink/renderer/core/fetch/fetch_data_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/fetch_data_loader.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/compiler_specific.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom-blink.h"
#include "third_party/blink/renderer/core/fetch/multipart_parser.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/prefinalizer.h"
#include "third_party/blink/renderer/platform/loader/fetch/bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/parsed_content_disposition.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

class FetchDataLoaderAsBlobHandle final : public FetchDataLoader,
                                          public FetchDataLoader::Client {
 public:
  FetchDataLoaderAsBlobHandle(
      const String& mime_type,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : mime_type_(mime_type), task_runner_(std::move(task_runner)) {}

  void Start(BytesConsumer* consumer,
             FetchDataLoader::Client* client) override {
    DCHECK(!client_);
    DCHECK(!consumer_);

    client_ = client;
    consumer_ = consumer;

    scoped_refptr<BlobDataHandle> blob_handle =
        consumer_->DrainAsBlobDataHandle();
    if (blob_handle) {
      DCHECK_NE(UINT64_MAX, blob_handle->size());
      if (blob_handle->GetType() != mime_type_) {
        // A new Blob is created to override the Blob's type.
        auto blob_size = blob_handle->size();
        auto blob_data = std::make_unique<BlobData>();
        blob_data->SetContentType(mime_type_);
        blob_data->AppendBlob(std::move(blob_handle), 0, blob_size);
        client_->DidFetchDataLoadedBlobHandle(
            BlobDataHandle::Create(std::move(blob_data), blob_size));
      } else {
        client_->DidFetchDataLoadedBlobHandle(std::move(blob_handle));
      }
      return;
    }

    data_pipe_loader_ = CreateLoaderAsDataPipe(task_runner_);
    data_pipe_loader_->Start(consumer_, this);
  }

  void Cancel() override {
    load_canceled_ = true;
    blob_handle_.reset();
    consumer_->Cancel();
  }

  void DidFetchDataStartedDataPipe(
      mojo::ScopedDataPipeConsumerHandle handle) override {
    DCHECK(BlobDataHandle::GetBlobRegistry());
    BlobDataHandle::GetBlobRegistry()->RegisterFromStream(
        mime_type_ ? mime_type_ : "", /*content_disposition=*/"",
        /*length_hint=*/0, std::move(handle),
        mojo::PendingAssociatedRemote<mojom::blink::ProgressClient>(),
        WTF::BindOnce(
            &FetchDataLoaderAsBlobHandle::FinishedCreatingFromDataPipe,
            WrapWeakPersistent(this)));
  }

  void DidFetchDataLoadedDataPipe() override {
    DCHECK(!load_complete_);
    load_complete_ = true;
    if (blob_handle_)
      client_->DidFetchDataLoadedBlobHandle(std::move(blob_handle_));
  }

  void DidFetchDataLoadFailed() override { client_->DidFetchDataLoadFailed(); }

  void Abort() override { client_->Abort(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(consumer_);
    visitor->Trace(client_);
    visitor->Trace(data_pipe_loader_);
    FetchDataLoader::Trace(visitor);
    FetchDataLoader::Client::Trace(visitor);
  }

 private:
  void FinishedCreatingFromDataPipe(
      const scoped_refptr<BlobDataHandle>& blob_handle) {
    if (load_canceled_)
      return;
    if (!blob_handle) {
      DidFetchDataLoadFailed();
      return;
    }
    if (!load_complete_) {
      blob_handle_ = blob_handle;
      return;
    }
    client_->DidFetchDataLoadedBlobHandle(blob_handle);
  }

  Member<BytesConsumer> consumer_;
  Member<FetchDataLoader::Client> client_;
  Member<FetchDataLoader> data_pipe_loader_;

  const String mime_type_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  scoped_refptr<BlobDataHandle> blob_handle_;
  bool load_complete_ = false;
  bool load_canceled_ = false;
};

class FetchDataLoaderAsArrayBuffer final : public FetchDataLoader,
                                           public BytesConsumer::Client {
 public:
  void Start(BytesConsumer* consumer,
             FetchDataLoader::Client* client) override {
    DCHECK(!client_);
    DCHECK(!consumer_);
    DCHECK(!buffer_);
    client_ = client;
    consumer_ = consumer;
    buffer_ = WTF::SharedBuffer::Create();
    consumer_->SetClient(this);
    OnStateChange();
  }

  void Cancel() override { consumer_->Cancel(); }

  void OnStateChange() override {
    while (true) {
      base::span<const char> buffer;
      auto result = consumer_->BeginRead(buffer);
      if (result == BytesConsumer::Result::kShouldWait)
        return;
      if (result == BytesConsumer::Result::kOk) {
        if (!buffer.empty()) {
          bool ok = Append(buffer);
          if (!ok) {
            [[maybe_unused]] auto unused = consumer_->EndRead(0);
            consumer_->Cancel();
            client_->DidFetchDataLoadFailed();
            return;
          }
        }
        result = consumer_->EndRead(buffer.size());
      }
      switch (result) {
        case BytesConsumer::Result::kOk:
          break;
        case BytesConsumer::Result::kShouldWait:
          NOTREACHED();
        case BytesConsumer::Result::kDone: {
          DOMArrayBuffer* array_buffer = BuildArrayBuffer();
          if (!array_buffer) {
            client_->DidFetchDataLoadFailed();
            return;
          }
          client_->DidFetchDataLoadedArrayBuffer(array_buffer);
          return;
        }
        case BytesConsumer::Result::kError:
          client_->DidFetchDataLoadFailed();
          return;
      }
    }
  }

  String DebugName() const override { return "FetchDataLoaderAsArrayBuffer"; }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(consumer_);
    visitor->Trace(client_);
    FetchDataLoader::Trace(visitor);
    BytesConsumer::Client::Trace(visitor);
  }

 private:
  // Appending empty data is not allowed. Returns false upon buffer overflow.
  bool Append(base::span<const char> data) {
    DCHECK(!data.empty());
    buffer_->Append(data);
    if (buffer_->size() >
        static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
      return false;
    }
    return true;
  }

  // Builds a DOMArrayBuffer from the received bytes.
  DOMArrayBuffer* BuildArrayBuffer() {
    DOMArrayBuffer* result = DOMArrayBuffer::CreateUninitializedOrNull(
        base::checked_cast<unsigned>(buffer_->size()), 1);
    // Handle a failed allocation.
    if (!result) {
      return result;
    }
    CHECK(buffer_->GetBytes(result->ByteSpan()));
    buffer_->Clear();
    return result;
  }

  Member<BytesConsumer> consumer_;
  Member<FetchDataLoader::Client> client_;

  scoped_refptr<SharedBuffer> buffer_;
};

class FetchDataLoaderAsFailure final : public FetchDataLoader,
                                       public BytesConsumer::Client {
 public:
  void Start(BytesConsumer* consumer,
             FetchDataLoader::Client* client) override {
    DCHECK(!client_);
    DCHECK(!consumer_);
    client_ = client;
    consumer_ = consumer;
    consumer_->SetClient(this);
    OnStateChange();
  }

  void OnStateChange() override {
    while (true) {
      base::span<const char> buffer;
      auto result = consumer_->BeginRead(buffer);
      if (result == BytesConsumer::Result::kShouldWait)
        return;
      if (result == BytesConsumer::Result::kOk)
        result = consumer_->EndRead(buffer.size());
      switch (result) {
        case BytesConsumer::Result::kOk:
          break;
        case BytesConsumer::Result::kShouldWait:
          NOTREACHED();
        case BytesConsumer::Result::kDone:
        case BytesConsumer::Result::kError:
          client_->DidFetchDataLoadFailed();
          return;
      }
    }
  }

  String DebugName() const override { return "FetchDataLoaderAsFailure"; }

  void Cancel() override { consumer_->Cancel(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(consumer_);
    visitor->Trace(client_);
    FetchDataLoader::Trace(visitor);
    BytesConsumer::Client::Trace(visitor);
  }

 private:
  Member<BytesConsumer> consumer_;
  Member<FetchDataLoader::Client> client_;
};

class FetchDataLoaderAsFormData final : public FetchDataLoader,
                                        public BytesConsumer::Client,
                                        public MultipartParser::Client {
 public:
  explicit FetchDataLoaderAsFormData(const String& multipart_boundary)
      : multipart_boundary_(multipart_boundary) {}

  void Start(BytesConsumer* consumer,
             FetchDataLoader::Client* client) override {
    DCHECK(!client_);
    DCHECK(!consumer_);
    DCHECK(!form_data_);
    DCHECK(!multipart_parser_);

    StringUTF8Adaptor multipart_boundary_utf8(multipart_boundary_);
    Vector<char> multipart_boundary_vector;
    multipart_boundary_vector.AppendSpan(base::span(multipart_boundary_utf8));

    client_ = client;
    form_data_ = MakeGarbageCollected<FormData>();
    multipart_parser_ = MakeGarbageCollected<MultipartParser>(
        std::move(multipart_boundary_vector), this);
    consumer_ = consumer;
    consumer_->SetClient(this);
    OnStateChange();
  }

  void OnStateChange() override {
    while (true) {
      base::span<const char> buffer;
      auto result = consumer_->BeginRead(buffer);
      if (result == BytesConsumer::Result::kShouldWait)
        return;
      if (result == BytesConsumer::Result::kOk) {
        const bool buffer_appended = multipart_parser_->AppendData(buffer);
        const bool multipart_receive_failed = multipart_parser_->IsCancelled();
        result = consumer_->EndRead(buffer.size());
        if (!buffer_appended || multipart_receive_failed) {
          // No point in reading any more as the input is invalid.
          consumer_->Cancel();
          client_->DidFetchDataLoadFailed();
          return;
        }
      }
      switch (result) {
        case BytesConsumer::Result::kOk:
          break;
        case BytesConsumer::Result::kShouldWait:
          NOTREACHED();
        case BytesConsumer::Result::kDone:
          if (multipart_parser_->Finish()) {
            DCHECK(!multipart_parser_->IsCancelled());
            client_->DidFetchDataLoadedFormData(form_data_);
          } else {
            client_->DidFetchDataLoadFailed();
          }
          return;
        case BytesConsumer::Result::kError:
          client_->DidFetchDataLoadFailed();
          return;
      }
    }
  }

  String DebugName() const override { return "FetchDataLoaderAsFormData"; }

  void Cancel() override {
    consumer_->Cancel();
    multipart_parser_->Cancel();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(consumer_);
    visitor->Trace(client_);
    visitor->Trace(form_data_);
    visitor->Trace(multipart_parser_);
    FetchDataLoader::Trace(visitor);
    BytesConsumer::Client::Trace(visitor);
    MultipartParser::Client::Trace(visitor);
  }

 private:
  void PartHeaderFieldsInMultipartReceived(
      const HTTPHeaderMap& header_fields) override {
    if (!current_entry_.Initialize(header_fields))
      multipart_parser_->Cancel();
  }

  void PartDataInMultipartReceived(base::span<const char> bytes) override {
    if (!current_entry_.AppendBytes(bytes)) {
      multipart_parser_->Cancel();
    }
  }

  void PartDataInMultipartFullyReceived() override {
    if (!current_entry_.Finish(form_data_))
      multipart_parser_->Cancel();
  }

  class Entry {
   public:
    bool Initialize(const HTTPHeaderMap& header_fields) {
      const ParsedContentDisposition disposition(
          header_fields.Get(http_names::kContentDisposition));
      const String disposition_type = disposition.Type();
      filename_ = disposition.Filename();
      name_ = disposition.ParameterValueForName("name");
      blob_data_.reset();
      string_builder_.reset();
      if (disposition_type != "form-data" || name_.IsNull())
        return false;
      if (!filename_.IsNull()) {
        blob_data_ = std::make_unique<BlobData>();
        const AtomicString& content_type =
            header_fields.Get(http_names::kContentType);
        blob_data_->SetContentType(
            content_type.IsNull() ? AtomicString("text/plain") : content_type);
      } else {
        if (!string_decoder_) {
          string_decoder_ = std::make_unique<TextResourceDecoder>(
              TextResourceDecoderOptions::CreateUTF8DecodeWithoutBOM());
        }
        string_builder_ = std::make_unique<StringBuilder>();
      }
      return true;
    }

    bool AppendBytes(base::span<const char> chars) {
      if (blob_data_)
        blob_data_->AppendBytes(base::as_bytes(chars));
      if (string_builder_) {
        string_builder_->Append(string_decoder_->Decode(chars));
        if (string_decoder_->SawError())
          return false;
      }
      return true;
    }

    bool Finish(FormData* form_data) {
      if (blob_data_) {
        DCHECK(!string_builder_);
        const auto size = blob_data_->length();
        auto* file = MakeGarbageCollected<File>(
            filename_, std::nullopt,
            BlobDataHandle::Create(std::move(blob_data_), size));
        form_data->append(name_, file, filename_);
        return true;
      }
      DCHECK(!blob_data_);
      DCHECK(string_builder_);
      string_builder_->Append(string_decoder_->Flush());
      if (string_decoder_->SawError())
        return false;
      form_data->append(name_, string_builder_->ToString());
      return true;
    }

   private:
    std::unique_ptr<BlobData> blob_data_;
    String filename_;
    String name_;
    std::unique_ptr<StringBuilder> string_builder_;
    std::unique_ptr<TextResourceDecoder> string_decoder_;
  };

  Member<BytesConsumer> consumer_;
  Member<FetchDataLoader::Client> client_;
  Member<FormData> form_data_;
  Member<MultipartParser> multipart_parser_;

  Entry current_entry_;
  String multipart_boundary_;
};

class FetchDataLoaderAsString final : public FetchDataLoader,
                                      public BytesConsumer::Client {
 public:
  explicit FetchDataLoaderAsString(const TextResourceDecoderOptions& options)
      : decoder_options_(options) {}

  void Start(BytesConsumer* consumer,
             FetchDataLoader::Client* client) override {
    DCHECK(!client_);
    DCHECK(!decoder_);
    DCHECK(!consumer_);
    client_ = client;
    decoder_ = std::make_unique<TextResourceDecoder>(decoder_options_);
    consumer_ = consumer;
    consumer_->SetClient(this);
    OnStateChange();
  }

  void OnStateChange() override {
    while (true) {
      base::span<const char> buffer;
      auto result = consumer_->BeginRead(buffer);
      if (result == BytesConsumer::Result::kShouldWait)
        return;
      if (result == BytesConsumer::Result::kOk) {
        if (!buffer.empty()) {
          builder_.Append(decoder_->Decode(base::as_bytes(buffer)));
        }
        result = consumer_->EndRead(buffer.size());
      }
      switch (result) {
        case BytesConsumer::Result::kOk:
          break;
        case BytesConsumer::Result::kShouldWait:
          NOTREACHED();
        case BytesConsumer::Result::kDone:
          builder_.Append(decoder_->Flush());
          client_->DidFetchDataLoadedString(builder_.ToString());
          return;
        case BytesConsumer::Result::kError:
          client_->DidFetchDataLoadFailed();
          return;
      }
    }
  }

  String DebugName() const override { return "FetchDataLoaderAsString"; }

  void Cancel() override { consumer_->Cancel(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(consumer_);
    visitor->Trace(client_);
    FetchDataLoader::Trace(visitor);
    BytesConsumer::Client::Trace(visitor);
  }

 private:
  Member<BytesConsumer> consumer_;
  Member<FetchDataLoader::Client> client_;

  std::unique_ptr<TextResourceDecoder> decoder_;
  TextResourceDecoderOptions decoder_options_;
  StringBuilder builder_;
};

class FetchDataLoaderAsDataPipe final : public FetchDataLoader,
                                        public BytesConsumer::Client {
  USING_PRE_FINALIZER(FetchDataLoaderAsDataPipe, Dispose);

 public:
  explicit FetchDataLoaderAsDataPipe(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : data_pipe_watcher_(FROM_HERE,
                           mojo::SimpleWatcher::ArmingPolicy::MANUAL,
                           task_runner),
        data_pipe_close_watcher_(FROM_HERE,
                                 mojo::SimpleWatcher::ArmingPolicy::AUTOMATIC,
                                 std::move(task_runner)) {}
  ~FetchDataLoaderAsDataPipe() override = default;

  void Start(BytesConsumer* consumer,
             FetchDataLoader::Client* client) override {
    DCHECK(!client_);
    DCHECK(!consumer_);

    client_ = client;
    consumer_ = consumer;
    consumer_->SetClient(this);

    // First, try to drain the underlying mojo::DataPipe from the consumer
    // directly.  If this succeeds, all we need to do here is watch for
    // the pipe to be closed to signal completion.
    mojo::ScopedDataPipeConsumerHandle pipe_consumer =
        consumer->DrainAsDataPipe();
    if (!pipe_consumer.is_valid()) {
      // If we cannot drain the pipe from the consumer then we must copy
      // data from the consumer into a new pipe.
      MojoCreateDataPipeOptions options;
      options.struct_size = sizeof(MojoCreateDataPipeOptions);
      options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
      options.element_num_bytes = 1;
      // Use the default pipe capacity since we don't know the total data
      // size to target.
      options.capacity_num_bytes = 0;

      MojoResult rv =
          mojo::CreateDataPipe(&options, out_data_pipe_, pipe_consumer);
      if (rv != MOJO_RESULT_OK) {
        StopInternal();
        client_->DidFetchDataLoadFailed();
        return;
      }
      DCHECK(out_data_pipe_.is_valid());

      data_pipe_watcher_.Watch(
          out_data_pipe_.get(), MOJO_HANDLE_SIGNAL_WRITABLE,
          WTF::BindRepeating(&FetchDataLoaderAsDataPipe::OnWritable,
                             WrapWeakPersistent(this)));
      data_pipe_close_watcher_.Watch(
          out_data_pipe_.get(), MOJO_HANDLE_SIGNAL_PEER_CLOSED,
          MOJO_TRIGGER_CONDITION_SIGNALS_SATISFIED,
          WTF::BindRepeating(&FetchDataLoaderAsDataPipe::OnPeerClosed,
                             WrapWeakPersistent(this)));

      data_pipe_watcher_.ArmOrNotify();
      data_pipe_close_watcher_.ArmOrNotify();
    }

    // Give the resulting pipe consumer handle to the client.
    DCHECK(pipe_consumer.is_valid());
    client_->DidFetchDataStartedDataPipe(std::move(pipe_consumer));

    // Its possible that the consumer changes state immediately after
    // calling DrainDataPipe.  In this case we call OnStateChange()
    // to process the new state.
    if (consumer->GetPublicState() !=
        BytesConsumer::PublicState::kReadableOrWaiting)
      OnStateChange();
  }

  void OnPeerClosed(MojoResult result, const mojo::HandleSignalsState& state) {
    StopInternal();
    client_->DidFetchDataLoadFailed();
  }

  void OnWritable(MojoResult) { OnStateChange(); }

  // Implements BytesConsumer::Client.
  void OnStateChange() override {
    bool should_wait = false;
    while (!should_wait) {
      base::span<const char> buffer;
      auto result = consumer_->BeginRead(buffer);
      if (result == BytesConsumer::Result::kShouldWait)
        return;
      if (result == BytesConsumer::Result::kOk) {
        if (buffer.empty()) {
          result = consumer_->EndRead(0);
        } else {
          size_t actually_written_bytes = 0;
          MojoResult mojo_result = out_data_pipe_->WriteData(
              base::as_bytes(buffer), MOJO_WRITE_DATA_FLAG_NONE,
              actually_written_bytes);
          if (mojo_result == MOJO_RESULT_OK) {
            result = consumer_->EndRead(actually_written_bytes);
          } else if (mojo_result == MOJO_RESULT_SHOULD_WAIT) {
            result = consumer_->EndRead(0);
            should_wait = true;
            data_pipe_watcher_.ArmOrNotify();
          } else {
            result = consumer_->EndRead(0);
            StopInternal();
            client_->DidFetchDataLoadFailed();
            return;
          }
        }
      }
      switch (result) {
        case BytesConsumer::Result::kOk:
          break;
        case BytesConsumer::Result::kShouldWait:
          NOTREACHED();
        case BytesConsumer::Result::kDone:
          StopInternal();
          client_->DidFetchDataLoadedDataPipe();
          return;
        case BytesConsumer::Result::kError:
          StopInternal();
          client_->DidFetchDataLoadFailed();
          return;
      }
    }
  }

  String DebugName() const override { return "FetchDataLoaderAsDataPipe"; }

  void Cancel() override { StopInternal(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(consumer_);
    visitor->Trace(client_);
    FetchDataLoader::Trace(visitor);
    BytesConsumer::Client::Trace(visitor);
  }

 private:
  void StopInternal() {
    consumer_->Cancel();
    Dispose();
  }

  void Dispose() {
    data_pipe_watcher_.Cancel();
    data_pipe_close_watcher_.Cancel();
    out_data_pipe_.reset();
  }

  Member<BytesConsumer> consumer_;
  Member<FetchDataLoader::Client> client_;

  mojo::ScopedDataPipeProducerHandle out_data_pipe_;
  mojo::SimpleWatcher data_pipe_watcher_;
  mojo::SimpleWatcher data_pipe_close_watcher_;
};

}  // namespace

FetchDataLoader* FetchDataLoader::CreateLoaderAsBlobHandle(
    const String& mime_type,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  return MakeGarbageCollected<FetchDataLoaderAsBlobHandle>(
      mime_type, std::move(task_runner));
}

FetchDataLoader* FetchDataLoader::CreateLoaderAsArrayBuffer() {
  return MakeGarbageCollected<FetchDataLoaderAsArrayBuffer>();
}

FetchDataLoader* FetchDataLoader::CreateLoaderAsFailure() {
  return MakeGarbageCollected<FetchDataLoaderAsFailure>();
}

FetchDataLoader* FetchDataLoader::CreateLoaderAsFormData(
    const String& multipartBoundary) {
  return MakeGarbageCollected<FetchDataLoaderAsFormData>(multipartBoundary);
}

FetchDataLoader* FetchDataLoader::CreateLoaderAsString(
    const TextResourceDecoderOptions& options) {
  return MakeGarbageCollected<FetchDataLoaderAsString>(options);
}

FetchDataLoader* FetchDataLoader::CreateLoaderAsDataPipe(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  return MakeGarbageCollected<FetchDataLoaderAsDataPipe>(
      std::move(task_runner));
}

}  // namespace blink

"""

```