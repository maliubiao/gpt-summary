Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the C++ test file `form_data_bytes_consumer_test.cc`. This means understanding its purpose, how it relates to web technologies, identifying potential errors, and outlining debugging steps.

**2. Initial Skim and Keyword Identification:**

First, I quickly scanned the code for prominent keywords and patterns. This helps get a high-level overview:

* **`FormDataBytesConsumer`**:  This is the central class being tested. The name suggests it deals with consuming bytes related to form data.
* **`BytesConsumerTestReader`**:  This looks like a utility for testing `BytesConsumer` implementations by reading data from them.
* **`EncodedFormData`**:  Likely represents the structured form data being processed.
* **`DataPipeGetter`**:  Indicates the involvement of asynchronous data streams, common in Chromium for performance.
* **`BlobDataHandle`**: Points to the ability to treat form data as binary blobs.
* **`DOMArrayBuffer`, `DOMUint8Array`**:  Shows interaction with JavaScript's typed arrays.
* **`TEST_F`**:  Clearly marks this as a Google Test file.
* **`DrainAsString`, `DrainAsFormData`, `DrainAsBlobDataHandle`**:  These methods suggest different ways to retrieve the consumed data.
* **Various test names (e.g., `TwoPhaseReadFromString`, `DrainAsBlobDataHandleFromString`)**: These hint at the specific scenarios being tested.

**3. Identifying Core Functionality:**

Based on the keywords and test names, I can infer the main purpose of `FormDataBytesConsumer`:

* **Consuming various forms of input:** Strings, ArrayBuffers, `EncodedFormData` (which can contain files, blobs, and data pipes).
* **Providing different output formats:**  Raw bytes (through `BytesConsumer` interface), `EncodedFormData` objects, and `BlobDataHandle` objects.
* **Handling asynchronous data:**  Specifically, the `DataPipeGetter` demonstrates support for streaming data.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

Now, connect the C++ code to the frontend technologies:

* **HTML Forms:** The name "FormData" directly links to HTML `<form>` elements. When a form is submitted, the browser needs to encode the data. This test likely verifies how that encoded data is handled internally.
* **JavaScript `FormData` API:**  JavaScript provides the `FormData` API to programmatically create and manipulate form data. This C++ code is part of the underlying implementation that makes this API work. Methods like `append()` in the tests directly correspond to JavaScript `FormData.append()`.
* **`ArrayBuffer`, `Uint8Array`:** These are JavaScript's typed arrays. The tests explicitly check how `FormDataBytesConsumer` handles data coming from these types, demonstrating interoperability between JavaScript and the browser's internal data handling.
* **Blobs:**  HTML allows uploading files, which are often represented as Blobs. The tests with `BlobDataHandle` confirm that the consumer can handle file uploads.
* **Data Pipes:** While not directly exposed in simple HTML/JS, data pipes are an optimization in Chromium. They are relevant when dealing with large data transfers, potentially initiated by JavaScript (e.g., large file uploads).

**5. Logical Reasoning and Example Input/Output:**

For each test case, consider what input is being provided and what the expected output should be. For example:

* **`TwoPhaseReadFromString`:** Input: `"hello, world"`. Output: `"hello, world"` (as a byte vector).
* **`TwoPhaseReadFromSimpleFormData`:** Input: `EncodedFormData` containing "foo" and "hoge". Output: `"foohoge"`.
* **`DataPipeFormData`:** Input: `EncodedFormData` with strings and data pipes. Output: The concatenation of all the data.

**6. Identifying Potential User/Programming Errors:**

Think about how developers or users might misuse the related APIs:

* **Incorrect `Content-Type`:** If the server expects `application/x-www-form-urlencoded` but the JavaScript sends `multipart/form-data` (or vice versa), the backend might fail to parse the data. The C++ code likely handles different encodings.
* **Missing Boundary in `multipart/form-data`:**  This is a common error when manually constructing `multipart/form-data`. The tests might verify boundary handling.
* **Large File Uploads and Memory:**  If a user uploads a very large file, it could lead to memory issues. The data pipe mechanism is designed to handle this more efficiently, and the tests involving data pipes are relevant here.
* **Incorrectly Using `FormData` in JavaScript:**  For example, appending the wrong type of data or not setting the `Content-Type` correctly.

**7. Tracing User Operations to the Code:**

Consider the steps a user takes in the browser that would eventually lead to this C++ code being executed:

1. **User interacts with an HTML form:** Submitting a form, either via a submit button or JavaScript's `submit()` method.
2. **Browser encodes the form data:** This involves determining the appropriate `Content-Type` and formatting the data (e.g., URL-encoding or `multipart/form-data`).
3. **Network request is created:** The encoded form data is attached to the request body.
4. **On the receiving end (potentially in a test environment), the `FormDataBytesConsumer` is used:** This class is responsible for reading and interpreting the bytes of the form data.

**8. Structure and Refinement:**

Finally, organize the information logically, using clear headings and examples. Review the initial analysis and fill in any gaps. Ensure the language is precise and addresses all aspects of the request. For instance, the use of `gmock` and `gtest` is a key detail about the testing framework.

By following these steps, I can arrive at a comprehensive and accurate analysis of the given C++ test file, covering its functionality, relationships to web technologies, potential errors, and debugging context.
这个文件 `blink/renderer/core/fetch/form_data_bytes_consumer_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `FormDataBytesConsumer` 类的功能。 `FormDataBytesConsumer` 的作用是将各种形式的表单数据转换为字节流，以便进行网络传输或其他处理。

以下是该文件的功能详细列表，并解释了它与 JavaScript、HTML、CSS 的关系，以及可能出现的错误和调试线索：

**文件功能:**

1. **测试 `FormDataBytesConsumer` 的基本字节流读取功能:**
   - 测试从字符串、`DOMArrayBuffer`（JavaScript 中的 ArrayBuffer 对象）、`DOMUint8Array`（JavaScript 中 Uint8Array 对象）创建的 `FormDataBytesConsumer` 是否能正确读取出字节流。
   - 测试读取非 ASCII 字符的情况。

2. **测试从 `EncodedFormData` 读取字节流:**
   - 测试从简单的 `EncodedFormData` 对象（只包含文本数据）读取字节流。
   - 测试从复杂的 `EncodedFormData` 对象读取字节流，这些对象可能包含文件、Blob 数据等。
   - 测试 `EncodedFormData` 中包含 `DataPipeGetter` 的情况，这表示异步的数据流。

3. **测试 `FormDataBytesConsumer` 的 `DrainAsBlobDataHandle` 方法:**
   - 测试将 `FormDataBytesConsumer` 中的数据转换为 `BlobDataHandle` 对象。`BlobDataHandle` 用于表示二进制大数据，常用于文件上传等场景。
   - 测试从不同类型的 `FormDataBytesConsumer`（字符串、`ArrayBuffer`、`EncodedFormData`）转换为 `BlobDataHandle` 的正确性。

4. **测试 `FormDataBytesConsumer` 的 `DrainAsFormData` 方法:**
   - 测试将 `FormDataBytesConsumer` 中的数据重新转换为 `EncodedFormData` 对象。
   - 测试从不同类型的 `FormDataBytesConsumer` 转换为 `EncodedFormData` 的正确性。

5. **测试 `FormDataBytesConsumer` 的状态管理和生命周期:**
   - 测试 `BeginRead` 和 `EndRead` 方法的调用顺序和状态变化。
   - 测试在读取过程中调用 `DrainAsFormData` 或 `DrainAsBlobDataHandle` 的行为。
   - 测试设置和清除客户端（`BytesConsumer::Client`）的行为。
   - 测试取消读取操作 (`Cancel`) 的行为。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    - **`DOMArrayBuffer`, `DOMUint8Array`:**  这些是 JavaScript 中用于处理二进制数据的对象。测试文件中创建 `FormDataBytesConsumer` 时使用了这些对象，模拟了 JavaScript 将二进制数据传递给浏览器引擎进行处理的情况。
    - **`FormData` API:**  虽然测试文件没有直接使用 JavaScript 的 `FormData` API，但它测试的 `FormDataBytesConsumer` 类正是用于处理通过 JavaScript 的 `FormData` API 或 HTML 表单提交上来的数据。JavaScript 可以使用 `FormData` 对象来构建表单数据，包括文本和文件等，然后通过 `fetch` 或 `XMLHttpRequest` 发送出去。`FormDataBytesConsumer` 就负责读取这些发送出去的数据。
    - **Blobs:**  JavaScript 的 `Blob` 对象可以被添加到 `FormData` 中。测试文件中使用了 `BlobDataHandle`，这与 JavaScript 中的 `Blob` 对象密切相关。

* **HTML:**
    - **`<form>` 元素:**  HTML 的 `<form>` 元素是用户提交数据的基本方式。当用户提交表单时，浏览器会将表单数据编码并发送到服务器。`FormDataBytesConsumer` 用于处理这种编码后的数据。
    - **`<input type="file">`:**  当表单中包含文件上传控件时，用户选择的文件数据会被添加到 `FormData` 中，最终可能被 `FormDataBytesConsumer` 处理。

* **CSS:**
    - **无直接关系:**  CSS 主要负责页面的样式和布局，与表单数据的处理过程没有直接的关联。

**举例说明:**

* **JavaScript + HTML:**  假设一个 HTML 表单如下：

  ```html
  <form id="myForm">
    <input type="text" name="name" value="John">
    <input type="file" name="avatar">
    <button type="submit">Submit</button>
  </form>
  <script>
    const form = document.getElementById('myForm');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(form);
      const response = await fetch('/submit', {
        method: 'POST',
        body: formData
      });
      // ... 处理响应
    });
  </script>
  ```

  当用户点击 "Submit" 按钮时，JavaScript 代码会创建一个 `FormData` 对象，其中包含了文本输入框的值和用户选择的文件。 `fetch` API 会将这个 `FormData` 发送到服务器。在浏览器引擎内部，`FormDataBytesConsumer` 的功能类似于将 `formData` 中的数据（包括 "John" 这个字符串和文件内容）转换为可以发送的网络请求体。测试文件中的 `TwoPhaseReadFromSimpleFormData` 和 `TwoPhaseReadFromComplexFormData` 等测试用例就模拟了这种情况。

* **JavaScript ArrayBuffer:**  JavaScript 可以创建 `ArrayBuffer` 对象来存储二进制数据，例如从 WebSocket 接收到的数据或者使用 `FileReader` 读取的文件内容。可以将 `ArrayBuffer` 或其视图（如 `Uint8Array`) 直接传递给 `FormData` (虽然不常见，但技术上可行)。测试文件中的 `TwoPhaseReadFromArrayBuffer` 和 `TwoPhaseReadFromArrayBufferView` 测试了 `FormDataBytesConsumer` 处理这种情况的能力.

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个包含文本 "hello" 和文件 "world.txt" (内容为 "world") 的 `EncodedFormData` 对象。
* **预期输出 (使用 `DrainAsString` 或类似的读取方法):**  取决于 `EncodedFormData` 的编码方式（例如 `multipart/form-data`），输出可能是包含边界符和头部信息的字符串，例如：

  ```
  ------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n
  Content-Disposition: form-data; name="text"\r\n\r\n
  hello\r\n
  ------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n
  Content-Disposition: form-data; name="file"; filename="world.txt"\r\n
  Content-Type: text/plain\r\n\r\n
  world\r\n
  ------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n
  ```

* **假设输入:**  一个包含字符串 "test" 的 `DOMArrayBuffer` 对象。
* **预期输出 (使用 `DrainAsString`):** "test"

**用户或编程常见的使用错误:**

1. **JavaScript 中 `FormData` 的 `Content-Type` 设置错误:**
   - 错误：手动设置了错误的 `Content-Type`，例如将包含文件的 `FormData` 的 `Content-Type` 设置为 `application/x-www-form-urlencoded`。
   - 后果：服务器可能无法正确解析表单数据。
   - 调试线索：检查网络请求头部的 `Content-Type` 是否与 `FormData` 的内容匹配。

2. **后端服务器无法处理 `multipart/form-data`:**
   - 错误：前端使用了 `multipart/form-data` 发送数据（通常包含文件），但后端服务器没有相应的处理程序。
   - 后果：服务器可能无法解析请求体，导致数据丢失或错误。
   - 调试线索：检查后端服务器的日志，看是否能正确解析 `multipart/form-data`。

3. **在 JavaScript 中向 `FormData` 添加了错误类型的数据:**
   - 错误：尝试向 `FormData` 添加非字符串、非 Blob、非 File 类型的数据。
   - 后果：可能导致 `FormData` 对象状态异常或发送的数据格式不正确。
   - 调试线索：检查 JavaScript 代码中向 `FormData` 添加数据的方式。

4. **网络传输过程中数据损坏:**
   - 错误：由于网络问题，部分数据在传输过程中丢失或损坏。
   - 后果：`FormDataBytesConsumer` 读取到的数据不完整或错误。
   - 调试线索：使用网络抓包工具（如 Wireshark 或 Chrome 开发者工具的网络面板）检查发送和接收的原始数据。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在网页上填写了一个包含文本输入框和文件上传控件的表单。**
2. **用户点击了表单的提交按钮。**
3. **浏览器 JavaScript 代码（如果有的话）可能会拦截表单提交事件，并创建一个 `FormData` 对象。**
4. **浏览器根据 `FormData` 的内容和可能的设置，确定 `Content-Type` (通常是 `application/x-www-form-urlencoded` 或 `multipart/form-data`)。**
5. **浏览器将 `FormData` 中的数据编码成字节流，并添加到 HTTP 请求的请求体中。**
6. **这个 HTTP 请求被发送到服务器。**
7. **在 Chromium 渲染进程中，当需要处理接收到的包含表单数据的响应时，或者在发送包含表单数据的请求前，`FormDataBytesConsumer` 类会被用来读取或准备这些字节流数据。**
8. **如果开发者在测试或调试网络请求处理流程，可能会使用到类似的测试工具或代码来模拟生成或解析表单数据，这时就会涉及到 `FormDataBytesConsumer` 的相关代码。**

**调试线索:**

* **网络请求检查:** 使用 Chrome 开发者工具的网络面板，查看请求的 `Headers` (特别是 `Content-Type`) 和 `Payload` (请求体)。
* **断点调试:** 在 `blink/renderer/core/fetch/form_data_bytes_consumer.cc` 文件中设置断点，跟踪数据是如何被读取和处理的。
* **日志输出:** 在 `FormDataBytesConsumer` 的相关代码中添加日志输出，查看中间状态和数据内容。
* **对比预期结果:**  了解 `FormData` 被编码后的预期格式，与 `FormDataBytesConsumer` 读取到的实际数据进行对比。
* **检查 JavaScript 代码:**  确认 JavaScript 中 `FormData` 的创建和数据添加逻辑是否正确。

总而言之，`form_data_bytes_consumer_test.cc` 是一个非常重要的测试文件，它确保了 Blink 引擎能够正确处理各种形式的表单数据，这对于 Web 应用的功能正常运行至关重要。 通过理解这个测试文件的内容，可以更好地理解浏览器处理表单数据的内部机制，并能更有效地进行相关问题的调试。

Prompt: 
```
这是目录为blink/renderer/core/fetch/form_data_bytes_consumer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"

#include "base/containers/span.h"
#include "base/memory/scoped_refptr.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver_set.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "services/network/public/mojom/data_pipe_getter.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_http_body.h"
#include "third_party/blink/renderer/core/fetch/bytes_consumer_test_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/testing/file_backed_blob_factory_test_helper.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/network/wrapped_data_pipe_getter.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

using Result = BytesConsumer::Result;
using testing::_;
using testing::DoAll;
using testing::InSequence;
using testing::Return;
using Checkpoint = testing::StrictMock<testing::MockFunction<void(int)>>;
using MockBytesConsumer = BytesConsumerTestUtil::MockBytesConsumer;

class SimpleDataPipeGetter : public network::mojom::blink::DataPipeGetter {
 public:
  SimpleDataPipeGetter(
      const String& str,
      mojo::PendingReceiver<network::mojom::blink::DataPipeGetter> receiver)
      : str_(str) {
    receivers_.set_disconnect_handler(WTF::BindRepeating(
        &SimpleDataPipeGetter::OnMojoDisconnect, WTF::Unretained(this)));
    receivers_.Add(this, std::move(receiver));
  }
  SimpleDataPipeGetter(const SimpleDataPipeGetter&) = delete;
  SimpleDataPipeGetter& operator=(const SimpleDataPipeGetter&) = delete;
  ~SimpleDataPipeGetter() override = default;

  // network::mojom::DataPipeGetter implementation:
  void Read(mojo::ScopedDataPipeProducerHandle handle,
            ReadCallback callback) override {
    bool result = mojo::BlockingCopyFromString(str_.Utf8(), handle);
    ASSERT_TRUE(result);
    std::move(callback).Run(0 /* OK */, str_.length());
  }

  void Clone(mojo::PendingReceiver<network::mojom::blink::DataPipeGetter> receiver) override {
    receivers_.Add(this, std::move(receiver));
  }

  void OnMojoDisconnect() {
    if (receivers_.empty())
      delete this;
  }

 private:
  String str_;
  mojo::ReceiverSet<network::mojom::blink::DataPipeGetter> receivers_;
};

scoped_refptr<EncodedFormData> ComplexFormData() {
  scoped_refptr<EncodedFormData> data = EncodedFormData::Create();

  data->AppendData(base::span_from_cstring("foo"));
  data->AppendFileRange("/foo/bar/baz", 3, 4,
                        base::Time::FromSecondsSinceUnixEpoch(5));
  auto blob_data = std::make_unique<BlobData>();
  blob_data->AppendText("hello", false);
  auto size = blob_data->length();
  scoped_refptr<BlobDataHandle> blob_data_handle =
      BlobDataHandle::Create(std::move(blob_data), size);
  data->AppendBlob(blob_data_handle);
  Vector<char> boundary;
  boundary.Append("\0", 1);
  data->SetBoundary(boundary);
  return data;
}

scoped_refptr<EncodedFormData> DataPipeFormData() {
  WebHTTPBody body;
  body.Initialize();
  // Add data.
  body.AppendData(WebData("foo", 3));

  // Add data pipe.
  mojo::PendingRemote<network::mojom::blink::DataPipeGetter>
      data_pipe_getter_remote;
  // Object deletes itself.
  new SimpleDataPipeGetter(
      String(" hello world"),
      data_pipe_getter_remote.InitWithNewPipeAndPassReceiver());
  body.AppendDataPipe(std::move(data_pipe_getter_remote));

  // Add another data pipe.
  mojo::PendingRemote<network::mojom::blink::DataPipeGetter>
      data_pipe_getter_remote2;
  // Object deletes itself.
  new SimpleDataPipeGetter(
      String(" here's another data pipe "),
      data_pipe_getter_remote2.InitWithNewPipeAndPassReceiver());
  body.AppendDataPipe(std::move(data_pipe_getter_remote2));

  // Add some more data.
  body.AppendData(WebData("bar baz", 7));

  body.SetUniqueBoundary();
  return body;
}

class NoopClient final : public GarbageCollected<NoopClient>,
                         public BytesConsumer::Client {
 public:
  void OnStateChange() override {}
  String DebugName() const override { return "NoopClient"; }
};

class FormDataBytesConsumerTest : public PageTestBase {
 public:
  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    file_factory_helper_ = std::make_unique<FileBackedBlobFactoryTestHelper>(
        GetFrame().GetDocument()->GetExecutionContext());
  }

  String DrainAsString(scoped_refptr<EncodedFormData> input_form_data) {
    auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
        GetFrame().DomWindow(), input_form_data);
    auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(consumer);
    std::pair<BytesConsumer::Result, Vector<char>> result = reader->Run();
    EXPECT_EQ(Result::kDone, result.first);
    return String(result.second);
  }

  scoped_refptr<EncodedFormData> DrainAsFormData(
      scoped_refptr<EncodedFormData> input_form_data) {
    auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
        GetFrame().DomWindow(), input_form_data);
    return consumer->DrainAsFormData();
  }

  scoped_refptr<BlobDataHandle> DrainAsBlobDataHandle(
      scoped_refptr<EncodedFormData> input_form_data) {
    auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
        GetFrame().DomWindow(), input_form_data);
    return consumer->DrainAsBlobDataHandle(
        BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize);
  }

 private:
  std::unique_ptr<FileBackedBlobFactoryTestHelper> file_factory_helper_;
};

TEST_F(FormDataBytesConsumerTest, TwoPhaseReadFromString) {
  auto result =
      (MakeGarbageCollected<BytesConsumerTestReader>(
           MakeGarbageCollected<FormDataBytesConsumer>("hello, world")))
          ->Run();
  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ("hello, world", String(result.second));
}

TEST_F(FormDataBytesConsumerTest, TwoPhaseReadFromStringNonLatin) {
  constexpr UChar kCs[] = {0x3042, 0};
  auto result = (MakeGarbageCollected<BytesConsumerTestReader>(
                     MakeGarbageCollected<FormDataBytesConsumer>(String(kCs))))
                    ->Run();
  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ("\xe3\x81\x82", String(result.second));
}

TEST_F(FormDataBytesConsumerTest, TwoPhaseReadFromArrayBuffer) {
  constexpr unsigned char kData[] = {0x21, 0xfe, 0x00, 0x00, 0xff, 0xa3,
                                     0x42, 0x30, 0x42, 0x99, 0x88};
  DOMArrayBuffer* buffer = DOMArrayBuffer::Create(kData);
  auto result = (MakeGarbageCollected<BytesConsumerTestReader>(
                     MakeGarbageCollected<FormDataBytesConsumer>(buffer)))
                    ->Run();
  Vector<char> expected;
  expected.Append(kData, std::size(kData));

  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ(expected, result.second);
}

TEST_F(FormDataBytesConsumerTest, TwoPhaseReadFromArrayBufferView) {
  constexpr unsigned char kData[] = {0x21, 0xfe, 0x00, 0x00, 0xff, 0xa3,
                                     0x42, 0x30, 0x42, 0x99, 0x88};
  constexpr size_t kOffset = 1, kSize = 4;
  DOMArrayBuffer* buffer = DOMArrayBuffer::Create(kData);
  auto result = (MakeGarbageCollected<BytesConsumerTestReader>(
                     MakeGarbageCollected<FormDataBytesConsumer>(
                         DOMUint8Array::Create(buffer, kOffset, kSize))))
                    ->Run();
  Vector<char> expected;
  expected.AppendSpan(base::span(kData).subspan(kOffset, kSize));

  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ(expected, result.second);
}

TEST_F(FormDataBytesConsumerTest, TwoPhaseReadFromSimpleFormData) {
  scoped_refptr<EncodedFormData> data = EncodedFormData::Create();
  data->AppendData(base::span_from_cstring("foo"));
  data->AppendData(base::span_from_cstring("hoge"));

  auto result = (MakeGarbageCollected<BytesConsumerTestReader>(
                     MakeGarbageCollected<FormDataBytesConsumer>(
                         GetFrame().DomWindow(), data)))
                    ->Run();
  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ("foohoge", String(result.second));
}

TEST_F(FormDataBytesConsumerTest, TwoPhaseReadFromComplexFormData) {
  scoped_refptr<EncodedFormData> data = ComplexFormData();
  auto* underlying = MakeGarbageCollected<MockBytesConsumer>();
  auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), data, underlying);
  Checkpoint checkpoint;

  base::span<const char> buffer;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*underlying, BeginRead(buffer)).WillOnce(Return(Result::kOk));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*underlying, EndRead(0)).WillOnce(Return(Result::kOk));
  EXPECT_CALL(checkpoint, Call(3));

  checkpoint.Call(1);
  ASSERT_EQ(Result::kOk, consumer->BeginRead(buffer));
  checkpoint.Call(2);
  EXPECT_EQ(Result::kOk, consumer->EndRead(0));
  checkpoint.Call(3);
}

TEST_F(FormDataBytesConsumerTest, EndReadCanReturnDone) {
  BytesConsumer* consumer =
      MakeGarbageCollected<FormDataBytesConsumer>("hello, world");
  base::span<const char> buffer;
  ASSERT_EQ(Result::kOk, consumer->BeginRead(buffer));
  ASSERT_EQ(12u, buffer.size());
  EXPECT_EQ("hello, world", String(base::as_bytes(buffer)));
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            consumer->GetPublicState());
  EXPECT_EQ(Result::kDone, consumer->EndRead(buffer.size()));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, DrainAsBlobDataHandleFromString) {
  BytesConsumer* consumer =
      MakeGarbageCollected<FormDataBytesConsumer>("hello, world");
  scoped_refptr<BlobDataHandle> blob_data_handle =
      consumer->DrainAsBlobDataHandle();
  ASSERT_TRUE(blob_data_handle);

  EXPECT_EQ(String(), blob_data_handle->GetType());
  EXPECT_EQ(12u, blob_data_handle->size());
  EXPECT_FALSE(consumer->DrainAsFormData());
  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, DrainAsBlobDataHandleFromArrayBuffer) {
  BytesConsumer* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      DOMArrayBuffer::Create(base::byte_span_from_cstring("foo")));
  scoped_refptr<BlobDataHandle> blob_data_handle =
      consumer->DrainAsBlobDataHandle();
  ASSERT_TRUE(blob_data_handle);

  EXPECT_EQ(String(), blob_data_handle->GetType());
  EXPECT_EQ(3u, blob_data_handle->size());
  EXPECT_FALSE(consumer->DrainAsFormData());
  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, DrainAsBlobDataHandleFromSimpleFormData) {
  auto* data = MakeGarbageCollected<FormData>(UTF8Encoding());
  data->append("name1", "value1");
  data->append("name2", "value2");
  scoped_refptr<EncodedFormData> input_form_data =
      data->EncodeMultiPartFormData();

  BytesConsumer* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data);
  scoped_refptr<BlobDataHandle> blob_data_handle =
      consumer->DrainAsBlobDataHandle();
  ASSERT_TRUE(blob_data_handle);

  EXPECT_EQ(String(), blob_data_handle->GetType());
  EXPECT_EQ(input_form_data->FlattenToString().Utf8().length(),
            blob_data_handle->size());
  EXPECT_FALSE(consumer->DrainAsFormData());
  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, DrainAsBlobDataHandleFromComplexFormData) {
  scoped_refptr<EncodedFormData> input_form_data = ComplexFormData();

  BytesConsumer* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data);
  scoped_refptr<BlobDataHandle> blob_data_handle =
      consumer->DrainAsBlobDataHandle();
  ASSERT_TRUE(blob_data_handle);

  EXPECT_FALSE(consumer->DrainAsFormData());
  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, DrainAsFormDataFromString) {
  BytesConsumer* consumer =
      MakeGarbageCollected<FormDataBytesConsumer>("hello, world");
  scoped_refptr<EncodedFormData> form_data = consumer->DrainAsFormData();
  ASSERT_TRUE(form_data);
  EXPECT_EQ("hello, world", form_data->FlattenToString());

  EXPECT_FALSE(consumer->DrainAsBlobDataHandle());
  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, DrainAsFormDataFromArrayBuffer) {
  BytesConsumer* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      DOMArrayBuffer::Create(base::byte_span_from_cstring("foo")));
  scoped_refptr<EncodedFormData> form_data = consumer->DrainAsFormData();
  ASSERT_TRUE(form_data);
  EXPECT_TRUE(form_data->IsSafeToSendToAnotherThread());
  EXPECT_EQ("foo", form_data->FlattenToString());

  EXPECT_FALSE(consumer->DrainAsBlobDataHandle());
  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, DrainAsFormDataFromSimpleFormData) {
  auto* data = MakeGarbageCollected<FormData>(UTF8Encoding());
  data->append("name1", "value1");
  data->append("name2", "value2");
  scoped_refptr<EncodedFormData> input_form_data =
      data->EncodeMultiPartFormData();

  BytesConsumer* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data);
  EXPECT_EQ(input_form_data, consumer->DrainAsFormData());
  EXPECT_FALSE(consumer->DrainAsBlobDataHandle());
  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, DrainAsFormDataFromComplexFormData) {
  scoped_refptr<EncodedFormData> input_form_data = ComplexFormData();

  BytesConsumer* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data);
  EXPECT_EQ(input_form_data, consumer->DrainAsFormData());
  EXPECT_FALSE(consumer->DrainAsBlobDataHandle());
  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, BeginReadAffectsDraining) {
  base::span<const char> buffer;
  BytesConsumer* consumer =
      MakeGarbageCollected<FormDataBytesConsumer>("hello, world");
  ASSERT_EQ(Result::kOk, consumer->BeginRead(buffer));
  EXPECT_EQ("hello, world", String(base::as_bytes(buffer)));

  ASSERT_EQ(Result::kOk, consumer->EndRead(0));
  EXPECT_FALSE(consumer->DrainAsFormData());
  EXPECT_FALSE(consumer->DrainAsBlobDataHandle());
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            consumer->GetPublicState());
}

TEST_F(FormDataBytesConsumerTest, BeginReadAffectsDrainingWithComplexFormData) {
  auto* underlying = MakeGarbageCollected<MockBytesConsumer>();
  BytesConsumer* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), ComplexFormData(), underlying);

  base::span<const char> buffer;
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*underlying, BeginRead(buffer)).WillOnce(Return(Result::kOk));
  EXPECT_CALL(*underlying, EndRead(0)).WillOnce(Return(Result::kOk));
  EXPECT_CALL(checkpoint, Call(2));
  // drainAsFormData should not be called here.
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*underlying, DrainAsBlobDataHandle(_));
  EXPECT_CALL(checkpoint, Call(4));
  // |consumer| delegates the getPublicState call to |underlying|.
  EXPECT_CALL(*underlying, GetPublicState())
      .WillOnce(Return(BytesConsumer::PublicState::kReadableOrWaiting));
  EXPECT_CALL(checkpoint, Call(5));

  checkpoint.Call(1);
  ASSERT_EQ(Result::kOk, consumer->BeginRead(buffer));
  ASSERT_EQ(Result::kOk, consumer->EndRead(0));
  checkpoint.Call(2);
  EXPECT_FALSE(consumer->DrainAsFormData());
  checkpoint.Call(3);
  EXPECT_FALSE(consumer->DrainAsBlobDataHandle());
  checkpoint.Call(4);
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            consumer->GetPublicState());
  checkpoint.Call(5);
}

TEST_F(FormDataBytesConsumerTest, SetClientWithComplexFormData) {
  scoped_refptr<EncodedFormData> input_form_data = ComplexFormData();

  auto* underlying = MakeGarbageCollected<MockBytesConsumer>();
  auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data, underlying);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*underlying, SetClient(_));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*underlying, ClearClient());
  EXPECT_CALL(checkpoint, Call(3));

  checkpoint.Call(1);
  consumer->SetClient(MakeGarbageCollected<NoopClient>());
  checkpoint.Call(2);
  consumer->ClearClient();
  checkpoint.Call(3);
}

TEST_F(FormDataBytesConsumerTest, CancelWithComplexFormData) {
  scoped_refptr<EncodedFormData> input_form_data = ComplexFormData();

  auto* underlying = MakeGarbageCollected<MockBytesConsumer>();
  auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data, underlying);
  Checkpoint checkpoint;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*underlying, Cancel());
  EXPECT_CALL(checkpoint, Call(2));

  checkpoint.Call(1);
  consumer->Cancel();
  checkpoint.Call(2);
}

// Tests consuming an EncodedFormData with data pipe elements.
TEST_F(FormDataBytesConsumerTest, DataPipeFormData) {
  scoped_refptr<EncodedFormData> input_form_data = DataPipeFormData();
  auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data);
  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(consumer);
  std::pair<BytesConsumer::Result, Vector<char>> result = reader->Run();
  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ("foo hello world here's another data pipe bar baz",
            String(result.second));
}

// Tests DrainAsFormData() on an EncodedFormData with data pipe elements.
TEST_F(FormDataBytesConsumerTest, DataPipeFormData_DrainAsFormData) {
  scoped_refptr<EncodedFormData> input_form_data = DataPipeFormData();
  auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data);
  scoped_refptr<EncodedFormData> drained_form_data =
      consumer->DrainAsFormData();
  EXPECT_EQ(*input_form_data, *drained_form_data);
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
}

// Tests DrainAsFormData() on an EncodedFormData with data pipe elements after
// starting to read.
TEST_F(FormDataBytesConsumerTest,
       DataPipeFormData_DrainAsFormDataWhileReading) {
  // Create the consumer and start reading.
  scoped_refptr<EncodedFormData> input_form_data = DataPipeFormData();
  auto* consumer = MakeGarbageCollected<FormDataBytesConsumer>(
      GetFrame().DomWindow(), input_form_data);
  base::span<const char> buffer;
  EXPECT_EQ(BytesConsumer::Result::kOk, consumer->BeginRead(buffer));
  EXPECT_EQ("foo", String(base::as_bytes(buffer)));

  // Try to drain form data. It should return null since we started reading.
  scoped_refptr<EncodedFormData> drained_form_data =
      consumer->DrainAsFormData();
  EXPECT_FALSE(drained_form_data);
  EXPECT_EQ(BytesConsumer::PublicState::kReadableOrWaiting,
            consumer->GetPublicState());
  EXPECT_EQ(BytesConsumer::Result::kOk, consumer->EndRead(buffer.size()));

  // The consumer should still be readable. Finish reading.
  auto* reader = MakeGarbageCollected<BytesConsumerTestReader>(consumer);
  std::pair<BytesConsumer::Result, Vector<char>> result = reader->Run();
  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ(" hello world here's another data pipe bar baz",
            String(result.second));
}

void AppendDataPipe(scoped_refptr<EncodedFormData> data, String content) {
  mojo::PendingRemote<network::mojom::blink::DataPipeGetter> data_pipe_getter;
  // Object deletes itself.
  new SimpleDataPipeGetter(content,
                           data_pipe_getter.InitWithNewPipeAndPassReceiver());
  auto wrapped =
      base::MakeRefCounted<WrappedDataPipeGetter>(std::move(data_pipe_getter));
  data->AppendDataPipe(std::move(wrapped));
}

scoped_refptr<BlobDataHandle> CreateBlobHandle(const String& content) {
  auto blob_data = std::make_unique<BlobData>();
  blob_data->AppendText(content, false);
  auto size = blob_data->length();
  return BlobDataHandle::Create(std::move(blob_data), size);
}

scoped_refptr<EncodedFormData> CreateDataPipeData() {
  scoped_refptr<EncodedFormData> data = EncodedFormData::Create();
  Vector<char> boundary;
  boundary.Append("\0", 1);
  data->SetBoundary(boundary);

  data->AppendData(base::span_from_cstring("foo"));
  AppendDataPipe(data, " hello world");
  return data;
}

TEST_F(FormDataBytesConsumerTest, InvalidType1) {
  const String kExpected = "foo hello world";
  ASSERT_EQ(kExpected, DrainAsString(CreateDataPipeData()));

  scoped_refptr<EncodedFormData> data = CreateDataPipeData();
  data->AppendBlob(CreateBlobHandle("bar"));
  ASSERT_EQ(EncodedFormData::FormDataType::kInvalid, data->GetType());

  // sizeof("foo" + "bar") ignoring the mid "hello world" datapipe.
  // TODO(crbug.com/374124998): Unfortunately BytesConsumerTestReader can not
  // work with blob to drain string. We should fix it.
  EXPECT_EQ(6u, DrainAsBlobDataHandle(data)->size());
}

scoped_refptr<EncodedFormData> CreateBlobData() {
  scoped_refptr<EncodedFormData> data = EncodedFormData::Create();
  Vector<char> boundary;
  boundary.Append("\0", 1);
  data->SetBoundary(boundary);

  data->AppendData(base::span_from_cstring("foo"));
  data->AppendBlob(CreateBlobHandle("bar"));
  return data;
}

TEST_F(FormDataBytesConsumerTest, InvalidType2) {
  scoped_refptr<EncodedFormData> data = CreateBlobData();
  AppendDataPipe(data, " datapipe");
  ASSERT_EQ(EncodedFormData::FormDataType::kInvalid, data->GetType());

  auto* consumer =
      MakeGarbageCollected<FormDataBytesConsumer>(GetFrame().DomWindow(), data);
  Vector<char> str;
  {
    base::span<const char> buffer;
    EXPECT_EQ(BytesConsumer::Result::kOk, consumer->BeginRead(buffer));
    str.AppendSpan(buffer);
    EXPECT_EQ(BytesConsumer::Result::kOk, consumer->EndRead(buffer.size()));
  }
  EXPECT_EQ("foo", String(str));

  {
    base::span<const char> buffer;
    EXPECT_EQ(BytesConsumer::Result::kError, consumer->BeginRead(buffer));
  }
}
// TODO(crbug.com/374124998): We should add more testing.

}  // namespace
}  // namespace blink

"""

```