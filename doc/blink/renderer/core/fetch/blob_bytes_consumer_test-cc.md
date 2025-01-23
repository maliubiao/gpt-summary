Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `blob_bytes_consumer_test.cc` immediately suggests it's a test file for something called `BlobBytesConsumer`. The `_test.cc` suffix is a standard convention in C++ testing (especially within Chromium).

2. **Examine Includes:** The included headers provide crucial context.
    * `<third_party/blink/...>` indicates this is part of the Blink rendering engine.
    * `blob_bytes_consumer.h`: This is the header for the class being tested. This is the primary subject of the test.
    * `testing/gtest/include/gtest/gtest.h`:  Confirms this uses the Google Test framework.
    * `bytes_consumer_test_util.h`, `bytes_consumer_test_reader.h`: These likely contain utility functions and helper classes for testing `BytesConsumer` implementations.
    * Headers related to `frame`, `loader`, `blob`, `network`: These indicate the context in which `BlobBytesConsumer` operates – within the fetching and loading pipeline of the rendering engine, dealing with `Blob` objects.

3. **Understand the Test Structure:**  The code uses `TEST_F` which is a Google Test macro for defining test cases within a *fixture* class. The `BlobBytesConsumerTest` class is the fixture, inheriting from `PageTestBase`. This suggests the tests need a minimal page environment to run. The `SetUp()` method further confirms this by initializing a page.

4. **Analyze Individual Test Cases (`TEST_F` blocks):**  Go through each test case, trying to understand what it's testing:
    * `TwoPhaseRead`:  This tests the typical read operation in two steps: `BeginRead` followed by actually consuming the data. It also checks that `DrainAsBlobDataHandle` and `DrainAsFormData` return null before the read is complete.
    * `CancelBeforeStarting`: Tests the behavior when cancellation occurs before any data is read. It checks the state and confirms no loading has started.
    * `CancelAfterStarting`: Tests cancellation after a read operation has been initiated.
    * `DrainAsBlobDataHandle`:  Focuses on the `DrainAsBlobDataHandle` method, verifying it returns the correct `BlobDataHandle` and transitions the consumer to a closed state. There are multiple variations of this test, likely testing different scenarios (e.g., valid vs. invalid blob size).
    * `DrainAsFormData`: Tests the `DrainAsFormData` method, ensuring it correctly creates an `EncodedFormData` containing the blob.
    * `ConstructedFromNullHandle`: Tests the case where the `BlobBytesConsumer` is initialized with a null `BlobDataHandle`.

5. **Infer Functionality of `BlobBytesConsumer`:** Based on the tests, we can deduce the responsibilities of `BlobBytesConsumer`:
    * Consuming data from a `BlobDataHandle`.
    * Providing a way to read the data in chunks (`BeginRead`).
    * Allowing cancellation of the read operation.
    * Providing methods to extract the data as either a `BlobDataHandle` or `EncodedFormData`.
    * Maintaining a state (e.g., `kReadableOrWaiting`, `kClosed`).

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Consider how Blobs are used in web development.
    * **JavaScript `Blob` API:** This is the most direct connection. The C++ `BlobBytesConsumer` is the underlying implementation that handles the data within a JavaScript `Blob` object.
    * **`FileReader` API:** When JavaScript uses `FileReader` to read a Blob, this C++ code is likely involved in streaming the data.
    * **`fetch` API:**  When fetching resources, the response body can be a Blob. `BlobBytesConsumer` would be used to handle the incoming data.
    * **Form submission:**  Blobs can be part of form data submitted to a server. `DrainAsFormData` is directly relevant here.
    * **`createObjectURL`:**  While not directly tested, the creation of a Blob URL would involve the underlying Blob data handled by this component.

7. **Consider User/Programming Errors:** Think about how developers might misuse the Blob API and how the `BlobBytesConsumer` might handle those scenarios. The tests themselves hint at some:
    * Cancelling a read operation.
    * Trying to read after cancellation or draining.
    * Dealing with Blobs of potentially unknown or invalid sizes.

8. **Trace User Operations (Debugging):**  Imagine a user interacting with a web page and how that might lead to this code being executed:
    * Downloading a large file.
    * Using JavaScript to create a Blob from user input or other data.
    * Submitting a form with a file upload.
    * Using the `fetch` API to retrieve a resource where the server sends a Blob.

9. **Hypothesize Inputs and Outputs:** For specific test cases, think about the input to the `BlobBytesConsumer` (the `BlobDataHandle`) and the expected output (the read data, the drained Blob/FormData, the state transitions). The test cases themselves provide clear examples.

10. **Refine and Structure the Answer:** Organize the information logically, starting with the core functionality, then connecting it to web technologies, user errors, and debugging. Use clear examples to illustrate the relationships.

By following this systematic approach, combining code analysis with knowledge of web technologies and common usage patterns, we can generate a comprehensive explanation of the `blob_bytes_consumer_test.cc` file and its role within the Chromium browser.
这是 `blink/renderer/core/fetch/blob_bytes_consumer_test.cc` 文件，是 Chromium Blink 引擎中用于测试 `BlobBytesConsumer` 类的单元测试文件。 `BlobBytesConsumer` 的作用是从一个 `BlobDataHandle` 中消费（读取）字节数据。

**功能列举:**

该测试文件的主要功能是：

1. **验证 `BlobBytesConsumer` 的基本读取功能:**
   - 测试 `BeginRead` 方法是否能正确启动读取过程。
   - 测试是否能分阶段读取 Blob 数据（`TwoPhaseRead` 测试用例）。
   - 验证读取完成后，消费者状态是否正确。

2. **测试 `BlobBytesConsumer` 的取消功能:**
   - 测试在读取开始之前取消读取 (`CancelBeforeStarting` 测试用例)。
   - 测试在读取开始之后取消读取 (`CancelAfterStarting` 测试用例)。
   - 验证取消操作是否会阻止实际的 Blob 读取操作。

3. **测试 `BlobBytesConsumer` 将数据导出为 `BlobDataHandle` 的功能:**
   - 测试 `DrainAsBlobDataHandle` 方法，验证它可以将已消费的数据再次以 `BlobDataHandle` 的形式返回 (`DrainAsBlobDataHandle`, `DrainAsBlobDataHandle_2` 测试用例)。
   - 测试 `DrainAsBlobDataHandle` 对于大小未知的 Blob 的处理 (`DrainAsBlobDataHandle_3` 测试用例)。

4. **测试 `BlobBytesConsumer` 将数据导出为 `EncodedFormData` 的功能:**
   - 测试 `DrainAsFormData` 方法，验证它可以将 Blob 数据转换为可以用于表单提交的 `EncodedFormData` 对象 (`DrainAsFormData` 测试用例)。

5. **测试 `BlobBytesConsumer` 在使用空 `BlobDataHandle` 初始化时的行为:**
   - 测试当使用 `nullptr` 初始化 `BlobBytesConsumer` 时，其状态和读取操作的行为 (`ConstructedFromNullHandle` 测试用例)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`BlobBytesConsumer` 位于 Blink 渲染引擎的核心部分，它处理浏览器内部对 Blob 数据的操作。Blob 对象在 JavaScript 中广泛使用，用于处理二进制大型对象，例如用户上传的文件、通过网络接收的数据等。

* **JavaScript `Blob` API:** 当 JavaScript 代码创建一个 `Blob` 对象时，底层会创建一个对应的 `BlobDataHandle` 来管理实际的二进制数据。`BlobBytesConsumer` 就是用来读取这个 `BlobDataHandle` 中的数据的。

   ```javascript
   // JavaScript 示例
   const blob = new Blob(['Hello, Blob!'], { type: 'text/plain' });

   const reader = new FileReader();
   reader.onload = function() {
     console.log(reader.result); // "Hello, Blob!"
   };
   reader.readAsText(blob);
   ```

   在这个例子中，当 `FileReader` 读取 `blob` 的内容时，Blink 内部会使用类似于 `BlobBytesConsumer` 的机制来读取 Blob 的数据。

* **`fetch` API 的响应体:** 当使用 `fetch` API 请求网络资源，且响应体的类型为 Blob 时，Blink 引擎会创建一个 `BlobDataHandle` 来存储响应体的数据。 `BlobBytesConsumer` 可以被用来消费这个响应体的数据。

   ```javascript
   // JavaScript 示例
   fetch('https://example.com/image.png')
     .then(response => response.blob())
     .then(blob => {
       // blob 是一个 Blob 对象
       console.log(blob.type); // "image/png"
     });
   ```

   当 `response.blob()` 被调用时，Blink 内部会使用相应的机制（可能涉及到 `BlobBytesConsumer`）来读取响应体的数据并创建 Blob 对象。

* **`FormData` 和文件上传:** 当在 HTML 表单中使用 `<input type="file">` 上传文件时，JavaScript 可以将这些文件作为 `Blob` 对象添加到 `FormData` 中。 `BlobBytesConsumer` 的 `DrainAsFormData` 方法模拟了将 Blob 数据添加到表单数据的过程。

   ```html
   <!-- HTML 示例 -->
   <form id="myForm">
     <input type="file" id="fileInput" name="file">
     <button type="submit">提交</button>
   </form>

   <script>
     const form = document.getElementById('myForm');
     form.addEventListener('submit', (event) => {
       event.preventDefault();
       const fileInput = document.getElementById('fileInput');
       const file = fileInput.files[0];
       const formData = new FormData();
       formData.append('file', file);

       // 使用 fetch 或 XMLHttpRequest 发送 formData
     });
   </script>
   ```

   当 `FormData.append('file', file)` 被调用时，Blink 内部会将 `file` (一个 `Blob` 对象) 的数据表示添加到 `FormData` 中，这与 `BlobBytesConsumer` 的 `DrainAsFormData` 功能相关。

* **`createObjectURL`:**  `URL.createObjectURL()` 方法可以为 Blob 对象创建一个临时的 URL，这个 URL 可以用于 `<img>` 标签或其他需要 URL 的地方来显示或访问 Blob 的内容。  虽然测试文件没有直接测试 `createObjectURL`，但 `BlobBytesConsumer` 处理的是 Blob 的底层数据，因此与这个功能也有间接联系。

**逻辑推理，假设输入与输出:**

以 `TwoPhaseRead` 测试用例为例：

**假设输入:**

* 一个包含字符串 "hello, world" 的 `BlobDataHandle`。
* 一个新创建的 `BlobBytesConsumer` 对象，使用上述 `BlobDataHandle` 初始化。

**逻辑推理:**

1. 初始化后，`consumer->GetPublicState()` 应该为 `PublicState::kReadableOrWaiting`，表示可以读取或等待读取。
2. 第一次调用 `consumer->BeginRead(buffer)` 时，由于没有提供足够的缓冲区，应该返回 `Result::kShouldWait`，表示需要等待。同时，Blob 的读取操作应该开始 (`DidStartLoading()` 返回 `true`)。
3. `DrainAsBlobDataHandle` 和 `DrainAsFormData` 在读取完成前不应返回有效数据。
4. 通过 `BytesConsumerTestReader` 读取所有数据后，`result.first` 应该为 `Result::kDone`，表示读取完成，`result.second` 应该为 "hello, world"，表示成功读取到 Blob 的内容。

**假设输出:**

* `consumer->GetPublicState()` (初始): `PublicState::kReadableOrWaiting`
* `DidStartLoading()` (第一次 `BeginRead` 后): `true`
* `consumer->BeginRead(buffer)` (第一次): `Result::kShouldWait`
* `consumer->DrainAsBlobDataHandle(...)`: `nullptr` (或 `false`)
* `consumer->DrainAsFormData()`: `nullptr` (或 `false`)
* `consumer->GetPublicState()` (读取过程中): `PublicState::kReadableOrWaiting`
* `BytesConsumerTestReader::Run().first`: `Result::kDone`
* `BytesConsumerTestReader::Run().second`: `"hello, world"`

**用户或编程常见的使用错误举例说明:**

* **过早调用 `DrainAsBlobDataHandle` 或 `DrainAsFormData`:**  如果开发者在数据完全读取完成之前尝试调用这些方法，可能会得到空指针或不完整的数据。

   ```javascript
   const blob = new Blob(['some data']);
   const reader = new FileReader();
   reader.onloadstart = function() {
     // 错误：在数据加载开始时就尝试获取 Blob
     const url = URL.createObjectURL(blob); // 可能会创建一个不完整的 Blob URL
   };
   reader.readAsArrayBuffer(blob);
   ```

* **忘记处理异步读取:** Blob 的读取通常是异步的。开发者需要使用 `onload` 等事件来处理读取完成后的数据，而不是同步地期望数据立即可用。

   ```javascript
   const blob = new Blob(['more data']);
   const reader = new FileReader();
   reader.readAsText(blob);
   // 错误：假设 reader.result 已经可用
   console.log(reader.result); // 可能为 null 或空字符串
   reader.onload = function() {
     console.log(reader.result); // 正确的处理方式
   };
   ```

* **取消读取后继续操作:** 如果在读取 Blob 的过程中取消了操作，开发者不应再尝试读取或使用相关的资源，因为状态可能已经变为 `kClosed`。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户在浏览器中进行以下操作时，可能会触发与 Blob 处理相关的代码，最终可能涉及到 `BlobBytesConsumer`：

1. **用户上传文件:**
   - 用户点击 `<input type="file">` 元素选择文件。
   - 浏览器读取文件内容并创建 `Blob` 对象。
   - 当 JavaScript 代码使用 `FileReader` 或 `fetch` API 处理这个 Blob 时，`BlobBytesConsumer` 可能会被用来读取 Blob 的数据。

2. **网页使用 JavaScript 创建 Blob:**
   - JavaScript 代码使用 `new Blob()` 创建 Blob 对象。
   - 这个 Blob 对象的数据可能需要被读取，例如通过 `FileReader` 或发送到服务器。

3. **网页通过 `fetch` API 下载数据，响应类型为 Blob:**
   - 用户访问一个返回 Blob 数据的 URL。
   - `fetch` API 获取响应，并将响应体作为 Blob 对象处理。
   - 浏览器需要读取响应体的数据来构建 Blob 对象。

**调试线索:**

如果在调试过程中遇到了与 Blob 处理相关的问题，可以关注以下线索：

* **查看网络请求:** 确认请求的响应头中 `Content-Type` 是否指示了 Blob 类型的数据。
* **检查 JavaScript 代码:** 确认 JavaScript 代码中对 Blob 的操作是否正确，例如是否正确使用了 `FileReader` 或 `fetch` API。
* **断点调试:** 在 Blink 渲染引擎的相关代码中设置断点，例如在 `BlobBytesConsumer` 的 `BeginRead`、`DrainAsBlobDataHandle` 等方法中，查看 Blob 的读取和处理过程。
* **查看 Blink 的日志:** Blink 引擎可能会输出与 Blob 处理相关的日志信息，可以帮助定位问题。
* **检查 Blob 的状态:** 如果有可能，在 JavaScript 中检查 Blob 对象的大小和类型，以确保 Blob 对象本身是有效的。

总而言之，`blob_bytes_consumer_test.cc` 文件通过一系列单元测试，确保了 `BlobBytesConsumer` 类能够正确地从 Blob 数据源读取和处理数据，这对于浏览器中涉及 Blob 对象的各种功能至关重要。

### 提示词
```
这是目录为blink/renderer/core/fetch/blob_bytes_consumer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/fetch/bytes_consumer_test_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/threadable_loader.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/blob/testing/fake_blob.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

using PublicState = BytesConsumer::PublicState;
using Result = BytesConsumer::Result;

class BlobBytesConsumerTestClient final
    : public GarbageCollected<BlobBytesConsumerTestClient>,
      public BytesConsumer::Client {
 public:
  void OnStateChange() override { ++num_on_state_change_called_; }
  String DebugName() const override { return "BlobBytesConsumerTestClient"; }
  int NumOnStateChangeCalled() const { return num_on_state_change_called_; }

 private:
  int num_on_state_change_called_ = 0;
};

class BlobBytesConsumerTest : public PageTestBase {
 public:
  void SetUp() override { PageTestBase::SetUp(gfx::Size(1, 1)); }
  scoped_refptr<BlobDataHandle> CreateBlob(const String& body) {
    mojo::PendingRemote<mojom::blink::Blob> mojo_blob;
    mojo::MakeSelfOwnedReceiver(
        std::make_unique<FakeBlob>(kBlobUUID, body, &blob_state_),
        mojo_blob.InitWithNewPipeAndPassReceiver());
    return BlobDataHandle::Create(kBlobUUID, "", body.length(),
                                  std::move(mojo_blob));
  }

  bool DidStartLoading() {
    base::RunLoop().RunUntilIdle();
    return blob_state_.did_initiate_read_operation;
  }

 private:
  const String kBlobUUID = "blob-id";
  FakeBlob::State blob_state_;
};

TEST_F(BlobBytesConsumerTest, TwoPhaseRead) {
  String body = "hello, world";
  scoped_refptr<BlobDataHandle> blob_data_handle = CreateBlob(body);

  BlobBytesConsumer* consumer = MakeGarbageCollected<BlobBytesConsumer>(
      GetFrame().DomWindow(), blob_data_handle);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());

  base::span<const char> buffer;
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  EXPECT_TRUE(DidStartLoading());
  EXPECT_FALSE(consumer->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize));
  EXPECT_FALSE(consumer->DrainAsFormData());
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());

  auto result =
      (MakeGarbageCollected<BytesConsumerTestReader>(consumer))->Run();
  EXPECT_EQ(Result::kDone, result.first);
  EXPECT_EQ("hello, world", String(result.second));
}

TEST_F(BlobBytesConsumerTest, CancelBeforeStarting) {
  scoped_refptr<BlobDataHandle> blob_data_handle = CreateBlob("foo bar");
  BlobBytesConsumer* consumer = MakeGarbageCollected<BlobBytesConsumer>(
      GetFrame().DomWindow(), blob_data_handle);
  BlobBytesConsumerTestClient* client =
      MakeGarbageCollected<BlobBytesConsumerTestClient>();
  consumer->SetClient(client);

  consumer->Cancel();

  base::span<const char> buffer;
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());
  EXPECT_EQ(0, client->NumOnStateChangeCalled());
}

TEST_F(BlobBytesConsumerTest, CancelAfterStarting) {
  scoped_refptr<BlobDataHandle> blob_data_handle = CreateBlob("foo bar");
  BlobBytesConsumer* consumer = MakeGarbageCollected<BlobBytesConsumer>(
      GetFrame().DomWindow(), blob_data_handle);
  BlobBytesConsumerTestClient* client =
      MakeGarbageCollected<BlobBytesConsumerTestClient>();
  consumer->SetClient(client);

  base::span<const char> buffer;
  EXPECT_EQ(Result::kShouldWait, consumer->BeginRead(buffer));
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_EQ(0, client->NumOnStateChangeCalled());

  consumer->Cancel();
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
  EXPECT_EQ(0, client->NumOnStateChangeCalled());
  EXPECT_TRUE(DidStartLoading());
}

TEST_F(BlobBytesConsumerTest, DrainAsBlobDataHandle) {
  String body = "hello, world";
  scoped_refptr<BlobDataHandle> blob_data_handle = CreateBlob(body);
  BlobBytesConsumer* consumer = MakeGarbageCollected<BlobBytesConsumer>(
      GetFrame().DomWindow(), blob_data_handle);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());

  scoped_refptr<BlobDataHandle> result = consumer->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize);
  ASSERT_TRUE(result);
  EXPECT_FALSE(consumer->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize));
  EXPECT_EQ(body.length(), result->size());
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());
}

TEST_F(BlobBytesConsumerTest, DrainAsBlobDataHandle_2) {
  scoped_refptr<BlobDataHandle> blob_data_handle =
      BlobDataHandle::Create("uuid", "", std::numeric_limits<uint64_t>::max(),
                             CreateBlob("foo bar")->CloneBlobRemote());
  BlobBytesConsumer* consumer = MakeGarbageCollected<BlobBytesConsumer>(
      GetFrame().DomWindow(), blob_data_handle);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());

  scoped_refptr<BlobDataHandle> result = consumer->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize);
  ASSERT_TRUE(result);
  EXPECT_FALSE(consumer->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize));
  EXPECT_EQ(UINT64_MAX, result->size());
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());
}

TEST_F(BlobBytesConsumerTest, DrainAsBlobDataHandle_3) {
  scoped_refptr<BlobDataHandle> blob_data_handle =
      BlobDataHandle::Create("uuid", "", std::numeric_limits<uint64_t>::max(),
                             CreateBlob("foo bar")->CloneBlobRemote());
  BlobBytesConsumer* consumer = MakeGarbageCollected<BlobBytesConsumer>(
      GetFrame().DomWindow(), blob_data_handle);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());

  EXPECT_FALSE(consumer->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize));
  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());
}

TEST_F(BlobBytesConsumerTest, DrainAsFormData) {
  String body = "hello, world";
  scoped_refptr<BlobDataHandle> blob_data_handle = CreateBlob(body);
  BlobBytesConsumer* consumer = MakeGarbageCollected<BlobBytesConsumer>(
      GetFrame().DomWindow(), blob_data_handle);

  EXPECT_EQ(PublicState::kReadableOrWaiting, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());

  scoped_refptr<EncodedFormData> result = consumer->DrainAsFormData();
  ASSERT_TRUE(result);
  ASSERT_EQ(1u, result->Elements().size());
  ASSERT_EQ(FormDataElement::kEncodedBlob, result->Elements()[0].type_);
  ASSERT_TRUE(result->Elements()[0].blob_data_handle_);
  EXPECT_EQ(body.length(), result->Elements()[0].blob_data_handle_->size());
  EXPECT_EQ(blob_data_handle, result->Elements()[0].blob_data_handle_);
  EXPECT_EQ(PublicState::kClosed, consumer->GetPublicState());
  EXPECT_FALSE(DidStartLoading());
}

TEST_F(BlobBytesConsumerTest, ConstructedFromNullHandle) {
  BlobBytesConsumer* consumer =
      MakeGarbageCollected<BlobBytesConsumer>(GetFrame().DomWindow(), nullptr);
  base::span<const char> buffer;
  EXPECT_EQ(BytesConsumer::PublicState::kClosed, consumer->GetPublicState());
  EXPECT_EQ(Result::kDone, consumer->BeginRead(buffer));
}

}  // namespace

}  // namespace blink
```