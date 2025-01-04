Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of `fetch_data_loader_test.cc`, its relation to web technologies, logical inferences, common errors, debugging context, and a summary of its purpose. The "Part 1 of 2" hints that there will be more to analyze later.

**2. High-Level Structure and Keywords:**

First, I scan the file for obvious clues:

* **`// Copyright ...`**:  Indicates standard Chromium/Blink licensing. Not directly functional but good to note.
* **`#include ...`**:  Lists dependencies. I recognize some key ones:
    *  `fetch_data_loader.h`:  The class being tested.
    *  `testing/gmock/include/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  Indicates this is a unit test file using Google Test and Google Mock.
    *  `core/fetch/...`, `core/fileapi/...`, `core/html/...`:  Points to the core fetch, file API, and HTML functionalities within Blink. This is a strong indication of the file's purpose.
    *  `platform/loader/fetch/...`:  More loading-related components.
    *  `platform/scheduler/...`:  Related to task scheduling.
* **`namespace blink { namespace { ... } }`**:  Standard C++ namespacing.

**3. Identifying Test Fixtures:**

I look for classes that inherit from `testing::Test`. These set up the testing environment:

* `FetchDataLoaderTest`: Basic setup.
* `FetchDataLoaderBlobTest`:  Specifically for testing Blob-related functionality. The constructor involving `FakeBlobRegistry` confirms this.

**4. Analyzing Helper Structures and Functions:**

* `PipingClient`:  This looks like a custom client for `FetchDataLoader` that directly pipes data to a `DataPipeBytesConsumer`. This is a strong clue that `FetchDataLoader` deals with data pipes.
* `ACTION_P(QUITLOOP, loop)`: A Google Mock action to quit a `base::RunLoop`. This tells me asynchronous operations are being tested.

**5. Deconstructing Individual Tests (The Core Functionality):**

I go through each `TEST_F` function and try to understand its purpose by:

* **Test Name:**  The name usually gives a good indication (e.g., `LoadAsBlob`, `LoadAsArrayBufferFailed`, `LoadAsFormData`).
* **Mock Objects:** The use of `StrictMock<testing::MockFunction<void(int)>> Checkpoint;` and `MakeGarbageCollected<MockBytesConsumer>()` along with `MockFetchDataLoaderClient` are clear signs of testing interactions with dependencies using mocks.
* **`EXPECT_CALL` Statements:** These are the heart of the tests. They define the expected sequence of calls and their return values on the mock objects. I focus on what methods are being called on `MockBytesConsumer` and `MockFetchDataLoaderClient`.
* **`FetchDataLoader::CreateLoader...`:** This reveals the different ways `FetchDataLoader` can be configured (as blob, array buffer, form data, string).
* **`fetch_data_loader->Start(...)` and `fetch_data_loader->Cancel()`:**  Basic lifecycle operations of the loader.
* **Assertions (`ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_STREQ`):**  Verify the outcomes of the operations, such as the type, size, and content of the loaded data.
* **`base::RunLoop run_loop; run_loop.Run();` and `fake_task_runner_->RunUntilIdle();`:**  Confirm the testing of asynchronous operations and the need to pump the task runner.

**6. Connecting to Web Technologies (JavaScript, HTML, CSS):**

As I analyze the tests, I think about how these data types (`Blob`, `ArrayBuffer`, `FormData`, `String`) are used in web development:

* **Blob:**  Used for representing raw binary data, often for files or media. Relates to `<input type="file">`, `FileReader`, `fetch()` API for binary data.
* **ArrayBuffer:**  A raw binary data buffer, often used for more low-level data manipulation in JavaScript. Related to `XMLHttpRequest`, `WebSockets`, and Typed Arrays.
* **FormData:** Used for submitting forms via the `fetch()` or `XMLHttpRequest` API. Directly related to HTML `<form>` elements.
* **String:**  Basic text data, fundamental to HTML content, JavaScript strings, and CSS values.

**7. Logical Inferences and Hypothetical Inputs/Outputs:**

For tests that seem to involve data manipulation (like `LoadAsFormData`), I mentally run through the process with the provided example data (`kQuickBrownFoxFormData`). I anticipate how the boundary delimiters are used to separate form entries and how the content disposition and type headers are parsed.

**8. Identifying Potential User Errors:**

I consider scenarios where a developer might misuse these APIs:

* Incorrect `Content-Type` headers when creating Blobs.
* Providing an incorrect boundary string when processing `FormData`.
* Cancelling a fetch operation prematurely and not handling the potential lack of data.

**9. Debugging Context:**

I think about how a developer might end up debugging this code:

* Investigating issues with file uploads or form submissions.
* Debugging errors related to fetching binary data or media.
* Tracing the flow of data when using the `fetch()` API.

**10. Summarizing the Functionality:**

After analyzing the individual tests, I can synthesize the overall purpose of the file: to rigorously test the `FetchDataLoader` class in Blink, covering various ways to load data (as Blob, ArrayBuffer, FormData, String) and different success and failure scenarios, including cancellation.

**Self-Correction/Refinement During Analysis:**

* Initially, I might just see a lot of `EXPECT_CALL` statements. I then need to connect these back to the *actions* being tested on `FetchDataLoader`.
* I might need to refer back to the included headers to fully understand the types being used (e.g., `BlobDataHandle`, `FormData`).
* If a test name is unclear, I examine the `EXPECT_CALL` sequence to infer its purpose.

By following this systematic approach, I can effectively analyze the C++ test file and extract the requested information. The process involves understanding the testing framework, the specific code being tested, and its relationship to broader web technologies.
好的，我们来分析一下 `blink/renderer/core/fetch/fetch_data_loader_test.cc` 这个文件的功能。

**文件功能归纳：**

这个 C++ 文件是 Chromium Blink 引擎中 `FetchDataLoader` 类的单元测试文件。它的主要功能是：

1. **测试 `FetchDataLoader` 类的各种数据加载方式：**  它测试了 `FetchDataLoader` 将网络或本地数据加载为 `Blob`、`ArrayBuffer`、`FormData` 和字符串 (String) 的功能。
2. **测试加载过程中的成功和失败场景：**  测试了数据成功加载、加载失败（例如，网络错误、数据格式错误）以及加载被取消的情况。
3. **验证 `FetchDataLoader` 与 `BytesConsumer` 的交互：**  `FetchDataLoader` 依赖于 `BytesConsumer` 来接收和处理数据流，这个测试文件模拟了 `BytesConsumer` 的行为，并验证了 `FetchDataLoader` 与其之间的正确交互。
4. **使用 Mock 对象进行隔离测试：**  为了隔离被测试单元，该文件使用了 Google Mock 框架来模拟依赖项的行为，例如 `MockBytesConsumer` 和 `MockFetchDataLoaderClient`。
5. **测试异步操作：**  数据加载通常是异步的，该文件使用了 `base::RunLoop` 和 `fake_task_runner_` 来模拟和控制异步操作的执行，确保测试的准确性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`FetchDataLoader` 位于 Blink 引擎的核心网络层，负责处理网络请求的数据。它加载的数据最终会被 JavaScript API 使用，并影响 HTML 页面的渲染和 CSS 样式的应用。

1. **JavaScript 和 Blob：**
   - **功能关系：** JavaScript 的 `fetch()` API 可以请求资源并将响应体作为 `Blob` 对象返回。`FetchDataLoader` 的 `CreateLoaderAsBlobHandle` 方法就是用来测试这种场景。
   - **举例说明：**
     ```javascript
     fetch('image.png')
       .then(response => response.blob())
       .then(blob => {
         // 使用 blob 对象，例如显示图片
         const imageUrl = URL.createObjectURL(blob);
         const img = document.createElement('img');
         img.src = imageUrl;
         document.body.appendChild(img);
       });
     ```
     在这个例子中，`FetchDataLoader` 负责下载 `image.png` 的数据，并将其转换为 `Blob` 对象，最终传递给 JavaScript。该测试文件会模拟 `FetchDataLoader` 将数据加载为 `Blob` 的过程。

2. **JavaScript 和 ArrayBuffer：**
   - **功能关系：** `fetch()` API 也可以将响应体作为 `ArrayBuffer` 返回，用于处理二进制数据。`FetchDataLoader` 的 `CreateLoaderAsArrayBuffer` 方法测试了这种场景。
   - **举例说明：**
     ```javascript
     fetch('data.bin')
       .then(response => response.arrayBuffer())
       .then(buffer => {
         // 使用 ArrayBuffer，例如进行 WebGL 渲染
         const dataView = new DataView(buffer);
         // ... 使用 dataView 读取二进制数据
       });
     ```
     `FetchDataLoader` 负责下载 `data.bin` 的原始二进制数据，并将其转化为 `ArrayBuffer` 提供给 JavaScript。

3. **JavaScript 和 FormData：**
   - **功能关系：** 当使用 `fetch()` 或 `<form>` 元素提交表单时，数据可以被编码为 `FormData` 对象。`FetchDataLoader` 的 `CreateLoaderAsFormData` 方法测试了如何解析这种格式的数据。
   - **举例说明：**
     ```html
     <form id="myForm">
       <input type="text" name="username" value="test">
       <input type="file" name="avatar">
       <button type="submit">提交</button>
     </form>
     <script>
       const form = document.getElementById('myForm');
       form.addEventListener('submit', (event) => {
         event.preventDefault();
         const formData = new FormData(form);
         fetch('/submit', {
           method: 'POST',
           body: formData
         });
       });
     </script>
     ```
     当表单提交时，浏览器会将表单数据编码成 `FormData`。在 Blink 引擎内部，`FetchDataLoader` 会负责解析接收到的 `FormData` 数据。测试文件中的 `kQuickBrownFoxFormData` 常量模拟了 `FormData` 的数据格式。

4. **JavaScript 和 String：**
   - **功能关系：** `fetch()` API 可以将响应体作为文本字符串返回。`FetchDataLoader` 的 `CreateLoaderAsString` 方法测试了这种场景。这对于加载 HTML, CSS, JavaScript 或其他文本资源非常重要。
   - **举例说明：**
     ```javascript
     fetch('style.css')
       .then(response => response.text())
       .then(cssText => {
         // 将 CSS 文本添加到页面
         const style = document.createElement('style');
         style.textContent = cssText;
         document.head.appendChild(style);
       });
     ```
     `FetchDataLoader` 负责下载 `style.css` 的文本内容，并将其解码为字符串提供给 JavaScript。

**逻辑推理与假设输入/输出：**

以下是一些基于测试用例的逻辑推理和假设输入/输出：

1. **`LoadAsBlob` 测试：**
   - **假设输入：** 一个 `MockBytesConsumer`，它模拟了提供字符串 "Quick brown fox" 的数据流。
   - **逻辑推理：** `FetchDataLoader` 被配置为加载 Blob 数据。它应该从 `BytesConsumer` 读取数据，创建一个 `BlobDataHandle`，并将数据存储在其中。
   - **预期输出：** `DidFetchDataLoadedBlobHandleMock` 回调函数被调用，并传递一个指向包含 "Quick brown fox" 数据的 `BlobDataHandle` 的指针，其 `size` 为 16（包含 null 终止符），`type` 为 "text/test"。

2. **`LoadAsFormData` 测试：**
   - **假设输入：** 一个 `MockBytesConsumer`，它模拟了提供 `kQuickBrownFoxFormData` 字符串的数据流。
   - **逻辑推理：** `FetchDataLoader` 被配置为加载 FormData，边界字符串为 "boundary"。它应该解析输入流，识别不同的表单字段（包括文件和文本），并创建相应的 `FormData` 对象。
   - **预期输出：** `DidFetchDataLoadedFormDataMock` 回调函数被调用，并传递一个指向 `FormData` 对象的指针，该对象包含四个条目，分别对应 `kQuickBrownFoxFormData` 中的四个部分，并且正确解析了名称、文件名、内容和内容类型。

3. **`LoadAsStringFailed` 测试：**
   - **假设输入：** 一个 `MockBytesConsumer`，它开始提供数据，但在读取过程中返回 `Result::kError`。
   - **逻辑推理：** `FetchDataLoader` 尝试从 `BytesConsumer` 读取数据，但遇到了错误。
   - **预期输出：** `DidFetchDataLoadFailed` 回调函数被调用，表明加载失败。

**用户或编程常见的使用错误：**

1. **Blob 加载时指定了错误的 Content-Type：**
   - 用户可能在 JavaScript 中使用 `fetch()` 并手动设置了错误的 `Content-Type` 请求头，或者服务器返回了错误的 `Content-Type` 响应头。这可能导致 `FetchDataLoader` 创建 `Blob` 时使用了错误的类型信息。
   - **测试用例体现：** 虽然测试用例中直接控制了 Blob 的类型，但在实际场景中，如果服务器返回了错误的 `Content-Type`，可能会导致后续的 Blob 处理出现问题，例如图片无法正确显示。

2. **FormData 加载时使用了错误的边界字符串：**
   - 如果在创建 `FormData` 加载器时指定的边界字符串与实际 `multipart/form-data` 的边界不匹配，`FetchDataLoader` 将无法正确解析数据。
   - **测试用例体现：** `LoadAsFormDataPartialInput` 测试用例模拟了数据不完整的情况，这可能类似于边界字符串错误导致解析提前结束。如果边界不匹配，解析会失败。

3. **过早取消 Fetch 请求：**
   - 用户可能在 JavaScript 中调用了 `AbortController.abort()` 来取消一个正在进行的 `fetch` 请求。
   - **测试用例体现：** 多个测试用例（例如 `LoadAsBlobCancel`, `LoadAsArrayBufferCancel`）显式地调用了 `fetch_data_loader->Cancel()`，模拟了取消操作，并验证了取消后不会再有成功回调。

**用户操作到达这里的步骤 (调试线索)：**

假设用户遇到了一个与网络资源加载相关的问题，并且需要深入到 Blink 引擎的层面进行调试，以下是可能到达 `fetch_data_loader_test.cc` 的一些步骤：

1. **用户在浏览器中访问一个网页。**
2. **网页上的 JavaScript 代码使用 `fetch()` API 发起了一个网络请求，例如请求一个图片、JSON 数据或提交一个表单。**
3. **在 Blink 引擎内部，`FetchRequest` 对象被创建，并交给网络层处理。**
4. **网络层接收到响应数据后，会创建一个 `BytesConsumer` 来接收数据流。**
5. **根据请求的类型（例如，`response.blob()`, `response.arrayBuffer()`, `response.text()`, 或 `FormData` 的处理），会创建一个相应的 `FetchDataLoader` 实例。**
6. **`FetchDataLoader` 开始从 `BytesConsumer` 读取数据并进行相应的处理（例如，创建 Blob 对象，解析 FormData）。**
7. **如果在加载过程中出现问题（例如，网络错误、数据格式错误、请求被取消），开发者可能会尝试以下调试步骤：**
   - **使用 Chrome 开发者工具的网络面板查看请求的详细信息，包括请求头、响应头和响应内容。**
   - **在 "Sources" 面板中设置断点，尝试跟踪 JavaScript 代码中 `fetch()` API 的执行流程。**
   - **如果怀疑是 Blink 引擎内部的问题，开发者（通常是 Chromium 的贡献者或深入研究者）可能会需要查看 Blink 的源代码。**
   - **根据问题现象，可能会定位到 `core/fetch` 目录下的相关代码，例如 `FetchDataLoader` 或 `BytesConsumer`。**
   - **为了验证 `FetchDataLoader` 的行为是否符合预期，开发者可能会参考或运行 `fetch_data_loader_test.cc` 中的单元测试用例，以了解 `FetchDataLoader` 在各种情况下的预期行为。**
   - **例如，如果怀疑 Blob 加载有问题，可能会查看 `LoadAsBlob` 相关的测试用例。如果怀疑 FormData 解析有问题，可能会查看 `LoadAsFormData` 相关的测试用例。**
   - **通过阅读测试用例的代码，开发者可以了解 `FetchDataLoader` 的工作原理、依赖关系以及如何使用 Mock 对象进行测试，从而更好地理解和调试实际遇到的问题。**

**总结：**

`blink/renderer/core/fetch/fetch_data_loader_test.cc` 是一个关键的单元测试文件，用于确保 `FetchDataLoader` 类在各种数据加载场景下的正确性和稳定性。它覆盖了将网络数据加载为 JavaScript 可以使用的各种数据类型的场景，并测试了成功、失败和取消等不同的结果。这个文件对于理解 Blink 引擎如何处理网络请求的数据至关重要，并且可以作为调试网络加载相关问题的起点。

Prompt: 
```
这是目录为blink/renderer/core/fetch/fetch_data_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/fetch_data_loader.h"

#include <memory>

#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/fetch/bytes_consumer_test_util.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/platform/blob/testing/fake_blob_registry.h"
#include "third_party/blink/renderer/platform/loader/fetch/data_pipe_bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/loader/testing/bytes_consumer_test_reader.h"
#include "third_party/blink/renderer/platform/loader/testing/replaying_bytes_consumer.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

namespace {

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::InSequence;
using testing::Return;
using testing::SaveArg;
using testing::SetArgReferee;
using testing::StrictMock;
using Checkpoint = StrictMock<testing::MockFunction<void(int)>>;
using MockFetchDataLoaderClient =
    BytesConsumerTestUtil::MockFetchDataLoaderClient;
using MockBytesConsumer = BytesConsumerTestUtil::MockBytesConsumer;
using Result = BytesConsumer::Result;

constexpr char kQuickBrownFox[] = "Quick brown fox";
constexpr size_t kQuickBrownFoxLength = 15;
constexpr size_t kQuickBrownFoxLengthWithTerminatingNull = 16;
constexpr char kQuickBrownFoxFormData[] =
    "--boundary\r\n"
    "Content-Disposition: form-data; name=blob; filename=blob\r\n"
    "Content-Type: text/plain; charset=iso-8859-1\r\n"
    "\r\n"
    "Quick brown fox\r\n"
    "--boundary\r\n"
    "Content-Disposition: form-data; name=\"blob\xC2\xA0without\xC2\xA0type\"; "
    "filename=\"blob\xC2\xA0without\xC2\xA0type.txt\"\r\n"
    "\r\n"
    "Quick brown fox\r\n"
    "--boundary\r\n"
    "Content-Disposition: form-data; name=string\r\n"
    "\r\n"
    "Quick brown fox\r\n"
    "--boundary\r\n"
    "Content-Disposition: form-data; name=string-with-type\r\n"
    "Content-Type: text/plain; charset=invalid\r\n"
    "\r\n"
    "Quick brown fox\r\n"
    "--boundary--\r\n";
constexpr size_t kQuickBrownFoxFormDataLength =
    std::size(kQuickBrownFoxFormData) - 1u;

class FetchDataLoaderTest : public testing::Test {
 protected:
  struct PipingClient : public GarbageCollected<PipingClient>,
                        public FetchDataLoader::Client {
   public:
    explicit PipingClient(
        scoped_refptr<base::SingleThreadTaskRunner> task_runner)
        : task_runner_(std::move(task_runner)) {}

    void DidFetchDataStartedDataPipe(
        mojo::ScopedDataPipeConsumerHandle handle) override {
      DataPipeBytesConsumer::CompletionNotifier* notifier;
      destination_ = MakeGarbageCollected<DataPipeBytesConsumer>(
          task_runner_, std::move(handle), &notifier);
      completion_notifier_ = notifier;
    }
    void DidFetchDataLoadedDataPipe() override {
      completion_notifier_->SignalComplete();
    }
    void DidFetchDataLoadFailed() override {
      completion_notifier_->SignalError(BytesConsumer::Error());
    }
    void Abort() override {
      completion_notifier_->SignalError(BytesConsumer::Error());
    }

    BytesConsumer* GetDestination() { return destination_.Get(); }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(destination_);
      visitor->Trace(completion_notifier_);
      FetchDataLoader::Client::Trace(visitor);
    }

   private:
    const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
    Member<BytesConsumer> destination_;
    Member<DataPipeBytesConsumer::CompletionNotifier> completion_notifier_;
  };
  test::TaskEnvironment task_environment_;
};

class FetchDataLoaderBlobTest : public FetchDataLoaderTest {
 public:
  FetchDataLoaderBlobTest()
      : fake_task_runner_(base::MakeRefCounted<scheduler::FakeTaskRunner>()),
        blob_registry_receiver_(
            &fake_blob_registry_,
            blob_registry_remote_.BindNewPipeAndPassReceiver()) {
    BlobDataHandle::SetBlobRegistryForTesting(blob_registry_remote_.get());
  }

  ~FetchDataLoaderBlobTest() override {
    BlobDataHandle::SetBlobRegistryForTesting(nullptr);
  }

 protected:
  scoped_refptr<scheduler::FakeTaskRunner> fake_task_runner_;

 private:
  FakeBlobRegistry fake_blob_registry_;
  mojo::Remote<mojom::blink::BlobRegistry> blob_registry_remote_;
  mojo::Receiver<mojom::blink::BlobRegistry> blob_registry_receiver_;
};

ACTION_P(QUITLOOP, loop) {
  loop->Quit();
}

TEST_F(FetchDataLoaderBlobTest, LoadAsBlob) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsBlobHandle("text/test", fake_task_runner_);
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();
  scoped_refptr<BlobDataHandle> blob_data_handle;

  base::RunLoop run_loop;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer,
              DrainAsBlobDataHandle(
                  BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize))
      .WillOnce(Return(ByMove(nullptr)));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, DrainAsDataPipe());
  EXPECT_CALL(*consumer, GetPublicState())
      .WillOnce(Return(BytesConsumer::PublicState::kReadableOrWaiting));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(
          SetArgReferee<0>(base::span_with_nul_from_cstring(kQuickBrownFox)),
          Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxLengthWithTerminatingNull))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kDone));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadedBlobHandleMock(_))
      .WillOnce(DoAll(SaveArg<0>(&blob_data_handle), QUITLOOP(&run_loop)));
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  // Pump the |task_runner| to process the data pipe's task indicating its
  // writable.
  fake_task_runner_->RunUntilIdle();
  checkpoint.Call(3);
  client->OnStateChange();
  run_loop.Run();
  checkpoint.Call(4);

  ASSERT_TRUE(blob_data_handle);
  EXPECT_EQ(kQuickBrownFoxLengthWithTerminatingNull, blob_data_handle->size());
  EXPECT_EQ(String("text/test"), blob_data_handle->GetType());
}

TEST_F(FetchDataLoaderBlobTest, LoadAsBlobFailed) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsBlobHandle("text/test", fake_task_runner_);
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer,
              DrainAsBlobDataHandle(
                  BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize))
      .WillOnce(Return(ByMove(nullptr)));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, DrainAsDataPipe());
  EXPECT_CALL(*consumer, GetPublicState())
      .WillOnce(Return(BytesConsumer::PublicState::kReadableOrWaiting));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(
          SetArgReferee<0>(base::span_with_nul_from_cstring(kQuickBrownFox)),
          Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxLengthWithTerminatingNull))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kError));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadFailed());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  // Pump the |task_runner| to process the data pipe's task indicating its
  // writable.
  fake_task_runner_->RunUntilIdle();
  checkpoint.Call(3);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(4);
}

TEST_F(FetchDataLoaderBlobTest, LoadAsBlobCancel) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsBlobHandle("text/test", fake_task_runner_);
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer,
              DrainAsBlobDataHandle(
                  BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize))
      .WillOnce(Return(ByMove(nullptr)));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, DrainAsDataPipe());
  EXPECT_CALL(*consumer, GetPublicState())
      .WillOnce(Return(BytesConsumer::PublicState::kReadableOrWaiting));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  // Pump the |task_runner| to process the data pipe's task indicating its
  // writable.
  fake_task_runner_->RunUntilIdle();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);
}

TEST_F(FetchDataLoaderBlobTest, LoadAsBlobNoClientCallbacksAfterCancel) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsBlobHandle("text/test", fake_task_runner_);
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();
  scoped_refptr<BlobDataHandle> blob_data_handle;

  base::RunLoop run_loop;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer,
              DrainAsBlobDataHandle(
                  BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize))
      .WillOnce(Return(ByMove(nullptr)));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, DrainAsDataPipe());
  EXPECT_CALL(*consumer, GetPublicState())
      .WillOnce(Return(BytesConsumer::PublicState::kReadableOrWaiting));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(
          SetArgReferee<0>(base::span_with_nul_from_cstring(kQuickBrownFox)),
          Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxLengthWithTerminatingNull))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(4));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(5));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kDone));
  EXPECT_CALL(*consumer, Cancel());
  // This should never happen due to explicit FetchDataLoader::Cancel call.
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadedBlobHandleMock(_))
      .Times(0);
  EXPECT_CALL(checkpoint, Call(6));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  fake_task_runner_->RunUntilIdle();
  checkpoint.Call(3);
  client->OnStateChange();
  run_loop.RunUntilIdle();
  checkpoint.Call(4);
  // Cancel the load to verify no FetchDataLoader::Client calls happen
  // afterwards.
  fetch_data_loader->Cancel();
  checkpoint.Call(5);
  client->OnStateChange();
  run_loop.RunUntilIdle();
  checkpoint.Call(6);
}

TEST_F(FetchDataLoaderBlobTest,
       LoadAsBlobViaDrainAsBlobDataHandleWithSameContentType) {
  auto blob_data = std::make_unique<BlobData>();
  blob_data->AppendBytes(
      base::as_bytes(base::span_with_nul_from_cstring(kQuickBrownFox)));
  blob_data->SetContentType("text/test");
  scoped_refptr<BlobDataHandle> input_blob_data_handle = BlobDataHandle::Create(
      std::move(blob_data), kQuickBrownFoxLengthWithTerminatingNull);

  Checkpoint checkpoint;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsBlobHandle("text/test", fake_task_runner_);
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();
  scoped_refptr<BlobDataHandle> blob_data_handle;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer,
              DrainAsBlobDataHandle(
                  BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize))
      .WillOnce(Return(ByMove(input_blob_data_handle)));
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadedBlobHandleMock(_))
      .WillOnce(SaveArg<0>(&blob_data_handle));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(3));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  fetch_data_loader->Cancel();
  checkpoint.Call(3);

  ASSERT_TRUE(blob_data_handle);
  EXPECT_EQ(input_blob_data_handle, blob_data_handle);
  EXPECT_EQ(kQuickBrownFoxLengthWithTerminatingNull, blob_data_handle->size());
  EXPECT_EQ(String("text/test"), blob_data_handle->GetType());
}

TEST_F(FetchDataLoaderBlobTest,
       LoadAsBlobViaDrainAsBlobDataHandleWithDifferentContentType) {
  auto blob_data = std::make_unique<BlobData>();
  blob_data->AppendBytes(
      base::as_bytes(base::span_with_nul_from_cstring(kQuickBrownFox)));
  blob_data->SetContentType("text/different");
  scoped_refptr<BlobDataHandle> input_blob_data_handle = BlobDataHandle::Create(
      std::move(blob_data), kQuickBrownFoxLengthWithTerminatingNull);

  Checkpoint checkpoint;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsBlobHandle("text/test", fake_task_runner_);
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();
  scoped_refptr<BlobDataHandle> blob_data_handle;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer,
              DrainAsBlobDataHandle(
                  BytesConsumer::BlobSizePolicy::kDisallowBlobWithInvalidSize))
      .WillOnce(Return(ByMove(input_blob_data_handle)));
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadedBlobHandleMock(_))
      .WillOnce(SaveArg<0>(&blob_data_handle));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(3));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  fetch_data_loader->Cancel();
  checkpoint.Call(3);

  ASSERT_TRUE(blob_data_handle);
  EXPECT_NE(input_blob_data_handle, blob_data_handle);
  EXPECT_EQ(kQuickBrownFoxLengthWithTerminatingNull, blob_data_handle->size());
  EXPECT_EQ(String("text/test"), blob_data_handle->GetType());
}

TEST_F(FetchDataLoaderTest, LoadAsArrayBuffer) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsArrayBuffer();
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();
  DOMArrayBuffer* array_buffer = nullptr;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(
          SetArgReferee<0>(base::span_with_nul_from_cstring(kQuickBrownFox)),
          Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxLengthWithTerminatingNull))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kDone));
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadedArrayBufferMock(_))
      .WillOnce(SaveArg<0>(&array_buffer));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);

  ASSERT_TRUE(array_buffer);
  ASSERT_EQ(kQuickBrownFoxLengthWithTerminatingNull,
            array_buffer->ByteLength());
  EXPECT_STREQ(kQuickBrownFox, static_cast<const char*>(array_buffer->Data()));
}

TEST_F(FetchDataLoaderTest, LoadAsArrayBufferFailed) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsArrayBuffer();
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(
          SetArgReferee<0>(base::span_with_nul_from_cstring(kQuickBrownFox)),
          Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxLengthWithTerminatingNull))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kError));
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadFailed());
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);
}

TEST_F(FetchDataLoaderTest, LoadAsArrayBufferCancel) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsArrayBuffer();
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(3));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  fetch_data_loader->Cancel();
  checkpoint.Call(3);
}

TEST_F(FetchDataLoaderTest, LoadAsFormData) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsFormData("boundary");
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();
  FormData* form_data = nullptr;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(
          SetArgReferee<0>(base::span_from_cstring(kQuickBrownFoxFormData)),
          Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxFormDataLength))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kDone));
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadedFormDataMock(_))
      .WillOnce(SaveArg<0>(&form_data));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);

  ASSERT_TRUE(form_data);
  ASSERT_EQ(4u, form_data->Entries().size());

  EXPECT_EQ("blob", form_data->Entries()[0]->name());
  EXPECT_EQ("blob", form_data->Entries()[0]->Filename());
  ASSERT_TRUE(form_data->Entries()[0]->isFile());
  EXPECT_EQ(kQuickBrownFoxLength, form_data->Entries()[0]->GetBlob()->size());
  EXPECT_EQ("text/plain; charset=iso-8859-1",
            form_data->Entries()[0]->GetBlob()->type());

  EXPECT_EQ("blob\xC2\xA0without\xC2\xA0type",
            form_data->Entries()[1]->name().Utf8());
  EXPECT_EQ("blob\xC2\xA0without\xC2\xA0type.txt",
            form_data->Entries()[1]->Filename().Utf8());
  ASSERT_TRUE(form_data->Entries()[1]->isFile());
  EXPECT_EQ(kQuickBrownFoxLength, form_data->Entries()[1]->GetBlob()->size());
  EXPECT_EQ("text/plain", form_data->Entries()[1]->GetBlob()->type());

  EXPECT_EQ("string", form_data->Entries()[2]->name());
  EXPECT_TRUE(form_data->Entries()[2]->Filename().IsNull());
  ASSERT_TRUE(form_data->Entries()[2]->IsString());
  EXPECT_EQ(kQuickBrownFox, form_data->Entries()[2]->Value());

  EXPECT_EQ("string-with-type", form_data->Entries()[3]->name());
  EXPECT_TRUE(form_data->Entries()[3]->Filename().IsNull());
  ASSERT_TRUE(form_data->Entries()[3]->IsString());
  EXPECT_EQ(kQuickBrownFox, form_data->Entries()[3]->Value());
}

TEST_F(FetchDataLoaderTest, LoadAsFormDataPartialInput) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsFormData("boundary");
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(
          DoAll(SetArgReferee<0>(base::span_from_cstring(kQuickBrownFoxFormData)
                                     .first(kQuickBrownFoxFormDataLength - 3u)),
                Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxFormDataLength - 3u))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kDone));
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadFailed());
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);
}

TEST_F(FetchDataLoaderTest, LoadAsFormDataFailed) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsFormData("boundary");
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(
          SetArgReferee<0>(base::span_from_cstring(kQuickBrownFoxFormData)),
          Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxFormDataLength))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kError));
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadFailed());
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);
}

TEST_F(FetchDataLoaderTest, LoadAsFormDataCancel) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader =
      FetchDataLoader::CreateLoaderAsFormData("boundary");
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(3));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  fetch_data_loader->Cancel();
  checkpoint.Call(3);
}

TEST_F(FetchDataLoaderTest, LoadAsString) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader = FetchDataLoader::CreateLoaderAsString(
      TextResourceDecoderOptions::CreateUTF8Decode());
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span_from_cstring(kQuickBrownFox)),
                      Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxLength))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kDone));
  EXPECT_CALL(*fetch_data_loader_client,
              DidFetchDataLoadedString(String(kQuickBrownFox)));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);
}

TEST_F(FetchDataLoaderTest, LoadAsStringWithNullBytes) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader = FetchDataLoader::CreateLoaderAsString(
      TextResourceDecoderOptions::CreateUTF8Decode());
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  constexpr char kPattern[] = "Quick\0brown\0fox";

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(
          DoAll(SetArgReferee<0>(base::span_with_nul_from_cstring(kPattern)),
                Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(16)).WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kDone));
  EXPECT_CALL(*fetch_data_loader_client,
              DidFetchDataLoadedString(
                  String(base::span_with_nul_from_cstring(kPattern))));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);
}

TEST_F(FetchDataLoaderTest, LoadAsStringError) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader = FetchDataLoader::CreateLoaderAsString(
      TextResourceDecoderOptions::CreateUTF8Decode());
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span_from_cstring(kQuickBrownFox)),
                      Return(Result::kOk)));
  EXPECT_CALL(*consumer, EndRead(kQuickBrownFoxLength))
      .WillOnce(Return(Result::kOk));
  EXPECT_CALL(*consumer, BeginRead(_)).WillOnce(Return(Result::kError));
  EXPECT_CALL(*fetch_data_loader_client, DidFetchDataLoadFailed());
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*consumer, Cancel());
  EXPECT_CALL(checkpoint, Call(4));

  checkpoint.Call(1);
  fetch_data_loader->Start(consumer, fetch_data_loader_client);
  checkpoint.Call(2);
  ASSERT_TRUE(client);
  client->OnStateChange();
  checkpoint.Call(3);
  fetch_data_loader->Cancel();
  checkpoint.Call(4);
}

TEST_F(FetchDataLoaderTest, LoadAsStringCancel) {
  Checkpoint checkpoint;
  BytesConsumer::Client* client = nullptr;
  auto* consumer = MakeGarbageCollected<MockBytesConsumer>();

  FetchDataLoader* fetch_data_loader = FetchDataLoader::CreateLoaderAsString(
      TextResourceDecoderOptions::CreateUTF8Decode());
  auto* fetch_data_loader_client =
      MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*consumer, SetClient(_)).WillOnce(SaveArg<0>(&client));
  EXPECT_CALL(*consumer, BeginRead(_))
      .WillOnce(DoAll(SetArgReferee<0>(base::span<const char>{}),
                      Return(Result::kShouldWait)));
  EXPECT_CALL
"""


```