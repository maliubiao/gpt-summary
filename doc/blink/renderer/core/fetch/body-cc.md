Response:
Let's break down the thought process for analyzing the `body.cc` file and generating the comprehensive explanation.

**1. Understanding the Goal:**

The primary goal is to explain the functionality of `body.cc` in the Blink rendering engine, focusing on its relationship with JavaScript, HTML, and CSS, while also considering debugging aspects and potential errors.

**2. Initial Code Scan and High-Level Overview:**

The first step is to quickly scan the code to get a general idea of its purpose. Keywords like `fetch`, `Body`, `Blob`, `ArrayBuffer`, `FormData`, `json`, `text`, `ReadableStream`, `ScriptPromiseResolver`, and `FetchDataLoader` stand out. This immediately suggests the file is involved in handling the body of HTTP responses (or requests, though the focus here seems to be responses based on the data conversion methods). The presence of promise resolvers indicates asynchronous operations.

**3. Identifying Core Classes and Functionality:**

Next, focus on the main classes and their roles:

* **`Body`:** This is the central class. It likely represents the body of a fetch request or response. It has methods like `arrayBuffer`, `blob`, `formData`, `json`, `text`, and `body`, suggesting it provides ways to access the body in different formats.
* **`BodyBuffer` (inferred):** The code mentions `BodyBuffer()` and its methods like `StartLoading`, `Stream`, `IsStreamDisturbed`, and `IsStreamLocked`. While not defined in this file, it's clear `BodyBuffer` is responsible for managing the underlying data of the body and its state (loading, used, locked).
* **`FetchDataLoader`:** This class is responsible for actually fetching the data. It has methods like `CreateLoaderAsArrayBuffer`, `CreateLoaderAsBlobHandle`, `CreateLoaderAsFormData`, etc., indicating different strategies for loading the data.
* **`BodyConsumerBase` and its subclasses (`BodyBlobConsumer`, `BodyArrayBufferConsumer`, etc.):** These classes act as callbacks when the data loading is complete. They take the loaded data and resolve the associated JavaScript promise with the appropriate type. This highlights the asynchronous nature of fetching.
* **`ScriptPromiseResolver`:**  Used to manage the promises returned by the `Body` methods. They are resolved or rejected based on the success or failure of the data loading.

**4. Mapping Functionality to JavaScript APIs:**

Now, connect the dots between the C++ code and the corresponding JavaScript Fetch API:

* **`body.arrayBuffer()`:**  Clearly maps to the JavaScript `response.arrayBuffer()` method.
* **`body.blob()`:** Maps to `response.blob()`.
* **`body.formData()`:** Maps to `response.formData()`.
* **`body.json()`:** Maps to `response.json()`.
* **`body.text()`:** Maps to `response.text()`.
* **`body()`:** Maps to `response.body`, which returns a `ReadableStream`.
* **`IsBodyUsed()`:**  Corresponds to checking if the body has been read (the stream is disturbed).
* **`IsBodyLocked()`:** Corresponds to checking if the body stream is locked by a reader.

**5. Explaining Relationships with HTML and CSS (Indirect):**

The relationship with HTML and CSS is less direct but still important:

* **HTML:**  The Fetch API is heavily used in JavaScript within HTML pages to make network requests (e.g., fetching data for dynamic content, submitting forms). The `body.cc` file is crucial for processing the responses to those requests. Form submissions (using `<form>`) can result in `multipart/form-data` or `application/x-www-form-urlencoded` bodies, which are handled by `Body::formData`.
* **CSS:** While less common, CSS can also trigger fetch requests (e.g., `@font-face`, `url()` in `background-image`). The `body.cc` would be involved in handling the responses for these resources as well.

**6. Illustrating with Examples:**

Concrete examples make the explanation much clearer:

* **JavaScript Fetch:**  Demonstrate basic `fetch` calls and how the `response.arrayBuffer()`, `response.json()`, etc., methods are used.
* **HTML Form Submission:** Show how a form submission triggers a request with a body, which `body.cc` handles.

**7. Logical Reasoning and Assumptions:**

* **Assumption:**  The code is primarily dealing with *response* bodies. While request bodies exist, the file name and methods lean towards response processing.
* **Logical Deduction:** The `BodyConsumer` classes and the `FetchDataLoader` interactions demonstrate the asynchronous nature of fetching and how promises are used to manage the results.

**8. Identifying Common Errors:**

Think about what can go wrong when using the Fetch API:

* **Reading the body multiple times:**  This is a classic error that `IsBodyUsed()` addresses.
* **Trying to read the body after locking the stream:** This is what `IsBodyLocked()` prevents.
* **Incorrect MIME type for `formData()`:**  The code explicitly handles different MIME types for form data.
* **JSON parsing errors:** The `BodyJsonConsumer` includes error handling for invalid JSON.
* **Network errors:** `DidFetchDataLoadFailed` handles general fetch failures.

**9. Debugging Guidance:**

Consider how a developer might end up looking at this code:

* **Network request issues:**  If a fetch request is failing or returning unexpected data, a developer might trace the execution flow into the Blink rendering engine's network handling code, eventually reaching `body.cc`.
* **Problems with response body processing:** If `response.json()` or `response.text()` is failing, stepping through the code in `body.cc` could reveal the issue.
* **Understanding the Fetch API's internal workings:**  A developer might explore Blink's source code to gain a deeper understanding of how the Fetch API is implemented.

**10. Structuring the Explanation:**

Organize the information logically:

* **Overview:** Start with a high-level summary of the file's purpose.
* **Core Functionality:** Detail the main classes and their responsibilities.
* **JavaScript/HTML/CSS Relationships:** Explain how the code interacts with web technologies.
* **Examples:** Provide concrete code snippets.
* **Logical Reasoning:**  Explain any assumptions or deductions.
* **Common Errors:** List potential pitfalls for developers.
* **Debugging:**  Offer guidance on how the file can be relevant during debugging.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file handles both request and response bodies equally. **Correction:**  The methods and naming conventions strongly suggest a focus on *response* body processing.
* **Initial thought:**  Focus heavily on the technical details of each class. **Correction:** Balance technical details with explanations of the *purpose* and *usage* of the code in the context of web development. Emphasize the connection to JavaScript APIs.
* **Initial thought:**  Provide very detailed code walkthroughs. **Correction:** Focus on the overall functionality and key logic, rather than getting bogged down in every line of code. The goal is understanding, not a line-by-line audit.

By following these steps, combining code analysis with an understanding of web development concepts, and iteratively refining the explanation, we can generate a comprehensive and informative answer like the example provided in the initial prompt.
好的，让我们来分析一下 `blink/renderer/core/fetch/body.cc` 这个文件。

**功能概述:**

`body.cc` 文件是 Chromium Blink 渲染引擎中负责处理 HTTP 响应体（Body）的核心组件。它的主要功能是将接收到的响应体数据转换成 JavaScript 可以使用的各种数据类型，例如：

* **ArrayBuffer:**  表示原始的二进制数据缓冲区。
* **Blob:**  表示一个不可变的、原始数据的类文件对象。
* **FormData:**  表示 HTML 表单数据。
* **JSON:**  表示 JSON 格式的数据。
* **Text:**  表示文本数据。
* **ReadableStream:**  提供了一种异步读取响应体数据的流式接口。

此外，它还负责管理响应体的状态，例如是否已被读取（used）或锁定（locked）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件与 JavaScript 的 Fetch API 紧密相关。当 JavaScript 代码使用 `fetch()` 方法发起网络请求并接收到响应时，`body.cc` 中的代码会被调用来处理响应体。

* **JavaScript:**
    * **`response.arrayBuffer()`:**  `body.cc` 中的 `Body::arrayBuffer()` 方法实现了将响应体数据转换为 `ArrayBuffer` 的逻辑。
        ```javascript
        fetch('https://example.com/data.bin')
          .then(response => response.arrayBuffer())
          .then(buffer => {
            // buffer 是一个 ArrayBuffer 对象
            console.log(buffer);
          });
        ```
    * **`response.blob()`:** `Body::blob()` 方法实现了将响应体数据转换为 `Blob` 对象的逻辑。
        ```javascript
        fetch('https://example.com/image.png')
          .then(response => response.blob())
          .then(blob => {
            // blob 是一个 Blob 对象
            console.log(blob);
          });
        ```
    * **`response.formData()`:** `Body::formData()` 方法负责将 `multipart/form-data` 或 `application/x-www-form-urlencoded` 类型的响应体数据解析为 `FormData` 对象。
        ```javascript
        fetch('https://example.com/submit', { method: 'POST', body: new FormData(formElement) })
          .then(response => response.formData())
          .then(formData => {
            // formData 是一个 FormData 对象
            console.log(formData.get('username'));
          });

        fetch('https://example.com/data', {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        }).then(response => response.formData())
          .then(formData => {
             // 处理 URL 编码的数据
             console.log(formData.get('key'));
          });
        ```
    * **`response.json()`:** `Body::json()` 方法将响应体数据解析为 JSON 对象。
        ```javascript
        fetch('https://example.com/data.json')
          .then(response => response.json())
          .then(data => {
            // data 是一个 JavaScript 对象
            console.log(data.name);
          });
        ```
    * **`response.text()`:** `Body::text()` 方法将响应体数据转换为文本字符串。
        ```javascript
        fetch('https://example.com/document.txt')
          .then(response => response.text())
          .then(text => {
            // text 是一个字符串
            console.log(text);
          });
        ```
    * **`response.body`:** `Body::body()` 方法返回一个 `ReadableStream` 对象，允许逐步读取响应体数据。
        ```javascript
        fetch('https://example.com/large-file')
          .then(response => {
            const reader = response.body.getReader();
            return new ReadableStream({
              start(controller) {
                function push() {
                  reader.read().then(({ done, value }) => {
                    if (done) {
                      controller.close();
                      return;
                    }
                    controller.enqueue(value);
                    push();
                  });
                }
                push();
              }
            });
          })
          .then(stream => new Response(stream))
          .then(response => response.blob()) // 或者其他处理方式
          .then(blob => console.log("Streamed Blob:", blob));
        ```

* **HTML:**  HTML 中的 `<form>` 元素提交数据时，浏览器会将表单数据编码并通过 HTTP 请求发送到服务器。`body.cc` 中的 `Body::formData()` 方法就负责处理这类请求的响应体。

* **CSS:**  CSS 文件本身通常没有请求体，但 CSS 中可能引用外部资源，例如字体文件 (`@font-face`) 或背景图片 (`background-image: url(...)`)。当浏览器下载这些资源时，`body.cc` 会参与处理这些响应体的过程，虽然 CSS 本身并不直接操作 `response.body` 提供的方法。

**逻辑推理、假设输入与输出:**

以 `Body::json()` 方法为例：

* **假设输入:**
    * 一个 `ScriptState` 对象，表示 JavaScript 的执行状态。
    * 一个 HTTP 响应，其 `Content-Type` 头部表明是 JSON 数据，且响应体内容为合法的 JSON 字符串，例如：`{"name": "John", "age": 30}`。
* **逻辑推理:**
    1. `ShouldLoadBody()` 检查响应体是否可以被读取（未被锁定或使用过）。
    2. 创建一个 `ScriptPromiseResolver` 来处理异步操作的结果。
    3. 调用 `FetchDataLoader::CreateLoaderAsStringWithUTF8Decode()` 创建一个数据加载器，用于将响应体作为 UTF-8 字符串加载。
    4. 创建一个 `BodyJsonConsumer` 对象，用于在数据加载完成后处理结果。
    5. `BodyBuffer` (如果存在) 开始加载数据。
    6. `FetchDataLoader` 完成数据加载，并将 JSON 字符串传递给 `BodyJsonConsumer::DidFetchDataLoadedString()`。
    7. `DidFetchDataLoadedString()` 方法使用 V8 的 JSON 解析器将字符串转换为 JavaScript 对象。
    8. 如果解析成功，`ScriptPromiseResolver` 的 `Resolve()` 方法会被调用，将解析后的 JavaScript 对象作为 Promise 的 resolve 值。
    9. 如果解析失败（例如，JSON 格式错误），`ScriptPromiseResolver` 的 `Reject()` 方法会被调用，将错误信息作为 Promise 的 reject 值。
* **输出:**
    * **成功:** 一个 resolved 的 JavaScript Promise，其 value 是一个包含 `{name: "John", age: 30}` 的 JavaScript 对象。
    * **失败:** 一个 rejected 的 JavaScript Promise，其 reason 是一个 JavaScript `SyntaxError` 对象，表明 JSON 解析失败。

**用户或编程常见的使用错误:**

1. **多次读取响应体:**  HTTP 响应体只能被读取一次。在 JavaScript 中，如果尝试多次调用 `response.arrayBuffer()`、`response.json()`、`response.text()` 或 `response.blob()` 中的任何一个方法，后续的调用将会失败。`body.cc` 中的 `IsBodyUsed()` 和 `RejectInvalidConsumption()` 方法用于检测和阻止这种错误。
   ```javascript
   fetch('https://example.com/data.json')
     .then(response => {
       response.json().then(data1 => console.log(data1));
       response.json().then(data2 => console.log(data2)); // 错误：body 已被读取
     });
   ```

2. **在读取响应体后尝试获取 `ReadableStream`:**  一旦使用了 `arrayBuffer()`、`json()` 等方法读取了响应体，就不能再通过 `response.body` 获取 `ReadableStream`，因为响应体已经被消耗。
   ```javascript
   fetch('https://example.com/data.json')
     .then(response => {
       response.json();
       response.body.getReader(); // 错误：body 已被读取
     });
   ```

3. **MIME 类型不匹配导致解析错误:**  尝试使用 `response.json()` 解析非 JSON 格式的响应体，或者使用 `response.formData()` 处理非 `multipart/form-data` 或 `application/x-www-form-urlencoded` 的响应体，会导致解析错误。`body.cc` 中的代码会根据 `Content-Type` 头部进行不同的处理，如果类型不匹配，可能会抛出异常或返回错误的结果。
   ```javascript
   fetch('https://example.com/document.txt')
     .then(response => response.json()) // 错误：Content-Type 不是 application/json
     .catch(error => console.error(error));
   ```

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在浏览器中访问了一个网页，该网页的 JavaScript 代码发起了一个 `fetch` 请求获取 JSON 数据：

1. **用户在浏览器地址栏输入 URL 或点击链接，触发页面加载。**
2. **浏览器解析 HTML，执行 JavaScript 代码。**
3. **JavaScript 代码中调用了 `fetch('https://api.example.com/users')`。**
4. **Blink 引擎的网络模块发起 HTTP 请求到 `api.example.com`。**
5. **服务器返回 HTTP 响应，包含响应头和响应体（假设是 JSON 数据）。**
6. **Blink 引擎的网络模块接收到响应数据。**
7. **JavaScript 代码中调用了 `response.json()` 方法。**
8. **这个调用会进入到 `blink/renderer/core/fetch/body.cc` 文件的 `Body::json()` 方法。**
9. **`Body::json()` 方法会创建一个 Promise，并指示 `FetchDataLoader` 加载响应体数据。**
10. **`FetchDataLoader` 将响应体数据读取为字符串。**
11. **`BodyJsonConsumer::DidFetchDataLoadedString()` 方法被调用，使用 V8 的 JSON 解析器解析字符串。**
12. **如果解析成功，Promise 被 resolve，JavaScript 代码中的 `.then()` 回调函数被执行。**
13. **如果在解析过程中发生错误（例如，JSON 格式错误），Promise 被 reject，JavaScript 代码中的 `.catch()` 回调函数被执行。**

**调试线索:**

当开发者遇到与 `fetch` 相关的错误，特别是涉及到响应体处理时，可能会需要查看 `body.cc` 的代码来理解 Blink 引擎是如何处理不同类型的响应数据的。以下是一些可能的调试场景和线索：

* **`response.json()` 报错:** 开发者可能会查看 `Body::json()` 和 `BodyJsonConsumer::DidFetchDataLoadedString()` 方法，查看 JSON 解析的逻辑和错误处理。
* **`response.formData()` 处理表单数据异常:** 开发者可能会查看 `Body::formData()` 方法，特别是针对 `multipart/form-data` 和 `application/x-www-form-urlencoded` 两种类型的处理逻辑，以及如何解析边界 (boundary)。
* **多次读取 body 导致错误:** 开发者可能会查看 `IsBodyUsed()` 和 `RejectInvalidConsumption()` 方法，理解 Blink 如何阻止多次读取。
* **使用 `response.body` 的 `ReadableStream` 时遇到问题:** 开发者可能会查看 `Body::body()` 方法，了解 `ReadableStream` 的创建和使用。

通过断点调试 Blink 引擎的源代码，开发者可以逐步跟踪 `fetch` 请求的处理流程，观察响应体数据是如何被加载、解析和转换的，从而定位问题的根源。 尤其关注 `FetchDataLoader` 的工作方式以及 `BodyConsumerBase` 及其子类的实现。

希望以上分析能够帮助你理解 `blink/renderer/core/fetch/body.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/fetch/body.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/body.h"

#include <memory>
#include <utility>

#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"
#include "third_party/blink/renderer/core/fetch/fetch_data_loader.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/url/url_search_params.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/disallow_new_wrapper.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/network/parsed_content_type.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

class BodyConsumerBase : public GarbageCollected<BodyConsumerBase>,
                         public FetchDataLoader::Client {
 public:
  explicit BodyConsumerBase(ScriptPromiseResolverBase* resolver)
      : resolver_(resolver),
        task_runner_(ExecutionContext::From(resolver_->GetScriptState())
                         ->GetTaskRunner(TaskType::kNetworking)) {
  }
  BodyConsumerBase(const BodyConsumerBase&) = delete;
  BodyConsumerBase& operator=(const BodyConsumerBase&) = delete;

  ScriptPromiseResolverBase* Resolver() { return resolver_.Get(); }
  void DidFetchDataLoadFailed() override {
    ScriptState::Scope scope(Resolver()->GetScriptState());
    resolver_->Reject(V8ThrowException::CreateTypeError(
        Resolver()->GetScriptState()->GetIsolate(), "Failed to fetch"));
  }

  void Abort() override {
    resolver_->Reject(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kAbortError));
  }

  // Resource Timing event is not yet added, so delay the resolution timing
  // a bit. See https://crbug.com/507169.
  // TODO(yhirano): Fix this problem in a more sophisticated way.
  template <typename IDLType, typename T>
  void ResolveLater(const T& object) {
    task_runner_->PostTask(
        FROM_HERE, WTF::BindOnce(&BodyConsumerBase::ResolveNow<IDLType, T>,
                                 WrapPersistent(this), object));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(resolver_);
    FetchDataLoader::Client::Trace(visitor);
  }

 private:
  template <typename IDLType, typename T>
    requires(
        !std::is_same<T, Persistent<DisallowNewWrapper<ScriptValue>>>::value)
  void ResolveNow(const T& object) {
    resolver_->DowncastTo<IDLType>()->Resolve(object);
  }

  template <typename IDLType, typename T>
    requires std::is_same<T, Persistent<DisallowNewWrapper<ScriptValue>>>::value
  void ResolveNow(const Persistent<DisallowNewWrapper<ScriptValue>>& object) {
    resolver_->DowncastTo<IDLType>()->Resolve(object->Value());
  }

  const Member<ScriptPromiseResolverBase> resolver_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};
class BodyBlobConsumer final : public BodyConsumerBase {
 public:
  using BodyConsumerBase::BodyConsumerBase;
  using ResolveType = Blob;

  void DidFetchDataLoadedBlobHandle(
      scoped_refptr<BlobDataHandle> blob_data_handle) override {
    ResolveLater<ResolveType>(WrapPersistent(
        MakeGarbageCollected<Blob>(std::move(blob_data_handle))));
  }
};

class BodyArrayBufferConsumer final : public BodyConsumerBase {
 public:
  using BodyConsumerBase::BodyConsumerBase;
  using ResolveType = DOMArrayBuffer;

  void DidFetchDataLoadedArrayBuffer(DOMArrayBuffer* array_buffer) override {
    ResolveLater<ResolveType>(WrapPersistent(array_buffer));
  }
};

class BodyUint8ArrayConsumer final : public BodyConsumerBase {
 public:
  using BodyConsumerBase::BodyConsumerBase;
  using ResolveType = NotShared<DOMUint8Array>;

  void DidFetchDataLoadedArrayBuffer(DOMArrayBuffer* array_buffer) override {
    ResolveLater<ResolveType>(WrapPersistent(
        DOMUint8Array::Create(array_buffer, 0, array_buffer->ByteLength())));
  }
};

class BodyFormDataConsumer final : public BodyConsumerBase {
 public:
  using BodyConsumerBase::BodyConsumerBase;
  using ResolveType = FormData;

  void DidFetchDataLoadedFormData(FormData* form_data) override {
    ResolveLater<ResolveType>(WrapPersistent(form_data));
  }

  void DidFetchDataLoadedString(const String& string) override {
    auto* form_data = MakeGarbageCollected<FormData>();
    // URLSearchParams::Create() returns an on-heap object, but it can be
    // garbage collected, so making it a persistent variable on the stack
    // mitigates use-after-free scenarios. See crbug.com/1497997.
    Persistent<URLSearchParams> search_params = URLSearchParams::Create(string);
    for (const auto& [name, value] : search_params->Params()) {
      form_data->append(name, value);
    }
    DidFetchDataLoadedFormData(form_data);
  }
};

class BodyTextConsumer final : public BodyConsumerBase {
 public:
  using BodyConsumerBase::BodyConsumerBase;
  using ResolveType = IDLUSVString;

  void DidFetchDataLoadedString(const String& string) override {
    ResolveLater<ResolveType>(string);
  }
};

class BodyJsonConsumer final : public BodyConsumerBase {
 public:
  using BodyConsumerBase::BodyConsumerBase;
  using ResolveType = IDLAny;

  void DidFetchDataLoadedString(const String& string) override {
    if (!Resolver()->GetExecutionContext() ||
        Resolver()->GetExecutionContext()->IsContextDestroyed())
      return;
    ScriptState::Scope scope(Resolver()->GetScriptState());
    v8::Isolate* isolate = Resolver()->GetScriptState()->GetIsolate();
    v8::TryCatch try_catch(isolate);
    v8::Local<v8::Value> parsed =
        FromJSONString(Resolver()->GetScriptState(), string);
    if (try_catch.HasCaught()) {
      Resolver()->Reject(try_catch.Exception());
      return;
    }
    ResolveLater<ResolveType>(
        WrapPersistent(WrapDisallowNew(ScriptValue(isolate, parsed))));
  }
};

FetchDataLoader* CreateLoaderAsStringWithUTF8Decode() {
  return FetchDataLoader::CreateLoaderAsString(
      TextResourceDecoderOptions::CreateUTF8Decode());
}

}  // namespace

bool Body::ShouldLoadBody(ScriptState* script_state,
                          ExceptionState& exception_state) {
  RejectInvalidConsumption(exception_state);
  if (exception_state.HadException())
    return false;

  // When the main thread sends a V8::TerminateExecution() signal to a worker
  // thread, any V8 API on the worker thread starts returning an empty
  // handle. This can happen in this function. To avoid the situation, we
  // first check the ExecutionContext and return immediately if it's already
  // gone (which means that the V8::TerminateExecution() signal has been sent
  // to this worker thread).
  return ExecutionContext::From(script_state);
}

// `Consumer` must be a subclass of BodyConsumerBase which takes a
// ScriptPromiseResolverBase* as its constructor argument. `create_loader`
// should take no arguments and return a FetchDataLoader*. `on_no_body` should
// take a ScriptPromiseResolverBase* object and resolve or reject it, returning
// nothing.
template <class Consumer,
          typename CreateLoaderFunction,
          typename OnNoBodyFunction>
ScriptPromise<typename Consumer::ResolveType> Body::LoadAndConvertBody(
    ScriptState* script_state,
    CreateLoaderFunction create_loader,
    OnNoBodyFunction on_no_body,
    ExceptionState& exception_state) {
  if (!ShouldLoadBody(script_state, exception_state)) {
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<typename Consumer::ResolveType>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  if (auto* body_buffer = BodyBuffer()) {
    body_buffer->StartLoading(create_loader(),
                              MakeGarbageCollected<Consumer>(resolver),
                              exception_state);
    if (exception_state.HadException()) {
      resolver->Detach();
      return EmptyPromise();
    }
  } else {
    on_no_body(resolver);
  }
  return promise;
}

ScriptPromise<DOMArrayBuffer> Body::arrayBuffer(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto on_no_body = [](ScriptPromiseResolver<DOMArrayBuffer>* resolver) {
    resolver->Resolve(DOMArrayBuffer::Create(size_t{0}, size_t{0}));
  };

  return LoadAndConvertBody<BodyArrayBufferConsumer>(
      script_state, &FetchDataLoader::CreateLoaderAsArrayBuffer, on_no_body,
      exception_state);
}

ScriptPromise<Blob> Body::blob(ScriptState* script_state,
                               ExceptionState& exception_state) {
  auto create_loader = [this, script_state]() {
    ExecutionContext* context = ExecutionContext::From(script_state);
    return FetchDataLoader::CreateLoaderAsBlobHandle(
        MimeType(), context->GetTaskRunner(TaskType::kNetworking));
  };
  auto on_no_body = [this](ScriptPromiseResolver<Blob>* resolver) {
    auto blob_data = std::make_unique<BlobData>();
    blob_data->SetContentType(MimeType());
    resolver->Resolve(MakeGarbageCollected<Blob>(
        BlobDataHandle::Create(std::move(blob_data), 0)));
  };

  return LoadAndConvertBody<BodyBlobConsumer>(script_state, create_loader,
                                              on_no_body, exception_state);
}

ScriptPromise<NotShared<DOMUint8Array>> Body::bytes(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  auto on_no_body =
      [](ScriptPromiseResolver<NotShared<DOMUint8Array>>* resolver) {
        resolver->Resolve(
            NotShared<DOMUint8Array>(DOMUint8Array::Create(size_t{0})));
      };

  return LoadAndConvertBody<BodyUint8ArrayConsumer>(
      script_state, &FetchDataLoader::CreateLoaderAsArrayBuffer, on_no_body,
      exception_state);
}

ScriptPromise<FormData> Body::formData(ScriptState* script_state,
                                       ExceptionState& exception_state) {
  auto on_no_body_reject = [script_state](ScriptPromiseResolverBase* resolver) {
    resolver->Reject(V8ThrowException::CreateTypeError(
        script_state->GetIsolate(), "Invalid MIME type"));
  };
  const ParsedContentType parsed_type_with_parameters(ContentType());
  const String parsed_type =
      parsed_type_with_parameters.MimeType().LowerASCII();
  if (parsed_type == "multipart/form-data") {
    const String boundary =
        parsed_type_with_parameters.ParameterValueForName("boundary");
    if (!boundary.empty()) {
      auto create_loader = [&boundary]() {
        return FetchDataLoader::CreateLoaderAsFormData(boundary);
      };
      return LoadAndConvertBody<BodyFormDataConsumer>(
          script_state, create_loader, on_no_body_reject, exception_state);
    }
    if (!ShouldLoadBody(script_state, exception_state)) {
      return EmptyPromise();
    }
    auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<FormData>>(
        script_state, exception_state.GetContext());
    auto promise = resolver->Promise();
    on_no_body_reject(resolver);
    return promise;
  } else if (parsed_type == "application/x-www-form-urlencoded") {
    auto on_no_body_resolve = [](ScriptPromiseResolver<FormData>* resolver) {
      resolver->Resolve(MakeGarbageCollected<FormData>());
    };
    // According to https://fetch.spec.whatwg.org/#concept-body-package-data
    // application/x-www-form-urlencoded FormData bytes are parsed using
    // https://url.spec.whatwg.org/#concept-urlencoded-parser
    // which does not decode BOM.
    auto create_loader = []() {
      return FetchDataLoader::CreateLoaderAsString(
          TextResourceDecoderOptions::CreateUTF8DecodeWithoutBOM());
    };
    return LoadAndConvertBody<BodyFormDataConsumer>(
        script_state, create_loader, on_no_body_resolve, exception_state);
  } else {
    return LoadAndConvertBody<BodyFormDataConsumer>(
        script_state, &FetchDataLoader::CreateLoaderAsFailure,
        on_no_body_reject, exception_state);
  }
}

ScriptPromise<IDLAny> Body::json(ScriptState* script_state,
                                 ExceptionState& exception_state) {
  auto on_no_body = [script_state](ScriptPromiseResolverBase* resolver) {
    resolver->Reject(V8ThrowException::CreateSyntaxError(
        script_state->GetIsolate(), "Unexpected end of input"));
  };
  return LoadAndConvertBody<BodyJsonConsumer>(
      script_state, &CreateLoaderAsStringWithUTF8Decode, on_no_body,
      exception_state);
}

ScriptPromise<IDLUSVString> Body::text(ScriptState* script_state,
                                       ExceptionState& exception_state) {
  auto on_no_body = [](ScriptPromiseResolver<IDLUSVString>* resolver) {
    resolver->Resolve(String());
  };
  return LoadAndConvertBody<BodyTextConsumer>(
      script_state, &CreateLoaderAsStringWithUTF8Decode, on_no_body,
      exception_state);
}

ReadableStream* Body::body() {
  if (auto* execution_context = GetExecutionContext()) {
    if (execution_context->IsServiceWorkerGlobalScope()) {
      execution_context->CountUse(WebFeature::kFetchBodyStreamInServiceWorker);
    } else {
      execution_context->CountUse(
          WebFeature::kFetchBodyStreamOutsideServiceWorker);
    }
  }

  if (auto* body_buffer = BodyBuffer()) {
    return body_buffer->Stream();
  }

  return nullptr;
}

bool Body::IsBodyUsed() const {
  auto* body_buffer = BodyBuffer();
  return body_buffer && body_buffer->IsStreamDisturbed();
}

bool Body::IsBodyLocked() const {
  auto* body_buffer = BodyBuffer();
  return body_buffer && body_buffer->IsStreamLocked();
}

Body::Body(ExecutionContext* context) : ExecutionContextClient(context) {}

void Body::RejectInvalidConsumption(ExceptionState& exception_state) const {
  if (IsBodyLocked()) {
    exception_state.ThrowTypeError("body stream is locked");
  }

  if (IsBodyUsed()) {
    exception_state.ThrowTypeError("body stream already read");
  }
}

}  // namespace blink

"""

```