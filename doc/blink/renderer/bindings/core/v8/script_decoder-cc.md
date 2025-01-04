Response:
Let's break down the thought process for analyzing this `script_decoder.cc` file.

**1. Understanding the Core Purpose:**

The filename `script_decoder.cc` immediately suggests a role in processing script data. The presence of "decoder" strongly implies a transformation process, likely from some encoded format to a usable one. The `blink/renderer/bindings/core/v8/` path points to its connection with JavaScript within the Blink rendering engine. V8 is the JavaScript engine used by Chrome. Therefore, the primary function is probably decoding JavaScript code before it's executed by V8.

**2. Identifying Key Components and Data Flow:**

* **`TextResourceDecoder`:** This is a crucial dependency. It's responsible for the actual character encoding conversion (e.g., UTF-8, Latin-1). The `ScriptDecoder` likely *uses* this to handle different encodings of the JavaScript source.
* **`SegmentedBuffer` and `StringBuilder`:**  These indicate the process of accumulating the raw and decoded data respectively. `SegmentedBuffer` for the original bytes and `StringBuilder` for the resulting string.
* **`Digestor`:** This signals a security or integrity check. Hashing the data is common for verifying that the script hasn't been tampered with. SHA-256 is a strong cryptographic hash.
* **`base::SequencedTaskRunner` and `worker_pool::CreateSequencedTaskRunner`:**  These clearly indicate multithreading. The decoding process happens on a separate thread (`decoding_task_runner_`) to avoid blocking the main rendering thread (`client_task_runner_`). This is vital for performance.
* **`mojo::ScopedDataPipeConsumerHandle` and `mojo::DataPipeDrainer`:** These point to the use of Mojo, Chromium's inter-process communication system. This suggests a way to receive the script data from another process.
* **`ResponseBodyLoaderClient`:**  This signifies the decoder's integration into the resource loading pipeline. The decoder processes script data received as part of a network response.
* **`ScriptDecoder::Result`:**  This struct encapsulates the output of the decoding process: the raw data, the decoded string, and the hash digest.

**3. Analyzing Key Methods and their Logic:**

* **`DidReceiveData()`:** This is the entry point for feeding raw data to the decoder. The cross-thread posting is a key observation.
* **`FinishDecode()`:** This finalizes the decoding process, flushes any remaining data in the `TextResourceDecoder`, calculates the final hash, and sends the `Result` back to the main thread.
* **`AppendData()`:**  This private helper manages appending data to the `StringBuilder` and updating the `Digestor`. The logic to handle the 8-bit to 16-bit transition is a detail worth noting.
* **Constructors:** The different constructors indicate different ways the decoder can be used, either directly or as part of a data pipe or with a `ResponseBodyLoaderClient`.

**4. Identifying Relationships with Web Technologies:**

* **JavaScript:**  The entire purpose revolves around decoding JavaScript.
* **HTML:** JavaScript is embedded in HTML. The decoder processes the `<script>` content.
* **CSS:** While less direct, CSS can sometimes contain JavaScript expressions (though this is less common and has security implications). However, the file name and context strongly suggest the focus is primarily on `<script>` tags.
* **Character Encodings:**  The use of `TextResourceDecoder` highlights the importance of handling different character encodings specified in HTTP headers or HTML `<meta>` tags.

**5. Considering Error Scenarios and User Actions:**

Think about what could go wrong:

* **Incorrect Encoding:** The server sends data in one encoding, but the browser interprets it as another.
* **Corrupted Data:**  Network issues could lead to incomplete or modified script data.
* **Mismatched Hashes:** If the calculated hash doesn't match an expected value (if any), it signals potential tampering.

Relate these errors to user actions:

* **Visiting a webpage with an incorrect encoding declaration.**
* **Experiencing network problems while loading a page.**

**6. Tracing the Execution Flow (Debugging):**

Imagine debugging a script loading issue. How would you reach this code?

* Start with a network request for a web page.
* The browser receives the HTML.
* The HTML parser encounters a `<script>` tag.
* The browser fetches the script content.
* The response body (the script code) is passed to a `ScriptDecoder` instance.
* `DidReceiveData()` is called repeatedly with chunks of the script.
* `FinishDecode()` is called when the entire script is received.

**7. Structuring the Output:**

Organize the findings into logical sections: functionality, relationships to web technologies, logical reasoning, common errors, and debugging hints. Use clear and concise language. Provide concrete examples.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Is this decoder also used for CSS?  *Correction:* While CSS can contain some script-like syntax, the context and naming strongly suggest the focus is on JavaScript. The `TextResourceDecoder` is generic enough to handle CSS text too, but the *primary* use here is scripts.
* **Considering edge cases:** What happens if the script is very large?  The segmented buffer and the asynchronous nature of the decoder suggest it's designed to handle large scripts efficiently.
* **Double-checking assumptions:** Is the `client_task_runner_` always the main thread?  Yes, in the context of Blink rendering, this is a safe assumption.

By following this kind of structured thinking, breaking down the code into its components, analyzing the data flow, and considering the broader context of web development, you can arrive at a comprehensive understanding of the `script_decoder.cc` file's purpose and function.
好的，让我们来详细分析一下 `blink/renderer/bindings/core/v8/script_decoder.cc` 文件的功能。

**核心功能：JavaScript 脚本解码**

这个文件的核心功能是**解码下载的 JavaScript 脚本代码**，使其能够被 V8 JavaScript 引擎执行。当浏览器从网络上下载 JavaScript 文件（或嵌入在 HTML 中的 `<script>` 标签内的代码）时，这些代码可能使用特定的字符编码（例如 UTF-8、ISO-8859-1 等）。`ScriptDecoder` 的职责就是将这些编码的字节流转换为 V8 引擎能够理解的 Unicode 字符串。

**功能拆解：**

1. **字符编码转换：**
   - 依赖于 `TextResourceDecoder` 类来执行实际的字符编码转换。`TextResourceDecoder` 可以根据 HTTP 响应头中的 `Content-Type` 字段或 HTML 文档中的 `<meta>` 标签指定的字符编码来正确解码字节流。

2. **分块数据处理：**
   - `DidReceiveData()` 方法接收来自网络下载的 JavaScript 代码块 (`Vector<char> data`)。解码过程是逐步进行的，可以处理分段到达的数据，这对于大型 JavaScript 文件非常重要，可以避免一次性加载整个文件到内存。

3. **异步解码：**
   - 使用 `base::SequencedTaskRunner` 和 `worker_pool::CreateSequencedTaskRunner` 将解码任务放在一个单独的工作线程中执行 (`decoding_task_runner_`)。这避免了阻塞主线程（渲染线程），保证了用户界面的流畅性。解码完成后，通过 `client_task_runner_` 将解码结果传递回主线程。

4. **最终解码和回调：**
   - `FinishDecode()` 方法在所有数据接收完毕后被调用。它会刷新 `TextResourceDecoder`，确保所有剩余的数据都被解码。
   - 通过回调函数 (`OnDecodeFinishedCallback`) 将解码后的数据 (`decoded_data`) 以及原始数据 (`raw_data`) 和一个用于安全性的哈希值 (`digest`) 传递给客户端。

5. **数据完整性校验 (可选)：**
   - 使用 `Digestor` 类计算已解码数据的哈希值 (SHA-256)。这可以用于验证下载的 JavaScript 代码是否被篡改。

6. **DataPipe 支持 (DataPipeScriptDecoder)：**
   - 提供了 `DataPipeScriptDecoder` 类，用于处理通过 Mojo DataPipe 接收的 JavaScript 代码。这是一种更高效的数据传输方式，特别适用于 Service Workers 和其他需要进程间通信的场景。

7. **与 `ResponseBodyLoaderClient` 集成 (ScriptDecoderWithClient)：**
   - `ScriptDecoderWithClient` 类允许在解码的同时将原始数据传递给 `ResponseBodyLoaderClient`。这在某些情况下很有用，例如需要访问原始字节流进行某些处理。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript：** `ScriptDecoder` 直接负责解码 JavaScript 代码，这是其最核心的功能。它确保浏览器能够正确理解和执行下载的 JavaScript 逻辑。
    * **举例：** 当浏览器下载一个包含以下内容的 JavaScript 文件时：
      ```javascript
      console.log("你好，世界！");
      ```
      `ScriptDecoder` 会根据文件的字符编码（例如 UTF-8）将其解码为 Unicode 字符串，V8 引擎才能正确识别中文字符。

* **HTML：**  HTML 文档中通常会包含 `<script>` 标签来嵌入或链接 JavaScript 代码。当浏览器解析 HTML 时，遇到 `<script>` 标签并下载外部脚本或处理内联脚本时，`ScriptDecoder` 就会被调用来解码这些脚本内容。
    * **举例：** 考虑以下 HTML 代码：
      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="gbk">
        <title>测试页面</title>
      </head>
      <body>
        <script>
          console.log("这是一个GBK编码的字符串");
        </script>
      </body>
      </html>
      ```
      如果 HTML 文档声明了 `gbk` 编码，`ScriptDecoder` 会使用 GBK 解码器来处理 `<script>` 标签内的 JavaScript 代码。

* **CSS：** `ScriptDecoder` 与 CSS 的关系相对间接。虽然 CSS 本身不涉及脚本解码，但有时 CSS 中会包含可以通过 JavaScript 操作的内容（例如，通过 CSSOM）。此外，在 Service Workers 或某些高级场景下，可能需要使用 JavaScript 来处理 CSS 内容。  `ScriptDecoder` 本身并不直接解码 CSS 文件。CSS 文件的解码通常由专门的 CSS 解析器处理。

**逻辑推理 (假设输入与输出)：**

**假设输入：**

* **场景 1：** 下载了一个 UTF-8 编码的 JavaScript 文件，内容为 `const message = "Hello, World!";`，以字节流形式 `[0x63, 0x6f, 0x6e, 0x73, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x3d, 0x20, 0x22, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x22, 0x3b]`。
* **场景 2：** 下载了一个 GBK 编码的 JavaScript 文件，内容为 `console.log("你好");`，以字节流形式 (GBK 编码) `[0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x2e, 0x6c, 0x6f, 0x67, 0x28, 0x22, 0xc4, 0xe3, 0xba, 0xc3, 0x22, 0x29, 0x3b]`。
* **场景 3：**  通过 DataPipe 接收了一段 UTF-8 编码的 JavaScript 代码块 `function add(a, b) { return a + b; }`。

**假设输出：**

* **场景 1：** `decoded_data` 将会是 Unicode 字符串 `"const message = "Hello, World!";"`。
* **场景 2：** `decoded_data` 将会是 Unicode 字符串 `"console.log("你好");"`。
* **场景 3：** `DataPipeScriptDecoder` 的回调函数会接收到 Unicode 字符串 `"function add(a, b) { return a + b; }"`.

**用户或编程常见的使用错误：**

1. **服务器配置错误的字符编码：**
   - **错误：** 服务器返回 JavaScript 文件时，HTTP 响应头的 `Content-Type` 字段指定的字符编码与文件的实际编码不符。例如，文件是 UTF-8 编码，但 `Content-Type` 声明为 `text/javascript; charset=ISO-8859-1`。
   - **结果：** `TextResourceDecoder` 会使用错误的编码进行解码，导致 JavaScript 代码中的非 ASCII 字符显示为乱码或无法正确解析，最终可能导致脚本执行错误。

2. **HTML 中 `<meta>` 标签声明的字符编码与实际不符：**
   - **错误：**  对于内嵌在 HTML 中的 `<script>` 标签，如果 HTML 文档的 `<meta charset="...">` 声明与脚本的实际编码不一致，也会导致解码错误。
   - **结果：**  类似于服务器配置错误的情况，会导致脚本中的字符显示异常和执行错误。

3. **在二进制数据中错误地使用了 `ScriptDecoder`：**
   - **错误：** 尝试使用 `ScriptDecoder` 解码不包含文本数据的二进制文件。
   - **结果：**  解码过程会产生无意义的 Unicode 字符串，因为 `TextResourceDecoder` 是为文本数据设计的。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户访问一个包含外部 JavaScript 文件的网页，并且该 JavaScript 文件加载失败或执行出错，我们可以通过以下步骤追踪到 `ScriptDecoder` 的执行：

1. **用户在浏览器地址栏输入 URL 并按下回车键。**
2. **浏览器发送 HTTP 请求获取 HTML 页面。**
3. **浏览器接收到 HTML 响应，开始解析 HTML 内容。**
4. **HTML 解析器遇到 `<script src="script.js">` 标签。**
5. **浏览器发起对 `script.js` 的 HTTP 请求。**
6. **服务器响应 `script.js` 文件内容（可能是字节流）。**
7. **Blink 渲染引擎接收到 `script.js` 的响应数据。**
8. **根据响应头的 `Content-Type` 字段，确定需要进行 JavaScript 解码。**
9. **创建一个 `ScriptDecoder` 实例，并将 `TextResourceDecoder` 初始化为相应的字符编码解码器。**
10. **`ScriptDecoder::DidReceiveData()` 方法被多次调用，接收 `script.js` 的数据块。**
11. **在 `DidReceiveData()` 内部，`TextResourceDecoder::Decode()` 被调用，执行实际的字符编码转换。**
12. **当所有数据接收完毕后，`ScriptDecoder::FinishDecode()` 被调用。**
13. **`TextResourceDecoder::Flush()` 被调用，处理剩余的解码缓冲。**
14. **解码后的 JavaScript 代码被传递给 V8 JavaScript 引擎进行解析和执行。**

**调试线索：**

* **网络面板：** 查看网络请求，确认 `script.js` 的 HTTP 响应头中的 `Content-Type` 字段是否正确，以及响应内容是否完整。
* **控制台：** 查看是否有 JavaScript 语法错误或字符编码相关的错误信息。
* **Blink 开发者工具 (例如，通过 `chrome://inspect/#devices`)：** 可以设置断点在 `ScriptDecoder::DidReceiveData()` 或 `ScriptDecoder::FinishDecode()` 方法中，查看接收到的原始数据和解码后的数据，以及 `TextResourceDecoder` 的状态。
* **日志输出：** Blink 引擎内部可能有与解码相关的日志输出，可以帮助诊断问题。
* **检查 HTML 源码：** 对于内联脚本，检查 HTML 文档的 `<meta charset="...">` 声明是否正确。

希望以上详细的解释能够帮助你理解 `blink/renderer/bindings/core/v8/script_decoder.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/script_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/script_decoder.h"

#include <memory>

#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader_client.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"

namespace WTF {

template <>
struct CrossThreadCopier<blink::ScriptDecoder::Result> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = blink::ScriptDecoder::Result;
  static Type Copy(Type&& value) { return std::move(value); }
};

template <>
struct CrossThreadCopier<mojo::ScopedDataPipeConsumerHandle> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = mojo::ScopedDataPipeConsumerHandle;
  static Type Copy(Type&& value) { return std::move(value); }
};

}  // namespace WTF

namespace blink {

namespace {
void AppendDataImpl(Digestor* digestor,
                    StringBuilder* builder,
                    const String& data) {
  bool was_8bit = builder->Is8Bit();
  unsigned starting_length = builder->length();
  builder->Append(data);
  if (was_8bit == builder->Is8Bit()) {
    // Update the hash using the data from the builder, not the input string,
    // because the input string could be 8-bit when the builder is 16-bit.
    digestor->Update(builder
                         ->SubstringView(starting_length,
                                         builder->length() - starting_length)
                         .RawByteSpan());
  } else {
    // The hash data computed so far is invalid and must be recomputed. This can
    // only happen once per builder when it changes from 8-bit to 16-bit mode.
    DCHECK(!builder->Is8Bit());
    *digestor = Digestor(kHashAlgorithmSha256);
    digestor->Update(StringView(*builder).RawByteSpan());
  }
}
}  // namespace

ScriptDecoder::Result::Result(
    SegmentedBuffer raw_data,
    String decoded_data,
    std::unique_ptr<ParkableStringImpl::SecureDigest> digest)
    : raw_data(std::move(raw_data)),
      decoded_data(std::move(decoded_data)),
      digest(std::move(digest)) {}

////////////////////////////////////////////////////////////////////////
// ScriptDecoder
////////////////////////////////////////////////////////////////////////

ScriptDecoder::ScriptDecoder(
    std::unique_ptr<TextResourceDecoder> decoder,
    scoped_refptr<base::SequencedTaskRunner> client_task_runner)
    : decoder_(std::move(decoder)),
      client_task_runner_(std::move(client_task_runner)),
      decoding_task_runner_(worker_pool::CreateSequencedTaskRunner(
          {base::TaskPriority::USER_BLOCKING})) {}

void ScriptDecoder::DidReceiveData(Vector<char> data) {
  if (!decoding_task_runner_->RunsTasksInCurrentSequence()) {
    PostCrossThreadTask(
        *decoding_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&ScriptDecoder::DidReceiveData,
                            CrossThreadUnretained(this), std::move(data)));
    return;
  }

  CHECK(decoding_task_runner_->RunsTasksInCurrentSequence());
  CHECK(!client_task_runner_->RunsTasksInCurrentSequence());

  AppendData(decoder_->Decode(data));
  raw_data_.Append(std::move(data));
}

void ScriptDecoder::FinishDecode(
    OnDecodeFinishedCallback on_decode_finished_callback) {
  if (!decoding_task_runner_->RunsTasksInCurrentSequence()) {
    PostCrossThreadTask(
        *decoding_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&ScriptDecoder::FinishDecode,
                            CrossThreadUnretained(this),
                            std::move(on_decode_finished_callback)));
    return;
  }

  CHECK(decoding_task_runner_->RunsTasksInCurrentSequence());
  CHECK(!client_task_runner_->RunsTasksInCurrentSequence());

  AppendData(decoder_->Flush());
  ParkableStringImpl::UpdateDigestWithEncoding(&digestor_, builder_.Is8Bit());

  DigestValue digest_value;
  digestor_.Finish(digest_value);

  PostCrossThreadTask(
      *client_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          std::move(on_decode_finished_callback),
          Result(std::move(raw_data_), builder_.ReleaseString(),
                 std::make_unique<ParkableStringImpl::SecureDigest>(
                     digest_value))));
}

void ScriptDecoder::Delete() const {
  decoding_task_runner_->DeleteSoon(FROM_HERE, this);
}

void ScriptDecoder::AppendData(const String& data) {
  AppendDataImpl(&digestor_, &builder_, data);
}

void ScriptDecoderDeleter::operator()(const ScriptDecoder* ptr) {
  if (ptr) {
    ptr->Delete();
  }
}

ScriptDecoderPtr ScriptDecoder::Create(
    std::unique_ptr<TextResourceDecoder> decoder,
    scoped_refptr<base::SequencedTaskRunner> client_task_runner) {
  return ScriptDecoderPtr(
      new ScriptDecoder(std::move(decoder), std::move(client_task_runner)));
}

////////////////////////////////////////////////////////////////////////
// DataPipeScriptDecoder
////////////////////////////////////////////////////////////////////////

DataPipeScriptDecoder::DataPipeScriptDecoder(
    std::unique_ptr<TextResourceDecoder> decoder,
    scoped_refptr<base::SequencedTaskRunner> client_task_runner,
    OnDecodeFinishedCallback on_decode_finished_callback)
    : decoder_(std::move(decoder)),
      client_task_runner_(std::move(client_task_runner)),
      on_decode_finished_callback_(std::move(on_decode_finished_callback)),
      decoding_task_runner_(worker_pool::CreateSequencedTaskRunner(
          {base::TaskPriority::USER_BLOCKING})) {
  CHECK(features::kBackgroundCodeCacheDecoderStart.Get());
}

void DataPipeScriptDecoder::Start(mojo::ScopedDataPipeConsumerHandle source) {
  if (!decoding_task_runner_->RunsTasksInCurrentSequence()) {
    PostCrossThreadTask(
        *decoding_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&DataPipeScriptDecoder::Start,
                            CrossThreadUnretained(this), std::move(source)));
    return;
  }
  drainer_ = std::make_unique<mojo::DataPipeDrainer>(this, std::move(source));
}

void DataPipeScriptDecoder::OnDataAvailable(base::span<const uint8_t> data) {
  AppendData(decoder_->Decode(data));
  raw_data_.Append(data);
}

void DataPipeScriptDecoder::OnDataComplete() {
  AppendData(decoder_->Flush());
  ParkableStringImpl::UpdateDigestWithEncoding(&digestor_, builder_.Is8Bit());
  digestor_.Finish(digest_value_);
  PostCrossThreadTask(
      *client_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          std::move(on_decode_finished_callback_),
          ScriptDecoder::Result(
              std::move(raw_data_), builder_.ReleaseString(),
              std::make_unique<ParkableStringImpl::SecureDigest>(
                  digest_value_))));
}

void DataPipeScriptDecoder::AppendData(const String& data) {
  AppendDataImpl(&digestor_, &builder_, data);
}

void DataPipeScriptDecoder::Delete() const {
  decoding_task_runner_->DeleteSoon(FROM_HERE, this);
}

void DataPipeScriptDecoderDeleter::operator()(
    const DataPipeScriptDecoder* ptr) {
  if (ptr) {
    ptr->Delete();
  }
}

DataPipeScriptDecoderPtr DataPipeScriptDecoder::Create(
    std::unique_ptr<TextResourceDecoder> decoder,
    scoped_refptr<base::SequencedTaskRunner> client_task_runner,
    OnDecodeFinishedCallback on_decode_finished_callback) {
  return DataPipeScriptDecoderPtr(new DataPipeScriptDecoder(
      std::move(decoder), std::move(client_task_runner),
      std::move(on_decode_finished_callback)));
}

////////////////////////////////////////////////////////////////////////
// ScriptDecoderWithClient
////////////////////////////////////////////////////////////////////////

ScriptDecoderWithClient::ScriptDecoderWithClient(
    ResponseBodyLoaderClient* response_body_loader_client,
    std::unique_ptr<TextResourceDecoder> decoder,
    scoped_refptr<base::SequencedTaskRunner> client_task_runner)
    : decoder_(std::move(decoder)),
      client_task_runner_(std::move(client_task_runner)),
      decoding_task_runner_(worker_pool::CreateSequencedTaskRunner(
          {base::TaskPriority::USER_BLOCKING})),
      response_body_loader_client_(
          MakeCrossThreadWeakHandle(response_body_loader_client)) {}

void ScriptDecoderWithClient::DidReceiveData(Vector<char> data,
                                             bool send_to_client) {
  if (!decoding_task_runner_->RunsTasksInCurrentSequence()) {
    PostCrossThreadTask(
        *decoding_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&ScriptDecoderWithClient::DidReceiveData,
                            CrossThreadUnretained(this), std::move(data),
                            send_to_client));
    return;
  }

  CHECK(decoding_task_runner_->RunsTasksInCurrentSequence());
  CHECK(!client_task_runner_->RunsTasksInCurrentSequence());

  AppendData(decoder_->Decode(data));

  if (!send_to_client) {
    return;
  }
  PostCrossThreadTask(
      *client_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &ResponseBodyLoaderClient::DidReceiveData,
          MakeUnwrappingCrossThreadWeakHandle(response_body_loader_client_),
          std::move(data)));
}

void ScriptDecoderWithClient::FinishDecode(
    CrossThreadOnceClosure main_thread_continuation) {
  if (!decoding_task_runner_->RunsTasksInCurrentSequence()) {
    PostCrossThreadTask(
        *decoding_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&ScriptDecoderWithClient::FinishDecode,
                            CrossThreadUnretained(this),
                            std::move(main_thread_continuation)));
    return;
  }

  CHECK(decoding_task_runner_->RunsTasksInCurrentSequence());
  CHECK(!client_task_runner_->RunsTasksInCurrentSequence());

  AppendData(decoder_->Flush());
  ParkableStringImpl::UpdateDigestWithEncoding(&digestor_, builder_.Is8Bit());

  DigestValue digest_value;
  digestor_.Finish(digest_value);

  PostCrossThreadTask(
      *client_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          [](ResponseBodyLoaderClient* response_body_loader_client,
             const String& decoded_data,
             std::unique_ptr<ParkableStringImpl::SecureDigest> digest,
             CrossThreadOnceClosure main_thread_continuation) {
            if (response_body_loader_client) {
              response_body_loader_client->DidReceiveDecodedData(
                  decoded_data, std::move(digest));
            }
            std::move(main_thread_continuation).Run();
          },
          MakeUnwrappingCrossThreadWeakHandle(response_body_loader_client_),
          builder_.ReleaseString(),
          std::make_unique<ParkableStringImpl::SecureDigest>(digest_value),
          std::move(main_thread_continuation)));
}

void ScriptDecoderWithClient::Delete() const {
  decoding_task_runner_->DeleteSoon(FROM_HERE, this);
}

void ScriptDecoderWithClient::AppendData(const String& data) {
  AppendDataImpl(&digestor_, &builder_, data);
}

void ScriptDecoderWithClientDeleter::operator()(
    const ScriptDecoderWithClient* ptr) {
  if (ptr) {
    ptr->Delete();
  }
}

ScriptDecoderWithClientPtr ScriptDecoderWithClient::Create(
    ResponseBodyLoaderClient* response_body_loader_client,
    std::unique_ptr<TextResourceDecoder> decoder,
    scoped_refptr<base::SequencedTaskRunner> client_task_runner) {
  return ScriptDecoderWithClientPtr(new ScriptDecoderWithClient(
      response_body_loader_client, std::move(decoder),
      std::move(client_task_runner)));
}

}  // namespace blink

"""

```