Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for a functional description of the `streaming-decoder.cc` file, along with specific points like Torque presence, JavaScript relation, logical reasoning examples, and common errors.

2. **Initial Scan for Key Terms:** Quickly read through the code, looking for important keywords and class names. I see things like `StreamingDecoder`, `AsyncStreamingDecoder`, `StreamingProcessor`, `DecodingState`, `SectionBuffer`, and references to WASM concepts like "module header", "section", "function body". This immediately tells me this code is related to parsing and processing WebAssembly modules. The "streaming" aspect suggests it handles modules as they are being downloaded, rather than waiting for the entire module.

3. **Identify the Main Class:**  The core class seems to be `AsyncStreamingDecoder`. The other classes and structs appear to be helpers or internal components of this class.

4. **Trace the Data Flow (Conceptual):** How does this decoder work? The name `OnBytesReceived` is a big clue. It takes in chunks of bytes. There's a `DecodingState` that seems to manage the current stage of parsing. The comments mention a state diagram, which is a helpful high-level description. Sections, function lengths, and function bodies are being parsed.

5. **Examine the State Machine:** The `DecodingState` and its derived classes (like `DecodeModuleHeader`, `DecodeSectionID`, etc.) are crucial. Each state seems responsible for parsing a specific part of the WASM module structure. The `Next()` function in each state suggests the transitions between parsing stages. The state diagram in the comments confirms this.

6. **Look for Interactions with Other Components:** The `#include` directives at the beginning are important. They reveal dependencies on other V8 WASM components like `decoder.h`, `module-decoder.h`, `wasm-objects.h`, and `wasm-code-manager.h`. The `StreamingProcessor` class (passed in as a unique pointer) is a key interface, suggesting this decoder communicates with a higher-level component that does something with the parsed data.

7. **Address Specific Questions:** Now, let's go through the specific points requested in the prompt:

    * **Functionality:** Synthesize the observations so far into a concise description of the file's purpose. Focus on the core task: incrementally decoding a WASM module.
    * **Torque:** Look for the `.tq` extension in the filename. It's `.cc`, so it's standard C++. Mention this explicitly.
    * **JavaScript Relation:** Think about how WASM relates to JavaScript. WASM modules are loaded and executed within a JavaScript environment. The decoder's output (via `StreamingProcessor`) is used to create a WASM module object accessible from JavaScript. Provide a simple `WebAssembly.instantiateStreaming` example to illustrate this.
    * **Code Logic Reasoning:**  Choose a simple but illustrative part of the code. The decoding of section length (using `DecodeSectionLength`) is a good candidate. Define an input (a byte sequence representing a section ID and length) and trace how the decoder processes it, leading to an output (the extracted length).
    * **Common Programming Errors:**  Think about what could go wrong during WASM module creation. Common errors include invalid module format, incorrect section lengths, exceeding size limits, and malformed function bodies. Provide concrete examples of how these errors might manifest and how the decoder handles them (e.g., `Fail()`).

8. **Refine and Organize:**  Structure the answer logically with clear headings for each point. Use precise language. For the code logic reasoning, explain the assumptions made about the input.

9. **Review and Verify:** Reread the code and the generated answer to ensure accuracy and completeness. Check if all parts of the request have been addressed. For instance, did I miss mentioning the role of `SectionBuffer`? Does the JavaScript example clearly show the connection?

**Self-Correction Example During the Process:**

Initially, I might focus too much on the internal state transitions and low-level byte manipulation. However, the request emphasizes *functionality*. So, I need to step back and explain *what* this code achieves from a higher-level perspective (streaming WASM decoding) before diving into the details of the state machine. Also, I might initially forget to include a concrete JavaScript example. Reviewing the "JavaScript relation" point would prompt me to add that crucial connection. Similarly, if my code logic example is too complex, I'd simplify it to make the explanation clearer.
这个文件 `v8/src/wasm/streaming-decoder.cc` 是 V8 引擎中用于**流式解码 WebAssembly (Wasm) 模块**的源代码。它允许 V8 在 Wasm 模块下载的同时就开始解析和编译，而不是等待整个模块下载完成，从而提高加载速度和启动性能。

以下是其主要功能：

1. **管理流式解码过程:**  `AsyncStreamingDecoder` 类是核心，它维护了解码器的状态，处理接收到的字节流，并驱动解码过程。

2. **状态机驱动解码:** 解码过程被组织成一系列状态 (`DecodingState` 及其子类，如 `DecodeModuleHeader`, `DecodeSectionID`, `DecodeSectionLength`, `DecodeSectionPayload`, `DecodeNumberOfFunctions`, `DecodeFunctionLength`, `DecodeFunctionBody`)，每个状态负责解析 Wasm 模块的特定部分。这种状态机的方式使得解码过程有条不紊。

3. **处理接收到的字节:** `OnBytesReceived` 方法是接收字节流的入口点。它将接收到的字节添加到内部缓冲区，并根据当前解码状态进行解析。

4. **解析 Wasm 模块结构:**
   - **模块头 (Module Header):** `DecodeModuleHeader` 状态负责验证 Wasm 模块的魔数和版本号。
   - **段 (Sections):**  `DecodeSectionID`, `DecodeSectionLength`, `DecodeSectionPayload` 状态负责解析 Wasm 模块的各个段，如类型段、导入段、函数段、代码段等。
   - **代码段 (Code Section):**  `DecodeNumberOfFunctions`, `DecodeFunctionLength`, `DecodeFunctionBody` 状态专门负责解析代码段，包括函数数量、每个函数的长度和函数体。

5. **与 `StreamingProcessor` 交互:** `AsyncStreamingDecoder` 使用 `StreamingProcessor` 接口与上层组件通信。它将解析出的模块结构信息（如模块头、段信息、函数体等）传递给 `StreamingProcessor` 进行进一步处理（例如编译）。

6. **错误处理:**  解码过程中如果遇到错误（例如模块格式不正确、段长度超出限制等），会切换到错误状态 (`Fail()`) 并通知 `StreamingProcessor`。

7. **完成解码:** `Finish` 方法在所有字节接收完毕后被调用，执行最后的处理，并通知 `StreamingProcessor` 解码完成。

8. **中止解码:** `Abort` 方法允许提前中止解码过程。

9. **处理编译丢弃通知:** `NotifyCompilationDiscarded` 方法用于通知解码器编译过程被丢弃，清理相关资源。

10. **通知原生模块创建:** `NotifyNativeModuleCreated` 方法用于在原生模块创建后执行一些操作，例如设置回调。

**关于 `.tq` 结尾:**

如果 `v8/src/wasm/streaming-decoder.cc` 以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。 Torque 是一种 V8 自研的领域特定语言，用于编写高效的运行时代码。 然而，根据提供的信息，该文件以 `.cc` 结尾，因此它是标准的 C++ 源代码。

**与 JavaScript 的关系:**

`v8/src/wasm/streaming-decoder.cc` 的功能直接关系到 JavaScript 中使用 WebAssembly 的能力。 当 JavaScript 代码尝试加载一个 Wasm 模块时（通常使用 `WebAssembly.instantiateStreaming()`），V8 引擎会使用流式解码器来解析下载的模块字节。

**JavaScript 示例:**

```javascript
// 假设 server.com/module.wasm 返回一个 WebAssembly 模块的字节流
fetch('server.com/module.wasm')
  .then(response => WebAssembly.instantiateStreaming(response))
  .then(result => {
    const wasmModule = result.module;
    const wasmInstance = result.instance;
    // 使用 wasmInstance 调用导出的 WebAssembly 函数
    console.log(wasmInstance.exports.add(5, 3));
  });
```

在这个例子中，`WebAssembly.instantiateStreaming(response)` 函数会触发 V8 的流式解码器来处理 `response` 中的字节流。解码器解析 Wasm 模块的结构，并将其转换为 V8 可以执行的格式。

**代码逻辑推理示例:**

假设我们有以下 Wasm 模块字节流的一部分，表示一个简单的段（假设是一个自定义段）：

**输入字节 (十六进制):** `0a 05 01 02 03 04 05`

根据 Wasm 的二进制格式：

* `0a`:  段 ID (10，假设这是一个自定义段)
* `05`:  段长度 (5)
* `01 02 03 04 05`: 段的实际 payload

**解码过程推理:**

1. **`DecodeSectionID` 状态:** 解码器读取第一个字节 `0a`，确定段 ID 为 10。
2. **`DecodeSectionLength` 状态:** 解码器读取下一个字节 `05`，确定段长度为 5。
3. **`DecodeSectionPayload` 状态:** 解码器读取接下来的 5 个字节 `01 02 03 04 05`，作为该段的 payload。
4. **`ProcessSection` 调用:** `AsyncStreamingDecoder` 将段 ID (10) 和 payload (`[1, 2, 3, 4, 5]`) 以及相应的偏移量传递给 `StreamingProcessor` 的 `ProcessSection` 方法。

**假设输入与输出:**

* **输入:**  字节流 `0a 05 01 02 03 04 05`
* **输出 (传递给 `StreamingProcessor`):**
    * `section_code`: 10
    * `payload`: `base::Vector<const uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05}`
    * `module_offset`:  取决于该段在整个模块中的起始位置。

**用户常见的编程错误示例:**

在使用 WebAssembly 时，一些常见的编程错误可能会导致流式解码器遇到问题：

1. **提供的字节流不是有效的 Wasm 模块:**  例如，文件损坏，或者内容被错误地修改。解码器在 `DecodeModuleHeader` 状态就会失败，因为它无法找到正确的魔数 (`\0asm`) 和版本号。

   ```javascript
   fetch('invalid.wasm') // invalid.wasm 内容不是有效的 Wasm 模块
     .then(response => WebAssembly.instantiateStreaming(response))
     .catch(error => {
       console.error("实例化 Wasm 模块失败:", error); // 可能会报类似 "Uncaught (in promise) LinkError: import memory is not an object" 的错误，也可能在更早的解析阶段失败。
     });
   ```

2. **Wasm 模块的结构不符合规范:** 例如，段的长度声明与实际内容不符。

   假设一个段的长度声明为 3，但实际 payload 有 5 个字节：

   **错误的字节流 (十六进制):** `0a 03 01 02 03 04 05`

   解码器在 `DecodeSectionPayload` 状态会检测到接收到的字节数超过了声明的长度，并调用 `Fail()` 进入错误状态。

3. **代码段中声明的函数数量与实际提供的函数体数量不符:**  解码器在解析代码段时会进行检查。

   例如，声明了 2 个函数，但只提供了 1 个函数体的长度和内容。解码器在 `DecodeFunctionBody` 状态结束后，如果发现剩余的函数数量不为 0，就会进入错误状态。

4. **函数体的长度超过了允许的最大值 (`kV8MaxWasmFunctionSize`):**  解码器在 `DecodeFunctionLength` 状态会检查函数体的长度是否超过限制。

   ```c++
   class AsyncStreamingDecoder::DecodeFunctionLength : public DecodeVarInt32 {
    public:
     explicit DecodeFunctionLength(SectionBuffer* section_buffer,
                                   size_t buffer_offset,
                                   size_t num_remaining_functions)
         : DecodeVarInt32(kV8MaxWasmFunctionSize, "function body size"), // 这里限制了最大值
           // ...
   };
   ```

   如果 JavaScript 代码尝试加载一个包含过大函数的 Wasm 模块，解码器会报错。

这些例子说明了流式解码器在确保 Wasm 模块的有效性和符合规范方面起着至关重要的作用。它能够尽早地捕获错误，防止 V8 尝试执行无效的代码，从而提高安全性和稳定性。

Prompt: 
```
这是目录为v8/src/wasm/streaming-decoder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/streaming-decoder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/streaming-decoder.h"

#include <optional>

#include "src/logging/counters.h"
#include "src/wasm/decoder.h"
#include "src/wasm/leb-helper.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-result.h"

#define TRACE_STREAMING(...)                                \
  do {                                                      \
    if (v8_flags.trace_wasm_streaming) PrintF(__VA_ARGS__); \
  } while (false)

namespace v8::internal::wasm {

class V8_EXPORT_PRIVATE AsyncStreamingDecoder : public StreamingDecoder {
 public:
  explicit AsyncStreamingDecoder(std::unique_ptr<StreamingProcessor> processor);
  AsyncStreamingDecoder(const AsyncStreamingDecoder&) = delete;
  AsyncStreamingDecoder& operator=(const AsyncStreamingDecoder&) = delete;

  void OnBytesReceived(base::Vector<const uint8_t> bytes) override;

  void Finish(bool can_use_compiled_module) override;

  void Abort() override;

  void NotifyCompilationDiscarded() override {
    auto& active_processor = processor_ ? processor_ : failed_processor_;
    active_processor.reset();
    DCHECK_NULL(processor_);
    DCHECK_NULL(failed_processor_);
  }

  void NotifyNativeModuleCreated(
      const std::shared_ptr<NativeModule>& native_module) override;

 private:
  // The SectionBuffer is the data object for the content of a single section.
  // It stores all bytes of the section (including section id and section
  // length), and the offset where the actual payload starts.
  class SectionBuffer : public WireBytesStorage {
   public:
    // id: The section id.
    // payload_length: The length of the payload.
    // length_bytes: The section length, as it is encoded in the module bytes.
    SectionBuffer(uint32_t module_offset, uint8_t id, size_t payload_length,
                  base::Vector<const uint8_t> length_bytes)
        :  // ID + length + payload
          module_offset_(module_offset),
          bytes_(base::OwnedVector<uint8_t>::NewForOverwrite(
              1 + length_bytes.length() + payload_length)),
          payload_offset_(1 + length_bytes.length()) {
      bytes_.begin()[0] = id;
      memcpy(bytes_.begin() + 1, &length_bytes.first(), length_bytes.length());
    }

    SectionCode section_code() const {
      return static_cast<SectionCode>(bytes_.begin()[0]);
    }

    base::Vector<const uint8_t> GetCode(WireBytesRef ref) const final {
      DCHECK_LE(module_offset_, ref.offset());
      uint32_t offset_in_code_buffer = ref.offset() - module_offset_;
      return bytes().SubVector(offset_in_code_buffer,
                               offset_in_code_buffer + ref.length());
    }

    std::optional<ModuleWireBytes> GetModuleBytes() const final { return {}; }

    uint32_t module_offset() const { return module_offset_; }
    base::Vector<uint8_t> bytes() const { return bytes_.as_vector(); }
    base::Vector<uint8_t> payload() const { return bytes() + payload_offset_; }
    size_t length() const { return bytes_.size(); }
    size_t payload_offset() const { return payload_offset_; }

   private:
    const uint32_t module_offset_;
    const base::OwnedVector<uint8_t> bytes_;
    const size_t payload_offset_;
  };

  // The decoding of a stream of wasm module bytes is organized in states. Each
  // state provides a buffer to store the bytes required for the current state,
  // information on how many bytes have already been received, how many bytes
  // are needed, and a {Next} function which starts the next state once all
  // bytes of the current state were received.
  //
  // The states change according to the following state diagram:
  //
  //       Start
  //         |
  //         |
  //         v
  // DecodeModuleHeader
  //         |   _________________________________________
  //         |   |                                        |
  //         v   v                                        |
  //  DecodeSectionID --> DecodeSectionLength --> DecodeSectionPayload
  //         A                  |
  //         |                  | (if the section id == code)
  //         |                  v
  //         |      DecodeNumberOfFunctions -- > DecodeFunctionLength
  //         |                                          A    |
  //         |                                          |    |
  //         |  (after all functions were read)         |    v
  //         ------------------------------------- DecodeFunctionBody
  //
  class DecodingState {
   public:
    virtual ~DecodingState() = default;

    // Reads the bytes for the current state and returns the number of read
    // bytes.
    virtual size_t ReadBytes(AsyncStreamingDecoder* streaming,
                             base::Vector<const uint8_t> bytes);

    // Returns the next state of the streaming decoding.
    virtual std::unique_ptr<DecodingState> Next(
        AsyncStreamingDecoder* streaming) = 0;
    // The buffer to store the received bytes.
    virtual base::Vector<uint8_t> buffer() = 0;
    // The number of bytes which were already received.
    size_t offset() const { return offset_; }
    void set_offset(size_t value) { offset_ = value; }
    // A flag to indicate if finishing the streaming decoder is allowed without
    // error.
    virtual bool is_finishing_allowed() const { return false; }

   private:
    size_t offset_ = 0;
  };

  // Forward declarations of the concrete states. This is needed so that they
  // can access private members of the AsyncStreamingDecoder.
  class DecodeVarInt32;
  class DecodeModuleHeader;
  class DecodeSectionID;
  class DecodeSectionLength;
  class DecodeSectionPayload;
  class DecodeNumberOfFunctions;
  class DecodeFunctionLength;
  class DecodeFunctionBody;

  // Creates a buffer for the next section of the module.
  SectionBuffer* CreateNewBuffer(uint32_t module_offset, uint8_t section_id,
                                 size_t length,
                                 base::Vector<const uint8_t> length_bytes);

  std::unique_ptr<DecodingState> ToErrorState() {
    Fail();
    return nullptr;
  }

  void ProcessModuleHeader() {
    if (!ok()) return;
    if (!processor_->ProcessModuleHeader(state_->buffer())) Fail();
  }

  void ProcessSection(SectionBuffer* buffer) {
    if (!ok()) return;
    if (!processor_->ProcessSection(
            buffer->section_code(), buffer->payload(),
            buffer->module_offset() +
                static_cast<uint32_t>(buffer->payload_offset()))) {
      Fail();
    }
  }

  void StartCodeSection(int num_functions,
                        std::shared_ptr<WireBytesStorage> wire_bytes_storage,
                        int code_section_start, int code_section_length) {
    if (!ok()) return;
    // The offset passed to {ProcessCodeSectionHeader} is an error offset and
    // not the start offset of a buffer. Therefore we need the -1 here.
    if (!processor_->ProcessCodeSectionHeader(
            num_functions, module_offset() - 1, std::move(wire_bytes_storage),
            code_section_start, code_section_length)) {
      Fail();
    }
  }

  void ProcessFunctionBody(base::Vector<const uint8_t> bytes,
                           uint32_t module_offset) {
    if (!ok()) return;
    if (!processor_->ProcessFunctionBody(bytes, module_offset)) Fail();
  }

  void Fail() {
    // {Fail} cannot be called after {Finish}, {Abort}, or
    // {NotifyCompilationDiscarded}.
    DCHECK_EQ(processor_ == nullptr, failed_processor_ != nullptr);
    if (processor_ != nullptr) failed_processor_ = std::move(processor_);
    DCHECK_NULL(processor_);
    DCHECK_NOT_NULL(failed_processor_);
  }

  bool ok() const {
    DCHECK_EQ(processor_ == nullptr, failed_processor_ != nullptr);
    return processor_ != nullptr;
  }

  uint32_t module_offset() const { return module_offset_; }

  // As long as we did not detect an invalid module, {processor_} will be set.
  // On failure, the pointer is transferred to {failed_processor_} and will only
  // be used for a final callback once all bytes have arrived. Finally, both
  // {processor_} and {failed_processor_} will be null.
  std::unique_ptr<StreamingProcessor> processor_;
  std::unique_ptr<StreamingProcessor> failed_processor_;
  std::unique_ptr<DecodingState> state_;
  std::vector<std::shared_ptr<SectionBuffer>> section_buffers_;
  bool code_section_processed_ = false;
  uint32_t module_offset_ = 0;

  // Store the full wire bytes in a vector of vectors to avoid having to grow
  // large vectors (measured up to 100ms delay in 2023-03).
  // TODO(clemensb): Avoid holding the wire bytes live twice (here and in the
  // section buffers).
  std::vector<std::vector<uint8_t>> full_wire_bytes_{{}};
};

void AsyncStreamingDecoder::OnBytesReceived(base::Vector<const uint8_t> bytes) {
  DCHECK(!full_wire_bytes_.empty());
  // Fill the previous vector, growing up to 16kB. After that, allocate new
  // vectors on overflow.
  size_t remaining_capacity =
      std::max(full_wire_bytes_.back().capacity(), size_t{16} * KB) -
      full_wire_bytes_.back().size();
  size_t bytes_for_existing_vector = std::min(remaining_capacity, bytes.size());
  full_wire_bytes_.back().insert(full_wire_bytes_.back().end(), bytes.data(),
                                 bytes.data() + bytes_for_existing_vector);
  if (bytes.size() > bytes_for_existing_vector) {
    // The previous vector's capacity is not enough to hold all new bytes, and
    // it's bigger than 16kB, so expensive to copy. Allocate a new vector for
    // the remaining bytes, growing exponentially.
    size_t new_capacity = std::max(bytes.size() - bytes_for_existing_vector,
                                   2 * full_wire_bytes_.back().capacity());
    full_wire_bytes_.emplace_back();
    full_wire_bytes_.back().reserve(new_capacity);
    full_wire_bytes_.back().insert(full_wire_bytes_.back().end(),
                                   bytes.data() + bytes_for_existing_vector,
                                   bytes.end());
  }

  if (deserializing()) return;

  TRACE_STREAMING("OnBytesReceived(%zu bytes)\n", bytes.size());

  size_t current = 0;
  while (ok() && current < bytes.size()) {
    size_t num_bytes =
        state_->ReadBytes(this, bytes.SubVector(current, bytes.size()));
    current += num_bytes;
    module_offset_ += num_bytes;
    if (state_->offset() == state_->buffer().size()) {
      state_ = state_->Next(this);
    }
  }
  if (ok()) {
    processor_->OnFinishedChunk();
  }
}

size_t AsyncStreamingDecoder::DecodingState::ReadBytes(
    AsyncStreamingDecoder* streaming, base::Vector<const uint8_t> bytes) {
  base::Vector<uint8_t> remaining_buf = buffer() + offset();
  size_t num_bytes = std::min(bytes.size(), remaining_buf.size());
  TRACE_STREAMING("ReadBytes(%zu bytes)\n", num_bytes);
  memcpy(remaining_buf.begin(), &bytes.first(), num_bytes);
  set_offset(offset() + num_bytes);
  return num_bytes;
}

void AsyncStreamingDecoder::Finish(bool can_use_compiled_module) {
  TRACE_STREAMING("Finish\n");
  // {Finish} cannot be called after {Finish}, {Abort}, or
  // {NotifyCompilationDiscarded}.
  CHECK_EQ(processor_ == nullptr, failed_processor_ != nullptr);

  // Create a final copy of the overall wire bytes; this will finally be
  // transferred and stored in the NativeModule.
  base::OwnedVector<const uint8_t> bytes_copy;
  DCHECK_IMPLIES(full_wire_bytes_.back().empty(), full_wire_bytes_.size() == 1);
  if (!full_wire_bytes_.back().empty()) {
    size_t total_length = 0;
    for (auto& bytes : full_wire_bytes_) total_length += bytes.size();
    if (ok()) {
      // {DecodeSectionLength} enforces this with graceful error reporting.
      CHECK_LE(total_length, max_module_size());
    }
    auto all_bytes = base::OwnedVector<uint8_t>::NewForOverwrite(total_length);
    uint8_t* ptr = all_bytes.begin();
    for (auto& bytes : full_wire_bytes_) {
      memcpy(ptr, bytes.data(), bytes.size());
      ptr += bytes.size();
    }
    DCHECK_EQ(all_bytes.end(), ptr);
    bytes_copy = std::move(all_bytes);
  }

  if (ok() && deserializing()) {
    // Try to deserialize the module from wire bytes and module bytes.
    if (can_use_compiled_module &&
        processor_->Deserialize(compiled_module_bytes_,
                                base::VectorOf(bytes_copy))) {
      return;
    }

    // Compiled module bytes are invalidated by can_use_compiled_module = false
    // or the deserialization failed. Restart decoding using |bytes_copy|.
    // Reset {full_wire_bytes} to a single empty vector.
    full_wire_bytes_.assign({{}});
    compiled_module_bytes_ = {};
    DCHECK(!deserializing());
    OnBytesReceived(base::VectorOf(bytes_copy));
    // The decoder has received all wire bytes; fall through and finish.
  }

  if (ok() && !state_->is_finishing_allowed()) {
    // The byte stream ended too early, we report an error.
    Fail();
  }

  // Calling {OnFinishedStream} calls out to JS. Avoid further callbacks (by
  // aborting the stream) by resetting the processor field before calling
  // {OnFinishedStream}.
  const bool failed = !ok();
  std::unique_ptr<StreamingProcessor> processor =
      failed ? std::move(failed_processor_) : std::move(processor_);
  processor->OnFinishedStream(std::move(bytes_copy), failed);
}

void AsyncStreamingDecoder::Abort() {
  TRACE_STREAMING("Abort\n");
  // Ignore {Abort} after {Finish}.
  if (!processor_ && !failed_processor_) return;
  Fail();
  failed_processor_->OnAbort();
  failed_processor_.reset();
}

namespace {

class CallMoreFunctionsCanBeSerializedCallback
    : public CompilationEventCallback {
 public:
  CallMoreFunctionsCanBeSerializedCallback(
      std::weak_ptr<NativeModule> native_module,
      AsyncStreamingDecoder::MoreFunctionsCanBeSerializedCallback callback)
      : native_module_(std::move(native_module)),
        callback_(std::move(callback)) {
    // As a baseline we also count the modules that could be cached but
    // never reach the threshold.
    if (std::shared_ptr<NativeModule> module = native_module_.lock()) {
      module->counters()->wasm_cache_count()->AddSample(0);
    }
  }

  void call(CompilationEvent event) override {
    if (event != CompilationEvent::kFinishedCompilationChunk) return;
    // If the native module is still alive, get back a shared ptr and call the
    // callback.
    if (std::shared_ptr<NativeModule> native_module = native_module_.lock()) {
      native_module->counters()->wasm_cache_count()->AddSample(++cache_count_);
      callback_(native_module);
    }
  }

  ReleaseAfterFinalEvent release_after_final_event() override {
    return kKeepAfterFinalEvent;
  }

 private:
  const std::weak_ptr<NativeModule> native_module_;
  const AsyncStreamingDecoder::MoreFunctionsCanBeSerializedCallback callback_;
  int cache_count_ = 0;
};

}  // namespace

void AsyncStreamingDecoder::NotifyNativeModuleCreated(
    const std::shared_ptr<NativeModule>& native_module) {
  if (!more_functions_can_be_serialized_callback_) return;
  auto* comp_state = native_module->compilation_state();

  comp_state->AddCallback(
      std::make_unique<CallMoreFunctionsCanBeSerializedCallback>(
          native_module,
          std::move(more_functions_can_be_serialized_callback_)));
  more_functions_can_be_serialized_callback_ = {};
}

// An abstract class to share code among the states which decode VarInts. This
// class takes over the decoding of the VarInt and then calls the actual decode
// code with the decoded value.
class AsyncStreamingDecoder::DecodeVarInt32 : public DecodingState {
 public:
  explicit DecodeVarInt32(size_t max_value, const char* field_name)
      : max_value_(max_value), field_name_(field_name) {}

  base::Vector<uint8_t> buffer() override {
    return base::ArrayVector(byte_buffer_);
  }

  size_t ReadBytes(AsyncStreamingDecoder* streaming,
                   base::Vector<const uint8_t> bytes) override;

  std::unique_ptr<DecodingState> Next(
      AsyncStreamingDecoder* streaming) override;

  virtual std::unique_ptr<DecodingState> NextWithValue(
      AsyncStreamingDecoder* streaming) = 0;

 protected:
  uint8_t byte_buffer_[kMaxVarInt32Size];
  // The maximum valid value decoded in this state. {Next} returns an error if
  // this value is exceeded.
  const size_t max_value_;
  const char* const field_name_;
  size_t value_ = 0;
  size_t bytes_consumed_ = 0;
};

class AsyncStreamingDecoder::DecodeModuleHeader : public DecodingState {
 public:
  base::Vector<uint8_t> buffer() override {
    return base::ArrayVector(byte_buffer_);
  }

  std::unique_ptr<DecodingState> Next(
      AsyncStreamingDecoder* streaming) override;

 private:
  // Checks if the magic bytes of the module header are correct.
  void CheckHeader(Decoder* decoder);

  // The size of the module header.
  static constexpr size_t kModuleHeaderSize = 8;
  uint8_t byte_buffer_[kModuleHeaderSize];
};

class AsyncStreamingDecoder::DecodeSectionID : public DecodingState {
 public:
  explicit DecodeSectionID(uint32_t module_offset)
      : module_offset_(module_offset) {}

  base::Vector<uint8_t> buffer() override { return {&id_, 1}; }
  bool is_finishing_allowed() const override { return true; }

  std::unique_ptr<DecodingState> Next(
      AsyncStreamingDecoder* streaming) override;

 private:
  uint8_t id_ = 0;
  // The start offset of this section in the module.
  const uint32_t module_offset_;
};

class AsyncStreamingDecoder::DecodeSectionLength : public DecodeVarInt32 {
 public:
  explicit DecodeSectionLength(uint8_t id, uint32_t module_offset)
      : DecodeVarInt32(max_module_size(), "section length"),
        section_id_(id),
        module_offset_(module_offset) {}

  std::unique_ptr<DecodingState> NextWithValue(
      AsyncStreamingDecoder* streaming) override;

 private:
  const uint8_t section_id_;
  // The start offset of this section in the module.
  const uint32_t module_offset_;
};

class AsyncStreamingDecoder::DecodeSectionPayload : public DecodingState {
 public:
  explicit DecodeSectionPayload(SectionBuffer* section_buffer)
      : section_buffer_(section_buffer) {}

  base::Vector<uint8_t> buffer() override { return section_buffer_->payload(); }

  std::unique_ptr<DecodingState> Next(
      AsyncStreamingDecoder* streaming) override;

 private:
  SectionBuffer* const section_buffer_;
};

class AsyncStreamingDecoder::DecodeNumberOfFunctions : public DecodeVarInt32 {
 public:
  explicit DecodeNumberOfFunctions(SectionBuffer* section_buffer)
      : DecodeVarInt32(v8_flags.max_wasm_functions, "functions count"),
        section_buffer_(section_buffer) {}

  std::unique_ptr<DecodingState> NextWithValue(
      AsyncStreamingDecoder* streaming) override;

 private:
  SectionBuffer* const section_buffer_;
};

class AsyncStreamingDecoder::DecodeFunctionLength : public DecodeVarInt32 {
 public:
  explicit DecodeFunctionLength(SectionBuffer* section_buffer,
                                size_t buffer_offset,
                                size_t num_remaining_functions)
      : DecodeVarInt32(kV8MaxWasmFunctionSize, "function body size"),
        section_buffer_(section_buffer),
        buffer_offset_(buffer_offset),
        // We are reading a new function, so one function less is remaining.
        num_remaining_functions_(num_remaining_functions - 1) {
    DCHECK_GT(num_remaining_functions, 0);
  }

  std::unique_ptr<DecodingState> NextWithValue(
      AsyncStreamingDecoder* streaming) override;

 private:
  SectionBuffer* const section_buffer_;
  const size_t buffer_offset_;
  const size_t num_remaining_functions_;
};

class AsyncStreamingDecoder::DecodeFunctionBody : public DecodingState {
 public:
  explicit DecodeFunctionBody(SectionBuffer* section_buffer,
                              size_t buffer_offset, size_t function_body_length,
                              size_t num_remaining_functions,
                              uint32_t module_offset)
      : section_buffer_(section_buffer),
        buffer_offset_(buffer_offset),
        function_body_length_(function_body_length),
        num_remaining_functions_(num_remaining_functions),
        module_offset_(module_offset) {}

  base::Vector<uint8_t> buffer() override {
    base::Vector<uint8_t> remaining_buffer =
        section_buffer_->bytes() + buffer_offset_;
    return remaining_buffer.SubVector(0, function_body_length_);
  }

  std::unique_ptr<DecodingState> Next(
      AsyncStreamingDecoder* streaming) override;

 private:
  SectionBuffer* const section_buffer_;
  const size_t buffer_offset_;
  const size_t function_body_length_;
  const size_t num_remaining_functions_;
  const uint32_t module_offset_;
};

size_t AsyncStreamingDecoder::DecodeVarInt32::ReadBytes(
    AsyncStreamingDecoder* streaming, base::Vector<const uint8_t> bytes) {
  base::Vector<uint8_t> buf = buffer();
  base::Vector<uint8_t> remaining_buf = buf + offset();
  size_t new_bytes = std::min(bytes.size(), remaining_buf.size());
  TRACE_STREAMING("ReadBytes of a VarInt\n");
  memcpy(remaining_buf.begin(), &bytes.first(), new_bytes);
  buf.Truncate(offset() + new_bytes);
  Decoder decoder(buf,
                  streaming->module_offset() - static_cast<uint32_t>(offset()));
  value_ = decoder.consume_u32v(field_name_);

  if (decoder.failed()) {
    if (new_bytes == remaining_buf.size()) {
      // We only report an error if we read all bytes.
      streaming->Fail();
    }
    set_offset(offset() + new_bytes);
    return new_bytes;
  }

  // The number of bytes we actually needed to read.
  DCHECK_GT(decoder.pc(), buffer().begin());
  bytes_consumed_ = static_cast<size_t>(decoder.pc() - buf.begin());
  TRACE_STREAMING("  ==> %zu bytes consumed\n", bytes_consumed_);

  // We read all the bytes we needed.
  DCHECK_GT(bytes_consumed_, offset());
  new_bytes = bytes_consumed_ - offset();
  // Set the offset to the buffer size to signal that we are at the end of this
  // section.
  set_offset(buffer().size());
  return new_bytes;
}

std::unique_ptr<AsyncStreamingDecoder::DecodingState>
AsyncStreamingDecoder::DecodeVarInt32::Next(AsyncStreamingDecoder* streaming) {
  if (!streaming->ok()) return nullptr;

  if (value_ > max_value_) return streaming->ToErrorState();

  return NextWithValue(streaming);
}

std::unique_ptr<AsyncStreamingDecoder::DecodingState>
AsyncStreamingDecoder::DecodeModuleHeader::Next(
    AsyncStreamingDecoder* streaming) {
  TRACE_STREAMING("DecodeModuleHeader\n");
  streaming->ProcessModuleHeader();
  if (!streaming->ok()) return nullptr;
  return std::make_unique<DecodeSectionID>(streaming->module_offset());
}

std::unique_ptr<AsyncStreamingDecoder::DecodingState>
AsyncStreamingDecoder::DecodeSectionID::Next(AsyncStreamingDecoder* streaming) {
  TRACE_STREAMING("DecodeSectionID: %u (%s)\n", id_,
                  SectionName(static_cast<SectionCode>(id_)));
  if (!IsValidSectionCode(id_)) return streaming->ToErrorState();
  if (id_ == SectionCode::kCodeSectionCode) {
    // Explicitly check for multiple code sections as module decoder never
    // sees the code section and hence cannot track this section.
    if (streaming->code_section_processed_) return streaming->ToErrorState();
    streaming->code_section_processed_ = true;
  }
  return std::make_unique<DecodeSectionLength>(id_, module_offset_);
}

std::unique_ptr<AsyncStreamingDecoder::DecodingState>
AsyncStreamingDecoder::DecodeSectionLength::NextWithValue(
    AsyncStreamingDecoder* streaming) {
  TRACE_STREAMING("DecodeSectionLength(%zu)\n", value_);
  // Check if this section fits into the overall module length limit.
  // Note: {this->module_offset_} is the position of the section ID byte,
  // {streaming->module_offset_} is the start of the section's payload (i.e.
  // right after the just-decoded section length varint).
  // The latter can already exceed the max module size, when the previous
  // section barely fit into it, and this new section's ID or length crossed
  // the threshold.
  uint32_t payload_start = streaming->module_offset();
  size_t max_size = max_module_size();
  if (payload_start > max_size || max_size - payload_start < value_) {
    return streaming->ToErrorState();
  }
  SectionBuffer* buf =
      streaming->CreateNewBuffer(module_offset_, section_id_, value_,
                                 buffer().SubVector(0, bytes_consumed_));
  DCHECK_NOT_NULL(buf);
  if (value_ == 0) {
    if (section_id_ == SectionCode::kCodeSectionCode) {
      return streaming->ToErrorState();
    }
    // Process section without payload as well, to enforce section order and
    // other feature checks specific to each individual section.
    streaming->ProcessSection(buf);
    if (!streaming->ok()) return nullptr;
    // There is no payload, we go to the next section immediately.
    return std::make_unique<DecodeSectionID>(streaming->module_offset_);
  }
  if (section_id_ == SectionCode::kCodeSectionCode) {
    // We reached the code section. All functions of the code section are put
    // into the same SectionBuffer.
    return std::make_unique<DecodeNumberOfFunctions>(buf);
  }
  return std::make_unique<DecodeSectionPayload>(buf);
}

std::unique_ptr<AsyncStreamingDecoder::DecodingState>
AsyncStreamingDecoder::DecodeSectionPayload::Next(
    AsyncStreamingDecoder* streaming) {
  TRACE_STREAMING("DecodeSectionPayload\n");
  streaming->ProcessSection(section_buffer_);
  if (!streaming->ok()) return nullptr;
  return std::make_unique<DecodeSectionID>(streaming->module_offset());
}

std::unique_ptr<AsyncStreamingDecoder::DecodingState>
AsyncStreamingDecoder::DecodeNumberOfFunctions::NextWithValue(
    AsyncStreamingDecoder* streaming) {
  TRACE_STREAMING("DecodeNumberOfFunctions(%zu)\n", value_);
  // Copy the bytes we read into the section buffer.
  base::Vector<uint8_t> payload_buf = section_buffer_->payload();
  if (payload_buf.size() < bytes_consumed_) return streaming->ToErrorState();
  memcpy(payload_buf.begin(), buffer().begin(), bytes_consumed_);

  DCHECK_GE(kMaxInt, section_buffer_->module_offset() +
                         section_buffer_->payload_offset());
  int code_section_start = static_cast<int>(section_buffer_->module_offset() +
                                            section_buffer_->payload_offset());
  DCHECK_GE(kMaxInt, payload_buf.length());
  int code_section_len = static_cast<int>(payload_buf.length());
  DCHECK_GE(kMaxInt, value_);
  streaming->StartCodeSection(static_cast<int>(value_),
                              streaming->section_buffers_.back(),
                              code_section_start, code_section_len);
  if (!streaming->ok()) return nullptr;

  // {value} is the number of functions.
  if (value_ == 0) {
    if (payload_buf.size() != bytes_consumed_) {
      return streaming->ToErrorState();
    }
    return std::make_unique<DecodeSectionID>(streaming->module_offset());
  }

  return std::make_unique<DecodeFunctionLength>(
      section_buffer_, section_buffer_->payload_offset() + bytes_consumed_,
      value_);
}

std::unique_ptr<AsyncStreamingDecoder::DecodingState>
AsyncStreamingDecoder::DecodeFunctionLength::NextWithValue(
    AsyncStreamingDecoder* streaming) {
  TRACE_STREAMING("DecodeFunctionLength(%zu)\n", value_);
  // Copy the bytes we consumed into the section buffer.
  base::Vector<uint8_t> fun_length_buffer =
      section_buffer_->bytes() + buffer_offset_;
  if (fun_length_buffer.size() < bytes_consumed_) {
    return streaming->ToErrorState();
  }
  memcpy(fun_length_buffer.begin(), buffer().begin(), bytes_consumed_);

  // {value} is the length of the function.
  if (value_ == 0) return streaming->ToErrorState();

  if (buffer_offset_ + bytes_consumed_ + value_ > section_buffer_->length()) {
    return streaming->ToErrorState();
  }

  return std::make_unique<DecodeFunctionBody>(
      section_buffer_, buffer_offset_ + bytes_consumed_, value_,
      num_remaining_functions_, streaming->module_offset());
}

std::unique_ptr<AsyncStreamingDecoder::DecodingState>
AsyncStreamingDecoder::DecodeFunctionBody::Next(
    AsyncStreamingDecoder* streaming) {
  TRACE_STREAMING("DecodeFunctionBody\n");
  streaming->ProcessFunctionBody(buffer(), module_offset_);
  if (!streaming->ok()) return nullptr;

  size_t end_offset = buffer_offset_ + function_body_length_;
  if (num_remaining_functions_ > 0) {
    return std::make_unique<DecodeFunctionLength>(section_buffer_, end_offset,
                                                  num_remaining_functions_);
  }
  // We just read the last function body. Continue with the next section.
  if (end_offset != section_buffer_->length()) {
    return streaming->ToErrorState();
  }
  return std::make_unique<DecodeSectionID>(streaming->module_offset());
}

AsyncStreamingDecoder::AsyncStreamingDecoder(
    std::unique_ptr<StreamingProcessor> processor)
    : processor_(std::move(processor)),
      // A module always starts with a module header.
      state_(new DecodeModuleHeader()) {}

AsyncStreamingDecoder::SectionBuffer* AsyncStreamingDecoder::CreateNewBuffer(
    uint32_t module_offset, uint8_t section_id, size_t length,
    base::Vector<const uint8_t> length_bytes) {
  // Section buffers are allocated in the same order they appear in the module,
  // they will be processed and later on concatenated in that same order.
  section_buffers_.emplace_back(std::make_shared<SectionBuffer>(
      module_offset, section_id, length, length_bytes));
  return section_buffers_.back().get();
}

std::unique_ptr<StreamingDecoder> StreamingDecoder::CreateAsyncStreamingDecoder(
    std::unique_ptr<StreamingProcessor> processor) {
  return std::make_unique<AsyncStreamingDecoder>(std::move(processor));
}

}  // namespace v8::internal::wasm

#undef TRACE_STREAMING

"""

```