Response: Let's break down the thought process to understand the provided C++ code and explain its JavaScript relevance.

1. **Understand the Core Task:** The filename `streaming-decoder.cc` and the class name `AsyncStreamingDecoder` strongly suggest the code is responsible for decoding WebAssembly (Wasm) modules in a *streaming* fashion. This means processing the module data as it arrives, rather than waiting for the entire module to be downloaded.

2. **Identify Key Classes and Data Structures:**  Scan the code for class definitions and important data structures:
    * `AsyncStreamingDecoder`: The main class doing the work.
    * `StreamingProcessor`: An abstract class (likely defined elsewhere) that handles the higher-level processing of the decoded Wasm data. This follows a common design pattern where the decoder separates the *how* of decoding from the *what* to do with the decoded data.
    * `SectionBuffer`: Represents a single section within the Wasm module. It holds the raw bytes and metadata about the section.
    * `DecodingState`: An abstract base class for different states in the decoding process. The derived classes (e.g., `DecodeModuleHeader`, `DecodeSectionID`) represent the steps involved in parsing the Wasm binary format.
    * `WireBytesStorage`: An interface for accessing the raw bytes of the module (likely used for storing and retrieving parts of the module data).
    * `NativeModule`: Represents the compiled Wasm module in V8.
    * `CompilationEventCallback`: Used for signaling compilation events, important for asynchronous compilation and potential caching.

3. **Trace the Decoding Process (State Machine):** The comment about the "state diagram" is crucial. Analyze the `DecodingState` hierarchy and the `Next()` methods within each state. This reveals the step-by-step process:
    * Start -> Decode Module Header
    * Decode Section ID -> Decode Section Length -> Decode Section Payload
    * If Section ID is "Code": Decode Number of Functions -> Decode Function Length -> Decode Function Body (repeated for each function).

4. **Focus on `OnBytesReceived()`:** This method is the heart of the streaming aspect. Understand how it receives chunks of bytes and feeds them into the current `DecodingState`. The loop within `OnBytesReceived()` and the `ReadBytes()` method of `DecodingState` are key.

5. **Examine the Role of `StreamingProcessor`:** Note the calls to methods like `ProcessModuleHeader()`, `ProcessSection()`, `ProcessCodeSectionHeader()`, and `ProcessFunctionBody()`. These calls delegate the actual interpretation and handling of the decoded data to the `StreamingProcessor`. This emphasizes the separation of concerns.

6. **Understand `Finish()` and `Abort()`:**  These methods handle the completion (successful or failed) of the streaming process. Pay attention to how `Finish()` handles potential deserialization from cached data and the handling of the final `bytes_copy`. `Abort()` is for handling errors or premature termination.

7. **Identify JavaScript Connections:**  Consider *why* this code exists within V8. WebAssembly is executed within JavaScript environments. This implies the decoded Wasm module will eventually be used by JavaScript.
    * The `StreamingProcessor` likely has an implementation that bridges the gap between the C++ decoding and the JavaScript VM. It's responsible for creating the necessary JavaScript objects and structures to represent the Wasm module.
    * The callbacks (like the `MoreFunctionsCanBeSerializedCallback`) are used to notify the JavaScript side about the progress of compilation, allowing for optimizations or caching.
    * The overall goal is to take the raw bytes from a network stream (or other source) and turn them into an executable WebAssembly module usable by JavaScript.

8. **Construct the JavaScript Example:**  Think about the JavaScript API that uses streaming compilation. The `WebAssembly.compileStreaming()` and `WebAssembly.instantiateStreaming()` functions are the obvious candidates. Illustrate how these functions fetch Wasm bytecode and how the underlying C++ code (like this `AsyncStreamingDecoder`) would be involved in processing that stream of bytes. Emphasize the *asynchronous* nature of these JavaScript APIs and how it aligns with the "async" in `AsyncStreamingDecoder`.

9. **Summarize the Functionality:** Concisely describe the main purpose of the code, highlighting the streaming aspect, the state machine approach, and the interaction with the `StreamingProcessor`.

10. **Review and Refine:** Read through the explanation, ensuring clarity, accuracy, and completeness. Check for any jargon that needs further explanation. Make sure the JavaScript example is clear and illustrative.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this code directly creates JavaScript objects.
* **Correction:**  The separation of concerns suggests the `StreamingProcessor` handles the creation of those objects, making the decoder more focused on the raw byte processing.
* **Initial thought:** The state machine might be simpler.
* **Realization:** The complexity reflects the structure of the Wasm binary format itself, with its sections and variable-length encoding.
* **Initial thought:** The JavaScript connection is obvious.
* **Refinement:**  It's important to explicitly link the C++ code to the corresponding JavaScript APIs and explain *how* the streaming nature is reflected on the JavaScript side (promises, asynchronous operations).

By following these steps,  we arrive at a comprehensive understanding and explanation of the `streaming-decoder.cc` file and its relationship to JavaScript.
这个 C++ 源代码文件 `streaming-decoder.cc` 的主要功能是**异步地解码 WebAssembly (Wasm) 模块的字节流**。它实现了一种流式解码器，允许 V8 引擎在 Wasm 模块下载过程中逐步解析和处理模块内容，而无需等待整个模块下载完成。

以下是其主要功能点的归纳：

1. **异步处理字节流:** `AsyncStreamingDecoder` 类负责接收和处理来自网络或其他来源的 Wasm 模块字节流的片段。 `OnBytesReceived` 方法是接收新字节的关键入口点。

2. **状态机驱动的解码:**  解码过程被组织成一个状态机，由 `DecodingState` 及其派生类（如 `DecodeModuleHeader`, `DecodeSectionID`, `DecodeSectionLength`, `DecodeSectionPayload`, `DecodeNumberOfFunctions`, `DecodeFunctionLength`, `DecodeFunctionBody`）表示。每个状态负责解码 Wasm 模块的特定部分。

3. **逐段解析:**  解码器按照 Wasm 模块的结构逐段解析，包括模块头、各个段（如类型段、导入段、函数段、代码段等）以及代码段中的函数体。

4. **错误处理:**  解码器包含错误处理机制，例如当遇到无效的模块结构、超出限制的值等情况时，会切换到错误状态 (`ToErrorState`) 并停止解码。 `Fail()` 方法用于标记解码失败。

5. **与 `StreamingProcessor` 交互:**  解码器本身不负责解释 Wasm 代码或生成最终的可执行模块。它与一个 `StreamingProcessor` 接口（抽象类）进行交互，将解码后的模块结构信息传递给 `StreamingProcessor` 的具体实现。`StreamingProcessor` 负责实际的处理逻辑，例如创建内部数据结构、编译代码等。

6. **处理代码段的特殊逻辑:**  代码段的解码有特殊的处理流程，需要先解码函数数量，然后逐个解码函数体的长度和内容。

7. **支持模块缓存和反序列化:**  `Finish` 方法中包含了尝试反序列化已编译模块的逻辑，如果可以复用之前编译的结果，可以加速模块的加载。

8. **处理解码完成和中止:** `Finish` 方法在所有字节接收完毕后被调用，用于通知 `StreamingProcessor` 解码完成。 `Abort` 方法用于中止解码过程。

9. **回调机制:**  通过 `NotifyNativeModuleCreated` 方法，解码器可以注册回调函数 (`MoreFunctionsCanBeSerializedCallback`)，以便在 NativeModule 创建后通知 JavaScript 层面，这对于优化编译和缓存非常重要。

**与 JavaScript 的关系及示例:**

`streaming-decoder.cc` 是 V8 引擎内部实现的一部分，它直接支持 JavaScript 中加载和编译 WebAssembly 模块的流式 API。  JavaScript 提供了以下 API 来利用流式编译：

* **`WebAssembly.compileStreaming(source)`:**  该函数接收一个 `Response` 对象（通常来自 `fetch` API）或一个 Promise，该 Promise 解析为一个 `Response` 对象，其中包含 Wasm 模块的字节流。 它会异步地编译 Wasm 模块，而无需等待所有字节下载完成。

* **`WebAssembly.instantiateStreaming(source, importObject)`:**  类似于 `compileStreaming`，但它会同时编译和实例化 Wasm 模块，并允许传入导入对象。

**JavaScript 示例:**

```javascript
async function loadWasmModule(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const wasmModule = await WebAssembly.compileStreaming(response);
    const instance = await WebAssembly.instantiate(wasmModule);
    return instance.exports;
  } catch (error) {
    console.error("Could not load WASM module:", error);
  }
}

loadWasmModule('my-wasm-module.wasm')
  .then(exports => {
    console.log("WASM module loaded successfully!");
    // 使用导出的函数
    console.log(exports.add(5, 3));
  });
```

**在这个 JavaScript 示例中，当 `WebAssembly.compileStreaming(response)` 被调用时，V8 引擎内部会创建 `AsyncStreamingDecoder` 的实例来处理 `response.body` 中返回的字节流。**  `AsyncStreamingDecoder` 会在数据到达时逐步解码 Wasm 模块，并将解码后的信息传递给 `StreamingProcessor` 的实现，最终生成可执行的 Wasm 模块。

**总结来说，`streaming-decoder.cc` 是 V8 引擎实现 WebAssembly 流式编译的核心组件，它使得 JavaScript 能够更高效地加载和执行大型 Wasm 模块，提升了 Web 应用的性能和用户体验。**

Prompt: 
```
这是目录为v8/src/wasm/streaming-decoder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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