Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for the functionality of `module-decoder.cc` and how it relates to JavaScript, including a JavaScript example. This means we need to identify the core responsibilities of the C++ code in the context of WebAssembly and then bridge that understanding to the JavaScript API for WebAssembly.

2. **Initial Scan for Keywords and Concepts:**  A quick skim of the code reveals several important keywords and concepts:
    * `wasm` (repeated many times)
    * `module`
    * `decoder`
    * `section` (Type, Import, Function, Code, etc.)
    * `signature`
    * `function body`
    * `validate`
    * `error`
    * `name` (NameSection)
    * `javascript` (in comments, though not directly in the C++ code)

3. **Identify the Core Functionality:** Based on the keywords, it's clear the code is about processing WebAssembly modules. The presence of "decoder" and various "section codes" strongly suggests this file is responsible for taking the binary representation of a WebAssembly module and interpreting its structure and contents. The functions like `DecodeWasmModule`, `DecodeSection`, `DecodeFunctionBody` reinforce this idea.

4. **Analyze Key Functions and Classes:**
    * **`DecodeWasmModule`:** This appears to be the main entry point for decoding a complete WASM module. There are overloaded versions, suggesting different ways the decoding can happen (with or without validation, metrics, etc.).
    * **`ModuleDecoderImpl`:** This class seems to be the workhorse, containing the actual logic for parsing the WASM binary. The `impl_` member in `ModuleDecoder` suggests a common pattern for hiding implementation details.
    * **`DecodeSection`:**  Handles the decoding of individual sections within the WASM module. The `switch` statement in `SectionName` is crucial for understanding the different types of sections.
    * **`DecodeFunctionBody`:**  Specifically deals with parsing the bytecode within a function.
    * **`ValidateFunctions`:**  Responsible for ensuring the correctness and safety of the function bytecode.
    * **`DecodeNameMap` and related functions:** Handle the optional "name section" which provides symbolic names for functions, locals, etc. This is important for debugging and developer experience.

5. **Map C++ Concepts to WASM Structure:**  The section codes (`kTypeSectionCode`, `kCodeSectionCode`, etc.) directly correspond to the structural elements of a WebAssembly binary format. Understanding the WASM specification is essential here.

6. **Identify the Relationship with JavaScript:** The crucial link is the process of *instantiating* a WebAssembly module in JavaScript. The `WebAssembly.instantiate()` or `WebAssembly.compile()` functions in JavaScript take the raw byte code of a WASM module as input. The C++ code in `module-decoder.cc` is a *part* of the V8 JavaScript engine that handles this input, parses it, and creates the internal representation of the module.

7. **Formulate the Summary:** Based on the analysis, the core functionality can be summarized as: Taking raw WASM bytecode, parsing it section by section, validating the code, and extracting information needed to represent the module within the JavaScript engine. The connection to JavaScript is that this is the engine's internal mechanism for handling WASM module loading.

8. **Develop the JavaScript Example:** To illustrate the connection, a simple example demonstrating the instantiation of a WASM module is needed. This should highlight the input (the WASM byte array) and the output (a `WebAssembly.Module` instance). A minimal WASM module that declares a simple function is a good choice for clarity. The example should show how the JavaScript code interacts with the *result* of the C++ code's work.

9. **Refine and Organize:**  Review the summary and example for clarity and accuracy. Ensure the explanation of how the C++ code contributes to the JavaScript process is clear. Organize the information logically, starting with the high-level function and then drilling down into specifics. Mention the implications, like error handling and performance, to provide a complete picture.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe the C++ code directly generates JavaScript code. **Correction:** No, the C++ code creates an internal representation that the V8 engine uses. JavaScript interacts with the *instantiated* module, not the decoding process itself.
* **Focus too much on low-level details:** While the section codes are important, the high-level goal is to understand *what* the file does, not *how* every single function works. **Correction:** Emphasize the overall purpose and the connection to the JavaScript API.
* **JavaScript example too complex:**  Start with a very simple WASM module to avoid unnecessary complications. **Correction:** Use a minimal example with a single exported function.

By following this systematic approach, combining code analysis with knowledge of WebAssembly and the JavaScript API, a comprehensive and accurate explanation can be generated.
这个C++源代码文件 `v8/src/wasm/module-decoder.cc` 的主要功能是**解码 WebAssembly 模块的二进制格式，并将其转换为 V8 引擎可以理解和执行的内部表示**。 简单来说，它负责解析 WebAssembly 的 `.wasm` 文件。

更具体地说，它的功能包括：

1. **读取和解析 WebAssembly 模块的各个部分（Sections）:** WebAssembly 模块由不同的段组成，例如类型段（Type Section）、导入段（Import Section）、函数段（Function Section）、代码段（Code Section）等等。这个文件中的代码定义了如何识别和解析这些不同的段。`SectionName` 函数就展示了已知的所有段的名称。

2. **解码模块头（Module Header）:** 验证模块的魔数和版本号，确保这是一个合法的 WebAssembly 模块。

3. **解码类型签名（Function Signatures）:** 解析类型段，提取函数、全局变量和表的类型信息。

4. **解码导入和导出（Imports and Exports）:** 解析导入段和导出段，记录模块导入的函数、全局变量、内存和表，以及模块导出的内容。

5. **解码函数定义（Function Definitions）:** 解析函数段和代码段，获取每个函数的签名和字节码指令。

6. **解码全局变量、内存和表（Globals, Memory, and Tables）:** 解析相应的段，获取全局变量的初始值，内存的大小限制，以及表的类型和初始内容。

7. **解码数据段和元素段（Data and Element Segments）:** 解析数据段和元素段，获取内存和表的初始数据。

8. **解码名称段（Name Section，可选）:** 解析可选的名称段，获取函数、局部变量、标签等的名称，用于调试和错误报告。

9. **验证 WebAssembly 代码（Validation）:**  在解码过程中或之后，可以对 WebAssembly 代码进行验证，确保其符合 WebAssembly 的规范，避免潜在的安全问题和运行时错误。`ValidateFunctions` 函数就负责并行地验证模块中的函数。

10. **处理自定义段（Custom Sections）:** 允许 WebAssembly 模块包含自定义的段，此文件也提供了识别和提取这些段的能力。

**与 JavaScript 的关系和 JavaScript 示例:**

`module-decoder.cc` 是 V8 JavaScript 引擎内部的一部分，当 JavaScript 代码尝试加载和实例化 WebAssembly 模块时，这个文件中的代码会被调用。

JavaScript 中加载和实例化 WebAssembly 模块的主要方法是使用 `WebAssembly.instantiate()` 或 `WebAssembly.compile()` API。

**JavaScript 示例:**

```javascript
// 一个简单的 WebAssembly 模块的二进制表示 (WAT 转换而来)
const wasmBytes = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, // 魔数: '\0asm'
  0x01, 0x00, 0x00, 0x00, // 版本: 1

  // 类型段 (Type Section)
  0x01, // 1 个段
  0x07, // 段长度
  0x01, // 1 个类型定义
  0x60, // 函数类型
  0x00, // 0 个参数
  0x01, // 1 个返回值
  0x7f, // i32

  // 导出段 (Export Section)
  0x07, // 1 个段
  0x05, // 段长度
  0x01, // 1 个导出项
  0x00, // 导出索引 0 (指向函数段中的第一个函数)
  0x00, // 导出名称长度
  // 注意: 这里导出的名称为空，通常情况下会有名称

  // 代码段 (Code Section)
  0x0a, // 1 个段
  0x06, // 段长度
  0x01, // 1 个函数体
  0x01, // 函数体大小
  0x00, // 局部变量数量
  0x41, 0x0a, 0x0b // i32.const 10, end
]);

// 加载和实例化 WebAssembly 模块
WebAssembly.instantiate(wasmBytes)
  .then(result => {
    const instance = result.instance;
    // 获取导出的函数 (这里导出的名称为空，所以需要通过索引访问，不推荐)
    // 通常导出时会指定名称，例如 "add"
    // const exportedFunction = instance.exports.add;
    // const result = exportedFunction(5, 3);
    // console.log(result); // 输出: 8

    // 注意：上面的 wasmBytes 定义的模块并没有导出任何带名字的函数。
    // 为了演示 module-decoder 的作用，我们假设上面的 wasmBytes 实际上导出了一个函数。

    console.log("WebAssembly 模块已成功加载和实例化:", instance);
  })
  .catch(error => {
    console.error("加载 WebAssembly 模块失败:", error);
  });
```

**解释 JavaScript 示例与 C++ 代码的关系:**

1. 当 JavaScript 引擎执行 `WebAssembly.instantiate(wasmBytes)` 时，它会将 `wasmBytes` (包含 WebAssembly 模块的二进制数据) 传递给 V8 引擎的内部机制。

2. V8 引擎内部会调用 `module-decoder.cc` 中的代码来解析 `wasmBytes`。

3. `module-decoder.cc` 中的代码会读取 `wasmBytes` 的魔数和版本号，然后逐个解析类型段、导出段、代码段等。

4. 在解析代码段时，`module-decoder.cc` 会提取函数的字节码指令 (`0x41, 0x0a, 0x0b` 在这个例子中代表 `i32.const 10, end`)。

5. 通过解析导出段，`module-decoder.cc` 知道模块导出了什么，并将这些导出信息传递给 JavaScript，最终体现在 `result.instance.exports` 对象中。

6. 如果 `module-decoder.cc` 在解析过程中遇到错误（例如，无效的 WebAssembly 格式），它会抛出错误，导致 JavaScript 的 `Promise` 被拒绝，并在 `catch` 块中捕获。

总之，`module-decoder.cc` 是 JavaScript 引擎理解和执行 WebAssembly 代码的关键组件，它负责将二进制的 WebAssembly 模块转化为引擎可以操作的内部结构，从而使得 JavaScript 可以加载和调用 WebAssembly 模块的功能。

### 提示词
```
这是目录为v8/src/wasm/module-decoder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/module-decoder.h"

#include "src/logging/metrics.h"
#include "src/tracing/trace-event.h"
#include "src/wasm/constant-expression.h"
#include "src/wasm/decoder.h"
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/struct-types.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-opcodes-inl.h"

namespace v8 {
namespace internal {
namespace wasm {

const char* SectionName(SectionCode code) {
  switch (code) {
    case kUnknownSectionCode:
      return "Unknown";
    case kTypeSectionCode:
      return "Type";
    case kImportSectionCode:
      return "Import";
    case kFunctionSectionCode:
      return "Function";
    case kTableSectionCode:
      return "Table";
    case kMemorySectionCode:
      return "Memory";
    case kGlobalSectionCode:
      return "Global";
    case kExportSectionCode:
      return "Export";
    case kStartSectionCode:
      return "Start";
    case kCodeSectionCode:
      return "Code";
    case kElementSectionCode:
      return "Element";
    case kDataSectionCode:
      return "Data";
    case kTagSectionCode:
      return "Tag";
    case kStringRefSectionCode:
      return "StringRef";
    case kDataCountSectionCode:
      return "DataCount";
    case kNameSectionCode:
      return kNameString;
    case kSourceMappingURLSectionCode:
      return kSourceMappingURLString;
    case kDebugInfoSectionCode:
      return kDebugInfoString;
    case kExternalDebugInfoSectionCode:
      return kExternalDebugInfoString;
    case kInstTraceSectionCode:
      return kInstTraceString;
    case kCompilationHintsSectionCode:
      return kCompilationHintsString;
    case kBranchHintsSectionCode:
      return kBranchHintsString;
    default:
      return "<unknown>";
  }
}

ModuleResult DecodeWasmModule(
    WasmEnabledFeatures enabled_features,
    base::Vector<const uint8_t> wire_bytes, bool validate_functions,
    ModuleOrigin origin, Counters* counters,
    std::shared_ptr<metrics::Recorder> metrics_recorder,
    v8::metrics::Recorder::ContextId context_id, DecodingMethod decoding_method,
    WasmDetectedFeatures* detected_features) {
  if (counters) {
    auto size_counter =
        SELECT_WASM_COUNTER(counters, origin, wasm, module_size_bytes);
    static_assert(kV8MaxWasmModuleSize < kMaxInt);
    size_counter->AddSample(static_cast<int>(wire_bytes.size()));
  }

  v8::metrics::WasmModuleDecoded metrics_event;
  base::ElapsedTimer timer;
  timer.Start();
  ModuleResult result =
      DecodeWasmModule(enabled_features, wire_bytes, validate_functions, origin,
                       detected_features);
  if (counters && result.ok()) {
    auto counter =
        SELECT_WASM_COUNTER(counters, origin, wasm_functions_per, module);
    counter->AddSample(
        static_cast<int>(result.value()->num_declared_functions));
  }

  // Record event metrics.
  metrics_event.wall_clock_duration_in_us = timer.Elapsed().InMicroseconds();
  timer.Stop();
  metrics_event.success = result.ok();
  metrics_event.async = decoding_method == DecodingMethod::kAsync ||
                        decoding_method == DecodingMethod::kAsyncStream;
  metrics_event.streamed = decoding_method == DecodingMethod::kSyncStream ||
                           decoding_method == DecodingMethod::kAsyncStream;
  if (result.ok()) {
    metrics_event.function_count = result.value()->num_declared_functions;
  }
  metrics_event.module_size_in_bytes = wire_bytes.size();
  metrics_recorder->DelayMainThreadEvent(metrics_event, context_id);

  return result;
}

ModuleResult DecodeWasmModule(WasmEnabledFeatures enabled_features,
                              base::Vector<const uint8_t> wire_bytes,
                              bool validate_functions, ModuleOrigin origin,
                              WasmDetectedFeatures* detected_features) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.DecodeWasmModule");
  ModuleDecoderImpl decoder{enabled_features, wire_bytes, origin,
                            detected_features};
  ModuleResult result = decoder.DecodeModule(validate_functions);
  return result;
}

ModuleResult DecodeWasmModuleForDisassembler(
    base::Vector<const uint8_t> wire_bytes, ITracer* tracer) {
  constexpr bool kNoValidateFunctions = false;
  WasmDetectedFeatures unused_detected_features;
  ModuleDecoderImpl decoder{WasmEnabledFeatures::All(), wire_bytes, kWasmOrigin,
                            &unused_detected_features, tracer};
  return decoder.DecodeModule(kNoValidateFunctions);
}

ModuleDecoder::ModuleDecoder(WasmEnabledFeatures enabled_features,
                             WasmDetectedFeatures* detected_features)
    : impl_(std::make_unique<ModuleDecoderImpl>(
          enabled_features, base::Vector<const uint8_t>{}, kWasmOrigin,
          detected_features)) {}

ModuleDecoder::~ModuleDecoder() = default;

const std::shared_ptr<WasmModule>& ModuleDecoder::shared_module() const {
  return impl_->shared_module();
}

void ModuleDecoder::DecodeModuleHeader(base::Vector<const uint8_t> bytes) {
  impl_->DecodeModuleHeader(bytes);
}

void ModuleDecoder::DecodeSection(SectionCode section_code,
                                  base::Vector<const uint8_t> bytes,
                                  uint32_t offset) {
  impl_->DecodeSection(section_code, bytes, offset);
}

void ModuleDecoder::DecodeFunctionBody(uint32_t index, uint32_t length,
                                       uint32_t offset) {
  impl_->DecodeFunctionBody(index, length, offset);
}

void ModuleDecoder::StartCodeSection(WireBytesRef section_bytes) {
  impl_->StartCodeSection(section_bytes);
}

bool ModuleDecoder::CheckFunctionsCount(uint32_t functions_count,
                                        uint32_t error_offset) {
  return impl_->CheckFunctionsCount(functions_count, error_offset);
}

ModuleResult ModuleDecoder::FinishDecoding() { return impl_->FinishDecoding(); }

size_t ModuleDecoder::IdentifyUnknownSection(ModuleDecoder* decoder,
                                             base::Vector<const uint8_t> bytes,
                                             uint32_t offset,
                                             SectionCode* result) {
  if (!decoder->ok()) return 0;
  decoder->impl_->Reset(bytes, offset);
  *result =
      IdentifyUnknownSectionInternal(decoder->impl_.get(), ITracer::NoTrace);
  return decoder->impl_->pc() - bytes.begin();
}

bool ModuleDecoder::ok() const { return impl_->ok(); }

Result<const FunctionSig*> DecodeWasmSignatureForTesting(
    WasmEnabledFeatures enabled_features, Zone* zone,
    base::Vector<const uint8_t> bytes) {
  WasmDetectedFeatures unused_detected_features;
  ModuleDecoderImpl decoder{enabled_features, bytes, kWasmOrigin,
                            &unused_detected_features};
  return decoder.toResult(decoder.DecodeFunctionSignature(zone, bytes.begin()));
}

ConstantExpression DecodeWasmInitExprForTesting(
    WasmEnabledFeatures enabled_features, base::Vector<const uint8_t> bytes,
    ValueType expected) {
  WasmDetectedFeatures unused_detected_features;
  ModuleDecoderImpl decoder{enabled_features, bytes, kWasmOrigin,
                            &unused_detected_features};
  return decoder.DecodeInitExprForTesting(expected);
}

FunctionResult DecodeWasmFunctionForTesting(
    WasmEnabledFeatures enabled_features, Zone* zone,
    ModuleWireBytes wire_bytes, const WasmModule* module,
    base::Vector<const uint8_t> function_bytes) {
  if (function_bytes.size() > kV8MaxWasmFunctionSize) {
    return FunctionResult{
        WasmError{0, "size > maximum function size (%zu): %zu",
                  kV8MaxWasmFunctionSize, function_bytes.size()}};
  }
  WasmDetectedFeatures unused_detected_features;
  ModuleDecoderImpl decoder{enabled_features, function_bytes, kWasmOrigin,
                            &unused_detected_features};
  return decoder.DecodeSingleFunctionForTesting(zone, wire_bytes, module);
}

AsmJsOffsetsResult DecodeAsmJsOffsets(
    base::Vector<const uint8_t> encoded_offsets) {
  std::vector<AsmJsOffsetFunctionEntries> functions;

  Decoder decoder(encoded_offsets);
  uint32_t functions_count = decoder.consume_u32v("functions count");
  // Consistency check.
  DCHECK_GE(encoded_offsets.size(), functions_count);
  functions.reserve(functions_count);

  for (uint32_t i = 0; i < functions_count; ++i) {
    uint32_t size = decoder.consume_u32v("table size");
    if (size == 0) {
      functions.emplace_back();
      continue;
    }
    DCHECK(decoder.checkAvailable(size));
    const uint8_t* table_end = decoder.pc() + size;
    uint32_t locals_size = decoder.consume_u32v("locals size");
    int function_start_position = decoder.consume_u32v("function start pos");
    int function_end_position = function_start_position;
    int last_byte_offset = locals_size;
    int last_asm_position = function_start_position;
    std::vector<AsmJsOffsetEntry> func_asm_offsets;
    func_asm_offsets.reserve(size / 4);  // conservative estimation
    // Add an entry for the stack check, associated with position 0.
    func_asm_offsets.push_back(
        {0, function_start_position, function_start_position});
    while (decoder.pc() < table_end) {
      DCHECK(decoder.ok());
      last_byte_offset += decoder.consume_u32v("byte offset delta");
      int call_position =
          last_asm_position + decoder.consume_i32v("call position delta");
      int to_number_position =
          call_position + decoder.consume_i32v("to_number position delta");
      last_asm_position = to_number_position;
      if (decoder.pc() == table_end) {
        // The last entry is the function end marker.
        DCHECK_EQ(call_position, to_number_position);
        function_end_position = call_position;
      } else {
        func_asm_offsets.push_back(
            {last_byte_offset, call_position, to_number_position});
      }
    }
    DCHECK_EQ(decoder.pc(), table_end);
    functions.emplace_back(AsmJsOffsetFunctionEntries{
        function_start_position, function_end_position,
        std::move(func_asm_offsets)});
  }
  DCHECK(decoder.ok());
  DCHECK(!decoder.more());

  return decoder.toResult(AsmJsOffsets{std::move(functions)});
}

std::vector<CustomSectionOffset> DecodeCustomSections(
    base::Vector<const uint8_t> bytes) {
  Decoder decoder(bytes);
  decoder.consume_bytes(4, "wasm magic");
  decoder.consume_bytes(4, "wasm version");

  std::vector<CustomSectionOffset> result;

  while (decoder.more()) {
    uint8_t section_code = decoder.consume_u8("section code");
    uint32_t section_length = decoder.consume_u32v("section length");
    uint32_t section_start = decoder.pc_offset();
    if (section_code != 0) {
      // Skip known sections.
      decoder.consume_bytes(section_length, "section bytes");
      continue;
    }
    uint32_t name_length = decoder.consume_u32v("name length");
    uint32_t name_offset = decoder.pc_offset();
    decoder.consume_bytes(name_length, "section name");
    uint32_t payload_offset = decoder.pc_offset();
    if (section_length < (payload_offset - section_start)) {
      decoder.error("invalid section length");
      break;
    }
    uint32_t payload_length = section_length - (payload_offset - section_start);
    decoder.consume_bytes(payload_length);
    if (decoder.failed()) break;
    result.push_back({{section_start, section_length},
                      {name_offset, name_length},
                      {payload_offset, payload_length}});
  }

  return result;
}

namespace {

bool FindNameSection(Decoder* decoder) {
  static constexpr int kModuleHeaderSize = 8;
  decoder->consume_bytes(kModuleHeaderSize, "module header");

  WasmSectionIterator section_iter(decoder, ITracer::NoTrace);

  while (decoder->ok() && section_iter.more() &&
         section_iter.section_code() != kNameSectionCode) {
    section_iter.advance(true);
  }
  if (!section_iter.more()) return false;

  // Reset the decoder to not read beyond the name section end.
  decoder->Reset(section_iter.payload(), decoder->pc_offset());
  return true;
}

enum class EmptyNames : bool { kAllow, kSkip };

void DecodeNameMapInternal(NameMap& target, Decoder& decoder,
                           EmptyNames empty_names = EmptyNames::kSkip) {
  uint32_t count = decoder.consume_u32v("names count");
  for (uint32_t i = 0; i < count; i++) {
    uint32_t index = decoder.consume_u32v("index");
    WireBytesRef name =
        consume_string(&decoder, unibrow::Utf8Variant::kLossyUtf8, "name");
    if (!decoder.ok()) break;
    if (index > NameMap::kMaxKey) continue;
    if (empty_names == EmptyNames::kSkip && name.is_empty()) continue;
    if (!validate_utf8(&decoder, name)) continue;
    target.Put(index, name);
  }
  target.FinishInitialization();
}

void DecodeNameMap(NameMap& target, Decoder& decoder,
                   uint32_t subsection_payload_length,
                   EmptyNames empty_names = EmptyNames::kSkip) {
  if (target.is_set()) {
    decoder.consume_bytes(subsection_payload_length);
    return;
  }
  DecodeNameMapInternal(target, decoder, empty_names);
}

void DecodeIndirectNameMap(IndirectNameMap& target, Decoder& decoder,
                           uint32_t subsection_payload_length) {
  if (target.is_set()) {
    decoder.consume_bytes(subsection_payload_length);
    return;
  }
  uint32_t outer_count = decoder.consume_u32v("outer count");
  for (uint32_t i = 0; i < outer_count; ++i) {
    uint32_t outer_index = decoder.consume_u32v("outer index");
    if (outer_index > IndirectNameMap::kMaxKey) continue;
    NameMap names;
    DecodeNameMapInternal(names, decoder);
    target.Put(outer_index, std::move(names));
    if (!decoder.ok()) break;
  }
  target.FinishInitialization();
}

}  // namespace

void DecodeFunctionNames(base::Vector<const uint8_t> wire_bytes,
                         NameMap& names) {
  Decoder decoder(wire_bytes);
  if (FindNameSection(&decoder)) {
    while (decoder.ok() && decoder.more()) {
      uint8_t name_type = decoder.consume_u8("name type");
      if (name_type & 0x80) break;  // no varuint7

      uint32_t name_payload_len = decoder.consume_u32v("name payload length");
      if (!decoder.checkAvailable(name_payload_len)) break;

      if (name_type != NameSectionKindCode::kFunctionCode) {
        decoder.consume_bytes(name_payload_len, "name subsection payload");
        continue;
      }
      // We need to allow empty function names for spec-conformant stack traces.
      DecodeNameMapInternal(names, decoder, EmptyNames::kAllow);
      // The spec allows only one occurrence of each subsection. We could be
      // more permissive and allow repeated subsections; in that case we'd
      // have to delay calling {target.FinishInitialization()} on the function
      // names map until we've seen them all.
      // For now, we stop decoding after finding the first function names
      // subsection.
      return;
    }
  }
}

namespace {
// A task that validates multiple functions in parallel, storing the earliest
// validation error in {this} decoder.
class ValidateFunctionsTask : public JobTask {
 public:
  explicit ValidateFunctionsTask(
      base::Vector<const uint8_t> wire_bytes, const WasmModule* module,
      WasmEnabledFeatures enabled_features, std::function<bool(int)> filter,
      WasmError* error_out,
      std::atomic<WasmDetectedFeatures>* detected_features)
      : wire_bytes_(wire_bytes),
        module_(module),
        enabled_features_(enabled_features),
        filter_(std::move(filter)),
        next_function_(module->num_imported_functions),
        after_last_function_(next_function_ + module->num_declared_functions),
        error_out_(error_out),
        detected_features_(detected_features) {
    DCHECK(!error_out->has_error());
  }

  void Run(JobDelegate* delegate) override {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
                 "wasm.ValidateFunctionsTask");

    WasmDetectedFeatures detected_features;
    Zone zone(GetWasmEngine()->allocator(), ZONE_NAME);
    do {
      // Get the index of the next function to validate.
      // {fetch_add} might overrun {after_last_function_} by a bit. Since the
      // number of functions is limited to a value much smaller than the
      // integer range, this is near impossible to happen.
      static_assert(kV8MaxWasmTotalFunctions < kMaxInt / 2);
      int func_index;
      do {
        func_index = next_function_.fetch_add(1, std::memory_order_relaxed);
        if (V8_UNLIKELY(func_index >= after_last_function_)) {
          UpdateDetectedFeatures(detected_features);
          return;
        }
        DCHECK_LE(0, func_index);
      } while ((filter_ && !filter_(func_index)) ||
               module_->function_was_validated(func_index));

      zone.Reset();
      if (!ValidateFunction(func_index, &zone, &detected_features)) {
        // No need to validate any more functions.
        next_function_.store(after_last_function_, std::memory_order_relaxed);
        return;
      }
    } while (!delegate->ShouldYield());
    UpdateDetectedFeatures(detected_features);
  }

  size_t GetMaxConcurrency(size_t /* worker_count */) const override {
    int next_func = next_function_.load(std::memory_order_relaxed);
    return std::max(0, after_last_function_ - next_func);
  }

 private:
  bool ValidateFunction(int func_index, Zone* zone,
                        WasmDetectedFeatures* detected_features) {
    const WasmFunction& function = module_->functions[func_index];
    DCHECK_LT(0, function.code.offset());
    bool is_shared = module_->type(function.sig_index).is_shared;
    FunctionBody body{function.sig, function.code.offset(),
                      wire_bytes_.begin() + function.code.offset(),
                      wire_bytes_.begin() + function.code.end_offset(),
                      is_shared};
    DecodeResult validation_result = ValidateFunctionBody(
        zone, enabled_features_, module_, detected_features, body);
    if (V8_UNLIKELY(validation_result.failed())) {
      SetError(func_index, std::move(validation_result).error());
      return false;
    }
    module_->set_function_validated(func_index);
    return true;
  }

  // Set the error from the argument if it's earlier than the error we already
  // have (or if we have none yet). Thread-safe.
  void SetError(int func_index, WasmError error) {
    base::MutexGuard mutex_guard{&set_error_mutex_};
    if (error_out_->has_error() && error_out_->offset() <= error.offset()) {
      return;
    }
    *error_out_ = GetWasmErrorWithName(wire_bytes_, func_index, module_, error);
  }

  void UpdateDetectedFeatures(WasmDetectedFeatures detected_features) {
    WasmDetectedFeatures old_features =
        detected_features_->load(std::memory_order_relaxed);
    while (!detected_features_->compare_exchange_weak(
        old_features, old_features | detected_features,
        std::memory_order_relaxed)) {
      // Retry with updated {old_features}.
    }
  }

  const base::Vector<const uint8_t> wire_bytes_;
  const WasmModule* const module_;
  const WasmEnabledFeatures enabled_features_;
  const std::function<bool(int)> filter_;
  std::atomic<int> next_function_;
  const int after_last_function_;
  base::Mutex set_error_mutex_;
  WasmError* const error_out_;
  std::atomic<WasmDetectedFeatures>* const detected_features_;
};
}  // namespace

WasmError ValidateFunctions(const WasmModule* module,
                            WasmEnabledFeatures enabled_features,
                            base::Vector<const uint8_t> wire_bytes,
                            std::function<bool(int)> filter,
                            WasmDetectedFeatures* detected_features_out) {
  TRACE_EVENT2(TRACE_DISABLED_BY_DEFAULT("v8.wasm.detailed"),
               "wasm.ValidateFunctions", "num_declared_functions",
               module->num_declared_functions, "has_filter", filter != nullptr);
  DCHECK_EQ(kWasmOrigin, module->origin);

  class NeverYieldDelegate final : public JobDelegate {
   public:
    bool ShouldYield() override { return false; }

    bool IsJoiningThread() const override { UNIMPLEMENTED(); }
    void NotifyConcurrencyIncrease() override { UNIMPLEMENTED(); }
    uint8_t GetTaskId() override { UNIMPLEMENTED(); }
  };

  // Create a {ValidateFunctionsTask} to validate all functions. The earliest
  // error found will be set on this decoder.
  WasmError validation_error;
  std::atomic<WasmDetectedFeatures> detected_features;
  std::unique_ptr<JobTask> validate_job =
      std::make_unique<ValidateFunctionsTask>(
          wire_bytes, module, enabled_features, std::move(filter),
          &validation_error, &detected_features);

  if (v8_flags.single_threaded) {
    // In single-threaded mode, run the {ValidateFunctionsTask} synchronously.
    NeverYieldDelegate delegate;
    validate_job->Run(&delegate);
  } else {
    // Spawn the task and join it.
    std::unique_ptr<JobHandle> job_handle = V8::GetCurrentPlatform()->CreateJob(
        TaskPriority::kUserVisible, std::move(validate_job));
    job_handle->Join();
  }

  *detected_features_out |= detected_features.load(std::memory_order_relaxed);
  return validation_error;
}

WasmError GetWasmErrorWithName(base::Vector<const uint8_t> wire_bytes,
                               int func_index, const WasmModule* module,
                               WasmError error) {
  WasmName name = ModuleWireBytes{wire_bytes}.GetNameOrNull(func_index, module);
  if (name.begin() == nullptr) {
    return WasmError(error.offset(), "Compiling function #%d failed: %s",
                     func_index, error.message().c_str());
  } else {
    TruncatedUserString<> truncated_name(name);
    return WasmError(error.offset(),
                     "Compiling function #%d:\"%.*s\" failed: %s", func_index,
                     truncated_name.length(), truncated_name.start(),
                     error.message().c_str());
  }
}

DecodedNameSection::DecodedNameSection(base::Vector<const uint8_t> wire_bytes,
                                       WireBytesRef name_section) {
  if (name_section.is_empty()) return;  // No name section.
  Decoder decoder(wire_bytes.begin() + name_section.offset(),
                  wire_bytes.begin() + name_section.end_offset(),
                  name_section.offset());
  while (decoder.ok() && decoder.more()) {
    uint8_t name_type = decoder.consume_u8("name type");
    if (name_type & 0x80) break;  // no varuint7

    uint32_t name_payload_len = decoder.consume_u32v("name payload length");
    if (!decoder.checkAvailable(name_payload_len)) break;

    switch (name_type) {
      case kModuleCode:
      case kFunctionCode:
        // Already handled elsewhere.
        decoder.consume_bytes(name_payload_len);
        break;
      case kLocalCode:
        static_assert(kV8MaxWasmTotalFunctions <= IndirectNameMap::kMaxKey);
        static_assert(kV8MaxWasmFunctionLocals <= NameMap::kMaxKey);
        DecodeIndirectNameMap(local_names_, decoder, name_payload_len);
        break;
      case kLabelCode:
        static_assert(kV8MaxWasmTotalFunctions <= IndirectNameMap::kMaxKey);
        static_assert(kV8MaxWasmFunctionSize <= NameMap::kMaxKey);
        DecodeIndirectNameMap(label_names_, decoder, name_payload_len);
        break;
      case kTypeCode:
        static_assert(kV8MaxWasmTypes <= NameMap::kMaxKey);
        DecodeNameMap(type_names_, decoder, name_payload_len);
        break;
      case kTableCode:
        static_assert(kV8MaxWasmTables <= NameMap::kMaxKey);
        DecodeNameMap(table_names_, decoder, name_payload_len);
        break;
      case kMemoryCode:
        static_assert(kV8MaxWasmMemories <= NameMap::kMaxKey);
        DecodeNameMap(memory_names_, decoder, name_payload_len);
        break;
      case kGlobalCode:
        static_assert(kV8MaxWasmGlobals <= NameMap::kMaxKey);
        DecodeNameMap(global_names_, decoder, name_payload_len);
        break;
      case kElementSegmentCode:
        static_assert(kV8MaxWasmTableInitEntries <= NameMap::kMaxKey);
        DecodeNameMap(element_segment_names_, decoder, name_payload_len);
        break;
      case kDataSegmentCode:
        static_assert(kV8MaxWasmDataSegments <= NameMap::kMaxKey);
        DecodeNameMap(data_segment_names_, decoder, name_payload_len);
        break;
      case kFieldCode:
        static_assert(kV8MaxWasmTypes <= IndirectNameMap::kMaxKey);
        static_assert(kV8MaxWasmStructFields <= NameMap::kMaxKey);
        DecodeIndirectNameMap(field_names_, decoder, name_payload_len);
        break;
      case kTagCode:
        static_assert(kV8MaxWasmTags <= NameMap::kMaxKey);
        DecodeNameMap(tag_names_, decoder, name_payload_len);
        break;
    }
  }
}

#undef TRACE

}  // namespace wasm
}  // namespace internal
}  // namespace v8
```