Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding - Core Purpose:**

The first thing I noticed is the file path: `v8/src/wasm/module-decoder.cc`. This immediately tells me the primary function is related to *decoding WebAssembly modules*. The name "decoder" is a strong indicator.

**2. High-Level Functionality Identification (Scanning for Keywords):**

I started scanning the code for keywords and patterns that suggest actions:

* **`DecodeWasmModule` (multiple variations):** This is a central function. The multiple overloads suggest different ways to invoke the decoding process, possibly with varying levels of validation or information gathering.
* **`ModuleDecoderImpl`:**  The presence of an `Impl` class strongly suggests a separation of interface and implementation, a common design pattern. This class likely contains the core decoding logic.
* **`DecodeSection`:**  Wasm modules are structured into sections. This function points to handling individual sections.
* **`DecodeFunctionBody`:**  A crucial part of WASM is the function code. This suggests handling the decoding of individual function bodies.
* **`ValidateFunctions`:**  Security and correctness are important. This function likely verifies the structure and semantics of the Wasm functions.
* **`DecodeNameMap` family:**  The presence of name maps and functions to decode them suggests the code handles debugging information (function names, local variable names, etc.) embedded in the Wasm module.
* **`SectionName`:** This function maps section codes to human-readable names, useful for debugging and logging.
* **Error handling:**  I looked for patterns like `ModuleResult`, `WasmError`, and checks for `decoder.ok()`. These indicate how errors during decoding are managed.
* **Metrics and Tracing:**  Includes of `src/logging/metrics.h` and `src/tracing/trace-event.h` and the usage of `metrics_recorder` and `TRACE_EVENT0` indicate performance monitoring and debugging instrumentation.

**3. Detailed Analysis of Key Functions:**

* **`DecodeWasmModule`:**  I looked at the different overloads. The core one takes `wire_bytes`, `validate_functions`, and other parameters. The other `DecodeWasmModule` functions act as wrappers, some adding metrics collection. The `DecodeWasmModuleForDisassembler` variant is interesting, as it disables validation, hinting at a use case outside of normal execution.
* **`ModuleDecoderImpl::DecodeModule`:** This is the heart of the decoding process. It likely iterates through the sections and calls the appropriate `DecodeSection` methods.
* **Section Decoding (`DecodeSection`):** Although the implementation is in `ModuleDecoderImpl`, the interface in `ModuleDecoder` is present. This signals how different parts of the module are processed. The `SectionName` function is clearly used to identify the sections.
* **Validation (`ValidateFunctions`):** I noticed the use of a `JobTask` and threading (`V8::GetCurrentPlatform()->CreateJob`). This suggests that function validation can be parallelized, improving performance. The `ValidateFunctionBody` call (even though the definition isn't in this file) is the core of the validation process.
* **Name Decoding (`DecodeFunctionNames`, `DecodeNameMap`):** I observed the different types of name maps (function, local, label, etc.) and the structure within the name section. The logic for handling indirect name maps was also noted.

**4. Answering Specific Questions:**

* **Functionality Listing:** Based on the above analysis, I compiled the list of functionalities, focusing on the core actions the code performs.
* **Torque Source:** I checked for the `.tq` extension in the filename. Since it's `.cc`, it's a C++ source file, not a Torque file.
* **JavaScript Relationship:** I thought about how the decoding process relates to JavaScript. The `WebAssembly.Module` constructor in JavaScript is the direct trigger for this decoding process. I provided a simple JavaScript example demonstrating this.
* **Logic Inference (Hypothetical Input/Output):** I chose a simple scenario: a minimal valid Wasm module. I reasoned about the expected output – a `ModuleResult` indicating success and a populated `WasmModule` object. For an invalid module, I predicted a `ModuleResult` indicating failure with an error message.
* **Common Programming Errors:**  I drew upon my knowledge of common issues in Wasm development and how decoding might surface them. Examples include invalid module headers, incorrect section sizes, and malformed instructions. I tried to connect these back to the decoding process itself.

**5. Refinement and Organization:**

Finally, I organized the information logically, using headings and bullet points for clarity. I reviewed the generated answer to ensure it was comprehensive, accurate, and addressed all aspects of the prompt. I paid attention to the wording to be clear and concise.

This iterative process of scanning, analyzing, and reasoning allowed me to understand the purpose and function of the `module-decoder.cc` file effectively, even without deep knowledge of every line of code.
这个文件 `v8/src/wasm/module-decoder.cc` 是 V8 引擎中用于解码 WebAssembly (Wasm) 模块的源代码。它的主要功能是将 WebAssembly 的二进制格式（也被称为 wire 格式）转换为 V8 内部表示的 Wasm 模块结构。

以下是 `v8/src/wasm/module-decoder.cc` 的一些关键功能：

1. **解码 WASM 模块:**
   - 它接收 Wasm 模块的二进制数据作为输入。
   - 它负责解析模块的各个部分（sections），如类型声明、导入、函数定义、内存、表、全局变量、导出、起始函数、代码、元素、数据等。
   - `DecodeWasmModule` 函数是入口点，它协调整个解码过程。

2. **处理模块头信息:**
   - 验证 Wasm 模块的魔数（magic number）和版本号，确保输入是有效的 Wasm 模块。

3. **解析和处理不同的 Section:**
   - **类型 Section (Type Section):**  解码函数签名（参数和返回类型）。
   - **导入 Section (Import Section):**  解码模块导入的函数、内存、表和全局变量。
   - **函数 Section (Function Section):**  解码模块中声明的函数的类型索引。
   - **表 Section (Table Section):**  解码表的类型、大小限制。
   - **内存 Section (Memory Section):**  解码内存的大小限制。
   - **全局变量 Section (Global Section):**  解码全局变量的类型、可变性以及初始值表达式。
   - **导出 Section (Export Section):**  解码模块导出的函数、内存、表和全局变量的名称和索引。
   - **起始 Section (Start Section):**  解码模块的起始函数的索引。
   - **代码 Section (Code Section):**  解码函数体（本地变量声明和指令）。这是最复杂的部分，涉及解析 Wasm 的字节码指令。
   - **元素 Section (Element Section):**  解码用于初始化表的元素段。
   - **数据 Section (Data Section):**  解码用于初始化内存的数据段。
   - **Tag Section (标签 Section):** (如果启用) 解码异常标签。
   - **StringRef Section (字符串引用 Section):** (如果启用) 解码字符串引用类型。
   - **DataCount Section (数据计数 Section):** (如果启用) 解码数据段的数量。
   - **名称 Section (Name Section):**  解码模块、函数、本地变量等的名称，用于调试和反射。
   - **SourceMappingURL Section (源映射 URL Section):** 解码源映射 URL。
   - **DebugInfoSection/ExternalDebugInfoSection (调试信息 Section):** 解码调试相关的信息。
   - **InstTraceSection/CompilationHintsSection/BranchHintsSection (性能提示 Section):** 解码性能分析和优化的提示信息。

4. **验证模块结构和内容:**
   - 在解码过程中，会进行各种验证，例如类型索引是否有效、内存和表的大小是否在限制范围内、指令是否合法等。

5. **构建内部表示:**
   - 解码后的信息被用来创建一个 `WasmModule` 对象，该对象包含了模块的所有结构信息，可以在 V8 中进一步编译和执行。

6. **支持异步解码:**
   - 代码中可以看到对 `DecodingMethod` 的处理，这表明该解码器可能支持同步和异步两种解码方式。

7. **性能监控:**
   - 使用 `metrics::Recorder` 记录解码过程中的性能指标，例如模块大小和解码时间。

8. **错误处理:**
   - `ModuleResult` 类型用于表示解码操作的结果，可能成功或失败，并携带错误信息。

**如果 `v8/src/wasm/module-decoder.cc` 以 `.tq` 结尾:**

如果文件名是 `v8/src/wasm/module-decoder.tq`，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 自研的一种领域特定语言（DSL），用于生成高效的 C++ 代码，特别是在解释器和编译器等性能关键部分。虽然当前的 `module-decoder.cc` 是 C++ 文件，但 V8 中很多类似的功能是用 Torque 编写的。

**与 JavaScript 的功能关系及举例:**

`v8/src/wasm/module-decoder.cc` 的功能直接关联到 JavaScript 中 `WebAssembly.Module` 构造函数的使用。当你创建一个 `WebAssembly.Module` 实例时，V8 内部会调用 `module-decoder.cc` 中的代码来解析传入的 WebAssembly 二进制数据。

```javascript
// 假设 wasmBuffer 包含 WebAssembly 模块的二进制数据
const wasmBuffer = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, // 魔数
  0x01, 0x00, 0x00, 0x00, // 版本
  0x01, 0x07,             // Type section, 7 bytes
  0x01,                   // One function type
  0x60,                   // Function type declaration
  0x00,                   // No parameters
  0x01, 0x7f,             // One result, i32

  0x03, 0x02,             // Function section, 2 bytes
  0x01, 0x00,             // One function, type index 0

  0x0a, 0x09,             // Code section, 9 bytes
  0x01,                   // One function body
  0x07,                   // Body size
  0x00,                   // No local declarations
  0x20, 0x00,             // get_local 0 (虽然没有本地变量，这里只是一个例子)
  0x0f,                   // return
  0x0b                    // end
]);

try {
  const wasmModule = new WebAssembly.Module(wasmBuffer);
  console.log("WebAssembly module decoded successfully!");
} catch (error) {
  console.error("Failed to decode WebAssembly module:", error);
}
```

在这个例子中，当执行 `new WebAssembly.Module(wasmBuffer)` 时，V8 会将 `wasmBuffer` 的内容传递给 `module-decoder.cc` 中的解码器。如果 `wasmBuffer` 的内容格式正确，解码器会成功解析并创建一个内部的 `WasmModule` 对象，然后 JavaScript 就可以使用这个模块进行实例化。如果 `wasmBuffer` 的格式不符合 WebAssembly 规范，解码器会抛出错误，导致 `WebAssembly.Module` 构造函数抛出异常。

**代码逻辑推理（假设输入与输出）:**

**假设输入:** 一个包含单个函数的简单 WebAssembly 模块，该函数返回常量 42。

```wasm
;; 定义一个返回 i32 的函数类型
(type $return_i32 (func (result i32)))

;; 定义一个函数，使用上面定义的类型
(func $get_forty_two (type $return_i32)
  i32.const 42
)

;; 导出这个函数
(export "getFortyTwo" (func $get_forty_two))
```

编译成二进制 (简化表示，实际二进制会更复杂):

```
[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,  // 魔数和版本
 0x01, 0x07, 0x01, 0x60, 0x00, 0x01, 0x7f,       // Type Section: func () -> i32
 0x03, 0x02, 0x01, 0x00,                         // Function Section: 函数索引 0 使用类型索引 0
 0x07, 0x0a, 0x01, 0x06, 0x00, 0x41, 0x2a, 0x0b, // Code Section: 函数体，返回常量 42
 0x07, 0x0a, 0x01, 0x00, 0x0b, 0x08, 0x67, 0x65, 0x74, 0x46, 0x6f, 0x72, 0x74, 0x79, 0x54, 0x77, 0x6f, 0x02, 0x00] // Export Section: 导出名为 "getFortyTwo" 的函数索引 0
```

**预期输出:**

`DecodeWasmModule` 函数会返回一个 `ModuleResult` 对象，其中包含一个成功的 `WasmModule` 实例。这个 `WasmModule` 实例将包含以下信息：

- 一个函数类型，表示无参数并返回 i32。
- 一个函数定义，其类型索引指向上面定义的函数类型。
- 函数的代码部分，包含 `i32.const 42` 和 `return` 指令。
- 一个导出项，将内部函数索引 0 关联到导出的名称 "getFortyTwo"。

**如果输入是无效的 WebAssembly 模块 (例如，魔数错误):**

**假设输入:**

```
[0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, ...] // 错误的魔数
```

**预期输出:**

`DecodeWasmModule` 函数会返回一个 `ModuleResult` 对象，表示解码失败，并包含一个 `WasmError` 对象，指出魔数不匹配。

**用户常见的编程错误举例:**

1. **提供的二进制数据不是有效的 WebAssembly 格式:**
   - **错误示例 (JavaScript):**
     ```javascript
     const invalidWasm = new Uint8Array([1, 2, 3, 4, 5]);
     try {
       const module = new WebAssembly.Module(invalidWasm);
     } catch (error) {
       console.error("Error decoding WASM:", error); // 输出解码错误
     }
     ```
   - **`module-decoder.cc` 中的表现:** 解码器会遇到魔数或版本号不匹配，或者在解析过程中遇到意外的字节，从而抛出 `WasmError`。

2. **WebAssembly 模块结构不符合规范:**
   - **错误示例 (假设手动创建了错误的二进制):** 例如，代码段引用了一个不存在的类型索引，或者代码指令格式错误。
   - **`module-decoder.cc` 中的表现:** 解码器在解析到相应的 section 时会检测到错误，例如在函数段或代码段验证时，会发现类型索引越界或指令不合法，从而抛出 `WasmError`。

3. **提供的 WebAssembly 模块超过 V8 的限制:**
   - **错误示例:** 模块包含过多的函数、过大的内存或表等。
   - **`module-decoder.cc` 中的表现:** 解码器在解析到相应的 section 时会进行大小检查，如果超过限制（例如 `kV8MaxWasmModuleSize`），会抛出 `WasmError`。

4. **名称段 (Name Section) 格式错误:**
   - **错误示例:** 名称段中的长度字段不正确，或者使用了无效的 UTF-8 编码。
   - **`module-decoder.cc` 中的表现:** 解码器在解析名称段时会进行格式验证，如果发现错误会抛出。

总而言之，`v8/src/wasm/module-decoder.cc` 是 V8 引擎中至关重要的组件，它负责将 WebAssembly 的二进制表示转换成可执行的内部结构，并在过程中进行各种验证，确保代码的安全性和正确性。 当 JavaScript 使用 `WebAssembly.Module` 加载 WebAssembly 代码时，这个文件中的代码就会被执行。

### 提示词
```
这是目录为v8/src/wasm/module-decoder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-decoder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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