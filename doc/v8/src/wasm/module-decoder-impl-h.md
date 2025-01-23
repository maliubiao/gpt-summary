Response:
My thought process for analyzing the provided C++ header file goes like this:

1. **Initial Skim for Keywords and Structure:** I quickly scanned the code looking for familiar C++ constructs like `#ifndef`, `#define`, `namespace`, `class`, `inline`, `constexpr`, comments (`//`), and function definitions. This gives me a high-level understanding of the file's purpose as a header file within a C++ project. The copyright notice confirms it's part of the V8 project.

2. **Conditional Compilation:** The `#if !V8_ENABLE_WEBASSEMBLY` block immediately tells me this code is specifically related to WebAssembly functionality. The `#error` directive reinforces this, indicating the header *must* be included when WebAssembly is enabled. This is a crucial piece of information for understanding its core purpose.

3. **Header Guards:** The `#ifndef V8_WASM_MODULE_DECODER_IMPL_H_` and `#define V8_WASM_MODULE_DECODER_IMPL_H_` pattern are standard header guards, preventing multiple inclusions and compilation errors.

4. **Includes:**  The `#include` directives reveal the dependencies of this header file. I noted includes from the `src` directory within V8 (`base`, `logging`, `strings`, `utils`, `wasm`). These give clues about the functionalities it might be interacting with, such as platform wrappers, logging, string handling, utilities, and other WebAssembly-related components.

5. **Namespace:** The `namespace v8::internal::wasm` clearly places this code within the WebAssembly implementation details of the V8 engine.

6. **Tracing Macros:** The `TRACE(...)` macro suggests the presence of debugging or logging capabilities during the decoding process. The `v8_flags.trace_wasm_decoder` condition indicates this is controlled by a runtime flag.

7. **Constants:** The `constexpr` definitions like `kNameString`, `kSourceMappingURLString`, etc., hint at the types of metadata or information being processed during module decoding. These strings likely correspond to specific sections or attributes within a WebAssembly module.

8. **`ExternalKindName` Function:**  This inline function maps `ImportExportKindCode` enum values to human-readable strings ("function", "table", etc.). This immediately points to the file's involvement in handling imports and exports within WebAssembly modules.

9. **String Handling Functions:** The `validate_utf8` and `consume_string` functions and their variants are strong indicators that this code deals with parsing and validating strings from the WebAssembly binary format. The different `Utf8Variant` options suggest the code needs to handle different string encodings.

10. **`IdentifyUnknownSectionInternal` Function:** This function's purpose is to identify the type of an unknown section in the WebAssembly module by examining its name. The hardcoded `kSpecialSections` array lists well-known custom section names.

11. **`WasmSectionIterator` Class:** This class is designed to iterate through the different sections of a WebAssembly module. Its methods (`more`, `section_code`, `payload`, `advance`) clearly indicate its role in parsing the structured format of a `.wasm` file.

12. **`DumpModule` Function:** This function suggests a debugging or diagnostic capability to save the raw module bytes to a file. The naming convention (`<hash>.{ok,failed}.wasm`) indicates whether the decoding process was successful.

13. **`ModuleDecoderImpl` Class:** This appears to be the core class responsible for decoding the WebAssembly module. Its constructor takes `WasmEnabledFeatures`, the raw byte vector, and other context information. The `DecodeModuleHeader` and `DecodeSection` methods confirm its central role in parsing the module structure.

14. **Section-Specific Decoding Methods:** The `DecodeTypeSection`, `DecodeImportSection`, `DecodeFunctionSection`, etc., methods indicate the code's responsibility for handling the logic of parsing each specific section of a WebAssembly module.

15. **Type System Decoding:**  The `consume_base_type_definition` and `consume_subtype_definition` functions, along with the handling of `kWasmFunctionTypeCode`, `kWasmStructTypeCode`, and `kWasmArrayTypeCode`, strongly suggest the code is involved in decoding the type definitions within a WebAssembly module, including support for GC types and subtyping.

16. **Import Handling Logic:** The `DecodeImportSection` method demonstrates the logic for parsing imported functions, tables, memories, globals, and tags.

17. **Error Handling:** The presence of `decoder->errorf` calls throughout the code highlights the importance of error detection and reporting during the decoding process.

**Synthesizing the Information:** Based on these observations, I can conclude that `v8/src/wasm/module-decoder-impl.h` defines the implementation details for decoding a WebAssembly module's binary format. It handles parsing the module header, iterating through sections, identifying known and unknown sections, validating the structure and content of each section, and extracting relevant information like types, imports, exports, functions, tables, memories, globals, and custom metadata. The code pays attention to error handling and provides debugging/tracing capabilities.

**Addressing Specific Questions:**

* **`.tq` Extension:** I note that the question explicitly asks about the `.tq` extension and Torque. Since this file ends in `.h`, it's a standard C++ header, *not* a Torque file. However, understanding the question helps me anticipate that the user might be interested in the relationship between this C++ code and any potential Torque equivalents or related functionalities.

* **JavaScript Relationship:** Because WebAssembly is designed to be executed within a JavaScript environment, I considered how the decoding process might relate to JavaScript. The information extracted by this decoder is ultimately used by the V8 engine to instantiate and execute the WebAssembly module within a JavaScript context. This involves creating JavaScript objects that represent the module's functions, memories, tables, etc.

* **Logic and Examples:** I looked for clear code logic patterns within the provided snippet. The section iteration and the handling of different section types are good examples. I started thinking about potential inputs (raw byte arrays of WebAssembly modules) and outputs (structured representations of the module).

* **Common Errors:** The validation checks within the decoding logic (e.g., UTF-8 validation, section size checks, type index bounds) hinted at potential user errors when creating or manipulating WebAssembly binaries.

By following this systematic analysis, I was able to build a comprehensive understanding of the header file's purpose and its role within the V8 WebAssembly implementation, allowing me to answer the user's questions effectively.
这是v8/src/wasm/module-decoder-impl.h的源代码分析，它是一个C++头文件，主要负责WebAssembly模块的**解码**实现。

**功能归纳:**

这个头文件的主要功能是定义了 `ModuleDecoderImpl` 类，该类负责将 WebAssembly 模块的二进制表示（字节流）解析成 V8 内部的 `WasmModule` 数据结构。  更具体地说，它做了以下事情：

1. **模块头解析:**  `DecodeModuleHeader` 函数负责读取并验证 WebAssembly 模块的魔数（magic number）和版本号。

2. **分段解码:** `WasmSectionIterator` 类用于迭代 WebAssembly 模块的各个段（section），`DecodeSection` 函数根据段的类型调用相应的解码函数，例如 `DecodeTypeSection`, `DecodeImportSection`, `DecodeFunctionSection` 等。

3. **类型段解码:** `DecodeTypeSection` 函数负责解析模块中定义的类型 (signatures)。这包括函数签名、结构体类型和数组类型，并支持递归类型和子类型。

4. **导入段解码:** `DecodeImportSection` 函数处理模块的导入声明，包括导入的函数、表、内存、全局变量和标签。

5. **其他段解码:** 代码中列举了对各种 WebAssembly 标准段（如函数段、表段、内存段、全局段、导出段、起始段、代码段、元素段、数据段）和一些自定义段（如名称段、源映射 URL 段、调试信息段、指令跟踪段、编译提示段、分支提示段、数据计数段、标签段、字符串引用段）的解码逻辑。

6. **错误处理:**  `Decoder` 基类提供的错误处理机制用于在解码过程中发现错误并记录。

7. **特性检测:** 在解码过程中，会检测模块使用的 WebAssembly 特性，并更新 `WasmDetectedFeatures`。

8. **调试支持:**  包含对调试信息段（DWARF）和外部调试信息段的处理。

**关于 .tq 扩展名:**

正如代码所示，`v8/src/wasm/module-decoder-impl.h` 以 `.h` 结尾，因此它是一个 **C++ 头文件**，而不是 V8 Torque 源代码。  如果以 `.tq` 结尾，那才表示它是一个 Torque 文件。

**与 JavaScript 的关系:**

`v8/src/wasm/module-decoder-impl.h` 的功能是 WebAssembly 在 V8 引擎中实现的关键部分。当 JavaScript 代码尝试加载并实例化一个 WebAssembly 模块时，V8 引擎会使用这里的代码来解析模块的二进制数据。

**JavaScript 示例:**

```javascript
// 假设 'module.wasm' 是一个 WebAssembly 模块的二进制文件
fetch('module.wasm')
  .then(response => response.arrayBuffer())
  .then(buffer => WebAssembly.instantiate(buffer))
  .then(result => {
    // result.instance 是 WebAssembly 模块的实例
    const exportedFunction = result.instance.exports.myFunction;
    if (exportedFunction) {
      console.log(exportedFunction(10));
    }
  });
```

在这个例子中，`WebAssembly.instantiate(buffer)` 函数内部会调用 V8 的 WebAssembly 解码器（包括 `ModuleDecoderImpl` 中定义的逻辑）来解析 `buffer` 中的 WebAssembly 字节码，并创建可以在 JavaScript 中调用的模块实例。

**代码逻辑推理 (假设输入与输出):**

**假设输入:** 一个包含以下内容的简化 WebAssembly 模块的字节数组：

```
00 61 73 6d  // Magic number (\0asm)
01 00 00 00  // Version (1)
01           // Type section (ID = 1)
07           // Section length (7 bytes)
01           // Number of type definitions (1)
60           // Function type declaration
01 7f        // One parameter, i32
00           // Zero return values
```

**预期输出 (部分):**  `ModuleDecoderImpl` 解码后，`WasmModule` 对象中关于类型的信息会包含一个函数签名，表示接受一个 `i32` 类型的参数，并且没有返回值。  在 `DecodeTypeSection` 函数执行后，`module_->types` 向量将会包含一个 `FunctionSig` 对象，其参数类型为 `kWasmI32`，返回类型为空。

**用户常见的编程错误 (与 WebAssembly 相关):**

1. **提供的 WebAssembly 模块格式错误:**  例如，魔数或版本号不正确，或者段的结构不符合规范。`ModuleDecoderImpl` 的 `DecodeModuleHeader` 和 `CheckSectionOrder` 等函数会检测这些错误。

   **例子:**  修改上面假设输入中的魔数，例如将 `00 61 73 6d` 改为 `00 00 00 00`。`DecodeModuleHeader` 会检测到魔数不匹配并报错。

2. **尝试导入不存在的函数或变量:**  如果 JavaScript 代码尝试访问 WebAssembly 模块中未导出的函数或变量，这会在模块实例化或调用时引发错误，但 `ModuleDecoderImpl` 主要负责解析阶段，这类错误会在后续的链接或执行阶段体现。

3. **类型不匹配:** 在 JavaScript 和 WebAssembly 之间进行数据交互时，如果类型不匹配（例如，JavaScript 传递了一个字符串给一个需要整数的 WebAssembly 函数），这会导致错误。`ModuleDecoderImpl` 负责解析 WebAssembly 模块的类型信息，确保 V8 能够正确理解模块的接口。

**第 1 部分功能归纳:**

`v8/src/wasm/module-decoder-impl.h` 的第 1 部分定义了 `ModuleDecoderImpl` 类及其辅助结构，负责 WebAssembly 模块的**基本结构解析和头部验证**。它包含了处理模块头部（魔数、版本）和遍历模块段的逻辑，并初步识别各个段的类型。  这为后续各个具体段的详细解码奠定了基础。 这部分还定义了一些辅助函数和宏，用于字符串处理、错误报告和调试追踪等。

### 提示词
```
这是目录为v8/src/wasm/module-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/module-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_MODULE_DECODER_IMPL_H_
#define V8_WASM_MODULE_DECODER_IMPL_H_

#include "src/base/platform/wrappers.h"
#include "src/logging/counters.h"
#include "src/strings/unicode.h"
#include "src/utils/ostreams.h"
#include "src/wasm/canonical-types.h"
#include "src/wasm/constant-expression-interface.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/module-decoder.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-subtyping.h"
#include "src/wasm/well-known-imports.h"

namespace v8::internal::wasm {

#define TRACE(...)                                        \
  do {                                                    \
    if (v8_flags.trace_wasm_decoder) PrintF(__VA_ARGS__); \
  } while (false)

constexpr char kNameString[] = "name";
constexpr char kSourceMappingURLString[] = "sourceMappingURL";
constexpr char kInstTraceString[] = "metadata.code.trace_inst";
constexpr char kCompilationHintsString[] = "compilationHints";
constexpr char kBranchHintsString[] = "metadata.code.branch_hint";
constexpr char kDebugInfoString[] = ".debug_info";
constexpr char kExternalDebugInfoString[] = "external_debug_info";

inline const char* ExternalKindName(ImportExportKindCode kind) {
  switch (kind) {
    case kExternalFunction:
      return "function";
    case kExternalTable:
      return "table";
    case kExternalMemory:
      return "memory";
    case kExternalGlobal:
      return "global";
    case kExternalTag:
      return "tag";
  }
  return "unknown";
}

inline bool validate_utf8(Decoder* decoder, WireBytesRef string) {
  return unibrow::Utf8::ValidateEncoding(
      decoder->start() + decoder->GetBufferRelativeOffset(string.offset()),
      string.length());
}

// Reads a length-prefixed string, checking that it is within bounds. Returns
// the offset of the string, and the length as an out parameter.
inline WireBytesRef consume_string(Decoder* decoder,
                                   unibrow::Utf8Variant grammar,
                                   const char* name, ITracer* tracer) {
  if (tracer) {
    tracer->Description(name);
    tracer->Description(" ");
  }
  uint32_t length = decoder->consume_u32v("length", tracer);
  if (tracer) {
    tracer->Description(": ");
    tracer->Description(length);
    tracer->NextLine();
  }
  uint32_t offset = decoder->pc_offset();
  const uint8_t* string_start = decoder->pc();
  // Consume bytes before validation to guarantee that the string is not oob.
  if (length > 0) {
    if (tracer) {
      tracer->Bytes(decoder->pc(), length);
      tracer->Description(name);
      tracer->Description(": ");
      tracer->Description(reinterpret_cast<const char*>(decoder->pc()), length);
      tracer->NextLine();
    }
    decoder->consume_bytes(length, name);
    if (decoder->ok()) {
      switch (grammar) {
        case unibrow::Utf8Variant::kLossyUtf8:
          break;
        case unibrow::Utf8Variant::kUtf8:
          if (!unibrow::Utf8::ValidateEncoding(string_start, length)) {
            decoder->errorf(string_start, "%s: no valid UTF-8 string", name);
          }
          break;
        case unibrow::Utf8Variant::kWtf8:
          if (!unibrow::Wtf8::ValidateEncoding(string_start, length)) {
            decoder->errorf(string_start, "%s: no valid WTF-8 string", name);
          }
          break;
        case unibrow::Utf8Variant::kUtf8NoTrap:
          UNREACHABLE();
      }
    }
  }
  return {offset, decoder->failed() ? 0 : length};
}

inline WireBytesRef consume_string(Decoder* decoder,
                                   unibrow::Utf8Variant grammar,
                                   const char* name) {
  return consume_string(decoder, grammar, name, ITracer::NoTrace);
}

inline WireBytesRef consume_utf8_string(Decoder* decoder, const char* name,
                                        ITracer* tracer) {
  return consume_string(decoder, unibrow::Utf8Variant::kUtf8, name, tracer);
}

inline SectionCode IdentifyUnknownSectionInternal(Decoder* decoder,
                                                  ITracer* tracer) {
  WireBytesRef string = consume_utf8_string(decoder, "section name", tracer);
  if (decoder->failed()) {
    return kUnknownSectionCode;
  }
  const uint8_t* section_name_start =
      decoder->start() + decoder->GetBufferRelativeOffset(string.offset());

  TRACE("  +%d  section name        : \"%.*s\"\n",
        static_cast<int>(section_name_start - decoder->start()),
        string.length() < 20 ? string.length() : 20, section_name_start);

  using SpecialSectionPair = std::pair<base::Vector<const char>, SectionCode>;
  static constexpr SpecialSectionPair kSpecialSections[]{
      {base::StaticCharVector(kNameString), kNameSectionCode},
      {base::StaticCharVector(kSourceMappingURLString),
       kSourceMappingURLSectionCode},
      {base::StaticCharVector(kInstTraceString), kInstTraceSectionCode},
      {base::StaticCharVector(kCompilationHintsString),
       kCompilationHintsSectionCode},
      {base::StaticCharVector(kBranchHintsString), kBranchHintsSectionCode},
      {base::StaticCharVector(kDebugInfoString), kDebugInfoSectionCode},
      {base::StaticCharVector(kExternalDebugInfoString),
       kExternalDebugInfoSectionCode}};

  auto name_vec = base::Vector<const char>::cast(
      base::VectorOf(section_name_start, string.length()));
  for (auto& special_section : kSpecialSections) {
    if (name_vec == special_section.first) return special_section.second;
  }

  return kUnknownSectionCode;
}

// An iterator over the sections in a wasm binary module.
// Automatically skips all unknown sections.
class WasmSectionIterator {
 public:
  explicit WasmSectionIterator(Decoder* decoder, ITracer* tracer)
      : decoder_(decoder),
        tracer_(tracer),
        section_code_(kUnknownSectionCode),
        section_start_(decoder->pc()),
        section_end_(decoder->pc()) {
    next();
  }

  bool more() const { return decoder_->ok() && decoder_->more(); }

  SectionCode section_code() const { return section_code_; }

  const uint8_t* section_start() const { return section_start_; }

  uint32_t section_length() const {
    return static_cast<uint32_t>(section_end_ - section_start_);
  }

  base::Vector<const uint8_t> payload() const {
    return {payload_start_, payload_length()};
  }

  const uint8_t* payload_start() const { return payload_start_; }

  uint32_t payload_length() const {
    return static_cast<uint32_t>(section_end_ - payload_start_);
  }

  const uint8_t* section_end() const { return section_end_; }

  // Advances to the next section, checking that decoding the current section
  // stopped at {section_end_}.
  void advance(bool move_to_section_end = false) {
    if (move_to_section_end && decoder_->pc() < section_end_) {
      decoder_->consume_bytes(
          static_cast<uint32_t>(section_end_ - decoder_->pc()));
    }
    if (decoder_->pc() != section_end_) {
      const char* msg = decoder_->pc() < section_end_ ? "shorter" : "longer";
      decoder_->errorf(decoder_->pc(),
                       "section was %s than expected size "
                       "(%u bytes expected, %zu decoded)",
                       msg, section_length(),
                       static_cast<size_t>(decoder_->pc() - section_start_));
    }
    next();
  }

 private:
  Decoder* decoder_;
  ITracer* tracer_;
  SectionCode section_code_;
  const uint8_t* section_start_;
  const uint8_t* payload_start_;
  const uint8_t* section_end_;

  // Reads the section code/name at the current position and sets up
  // the embedder fields.
  void next() {
    if (!decoder_->more()) {
      section_code_ = kUnknownSectionCode;
      return;
    }
    section_start_ = decoder_->pc();
    // Empty line before next section.
    if (tracer_) tracer_->NextLine();
    uint8_t section_code = decoder_->consume_u8("section kind", tracer_);
    if (tracer_) {
      tracer_->Description(": ");
      tracer_->Description(SectionName(static_cast<SectionCode>(section_code)));
      tracer_->NextLine();
    }
    // Read and check the section size.
    uint32_t section_length = decoder_->consume_u32v("section length", tracer_);
    if (tracer_) {
      tracer_->Description(section_length);
      tracer_->NextLine();
    }
    payload_start_ = decoder_->pc();
    section_end_ = payload_start_ + section_length;
    if (section_length > decoder_->available_bytes()) {
      decoder_->errorf(
          section_start_,
          "section (code %u, \"%s\") extends past end of the module "
          "(length %u, remaining bytes %u)",
          section_code, SectionName(static_cast<SectionCode>(section_code)),
          section_length, decoder_->available_bytes());
      section_end_ = payload_start_;
    }

    if (section_code == kUnknownSectionCode) {
      // Check for the known "name", "sourceMappingURL", or "compilationHints"
      // section.
      // To identify the unknown section we set the end of the decoder bytes to
      // the end of the custom section, so that we do not read the section name
      // beyond the end of the section.
      const uint8_t* module_end = decoder_->end();
      decoder_->set_end(section_end_);
      section_code = IdentifyUnknownSectionInternal(decoder_, tracer_);
      if (decoder_->ok()) decoder_->set_end(module_end);
      // As a side effect, the above function will forward the decoder to after
      // the identifier string.
      payload_start_ = decoder_->pc();
    } else if (!IsValidSectionCode(section_code)) {
      decoder_->errorf(decoder_->pc(), "unknown section code #0x%02x",
                       section_code);
    }
    section_code_ = decoder_->failed() ? kUnknownSectionCode
                                       : static_cast<SectionCode>(section_code);

    if (section_code_ == kUnknownSectionCode && section_end_ > decoder_->pc()) {
      // Skip to the end of the unknown section.
      uint32_t remaining = static_cast<uint32_t>(section_end_ - decoder_->pc());
      decoder_->consume_bytes(remaining, "section payload", tracer_);
    }
  }
};

inline void DumpModule(const base::Vector<const uint8_t> module_bytes,
                       bool ok) {
  std::string path;
  if (v8_flags.dump_wasm_module_path) {
    path = v8_flags.dump_wasm_module_path;
    if (path.size() && !base::OS::isDirectorySeparator(path[path.size() - 1])) {
      path += base::OS::DirectorySeparator();
    }
  }
  // File are named `<hash>.{ok,failed}.wasm`.
  // Limit the hash to 8 characters (32 bits).
  uint32_t hash = static_cast<uint32_t>(GetWireBytesHash(module_bytes));
  base::EmbeddedVector<char, 32> buf;
  SNPrintF(buf, "%08x.%s.wasm", hash, ok ? "ok" : "failed");
  path += buf.begin();
  size_t rv = 0;
  if (FILE* file = base::OS::FOpen(path.c_str(), "wb")) {
    rv = fwrite(module_bytes.begin(), module_bytes.length(), 1, file);
    base::Fclose(file);
  }
  if (rv != 1) {
    OFStream os(stderr);
    os << "Error while dumping wasm file to " << path << std::endl;
  }
}

// The main logic for decoding the bytes of a module.
class ModuleDecoderImpl : public Decoder {
 public:
  ModuleDecoderImpl(WasmEnabledFeatures enabled_features,
                    base::Vector<const uint8_t> wire_bytes, ModuleOrigin origin,
                    WasmDetectedFeatures* detected_features,
                    ITracer* tracer = ITracer::NoTrace)
      : Decoder(wire_bytes),
        enabled_features_(enabled_features),
        detected_features_(detected_features),
        module_(std::make_shared<WasmModule>(origin)),
        module_start_(wire_bytes.begin()),
        module_end_(wire_bytes.end()),
        tracer_(tracer) {}

  void onFirstError() override {
    pc_ = end_;  // On error, terminate section decoding loop.
  }

  void DecodeModuleHeader(base::Vector<const uint8_t> bytes) {
    if (failed()) return;
    Reset(bytes);

    const uint8_t* pos = pc_;
    uint32_t magic_word = consume_u32("wasm magic", tracer_);
    if (tracer_) tracer_->NextLine();
#define BYTES(x) (x & 0xFF), (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF
    if (magic_word != kWasmMagic) {
      errorf(pos,
             "expected magic word %02x %02x %02x %02x, "
             "found %02x %02x %02x %02x",
             BYTES(kWasmMagic), BYTES(magic_word));
    }

    pos = pc_;
    {
      uint32_t magic_version = consume_u32("wasm version", tracer_);
      if (tracer_) tracer_->NextLine();
      if (magic_version != kWasmVersion) {
        errorf(pos,
               "expected version %02x %02x %02x %02x, "
               "found %02x %02x %02x %02x",
               BYTES(kWasmVersion), BYTES(magic_version));
      }
    }
#undef BYTES
  }

  bool CheckSectionOrder(SectionCode section_code) {
    // Check the order of ordered sections.
    if (section_code >= kFirstSectionInModule &&
        section_code < kFirstUnorderedSection) {
      if (section_code < next_ordered_section_) {
        errorf(pc(), "unexpected section <%s>", SectionName(section_code));
        return false;
      }
      next_ordered_section_ = section_code + 1;
      return true;
    }

    // Ignore ordering problems in unknown / custom sections. Even allow them to
    // appear multiple times. As optional sections we use them on a "best
    // effort" basis.
    if (section_code == kUnknownSectionCode) return true;
    if (section_code > kLastKnownModuleSection) return true;

    // The rest is standardized unordered sections; they are checked more
    // thoroughly..
    DCHECK_LE(kFirstUnorderedSection, section_code);
    DCHECK_GE(kLastKnownModuleSection, section_code);

    // Check that unordered sections don't appear multiple times.
    if (has_seen_unordered_section(section_code)) {
      errorf(pc(), "Multiple %s sections not allowed",
             SectionName(section_code));
      return false;
    }
    set_seen_unordered_section(section_code);

    // Define a helper to ensure that sections <= {before} appear before the
    // current unordered section, and everything >= {after} appears after it.
    auto check_order = [this, section_code](SectionCode before,
                                            SectionCode after) -> bool {
      DCHECK_LT(before, after);
      if (next_ordered_section_ > after) {
        errorf(pc(), "The %s section must appear before the %s section",
               SectionName(section_code), SectionName(after));
        return false;
      }
      if (next_ordered_section_ <= before) next_ordered_section_ = before + 1;
      return true;
    };

    // Now check the ordering constraints of specific unordered sections.
    switch (section_code) {
      case kDataCountSectionCode:
        return check_order(kElementSectionCode, kCodeSectionCode);
      case kTagSectionCode:
        return check_order(kMemorySectionCode, kGlobalSectionCode);
      case kStringRefSectionCode:
        // TODO(12868): If there's a tag section, assert that we're after the
        // tag section.
        return check_order(kMemorySectionCode, kGlobalSectionCode);
      case kInstTraceSectionCode:
        // Custom section following code.metadata tool convention containing
        // offsets specifying where trace marks should be emitted.
        // Be lenient with placement of instruction trace section. All except
        // first occurrence after function section and before code section are
        // ignored.
        return true;
      default:
        return true;
    }
  }

  void DecodeSection(SectionCode section_code,
                     base::Vector<const uint8_t> bytes, uint32_t offset) {
    if (failed()) return;
    Reset(bytes, offset);
    TRACE("Section: %s\n", SectionName(section_code));
    TRACE("Decode Section %p - %p\n", bytes.begin(), bytes.end());

    if (!CheckSectionOrder(section_code)) return;

    switch (section_code) {
      case kUnknownSectionCode:
        break;
      case kTypeSectionCode:
        DecodeTypeSection();
        break;
      case kImportSectionCode:
        DecodeImportSection();
        break;
      case kFunctionSectionCode:
        DecodeFunctionSection();
        break;
      case kTableSectionCode:
        DecodeTableSection();
        break;
      case kMemorySectionCode:
        DecodeMemorySection();
        break;
      case kGlobalSectionCode:
        DecodeGlobalSection();
        break;
      case kExportSectionCode:
        DecodeExportSection();
        break;
      case kStartSectionCode:
        DecodeStartSection();
        break;
      case kCodeSectionCode:
        DecodeCodeSection();
        break;
      case kElementSectionCode:
        DecodeElementSection();
        break;
      case kDataSectionCode:
        DecodeDataSection();
        break;
      case kNameSectionCode:
        DecodeNameSection();
        break;
      case kSourceMappingURLSectionCode:
        DecodeSourceMappingURLSection();
        break;
      case kDebugInfoSectionCode:
        module_->debug_symbols[WasmDebugSymbols::Type::EmbeddedDWARF] = {
            WasmDebugSymbols::Type::EmbeddedDWARF, {}};
        consume_bytes(static_cast<uint32_t>(end_ - start_), ".debug_info");
        break;
      case kExternalDebugInfoSectionCode:
        DecodeExternalDebugInfoSection();
        break;
      case kInstTraceSectionCode:
        if (enabled_features_.has_instruction_tracing()) {
          DecodeInstTraceSection();
        } else {
          // Ignore this section when feature is disabled. It is an optional
          // custom section anyways.
          consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
        }
        break;
      case kCompilationHintsSectionCode:
        // TODO(jkummerow): We're missing tracing support for well-known
        // custom sections. This confuses `wami --full-hexdump` e.g.
        // for the modules created by
        // mjsunit/wasm/compilation-hints-streaming-compilation.js.
        if (enabled_features_.has_compilation_hints()) {
          DecodeCompilationHintsSection();
        } else {
          // Ignore this section when feature was disabled. It is an optional
          // custom section anyways.
          consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
        }
        break;
      case kBranchHintsSectionCode:
        if (enabled_features_.has_branch_hinting()) {
          DecodeBranchHintsSection();
        } else {
          // Ignore this section when feature was disabled. It is an optional
          // custom section anyways.
          consume_bytes(static_cast<uint32_t>(end_ - start_), nullptr);
        }
        break;
      case kDataCountSectionCode:
        DecodeDataCountSection();
        break;
      case kTagSectionCode:
        DecodeTagSection();
        break;
      case kStringRefSectionCode:
        if (enabled_features_.has_stringref()) {
          DecodeStringRefSection();
        } else {
          errorf(pc(),
                 "unexpected section <%s> (enable with "
                 "--experimental-wasm-stringref)",
                 SectionName(section_code));
        }
        break;
      default:
        errorf(pc(), "unexpected section <%s>", SectionName(section_code));
        return;
    }

    if (pc() != bytes.end()) {
      const char* msg = pc() < bytes.end() ? "shorter" : "longer";
      errorf(pc(),
             "section was %s than expected size "
             "(%zu bytes expected, %zu decoded)",
             msg, bytes.size(), static_cast<size_t>(pc() - bytes.begin()));
    }
  }

  static constexpr const char* TypeKindName(uint8_t kind) {
    switch (kind) {
      // clang-format off
      case kWasmFunctionTypeCode:    return "func";
      case kWasmStructTypeCode:      return "struct";
      case kWasmArrayTypeCode:       return "array";
      default:                       return "unknown";
        // clang-format on
    }
  }

  TypeDefinition consume_base_type_definition() {
    const bool is_final = true;
    bool shared = false;
    uint8_t kind = consume_u8(" kind", tracer_);
    if (tracer_) tracer_->Description(": ");
    if (kind == kSharedFlagCode) {
      if (!v8_flags.experimental_wasm_shared) {
        errorf(pc() - 1,
               "unknown type form: %d, enable with --experimental-wasm-shared",
               kind);
        return {};
      }
      shared = true;
      module_->has_shared_part = true;
      kind = consume_u8("shared ", tracer_);
    }
    if (tracer_) tracer_->Description(TypeKindName(kind));
    switch (kind) {
      case kWasmFunctionTypeCode: {
        const FunctionSig* sig = consume_sig(&module_->signature_zone);
        return {sig, kNoSuperType, is_final, shared};
      }
      case kWasmStructTypeCode: {
        module_->is_wasm_gc = true;
        const StructType* type = consume_struct(&module_->signature_zone);
        return {type, kNoSuperType, is_final, shared};
      }
      case kWasmArrayTypeCode: {
        module_->is_wasm_gc = true;
        const ArrayType* type = consume_array(&module_->signature_zone);
        return {type, kNoSuperType, is_final, shared};
      }
      default:
        if (tracer_) tracer_->NextLine();
        errorf(pc() - 1, "unknown type form: %d", kind);
        return {};
    }
  }

  // {current_type_index} is the index of the type that's being decoded.
  // Any supertype must have a lower index.
  TypeDefinition consume_subtype_definition(size_t current_type_index) {
    uint8_t kind = read_u8<Decoder::FullValidationTag>(pc(), "type kind");
    if (kind == kWasmSubtypeCode || kind == kWasmSubtypeFinalCode) {
      module_->is_wasm_gc = true;
      bool is_final = kind == kWasmSubtypeFinalCode;
      consume_bytes(1, is_final ? " subtype final, " : " subtype extensible, ",
                    tracer_);
      constexpr uint32_t kMaximumSupertypes = 1;
      uint32_t supertype_count =
          consume_count("supertype count", kMaximumSupertypes);
      uint32_t supertype = kNoSuperType.index;
      if (supertype_count == 1) {
        supertype = consume_u32v("supertype", tracer_);
        if (supertype >= current_type_index) {
          errorf("type %u: invalid supertype %u", current_type_index,
                 supertype);
          return {};
        }
        if (tracer_) {
          tracer_->Description(supertype);
          tracer_->NextLine();
        }
      }
      TypeDefinition type = consume_base_type_definition();
      type.supertype = ModuleTypeIndex{supertype};
      type.is_final = is_final;
      return type;
    } else {
      return consume_base_type_definition();
    }
  }

  void DecodeTypeSection() {
    TypeCanonicalizer* type_canon = GetTypeCanonicalizer();
    uint32_t types_count = consume_count("types count", kV8MaxWasmTypes);

    for (uint32_t i = 0; ok() && i < types_count; ++i) {
      TRACE("DecodeType[%d] module+%d\n", i, static_cast<int>(pc_ - start_));
      uint8_t kind = read_u8<Decoder::FullValidationTag>(pc(), "type kind");
      size_t initial_size = module_->types.size();
      if (kind == kWasmRecursiveTypeGroupCode) {
        module_->is_wasm_gc = true;
        uint32_t rec_group_offset = pc_offset();
        consume_bytes(1, "rec. group definition", tracer_);
        if (tracer_) tracer_->NextLine();
        uint32_t group_size =
            consume_count("recursive group size", kV8MaxWasmTypes);
        if (tracer_) tracer_->RecGroupOffset(rec_group_offset, group_size);
        if (initial_size + group_size > kV8MaxWasmTypes) {
          errorf(pc(), "Type definition count exceeds maximum %zu",
                 kV8MaxWasmTypes);
          return;
        }
        // We need to resize types before decoding the type definitions in this
        // group, so that the correct type size is visible to type definitions.
        module_->types.resize(initial_size + group_size);
        module_->isorecursive_canonical_type_ids.resize(initial_size +
                                                        group_size);
        for (uint32_t j = 0; j < group_size; j++) {
          if (tracer_) tracer_->TypeOffset(pc_offset());
          TypeDefinition type = consume_subtype_definition(initial_size + j);
          module_->types[initial_size + j] = type;
        }
        if (failed()) return;
        type_canon->AddRecursiveGroup(module_.get(), group_size);
        if (tracer_) {
          tracer_->Description("end of rec. group");
          tracer_->NextLine();
        }
      } else {
        if (tracer_) tracer_->TypeOffset(pc_offset());
        if (initial_size + 1 > kV8MaxWasmTypes) {
          errorf(pc(), "Type definition count exceeds maximum %zu",
                 kV8MaxWasmTypes);
          return;
        }
        // Similarly to above, we need to resize types for a group of size 1.
        module_->types.resize(initial_size + 1);
        module_->isorecursive_canonical_type_ids.resize(initial_size + 1);
        TypeDefinition type = consume_subtype_definition(initial_size);
        if (ok()) {
          module_->types[initial_size] = type;
          type_canon->AddRecursiveSingletonGroup(module_.get());
        }
      }
    }

    // Check validity of explicitly defined supertypes and propagate subtyping
    // depth.
    const WasmModule* module = module_.get();
    for (uint32_t i = 0; ok() && i < module_->types.size(); ++i) {
      ModuleTypeIndex explicit_super = module_->supertype(ModuleTypeIndex{i});
      if (!explicit_super.valid()) continue;
      DCHECK_LT(explicit_super.index, i);  // Checked during decoding.
      uint32_t depth = module->type(explicit_super).subtyping_depth + 1;
      module_->types[i].subtyping_depth = depth;
      DCHECK_GE(depth, 0);
      if (depth > kV8MaxRttSubtypingDepth) {
        errorf("type %u: subtyping depth is greater than allowed", i);
        continue;
      }
      // This check is technically redundant; we include for the improved error
      // message.
      if (module->type(explicit_super).is_final) {
        errorf("type %u extends final type %u", i, explicit_super.index);
        continue;
      }
      if (!ValidSubtypeDefinition(ModuleTypeIndex{i}, explicit_super, module,
                                  module)) {
        errorf("type %u has invalid explicit supertype %u", i,
               explicit_super.index);
        continue;
      }
    }
  }

  void DecodeImportSection() {
    uint32_t import_table_count =
        consume_count("imports count", kV8MaxWasmImports);
    module_->import_table.reserve(import_table_count);
    for (uint32_t i = 0; ok() && i < import_table_count; ++i) {
      TRACE("DecodeImportTable[%d] module+%d\n", i,
            static_cast<int>(pc_ - start_));
      if (tracer_) tracer_->ImportOffset(pc_offset());

      const uint8_t* pos = pc_;
      WireBytesRef module_name =
          consume_utf8_string(this, "module name", tracer_);
      WireBytesRef field_name =
          consume_utf8_string(this, "field name", tracer_);
      ImportExportKindCode kind =
          static_cast<ImportExportKindCode>(consume_u8("kind", tracer_));
      if (tracer_) {
        tracer_->Description(": ");
        tracer_->Description(ExternalKindName(kind));
      }
      module_->import_table.push_back(WasmImport{
          .module_name = module_name, .field_name = field_name, .kind = kind});
      WasmImport* import = &module_->import_table.back();
      switch (kind) {
        case kExternalFunction: {
          // ===== Imported function ===========================================
          import->index = static_cast<uint32_t>(module_->functions.size());
          module_->num_imported_functions++;
          module_->functions.push_back(WasmFunction{
              .func_index = import->index,
              .imported = true,
          });
          WasmFunction* function = &module_->functions.back();
          function->sig_index =
              consume_sig_index(module_.get(), &function->sig);
          break;
        }
        case kExternalTable: {
          // ===== Imported table ==============================================
          import->index = static_cast<uint32_t>(module_->tables.size());
          const uint8_t* type_position = pc();
          ValueType type = consume_value_type();
          if (!type.is_object_reference()) {
            errorf(type_position, "Invalid table type %s", type.name().c_str());
            break;
          }
          module_->num_imported_tables++;
          module_->tables.push_back(WasmTable{
              .type = type,
              .imported = true,
          });
          WasmTable* table = &module_->tables.back();
          consume_table_flags(table);
          if (table->shared) module_->has_shared_part = true;
          // Note that we should not throw an error if the declared maximum size
          // is oob. We will instead fail when growing at runtime.
          uint64_t kNoMaximum = kMaxUInt64;
          consume_resizable_limits(
              "table", "elements", v8_flags.wasm_max_table_size,
              &table->initial_size, table->has_maximum_size, kNoMaximum,
              &table->maximum_size,
              table->is_table64() ? k64BitLimits : k32BitLimits);
          break;
        }
        case kExternalMemory: {
          // ===== Imported memory =============================================
          static_assert(kV8MaxWasmMemories <= kMaxUInt32);
          if (module_->memories.size() >= kV8MaxWasmMemories - 1) {
            errorf("At most %u imported memories are supported",
                   kV8MaxWasmMemories);
            break;
          }
          uint32_t mem_index = static_cast<uint32_t>(module_->memories.size());
          import->index = mem_index;
          module_->memories.emplace_back();
          WasmMemory* external_memory = &module_->memories.back();
          external_memory->imported = true;
          external_memory->index = mem_index;

          consume_memory_flags(external_memory);
          uint32_t max_pages = external_memory->is_memory64()
                                   ? kSpecMaxMemory64Pages
                                   : kSpecMaxMemory32Pages;
          consume_resizable_limits(
              "memory", "pages", max_pages, &external_memory->initial_pages,
              external_memory->has_maximum_pages, max_pages,
              &external_memory->maximum_pages,
              external_memory->is_memory64() ? k64BitLimits : k32BitLimits);
          break;
        }
        case kExternalGlobal: {
          // ===== Imported global =============================================
          import->index = static_cast<uint32_t>(module_->globals.size());
          ValueType type = consume_value_type();
          auto [mutability, shared] = consume_global_flags();
          if (V8_UNLIKELY(failed())) break;
          if (V8_UNLIKELY(shared && !IsShared(type, module_.get()))) {
            error("shared imported global must have shared type");
            break;
          }
          module_->globals.push_back(
              WasmGlobal{.type = type,
                         .mutability = mutability,
                         .index = 0,  // set later in CalculateGlobalOffsets
                         .shared = shared,
                         .imported = true});
          module_->num_imported_globals++;
          DCHECK_EQ(module_->globals.size(), module_->num_imported_globals);
          if (shared) module_->has_shared_part = true;
          if (mutability) module_->num_imported_mutable_globals++;
          if (tracer_) tracer_->NextLine();
          break;
        }
        case kExternalTag: {
          // ===== Imported tag ================================================
          import->index = static_cast<uint32_t>(module_->tags.size());
          module_->num_imported_tags++;
          const WasmTagSig* tag_sig = nullptr;
          consume_exception_attribute();  // Attribute ignored for now.
          ModuleTypeIndex sig_index =
              consume_tag_sig_index(module_.get(), &tag_sig);
          module_->tags.emplace_back(tag_sig, sig_index);
          break;
        }
        default:
          errorf(pos, "unknown import kind 0x%02x", kind);
          break;
      }
    }
    if (module_->memories.size() > 1) detected_features_->add_multi_memory();
    UpdateComputedMemoryInformation();
    module_->type_feedback.well_known_imports.Initialize(
        module_->num_imported_functions);
    if (tracer_) tracer_->ImportsDone(module_.get());
  }

  void DecodeFunctionSection() {
    uint32_t functions_count =
        consume_coun
```