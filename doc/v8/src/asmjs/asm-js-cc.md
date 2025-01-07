Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Request:** The initial request asks for the functionality of `v8/src/asmjs/asm-js.cc`, whether it's Torque, its relation to JavaScript (with examples), code logic inferences (with inputs and outputs), and common programming errors it addresses.

2. **Initial Scan for Keywords and Structure:**  A quick scan reveals keywords like `asmjs`, `wasm`, `JavaScript`, `Compile`, `Instantiate`, `Stdlib`, `ArrayBuffer`, and `#include`. The file structure indicates it's a C++ source file within the V8 project. The presence of `#include "src/asmjs/asm-js.h"` suggests this is the implementation file for a header file. The namespace `v8::internal` confirms it's internal V8 code.

3. **Determining File Type:** The request specifically asks about `.tq`. Since the file ends in `.cc`, it's a standard C++ source file, not a Torque file. This is a direct, factual observation.

4. **Identifying Core Functionality - Compile and Instantiate:** The names `CompileAsmViaWasm` (although commented out but its components are present) and `InstantiateAsmWasm` immediately stand out. These strongly suggest the file is involved in taking asm.js code and making it runnable. The presence of `AsmJsCompilationJob` reinforces the "compilation" aspect.

5. **Tracing the Compilation Process (AsmJsCompilationJob):**
    * **`ExecuteJobImpl`:**  This method name suggests the core of the compilation logic. Looking inside, we see `wasm::AsmJsParser`. This indicates the code parses asm.js. The parser's output is used to build a WebAssembly module (`parser.module_builder()->WriteTo(module_)`). This is a crucial piece of information: **asm.js is being translated to WebAssembly within V8.** The reporting of compilation success and failure reinforces this.
    * **`FinalizeJobImpl`:** This step receives the translated WebAssembly module. It calls `wasm::GetWasmEngine()->SyncCompileTranslatedAsmJs`. This confirms the use of the WebAssembly engine for the final compilation stage. The timing metrics further support the idea of distinct compilation phases.

6. **Tracing the Instantiation Process (`InstantiateAsmWasm`):**
    * This function takes `wasm_data`, `stdlib`, `foreign`, and `memory` as arguments. These names hint at the required components for running asm.js.
    * The code checks the validity of the `stdlib` (standard library) and the `memory` (heap buffer). It specifically looks for `Infinity`, `NaN`, math functions, and typed array constructors within the `stdlib`. It enforces constraints on the `memory` (must be `ArrayBuffer`, not `SharedArrayBuffer` or `WebAssembly.Memory`, and specific size restrictions).
    * It calls `wasm_engine->FinalizeTranslatedAsmJs` (likely to create a `WasmModuleObject`) and then `wasm_engine->SyncInstantiate`. This confirms that the instantiation process also leverages the WebAssembly engine.
    * The code checks for a special export named `__single_function__`. This suggests a possible optimization or specific use case.

7. **Connecting to JavaScript (with Examples):**  The core relationship is that asm.js is a *subset* of JavaScript designed for performance. The file demonstrates this by *compiling* asm.js code that is syntactically valid JavaScript, but with strict rules.

    * **Compilation Example:** Show how an asm.js module is defined in JavaScript.
    * **Instantiation Example:** Demonstrate how `stdlib`, `foreign`, and `memory` are passed when calling the asm.js module's factory function. Highlight the typed array constructors in `stdlib` and the creation of the `ArrayBuffer`.

8. **Code Logic Inference (with Inputs/Outputs):** Choose a specific, relatively simple scenario to illustrate the logic. The `AreStdlibMembersValid` function is a good candidate.

    * **Input:** A `stdlib` object (e.g., `global`), a set of `members` to check (e.g., `Math.sin`, `Infinity`), and an initial value for `is_typed_array`.
    * **Logic:**  The function iterates through the required members, checks if they exist in `stdlib`, and verifies their types or values.
    * **Output:**  `true` if all required members are valid, `false` otherwise. The `is_typed_array` flag might be set to `true`.

9. **Common Programming Errors:**  Focus on the constraints enforced by the code, especially during instantiation.

    * **Invalid `stdlib`:** Missing or incorrect members.
    * **Incorrect `memory` type:**  Using `SharedArrayBuffer` or `WebAssembly.Memory`.
    * **Invalid `memory` size:** Not meeting the power-of-two or multiple-of-2^24 requirements.
    * **Instantiating as a generator/async function:** This is a restriction imposed by the asm.js design.

10. **Review and Refine:**  Go back through the analysis, ensuring clarity, accuracy, and completeness. Double-check the code snippets for correctness. Make sure the JavaScript examples directly relate to the C++ code's functionality. For instance, the `STDLIB_MATH_FUNC` macro directly correlates to checking for `Math.sin`, `Math.cos`, etc. in the JavaScript `stdlib`.

This structured approach helps in systematically understanding the purpose and functionality of a complex piece of code by breaking it down into smaller, more manageable parts. The key is to identify the core responsibilities and then delve into the details of how those responsibilities are implemented.
`v8/src/asmjs/asm-js.cc` 是 V8 引擎中处理 asm.js 代码的关键组件。它的主要功能是将符合 asm.js 规范的 JavaScript 代码编译并实例化为高效的 WebAssembly 模块。

以下是该文件的主要功能列表：

1. **asm.js 到 WebAssembly 的转换 (Compilation):**
   - 该文件包含将 asm.js 代码解析并转换为等效 WebAssembly 字节码的逻辑。 这通过 `AsmJsCompilationJob` 类实现。
   - 它使用 `wasm::AsmJsParser` 来解析 asm.js 代码，并验证其是否符合规范。
   - 转换后的 WebAssembly 模块被存储在 `wasm::ZoneBuffer` 中。
   - 它还生成一个包含 asm.js 偏移量信息的表 (`asm_offsets_`)。
   - 该过程会记录编译时间，并可以在控制台中输出编译成功或失败的消息（通过 `ReportCompilationSuccess` 和 `ReportCompilationFailure` 函数）。

2. **asm.js 模块的实例化 (Instantiation):**
   - `InstantiateAsmWasm` 函数负责将编译后的 WebAssembly 模块实例化为可执行的 V8 对象。
   - 它接收以下参数：
     - `shared`: 指向表示 asm.js 函数的 `SharedFunctionInfo` 的句柄。
     - `wasm_data`: 包含编译后的 WebAssembly 模块和相关数据的 `AsmWasmData` 对象。
     - `stdlib`: 代表标准库的对象，asm.js 模块可能依赖于此库中的函数和值（例如 `Math.sin`）。
     - `foreign`: 代表外部导入的对象，asm.js 模块可能需要调用外部 JavaScript 函数。
     - `memory`:  如果 asm.js 模块使用了堆内存，则此参数是 `ArrayBuffer` 对象的句柄。
   - 它会验证提供的 `stdlib` 是否包含了 asm.js 模块所期望的成员（通过 `AreStdlibMembersValid` 函数）。
   - 它会验证提供的 `memory` 对象是否符合 asm.js 的规范（例如，必须是 `ArrayBuffer`，大小符合要求）。
   - 它调用 WebAssembly 引擎的 `SyncInstantiate` 方法来创建 `WasmInstanceObject`。
   - 实例化的过程会记录实例化时间，并可以在控制台中输出实例化成功或失败的消息（通过 `ReportInstantiationSuccess` 和 `ReportInstantiationFailure` 函数）。
   - 如果 asm.js 模块定义了一个名为 `__single_function__` 的导出，则返回该导出的函数；否则，返回模块的 exports 对象。

3. **标准库验证 (`AreStdlibMembersValid`):**
   - 此函数检查传递给 asm.js 模块实例化的 `stdlib` 对象是否包含了正确的成员（例如 `Infinity`, `NaN`, `Math.sin`, `Int8Array` 等），并且这些成员的属性是否符合预期 (例如 `Math.sin` 必须是内置的 `Math.sin` 函数)。

4. **错误报告:**
   - 该文件包含用于报告编译和实例化过程中遇到的错误和警告的函数 (`Report`, `ReportCompilationFailure`, `ReportInstantiationFailure`)。

5. **统计信息记录:**
   - `RecordHistograms` 函数用于记录编译后的 asm.js 模块的大小。

**关于文件扩展名 `.tq`:**

`v8/src/asmjs/asm-js.cc` **不是**以 `.tq` 结尾。 因此，它不是一个 V8 Torque 源代码文件。 Torque 文件通常用于定义 V8 内部的运行时函数和类型。

**与 JavaScript 功能的关系 (带示例):**

asm.js 本身是 JavaScript 的一个严格子集，旨在可以被优化成高性能的机器码。 `asm-js.cc` 的主要作用就是桥接这个过程，将这种特殊的 JavaScript 代码转换为更底层的 WebAssembly。

**JavaScript 示例：**

假设有以下 asm.js 代码：

```javascript
function MyAsmModule(stdlib, foreign, heap) {
  "use asm";

  var HEAP8 = new stdlib.Int8Array(heap);
  var sin = stdlib.Math.sin;

  function multiply(x, y) {
    x = x | 0;
    y = y | 0;
    return (x * y) | 0;
  }

  function computeSin(angle) {
    angle = +angle; // 转换为 double
    return +sin(angle);
  }

  return {
    multiply: multiply,
    computeSin: computeSin
  };
}
```

在 V8 中，当这段代码被执行时，`asm-js.cc` 中的逻辑会被触发：

1. **编译:** `AsmJsCompilationJob` 会解析这段代码，验证其符合 asm.js 规范，并将其转换为 WebAssembly 字节码。
2. **实例化:**  通常会通过以下方式调用生成的模块：

```javascript
const stdlib = {
  Math: Math,
  Infinity: Infinity,
  NaN: NaN,
  Int8Array: Int8Array,
  // ... 其他可能用到的标准库成员
};

const foreign = {
  // 如果模块需要外部函数，可以在这里提供
};

const heapBuffer = new ArrayBuffer(256); // 提供堆内存

const asmModuleInstance = MyAsmModule(stdlib, foreign, heapBuffer);

const result = asmModuleInstance.multiply(5, 10);
const sinValue = asmModuleInstance.computeSin(Math.PI / 2);

console.log(result);      // 输出 50
console.log(sinValue);   // 输出接近 1
```

在这个例子中：

- `stdlib` 对象提供了 asm.js 模块所需的标准库函数和类型，例如 `Math.sin` 和 `Int8Array`。`asm-js.cc` 中的 `AreStdlibMembersValid` 函数会验证 `stdlib` 对象是否正确。
- `heapBuffer` 提供了 asm.js 模块可以使用的堆内存。 `asm-js.cc` 中的 `InstantiateAsmWasm` 函数会验证 `heapBuffer` 的类型和大小。
- `asmModuleInstance` 是 `InstantiateAsmWasm` 函数返回的实例化后的模块对象，我们可以调用其导出的函数 `multiply` 和 `computeSin`。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- 一个表示 asm.js 模块的 JavaScript 字符串。
- 一个包含 `Math.sin` 函数的 `stdlib` 对象。

**`AsmJsCompilationJob::ExecuteJobImpl` 阶段:**

- **输入:**  JavaScript 字符串被解析器接收。
- **处理:** `wasm::AsmJsParser` 会识别 `stdlib.Math.sin` 的使用。
- **输出:**  生成的 WebAssembly 模块会包含调用 `Math.sin` 的指令，并且 `stdlib_uses_` 成员变量会记录使用了 `Math.sin`。

**`AsmJs::InstantiateAsmWasm` 阶段:**

- **输入:**  编译后的 WebAssembly 模块数据，包含 `Math.sin` 的 `stdlib` 对象。
- **处理:** `AreStdlibMembersValid` 函数会被调用，它会检查 `stdlib` 对象是否拥有一个名为 `sin` 的属性，并且该属性是一个内置的 Math.sin 函数。
- **输出:** 如果 `stdlib` 正确提供了 `Math.sin`，则实例化成功，返回模块实例。否则，实例化失败，并报告错误。

**用户常见的编程错误 (举例说明):**

1. **`stdlib` 配置错误:**
   ```javascript
   const badStdlib = {
     Math: { cos: Math.cos }, // 缺少 sin
   };
   // 实例化会失败，因为 asm.js 模块期望 stdlib.Math.sin
   const asmModuleInstance = MyAsmModule(badStdlib, foreign, heapBuffer);
   ```
   `asm-js.cc` 会检测到 `stdlib` 中缺少 `sin` 属性，并通过 `ReportInstantiationFailure` 报告错误。

2. **错误的堆内存类型:**
   ```javascript
   const sharedHeap = new SharedArrayBuffer(256); // 错误的类型
   // 实例化会失败，因为 asm.js 需要 ArrayBuffer
   const asmModuleInstance = MyAsmModule(stdlib, foreign, sharedHeap);
   ```
   `InstantiateAsmWasm` 会检查 `memory` 的类型，发现是 `SharedArrayBuffer`，并通过 `ReportInstantiationFailure` 报告错误，指出堆类型无效。

3. **堆内存大小不符合规范:**
   ```javascript
   const smallHeap = new ArrayBuffer(10); // 小于 asm.js 要求的最小尺寸
   // 实例化会失败，因为堆大小无效
   const asmModuleInstance = MyAsmModule(stdlib, foreign, smallHeap);
   ```
   `IsValidAsmjsMemorySize` 函数会检查堆内存的大小，如果小于最小值（通常是 2 的 12 次方），则 `InstantiateAsmWasm` 会报告堆大小无效的错误.

4. **尝试将 asm.js 模块实例化为生成器或异步函数:**
   asm.js 模块不能被当作生成器或异步函数实例化。如果尝试这样做，`InstantiateAsmWasm` 会检查 `shared->scope_info()->function_kind()`，如果发现是可恢复的函数类型，则会调用 `ReportInstantiationFailure` 报告错误。

总而言之，`v8/src/asmjs/asm-js.cc` 是 V8 引擎中实现 asm.js 支持的核心，它负责将这种高性能 JavaScript 子集编译成 WebAssembly 并进行实例化，同时确保了与 JavaScript 环境的正确交互和对用户错误的有效处理。

Prompt: 
```
这是目录为v8/src/asmjs/asm-js.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/asmjs/asm-js.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/asmjs/asm-js.h"

#include <optional>

#include "src/asmjs/asm-names.h"
#include "src/asmjs/asm-parser.h"
#include "src/ast/ast.h"
#include "src/base/platform/elapsed-timer.h"
#include "src/base/vector.h"
#include "src/codegen/compiler.h"
#include "src/codegen/unoptimized-compilation-info.h"
#include "src/common/assert-scope.h"
#include "src/common/message-template.h"
#include "src/execution/execution.h"
#include "src/execution/isolate.h"
#include "src/handles/handles.h"
#include "src/heap/factory.h"
#include "src/logging/counters.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/scanner-character-streams.h"
#include "src/parsing/scanner.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-js.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-result.h"

namespace v8 {
namespace internal {

const char* const AsmJs::kSingleFunctionName = "__single_function__";

namespace {

Handle<Object> StdlibMathMember(Isolate* isolate, Handle<JSReceiver> stdlib,
                                Handle<Name> name) {
  Handle<Name> math_name(
      isolate->factory()->InternalizeString(base::StaticCharVector("Math")));
  Handle<Object> math = JSReceiver::GetDataProperty(isolate, stdlib, math_name);
  if (!IsJSReceiver(*math)) return isolate->factory()->undefined_value();
  Handle<JSReceiver> math_receiver = Cast<JSReceiver>(math);
  Handle<Object> value =
      JSReceiver::GetDataProperty(isolate, math_receiver, name);
  return value;
}

bool AreStdlibMembersValid(Isolate* isolate, Handle<JSReceiver> stdlib,
                           wasm::AsmJsParser::StdlibSet members,
                           bool* is_typed_array) {
  if (members.contains(wasm::AsmJsParser::StandardMember::kInfinity)) {
    members.Remove(wasm::AsmJsParser::StandardMember::kInfinity);
    Handle<Name> name = isolate->factory()->Infinity_string();
    DirectHandle<Object> value =
        JSReceiver::GetDataProperty(isolate, stdlib, name);
    if (!IsNumber(*value) || !std::isinf(Object::NumberValue(*value)))
      return false;
  }
  if (members.contains(wasm::AsmJsParser::StandardMember::kNaN)) {
    members.Remove(wasm::AsmJsParser::StandardMember::kNaN);
    Handle<Name> name = isolate->factory()->NaN_string();
    DirectHandle<Object> value =
        JSReceiver::GetDataProperty(isolate, stdlib, name);
    if (!IsNaN(*value)) return false;
  }
#define STDLIB_MATH_FUNC(fname, FName, ignore1, ignore2)                   \
  if (members.contains(wasm::AsmJsParser::StandardMember::kMath##FName)) { \
    members.Remove(wasm::AsmJsParser::StandardMember::kMath##FName);       \
    Handle<Name> name(isolate->factory()->InternalizeString(               \
        base::StaticCharVector(#fname)));                                  \
    Handle<Object> value = StdlibMathMember(isolate, stdlib, name);        \
    if (!IsJSFunction(*value)) return false;                               \
    Tagged<SharedFunctionInfo> shared = Cast<JSFunction>(value)->shared(); \
    if (!shared->HasBuiltinId() ||                                         \
        shared->builtin_id() != Builtin::kMath##FName) {                   \
      return false;                                                        \
    }                                                                      \
    DCHECK_EQ(shared->GetCode(isolate),                                    \
              isolate->builtins()->code(Builtin::kMath##FName));           \
  }
  STDLIB_MATH_FUNCTION_LIST(STDLIB_MATH_FUNC)
#undef STDLIB_MATH_FUNC
#define STDLIB_MATH_CONST(cname, const_value)                              \
  if (members.contains(wasm::AsmJsParser::StandardMember::kMath##cname)) { \
    members.Remove(wasm::AsmJsParser::StandardMember::kMath##cname);       \
    Handle<Name> name(isolate->factory()->InternalizeString(               \
        base::StaticCharVector(#cname)));                                  \
    DirectHandle<Object> value = StdlibMathMember(isolate, stdlib, name);  \
    if (!IsNumber(*value) || Object::NumberValue(*value) != const_value)   \
      return false;                                                        \
  }
  STDLIB_MATH_VALUE_LIST(STDLIB_MATH_CONST)
#undef STDLIB_MATH_CONST
#define STDLIB_ARRAY_TYPE(fname, FName)                                        \
  if (members.contains(wasm::AsmJsParser::StandardMember::k##FName)) {         \
    members.Remove(wasm::AsmJsParser::StandardMember::k##FName);               \
    *is_typed_array = true;                                                    \
    Handle<Name> name(isolate->factory()->InternalizeString(                   \
        base::StaticCharVector(#FName)));                                      \
    Handle<Object> value = JSReceiver::GetDataProperty(isolate, stdlib, name); \
    if (!IsJSFunction(*value)) return false;                                   \
    Handle<JSFunction> func = Cast<JSFunction>(value);                         \
    if (!func.is_identical_to(isolate->fname())) return false;                 \
  }
  STDLIB_ARRAY_TYPE(int8_array_fun, Int8Array)
  STDLIB_ARRAY_TYPE(uint8_array_fun, Uint8Array)
  STDLIB_ARRAY_TYPE(int16_array_fun, Int16Array)
  STDLIB_ARRAY_TYPE(uint16_array_fun, Uint16Array)
  STDLIB_ARRAY_TYPE(int32_array_fun, Int32Array)
  STDLIB_ARRAY_TYPE(uint32_array_fun, Uint32Array)
  STDLIB_ARRAY_TYPE(float32_array_fun, Float32Array)
  STDLIB_ARRAY_TYPE(float64_array_fun, Float64Array)
#undef STDLIB_ARRAY_TYPE
  // All members accounted for.
  DCHECK(members.empty());
  return true;
}

void Report(Handle<Script> script, int position, base::Vector<const char> text,
            MessageTemplate message_template,
            v8::Isolate::MessageErrorLevel level) {
  Isolate* isolate = script->GetIsolate();
  MessageLocation location(script, position, position);
  DirectHandle<String> text_object =
      isolate->factory()->InternalizeUtf8String(text);
  DirectHandle<JSMessageObject> message = MessageHandler::MakeMessageObject(
      isolate, message_template, &location, text_object);
  message->set_error_level(level);
  MessageHandler::ReportMessage(isolate, &location, message);
}

// Hook to report successful execution of {AsmJs::CompileAsmViaWasm} phase.
void ReportCompilationSuccess(Handle<Script> script, int position,
                              double compile_time, size_t module_size) {
  if (v8_flags.suppress_asm_messages || !v8_flags.trace_asm_time) return;
  base::EmbeddedVector<char, 100> text;
  int length = SNPrintF(text, "success, compile time %0.3f ms, %zu bytes",
                        compile_time, module_size);
  CHECK_NE(-1, length);
  text.Truncate(length);
  Report(script, position, text, MessageTemplate::kAsmJsCompiled,
         v8::Isolate::kMessageInfo);
}

// Hook to report failed execution of {AsmJs::CompileAsmViaWasm} phase.
void ReportCompilationFailure(ParseInfo* parse_info, int position,
                              const char* reason) {
  if (v8_flags.suppress_asm_messages) return;
  parse_info->pending_error_handler()->ReportWarningAt(
      position, position, MessageTemplate::kAsmJsInvalid, reason);
}

// Hook to report successful execution of {AsmJs::InstantiateAsmWasm} phase.
void ReportInstantiationSuccess(Handle<Script> script, int position,
                                double instantiate_time) {
  if (v8_flags.suppress_asm_messages || !v8_flags.trace_asm_time) return;
  base::EmbeddedVector<char, 50> text;
  int length = SNPrintF(text, "success, %0.3f ms", instantiate_time);
  CHECK_NE(-1, length);
  text.Truncate(length);
  Report(script, position, text, MessageTemplate::kAsmJsInstantiated,
         v8::Isolate::kMessageInfo);
}

// Hook to report failed execution of {AsmJs::InstantiateAsmWasm} phase.
void ReportInstantiationFailure(Handle<Script> script, int position,
                                const char* reason) {
  if (v8_flags.suppress_asm_messages) return;
  base::Vector<const char> text = base::CStrVector(reason);
  Report(script, position, text, MessageTemplate::kAsmJsLinkingFailed,
         v8::Isolate::kMessageWarning);
}

}  // namespace

// The compilation of asm.js modules is split into two distinct steps:
//  [1] ExecuteJobImpl: The asm.js module source is parsed, validated, and
//      translated to a valid WebAssembly module. The result are two vectors
//      representing the encoded module as well as encoded source position
//      information and a StdlibSet bit set.
//  [2] FinalizeJobImpl: The module is handed to WebAssembly which decodes it
//      into an internal representation and eventually compiles it to machine
//      code.
class AsmJsCompilationJob final : public UnoptimizedCompilationJob {
 public:
  explicit AsmJsCompilationJob(ParseInfo* parse_info, FunctionLiteral* literal,
                               AccountingAllocator* allocator)
      : UnoptimizedCompilationJob(parse_info->stack_limit(), parse_info,
                                  &compilation_info_),
        allocator_(allocator),
        zone_(allocator, ZONE_NAME),
        compilation_info_(&zone_, parse_info, literal),
        module_(nullptr),
        asm_offsets_(nullptr),
        compile_time_(0),
        module_source_size_(0) {}

  AsmJsCompilationJob(const AsmJsCompilationJob&) = delete;
  AsmJsCompilationJob& operator=(const AsmJsCompilationJob&) = delete;

 protected:
  Status ExecuteJobImpl() final;
  Status FinalizeJobImpl(Handle<SharedFunctionInfo> shared_info,
                         Isolate* isolate) final;
  Status FinalizeJobImpl(Handle<SharedFunctionInfo> shared_info,
                         LocalIsolate* isolate) final {
    return CompilationJob::RETRY_ON_MAIN_THREAD;
  }

 private:
  void RecordHistograms(Isolate* isolate);

  AccountingAllocator* allocator_;
  Zone zone_;
  UnoptimizedCompilationInfo compilation_info_;
  wasm::ZoneBuffer* module_;
  wasm::ZoneBuffer* asm_offsets_;
  wasm::AsmJsParser::StdlibSet stdlib_uses_;

  double compile_time_;     // Time (milliseconds) taken to execute step [2].
  int module_source_size_;  // Module source size in bytes.
};

UnoptimizedCompilationJob::Status AsmJsCompilationJob::ExecuteJobImpl() {
  DisallowHeapAccess no_heap_access;

  // Step 1: Translate asm.js module to WebAssembly module.
  Zone* compile_zone = &zone_;
  Zone translate_zone(allocator_, ZONE_NAME);

  Utf16CharacterStream* stream = parse_info()->character_stream();
  std::optional<AllowHandleDereference> allow_deref;
  if (stream->can_access_heap()) {
    allow_deref.emplace();
  }
  stream->Seek(compilation_info()->literal()->start_position());
  wasm::AsmJsParser parser(&translate_zone, stack_limit(), stream);
  if (!parser.Run()) {
    if (!v8_flags.suppress_asm_messages) {
      ReportCompilationFailure(parse_info(), parser.failure_location(),
                               parser.failure_message());
    }
    return FAILED;
  }
  module_ = compile_zone->New<wasm::ZoneBuffer>(compile_zone);
  parser.module_builder()->WriteTo(module_);
  if (module_->size() > v8_flags.wasm_max_module_size) {
    if (!v8_flags.suppress_asm_messages) {
      ReportCompilationFailure(
          parse_info(), parser.failure_location(),
          "Module size exceeds engine's supported maximum");
    }
    return FAILED;
  }
  asm_offsets_ = compile_zone->New<wasm::ZoneBuffer>(compile_zone);
  parser.module_builder()->WriteAsmJsOffsetTable(asm_offsets_);
  stdlib_uses_ = *parser.stdlib_uses();

  module_source_size_ = compilation_info()->literal()->end_position() -
                        compilation_info()->literal()->start_position();
  return SUCCEEDED;
}

UnoptimizedCompilationJob::Status AsmJsCompilationJob::FinalizeJobImpl(
    Handle<SharedFunctionInfo> shared_info, Isolate* isolate) {
  // Step 2: Compile and decode the WebAssembly module.
  base::ElapsedTimer compile_timer;
  compile_timer.Start();

  DirectHandle<HeapNumber> uses_bitset =
      isolate->factory()->NewHeapNumberFromBits(stdlib_uses_.ToIntegral());

  // The result is a compiled module and serialized standard library uses.
  wasm::ErrorThrower thrower(isolate, "AsmJs::Compile");
  Handle<Script> script(Cast<Script>(shared_info->script()), isolate);
  Handle<AsmWasmData> result =
      wasm::GetWasmEngine()
          ->SyncCompileTranslatedAsmJs(
              isolate, &thrower,
              wasm::ModuleWireBytes(module_->begin(), module_->end()), script,
              base::VectorOf(*asm_offsets_), uses_bitset,
              shared_info->language_mode())
          .ToHandleChecked();
  DCHECK(!thrower.error());
  compile_time_ = compile_timer.Elapsed().InMillisecondsF();

  compilation_info()->SetAsmWasmData(result);

  RecordHistograms(isolate);
  ReportCompilationSuccess(script, shared_info->StartPosition(), compile_time_,
                           module_->size());
  return SUCCEEDED;
}

void AsmJsCompilationJob::RecordHistograms(Isolate* isolate) {
  isolate->counters()->asm_module_size_bytes()->AddSample(module_source_size_);
}

std::unique_ptr<UnoptimizedCompilationJob> AsmJs::NewCompilationJob(
    ParseInfo* parse_info, FunctionLiteral* literal,
    AccountingAllocator* allocator) {
  return std::make_unique<AsmJsCompilationJob>(parse_info, literal, allocator);
}

namespace {
inline bool IsValidAsmjsMemorySize(size_t size) {
  // Enforce asm.js spec minimum size.
  if (size < (1u << 12u)) return false;
  // Enforce engine-limited and flag-limited maximum allocation size.
  if (size > wasm::max_mem32_bytes()) return false;
  // Enforce power-of-2 sizes for 2^12 - 2^24.
  if (size < (1u << 24u)) {
    uint32_t size32 = static_cast<uint32_t>(size);
    return base::bits::IsPowerOfTwo(size32);
  }
  // Enforce multiple of 2^24 for sizes >= 2^24
  if ((size % (1u << 24u)) != 0) return false;
  // Limitation of our implementation: for performance reasons, we use unsigned
  // uint32-to-uintptr extensions for memory addresses, which would give
  // incorrect behavior for memories larger than 2 GiB.
  // Note that this does not affect Chrome, which does not allow allocating
  // larger ArrayBuffers anyway.
  if (size > 0x8000'0000u) return false;
  // All checks passed!
  return true;
}
}  // namespace

MaybeHandle<Object> AsmJs::InstantiateAsmWasm(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared,
    DirectHandle<AsmWasmData> wasm_data, Handle<JSReceiver> stdlib,
    Handle<JSReceiver> foreign, Handle<JSArrayBuffer> memory) {
  base::ElapsedTimer instantiate_timer;
  instantiate_timer.Start();
  DirectHandle<HeapNumber> uses_bitset(wasm_data->uses_bitset(), isolate);
  Handle<Script> script(Cast<Script>(shared->script()), isolate);
  auto* wasm_engine = wasm::GetWasmEngine();

  // Allocate the WasmModuleObject.
  Handle<WasmModuleObject> module =
      wasm_engine->FinalizeTranslatedAsmJs(isolate, wasm_data, script);

  // TODO(asmjs): The position currently points to the module definition
  // but should instead point to the instantiation site (more intuitive).
  int position = shared->StartPosition();

  // Check that the module is not instantiated as a generator or async function.
  if (IsResumableFunction(shared->scope_info()->function_kind())) {
    ReportInstantiationFailure(script, position,
                               "Cannot be instantiated as resumable function");
    return MaybeHandle<Object>();
  }

  // Check that all used stdlib members are valid.
  bool stdlib_use_of_typed_array_present = false;
  wasm::AsmJsParser::StdlibSet stdlib_uses =
      wasm::AsmJsParser::StdlibSet::FromIntegral(uses_bitset->value_as_bits());
  if (!stdlib_uses.empty()) {  // No checking needed if no uses.
    if (stdlib.is_null()) {
      ReportInstantiationFailure(script, position, "Requires standard library");
      return MaybeHandle<Object>();
    }
    if (!AreStdlibMembersValid(isolate, stdlib, stdlib_uses,
                               &stdlib_use_of_typed_array_present)) {
      ReportInstantiationFailure(script, position, "Unexpected stdlib member");
      return MaybeHandle<Object>();
    }
  }

  // Check that a valid heap buffer is provided if required.
  if (stdlib_use_of_typed_array_present) {
    if (memory.is_null()) {
      ReportInstantiationFailure(script, position, "Requires heap buffer");
      return MaybeHandle<Object>();
    }
    // AsmJs memory must be an ArrayBuffer.
    if (memory->is_shared()) {
      ReportInstantiationFailure(script, position,
                                 "Invalid heap type: SharedArrayBuffer");
      return MaybeHandle<Object>();
    }
    // We don't allow resizable ArrayBuffers because resizable ArrayBuffers may
    // shrink, and then asm.js does out of bounds memory accesses.
    if (memory->is_resizable_by_js()) {
      ReportInstantiationFailure(script, position,
                                 "Invalid heap type: resizable ArrayBuffer");
      return MaybeHandle<Object>();
    }
    // We don't allow WebAssembly.Memory, because WebAssembly.Memory.grow()
    // detaches the ArrayBuffer, and that would invalidate the asm.js module.
    if (memory->GetBackingStore() &&
        memory->GetBackingStore()->is_wasm_memory()) {
      ReportInstantiationFailure(script, position,
                                 "Invalid heap type: WebAssembly.Memory");
      return MaybeHandle<Object>();
    }
    size_t size = memory->byte_length();
    // Check the asm.js heap size against the valid limits.
    if (!IsValidAsmjsMemorySize(size)) {
      ReportInstantiationFailure(script, position, "Invalid heap size");
      return MaybeHandle<Object>();
    }
    // Mark the buffer as undetachable. This implies that the buffer cannot be
    // postMessage()'d, as that detaches the buffer.
    memory->set_is_detachable(false);
  } else {
    memory = Handle<JSArrayBuffer>::null();
  }

  wasm::ErrorThrower thrower(isolate, "AsmJs::Instantiate");
  MaybeHandle<WasmInstanceObject> maybe_instance =
      wasm_engine->SyncInstantiate(isolate, &thrower, module, foreign, memory);
  if (maybe_instance.is_null()) {
    // Clear a possible stack overflow from function entry that would have
    // bypassed the {ErrorThrower}. Be careful not to clear a termination
    // exception.
    if (isolate->is_execution_terminating()) return {};
    if (isolate->has_exception()) isolate->clear_exception();
    if (thrower.error()) {
      base::ScopedVector<char> error_reason(100);
      SNPrintF(error_reason, "Internal wasm failure: %s", thrower.error_msg());
      ReportInstantiationFailure(script, position, error_reason.begin());
    } else {
      ReportInstantiationFailure(script, position, "Internal wasm failure");
    }
    thrower.Reset();  // Ensure exceptions do not propagate.
    return {};
  }
  DCHECK(!thrower.error());
  Handle<WasmInstanceObject> instance = maybe_instance.ToHandleChecked();

  ReportInstantiationSuccess(script, position,
                             instantiate_timer.Elapsed().InMillisecondsF());

  Handle<Name> single_function_name(
      isolate->factory()->InternalizeUtf8String(AsmJs::kSingleFunctionName));
  MaybeHandle<Object> single_function =
      Object::GetProperty(isolate, instance, single_function_name);
  if (!single_function.is_null() &&
      !IsUndefined(*single_function.ToHandleChecked(), isolate)) {
    return single_function;
  }

  // Here we rely on the fact that the exports object is eagerly created.
  // The following check is a weak indicator for that. If this ever changes,
  // then we'll have to call the "exports" getter, and be careful about
  // handling possible stack overflow exceptions.
  DCHECK(IsJSObject(instance->exports_object()));
  return handle(instance->exports_object(), isolate);
}

}  // namespace internal
}  // namespace v8

"""

```