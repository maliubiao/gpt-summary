Response: Let's break down the thought process to analyze the C++ code and generate the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and a JavaScript example demonstrating its relation to JavaScript. This means I need to identify the core purpose of the code and how it bridges the gap between C++ (V8 internals) and JavaScript (asm.js).

2. **Initial Skim for Keywords:** I'll quickly scan the code for recognizable terms and namespaces. Keywords like `asmjs`, `wasm`, `parser`, `compile`, `instantiate`, `javascript`, and function names like `CompileAsmViaWasm` and `InstantiateAsmWasm` immediately stand out. The inclusion of `#include "src/wasm/..."` files strongly suggests a connection to WebAssembly.

3. **Identify the Core Functionality:** Based on the keywords, it seems the file is responsible for handling asm.js code within the V8 JavaScript engine. The presence of "compile" and "instantiate" strongly points towards the process of taking asm.js source code and turning it into executable code. The interaction with WebAssembly further suggests that asm.js is being translated to WebAssembly.

4. **Analyze Key Functions and Classes:**

   * **`AsmJsCompilationJob`:** This class clearly handles the compilation process. The `ExecuteJobImpl` method likely does the translation to WebAssembly, and `FinalizeJobImpl` handles the actual WebAssembly compilation. The timing measurements (`compile_time_`) confirm this.
   * **`AsmJs::InstantiateAsmWasm`:** This function deals with the instantiation phase. It takes the compiled WebAssembly module (`wasm_data`), standard library (`stdlib`), foreign imports (`foreign`), and potentially a memory buffer (`memory`). The checks for `stdlib` members and `memory` validity are crucial.
   * **Helper Functions (e.g., `AreStdlibMembersValid`, `ReportCompilationSuccess`):** These provide supporting functionality like validating the standard library environment and reporting status/errors.

5. **Understand the asm.js to WebAssembly Connection:**  The code heavily references WebAssembly (`wasm` namespace, `WasmModuleObject`, `WasmInstanceObject`). This confirms the central idea: V8 handles asm.js by *translating* it into WebAssembly. This translation allows V8 to leverage its existing WebAssembly infrastructure for optimization and execution.

6. **Identify the JavaScript Relationship:** The core relationship is that this C++ code *implements* the functionality that allows JavaScript developers to run asm.js code within their browsers. When a JavaScript engine encounters asm.js code, this C++ logic is triggered.

7. **Formulate the Summary:**  Based on the analysis, I can now formulate a concise summary:

   * **Core Function:** Compiling and instantiating asm.js code.
   * **Mechanism:** Translation of asm.js to WebAssembly.
   * **Key Components:** Compilation job, instantiation function, standard library validation, memory management.
   * **Purpose:** Efficiently execute numerically intensive JavaScript code by using a subset with static typing guarantees.

8. **Construct the JavaScript Example:** To illustrate the connection, a simple asm.js module is the best approach. The example needs to:

   * **Declare an asm.js module:** Use the `"use asm"` directive.
   * **Define a function:**  Show a basic arithmetic operation within the module.
   * **Demonstrate calling the module:** Instantiate the module with the necessary standard library and call the defined function.
   * **Highlight the purpose:** Explain that the C++ code is the underlying mechanism that makes this execution possible within the JavaScript engine.

9. **Refine and Review:**  Read through the summary and example to ensure clarity, accuracy, and completeness. Check for any technical inaccuracies or confusing language. For instance, initially, I might have focused too much on the low-level C++ details. The final output should be geared towards explaining the *functionality* and its *impact* on JavaScript, rather than just describing the C++ implementation. Emphasizing the benefits of asm.js (performance for specific types of code) is important context.

Self-Correction during the process:

* **Initial Thought:** Maybe it directly interprets asm.js? **Correction:** The heavy WebAssembly involvement indicates translation, not direct interpretation.
* **Focus too much on C++ structures:** Realize the goal is to explain the *JavaScript* impact. Shift the focus towards the user-facing aspect of asm.js.
* **Too technical JavaScript example:** Simplify the example to the bare minimum to demonstrate the concept. Avoid overly complex scenarios.

By following these steps, combining code analysis with an understanding of the request's goal, I can create a comprehensive and informative response.
这个C++源代码文件 `asm-js.cc` 是 V8 JavaScript 引擎中负责处理 **asm.js** 代码的功能模块。它的主要功能是将 asm.js 代码编译和实例化为可执行的 WebAssembly 模块，从而在 V8 引擎中高效地运行。

以下是该文件的功能归纳：

1. **解析和验证 asm.js 代码:**  该文件包含了将 JavaScript 代码识别为 asm.js 模块，并对其进行语法和语义验证的逻辑。它使用 `AsmJsParser` 类来完成这项任务。
2. **将 asm.js 转换为 WebAssembly:**  该文件是 asm.js 到 WebAssembly 转换的核心部分。它将经过验证的 asm.js 代码转换成等效的 WebAssembly 字节码。这涉及到类型分析、内存布局管理和指令转换等复杂过程。
3. **编译 WebAssembly 模块:**  转换后的 WebAssembly 字节码被传递给 V8 的 WebAssembly 引擎进行编译，生成机器码。
4. **实例化 WebAssembly 模块:**  该文件负责将编译后的 WebAssembly 模块实例化，并将其与 JavaScript 环境连接起来。这包括处理标准库 (stdlib)、外部导入 (foreign) 和内存 (heap buffer) 等依赖项。
5. **处理标准库 (stdlib) 和外部导入 (foreign):**  asm.js 模块可以依赖于宿主环境提供的标准库函数（例如 `Math` 对象中的函数）和外部导入的对象。该文件负责验证和连接这些依赖项。
6. **管理内存 (heap buffer):**  asm.js 模块通常会使用一个类型化的数组缓冲区 (ArrayBuffer) 作为其线性内存。该文件负责检查和管理这个内存缓冲区，确保其符合 asm.js 的规范。
7. **错误报告和性能监控:**  该文件包含用于报告 asm.js 编译和实例化过程中发生的错误和警告的机制，以及用于跟踪编译和实例化时间的性能监控代码。

**与 JavaScript 的关系以及 JavaScript 示例：**

`asm-js.cc` 使得 JavaScript 引擎能够理解和执行特定的 JavaScript 子集——asm.js。asm.js 是一种为了实现接近本地性能的数值计算而设计的 JavaScript 代码风格。它的特点是静态类型、手动内存管理和对性能的优化。

当 V8 引擎遇到包含 `"use asm"` 指令的 JavaScript 代码时，它会将其识别为 asm.js 模块，并调用 `asm-js.cc` 中的逻辑进行处理。

**JavaScript 示例：**

```javascript
function createAsmModule(stdlib, foreign, heap) {
  "use asm";

  // 声明一个 32 位整数变量
  var count = 0;

  // 定义一个接受两个整数参数并返回一个整数的函数
  function add(a, b) {
    a = a | 0; // 将 a 转换为 32 位整数
    b = b | 0; // 将 b 转换为 32 位整数
    return (a + b) | 0; // 返回 32 位整数结果
  }

  // 定义一个使用全局 Math 对象的函数
  function squareRoot(x) {
    x = +x; // 将 x 转换为双精度浮点数
    return stdlib.Math.sqrt(x);
  }

  return {
    add: add,
    squareRoot: squareRoot
  };
}

// 创建一个足够大的 ArrayBuffer 作为堆内存
const heapBuffer = new ArrayBuffer(256);

// 定义标准库和外部导入对象
const stdlib = {
  Math: Math
};
const foreign = {};

// 调用 createAsmModule 函数创建 asm.js 模块实例
const asmModuleInstance = createAsmModule(stdlib, foreign, heapBuffer);

// 调用 asm.js 模块中的函数
const sum = asmModuleInstance.add(5, 10);
console.log("Sum:", sum); // 输出: Sum: 15

const sqrtValue = asmModuleInstance.squareRoot(25);
console.log("Square Root:", sqrtValue); // 输出: Square Root: 5
```

**解释：**

1. **`"use asm";`**: 这个指令告诉 JavaScript 引擎将这段代码视为 asm.js 模块。
2. **静态类型声明:**  通过 `| 0` 和 `+` 等操作符，开发者可以显式地声明变量的类型 (例如，`a = a | 0` 表示 `a` 是一个 32 位整数)。这有助于 V8 引擎进行优化。
3. **标准库访问:**  asm.js 模块可以通过 `stdlib` 参数访问宿主环境提供的标准库对象，例如 `Math` 对象。在示例中，`stdlib.Math.sqrt()` 调用了全局的 `Math.sqrt()` 函数。
4. **手动内存管理 (未在示例中完全展示):**  虽然示例没有显式地使用 `heap` 参数进行内存操作，但在更复杂的 asm.js 模块中，`heap` 参数指向一个 `ArrayBuffer`，开发者可以使用类型化数组视图 (例如 `Int32Array`) 来进行手动内存管理。

当 JavaScript 引擎执行这段代码时，`asm-js.cc` 中的代码会被调用，将 `createAsmModule` 函数内部的 asm.js 代码转换成高效的 WebAssembly 模块，并实例化该模块。这样，`asmModuleInstance.add()` 和 `asmModuleInstance.squareRoot()` 的调用实际上是在执行编译后的 WebAssembly 代码，从而获得更高的性能，尤其是在进行数值密集型计算时。

总而言之，`v8/src/asmjs/asm-js.cc` 是 V8 引擎中实现 asm.js 功能的关键组成部分，它负责将这种高性能 JavaScript 子集编译和运行为 WebAssembly，从而提升特定类型 JavaScript 代码的执行效率。

Prompt: 
```
这是目录为v8/src/asmjs/asm-js.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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