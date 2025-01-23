Response:
Let's break down the thought process for analyzing this V8 source code snippet.

1. **Initial Skim and Keywords:**  The first step is a quick scan for recognizable keywords and patterns. I see `#include`, `namespace v8::internal::wasm`, class definitions (`WasmWrapperTSGraphBuilder`), function definitions (`AbortIfNot`, `LoadExportedFunctionIndexAsSmi`, etc.), and macros like `IF_NOT`. The presence of `turboshaft` in several names (`compiler::turboshaft::`, `WasmWrapperTSGraphBuilder`) is a strong indicator of its purpose.

2. **Identifying the Core Class:** The `WasmWrapperTSGraphBuilder` class seems central. Its constructor takes `Zone*`, `Assembler&`, and `const CanonicalSig*`. This suggests it's involved in generating code or a graph-like representation of code for WebAssembly function wrappers. The `CanonicalSig` likely represents the function signature.

3. **Understanding the "TSGraphBuilder" Part:** The "TS" likely stands for "Turboshaft". Knowing that Turboshaft is V8's newer optimizing compiler for WebAssembly, the class name strongly suggests that this code is responsible for building the Turboshaft graph for wrapper functions.

4. **Analyzing Key Methods:** Now, let's examine some of the methods within `WasmWrapperTSGraphBuilder`:
    * `AbortIfNot`: This looks like a conditional assertion, probably used for debugging or verifying assumptions during graph construction.
    * `ModifyThreadInWasmFlagScope`:  This seems to handle setting and unsetting a flag when entering and exiting WebAssembly code. This is crucial for the V8 runtime to manage execution context and potentially for trap handling.
    * `LoadExportedFunctionIndexAsSmi`:  This clearly retrieves information from `exported_function_data`, likely related to the index of an exported WebAssembly function.
    * `BuildChangeInt32ToSmi`, `BuildChangeInt32ToNumber`, etc.: These functions are responsible for converting between WebAssembly types (like `i32`, `f32`, `f64`) and JavaScript types (like `Smi`, `Number`, `BigInt`). The conditional logic in `BuildChangeInt32ToNumber` about Smi values hints at performance optimizations.
    * `ToJS`:  This is a crucial function. The `switch` statement based on `CanonicalValueType` indicates that this function converts a WebAssembly value to its corresponding JavaScript representation. The handling of function references (`HeapType::kFunc`) and null references is interesting.
    * `BuildCallAllocateJSArray`: This directly interacts with JavaScript array allocation, suggesting it's used for returning multiple values from a WebAssembly function.
    * `BuildCallWasmFromWrapper`: This function seems to generate the actual call to the underlying WebAssembly function.
    * `BuildCallAndReturn`: This appears to orchestrate the process of calling a WebAssembly function from a JavaScript wrapper, including potential type conversions and setting the "in wasm" flag.
    * `BuildJSToWasmWrapper`:  This is for generating wrappers when calling *into* WebAssembly from JavaScript. The logic includes fast and slow paths for type conversions, indicating performance considerations.
    * `BuildWasmToJSWrapper`:  This handles the opposite: calling JavaScript functions *from* WebAssembly. It deals with argument marshalling, handling different `ImportCallKind` scenarios, and converting return values.
    * `BuildCapiCallWrapper`: This function seems specific to C API calls into WebAssembly, dealing with stack management and error handling.

5. **Inferring the Overall Purpose:** Based on the methods and the class name, the primary function of `v8/src/wasm/wrappers.cc` is to generate code (specifically, the Turboshaft graph) for *wrapper functions*. These wrappers act as bridges between JavaScript and WebAssembly, handling:
    * Type conversions between JavaScript and WebAssembly values.
    * Setting and unsetting flags related to execution context (e.g., "in wasm" flag).
    * Calling into and out of WebAssembly modules.
    * Handling multiple return values.
    * Potentially optimizing common conversion scenarios (the "fast path").
    * Supporting C API calls.

6. **Addressing the Specific Questions:** Now that the core functionality is understood, let's address the user's specific points:
    * **Functionality Listing:**  This becomes a summarization of the methods and their roles.
    * **`.tq` Extension:** The code uses `#include "src/compiler/turboshaft/define-assembler-macros.inc"`, which *implies* it's using Turboshaft's assembly-like DSL, but the `.cc` extension indicates it's standard C++. So, the answer is it's *not* a Torque file.
    * **Relationship with JavaScript:** The methods like `ToJS`, `FromJS`, `BuildCallAllocateJSArray`, `BuildJSToWasmWrapper`, and `BuildWasmToJSWrapper` clearly demonstrate the tight coupling with JavaScript. Examples of calling WebAssembly from JavaScript and vice-versa would be illustrative.
    * **Code Logic and Assumptions:** The type conversion functions (`BuildChange...`) and the conditional logic within them offer good examples for demonstrating input/output and underlying assumptions.
    * **Common Programming Errors:** Errors related to type mismatches when crossing the JavaScript/WebAssembly boundary are the most likely candidates.
    * **Summary:**  A concise recap of the file's purpose as a code generator for interoperability.

7. **Refinement and Organization:** The final step is to organize the findings logically, provide clear explanations, and use illustrative examples where requested. This involves grouping related functionalities and ensuring the language is precise and easy to understand. For instance, clustering the type conversion functions together makes the explanation clearer.

This iterative process of skimming, identifying core components, analyzing methods, inferring purpose, and then specifically addressing the given questions allows for a thorough understanding of the source code snippet.
这是V8源代码文件 `v8/src/wasm/wrappers.cc` 的第一部分，它主要负责生成 WebAssembly 和 JavaScript 之间互操作的**包装器 (wrappers)** 代码。这些包装器使得 JavaScript 可以调用 WebAssembly 函数，反之亦然。该文件使用 V8 的 **Turboshaft** 编译器框架来构建这些包装器的代码。

**功能归纳：**

总而言之，`v8/src/wasm/wrappers.cc` 的主要功能是使用 Turboshaft 编译器，动态生成允许 JavaScript 和 WebAssembly 代码相互调用的“桥梁”代码。它处理了参数和返回值的类型转换、执行上下文的切换以及错误处理等关键细节。

**详细功能列举：**

1. **构建 Turboshaft 图 (TSGraph):**  该文件定义了一个核心类 `WasmWrapperTSGraphBuilder`，它继承自 `WasmGraphBuilderBase`，专门用于构建表示包装器逻辑的 Turboshaft 图。Turboshaft 图是 Turboshaft 编译器内部使用的一种中间表示形式。

2. **生成 JavaScript 调用 WebAssembly 的包装器 (JSToWasmWrapper):**
   -  接收 JavaScript 函数的参数。
   -  **类型转换:** 将 JavaScript 的值转换为 WebAssembly 可以理解的类型（例如，将 JavaScript 的 Number 转换为 WebAssembly 的 i32 或 f64）。这部分代码包含快速路径优化，针对常见的类型转换场景。
   -  **调用 WebAssembly 函数:**  生成调用实际 WebAssembly 函数的代码。
   -  **处理返回值:** 将 WebAssembly 函数的返回值转换为 JavaScript 的值。支持单个返回值和多个返回值（通过创建 JavaScript 数组来返回）。
   -  **错误处理:** 如果参数类型不兼容，会抛出 JavaScript 的 `TypeError`。

3. **生成 WebAssembly 调用 JavaScript 的包装器 (WasmToJSWrapper):**
   -  接收 WebAssembly 函数的参数。
   -  **类型转换:** 将 WebAssembly 的值转换为 JavaScript 可以理解的类型。
   -  **调用 JavaScript 函数:** 生成调用 JavaScript 函数的代码。根据导入函数的不同类型（例如，普通的 JavaScript 函数，或者需要特定调用约定的函数），生成不同的调用代码。
   -  **处理返回值:** 将 JavaScript 函数的返回值转换为 WebAssembly 的值。
   -  **处理异步操作 (Suspend):**  支持在 WebAssembly 调用 JavaScript 函数时进行挂起和恢复操作。

4. **生成 C API 调用 WebAssembly 的包装器 (CapiCallWrapper):**
   -  处理通过 C API 调用 WebAssembly 函数的情况。
   -  涉及到更底层的栈管理和参数传递。
   -  处理 C 函数调用可能抛出的异常。

5. **辅助功能:**
   -  `AbortIfNot`:  用于在调试模式下进行断言检查。
   -  `ModifyThreadInWasmFlagScope`: 用于在进入和退出 WebAssembly 代码时设置和重置一个标志，这对于 V8 的运行时管理至关重要。
   -  `LoadExportedFunctionIndexAsSmi`:  加载导出函数的索引。
   -  各种 `BuildChange...To...` 函数： 用于执行具体的类型转换操作。
   -  `GetTargetForBuiltinCall`, `CallBuiltin`: 用于调用 V8 的内置函数。

**关于 `.tq` 结尾：**

你提到如果 `v8/src/wasm/wrappers.cc` 以 `.tq` 结尾，它将是 V8 Torque 源代码。 然而，**该文件以 `.cc` 结尾，因此它是标准的 C++ 源代码文件**，而不是 Torque 文件。尽管如此，该文件内部使用了 Turboshaft 编译器框架，而 Torque 也是 V8 中用于生成高效代码的一种 DSL (Domain Specific Language)，两者在目标上是相似的，都是为了提升性能。

**与 JavaScript 功能的关系及示例：**

`v8/src/wasm/wrappers.cc` 的核心功能就是建立 WebAssembly 和 JavaScript 之间的桥梁。

**JavaScript 调用 WebAssembly 的例子：**

假设有一个 WebAssembly 模块 `my_module.wasm`，导出一个名为 `add` 的函数，它接受两个 i32 类型的参数并返回一个 i32 类型的结果。

```javascript
// 加载 WebAssembly 模块
WebAssembly.instantiateStreaming(fetch('my_module.wasm'))
  .then(result => {
    const wasmInstance = result.instance;
    const addFunction = wasmInstance.exports.add;

    // JavaScript 调用 WebAssembly 的 add 函数
    const sum = addFunction(5, 10);
    console.log(sum); // 输出 15
  });
```

在这个例子中，当 JavaScript 调用 `addFunction(5, 10)` 时，`v8/src/wasm/wrappers.cc` 生成的包装器代码就会被执行。这个包装器会：

1. 接收 JavaScript 传递的参数 `5` 和 `10`。
2. 将 JavaScript 的 Number 类型 `5` 和 `10` 转换为 WebAssembly 的 i32 类型。
3. 调用 WebAssembly 模块中实际的 `add` 函数。
4. 将 WebAssembly `add` 函数返回的 i32 类型结果转换回 JavaScript 的 Number 类型。
5. 将结果返回给 JavaScript 代码。

**WebAssembly 调用 JavaScript 的例子：**

假设 WebAssembly 模块需要调用 JavaScript 中定义的一个函数 `logMessage`。

```javascript
// JavaScript 中定义的函数
function logMessage(message) {
  console.log("From WebAssembly:", message);
}

// 创建导入对象，传递 JavaScript 函数
const importObject = {
  env: {
    log: logMessage
  }
};

WebAssembly.instantiateStreaming(fetch('my_module_with_import.wasm'), importObject)
  .then(result => {
    const wasmInstance = result.instance;
    const runWasm = wasmInstance.exports.run;
    runWasm(); // WebAssembly 代码内部会调用导入的 log 函数
  });
```

在 `my_module_with_import.wasm` 中，会有一个导入声明，类似于：

```wat
(import "env" "log" (func $log (param i32)))
```

当 WebAssembly 代码调用导入的 `log` 函数时，`v8/src/wasm/wrappers.cc` 生成的包装器代码会被执行。这个包装器会：

1. 接收 WebAssembly 传递的参数（例如，一个 i32 类型的参数，表示消息的索引）。
2. 将 WebAssembly 的 i32 类型参数转换为 JavaScript 可以接受的类型（可能需要从 WebAssembly 内存中读取字符串）。
3. 调用 JavaScript 中实际的 `logMessage` 函数。
4. （如果 JavaScript 函数有返回值）将 JavaScript 函数的返回值转换回 WebAssembly 可以理解的类型。

**代码逻辑推理（假设输入与输出）：**

以 `BuildChangeInt32ToNumber` 函数为例：

**假设输入:**  一个 Turboshaft 操作索引 `value`，它代表一个 WebAssembly 的 i32 值。

**代码逻辑:**

```c++
  V<Number> BuildChangeInt32ToNumber(V<Word32> value) {
    // We expect most integers at runtime to be Smis, so it is important for
    // wrapper performance that Smi conversion be inlined.
    if (SmiValuesAre32Bits()) {
      return BuildChangeInt32ToSmi(value);
    }
    DCHECK(SmiValuesAre31Bits());

    // Double value to test if value can be a Smi, and if so, to convert it.
    V<Tuple<Word32, Word32>> add = __ Int32AddCheckOverflow(value, value);
    V<Word32> ovf = __ template Projection<1>(add);
    ScopedVar<Number> result(this, OpIndex::Invalid());
    IF_NOT (UNLIKELY(ovf)) {
      // If it didn't overflow, the result is {2 * value} as pointer-sized
      // value.
      result = __ BitcastWordPtrToSmi(
          __ ChangeInt32ToIntPtr(__ template Projection<0>(add)));
    } ELSE{
      // Otherwise, call builtin, to convert to a HeapNumber.
      result = CallBuiltin<WasmInt32ToHeapNumberDescriptor>(
          Builtin::kWasmInt32ToHeapNumber, Operator::kNoProperties, value);
    }
    return result;
  }
```

- 如果 Smi（Small Integer）是 32 位的，则直接调用 `BuildChangeInt32ToSmi` 进行转换。
- 否则（Smi 是 31 位的），它会尝试一个优化：将 `value` 加倍。
- 如果加倍没有溢出，那么 `value` 就可以表示为一个 Smi，直接进行位转换。
- 如果加倍溢出，说明 `value` 超出了 Smi 的范围，需要调用内置的 `kWasmInt32ToHeapNumber` 函数将其转换为一个 HeapNumber 对象。

**假设输入:** 一个代表 WebAssembly i32 值 `10` 的 `value` 操作索引。

**输出:** 一个代表 JavaScript Number 值 `10` 的 `result` 操作索引。 在 Smi 为 31 位的架构上，由于 `10 * 2 = 20` 不会溢出，输出会通过 `__ BitcastWordPtrToSmi` 快速生成。

**假设输入:** 一个代表 WebAssembly i32 值 `2147483647` (MAX_INT) 的 `value` 操作索引。

**输出:**  一个代表 JavaScript Number 值 `2147483647` 的 `result` 操作索引。在 Smi 为 31 位的架构上，`2147483647 * 2` 会溢出，因此会调用 `kWasmInt32ToHeapNumber` 生成一个 HeapNumber。

**用户常见的编程错误：**

当 JavaScript 与 WebAssembly 交互时，常见的编程错误通常与类型不匹配有关：

1. **传递错误类型的参数给 WebAssembly 函数：**

   ```javascript
   // WebAssembly 函数期望接收两个 i32
   addFunction("hello", 10); // 错误：传递了字符串
   ```

   在这种情况下，`v8/src/wasm/wrappers.cc` 生成的包装器代码会尝试将字符串 `"hello"` 转换为 i32，这通常会导致错误或者得到意想不到的结果。V8 可能会抛出一个 `TypeError`。

2. **WebAssembly 导出函数返回了 JavaScript 无法正确处理的类型：**

   虽然 `v8/src/wasm/wrappers.cc` 负责进行类型转换，但如果 WebAssembly 模块的行为不符合预期（例如，返回了一个未定义的引用但包装器期望一个具体的对象），也可能导致 JavaScript 错误。

3. **在 WebAssembly 导入的 JavaScript 函数中返回了 WebAssembly 无法处理的类型：**

   ```javascript
   // WebAssembly 期望导入的 log 函数不返回任何值
   function logMessage(message) {
     console.log("From WebAssembly:", message);
     return { status: "ok" }; // 错误：返回了对象
   }
   ```

   如果 WebAssembly 期望导入的 JavaScript 函数返回一个特定的 WebAssembly 类型，但 JavaScript 函数返回了不同的类型，`v8/src/wasm/wrappers.cc` 生成的包装器可能无法正确转换，从而导致错误。

**总结一下 `v8/src/wasm/wrappers.cc` (第 1 部分) 的功能：**

这是 V8 引擎中一个关键的源代码文件，它利用 Turboshaft 编译器框架，负责生成 JavaScript 和 WebAssembly 之间互操作所需的包装器代码。这些包装器处理了跨语言边界的参数和返回值转换、执行上下文管理以及错误处理，使得 JavaScript 和 WebAssembly 能够无缝地相互调用。该文件的第一部分主要定义了用于构建这些包装器的核心类和一些辅助功能，涵盖了从 JavaScript 调用 WebAssembly 的包装器生成逻辑。

### 提示词
```
这是目录为v8/src/wasm/wrappers.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wrappers.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/small-vector.h"
#include "src/codegen/bailout-reason.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/compiler/linkage.h"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/wasm-assembler-helpers.h"
#include "src/objects/object-list-macros.h"
#include "src/wasm/turboshaft-graph-interface.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects.h"
#include "src/zone/zone.h"

namespace v8::internal::wasm {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

using compiler::CallDescriptor;
using compiler::Operator;
using compiler::turboshaft::ConditionWithHint;
using compiler::turboshaft::Float32;
using compiler::turboshaft::Float64;
using compiler::turboshaft::Label;
using compiler::turboshaft::LoadOp;
using compiler::turboshaft::MemoryRepresentation;
using TSBlock = compiler::turboshaft::Block;
using compiler::turboshaft::OpEffects;
using compiler::turboshaft::OpIndex;
using compiler::turboshaft::OptionalOpIndex;
using compiler::turboshaft::RegisterRepresentation;
using compiler::turboshaft::StoreOp;
using compiler::turboshaft::TSCallDescriptor;
using compiler::turboshaft::Tuple;
using compiler::turboshaft::V;
using compiler::turboshaft::Variable;
using compiler::turboshaft::Word32;
using compiler::turboshaft::WordPtr;

namespace {
const TSCallDescriptor* GetBuiltinCallDescriptor(Builtin name, Zone* zone) {
  CallInterfaceDescriptor interface_descriptor =
      Builtins::CallInterfaceDescriptorFor(name);
  CallDescriptor* call_desc = compiler::Linkage::GetStubCallDescriptor(
      zone,                                           // zone
      interface_descriptor,                           // descriptor
      interface_descriptor.GetStackParameterCount(),  // stack parameter count
      CallDescriptor::kNoFlags,                       // flags
      compiler::Operator::kNoProperties,              // properties
      StubCallMode::kCallBuiltinPointer);             // stub call mode
  return TSCallDescriptor::Create(call_desc, compiler::CanThrow::kNo,
                                  compiler::LazyDeoptOnThrow::kNo, zone);
}
}  // namespace

class WasmWrapperTSGraphBuilder : public WasmGraphBuilderBase {
 public:
  WasmWrapperTSGraphBuilder(Zone* zone, Assembler& assembler,
                            const CanonicalSig* sig)
      : WasmGraphBuilderBase(zone, assembler), sig_(sig) {}

  void AbortIfNot(V<Word32> condition, AbortReason abort_reason) {
    if (!v8_flags.debug_code) return;
    IF_NOT (condition) {
      V<Number> message_id =
          __ NumberConstant(static_cast<int32_t>(abort_reason));
      CallRuntime(__ phase_zone(), Runtime::kAbort, {message_id},
                  __ NoContextConstant());
    }
  }

  class ModifyThreadInWasmFlagScope {
   public:
    ModifyThreadInWasmFlagScope(
        WasmWrapperTSGraphBuilder* wasm_wrapper_graph_builder, Assembler& asm_)
        : wasm_wrapper_graph_builder_(wasm_wrapper_graph_builder) {
      if (!trap_handler::IsTrapHandlerEnabled()) return;

      thread_in_wasm_flag_address_ =
          asm_.Load(asm_.LoadRootRegister(), OptionalOpIndex::Nullopt(),
                    LoadOp::Kind::RawAligned(), MemoryRepresentation::UintPtr(),
                    RegisterRepresentation::WordPtr(),
                    Isolate::thread_in_wasm_flag_address_offset());
      wasm_wrapper_graph_builder_->BuildModifyThreadInWasmFlagHelper(
          wasm_wrapper_graph_builder_->Asm().phase_zone(),
          thread_in_wasm_flag_address_, true);
    }

    ModifyThreadInWasmFlagScope(const ModifyThreadInWasmFlagScope&) = delete;

    ~ModifyThreadInWasmFlagScope() {
      if (!trap_handler::IsTrapHandlerEnabled()) return;
      wasm_wrapper_graph_builder_->BuildModifyThreadInWasmFlagHelper(
          wasm_wrapper_graph_builder_->Asm().phase_zone(),
          thread_in_wasm_flag_address_, false);
    }

   private:
    WasmWrapperTSGraphBuilder* wasm_wrapper_graph_builder_;
    V<WordPtr> thread_in_wasm_flag_address_;
  };

  V<Smi> LoadExportedFunctionIndexAsSmi(V<Object> exported_function_data) {
    return __ Load(exported_function_data,
                   LoadOp::Kind::TaggedBase().Immutable(),
                   MemoryRepresentation::TaggedSigned(),
                   WasmExportedFunctionData::kFunctionIndexOffset);
  }

  V<Smi> BuildChangeInt32ToSmi(V<Word32> value) {
    // With pointer compression, only the lower 32 bits are used.
    return V<Smi>::Cast(COMPRESS_POINTERS_BOOL
                            ? __ BitcastWord32ToWord64(__ Word32ShiftLeft(
                                  value, BuildSmiShiftBitsConstant32()))
                            : __ Word64ShiftLeft(__ ChangeInt32ToInt64(value),
                                                 BuildSmiShiftBitsConstant()));
  }

  V<WordPtr> GetTargetForBuiltinCall(Builtin builtin) {
    return WasmGraphBuilderBase::GetTargetForBuiltinCall(
        builtin, StubCallMode::kCallBuiltinPointer);
  }

  template <typename Descriptor, typename... Args>
  OpIndex CallBuiltin(Builtin name, OpIndex frame_state,
                      Operator::Properties properties, Args... args) {
    auto call_descriptor = compiler::Linkage::GetStubCallDescriptor(
        __ graph_zone(), Descriptor(), 0,
        frame_state.valid() ? CallDescriptor::kNeedsFrameState
                            : CallDescriptor::kNoFlags,
        Operator::kNoProperties, StubCallMode::kCallBuiltinPointer);
    const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
        call_descriptor, compiler::CanThrow::kNo,
        compiler::LazyDeoptOnThrow::kNo, __ graph_zone());
    V<WordPtr> call_target = GetTargetForBuiltinCall(name);
    return __ Call(call_target, frame_state, base::VectorOf({args...}),
                   ts_call_descriptor);
  }

  template <typename Descriptor, typename... Args>
  OpIndex CallBuiltin(Builtin name, Operator::Properties properties,
                      Args... args) {
    auto call_descriptor = compiler::Linkage::GetStubCallDescriptor(
        __ graph_zone(), Descriptor(), 0, CallDescriptor::kNoFlags,
        Operator::kNoProperties, StubCallMode::kCallBuiltinPointer);
    const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
        call_descriptor, compiler::CanThrow::kNo,
        compiler::LazyDeoptOnThrow::kNo, __ graph_zone());
    V<WordPtr> call_target = GetTargetForBuiltinCall(name);
    return __ Call(call_target, {args...}, ts_call_descriptor);
  }

  V<Number> BuildChangeInt32ToNumber(V<Word32> value) {
    // We expect most integers at runtime to be Smis, so it is important for
    // wrapper performance that Smi conversion be inlined.
    if (SmiValuesAre32Bits()) {
      return BuildChangeInt32ToSmi(value);
    }
    DCHECK(SmiValuesAre31Bits());

    // Double value to test if value can be a Smi, and if so, to convert it.
    V<Tuple<Word32, Word32>> add = __ Int32AddCheckOverflow(value, value);
    V<Word32> ovf = __ template Projection<1>(add);
    ScopedVar<Number> result(this, OpIndex::Invalid());
    IF_NOT (UNLIKELY(ovf)) {
      // If it didn't overflow, the result is {2 * value} as pointer-sized
      // value.
      result = __ BitcastWordPtrToSmi(
          __ ChangeInt32ToIntPtr(__ template Projection<0>(add)));
    } ELSE{
      // Otherwise, call builtin, to convert to a HeapNumber.
      result = CallBuiltin<WasmInt32ToHeapNumberDescriptor>(
          Builtin::kWasmInt32ToHeapNumber, Operator::kNoProperties, value);
    }
    return result;
  }

  V<Number> BuildChangeFloat32ToNumber(V<Float32> value) {
    return CallBuiltin<WasmFloat32ToNumberDescriptor>(
        Builtin::kWasmFloat32ToNumber, Operator::kNoProperties, value);
  }

  V<Number> BuildChangeFloat64ToNumber(V<Float64> value) {
    return CallBuiltin<WasmFloat64ToTaggedDescriptor>(
        Builtin::kWasmFloat64ToNumber, Operator::kNoProperties, value);
  }

  V<Object> ToJS(OpIndex ret, CanonicalValueType type, V<Context> context) {
    switch (type.kind()) {
      case kI32:
        return BuildChangeInt32ToNumber(ret);
      case kI64:
        return BuildChangeInt64ToBigInt(ret, StubCallMode::kCallBuiltinPointer);
      case kF32:
        return BuildChangeFloat32ToNumber(ret);
      case kF64:
        return BuildChangeFloat64ToNumber(ret);
      case kRef:
        switch (type.heap_representation_non_shared()) {
          case HeapType::kEq:
          case HeapType::kI31:
          case HeapType::kStruct:
          case HeapType::kArray:
          case HeapType::kAny:
          case HeapType::kExtern:
          case HeapType::kString:
          case HeapType::kNone:
          case HeapType::kNoFunc:
          case HeapType::kNoExtern:
            return ret;
          case HeapType::kExn:
          case HeapType::kNoExn:
          case HeapType::kBottom:
          case HeapType::kTop:
          case HeapType::kStringViewWtf8:
          case HeapType::kStringViewWtf16:
          case HeapType::kStringViewIter:
            UNREACHABLE();
          case HeapType::kFunc:
          default:
            if (type.heap_representation_non_shared() == HeapType::kFunc ||
                GetTypeCanonicalizer()->IsFunctionSignature(type.ref_index())) {
              // Function reference. Extract the external function.
              V<WasmInternalFunction> internal =
                  V<WasmInternalFunction>::Cast(__ LoadTrustedPointerField(
                      ret, LoadOp::Kind::TaggedBase(),
                      kWasmInternalFunctionIndirectPointerTag,
                      WasmFuncRef::kTrustedInternalOffset));
              ScopedVar<Object> maybe_external(
                  this, __ Load(internal, LoadOp::Kind::TaggedBase(),
                                MemoryRepresentation::TaggedPointer(),
                                WasmInternalFunction::kExternalOffset));
              IF (__ TaggedEqual(maybe_external, LOAD_ROOT(UndefinedValue))) {
                maybe_external =
                    CallBuiltin<WasmInternalFunctionCreateExternalDescriptor>(
                        Builtin::kWasmInternalFunctionCreateExternal,
                        Operator::kNoProperties, internal, context);
              }
              return maybe_external;
            } else {
              return ret;
            }
        }
      case kRefNull:
        switch (type.heap_representation_non_shared()) {
          case HeapType::kExtern:
          case HeapType::kNoExtern:
            return ret;
          case HeapType::kNone:
          case HeapType::kNoFunc:
            return LOAD_ROOT(NullValue);
          case HeapType::kExn:
          case HeapType::kNoExn:
            UNREACHABLE();
          case HeapType::kEq:
          case HeapType::kStruct:
          case HeapType::kArray:
          case HeapType::kString:
          case HeapType::kI31:
          case HeapType::kAny: {
            ScopedVar<Object> result(this, OpIndex::Invalid());
            IF_NOT (__ TaggedEqual(ret, LOAD_ROOT(WasmNull))) {
              result = ret;
            } ELSE{
              result = LOAD_ROOT(NullValue);
            }
            return result;
          }
          case HeapType::kFunc:
          default: {
            if (type.heap_representation_non_shared() == HeapType::kFunc ||
                GetTypeCanonicalizer()->IsFunctionSignature(type.ref_index())) {
              ScopedVar<Object> result(this, OpIndex::Invalid());
              IF (__ TaggedEqual(ret, LOAD_ROOT(WasmNull))) {
                result = LOAD_ROOT(NullValue);
              } ELSE{
                V<WasmInternalFunction> internal =
                    V<WasmInternalFunction>::Cast(__ LoadTrustedPointerField(
                        ret, LoadOp::Kind::TaggedBase(),
                        kWasmInternalFunctionIndirectPointerTag,
                        WasmFuncRef::kTrustedInternalOffset));
                V<Object> maybe_external =
                    __ Load(internal, LoadOp::Kind::TaggedBase(),
                            MemoryRepresentation::AnyTagged(),
                            WasmInternalFunction::kExternalOffset);
                IF (__ TaggedEqual(maybe_external, LOAD_ROOT(UndefinedValue))) {
                  V<Object> from_builtin =
                      CallBuiltin<WasmInternalFunctionCreateExternalDescriptor>(
                          Builtin::kWasmInternalFunctionCreateExternal,
                          Operator::kNoProperties, internal, context);
                  result = from_builtin;
                } ELSE{
                  result = maybe_external;
                }
              }
              return result;
            } else {
              ScopedVar<Object> result(this, OpIndex::Invalid());
              IF (__ TaggedEqual(ret, LOAD_ROOT(WasmNull))) {
                result = LOAD_ROOT(NullValue);
              } ELSE{
                result = ret;
              }
              return result;
            }
          }
        }
      case kRtt:
      case kI8:
      case kI16:
      case kF16:
      case kS128:
      case kVoid:
      case kTop:
      case kBottom:
        // If this is reached, then IsJSCompatibleSignature() is too permissive.
        UNREACHABLE();
    }
  }

  // Generate a call to the AllocateJSArray builtin.
  V<JSArray> BuildCallAllocateJSArray(V<Number> array_length,
                                      V<Object> context) {
    // Since we don't check that args will fit in an array,
    // we make sure this is true based on statically known limits.
    static_assert(kV8MaxWasmFunctionReturns <=
                  JSArray::kInitialMaxFastElementArray);
    return CallBuiltin<WasmAllocateJSArrayDescriptor>(
        Builtin::kWasmAllocateJSArray, Operator::kEliminatable, array_length,
        context);
  }

  void BuildCallWasmFromWrapper(Zone* zone, const CanonicalSig* sig,
                                V<WasmCodePtr> callee,
                                V<HeapObject> implicit_first_arg,
                                const base::Vector<OpIndex> args,
                                base::Vector<OpIndex> returns) {
    const TSCallDescriptor* descriptor = TSCallDescriptor::Create(
        compiler::GetWasmCallDescriptor(__ graph_zone(), sig),
        compiler::CanThrow::kYes, compiler::LazyDeoptOnThrow::kNo,
        __ graph_zone());

    args[0] = implicit_first_arg;
    OpIndex call = __ Call(callee, OpIndex::Invalid(), base::VectorOf(args),
                           descriptor, OpEffects().CanCallAnything());

    if (sig->return_count() == 1) {
      returns[0] = call;
    } else if (sig->return_count() > 1) {
      for (uint32_t i = 0; i < sig->return_count(); i++) {
        CanonicalValueType type = sig->GetReturn(i);
        returns[i] = __ Projection(call, i, RepresentationFor(type));
      }
    }
  }

  OpIndex BuildCallAndReturn(V<Context> js_context, V<HeapObject> function_data,
                             base::Vector<OpIndex> args, bool do_conversion,
                             bool set_in_wasm_flag,
                             uint64_t expected_sig_hash) {
    const int rets_count = static_cast<int>(sig_->return_count());
    base::SmallVector<OpIndex, 1> rets(rets_count);

    // Set the ThreadInWasm flag before we do the actual call.
    {
      std::optional<ModifyThreadInWasmFlagScope>
          modify_thread_in_wasm_flag_builder;
      if (set_in_wasm_flag) {
        modify_thread_in_wasm_flag_builder.emplace(this, Asm());
      }

      V<WasmInternalFunction> internal =
          V<WasmInternalFunction>::Cast(__ LoadProtectedPointerField(
              function_data, LoadOp::Kind::TaggedBase().Immutable(),
              WasmExportedFunctionData::kProtectedInternalOffset));
      auto [target, implicit_arg] =
          BuildFunctionTargetAndImplicitArg(internal, expected_sig_hash);
      BuildCallWasmFromWrapper(__ phase_zone(), sig_, target, implicit_arg,
                               args, base::VectorOf(rets));
    }

    V<Object> jsval;
    if (sig_->return_count() == 0) {
      jsval = LOAD_ROOT(UndefinedValue);
    } else if (sig_->return_count() == 1) {
      jsval = do_conversion ? ToJS(rets[0], sig_->GetReturn(), js_context)
                            : rets[0];
    } else {
      int32_t return_count = static_cast<int32_t>(sig_->return_count());
      V<Smi> size = __ SmiConstant(Smi::FromInt(return_count));

      jsval = BuildCallAllocateJSArray(size, js_context);

      V<FixedArray> fixed_array = __ Load(jsval, LoadOp::Kind::TaggedBase(),
                                          MemoryRepresentation::TaggedPointer(),
                                          JSObject::kElementsOffset);

      for (int i = 0; i < return_count; ++i) {
        V<Object> value = ToJS(rets[i], sig_->GetReturn(i), js_context);
        __ StoreFixedArrayElement(fixed_array, i, value,
                                  compiler::kFullWriteBarrier);
      }
    }
    return jsval;
  }

  void BuildJSToWasmWrapper(
      bool do_conversion = true,
      compiler::turboshaft::OptionalOpIndex frame_state =
          compiler::turboshaft::OptionalOpIndex::Nullopt(),
      bool set_in_wasm_flag = true) {
    const int wasm_param_count = static_cast<int>(sig_->parameter_count());

    __ Bind(__ NewBlock());

    // Create the js_closure and js_context parameters.
    V<JSFunction> js_closure =
        __ Parameter(compiler::Linkage::kJSCallClosureParamIndex,
                     RegisterRepresentation::Tagged());
    V<Context> js_context = __ Parameter(
        compiler::Linkage::GetJSCallContextParamIndex(wasm_param_count + 1),
        RegisterRepresentation::Tagged());
    V<SharedFunctionInfo> shared =
        __ Load(js_closure, LoadOp::Kind::TaggedBase(),
                MemoryRepresentation::TaggedPointer(),
                JSFunction::kSharedFunctionInfoOffset);
#ifdef V8_ENABLE_SANDBOX
    uint64_t signature_hash = SignatureHasher::Hash(sig_);
#else
    uint64_t signature_hash = 0;
#endif
    V<WasmFunctionData> function_data =
        V<WasmFunctionData>::Cast(__ LoadTrustedPointerField(
            shared, LoadOp::Kind::TaggedBase(),
            kWasmFunctionDataIndirectPointerTag,
            SharedFunctionInfo::kTrustedFunctionDataOffset));

    if (!IsJSCompatibleSignature(sig_)) {
      // Throw a TypeError. Use the js_context of the calling javascript
      // function (passed as a parameter), such that the generated code is
      // js_context independent.
      CallRuntime(__ phase_zone(), Runtime::kWasmThrowJSTypeError, {},
                  js_context);
      __ Unreachable();
      return;
    }

    const int args_count = wasm_param_count + 1;  // +1 for wasm_code.

    // Check whether the signature of the function allows for a fast
    // transformation (if any params exist that need transformation).
    // Create a fast transformation path, only if it does.
    bool include_fast_path =
        do_conversion && wasm_param_count > 0 && QualifiesForFastTransform();

    // Prepare Param() nodes. Param() nodes can only be created once,
    // so we need to use the same nodes along all possible transformation paths.
    base::SmallVector<OpIndex, 16> params(args_count);
    for (int i = 0; i < wasm_param_count; ++i) {
      params[i + 1] = __ Parameter(i + 1, RegisterRepresentation::Tagged());
    }

    Label<Object> done(&Asm());
    V<Object> jsval;
    if (include_fast_path) {
      TSBlock* slow_path = __ NewBlock();
      // Check if the params received on runtime can be actually transformed
      // using the fast transformation. When a param that cannot be transformed
      // fast is encountered, skip checking the rest and fall back to the slow
      // path.
      for (int i = 0; i < wasm_param_count; ++i) {
        CanTransformFast(params[i + 1], sig_->GetParam(i), slow_path);
      }
      // Convert JS parameters to wasm numbers using the fast transformation
      // and build the call.
      base::SmallVector<OpIndex, 16> args(args_count);
      for (int i = 0; i < wasm_param_count; ++i) {
        OpIndex wasm_param = FromJSFast(params[i + 1], sig_->GetParam(i));
        args[i + 1] = wasm_param;
      }
      jsval =
          BuildCallAndReturn(js_context, function_data, base::VectorOf(args),
                             do_conversion, set_in_wasm_flag, signature_hash);
      GOTO(done, jsval);
      __ Bind(slow_path);
    }
    // Convert JS parameters to wasm numbers using the default transformation
    // and build the call.
    base::SmallVector<OpIndex, 16> args(args_count);
    for (int i = 0; i < wasm_param_count; ++i) {
      if (do_conversion) {
        args[i + 1] =
            FromJS(params[i + 1], js_context, sig_->GetParam(i), frame_state);
      } else {
        OpIndex wasm_param = params[i + 1];

        // For Float32 parameters
        // we set UseInfo::CheckedNumberOrOddballAsFloat64 in
        // simplified-lowering and we need to add here a conversion from Float64
        // to Float32.
        if (sig_->GetParam(i).kind() == kF32) {
          wasm_param = __ TruncateFloat64ToFloat32(wasm_param);
        }
        args[i + 1] = wasm_param;
      }
    }

    jsval = BuildCallAndReturn(js_context, function_data, base::VectorOf(args),
                               do_conversion, set_in_wasm_flag, signature_hash);
    // If both the default and a fast transformation paths are present,
    // get the return value based on the path used.
    if (include_fast_path) {
      GOTO(done, jsval);
      BIND(done, result);
      __ Return(result);
    } else {
      __ Return(jsval);
    }
  }

  void BuildWasmToJSWrapper(ImportCallKind kind, int expected_arity,
                            Suspend suspend) {
    int wasm_count = static_cast<int>(sig_->parameter_count());

    __ Bind(__ NewBlock());
    base::SmallVector<OpIndex, 16> wasm_params(wasm_count);
    OpIndex ref = __ Parameter(0, RegisterRepresentation::Tagged());
    for (int i = 0; i < wasm_count; ++i) {
      RegisterRepresentation rep = RepresentationFor(sig_->GetParam(i));
      wasm_params[i] = (__ Parameter(1 + i, rep));
    }

    V<Context> native_context = __ Load(ref, LoadOp::Kind::TaggedBase(),
                                        MemoryRepresentation::TaggedPointer(),
                                        WasmImportData::kNativeContextOffset);

    if (kind == ImportCallKind::kRuntimeTypeError) {
      // =======================================================================
      // === Runtime TypeError =================================================
      // =======================================================================
      CallRuntime(zone_, Runtime::kWasmThrowJSTypeError, {}, native_context);
      __ Unreachable();
      return;
    }

    V<Undefined> undefined_node = LOAD_ROOT(UndefinedValue);
    int pushed_count = std::max(expected_arity, wasm_count);
    // 5 extra arguments: receiver, new target, arg count, dispatch handle and
    // context.
    bool has_dispatch_handle = kind == ImportCallKind::kUseCallBuiltin
                                   ? false
                                   : V8_ENABLE_LEAPTIERING_BOOL;
    base::SmallVector<OpIndex, 16> args(pushed_count + 4 +
                                        (has_dispatch_handle ? 1 : 0));
    // Position of the first wasm argument in the JS arguments.
    int pos = kind == ImportCallKind::kUseCallBuiltin ? 3 : 1;
    pos = AddArgumentNodes(base::VectorOf(args), pos, wasm_params, sig_,
                           native_context);
    for (int i = wasm_count; i < expected_arity; ++i) {
      args[pos++] = undefined_node;
    }

    V<JSFunction> callable_node = __ Load(ref, LoadOp::Kind::TaggedBase(),
                                          MemoryRepresentation::TaggedPointer(),
                                          WasmImportData::kCallableOffset);
    OpIndex old_sp = BuildSwitchToTheCentralStackIfNeeded();
    BuildModifyThreadInWasmFlag(__ phase_zone(), false);
    OpIndex call = OpIndex::Invalid();
    switch (kind) {
      // =======================================================================
      // === JS Functions ======================================================
      // =======================================================================
      case ImportCallKind::kJSFunctionArityMatch:
        DCHECK_EQ(expected_arity, wasm_count);
        [[fallthrough]];
      case ImportCallKind::kJSFunctionArityMismatch: {
        auto call_descriptor = compiler::Linkage::GetJSCallDescriptor(
            __ graph_zone(), false, pushed_count + 1, CallDescriptor::kNoFlags);
        const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
            call_descriptor, compiler::CanThrow::kYes,
            compiler::LazyDeoptOnThrow::kNo, __ graph_zone());

        // Determine receiver at runtime.
        args[0] =
            BuildReceiverNode(callable_node, native_context, undefined_node);
        DCHECK_EQ(pos, pushed_count + 1);
        args[pos++] = undefined_node;  // new target
        args[pos++] =
            __ Word32Constant(JSParameterCount(wasm_count));  // argument count
#ifdef V8_ENABLE_LEAPTIERING
        args[pos++] = __ Word32Constant(kPlaceholderDispatchHandle);
#endif
        args[pos++] = LoadContextFromJSFunction(callable_node);
        call = __ Call(callable_node, OpIndex::Invalid(), base::VectorOf(args),
                       ts_call_descriptor);
        break;
      }
      // =======================================================================
      // === General case of unknown callable ==================================
      // =======================================================================
      case ImportCallKind::kUseCallBuiltin: {
        DCHECK_EQ(expected_arity, wasm_count);
        OpIndex target = GetBuiltinPointerTarget(Builtin::kCall_ReceiverIsAny);
        args[0] = callable_node;
        args[1] =
            __ Word32Constant(JSParameterCount(wasm_count));  // argument count
        args[2] = undefined_node;                             // receiver

        auto call_descriptor = compiler::Linkage::GetStubCallDescriptor(
            __ graph_zone(), CallTrampolineDescriptor{}, wasm_count + 1,
            CallDescriptor::kNoFlags, Operator::kNoProperties,
            StubCallMode::kCallBuiltinPointer);
        const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
            call_descriptor, compiler::CanThrow::kYes,
            compiler::LazyDeoptOnThrow::kNo, __ graph_zone());

        // The native_context is sufficient here, because all kind of callables
        // which depend on the context provide their own context. The context
        // here is only needed if the target is a constructor to throw a
        // TypeError, if the target is a native function, or if the target is a
        // callable JSObject, which can only be constructed by the runtime.
        args[pos++] = native_context;
        call = __ Call(target, OpIndex::Invalid(), base::VectorOf(args),
                       ts_call_descriptor);
        break;
      }
      default:
        UNIMPLEMENTED();
    }
    // For asm.js the error location can differ depending on whether an
    // exception was thrown in imported JS code or an exception was thrown in
    // the ToNumber builtin that converts the result of the JS code a
    // WebAssembly value. The source position allows asm.js to determine the
    // correct error location. Source position 1 encodes the call to ToNumber,
    // source position 0 encodes the call to the imported JS code.
    __ output_graph().source_positions()[call] = SourcePosition(0);
    DCHECK(call.valid());

    if (suspend == kSuspend) {
      call = BuildSuspend(call, ref, &old_sp);
    }

    // Convert the return value(s) back.
    OpIndex val;
    base::SmallVector<OpIndex, 8> wasm_values;
    if (sig_->return_count() <= 1) {
      val = sig_->return_count() == 0
                ? __ Word32Constant(0)
                : FromJS(call, native_context, sig_->GetReturn());
    } else {
      V<FixedArray> fixed_array =
          BuildMultiReturnFixedArrayFromIterable(call, native_context);
      wasm_values.resize_no_init(sig_->return_count());
      for (unsigned i = 0; i < sig_->return_count(); ++i) {
        wasm_values[i] = FromJS(__ LoadFixedArrayElement(fixed_array, i),
                                native_context, sig_->GetReturn(i));
      }
    }
    BuildModifyThreadInWasmFlag(__ phase_zone(), true);
    BuildSwitchBackFromCentralStack(old_sp);
    if (sig_->return_count() <= 1) {
      __ Return(val);
    } else {
      __ Return(__ Word32Constant(0), base::VectorOf(wasm_values));
    }
  }

  void BuildCapiCallWrapper() {
    __ Bind(__ NewBlock());
    base::SmallVector<OpIndex, 8> incoming_params;
    // Instance.
    incoming_params.push_back(
        __ Parameter(0, RegisterRepresentation::Tagged()));
    // Wasm parameters.
    for (int i = 0; i < static_cast<int>(sig_->parameter_count()); ++i) {
      incoming_params.push_back(
          __ Parameter(i + 1, RepresentationFor(sig_->GetParam(i))));
    }
    // Store arguments on our stack, then align the stack for calling to C.
    int param_bytes = 0;
    for (CanonicalValueType type : sig_->parameters()) {
      param_bytes += type.value_kind_size();
    }
    int return_bytes = 0;
    for (CanonicalValueType type : sig_->returns()) {
      return_bytes += type.value_kind_size();
    }

    int stack_slot_bytes = std::max(param_bytes, return_bytes);
    OpIndex values = stack_slot_bytes == 0
                         ? __ IntPtrConstant(0)
                         : __ StackSlot(stack_slot_bytes, kDoubleAlignment);

    int offset = 0;
    for (size_t i = 0; i < sig_->parameter_count(); ++i) {
      CanonicalValueType type = sig_->GetParam(i);
      // Start from the parameter with index 1 to drop the instance_node.
      // TODO(jkummerow): When a values is a reference type, we should pass it
      // in a GC-safe way, not just as a raw pointer.
      SafeStore(offset, type, values, incoming_params[i + 1]);
      offset += type.value_kind_size();
    }

    V<Object> function_node =
        __ LoadTaggedField(incoming_params[0], WasmImportData::kCallableOffset);
    V<HeapObject> shared = LoadSharedFunctionInfo(function_node);
    V<WasmFunctionData> function_data =
        V<WasmFunctionData>::Cast(__ LoadTrustedPointerField(
            shared, LoadOp::Kind::TaggedBase(),
            kWasmFunctionDataIndirectPointerTag,
            SharedFunctionInfo::kTrustedFunctionDataOffset));
    V<Object> host_data_foreign = __ LoadTaggedField(
        function_data, WasmCapiFunctionData::kEmbedderDataOffset);

    BuildModifyThreadInWasmFlag(__ phase_zone(), false);
    OpIndex isolate_root = __ LoadRootRegister();
    OpIndex fp_value = __ FramePointer();
    __ Store(isolate_root, fp_value, StoreOp::Kind::RawAligned(),
             MemoryRepresentation::UintPtr(), compiler::kNoWriteBarrier,
             Isolate::c_entry_fp_offset());

    V<WordPtr> call_target =
        BuildLoadCallTargetFromExportedFunctionData(function_data);

    // Parameters: Address host_data_foreign, Address arguments.
    auto host_sig =
        FixedSizeSignature<MachineType>::Returns(MachineType::Pointer())
            .Params(MachineType::AnyTagged(), MachineType::Pointer());
    OpIndex return_value =
        CallC(&host_sig, call_target, {host_data_foreign, values});

    BuildModifyThreadInWasmFlag(__ phase_zone(), true);

    IF_NOT (__ WordPtrEqual(return_value, __ IntPtrConstant(0))) {
      WasmRethrowExplicitContextDescriptor interface_descriptor;
      auto call_descriptor = compiler::Linkage::GetStubCallDescriptor(
          __ graph_zone(), interface_descriptor,
          interface_descriptor.GetStackParameterCount(),
          CallDescriptor::kNoFlags, Operator::kNoProperties,
          StubCallMode::kCallBuiltinPointer);
      const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
          call_descriptor, compiler::CanThrow::kYes,
          compiler::LazyDeoptOnThrow::kNo, __ graph_zone());
      OpIndex call_target =
          GetTargetForBuiltinCall(Builtin::kWasmRethrowExplicitContext);
      V<Context> context =
          __ Load(incoming_params[0], LoadOp::Kind::TaggedBase(),
                  MemoryRepresentation::TaggedPointer(),
                  WasmImportData::kNativeContextOffset);
      __ Call(call_target, {return_value, context}, ts_call_descriptor);
      __ Unreachable();
    }

    DCHECK_LT(sig_->r
```