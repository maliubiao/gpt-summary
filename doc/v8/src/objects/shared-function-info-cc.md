Response:
My thinking process to analyze the provided C++ code snippet for `v8/src/objects/shared-function-info.cc` goes like this:

1. **Understand the Core Purpose:** The filename itself, `shared-function-info.cc`, immediately suggests that this code defines the structure and behavior of `SharedFunctionInfo` objects within the V8 JavaScript engine. I know that V8 compiles and executes JavaScript, and functions are a fundamental part of the language. Therefore, this class likely holds metadata and information about JavaScript functions.

2. **Scan for Key Data Members:** I quickly scan the code for member variables and important methods. I notice:
    * `kNoSharedNameSentinel`: A constant, likely used as a default or sentinel value.
    * `Hash()`:  Indicates a way to identify `SharedFunctionInfo` objects, probably for caching or lookup.
    * `Init()`:  A method for initializing a new `SharedFunctionInfo` object. The initializations here give hints about what information is tracked (e.g., `builtin_id`, `name_or_scope_info`, `script`, `length`).
    * `GetCode()`: This is crucial! It determines the actual executable code associated with a function. The logic within this method, with its checks for `BytecodeArray`, `Code`, `InterpreterData`, `UncompiledData`, and WASM related data, is central to understanding how V8 manages different stages of function compilation and execution.
    * `ScriptIterator`: Suggests a way to iterate through functions associated with a specific script.
    * `SetScript()`:  Indicates that a `SharedFunctionInfo` is linked to a `Script` object.
    * `CopyFrom()`: A method to copy the state of one `SharedFunctionInfo` to another.
    * `HasDebugInfo()`, `GetDebugInfo()`, `HasBreakInfo()`, `HasCoverageInfo()`:  These clearly relate to debugging and code coverage features.
    * `DebugNameCStr()`, `DebugName()`:  Methods for getting the name of the function, likely for debugging and profiling.
    * `PassesFilter()`:  Suggests the ability to filter functions based on their names.
    * `HasSourceCode()`, `GetSourceCode()`, `GetSourceCodeHarmony()`:  Deal with retrieving the original JavaScript source code of the function.
    * `DiscardCompiledMetadata()`, `DiscardCompiled()`:  Mechanisms for discarding compiled code, possibly to reclaim memory or re-compile with different optimizations.
    * `InitFromFunctionLiteral()`, `CreateAndSetUncompiledData()`:  These are vital for understanding how a `SharedFunctionInfo` is created from the Abstract Syntax Tree (AST) representation of a function (represented by `FunctionLiteral`).
    * `UpdateExpectedNofPropertiesFromEstimate()`, `UpdateAndFinalizeExpectedNofPropertiesFromEstimate()`:  Relate to estimating and tracking the number of properties an object created by this function will have, influencing object layout and performance.
    * `SetFunctionTokenPosition()`: Stores source code position information.
    * `StartPosition()`, `EndPosition()`:  Return the start and end positions of the function in the source code.
    * `UpdateFromFunctionLiteralForLiveEdit()`:  Specifically for live editing/hot-reloading scenarios.
    * `EnsureBytecodeArrayAvailable()`, `EnsureSourcePositionsAvailable()`, `InstallDebugBytecode()`: Methods to ensure the necessary compiled code and debugging information are available.

3. **Infer Functionality from Methods and Data:**  Based on the identified members and methods, I can start to infer the key functionalities of `SharedFunctionInfo`:
    * **Metadata Storage:** It holds crucial information about a JavaScript function, such as its name, associated script, parameter count, source code positions, compilation status, and optimization state.
    * **Code Management:**  It acts as a central point for accessing the executable code of a function, whether it's interpreted bytecode, baseline-compiled code, optimized code, or a built-in function.
    * **Compilation Lifecycle:** It tracks the compilation state of a function (uncompiled, bytecode, baseline, optimized) and provides mechanisms for transitioning between these states.
    * **Debugging and Profiling Support:** It provides access to debugging information, break points, and coverage data.
    * **Source Code Access:** It allows retrieval of the original JavaScript source code of the function.
    * **Optimization Control:** It stores information about whether optimization is enabled or disabled and the reasons for disabling it.
    * **Integration with AST:** It's closely linked to the AST representation of functions (`FunctionLiteral`) and is initialized from it.
    * **Live Edit Support:** It has specific mechanisms to handle changes to function definitions during live editing.

4. **Relate to JavaScript Concepts:** I connect the identified functionalities to corresponding JavaScript concepts:
    * Functions in JavaScript have names, parameters, and bodies.
    * JavaScript code is executed. V8 compiles it to machine code.
    * Debuggers allow setting breakpoints and inspecting variables.
    * Code coverage tools track which parts of the code have been executed.
    * JavaScript source code is what the developer writes.
    * Optimizations make code run faster.
    * Live editing allows modifying code while the application is running.

5. **Consider Edge Cases and Error Handling:** Although the snippet doesn't show explicit error handling, I consider potential issues:
    * What happens if compilation fails? The `GetCode()` method seems to handle different compilation states.
    * How are built-in functions handled?  The `builtin_id` and checks for `IsBuiltin` are relevant here.
    * What about asynchronous functions or generators?  While not explicitly shown, the framework likely supports these concepts.

6. **Formulate a Summary:** Based on the analysis, I formulate a concise summary of the functionality, highlighting the key roles of `SharedFunctionInfo`.

7. **Address Specific Questions:**  I then go back and address the specific questions asked in the prompt:
    * **Functionality Listing:** I create a bulleted list of the key functions.
    * **Torque Source:** I check the filename extension. Since it's `.cc`, it's not a Torque file.
    * **JavaScript Relation and Examples:** I provide JavaScript code examples that illustrate the concepts related to the functionality of `SharedFunctionInfo`, such as function declaration, calling functions, debugging, and examining function properties.
    * **Code Logic Inference (Hypothetical Input/Output):** I create a simple scenario to demonstrate how `GetCode()` might behave based on the compilation state.
    * **Common Programming Errors:** I think about common JavaScript errors related to functions, such as incorrect number of arguments, using `this` incorrectly, and accessing undefined variables, and how V8's internal mechanisms might relate to catching these errors.

8. **Refine and Organize:** Finally, I review my analysis and organize it logically to present a clear and comprehensive understanding of the `SharedFunctionInfo` class.
这是对 V8 引擎源代码文件 `v8/src/objects/shared-function-info.cc` 的第一部分分析。

**功能归纳：**

`v8/src/objects/shared-function-info.cc` 文件定义了 `SharedFunctionInfo` 类，这个类在 V8 JavaScript 引擎中扮演着至关重要的角色，它存储了 **关于函数的元数据和共享信息**。  可以将其视为函数对象的“蓝图”或“模板”。多个函数实例可以共享同一个 `SharedFunctionInfo` 对象。

其核心功能可以归纳为：

* **存储函数的基本信息：**  例如函数名、参数个数、起始和结束位置、函数在源代码中的 token 位置、语法类型（普通函数、箭头函数等）、语言模式（严格模式等）。
* **管理函数的编译状态：**  它记录了函数是否已编译，以及编译到了哪个阶段（未编译、已编译为字节码、已编译为机器码等）。
* **关联函数的代码：**  `SharedFunctionInfo` 负责找到与函数关联的可执行代码，无论是解释器执行的字节码，还是经过优化的机器码。 `GetCode()` 方法就是实现这个功能的关键。
* **维护函数的调试信息：**  它关联了函数的调试信息（例如断点、单步执行等），通过 `DebugInfo` 类进行管理。
* **跟踪函数的优化状态：**  记录函数是否被禁用优化，以及禁用的原因。
* **关联函数的源代码：**  它指向包含函数源代码的 `Script` 对象，并存储了函数在源代码中的起始和结束位置，方便获取函数的源代码。
* **支持代码热更新 (LiveEdit)：** 提供了在代码修改后更新 `SharedFunctionInfo` 的机制。
* **管理函数的属性预估：** 存储了对函数创建的对象属性数量的预估，用于优化对象内存分配。
* **作为脚本中函数的索引：**  通过 `ScriptIterator` 可以遍历一个脚本中所有的 `SharedFunctionInfo` 对象。

**关于文件类型：**

由于文件以 `.cc` 结尾，它是一个 **V8 C++ 源代码** 文件，而不是 Torque 源代码。Torque 源代码通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及示例：**

`SharedFunctionInfo` 存储的信息直接关系到 JavaScript 函数的各个方面。

```javascript
function myFunction(a, b) {
  console.log(a + b);
}

// 当 JavaScript 引擎解析并编译上面的函数时，会创建一个 SharedFunctionInfo 对象来存储关于 myFunction 的信息。

// 例如，SharedFunctionInfo 会存储：
// - 函数名: "myFunction"
// - 参数个数: 2
// - 函数在源代码中的位置（起始行号、列号，结束行号、列号）
// - 函数的字节码（如果已经编译为字节码）
// - 指向包含该函数源代码的 Script 对象的指针

// 当调用 myFunction 时，V8 引擎会使用其对应的 SharedFunctionInfo 对象来获取执行所需的各种信息，
// 例如找到函数的代码入口点。
```

**代码逻辑推理 (假设输入与输出)：**

考虑 `GetCode(Isolate* isolate)` 方法，假设有以下输入：

**假设输入 1：**  一个 `SharedFunctionInfo` 对象，其 `trusted_data_` 指向一个 `BytecodeArray` 对象。

**预期输出 1：**  `GetCode()` 方法应该返回解释器入口点的 `Code` 对象 (`Builtin::kInterpreterEntryTrampoline`)，因为该函数已经编译为字节码，需要通过解释器执行。

**假设输入 2：**  一个 `SharedFunctionInfo` 对象，其 `trusted_data_` 指向 `Smi::zero()`，且其 `untrusted_data_` 指向一个表示内置函数的 `Smi`。

**预期输出 2：** `GetCode()` 方法应该返回对应内置函数的 `Code` 对象，例如 `isolate->builtins()->code(builtin_id())`。

**用户常见的编程错误举例说明：**

虽然 `shared-function-info.cc` 本身不直接处理用户代码错误，但它存储的信息与运行时错误密切相关。 例如：

* **参数数量错误：**  `SharedFunctionInfo` 存储了函数的预期参数个数。当用户调用函数时传递了错误数量的参数，V8 引擎可以通过 `SharedFunctionInfo` 中存储的信息来检测并抛出 `TypeError`。

  ```javascript
  function add(a, b) {
    return a + b;
  }

  add(1); // 常见错误：传递的参数太少，与 add 函数的 SharedFunctionInfo 中记录的参数个数不符。
  add(1, 2, 3); // 常见错误：传递的参数太多。
  ```

* **`this` 指向错误：**  虽然 `SharedFunctionInfo` 本身不直接决定 `this` 的指向，但它存储了函数的类型（例如是否是箭头函数），这会影响 `this` 的绑定规则。错误地理解或使用 `this` 是常见的编程错误。

  ```javascript
  const myObject = {
    value: 10,
    getValue: function() {
      return this.value; // 'this' 指向 myObject
    },
    getArrowValue: () => {
      return this.value; // 'this' 指向外层作用域 (通常是 window 或 undefined)
    }
  };

  console.log(myObject.getValue()); // 输出 10
  console.log(myObject.getArrowValue()); // 输出 undefined 或报错，取决于运行环境

  // V8 引擎在执行 `getArrowValue` 时，会根据其 SharedFunctionInfo 中记录的箭头函数类型，
  // 确定 'this' 的绑定方式。
  ```

**总结 (针对第 1 部分)：**

`v8/src/objects/shared-function-info.cc` 定义了 `SharedFunctionInfo` 类，它是 V8 引擎中用于存储和管理 JavaScript 函数元数据和共享信息的关键数据结构。它关联了函数的名称、参数、源代码位置、编译状态、代码入口点、调试信息和优化状态，为 V8 引擎执行和管理 JavaScript 函数提供了必要的信息。它不是 Torque 源代码，并与 JavaScript 函数的各种功能紧密相关。

### 提示词
```
这是目录为v8/src/objects/shared-function-info.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/shared-function-info.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/shared-function-info.h"

#include <optional>

#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/debug/debug.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/isolate-utils.h"
#include "src/heap/combined-heap.h"
#include "src/objects/shared-function-info-inl.h"
#include "src/strings/string-builder-inl.h"

namespace v8::internal {

V8_EXPORT_PRIVATE constexpr Tagged<Smi>
    SharedFunctionInfo::kNoSharedNameSentinel;

uint32_t SharedFunctionInfo::Hash() {
  // Hash SharedFunctionInfo based on its start position and script id. Note: we
  // don't use the function's literal id since getting that is slow for compiled
  // functions.
  int start_pos = StartPosition();
  int script_id = IsScript(script()) ? Cast<Script>(script())->id() : 0;
  return static_cast<uint32_t>(base::hash_combine(start_pos, script_id));
}

void SharedFunctionInfo::Init(ReadOnlyRoots ro_roots, int unique_id) {
  DisallowGarbageCollection no_gc;

  // Set the function data to the "illegal" builtin. Ideally we'd use some sort
  // of "uninitialized" marker here, but it's cheaper to use a valid buitin and
  // avoid having to do uninitialized checks elsewhere.
  set_builtin_id(Builtin::kIllegal);

  // Set the name to the no-name sentinel, this can be updated later.
  set_name_or_scope_info(SharedFunctionInfo::kNoSharedNameSentinel,
                         kReleaseStore, SKIP_WRITE_BARRIER);
  set_more_scope_info_interface_name(ro_roots.empty_string(), SKIP_WRITE_BARRIER);
  set_more_scope_info_class_name(ro_roots.empty_string(), SKIP_WRITE_BARRIER);
  // Generally functions won't have feedback, unless they have been created
  // from a FunctionLiteral. Those can just reset this field to keep the
  // SharedFunctionInfo in a consistent state.
  set_raw_outer_scope_info_or_feedback_metadata(ro_roots.the_hole_value(),
                                                SKIP_WRITE_BARRIER);
  set_script(ro_roots.undefined_value(), kReleaseStore, SKIP_WRITE_BARRIER);
  set_function_literal_id(kInvalidInfoId);
  set_unique_id(unique_id);

  // Set integer fields (smi or int, depending on the architecture).
  set_length(0);
  set_internal_formal_parameter_count(JSParameterCount(0));
  set_expected_nof_properties(0);
  set_raw_function_token_offset(0);

  // All flags default to false or 0, except ConstructAsBuiltinBit just because
  // we're using the kIllegal builtin.
  set_flags(ConstructAsBuiltinBit::encode(true), kRelaxedStore);
  set_flags2(0);
  set_hook_flag(0);

  UpdateFunctionMapIndex();

  set_age(0);

  clear_padding();
}

Tagged<Code> SharedFunctionInfo::GetCode(Isolate* isolate) const {
  // ======
  // NOTE: This chain of checks MUST be kept in sync with the equivalent CSA
  // GetSharedFunctionInfoCode method in code-stub-assembler.cc.
  // ======

  Tagged<Object> data = GetTrustedData(isolate);
  if (data != Smi::zero()) {
    DCHECK(HasTrustedData());

    if (IsBytecodeArray(data)) {
      // Having a bytecode array means we are a compiled, interpreted function.
      DCHECK(HasBytecodeArray());
      return isolate->builtins()->code(Builtin::kInterpreterEntryTrampoline);
    }
    if (IsCode(data)) {
      // Having baseline Code means we are a compiled, baseline function.
      DCHECK(HasBaselineCode());
      return Cast<Code>(data);
    }
    if (IsInterpreterData(data)) {
      Tagged<Code> code = InterpreterTrampoline(isolate);
      DCHECK(IsCode(code));
      DCHECK(code->is_interpreter_trampoline_builtin());
      return code;
    }
    if (IsUncompiledData(data)) {
      // Having uncompiled data (with or without scope) means we need to
      // compile.
      DCHECK(HasUncompiledData());
      return isolate->builtins()->code(Builtin::kCompileLazy);
    }
#if V8_ENABLE_WEBASSEMBLY
    if (IsWasmExportedFunctionData(data)) {
      // Having a WasmExportedFunctionData means the code is in there.
      DCHECK(HasWasmExportedFunctionData());
      return wasm_exported_function_data()->wrapper_code(isolate);
    }
    if (IsWasmJSFunctionData(data)) {
      return wasm_js_function_data()->wrapper_code(isolate);
    }
    if (IsWasmCapiFunctionData(data)) {
      return wasm_capi_function_data()->wrapper_code(isolate);
    }
#endif  // V8_ENABLE_WEBASSEMBLY
  } else {
    DCHECK(HasUntrustedData());
    data = GetUntrustedData();

    if (IsSmi(data)) {
      // Holding a Smi means we are a builtin.
      DCHECK(HasBuiltinId());
      return isolate->builtins()->code(builtin_id());
    }
    if (IsFunctionTemplateInfo(data)) {
      // Having a function template info means we are an API function.
      DCHECK(IsApiFunction());
      return isolate->builtins()->code(Builtin::kHandleApiCallOrConstruct);
    }
#if V8_ENABLE_WEBASSEMBLY
    if (IsAsmWasmData(data)) {
      // Having AsmWasmData means we are an asm.js/wasm function.
      DCHECK(HasAsmWasmData());
      return isolate->builtins()->code(Builtin::kInstantiateAsmJs);
    }
    if (IsWasmResumeData(data)) {
      if (static_cast<wasm::OnResume>(wasm_resume_data()->on_resume()) ==
          wasm::OnResume::kContinue) {
        return isolate->builtins()->code(Builtin::kWasmResume);
      } else {
        return isolate->builtins()->code(Builtin::kWasmReject);
      }
    }
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  UNREACHABLE();
}

SharedFunctionInfo::ScriptIterator::ScriptIterator(Isolate* isolate,
                                                   Tagged<Script> script)
    : ScriptIterator(handle(script->infos(), isolate)) {}

SharedFunctionInfo::ScriptIterator::ScriptIterator(Handle<WeakFixedArray> infos)
    : infos_(infos), index_(0) {}

Tagged<SharedFunctionInfo> SharedFunctionInfo::ScriptIterator::Next() {
  while (index_ < infos_->length()) {
    Tagged<MaybeObject> raw = infos_->get(index_++);
    Tagged<HeapObject> heap_object;
    if (!raw.GetHeapObject(&heap_object) ||
        !IsSharedFunctionInfo(heap_object)) {
      continue;
    }
    return Cast<SharedFunctionInfo>(heap_object);
  }
  return SharedFunctionInfo();
}

void SharedFunctionInfo::ScriptIterator::Reset(Isolate* isolate,
                                               Tagged<Script> script) {
  infos_ = handle(script->infos(), isolate);
  index_ = 0;
}

void SharedFunctionInfo::SetScript(IsolateForSandbox isolate,
                                   ReadOnlyRoots roots,
                                   Tagged<HeapObject> script_object,
                                   int function_literal_id,
                                   bool reset_preparsed_scope_data) {
  DisallowGarbageCollection no_gc;

  if (script() == script_object) return;

  if (reset_preparsed_scope_data && HasUncompiledDataWithPreparseData()) {
    ClearPreparseData(isolate);
  }

  // Add shared function info to new script's list. If a collection occurs,
  // the shared function info may be temporarily in two lists.
  // This is okay because the gc-time processing of these lists can tolerate
  // duplicates.
  if (IsScript(script_object)) {
    DCHECK(!IsScript(script()));
    Tagged<Script> script = Cast<Script>(script_object);
    Tagged<WeakFixedArray> list = script->infos();
#ifdef DEBUG
    DCHECK_LT(function_literal_id, list->length());
    Tagged<MaybeObject> maybe_object = list->get(function_literal_id);
    Tagged<HeapObject> heap_object;
    if (maybe_object.GetHeapObjectIfWeak(&heap_object)) {
      DCHECK_EQ(heap_object, *this);
    }
#endif
    list->set(function_literal_id, MakeWeak(Tagged(*this)));
  } else {
    DCHECK(IsScript(script()));

    // Remove shared function info from old script's list.
    Tagged<Script> old_script = Cast<Script>(script());

    // Due to liveedit, it might happen that the old_script doesn't know
    // about the SharedFunctionInfo, so we have to guard against that.
    Tagged<WeakFixedArray> infos = old_script->infos();
    if (function_literal_id < infos->length()) {
      Tagged<MaybeObject> raw = old_script->infos()->get(function_literal_id);
      Tagged<HeapObject> heap_object;
      if (raw.GetHeapObjectIfWeak(&heap_object) && heap_object == *this) {
        old_script->infos()->set(function_literal_id, roots.undefined_value());
      }
    }
  }

  // Finally set new script.
  set_script(script_object, kReleaseStore);
}

void SharedFunctionInfo::CopyFrom(Tagged<SharedFunctionInfo> other,
                                  IsolateForSandbox isolate) {
  if (other->HasTrustedData()) {
    SetTrustedData(Cast<ExposedTrustedObject>(other->GetTrustedData(isolate)));
  } else {
    SetUntrustedData(other->GetUntrustedData());
  }

  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);
  set_name_or_scope_info(other->name_or_scope_info(cage_base, kAcquireLoad),
                         kReleaseStore);
  set_outer_scope_info_or_feedback_metadata(
      other->outer_scope_info_or_feedback_metadata(cage_base));
  set_script(other->script(cage_base, kAcquireLoad), kReleaseStore);

  set_length(other->length());
  set_formal_parameter_count(other->formal_parameter_count());
  set_function_token_offset(other->function_token_offset());
  set_expected_nof_properties(other->expected_nof_properties());
  set_flags2(other->flags2());
  set_flags(other->flags(kRelaxedLoad), kRelaxedStore);
  set_function_literal_id(other->function_literal_id());
  set_unique_id(other->unique_id());
  set_age(0);

#if DEBUG
  // This should now be byte-for-byte identical to the input except for the age
  // field (could be reset concurrently). Compare content before age field now:
  DCHECK_EQ(memcmp(reinterpret_cast<void*>(address()),
                   reinterpret_cast<void*>(other.address()),
                   SharedFunctionInfo::kAgeOffset),
            0);
  // Compare content after age field.
  constexpr Address kPastAgeOffset =
      SharedFunctionInfo::kAgeOffset + SharedFunctionInfo::kAgeSize;
  DCHECK_EQ(memcmp(reinterpret_cast<void*>(address() + kPastAgeOffset),
                   reinterpret_cast<void*>(other.address() + kPastAgeOffset),
                   SharedFunctionInfo::kSize - kPastAgeOffset),
            0);
#endif
}

bool SharedFunctionInfo::HasDebugInfo(Isolate* isolate) const {
  return isolate->debug()->HasDebugInfo(*this);
}

// Needs to be kept in sync with Scope::UniqueIdInScript and
// ScopeInfo::UniqueIdInScript.
int SharedFunctionInfo::UniqueIdInScript() const {
  // Script scopes start "before" the script to avoid clashing with a scope that
  // starts on character 0.
  if (function_literal_id() == kFunctionLiteralIdTopLevel) return -2;
  // Wrapped functions start before the function body, but after the script
  // start, to avoid clashing with a scope starting on character 0.
  if (syntax_kind() == FunctionSyntaxKind::kWrapped) return -1;
  // Default constructors have the same start position as their parent class
  // scope. Use the next char position to distinguish this scope.
  return StartPosition() + IsDefaultConstructor(kind());
}

Tagged<DebugInfo> SharedFunctionInfo::GetDebugInfo(Isolate* isolate) const {
  return isolate->debug()->TryGetDebugInfo(*this).value();
}

std::optional<Tagged<DebugInfo>> SharedFunctionInfo::TryGetDebugInfo(
    Isolate* isolate) const {
  return isolate->debug()->TryGetDebugInfo(*this);
}

bool SharedFunctionInfo::HasBreakInfo(Isolate* isolate) const {
  return isolate->debug()->HasBreakInfo(*this);
}

bool SharedFunctionInfo::BreakAtEntry(Isolate* isolate) const {
  return isolate->debug()->BreakAtEntry(*this);
}

bool SharedFunctionInfo::HasCoverageInfo(Isolate* isolate) const {
  return isolate->debug()->HasCoverageInfo(*this);
}

Tagged<CoverageInfo> SharedFunctionInfo::GetCoverageInfo(
    Isolate* isolate) const {
  DCHECK(HasCoverageInfo(isolate));
  return Cast<CoverageInfo>(GetDebugInfo(isolate)->coverage_info());
}

std::unique_ptr<char[]> SharedFunctionInfo::DebugNameCStr() const {
#if V8_ENABLE_WEBASSEMBLY
  if (HasWasmExportedFunctionData()) {
    return WasmExportedFunction::GetDebugName(
        wasm_exported_function_data()->sig());
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  DisallowGarbageCollection no_gc;
  Tagged<String> function_name = Name();
  if (function_name->length() == 0) function_name = inferred_name();
  return function_name->ToCString();
}

// static
Handle<String> SharedFunctionInfo::DebugName(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
#if V8_ENABLE_WEBASSEMBLY
  if (shared->HasWasmExportedFunctionData()) {
    return isolate->factory()
        ->NewStringFromUtf8(base::CStrVector(shared->DebugNameCStr().get()))
        .ToHandleChecked();
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  FunctionKind function_kind = shared->kind();
  if (IsClassMembersInitializerFunction(function_kind)) {
    return function_kind == FunctionKind::kClassMembersInitializerFunction
               ? isolate->factory()->instance_members_initializer_string()
               : isolate->factory()->static_initializer_string();
  }
  DisallowHeapAllocation no_gc;
  Tagged<String> function_name = shared->Name();
  if (function_name->length() == 0) function_name = shared->inferred_name();
  return handle(function_name, isolate);
}

bool SharedFunctionInfo::PassesFilter(const char* raw_filter) {
  // Filters are almost always "*", so check for that and exit quickly.
  if (V8_LIKELY(raw_filter[0] == '*' && raw_filter[1] == '\0')) {
    return true;
  }
  base::Vector<const char> filter = base::CStrVector(raw_filter);
  return v8::internal::PassesFilter(base::CStrVector(DebugNameCStr().get()),
                                    filter);
}

bool SharedFunctionInfo::HasSourceCode() const {
  ReadOnlyRoots roots = GetReadOnlyRoots();
  return !IsUndefined(script(), roots) &&
         !IsUndefined(Cast<Script>(script())->source(), roots) &&
         Cast<String>(Cast<Script>(script())->source())->length() > 0;
}

void SharedFunctionInfo::DiscardCompiledMetadata(
    Isolate* isolate,
    std::function<void(Tagged<HeapObject> object, ObjectSlot slot,
                       Tagged<HeapObject> target)>
        gc_notify_updated_slot) {
  DisallowGarbageCollection no_gc;
  if (HasFeedbackMetadata()) {
    if (v8_flags.trace_flush_code) {
      CodeTracer::Scope scope(isolate->GetCodeTracer());
      PrintF(scope.file(), "[discarding compiled metadata for ");
      ShortPrint(*this, scope.file());
      PrintF(scope.file(), "]\n");
    }

    Tagged<HeapObject> outer_scope_info;
    if (scope_info()->HasOuterScopeInfo()) {
      outer_scope_info = scope_info()->OuterScopeInfo();
    } else {
      outer_scope_info = ReadOnlyRoots(isolate).the_hole_value();
    }

    // Raw setter to avoid validity checks, since we're performing the unusual
    // task of decompiling.
    set_raw_outer_scope_info_or_feedback_metadata(outer_scope_info);
    gc_notify_updated_slot(
        *this,
        RawField(SharedFunctionInfo::kOuterScopeInfoOrFeedbackMetadataOffset),
        outer_scope_info);
  } else {
    DCHECK(IsScopeInfo(outer_scope_info()) || IsTheHole(outer_scope_info()));
  }

  // TODO(rmcilroy): Possibly discard ScopeInfo here as well.
}

// static
void SharedFunctionInfo::DiscardCompiled(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared_info) {
  DCHECK(shared_info->CanDiscardCompiled());

  Handle<String> inferred_name_val(shared_info->inferred_name(), isolate);
  int start_position = shared_info->StartPosition();
  int end_position = shared_info->EndPosition();

  MaybeHandle<UncompiledData> data;
  if (!shared_info->HasUncompiledDataWithPreparseData()) {
    // Create a new UncompiledData, without pre-parsed scope.
    data = isolate->factory()->NewUncompiledDataWithoutPreparseData(
        inferred_name_val, start_position, end_position);
  }

  // If the GC runs after changing one but not both fields below, it could see
  // the SharedFunctionInfo in an unexpected state.
  DisallowGarbageCollection no_gc;

  shared_info->DiscardCompiledMetadata(isolate);

  // Replace compiled data with a new UncompiledData object.
  if (shared_info->HasUncompiledDataWithPreparseData()) {
    // If this is uncompiled data with a pre-parsed scope data, we can just
    // clear out the scope data and keep the uncompiled data.
    shared_info->ClearPreparseData(isolate);
    DCHECK(data.is_null());
  } else {
    // Update the function data to point to the UncompiledData without preparse
    // data created above. Use the raw function data setter to avoid validity
    // checks, since we're performing the unusual task of decompiling.
    shared_info->SetTrustedData(*data.ToHandleChecked());
  }
}

// static
Handle<Object> SharedFunctionInfo::GetSourceCode(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
  if (!shared->HasSourceCode()) return isolate->factory()->undefined_value();
  Handle<String> source(Cast<String>(Cast<Script>(shared->script())->source()),
                        isolate);
  return isolate->factory()->NewSubString(source, shared->StartPosition(),
                                          shared->EndPosition());
}

// static
Handle<Object> SharedFunctionInfo::GetSourceCodeHarmony(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared) {
  if (!shared->HasSourceCode()) return isolate->factory()->undefined_value();
  Handle<String> script_source(
      Cast<String>(Cast<Script>(shared->script())->source()), isolate);
  int start_pos = shared->function_token_position();
  DCHECK_NE(start_pos, kNoSourcePosition);
  Handle<String> source = isolate->factory()->NewSubString(
      script_source, start_pos, shared->EndPosition());
  if (!shared->is_wrapped()) return source;

  DCHECK(!shared->name_should_print_as_anonymous());
  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("function ");
  builder.AppendString(Handle<String>(shared->Name(), isolate));
  builder.AppendCharacter('(');
  DirectHandle<FixedArray> args(
      Cast<Script>(shared->script())->wrapped_arguments(), isolate);
  int argc = args->length();
  for (int i = 0; i < argc; i++) {
    if (i > 0) builder.AppendCStringLiteral(", ");
    builder.AppendString(Handle<String>(Cast<String>(args->get(i)), isolate));
  }
  builder.AppendCStringLiteral(") {\n");
  builder.AppendString(source);
  builder.AppendCStringLiteral("\n}");
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

int SharedFunctionInfo::SourceSize() { return EndPosition() - StartPosition(); }

// Output the source code without any allocation in the heap.
std::ostream& operator<<(std::ostream& os, const SourceCodeOf& v) {
  const Tagged<SharedFunctionInfo> s = v.value;
  // For some native functions there is no source.
  if (!s->HasSourceCode()) return os << "<No Source>";

  // Get the source for the script which this function came from.
  // Don't use Cast<String> because we don't want more assertion errors while
  // we are already creating a stack dump.
  Tagged<String> script_source =
      UncheckedCast<String>(Cast<Script>(s->script())->source());

  if (!s->is_toplevel()) {
    os << "function ";
    Tagged<String> name = s->Name();
    if (name->length() > 0) {
      name->PrintUC16(os);
    }
  }

  int len = s->EndPosition() - s->StartPosition();
  if (len <= v.max_length || v.max_length < 0) {
    script_source->PrintUC16(os, s->StartPosition(), s->EndPosition());
    return os;
  } else {
    script_source->PrintUC16(os, s->StartPosition(),
                             s->StartPosition() + v.max_length);
    return os << "...\n";
  }
}

void SharedFunctionInfo::DisableOptimization(Isolate* isolate,
                                             BailoutReason reason) {
  DCHECK_NE(reason, BailoutReason::kNoReason);

  set_flags(DisabledOptimizationReasonBits::update(flags(kRelaxedLoad), reason),
            kRelaxedStore);
  // Code should be the lazy compilation stub or else interpreted.
  if constexpr (DEBUG_BOOL) {
    CodeKind kind = abstract_code(isolate)->kind(isolate);
    CHECK(kind == CodeKind::INTERPRETED_FUNCTION || kind == CodeKind::BUILTIN);
  }
  PROFILE(isolate, CodeDisableOptEvent(handle(abstract_code(isolate), isolate),
                                       handle(*this, isolate)));
  if (v8_flags.trace_opt) {
    CodeTracer::Scope scope(isolate->GetCodeTracer());
    PrintF(scope.file(), "[disabled optimization for ");
    ShortPrint(*this, scope.file());
    PrintF(scope.file(), ", reason: %s]\n", GetBailoutReason(reason));
  }
}

// static
template <typename IsolateT>
void SharedFunctionInfo::InitFromFunctionLiteral(IsolateT* isolate,
                                                 FunctionLiteral* lit,
                                                 bool is_toplevel) {
  DCHECK(!IsScopeInfo(
      lit->shared_function_info()->name_or_scope_info(kAcquireLoad)));
  {
    DisallowGarbageCollection no_gc;
    Tagged<SharedFunctionInfo> raw_sfi = *lit->shared_function_info();
    DCHECK_EQ(raw_sfi->function_literal_id(), lit->function_literal_id());
    // When adding fields here, make sure DeclarationScope::AnalyzePartially is
    // updated accordingly.
    raw_sfi->set_internal_formal_parameter_count(
        JSParameterCount(lit->parameter_count()));
    raw_sfi->SetFunctionTokenPosition(lit->function_token_position(),
                                      lit->start_position());
    raw_sfi->set_syntax_kind(lit->syntax_kind());
    raw_sfi->set_allows_lazy_compilation(lit->AllowsLazyCompilation());
    raw_sfi->set_language_mode(lit->language_mode());
    // FunctionKind must have already been set.
    DCHECK(lit->kind() == raw_sfi->kind());
    DCHECK_IMPLIES(lit->requires_instance_members_initializer(),
                   IsClassConstructor(lit->kind()));
    raw_sfi->set_requires_instance_members_initializer(
        lit->requires_instance_members_initializer());
    DCHECK_IMPLIES(lit->class_scope_has_private_brand(),
                   IsClassConstructor(lit->kind()));
    raw_sfi->set_class_scope_has_private_brand(
        lit->class_scope_has_private_brand());
    DCHECK_IMPLIES(lit->has_static_private_methods_or_accessors(),
                   IsClassConstructor(lit->kind()));
    raw_sfi->set_has_static_private_methods_or_accessors(
        lit->has_static_private_methods_or_accessors());

    raw_sfi->set_is_toplevel(is_toplevel);
    DCHECK(IsTheHole(raw_sfi->outer_scope_info()));
    Scope* outer_scope = lit->scope()->GetOuterScopeWithContext();
    if (outer_scope && (!is_toplevel || !outer_scope->is_script_scope())) {
      raw_sfi->set_outer_scope_info(*outer_scope->scope_info());
      raw_sfi->set_private_name_lookup_skips_outer_class(
          lit->scope()->private_name_lookup_skips_outer_class());
    }
    if (lit->scope()->is_reparsed()) {
      raw_sfi->SetScopeInfo(*lit->scope()->scope_info());
    }

    raw_sfi->set_length(lit->function_length());

    // For lazy parsed functions, the following flags will be inaccurate since
    // we don't have the information yet. They're set later in
    // UpdateSharedFunctionFlagsAfterCompilation (compiler.cc), when the
    // function is really parsed and compiled.
    if (lit->ShouldEagerCompile()) {
      raw_sfi->set_has_duplicate_parameters(lit->has_duplicate_parameters());
      raw_sfi->UpdateAndFinalizeExpectedNofPropertiesFromEstimate(lit);
      DCHECK_NULL(lit->produced_preparse_data());

      // If we're about to eager compile, we'll have the function literal
      // available, so there's no need to wastefully allocate an uncompiled
      // data.
      return;
    }

    raw_sfi->UpdateExpectedNofPropertiesFromEstimate(lit);
  }
  CreateAndSetUncompiledData(isolate, lit);
}

template <typename IsolateT>
void SharedFunctionInfo::CreateAndSetUncompiledData(IsolateT* isolate,
                                                    FunctionLiteral* lit) {
  DCHECK(!lit->shared_function_info()->HasUncompiledData());
  Handle<UncompiledData> data;
  ProducedPreparseData* scope_data = lit->produced_preparse_data();
  if (scope_data != nullptr) {
    Handle<PreparseData> preparse_data = scope_data->Serialize(isolate);

    if (lit->should_parallel_compile()) {
      data = isolate->factory()->NewUncompiledDataWithPreparseDataAndJob(
          lit->GetInferredName(isolate), lit->start_position(),
          lit->end_position(), preparse_data);
    } else {
      data = isolate->factory()->NewUncompiledDataWithPreparseData(
          lit->GetInferredName(isolate), lit->start_position(),
          lit->end_position(), preparse_data);
    }
  } else {
    if (lit->should_parallel_compile()) {
      data = isolate->factory()->NewUncompiledDataWithoutPreparseDataWithJob(
          lit->GetInferredName(isolate), lit->start_position(),
          lit->end_position());
    } else {
      data = isolate->factory()->NewUncompiledDataWithoutPreparseData(
          lit->GetInferredName(isolate), lit->start_position(),
          lit->end_position());
    }
  }

  lit->shared_function_info()->set_uncompiled_data(*data);
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void SharedFunctionInfo::
    InitFromFunctionLiteral<Isolate>(Isolate* isolate,
                                     FunctionLiteral* lit, bool is_toplevel);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void SharedFunctionInfo::
    InitFromFunctionLiteral<LocalIsolate>(LocalIsolate* isolate,
                                          FunctionLiteral* lit,
                                          bool is_toplevel);

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void SharedFunctionInfo::
    CreateAndSetUncompiledData<Isolate>(Isolate* isolate, FunctionLiteral* lit);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void SharedFunctionInfo::
    CreateAndSetUncompiledData<LocalIsolate>(LocalIsolate* isolate,
                                             FunctionLiteral* lit);

uint16_t SharedFunctionInfo::get_property_estimate_from_literal(
    FunctionLiteral* literal) {
  int estimate = literal->expected_property_count();

  // If this is a class constructor, we may have already parsed fields.
  if (is_class_constructor()) {
    estimate += expected_nof_properties();
  }
  return estimate;
}

void SharedFunctionInfo::UpdateExpectedNofPropertiesFromEstimate(
    FunctionLiteral* literal) {
  // Limit actual estimate to fit in a 8 bit field, we will never allocate
  // more than this in any case.
  static_assert(JSObject::kMaxInObjectProperties <= kMaxUInt8);
  int estimate = get_property_estimate_from_literal(literal);
  set_expected_nof_properties(std::min(estimate, kMaxUInt8));
}

void SharedFunctionInfo::UpdateAndFinalizeExpectedNofPropertiesFromEstimate(
    FunctionLiteral* literal) {
  DCHECK(literal->ShouldEagerCompile());
  if (are_properties_final()) {
    return;
  }
  int estimate = get_property_estimate_from_literal(literal);

  // If no properties are added in the constructor, they are more likely
  // to be added later.
  if (estimate == 0) estimate = 2;

  // Limit actual estimate to fit in a 8 bit field, we will never allocate
  // more than this in any case.
  static_assert(JSObject::kMaxInObjectProperties <= kMaxUInt8);
  estimate = std::min(estimate, kMaxUInt8);

  set_expected_nof_properties(estimate);
  set_are_properties_final(true);
}

void SharedFunctionInfo::SetFunctionTokenPosition(int function_token_position,
                                                  int start_position) {
  int offset;
  if (function_token_position == kNoSourcePosition) {
    offset = 0;
  } else {
    offset = start_position - function_token_position;
  }

  if (offset > kMaximumFunctionTokenOffset) {
    offset = kFunctionTokenOutOfRange;
  }
  set_raw_function_token_offset(offset);
}

int SharedFunctionInfo::StartPosition() const {
  Tagged<Object> maybe_scope_info = name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(maybe_scope_info)) {
    Tagged<ScopeInfo> info = Cast<ScopeInfo>(maybe_scope_info);
    if (info->HasPositionInfo()) {
      return info->StartPosition();
    }
  }
  if (HasUncompiledData()) {
    // Works with or without scope.
    return uncompiled_data(GetIsolateForSandbox(*this))->start_position();
  }
  if (IsApiFunction() || HasBuiltinId()) {
    DCHECK_IMPLIES(HasBuiltinId(), builtin_id() != Builtin::kCompileLazy);
    return 0;
  }
#if V8_ENABLE_WEBASSEMBLY
  if (HasWasmExportedFunctionData()) {
    Tagged<WasmTrustedInstanceData> instance_data =
        wasm_exported_function_data()->instance_data();
    int func_index = wasm_exported_function_data()->function_index();
    auto& function = instance_data->module()->functions[func_index];
    return static_cast<int>(function.code.offset());
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  return kNoSourcePosition;
}

int SharedFunctionInfo::EndPosition() const {
  Tagged<Object> maybe_scope_info = name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(maybe_scope_info)) {
    Tagged<ScopeInfo> info = Cast<ScopeInfo>(maybe_scope_info);
    if (info->HasPositionInfo()) {
      return info->EndPosition();
    }
  }
  if (HasUncompiledData()) {
    // Works with or without scope.
    return uncompiled_data(GetIsolateForSandbox(*this))->end_position();
  }
  if (IsApiFunction() || HasBuiltinId()) {
    DCHECK_IMPLIES(HasBuiltinId(), builtin_id() != Builtin::kCompileLazy);
    return 0;
  }
#if V8_ENABLE_WEBASSEMBLY
  if (HasWasmExportedFunctionData()) {
    Tagged<WasmTrustedInstanceData> instance_data =
        wasm_exported_function_data()->instance_data();
    int func_index = wasm_exported_function_data()->function_index();
    auto& function = instance_data->module()->functions[func_index];
    return static_cast<int>(function.code.end_offset());
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  return kNoSourcePosition;
}

void SharedFunctionInfo::UpdateFromFunctionLiteralForLiveEdit(
    IsolateForSandbox isolate, FunctionLiteral* lit) {
  Tagged<Object> maybe_scope_info = name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(maybe_scope_info)) {
    // Updating the ScopeInfo is safe since they are identical modulo
    // source positions.
    Tagged<ScopeInfo> new_scope_info = *lit->scope()->scope_info();
    DCHECK(new_scope_info->Equals(Cast<ScopeInfo>(maybe_scope_info), true));
    SetScopeInfo(new_scope_info);
  } else if (!is_compiled()) {
    CHECK(HasUncompiledData());
    if (HasUncompiledDataWithPreparseData()) {
      ClearPreparseData(isolate);
    }
    uncompiled_data(isolate)->set_start_position(lit->start_position());
    uncompiled_data(isolate)->set_end_position(lit->end_position());

    if (!is_toplevel()) {
      Scope* outer_scope = lit->scope()->GetOuterScopeWithContext();
      if (outer_scope) {
        // Use the raw accessor since we have to replace the existing outer
        // scope.
        set_raw_outer_scope_info_or_feedback_metadata(
            *outer_scope->scope_info());
      }
    }
  }
  SetFunctionTokenPosition(lit->function_token_position(),
                           lit->start_position());
}

CachedTieringDecision SharedFunctionInfo::cached_tiering_decision() {
  return CachedTieringDecisionBits::decode(flags2());
}

void SharedFunctionInfo::set_cached_tiering_decision(
    CachedTieringDecision decision) {
  set_flags2(CachedTieringDecisionBits::update(flags2(), decision));
}

// static
void SharedFunctionInfo::EnsureBytecodeArrayAvailable(
    Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
    IsCompiledScope* is_compiled_scope, CreateSourcePositions flag) {
  if (!shared_info->HasBytecodeArray()) {
    if (!Compiler::Compile(isolate, shared_info, Compiler::CLEAR_EXCEPTION,
                           is_compiled_scope, flag)) {
      FATAL("Failed to compile shared info that was already compiled before");
    }
    DCHECK(shared_info->GetBytecodeArray(isolate)->HasSourcePositionTable());
  } else {
    *is_compiled_scope = shared_info->is_compiled_scope(isolate);
  }
}

// static
void SharedFunctionInfo::EnsureSourcePositionsAvailable(
    Isolate* isolate, Handle<SharedFunctionInfo> shared_info) {
  if (shared_info->CanCollectSourcePosition(isolate)) {
    std::optional<Isolate::ExceptionScope> exception_scope;
    if (isolate->has_exception()) {
      exception_scope.emplace(isolate);
    }
    Compiler::CollectSourcePositions(isolate, shared_info);
  }
}

// static
void SharedFunctionInfo::InstallDebugBytecode(
    DirectHandle<SharedFunctionInfo> shared, Isolate* isolate) {
  DCHECK(shared->HasBytecodeArray());
  DirectHandle<BytecodeArray> original_bytecode_array(
      shared->GetBytecodeArray(isola
```