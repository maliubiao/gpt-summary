Response:
Let's break down the thought process to analyze the provided C++ header file `v8/src/objects/shared-function-info.h`.

**1. Initial Scan and Identification of Key Elements:**

My first step is to quickly scan the file for recognizable keywords, class names, and patterns. I notice:

* `#ifndef`, `#define`, `#endif`:  Standard header guard, indicating this file defines a header.
* `#include`:  Lots of includes, suggesting this file relies on other V8 components. I'd mentally note some of the key ones like `"src/objects/objects.h"`, `"src/codegen/bailout-reason.h"`, etc. These give hints about the file's purpose.
* `namespace v8::internal`:  This is clearly a V8 internal header.
* Class definitions: `PreparseData`, `UncompiledData` (and its variations), `InterpreterData`, and the central class `SharedFunctionInfo`. The variations of `UncompiledData` hint at different states or amounts of pre-parsing.
* `TorqueGenerated...`:  This is a strong indicator of Torque, V8's internal DSL for generating code. The presence of `torque-generated/src/objects/shared-function-info-tq.inc` confirms this.
* `enum class`:  `CreateSourcePositions` is a simple enumeration.
* `V8_EXPORT_PRIVATE`:  Indicates functions and members intended for internal V8 use.
* `DECL_...`:  Macros like `DECL_GETTER`, `DECL_ACCESSORS`, `DECL_BOOLEAN_ACCESSORS` suggest automatically generated accessors for class members, likely tied to Torque.
* Comments: The comments provide valuable high-level descriptions of classes and members.

**2. Focus on the Core: `SharedFunctionInfo`:**

Given the filename, the `SharedFunctionInfo` class is clearly the central focus. I'd read its introductory comment: "SharedFunctionInfo describes the JSFunction information that can be shared by multiple instances of the function." This immediately tells me its primary function: to store function-related data that can be shared across different instances of the same JavaScript function. This is crucial for memory efficiency.

**3. Analyze Member Variables and Methods (Categorization):**

I'd then go through the members and methods, trying to group them by functionality. This helps understand the different aspects of a JavaScript function that `SharedFunctionInfo` manages. My mental categorization would look something like this:

* **Identification and Linking:** `Name()`, `SetName()`, `SetScript()`, `unique_id`, `script()`. These connect the `SharedFunctionInfo` to the function's name and its source code.
* **Code and Compilation:** `GetCode()`, `abstract_code()`, `is_compiled()`, `is_compiled_scope()`, `GetBytecodeArray()`, `interpreter_data()`, `baseline_code()`, `DiscardCompiled()`. This group deals with the compiled or interpreted form of the function.
* **Pre-parsing and Lazy Compilation:** `HasUncompiledData...()`, `uncompiled_data...()`, `PreparseData`. This relates to the initial stages of processing the function's source code.
* **Optimization and Inlining:** `optimization_disabled()`, `DisableOptimization()`, `GetInlineability()`. This concerns V8's optimization pipeline.
* **Debugging and Profiling:** `HasDebugInfo()`, `GetDebugInfo()`, `DebugNameCStr()`, `PassesFilter()`.
* **Parameters and Scope:** `internal_formal_parameter_count...()`, `GetOuterScopeInfo()`, `scope_info()`.
* **WebAssembly Integration:** `HasAsmWasmData()`, `HasWasmFunctionData()`, etc.
* **Flags and Attributes:**  The numerous `DECL_BOOLEAN_ACCESSORS` and `DECL_UINT..._ACCESSORS` point to various flags and properties of the function (e.g., `is_toplevel`, `is_wrapped`, `native`).
* **Builtins:** `HasBuiltinId()`, `builtin_id()`.
* **Source Code:** `HasSourceCode()`, `GetSourceCode()`.
* **Metadata:** `feedback_metadata()`.
* **Internal State Management:** `Init()`, `CopyFrom()`, `clear_padding()`, `UpdateFunctionMapIndex()`.

**4. Connecting to JavaScript Concepts:**

As I analyze the members, I'd connect them to corresponding JavaScript concepts. For example:

* `Name()` -> the function's name property.
* `GetCode()` -> the actual executable code of the function.
* `formal_parameter_count` -> the number of declared parameters.
* `script()` -> the `<script>` tag or module where the function is defined.
* `is_compiled()` -> whether the function has been optimized by the JIT compiler.

**5. Torque Recognition:**

The presence of `.tq` in the prompt and the numerous `TorqueGenerated...` classes and macros make it clear that Torque is involved. I'd understand that `.tq` files are Torque source files and that Torque generates C++ code from them. This also explains the `DEFINE_TORQUE_GENERATED_SHARED_FUNCTION_INFO_FLAGS()` style macros – they are part of the Torque code generation process.

**6. Hypothesizing Inputs and Outputs (Where Applicable):**

For some methods, I'd think about potential inputs and outputs. For instance:

* `GetCode(Isolate* isolate)`: Input is the V8 `Isolate`; output is a `Code` object (the compiled code).
* `SetScript(IsolateForSandbox isolate, ReadOnlyRoots roots, Tagged<HeapObject> script_object, int function_literal_id, bool reset_preparsed_scope_data = true)`: Inputs are various V8 objects and parameters; the output is the `SharedFunctionInfo` being linked to the `Script`.

**7. Considering Common Programming Errors:**

Based on the functionality, I'd consider potential errors:

* Incorrectly assuming a function is compiled (`is_compiled()`) without using `IsCompiledScope` and then encountering uncompiled code later.
* Misunderstanding the difference between `Name()` and `inferred_name()`.
* Issues related to closures and `GetOuterScopeInfo()`.

**8. Synthesizing the Summary:**

Finally, I'd synthesize the information into a concise summary, hitting the key points:

* Core purpose: Stores shared information about JavaScript functions.
* Key information stored: Name, code, script, parameters, optimization status, debugging info, etc.
* Relationship to Torque.
* Connection to JavaScript concepts.

This systematic approach, starting with a broad overview and then focusing on key elements and their relationships, allows for a comprehensive understanding of the provided C++ header file. The presence of Torque is a crucial piece of the puzzle, explaining the code generation aspects.
Let's break down the functionality of `v8/src/objects/shared-function-info.h`.

**Core Functionality of `SharedFunctionInfo`:**

The primary purpose of the `SharedFunctionInfo` class in V8 is to store information about JavaScript functions that can be **shared** across multiple instances (closures) of the same function. This is a crucial optimization for memory efficiency. Instead of each function instance carrying all its metadata, they can point to a single `SharedFunctionInfo` object containing the common information.

Here's a breakdown of the key aspects managed by `SharedFunctionInfo`:

* **Identification and Naming:**
    * Stores the function's name (`Name()`, `SetName()`, `inferred_name()`).
    * Tracks a unique ID within the script (`UniqueIdInScript()`).
* **Source Code and Location:**
    * Holds a reference to the `Script` object where the function is defined (`script()`).
    * Stores the start and end positions of the function in the source code (`StartPosition()`, `EndPosition()`).
    * Records the position of the 'function' keyword (`function_token_position()`).
* **Code and Compilation Status:**
    * Manages the compiled code of the function (`GetCode()`, `abstract_code()`). This could be actual machine code or bytecode.
    * Tracks whether the function has been compiled (`is_compiled()`).
    * Stores information related to different tiers of compilation (e.g., baseline code, optimized code).
    * Holds a reference to the `BytecodeArray` for interpreted functions (`GetBytecodeArray()`).
    * Manages `InterpreterData` when the function is using the interpreter.
* **Optimization Information:**
    * Stores whether optimization is disabled for the function and the reason why (`optimization_disabled()`, `disabled_optimization_reason()`).
    * Caches tiering decisions for optimization.
    * Tracks if the function is currently being compiled by Sparkplug or if Maglev compilation failed.
* **Pre-parsing and Lazy Compilation:**
    * Stores data from the pre-parser (`PreparseData`), which helps speed up compilation.
    * Manages different states of uncompiled data (`UncompiledData`, `UncompiledDataWithPreparseData`, etc.).
* **Function Properties:**
    * Stores the number of formal parameters (`internal_formal_parameter_count_with_receiver()`).
    * Tracks the function's kind (e.g., normal function, generator, async function) (`kind()`).
    * Indicates the function's syntax kind.
    * Stores the language mode of the function.
    * Flags for whether the function is native, wrapped in a function, has duplicate parameters, etc.
* **Scope Information:**
    * Holds a reference to the `ScopeInfo` object, describing the function's lexical scope (`scope_info()`, `GetOuterScopeInfo()`).
* **Debugging and Profiling:**
    * Provides access to debugging information (`GetDebugInfo()`).
    * Tracks coverage information (`GetCoverageInfo()`).
* **WebAssembly Integration:**
    * If WebAssembly is enabled, it can store data related to WebAssembly functions (`AsmWasmData`, `WasmFunctionData`, etc.).
* **Built-in Functions:**
    * Can store the ID of a built-in function (`builtin_id`).
* **Flags and Attributes:**
    * Uses bitfields (`flags`, `flags2`) to efficiently store various boolean attributes of the function.
* **Function Templates (for API functions):**
    * Can hold a reference to a `FunctionTemplateInfo` for functions exposed through the V8 API.
* **Feedback Metadata:**
    * Stores metadata for feedback vectors used in optimizing function calls (`feedback_metadata()`).

**Is it a Torque Source File?**

The provided code snippet **does not end with `.tq`**. However, it **includes** the file `"torque-generated/src/objects/shared-function-info-tq.inc"`. This indicates that while `shared-function-info.h` itself is a regular C++ header file, **part of its implementation or structure is generated by Torque**.

Torque is V8's internal domain-specific language used to generate efficient C++ code, especially for object layouts and built-in functions. The `.inc` file likely contains generated code related to the layout, accessors, and possibly some methods of the `SharedFunctionInfo` class.

**Relationship to JavaScript and Examples:**

Yes, `SharedFunctionInfo` is directly related to JavaScript functions. Every JavaScript function created in V8 will have an associated `SharedFunctionInfo` object.

**Example:**

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

const sayHello = greet; // sayHello and greet now share the same SharedFunctionInfo

const greeter = function(name) {
  console.log("Greetings, " + name + "!");
};
```

In this JavaScript example:

* Both `greet` and `sayHello` will point to the **same `SharedFunctionInfo` object**. This object will store information like the function's name ("greet"), its source code, the number of parameters, etc.
* The anonymous function assigned to `greeter` will have its **own `SharedFunctionInfo` object**.

**Code Logic Inference (Hypothetical):**

Let's consider a hypothetical scenario related to inlining:

**Assumption:**  The `GetInlineability()` method checks various conditions to determine if a function can be inlined.

**Input:** A `SharedFunctionInfo` object representing the `greet` function from the example above.

**Output (Possible):** `SharedFunctionInfo::Inlineability::kIsInlineable`

**Reasoning:** If the `greet` function is relatively small, doesn't have any features that prevent inlining (like `eval` or complex control flow in some cases), and its optimization hasn't been disabled, then `GetInlineability()` might return `kIsInlineable`, indicating that the compiler can potentially inline calls to this function for performance gains.

**User Programming Errors:**

While users don't directly interact with `SharedFunctionInfo`, understanding its concepts helps in understanding performance implications and debugging. A common related programming error is creating too many small, anonymous functions within loops or frequently called sections of code. This can lead to increased memory pressure due to the creation of many separate `SharedFunctionInfo` objects (though V8 has optimizations for this).

**Example of a related programming error:**

```javascript
function processData(data) {
  return data.map(item => { // Creating a new anonymous function for each call to map
    return item * 2;
  });
}
```

While functionally correct, creating a new anonymous function inside `map` for each call might have a slight performance overhead compared to defining the doubling function once outside. V8's optimizations often mitigate this, but in very performance-sensitive code, it's something to be aware of.

**Summary of Functionality (Part 1):**

The `v8/src/objects/shared-function-info.h` header defines the `SharedFunctionInfo` class, which is a fundamental component in V8's architecture. It acts as a central repository for metadata about JavaScript functions that can be shared across multiple instances of the same function. This shared information includes the function's name, source code location, compilation status, optimization details, scope information, and more. It plays a critical role in memory efficiency and the overall performance of JavaScript execution in V8. The file itself is a C++ header, but it relies on Torque to generate parts of its implementation, highlighting the use of V8's internal tools for performance optimization.

### 提示词
```
这是目录为v8/src/objects/shared-function-info.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/shared-function-info.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_SHARED_FUNCTION_INFO_H_
#define V8_OBJECTS_SHARED_FUNCTION_INFO_H_

#include <memory>
#include <optional>

#include "src/base/bit-field.h"
#include "src/builtins/builtins.h"
#include "src/codegen/bailout-reason.h"
#include "src/common/globals.h"
#include "src/objects/compressed-slots.h"
#include "src/objects/function-kind.h"
#include "src/objects/function-syntax-kind.h"
#include "src/objects/name.h"
#include "src/objects/objects.h"
#include "src/objects/script.h"
#include "src/objects/slots.h"
#include "src/objects/smi.h"
#include "src/objects/struct.h"
#include "src/roots/roots.h"
#include "testing/gtest/include/gtest/gtest_prod.h"  // nogncheck
#include "torque-generated/bit-fields.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

class AsmWasmData;
class BytecodeArray;
class CoverageInfo;
class DebugInfo;
class IsCompiledScope;
template <typename>
class Signature;
class WasmFunctionData;
class WasmCapiFunctionData;
class WasmExportedFunctionData;
class WasmJSFunctionData;
class WasmResumeData;

#if V8_ENABLE_WEBASSEMBLY
namespace wasm {
class CanonicalValueType;
struct WasmModule;
class ValueType;
using FunctionSig = Signature<ValueType>;
using CanonicalSig = Signature<CanonicalValueType>;
}  // namespace wasm
#endif

#include "torque-generated/src/objects/shared-function-info-tq.inc"

// Defines whether the source positions should be created during function
// compilation.
enum class CreateSourcePositions { kNo, kYes };

// Data collected by the pre-parser storing information about scopes and inner
// functions.
//
// PreparseData Layout:
// +-------------------------------+
// | data_length | children_length |
// +-------------------------------+
// | Scope Byte Data ...           |
// | ...                           |
// +-------------------------------+
// | [Padding]                     |
// +-------------------------------+
// | Inner PreparseData 1          |
// +-------------------------------+
// | ...                           |
// +-------------------------------+
// | Inner PreparseData N          |
// +-------------------------------+
class PreparseData
    : public TorqueGeneratedPreparseData<PreparseData, HeapObject> {
 public:
  inline int inner_start_offset() const;
  inline ObjectSlot inner_data_start() const;

  inline uint8_t get(int index) const;
  inline void set(int index, uint8_t value);
  inline void copy_in(int index, const uint8_t* buffer, int length);

  inline Tagged<PreparseData> get_child(int index) const;
  inline void set_child(int index, Tagged<PreparseData> value,
                        WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  // Clear uninitialized padding space.
  inline void clear_padding();

  DECL_PRINTER(PreparseData)
  DECL_VERIFIER(PreparseData)

  static const int kDataStartOffset = kSize;

  class BodyDescriptor;

  static int InnerOffset(int data_length) {
    return RoundUp(kDataStartOffset + data_length * kByteSize, kTaggedSize);
  }

  static int SizeFor(int data_length, int children_length) {
    return InnerOffset(data_length) + children_length * kTaggedSize;
  }

  TQ_OBJECT_CONSTRUCTORS(PreparseData)

 private:
  inline Tagged<Object> get_child_raw(int index) const;
};

// Abstract class representing extra data for an uncompiled function, which is
// not stored in the SharedFunctionInfo.
class UncompiledData
    : public TorqueGeneratedUncompiledData<UncompiledData,
                                           ExposedTrustedObject> {
 public:
  inline void InitAfterBytecodeFlush(
      IsolateForSandbox isolate, Tagged<String> inferred_name,
      int start_position, int end_position,
      std::function<void(Tagged<HeapObject> object, ObjectSlot slot,
                         Tagged<HeapObject> target)>
          gc_notify_updated_slot);

  TQ_OBJECT_CONSTRUCTORS(UncompiledData)
};

// Class representing data for an uncompiled function that does not have any
// data from the pre-parser, either because it's a leaf function or because the
// pre-parser bailed out.
class UncompiledDataWithoutPreparseData
    : public TorqueGeneratedUncompiledDataWithoutPreparseData<
          UncompiledDataWithoutPreparseData, UncompiledData> {
 public:
  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(UncompiledDataWithoutPreparseData)
};

// Class representing data for an uncompiled function that has pre-parsed scope
// data.
class UncompiledDataWithPreparseData
    : public TorqueGeneratedUncompiledDataWithPreparseData<
          UncompiledDataWithPreparseData, UncompiledData> {
 public:
  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(UncompiledDataWithPreparseData)
};

// Class representing data for an uncompiled function that does not have any
// data from the pre-parser, either because it's a leaf function or because the
// pre-parser bailed out, but has a job pointer.
class UncompiledDataWithoutPreparseDataWithJob
    : public TorqueGeneratedUncompiledDataWithoutPreparseDataWithJob<
          UncompiledDataWithoutPreparseDataWithJob,
          UncompiledDataWithoutPreparseData> {
 public:
  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(UncompiledDataWithoutPreparseDataWithJob)
};

// Class representing data for an uncompiled function that has pre-parsed scope
// data and a job pointer.
class UncompiledDataWithPreparseDataAndJob
    : public TorqueGeneratedUncompiledDataWithPreparseDataAndJob<
          UncompiledDataWithPreparseDataAndJob,
          UncompiledDataWithPreparseData> {
 public:
  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(UncompiledDataWithPreparseDataAndJob)
};

class InterpreterData
    : public TorqueGeneratedInterpreterData<InterpreterData,
                                            ExposedTrustedObject> {
 public:
  DECL_PROTECTED_POINTER_ACCESSORS(bytecode_array, BytecodeArray)
  DECL_PROTECTED_POINTER_ACCESSORS(interpreter_trampoline, Code)

  class BodyDescriptor;

 private:
  TQ_OBJECT_CONSTRUCTORS(InterpreterData)
};

using NameOrScopeInfoT = UnionOf<Smi, String, ScopeInfo>;

// SharedFunctionInfo describes the JSFunction information that can be
// shared by multiple instances of the function.
class SharedFunctionInfo
    : public TorqueGeneratedSharedFunctionInfo<SharedFunctionInfo, HeapObject> {
 public:
  DEFINE_TORQUE_GENERATED_SHARED_FUNCTION_INFO_FLAGS()
  DEFINE_TORQUE_GENERATED_SHARED_FUNCTION_INFO_FLAGS2()
  DEFINE_TORQUE_GENERATED_SHARED_FUNCTION_INFO_HOOK_FLAG()

  // This initializes the SharedFunctionInfo after allocation. It must
  // initialize all fields, and leave the SharedFunctionInfo in a state where
  // it is safe for the GC to visit it.
  //
  // Important: This function MUST not allocate.
  void Init(ReadOnlyRoots roots, int unique_id);

  V8_EXPORT_PRIVATE static constexpr Tagged<Smi> const kNoSharedNameSentinel =
      Smi::zero();

  // [name]: Returns shared name if it exists or an empty string otherwise.
  inline Tagged<String> Name() const;
  inline void SetName(Tagged<String> name);

  // Get the code object which represents the execution of this function.
  V8_EXPORT_PRIVATE Tagged<Code> GetCode(Isolate* isolate) const;

  // Get the abstract code associated with the function, which will either be
  // a Code object or a BytecodeArray.
  inline Tagged<AbstractCode> abstract_code(Isolate* isolate);

  // Set up the link between shared function info and the script. The shared
  // function info is added to the list on the script.
  V8_EXPORT_PRIVATE void SetScript(IsolateForSandbox isolate,
                                   ReadOnlyRoots roots,
                                   Tagged<HeapObject> script_object,
                                   int function_literal_id,
                                   bool reset_preparsed_scope_data = true);

  // Copy the data from another SharedFunctionInfo. Used for copying data into
  // and out of a placeholder SharedFunctionInfo, for off-thread compilation
  // which is not allowed to touch a main-thread-visible SharedFunctionInfo.
  void CopyFrom(Tagged<SharedFunctionInfo> other, IsolateForSandbox isolate);

  // Layout description of the optimized code map.
  static const int kEntriesStart = 0;
  static const int kContextOffset = 0;
  static const int kCachedCodeOffset = 1;
  static const int kEntryLength = 2;
  static const int kInitialLength = kEntriesStart + kEntryLength;

  static const int kNotFound = -1;

  static constexpr int kAgeSize = kAgeOffsetEnd - kAgeOffset + 1;
  static constexpr uint16_t kMaxAge = UINT16_MAX;

  DECL_ACQUIRE_GETTER(scope_info, Tagged<ScopeInfo>)
  // Deprecated, use the ACQUIRE version instead.
  DECL_GETTER(scope_info, Tagged<ScopeInfo>)
  // Slow but safe:
  inline Tagged<ScopeInfo> EarlyScopeInfo(AcquireLoadTag tag);

  // Set scope_info without moving the existing name onto the ScopeInfo.
  inline void set_raw_scope_info(Tagged<ScopeInfo> scope_info,
                                 WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  inline void SetScopeInfo(Tagged<ScopeInfo> scope_info,
                           WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  inline bool is_script() const;
  inline bool needs_script_context() const;

  // End position of this function in the script source.
  V8_EXPORT_PRIVATE int EndPosition() const;

  // Start position of this function in the script source.
  V8_EXPORT_PRIVATE int StartPosition() const;

  V8_EXPORT_PRIVATE void UpdateFromFunctionLiteralForLiveEdit(
      IsolateForSandbox isolate, FunctionLiteral* lit);

  // [outer scope info | feedback metadata] Shared storage for outer scope info
  // (on uncompiled functions) and feedback metadata (on compiled functions).
  DECL_ACCESSORS(raw_outer_scope_info_or_feedback_metadata, Tagged<HeapObject>)
  DECL_ACQUIRE_GETTER(raw_outer_scope_info_or_feedback_metadata,
                      Tagged<HeapObject>)
 private:
  using TorqueGeneratedSharedFunctionInfo::
      outer_scope_info_or_feedback_metadata;
  using TorqueGeneratedSharedFunctionInfo::
      set_outer_scope_info_or_feedback_metadata;

 public:
  // Get the outer scope info whether this function is compiled or not.
  inline bool HasOuterScopeInfo() const;
  inline Tagged<ScopeInfo> GetOuterScopeInfo() const;

  // [feedback metadata] Metadata template for feedback vectors of instances of
  // this function.
  inline bool HasFeedbackMetadata() const;
  inline bool HasFeedbackMetadata(AcquireLoadTag tag) const;
  DECL_GETTER(feedback_metadata, Tagged<FeedbackMetadata>)
  DECL_RELEASE_ACQUIRE_ACCESSORS(feedback_metadata, Tagged<FeedbackMetadata>)

  // Returns if this function has been compiled yet. Note: with bytecode
  // flushing, any GC after this call is made could cause the function
  // to become uncompiled. If you need to ensure the function remains compiled
  // for some period of time, use IsCompiledScope instead.
  inline bool is_compiled() const;

  // Returns an IsCompiledScope which reports whether the function is compiled,
  // and if compiled, will avoid the function becoming uncompiled while it is
  // held.
  template <typename IsolateT>
  inline IsCompiledScope is_compiled_scope(IsolateT* isolate) const;

  // [internal formal parameter count]: The declared number of parameters.
  // For subclass constructors, also includes new.target.
  // The size of function's frame is
  // internal_formal_parameter_count_with_receiver.
  //
  // NOTE: this API should be considered DEPRECATED. Please obtain the
  // parameter count from the Code/BytecodeArray or another trusted source
  // instead. See also crbug.com/40931165.
  // TODO(saelo): mark as V8_DEPRECATE_SOON once the remaining users are fixed.
  inline void set_internal_formal_parameter_count(int value);
  inline uint16_t internal_formal_parameter_count_with_receiver() const;
  inline uint16_t internal_formal_parameter_count_without_receiver() const;

 private:
  using TorqueGeneratedSharedFunctionInfo::formal_parameter_count;
  using TorqueGeneratedSharedFunctionInfo::set_formal_parameter_count;

 public:
  // Set the formal parameter count so the function code will be
  // called without using argument adaptor frames.
  inline void DontAdaptArguments();
  inline bool IsDontAdaptArguments() const;

  // Accessors for the data associated with this SFI.
  //
  // Currently it can be one of:
  //  - a FunctionTemplateInfo to make benefit the API [IsApiFunction()].
  //  - a BytecodeArray for the interpreter [HasBytecodeArray()].
  //  - a InterpreterData with the BytecodeArray and a copy of the
  //    interpreter trampoline [HasInterpreterData()]
  //  - an AsmWasmData with Asm->Wasm conversion [HasAsmWasmData()].
  //  - a Smi containing the builtin id [HasBuiltinId()]
  //  - a UncompiledDataWithoutPreparseData for lazy compilation
  //    [HasUncompiledDataWithoutPreparseData()]
  //  - a UncompiledDataWithPreparseData for lazy compilation
  //    [HasUncompiledDataWithPreparseData()]
  //  - a WasmExportedFunctionData for Wasm [HasWasmExportedFunctionData()]
  //  - a WasmJSFunctionData for functions created with WebAssembly.Function
  //  - a WasmCapiFunctionData for Wasm C-API functions
  //  - a WasmResumeData for JSPI Wasm functions
  //
  // If the (expected) type of data is known, prefer to use the specialized
  // accessors (e.g. bytecode_array(), uncompiled_data(), etc.).
  inline Tagged<Object> GetTrustedData(IsolateForSandbox isolate) const;
  inline Tagged<Object> GetUntrustedData() const;

  // Helper function for use when a specific data type is expected.
  template <typename T, IndirectPointerTag tag>
  inline Tagged<T> GetTrustedData(IsolateForSandbox isolate) const;

  // Helper function when no Isolate is available. Prefer to use the variant
  // with an isolate parameter if possible.
  inline Tagged<Object> GetTrustedData() const;

 private:
  // For the sandbox, the function's data is split across two fields, with the
  // "trusted" part containing a trusted pointer and the regular/untrusted part
  // containing a tagged pointer. In that case, code accessing the data field
  // will first load the trusted data field. If that is empty (i.e.
  // kNullIndirectPointerHandle), it will then load the regular field. With
  // that, the only racy transition would be a tagged -> trusted transition
  // (one thread may first read the empty trusted pointer, then another thread
  // transitions to the trusted field, clearing the tagged field, and then the
  // first thread continues to load the tagged field). As such, this transition
  // is only allowed on the main thread. From a GC perspective, both fields
  // always contain a valid value and so can be processed unconditionally.
  // Only one of these two fields should be in use at any time and the other
  // field should be cleared. As such, when setting these fields use
  // SetTrustedData() and SetUntrustedData() which automatically clear the
  // inactive field.
  // TODO(chromium:1490564): try to merge these two fields back together, for
  // example by moving all data objects into trusted space.
  inline void SetTrustedData(Tagged<ExposedTrustedObject> value,
                             WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  inline void SetUntrustedData(Tagged<Object> value,
                               WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  inline bool HasTrustedData() const;
  inline bool HasUntrustedData() const;

 public:
  inline bool IsApiFunction() const;
  inline bool is_class_constructor() const;
  DECL_ACCESSORS(api_func_data, Tagged<FunctionTemplateInfo>)
  DECL_GETTER(HasBytecodeArray, bool)
  template <typename IsolateT>
  inline Tagged<BytecodeArray> GetBytecodeArray(IsolateT* isolate) const;

  // Sets the bytecode for this SFI. This is only allowed when this SFI has not
  // yet been compiled or if it has been "uncompiled", or in other words when
  // there is no existing bytecode yet.
  inline void set_bytecode_array(Tagged<BytecodeArray> bytecode);
  // Like set_bytecode_array but allows overwriting existing bytecode.
  inline void overwrite_bytecode_array(Tagged<BytecodeArray> bytecode);

  inline Tagged<Code> InterpreterTrampoline(IsolateForSandbox isolate) const;
  inline bool HasInterpreterData(IsolateForSandbox isolate) const;
  inline Tagged<InterpreterData> interpreter_data(
      IsolateForSandbox isolate) const;
  inline void set_interpreter_data(
      Tagged<InterpreterData> interpreter_data,
      WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  DECL_GETTER(HasBaselineCode, bool)
  DECL_RELEASE_ACQUIRE_ACCESSORS(baseline_code, Tagged<Code>)
  inline void FlushBaselineCode();
  inline Tagged<BytecodeArray> GetActiveBytecodeArray(
      IsolateForSandbox isolate) const;
  inline void SetActiveBytecodeArray(Tagged<BytecodeArray> bytecode,
                                     IsolateForSandbox isolate);

#if V8_ENABLE_WEBASSEMBLY
  inline bool HasAsmWasmData() const;
  inline bool HasWasmFunctionData() const;
  inline bool HasWasmExportedFunctionData() const;
  inline bool HasWasmJSFunctionData() const;
  inline bool HasWasmCapiFunctionData() const;
  inline bool HasWasmResumeData() const;
  DECL_ACCESSORS(asm_wasm_data, Tagged<AsmWasmData>)

  // Note: The accessors below will read a trusted pointer; when accessing it
  // again, you must assume that it might have been swapped out e.g. by a
  // concurrently running worker.
  DECL_GETTER(wasm_function_data, Tagged<WasmFunctionData>)
  DECL_GETTER(wasm_exported_function_data, Tagged<WasmExportedFunctionData>)
  DECL_GETTER(wasm_js_function_data, Tagged<WasmJSFunctionData>)
  DECL_GETTER(wasm_capi_function_data, Tagged<WasmCapiFunctionData>)

  DECL_GETTER(wasm_resume_data, Tagged<WasmResumeData>)
#endif  // V8_ENABLE_WEBASSEMBLY

  // builtin corresponds to the auto-generated Builtin enum.
  inline bool HasBuiltinId() const;
  DECL_PRIMITIVE_ACCESSORS(builtin_id, Builtin)

  inline bool HasUncompiledData() const;
  inline Tagged<UncompiledData> uncompiled_data(
      IsolateForSandbox isolate) const;
  inline void set_uncompiled_data(Tagged<UncompiledData> data,
                                  WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  inline bool HasUncompiledDataWithPreparseData() const;
  inline Tagged<UncompiledDataWithPreparseData>
  uncompiled_data_with_preparse_data(IsolateForSandbox isolate) const;
  inline void set_uncompiled_data_with_preparse_data(
      Tagged<UncompiledDataWithPreparseData> data,
      WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  inline bool HasUncompiledDataWithoutPreparseData() const;
  inline void ClearUncompiledDataJobPointer(IsolateForSandbox isolate);

  // Clear out pre-parsed scope data from UncompiledDataWithPreparseData,
  // turning it into UncompiledDataWithoutPreparseData.
  inline void ClearPreparseData(IsolateForSandbox isolate);

  // The inferred_name is inferred from variable or property assignment of this
  // function. It is used to facilitate debugging and profiling of JavaScript
  // code written in OO style, where almost all functions are anonymous but are
  // assigned to object properties.
  inline bool HasInferredName();
  DECL_GETTER(inferred_name, Tagged<String>)

  // All DebugInfo accessors forward to the Debug object which stores DebugInfo
  // objects in a sidetable.
  bool HasDebugInfo(Isolate* isolate) const;
  V8_EXPORT_PRIVATE Tagged<DebugInfo> GetDebugInfo(Isolate* isolate) const;
  V8_EXPORT_PRIVATE std::optional<Tagged<DebugInfo>> TryGetDebugInfo(
      Isolate* isolate) const;
  V8_EXPORT_PRIVATE bool HasBreakInfo(Isolate* isolate) const;
  bool BreakAtEntry(Isolate* isolate) const;
  bool HasCoverageInfo(Isolate* isolate) const;
  Tagged<CoverageInfo> GetCoverageInfo(Isolate* isolate) const;

  // The function's name if it is non-empty, otherwise the inferred name.
  std::unique_ptr<char[]> DebugNameCStr() const;
  static Handle<String> DebugName(Isolate* isolate,
                                  DirectHandle<SharedFunctionInfo> shared);

  // Used for flags such as --turbo-filter.
  bool PassesFilter(const char* raw_filter);

  // [script]: the Script from which the function originates, or undefined.
  DECL_RELEASE_ACQUIRE_ACCESSORS(script, Tagged<HeapObject>)
  // Use `raw_script` if deserialization of this SharedFunctionInfo may still
  // be in progress and thus the `script` field still equal to
  // Smi::uninitialized_deserialization_value.
  DECL_RELEASE_ACQUIRE_ACCESSORS(raw_script, Tagged<Object>)
  // TODO(jgruber): Remove these overloads and pass the kAcquireLoad tag
  // explicitly.
  inline Tagged<HeapObject> script() const;
  inline Tagged<HeapObject> script(PtrComprCageBase cage_base) const;
  inline bool has_script(AcquireLoadTag tag) const;

  // True if the underlying script was parsed and compiled in REPL mode.
  inline bool is_repl_mode() const;

  // The offset of the 'function' token in the script source relative to the
  // start position. Can return kFunctionTokenOutOfRange if offset doesn't
  // fit in 16 bits.
  DECL_UINT16_ACCESSORS(raw_function_token_offset)
 private:
  using TorqueGeneratedSharedFunctionInfo::function_token_offset;
  using TorqueGeneratedSharedFunctionInfo::set_function_token_offset;

 public:
  // The position of the 'function' token in the script source. Can return
  // kNoSourcePosition if raw_function_token_offset() returns
  // kFunctionTokenOutOfRange.
  inline int function_token_position() const;

  // Returns true if the function has shared name.
  inline bool HasSharedName() const;

  // [flags] Bit field containing various flags about the function.
  DECL_RELAXED_INT32_ACCESSORS(flags)
  DECL_UINT8_ACCESSORS(flags2)

  DECL_UINT16_ACCESSORS(age)

  DECL_BOOLEAN_ACCESSORS(hook_running)
  DECL_BOOLEAN_ACCESSORS(hooked)
  // True if the outer class scope contains a private brand for
  // private instance methods.
  DECL_BOOLEAN_ACCESSORS(class_scope_has_private_brand)
  DECL_BOOLEAN_ACCESSORS(has_static_private_methods_or_accessors)

  DECL_BOOLEAN_ACCESSORS(is_sparkplug_compiling)
  DECL_BOOLEAN_ACCESSORS(maglev_compilation_failed)

  CachedTieringDecision cached_tiering_decision();
  void set_cached_tiering_decision(CachedTieringDecision decision);

  DECL_BOOLEAN_ACCESSORS(function_context_independent_compiled)

  // Is this function a top-level function (scripts, evals).
  DECL_BOOLEAN_ACCESSORS(is_toplevel)

  // Indicates if this function can be lazy compiled.
  DECL_BOOLEAN_ACCESSORS(allows_lazy_compilation)

  // Indicates the language mode.
  inline LanguageMode language_mode() const;
  inline void set_language_mode(LanguageMode language_mode);

  // How the function appears in source text.
  DECL_PRIMITIVE_ACCESSORS(syntax_kind, FunctionSyntaxKind)

  // Indicates whether the source is implicitly wrapped in a function.
  inline bool is_wrapped() const;

  // True if the function has any duplicated parameter names.
  DECL_BOOLEAN_ACCESSORS(has_duplicate_parameters)

  // Indicates whether the function is a native function.
  // These needs special treatment in .call and .apply since
  // null passed as the receiver should not be translated to the
  // global object.
  DECL_BOOLEAN_ACCESSORS(native)

#if V8_ENABLE_WEBASSEMBLY
  // Indicates that asm->wasm conversion failed and should not be re-attempted.
  DECL_BOOLEAN_ACCESSORS(is_asm_wasm_broken)
#endif  // V8_ENABLE_WEBASSEMBLY

  // Indicates that the function was created by the Function function.
  // Though it's anonymous, toString should treat it as if it had the name
  // "anonymous".  We don't set the name itself so that the system does not
  // see a binding for it.
  DECL_BOOLEAN_ACCESSORS(name_should_print_as_anonymous)

  // Whether or not the number of expected properties may change.
  DECL_BOOLEAN_ACCESSORS(are_properties_final)

  // Indicates that the function has been reported for binary code coverage.
  DECL_BOOLEAN_ACCESSORS(has_reported_binary_coverage)

  // Indicates that the private name lookups inside the function skips the
  // closest outer class scope.
  DECL_BOOLEAN_ACCESSORS(private_name_lookup_skips_outer_class)

  inline FunctionKind kind() const;

  int UniqueIdInScript() const;

  // Defines the index in a native context of closure's map instantiated using
  // this shared function info.
  DECL_INT_ACCESSORS(function_map_index)

  // Clear uninitialized padding space. This ensures that the snapshot content
  // is deterministic.
  inline void clear_padding();

  // Recalculates the |map_index| value after modifications of this shared info.
  inline void UpdateFunctionMapIndex();

  // Indicates whether optimizations have been disabled for this shared function
  // info. If we cannot optimize the function we disable optimization to avoid
  // spending time attempting to optimize it again.
  inline bool optimization_disabled() const;

  // The reason why optimization was disabled.
  inline BailoutReason disabled_optimization_reason() const;

  // Disable (further) attempted optimization of all functions sharing this
  // shared function info.
  void DisableOptimization(Isolate* isolate, BailoutReason reason);

  // This class constructor needs to call out to an instance fields
  // initializer. This flag is set when creating the
  // SharedFunctionInfo as a reminder to emit the initializer call
  // when generating code later.
  DECL_BOOLEAN_ACCESSORS(requires_instance_members_initializer)

  // [source code]: Source code for the function.
  bool HasSourceCode() const;
  static Handle<Object> GetSourceCode(Isolate* isolate,
                                      DirectHandle<SharedFunctionInfo> shared);
  static Handle<Object> GetSourceCodeHarmony(
      Isolate* isolate, DirectHandle<SharedFunctionInfo> shared);

  // Tells whether this function should be subject to debugging, e.g. for
  // - scope inspection
  // - internal break points
  // - coverage and type profile
  // - error stack trace
  inline bool IsSubjectToDebugging() const;

  // Whether this function is defined in user-provided JavaScript code.
  inline bool IsUserJavaScript() const;

  // True if one can flush compiled code from this function, in such a way that
  // it can later be re-compiled.
  inline bool CanDiscardCompiled() const;

  // Flush compiled data from this function, setting it back to CompileLazy and
  // clearing any compiled metadata.
  V8_EXPORT_PRIVATE static void DiscardCompiled(
      Isolate* isolate, DirectHandle<SharedFunctionInfo> shared_info);

  // Discard the compiled metadata. If called during GC then
  // |gc_notify_updated_slot| should be used to record any slot updates.
  void DiscardCompiledMetadata(
      Isolate* isolate,
      std::function<void(Tagged<HeapObject> object, ObjectSlot slot,
                         Tagged<HeapObject> target)>
          gc_notify_updated_slot = [](Tagged<HeapObject> object,
                                      ObjectSlot slot,
                                      Tagged<HeapObject> target) {});

  // Returns true if the function has old bytecode that could be flushed. This
  // function shouldn't access any flags as it is used by concurrent marker.
  // Hence it takes the mode as an argument.
  inline bool ShouldFlushCode(base::EnumSet<CodeFlushMode> code_flush_mode);

  enum Inlineability {
    // Different reasons for not being inlineable:
    kHasNoScript,
    kNeedsBinaryCoverage,
    kIsBuiltin,
    kIsNotUserCode,
    kHasNoBytecode,
    kExceedsBytecodeLimit,
    kMayContainBreakPoints,
    kHasOptimizationDisabled,
    // Actually inlineable!
    kIsInlineable,
  };
  // Returns the first value that applies (see enum definition for the order).
  template <typename IsolateT>
  Inlineability GetInlineability(IsolateT* isolate) const;

  // Source size of this function.
  int SourceSize();

  // Returns `false` if formal parameters include rest parameters, optional
  // parameters, or destructuring parameters.
  // TODO(caitp): make this a flag set during parsing
  inline bool has_simple_parameters();

  // Initialize a SharedFunctionInfo from a parsed or preparsed function
  // literal.
  template <typename IsolateT>
  static void InitFromFunctionLiteral(IsolateT* isolate,
                                      FunctionLiteral* lit, bool is_toplevel);

  template <typename IsolateT>
  static void CreateAndSetUncompiledData(IsolateT* isolate,
                                         FunctionLiteral* lit);

  // Updates the expected number of properties based on estimate from parser.
  void UpdateExpectedNofPropertiesFromEstimate(FunctionLiteral* literal);
  void UpdateAndFinalizeExpectedNofPropertiesFromEstimate(
      FunctionLiteral* literal);

  // Sets the FunctionTokenOffset field based on the given token position and
  // start position.
  void SetFunctionTokenPosition(int function_token_position,
                                int start_position);

  static void EnsureBytecodeArrayAvailable(
      Isolate* isolate, Handle<SharedFunctionInfo> shared_info,
      IsCompiledScope* is_compiled_scope,
      CreateSourcePositions flag = CreateSourcePositions::kNo);

  inline bool CanCollectSourcePosition(Isolate* isolate);
  static void EnsureSourcePositionsAvailable(
      Isolate* isolate, Handle<SharedFunctionInfo> shared_info);

  template <typename IsolateT>
  bool AreSourcePositionsAvailable(IsolateT* isolate) const;

  // Hash based on function literal id and script id.
  V8_EXPORT_PRIVATE uint32_t Hash();

  inline bool construct_as_builtin() const;

  // Determines and sets the ConstructAsBuiltinBit in |flags|, based on the
  // |function_data|. Must be called when creating the SFI after other fields
  // are initialized. The ConstructAsBuiltinBit determines whether
  // JSBuiltinsConstructStub or JSConstructStubGeneric should be called to
  // construct this function.
  inline void CalculateConstructAsBuiltin();

  // Replaces the current age with a new value if the current value matches the
  // one expected. Returns the value before this operation.
  inline uint16_t CompareExchangeAge(uint16_t expected_age, uint16_t new_age);

  // Bytecode aging
  V8_EXPORT_PRIVATE static void EnsureOldForTesting(
      Tagged<SharedFunctionInfo> sfu);

  // Dispatched behavior.
  DECL_PRINTER(SharedFunctionInfo)
  DECL_VERIFIER(SharedFunctionInfo)
#ifdef VERIFY_HEAP
  void SharedFunctionInfoVerify(LocalIsolate* isolate);
#endif
#ifdef OBJECT_PRINT
  void PrintSourceCode(std::ostream& os);
#endif

  // Iterate over all shared function infos in a given script.
  class ScriptIterator {
   public:
    V8_EXPORT_PRIVATE ScriptIterator(Isolate* isolate, Tagged<Script> script);
    explicit ScriptIterator(Handle<WeakFixedArray> infos);
    ScriptIterator(const ScriptIterator&) = delete;
    ScriptIterator& operator=(const ScriptIterator&) = delete;
    V8_EXPORT_PRIVATE Tagged<SharedFunctionInfo> Next();
    int CurrentIndex() const { return index_ - 1; }

    // Reset the iterator to run on |script|.
    void Reset(Isolate* isolate, Tagged<Script> script);

   private:
    Handle<WeakFixedArray> infos_;
    int index_;
  };

  // Constants.
  static const int kMaximumFunctionTokenOffset = kMaxUInt16 - 1;
  static const uint16_t kFunctionTokenOutOfRange = static_cast<uint16_t>(-1);
  static_assert(kMaximumFunctionTokenOffset + 1 == kFunctionTokenOutOfRange);

  static_assert(kSize % kTaggedSize == 0);

  class BodyDescriptor;

  // Bailout reasons must fit in the DisabledOptimizationReason bitfield.
  static_assert(DisabledOptimizationReasonBits::is_valid(
      BailoutReason::kLastErrorMessage));

  static_assert(FunctionKindBits::is_valid(FunctionKind::kLastFunctionKind));
  static_assert(FunctionSyntaxKindBits::is_valid(
      FunctionSyntaxKind::kLastFunctionSyntaxKind));

  // Sets the bytecode in {shared}'s DebugInfo as the bytecode to
  // be returned by following calls to GetActiveBytecodeArray. Stores a
  // reference to the original bytecode in the DebugInfo.
  static void InstallDebugBytecode(DirectHandle<SharedFunctionInfo> shared,
                                   Isolate* isolate);
  // Removes the debug bytecode and restores the original bytecode to be
  // returned by following calls to GetActiveBytecodeArray.
  static void UninstallDebugBytecode(Tagged<SharedFunctionInfo> shared,
                                     Isolate* isolate);

#ifdef DEBUG
  // Verifies that all SFI::unique_id values on the heap are unique, including
  // Isolate::new_unique_sfi_id_.
  static bool UniqueIdsAreUnique(Isolate* isolate);
#endif  // DEBUG

 private:
#ifdef VERIFY_HEAP
  void SharedFunctionInfoVerify(ReadOnlyRoots roots);
#endif
```