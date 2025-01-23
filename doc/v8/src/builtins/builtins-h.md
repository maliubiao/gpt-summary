Response:
My thought process for analyzing the `builtins.h` file went through these stages:

1. **Identify the Core Purpose:** The file name itself, "builtins.h," strongly suggests this file defines and manages the built-in functions of the V8 JavaScript engine. The initial comments confirm this, mentioning built-in functions and their execution.

2. **Scan for Key Structures and Enums:** I looked for the main data structures and enumerations that organize the built-in functions. The `Builtin` enum immediately stood out. This enum lists all the built-in functions, prefixed with `k`. The macros `BUILTIN_LIST` and its variations (`BUILTIN_LIST_TIER0`, `BUILTIN_LIST_BYTECODE_HANDLERS`) are also crucial. They are used to generate the contents of the `Builtin` enum and related constants.

3. **Understand the `Builtin` Enum:** I recognized the pattern in the `Builtin` enum and the macros. The `DEF_ENUM` macro, used within `BUILTIN_LIST`, suggests that each built-in has a symbolic name. The `k` prefix is a common convention for constants. I noticed the `kFirstBytecodeHandler` definition, indicating a separation between standard built-ins and bytecode handlers.

4. **Look for Metadata and Organization:**  I searched for how built-ins are categorized and managed. The `TieringBuiltin` enum suggests different tiers of built-ins, likely related to optimization levels. The constants like `kBuiltinCount`, `kBuiltinTier0Count`, and the calculations for bytecode handler ranges are evidence of organizational structures.

5. **Identify Functionality and Methods:** I scanned the `Builtins` class for its public methods. Methods like `code()`, `code_handle()`, `CallableFor()`, `GetStackParameterCount()`, `GetFormalParameterCount()`, and `name()` clearly indicate ways to access information about and interact with built-ins. Methods like `Generate_Adaptor`, `Generate_CEntry`, and the `Generate_` prefix for many other methods suggest code generation or compilation of built-ins.

6. **Connect to JavaScript Concepts:** I started thinking about how the defined built-ins relate to JavaScript functionality. The presence of `CallFunction`, `Call`, `NonPrimitiveToPrimitive`, `StringAdd`, and `LoadGlobalIC` strongly suggested connections to core JavaScript operations.

7. **Infer Relationships and Purpose (Reasoning):**  Based on the identified elements, I started to infer the relationships and purpose of different parts of the code:
    * The `Builtin` enum is a central registry of all built-in functions.
    * The `Builtins` class provides methods for accessing and managing these built-ins.
    * The macros simplify the generation of the `Builtin` enum and related constants.
    * The different kinds of built-ins (CPP, TSJ, TFJ, etc.) likely represent different implementation technologies (C++, Torque, etc.).
    * The "tiering" concept likely refers to different optimization levels for built-ins.
    * The methods starting with `Generate_` are involved in generating the actual code for the built-ins.

8. **Consider Potential User Errors and Torque:** I thought about common mistakes JavaScript developers might make that would involve these built-ins. Type errors, incorrect function calls, and issues with global variables came to mind. I also noted the mention of `.tq` files and Torque, realizing that some built-ins might be implemented using this language.

9. **Structure the Answer:** Finally, I organized my findings into logical sections, addressing each part of the prompt:
    * **Functionality:**  A high-level overview of the file's purpose.
    * **Torque Source:** Explicitly address the `.tq` file question.
    * **Relationship with JavaScript:** Provide concrete JavaScript examples to illustrate how the built-ins are used implicitly.
    * **Code Logic Inference:**  Focus on the `Builtin` enum and its structure, providing a hypothetical input and output.
    * **Common Programming Errors:**  Give examples of JavaScript errors that might trigger built-ins.

**Self-Correction/Refinement:**

* Initially, I might have just listed the methods in the `Builtins` class without explaining their significance. I refined this by connecting them to their purpose (e.g., accessing code, getting parameter counts).
* I made sure to explicitly address the `.tq` file question, even though it was a simple "yes."
* I tried to choose JavaScript examples that were clear and directly related to the built-in function names. For example, using `String()` for `NonPrimitiveToPrimitive`.
* I focused the "Code Logic Inference" on the most easily understood part – the `Builtin` enum.
* I made sure to provide context and explanations, not just lists of code elements.

By following these steps, I could systematically analyze the `builtins.h` file and provide a comprehensive answer that addressed all aspects of the prompt.
看起来你提供的是 V8 JavaScript 引擎源代码目录 `v8/src/builtins/builtins.h` 的内容。这个头文件定义了 V8 中所有内置函数的核心结构和元数据。

以下是 `v8/src/builtins/builtins.h` 的功能列表：

**核心功能:**

1. **定义内置函数枚举 (`Builtin`):**  这是此文件的核心。`Builtin` 枚举类型列出了 V8 引擎中所有预定义的、用 C++ 或 Torque (一种 V8 自研的 DSL) 实现的函数。这些函数涵盖了 JavaScript 语言的各种核心功能，以及 V8 引擎内部的操作。
2. **定义内置函数的元数据:**  除了枚举之外，这个头文件还定义了与内置函数相关的元数据，例如：
    * **内置函数的种类 (`Kind`):**  例如 `CPP` (C++ 实现), `TSJ` (Torque 编译为 JavaScript), `TFJ` (Torque 编译为 TurboFan 优化代码) 等，表明了内置函数的实现方式。
    * **栈参数数量 (`GetStackParameterCount`)**:  内置函数期望在调用栈上接收的参数数量。
    * **形式参数数量 (`GetFormalParameterCount`)**:  内置函数期望的最小参数数量，用于参数适配。
    * **入口点标签 (`EntrypointTagFor`)**:  用于标记内置函数入口点的类型。
3. **提供访问内置函数的接口:**  `Builtins` 类提供了多种方法来获取关于内置函数的信息和访问其代码：
    * `code(Builtin builtin)`: 获取内置函数的 `Code` 对象（已编译的代码）。
    * `code_handle(Builtin builtin)`: 获取内置函数的 `Code` 对象的句柄。
    * `CallableFor(Isolate* isolate, Builtin builtin)`: 获取可调用的内置函数表示。
    * `name(Builtin builtin)`: 获取内置函数的名称。
    * `CppEntryOf(Builtin builtin)`:  获取 C++ 实现的内置函数的入口地址。
    * `EntryOf(Builtin builtin, Isolate* isolate)`: 获取内置函数的入口地址。
4. **支持内置函数的代码生成:**  头文件中声明了许多以 `Generate_` 开头的静态方法，这些方法负责为不同种类的内置函数生成机器码。例如 `Generate_CallFunction`, `Generate_CEntry` 等。
5. **处理不同类型的内置函数:**  文件中区分了不同类型的内置函数，例如字节码处理器 (`kFirstBytecodeHandler`)、分层编译相关的内置函数 (`TieringBuiltin`)，以及 WebAssembly 相关的内置函数 (`kWasmIndirectlyCallableBuiltins`)。
6. **定义与调用约定相关的辅助函数和宏:**  例如 `BUILTIN_CODE` 宏用于简化访问内置函数代码的操作。还定义了一些内联函数来获取特定类型的内置函数，如 `RecordWrite` 和 `CallFunction`。
7. **提供调试和分析支持:**  例如 `PrintBuiltinCode` 和 `PrintBuiltinSize` 用于打印内置函数的代码和大小信息。

**关于 `.tq` 结尾的源代码:**

如果一个 V8 源代码文件以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。 Torque 是一种 V8 自研的领域特定语言 (DSL)，用于更安全、更易于理解地编写内置函数。  `.tq` 文件会被 Torque 编译器编译成 C++ 代码，然后与其他 V8 代码一起编译。

**与 JavaScript 功能的关系及示例:**

`v8/src/builtins/builtins.h` 中定义的内置函数是 JavaScript 语言实现的基础。 每当你执行一段 JavaScript 代码时，V8 引擎都会在幕后调用这些内置函数来完成相应的操作。

以下是一些 `builtins.h` 中可能定义的内置函数以及它们对应的 JavaScript 功能示例：

* **`kCallFunction` / `kCall`**:  与 JavaScript 中的函数调用直接相关。
   ```javascript
   function myFunction(a, b) {
       return a + b;
   }
   myFunction(1, 2); //  这里会调用内置的函数调用机制
   ```

* **`kStringAdd`**:  处理字符串的拼接操作。
   ```javascript
   const str1 = "Hello";
   const str2 = "World";
   const result = str1 + str2; // 这里会调用内置的字符串加法操作
   ```

* **`kNonPrimitiveToPrimitive`**:  当 JavaScript 需要将一个对象转换为原始值时调用。
   ```javascript
   const obj = {
       toString() { return "Custom String"; }
   };
   String(obj); // 这里会调用内置的 ToPrimitive 转换机制
   ```

* **`kLoadGlobalIC`**:  用于访问全局变量。
   ```javascript
   console.log("Hello"); // 这里会访问全局对象 console 的属性 log
   ```

* **`kArrayPush` (可能在其他相关文件中定义，但概念类似)**: 用于数组的 `push` 方法。
   ```javascript
   const arr = [1, 2, 3];
   arr.push(4); // 这里会调用内置的数组 push 操作
   ```

**代码逻辑推理示例:**

假设我们关注 `Builtin` 枚举的定义和 `IsBuiltinId` 函数。

**假设输入:**

* `maybe_id = 5` (一个整数)
* `kBuiltinCount` 的值为 `100` (假设总共有 100 个内置函数)

**代码逻辑:**

`IsBuiltinId(int maybe_id)` 函数的实现如下：

```c++
static constexpr bool IsBuiltinId(int maybe_id) {
  static_assert(static_cast<int>(Builtin::kNoBuiltinId) == -1);
  return static_cast<uint32_t>(maybe_id) <
         static_cast<uint32_t>(kBuiltinCount);
}
```

**推理过程:**

1. 将 `maybe_id` (5) 转换为无符号 32 位整数。
2. 将 `kBuiltinCount` (100) 转换为无符号 32 位整数。
3. 比较这两个无符号整数。

**输出:**

由于 `5 < 100`，函数将返回 `true`，表明 `5` 可能是一个有效的内置函数 ID。

**用户常见的编程错误示例:**

这个头文件本身不直接涉及用户的编程错误，因为它定义的是引擎内部的结构。 但是，用户在编写 JavaScript 代码时的一些常见错误最终会触发或与这些内置函数交互。

* **类型错误:**  例如，尝试将一个非数字类型与数字进行加法运算，可能会触发内置的类型转换或错误处理逻辑。
   ```javascript
   const num = 10;
   const str = "abc";
   const result = num + str; // JavaScript 会尝试将 num 转换为字符串，这涉及到内置的类型转换机制。
   ```

* **调用未定义的方法或属性:**  尝试访问一个对象上不存在的属性或方法，会触发内置的属性查找和错误处理机制。
   ```javascript
   const obj = {};
   console.log(obj.someMethod()); // 这里会抛出一个 TypeError，V8 内部会调用相应的内置函数来处理这个错误。
   ```

* **不正确的函数调用:**  例如，调用一个函数时传递了错误数量或类型的参数，可能会触发内置的参数检查和适配逻辑。
   ```javascript
   function add(a, b) {
       return a + b;
   }
   add(1); // 调用时缺少一个参数，V8 内部的调用机制会处理这种情况。
   ```

总而言之，`v8/src/builtins/builtins.h` 是 V8 引擎中至关重要的一个头文件，它定义了所有内置函数的基础结构，是理解 V8 引擎如何执行 JavaScript 代码的关键入口点。虽然开发者不会直接编辑这个文件，但他们编写的每一行 JavaScript 代码都在某种程度上依赖于这里定义的内置函数。

### 提示词
```
这是目录为v8/src/builtins/builtins.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BUILTINS_BUILTINS_H_
#define V8_BUILTINS_BUILTINS_H_

#include "src/base/flags.h"
#include "src/builtins/builtins-definitions.h"
#include "src/common/globals.h"
#include "src/objects/type-hints.h"
#include "src/sandbox/code-entrypoint-tag.h"

#ifdef V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-code-pointer-table.h"
#endif

namespace v8 {
namespace internal {

class ByteArray;
class CallInterfaceDescriptor;
class Callable;

// Forward declarations.
class BytecodeOffset;
class RootVisitor;
enum class InterpreterPushArgsMode : unsigned;
class Zone;
namespace compiler {
class CodeAssemblerState;
namespace turboshaft {
class Graph;
class PipelineData;
}  // namespace turboshaft
}  // namespace compiler

template <typename T>
static constexpr T FirstFromVarArgs(T x, ...) noexcept {
  return x;
}

// Convenience macro to avoid generating named accessors for all builtins.
#define BUILTIN_CODE(isolate, name) \
  (isolate)->builtins()->code_handle(i::Builtin::k##name)

enum class Builtin : int32_t {
  kNoBuiltinId = -1,
#define DEF_ENUM(Name, ...) k##Name,
  BUILTIN_LIST(DEF_ENUM, DEF_ENUM, DEF_ENUM, DEF_ENUM, DEF_ENUM, DEF_ENUM,
               DEF_ENUM, DEF_ENUM, DEF_ENUM)
#undef DEF_ENUM
#define EXTRACT_NAME(Name, ...) k##Name,
  // Define kFirstBytecodeHandler,
  kFirstBytecodeHandler =
      FirstFromVarArgs(BUILTIN_LIST_BYTECODE_HANDLERS(EXTRACT_NAME) 0)
#undef EXTRACT_NAME
};
enum class TieringBuiltin : int32_t {
#define DEF_ENUM(Name, ...) k##Name = static_cast<int32_t>(Builtin::k##Name),
  BUILTIN_LIST_BASE_TIERING(DEF_ENUM)
#undef DEF_ENUM
};
V8_INLINE bool IsValidTieringBuiltin(TieringBuiltin builtin) {
#define CASE(Name, ...)                     \
  if (builtin == TieringBuiltin::k##Name) { \
    return true;                            \
  }
  BUILTIN_LIST_BASE_TIERING(CASE)
#undef CASE
  return false;
}

V8_INLINE constexpr bool operator<(Builtin a, Builtin b) {
  using type = typename std::underlying_type<Builtin>::type;
  return static_cast<type>(a) < static_cast<type>(b);
}

V8_INLINE Builtin operator++(Builtin& builtin) {
  using type = typename std::underlying_type<Builtin>::type;
  return builtin = static_cast<Builtin>(static_cast<type>(builtin) + 1);
}

class Builtins {
 public:
  explicit Builtins(Isolate* isolate) : isolate_(isolate) {}

  Builtins(const Builtins&) = delete;
  Builtins& operator=(const Builtins&) = delete;

  void TearDown();

  // Disassembler support.
  const char* Lookup(Address pc);

#if !defined(V8_SHORT_BUILTIN_CALLS) || defined(V8_COMPRESS_POINTERS)
  static constexpr bool kCodeObjectsAreInROSpace = true;
#else
  static constexpr bool kCodeObjectsAreInROSpace = false;
#endif  // !defined(V8_SHORT_BUILTIN_CALLS) || \
        // defined(V8_COMPRESS_POINTERS)

#define ADD_ONE(Name, ...) +1
  static constexpr int kBuiltinCount =
      0 BUILTIN_LIST(ADD_ONE, ADD_ONE, ADD_ONE, ADD_ONE, ADD_ONE, ADD_ONE,
                     ADD_ONE, ADD_ONE, ADD_ONE);
  static constexpr int kBuiltinTier0Count = 0 BUILTIN_LIST_TIER0(
      ADD_ONE, ADD_ONE, ADD_ONE, ADD_ONE, ADD_ONE, ADD_ONE, ADD_ONE);
#undef ADD_ONE

  static constexpr Builtin kFirst = static_cast<Builtin>(0);
  static constexpr Builtin kLast = static_cast<Builtin>(kBuiltinCount - 1);
  static constexpr Builtin kLastTier0 =
      static_cast<Builtin>(kBuiltinTier0Count - 1);

  static constexpr int kFirstWideBytecodeHandler =
      static_cast<int>(Builtin::kFirstBytecodeHandler) +
      kNumberOfBytecodeHandlers;
  static constexpr int kFirstExtraWideBytecodeHandler =
      kFirstWideBytecodeHandler + kNumberOfWideBytecodeHandlers;
  static constexpr int kLastBytecodeHandlerPlusOne =
      kFirstExtraWideBytecodeHandler + kNumberOfWideBytecodeHandlers;
  static constexpr bool kBytecodeHandlersAreSortedLast =
      kLastBytecodeHandlerPlusOne == kBuiltinCount;
  static_assert(kBytecodeHandlersAreSortedLast);

#ifdef V8_ENABLE_WEBASSEMBLY
  // The list of builtins that can be called indirectly from Wasm and need an
  // entry in the WasmCodePointerTable.
  static constexpr Builtin kWasmIndirectlyCallableBuiltins[] = {
      Builtin::kWasmToJsWrapperInvalidSig, Builtin::kWasmToJsWrapperAsm};
  static constexpr size_t kNumWasmIndirectlyCallableBuiltins =
      arraysize(kWasmIndirectlyCallableBuiltins);
  using WasmBuiltinHandleArray =
      wasm::WasmCodePointerTable::Handle[kNumWasmIndirectlyCallableBuiltins];
  // TODO(sroettger): this can be consteval, but the gcc bot doesn't support it.
  template <Builtin builtin>
  static constexpr size_t WasmBuiltinHandleArrayIndex();
#endif

  static constexpr bool IsBuiltinId(Builtin builtin) {
    return builtin != Builtin::kNoBuiltinId;
  }
  static constexpr bool IsBuiltinId(int maybe_id) {
    static_assert(static_cast<int>(Builtin::kNoBuiltinId) == -1);
    return static_cast<uint32_t>(maybe_id) <
           static_cast<uint32_t>(kBuiltinCount);
  }
  static constexpr bool IsTier0(Builtin builtin) {
    return builtin <= kLastTier0 && IsBuiltinId(builtin);
  }

  static constexpr Builtin FromInt(int id) {
    DCHECK(IsBuiltinId(id));
    return static_cast<Builtin>(id);
  }
  static constexpr int ToInt(Builtin id) {
    DCHECK(IsBuiltinId(id));
    return static_cast<int>(id);
  }

  // The different builtin kinds are documented in builtins-definitions.h.
  enum Kind { CPP, TSJ, TFJ, TSC, TFC, TFS, TFH, BCH, ASM };

  static BytecodeOffset GetContinuationBytecodeOffset(Builtin builtin);
  static Builtin GetBuiltinFromBytecodeOffset(BytecodeOffset);

  //
  // Convenience wrappers.
  //
  static inline constexpr Builtin RecordWrite(SaveFPRegsMode fp_mode);
  static inline constexpr Builtin IndirectPointerBarrier(
      SaveFPRegsMode fp_mode);
  static inline constexpr Builtin EphemeronKeyBarrier(SaveFPRegsMode fp_mode);

  static inline constexpr Builtin AdaptorWithBuiltinExitFrame(
      int formal_parameter_count);

  static inline constexpr Builtin CallFunction(
      ConvertReceiverMode = ConvertReceiverMode::kAny);
  static inline constexpr Builtin Call(
      ConvertReceiverMode = ConvertReceiverMode::kAny);
  // Whether the given builtin is one of the JS function call builtins.
  static inline constexpr bool IsAnyCall(Builtin builtin);

  static inline constexpr Builtin NonPrimitiveToPrimitive(
      ToPrimitiveHint hint = ToPrimitiveHint::kDefault);
  static inline constexpr Builtin OrdinaryToPrimitive(
      OrdinaryToPrimitiveHint hint);

  static inline constexpr Builtin StringAdd(
      StringAddFlags flags = STRING_ADD_CHECK_NONE);

  static inline constexpr Builtin LoadGlobalIC(TypeofMode typeof_mode);
  static inline constexpr Builtin LoadGlobalICInOptimizedCode(
      TypeofMode typeof_mode);

  static inline constexpr Builtin CEntry(int result_size, ArgvMode argv_mode,
                                         bool builtin_exit_frame = false,
                                         bool switch_to_central_stack = false);

  static inline constexpr Builtin RuntimeCEntry(
      int result_size, bool switch_to_central_stack = false);

  static inline constexpr Builtin InterpreterCEntry(int result_size);
  static inline constexpr Builtin InterpreterPushArgsThenCall(
      ConvertReceiverMode receiver_mode, InterpreterPushArgsMode mode);
  static inline constexpr Builtin InterpreterPushArgsThenConstruct(
      InterpreterPushArgsMode mode);

  // Used by CreateOffHeapTrampolines in isolate.cc.
  void set_code(Builtin builtin, Tagged<Code> code);

  V8_EXPORT_PRIVATE Tagged<Code> code(Builtin builtin);
  V8_EXPORT_PRIVATE Handle<Code> code_handle(Builtin builtin);

  static CallInterfaceDescriptor CallInterfaceDescriptorFor(Builtin builtin);
  V8_EXPORT_PRIVATE static Callable CallableFor(Isolate* isolate,
                                                Builtin builtin);
  V8_EXPORT_PRIVATE static bool HasJSLinkage(Builtin builtin);

  // Returns the number builtin's parameters passed on the stack.
  V8_EXPORT_PRIVATE static int GetStackParameterCount(Builtin builtin);

  // Formal parameter count is the minimum number of JS arguments that's
  // expected to be present on the stack when a builtin is called. When
  // a JavaScript function is called with less arguments than expected by
  // a builtin the stack is "adapted" - i.e. the required number of undefined
  // values is pushed to the stack to match the target builtin expectations.
  // In case the builtin does not require arguments adaptation it returns
  // kDontAdaptArgumentsSentinel.
  static constexpr inline int GetFormalParameterCount(Builtin builtin);

  // Checks that the formal parameter count specified in CPP macro matches
  // the value set in SharedFunctionInfo.
  static bool CheckFormalParameterCount(
      Builtin builtin, int function_length,
      int formal_parameter_count_with_receiver);

  V8_EXPORT_PRIVATE static const char* name(Builtin builtin);
  V8_EXPORT_PRIVATE static const char* NameForStackTrace(Isolate* isolate,
                                                         Builtin builtin);

  // Support for --print-builtin-size and --print-builtin-code.
  void PrintBuiltinCode();
  void PrintBuiltinSize();

  // Returns the C++ entry point for builtins implemented in C++, and the null
  // Address otherwise.
  static Address CppEntryOf(Builtin builtin);

  // Loads the builtin's entry (start of instruction stream) from the isolate's
  // builtin_entry_table, initialized earlier via {InitializeIsolateDataTables}.
  static inline Address EntryOf(Builtin builtin, Isolate* isolate);

#ifdef V8_ENABLE_WEBASSEMBLY
  // Returns a handle to the WasmCodePointerTable entry for a given builtin.
  template <Builtin builtin>
  static inline wasm::WasmCodePointerTable::Handle WasmBuiltinHandleOf(
      Isolate* isolate);
#endif

  V8_EXPORT_PRIVATE static Kind KindOf(Builtin builtin);
  static const char* KindNameOf(Builtin builtin);

  // The tag for the builtins entrypoint.
  V8_EXPORT_PRIVATE static CodeEntrypointTag EntrypointTagFor(Builtin builtin);

  V8_EXPORT_PRIVATE static bool IsCpp(Builtin builtin);

  // True, iff the given code object is a builtin. Note that this does not
  // necessarily mean that its kind is InstructionStream::BUILTIN.
  static bool IsBuiltin(const Tagged<Code> code);

  // As above, but safe to access off the main thread since the check is done
  // by handle location. Similar to Heap::IsRootHandle.
  bool IsBuiltinHandle(Handle<HeapObject> maybe_code, Builtin* index) const;

  // True, iff the given builtin contains no isolate-specific code and can be
  // embedded into the binary.
  static constexpr bool kAllBuiltinsAreIsolateIndependent = true;
  static constexpr bool AllBuiltinsAreIsolateIndependent() {
    return kAllBuiltinsAreIsolateIndependent;
  }
  static constexpr bool IsIsolateIndependent(Builtin builtin) {
    static_assert(kAllBuiltinsAreIsolateIndependent);
    return kAllBuiltinsAreIsolateIndependent;
  }

  // True, iff the given code object is a builtin with off-heap embedded code.
  static bool IsIsolateIndependentBuiltin(Tagged<Code> code);

  static void InitializeIsolateDataTables(Isolate* isolate);

  // Emits a CodeCreateEvent for every builtin.
  static void EmitCodeCreateEvents(Isolate* isolate);

  bool is_initialized() const { return initialized_; }

  // Used by SetupIsolateDelegate and Deserializer.
  void MarkInitialized() {
    DCHECK(!initialized_);
    initialized_ = true;
  }

  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> InvokeApiFunction(
      Isolate* isolate, bool is_construct,
      Handle<FunctionTemplateInfo> function, Handle<Object> receiver, int argc,
      Handle<Object> args[], Handle<HeapObject> new_target);

  static void Generate_Adaptor(MacroAssembler* masm, int formal_parameter_count,
                               Address builtin_address);

  static void Generate_CEntry(MacroAssembler* masm, int result_size,
                              ArgvMode argv_mode, bool builtin_exit_frame,
                              bool switch_to_central_stack);

  static bool AllowDynamicFunction(Isolate* isolate,
                                   DirectHandle<JSFunction> target,
                                   Handle<JSObject> target_global_proxy);

  // Creates a copy of InterpreterEntryTrampolineForProfiling in the code space.
  static Handle<Code> CreateInterpreterEntryTrampolineForProfiling(
      Isolate* isolate);

  static inline constexpr bool IsJSEntryVariant(Builtin builtin);

  int js_entry_handler_offset() const {
    DCHECK_NE(js_entry_handler_offset_, 0);
    return js_entry_handler_offset_;
  }

  int jspi_prompt_handler_offset() const {
    DCHECK_NE(jspi_prompt_handler_offset_, 0);
    return jspi_prompt_handler_offset_;
  }

  void SetJSEntryHandlerOffset(int offset) {
    // Check the stored offset is either uninitialized or unchanged (we
    // generate multiple variants of this builtin but they should all have the
    // same handler offset).
    CHECK(js_entry_handler_offset_ == 0 || js_entry_handler_offset_ == offset);
    js_entry_handler_offset_ = offset;
  }

  void SetJSPIPromptHandlerOffset(int offset) {
    CHECK_EQ(jspi_prompt_handler_offset_, 0);
    jspi_prompt_handler_offset_ = offset;
  }

#if V8_ENABLE_DRUMBRAKE
  int cwasm_interpreter_entry_handler_offset() const {
    DCHECK_NE(cwasm_interpreter_entry_handler_offset_, 0);
    return cwasm_interpreter_entry_handler_offset_;
  }

  void SetCWasmInterpreterEntryHandlerOffset(int offset) {
    // Check the stored offset is either uninitialized or unchanged (we
    // generate multiple variants of this builtin but they should all have the
    // same handler offset).
    CHECK(cwasm_interpreter_entry_handler_offset_ == 0 ||
          cwasm_interpreter_entry_handler_offset_ == offset);
    cwasm_interpreter_entry_handler_offset_ = offset;
  }
#endif  // V8_ENABLE_DRUMBRAKE

  // Returns given builtin's slot in the main builtin table.
  FullObjectSlot builtin_slot(Builtin builtin);
  // Returns given builtin's slot in the tier0 builtin table.
  FullObjectSlot builtin_tier0_slot(Builtin builtin);

  // Public for ia32-specific helper.
  enum class ForwardWhichFrame { kCurrentFrame, kParentFrame };

 private:
  static void Generate_CallFunction(MacroAssembler* masm,
                                    ConvertReceiverMode mode);

  static void Generate_CallBoundFunctionImpl(MacroAssembler* masm);

  static void Generate_Call(MacroAssembler* masm, ConvertReceiverMode mode);

  static void Generate_CallOrConstructVarargs(MacroAssembler* masm,
                                              Builtin target_builtin);
  enum class CallOrConstructMode { kCall, kConstruct };
  static void Generate_CallOrConstructForwardVarargs(MacroAssembler* masm,
                                                     CallOrConstructMode mode,
                                                     Builtin target_builtin);

  static void Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                     bool save_new_target);

  enum class InterpreterEntryTrampolineMode {
    // The version of InterpreterEntryTrampoline used by default.
    kDefault,
    // The position independent version of InterpreterEntryTrampoline used as
    // a template to create copies of the builtin at runtime. The copies are
    // used to create better profiling information for ticks in bytecode
    // execution. See v8_flags.interpreted_frames_native_stack for details.
    kForProfiling
  };
  static void Generate_InterpreterEntryTrampoline(
      MacroAssembler* masm, InterpreterEntryTrampolineMode mode);

  static void Generate_InterpreterPushArgsThenCallImpl(
      MacroAssembler* masm, ConvertReceiverMode receiver_mode,
      InterpreterPushArgsMode mode);

  static void Generate_InterpreterPushArgsThenConstructImpl(
      MacroAssembler* masm, InterpreterPushArgsMode mode);

  static void Generate_ConstructForwardAllArgsImpl(
      MacroAssembler* masm, ForwardWhichFrame which_frame);

  static void Generate_CallApiCallbackImpl(MacroAssembler* masm,
                                           CallApiCallbackMode mode);

#define DECLARE_ASM(Name, ...) \
  static void Generate_##Name(MacroAssembler* masm);
#define DECLARE_TF(Name, ...) \
  static void Generate_##Name(compiler::CodeAssemblerState* state);
#define DECLARE_TS(Name, ...)                                           \
  static void Generate_##Name(compiler::turboshaft::PipelineData* data, \
                              Isolate* isolate,                         \
                              compiler::turboshaft::Graph& graph, Zone* zone);

  BUILTIN_LIST(IGNORE_BUILTIN, DECLARE_TS, DECLARE_TF, DECLARE_TS, DECLARE_TF,
               DECLARE_TF, DECLARE_TF, IGNORE_BUILTIN, DECLARE_ASM)

#undef DECLARE_ASM
#undef DECLARE_TF

  Isolate* isolate_;
  bool initialized_ = false;

  // Stores the offset of exception handler entry point (the handler_entry
  // label) in JSEntry and its variants. It's used to generate the handler table
  // during codegen (mksnapshot-only).
  int js_entry_handler_offset_ = 0;

#if V8_ENABLE_DRUMBRAKE
  // Stores the offset of exception handler entry point (the handler_entry
  // label) in CWasmInterpreterEntry. It's used to generate the handler table
  // during codegen (mksnapshot-only).
  int cwasm_interpreter_entry_handler_offset_ = 0;
#endif  // V8_ENABLE_DRUMBRAKE

  // Do the same for the JSPI prompt, which catches uncaught exceptions and
  // rejects the corresponding promise.
  int jspi_prompt_handler_offset_ = 0;

  friend class SetupIsolateDelegate;
};

V8_INLINE constexpr bool IsInterpreterTrampolineBuiltin(Builtin builtin_id) {
  // Check for kNoBuiltinId first to abort early when the current
  // InstructionStream object is not a builtin.
  return builtin_id != Builtin::kNoBuiltinId &&
         (builtin_id == Builtin::kInterpreterEntryTrampoline ||
          builtin_id == Builtin::kInterpreterEnterAtBytecode ||
          builtin_id == Builtin::kInterpreterEnterAtNextBytecode);
}

V8_INLINE constexpr bool IsBaselineTrampolineBuiltin(Builtin builtin_id) {
  // Check for kNoBuiltinId first to abort early when the current
  // InstructionStream object is not a builtin.
  return builtin_id != Builtin::kNoBuiltinId &&
         (builtin_id == Builtin::kBaselineOutOfLinePrologue ||
          builtin_id == Builtin::kBaselineOutOfLinePrologueDeopt ||
          builtin_id == Builtin::kBaselineOrInterpreterEnterAtBytecode ||
          builtin_id == Builtin::kBaselineOrInterpreterEnterAtNextBytecode);
}

Builtin ExampleBuiltinForTorqueFunctionPointerType(
    size_t function_pointer_type_id);

}  // namespace internal
}  // namespace v8

// Helper while transitioning some functions to libm.
#if defined(V8_USE_LIBM_TRIG_FUNCTIONS)
#define SIN_IMPL(X)                                             \
  v8_flags.use_libm_trig_functions ? base::ieee754::libm_sin(X) \
                                   : base::ieee754::fdlibm_sin(X)
#define COS_IMPL(X)                                             \
  v8_flags.use_libm_trig_functions ? base::ieee754::libm_cos(X) \
                                   : base::ieee754::fdlibm_cos(X)
#else
#define SIN_IMPL(X) base::ieee754::sin(X)
#define COS_IMPL(X) base::ieee754::cos(X)
#endif

#endif  // V8_BUILTINS_BUILTINS_H_
```