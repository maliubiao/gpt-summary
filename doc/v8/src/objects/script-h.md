Response:
Let's break down the thought process for analyzing the `v8/src/objects/script.h` header file.

1. **Initial Scan and High-Level Understanding:**

   - The file name `script.h` strongly suggests it deals with the concept of scripts within V8.
   - The header comment indicates it's about scripts added to the VM.
   - Includes like `v8-script.h`, `objects.h`, and the `torque-generated` files point towards its role in V8's internal object model and potential code generation.

2. **Checking for Torque:**

   - The prompt specifically asks about `.tq` files. A quick scan reveals `#include "torque-generated/src/objects/script-tq.inc"` and `DEFINE_TORQUE_GENERATED_SCRIPT_FLAGS()`. This immediately confirms that this header *is* associated with Torque. While the header itself ends in `.h`, it *uses* Torque-generated code.

3. **Identifying Core Functionality - Enums:**

   - The nested `enum class` declarations (`Type`, `CompilationType`, `CompilationState`) provide crucial information about the different states and categories a `Script` object can be in. These are fundamental to understanding how V8 manages scripts.

4. **Identifying Core Functionality - Member Accessors (DECL_*)**:

   - The numerous `DECL_ACCESSORS` and `DECL_INT_ACCESSORS` macros strongly indicate the attributes or properties of a `Script` object. These are the data it holds. Listing them provides a detailed overview of the information associated with a script. Examples: `eval_from_shared`, `wrapped_arguments`, `wasm_breakpoint_infos`, `flags`, `compiled_lazy_function_positions`.

5. **Identifying Core Functionality - Key Methods:**

   - Focus on methods that aren't simple accessors. Look for verbs and descriptive names. Examples:
     - `is_wrapped()`, `has_eval_from_shared()`: Boolean checks about the script's nature.
     - `HasValidSource()`: Checks source accessibility.
     - `GetScriptHash()`:  Calculates a hash.
     - `GetEvalPosition()`:  Gets the position of an `eval` call.
     - `InitLineEnds()`:  Handles line ending information for source code mapping.
     - `GetPositionInfo()`:  Retrieves line and column numbers for a given code position.
     - `IsSubjectToDebugging()`, `IsUserJavaScript()`: Indicate the script's role in debugging and user code.
     - `FindSharedFunctionInfo()`:  Looks up related function information.
     - `Iterator`:  Allows iteration over script objects.

6. **Connecting to JavaScript (if applicable):**

   -  Think about how the identified functionality relates to JavaScript features.
   - `eval`: The presence of `eval_from_shared`, `eval_from_position`, and related concepts directly links to the JavaScript `eval()` function.
   - Source Maps/Debugging: The `InitLineEnds()` and `GetPositionInfo()` methods are clearly related to mapping compiled code back to the original source, a crucial aspect of debugging.
   - WebAssembly:  The `V8_ENABLE_WEBASSEMBLY` conditionals and members like `wasm_breakpoint_infos` and `wasm_native_module` directly connect to WebAssembly integration.
   - Script Types:  The `Type` enum (kNormal, kExtension, kNative) reflects different origins and purposes of scripts, some visible in JavaScript environments (e.g., browser extensions).

7. **Code Logic/Reasoning (Hypothetical Input/Output):**

   - For methods like `GetPositionInfo()`,  consider a simple example: a short JavaScript string and a specific character index. Think about how the method would map that index to a line and column number. This helps illustrate the method's purpose.

8. **Common Programming Errors:**

   -  Relate the functionality to potential programmer mistakes.
   - `eval()`:  Highlight the security risks and performance implications.
   - Source Maps: Mention issues with incorrect or missing source maps hindering debugging.
   - WebAssembly:  If WebAssembly is enabled, and the code deals with it, consider errors related to module linking or instantiation.

9. **Structuring the Answer:**

   - Start with a summary of the file's purpose.
   - Address the Torque question directly.
   - Categorize the functionality into logical groups (script properties, compilation, source mapping, debugging, etc.).
   - Provide clear JavaScript examples where relevant.
   - Offer concrete hypothetical input/output scenarios for complex logic.
   - Give practical examples of common programming errors.
   - Maintain a clear and organized structure using headings and bullet points.

10. **Review and Refine:**

    - Read through the analysis to ensure accuracy and completeness.
    - Check for clarity and conciseness.
    - Make sure the JavaScript examples are correct and illustrative.

By following these steps, one can systematically analyze a complex header file like `script.h` and extract its key functionalities, relationships to JavaScript, and potential areas for programming errors. The process involves a combination of code reading, domain knowledge (V8 internals, JavaScript), and logical reasoning.```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_SCRIPT_H_
#define V8_OBJECTS_SCRIPT_H_

#include <memory>

#include "include/v8-script.h"
#include "src/base/export-template.h"
#include "src/heap/factory-base.h"
#include "src/heap/factory.h"
#include "src/heap/local-factory.h"
#include "src/objects/fixed-array.h"
#include "src/objects/objects.h"
#include "src/objects/string.h"
#include "src/objects/struct.h"
#include "torque-generated/bit-fields.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {

namespace internal {

class FunctionLiteral;
class StructBodyDescriptor;

namespace wasm {
class NativeModule;
}  // namespace wasm

#include "torque-generated/src/objects/script-tq.inc"

// Script describes a script which has been added to the VM.
class Script : public TorqueGeneratedScript<Script, Struct> {
 public:
  // Script ID used for temporary scripts, which shouldn't be added to the
  // script list.
  static constexpr int kTemporaryScriptId = -2;

  NEVER_READ_ONLY_SPACE
  // Script types.
  enum class Type {
    kNative = 0,
    kExtension = 1,
    kNormal = 2,
#if V8_ENABLE_WEBASSEMBLY
    kWasm = 3,
#endif  // V8_ENABLE_WEBASSEMBLY
    kInspector = 4
  };

  // Script compilation types.
  enum class CompilationType { kHost = 0, kEval = 1 };

  // Script compilation state.
  enum class CompilationState { kInitial = 0, kCompiled = 1 };

  // [type]: the script type.
  DECL_PRIMITIVE_ACCESSORS(type, Type)

  DECL_ACCESSORS(eval_from_shared_or_wrapped_arguments, Tagged<Object>)

  // [eval_from_shared]: for eval scripts the shared function info for the
  // function from which eval was called.
  DECL_ACCESSORS(eval_from_shared, Tagged<SharedFunctionInfo>)

  // [wrapped_arguments]: for the list of arguments in a wrapped script.
  DECL_ACCESSORS(wrapped_arguments, Tagged<FixedArray>)

  // Whether the script is implicitly wrapped in a function.
  inline bool is_wrapped() const;

  // Whether the eval_from_shared field is set with a shared function info
  // for the eval site.
  inline bool has_eval_from_shared() const;

  // [eval_from_position]: the source position in the code for the function
  // from which eval was called, as positive integer. Or the code offset in the
  // code from which eval was called, as negative integer.
  DECL_INT_ACCESSORS(eval_from_position)

  // [infos]: weak fixed array containing all shared function infos and scope
  // infos for eval created from this script.
  DECL_ACCESSORS(infos, Tagged<WeakFixedArray>)

#if V8_ENABLE_WEBASSEMBLY
  // [wasm_breakpoint_infos]: the list of {BreakPointInfo} objects describing
  // all WebAssembly breakpoints for modules/instances managed via this script.
  // This must only be called if the type of this script is TYPE_WASM.
  DECL_ACCESSORS(wasm_breakpoint_infos, Tagged<FixedArray>)
  inline bool has_wasm_breakpoint_infos() const;

  // [wasm_native_module]: the wasm {NativeModule} this script belongs to.
  // This must only be called if the type of this script is TYPE_WASM.
  DECL_ACCESSORS(wasm_managed_native_module, Tagged<Object>)
  inline wasm::NativeModule* wasm_native_module() const;

  // [wasm_weak_instance_list]: the list of all {WasmInstanceObject} being
  // affected by breakpoints that are managed via this script.
  // This must only be called if the type of this script is TYPE_WASM.
  DECL_ACCESSORS(wasm_weak_instance_list, Tagged<WeakArrayList>)

  // [break_on_entry] (wasm only): whether an instrumentation breakpoint is set
  // for this script; this information will be transferred to existing and
  // future instances to make sure that we stop before executing any code in
  // this wasm module.
  inline bool break_on_entry() const;
  inline void set_break_on_entry(bool value);

  // Check if the script contains any Asm modules.
  bool ContainsAsmModule();
#endif  // V8_ENABLE_WEBASSEMBLY

  // Read/write the raw 'flags' field. This uses relaxed atomic loads/stores
  // because the flags are read by background compile threads and updated by the
  // main thread.
  inline uint32_t flags() const;
  inline void set_flags(uint32_t new_flags);

  // [compilation_type]: how the the script was compiled. Encoded in the
  // 'flags' field.
  inline CompilationType compilation_type() const;
  inline void set_compilation_type(CompilationType type);

  inline bool produce_compile_hints() const;
  inline void set_produce_compile_hints(bool produce_compile_hints);

  inline bool deserialized() const;
  inline void set_deserialized(bool value);

  // [compilation_state]: determines whether the script has already been
  // compiled. Encoded in the 'flags' field.
  inline CompilationState compilation_state();
  inline void set_compilation_state(CompilationState state);

  // [is_repl_mode]: whether this script originated from a REPL via debug
  // evaluate and therefore has different semantics, e.g. re-declaring let.
  inline bool is_repl_mode() const;
  inline void set_is_repl_mode(bool value);

  // [origin_options]: optional attributes set by the embedder via ScriptOrigin,
  // and used by the embedder to make decisions about the script. V8 just passes
  // this through. Encoded in the 'flags' field.
  inline v8::ScriptOriginOptions origin_options();
  inline void set_origin_options(ScriptOriginOptions origin_options);

  DECL_ACCESSORS(compiled_lazy_function_positions, Tagged<Object>)

  // If script source is an external string, check that the underlying
  // resource is accessible. Otherwise, always return true.
  inline bool HasValidSource();

  // If the script has a non-empty sourceURL comment.
  inline bool HasSourceURLComment() const;

  // Streaming compilation only attaches the source to the Script upon
  // finalization. This predicate returns true, if this script may still be
  // unfinalized.
  inline bool IsMaybeUnfinalized(Isolate* isolate) const;

  Tagged<Object> GetNameOrSourceURL();
  static Handle<String> GetScriptHash(Isolate* isolate,
                                      DirectHandle<Script> script,
                                      bool forceForInspector);

  // Retrieve source position from where eval was called.
  static int GetEvalPosition(Isolate* isolate, DirectHandle<Script> script);

  Tagged<Script> inline GetEvalOrigin();

  // Initialize line_ends array with source code positions of line ends if
  // it doesn't exist yet.
  static inline void InitLineEnds(Isolate* isolate,
                                  DirectHandle<Script> script);
  static inline void InitLineEnds(LocalIsolate* isolate,
                                  DirectHandle<Script> script);

  // Obtain line ends as a vector, without modifying the script object
  V8_EXPORT_PRIVATE static String::LineEndsVector GetLineEnds(
      Isolate* isolate, DirectHandle<Script> script);

  inline bool has_line_ends() const;

  // Will initialize the line ends if required.
  static void SetSource(Isolate* isolate, DirectHandle<Script> script,
                        DirectHandle<String> source);

  bool inline CanHaveLineEnds() const;

  // Carries information about a source position.
  struct PositionInfo {
    PositionInfo() : line(-1), column(-1), line_start(-1), line_end(-1) {}

    int line;        // Zero-based line number.
    int column;      // Zero-based column number.
    int line_start;  // Position of first character in line.
    int line_end;    // Position of final linebreak character in line.
  };

  // Specifies whether to add offsets to position infos.
  enum class OffsetFlag { kNoOffset, kWithOffset };

  // Retrieves information about the given position, optionally with an offset.
  // Returns false on failure, and otherwise writes into the given info object
  // on success.
  // The static method should is preferable for handlified callsites because it
  // initializes the line ends array, avoiding expensive recomputations.
  // The non-static version is not allocating and safe for unhandlified
  // callsites.
  static bool GetPositionInfo(DirectHandle<Script> script, int position,
                              PositionInfo* info,
                              OffsetFlag offset_flag = OffsetFlag::kWithOffset);
  static bool GetLineColumnWithLineEnds(
      int position, int& line, int& column,
      const String::LineEndsVector& line_ends);
  V8_EXPORT_PRIVATE bool GetPositionInfo(
      int position, PositionInfo* info,
      OffsetFlag offset_flag = OffsetFlag::kWithOffset) const;
  V8_EXPORT_PRIVATE bool GetPositionInfoWithLineEnds(
      int position, PositionInfo* info, const String::LineEndsVector& line_ends,
      OffsetFlag offset_flag = OffsetFlag::kWithOffset) const;
  V8_EXPORT_PRIVATE void AddPositionInfoOffset(
      PositionInfo* info,
      OffsetFlag offset_flag = OffsetFlag::kWithOffset) const;

  // Tells whether this script should be subject to debugging, e.g. for
  // - scope inspection
  // - internal break points
  // - coverage and type profile
  // - error stack trace
  bool IsSubjectToDebugging() const;

  bool IsUserJavaScript() const;

  // Wrappers for GetPositionInfo
  static int GetColumnNumber(DirectHandle<Script> script, int code_offset);
  int GetColumnNumber(int code_pos) const;
  V8_EXPORT_PRIVATE static int GetLineNumber(DirectHandle<Script> script,
                                             int code_offset);
  int GetLineNumber(int code_pos) const;

  // Look through the list of existing shared function infos to find one
  // that matches the function literal. Return empty handle if not found.
  template <typename IsolateT>
  static MaybeHandle<SharedFunctionInfo> FindSharedFunctionInfo(
      DirectHandle<Script> script, IsolateT* isolate,
      FunctionLiteral* function_literal);

  // Iterate over all script objects on the heap.
  class V8_EXPORT_PRIVATE Iterator {
   public:
    explicit Iterator(Isolate* isolate);
    Iterator(const Iterator&) = delete;
    Iterator& operator=(const Iterator&) = delete;
    Tagged<Script> Next();

   private:
    WeakArrayList::Iterator iterator_;
  };

  // Dispatched behavior.
  DECL_PRINTER(Script)
  DECL_VERIFIER(Script)

  using BodyDescriptor = StructBodyDescriptor;

 private:
  template <typename LineEndsContainer>
  bool GetPositionInfoInternal(const LineEndsContainer& ends, int position,
                               Script::PositionInfo* info,
                               const DisallowGarbageCollection& no_gc) const;

  friend Factory;
  friend FactoryBase<Factory>;
  friend FactoryBase<LocalFactory>;

  // Hide torque-generated accessor, use Script::SetSource instead.
  using TorqueGeneratedScript::set_source;

  // Bit positions in the flags field.
  DEFINE_TORQUE_GENERATED_SCRIPT_FLAGS()

  TQ_OBJECT_CONSTRUCTORS(Script)

  template <typename IsolateT>
  EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
  static void V8_PRESERVE_MOST
      InitLineEndsInternal(IsolateT* isolate, DirectHandle<Script> script);
};

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_SCRIPT_H_
```

### 功能列举

`v8/src/objects/script.h` 文件定义了 V8 引擎中 `Script` 对象的结构和行为。`Script` 对象代表了已经被添加到 V8 虚拟机中的一段脚本代码。其主要功能包括：

1. **存储脚本元数据:**
   - **类型 (Type):**  区分脚本的来源和用途，例如 `kNative` (内置), `kExtension` (浏览器扩展), `kNormal` (普通脚本), `kWasm` (WebAssembly), `kInspector` (调试器脚本)。
   - **编译类型 (CompilationType):**  指示脚本是如何被编译的，例如 `kHost` (由宿主环境编译), `kEval` (通过 `eval()` 编译)。
   - **编译状态 (CompilationState):**  记录脚本的编译进度，例如 `kInitial` (初始状态), `kCompiled` (已编译)。
   - **标记 (flags):**  包含多种布尔标志，例如是否已反序列化 (`deserialized`), 是否生成编译提示 (`produce_compile_hints`), 以及可选的来源属性 (`origin_options`)。
   - **是否为 REPL 模式 (`is_repl_mode`):**  指示脚本是否来源于 REPL 环境，这会影响某些语义，例如变量的重复声明。
   - **编译的惰性函数位置 (`compiled_lazy_function_positions`):**  存储用于惰性编译的信息。

2. **处理 `eval()` 调用:**
   - **`eval_from_shared`:**  存储调用 `eval()` 的函数的共享函数信息。
   - **`wrapped_arguments`:**  存储包装脚本中的参数列表。
   - **`eval_from_position`:**  记录 `eval()` 调用的源代码位置。
   - **`infos`:**  存储与此脚本相关的 `eval` 创建的共享函数信息和作用域信息的弱引用数组。

3. **支持 WebAssembly:**
   - **`wasm_breakpoint_infos`:**  存储 WebAssembly 模块/实例的断点信息。
   - **`wasm_managed_native_module`:**  指向此脚本所属的 WebAssembly 的 `NativeModule`。
   - **`wasm_weak_instance_list`:**  存储受此脚本管理断点影响的 `WasmInstanceObject` 列表。
   - **`break_on_entry`:**  指示是否为此 WebAssembly 脚本设置了入口断点。
   - **`ContainsAsmModule()`:**  检查脚本是否包含 Asm.js 模块。

4. **管理脚本源代码:**
   - **`HasValidSource()`:**  检查外部字符串形式的脚本源代码是否可访问。
   - **`HasSourceURLComment()`:**  检查脚本是否包含 `//# sourceURL=` 注释。
   - **`IsMaybeUnfinalized()`:**  判断流式编译的脚本是否可能尚未完成最终化，源代码可能尚未完全附加。
   - **`GetNameOrSourceURL()`:**  获取脚本的名称或 SourceURL。
   - **`GetScriptHash()`:**  计算脚本的哈希值。
   - **`SetSource()`:**  设置脚本的源代码。

5. **提供源代码位置信息:**
   - **`InitLineEnds()`:**  初始化存储行尾位置的数组，用于快速定位代码的行号和列号。
   - **`GetLineEnds()`:**  获取行尾位置向量。
   - **`has_line_ends()`:**  判断是否已初始化行尾信息。
   - **`CanHaveLineEnds()`:**  判断脚本是否可以拥有行尾信息。
   - **`PositionInfo` 结构体:**  定义了存储源代码位置信息的结构，包括行号、列号、行起始位置和行结束位置。
   - **`GetPositionInfo()`:**  根据代码偏移量获取源代码位置信息（行号、列号）。
   - **`GetLineNumber()` 和 `GetColumnNumber()`:**  便捷方法，用于根据代码偏移量获取行号和列号。

6. **支持调试:**
   - **`IsSubjectToDebugging()`:**  判断此脚本是否应该被调试器监控（例如，用于作用域检查、断点、覆盖率等）。
   - **`IsUserJavaScript()`:**  判断是否是用户编写的 JavaScript 代码。

7. **查找共享函数信息:**
   - **`FindSharedFunctionInfo()`:**  在已有的共享函数信息列表中查找与给定函数字面量匹配的项。

8. **迭代器:**
   - 提供 `Iterator` 类，用于遍历堆上的所有 `Script` 对象。

### v8/src/objects/script.h 是否为 Torque 源代码

从代码中可以看出：

-  `#include "torque-generated/src/objects/script-tq.inc"`: 包含了 Torque 生成的代码。
-  `class Script : public TorqueGeneratedScript<Script, Struct> `:  `Script` 类继承自 `TorqueGeneratedScript`。
-  `DEFINE_TORQUE_GENERATED_SCRIPT_FLAGS()`:  使用了 Torque 宏来定义标志位。
-  `TQ_OBJECT_CONSTRUCTORS(Script)`:  使用了 Torque 宏来生成构造函数。

虽然 `v8/src/objects/script.h` 本身的文件扩展名是 `.h`，但它**大量使用了 Torque 生成的代码和特性**。因此，可以认为它的实现部分依赖于 Torque，并且其结构和一些底层操作是由 Torque 定义的。虽然头文件本身不是 `.tq` 文件，但它与 Torque 的关系非常紧密。

**结论：虽然文件扩展名是 `.h`，但 `v8/src/objects/script.h` 深度集成了 Torque，并且依赖 Torque 生成代码来完成其功能。**

### 与 JavaScript 功能的关系及示例

`v8/src/objects/script.h` 中定义的 `Script` 对象是 V8 执行 JavaScript 代码的核心表示。它直接关联到以下 JavaScript 功能：

1. **`eval()` 函数:**
   - `eval_from_shared`, `eval_from_position`, `infos` 等成员变量直接用于支持 `eval()` 函数的实现，记录 `eval()` 调用的上下文信息。

   ```javascript
   function outerFunction() {
     const x = 10;
     eval('console.log(x);'); // eval 在 outerFunction 的上下文中执行
   }
   outerFunction();
   ```

2. **Source Maps 和调试:**
   - `InitLineEnds()`, `GetPositionInfo()` 等方法用于将 JavaScript 代码的运行时错误或断点位置映射回原始源代码，这是 Source Maps 和调试器的基础。

   ```javascript
   // 假设这段代码在一个单独的 script.js 文件中
   function myFunction() {
     console.log("Hello");
     throw new Error("Something went wrong"); // 调试器可以定位到这一行
   }
   myFunction();
   ```

3. **WebAssembly 集成:**
   - 当 JavaScript 代码加载和运行 WebAssembly 模块时，`Script` 对象的 `Type` 可以是 `kWasm`，并且相关的 `wasm_` 前缀的成员变量会被使用。

   ```javascript
   async function loadWasm() {
     const response = await fetch('module.wasm');
     const buffer = await response.arrayBuffer();
     const module = await WebAssembly.compile(buffer);
     const instance = await WebAssembly.instantiate(module);
     instance.
### 提示词
```
这是目录为v8/src/objects/script.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/script.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_SCRIPT_H_
#define V8_OBJECTS_SCRIPT_H_

#include <memory>

#include "include/v8-script.h"
#include "src/base/export-template.h"
#include "src/heap/factory-base.h"
#include "src/heap/factory.h"
#include "src/heap/local-factory.h"
#include "src/objects/fixed-array.h"
#include "src/objects/objects.h"
#include "src/objects/string.h"
#include "src/objects/struct.h"
#include "torque-generated/bit-fields.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {

namespace internal {

class FunctionLiteral;
class StructBodyDescriptor;

namespace wasm {
class NativeModule;
}  // namespace wasm

#include "torque-generated/src/objects/script-tq.inc"

// Script describes a script which has been added to the VM.
class Script : public TorqueGeneratedScript<Script, Struct> {
 public:
  // Script ID used for temporary scripts, which shouldn't be added to the
  // script list.
  static constexpr int kTemporaryScriptId = -2;

  NEVER_READ_ONLY_SPACE
  // Script types.
  enum class Type {
    kNative = 0,
    kExtension = 1,
    kNormal = 2,
#if V8_ENABLE_WEBASSEMBLY
    kWasm = 3,
#endif  // V8_ENABLE_WEBASSEMBLY
    kInspector = 4
  };

  // Script compilation types.
  enum class CompilationType { kHost = 0, kEval = 1 };

  // Script compilation state.
  enum class CompilationState { kInitial = 0, kCompiled = 1 };

  // [type]: the script type.
  DECL_PRIMITIVE_ACCESSORS(type, Type)

  DECL_ACCESSORS(eval_from_shared_or_wrapped_arguments, Tagged<Object>)

  // [eval_from_shared]: for eval scripts the shared function info for the
  // function from which eval was called.
  DECL_ACCESSORS(eval_from_shared, Tagged<SharedFunctionInfo>)

  // [wrapped_arguments]: for the list of arguments in a wrapped script.
  DECL_ACCESSORS(wrapped_arguments, Tagged<FixedArray>)

  // Whether the script is implicitly wrapped in a function.
  inline bool is_wrapped() const;

  // Whether the eval_from_shared field is set with a shared function info
  // for the eval site.
  inline bool has_eval_from_shared() const;

  // [eval_from_position]: the source position in the code for the function
  // from which eval was called, as positive integer. Or the code offset in the
  // code from which eval was called, as negative integer.
  DECL_INT_ACCESSORS(eval_from_position)

  // [infos]: weak fixed array containing all shared function infos and scope
  // infos for eval created from this script.
  DECL_ACCESSORS(infos, Tagged<WeakFixedArray>)

#if V8_ENABLE_WEBASSEMBLY
  // [wasm_breakpoint_infos]: the list of {BreakPointInfo} objects describing
  // all WebAssembly breakpoints for modules/instances managed via this script.
  // This must only be called if the type of this script is TYPE_WASM.
  DECL_ACCESSORS(wasm_breakpoint_infos, Tagged<FixedArray>)
  inline bool has_wasm_breakpoint_infos() const;

  // [wasm_native_module]: the wasm {NativeModule} this script belongs to.
  // This must only be called if the type of this script is TYPE_WASM.
  DECL_ACCESSORS(wasm_managed_native_module, Tagged<Object>)
  inline wasm::NativeModule* wasm_native_module() const;

  // [wasm_weak_instance_list]: the list of all {WasmInstanceObject} being
  // affected by breakpoints that are managed via this script.
  // This must only be called if the type of this script is TYPE_WASM.
  DECL_ACCESSORS(wasm_weak_instance_list, Tagged<WeakArrayList>)

  // [break_on_entry] (wasm only): whether an instrumentation breakpoint is set
  // for this script; this information will be transferred to existing and
  // future instances to make sure that we stop before executing any code in
  // this wasm module.
  inline bool break_on_entry() const;
  inline void set_break_on_entry(bool value);

  // Check if the script contains any Asm modules.
  bool ContainsAsmModule();
#endif  // V8_ENABLE_WEBASSEMBLY

  // Read/write the raw 'flags' field. This uses relaxed atomic loads/stores
  // because the flags are read by background compile threads and updated by the
  // main thread.
  inline uint32_t flags() const;
  inline void set_flags(uint32_t new_flags);

  // [compilation_type]: how the the script was compiled. Encoded in the
  // 'flags' field.
  inline CompilationType compilation_type() const;
  inline void set_compilation_type(CompilationType type);

  inline bool produce_compile_hints() const;
  inline void set_produce_compile_hints(bool produce_compile_hints);

  inline bool deserialized() const;
  inline void set_deserialized(bool value);

  // [compilation_state]: determines whether the script has already been
  // compiled. Encoded in the 'flags' field.
  inline CompilationState compilation_state();
  inline void set_compilation_state(CompilationState state);

  // [is_repl_mode]: whether this script originated from a REPL via debug
  // evaluate and therefore has different semantics, e.g. re-declaring let.
  inline bool is_repl_mode() const;
  inline void set_is_repl_mode(bool value);

  // [origin_options]: optional attributes set by the embedder via ScriptOrigin,
  // and used by the embedder to make decisions about the script. V8 just passes
  // this through. Encoded in the 'flags' field.
  inline v8::ScriptOriginOptions origin_options();
  inline void set_origin_options(ScriptOriginOptions origin_options);

  DECL_ACCESSORS(compiled_lazy_function_positions, Tagged<Object>)

  // If script source is an external string, check that the underlying
  // resource is accessible. Otherwise, always return true.
  inline bool HasValidSource();

  // If the script has a non-empty sourceURL comment.
  inline bool HasSourceURLComment() const;

  // Streaming compilation only attaches the source to the Script upon
  // finalization. This predicate returns true, if this script may still be
  // unfinalized.
  inline bool IsMaybeUnfinalized(Isolate* isolate) const;

  Tagged<Object> GetNameOrSourceURL();
  static Handle<String> GetScriptHash(Isolate* isolate,
                                      DirectHandle<Script> script,
                                      bool forceForInspector);

  // Retrieve source position from where eval was called.
  static int GetEvalPosition(Isolate* isolate, DirectHandle<Script> script);

  Tagged<Script> inline GetEvalOrigin();

  // Initialize line_ends array with source code positions of line ends if
  // it doesn't exist yet.
  static inline void InitLineEnds(Isolate* isolate,
                                  DirectHandle<Script> script);
  static inline void InitLineEnds(LocalIsolate* isolate,
                                  DirectHandle<Script> script);

  // Obtain line ends as a vector, without modifying the script object
  V8_EXPORT_PRIVATE static String::LineEndsVector GetLineEnds(
      Isolate* isolate, DirectHandle<Script> script);

  inline bool has_line_ends() const;

  // Will initialize the line ends if required.
  static void SetSource(Isolate* isolate, DirectHandle<Script> script,
                        DirectHandle<String> source);

  bool inline CanHaveLineEnds() const;

  // Carries information about a source position.
  struct PositionInfo {
    PositionInfo() : line(-1), column(-1), line_start(-1), line_end(-1) {}

    int line;        // Zero-based line number.
    int column;      // Zero-based column number.
    int line_start;  // Position of first character in line.
    int line_end;    // Position of final linebreak character in line.
  };

  // Specifies whether to add offsets to position infos.
  enum class OffsetFlag { kNoOffset, kWithOffset };

  // Retrieves information about the given position, optionally with an offset.
  // Returns false on failure, and otherwise writes into the given info object
  // on success.
  // The static method should is preferable for handlified callsites because it
  // initializes the line ends array, avoiding expensive recomputations.
  // The non-static version is not allocating and safe for unhandlified
  // callsites.
  static bool GetPositionInfo(DirectHandle<Script> script, int position,
                              PositionInfo* info,
                              OffsetFlag offset_flag = OffsetFlag::kWithOffset);
  static bool GetLineColumnWithLineEnds(
      int position, int& line, int& column,
      const String::LineEndsVector& line_ends);
  V8_EXPORT_PRIVATE bool GetPositionInfo(
      int position, PositionInfo* info,
      OffsetFlag offset_flag = OffsetFlag::kWithOffset) const;
  V8_EXPORT_PRIVATE bool GetPositionInfoWithLineEnds(
      int position, PositionInfo* info, const String::LineEndsVector& line_ends,
      OffsetFlag offset_flag = OffsetFlag::kWithOffset) const;
  V8_EXPORT_PRIVATE void AddPositionInfoOffset(
      PositionInfo* info,
      OffsetFlag offset_flag = OffsetFlag::kWithOffset) const;

  // Tells whether this script should be subject to debugging, e.g. for
  // - scope inspection
  // - internal break points
  // - coverage and type profile
  // - error stack trace
  bool IsSubjectToDebugging() const;

  bool IsUserJavaScript() const;

  // Wrappers for GetPositionInfo
  static int GetColumnNumber(DirectHandle<Script> script, int code_offset);
  int GetColumnNumber(int code_pos) const;
  V8_EXPORT_PRIVATE static int GetLineNumber(DirectHandle<Script> script,
                                             int code_offset);
  int GetLineNumber(int code_pos) const;

  // Look through the list of existing shared function infos to find one
  // that matches the function literal. Return empty handle if not found.
  template <typename IsolateT>
  static MaybeHandle<SharedFunctionInfo> FindSharedFunctionInfo(
      DirectHandle<Script> script, IsolateT* isolate,
      FunctionLiteral* function_literal);

  // Iterate over all script objects on the heap.
  class V8_EXPORT_PRIVATE Iterator {
   public:
    explicit Iterator(Isolate* isolate);
    Iterator(const Iterator&) = delete;
    Iterator& operator=(const Iterator&) = delete;
    Tagged<Script> Next();

   private:
    WeakArrayList::Iterator iterator_;
  };

  // Dispatched behavior.
  DECL_PRINTER(Script)
  DECL_VERIFIER(Script)

  using BodyDescriptor = StructBodyDescriptor;

 private:
  template <typename LineEndsContainer>
  bool GetPositionInfoInternal(const LineEndsContainer& ends, int position,
                               Script::PositionInfo* info,
                               const DisallowGarbageCollection& no_gc) const;

  friend Factory;
  friend FactoryBase<Factory>;
  friend FactoryBase<LocalFactory>;

  // Hide torque-generated accessor, use Script::SetSource instead.
  using TorqueGeneratedScript::set_source;

  // Bit positions in the flags field.
  DEFINE_TORQUE_GENERATED_SCRIPT_FLAGS()

  TQ_OBJECT_CONSTRUCTORS(Script)

  template <typename IsolateT>
  EXPORT_TEMPLATE_DECLARE(V8_EXPORT_PRIVATE)
  static void V8_PRESERVE_MOST
      InitLineEndsInternal(IsolateT* isolate, DirectHandle<Script> script);
};

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_SCRIPT_H_
```