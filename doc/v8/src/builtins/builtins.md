Response: Let's break down the thought process for analyzing this C++ code and summarizing its functionality, especially concerning its relationship with JavaScript.

1. **Initial Scan for Keywords and Structure:**  The first step is to quickly scan the code for recognizable keywords and structural elements. Things like `#include`, `namespace`, `struct`, `union`, `#define`, function definitions (e.g., `Address Builtin_...`), and the presence of a large constant array (`builtin_metadata`) are strong indicators of the file's purpose. The copyright notice confirms it's part of the V8 project.

2. **Identify the Core Data Structure:** The `builtin_metadata` array immediately stands out. The names within the `#define` macros (`DECL_CPP`, `DECL_TSJ`, etc.) strongly suggest that this array is mapping names to different types or properties of built-in functions. The `Builtins::Kind` enum further reinforces this. This looks like the central registry for built-in functionality.

3. **Analyze the `BuiltinMetadata` Structure:** Examining the members of `BuiltinMetadata` reveals more. `name` is obvious. `kind` tells us the *type* of builtin. The `data` union is crucial – it stores kind-specific information like C++ function pointers (`cpp_entry`), parameter counts (`parameter_count`), or bytecode information (`bytecode_and_scale`). This suggests different implementation approaches for built-ins.

4. **Infer the Role of the File:**  Based on the `builtin_metadata` and the surrounding code, it's highly likely that this file is responsible for:
    * **Defining and registering** all the built-in functions within the V8 engine.
    * **Providing metadata** about these built-ins (name, type, implementation details).
    * **Facilitating access** to these built-ins (e.g., looking them up by address or name).

5. **Look for JavaScript Connections:** The term "Builtin" itself suggests functions that are part of the core JavaScript language. The different `Builtins::Kind` values (CPP, TSJ, TFJ, BCH) hint at different implementation techniques, some of which might directly involve JavaScript or bytecode execution.

6. **Focus on Specific Functionalities and their JavaScript Implications:** Now, delve into specific functions:
    * `Builtins::Lookup(Address pc)`:  This function takes an address and tries to find the corresponding built-in. This is important for debugging, profiling, and understanding the call stack – all relevant to JavaScript execution.
    * `Builtins::code(Builtin builtin)` and `Builtins::code_handle(Builtin builtin)`: These functions retrieve the compiled code associated with a built-in. This is a direct link to how these functions are executed, whether it's native code or interpreted bytecode triggered by JavaScript calls.
    * `Builtins::GetStackParameterCount(Builtin builtin)`: This is explicitly about parameter counts, a fundamental concept in function calls in JavaScript.
    * `Builtins::CallInterfaceDescriptorFor(Builtin builtin)`: This function seems to define how built-ins are called, which is directly related to the calling conventions and execution mechanisms when JavaScript invokes these functions.
    * `Builtins::name(Builtin builtin)` and `Builtins::NameForStackTrace(Isolate* isolate, Builtin builtin)`: These are clearly about getting the names of built-ins, crucial for debugging and displaying meaningful information in stack traces when JavaScript code interacts with them. The `NameForStackTrace` function even has specific cases for `DataView` and `String` methods, solidifying the JavaScript connection.

7. **Connect the Dots with JavaScript Examples:**  At this point, you have enough understanding to construct JavaScript examples. Think about common built-in functions and how they might relate to the metadata and functionalities observed in the C++ code.

    * **`Math.abs()`**:  A classic example of a built-in JavaScript function likely implemented in C++ for performance.
    * **`Array.prototype.push()`**:  Another common method, potentially implemented with a mix of C++ and bytecode.
    * **`String.prototype.indexOf()`**:  The C++ code even mentions this explicitly in `NameForStackTrace`, making it an excellent example.
    * **`DataView` methods**:  These are also explicitly mentioned, showcasing how low-level data manipulation in JavaScript is often backed by optimized C++ implementations.

8. **Summarize and Refine:**  Finally, synthesize the observations into a clear and concise summary. Emphasize the core function of the file (defining and managing built-ins), the different types of built-ins, and how this relates to JavaScript functionality through concrete examples. Highlight the role of this file in the V8 engine's execution of JavaScript code.

**Self-Correction/Refinement during the process:**

* **Initially, I might have just focused on the `BUILTIN_LIST` macro without fully understanding `builtin_metadata`.**  Realizing that `builtin_metadata` *stores* the information defined by `BUILTIN_LIST` is a key refinement.
* **I might have overlooked the `Builtins::Kind` enum initially.**  Recognizing its significance in categorizing built-ins adds depth to the analysis.
* **Connecting the "CPP," "TSJ," etc., kinds to different implementation strategies** requires some deeper thought about how a JavaScript engine might work internally. This might involve recalling knowledge about interpreters, compilers, and the use of native code for performance.
* **The `NameForStackTrace` function is a particularly strong clue** regarding the connection to JavaScript and debugging. Don't just gloss over the specific examples within it.

By following these steps, moving from a broad overview to specific details and then connecting those details back to the bigger picture, you can effectively analyze and summarize complex source code like this. The key is to look for patterns, key data structures, and functions that reveal the file's underlying purpose and its interactions with other parts of the system (in this case, JavaScript).

这个C++源代码文件 `builtins.cc` 的主要功能是**定义和管理 V8 JavaScript 引擎的内置函数 (built-ins)**。它充当了 V8 引擎中一个核心的注册表，记录了各种内置函数的元数据，包括它们的名称、类型、以及如何调用它们。

更具体地说，这个文件做了以下事情：

1. **声明内置函数的 C++ 入口点:**  使用宏 `BUILTIN_LIST_C(FORWARD_DECLARE)` 声明了所有 C++ 实现的内置函数的函数签名。这些函数（例如 `Builtin_ArrayPush`，`Builtin_ObjectCreate` 等）的实际 C++ 代码可能在其他文件中。

2. **定义内置函数的元数据:**  通过 `builtin_metadata` 数组，定义了每个内置函数的关键信息。这些信息包括：
   - `name`:  内置函数的字符串名称，例如 "ArrayPush", "ObjectCreate"。
   - `kind`:  内置函数的类型，例如 `CPP` (C++ 实现), `TSJ` (Torque-generated JavaScript), `TFJ` (Torque-generated Function with JavaScript fallback) 等。这表明 V8 的内置函数可能以不同的方式实现。
   - `data`: 一个联合体，根据 `kind` 存储不同的数据：
     - 对于 `CPP` 函数，存储 C++ 函数的地址 (`cpp_entry`)。
     - 对于 `TSJ`/`TFJ` 函数，存储参数个数 (`parameter_count`)。
     - 对于 `BCH` (Bytecode Handler) 函数，存储字节码和操作数规模。

3. **提供访问内置函数信息的接口:**  提供了各种静态方法来查询内置函数的信息，例如：
   - `Builtins::Lookup(Address pc)`:  根据程序计数器 (pc) 查找对应的内置函数名称（用于调试和分析）。
   - `Builtins::code(Builtin builtin)`: 获取内置函数的 `Code` 对象（已编译的代码）。
   - `Builtins::name(Builtin builtin)`: 获取内置函数的名称。
   - `Builtins::KindOf(Builtin builtin)`: 获取内置函数的类型。
   - `Builtins::CppEntryOf(Builtin builtin)`: 获取 C++ 实现的内置函数的入口地址。
   - `Builtins::CallInterfaceDescriptorFor(Builtin builtin)`:  获取调用内置函数所需的接口描述符。

4. **处理内置函数的调用约定:**  `CallInterfaceDescriptorFor` 函数定义了不同类型内置函数的调用约定，这与 JavaScript 如何调用这些内置函数密切相关。

5. **支持字节码处理器的内置函数:**  `BCH` 类型的内置函数表示由解释器直接执行的字节码处理器。

**与 JavaScript 的关系以及示例**

`builtins.cc` 中定义的内置函数是 JavaScript 语言的核心组成部分。当 JavaScript 代码执行时，许多操作最终会调用这些内置函数。

**JavaScript 例子:**

1. **`Math.abs()`:**

   ```javascript
   let result = Math.abs(-5); // 调用 Math 对象的 abs 方法
   ```

   在 V8 引擎内部，当执行 `Math.abs(-5)` 时，会调用 `builtins.cc` 中定义并注册的 `Builtin_MathAbs` (假设它是 C++ 实现的，即 `kind` 为 `CPP`)。`Builtin_MathAbs` 函数会用 C++ 代码高效地计算绝对值。

2. **`Array.prototype.push()`:**

   ```javascript
   let arr = [1, 2, 3];
   arr.push(4); // 调用数组的 push 方法
   ```

   执行 `arr.push(4)` 会调用 `builtins.cc` 中注册的 `Builtin_ArrayPush`。这个内置函数会用 C++ 代码实现将元素添加到数组末尾的操作。

3. **`String.prototype.indexOf()`:**

   ```javascript
   let str = "hello world";
   let index = str.indexOf("world"); // 调用字符串的 indexOf 方法
   ```

   类似地，`str.indexOf("world")` 会调用 `builtins.cc` 中对应的内置函数，该函数会用高效的算法在字符串中查找子字符串。

4. **对象创建:**

   ```javascript
   let obj = {}; // 创建一个空对象
   ```

   创建空对象的操作也可能涉及到调用内置函数，例如 `Builtin_ObjectCreate`。

**`builtin_metadata` 数组的关联:**

`builtin_metadata` 数组存储了这些内置函数的关键信息。例如，对于 `Math.abs()`，`builtin_metadata` 中可能包含：

```c++
{"MathAbs", Builtins::CPP, {FUNCTION_ADDR(Builtin_MathAbs)}},
```

这表明 `MathAbs` 是一个 `CPP` 类型的内置函数，并且它的 C++ 实现入口点是 `Builtin_MathAbs` 函数的地址。

对于使用 Torque 生成的 JavaScript 代码的内置函数，例如 `Array.prototype.map()` (假设是 `TFJ` 类型)，`builtin_metadata` 可能包含参数个数信息，以及可能存在的 JavaScript fallback 代码的入口点。

**总结:**

`v8/src/builtins/builtins.cc` 是 V8 引擎中一个至关重要的文件，它集中定义和管理了 JavaScript 语言的内置函数。它提供了元数据、访问接口，并处理了不同类型内置函数的调用约定。当 JavaScript 代码执行时，会频繁地调用这里定义的内置函数来完成各种核心操作。 理解这个文件有助于深入理解 V8 引擎如何执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/builtins/builtins.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins.h"

#include "src/api/api-inl.h"
#include "src/builtins/builtins-descriptors.h"
#include "src/builtins/builtins-inl.h"
#include "src/builtins/data-view-ops.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/isolate.h"
#include "src/interpreter/bytecodes.h"
#include "src/logging/code-events.h"  // For CodeCreateEvent.
#include "src/logging/log.h"          // For V8FileLogger.
#include "src/objects/fixed-array.h"
#include "src/objects/objects-inl.h"
#include "src/objects/visitors.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

// Forward declarations for C++ builtins.
#define FORWARD_DECLARE(Name, Argc) \
  Address Builtin_##Name(int argc, Address* args, Isolate* isolate);
BUILTIN_LIST_C(FORWARD_DECLARE)
#undef FORWARD_DECLARE

namespace {

// TODO(jgruber): Pack in CallDescriptors::Key.
struct BuiltinMetadata {
  const char* name;
  Builtins::Kind kind;

  struct BytecodeAndScale {
    interpreter::Bytecode bytecode : 8;
    interpreter::OperandScale scale : 8;
  };

  static_assert(sizeof(interpreter::Bytecode) == 1);
  static_assert(sizeof(interpreter::OperandScale) == 1);
  static_assert(sizeof(BytecodeAndScale) <= sizeof(Address));

  // The `data` field has kind-specific contents.
  union KindSpecificData {
    // TODO(jgruber): Union constructors are needed since C++11 does not support
    // designated initializers (e.g.: {.parameter_count = count}). Update once
    // we're at C++20 :)
    // The constructors are marked constexpr to avoid the need for a static
    // initializer for builtins.cc (see check-static-initializers.sh).
    constexpr KindSpecificData() : cpp_entry(kNullAddress) {}
    constexpr KindSpecificData(Address cpp_entry) : cpp_entry(cpp_entry) {}
    constexpr KindSpecificData(int parameter_count,
                               int /* To disambiguate from above */)
        : parameter_count(static_cast<int16_t>(parameter_count)) {}
    constexpr KindSpecificData(interpreter::Bytecode bytecode,
                               interpreter::OperandScale scale)
        : bytecode_and_scale{bytecode, scale} {}
    Address cpp_entry;                    // For CPP builtins.
    int16_t parameter_count;              // For TFJ builtins.
    BytecodeAndScale bytecode_and_scale;  // For BCH builtins.
  } data;
};

#define DECL_CPP(Name, Argc) \
  {#Name, Builtins::CPP, {FUNCTION_ADDR(Builtin_##Name)}},
#define DECL_TSJ(Name, Count, ...) {#Name, Builtins::TSJ, {Count, 0}},
#define DECL_TFJ(Name, Count, ...) {#Name, Builtins::TFJ, {Count, 0}},
#define DECL_TSC(Name, ...) {#Name, Builtins::TSC, {}},
#define DECL_TFC(Name, ...) {#Name, Builtins::TFC, {}},
#define DECL_TFS(Name, ...) {#Name, Builtins::TFS, {}},
#define DECL_TFH(Name, ...) {#Name, Builtins::TFH, {}},
#define DECL_BCH(Name, OperandScale, Bytecode) \
  {#Name, Builtins::BCH, {Bytecode, OperandScale}},
#define DECL_ASM(Name, ...) {#Name, Builtins::ASM, {}},
const BuiltinMetadata builtin_metadata[] = {
    BUILTIN_LIST(DECL_CPP, DECL_TSJ, DECL_TFJ, DECL_TSC, DECL_TFC, DECL_TFS,
                 DECL_TFH, DECL_BCH, DECL_ASM)};
#undef DECL_CPP
#undef DECL_TFJ
#undef DECL_TSC
#undef DECL_TFC
#undef DECL_TFS
#undef DECL_TFH
#undef DECL_BCH
#undef DECL_ASM

}  // namespace

BytecodeOffset Builtins::GetContinuationBytecodeOffset(Builtin builtin) {
  DCHECK(Builtins::KindOf(builtin) == TFJ || Builtins::KindOf(builtin) == TFC ||
         Builtins::KindOf(builtin) == TFS);
  return BytecodeOffset(BytecodeOffset::kFirstBuiltinContinuationId +
                        ToInt(builtin));
}

Builtin Builtins::GetBuiltinFromBytecodeOffset(BytecodeOffset id) {
  Builtin builtin = Builtins::FromInt(
      id.ToInt() - BytecodeOffset::kFirstBuiltinContinuationId);
  DCHECK(Builtins::KindOf(builtin) == TFJ || Builtins::KindOf(builtin) == TFC ||
         Builtins::KindOf(builtin) == TFS);
  return builtin;
}

void Builtins::TearDown() { initialized_ = false; }

const char* Builtins::Lookup(Address pc) {
  // Off-heap pc's can be looked up through binary search.
  Builtin builtin = OffHeapInstructionStream::TryLookupCode(isolate_, pc);
  if (Builtins::IsBuiltinId(builtin)) return name(builtin);

  // May be called during initialization (disassembler).
  if (!initialized_) return nullptr;
  for (Builtin builtin_ix = Builtins::kFirst; builtin_ix <= Builtins::kLast;
       ++builtin_ix) {
    if (code(builtin_ix)->contains(isolate_, pc)) {
      return name(builtin_ix);
    }
  }
  return nullptr;
}

FullObjectSlot Builtins::builtin_slot(Builtin builtin) {
  Address* location = &isolate_->builtin_table()[Builtins::ToInt(builtin)];
  return FullObjectSlot(location);
}

FullObjectSlot Builtins::builtin_tier0_slot(Builtin builtin) {
  DCHECK(IsTier0(builtin));
  Address* location =
      &isolate_->builtin_tier0_table()[Builtins::ToInt(builtin)];
  return FullObjectSlot(location);
}

void Builtins::set_code(Builtin builtin, Tagged<Code> code) {
  DCHECK_EQ(builtin, code->builtin_id());
  DCHECK(Internals::HasHeapObjectTag(code.ptr()));
  // The given builtin may be uninitialized thus we cannot check its type here.
  isolate_->builtin_table()[Builtins::ToInt(builtin)] = code.ptr();
}

Tagged<Code> Builtins::code(Builtin builtin) {
  Address ptr = isolate_->builtin_table()[Builtins::ToInt(builtin)];
  return Cast<Code>(Tagged<Object>(ptr));
}

Handle<Code> Builtins::code_handle(Builtin builtin) {
  Address* location = &isolate_->builtin_table()[Builtins::ToInt(builtin)];
  return Handle<Code>(location);
}

// static
int Builtins::GetStackParameterCount(Builtin builtin) {
  DCHECK(Builtins::KindOf(builtin) == TSJ || Builtins::KindOf(builtin) == TFJ);
  return builtin_metadata[ToInt(builtin)].data.parameter_count;
}

namespace {

void ParameterCountToString(char* buffer, size_t buffer_size,
                            int parameter_count) {
  if (parameter_count == kDontAdaptArgumentsSentinel) {
    snprintf(buffer, buffer_size, "kDontAdaptArgumentsSentinel");
  } else {
    snprintf(buffer, buffer_size, "JSParameterCount(%d)", parameter_count - 1);
  }
}

}  // namespace

// static
bool Builtins::CheckFormalParameterCount(
    Builtin builtin, int function_length,
    int formal_parameter_count_with_receiver) {
  DCHECK_LE(0, function_length);
  if (!Builtins::IsBuiltinId(builtin)) {
    return true;
  }

  Kind kind = KindOf(builtin);
  // TODO(ishell): enable the check for TFJ/TSJ.
  if (kind == CPP) {
    int parameter_count = Builtins::GetFormalParameterCount(builtin);
    if (parameter_count != formal_parameter_count_with_receiver) {
      if ((false)) {
        // Enable this block to print a command line that should fix the
        // mismatch.
        const size_t kBufSize = 32;
        char actual_count[kBufSize];
        char expected_count[kBufSize];
        ParameterCountToString(actual_count, kBufSize, parameter_count);
        ParameterCountToString(expected_count, kBufSize,
                               formal_parameter_count_with_receiver);
        PrintF(
            "\n##### "
            "sed -i -z -r 's/%s\\(%s,[\\\\\\n[:space:]]+%s\\)/%s(%s, %s)/g' "
            "src/builtins/builtins-definitions.h\n",
            KindNameOf(builtin), name(builtin), actual_count,
            KindNameOf(builtin), name(builtin), expected_count);
      }
      return false;
    }
  }
  return true;
}

// static
CallInterfaceDescriptor Builtins::CallInterfaceDescriptorFor(Builtin builtin) {
  CallDescriptors::Key key;
  switch (builtin) {
// This macro is deliberately crafted so as to emit very little code,
// in order to keep binary size of this function under control.
#define CASE_OTHER(Name, ...)                          \
  case Builtin::k##Name: {                             \
    key = Builtin_##Name##_InterfaceDescriptor::key(); \
    break;                                             \
  }
    BUILTIN_LIST(IGNORE_BUILTIN, IGNORE_BUILTIN, IGNORE_BUILTIN, CASE_OTHER,
                 CASE_OTHER, CASE_OTHER, CASE_OTHER, IGNORE_BUILTIN, CASE_OTHER)
#undef CASE_OTHER
    default:
      Builtins::Kind kind = Builtins::KindOf(builtin);
      DCHECK_NE(BCH, kind);
      if (kind == TSJ || kind == TFJ || kind == CPP) {
        return JSTrampolineDescriptor{};
      }
      UNREACHABLE();
  }
  return CallInterfaceDescriptor{key};
}

// static
Callable Builtins::CallableFor(Isolate* isolate, Builtin builtin) {
  Handle<Code> code = isolate->builtins()->code_handle(builtin);
  return Callable{code, CallInterfaceDescriptorFor(builtin)};
}

// static
bool Builtins::HasJSLinkage(Builtin builtin) {
  DCHECK_NE(BCH, Builtins::KindOf(builtin));
  return CallInterfaceDescriptorFor(builtin) == JSTrampolineDescriptor{};
}

// static
const char* Builtins::name(Builtin builtin) {
  int index = ToInt(builtin);
  DCHECK(IsBuiltinId(index));
  return builtin_metadata[index].name;
}

// static
const char* Builtins::NameForStackTrace(Isolate* isolate, Builtin builtin) {
#if V8_ENABLE_WEBASSEMBLY
  // Most builtins are never shown in stack traces. Those that are exposed
  // to JavaScript get their name from the object referring to them. Here
  // we only support a few internal builtins that have special reasons for
  // being shown on stack traces:
  // - builtins that are allowlisted in {StubFrame::Summarize}.
  // - builtins that throw the same error as one of those above, but would
  //   lose information and e.g. print "indexOf" instead of "String.indexOf".
  switch (builtin) {
    case Builtin::kDataViewPrototypeGetBigInt64:
      return "DataView.prototype.getBigInt64";
    case Builtin::kDataViewPrototypeGetBigUint64:
      return "DataView.prototype.getBigUint64";
    case Builtin::kDataViewPrototypeGetFloat16:
      return "DataView.prototype.getFloat16";
    case Builtin::kDataViewPrototypeGetFloat32:
      return "DataView.prototype.getFloat32";
    case Builtin::kDataViewPrototypeGetFloat64:
      return "DataView.prototype.getFloat64";
    case Builtin::kDataViewPrototypeGetInt8:
      return "DataView.prototype.getInt8";
    case Builtin::kDataViewPrototypeGetInt16:
      return "DataView.prototype.getInt16";
    case Builtin::kDataViewPrototypeGetInt32:
      return "DataView.prototype.getInt32";
    case Builtin::kDataViewPrototypeGetUint8:
      return "DataView.prototype.getUint8";
    case Builtin::kDataViewPrototypeGetUint16:
      return "DataView.prototype.getUint16";
    case Builtin::kDataViewPrototypeGetUint32:
      return "DataView.prototype.getUint32";
    case Builtin::kDataViewPrototypeSetBigInt64:
      return "DataView.prototype.setBigInt64";
    case Builtin::kDataViewPrototypeSetBigUint64:
      return "DataView.prototype.setBigUint64";
    case Builtin::kDataViewPrototypeSetFloat16:
      return "DataView.prototype.setFloat16";
    case Builtin::kDataViewPrototypeSetFloat32:
      return "DataView.prototype.setFloat32";
    case Builtin::kDataViewPrototypeSetFloat64:
      return "DataView.prototype.setFloat64";
    case Builtin::kDataViewPrototypeSetInt8:
      return "DataView.prototype.setInt8";
    case Builtin::kDataViewPrototypeSetInt16:
      return "DataView.prototype.setInt16";
    case Builtin::kDataViewPrototypeSetInt32:
      return "DataView.prototype.setInt32";
    case Builtin::kDataViewPrototypeSetUint8:
      return "DataView.prototype.setUint8";
    case Builtin::kDataViewPrototypeSetUint16:
      return "DataView.prototype.setUint16";
    case Builtin::kDataViewPrototypeSetUint32:
      return "DataView.prototype.setUint32";
    case Builtin::kDataViewPrototypeGetByteLength:
      return "get DataView.prototype.byteLength";
    case Builtin::kThrowDataViewDetachedError:
    case Builtin::kThrowDataViewOutOfBounds:
    case Builtin::kThrowDataViewTypeError: {
      DataViewOp op = static_cast<DataViewOp>(isolate->error_message_param());
      return ToString(op);
    }
    case Builtin::kStringPrototypeToLocaleLowerCase:
      return "String.toLocaleLowerCase";
    case Builtin::kStringPrototypeIndexOf:
    case Builtin::kThrowIndexOfCalledOnNull:
      return "String.indexOf";
#if V8_INTL_SUPPORT
    case Builtin::kStringPrototypeToLowerCaseIntl:
#endif
    case Builtin::kThrowToLowerCaseCalledOnNull:
      return "String.toLowerCase";
    case Builtin::kWasmIntToString:
      return "Number.toString";
    default:
      // Callers getting this might well crash, which might be desirable
      // because it's similar to {UNREACHABLE()}, but contrary to that a
      // careful caller can also check the value and use it as an "is a
      // name available for this builtin?" check.
      return nullptr;
  }
#else
  return nullptr;
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Builtins::PrintBuiltinCode() {
  DCHECK(v8_flags.print_builtin_code);
#ifdef ENABLE_DISASSEMBLER
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    const char* builtin_name = name(builtin);
    if (PassesFilter(base::CStrVector(builtin_name),
                     base::CStrVector(v8_flags.print_builtin_code_filter))) {
      CodeTracer::Scope trace_scope(isolate_->GetCodeTracer());
      OFStream os(trace_scope.file());
      Tagged<Code> builtin_code = code(builtin);
      builtin_code->Disassemble(builtin_name, os, isolate_);
      os << "\n";
    }
  }
#endif
}

void Builtins::PrintBuiltinSize() {
  DCHECK(v8_flags.print_builtin_size);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    const char* builtin_name = name(builtin);
    const char* kind = KindNameOf(builtin);
    Tagged<Code> code = Builtins::code(builtin);
    PrintF(stdout, "%s Builtin, %s, %d\n", kind, builtin_name,
           code->instruction_size());
  }
}

// static
Address Builtins::CppEntryOf(Builtin builtin) {
  DCHECK(Builtins::IsCpp(builtin));
  return builtin_metadata[ToInt(builtin)].data.cpp_entry;
}

// static
bool Builtins::IsBuiltin(const Tagged<Code> code) {
  return Builtins::IsBuiltinId(code->builtin_id());
}

bool Builtins::IsBuiltinHandle(Handle<HeapObject> maybe_code,
                               Builtin* builtin) const {
  Address* handle_location = maybe_code.location();
  Address* builtins_table = isolate_->builtin_table();
  if (handle_location < builtins_table) return false;
  Address* builtins_table_end = &builtins_table[Builtins::kBuiltinCount];
  if (handle_location >= builtins_table_end) return false;
  *builtin = FromInt(static_cast<int>(handle_location - builtins_table));
  return true;
}

// static
bool Builtins::IsIsolateIndependentBuiltin(Tagged<Code> code) {
  Builtin builtin = code->builtin_id();
  return Builtins::IsBuiltinId(builtin) &&
         Builtins::IsIsolateIndependent(builtin);
}

// static
void Builtins::InitializeIsolateDataTables(Isolate* isolate) {
  EmbeddedData embedded_data = EmbeddedData::FromBlob(isolate);
  IsolateData* isolate_data = isolate->isolate_data();

  // The entry table.
  for (Builtin i = Builtins::kFirst; i <= Builtins::kLast; ++i) {
    DCHECK(Builtins::IsBuiltinId(isolate->builtins()->code(i)->builtin_id()));
    DCHECK(!isolate->builtins()->code(i)->has_instruction_stream());
    isolate_data->builtin_entry_table()[ToInt(i)] =
        embedded_data.InstructionStartOf(i);
  }

  // T0 tables.
  for (Builtin i = Builtins::kFirst; i <= Builtins::kLastTier0; ++i) {
    const int ii = ToInt(i);
    isolate_data->builtin_tier0_entry_table()[ii] =
        isolate_data->builtin_entry_table()[ii];
    isolate_data->builtin_tier0_table()[ii] = isolate_data->builtin_table()[ii];
  }
}

// static
void Builtins::EmitCodeCreateEvents(Isolate* isolate) {
  if (!isolate->IsLoggingCodeCreation()) return;

  Address* builtins = isolate->builtin_table();
  int i = 0;
  HandleScope scope(isolate);
  for (; i < ToInt(Builtin::kFirstBytecodeHandler); i++) {
    Handle<Code> builtin_code(&builtins[i]);
    Handle<AbstractCode> code = Cast<AbstractCode>(builtin_code);
    PROFILE(isolate, CodeCreateEvent(LogEventListener::CodeTag::kBuiltin, code,
                                     Builtins::name(FromInt(i))));
  }

  static_assert(kLastBytecodeHandlerPlusOne == kBuiltinCount);
  for (; i < kBuiltinCount; i++) {
    Handle<Code> builtin_code(&builtins[i]);
    Handle<AbstractCode> code = Cast<AbstractCode>(builtin_code);
    interpreter::Bytecode bytecode =
        builtin_metadata[i].data.bytecode_and_scale.bytecode;
    interpreter::OperandScale scale =
        builtin_metadata[i].data.bytecode_and_scale.scale;
    PROFILE(isolate,
            CodeCreateEvent(
                LogEventListener::CodeTag::kBytecodeHandler, code,
                interpreter::Bytecodes::ToString(bytecode, scale).c_str()));
  }
}

// static
Handle<Code> Builtins::CreateInterpreterEntryTrampolineForProfiling(
    Isolate* isolate) {
  DCHECK_NOT_NULL(isolate->embedded_blob_code());
  DCHECK_NE(0, isolate->embedded_blob_code_size());

  Tagged<Code> code = isolate->builtins()->code(
      Builtin::kInterpreterEntryTrampolineForProfiling);

  CodeDesc desc;
  desc.buffer = reinterpret_cast<uint8_t*>(code->instruction_start());

  int instruction_size = code->instruction_size();
  desc.buffer_size = instruction_size;
  desc.instr_size = instruction_size;

  // Ensure the code doesn't require creation of metadata, otherwise respective
  // fields of CodeDesc should be initialized.
  DCHECK_EQ(code->safepoint_table_size(), 0);
  DCHECK_EQ(code->handler_table_size(), 0);
  DCHECK_EQ(code->constant_pool_size(), 0);
  // TODO(v8:11036): The following DCHECK currently fails if the mksnapshot is
  // run with enabled code comments, i.e. --interpreted_frames_native_stack is
  // incompatible with --code-comments at mksnapshot-time. If ever needed,
  // implement support.
  DCHECK_EQ(code->code_comments_size(), 0);
  DCHECK_EQ(code->unwinding_info_size(), 0);

  desc.safepoint_table_offset = instruction_size;
  desc.handler_table_offset = instruction_size;
  desc.constant_pool_offset = instruction_size;
  desc.code_comments_offset = instruction_size;
  desc.builtin_jump_table_info_offset = instruction_size;

  CodeDesc::Verify(&desc);

  return Factory::CodeBuilder(isolate, desc, CodeKind::BUILTIN)
      // Mimic the InterpreterEntryTrampoline.
      .set_builtin(Builtin::kInterpreterEntryTrampoline)
      .Build();
}

Builtins::Kind Builtins::KindOf(Builtin builtin) {
  DCHECK(IsBuiltinId(builtin));
  return builtin_metadata[ToInt(builtin)].kind;
}

// static
const char* Builtins::KindNameOf(Builtin builtin) {
  Kind kind = Builtins::KindOf(builtin);
  // clang-format off
  switch (kind) {
    case CPP: return "CPP";
    case TSJ: return "TSJ";
    case TFJ: return "TFJ";
    case TSC: return "TSC";
    case TFC: return "TFC";
    case TFS: return "TFS";
    case TFH: return "TFH";
    case BCH: return "BCH";
    case ASM: return "ASM";
  }
  // clang-format on
  UNREACHABLE();
}

// static
bool Builtins::IsCpp(Builtin builtin) {
  return Builtins::KindOf(builtin) == CPP;
}

// static
CodeEntrypointTag Builtins::EntrypointTagFor(Builtin builtin) {
  if (builtin == Builtin::kNoBuiltinId) {
    // Special case needed for example for tests.
    return kDefaultCodeEntrypointTag;
  }

#if V8_ENABLE_DRUMBRAKE
  if (builtin == Builtin::kGenericJSToWasmInterpreterWrapper) {
    return kJSEntrypointTag;
  } else if (builtin == Builtin::kGenericWasmToJSInterpreterWrapper) {
    return kWasmEntrypointTag;
  }
#endif  // V8_ENABLE_DRUMBRAKE

  Kind kind = Builtins::KindOf(builtin);
  switch (kind) {
    case CPP:
    case TSJ:
    case TFJ:
      return kJSEntrypointTag;
    case BCH:
      return kBytecodeHandlerEntrypointTag;
    case TFC:
    case TSC:
    case TFS:
    case TFH:
    case ASM:
      return CallInterfaceDescriptorFor(builtin).tag();
  }
  UNREACHABLE();
}

// static
bool Builtins::AllowDynamicFunction(Isolate* isolate,
                                    DirectHandle<JSFunction> target,
                                    Handle<JSObject> target_global_proxy) {
  if (v8_flags.allow_unsafe_function_constructor) return true;
  HandleScopeImplementer* impl = isolate->handle_scope_implementer();
  Handle<NativeContext> responsible_context = impl->LastEnteredContext();
  // TODO(verwaest): Remove this.
  if (responsible_context.is_null()) {
    return true;
  }
  if (*responsible_context == target->context()) return true;
  return isolate->MayAccess(responsible_context, target_global_proxy);
}

Builtin ExampleBuiltinForTorqueFunctionPointerType(
    size_t function_pointer_type_id) {
  switch (function_pointer_type_id) {
#define FUNCTION_POINTER_ID_CASE(id, name) \
  case id:                                 \
    return Builtin::k##name;
    TORQUE_FUNCTION_POINTER_TYPE_TO_BUILTIN_MAP(FUNCTION_POINTER_ID_CASE)
#undef FUNCTION_POINTER_ID_CASE
    default:
      UNREACHABLE();
  }
}

}  // namespace internal
}  // namespace v8

"""

```