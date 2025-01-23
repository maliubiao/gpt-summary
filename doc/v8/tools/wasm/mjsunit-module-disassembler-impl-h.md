Response:
Let's break down the thought process for analyzing this V8 header file.

**1. Initial Scan and Identification:**

* **File Extension:** The filename ends in `.h`, which immediately signals a C++ header file in V8. The prompt's conditional about `.tq` is a bit of a red herring –  it's good to note, but this file isn't Torque.
* **Copyright and Headers:** The standard copyright notice and `#ifndef` guards confirm it's a header. The included headers (`<ctime>`, various `src/wasm/` headers, `src/numbers/conversions.h`) provide initial clues about the file's purpose: time-related functions, WebAssembly specific components (decoding, disassembly, module representation), string building, and number conversions.
* **Namespace:** The code is within the `v8::internal::wasm` namespace, solidifying its connection to V8's internal WebAssembly implementation.

**2. Core Functionality - The `MjsunitModuleDis` Class:**

* **Central Role:** The comment block mentioning "module disassembler" and "mjsunit format" immediately points to the primary function. The key public method `PrintModule()` is explicitly mentioned, confirming this.
* **"mjsunit format":** This is a crucial piece of information. It tells us the output format targets V8's testing framework. Specifically, it's about generating JavaScript code that uses `WasmModuleBuilder` to recreate the disassembled module. This explains why the output examples in the code use methods like `.addFunction()`, `.addBody()`, etc.
* **Key Helpers and Data:**  Look for supporting classes and data members within `MjsunitModuleDis`. `MjsunitNamesProvider` stands out – it's responsible for generating meaningful names for functions, globals, etc., in the generated JavaScript. This addresses a potential user programming error (using incorrect names) if the disassembler didn't handle naming effectively.

**3. Deeper Dive into `MjsunitNamesProvider`:**

* **Naming Logic:** Carefully read the comments and the code within `MjsunitNamesProvider`. The steps for generating function names (name section, imports, exports, fallback to `$func123`) reveal the logic behind the naming scheme. The "suitable name" criteria are also important for understanding why certain names are chosen.
* **`Print...` Methods:**  The various `Print...` methods (e.g., `PrintFunctionName`, `PrintGlobalReferenceLeb`) demonstrate how different WebAssembly elements are represented in the output JavaScript code. The `MaybeLebScope` helper hints at handling LEB128 encoding.
* **Type Handling:** Pay attention to `PrintTypeVariableName`, `PrintStructType`, `PrintArrayType`, etc. This shows how WebAssembly types are translated into the `WasmModuleBuilder` syntax (e.g., `$struct0`, `wasmRefType()`). The `PrintHeapType` and `PrintValueType` functions are essential for handling different WebAssembly types.
* **`PrintMakeSignature`:** This function is responsible for generating the `makeSig()` calls in the JavaScript output, representing WebAssembly function signatures.

**4. Analyzing `MjsunitFunctionDis`:**

* **Purpose:** This class focuses on disassembling individual function bodies.
* **`WriteMjsunit`:** This is the core method for disassembling a function. Notice how it handles locals, the function body, and uses indentation for readability in the output JavaScript.
* **Opcode Handling:**  The logic for handling different opcodes (including prefix opcodes) is crucial. The `PrintPrefixedOpcode` function and the `switch` statement in `WriteMjsunit` are key here. The special handling for `kExprEnd`, `kExprDelegate`, `kExprElse`, etc., shows attention to detail for generating correct `WasmModuleBuilder` code.
* **Immediate Printing:**  The `PrintMjsunitImmediatesAndGetLength` function (and the separate `MjsunitImmediatesPrinter` class) are responsible for handling the operands (immediates) that follow each opcode. This involves correctly formatting numbers, indices, and other data.

**5. Identifying Potential Issues and Connections to JavaScript:**

* **JavaScript Interaction:** The entire purpose of the disassembler is to generate *JavaScript* code that uses `WasmModuleBuilder`. This is the primary relationship with JavaScript. The examples in the `Print...` methods directly illustrate this.
* **User Programming Errors:** The naming logic in `MjsunitNamesProvider` helps avoid name collisions that would break the generated test code. The comments in `WriteMjsunit` about invalid modules (missing `kExprEnd`) also point to potential errors.

**6. Hypothetical Input and Output:**

* To create an example, pick a simple WebAssembly snippet (e.g., a function that adds two numbers). Imagine the raw byte code for this function. Then, mentally trace how the `MjsunitFunctionDis` and `MjsunitNamesProvider` would process it, resulting in the corresponding `WasmModuleBuilder` JavaScript code.

**7. Structure and Summarization:**

* Organize the findings logically: Overall purpose, key classes, important methods, relationships with JavaScript, and potential issues. The prompt asks for a summary of the *functionality*, so focus on what the code *does*.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This looks like a standard disassembler."
* **Correction:** "Ah, it's not just *any* disassembler, it's specifically for generating *mjsunit* test cases, targeting the `WasmModuleBuilder` API." This realization significantly narrows down the interpretation.
* **Initial thought:** "The naming logic is probably straightforward."
* **Refinement:** "The naming logic is actually quite involved, considering name sections, imports, exports, and avoiding collisions with reserved names."  This highlights the complexity and importance of `MjsunitNamesProvider`.
* **Initial thought:** "The immediate printing is just about dumping bytes."
* **Refinement:** "No, the immediate printing is type-aware and formats the output according to the expected `WasmModuleBuilder` syntax (e.g., `wasmI32Const()`, `wasmRefType()`)."

By following these steps and constantly refining the understanding based on the code's details, one can arrive at a comprehensive and accurate description of the header file's functionality.好的，让我们来分析一下 `v8/tools/wasm/mjsunit-module-disassembler-impl.h` 这个 V8 源代码文件的功能。

**文件功能概览**

`v8/tools/wasm/mjsunit-module-disassembler-impl.h`  是一个 C++ 头文件，它定义了一个 WebAssembly 模块反汇编器的实现，其主要目标是生成可以在 V8 的 mjsunit 测试框架中使用的测试用例代码。

具体来说，这个反汇编器会将一个编译好的 WebAssembly 模块的二进制表示（字节码）转换成一段 JavaScript 代码，这段 JavaScript 代码使用 `test/mjsunit/wasm/wasm-module-builder.js` 中定义的 `WasmModuleBuilder` 对象来重新构建这个 WebAssembly 模块。

**功能详细列举**

1. **模块反汇编:**  核心功能是将 WebAssembly 模块的二进制数据解码并解析其结构，包括类型定义、导入、导出、函数、全局变量、内存、表格、数据段和元素段等。
2. **生成 mjsunit 格式的测试用例:**  它生成的输出是一段可以被 V8 的 mjsunit 测试框架执行的 JavaScript 代码。这种格式便于开发者编写和维护 WebAssembly 相关的测试。
3. **使用 `WasmModuleBuilder`:**  生成的 JavaScript 代码依赖于 `WasmModuleBuilder` 类来构建 WebAssembly 模块。`WasmModuleBuilder` 提供了一系列的方法，例如 `addFunction`、`addBody`、`addExport` 等，用于以声明式的方式定义 WebAssembly 模块的各个部分。
4. **处理 WebAssembly 的各种结构:**  它能够处理 WebAssembly 的各种特性和结构，包括但不限于：
    * 函数签名 (function signatures)
    * 局部变量 (local variables)
    * 指令 (instructions)
    * 控制流 (control flow: block, loop, if, else, try, catch)
    * 内存访问 (memory access)
    * 全局变量访问 (global variable access)
    * 表格操作 (table operations)
    * 类型定义 (type definitions，包括结构体和数组)
    * 引用类型 (reference types)
    * 数据段和元素段 (data and element segments)
5. **提供名称生成策略:**  `MjsunitNamesProvider` 类负责为 WebAssembly 模块中的各种实体（如函数、全局变量、类型等）生成有意义的 JavaScript 变量名，以便生成的测试代码更易读。它会尝试使用名称段中定义的名称、导入/导出名称，或者生成类似 `$func123` 的名称。
6. **处理 LEB128 编码:**  代码中可以看到对 LEB128 编码的处理 (`MaybeLebScope`)，这是一种在 WebAssembly 中用于紧凑表示整数的变长编码方式。
7. **处理不同的输出上下文:**  `OutputContext` 枚举用于控制输出的格式，例如在函数体内部输出原始的字节码 (`kEmitWireBytes`)，或者在模块构建器函数中输出 JavaScript 对象 (`kEmitObjects`)。
8. **提供辅助函数:**  包含一些辅助函数，例如用于打印不同类型的 WebAssembly 值类型 (`PrintValueType`) 和堆类型 (`PrintHeapType`)，以及生成函数签名的 JavaScript 表示 (`PrintMakeSignature`)。

**关于文件扩展名和 Torque**

如果 `v8/tools/wasm/mjsunit-module-disassembler-impl.h` 以 `.tq` 结尾，那么它确实会是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的类型化的中间语言，用于生成高效的 C++ 代码。但是，根据你提供的文件名，它以 `.h` 结尾，所以它是一个 C++ 头文件，包含了 C++ 类的声明和定义。

**与 JavaScript 的关系 (已通过 `WasmModuleBuilder` 说明)**

这个文件的核心功能就是为了生成 JavaScript 代码。它将底层的 WebAssembly 字节码转换成高层次的 JavaScript API 调用，使得开发者可以使用 `WasmModuleBuilder` 在 JavaScript 环境中重构相同的 WebAssembly 模块。

**代码逻辑推理、假设输入与输出**

假设我们有一个非常简单的 WebAssembly 模块，它定义了一个将两个 i32 类型的参数相加并返回结果的函数。

**假设输入的 WebAssembly 模块（简化表示）：**

```
模块结构:
  类型定义:
    - sig (i32, i32) -> i32
  函数定义:
    - 函数索引 0，使用上面的签名
    - 局部变量: 无
    - 函数体:
      local.get 0
      local.get 1
      i32.add
      end
  导出:
    - "add": 函数索引 0
```

**`MjsunitModuleDis` 可能生成的 JavaScript 输出 (简化示例)：**

```javascript
const builder = new WasmModuleBuilder();
builder.addType(makeSig([kWasmI32, kWasmI32], [kWasmI32])); // $sig0
builder.addFunction('$func0', '$sig0') // 假设命名为 $func0
  .addBody([
    kExprLocalGet, 0,  // local.get 0
    kExprLocalGet, 1,  // local.get 1
    kExprI32Add
  ]);
builder.addExport('add', '$func0');
const instance = builder.instantiate();
assertEquals(3, instance.exports.add(1, 2));
```

**用户常见的编程错误示例**

这个头文件本身主要是 V8 内部实现，用户不会直接编写或修改它。然而，如果用户试图手动编写类似于这个反汇编器生成的 `WasmModuleBuilder` 代码，可能会犯以下错误：

1. **错误的 opcode 或参数:**  在 `addBody` 中使用错误的 `kExpr...` 常量，或者为指令提供错误的参数数量或类型。

   ```javascript
   // 错误示例：使用了不存在的 opcode
   builder.addFunction('myFunc', kSig_v_v)
     .addBody([kExprInvalidOpcode]); // 假设 kExprInvalidOpcode 不存在
   ```

2. **类型不匹配:**  在定义函数签名或局部变量时使用了不兼容的类型。

   ```javascript
   // 错误示例：函数体试图返回一个值，但签名声明没有返回值
   builder.addFunction('badFunc', kSig_v_v)
     .addBody([kExprI32Const, 10, kExprReturn]); // 签名是 v_v，不应该有返回值
   ```

3. **名称冲突:**  在手动命名函数、全局变量等时，使用的名称与 `WasmModuleBuilder` 内部生成的名称或其他保留名称冲突。虽然 `MjsunitNamesProvider` 尝试避免这种情况，但手动编写时可能会发生。

4. **忘记添加导出或导入:**  如果 WebAssembly 模块有导出或导入，但在 `WasmModuleBuilder` 代码中忘记添加相应的 `addExport` 或 `addImport` 调用，会导致构建的模块与原始模块不一致。

**功能归纳 (针对第 1 部分)**

`v8/tools/wasm/mjsunit-module-disassembler-impl.h` 的主要功能是**实现一个 WebAssembly 模块反汇编器，其目的是将 WebAssembly 模块的二进制表示转换为使用 `WasmModuleBuilder` API 的 JavaScript 代码，以便在 V8 的 mjsunit 测试框架中进行测试和验证。** 它负责解析模块的结构，生成相应的 `WasmModuleBuilder` 调用，并提供命名策略以使生成的代码更易读。这个工具对于 V8 开发者理解和测试 WebAssembly 实现的各个方面至关重要。

请提供第 2 部分的内容，以便我继续进行分析。

### 提示词
```
这是目录为v8/tools/wasm/mjsunit-module-disassembler-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/tools/wasm/mjsunit-module-disassembler-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TOOLS_WASM_MJSUNIT_MODULE_DISASSEMBLER_IMPL_H_
#define V8_TOOLS_WASM_MJSUNIT_MODULE_DISASSEMBLER_IMPL_H_

#include <ctime>

#include "src/numbers/conversions.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/module-decoder-impl.h"
#include "src/wasm/string-builder-multiline.h"
#include "src/wasm/wasm-disassembler-impl.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes-inl.h"

namespace v8::internal::wasm {

// Provides an implementation of a module disassembler that can produce
// test cases in "mjsunit format", i.e. using the WasmModuleBuilder from
// test/mjsunit/wasm/wasm-module-builder.js to define the module.
//
// The one relevant public method is MjsunitModuleDis::PrintModule().

static constexpr char kHexChars[] = "0123456789abcdef";

StringBuilder& operator<<(StringBuilder& sb, base::Vector<const char> chars) {
  sb.write(chars.cbegin(), chars.size());
  return sb;
}

enum OutputContext : bool {
  // Print "kAnyRefCode" and "kWasmRef, 1," etc (inside function bodies).
  kEmitWireBytes = true,
  // Print "kWasmAnyRef" and "wasmRefType(1)" etc (in module builder functions).
  kEmitObjects = false,
};

// Helper to surround a value by an optional ...wasmUnsignedLeb() call.
class MaybeLebScope {
 public:
  MaybeLebScope(StringBuilder& out, uint32_t index) : out(out), index(index) {
    if (index > 0x7F) {
      out << "...wasmUnsignedLeb(";
    }
  }
  ~MaybeLebScope() {
    if (index > 0x7F) {
      out << ')';
    }
  }

 private:
  StringBuilder& out;
  uint32_t index;
};

class MjsunitNamesProvider {
 public:
  static constexpr const char* kLocalPrefix = "$var";

  MjsunitNamesProvider(const WasmModule* module, ModuleWireBytes wire_bytes)
      : module_(module), wire_bytes_(wire_bytes) {
    function_variable_names_.resize(module->functions.size());
    // Algorithm for selecting function names:
    // 1. If the name section defines a suitable name, use that.
    // 2. Else, if the function is imported and the import "field name" is
    //    a suitable name, use that.
    // 3. Else, if the function is exported and its export name is a
    //    suitable name, use that.
    // 4. Else, generate a name like "$func123".
    // The definition of "suitable" is:
    // - the name has at least one character
    // - and all characters are in the set [a-zA-Z0-9$_]
    // - and the name doesn't clash with common auto-generated names.
    for (uint32_t i = 0; i < module->functions.size(); i++) {
      WireBytesRef name =
          module_->lazily_generated_names.LookupFunctionName(wire_bytes, i);
      if (IsSuitableFunctionVariableName(name)) {
        function_variable_names_[i] = name;
      }
    }
    for (const WasmImport& imp : module_->import_table) {
      if (imp.kind != kExternalFunction) continue;
      if (function_variable_names_[imp.index].is_set()) continue;
      if (IsSuitableFunctionVariableName(imp.field_name)) {
        function_variable_names_[imp.index] = imp.field_name;
      }
    }
    for (const WasmExport& ex : module_->export_table) {
      if (ex.kind != kExternalFunction) continue;
      if (function_variable_names_[ex.index].is_set()) continue;
      if (IsSuitableFunctionVariableName(ex.name)) {
        function_variable_names_[ex.index] = ex.name;
      }
    }
  }

  bool HasFunctionName(uint32_t function_index) {
    WireBytesRef ref = module_->lazily_generated_names.LookupFunctionName(
        wire_bytes_, function_index);
    return ref.is_set();
  }

  bool FunctionNameEquals(uint32_t function_index, WireBytesRef ref) {
    WireBytesRef name_ref = module_->lazily_generated_names.LookupFunctionName(
        wire_bytes_, function_index);
    if (name_ref.length() != ref.length()) return false;
    if (name_ref.offset() == ref.offset()) return true;
    WasmName name = wire_bytes_.GetNameOrNull(name_ref);
    WasmName question = wire_bytes_.GetNameOrNull(ref);
    return memcmp(name.begin(), question.begin(), name.length()) == 0;
  }

  void PrintTypeVariableName(StringBuilder& out, ModuleTypeIndex index) {
    // The name creation scheme must be in sync with {PrintStructType} etc.
    // below!
    if (module_->has_struct(index)) {
      out << "$struct" << index;
    } else if (module_->has_array(index)) {
      out << "$array" << index;
    } else {
      // This function is meant for dumping the type section, so we can assume
      // validity.
      DCHECK(module_->has_signature(index));
      out << "$sig" << index;
    }
  }

  void PrintStructType(StringBuilder& out, ModuleTypeIndex index,
                       OutputContext mode) {
    DCHECK(module_->has_struct(index));
    PrintMaybeLEB(out, "$struct", index, mode);
  }

  void PrintArrayType(StringBuilder& out, ModuleTypeIndex index,
                      OutputContext mode) {
    DCHECK(module_->has_array(index));
    PrintMaybeLEB(out, "$array", index, mode);
  }

  void PrintSigType(StringBuilder& out, ModuleTypeIndex index,
                    OutputContext mode) {
    DCHECK(module_->has_signature(index));
    PrintMaybeLEB(out, "$sig", index, mode);
  }

  void PrintTypeIndex(StringBuilder& out, ModuleTypeIndex index,
                      OutputContext mode) {
    if (module_->has_struct(index)) {
      PrintStructType(out, index, mode);
    } else if (module_->has_array(index)) {
      PrintArrayType(out, index, mode);
    } else if (module_->has_signature(index)) {
      PrintSigType(out, index, mode);
    } else {
      // Support building invalid modules for testing.
      PrintMaybeLEB(out, "/* invalid type */ ", index, mode);
    }
  }

  // For the name section.
  void PrintFunctionName(StringBuilder& out, uint32_t index) {
    WireBytesRef ref =
        module_->lazily_generated_names.LookupFunctionName(wire_bytes_, index);
    DCHECK(ref.is_set());  // Callers should use `HasFunctionName` to check.
    out.write(wire_bytes_.start() + ref.offset(), ref.length());
  }

  // For the JS variable referring to the function.
  void PrintFunctionVariableName(StringBuilder& out, uint32_t index) {
    if (index >= function_variable_names_.size()) {
      // Invalid module.
      out << "$invalid" << index;
      return;
    }
    WasmName name = wire_bytes_.GetNameOrNull(function_variable_names_[index]);
    if (name.size() > 0) {
      out << name << index;
    } else {
      out << "$func" << index;
    }
  }

  // Prints "$func" or "$func.index" depending on whether $func is imported
  // or defined by `builder.addFunction`.
  void PrintFunctionReference(StringBuilder& out, uint32_t index) {
    PrintFunctionVariableName(out, index);
    if (index < module_->functions.size() &&
        !module_->functions[index].imported) {
      out << ".index";
    }
  }
  void PrintFunctionReferenceLeb(StringBuilder& out, uint32_t index) {
    MaybeLebScope leb_scope(out, index);
    PrintFunctionReference(out, index);
  }

  // We only use this for comments, so it doesn't need to bother with LEBs.
  void PrintLocalName(StringBuilder& out, uint32_t index) {
    out << kLocalPrefix << index;
  }

  void PrintGlobalName(StringBuilder& out, uint32_t index) {
    out << "$global" << index;
  }
  void PrintGlobalReference(StringBuilder& out, uint32_t index) {
    PrintGlobalName(out, index);
    if (index < module_->globals.size() && !module_->globals[index].imported) {
      out << ".index";
    }
  }
  void PrintGlobalReferenceLeb(StringBuilder& out, uint32_t index) {
    MaybeLebScope leb_scope(out, index);
    PrintGlobalReference(out, index);
  }

  void PrintTableName(StringBuilder& out, uint32_t index) {
    out << "$table" << index;
  }
  void PrintTableReference(StringBuilder& out, uint32_t index) {
    PrintTableName(out, index);
    if (index < module_->tables.size() && !module_->tables[index].imported) {
      out << ".index";
    }
  }

  void PrintTableReferenceLeb(StringBuilder& out, uint32_t index) {
    MaybeLebScope leb_scope(out, index);
    PrintTableReference(out, index);
  }

  void PrintMemoryName(StringBuilder& out, uint32_t index) {
    out << "$mem" << index;
  }
  void PrintMemoryReferenceLeb(StringBuilder& out, uint32_t index) {
    MaybeLebScope leb_scope(out, index);
    PrintMemoryName(out, index);
  }

  void PrintTagName(StringBuilder& out, uint32_t index) {
    out << "$tag" << index;
  }
  void PrintTagReferenceLeb(StringBuilder& out, uint32_t index) {
    MaybeLebScope leb_scope(out, index);
    PrintTagName(out, index);
  }

  void PrintDataSegmentName(StringBuilder& out, uint32_t index) {
    out << "$data" << index;
  }
  void PrintDataSegmentReferenceLeb(StringBuilder& out, uint32_t index) {
    MaybeLebScope leb_scope(out, index);
    PrintDataSegmentName(out, index);
  }

  void PrintElementSegmentName(StringBuilder& out, uint32_t index) {
    out << "$segment" << index;
  }
  void PrintElementSegmentReferenceLeb(StringBuilder& out, uint32_t index) {
    MaybeLebScope leb_scope(out, index);
    PrintElementSegmentName(out, index);
  }

  // Format: HeapType::* enum value, JS global constant.
#define ABSTRACT_TYPE_LIST(V)                                     \
  V(kAny, kWasmAnyRef, kAnyRefCode)                               \
  V(kArray, kWasmArrayRef, kArrayRefCode)                         \
  V(kEq, kWasmEqRef, kEqRefCode)                                  \
  V(kExn, kWasmExnRef, kExnRefCode)                               \
  V(kExtern, kWasmExternRef, kExternRefCode)                      \
  V(kFunc, kWasmFuncRef, kFuncRefCode)                            \
  V(kI31, kWasmI31Ref, kI31RefCode)                               \
  V(kNone, kWasmNullRef, kNullRefCode)                            \
  V(kNoExn, kWasmNullExnRef, kNullExnRefCode)                     \
  V(kNoExtern, kWasmNullExternRef, kNullExternRefCode)            \
  V(kNoFunc, kWasmNullFuncRef, kNullFuncRefCode)                  \
  V(kString, kWasmStringRef, kStringRefCode)                      \
  V(kStruct, kWasmStructRef, kStructRefCode)

// Same, but for types where the shorthand is non-nullable.
#define ABSTRACT_NN_TYPE_LIST(V)                                  \
  V(kStringViewWtf16, kWasmStringViewWtf16, kStringViewWtf16Code) \
  V(kStringViewWtf8, kWasmStringViewWtf8, kStringViewWtf8Code)    \
  V(kStringViewIter, kWasmStringViewIter, kStringViewIterCode)

  void PrintHeapType(StringBuilder& out, HeapType type, OutputContext mode) {
    switch (type.representation()) {
#define CASE(kCpp, JS, JSCode)                       \
  case HeapType::kCpp:                               \
    out << (mode == kEmitWireBytes ? #JSCode : #JS); \
    return;
      ABSTRACT_TYPE_LIST(CASE)
      ABSTRACT_NN_TYPE_LIST(CASE)
#undef CASE
      case HeapType::kBottom:
      case HeapType::kTop:
        UNREACHABLE();
      default:
        PrintTypeIndex(out, type.ref_index(), mode);
    }
  }

  void PrintValueType(StringBuilder& out, ValueType type, OutputContext mode) {
    switch (type.kind()) {
        // clang-format off
      case kI8:   out << "kWasmI8";   return;
      case kI16:  out << "kWasmI16";  return;
      case kI32:  out << "kWasmI32";  return;
      case kI64:  out << "kWasmI64";  return;
      case kF16:  out << "kWasmF16";  return;
      case kF32:  out << "kWasmF32";  return;
      case kF64:  out << "kWasmF64";  return;
      case kS128: out << "kWasmS128"; return;
      // clang-format on
      case kRefNull:
        switch (type.heap_representation()) {
#define CASE(kCpp, _, _2) case HeapType::kCpp:
          ABSTRACT_TYPE_LIST(CASE)
#undef CASE
          return PrintHeapType(out, type.heap_type(), mode);
          case HeapType::kBottom:
          case HeapType::kTop:
            UNREACHABLE();
          default:
            out << (mode == kEmitObjects ? "wasmRefNullType("
                                         : "kWasmRefNull, ");
            break;
        }
        break;
      case kRef:
        switch (type.heap_representation()) {
#define CASE(kCpp, _, _2) case HeapType::kCpp:
          ABSTRACT_NN_TYPE_LIST(CASE)
#undef CASE
          return PrintHeapType(out, type.heap_type(), mode);
          case HeapType::kBottom:
            UNREACHABLE();
          default:
            out << (mode == kEmitObjects ? "wasmRefType(" : "kWasmRef, ");
            break;
        }
        break;
      case kBottom:
        out << "/*<bot>*/";
        return;
      case kTop:
      case kRtt:
      case kVoid:
        UNREACHABLE();
    }
    PrintHeapType(out, type.heap_type(), mode);
    if (mode == kEmitObjects) out << ")";
  }

  void PrintMakeSignature(StringBuilder& out, const FunctionSig* sig) {
    // Check if we can use an existing definition (for a couple of
    // common cases).
    // TODO(jkummerow): Is more complete coverage here worth it?
#define PREDEFINED(name)           \
  if (*sig == impl::kSig_##name) { \
    out << "kSig_" #name;          \
    return;                        \
  }
    PREDEFINED(d_d)
    PREDEFINED(d_dd)
    PREDEFINED(i_i)
    PREDEFINED(i_ii)
    PREDEFINED(i_iii)
    PREDEFINED(i_v)
    PREDEFINED(l_l)
    PREDEFINED(l_ll)
    PREDEFINED(v_i)
    PREDEFINED(v_ii)
    PREDEFINED(v_v)
#undef PREDEFINED

    // No hit among predefined signatures we checked for; define our own.
    out << "makeSig([";
    for (size_t i = 0; i < sig->parameter_count(); i++) {
      if (i > 0) out << ", ";
      PrintValueType(out, sig->GetParam(i), kEmitObjects);
    }
    out << "], [";
    for (size_t i = 0; i < sig->return_count(); i++) {
      if (i > 0) out << ", ";
      PrintValueType(out, sig->GetReturn(i), kEmitObjects);
    }
    out << "])";
  }

  void PrintSignatureComment(StringBuilder& out, const FunctionSig* sig) {
    out << ": [";
    for (uint32_t i = 0; i < sig->parameter_count(); i++) {
      if (i > 0) out << ", ";
      if (sig->parameter_count() > 3) {
        out << kLocalPrefix << i << ":";
      }
      PrintValueType(out, sig->GetParam(i), kEmitObjects);
    }
    out << "] -> [";
    for (uint32_t i = 0; i < sig->return_count(); i++) {
      if (i > 0) out << ", ";
      PrintValueType(out, sig->GetReturn(i), kEmitObjects);
    }
    out << "]";
  }

 private:
  bool IsSuitableFunctionVariableName(WireBytesRef ref) {
    if (!ref.is_set()) return false;
    if (ref.length() == 0) return false;
    WasmName name = wire_bytes_.GetNameOrNull(ref);
    // Check for invalid characters.
    for (uint32_t i = 0; i < ref.length(); i++) {
      char c = name[i];
      char uc = c | 0x20;
      if (uc >= 'a' && uc <= 'z') continue;
      if (c == '$' || c == '_') continue;
      if (c >= '0' && c <= '9') continue;
      return false;
    }
    // Check for clashes with auto-generated names.
    // This isn't perfect: any collision with a function (e.g. "makeSig")
    // or constant (e.g. "kFooRefCode") would also break the generated test,
    // but it doesn't seem feasible to accurately guard against all of those.
    if (name.length() >= 8) {
      if (memcmp(name.begin(), "$segment", 8) == 0) return false;
    }
    if (name.length() >= 7) {
      if (memcmp(name.begin(), "$global", 7) == 0) return false;
      if (memcmp(name.begin(), "$struct", 7) == 0) return false;
    }
    if (name.length() >= 6) {
      if (memcmp(name.begin(), "$array", 6) == 0) return false;
      if (memcmp(name.begin(), "$table", 6) == 0) return false;
    }
    if (name.length() >= 5) {
      if (memcmp(name.begin(), "$data", 5) == 0) return false;
      if (memcmp(name.begin(), "$func", 5) == 0) return false;
      if (memcmp(name.begin(), "kExpr", 5) == 0) return false;
      if (memcmp(name.begin(), "kSig_", 5) == 0) return false;
      if (memcmp(name.begin(), "kWasm", 5) == 0) return false;
    }
    if (name.length() >= 4) {
      if (memcmp(name.begin(), "$mem", 4) == 0) return false;
      if (memcmp(name.begin(), "$sig", 4) == 0) return false;
      if (memcmp(name.begin(), "$tag", 4) == 0) return false;
    }
    return true;
  }

  void PrintMaybeLEB(StringBuilder& out, const char* prefix,
                     ModuleTypeIndex index, OutputContext mode) {
    if (index.index <= 0x3F || mode == kEmitObjects) {
      out << prefix << index;
    } else {
      out << "...wasmSignedLeb(" << prefix << index << ")";
    }
  }

  const WasmModule* module_;
  ModuleWireBytes wire_bytes_;
  std::vector<WireBytesRef> function_variable_names_;
};

namespace {
const char* RawOpcodeName(WasmOpcode opcode) {
  switch (opcode) {
#define DECLARE_NAME_CASE(name, ...) \
  case kExpr##name:                  \
    return "kExpr" #name;
    FOREACH_OPCODE(DECLARE_NAME_CASE)
#undef DECLARE_NAME_CASE
    default:
      break;
  }
  return "Unknown";
}
const char* PrefixName(WasmOpcode prefix_opcode) {
  switch (prefix_opcode) {
#define DECLARE_PREFIX_CASE(name, opcode) \
  case k##name##Prefix:                   \
    return "k" #name "Prefix";
    FOREACH_PREFIX(DECLARE_PREFIX_CASE)
#undef DECLARE_PREFIX_CASE
    default:
      return "Unknown prefix";
  }
}
}  // namespace

template <typename ValidationTag>
class MjsunitImmediatesPrinter;
class MjsunitFunctionDis : public WasmDecoder<Decoder::FullValidationTag> {
 public:
  using ValidationTag = Decoder::FullValidationTag;

  MjsunitFunctionDis(Zone* zone, const WasmModule* module, uint32_t func_index,
                     bool shared, WasmDetectedFeatures* detected,
                     const FunctionSig* sig, const uint8_t* start,
                     const uint8_t* end, uint32_t offset,
                     MjsunitNamesProvider* mjsunit_names,
                     Indentation indentation)
      : WasmDecoder<ValidationTag>(zone, module, WasmEnabledFeatures::All(),
                                   detected, sig, shared, start, end, offset),
        names_(mjsunit_names),
        indentation_(indentation) {}

  void WriteMjsunit(MultiLineStringBuilder& out);

  // TODO(jkummerow): Support for compilation hints is missing.

  void DecodeGlobalInitializer(StringBuilder& out);

  uint32_t PrintMjsunitImmediatesAndGetLength(StringBuilder& out);

 private:
  template <typename ValidationTag>
  friend class MjsunitImmediatesPrinter;

  WasmOpcode PrintPrefixedOpcode(StringBuilder& out, WasmOpcode prefix) {
    auto [prefixed, prefixed_length] = read_u32v<ValidationTag>(pc_ + 1);
    if (failed()) {
      out << PrefixName(prefix) << ", ";
      return prefix;
    }
    int shift = prefixed > 0xFF ? 12 : 8;
    WasmOpcode opcode = static_cast<WasmOpcode>((prefix << shift) | prefixed);
    if (prefixed <= 0x7F) {
      if (opcode != kExprS128Const) {
        out << PrefixName(prefix) << ", ";
        out << RawOpcodeName(opcode) << ",";
      }
      if (opcode == kExprAtomicFence) {
        // Unused zero-byte.
        out << " 0,";
      }
    } else if (prefix == kSimdPrefix) {
      if (prefixed > 0xFF) {
        out << "kSimdPrefix, ..." << RawOpcodeName(opcode) << ",";
      } else {
        out << "...SimdInstr(" << RawOpcodeName(opcode) << "),";
      }
    } else if (prefix == kGCPrefix) {
      out << "...GCInstr(" << RawOpcodeName(opcode) << "),";
    } else {
      // Invalid module.
      out << "0x" << kHexChars[prefix >> 4] << kHexChars[prefix & 0xF] << ", ";
      while (prefixed > 0) {
        uint32_t chunk = prefixed & 0x7F;
        prefixed >>= 7;
        if (prefixed) chunk |= 0x80;
        out << "0x" << kHexChars[chunk >> 4] << kHexChars[chunk & 0xF] << ", ";
      }
    }
    return opcode;
  }

  MjsunitNamesProvider* names() { return names_; }

  MjsunitNamesProvider* names_;
  Indentation indentation_;
  WasmOpcode current_opcode_;
};

void MjsunitFunctionDis::WriteMjsunit(MultiLineStringBuilder& out) {
  if (!more()) {
    out << ".addBodyWithEnd([]);  // Invalid: missing kExprEnd.";
    return;
  }
  if (end_ == pc_ + 1 && *pc_ == static_cast<uint8_t>(kExprEnd)) {
    out << ".addBody([]);";
    return;
  }

  // Emit the locals.
  uint32_t locals_length = DecodeLocals(pc_);
  if (failed()) {
    out << "// Failed to decode locals\n";
    return;
  }
  uint32_t num_params = static_cast<uint32_t>(sig_->parameter_count());
  if (num_locals_ > num_params) {
    for (uint32_t pos = num_params, count = 1; pos < num_locals_;
         pos += count, count = 1) {
      ValueType type = local_types_[pos];
      while (pos + count < num_locals_ && local_types_[pos + count] == type) {
        count++;
      }
      if (pos > num_params) out << indentation_;
      out << ".addLocals(";
      names()->PrintValueType(out, type, kEmitObjects);
      out << ", " << count << ")  // ";
      names()->PrintLocalName(out, pos);
      if (count > 1) {
        out << " - ";
        names()->PrintLocalName(out, pos + count - 1);
      }
      out.NextLine(0);
    }
    out << indentation_;
  }
  consume_bytes(locals_length);

  // Emit the function body.
  out << ".addBody([";
  out.NextLine(0);
  indentation_.increase();
  int base_indentation = indentation_.current();
  while (pc_ < end_ && ok()) {
    WasmOpcode opcode = static_cast<WasmOpcode>(*pc_);
    if (WasmOpcodes::IsPrefixOpcode(opcode)) {
      out << indentation_;
      opcode = PrintPrefixedOpcode(out, opcode);
    } else {
      bool decrease_indentation = false;
      bool increase_indentation_after = false;
      bool bailout = false;
      bool print_instruction = true;
      switch (opcode) {
        case kExprEnd:
          // Don't print the final "end", it's implicit in {addBody()}.
          if (pc_ + 1 == end_) {
            bailout = true;
          } else {
            decrease_indentation = true;
          }
          break;
        case kExprDelegate:
          decrease_indentation = true;
          break;
        case kExprElse:
        case kExprCatch:
        case kExprCatchAll:
          decrease_indentation = true;
          increase_indentation_after = true;
          break;
        case kExprBlock:
        case kExprIf:
        case kExprLoop:
        case kExprTry:
        case kExprTryTable:
          increase_indentation_after = true;
          break;
        case kExprI32Const:
        case kExprI64Const:
        case kExprF32Const:
        case kExprF64Const:
          print_instruction = false;
          break;
        default:
          // The other instructions get no special treatment.
          break;
      }
      if (decrease_indentation && indentation_.current() > base_indentation) {
        indentation_.decrease();
      }
      if (bailout) break;
      out << indentation_;
      if (print_instruction) out << RawOpcodeName(opcode) << ",";
      if (increase_indentation_after) indentation_.increase();
    }
    current_opcode_ = opcode;
    pc_ += PrintMjsunitImmediatesAndGetLength(out);
    out.NextLine(0);
  }

  indentation_.decrease();
  out << indentation_ << "]);";
  out.NextLine(0);
}

void PrintF32Const(StringBuilder& out, ImmF32Immediate& imm) {
  uint32_t bits = base::bit_cast<uint32_t>(imm.value);
  if (bits == 0x80000000) {
    out << "wasmF32Const(-0)";
    return;
  }
  if (std::isnan(imm.value)) {
    out << "[kExprF32Const";
    for (int i = 0; i < 4; i++) {
      uint32_t chunk = bits & 0xFF;
      bits >>= 8;
      out << ", 0x" << kHexChars[chunk >> 4] << kHexChars[chunk & 0xF];
    }
    out << "]";
    return;
  }
  char buffer[100];
  const char* str =
      DoubleToCString(imm.value, base::VectorOf(buffer, sizeof(buffer)));
  out << "wasmF32Const(" << str << ")";
}

void PrintF64Const(StringBuilder& out, ImmF64Immediate& imm) {
  uint64_t bits = base::bit_cast<uint64_t>(imm.value);
  if (bits == base::bit_cast<uint64_t>(-0.0)) {
    out << "wasmF64Const(-0)";
    return;
  }
  if (std::isnan(imm.value)) {
    out << "[kExprF64Const";
    for (int i = 0; i < 8; i++) {
      uint32_t chunk = bits & 0xFF;
      bits >>= 8;
      out << ", 0x" << kHexChars[chunk >> 4] << kHexChars[chunk & 0xF];
    }
    out << "]";
    return;
  }
  char buffer[100];
  const char* str =
      DoubleToCString(imm.value, base::VectorOf(buffer, sizeof(buffer)));
  out << "wasmF64Const(" << str << ")";
}

void PrintI64Const(StringBuilder& out, ImmI64Immediate& imm) {
  out << "wasmI64Const(";
  if (imm.value >= 0) {
    out << static_cast<uint64_t>(imm.value);
  } else {
    out << "-" << ((~static_cast<uint64_t>(imm.value)) + 1);
  }
  out << "n)";  // `n` to make it a BigInt literal.
}

void MjsunitFunctionDis::DecodeGlobalInitializer(StringBuilder& out) {
  // Special: Pretty-print simple constants (that aren't handled by the
  // i32 special case at the caller).
  uint32_t length = static_cast<uint32_t>(end_ - pc_);
  if (*(end_ - 1) == kExprEnd) {
    if (*pc_ == kExprF32Const && length == 6) {
      ImmF32Immediate imm(this, pc_ + 1, validate);
      return PrintF32Const(out, imm);
    }
    if (*pc_ == kExprF64Const && length == 10) {
      ImmF64Immediate imm(this, pc_ + 1, validate);
      return PrintF64Const(out, imm);
    }
    if (*pc_ == kExprI64Const) {
      ImmI64Immediate imm(this, pc_ + 1, validate);
      if (length == 2 + imm.length) {
        return PrintI64Const(out, imm);
      }
    }
  }
  // Regular path.
  out << "[";
  const char* old_cursor = out.cursor();
  while (pc_ < end_ && ok()) {
    WasmOpcode opcode = static_cast<WasmOpcode>(*pc_);
    if (WasmOpcodes::IsPrefixOpcode(opcode)) {
      opcode = PrintPrefixedOpcode(out, opcode);
    } else {
      // Don't print the final "end".
      if (opcode == kExprEnd && pc_ + 1 == end_) break;
      // Constants will decide whether to print the instruction.
      if (opcode != kExprI32Const && opcode != kExprI64Const &&
          opcode != kExprF32Const && opcode != kExprF64Const) {
        out << RawOpcodeName(opcode) << ",";
      }
    }
    current_opcode_ = opcode;
    pc_ += PrintMjsunitImmediatesAndGetLength(out);
  }
  if (out.cursor() != old_cursor) {
    // If anything was written, then it ends with a comma. Erase that to
    // replace it with ']' for conciseness.
    DCHECK_EQ(*(out.cursor() - 1), ',');
    out.backspace();
  }
  out << "]";
}

template <typename ValidationTag>
class MjsunitImmediatesPrinter {
 public:
  MjsunitImmediatesPrinter(StringBuilder& out, MjsunitFunctionDis* owner)
      : out_(out), owner_(owner) {}

  MjsunitNamesProvider* names() { return owner_->names_; }

  void PrintSignature(ModuleTypeIndex sig_index) {
    out_ << " ";
    if (owner_->module_->has_signature(sig_index)) {
      names()->PrintSigType(out_, sig_index, kEmitWireBytes);
    } else {
      out_ << sig_index << " /* invalid signature */";
    }
    out_ << ",";
  }

  void BlockType(BlockTypeImmediate& imm) {
    if (imm.sig.all().begin() == nullptr) {
      PrintSignature(imm.sig_index);
    } else if (imm.sig.return_count() == 0) {
      out_ << " kWasmVoid,";
    } else {
      out_ << " ";
      names()->PrintValueType(out_, imm.sig.GetReturn(), kEmitWireBytes);
      out_ << ",";
    }
  }

  void HeapType(HeapTypeImmediate& imm) {
    out_ << " ";
    names()->PrintHeapType(out_, imm.type, kEmitWireBytes);
    out_ << ",";
  }

  void ValueType(HeapTypeImmediate& imm, bool is_nullable) {
    if (owner_->current_opcode_ == kExprBrOnCast ||
        owner_->current_opcode_ == kExprBrOnCastFail) {
      // We somewhat incorrectly use the {ValueType} callback rather than
      // {HeapType()} for br_on_cast[_fail], because that's convenient
      // for disassembling to the text format. For module builder output,
      // fix that hack here, by dispatching back to {HeapType()}.
      return HeapType(imm);
    }
    out_ << " ";
    names()->PrintValueType(
        out_,
        ValueType::RefMaybeNull(imm.type,
                                is_nullable ? kNullable : kNonNullable),
        kEmitWireBytes);
    out_ << ",";
  }

  void BrOnCastFlags(BrOnCastImmediate& flags) {
    out_ << " 0b";
    out_ << ((flags.raw_value & 2) ? "1" : "0");
    out_ << ((flags.raw_value & 1) ? "1" : "0");
    out_ << " /* " << (flags.flags.src_is_null ? "" : "non-") << "nullable -> "
         << (flags.flags.res_is_null ? "" : "non-") << "nullable */,";
  }

  void BranchDepth(BranchDepthImmediate& imm) { WriteUnsignedLEB(imm.depth); }

  void BranchTable(BranchTableImmediate& imm) {
    WriteUnsignedLEB(imm.table_count);
    const uint8_t* pc = imm.table;
    // i == table_count is the default case.
    for (uint32_t i = 0; i <= imm.table_count; i++) {
      auto [target, length] = owner_->read_u32v<ValidationTag>(pc);
      pc += length;
      WriteUnsignedLEB(target);
    }
  }

  void TryTable(TryTableImmediate& imm) {
    WriteUnsignedLEB(imm.table_count);
    owner_->indentation_.increase();
    owner_->indentation_.increase();
    const uint8_t* pc = imm.table;
    for (uint32_t i = 0; i < imm.table_count; i++) {
      out_ << "\n" << owner_->indentation_;
      uint8_t kind = owner_->read_u8<ValidationTag>(pc++);
      switch (kind) {
        case kCatch:
          out_ << "kCatchNoRef, ";
          break;
        case kCatchRef:
          out_ << "kCatchRef, ";
          break;
        case kCatchAll:
          out_ << "kCatchAllNoRef, ";
          break;
        case kCatchAllRef:
          out_ << "kCatchAllRef, ";
          break;
        default:
          out_ << kind;
      }
      if (kind == kCatch || kind == kCatchRef) {
        auto [tag, length] = owner_->read_u32v<ValidationTag>(pc);
        pc += length;
        names()->PrintTagReferenceLeb(out_, tag);
        out_ << ", ";
      }
      auto [target, length] = owner_->read_u32v<ValidationTag>(pc);
      pc += length;
      out_ << target << ",";
    }
    owner_->indentation_.decrease();
    owner_->indentation_.decrease();
  }

  void CallIndirect(CallIndirectImmediate& imm) {
    PrintSignature(imm.sig_imm.index);
    TableIndex(imm.table_imm);
  }

  void SelectType(SelectTypeImmediate& imm) {
    out_ << " 1, ";  // One type.
    names()->PrintValueType(out_, imm.type, kEmitWireBytes);
    out_ << ",";
  }

  void MemoryAccess(MemoryAccessImmediate& imm) {
    uint32_t align = imm.alignment;
    if (imm.mem_index != 0) {
      align |= 0x40;
      WriteUnsignedLEB(align);
      WriteUnsignedLEB(imm.mem_index);
    } else {
      WriteUnsignedLEB(align);
    }
    if (imm.mem_index < owner_->module_->memories.size() &&
        owner_->module_->memories[imm.mem_index].is_memory64()) {
      WriteLEB64(imm.offset);
    } else {
      DCHECK_LE(imm.offset, std::numeric_limits<uint32_t>::max());
      WriteUnsignedLEB(static_cast<uint32_t>(imm.offset));
    }
  }

  void SimdLane(SimdLaneImmediate& imm) { out_ << " " << imm.lane << ","; }

  void Field(FieldImmediate& imm) {
    TypeIndex(imm.struct_imm);
    WriteUnsignedLEB(imm.field_imm.index);
  }

  void Length(IndexImmediate& imm) { WriteUnsignedLEB(imm.index); }

  void TagIndex(TagIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTagReferenceLeb(out_, imm.index);
    out_ << ",";
  }

  void FunctionIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintFunctionReferenceLeb(out_, imm.index);
    out_ << ",";
  }

  void TypeIndex(TypeIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTypeIndex(out_, imm.index, kEmitWireBytes);
    out_ << ",";
  }

  void LocalIndex(IndexImmediate& imm) {
    WriteUnsignedLEB(imm.index);
    out_ << "  // ";
    names()->PrintLocalName(out_, imm.index);
  }

  void GlobalIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintGlobalReferenceLeb(out_, imm.index);
    out_ << ",";
  }

  void TableIndex(TableIndexImmediate& imm) {
    out_ << " ";
    names()->PrintTableReferenceLeb(out_, imm.index);
    out_ << ",";
  }

  void MemoryIndex(MemoryIndexImmediate& imm) {
    out_ << " ";
    names()->PrintMemoryReferenceLeb(out_, imm.index);
    out_ << ",";
  }

  void DataSegmentIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintDataSegmentReferenceLeb(out_, imm.index);
    out_ << ",";
  }

  void ElemSegmentIndex(IndexImmediate& imm) {
    out_ << " ";
    names()->PrintElementSegmentReferenceLeb(out_, imm.index);
    out_ << ",";
  }

  void I32Const(ImmI32Immediate& imm) {
    if (imm.value >= 0 && imm.value <= 0x3F) {
      out_ << "kExprI32Const, " << imm.value << ",";
    } else {
      out_ << "...wasmI32Const(" << imm.value << "),";
    }
  }

  void I64Const(ImmI64Immediate& imm) {
    if (imm.value >= 0 && imm.value <= 0x3F) {
      out_ << "kExprI64Const, " << static_cast<uint32_t>(imm.value) << ',';
      return;
    }
    out_ << "...";
    PrintI64Const(out_, imm);
    out_ << ",";
  }

  void F32Const(ImmF32Immediate& imm) {
    out_ << "...";
    PrintF32Const(out_, imm);
    out_ << ",";
  }

  void F64Const(ImmF64Immediate& imm) {
    out_ << "...";
    PrintF64Const(ou
```