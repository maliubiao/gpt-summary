Response:
The user wants a summary of the functionality of the provided C++ header file `v8/tools/wasm/mjsunit-module-disassembler-impl.h`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The filename and the surrounding code clearly indicate that this file is related to disassembling WebAssembly modules specifically for `mjsunit` tests within the V8 JavaScript engine.

2. **Analyze the Key Classes:**  The code defines two primary classes: `MjsunitFunctionDis` and `MjsunitModuleDis`. These are the main actors in the process.

3. **Understand `MjsunitFunctionDis`:**
    * It takes a function's bytecode as input.
    * It iterates through the bytecode, identifying opcodes and their immediates.
    * It formats the output into a human-readable, `mjsunit`-compatible JavaScript representation.
    * It uses `StringBuilder` to build the output string.
    * It leverages helper functions (`PrintMjsunitImmediatesAndGetLength`, `MjsunitImmediatesPrinter`) to handle immediate values correctly, choosing between inline values and helper functions like `wasmI32Const`.

4. **Understand `MjsunitModuleDis`:**
    * It takes a `WasmModule` object (the parsed representation of a WebAssembly module) as input.
    * It iterates through the different sections of the module (types, imports, functions, exports, etc.).
    * For each section, it generates the corresponding `mjsunit` JavaScript code using the `WasmModuleBuilder` API.
    * It uses `MjsunitFunctionDis` to disassemble the individual function bodies.
    * It handles type declarations, including recursive groups.
    * It manages imports, globals, tables, memories, data segments, element segments, and tags.
    * It attempts to generate code that, when executed, recreates the original WebAssembly module using `WasmModuleBuilder`.
    * It includes logic to handle potential compilation errors and outputs `assertThrows` in those cases.

5. **Connect to JavaScript:** The generated output is explicitly designed to be valid JavaScript code that utilizes the `WasmModuleBuilder`. This directly relates to JavaScript's ability to create and interact with WebAssembly modules.

6. **Consider Potential Errors:** The code includes checks for errors during function disassembly. The generated `mjsunit` code also includes error handling with `assertThrows`. This suggests that the disassembler is designed to handle potentially invalid or problematic WebAssembly modules.

7. **Identify Potential User Programming Errors:**  While the *disassembler* itself doesn't introduce user programming errors, the *generated code* uses the `WasmModuleBuilder`. Common errors when *manually* using `WasmModuleBuilder` (which this tool automates) could include incorrect types, mismatched import/export signatures, or invalid memory/table sizes.

8. **Infer Logic and I/O:**
    * **Input (for `MjsunitFunctionDis`):**  Wasm bytecode, opcode, immediates.
    * **Output (for `MjsunitFunctionDis`):**  String representation of the opcode and immediates in `mjsunit` format.
    * **Input (for `MjsunitModuleDis`):**  `WasmModule` object.
    * **Output (for `MjsunitModuleDis`):**  A complete `mjsunit` JavaScript test case that (ideally) reconstructs the original Wasm module.

9. **Address the `.tq` Check:** The prompt asks about the `.tq` extension. This requires noting that the file is `.h`, not `.tq`, and therefore not a Torque source file.

10. **Structure the Summary:** Organize the findings into clear points addressing the different aspects of the request: core functionality, relationship to JavaScript, code logic, error handling, and the `.tq` question.

11. **Refine and Elaborate:** Flesh out the points with more detail and context from the code. For example, explicitly mention the use of `WasmModuleBuilder` and explain the purpose of the `MjsunitImmediatesPrinter`.

By following this thought process, one can arrive at a comprehensive and accurate summary of the functionality of the provided header file.
这是对V8源代码文件 `v8/tools/wasm/mjsunit-module-disassembler-impl.h` 的功能归纳：

**核心功能：将 WebAssembly 模块反汇编为可读的 mjsunit JavaScript 代码**

该头文件定义了两个主要类，用于将编译后的 WebAssembly 模块转换成可被 V8 的 mjsunit 测试框架执行的 JavaScript 代码。生成的 JavaScript 代码使用 `WasmModuleBuilder` API 来重新构建原始的 WebAssembly 模块。

**具体功能点：**

1. **`MjsunitFunctionDis` 类：反汇编单个 WebAssembly 函数**
    *   接收一个 WebAssembly 函数的字节码作为输入。
    *   遍历函数字节码，识别操作码和立即数。
    *   将操作码和立即数转换成相应的 `mjsunit` 风格的 JavaScript 代码。例如，`kExprI32Const 10` 会被转换成 `...wasmI32Const(10)`.
    *   处理各种类型的立即数，包括整数、浮点数、函数索引、类型索引、全局索引、内存索引、文本常量等。
    *   针对特定的操作码（例如 `kExprI8x16Shuffle` 和 `kExprS128Const`）有特殊的处理逻辑来打印 SIMD 立即数。
    *   使用 `StringBuilder` 来构建输出的 JavaScript 代码字符串。
    *   能够处理全局初始化表达式。

2. **`MjsunitModuleDis` 类：反汇编整个 WebAssembly 模块**
    *   接收一个 `WasmModule` 对象（V8 中 WebAssembly 模块的内部表示）作为输入。
    *   遍历模块的各个部分，例如类型定义、导入、函数、导出、全局变量、内存、表、数据段、元素段、标签等。
    *   针对模块的每个部分，生成相应的 `mjsunit` JavaScript 代码，使用 `WasmModuleBuilder` 的方法来重建这些部分。
    *   处理类型定义，包括结构体、数组和函数签名，并能处理递归类型。
    *   处理导入的函数、表、全局变量、内存和标签。
    *   反汇编模块中的每个函数，调用 `MjsunitFunctionDis` 来完成函数体的反汇编。
    *   处理模块的起始函数。
    *   处理内存和数据段的初始化。
    *   处理全局变量的初始化表达式。
    *   处理表和元素段的初始化表达式。
    *   处理导出的函数、内存、全局变量和表。
    *   生成实例化模块和调用导出函数的 JavaScript 代码。
    *   如果反汇编过程中检测到错误，会生成 `assertThrows` 语句来断言模块实例化会抛出 `WebAssembly.CompileError`。

**与 JavaScript 的关系：**

该文件的主要功能是将 WebAssembly 代码转换为可执行的 JavaScript 代码。生成的代码依赖于 V8 的 `WasmModuleBuilder` API，这是一个 JavaScript API，用于在 JavaScript 中构建 WebAssembly 模块。

**JavaScript 示例：**

假设一个简单的 WebAssembly 函数将两个整数相加并返回结果。`MjsunitFunctionDis` 可能会将其反汇编成类似下面的 JavaScript 代码：

```javascript
builder.addFunction(undefined, $sig0)
  .addBody([
    kExprLocalGet, 0,
    kExprLocalGet, 1,
    kExprI32Add,
    kExprReturn
  ]);
```

`MjsunitModuleDis` 会将整个模块反汇编成一个包含 `WasmModuleBuilder` 操作的 JavaScript 文件，最终可以被 d8 执行。

**代码逻辑推理：**

假设输入的 WebAssembly 模块包含一个将常量 10 推入栈的指令：

*   **输入（`MjsunitFunctionDis`）：** 操作码 `kExprI32Const`，立即数 `10`。
*   **输出（`MjsunitFunctionDis` 生成的 JavaScript 代码片段）：** `...wasmI32Const(10),`

假设输入的 WebAssembly 模块定义了一个类型索引为 0 的函数签名：

*   **输入（`MjsunitModuleDis`）：**  模块的类型信息包含一个函数签名。
*   **输出（`MjsunitModuleDis` 生成的 JavaScript 代码片段）：**  类似 `builder.addType(makeSig([wasmI32], [wasmI32]));` 的代码，具体取决于函数签名的参数和返回值类型。

**用户常见的编程错误（在生成的代码中可以避免）：**

虽然这个文件本身是 V8 内部的代码，但它生成的 JavaScript 代码旨在避免在手动编写 `WasmModuleBuilder` 代码时可能出现的错误。例如：

*   **类型不匹配：**  如果手动添加函数时，指定的函数签名与实际的参数和返回值类型不符，会导致错误。`MjsunitModuleDis` 通过读取 WebAssembly 模块的元数据来避免这个问题。
*   **索引错误：**  在引用函数、全局变量或表时，使用错误的索引会导致错误。`MjsunitModuleDis` 通过正确解析 WebAssembly 模块的索引信息来避免这个问题。
*   **内存或表大小错误：**  在定义内存或表时，指定无效的初始或最大大小会导致错误。`MjsunitModuleDis` 从 WebAssembly 模块中获取这些信息。

**归纳其功能（作为第2部分）：**

`v8/tools/wasm/mjsunit-module-disassembler-impl.h` 的主要功能是提供一种机制，将编译后的 WebAssembly 模块转换回人类可读且可执行的 JavaScript 代码。这个过程对于理解 WebAssembly 模块的结构和行为，以及进行 V8 内部的 WebAssembly 相关测试和调试至关重要。 它自动化了将 WebAssembly 模块表示为 `WasmModuleBuilder` 指令的过程，使得开发者可以方便地查看 WebAssembly 模块的等效 JavaScript 表示。

Prompt: 
```
这是目录为v8/tools/wasm/mjsunit-module-disassembler-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/tools/wasm/mjsunit-module-disassembler-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
t_, imm);
    out_ << ",";
  }

  void S128Const(Simd128Immediate& imm) {
    if (owner_->current_opcode_ == kExprI8x16Shuffle) {
      for (int i = 0; i < 16; i++) {
        out_ << " " << uint32_t{imm.value[i]} << ",";
      }
    } else {
      DCHECK_EQ(owner_->current_opcode_, kExprS128Const);
      out_ << "...wasmS128Const([";
      for (int i = 0; i < 16; i++) {
        if (i > 0) out_ << ", ";
        out_ << uint32_t{imm.value[i]};
      }
      out_ << "]),";
    }
  }

  void StringConst(StringConstImmediate& imm) {
    // TODO(jkummerow): Support for string constants is incomplete, we never
    // emit a strings section.
    WriteUnsignedLEB(imm.index);
  }

  void MemoryInit(MemoryInitImmediate& imm) {
    DataSegmentIndex(imm.data_segment);
    WriteUnsignedLEB(imm.memory.index);
  }

  void MemoryCopy(MemoryCopyImmediate& imm) {
    out_ << " ";
    names()->PrintMemoryReferenceLeb(out_, imm.memory_dst.index);
    out_ << ", ";
    names()->PrintMemoryReferenceLeb(out_, imm.memory_src.index);
    out_ << ",";
  }

  void TableInit(TableInitImmediate& imm) {
    out_ << " ";
    names()->PrintElementSegmentReferenceLeb(out_, imm.element_segment.index);
    out_ << ", ";
    names()->PrintTableReferenceLeb(out_, imm.table.index);
    out_ << ",";
  }

  void TableCopy(TableCopyImmediate& imm) {
    out_ << " ";
    names()->PrintTableReferenceLeb(out_, imm.table_dst.index);
    out_ << ", ";
    names()->PrintTableReferenceLeb(out_, imm.table_src.index);
    out_ << ",";
  }

  void ArrayCopy(TypeIndexImmediate& dst, TypeIndexImmediate& src) {
    out_ << " ";
    names()->PrintTypeIndex(out_, dst.index, kEmitWireBytes);
    out_ << ", ";
    names()->PrintTypeIndex(out_, src.index, kEmitWireBytes);
    out_ << ",";
  }

 private:
  void WriteUnsignedLEB(uint32_t value) {
    if (value < 128) {
      out_ << " " << value << ",";
    } else {
      out_ << " ...wasmUnsignedLeb(" << value << "),";
    }
  }
  void WriteLEB64(uint64_t value) {
    if (value < 128) {
      out_ << " " << value << ",";
    } else {
      // TODO(jkummerow): Technically we should use an unsigned version,
      // but the module builder doesn't offer one yet.
      out_ << " ...wasmSignedLeb64(" << value << "n),";
    }
  }

  StringBuilder& out_;
  MjsunitFunctionDis* owner_;
};

// For opcodes that produce constants (such as `kExprI32Const`), this prints
// more than just the immediate: it also decides whether to use
// "kExprI32Const, 0," or "...wasmI32Const(1234567)".
uint32_t MjsunitFunctionDis::PrintMjsunitImmediatesAndGetLength(
    StringBuilder& out) {
  using Printer = MjsunitImmediatesPrinter<ValidationTag>;
  Printer imm_printer(out, this);
  return WasmDecoder::OpcodeLength<Printer>(this, this->pc_, imm_printer);
}

class MjsunitModuleDis {
 public:
  MjsunitModuleDis(MultiLineStringBuilder& out, const WasmModule* module,
                   NamesProvider* names, const ModuleWireBytes wire_bytes,
                   AccountingAllocator* allocator, bool has_error = false)
      : out_(out),
        module_(module),
        names_provider_(names),
        mjsunit_names_(module, wire_bytes),
        wire_bytes_(wire_bytes),
        zone_(allocator, "disassembler"),
        has_error_(has_error) {
    offsets_.CollectOffsets(module, wire_bytes.module_bytes());
  }

  void PrintModule() {
    tzset();
    time_t current_time = time(nullptr);
    struct tm current_localtime;
#ifdef V8_OS_WIN
    localtime_s(&current_localtime, &current_time);
#else
    localtime_r(&current_time, &current_localtime);
#endif
    int year = 1900 + current_localtime.tm_year;

    out_ << "// Copyright " << year
         << " the V8 project authors. All rights reserved.\n"
            "// Use of this source code is governed by a BSD-style license "
            "that can be\n"
            "// found in the LICENSE file.\n"
            "\n"
            "// Flags: --wasm-staging --wasm-inlining-call-indirect\n"
            "\n"
            "d8.file.execute('test/mjsunit/wasm/wasm-module-builder.js');\n"
            "\n"
            "const builder = new WasmModuleBuilder();";
    out_.NextLine(0);

    // Module name, if present.
    if (module_->name.is_set()) {
      out_ << "builder.setName('";
      PrintName(module_->name);
      out_ << "');";
      out_.NextLine(0);
    }

    // Types.
    // TODO(14616): Support shared types.

    // Support self-referential and mutually-recursive types.
    std::vector<uint32_t> needed_at(module_->types.size(), kMaxUInt32);
    auto MarkAsNeededHere = [&needed_at](ValueType vt, uint32_t here) {
      if (!vt.is_object_reference()) return;
      HeapType ht = vt.heap_type();
      if (!ht.is_index()) return;
      if (ht.ref_index().index < here) return;
      if (needed_at[ht.ref_index().index] < here) return;
      needed_at[ht.ref_index().index] = here;
    };
    for (uint32_t i = 0; i < module_->types.size(); i++) {
      if (module_->has_struct(ModuleTypeIndex{i})) {
        const StructType* struct_type = module_->types[i].struct_type;
        for (uint32_t fi = 0; fi < struct_type->field_count(); fi++) {
          MarkAsNeededHere(struct_type->field(fi), i);
        }
      } else if (module_->has_array(ModuleTypeIndex{i})) {
        MarkAsNeededHere(module_->types[i].array_type->element_type(), i);
      } else {
        DCHECK(module_->has_signature(ModuleTypeIndex{i}));
        const FunctionSig* sig = module_->types[i].function_sig;
        for (size_t pi = 0; pi < sig->parameter_count(); pi++) {
          MarkAsNeededHere(sig->GetParam(pi), i);
        }
        for (size_t ri = 0; ri < sig->return_count(); ri++) {
          MarkAsNeededHere(sig->GetReturn(ri), i);
        }
      }
    }

    uint32_t recgroup_index = 0;
    OffsetsProvider::RecGroup recgroup = offsets_.recgroup(recgroup_index++);
    bool in_explicit_recgroup = false;
    for (uint32_t i = 0; i < module_->types.size(); i++) {
      while (i == recgroup.start_type_index) {
        out_ << "builder.startRecGroup();";
        out_.NextLine(0);
        if (V8_UNLIKELY(recgroup.end_type_index == i)) {
          // Empty recgroup.
          out_ << "builder.endRecGroup();";
          out_.NextLine(0);
          DCHECK(!in_explicit_recgroup);
          recgroup = offsets_.recgroup(recgroup_index++);
          continue;
        } else {
          in_explicit_recgroup = true;
          break;
        }
      }
      uint32_t end_index =
          recgroup.end_type_index != OffsetsProvider::RecGroup::kInvalid
              ? recgroup.end_type_index
              : i + 1;
      for (uint32_t pre = i; pre < end_index; pre++) {
        if (needed_at[pre] == i) {
          out_ << "let ";
          names()->PrintTypeVariableName(out_, ModuleTypeIndex{pre});
          if (pre == i) {
            out_ << " = builder.nextTypeIndex();";
          } else {
            out_ << " = builder.nextTypeIndex() + " << (pre - i) << ";";
          }
          out_.NextLine(0);
        }
      }
      ModuleTypeIndex supertype = module_->types[i].supertype;
      bool is_final = module_->types[i].is_final;
      if (needed_at[i] == kMaxUInt32) {
        out_ << "let ";
        names()->PrintTypeVariableName(out_, ModuleTypeIndex{i});
        out_ << " = ";
      } else {
        out_ << "/* ";
        names()->PrintTypeVariableName(out_, ModuleTypeIndex{i});
        out_ << " */ ";
      }
      if (module_->has_struct(ModuleTypeIndex{i})) {
        const StructType* struct_type = module_->types[i].struct_type;
        out_ << "builder.addStruct([";
        for (uint32_t fi = 0; fi < struct_type->field_count(); fi++) {
          if (fi > 0) out_ << ", ";
          out_ << "makeField(";
          names()->PrintValueType(out_, struct_type->field(fi), kEmitObjects);
          out_ << ", " << (struct_type->mutability(fi) ? "true" : "false");
          out_ << ")";
        }
        out_ << "], ";
        if (supertype != kNoSuperType) {
          names()->PrintTypeIndex(out_, supertype, kEmitObjects);
        } else {
          out_ << "kNoSuperType";
        }
        out_ << ", " << (is_final ? "true" : "false") << ");";
        out_.NextLine(0);
      } else if (module_->has_array(ModuleTypeIndex{i})) {
        const ArrayType* array_type = module_->types[i].array_type;
        out_ << "builder.addArray(";
        names()->PrintValueType(out_, array_type->element_type(), kEmitObjects);
        out_ << ", ";
        out_ << (array_type->mutability() ? "true" : "false") << ", ";
        if (supertype != kNoSuperType) {
          names()->PrintTypeIndex(out_, supertype, kEmitObjects);
        } else {
          out_ << "kNoSuperType";
        }
        out_ << ", " << (is_final ? "true" : "false") << ");";
        out_.NextLine(0);
      } else {
        DCHECK(module_->has_signature(ModuleTypeIndex{i}));
        const FunctionSig* sig = module_->types[i].function_sig;
        out_ << "builder.addType(";
        names()->PrintMakeSignature(out_, sig);
        if (!is_final || supertype != kNoSuperType) {
          out_ << ", ";
          if (supertype != kNoSuperType) {
            names()->PrintTypeIndex(out_, supertype, kEmitObjects);
          } else {
            out_ << "kNoSuperType";
          }
          if (!is_final) out_ << ", false";
        }
        out_ << ");";
        out_.NextLine(0);
      }
      if (in_explicit_recgroup && i == recgroup.end_type_index - 1) {
        in_explicit_recgroup = false;
        out_ << "builder.endRecGroup();";
        out_.NextLine(0);
        recgroup = offsets_.recgroup(recgroup_index++);
      }
    }
    while (recgroup.valid()) {
      // There could be empty recgroups at the end of the type section.
      DCHECK_GE(recgroup.start_type_index, module_->types.size());
      DCHECK_EQ(recgroup.start_type_index, recgroup.end_type_index);
      out_ << "builder.startRecgroup();\nbuilder.endRecGroup();";
      out_.NextLine(0);
      recgroup = offsets_.recgroup(recgroup_index++);
    }

    // Imports.
    for (const WasmImport& imported : module_->import_table) {
      out_ << "let ";
      switch (imported.kind) {
        case kExternalFunction:
          names()->PrintFunctionVariableName(out_, imported.index);
          out_ << " = builder.addImport('" << V(imported.module_name);
          out_ << "', '" << V(imported.field_name) << "', ";
          names()->PrintTypeIndex(
              out_, module_->functions[imported.index].sig_index, kEmitObjects);
          break;

        case kExternalTable: {
          names()->PrintTableName(out_, imported.index);
          out_ << " = builder.addImportedTable('" << V(imported.module_name);
          out_ << "', '" << V(imported.field_name) << "', ";
          const WasmTable& table = module_->tables[imported.index];
          out_ << table.initial_size << ", ";
          if (table.has_maximum_size) {
            out_ << table.maximum_size << ", ";
          } else {
            out_ << "undefined, ";
          }
          names()->PrintValueType(out_, table.type, kEmitObjects);
          if (table.is_table64()) out_ << ", true";
          break;
        }
        case kExternalGlobal: {
          names()->PrintGlobalName(out_, imported.index);
          out_ << " = builder.addImportedGlobal('" << V(imported.module_name);
          out_ << "', '" << V(imported.field_name) << "', ";
          const WasmGlobal& global = module_->globals[imported.index];
          names()->PrintValueType(out_, global.type, kEmitObjects);
          if (global.mutability || global.shared) {
            out_ << ", " << (global.mutability ? "true" : "false");
          }
          if (global.shared) out_ << ", true";
          break;
        }
        case kExternalMemory: {
          names()->PrintMemoryName(out_, imported.index);
          out_ << " = builder.addImportedMemory('" << V(imported.module_name);
          out_ << "', '" << V(imported.field_name) << "', ";
          const WasmMemory& memory = module_->memories[imported.index];
          out_ << memory.initial_pages << ", ";
          if (memory.has_maximum_pages) {
            out_ << memory.maximum_pages << ", ";
          } else {
            out_ << "undefined, ";
          }
          out_ << (memory.is_shared ? "true" : "false");
          if (memory.is_memory64()) out_ << ", true";
          break;
        }
        case kExternalTag: {
          names()->PrintTagName(out_, imported.index);
          out_ << " = builder.addImportedTag('" << V(imported.module_name);
          out_ << "', '" << V(imported.field_name) << "', ";
          names()->PrintTypeIndex(out_, module_->tags[imported.index].sig_index,
                                  kEmitObjects);
          break;
        }
      }
      out_ << ");";
      out_.NextLine(0);
    }

    // Declare functions (without bodies).
    //
    // TODO(jkummerow): We need function variables to be defined in case they
    // are used by init expressions, element segments, or in function bodies.
    // For now, we just declare all functions up front. We could do this
    // selectively (in the interest of conciseness), if we performed a pre-scan
    // of the module to find functions that are referenced by index anywhere.
    //
    // For testing, we ensure that the order of exports remains the same.
    // So when there are non-function imports, we don't annotate functions
    // as exported right away, but postpone that until the exports section.
    // This behavior is not required for correctness, it just helps with
    // differential testing (roundtripping a module through `wami --mjsunit`
    // and `d8 --dump-wasm-module`).
    static constexpr bool kMaintainExportOrder = true;
    bool export_functions_late = false;
    if constexpr (kMaintainExportOrder) {
      for (const WasmExport& ex : module_->export_table) {
        if (ex.kind != kExternalFunction ||
            module_->functions[ex.index].imported) {
          export_functions_late = true;
          break;
        }
      }
    }
    for (const WasmFunction& func : module_->functions) {
      if (func.imported) continue;
      uint32_t index = func.func_index;
      out_ << "let ";
      names()->PrintFunctionVariableName(out_, index);
      out_ << " = builder.addFunction(";
      if (names()->HasFunctionName(index)) {
        out_ << '"';
        names()->PrintFunctionName(out_, index);
        out_ << '"';
      } else {
        out_ << "undefined";
      }
      out_ << ", ";
      out_ << "$sig" << func.sig_index.index;
      out_ << ")";
      if (func.exported && !export_functions_late) {
        for (const WasmExport& ex : module_->export_table) {
          if (ex.kind != kExternalFunction || ex.index != index) continue;
          if (names()->FunctionNameEquals(index, ex.name)) {
            out_ << ".exportFunc()";
          } else {
            out_ << ".exportAs('";
            PrintName(ex.name);
            out_ << "')";
          }
        }
      }
      out_ << ";";
      out_.NextLine(0);
    }

    // Start function.
    if (module_->start_function_index >= 0) {
      out_ << "builder.addStart(";
      names()->PrintFunctionReference(out_, module_->start_function_index);
      out_ << ");";
      out_.NextLine(0);
    }

    // Memories.
    for (const WasmMemory& memory : module_->memories) {
      if (memory.imported) continue;
      out_ << "let ";
      names()->PrintMemoryName(out_, memory.index);
      if (memory.is_memory64()) {
        out_ << " = builder.addMemory64(";
      } else {
        out_ << " = builder.addMemory(";
      }
      out_ << memory.initial_pages;
      if (memory.has_maximum_pages) {
        out_ << ", " << memory.maximum_pages;
      } else {
        out_ << ", undefined";
      }
      if (memory.is_shared) {
        out_ << ", true";
      }
      out_ << ");";
      out_.NextLine(0);
    }

    // Data segments.
    for (uint32_t i = 0; i < module_->data_segments.size(); i++) {
      const WasmDataSegment& segment = module_->data_segments[i];
      base::Vector<const uint8_t> data = wire_bytes_.module_bytes().SubVector(
          segment.source.offset(), segment.source.end_offset());
      out_ << "let ";
      names()->PrintDataSegmentName(out_, i);
      if (segment.active) {
        out_ << " = builder.addActiveDataSegment(" << segment.memory_index
             << ", ";
        DecodeAndAppendInitExpr(segment.dest_addr, kWasmI32);
        out_ << ", ";
      } else {
        out_ << " = builder.addPassiveDataSegment(";
      }
      out_ << "[";
      uint32_t num_bytes = static_cast<uint32_t>(data.size());
      if (num_bytes > 0) out_ << uint32_t{data[0]};
      for (uint32_t i = 1; i < num_bytes; i++) {
        out_ << ", " << uint32_t{data[i]};
      }
      out_ << "]";
      if (segment.shared) out_ << ", true";
      out_ << ");";
      out_.NextLine(0);
    }

    // Globals.
    for (uint32_t i = module_->num_imported_globals;
         i < module_->globals.size(); i++) {
      const WasmGlobal& global = module_->globals[i];
      out_ << "let ";
      names()->PrintGlobalName(out_, i);
      out_ << " = builder.addGlobal(";
      names()->PrintValueType(out_, global.type, kEmitObjects);
      out_ << ", " << (global.mutability ? "true" : "false") << ", ";
      out_ << (global.shared ? "true" : "false") << ", ";
      DecodeAndAppendInitExpr(global.init, global.type);
      if (!kMaintainExportOrder && global.exported) {
        out_ << ").exportAs('";
        PrintExportName(kExternalGlobal, i);
        out_ << "'";
      }
      out_ << ");";
      out_.NextLine(0);
    }

    // Tables.
    for (uint32_t i = module_->num_imported_tables; i < module_->tables.size();
         i++) {
      const WasmTable& table = module_->tables[i];
      out_ << "let ";
      names()->PrintTableName(out_, i);
      if (table.is_table64()) {
        out_ << " = builder.addTable64(";
      } else {
        out_ << " = builder.addTable(";
      }
      names()->PrintValueType(out_, table.type, kEmitObjects);
      out_ << ", " << table.initial_size << ", ";
      if (table.has_maximum_size) {
        out_ << table.maximum_size;
      } else {
        out_ << "undefined";
      }
      if (table.initial_value.is_set()) {
        out_ << ", ";
        DecodeAndAppendInitExpr(table.initial_value, table.type);
      } else if (table.shared) {
        out_ << ", undefined";
      }
      if (table.shared) out_ << ", true";
      if (!kMaintainExportOrder && table.exported) {
        out_ << ").exportAs('";
        PrintExportName(kExternalTable, i);
        out_ << "'";
      }
      out_ << ");";
      out_.NextLine(0);
    }

    // Element segments.
    for (uint32_t i = 0; i < module_->elem_segments.size(); i++) {
      const WasmElemSegment& segment = module_->elem_segments[i];
      out_ << "let ";
      names()->PrintElementSegmentName(out_, i);
      if (segment.status == WasmElemSegment::kStatusActive) {
        out_ << " = builder.addActiveElementSegment(";
        names()->PrintTableReference(out_, segment.table_index);
        out_ << ", ";
        DecodeAndAppendInitExpr(segment.offset, kWasmI32);
        out_ << ", ";
      } else if (segment.status == WasmElemSegment::kStatusPassive) {
        out_ << " = builder.addPassiveElementSegment(";
      } else {
        DCHECK_EQ(segment.status, WasmElemSegment::kStatusDeclarative);
        out_ << " = builder.addDeclarativeElementSegment(";
      }
      out_ << "[";
      WasmDetectedFeatures unused_detected_features;
      ModuleDecoderImpl decoder(
          WasmEnabledFeatures::All(), wire_bytes_.module_bytes(),
          ModuleOrigin::kWasmOrigin, &unused_detected_features);
      // This implementation detail is load-bearing: if we simply let the
      // {decoder} start at this offset, it could produce WireBytesRefs that
      // start at offset 0, which violates DCHECK-guarded assumptions.
      decoder.consume_bytes(segment.elements_wire_bytes_offset);
      for (uint32_t j = 0; j < segment.element_count; j++) {
        if (j > 0) out_ << ", ";
        ConstantExpression expr = decoder.consume_element_segment_entry(
            const_cast<WasmModule*>(module_), segment);
        if (segment.element_type == WasmElemSegment::kExpressionElements) {
          DecodeAndAppendInitExpr(expr, segment.type);
        } else {
          names()->PrintFunctionReference(out_, expr.index());
        }
      }
      out_ << "]";
      if (segment.element_type == WasmElemSegment::kExpressionElements) {
        out_ << ", ";
        names()->PrintValueType(out_, segment.type, kEmitObjects);
      }
      if (segment.shared) out_ << ", true";
      out_ << ");";
      out_.NextLine(0);
    }

    // Tags.
    for (uint32_t i = module_->num_imported_tags; i < module_->tags.size();
         i++) {
      const WasmTag& tag = module_->tags[i];
      out_ << "let ";
      names()->PrintTagName(out_, i);
      out_ << " = builder.addTag(";
      // The signature was already emitted as one of the types.
      // TODO(jkummerow): For conciseness, consider pre-scanning signatures
      // that are only used by tags, and using {PrintMakeSignature(
      // tag.ToFunctionSig())} here.
      names()->PrintSigType(out_, tag.sig_index, kEmitObjects);
      out_ << ");";
      out_.NextLine(0);
    }

    // Functions.
    for (const WasmFunction& func : module_->functions) {
      if (func.imported) continue;
      uint32_t index = func.func_index;

      // Header and signature.
      out_.NextLine(0);
      out_ << "// func ";
      names_provider_->PrintFunctionName(out_, index, NamesProvider::kDevTools);
      names()->PrintSignatureComment(out_, func.sig);
      out_.NextLine(0);

      names()->PrintFunctionVariableName(out_, index);

      base::Vector<const uint8_t> func_code =
          wire_bytes_.GetFunctionBytes(&func);

      // Locals and body.
      bool shared = module_->type(func.sig_index).is_shared;
      WasmDetectedFeatures detected;
      MjsunitFunctionDis d(&zone_, module_, index, shared, &detected, func.sig,
                           func_code.begin(), func_code.end(),
                           func.code.offset(), &mjsunit_names_,
                           Indentation{2, 2});
      d.WriteMjsunit(out_);
      if (d.failed()) has_error_ = true;
    }
    out_.NextLine(0);

    // Exports.
    bool added_any_export = false;
    for (const WasmExport& ex : module_->export_table) {
      switch (ex.kind) {
        case kExternalFunction:
          if (!export_functions_late &&
              !module_->functions[ex.index].imported) {
            continue;  // Handled above.
          }
          out_ << "builder.addExport('";
          PrintName(ex.name);
          out_ << "', ";
          names()->PrintFunctionReference(out_, ex.index);
          out_ << ");";
          break;
        case kExternalMemory:
          out_ << "builder.exportMemoryAs('";
          PrintName(ex.name);
          out_ << "', ";
          names()->PrintMemoryName(out_, ex.index);
          out_ << ");";
          break;
        case kExternalGlobal:
          if (!kMaintainExportOrder &&
              ex.index >= module_->num_imported_globals) {
            continue;
          }
          out_ << "builder.addExportOfKind('";
          PrintName(ex.name);
          out_ << "', kExternalGlobal, ";
          names()->PrintGlobalReference(out_, ex.index);
          out_ << ");";
          break;
        case kExternalTable:
          if (!kMaintainExportOrder &&
              ex.index >= module_->num_imported_tables) {
            continue;
          }
          out_ << "builder.addExportOfKind('";
          PrintName(ex.name);
          out_ << "', kExternalTable, ";
          names()->PrintTableReference(out_, ex.index);
          out_ << ");";
          break;
        case kExternalTag:
          out_ << "builder.addExportOfKind('";
          PrintName(ex.name);
          out_ << "', kExternalTag, ";
          names()->PrintTagName(out_, ex.index);
          out_ << ");";
          break;
      }
      out_.NextLine(0);
      added_any_export = true;
    }

    // Instantiate and invoke.
    if (added_any_export) out_.NextLine(0);
    bool compiles = !has_error_;
    if (compiles) {
      out_ << "let kBuiltins = { builtins: ['js-string', 'text-decoder', "
              "'text-encoder'] };\n"
              "const instance = builder.instantiate({}, kBuiltins);\n"
              "try {\n"
              "  print(instance.exports.main(1, 2, 3));\n"
              "} catch (e) {\n"
              "  print('caught exception', e);\n"
              "}";
      out_.NextLine(0);
    } else {
      out_ << "assertThrows(() => builder.instantiate(), "
              "WebAssembly.CompileError);";
      out_.NextLine(0);
    }
  }

 private:
  base::Vector<const char> V(WireBytesRef ref) {
    return {reinterpret_cast<const char*>(wire_bytes_.start()) + ref.offset(),
            ref.length()};
  }
  void PrintName(WireBytesRef ref) {
    out_.write(wire_bytes_.start() + ref.offset(), ref.length());
  }

  void PrintExportName(ImportExportKindCode kind, uint32_t index) {
    for (const WasmExport& ex : module_->export_table) {
      if (ex.kind != kind || ex.index != index) continue;
      PrintName(ex.name);
    }
  }

  void DecodeAndAppendInitExpr(ConstantExpression init, ValueType expected) {
    switch (init.kind()) {
      case ConstantExpression::kEmpty:
        UNREACHABLE();
      case ConstantExpression::kI32Const:
        out_ << "wasmI32Const(" << init.i32_value() << ")";
        break;
      case ConstantExpression::kRefNull:
        out_ << "[kExprRefNull, ";
        names()->PrintHeapType(out_, HeapType(init.repr()), kEmitWireBytes);
        out_ << "]";
        break;
      case ConstantExpression::kRefFunc:
        out_ << "[kExprRefFunc, ";
        names()->PrintFunctionReferenceLeb(out_, init.index());
        out_ << "]";
        break;
      case ConstantExpression::kWireBytesRef: {
        WireBytesRef ref = init.wire_bytes_ref();
        const uint8_t* start = wire_bytes_.start() + ref.offset();
        const uint8_t* end = start + ref.length();
        auto sig = FixedSizeSignature<ValueType>::Returns(expected);
        WasmDetectedFeatures detected;
        MjsunitFunctionDis d(&zone_, module_, 0, false, &detected, &sig, start,
                             end, ref.offset(), &mjsunit_names_,
                             Indentation{0, 0});
        d.DecodeGlobalInitializer(out_);
        if (d.failed()) has_error_ = true;
        break;
      }
    }
  }

  MjsunitNamesProvider* names() { return &mjsunit_names_; }

  MultiLineStringBuilder& out_;
  const WasmModule* module_;
  NamesProvider* names_provider_;
  MjsunitNamesProvider mjsunit_names_;
  OffsetsProvider offsets_;
  const ModuleWireBytes wire_bytes_;
  Zone zone_;
  bool has_error_{false};
};

}  // namespace v8::internal::wasm

#endif  // V8_TOOLS_WASM_MJSUNIT_MODULE_DISASSEMBLER_IMPL_H_

"""


```