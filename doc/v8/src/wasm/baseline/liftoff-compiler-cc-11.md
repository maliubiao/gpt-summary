Response:
My thinking process to answer the request about `liftoff-compiler.cc` goes through these stages:

1. **Understanding the Core Request:** The primary goal is to summarize the functionality of the `liftoff-compiler.cc` file within the V8 JavaScript engine. Key aspects to cover include its role in WebAssembly compilation, how it relates to JavaScript (if at all), potential programming errors, and specifically, a summary of the provided code snippet.

2. **General Knowledge about Liftoff:** I access my internal knowledge about V8's architecture and compilation pipelines. I know:
    * **Liftoff is a baseline compiler for WebAssembly.** This means it's designed for fast compilation and decent execution speed, not peak performance. It's a step above an interpreter but less optimized than TurboFan.
    * **Its purpose is to quickly get WebAssembly code running.** This often involves simpler code generation strategies.
    * **It interacts with other parts of V8's Wasm infrastructure.** This includes the decoder, memory management, and runtime functions.

3. **Analyzing the Code Snippet (Detailed Focus):** This is crucial for understanding the specific functionality demonstrated in this *part* of the file. I break down the code into logical sections:

    * **Table Access and Bounds Checking:** The code clearly deals with `call_indirect` operations in WebAssembly. It checks if the `index` into the table is within the `max_table_size`. I note the different handling for 32-bit and 64-bit architectures. The `static_assert` is important for understanding assumptions.
    * **Dispatch Table Handling:**  The code distinguishes between static and dynamic function indices. For static indices, it calculates an offset. For dynamic indices, it performs calculations to find the dispatch table entry. The comment "TODO(clemensb): Produce better code..." indicates potential optimization areas.
    * **Type and Null Checking:** The code verifies the signature of the function being called indirectly. This is essential for type safety in WebAssembly. It also handles null checks for table entries. The complex logic involving `CanonicalTypeIndex` and RTTs (Runtime Type Information) points to support for subtyping and more advanced WebAssembly features.
    * **Indirect Call Execution:** This section loads the target function and its associated data from the dispatch table and then performs the actual call. The handling of `v8_flags.wasm_inlining_call_indirect` signifies support for inlining in the baseline compiler.
    * **Deoptimization Support:** The `EmitDeoptPoint` and related code show that Liftoff supports deoptimization, which is necessary for seamless transitions to more optimized tiers like TurboFan.
    * **CallRef Implementation:**  This part handles direct calls to function references (`call_ref`), with both inlining and non-inlining paths.
    * **Helper Functions:** I recognize functions like `LoadNullValue`, `MaybeEmitNullCheck`, `BoundsCheckArray`, and others as utility functions used for common WebAssembly operations.

4. **Connecting the Snippet to Overall Functionality:**  I realize that this snippet focuses heavily on the `call_indirect` and `call_ref` instructions in WebAssembly. It showcases Liftoff's responsibility for:
    * **Safety:** Performing bounds checks, null checks, and type checks.
    * **Indirect Calls:** Implementing the logic to look up and execute functions through tables.
    * **Direct Calls to References:** Handling calls to function references.
    * **Integration with V8's Runtime:** Using built-in functions for traps and deoptimization.
    * **Potential Optimization:** The inlining flag suggests that even the baseline compiler can incorporate some optimizations.

5. **Addressing Specific Points in the Request:**

    * **Functionality Listing:**  Based on the code analysis and general knowledge, I list the core functions.
    * **Torque Source:** I check the file extension (`.cc`) and correctly identify it as C++, not Torque.
    * **JavaScript Relationship:** I consider how WebAssembly interacts with JavaScript. The key connection is calling WebAssembly functions from JavaScript and vice-versa. I provide a simple JavaScript example demonstrating this.
    * **Code Logic Inference:**  I choose a simplified scenario for `call_indirect` with a static index to illustrate the input and output, highlighting the key steps.
    * **Common Programming Errors:** I think about typical WebAssembly errors related to indirect calls, such as out-of-bounds access and signature mismatches.
    * **Part of a Larger System:** I recognize that this is just one part of the Liftoff compiler and needs to be integrated with other components.

6. **Synthesizing the Summary:** I combine the detailed analysis of the snippet with my broader understanding of Liftoff to create a concise summary of its role and the specific functions it performs, especially as illustrated by the provided code. I emphasize its role as a fast, initial compiler for WebAssembly within V8.

7. **Review and Refinement:** I read through my answer to ensure it's clear, accurate, and addresses all aspects of the original request. I make sure the language is appropriate for someone familiar with programming concepts but potentially less so with the internals of a JavaScript engine.

This iterative process of understanding the request, analyzing the code, connecting it to broader concepts, and then structuring the answer allows me to generate a comprehensive and informative response.好的，让我们来分析一下 `v8/src/wasm/baseline/liftoff-compiler.cc` 这个文件的功能。

**主要功能：**

`liftoff-compiler.cc` 文件是 V8 JavaScript 引擎中 **Liftoff 基线 WebAssembly 编译器** 的核心源代码文件。它的主要功能是：

1. **快速编译 WebAssembly 代码：** Liftoff 是一种“零延迟”的编译器，它的目标是以极快的速度将 WebAssembly 字节码转换为机器码。这意味着当 WebAssembly 模块加载时，它可以几乎立即开始执行，而无需等待更高级的优化编译器（如 TurboFan）完成编译。

2. **生成非优化但可执行的机器码：** Liftoff 生成的机器码虽然没有经过高度优化，但足以正确执行 WebAssembly 代码。它避免了复杂的优化过程，以换取编译速度。

3. **支持 WebAssembly 的核心功能：**  从提供的代码片段可以看出，Liftoff 编译器负责处理 WebAssembly 的 `call_indirect` (间接调用) 和 `call_ref` (调用函数引用) 指令，并且涉及到以下子功能：
    * **表（Table）访问和边界检查：**  确保对 WebAssembly 表的访问在有效范围内，防止越界访问导致的错误或安全问题。
    * **函数签名匹配：** 在间接调用时，验证被调用函数的签名是否与调用点期望的签名一致，保证类型安全。
    * **空值检查：**  在访问可能为空的引用类型时进行空值检查，防止空指针解引用。
    * **调用目标查找：**  根据索引从 dispatch table 中查找要调用的函数地址和相关信息。
    * **参数准备和调用执行：**  准备函数调用的参数，并执行实际的函数调用。
    * **Deoptimization (反优化) 支持：**  为后续可能发生的 TurboFan 优化编译和反优化提供支持。
    * **内联 (Inlining) 的考虑：** 代码中出现了 `v8_flags.wasm_inlining_call_indirect` 和 `v8_flags.wasm_inlining`，表明 Liftoff 也考虑了在某些情况下进行简单的内联优化。
    * **反馈收集 (Feedback Collection)：**  `CallIndirectIC` 和 `CallRefIC` 的使用表明 Liftoff 可以收集运行时反馈信息，这些信息可以被 TurboFan 等优化编译器利用。
    * **结构体和数组操作：** 代码中出现了 `StructFieldOffset`、`LoadObjectField`、`StoreObjectField` 和 `ArrayFillImpl`，表明 Liftoff 负责处理结构体和数组的字段访问和存储。
    * **异常处理：** 通过 `AddOutOfLineTrap` 添加了在运行时发生错误时跳转到的陷阱处理代码。
    * **Null 值处理：**  提供了加载和比较 Null 值的功能。

4. **作为 V8 编译流水线的早期阶段：** Liftoff 生成的代码通常作为 WebAssembly 代码的初始执行版本。在程序运行过程中，V8 的优化编译器（TurboFan）可能会在后台对热点代码进行重新编译和优化，以提高性能。

**关于文件扩展名和 Torque：**

你提供的信息表明 `v8/src/wasm/baseline/liftoff-compiler.cc` 的扩展名是 `.cc`，这意味着它是一个 **C++ 源代码文件**。如果文件以 `.tq` 结尾，那么它才是 V8 的 Torque 源代码。Torque 是一种 V8 自定义的领域特定语言，用于编写 V8 内部的运行时函数和内置函数。

**与 JavaScript 的关系及示例：**

Liftoff 编译器编译的是 WebAssembly 代码，而 WebAssembly 经常与 JavaScript 一起使用。JavaScript 可以加载、编译和执行 WebAssembly 模块，并且两者可以互相调用函数。

**JavaScript 示例：**

```javascript
async function loadAndRunWasm() {
  const response = await fetch('my_wasm_module.wasm'); // 假设有一个名为 my_wasm_module.wasm 的 WebAssembly 文件
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer); // V8 内部会使用 Liftoff 或 TurboFan 进行编译
  const instance = await WebAssembly.instantiate(module);

  // 调用 WebAssembly 模块导出的函数
  const result = instance.exports.add(5, 3);
  console.log('WebAssembly 函数的返回值:', result);
}

loadAndRunWasm();
```

在这个例子中，当 `WebAssembly.compile(buffer)` 被调用时，V8 会解析 WebAssembly 字节码。对于初始的快速编译，V8 可能会使用 Liftoff 编译器来生成可执行代码。然后，`instance.exports.add(5, 3)`  会调用 WebAssembly 模块中名为 `add` 的导出函数。

**代码逻辑推理（假设输入与输出）：**

假设我们正在处理一个 `call_indirect` 指令，并且有以下输入：

* **`index_reg` (输入):**  寄存器中存储着要调用的函数在 WebAssembly 表中的索引，假设值为 `2`。
* **`max_table_size` (常量):**  WebAssembly 表的最大大小，假设值为 `10`。
* **`dispatch_table` (输入):**  指向 WebAssembly 模块的 dispatch table 的指针。
* **`imm.sig_imm.index` (常量):**  期望的函数签名索引。
* **WebAssembly 表内容 (假设):** 表中索引为 2 的条目包含一个函数的地址，其签名与 `imm.sig_imm.index` 匹配。

**代码逻辑推理和可能的输出：**

1. **边界检查：** 代码会检查 `index_reg` 的值 (2) 是否小于 `max_table_size` (10)。由于 2 < 10，边界检查通过。
2. **Dispatch Table 偏移计算：** 由于我们假设索引是动态的 (`!is_static_index`)，代码会计算 dispatch table 中索引为 2 的条目的偏移量。
3. **加载函数地址和元数据：** 代码会从 dispatch table 中加载与索引 2 对应的函数的地址 (`target`) 和其他元数据 (`implicit_arg`)。
4. **签名检查：** 代码会加载实际的函数签名，并将其与期望的签名 (`imm.sig_imm.index`) 进行比较。如果匹配，则继续执行。
5. **执行间接调用：** 代码会准备参数并执行对加载的函数地址的间接调用。

**假设输出 (简化)：**

* 程序计数器跳转到从 dispatch table 中加载的函数地址。
* 函数开始执行。

**用户常见的编程错误 (涉及 `call_indirect`):**

1. **越界访问表 (Table out of bounds):**  使用了一个超出 WebAssembly 表大小的索引进行间接调用。这会导致运行时错误。

   ```c++
   // WebAssembly 代码 (示意)
   (module
     (table funcref (export "my_table") 10) // 表大小为 10
     (func $f1)
     (func $f2)
     (elem (i32.const 0) $f1 $f2) // 表中前两个元素
     (func (export "call_indirect_oob") (param $idx i32)
       (call_indirect (type-index 0) (local.get $idx)))
   )
   ```

   如果在 JavaScript 中调用 `instance.exports.call_indirect_oob(15)`，则会发生越界错误，因为索引 15 超出了表的大小。

2. **签名不匹配 (Signature mismatch):** 尝试通过 `call_indirect` 调用一个函数，但实际调用的函数的签名与 `call_indirect` 指令指定的签名不符。

   ```c++
   // WebAssembly 代码 (示意)
   (module
     (type $sig_i_i (func (param i32) (result i32)))
     (type $sig_v_v (func))
     (table funcref (export "my_table") 1)
     (func $f_i_i (param $x i32) (result i32) (local.get $x))
     (func $f_v_v (nop))
     (elem (i32.const 0) $f_i_i)
     (func (export "call_indirect_mismatch")
       (call_indirect (type $sig_v_v) (i32.const 0))) // 尝试用无参无返回的签名调用
   )
   ```

   在上面的例子中，`call_indirect` 指令期望调用一个无参数且无返回值的函数，但表中索引 0 的函数 `$f_i_i` 接受一个 `i32` 参数并返回一个 `i32`，这会导致签名不匹配错误。

3. **调用空表项 (Calling a null table entry):** 如果 WebAssembly 表中的某个条目尚未初始化或被显式设置为 null，尝试通过该条目进行间接调用会导致错误。

**作为第 12 部分的功能归纳：**

考虑到这是 13 个部分中的第 12 部分，并且从提供的代码片段来看，这个部分主要集中在 **WebAssembly 的函数调用机制，特别是间接调用 (`call_indirect`) 和函数引用调用 (`call_ref`) 的实现细节**。它涵盖了从边界检查、类型检查到实际调用执行的整个过程。此外，它还展示了 Liftoff 编译器如何与 V8 的其他组件（如内联优化和反优化机制）进行交互。

总而言之，`v8/src/wasm/baseline/liftoff-compiler.cc` 是 V8 快速执行 WebAssembly 代码的关键组成部分，它牺牲了极致的性能优化来换取更快的编译速度，并负责处理 WebAssembly 模块加载后的初始执行。提供的代码片段具体展示了 Liftoff 如何安全可靠地实现 WebAssembly 的函数调用机制。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/baseline/liftoff-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共13部分，请归纳一下它的功能

"""
dex_slot.i32_const(), max_table_size);
        } else if (Is64() && table->is_table64()) {
          // On 32-bit, this is the same as below, so include the `Is64()` test
          // to statically tell the compiler to skip this branch.
          // Note: {max_table_size} will be sign-extended, which is fine because
          // the MSB is known to be 0 (asserted by the static_assert below).
          static_assert(kV8MaxWasmTableSize <= kMaxInt);
          __ emit_ptrsize_cond_jumpi(kUnsignedGreaterThanEqual,
                                     out_of_bounds_label, index_reg,
                                     max_table_size, trapping);
        } else {
          __ emit_i32_cond_jumpi(kUnsignedGreaterThanEqual, out_of_bounds_label,
                                 index_reg, max_table_size, trapping);
        }
      }
    }

    // If the function index is dynamic, compute a pointer to the dispatch table
    // entry. Otherwise remember the static offset from the dispatch table to
    // add it to later loads from that table.
    ScopedTempRegister dispatch_table_base{std::move(dispatch_table)};
    int dispatch_table_offset = 0;
    if (is_static_index) {
      // Avoid potential integer overflow here by excluding too large
      // (statically OOB) indexes. This code is not reached for statically OOB
      // indexes anyway.
      dispatch_table_offset =
          statically_oob
              ? 0
              : wasm::ObjectAccess::ToTagged(
                    WasmDispatchTable::OffsetOf(index_slot.i32_const()));
    } else {
      // TODO(clemensb): Produce better code for this (via more specialized
      // platform-specific methods?).

      Register entry_offset = index_reg;
      // After this computation we don't need the index register any more. If
      // there is no other user we can overwrite it.
      bool index_reg_still_used =
          __ cache_state() -> get_use_count(LiftoffRegister{index_reg}) > 1;
      if (index_reg_still_used) entry_offset = temps.Acquire(kGpReg).gp();

      __ emit_u32_to_uintptr(entry_offset, index_reg);
      index_reg = no_reg;
      __ emit_ptrsize_muli(entry_offset, entry_offset,
                           WasmDispatchTable::kEntrySize);
      __ emit_ptrsize_add(dispatch_table_base.gp_reg(),
                          dispatch_table_base.gp_reg(), entry_offset);
      if (index_reg_still_used) temps.Return(std::move(entry_offset));
      dispatch_table_offset =
          wasm::ObjectAccess::ToTagged(WasmDispatchTable::kEntriesOffset);
    }

    bool needs_type_check = !EquivalentTypes(
        table->type.AsNonNull(), ValueType::Ref(imm.sig_imm.index),
        decoder->module_, decoder->module_);
    bool needs_null_check = table->type.is_nullable();

    // We do both the type check and the null check by checking the signature,
    // so this shares most code. For the null check we then only check if the
    // stored signature is != -1.
    if (needs_type_check || needs_null_check) {
      SCOPED_CODE_COMMENT(needs_type_check ? "Check signature"
                                           : "Check for null entry");
      ScopedTempRegister real_sig_id{temps, kGpReg};

      // Load the signature from the dispatch table.
      __ Load(real_sig_id.reg(), dispatch_table_base.gp_reg(), no_reg,
              dispatch_table_offset + WasmDispatchTable::kSigBias,
              LoadType::kI32Load);

      // Compare against expected signature.
      // Since Liftoff code is never serialized (hence not reused across
      // isolates / processes) the canonical signature ID is a static integer.
      CanonicalTypeIndex canonical_sig_id =
          decoder->module_->canonical_sig_id(imm.sig_imm.index);
      Label* sig_mismatch_label =
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapFuncSigMismatch);
      __ DropValues(1);

      if (!needs_type_check) {
        DCHECK(needs_null_check);
        // Only check for -1 (nulled table entry).
        FREEZE_STATE(frozen);
        __ emit_i32_cond_jumpi(kEqual, sig_mismatch_label, real_sig_id.gp_reg(),
                               -1, frozen);
      } else if (!decoder->module_->type(imm.sig_imm.index).is_final) {
        Label success_label;
        FREEZE_STATE(frozen);
        __ emit_i32_cond_jumpi(kEqual, &success_label, real_sig_id.gp_reg(),
                               canonical_sig_id.index, frozen);
        if (needs_null_check) {
          __ emit_i32_cond_jumpi(kEqual, sig_mismatch_label,
                                 real_sig_id.gp_reg(), -1, frozen);
        }
        ScopedTempRegister real_rtt{temps, kGpReg};
        __ LoadFullPointer(
            real_rtt.gp_reg(), kRootRegister,
            IsolateData::root_slot_offset(RootIndex::kWasmCanonicalRtts));
        __ LoadTaggedPointer(
            real_rtt.gp_reg(), real_rtt.gp_reg(), real_sig_id.gp_reg(),
            ObjectAccess::ToTagged(OFFSET_OF_DATA_START(WeakFixedArray)),
            nullptr, true);
        // real_sig_id is not used any more.
        real_sig_id.Reset();
        // Remove the weak reference tag.
        if constexpr (kSystemPointerSize == 4) {
          __ emit_i32_andi(real_rtt.gp_reg(), real_rtt.gp_reg(),
                           static_cast<int32_t>(~kWeakHeapObjectMask));
        } else {
          __ emit_i64_andi(real_rtt.reg(), real_rtt.reg(),
                           static_cast<int32_t>(~kWeakHeapObjectMask));
        }
        // Constant-time subtyping check: load exactly one candidate RTT from
        // the supertypes list.
        // Step 1: load the WasmTypeInfo.
        constexpr int kTypeInfoOffset = wasm::ObjectAccess::ToTagged(
            Map::kConstructorOrBackPointerOrNativeContextOffset);
        ScopedTempRegister type_info{std::move(real_rtt)};
        __ LoadTaggedPointer(type_info.gp_reg(), type_info.gp_reg(), no_reg,
                             kTypeInfoOffset);
        // Step 2: check the list's length if needed.
        uint32_t rtt_depth =
            GetSubtypingDepth(decoder->module_, imm.sig_imm.index);
        if (rtt_depth >= kMinimumSupertypeArraySize) {
          ScopedTempRegister list_length{temps, kGpReg};
          int offset =
              ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesLengthOffset);
          __ LoadSmiAsInt32(list_length.reg(), type_info.gp_reg(), offset);
          __ emit_i32_cond_jumpi(kUnsignedLessThanEqual, sig_mismatch_label,
                                 list_length.gp_reg(), rtt_depth, frozen);
        }
        // Step 3: load the candidate list slot, and compare it.
        ScopedTempRegister maybe_match{std::move(type_info)};
        __ LoadTaggedPointer(
            maybe_match.gp_reg(), maybe_match.gp_reg(), no_reg,
            ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesOffset +
                                   rtt_depth * kTaggedSize));
        ScopedTempRegister formal_rtt{temps, kGpReg};
        // Instead of {pinned}, we use {kGpCacheRegList} as the list of pinned
        // registers, to prevent any attempt to cache the instance, which would
        // be incompatible with the {FREEZE_STATE} that is in effect here.
        LOAD_TAGGED_PTR_INSTANCE_FIELD(formal_rtt.gp_reg(), ManagedObjectMaps,
                                       kGpCacheRegList);
        __ LoadTaggedPointer(
            formal_rtt.gp_reg(), formal_rtt.gp_reg(), no_reg,
            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                imm.sig_imm.index.index));
        __ emit_cond_jump(kNotEqual, sig_mismatch_label, kRtt,
                          formal_rtt.gp_reg(), maybe_match.gp_reg(), frozen);

        __ bind(&success_label);
      } else {
        FREEZE_STATE(trapping);
        __ emit_i32_cond_jumpi(kNotEqual, sig_mismatch_label,
                               real_sig_id.gp_reg(), canonical_sig_id.index,
                               trapping);
      }
    } else {
      __ DropValues(1);
    }

    {
      SCOPED_CODE_COMMENT("Execute indirect call");

      // The first parameter will be either a WasmTrustedInstanceData or a
      // WasmImportData.
      Register implicit_arg = temps.Acquire(kGpReg).gp();
      Register target = temps.Acquire(kGpReg).gp();

      {
        SCOPED_CODE_COMMENT("Load implicit arg and target from dispatch table");
        __ LoadProtectedPointer(
            implicit_arg, dispatch_table_base.gp_reg(),
            dispatch_table_offset + WasmDispatchTable::kImplicitArgBias);
        __ LoadCodePointer(
            target, dispatch_table_base.gp_reg(),
            dispatch_table_offset + WasmDispatchTable::kTargetBias);
      }

      if (v8_flags.wasm_inlining_call_indirect) {
        SCOPED_CODE_COMMENT("Feedback collection for speculative inlining");

        ScopedTempRegister vector{std::move(dispatch_table_base)};
        __ Fill(vector.reg(), WasmLiftoffFrameConstants::kFeedbackVectorOffset,
                kRef);
        VarState vector_var{kRef, vector.reg(), 0};

        // A constant `uint32_t` is sufficient for the vector slot index.
        // The number of call instructions (and hence feedback vector slots) is
        // capped by the number of instructions, which is capped by the maximum
        // function body size.
        static_assert(kV8MaxWasmFunctionSize <
                      std::numeric_limits<uint32_t>::max() / 2);
        uint32_t vector_slot =
            static_cast<uint32_t>(encountered_call_instructions_.size()) * 2;
        encountered_call_instructions_.push_back(
            FunctionTypeFeedback::kCallIndirect);
        VarState index_var(kI32, vector_slot, 0);

        // Thread the target and ref through the builtin call (i.e., pass them
        // as parameters and return them unchanged) as `CallBuiltin` otherwise
        // clobbers them. (The spilling code in `SpillAllRegisters` is only
        // aware of registers used on Liftoff's abstract value stack, not the
        // ones manually allocated above.)
        // TODO(335082212): We could avoid this and reduce the code size for
        // each call_indirect by moving the target and ref lookup into the
        // builtin as well.
        // However, then we would either (a) need to replicate the optimizations
        // above for static indices etc., which increases code duplication and
        // maintenance cost, or (b) regress performance even more than the
        // builtin call itself already does.
        // All in all, let's keep it simple at first, i.e., share the maximum
        // amount of code when inlining is enabled vs. not.
        VarState target_var(kIntPtrKind, LiftoffRegister(target), 0);
        VarState implicit_arg_var(kRef, LiftoffRegister(implicit_arg), 0);

        // CallIndirectIC(vector: FixedArray, vectorIndex: int32,
        //                target: RawPtr,
        //                implicitArg: WasmTrustedInstanceData|WasmImportData)
        //               -> <target, implicit_arg>
        CallBuiltin(Builtin::kCallIndirectIC,
                    MakeSig::Returns(kIntPtrKind, kIntPtrKind)
                        .Params(kRef, kI32, kIntPtrKind, kRef),
                    {vector_var, index_var, target_var, implicit_arg_var},
                    decoder->position());
        target = kReturnRegister0;
        implicit_arg = kReturnRegister1;
      }

      auto call_descriptor = compiler::GetWasmCallDescriptor(zone_, imm.sig);
      call_descriptor = GetLoweredCallDescriptor(zone_, call_descriptor);

      __ PrepareCall(&sig, call_descriptor, &target, implicit_arg);
      if (call_jump_mode == CallJumpMode::kTailCall) {
        __ PrepareTailCall(
            static_cast<int>(call_descriptor->ParameterSlotCount()),
            static_cast<int>(
                call_descriptor->GetStackParameterDelta(descriptor_)));
        __ TailCallIndirect(target);
      } else {
        source_position_table_builder_.AddPosition(
            __ pc_offset(), SourcePosition(decoder->position()), true);
        __ CallIndirect(&sig, call_descriptor, target);
        FinishCall(decoder, &sig, call_descriptor);
      }
    }
  }

  void StoreFrameDescriptionForDeopt(
      FullDecoder* decoder, uint32_t adapt_shadow_stack_pc_offset = 0) {
    DCHECK(v8_flags.wasm_deopt);
    DCHECK(!frame_description_);

    frame_description_ = std::make_unique<LiftoffFrameDescriptionForDeopt>(
        LiftoffFrameDescriptionForDeopt{
            decoder->pc_offset(), static_cast<uint32_t>(__ pc_offset()),
#ifdef V8_ENABLE_CET_SHADOW_STACK
            adapt_shadow_stack_pc_offset,
#endif  // V8_ENABLE_CET_SHADOW_STACK
            std::vector<LiftoffVarState>(__ cache_state()->stack_state.begin(),
                                         __ cache_state()->stack_state.end()),
            __ cache_state()->cached_instance_data});
  }

  void EmitDeoptPoint(FullDecoder* decoder) {
#if defined(DEBUG) and !defined(V8_TARGET_ARCH_ARM)
    // Liftoff may only use "allocatable registers" as defined by the
    // RegisterConfiguration. (The deoptimizer will not handle non-allocatable
    // registers).
    // Note that this DCHECK is skipped for arm 32 bit as its deoptimizer
    // decides to handle all available double / simd registers.
    const RegisterConfiguration* config = RegisterConfiguration::Default();
    DCHECK_LE(kLiftoffAssemblerFpCacheRegs.Count(),
              config->num_allocatable_simd128_registers());
    for (DoubleRegister reg : kLiftoffAssemblerFpCacheRegs) {
      const int* end = config->allocatable_simd128_codes() +
                       config->num_allocatable_simd128_registers();
      DCHECK(std::find(config->allocatable_simd128_codes(), end, reg.code()) !=
             end);
    }
#endif

    LiftoffAssembler::CacheState initial_state(zone_);
    initial_state.Split(*__ cache_state());
    // TODO(mliedtke): The deopt point should be in out-of-line-code.
    Label deopt_point;
    Label callref;
    __ emit_jump(&callref);
    __ bind(&deopt_point);
    uint32_t adapt_shadow_stack_pc_offset = __ pc_offset();
#ifdef V8_ENABLE_CET_SHADOW_STACK
    if (v8_flags.cet_compatible) {
      __ CallBuiltin(Builtin::kAdaptShadowStackForDeopt);
    }
#endif  // V8_ENABLE_CET_SHADOW_STACK
    StoreFrameDescriptionForDeopt(decoder, adapt_shadow_stack_pc_offset);
    CallBuiltin(Builtin::kWasmLiftoffDeoptFinish, MakeSig(), {},
                kNoSourcePosition);
    __ MergeStackWith(initial_state, 0, LiftoffAssembler::kForwardJump);
    __ cache_state() -> Steal(initial_state);
    __ bind(&callref);
  }

  void CallRefImpl(FullDecoder* decoder, ValueType func_ref_type,
                   const FunctionSig* type_sig, CallJumpMode call_jump_mode) {
    MostlySmallValueKindSig sig(zone_, type_sig);
    for (ValueKind ret : sig.returns()) {
      if (!CheckSupportedType(decoder, ret, "return")) return;
    }
    compiler::CallDescriptor* call_descriptor =
        compiler::GetWasmCallDescriptor(zone_, type_sig);
    call_descriptor = GetLoweredCallDescriptor(zone_, call_descriptor);

    Register target_reg = no_reg;
    Register implicit_arg_reg = no_reg;

    if (v8_flags.wasm_inlining) {
      if (v8_flags.wasm_deopt &&
          env_->deopt_info_bytecode_offset == decoder->pc_offset() &&
          env_->deopt_location_kind == LocationKindForDeopt::kEagerDeopt) {
        EmitDeoptPoint(decoder);
      }
      LiftoffRegList pinned;
      LiftoffRegister func_ref = pinned.set(__ PopToRegister(pinned));
      LiftoffRegister vector = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      MaybeEmitNullCheck(decoder, func_ref.gp(), pinned, func_ref_type);
      VarState func_ref_var(kRef, func_ref, 0);

#if V8_ENABLE_SANDBOX
      LiftoffRegister sig_hash_reg =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      __ LoadConstant(sig_hash_reg, WasmValue{SignatureHasher::Hash(type_sig)});
      VarState sig_hash_var{kIntPtrKind, sig_hash_reg, 0};
#else
      VarState sig_hash_var{kIntPtrKind, 0, 0};  // Unused by callee.
#endif

      __ Fill(vector, WasmLiftoffFrameConstants::kFeedbackVectorOffset, kRef);
      VarState vector_var{kRef, vector, 0};
      // A constant `uint32_t` is sufficient for the vector slot index.
      // The number of call instructions (and hence feedback vector slots) is
      // capped by the number of instructions, which is capped by the maximum
      // function body size.
      static_assert(kV8MaxWasmFunctionSize <
                    std::numeric_limits<uint32_t>::max() / 2);
      uint32_t vector_slot =
          static_cast<uint32_t>(encountered_call_instructions_.size()) * 2;
      encountered_call_instructions_.push_back(FunctionTypeFeedback::kCallRef);
      VarState index_var(kI32, vector_slot, 0);

      // CallRefIC(vector: FixedArray, vectorIndex: int32,
      //           signatureHash: uintptr,
      //           funcref: WasmFuncRef) -> <target, implicit_arg>
      CallBuiltin(Builtin::kCallRefIC,
                  MakeSig::Returns(kIntPtrKind, kIntPtrKind)
                      .Params(kRef, kI32, kIntPtrKind, kRef),
                  {vector_var, index_var, sig_hash_var, func_ref_var},
                  decoder->position());
      target_reg = LiftoffRegister(kReturnRegister0).gp();
      implicit_arg_reg = kReturnRegister1;
    } else {  // v8_flags.wasm_inlining
      // Non-feedback-collecting version.
      // Executing a write barrier needs temp registers; doing this on a
      // conditional branch confuses the LiftoffAssembler's register management.
      // Spill everything up front to work around that.
      __ SpillAllRegisters();

      LiftoffRegList pinned;
      Register func_ref = pinned.set(__ PopToModifiableRegister(pinned)).gp();
      MaybeEmitNullCheck(decoder, func_ref, pinned, func_ref_type);
      implicit_arg_reg = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      target_reg = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();

      // Load the WasmInternalFunction from the WasmFuncRef.
      Register internal_function = func_ref;
      __ LoadTrustedPointer(
          internal_function, func_ref,
          ObjectAccess::ToTagged(WasmFuncRef::kTrustedInternalOffset),
          kWasmInternalFunctionIndirectPointerTag);

      // Load the implicit argument (WasmTrustedInstanceData or WasmImportData)
      // and target.
      __ LoadProtectedPointer(
          implicit_arg_reg, internal_function,
          wasm::ObjectAccess::ToTagged(
              WasmInternalFunction::kProtectedImplicitArgOffset));

      __ LoadFullPointer(target_reg, internal_function,
                         wasm::ObjectAccess::ToTagged(
                             WasmInternalFunction::kCallTargetOffset));

      // Now the call target is in {target_reg} and the first parameter
      // (WasmTrustedInstanceData or WasmImportData) is in
      // {implicit_arg_reg}.
    }  // v8_flags.wasm_inlining

    __ PrepareCall(&sig, call_descriptor, &target_reg, implicit_arg_reg);
    if (call_jump_mode == CallJumpMode::kTailCall) {
      __ PrepareTailCall(
          static_cast<int>(call_descriptor->ParameterSlotCount()),
          static_cast<int>(
              call_descriptor->GetStackParameterDelta(descriptor_)));
      __ TailCallIndirect(target_reg);
    } else {
      source_position_table_builder_.AddPosition(
          __ pc_offset(), SourcePosition(decoder->position()), true);
      __ CallIndirect(&sig, call_descriptor, target_reg);
      FinishCall(decoder, &sig, call_descriptor);
    }
  }

  void LoadNullValue(Register null, ValueType type) {
    __ LoadFullPointer(
        null, kRootRegister,
        type.use_wasm_null()
            ? IsolateData::root_slot_offset(RootIndex::kWasmNull)
            : IsolateData::root_slot_offset(RootIndex::kNullValue));
  }

  // Stores the null value representation in the passed register.
  // If pointer compression is active, only the compressed tagged pointer
  // will be stored. Any operations with this register therefore must
  // not compare this against 64 bits using quadword instructions.
  void LoadNullValueForCompare(Register null, LiftoffRegList pinned,
                               ValueType type) {
#if V8_STATIC_ROOTS_BOOL
    uint32_t value = type.use_wasm_null() ? StaticReadOnlyRoot::kWasmNull
                                          : StaticReadOnlyRoot::kNullValue;
    __ LoadConstant(LiftoffRegister(null),
                    WasmValue(static_cast<uint32_t>(value)));
#else
    LoadNullValue(null, type);
#endif
  }

  void LoadExceptionSymbol(Register dst, LiftoffRegList pinned,
                           RootIndex root_index) {
    __ LoadFullPointer(dst, kRootRegister,
                       IsolateData::root_slot_offset(root_index));
  }

  void MaybeEmitNullCheck(FullDecoder* decoder, Register object,
                          LiftoffRegList pinned, ValueType type) {
    if (v8_flags.experimental_wasm_skip_null_checks || !type.is_nullable()) {
      return;
    }
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapNullDereference);
    LiftoffRegister null = __ GetUnusedRegister(kGpReg, pinned);
    LoadNullValueForCompare(null.gp(), pinned, type);
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kEqual, trap_label, kRefNull, object, null.gp(),
                      trapping);
  }

  void BoundsCheckArray(FullDecoder* decoder, bool implicit_null_check,
                        LiftoffRegister array, LiftoffRegister index,
                        LiftoffRegList pinned) {
    if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) return;
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapArrayOutOfBounds);
    LiftoffRegister length = __ GetUnusedRegister(kGpReg, pinned);
    constexpr int kLengthOffset =
        wasm::ObjectAccess::ToTagged(WasmArray::kLengthOffset);
    uint32_t protected_instruction_pc = 0;
    __ Load(length, array.gp(), no_reg, kLengthOffset, LoadType::kI32Load,
            implicit_null_check ? &protected_instruction_pc : nullptr);
    if (implicit_null_check) {
      RegisterProtectedInstruction(decoder, protected_instruction_pc);
    }
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kUnsignedGreaterThanEqual, trap_label, kI32, index.gp(),
                      length.gp(), trapping);
  }

  int StructFieldOffset(const StructType* struct_type, int field_index) {
    return wasm::ObjectAccess::ToTagged(WasmStruct::kHeaderSize +
                                        struct_type->field_offset(field_index));
  }

  std::pair<bool, bool> null_checks_for_struct_op(ValueType struct_type,
                                                  int field_index) {
    bool explicit_null_check =
        struct_type.is_nullable() &&
        (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit ||
         field_index > wasm::kMaxStructFieldIndexForImplicitNullCheck);
    bool implicit_null_check =
        struct_type.is_nullable() && !explicit_null_check;
    return {explicit_null_check, implicit_null_check};
  }

  void LoadObjectField(FullDecoder* decoder, LiftoffRegister dst, Register src,
                       Register offset_reg, int offset, ValueKind kind,
                       bool is_signed, bool trapping, LiftoffRegList pinned) {
    uint32_t protected_load_pc = 0;
    if (is_reference(kind)) {
      __ LoadTaggedPointer(dst.gp(), src, offset_reg, offset,
                           trapping ? &protected_load_pc : nullptr);
    } else {
      // Primitive kind.
      LoadType load_type = LoadType::ForValueKind(kind, is_signed);
      __ Load(dst, src, offset_reg, offset, load_type,
              trapping ? &protected_load_pc : nullptr);
    }
    if (trapping) RegisterProtectedInstruction(decoder, protected_load_pc);
  }

  void StoreObjectField(FullDecoder* decoder, Register obj, Register offset_reg,
                        int offset, LiftoffRegister value, bool trapping,
                        LiftoffRegList pinned, ValueKind kind,
                        LiftoffAssembler::SkipWriteBarrier skip_write_barrier =
                            LiftoffAssembler::kNoSkipWriteBarrier) {
    uint32_t protected_load_pc = 0;
    if (is_reference(kind)) {
      __ StoreTaggedPointer(obj, offset_reg, offset, value.gp(), pinned,
                            trapping ? &protected_load_pc : nullptr,
                            skip_write_barrier);
    } else {
      // Primitive kind.
      StoreType store_type = StoreType::ForValueKind(kind);
      __ Store(obj, offset_reg, offset, value, store_type, pinned,
               trapping ? &protected_load_pc : nullptr);
    }
    if (trapping) RegisterProtectedInstruction(decoder, protected_load_pc);
  }

  void SetDefaultValue(LiftoffRegister reg, ValueType type) {
    DCHECK(is_defaultable(type.kind()));
    switch (type.kind()) {
      case kI8:
      case kI16:
      case kI32:
        return __ LoadConstant(reg, WasmValue(int32_t{0}));
      case kI64:
        return __ LoadConstant(reg, WasmValue(int64_t{0}));
      case kF16:
      case kF32:
        return __ LoadConstant(reg, WasmValue(float{0.0}));
      case kF64:
        return __ LoadConstant(reg, WasmValue(double{0.0}));
      case kS128:
        DCHECK(CpuFeatures::SupportsWasmSimd128());
        return __ emit_s128_xor(reg, reg, reg);
      case kRefNull:
        return LoadNullValue(reg.gp(), type);
      case kRtt:
      case kVoid:
      case kTop:
      case kBottom:
      case kRef:
        UNREACHABLE();
    }
  }

  void MaybeOSR() {
    if (V8_UNLIKELY(for_debugging_)) {
      __ MaybeOSR();
    }
  }

  void FinishCall(FullDecoder* decoder, ValueKindSig* sig,
                  compiler::CallDescriptor* call_descriptor) {
    DefineSafepoint();
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    if (v8_flags.wasm_deopt &&
        env_->deopt_info_bytecode_offset == decoder->pc_offset() &&
        env_->deopt_location_kind == LocationKindForDeopt::kInlinedCall) {
      uint32_t adapt_shadow_stack_pc_offset = 0;
#ifdef V8_ENABLE_CET_SHADOW_STACK
      if (v8_flags.cet_compatible) {
        // AdaptShadowStackForDeopt is be called to build shadow stack after
        // deoptimization. Deoptimizer will directly jump to
        // `call AdaptShadowStackForDeopt`. But, in any other case, it should be
        // ignored.
        Label deopt_point;
        __ emit_jump(&deopt_point);
        adapt_shadow_stack_pc_offset = __ pc_offset();
        __ CallBuiltin(Builtin::kAdaptShadowStackForDeopt);
        __ bind(&deopt_point);
      }
#endif  // V8_ENABLE_CET_SHADOW_STACK
      StoreFrameDescriptionForDeopt(decoder, adapt_shadow_stack_pc_offset);
    }

    int pc_offset = __ pc_offset();
    MaybeOSR();
    EmitLandingPad(decoder, pc_offset);
    __ FinishCall(sig, call_descriptor);
  }

  void CheckNan(LiftoffRegister src, LiftoffRegList pinned, ValueKind kind) {
    DCHECK(kind == ValueKind::kF32 || kind == ValueKind::kF64);
    auto nondeterminism_addr = __ GetUnusedRegister(kGpReg, pinned);
    __ LoadConstant(
        nondeterminism_addr,
        WasmValue::ForUintPtr(reinterpret_cast<uintptr_t>(nondeterminism_)));
    __ emit_set_if_nan(nondeterminism_addr.gp(), src.fp(), kind);
  }

  void CheckS128Nan(LiftoffRegister dst, LiftoffRegList pinned,
                    ValueKind lane_kind) {
    RegClass rc = reg_class_for(kS128);
    LiftoffRegister tmp_gp = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LiftoffRegister tmp_s128 = pinned.set(__ GetUnusedRegister(rc, pinned));
    LiftoffRegister nondeterminism_addr =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(
        nondeterminism_addr,
        WasmValue::ForUintPtr(reinterpret_cast<uintptr_t>(nondeterminism_)));
    __ emit_s128_set_if_nan(nondeterminism_addr.gp(), dst, tmp_gp.gp(),
                            tmp_s128, lane_kind);
  }

  void ArrayFillImpl(FullDecoder* decoder, LiftoffRegList pinned,
                     LiftoffRegister obj, LiftoffRegister index,
                     LiftoffRegister value, LiftoffRegister length,
                     ValueKind elem_kind,
                     LiftoffAssembler::SkipWriteBarrier skip_write_barrier) {
    // initial_offset = WasmArray::kHeaderSize + index * elem_size.
    LiftoffRegister offset = index;
    if (value_kind_size_log2(elem_kind) != 0) {
      __ emit_i32_shli(offset.gp(), index.gp(),
                       value_kind_size_log2(elem_kind));
    }
    __ emit_i32_addi(offset.gp(), offset.gp(),
                     wasm::ObjectAccess::ToTagged(WasmArray::kHeaderSize));

    // end_offset = initial_offset + length * elem_size.
    LiftoffRegister end_offset = length;
    if (value_kind_size_log2(elem_kind) != 0) {
      __ emit_i32_shli(end_offset.gp(), length.gp(),
                       value_kind_size_log2(elem_kind));
    }
    __ emit_i32_add(end_offset.gp(), end_offset.gp(), offset.gp());

    FREEZE_STATE(frozen_for_conditional_jumps);
    Label loop, done;
    __ bind(&loop);
    __ emit_cond_jump(kUnsignedGreaterThanEqual, &done, kI32, offset.gp(),
                      end_offset.gp(), frozen_for_conditional_jumps);
    StoreObjectField(decoder, obj.gp(), offset.gp(), 0, value, false, pinned,
                     elem_kind, skip_write_barrier);
    __ emit_i32_addi(offset.gp(), offset.gp(), value_kind_size(elem_kind));
    __ emit_jump(&loop);

    __ bind(&done);
  }

  void RegisterProtectedInstruction(FullDecoder* decoder,
                                    uint32_t protected_instruction_pc) {
    protected_instructions_.emplace_back(
        trap_handler::ProtectedInstructionData{protected_instruction_pc});
    source_position_table_builder_.AddPosition(
        protected_instruction_pc, SourcePosition(decoder->position()), true);
    if (for_debugging_) {
      DefineSafepoint(protected_instruction_pc);
    }
  }

  bool has_outstanding_op() const {
    return outstanding_op_ != kNoOutstandingOp;
  }

  bool test_and_reset_outstanding_op(WasmOpcode opcode) {
    DCHECK_NE(kNoOutstandingOp, opcode);
    if (outstanding_op_ != opcode) return false;
    outstanding_op_ = kNoOutstandingOp;
    return true;
  }

  void TraceCacheState(FullDecoder* decoder) const {
    if (!v8_flags.trace_liftoff) return;
    StdoutStream os;
    for (int control_depth = decoder->control_depth() - 1; control_depth >= -1;
         --control_depth) {
      auto* cache_state =
          control_depth == -1 ? __ cache_state()
                              : &decoder->control_at(control_depth)
                                     ->label_state;
      os << PrintCollection(cache_state->stack_state);
      if (control_depth != -1) PrintF("; ");
    }
    os << "\n";
  }

  void DefineSafepoint(int pc_offset = 0) {
    if (pc_offset == 0) pc_offset = __ pc_offset_for_safepoint();
    if (pc_offset == last_safepoint_offset_) return;
    last_safepoint_offset_ = pc_offset;
    auto safepoint = safepoint_table_builder_.DefineSafepoint(&asm_, pc_offset);
    __ cache_state()->DefineSafepoint(safepoint);
  }

  void DefineSafepointWithCalleeSavedRegisters() {
    int pc_offset = __ pc_offset_for_safepoint();
    if (pc_offset == last_safepoint_offset_) return;
    last_safepoint_offset_ = pc_offset;
    auto safepoint = safepoint_table_builder_.DefineSafepoint(&asm_, pc_offset);
    __ cache_state()->DefineSafepointWithCalleeSavedRegisters(safepoint);
  }

  // Return a register holding the instance, populating the "cached instance"
  // register if possible. If no free register is available, the cache is not
  // set and we use {fallback} instead. This can be freely overwritten by the
  // caller then.
  V8_INLINE Register LoadInstanceIntoRegister(LiftoffRegList pinned,
                                              Register fallback) {
    Register instance = __ cache_state() -> cached_instance_data;
    if (V8_UNLIKELY(instance == no_reg)) {
      instance = LoadInstanceIntoRegister_Slow(pinned, fallback);
    }
    return instance;
  }

  V8_NOINLINE V8_PRESERVE_MOST Register
  LoadInstanceIntoRegister_Slow(LiftoffRegList pinned, Register fallback) {
    DCHECK_EQ(no_reg, __ cache_state()->cached_instance_data);
    SCOPED_CODE_COMMENT("load instance");
    Register instance = __ cache_state()->TrySetCachedInstanceRegister(
        pinned | LiftoffRegList{fallback});
    if (instance == no_reg) instance = fallback;
    __ LoadInstanceDataFromFrame(instance);
    return instance;
  }

  static constexpr WasmOpcode kNoOutstandingOp = kExprUnreachable;
  static constexpr base::EnumSet<ValueKind> kUnconditionallySupported{
      // MVP:
      kI32, kI64, kF32, kF64,
      // Extern ref:
      kRef, kRefNull, kRtt, kI8, kI16};

  LiftoffAssembler asm_;

  // Used for merging code generation of subsequent operations (via look-ahea
"""


```