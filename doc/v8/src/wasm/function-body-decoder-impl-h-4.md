Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/function-body-decoder-impl.h`.

The request has several constraints:
- List the functionalities.
- Explain if the file would be a Torque source file if it ended with `.tq`.
- Explain the relationship with JavaScript and provide a JavaScript example if applicable.
- Provide code logic reasoning with hypothetical input and output.
- Illustrate common programming errors.
- This is part 5 of 9, so focus on the functionalities within this specific snippet.

The code snippet seems to be handling the decoding of various WebAssembly instructions. It includes logic for:
- **Control Flow**: `BrOnNonNull`, `Loop`, `If`, `Else`, `End`, `Select`, `SelectWithType`, `Br`, `BrIf`, `BrTable`, `Return`, `Unreachable`.
- **Constants**: `I32Const`, `I64Const`, `F32Const`, `F64Const`, `RefNull`.
- **References**: `RefIsNull`, `RefFunc`, `RefAsNonNull`, `RefEq`.
- **Locals**: `LocalGet`, `LocalSet`, `LocalTee`.
- **Globals**: `GlobalGet`, `GlobalSet`.
- **Memory**: `TableGet`, `TableSet`, `LoadMem`, `StoreMem`, `MemoryGrow`, `MemorySize`.
- **Function Calls**: `CallFunction`, `CallIndirect`, `ReturnCall`, `ReturnCallIndirect`, `CallRef`, `ReturnCallRef`.
- **Other**: `Drop`, `Numeric`, `Simd`, `Atomic`, `GC`, and potentially some prototype opcodes.

Let's break down each constraint:

1. **Functionalities**: List the high-level actions performed by the code.
2. **Torque Source**: Explain if the `.tq` extension indicates a Torque file.
3. **JavaScript Relationship**: Identify how these WASM operations relate to JavaScript.
4. **Code Logic Reasoning**: Choose a specific instruction and explain its input, processing, and output.
5. **Common Programming Errors**:  Think about errors that could occur while writing WASM that this decoder would handle or related JavaScript issues.
6. **Part 5 Summary**:  Synthesize the main purpose of this code block within the larger decoding process.
这是v8源代码文件 `v8/src/wasm/function-body-decoder-impl.h` 的一部分，它定义了 `WasmFullDecoder` 类中用于解码 WebAssembly 函数体字节码的方法。以下是代码片段中包含的功能的归纳：

**功能列举:**

1. **解码 `BrOnNonNull` 指令:**
   - 检查栈顶的值是否为非 null 的对象引用。
   - 如果是非 null，则跳转到指定的由 `imm.depth` 指示的控制块。
   - 如果为 null，则继续执行后续代码。
   - 涉及到类型检查，确保操作数是合适的引用类型。

2. **解码 `Loop` 指令:**
   - 开始一个新的循环控制块。
   - 将循环的入口标签推入控制流栈。
   - 调用接口方法通知后端（例如 TurboFan 或 Liftoff）开始处理循环。
   - 在循环入口处推送合并值。

3. **解码 `If` 指令:**
   - 开始一个新的 `if` 控制块。
   - 从栈顶弹出一个 i32 类型的条件值。
   - 将 `if` 块的入口标签推入控制流栈。
   - 调用接口方法通知后端开始处理 `if` 块。

4. **解码 `Else` 指令:**
   - 处理 `if` 块的 `else` 分支。
   - 检查当前的控制块是否是一个没有 `else` 分支的 `if` 块。
   - 执行类型检查，确保控制流可以到达 `else` 分支。
   - 调用接口方法通知后端开始处理 `else` 分支。
   - 回滚 `if` 块中声明的局部变量的初始化状态。
   - 在 `else` 分支入口处推送合并值。

5. **解码 `End` 指令:**
   - 结束当前的控制块（例如 `if`，`else`，`loop`，`block`，`try`）。
   - 对于 `try` 块，处理 `catch` 子句的逻辑。
   - 如果是函数体的结尾，则处理隐式的 `return`。
   - 执行类型检查，确保控制流正常结束。
   - 将控制权交还给上一个控制块。

6. **解码 `Select` 指令:**
   - 从栈顶弹出两个相同类型的操作数和一个 i32 类型的条件值。
   - 根据条件值选择其中一个操作数并将其推入栈顶。
   - 存在 `SelectWithType` 指令，允许指定结果类型，用于处理引用类型。

7. **解码 `Br` 指令:**
   - 无条件跳转到由 `imm.depth` 指示的控制块。
   - 执行类型检查，确保跳转操作的类型安全。
   - 调用接口方法通知后端执行跳转。
   - 标记目标控制块为已到达。

8. **解码 `BrIf` 指令:**
   - 从栈顶弹出一个 i32 类型的条件值。
   - 如果条件值为真（非零），则跳转到由 `imm.depth` 指示的控制块。
   - 执行类型检查，确保跳转操作的类型安全。
   - 调用接口方法通知后端执行条件跳转。
   - 标记目标控制块为已到达。

9. **解码 `BrTable` 指令:**
   - 从栈顶弹出一个 i32 类型的索引值。
   - 根据索引值跳转到目标分支表中的相应标签，如果索引超出范围，则跳转到默认标签。
   - 执行类型检查，确保所有分支目标的类型一致。
   - 调用接口方法通知后端执行分支表跳转。
   - 标记所有可能的目标控制块为已到达。

10. **解码 `Return` 指令:**
    - 从栈顶弹出函数的返回值（如果有）。
    - 结束当前函数的执行并将控制权返回给调用者。

11. **解码 `Unreachable` 指令:**
    - 表示执行流永远不会到达此指令。
    - 调用接口方法通知后端此处为不可达代码。
    - 结束当前的控制块。

12. **解码常量指令 (`I32Const`, `I64Const`, `F32Const`, `F64Const`):**
    - 将相应的常量值推入栈顶。

13. **解码 `RefNull` 指令:**
    - 将一个指定类型的 null 引用值推入栈顶。

14. **解码 `RefIsNull` 指令:**
    - 从栈顶弹出一个引用值。
    - 如果该引用为 null，则将 1 推入栈顶，否则将 0 推入栈顶。

15. **解码 `RefFunc` 指令:**
    - 将一个指向指定函数的引用推入栈顶。

16. **解码 `RefAsNonNull` 指令:**
    - 从栈顶弹出一个可空引用。
    - 如果该引用为 null，则触发一个错误（或者在某些情况下，通过接口通知后端）。
    - 如果该引用非 null，则将其视为非 null 引用推入栈顶。

17. **解码局部变量相关指令 (`LocalGet`, `LocalSet`, `LocalTee`):**
    - `LocalGet`: 将指定局部变量的值推入栈顶。
    - `LocalSet`: 从栈顶弹出一个值并赋值给指定的局部变量。
    - `LocalTee`: 从栈顶弹出一个值，赋值给指定的局部变量，并将该值再次推入栈顶。

18. **解码 `Drop` 指令:**
    - 从栈顶弹出一个值并丢弃。

19. **解码全局变量相关指令 (`GlobalGet`, `GlobalSet`):**
    - `GlobalGet`: 将指定全局变量的值推入栈顶。
    - `GlobalSet`: 从栈顶弹出一个值并赋值给指定的全局变量。

20. **解码表相关指令 (`TableGet`, `TableSet`):**
    - `TableGet`: 从栈顶弹出一个索引，并获取指定 WebAssembly 表中该索引处的元素值，推入栈顶。
    - `TableSet`: 从栈顶弹出索引和值，并将该值设置到指定 WebAssembly 表的相应索引处。

21. **解码内存相关指令 (`LoadMem`, `StoreMem`, `MemoryGrow`, `MemorySize`):**
    - `LoadMem`: 从指定的内存地址加载值并推入栈顶。
    - `StoreMem`: 从栈顶弹出值和内存地址，并将值存储到指定的内存地址。
    - `MemoryGrow`: 尝试增加 WebAssembly 实例的内存大小。
    - `MemorySize`: 获取当前 WebAssembly 实例的内存大小。

22. **解码函数调用相关指令 (`CallFunction`, `CallIndirect`, `ReturnCall`, `ReturnCallIndirect`, `CallRef`, `ReturnCallRef`):**
    - `CallFunction`: 直接调用一个已知的 WebAssembly 函数。
    - `CallIndirect`: 通过函数表调用 WebAssembly 函数。
    - `ReturnCall`: 尾调用一个已知的 WebAssembly 函数。
    - `ReturnCallIndirect`: 尾调用一个通过函数表查找的 WebAssembly 函数。
    - `CallRef`: 通过函数引用调用函数。
    - `ReturnCallRef`: 尾调用一个函数引用。

23. **解码 `RefEq` 指令:**
    - 从栈顶弹出两个引用值。
    - 比较这两个引用是否相等，并将比较结果（1 或 0）推入栈顶。

24. **解码 `Numeric`, `Simd`, `Atomic`, `GC` 前缀指令:**
    - 这些指令是带有附加操作码的复合指令，会调用相应的解码函数来处理更具体的操作。

25. **处理简单的原型操作码:**
    - 存在一个宏 `FOREACH_SIMPLE_PROTOTYPE_OPCODE`，表明可能存在一些简单的原型指令被处理。

26. **处理未知的或 Asm.js 操作码:**
    - 如果遇到无法识别的操作码，或者当前模块是 Asm.js 模块，则进行相应的处理。

**关于 `.tq` 结尾：**

如果 `v8/src/wasm/function-body-decoder-impl.h` 以 `.tq` 结尾，那么它将是一个 **v8 Torque 源代码文件**。Torque 是一种用于编写 V8 内部代码的领域特定语言，它可以生成 C++ 代码。

**与 JavaScript 的关系：**

这段代码的功能是解码 WebAssembly 的指令，而 WebAssembly 是一种可以在现代 Web 浏览器中运行的二进制指令格式。JavaScript 通过 `WebAssembly` API 可以加载、编译和执行 WebAssembly 模块。

**JavaScript 示例：**

```javascript
// 假设我们有一个编译好的 WebAssembly 模块的字节码 buffer
const wasmBytes = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, // 魔数 WASM
  0x01, 0x00, 0x00, 0x00, // 版本
  // ... 模块的其他部分 ...
  0x0a, // Section: Code
  0x01, // 函数数量
  0x0c, // 函数体大小
  0x00, // 局部变量数量
  0x20, 0x00, // local.get 0
  0x41, 0x0a, // i32.const 10
  0x6a,       // i32.add
  0x0f,       // return
  0x0b  // end
]);

WebAssembly.instantiate(wasmBytes).then(module => {
  const instance = module.instance;
  const result = instance.exports.addTen(5); // 调用导出的函数
  console.log(result); // 输出 15
});
```

在这个例子中，`wasmBytes` 包含了 WebAssembly 的字节码，其中一部分字节码（例如 `0x20`, `0x41`, `0x6a`, `0x0f`）会被 `function-body-decoder-impl.h` 中的代码解码，以理解函数 `addTen` 的具体操作（获取局部变量 0，加载常量 10，进行 i32 加法，然后返回）。

**代码逻辑推理 (以 `I32Const` 为例):**

**假设输入:** 当前解码器的程序计数器 `this->pc_` 指向 `I32Const` 操作码的起始位置，紧随其后的是 i32 常量值的字节表示。例如，如果常量是 10，那么字节序列可能是 `0x41 0x0a`。

**处理过程:**

1. `DECODE(I32Const)` 被调用。
2. `ImmI32Immediate imm(this, this->pc_ + 1, validate);` 创建一个 `ImmI32Immediate` 对象，用于解析紧随操作码后的立即数（常量值）。这个过程会读取字节流并将 `0x0a` 解析为整数 10。
3. `Value* value = Push(kWasmI32);` 在栈上分配一个位置来存储 i32 类型的值。
4. `CALL_INTERFACE_IF_OK_AND_REACHABLE(I32Const, value, imm.value);` 调用后端接口（可能是 TurboFan 或 Liftoff 的代码生成器），通知它遇到了一个 i32 常量指令，并将解析出的常量值（10）传递给它。后端会将这个常量值存储到之前在栈上分配的位置。
5. `return 1 + imm.length;` 返回指令的长度，以便解码器可以移动到下一个指令。`imm.length` 在这个例子中取决于 10 的 LEB128 编码长度。

**假设输出:** 栈顶会增加一个类型为 `kWasmI32`，值为 10 的元素。解码器的程序计数器 `this->pc_` 会前进 `1 + imm.length` 个字节。

**用户常见的编程错误：**

1. **类型不匹配:**  例如，尝试将一个非引用的值传递给 `BrOnNonNull` 指令，这会导致 `PopTypeError`。
   ```c++
   // WebAssembly 代码片段 (伪代码)
   i32.const 0
   br_on_non_null  // 错误：栈顶是 i32，需要引用类型
   ```

2. **`else` 语句不匹配 `if`:** 在没有 `if` 语句的情况下使用 `else` 语句。
   ```c++
   // WebAssembly 代码片段 (伪代码)
   else  // 错误：前面没有 if
   ```

3. **跳转到不存在的标签:** `Br`，`BrIf` 或 `BrTable` 指令尝试跳转到超出当前控制流栈深度的标签。
   ```c++
   // WebAssembly 代码片段 (伪代码)
   block
     br 1 // 假设只有一个 block，深度为 0
   end
   br 1 // 错误：此时深度 1 的标签不存在
   ```

4. **`return` 语句返回值类型错误:** 函数声明了返回值类型，但是 `return` 语句返回了不兼容的类型或缺少返回值。

**归纳一下它的功能 (作为第 5 部分):**

这部分代码主要负责 WebAssembly 函数体中**控制流指令**（如分支、循环、条件语句）和**常量指令**的解码和初步处理。它读取字节码，识别指令类型，并提取指令的操作数。同时，它还进行基本的**类型检查**和**验证**，确保指令的使用符合 WebAssembly 规范。解码器通过调用接口方法，将解码出的信息传递给 V8 的其他组件（例如代码生成器），以便进行后续的编译和执行。这部分是 WebAssembly 代码执行流程中的关键步骤，负责将二进制指令转化为 V8 可以理解和执行的形式。

Prompt: 
```
这是目录为v8/src/wasm/function-body-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-body-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共9部分，请归纳一下它的功能

"""
r(0, ref_object, "object reference");
        return 0;
    }
    return 1 + imm.length;
  }

  DECODE(BrOnNonNull) {
    this->detected_->add_typed_funcref();
    BranchDepthImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm, control_.size())) return 0;
    Value ref_object = Pop();
    if (!VALIDATE(ref_object.type.is_object_reference() ||
                  ref_object.type.is_bottom())) {
      PopTypeError(
          0, ref_object,
          "subtype of ((ref null any), (ref null extern) or (ref null func))");
      return 0;
    }
    // Typechecking the branch and creating the branch merges requires the
    // non-null value on the stack, so we push it temporarily.
    Value* value_on_branch = Push(ref_object.type.AsNonNull());
    Control* c = control_at(imm.depth);
    if (!VALIDATE(
            (TypeCheckBranch<PushBranchValues::kYes, RewriteStackTypes::kYes>(
                c)))) {
      return 0;
    }
    switch (ref_object.type.kind()) {
      case kBottom:
        // We are in unreachable code. Do nothing.
        DCHECK(!current_code_reachable_and_ok_);
        break;
      case kRef:
        // For a non-nullable value, we always take the branch.
        if (V8_LIKELY(current_code_reachable_and_ok_)) {
          CALL_INTERFACE(Forward, ref_object, value_on_branch);
          CALL_INTERFACE(BrOrRet, imm.depth);
          // We know that the following code is not reachable, but according
          // to the spec it technically is. Set it to spec-only reachable.
          SetSucceedingCodeDynamicallyUnreachable();
          c->br_merge()->reached = true;
        }
        break;
      case kRefNull: {
        if (V8_LIKELY(current_code_reachable_and_ok_)) {
          CALL_INTERFACE(BrOnNonNull, ref_object, value_on_branch, imm.depth,
                         true);
          c->br_merge()->reached = true;
        }
        break;
      }
      default:
        PopTypeError(0, ref_object, "object reference");
        return 0;
    }
    Drop(*value_on_branch);
    return 1 + imm.length;
  }

  DECODE(Loop) {
    BlockTypeImmediate imm(this->enabled_, this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    Control* block = PushControl(kControlLoop, imm);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Loop, block);
    // Loops have a merge point at block entry, hence push the merge values
    // (Phis in case of TurboFan) after calling the interface.
    // TODO(clemensb): Can we skip this (and the related PushMergeValues in
    // PopControl) for Liftoff?
    PushMergeValues(block, &block->start_merge);
    return 1 + imm.length;
  }

  DECODE(If) {
    BlockTypeImmediate imm(this->enabled_, this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    Value cond = Pop(kWasmI32);
    Control* if_block = PushControl(kControlIf, imm);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(If, cond, if_block);
    return 1 + imm.length;
  }

  DECODE(Else) {
    DCHECK(!control_.empty());
    Control* c = &control_.back();
    if (!VALIDATE(c->is_if())) {
      this->DecodeError("else does not match an if");
      return 0;
    }
    if (!VALIDATE(c->is_onearmed_if())) {
      this->DecodeError("else already present for if");
      return 0;
    }
    if (!VALIDATE(TypeCheckFallThru())) return 0;
    c->kind = kControlIfElse;
    CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(Else, c);
    if (c->reachable()) c->end_merge.reached = true;
    RollbackLocalsInitialization(c);
    PushMergeValues(c, &c->start_merge);
    c->reachability = control_at(1)->innerReachability();
    current_code_reachable_and_ok_ = VALIDATE(this->ok()) && c->reachable();
    return 1;
  }

  DECODE(End) {
    DCHECK(!control_.empty());
    if constexpr (decoding_mode == kFunctionBody) {
      Control* c = &control_.back();
      if (c->is_incomplete_try()) {
        // Catch-less try, fall through to the implicit catch-all.
        c->kind = kControlTryCatch;
        current_catch_ = c->previous_catch;  // Pop try scope.
      }
      if (c->is_try_catch()) {
        // Emulate catch-all + re-throw.
        FallThrough();
        c->reachability = control_at(1)->innerReachability();
        current_code_reachable_and_ok_ = VALIDATE(this->ok()) && c->reachable();
        // Cache `c->might_throw` so we can access it safely after `c`'s
        // destructor is called in `PopContol()`.
        bool might_throw = c->might_throw;
        if (might_throw) {
          CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(CatchAll, c);
          CALL_INTERFACE_IF_OK_AND_REACHABLE(Rethrow, c);
        }
        EndControl();
        PopControl();
        // We must mark the parent catch block as `might_throw`, since this
        // conceptually rethrows. Note that we do this regardless of whether
        // the code at this point is reachable.
        if (might_throw && current_catch() != -1) {
          control_at(control_depth_of_current_catch())->might_throw = true;
        }
        return 1;
      }
      if (c->is_onearmed_if()) {
        if (!VALIDATE(TypeCheckOneArmedIf(c))) return 0;
      }
      if (c->is_try_table()) {
        // "Pop" the {current_catch_} index. We did not push it if the block has
        // no handler, so also skip it here in this case.
        if (c->catch_cases.size() > 0) {
          current_catch_ = c->previous_catch;
        }
        FallThrough();
        // Temporarily set the reachability for the catch handlers, and restore
        // it before we actually exit the try block.
        Reachability reachability_at_end = c->reachability;
        c->reachability = control_at(1)->innerReachability();
        current_code_reachable_and_ok_ = VALIDATE(this->ok()) && c->reachable();
        for (CatchCase& catch_case : c->catch_cases) {
          uint32_t stack_size = stack_.size();
          size_t push_count = 0;
          if (catch_case.kind == kCatch || catch_case.kind == kCatchRef) {
            const WasmTagSig* sig = catch_case.maybe_tag.tag_imm.tag->sig;
            stack_.EnsureMoreCapacity(static_cast<int>(sig->parameter_count()),
                                      this->zone_);
            for (ValueType type : sig->parameters()) Push(type);
            push_count = sig->parameter_count();
          }
          if (catch_case.kind == kCatchRef || catch_case.kind == kCatchAllRef) {
            stack_.EnsureMoreCapacity(1, this->zone_);
            Push(ValueType::Ref(HeapType::kExn));
            push_count += 1;
          }
          base::Vector<Value> values(
              stack_.begin() + stack_.size() - push_count, push_count);
          if (c->might_throw) {
            // Already type checked on block entry.
            CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(CatchCase, c, catch_case,
                                                      values);
            if (current_code_reachable_and_ok_) {
              Control* target = control_at(catch_case.br_imm.depth);
              target->br_merge()->reached = true;
            }
          }
          stack_.shrink_to(stack_size);
          if (catch_case.kind == kCatchAll || catch_case.kind == kCatchAllRef) {
            break;
          }
        }
        c->reachability = reachability_at_end;
        // If there is no catch-all case, we must mark the parent catch block as
        // `might_throw`, since this conceptually rethrows. Note that we do this
        // regardless of whether the code at this point is reachable.
        if (c->might_throw && !HasCatchAll(c) && current_catch() != -1) {
          control_at(control_depth_of_current_catch())->might_throw = true;
        }
        EndControl();
        PopControl();
        return 1;
      }
    }

    if (control_.size() == 1) {
      // We need to call this first because the interface might set
      // {this->end_}, making the next check pass.
      DoReturn<kStrictCounting, decoding_mode == kFunctionBody
                                    ? kFallthroughMerge
                                    : kInitExprMerge>();
      // If at the last (implicit) control, check we are at end.
      if (!VALIDATE(this->pc_ + 1 == this->end_)) {
        this->DecodeError(this->pc_ + 1, "trailing code after function end");
        return 0;
      }
      // The result of the block is the return value.
      trace_msg->Append("\n" TRACE_INST_FORMAT, startrel(this->pc_),
                        "(implicit) return");
      control_.pop();
      return 1;
    }

    if (!VALIDATE(TypeCheckFallThru())) return 0;
    PopControl();
    return 1;
  }

  DECODE(Select) {
    auto [tval, fval, cond] = Pop(kWasmBottom, kWasmBottom, kWasmI32);
    ValueType result_type = tval.type;
    if (result_type == kWasmBottom) {
      result_type = fval.type;
    } else {
      ValidateStackValue(1, fval, result_type);
    }
    if (!VALIDATE(!result_type.is_reference())) {
      this->DecodeError(
          "select without type is only valid for value type inputs");
      return 0;
    }
    Value* result = Push(result_type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Select, cond, fval, tval, result);
    return 1;
  }

  DECODE(SelectWithType) {
    this->detected_->add_reftypes();
    SelectTypeImmediate imm(this->enabled_, this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    auto [tval, fval, cond] = Pop(imm.type, imm.type, kWasmI32);
    Value* result = Push(imm.type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Select, cond, fval, tval, result);
    return 1 + imm.length;
  }

  DECODE(Br) {
    BranchDepthImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm, control_.size())) return 0;
    Control* c = control_at(imm.depth);
    if (!VALIDATE(
            (TypeCheckBranch<PushBranchValues::kNo, RewriteStackTypes::kNo>(
                c)))) {
      return 0;
    }
    if (V8_LIKELY(current_code_reachable_and_ok_)) {
      CALL_INTERFACE(BrOrRet, imm.depth);
      c->br_merge()->reached = true;
    }
    EndControl();
    return 1 + imm.length;
  }

  DECODE(BrIf) {
    BranchDepthImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm, control_.size())) return 0;
    Value cond = Pop(kWasmI32);
    Control* c = control_at(imm.depth);
    if (!VALIDATE(
            (TypeCheckBranch<PushBranchValues::kYes, RewriteStackTypes::kYes>(
                c)))) {
      return 0;
    }
    if (V8_LIKELY(current_code_reachable_and_ok_)) {
      CALL_INTERFACE(BrIf, cond, imm.depth);
      c->br_merge()->reached = true;
    }
    return 1 + imm.length;
  }

  DECODE(BrTable) {
    BranchTableImmediate imm(this, this->pc_ + 1, validate);
    BranchTableIterator<ValidationTag> iterator(this, imm);
    Value key = Pop(kWasmI32);
    if (!VALIDATE(this->ok())) return 0;
    if (!this->Validate(this->pc_ + 1, imm)) return 0;

    // Cache the branch targets during the iteration, so that we can set
    // all branch targets as reachable after the {CALL_INTERFACE} call.
    SmallZoneVector<bool, 32> br_targets(control_.size(), this->zone());
    std::uninitialized_fill(br_targets.begin(), br_targets.end(), false);

    uint32_t arity = 0;

    while (iterator.has_next()) {
      const uint32_t index = iterator.cur_index();
      const uint8_t* pos = iterator.pc();
      const uint32_t target = iterator.next();
      if (!VALIDATE(target < control_depth())) {
        this->DecodeError(pos, "invalid branch depth: %u", target);
        return 0;
      }
      // Avoid redundant branch target checks.
      if (br_targets[target]) continue;
      br_targets[target] = true;

      if (ValidationTag::validate) {
        if (index == 0) {
          arity = control_at(target)->br_merge()->arity;
        } else if (!VALIDATE(control_at(target)->br_merge()->arity == arity)) {
          this->DecodeError(
              pos, "br_table: label arity inconsistent with previous arity %d",
              arity);
          return 0;
        }
        if (!VALIDATE(
                (TypeCheckBranch<PushBranchValues::kNo, RewriteStackTypes::kNo>(
                    control_at(target))))) {
          return 0;
        }
      }
    }

    if (V8_LIKELY(current_code_reachable_and_ok_)) {
      CALL_INTERFACE(BrTable, imm, key);

      for (uint32_t i = 0; i < control_depth(); ++i) {
        control_at(i)->br_merge()->reached |= br_targets[i];
      }
    }
    EndControl();
    return 1 + iterator.length();
  }

  DECODE(Return) {
    return DoReturn<kNonStrictCounting, kReturnMerge>() ? 1 : 0;
  }

  DECODE(Unreachable) {
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Trap, TrapReason::kTrapUnreachable);
    EndControl();
    return 1;
  }

  DECODE(I32Const) {
    ImmI32Immediate imm(this, this->pc_ + 1, validate);
    Value* value = Push(kWasmI32);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(I32Const, value, imm.value);
    return 1 + imm.length;
  }

  DECODE(I64Const) {
    ImmI64Immediate imm(this, this->pc_ + 1, validate);
    Value* value = Push(kWasmI64);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(I64Const, value, imm.value);
    return 1 + imm.length;
  }

  DECODE(F32Const) {
    ImmF32Immediate imm(this, this->pc_ + 1, validate);
    Value* value = Push(kWasmF32);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(F32Const, value, imm.value);
    return 1 + imm.length;
  }

  DECODE(F64Const) {
    ImmF64Immediate imm(this, this->pc_ + 1, validate);
    Value* value = Push(kWasmF64);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(F64Const, value, imm.value);
    return 1 + imm.length;
  }

  DECODE(RefNull) {
    this->detected_->add_reftypes();
    HeapTypeImmediate imm(this->enabled_, this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    if (!VALIDATE(!this->enabled_.has_stringref() ||
                  !imm.type.is_string_view())) {
      this->DecodeError(this->pc_ + 1, "cannot create null string view");
      return 0;
    }
    ValueType type = ValueType::RefNull(imm.type);
    Value* value = Push(type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(RefNull, type, value);
    return 1 + imm.length;
  }

  DECODE(RefIsNull) {
    this->detected_->add_reftypes();
    Value value = Pop();
    Value* result = Push(kWasmI32);
    switch (value.type.kind()) {
      case kRefNull:
        CALL_INTERFACE_IF_OK_AND_REACHABLE(UnOp, kExprRefIsNull, value, result);
        return 1;
      case kBottom:
        // We are in unreachable code, the return value does not matter.
      case kRef:
        // For non-nullable references, the result is always false.
        CALL_INTERFACE_IF_OK_AND_REACHABLE(Drop);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(I32Const, result, 0);
        return 1;
      default:
        if constexpr (!ValidationTag::validate) UNREACHABLE();
        PopTypeError(0, value, "reference type");
        return 0;
    }
  }

  DECODE(RefFunc) {
    this->detected_->add_reftypes();
    IndexImmediate imm(this, this->pc_ + 1, "function index", validate);
    if (!this->ValidateFunction(this->pc_ + 1, imm)) return 0;
    Value* value =
        Push(ValueType::Ref(this->module_->functions[imm.index].sig_index));
    CALL_INTERFACE_IF_OK_AND_REACHABLE(RefFunc, imm.index, value);
    return 1 + imm.length;
  }

  DECODE(RefAsNonNull) {
    this->detected_->add_typed_funcref();
    Value value = Pop();
    switch (value.type.kind()) {
      case kBottom:
        // We are in unreachable code. Forward the bottom value.
      case kRef:
        // A non-nullable value can remain as-is.
        Push(value);
        return 1;
      case kRefNull: {
        Value* result = Push(ValueType::Ref(value.type.heap_type()));
        CALL_INTERFACE_IF_OK_AND_REACHABLE(RefAsNonNull, value, result);
        return 1;
      }
      default:
        if constexpr (!ValidationTag::validate) UNREACHABLE();
        PopTypeError(0, value, "reference type");
        return 0;
    }
  }

  V8_INLINE DECODE(LocalGet) {
    IndexImmediate imm(this, this->pc_ + 1, "local index", validate);
    if (!this->ValidateLocal(this->pc_ + 1, imm)) return 0;
    if (!VALIDATE(this->is_local_initialized(imm.index))) {
      this->DecodeError(this->pc_, "uninitialized non-defaultable local: %u",
                        imm.index);
      return 0;
    }
    Value* value = Push(this->local_type(imm.index));
    CALL_INTERFACE_IF_OK_AND_REACHABLE(LocalGet, value, imm);
    return 1 + imm.length;
  }

  DECODE(LocalSet) {
    IndexImmediate imm(this, this->pc_ + 1, "local index", validate);
    if (!this->ValidateLocal(this->pc_ + 1, imm)) return 0;
    Value value = Pop(this->local_type(imm.index));
    CALL_INTERFACE_IF_OK_AND_REACHABLE(LocalSet, value, imm);
    this->set_local_initialized(imm.index);
    return 1 + imm.length;
  }

  DECODE(LocalTee) {
    IndexImmediate imm(this, this->pc_ + 1, "local index", validate);
    if (!this->ValidateLocal(this->pc_ + 1, imm)) return 0;
    ValueType local_type = this->local_type(imm.index);
    Value value = Pop(local_type);
    Value* result = Push(local_type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(LocalTee, value, result, imm);
    this->set_local_initialized(imm.index);
    return 1 + imm.length;
  }

  DECODE(Drop) {
    Pop();
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Drop);
    return 1;
  }

  DECODE(GlobalGet) {
    GlobalIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    Value* result = Push(imm.global->type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(GlobalGet, result, imm);
    return 1 + imm.length;
  }

  DECODE(GlobalSet) {
    GlobalIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    if (!VALIDATE(imm.global->mutability)) {
      this->DecodeError("immutable global #%u cannot be assigned", imm.index);
      return 0;
    }
    Value value = Pop(imm.global->type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(GlobalSet, value, imm);
    return 1 + imm.length;
  }

  DECODE(TableGet) {
    this->detected_->add_reftypes();
    TableIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    Value index = Pop(TableAddressType(imm.table));
    Value* result = Push(imm.table->type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(TableGet, index, result, imm);
    return 1 + imm.length;
  }

  DECODE(TableSet) {
    this->detected_->add_reftypes();
    TableIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    ValueType table_address_type = TableAddressType(imm.table);
    auto [index, value] = Pop(table_address_type, imm.table->type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(TableSet, index, value, imm);
    return 1 + imm.length;
  }

  DECODE(LoadMem) { return DecodeLoadMem(GetLoadType(opcode)); }

  DECODE(StoreMem) { return DecodeStoreMem(GetStoreType(opcode)); }

  DECODE(MemoryGrow) {
    // This opcode will not be emitted by the asm translator.
    DCHECK_EQ(kWasmOrigin, this->module_->origin);
    MemoryIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    ValueType mem_type = MemoryAddressType(imm.memory);
    Value value = Pop(mem_type);
    Value* result = Push(mem_type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(MemoryGrow, imm, value, result);
    return 1 + imm.length;
  }

  DECODE(MemorySize) {
    MemoryIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    ValueType result_type = MemoryAddressType(imm.memory);
    Value* result = Push(result_type);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(CurrentMemoryPages, imm, result);
    return 1 + imm.length;
  }

  DECODE(CallFunction) {
    CallFunctionImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    PoppedArgVector args = PopArgs(imm.sig);
    Value* returns = PushReturns(imm.sig);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(CallDirect, imm, args.data(), returns);
    MarkMightThrow();
    return 1 + imm.length;
  }

  DECODE(CallIndirect) {
    CallIndirectImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    Value index = Pop(TableAddressType(imm.table_imm.table));
    PoppedArgVector args = PopArgs(imm.sig);
    Value* returns = PushReturns(imm.sig);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(CallIndirect, index, imm, args.data(),
                                       returns);
    MarkMightThrow();
    if (!this->module_->type(imm.sig_imm.index).is_final) {
      // In this case we emit an rtt.canon as part of the indirect call.
      this->detected_->add_gc();
    }
    return 1 + imm.length;
  }

  DECODE(ReturnCall) {
    this->detected_->add_return_call();
    CallFunctionImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    if (!VALIDATE(this->CanReturnCall(imm.sig))) {
      this->DecodeError("%s: %s", WasmOpcodes::OpcodeName(kExprReturnCall),
                        "tail call type error");
      return 0;
    }
    PoppedArgVector args = PopArgs(imm.sig);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(ReturnCall, imm, args.data());
    EndControl();
    return 1 + imm.length;
  }

  DECODE(ReturnCallIndirect) {
    this->detected_->add_return_call();
    CallIndirectImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    if (!VALIDATE(this->CanReturnCall(imm.sig))) {
      this->DecodeError("%s: %s",
                        WasmOpcodes::OpcodeName(kExprReturnCallIndirect),
                        "tail call return types mismatch");
      return 0;
    }
    Value index = Pop(TableAddressType(imm.table_imm.table));
    PoppedArgVector args = PopArgs(imm.sig);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(ReturnCallIndirect, index, imm,
                                       args.data());
    EndControl();
    if (!this->module_->type(imm.sig_imm.index).is_final) {
      // In this case we emit an rtt.canon as part of the indirect call.
      this->detected_->add_gc();
    }
    return 1 + imm.length;
  }

  DECODE(CallRef) {
    this->detected_->add_typed_funcref();
    SigIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    Value func_ref = Pop(ValueType::RefNull(imm.index));
    PoppedArgVector args = PopArgs(imm.sig);
    Value* returns = PushReturns(imm.sig);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(CallRef, func_ref, imm.sig, args.data(),
                                       returns);
    MarkMightThrow();
    return 1 + imm.length;
  }

  DECODE(ReturnCallRef) {
    this->detected_->add_typed_funcref();
    this->detected_->add_return_call();
    SigIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    if (!VALIDATE(this->CanReturnCall(imm.sig))) {
      this->DecodeError("%s: %s", WasmOpcodes::OpcodeName(kExprReturnCallRef),
                        "tail call return types mismatch");
      return 0;
    }
    Value func_ref = Pop(ValueType::RefNull(imm.index));
    PoppedArgVector args = PopArgs(imm.sig);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(ReturnCallRef, func_ref, imm.sig,
                                       args.data());
    EndControl();
    return 1 + imm.length;
  }

  DECODE(RefEq) {
    this->detected_->add_gc();
    Value lhs = Pop();
    if (!VALIDATE(IsSubtypeOf(lhs.type, kWasmEqRef, this->module_) ||
                  IsSubtypeOf(lhs.type, ValueType::RefNull(HeapType::kEqShared),
                              this->module_) ||
                  control_.back().unreachable())) {
      this->DecodeError(this->pc_,
                        "ref.eq[0] expected either eqref or (ref null shared "
                        "eq), found %s of type %s",
                        SafeOpcodeNameAt(lhs.pc()), lhs.type.name().c_str());
    }
    Value rhs = Pop();
    if (!VALIDATE(IsSubtypeOf(rhs.type, kWasmEqRef, this->module_) ||
                  IsSubtypeOf(rhs.type, ValueType::RefNull(HeapType::kEqShared),
                              this->module_) ||
                  control_.back().unreachable())) {
      this->DecodeError(this->pc_,
                        "ref.eq[0] expected either eqref or (ref null shared "
                        "eq), found %s of type %s",
                        SafeOpcodeNameAt(rhs.pc()), rhs.type.name().c_str());
    }
    Value* result = Push(kWasmI32);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(BinOp, kExprRefEq, lhs, rhs, result);
    return 1;
  }

  DECODE(Numeric) {
    auto [full_opcode, opcode_length] =
        this->template read_prefixed_opcode<ValidationTag>(this->pc_,
                                                           "numeric index");
    if (full_opcode == kExprTableGrow || full_opcode == kExprTableSize ||
        full_opcode == kExprTableFill) {
      this->detected_->add_reftypes();
    }
    trace_msg->AppendOpcode(full_opcode);
    return DecodeNumericOpcode(full_opcode, opcode_length);
  }

  DECODE(Simd) {
    this->detected_->add_simd();
    if (!CheckHardwareSupportsSimd()) {
      if (v8_flags.correctness_fuzzer_suppressions) {
        FATAL("Aborting on missing Wasm SIMD support");
      }
      this->DecodeError("Wasm SIMD unsupported");
      return 0;
    }
    auto [full_opcode, opcode_length] =
        this->template read_prefixed_opcode<ValidationTag>(this->pc_);
    if (!VALIDATE(this->ok())) return 0;
    trace_msg->AppendOpcode(full_opcode);
    if (WasmOpcodes::IsFP16SimdOpcode(full_opcode)) {
      this->detected_->add_fp16();
    } else if (WasmOpcodes::IsRelaxedSimdOpcode(full_opcode)) {
      this->detected_->add_relaxed_simd();
    }
    return DecodeSimdOpcode(full_opcode, opcode_length);
  }

  DECODE(Atomic) {
    this->detected_->add_threads();
    auto [full_opcode, opcode_length] =
        this->template read_prefixed_opcode<ValidationTag>(this->pc_,
                                                           "atomic index");
    trace_msg->AppendOpcode(full_opcode);
    return DecodeAtomicOpcode(full_opcode, opcode_length);
  }

  DECODE(GC) {
    auto [full_opcode, opcode_length] =
        this->template read_prefixed_opcode<ValidationTag>(this->pc_,
                                                           "gc index");
    trace_msg->AppendOpcode(full_opcode);
    // If we are validating we could have read an illegal opcode. Handle that
    // separately.
    if (!VALIDATE(full_opcode != 0)) {
      DCHECK(this->failed());
      return 0;
    } else if (full_opcode >= kExprStringNewUtf8) {
      CHECK_PROTOTYPE_OPCODE(stringref);
      return DecodeStringRefOpcode(full_opcode, opcode_length);
    } else {
      this->detected_->add_gc();
      return DecodeGCOpcode(full_opcode, opcode_length);
    }
  }

#define SIMPLE_PROTOTYPE_CASE(name, ...) \
  DECODE(name) { return BuildSimplePrototypeOperator(opcode); }
  FOREACH_SIMPLE_PROTOTYPE_OPCODE(SIMPLE_PROTOTYPE_CASE)
#undef SIMPLE_PROTOTYPE_CASE

  DECODE(UnknownOrAsmJs) {
    // Deal with special asmjs opcodes.
    if (!VALIDATE(is_asmjs_module(this->module_))) {
      this->DecodeError("Invalid opcode 0x%x", opcode);
      return 0;
    }
    const FunctionSig* sig = WasmOpcodes::AsmjsSignature(opcode);
    DCHECK_NOT_NULL(sig);
    return BuildSimpleOperator(opcode, sig);
  }

#undef DECODE

  static int NonConstError(WasmFullDecoder* decoder, WasmOpcode opcode) {
    decoder->DecodeError("opcode %s is not allowed in constant expressions",
                         WasmOpcodes::OpcodeName(opcode));
    return 0;
  }

  using OpcodeHandler = int (*)(WasmFullDecoder*, WasmOpcode);

  // Ideally we would use template specialization for the different opcodes, but
  // GCC does not allow to specialize templates in class scope
  // (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=85282), and specializing
  // outside the class is not allowed for non-specialized classes.
  // Hence just list all implementations explicitly here, which also gives more
  // freedom to use the same implementation for different opcodes.
#define DECODE_IMPL(opcode) DECODE_IMPL2(kExpr##opcode, opcode)
#define DECODE_IMPL2(opcode, name)                        \
  if (idx == opcode) {                                    \
    if constexpr (decoding_mode == kConstantExpression) { \
      return &WasmFullDecoder::NonConstError;             \
    } else {                                              \
      return &WasmFullDecoder::Decode##name;              \
    }                                                     \
  }
#define DECODE_IMPL_CONST(opcode) DECODE_IMPL_CONST2(kExpr##opcode, opcode)
#define DECODE_IMPL_CONST2(opcode, name) \
  if (idx == opcode) return &WasmFullDecoder::Decode##name

  static constexpr OpcodeHandler GetOpcodeHandlerTableEntry(size_t idx) {
    DECODE_IMPL(Nop);
#define BUILD_SIMPLE_OPCODE(op, ...) DECODE_IMPL(op);
    FOREACH_SIMPLE_NON_CONST_OPCODE(BUILD_SIMPLE_OPCODE)
#undef BUILD_SIMPLE_OPCODE
#define BUILD_SIMPLE_EXTENDED_CONST_OPCODE(op, ...) DECODE_IMPL_CONST(op);
    FOREACH_SIMPLE_EXTENDED_CONST_OPCODE(BUILD_SIMPLE_EXTENDED_CONST_OPCODE)
#undef BUILD_SIMPLE_EXTENDED_CONST_OPCODE
    DECODE_IMPL(Block);
    DECODE_IMPL(Rethrow);
    DECODE_IMPL(Throw);
    DECODE_IMPL(Try);
    DECODE_IMPL(TryTable);
    DECODE_IMPL(ThrowRef);
    DECODE_IMPL(Catch);
    DECODE_IMPL(Delegate);
    DECODE_IMPL(CatchAll);
    DECODE_IMPL(BrOnNull);
    DECODE_IMPL(BrOnNonNull);
    DECODE_IMPL(Loop);
    DECODE_IMPL(If);
    DECODE_IMPL(Else);
    DECODE_IMPL_CONST(End);
    DECODE_IMPL(Select);
    DECODE_IMPL(SelectWithType);
    DECODE_IMPL(Br);
    DECODE_IMPL(BrIf);
    DECODE_IMPL(BrTable);
    DECODE_IMPL(Return);
    DECODE_IMPL(Unreachable);
    DECODE_IMPL(NopForTestingUnsupportedInLiftoff);
    DECODE_IMPL_CONST(I32Const);
    DECODE_IMPL_CONST(I64Const);
    DECODE_IMPL_CONST(F32Const);
    DECODE_IMPL_CONST(F64Const);
    DECODE_IMPL_CONST(RefNull);
    DECODE_IMPL(RefIsNull);
    DECODE_IMPL_CONST(RefFunc);
    DECODE_IMPL(RefAsNonNull);
    DECODE_IMPL(RefEq);
    DECODE_IMPL(LocalGet);
    DECODE_IMPL(LocalSet);
    DECODE_IMPL(LocalTee);
    DECODE_IMPL(Drop);
    DECODE_IMPL_CONST(GlobalGet);
    DECODE_IMPL(GlobalSet);
    DECODE_IMPL(TableGet);
    DECODE_IMPL(TableSet);
#define DECODE_LOAD_MEM(op, ...) DECODE_IMPL2(kExpr##op, LoadMem);
    FOREACH_LOAD_MEM_OPCODE(DECODE_LOAD_MEM)
#undef DECODE_LOAD_MEM
#define DECODE_STORE_MEM(op, ...) DECODE_IMPL2(kExpr##op, StoreMem);
    FOREACH_STORE_MEM_OPCODE(DECODE_STORE_MEM)
#undef DECODE_LOAD_MEM
    DECODE_IMPL(MemoryGrow);
    DECODE_IMPL(MemorySize);
    DECODE_IMPL(CallFunction);
    DECODE_IMPL(CallIndirect);
    DECODE_IMPL(ReturnCall);
    DECODE_IMPL(ReturnCallIndirect);
    DECODE_IMPL(CallRef);
    DECODE_IMPL(ReturnCallRef);
    DECODE_IMPL2(kNumericPrefix, Numeric);
    DECODE_IMPL_CONST2(kSimdPrefix, Simd);
    DECODE_IMPL2(kAtomicPrefix, Atomic);
    DECODE_IMPL_CONST2(kGCPrefix, GC);
#define SIMPLE_PROTOTYPE_CASE(name, ...) DECODE_IMPL(name);
    FOREACH_SIMPLE_PROTOTYPE_OPCODE(SIMPLE_PROTOTYPE_CASE)
#undef SIMPLE_PROTOTYPE_CASE
    return &WasmFullDecoder::DecodeUnknownOrAsmJs;
  }

#undef DECODE_IMPL
#undef DECODE_IMPL2

  OpcodeHandler GetOpcodeHandler(uint8_t opcode) {
    static constexpr std::array<OpcodeHandler, 256> kOpcodeHandlers =
        base::make_array<256>(GetOpcodeHandlerTableEntry);
    return kOpcodeHandlers[opcode];
  }

  void EndControl() {
    DCHECK(!control_.empty());
    Control* current = &control_.back();
    stack_.shrink_to(current->stack_depth);
    current->reachability = kUnreachable;
    current_code_reachable_and_ok_ = false;
  }

  template <typename func>
  V8_INLINE void InitMerge(Merge<Value>* merge, uint32_t arity, func get_val) {
    merge->arity = arity;
    if constexpr (std::is_null_pointer_v<func>) {
      DCHECK_EQ(0, arity);
    } else if (arity == 1) {
      merge->vals.first = get_val(0);
    } else if (arity > 1) {
      merge->vals.array = this->zone()->template AllocateArray<Value>(arity);
      for (uint32_t i = 0; i < arity; i++) {
        merge->vals.array[i] = get_val(i);
      }
    }
  }

  // In reachable code, check if there are at least {count} values on the stack.
  // In unreachable code, if there are less than {count} values on the stack,
  // insert a number of unreachable values underneath the current values equal
  // to the difference, and return that number.
  V8_INLINE int EnsureStackArguments(int count) {
    uint32_t limit = control_.back().stack_depth;
    if (V8_LIKELY(stack_.size() >= count + limit)) return 0;
    return EnsureStackArguments_Slow(count);
  }

  V8_NOINLINE V8_PRESERVE_MOST int EnsureStackArguments_Slow(int count) {
    uint32_t limit =
"""


```