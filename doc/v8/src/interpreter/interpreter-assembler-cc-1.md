Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/interpreter/interpreter-assembler.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core class:** The code is within the `InterpreterAssembler` class. This suggests the code is involved in the implementation of the V8 interpreter.

2. **Look for key methods and their actions:**  Scan the code for prominent methods and understand their purpose. Focus on methods that perform actions like calling builtins, manipulating bytecode, handling control flow, and interacting with the runtime.

3. **Group related functionalities:**  Notice patterns in the method names and their actions. For instance, `Construct*` methods are related to object construction, methods involving `InterruptBudget` deal with performance and interruption, and methods starting with `Jump*` handle control flow changes.

4. **Identify interactions with other V8 components:** Look for references to concepts like `Builtin`, `Runtime`, `FeedbackVector`, `Bytecode`, and `Context`. This helps understand how the `InterpreterAssembler` interacts with the broader V8 ecosystem.

5. **Pay attention to conditional compilation (`#ifndef V8_JITLESS`):**  Recognize that certain code sections are only active when JITless mode is *not* enabled. This indicates these parts are likely related to optimizations and feedback collection, which are less relevant in a purely interpreted scenario.

6. **Infer the role based on the code's behavior:** Based on the observed functionalities, deduce the overall role of `InterpreterAssembler`. It appears to be a helper class that simplifies the implementation of bytecode handlers within the interpreter. It provides abstractions for common interpreter tasks.

7. **Address specific user queries:** Go through the user's requests and see how they apply to the code:
    * **Functionality list:** Extract the key functionalities identified in step 2.
    * **Torque source:**  Confirm that the `.cc` extension means it's not a Torque file.
    * **JavaScript relationship:** Look for actions that directly correspond to JavaScript behavior, like object construction and function calls. Provide illustrative JavaScript examples.
    * **Code logic reasoning:** For methods with clear logic, provide hypothetical inputs and outputs. Focus on simple examples to illustrate the function's effect.
    * **Common programming errors:** Identify areas where developers using the interpreter's primitives might make mistakes. Focus on things like incorrect argument passing or misunderstanding the impact of certain operations.
    * **Overall function (for this part):**  Synthesize the findings into a concise summary of the code's role within the larger interpreter framework.

8. **Refine and structure the answer:** Organize the findings logically, using headings and bullet points for clarity. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. Connect the individual functionalities to the overall purpose of the code.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on individual low-level details. Realize that the user needs a higher-level understanding of the functionalities. Shift focus to the purpose and interactions of the methods.
* Notice that some code blocks are within conditional compilation. Acknowledge this distinction and explain why certain features might not be present in all builds.
*  When providing JavaScript examples, ensure they are clear and directly relate to the C++ code's actions. Avoid overly complex or ambiguous examples.
* For the input/output examples, start with very simple cases to demonstrate the core functionality before considering more complex scenarios (if necessary).
* Ensure the summary accurately reflects the content of the provided snippet and avoids making overly broad generalizations about the entire `interpreter-assembler.cc` file.

By following these steps and iteratively refining the understanding, I can construct a comprehensive and accurate answer to the user's request.
这是 `v8/src/interpreter/interpreter-assembler.cc` 文件的第二部分代码，主要集中在以下功能：

**核心功能归纳：**

这部分代码主要提供了 `InterpreterAssembler` 类中用于处理函数调用和构造器调用的汇编器指令，并且包含了对中断预算的管理、控制流跳转、以及与优化相关的逻辑（OSR - On-Stack Replacement）。

**详细功能列表：**

* **构造器调用 (Construct Calls):**
    * `Construct`:  处理使用 `new` 关键字的构造器调用。它会尝试快速构造路径，如果失败则回退到通用的构造逻辑。针对 `Array` 构造器有特殊处理，可能会收集分配站点的反馈信息。
    * `ConstructWithSpread`: 处理带有 spread 运算符的构造器调用。
    * `ConstructForwardAllArgs`: 处理使用 `.call` 或 `.apply` 转发所有参数的构造器调用。
    * 这些方法都涉及到收集反馈信息以进行后续的优化。

* **运行时函数调用 (Runtime Calls):**
    * `CallRuntimeN`:  允许调用 V8 的运行时函数。它根据 `function_id` 查找运行时函数的入口地址，并使用解释器 C 入口点进行调用。

* **中断预算管理 (Interrupt Budget Management):**
    * `UpdateInterruptBudget`: 更新函数的执行中断预算。
    * `DecreaseInterruptBudget`: 减少中断预算，并在预算耗尽时触发中断检查，可能导致栈检查或调用特定的运行时函数。这是 V8 用来防止无限循环和进行性能采样的机制。

* **控制流跳转 (Control Flow Jumps):**
    * `Advance`: 递增 bytecode 偏移量。
    * `JumpToOffset`: 无条件跳转到指定的 bytecode 偏移量。
    * `Jump`: 向前跳转指定的偏移量。
    * `JumpBackward`: 向后跳转指定的偏移量，并减少中断预算。
    * `JumpConditional`: 基于条件进行跳转。
    * `JumpConditionalByImmediateOperand`: 基于立即数操作数的值进行条件跳转。
    * `JumpConditionalByConstantOperand`: 基于常量池中的常量进行条件跳转。
    * `JumpIfTaggedEqual`, `JumpIfTaggedNotEqual`: 基于标签相等性进行条件跳转，有立即数和常量操作数版本。

* **字节码加载 (Bytecode Loading):**
    * `LoadBytecode`: 加载指定偏移量的字节码。
    * `LoadParameterCountWithoutReceiver`: 加载不包含接收者的参数数量。

* **优化相关 (Optimization Related):**
    * `StarDispatchLookahead`, `InlineShortStar`: 处理 `Star` 系列字节码，用于优化寄存器存储。
    * `Dispatch`, `DispatchToBytecodeWithOptionalStarLookahead`, `DispatchToBytecode`, `DispatchToBytecodeHandlerEntry`:  负责将控制流分发到下一个要执行的字节码处理程序。
    * `DispatchWide`: 处理带有 `WIDE` 或 `EXTRA_WIDE` 前缀的字节码。
    * `UpdateInterruptBudgetOnReturn`: 在函数返回时更新中断预算。
    * `LoadOsrState`: 加载 OSR (On-Stack Replacement) 状态。
    * `OnStackReplacement`: 处理栈上替换 (OSR) 的逻辑，判断是否以及如何触发优化编译 (Turbofan 或 Sparkplug)。

* **调试和断言 (Debugging and Assertions):**
    * `Abort`:  终止程序执行并输出错误信息。
    * `AbortIfWordNotEqual`: 如果两个 Word 值不相等则终止程序。
    * `AbortIfRegisterCountInvalid`: 检查寄存器数量是否有效。
    * `TraceBytecode`, `TraceBytecodeDispatch`: 用于跟踪字节码执行，仅在特定编译选项下生效。

* **寄存器文件操作 (Register File Operations for Generators):**
    * `ExportParametersAndRegisterFile`: 将参数和寄存器值导出到 FixedArray 中，用于生成器暂停时的状态保存。
    * `ImportRegisterFile`: 从 FixedArray 中导入寄存器值，用于生成器恢复执行时的状态恢复。

* **类型转换 (Type Conversion):**
    * `ToNumberOrNumeric`: 将累加器中的对象转换为数字或 Numeric 类型。

**是否为 Torque 源代码:**

根据描述，`v8/src/interpreter/interpreter-assembler.cc` 以 `.cc` 结尾，因此它不是一个 V8 Torque 源代码。Torque 源代码的文件名通常以 `.tq` 结尾。

**与 Javascript 功能的关系及 Javascript 示例:**

这部分代码直接关系到 Javascript 的函数调用和对象构造过程。

* **构造器调用 (`Construct`)**: 对应 Javascript 中使用 `new` 关键字创建对象：

```javascript
function MyClass(arg1, arg2) {
  this.property1 = arg1;
  this.property2 = arg2;
}

const myObject = new MyClass(10, "hello");
```
在 V8 的解释器中，执行 `new MyClass(10, "hello")` 时，会调用类似 `InterpreterAssembler::Construct` 的方法来处理对象创建的流程。

* **带有 Spread 的构造器调用 (`ConstructWithSpread`)**: 对应 Javascript 中使用 spread 运算符的构造函数调用：

```javascript
function AnotherClass(a, b, c) {
  this.propA = a;
  this.propB = b;
  this.propC = c;
}

const args = [1, 2];
const anotherObject = new AnotherClass(...args, 3);
```
`InterpreterAssembler::ConstructWithSpread` 会处理这种参数展开的情况。

* **运行时函数调用 (`CallRuntimeN`)**:  虽然开发者不能直接调用这些运行时函数，但 V8 内部会使用它们来实现某些 Javascript 的内置功能，例如：

```javascript
// 例如，JSON.stringify 可能会在内部调用某些 runtime 函数
const jsonString = JSON.stringify({ key: 'value' });
```

* **控制流跳转 (Jump 系列方法)**: 对应 Javascript 中的控制流语句，例如 `if`, `else`, `for`, `while` 等：

```javascript
let x = 5;
if (x > 0) {
  // ...
} else {
  // ...
}

for (let i = 0; i < 10; i++) {
  // ...
}
```
解释器会根据这些语句生成不同的字节码，并使用 `Jump` 等方法来改变执行流程。

**代码逻辑推理、假设输入与输出:**

以 `DecreaseInterruptBudget` 方法为例：

**假设输入:**
* `weight`:  一个正整数，表示要减少的中断预算量，例如 `Int32Constant(5)`.
* `stack_check_behavior`:  `kEnableStackCheck` 或 `kDisableStackCheck`.

**代码逻辑:**

1. 将 `weight` 加上当前字节码的大小。
2. 调用 `UpdateInterruptBudget` 从当前预算中减去计算后的权重。
3. 检查新的预算是否小于 0。
4. 如果小于 0，则根据 `stack_check_behavior` 调用相应的运行时函数进行中断处理（可能触发栈溢出检查）。

**假设输出:**

该方法的主要作用是副作用，即更新中断预算，并可能触发运行时调用。返回值是更新后的中断预算，但在此方法中没有直接使用。

**涉及用户常见的编程错误:**

虽然用户通常不会直接操作 `InterpreterAssembler` 的指令，但理解其背后的逻辑可以帮助理解一些常见的性能问题：

* **无限循环:**  `DecreaseInterruptBudget` 的机制就是为了防止无限循环导致程序卡死。如果用户编写了无限循环的 Javascript 代码，V8 的解释器会不断减少中断预算，最终触发中断处理。

```javascript
// 潜在的无限循环
function potentiallyInfinite() {
  let i = 0;
  while (true) {
    i++;
    // 如果没有退出条件，就会无限循环
  }
}
```

* **非常深的递归调用:**  虽然 `DecreaseInterruptBudget` 主要是为了防止无限 *循环*，但过深的递归调用也可能导致栈溢出，而栈溢出检查可能会在中断处理中发生。

```javascript
function recursiveFunction(n) {
  if (n > 0) {
    recursiveFunction(n - 1);
  }
}
recursiveFunction(100000); // 可能导致栈溢出
```

* **性能瓶颈:** 理解中断预算的机制可以帮助理解为什么某些看似简单的操作在解释器模式下可能会比较慢。频繁执行复杂或耗时的字节码会导致中断预算快速消耗，从而触发更多的中断处理。

**总结该部分的功能:**

总而言之，这部分 `InterpreterAssembler` 的代码是 V8 解释器中至关重要的一部分，它提供了构建和处理函数调用、构造器调用以及控制流跳转的基础指令。它还包含了用于性能监控和优化的机制，例如中断预算和栈上替换 (OSR)。理解这部分代码的功能有助于深入了解 V8 解释器的工作原理。

Prompt: 
```
这是目录为v8/src/interpreter/interpreter-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/interpreter-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
t);
  TVARIABLE(AllocationSite, var_site);
  Label return_result(this), try_fast_construct(this), construct_generic(this),
      construct_array(this, &var_site);

  TNode<Word32T> args_count = JSParameterCount(args.reg_count());
  // TODO(42200059): Propagate TaggedIndex usage.
  CollectConstructFeedback(context, target, new_target, maybe_feedback_vector,
                           IntPtrToTaggedIndex(Signed(slot_id)),
                           UpdateFeedbackMode::kOptionalFeedback,
                           &try_fast_construct, &construct_array, &var_site);

  BIND(&try_fast_construct);
  {
    Comment("call using FastConstruct builtin");
    GotoIf(TaggedIsSmi(target), &construct_generic);
    GotoIfNot(IsJSFunction(CAST(target)), &construct_generic);
    var_result =
        CallBuiltin(Builtin::kInterpreterPushArgsThenFastConstructFunction,
                    context, args_count, args.base_reg_location(), target,
                    new_target, UndefinedConstant());
    Goto(&return_result);
  }

  BIND(&construct_generic);
  {
    // TODO(bmeurer): Remove the generic type_info parameter from the Construct.
    Comment("call using Construct builtin");
    Builtin builtin = Builtins::InterpreterPushArgsThenConstruct(
        InterpreterPushArgsMode::kOther);
    var_result =
        CallBuiltin(builtin, context, args_count, args.base_reg_location(),
                    target, new_target, UndefinedConstant());
    Goto(&return_result);
  }

  BIND(&construct_array);
  {
    // TODO(bmeurer): Introduce a dedicated builtin to deal with the Array
    // constructor feedback collection inside of Ignition.
    Comment("call using ConstructArray builtin");
    Builtin builtin = Builtins::InterpreterPushArgsThenConstruct(
        InterpreterPushArgsMode::kArrayFunction);
    var_result =
        CallBuiltin(builtin, context, args_count, args.base_reg_location(),
                    target, new_target, var_site.value());
    Goto(&return_result);
  }

  BIND(&return_result);
  return var_result.value();
}

TNode<Object> InterpreterAssembler::ConstructWithSpread(
    TNode<Object> target, TNode<Context> context, TNode<Object> new_target,
    const RegListNodePair& args, TNode<UintPtrT> slot_id) {
  // TODO(bmeurer): Unify this with the Construct bytecode feedback
  // above once we have a way to pass the AllocationSite to the Array
  // constructor _and_ spread the last argument at the same time.
  DCHECK(Bytecodes::MakesCallAlongCriticalPath(bytecode_));

#ifndef V8_JITLESS
  // TODO(syg): Is the feedback collection logic here the same as
  // CollectConstructFeedback?
  Label extra_checks(this, Label::kDeferred), construct(this);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  GotoIf(IsUndefined(maybe_feedback_vector), &construct);
  TNode<FeedbackVector> feedback_vector = CAST(maybe_feedback_vector);

  // Increment the call count.
  IncrementCallCount(feedback_vector, slot_id);

  // Check if we have monomorphic {new_target} feedback already.
  TNode<HeapObjectReference> feedback =
      CAST(LoadFeedbackVectorSlot(feedback_vector, slot_id));
  Branch(IsWeakReferenceToObject(feedback, new_target), &construct,
         &extra_checks);

  BIND(&extra_checks);
  {
    Label check_initialized(this), initialize(this), mark_megamorphic(this);

    // Check if it is a megamorphic {new_target}.
    Comment("check if megamorphic");
    TNode<BoolT> is_megamorphic = TaggedEqual(
        feedback,
        HeapConstantNoHole(FeedbackVector::MegamorphicSentinel(isolate())));
    GotoIf(is_megamorphic, &construct);

    Comment("check if weak reference");
    GotoIfNot(IsWeakOrCleared(feedback), &check_initialized);

    // If the weak reference is cleared, we have a new chance to become
    // monomorphic.
    Comment("check if weak reference is cleared");
    Branch(IsCleared(feedback), &initialize, &mark_megamorphic);

    BIND(&check_initialized);
    {
      // Check if it is uninitialized.
      Comment("check if uninitialized");
      TNode<BoolT> is_uninitialized =
          TaggedEqual(feedback, UninitializedSymbolConstant());
      Branch(is_uninitialized, &initialize, &mark_megamorphic);
    }

    BIND(&initialize);
    {
      Comment("check if function in same native context");
      GotoIf(TaggedIsSmi(new_target), &mark_megamorphic);
      // Check if the {new_target} is a JSFunction or JSBoundFunction
      // in the current native context.
      TVARIABLE(HeapObject, var_current, CAST(new_target));
      Label loop(this, &var_current), done_loop(this);
      Goto(&loop);
      BIND(&loop);
      {
        Label if_boundfunction(this), if_function(this);
        TNode<HeapObject> current = var_current.value();
        TNode<Uint16T> current_instance_type = LoadInstanceType(current);
        GotoIf(InstanceTypeEqual(current_instance_type, JS_BOUND_FUNCTION_TYPE),
               &if_boundfunction);
        Branch(IsJSFunctionInstanceType(current_instance_type), &if_function,
               &mark_megamorphic);

        BIND(&if_function);
        {
          // Check that the JSFunction {current} is in the current native
          // context.
          TNode<Context> current_context =
              CAST(LoadObjectField(current, JSFunction::kContextOffset));
          TNode<NativeContext> current_native_context =
              LoadNativeContext(current_context);
          Branch(
              TaggedEqual(LoadNativeContext(context), current_native_context),
              &done_loop, &mark_megamorphic);
        }

        BIND(&if_boundfunction);
        {
          // Continue with the [[BoundTargetFunction]] of {current}.
          var_current = LoadObjectField<HeapObject>(
              current, JSBoundFunction::kBoundTargetFunctionOffset);
          Goto(&loop);
        }
      }
      BIND(&done_loop);
      StoreWeakReferenceInFeedbackVector(feedback_vector, slot_id,
                                         CAST(new_target));
      ReportFeedbackUpdate(feedback_vector, slot_id,
                           "ConstructWithSpread:Initialize");
      Goto(&construct);
    }

    BIND(&mark_megamorphic);
    {
      // MegamorphicSentinel is an immortal immovable object so
      // write-barrier is not needed.
      Comment("transition to megamorphic");
      DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kmegamorphic_symbol));
      StoreFeedbackVectorSlot(
          feedback_vector, slot_id,
          HeapConstantNoHole(FeedbackVector::MegamorphicSentinel(isolate())),
          SKIP_WRITE_BARRIER);
      ReportFeedbackUpdate(feedback_vector, slot_id,
                           "ConstructWithSpread:TransitionMegamorphic");
      Goto(&construct);
    }
  }

  BIND(&construct);
#endif  // !V8_JITLESS
  Comment("call using ConstructWithSpread builtin");
  Builtin builtin = Builtins::InterpreterPushArgsThenConstruct(
      InterpreterPushArgsMode::kWithFinalSpread);
  TNode<Word32T> args_count = JSParameterCount(args.reg_count());
  return CallBuiltin(builtin, context, args_count, args.base_reg_location(),
                     target, new_target, UndefinedConstant());
}

// TODO(v8:13249): Add a FastConstruct variant to avoid pushing arguments twice
// (once here, and once again in construct stub).
TNode<Object> InterpreterAssembler::ConstructForwardAllArgs(
    TNode<Object> target, TNode<Context> context, TNode<Object> new_target,
    TNode<TaggedIndex> slot_id) {
  DCHECK(Bytecodes::MakesCallAlongCriticalPath(bytecode_));
  TVARIABLE(Object, var_result);
  TVARIABLE(AllocationSite, var_site);

#ifndef V8_JITLESS
  Label construct(this);

  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  GotoIf(IsUndefined(maybe_feedback_vector), &construct);

  CollectConstructFeedback(context, target, new_target, maybe_feedback_vector,
                           slot_id, UpdateFeedbackMode::kOptionalFeedback,
                           &construct, &construct, &var_site);
  BIND(&construct);
#endif  // !V8_JITLESS

  return CallBuiltin(Builtin::kInterpreterForwardAllArgsThenConstruct, context,
                     target, new_target);
}

template <class T>
TNode<T> InterpreterAssembler::CallRuntimeN(TNode<Uint32T> function_id,
                                            TNode<Context> context,
                                            const RegListNodePair& args,
                                            int return_count) {
  DCHECK(Bytecodes::MakesCallAlongCriticalPath(bytecode_));
  DCHECK(Bytecodes::IsCallRuntime(bytecode_));

  // Get the function entry from the function id.
  TNode<RawPtrT> function_table = ReinterpretCast<RawPtrT>(ExternalConstant(
      ExternalReference::runtime_function_table_address(isolate())));
  TNode<Word32T> function_offset =
      Int32Mul(function_id, Int32Constant(sizeof(Runtime::Function)));
  TNode<WordT> function =
      IntPtrAdd(function_table, ChangeUint32ToWord(function_offset));
  TNode<RawPtrT> function_entry = Load<RawPtrT>(
      function, IntPtrConstant(offsetof(Runtime::Function, entry)));

  Builtin centry = Builtins::InterpreterCEntry(return_count);
  return CallBuiltin<T>(centry, context, args.reg_count(),
                        args.base_reg_location(), function_entry);
}

template V8_EXPORT_PRIVATE TNode<Object> InterpreterAssembler::CallRuntimeN(
    TNode<Uint32T> function_id, TNode<Context> context,
    const RegListNodePair& args, int return_count);
template V8_EXPORT_PRIVATE TNode<PairT<Object, Object>>
InterpreterAssembler::CallRuntimeN(TNode<Uint32T> function_id,
                                   TNode<Context> context,
                                   const RegListNodePair& args,
                                   int return_count);

TNode<Int32T> InterpreterAssembler::UpdateInterruptBudget(
    TNode<Int32T> weight) {
  TNode<JSFunction> function = LoadFunctionClosure();
  TNode<FeedbackCell> feedback_cell =
      LoadObjectField<FeedbackCell>(function, JSFunction::kFeedbackCellOffset);
  TNode<Int32T> old_budget = LoadObjectField<Int32T>(
      feedback_cell, FeedbackCell::kInterruptBudgetOffset);

  // Update budget by |weight| and check if it reaches zero.
  TNode<Int32T> new_budget = Int32Sub(old_budget, weight);
  // Update budget.
  StoreObjectFieldNoWriteBarrier(
      feedback_cell, FeedbackCell::kInterruptBudgetOffset, new_budget);
  return new_budget;
}

void InterpreterAssembler::DecreaseInterruptBudget(
    TNode<Int32T> weight, StackCheckBehavior stack_check_behavior) {
  Comment("[ DecreaseInterruptBudget");
  Label done(this), interrupt_check(this);

  // Assert that the weight is positive.
  CSA_DCHECK(this, Int32GreaterThanOrEqual(weight, Int32Constant(0)));

  // Make sure we include the current bytecode in the budget calculation.
  TNode<Int32T> weight_after_bytecode =
      Int32Add(weight, Int32Constant(CurrentBytecodeSize()));
  TNode<Int32T> new_budget = UpdateInterruptBudget(weight_after_bytecode);
  Branch(Int32GreaterThanOrEqual(new_budget, Int32Constant(0)), &done,
         &interrupt_check);

  BIND(&interrupt_check);
  TNode<JSFunction> function = LoadFunctionClosure();
  CallRuntime(stack_check_behavior == kEnableStackCheck
                  ? Runtime::kBytecodeBudgetInterruptWithStackCheck_Ignition
                  : Runtime::kBytecodeBudgetInterrupt_Ignition,
              GetContext(), function);
  Goto(&done);

  BIND(&done);

  Comment("] DecreaseInterruptBudget");
}

TNode<IntPtrT> InterpreterAssembler::Advance() {
  return Advance(CurrentBytecodeSize());
}

TNode<IntPtrT> InterpreterAssembler::Advance(int delta) {
  return Advance(IntPtrConstant(delta));
}

TNode<IntPtrT> InterpreterAssembler::Advance(TNode<IntPtrT> delta) {
  TNode<IntPtrT> next_offset = IntPtrAdd(BytecodeOffset(), delta);
  bytecode_offset_ = next_offset;
  return next_offset;
}

void InterpreterAssembler::JumpToOffset(TNode<IntPtrT> new_bytecode_offset) {
  DCHECK(!Bytecodes::IsStarLookahead(bytecode_, operand_scale_));
#ifdef V8_TRACE_UNOPTIMIZED
  TraceBytecode(Runtime::kTraceUnoptimizedBytecodeExit);
#endif
  bytecode_offset_ = new_bytecode_offset;
  TNode<RawPtrT> target_bytecode =
      UncheckedCast<RawPtrT>(LoadBytecode(new_bytecode_offset));
  DispatchToBytecode(target_bytecode, new_bytecode_offset);
}

void InterpreterAssembler::Jump(TNode<IntPtrT> jump_offset) {
  JumpToOffset(IntPtrAdd(BytecodeOffset(), jump_offset));
}

void InterpreterAssembler::JumpBackward(TNode<IntPtrT> jump_offset) {
  DecreaseInterruptBudget(TruncateIntPtrToInt32(jump_offset),
                          kEnableStackCheck);
  JumpToOffset(IntPtrSub(BytecodeOffset(), jump_offset));
}

void InterpreterAssembler::JumpConditional(TNode<BoolT> condition,
                                           TNode<IntPtrT> jump_offset) {
  Label match(this), no_match(this);

  Branch(condition, &match, &no_match);
  BIND(&match);
  Jump(jump_offset);
  BIND(&no_match);
  Dispatch();
}

void InterpreterAssembler::JumpConditionalByImmediateOperand(
    TNode<BoolT> condition, int operand_index) {
  Label match(this), no_match(this);

  Branch(condition, &match, &no_match);
  BIND(&match);
  TNode<IntPtrT> jump_offset = Signed(BytecodeOperandUImmWord(operand_index));
  Jump(jump_offset);
  BIND(&no_match);
  Dispatch();
}

void InterpreterAssembler::JumpConditionalByConstantOperand(
    TNode<BoolT> condition, int operand_index) {
  Label match(this), no_match(this);

  Branch(condition, &match, &no_match);
  BIND(&match);
  TNode<IntPtrT> jump_offset =
      LoadAndUntagConstantPoolEntryAtOperandIndex(operand_index);
  Jump(jump_offset);
  BIND(&no_match);
  Dispatch();
}

void InterpreterAssembler::JumpIfTaggedEqual(TNode<Object> lhs,
                                             TNode<Object> rhs,
                                             TNode<IntPtrT> jump_offset) {
  JumpConditional(TaggedEqual(lhs, rhs), jump_offset);
}

void InterpreterAssembler::JumpIfTaggedEqual(TNode<Object> lhs,
                                             TNode<Object> rhs,
                                             int operand_index) {
  JumpConditionalByImmediateOperand(TaggedEqual(lhs, rhs), operand_index);
}

void InterpreterAssembler::JumpIfTaggedEqualConstant(TNode<Object> lhs,
                                                     TNode<Object> rhs,
                                                     int operand_index) {
  JumpConditionalByConstantOperand(TaggedEqual(lhs, rhs), operand_index);
}

void InterpreterAssembler::JumpIfTaggedNotEqual(TNode<Object> lhs,
                                                TNode<Object> rhs,
                                                TNode<IntPtrT> jump_offset) {
  JumpConditional(TaggedNotEqual(lhs, rhs), jump_offset);
}

void InterpreterAssembler::JumpIfTaggedNotEqual(TNode<Object> lhs,
                                                TNode<Object> rhs,
                                                int operand_index) {
  JumpConditionalByImmediateOperand(TaggedNotEqual(lhs, rhs), operand_index);
}

void InterpreterAssembler::JumpIfTaggedNotEqualConstant(TNode<Object> lhs,
                                                        TNode<Object> rhs,
                                                        int operand_index) {
  JumpConditionalByConstantOperand(TaggedNotEqual(lhs, rhs), operand_index);
}

TNode<WordT> InterpreterAssembler::LoadBytecode(
    TNode<IntPtrT> bytecode_offset) {
  TNode<Uint8T> bytecode =
      Load<Uint8T>(BytecodeArrayTaggedPointer(), bytecode_offset);
  return ChangeUint32ToWord(bytecode);
}

TNode<IntPtrT> InterpreterAssembler::LoadParameterCountWithoutReceiver() {
  TNode<Int32T> parameter_count =
      LoadBytecodeArrayParameterCountWithoutReceiver(
          BytecodeArrayTaggedPointer());
  return ChangeInt32ToIntPtr(parameter_count);
}

void InterpreterAssembler::StarDispatchLookahead(TNode<WordT> target_bytecode) {
  Label do_inline_star(this), done(this);

  // Check whether the following opcode is one of the short Star codes. All
  // opcodes higher than the short Star variants are invalid, and invalid
  // opcodes are never deliberately written, so we can use a one-sided check.
  // This is no less secure than the normal-length Star handler, which performs
  // no validation on its operand.
  static_assert(static_cast<int>(Bytecode::kLastShortStar) + 1 ==
                static_cast<int>(Bytecode::kIllegal));
  static_assert(Bytecode::kIllegal == Bytecode::kLast);
  TNode<Int32T> first_short_star_bytecode =
      Int32Constant(static_cast<int>(Bytecode::kFirstShortStar));
  TNode<BoolT> is_star = Uint32GreaterThanOrEqual(
      TruncateWordToInt32(target_bytecode), first_short_star_bytecode);
  Branch(is_star, &do_inline_star, &done);

  BIND(&do_inline_star);
  {
    InlineShortStar(target_bytecode);

    // Rather than merging control flow to a single indirect jump, we can get
    // better branch prediction by duplicating it. This is because the
    // instruction following a merged X + StarN is a bad predictor of the
    // instruction following a non-merged X, and vice versa.
    DispatchToBytecode(LoadBytecode(BytecodeOffset()), BytecodeOffset());
  }
  BIND(&done);
}

void InterpreterAssembler::InlineShortStar(TNode<WordT> target_bytecode) {
  Bytecode previous_bytecode = bytecode_;
  ImplicitRegisterUse previous_acc_use = implicit_register_use_;

  // At this point we don't know statically what bytecode we're executing, but
  // kStar0 has the right attributes (namely, no operands) for any of the short
  // Star codes.
  bytecode_ = Bytecode::kStar0;
  implicit_register_use_ = ImplicitRegisterUse::kNone;

#ifdef V8_TRACE_UNOPTIMIZED
  TraceBytecode(Runtime::kTraceUnoptimizedBytecodeEntry);
#endif

  StoreRegisterForShortStar(GetAccumulator(), target_bytecode);

  DCHECK_EQ(implicit_register_use_,
            Bytecodes::GetImplicitRegisterUse(bytecode_));

  Advance();
  bytecode_ = previous_bytecode;
  implicit_register_use_ = previous_acc_use;
}

void InterpreterAssembler::Dispatch() {
  Comment("========= Dispatch");
  DCHECK_IMPLIES(Bytecodes::MakesCallAlongCriticalPath(bytecode_), made_call_);
  TNode<IntPtrT> target_offset = Advance();
  TNode<WordT> target_bytecode = LoadBytecode(target_offset);
  DispatchToBytecodeWithOptionalStarLookahead(target_bytecode);
}

void InterpreterAssembler::DispatchToBytecodeWithOptionalStarLookahead(
    TNode<WordT> target_bytecode) {
  if (Bytecodes::IsStarLookahead(bytecode_, operand_scale_)) {
    StarDispatchLookahead(target_bytecode);
  }
  DispatchToBytecode(target_bytecode, BytecodeOffset());
}

void InterpreterAssembler::DispatchToBytecode(
    TNode<WordT> target_bytecode, TNode<IntPtrT> new_bytecode_offset) {
  if (V8_IGNITION_DISPATCH_COUNTING_BOOL) {
    TraceBytecodeDispatch(target_bytecode);
  }

  TNode<RawPtrT> target_code_entry = Load<RawPtrT>(
      DispatchTablePointer(), TimesSystemPointerSize(target_bytecode));

  DispatchToBytecodeHandlerEntry(target_code_entry, new_bytecode_offset);
}

void InterpreterAssembler::DispatchToBytecodeHandlerEntry(
    TNode<RawPtrT> handler_entry, TNode<IntPtrT> bytecode_offset) {
  TailCallBytecodeDispatch(
      InterpreterDispatchDescriptor{}, handler_entry, GetAccumulatorUnchecked(),
      bytecode_offset, BytecodeArrayTaggedPointer(), DispatchTablePointer());
}

void InterpreterAssembler::DispatchWide(OperandScale operand_scale) {
  // Dispatching a wide bytecode requires treating the prefix
  // bytecode a base pointer into the dispatch table and dispatching
  // the bytecode that follows relative to this base.
  //
  //   Indices 0-255 correspond to bytecodes with operand_scale == 0
  //   Indices 256-511 correspond to bytecodes with operand_scale == 1
  //   Indices 512-767 correspond to bytecodes with operand_scale == 2
  DCHECK_IMPLIES(Bytecodes::MakesCallAlongCriticalPath(bytecode_), made_call_);
  TNode<IntPtrT> next_bytecode_offset = Advance(1);
  TNode<WordT> next_bytecode = LoadBytecode(next_bytecode_offset);

  if (V8_IGNITION_DISPATCH_COUNTING_BOOL) {
    TraceBytecodeDispatch(next_bytecode);
  }

  TNode<IntPtrT> base_index;
  switch (operand_scale) {
    case OperandScale::kDouble:
      base_index = IntPtrConstant(1 << kBitsPerByte);
      break;
    case OperandScale::kQuadruple:
      base_index = IntPtrConstant(2 << kBitsPerByte);
      break;
    default:
      UNREACHABLE();
  }
  TNode<WordT> target_index = IntPtrAdd(base_index, next_bytecode);
  TNode<RawPtrT> target_code_entry = Load<RawPtrT>(
      DispatchTablePointer(), TimesSystemPointerSize(target_index));

  DispatchToBytecodeHandlerEntry(target_code_entry, next_bytecode_offset);
}

void InterpreterAssembler::UpdateInterruptBudgetOnReturn() {
  // TODO(rmcilroy): Investigate whether it is worth supporting self
  // optimization of primitive functions like FullCodegen.

  // Update profiling count by the number of bytes between the end of the
  // current bytecode and the start of the first one, to simulate backedge to
  // start of function.
  //
  // With headers and current offset, the bytecode array layout looks like:
  //
  //           <---------- simulated backedge ----------
  // | header | first bytecode | .... | return bytecode |
  //  |<------ current offset ------->
  //  ^ tagged bytecode array pointer
  //
  // UpdateInterruptBudget already handles adding the bytecode size to the
  // length of the back-edge, so we just have to correct for the non-zero offset
  // of the first bytecode.

  TNode<Int32T> profiling_weight =
      Int32Sub(TruncateIntPtrToInt32(BytecodeOffset()),
               Int32Constant(kFirstBytecodeOffset));
  DecreaseInterruptBudget(profiling_weight, kDisableStackCheck);
}

TNode<Int8T> InterpreterAssembler::LoadOsrState(
    TNode<FeedbackVector> feedback_vector) {
  // We're loading an 8-bit field, mask it.
  return UncheckedCast<Int8T>(Word32And(
      LoadObjectField<Int8T>(feedback_vector, FeedbackVector::kOsrStateOffset),
      0xFF));
}

void InterpreterAssembler::Abort(AbortReason abort_reason) {
  TNode<Smi> abort_id = SmiConstant(abort_reason);
  CallRuntime(Runtime::kAbort, GetContext(), abort_id);
}

void InterpreterAssembler::AbortIfWordNotEqual(TNode<WordT> lhs,
                                               TNode<WordT> rhs,
                                               AbortReason abort_reason) {
  Label ok(this), abort(this, Label::kDeferred);
  Branch(WordEqual(lhs, rhs), &ok, &abort);

  BIND(&abort);
  Abort(abort_reason);
  Goto(&ok);

  BIND(&ok);
}

void InterpreterAssembler::OnStackReplacement(
    TNode<Context> context, TNode<FeedbackVector> feedback_vector,
    TNode<IntPtrT> relative_jump, TNode<Int32T> loop_depth,
    TNode<IntPtrT> feedback_slot, TNode<Int8T> osr_state,
    OnStackReplacementParams params) {
  // Three cases may cause us to attempt OSR, in the following order:
  //
  // 1) Presence of cached OSR Turbofan/Maglev code.
  // 2) Presence of cached OSR Sparkplug code.
  // 3) The OSR urgency exceeds the current loop depth - in that case, trigger
  //    a Turbofan OSR compilation.

  TVARIABLE(Object, maybe_target_code, SmiConstant(0));
  Label osr_to_opt(this), osr_to_sparkplug(this);

  // Case 1).
  {
    Label next(this);
    TNode<MaybeObject> maybe_cached_osr_code =
        LoadFeedbackVectorSlot(feedback_vector, feedback_slot);
    GotoIf(IsCleared(maybe_cached_osr_code), &next);
    maybe_target_code = GetHeapObjectAssumeWeak(maybe_cached_osr_code);

    // Is it marked_for_deoptimization? If yes, clear the slot.
    TNode<CodeWrapper> code_wrapper = CAST(maybe_target_code.value());
    maybe_target_code =
        LoadCodePointerFromObject(code_wrapper, CodeWrapper::kCodeOffset);
    GotoIfNot(IsMarkedForDeoptimization(CAST(maybe_target_code.value())),
              &osr_to_opt);
    StoreFeedbackVectorSlot(feedback_vector, Unsigned(feedback_slot),
                            ClearedValue(), UNSAFE_SKIP_WRITE_BARRIER);
    maybe_target_code = SmiConstant(0);

    Goto(&next);
    BIND(&next);
  }

  // Case 2).
  if (params == OnStackReplacementParams::kBaselineCodeIsCached) {
    Goto(&osr_to_sparkplug);
  } else {
    DCHECK_EQ(params, OnStackReplacementParams::kDefault);
    TNode<SharedFunctionInfo> sfi = LoadObjectField<SharedFunctionInfo>(
        LoadFunctionClosure(), JSFunction::kSharedFunctionInfoOffset);
    GotoIf(SharedFunctionInfoHasBaselineCode(sfi), &osr_to_sparkplug);

    // Case 3).
    {
      static_assert(FeedbackVector::OsrUrgencyBits::kShift == 0);
      TNode<Int32T> osr_urgency = Word32And(
          osr_state, Int32Constant(FeedbackVector::OsrUrgencyBits::kMask));
      GotoIf(Uint32LessThan(loop_depth, osr_urgency), &osr_to_opt);
      JumpBackward(relative_jump);
    }
  }

  BIND(&osr_to_opt);
  {
    TNode<Uint32T> length =
        LoadAndUntagBytecodeArrayLength(BytecodeArrayTaggedPointer());
    TNode<Uint32T> weight =
        Uint32Mul(length, Uint32Constant(v8_flags.osr_to_tierup));
    DecreaseInterruptBudget(Signed(weight), kDisableStackCheck);
    CallBuiltin(Builtin::kInterpreterOnStackReplacement, context,
                maybe_target_code.value());
    UpdateInterruptBudget(Int32Mul(Signed(weight), Int32Constant(-1)));
    JumpBackward(relative_jump);
  }

  BIND(&osr_to_sparkplug);
  {
    // We already compiled the baseline code, so we don't need to handle failed
    // compilation as in the Ignition -> Turbofan case. Therefore we can just
    // tailcall to the OSR builtin.
    SaveBytecodeOffset();
    TailCallBuiltin(Builtin::kInterpreterOnStackReplacement_ToBaseline,
                    context);
  }
}

void InterpreterAssembler::TraceBytecode(Runtime::FunctionId function_id) {
  CallRuntime(function_id, GetContext(), BytecodeArrayTaggedPointer(),
              SmiTag(BytecodeOffset()), GetAccumulatorUnchecked());
}

void InterpreterAssembler::TraceBytecodeDispatch(TNode<WordT> target_bytecode) {
  TNode<ExternalReference> counters_table = ExternalConstant(
      ExternalReference::interpreter_dispatch_counters(isolate()));
  TNode<IntPtrT> source_bytecode_table_index = IntPtrConstant(
      static_cast<int>(bytecode_) * (static_cast<int>(Bytecode::kLast) + 1));

  TNode<WordT> counter_offset = TimesSystemPointerSize(
      IntPtrAdd(source_bytecode_table_index, target_bytecode));
  TNode<IntPtrT> old_counter = Load<IntPtrT>(counters_table, counter_offset);

  Label counter_ok(this), counter_saturated(this, Label::kDeferred);

  TNode<BoolT> counter_reached_max = WordEqual(
      old_counter, IntPtrConstant(std::numeric_limits<uintptr_t>::max()));
  Branch(counter_reached_max, &counter_saturated, &counter_ok);

  BIND(&counter_ok);
  {
    TNode<IntPtrT> new_counter = IntPtrAdd(old_counter, IntPtrConstant(1));
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), counters_table,
                        counter_offset, new_counter);
    Goto(&counter_saturated);
  }

  BIND(&counter_saturated);
}

// static
bool InterpreterAssembler::TargetSupportsUnalignedAccess() {
#if V8_TARGET_ARCH_MIPS64 || V8_TARGET_ARCH_RISCV64 || V8_TARGET_ARCH_RISCV32
  return false;
#elif V8_TARGET_ARCH_IA32 || V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_S390X || \
    V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_ARM64 || V8_TARGET_ARCH_PPC64 ||  \
    V8_TARGET_ARCH_LOONG64
  return true;
#else
#error "Unknown Architecture"
#endif
}

void InterpreterAssembler::AbortIfRegisterCountInvalid(
    TNode<FixedArray> parameters_and_registers, TNode<IntPtrT> parameter_count,
    TNode<UintPtrT> register_count) {
  TNode<IntPtrT> array_size =
      LoadAndUntagFixedArrayBaseLength(parameters_and_registers);

  Label ok(this), abort(this, Label::kDeferred);
  Branch(UintPtrLessThanOrEqual(IntPtrAdd(parameter_count, register_count),
                                array_size),
         &ok, &abort);

  BIND(&abort);
  Abort(AbortReason::kInvalidParametersAndRegistersInGenerator);
  Goto(&ok);

  BIND(&ok);
}

TNode<FixedArray> InterpreterAssembler::ExportParametersAndRegisterFile(
    TNode<FixedArray> array, const RegListNodePair& registers) {
  // Store the formal parameters (without receiver) followed by the
  // registers into the generator's internal parameters_and_registers field.
  TNode<IntPtrT> parameter_count = LoadParameterCountWithoutReceiver();
  TNode<UintPtrT> register_count = ChangeUint32ToWord(registers.reg_count());
  if (v8_flags.debug_code) {
    CSA_DCHECK(this, IntPtrEqual(registers.base_reg_location(),
                                 RegisterLocation(Register(0))));
    AbortIfRegisterCountInvalid(array, parameter_count, register_count);
  }

  {
    TVARIABLE(IntPtrT, var_index);
    var_index = IntPtrConstant(0);

    // Iterate over parameters and write them into the array.
    Label loop(this, &var_index), done_loop(this);

    TNode<IntPtrT> reg_base =
        IntPtrConstant(Register::FromParameterIndex(0).ToOperand() + 1);

    Goto(&loop);
    BIND(&loop);
    {
      TNode<IntPtrT> index = var_index.value();
      GotoIfNot(UintPtrLessThan(index, parameter_count), &done_loop);

      TNode<IntPtrT> reg_index = IntPtrAdd(reg_base, index);
      TNode<Object> value = LoadRegister(reg_index);

      StoreFixedArrayElement(array, index, value);

      var_index = IntPtrAdd(index, IntPtrConstant(1));
      Goto(&loop);
    }
    BIND(&done_loop);
  }

  {
    // Iterate over register file and write values into array.
    // The mapping of register to array index must match that used in
    // BytecodeGraphBuilder::VisitResumeGenerator.
    TVARIABLE(IntPtrT, var_index);
    var_index = IntPtrConstant(0);

    Label loop(this, &var_index), done_loop(this);
    Goto(&loop);
    BIND(&loop);
    {
      TNode<IntPtrT> index = var_index.value();
      GotoIfNot(UintPtrLessThan(index, register_count), &done_loop);

      TNode<IntPtrT> reg_index =
          IntPtrSub(IntPtrConstant(Register(0).ToOperand()), index);
      TNode<Object> value = LoadRegister(reg_index);

      TNode<IntPtrT> array_index = IntPtrAdd(parameter_count, index);
      StoreFixedArrayElement(array, array_index, value);

      var_index = IntPtrAdd(index, IntPtrConstant(1));
      Goto(&loop);
    }
    BIND(&done_loop);
  }

  return array;
}

TNode<FixedArray> InterpreterAssembler::ImportRegisterFile(
    TNode<FixedArray> array, const RegListNodePair& registers) {
  TNode<IntPtrT> parameter_count = LoadParameterCountWithoutReceiver();
  TNode<UintPtrT> register_count = ChangeUint32ToWord(registers.reg_count());
  if (v8_flags.debug_code) {
    CSA_DCHECK(this, IntPtrEqual(registers.base_reg_location(),
                                 RegisterLocation(Register(0))));
    AbortIfRegisterCountInvalid(array, parameter_count, register_count);
  }

  TVARIABLE(IntPtrT, var_index, IntPtrConstant(0));

  // Iterate over array and write values into register file.  Also erase the
  // array contents to not keep them alive artificially.
  Label loop(this, &var_index), done_loop(this);
  Goto(&loop);
  BIND(&loop);
  {
    TNode<IntPtrT> index = var_index.value();
    GotoIfNot(UintPtrLessThan(index, register_count), &done_loop);

    TNode<IntPtrT> array_index = IntPtrAdd(parameter_count, index);
    TNode<Object> value = LoadFixedArrayElement(array, array_index);

    TNode<IntPtrT> reg_index =
        IntPtrSub(IntPtrConstant(Register(0).ToOperand()), index);
    StoreRegister(value, reg_index);

    StoreFixedArrayElement(array, array_index, StaleRegisterConstant());

    var_index = IntPtrAdd(index, IntPtrConstant(1));
    Goto(&loop);
  }
  BIND(&done_loop);

  return array;
}

int InterpreterAssembler::CurrentBytecodeSize() const {
  return Bytecodes::Size(bytecode_, operand_scale_);
}

void InterpreterAssembler::ToNumberOrNumeric(Object::Conversion mode) {
  TNode<Object> object = GetAccumulator();
  TNode<Context> context = GetContext();

  TVARIABLE(Smi, var_type_feedback);
  TVARIABLE(Numeric, var_result);
  Label if_done(this), if_objectissmi(this), if_objectisheapnumber(this),
      if_objectisother(this, Label::kDeferred);

  GotoIf(TaggedIsSmi(object), &if_objectissmi);
  Branch(IsHeapNumber(CAST(object)), &if_objectisheapnumber, &if_objectisother);

  BIND(&if_objectissmi);
  {
    var_result = CAST(object);
    var_type_feedback = SmiConstant(BinaryOperationFeedback::kSignedSmall);
    Goto(&if_done);
  }

  BIND(&if_objectisheapnumber);
  {
    var_result = CAST(object);
    var_type_feedback = SmiConstant(BinaryOperationFeedback::kNumber);
    Goto(&if_done);
  }

  BIND(&if_objectisother);
  {
    auto builtin = Builtin::kNonNumberToNumber;
    if (mode == Object::Conversion::kToNumeric) {
      builtin = Builtin::kNonNumberToNumeric;
      // Special case for collecting BigInt feedback.
      Label not_bigint(this);
      GotoIfNot(IsBigInt(CAST(object)), &not_bigint);
      {
        var_result = CAST(object);
        var_t
"""


```