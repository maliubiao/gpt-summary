Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the second part of a larger file.

My plan is to:
1. **Continue the analysis** from the previous part, identifying the purpose of each method in this section.
2. **Identify relationships** between the methods and their overall contribution to bytecode generation.
3. **Address the specific questions** in the prompt: .tq extension, JavaScript relationship with examples, code logic reasoning with examples, common programming errors, and a general summary.
这是v8源代码文件`v8/src/interpreter/bytecode-array-builder.cc`的第二部分，延续了第一部分的功能，主要负责构建V8 JavaScript引擎的字节码数组。它提供了一系列的接口方法，用于生成各种字节码指令，这些指令最终会被V8的解释器执行。

**归纳一下它的功能：**

这部分代码继续构建字节码数组，提供了用于生成更多特定类型字节码指令的方法，这些指令主要围绕以下几个方面：

1. **对象操作：**  包括设置和定义对象的属性（包括普通属性和键值属性），以及处理类字段的初始化。
2. **作用域和上下文管理：**  创建不同类型的上下文（块级、catch、函数、eval、with），以及处理上下文的压栈和出栈。
3. **字面量创建：**  创建闭包、正则表达式字面量、数组字面量（包括空数组和包含元素的数组）、对象字面量（包括空对象）。
4. **类型转换：**  将值转换为对象、名称、字符串、布尔值和数字。
5. **控制流：**  定义标签、绑定标签、标记异常处理器（try/catch）、执行各种类型的跳转（无条件跳转、条件跳转基于布尔值、null、undefined、JSReceiver等）、以及循环跳转。
6. **异常处理：**  抛出和重新抛出异常，以及特定的引用错误。
7. **调试：**  生成调试器断点指令。
8. **代码覆盖率：**  递增代码块计数器。
9. **For-In 循环：**  支持 `for...in` 循环的字节码生成。
10. **模块变量：**  加载和存储模块级别的变量。
11. **生成器：**  支持生成器函数的暂停和恢复操作。
12. **函数调用：**  生成不同类型的函数调用指令，包括普通函数调用、接收者为 undefined 的调用、接收者任意的调用、带扩展运算符的调用。
13. **构造函数调用：** 生成 `new` 运算符的调用指令，包括带扩展运算符的情况。
14. **运行时调用：**  调用内置的运行时函数和JSRuntime函数。
15. **删除属性：**  生成删除对象属性的指令。
16. **常量池管理：**  获取常量池条目的索引。
17. **跳转表管理：**  分配和绑定跳转表条目，用于 `switch` 语句等。
18. **寄存器管理：**  对寄存器的有效性进行检查，并提供方法获取输入和输出寄存器的操作数表示。
19. **源码位置信息：**  记录函数开始的源码位置。

**如果`v8/src/interpreter/bytecode-array-builder.cc`以`.tq`结尾，那它是个v8 torque源代码。**

但正如你提供的文件内容所示，它以 `.cc` 结尾，所以它是一个 **C++** 源代码文件，而不是 Torque 文件。 Torque 文件通常用于定义 V8 内部的内置函数和类型操作。

**如果它与javascript的功能有关系，请用javascript举例说明:**

是的，`BytecodeArrayBuilder` 的每一个方法几乎都直接对应着 JavaScript 的某种语法结构或操作。以下是一些例子：

* **`DefineKeyedOwnProperty(object, key, flags, feedback_slot)`:** 对应 JavaScript 中定义对象的键值属性，例如：
  ```javascript
  const obj = {};
  const myKey = 'name';
  obj[myKey] = 'value';
  Object.defineProperty(obj, 'age', { value: 30, enumerable: true });
  ```

* **`CreateClosure(shared_function_info_entry, slot, flags)`:** 对应 JavaScript 中创建闭包，例如：
  ```javascript
  function outer() {
    const name = 'outer';
    function inner() {
      console.log(name); // inner 函数闭包了 outer 函数的 name 变量
    }
    return inner;
  }
  const closure = outer();
  ```

* **`CreateBlockContext(scope)`:** 对应 JavaScript 中创建块级作用域，例如：
  ```javascript
  {
    const blockVar = 'inside block';
    console.log(blockVar);
  }
  // console.log(blockVar); // 报错，blockVar 不在外部作用域
  ```

* **`CallProperty(callable, args, feedback_slot)`:** 对应 JavaScript 中调用对象的方法或访问属性（如果 getter 是函数），例如：
  ```javascript
  const obj = {
    greet(name) {
      console.log(`Hello, ${name}!`);
    }
  };
  obj.greet('World');
  ```

* **`Construct(constructor, args, feedback_slot_id)`:** 对应 JavaScript 中的 `new` 运算符，例如：
  ```javascript
  class MyClass {
    constructor(value) {
      this.value = value;
    }
  }
  const instance = new MyClass(10);
  ```

* **`Throw()`:** 对应 JavaScript 中的 `throw` 语句，例如：
  ```javascript
  function mightThrow() {
    throw new Error('Something went wrong!');
  }
  ```

* **`Return()`:** 对应 JavaScript 中的 `return` 语句，例如：
  ```javascript
  function add(a, b) {
    return a + b;
  }
  ```

**如果有代码逻辑推理，请给出假设输入与输出：**

以 `SetNamedProperty(object, name_index, feedback_slot, language_mode)` 为例：

**假设输入：**

* `object`: 一个表示对象的寄存器，假设为 `r1`。
* `name_index`: 常量池中属性名称的索引，假设为 `5`，常量池中索引 5 的条目是字符串 `"propertyName"`。
* `feedback_slot`: 反馈向量的槽位，假设为 `10`。
* `language_mode`: 语言模式，假设为 `LanguageMode::kStrict`。

**推断的字节码指令：**

根据 `language_mode` 的值，会调用不同的输出方法。由于是 `kStrict`，会调用 `OutputStaNamedPropertyStrict(r1, 5, 10)`。

**可能的字节码输出（简化表示）：**

`StaNamedPropertyStrict r1, [ConstantPool[5]], [FeedbackVectorSlot[10]]`

这条字节码指令的含义是：将累加器中的值存储到寄存器 `r1` 所指向的对象的名为 `"propertyName"` 的属性中，并使用反馈向量的第 10 个槽位进行优化。由于这是一个 `Set` 操作，之前很可能有一个 `Lda` 指令将要设置的值加载到了累加器中。

**如果涉及用户常见的编程错误，请举例说明：**

`BytecodeArrayBuilder` 本身是 V8 内部的组件，开发者不会直接编写这里的代码。然而，它生成的字节码指令是为了执行 JavaScript 代码，所以它可以帮助我们理解一些常见的 JavaScript 编程错误是如何在底层被处理的。

例如，考虑以下 JavaScript 代码：

```javascript
function foo(obj) {
  obj.nonExistentProperty = 10; // 尝试设置一个不存在的属性
}

const myObj = {};
foo(myObj);
console.log(myObj.nonExistentProperty); // 输出 10
```

当执行 `obj.nonExistentProperty = 10;` 时，`BytecodeArrayBuilder` 会生成类似 `StaNamedProperty` 的字节码。如果对象 `obj` 没有这个属性，V8 的解释器会根据对象的类型和属性的描述符来决定如何处理（例如，添加一个新属性）。

一个更明显的编程错误场景是 `TypeError`，例如尝试调用一个非函数的值：

```javascript
const notAFunction = 10;
notAFunction(); // TypeError: notAFunction is not a function
```

当执行 `notAFunction()` 时，`BytecodeArrayBuilder` 会生成函数调用相关的字节码。在执行时，V8 会检查 `notAFunction` 是否可调用，如果不是，则会抛出一个 `TypeError`。`BytecodeArrayBuilder` 中可能存在与生成抛出这种类型错误的字节码相关的逻辑，例如 `Throw()` 方法。

总而言之，`BytecodeArrayBuilder` 的功能是至关重要的，它将高级的 JavaScript 代码转换为 V8 解释器可以理解和执行的低级字节码指令。理解它的功能有助于深入了解 JavaScript 代码的执行过程和 V8 引擎的内部工作机制。

### 提示词
```
这是目录为v8/src/interpreter/bytecode-array-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/bytecode-array-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
language_mode);
  OutputSetKeyedProperty(object, key, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::DefineKeyedOwnProperty(
    Register object, Register key, DefineKeyedOwnPropertyFlags flags,
    int feedback_slot) {
  // Ensure that the IC uses a strict language mode, as this is the only
  // supported mode for this use case.
  DCHECK_EQ(GetLanguageModeFromSlotKind(feedback_vector_spec()->GetKind(
                FeedbackVector::ToSlot(feedback_slot))),
            LanguageMode::kStrict);
  OutputDefineKeyedOwnProperty(object, key, flags, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreInArrayLiteral(
    Register array, Register index, int feedback_slot) {
  OutputStaInArrayLiteral(array, index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreClassFieldsInitializer(
    Register constructor, int feedback_slot) {
  size_t name_index = ClassFieldsSymbolConstantPoolEntry();
  return SetNamedProperty(constructor, name_index, feedback_slot,
                          LanguageMode::kStrict);
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadClassFieldsInitializer(
    Register constructor, int feedback_slot) {
  size_t name_index = ClassFieldsSymbolConstantPoolEntry();
  OutputGetNamedProperty(constructor, name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateClosure(
    size_t shared_function_info_entry, int slot, int flags) {
  OutputCreateClosure(shared_function_info_entry, slot, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateBlockContext(
    const Scope* scope) {
  size_t entry = GetConstantPoolEntry(scope);
  OutputCreateBlockContext(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateCatchContext(
    Register exception, const Scope* scope) {
  size_t scope_index = GetConstantPoolEntry(scope);
  OutputCreateCatchContext(exception, scope_index);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateFunctionContext(
    const Scope* scope, int slots) {
  size_t scope_index = GetConstantPoolEntry(scope);
  OutputCreateFunctionContext(scope_index, slots);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateEvalContext(
    const Scope* scope, int slots) {
  size_t scope_index = GetConstantPoolEntry(scope);
  OutputCreateEvalContext(scope_index, slots);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateWithContext(
    Register object, const Scope* scope) {
  size_t scope_index = GetConstantPoolEntry(scope);
  OutputCreateWithContext(object, scope_index);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateArguments(
    CreateArgumentsType type) {
  switch (type) {
    case CreateArgumentsType::kMappedArguments:
      OutputCreateMappedArguments();
      break;
    case CreateArgumentsType::kUnmappedArguments:
      OutputCreateUnmappedArguments();
      break;
    case CreateArgumentsType::kRestParameter:
      OutputCreateRestParameter();
      break;
    default:
      UNREACHABLE();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateRegExpLiteral(
    const AstRawString* pattern, int literal_index, int flags) {
  size_t pattern_entry = GetConstantPoolEntry(pattern);
  OutputCreateRegExpLiteral(pattern_entry, literal_index, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateEmptyArrayLiteral(
    int literal_index) {
  OutputCreateEmptyArrayLiteral(literal_index);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateArrayLiteral(
    size_t constant_elements_entry, int literal_index, int flags) {
  OutputCreateArrayLiteral(constant_elements_entry, literal_index, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateArrayFromIterable() {
  OutputCreateArrayFromIterable();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateObjectLiteral(
    size_t constant_properties_entry, int literal_index, int flags) {
  OutputCreateObjectLiteral(constant_properties_entry, literal_index, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateEmptyObjectLiteral() {
  OutputCreateEmptyObjectLiteral();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CloneObject(Register source,
                                                        int flags,
                                                        int feedback_slot) {
  OutputCloneObject(source, flags, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::GetTemplateObject(
    size_t template_object_description_entry, int feedback_slot) {
  OutputGetTemplateObject(template_object_description_entry, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::PushContext(Register context) {
  OutputPushContext(context);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::PopContext(Register context) {
  OutputPopContext(context);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToObject(Register out) {
  OutputToObject(out);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToName() {
  OutputToName();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToString() {
  OutputToString();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToBoolean(ToBooleanMode mode) {
  if (mode == ToBooleanMode::kAlreadyBoolean) {
    // No-op, the accumulator is already a boolean and ToBoolean both reads and
    // writes the accumulator.
  } else {
    DCHECK_EQ(mode, ToBooleanMode::kConvertToBoolean);
    OutputToBoolean();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToNumber(int feedback_slot) {
  OutputToNumber(feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToNumeric(int feedback_slot) {
  OutputToNumeric(feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Bind(BytecodeLabel* label) {
  // Don't generate code for a label which hasn't had a corresponding forward
  // jump generated already. For backwards jumps, use BindLoopHeader.
  if (!label->has_referrer_jump()) return *this;

  // Flush the register optimizer when binding a label to ensure all
  // expected registers are valid when jumping to this label.
  if (register_optimizer_) {
    register_optimizer_->Flush();
    register_optimizer_->ResetTypeHintForAccumulator();
  }
  bytecode_array_writer_.BindLabel(label);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Bind(
    BytecodeLoopHeader* loop_header) {
  // Flush the register optimizer when starting a loop to ensure all expected
  // registers are valid when jumping to the loop header.
  if (register_optimizer_) {
    register_optimizer_->Flush();
    register_optimizer_->ResetTypeHintForAccumulator();
  }
  bytecode_array_writer_.BindLoopHeader(loop_header);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Bind(BytecodeJumpTable* jump_table,
                                                 int case_value) {
  // Flush the register optimizer when binding a jump table entry to ensure
  // all expected registers are valid when jumping to this location.
  if (register_optimizer_) {
    register_optimizer_->Flush();
    register_optimizer_->ResetTypeHintForAccumulator();
  }
  bytecode_array_writer_.BindJumpTableEntry(jump_table, case_value);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::MarkHandler(
    int handler_id, HandlerTable::CatchPrediction catch_prediction) {
  // The handler starts a new basic block, and any reasonable try block won't
  // let control fall through into it.
  DCHECK_IMPLIES(register_optimizer_,
                 register_optimizer_->EnsureAllRegistersAreFlushed());
  DCHECK_IMPLIES(register_optimizer_,
                 register_optimizer_->IsAccumulatorReset());
  bytecode_array_writer_.BindHandlerTarget(handler_table_builder(), handler_id);
  handler_table_builder()->SetPrediction(handler_id, catch_prediction);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::MarkTryBegin(int handler_id,
                                                         Register context) {
  // Flush registers to make sure everything visible to the handler is
  // materialized.
  if (register_optimizer_) register_optimizer_->Flush();
  bytecode_array_writer_.BindTryRegionStart(handler_table_builder(),
                                            handler_id);
  handler_table_builder()->SetContextRegister(handler_id, context);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::MarkTryEnd(int handler_id) {
  if (register_optimizer_) {
    register_optimizer_->ResetTypeHintForAccumulator();
  }
  bytecode_array_writer_.BindTryRegionEnd(handler_table_builder(), handler_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Jump(BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJump(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfTrue(ToBooleanMode mode,
                                                       BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  if (mode == ToBooleanMode::kAlreadyBoolean) {
    OutputJumpIfTrue(label, 0);
  } else {
    DCHECK_EQ(mode, ToBooleanMode::kConvertToBoolean);
    OutputJumpIfToBooleanTrue(label, 0);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfFalse(ToBooleanMode mode,
                                                        BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  if (mode == ToBooleanMode::kAlreadyBoolean) {
    OutputJumpIfFalse(label, 0);
  } else {
    DCHECK_EQ(mode, ToBooleanMode::kConvertToBoolean);
    OutputJumpIfToBooleanFalse(label, 0);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNull(BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfNull(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNotNull(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfNotNull(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfUndefined(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfUndefined(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfUndefinedOrNull(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfUndefinedOrNull(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNotUndefined(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfNotUndefined(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNil(BytecodeLabel* label,
                                                      Token::Value op,
                                                      NilValue nil) {
  if (op == Token::kEq) {
    // TODO(rmcilroy): Implement JumpIfUndetectable.
    return CompareUndetectable().JumpIfTrue(ToBooleanMode::kAlreadyBoolean,
                                            label);
  } else {
    DCHECK_EQ(Token::kEqStrict, op);
    if (nil == kUndefinedValue) {
      return JumpIfUndefined(label);
    } else {
      DCHECK_EQ(kNullValue, nil);
      return JumpIfNull(label);
    }
  }
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNotNil(BytecodeLabel* label,
                                                         Token::Value op,
                                                         NilValue nil) {
  if (op == Token::kEq) {
    // TODO(rmcilroy): Implement JumpIfUndetectable.
    return CompareUndetectable().JumpIfFalse(ToBooleanMode::kAlreadyBoolean,
                                             label);
  } else {
    DCHECK_EQ(Token::kEqStrict, op);
    if (nil == kUndefinedValue) {
      return JumpIfNotUndefined(label);
    } else {
      DCHECK_EQ(kNullValue, nil);
      return JumpIfNotNull(label);
    }
  }
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfJSReceiver(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfJSReceiver(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfForInDone(
    BytecodeLabel* label, Register index, Register cache_length) {
  DCHECK(!label->is_bound());
  OutputJumpIfForInDone(label, 0, index, cache_length);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpLoop(
    BytecodeLoopHeader* loop_header, int loop_depth, int position,
    int feedback_slot) {
  if (position != kNoSourcePosition) {
    // We need to attach a non-breakable source position to JumpLoop for its
    // implicit stack check, so we simply add it as expression position. There
    // can be a prior statement position from constructs like:
    //
    //    do var x;  while (false);
    //
    // A Nop could be inserted for empty statements, but since no code
    // is associated with these positions, instead we force the jump loop's
    // expression position which eliminates the empty statement's position.
    latest_source_info_.ForceExpressionPosition(position);
  }
  OutputJumpLoop(loop_header, loop_depth, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SwitchOnSmiNoFeedback(
    BytecodeJumpTable* jump_table) {
  OutputSwitchOnSmiNoFeedback(jump_table);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SetPendingMessage() {
  OutputSetPendingMessage();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Throw() {
  OutputThrow();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ReThrow() {
  OutputReThrow();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Abort(AbortReason reason) {
  DCHECK_LT(reason, AbortReason::kLastErrorMessage);
  DCHECK_GE(reason, AbortReason::kNoReason);
  OutputAbort(static_cast<int>(reason));
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Return() {
  OutputReturn();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ThrowReferenceErrorIfHole(
    const AstRawString* name) {
  size_t entry = GetConstantPoolEntry(name);
  OutputThrowReferenceErrorIfHole(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ThrowSuperNotCalledIfHole() {
  OutputThrowSuperNotCalledIfHole();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ThrowSuperAlreadyCalledIfNotHole() {
  OutputThrowSuperAlreadyCalledIfNotHole();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ThrowIfNotSuperConstructor(
    Register constructor) {
  OutputThrowIfNotSuperConstructor(constructor);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Debugger() {
  OutputDebugger();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::IncBlockCounter(
    int coverage_array_slot) {
  OutputIncBlockCounter(coverage_array_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ForInEnumerate(Register receiver) {
  OutputForInEnumerate(receiver);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ForInPrepare(
    RegisterList cache_info_triple, int feedback_slot) {
  DCHECK_EQ(3, cache_info_triple.register_count());
  OutputForInPrepare(cache_info_triple, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ForInNext(
    Register receiver, Register index, RegisterList cache_type_array_pair,
    int feedback_slot) {
  DCHECK_EQ(2, cache_type_array_pair.register_count());
  OutputForInNext(receiver, index, cache_type_array_pair, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ForInStep(Register index) {
  OutputForInStep(index);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreModuleVariable(int cell_index,
                                                                int depth) {
  OutputStaModuleVariable(cell_index, depth);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadModuleVariable(int cell_index,
                                                               int depth) {
  OutputLdaModuleVariable(cell_index, depth);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SuspendGenerator(
    Register generator, RegisterList registers, int suspend_id) {
  OutputSuspendGenerator(generator, registers, registers.register_count(),
                         suspend_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SwitchOnGeneratorState(
    Register generator, BytecodeJumpTable* jump_table) {
  DCHECK_EQ(jump_table->case_value_base(), 0);
  BytecodeNode node(CreateSwitchOnGeneratorStateNode(
      generator, jump_table->constant_pool_index(), jump_table->size()));
  WriteSwitch(&node, jump_table);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ResumeGenerator(
    Register generator, RegisterList registers) {
  OutputResumeGenerator(generator, registers, registers.register_count());
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallProperty(Register callable,
                                                         RegisterList args,
                                                         int feedback_slot) {
  if (args.register_count() == 1) {
    OutputCallProperty0(callable, args[0], feedback_slot);
  } else if (args.register_count() == 2) {
    OutputCallProperty1(callable, args[0], args[1], feedback_slot);
  } else if (args.register_count() == 3) {
    OutputCallProperty2(callable, args[0], args[1], args[2], feedback_slot);
  } else {
    OutputCallProperty(callable, args, args.register_count(), feedback_slot);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallUndefinedReceiver(
    Register callable, RegisterList args, int feedback_slot) {
  if (args.register_count() == 0) {
    OutputCallUndefinedReceiver0(callable, feedback_slot);
  } else if (args.register_count() == 1) {
    OutputCallUndefinedReceiver1(callable, args[0], feedback_slot);
  } else if (args.register_count() == 2) {
    OutputCallUndefinedReceiver2(callable, args[0], args[1], feedback_slot);
  } else {
    OutputCallUndefinedReceiver(callable, args, args.register_count(),
                                feedback_slot);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallAnyReceiver(Register callable,
                                                            RegisterList args,
                                                            int feedback_slot) {
  OutputCallAnyReceiver(callable, args, args.register_count(), feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallWithSpread(Register callable,
                                                           RegisterList args,
                                                           int feedback_slot) {
  OutputCallWithSpread(callable, args, args.register_count(), feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Construct(Register constructor,
                                                      RegisterList args,
                                                      int feedback_slot_id) {
  OutputConstruct(constructor, args, args.register_count(), feedback_slot_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ConstructWithSpread(
    Register constructor, RegisterList args, int feedback_slot_id) {
  OutputConstructWithSpread(constructor, args, args.register_count(),
                            feedback_slot_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ConstructForwardAllArgs(
    Register constructor, int feedback_slot_id) {
  OutputConstructForwardAllArgs(constructor, feedback_slot_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntime(
    Runtime::FunctionId function_id, RegisterList args) {
  DCHECK_EQ(1, Runtime::FunctionForId(function_id)->result_size);
  DCHECK_LE(Bytecodes::SizeForUnsignedOperand(function_id),
            OperandSize::kShort);
  if (IntrinsicsHelper::IsSupported(function_id)) {
    IntrinsicsHelper::IntrinsicId intrinsic_id =
        IntrinsicsHelper::FromRuntimeId(function_id);
    OutputInvokeIntrinsic(static_cast<int>(intrinsic_id), args,
                          args.register_count());
  } else {
    OutputCallRuntime(static_cast<int>(function_id), args,
                      args.register_count());
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntime(
    Runtime::FunctionId function_id, Register arg) {
  return CallRuntime(function_id, RegisterList(arg));
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntime(
    Runtime::FunctionId function_id) {
  return CallRuntime(function_id, RegisterList());
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntimeForPair(
    Runtime::FunctionId function_id, RegisterList args,
    RegisterList return_pair) {
  DCHECK_EQ(2, Runtime::FunctionForId(function_id)->result_size);
  DCHECK_LE(Bytecodes::SizeForUnsignedOperand(function_id),
            OperandSize::kShort);
  DCHECK_EQ(2, return_pair.register_count());
  OutputCallRuntimeForPair(static_cast<uint16_t>(function_id), args,
                           args.register_count(), return_pair);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntimeForPair(
    Runtime::FunctionId function_id, Register arg, RegisterList return_pair) {
  return CallRuntimeForPair(function_id, RegisterList(arg), return_pair);
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallJSRuntime(int context_index,
                                                          RegisterList args) {
  OutputCallJSRuntime(context_index, args, args.register_count());
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Delete(Register object,
                                                   LanguageMode language_mode) {
  if (language_mode == LanguageMode::kSloppy) {
    OutputDeletePropertySloppy(object);
  } else {
    DCHECK_EQ(language_mode, LanguageMode::kStrict);
    OutputDeletePropertyStrict(object);
  }
  return *this;
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(
    const AstRawString* raw_string) {
  return constant_array_builder()->Insert(raw_string);
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(
    const AstConsString* cons_string) {
  return constant_array_builder()->Insert(cons_string);
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(AstBigInt bigint) {
  return constant_array_builder()->Insert(bigint);
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(const Scope* scope) {
  return constant_array_builder()->Insert(scope);
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(double number) {
  return constant_array_builder()->Insert(number);
}

#define ENTRY_GETTER(NAME, ...)                            \
  size_t BytecodeArrayBuilder::NAME##ConstantPoolEntry() { \
    return constant_array_builder()->Insert##NAME();       \
  }
SINGLETON_CONSTANT_ENTRY_TYPES(ENTRY_GETTER)
#undef ENTRY_GETTER

BytecodeJumpTable* BytecodeArrayBuilder::AllocateJumpTable(
    int size, int case_value_base) {
  DCHECK_GT(size, 0);

  size_t constant_pool_index = constant_array_builder()->InsertJumpTable(size);

  return zone()->New<BytecodeJumpTable>(constant_pool_index, size,
                                        case_value_base, zone());
}

size_t BytecodeArrayBuilder::AllocateDeferredConstantPoolEntry() {
  return constant_array_builder()->InsertDeferred();
}

void BytecodeArrayBuilder::SetDeferredConstantPoolEntry(size_t entry,
                                                        Handle<Object> object) {
  constant_array_builder()->SetDeferredAt(entry, object);
}

bool BytecodeArrayBuilder::RegisterIsValid(Register reg) const {
  if (!reg.is_valid()) {
    return false;
  }

  if (reg.is_current_context() || reg.is_function_closure()) {
    return true;
  } else if (reg.is_parameter()) {
    int parameter_index = reg.ToParameterIndex();
    return parameter_index >= 0 && parameter_index < parameter_count();
  } else if (reg.index() < fixed_register_count()) {
    return true;
  } else {
    return register_allocator()->RegisterIsLive(reg);
  }
}

bool BytecodeArrayBuilder::RegisterListIsValid(RegisterList reg_list) const {
  if (reg_list.register_count() == 0) {
    return reg_list.first_register() == Register(0);
  } else {
    int first_reg_index = reg_list.first_register().index();
    for (int i = 0; i < reg_list.register_count(); i++) {
      if (!RegisterIsValid(Register(first_reg_index + i))) {
        return false;
      }
    }
    return true;
  }
}

template <Bytecode bytecode, ImplicitRegisterUse implicit_register_use>
void BytecodeArrayBuilder::PrepareToOutputBytecode() {
  if (register_optimizer_) {
    register_optimizer_->PrepareForBytecode<bytecode, implicit_register_use>();
  }
}

uint32_t BytecodeArrayBuilder::GetInputRegisterOperand(Register reg) {
  DCHECK(RegisterIsValid(reg));
  if (register_optimizer_) reg = register_optimizer_->GetInputRegister(reg);
  return static_cast<uint32_t>(reg.ToOperand());
}

uint32_t BytecodeArrayBuilder::GetOutputRegisterOperand(Register reg) {
  DCHECK(RegisterIsValid(reg));
  if (register_optimizer_) register_optimizer_->PrepareOutputRegister(reg);
  return static_cast<uint32_t>(reg.ToOperand());
}

uint32_t BytecodeArrayBuilder::GetInputOutputRegisterOperand(Register reg) {
  DCHECK(RegisterIsValid(reg));
  if (register_optimizer_) {
    register_optimizer_->PrepareOutputRegister(reg);
    DCHECK_EQ(reg, register_optimizer_->GetInputRegister(reg));
  }
  return static_cast<uint32_t>(reg.ToOperand());
}

uint32_t BytecodeArrayBuilder::GetInputRegisterListOperand(
    RegisterList reg_list) {
  DCHECK(RegisterListIsValid(reg_list));
  if (register_optimizer_)
    reg_list = register_optimizer_->GetInputRegisterList(reg_list);
  return static_cast<uint32_t>(reg_list.first_register().ToOperand());
}

uint32_t BytecodeArrayBuilder::GetOutputRegisterListOperand(
    RegisterList reg_list) {
  DCHECK(RegisterListIsValid(reg_list));
  if (register_optimizer_)
    register_optimizer_->PrepareOutputRegisterList(reg_list);
  return static_cast<uint32_t>(reg_list.first_register().ToOperand());
}

void BytecodeArrayBuilder::EmitFunctionStartSourcePosition(int position) {
  bytecode_array_writer_.SetFunctionEntrySourcePosition(position);
  // Force an expression position to make sure we have one. If the next bytecode
  // overwrites it, it’s fine since it would mean we have a source position
  // anyway.
  latest_source_info_.ForceExpressionPosition(position);
}

std::ostream& operator<<(std::ostream& os,
                         const BytecodeArrayBuilder::ToBooleanMode& mode) {
  switch (mode) {
    case BytecodeArrayBuilder::ToBooleanMode::kAlreadyBoolean:
      return os << "AlreadyBoolean";
    case BytecodeArrayBuilder::ToBooleanMode::kConvertToBoolean:
      return os << "ConvertToBoolean";
  }
  UNREACHABLE();
}

}  // namespace interpreter
}  // namespace internal
}  // namespace v8
```