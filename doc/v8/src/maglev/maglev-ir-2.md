Response: The user wants a summary of the C++ source code file `v8/src/maglev/maglev-ir.cc`, specifically the part 3 of 5. The summary should focus on the functionalities implemented in this part. If the code relates to JavaScript features, a JavaScript example should be provided.

Based on the code snippets, this part of the file seems to define various IR (Intermediate Representation) nodes for the Maglev compiler in V8. These nodes represent operations and checks that are performed during JavaScript execution. Each node has methods for:
1. `SetValueLocationConstraints()`:  Specifying how the input and output values of the node should be located (e.g., in registers).
2. `GenerateCode()`: Emitting the actual machine code for the operation represented by the node.

The nodes in this part cover a range of functionalities, including:

* **Type Checking**:  Checking if a value is a string, a string or string wrapper, or a callable.
* **Value Conversion**: Converting values to objects (for receiver handling), handling the `this` value in constructors, and converting the hole value to undefined.
* **Object and Array Literal Creation**: Creating object and array literals with different optimization levels (shallow/non-shallow).
* **Closure and Context Creation**: Creating closures and function execution contexts.
* **Regular Expression Handling**: Creating regular expression literals.
* **Prototype Chain Lookup**: Checking if an object is in the prototype chain of another.
* **Debugging and Error Handling**:  Debug breakpoints and explicit program abortion.
* **Logical Operations**:  Logical NOT operation.
* **Property Access**: Generic load and store operations for named and indexed properties, including super calls and array literals.
* **Array Length Manipulation**: Updating the length of a JSArray.
* **Fast Element Handling**: Ensuring writable fast elements and potentially growing them.
* **Property Backing Store Management**: Extending the backing store of an object's properties.
* **Generator Support**:  Restoring and storing generator registers and state.
* **Type Conversion (Numeric)**: Converting values to numbers or numerics.
* **Equality Checks**: Checking for equality between strings and tagged values.
* **`instanceof` and `typeof` Operators**: Implementing the `instanceof` and `typeof` operators.
* **Boolean Conversion**: Converting values to boolean.
* **String Operations**: Getting string length, concatenating strings and string wrappers, and checking for string equality.

It seems like this part of the code deals with fundamental operations in JavaScript, particularly those involving type checking, object manipulation, and control flow related to function calls and property access.
这是 `v8/src/maglev/maglev-ir.cc` 文件的一部分，主要定义了 Maglev 编译器的中间表示（IR）节点，这些节点代表了 JavaScript 代码执行过程中的各种操作和检查。

**主要功能归纳:**

这部分代码主要定义了以下类型的 IR 节点：

1. **类型检查节点 (Check Nodes):**
   - `CheckString`: 检查一个值是否是字符串。
   - `CheckStringOrStringWrapper`: 检查一个值是否是字符串或 String 包装对象。
   - `CheckDetectableCallable`: 检查一个值是否是可调用的，并且不是不可检测的对象（例如 Proxy）。
   - `CheckNotHole`: 检查一个值是否不是 `the hole`。

2. **类型转换节点 (Conversion Nodes):**
   - `ConvertHoleToUndefined`: 将 `the hole` 值转换为 `undefined`。
   - `ConvertReceiver`: 用于处理函数调用的接收者 (`this` 值)，例如将原始值转换为对应的包装对象。

3. **构造函数调用结果检查节点 (Constructor Result Check Nodes):**
   - `CheckDerivedConstructResult`: 检查派生类构造函数的返回值是否为对象，如果不是则抛出错误。
   - `CheckConstructResult`: 检查普通构造函数的返回值，如果是 `undefined` 则使用隐式接收者 (`this`) 作为结果。

4. **对象和数组字面量创建节点 (Literal Creation Nodes):**
   - `CreateObjectLiteral`: 创建普通对象字面量。
   - `CreateShallowArrayLiteral`: 创建浅拷贝的数组字面量。
   - `CreateArrayLiteral`: 创建数组字面量。
   - `CreateShallowObjectLiteral`: 创建浅拷贝的对象字面量。

5. **内存分配节点 (Allocation Node):**
   - `AllocationBlock`: 分配一块内存。

6. **闭包和上下文创建节点 (Closure and Context Creation Nodes):**
   - `CreateClosure`: 创建一个新的闭包。
   - `FastCreateClosure`: 快速创建闭包。
   - `CreateFunctionContext`: 创建函数执行上下文。

7. **正则表达式字面量创建节点 (RegExp Literal Creation Node):**
   - `CreateRegExpLiteral`: 创建正则表达式字面量。

8. **模板对象获取节点 (Template Object Retrieval Node):**
   - `GetTemplateObject`: 获取模板字面量的模板对象。

9. **原型链检查节点 (Prototype Chain Check Node):**
   - `HasInPrototypeChain`: 检查一个对象是否在另一个对象的原型链上。

10. **调试和控制流节点 (Debug and Control Flow Nodes):**
    - `DebugBreak`: 设置断点。
    - `Abort`: 中止程序执行。
    - `LogicalNot`: 执行逻辑非运算。

11. **属性访问节点 (Property Access Nodes):**
    - `LoadNamedGeneric`: 通用的命名属性加载操作。
    - `LoadNamedFromSuperGeneric`: 从父类加载命名属性。
    - `SetNamedGeneric`: 通用的命名属性设置操作。
    - `DefineNamedOwnGeneric`: 定义一个自有命名属性。
    - `GetKeyedGeneric`: 通用的索引属性加载操作。
    - `SetKeyedGeneric`: 通用的索引属性设置操作。
    - `DefineKeyedOwnGeneric`: 定义一个自有索引属性。
    - `StoreInArrayLiteralGeneric`: 在数组字面量中存储值。

12. **数组操作节点 (Array Manipulation Nodes):**
    - `UpdateJSArrayLength`: 更新 JSArray 的长度。
    - `EnsureWritableFastElements`: 确保数组的元素是可写的快速元素。
    - `MaybeGrowFastElements`: 可能增长数组的快速元素存储空间。
    - `ExtendPropertiesBackingStore`: 扩展对象的属性后备存储。

13. **生成器相关节点 (Generator Nodes):**
    - `GeneratorRestoreRegister`: 从生成器对象恢复寄存器值。
    - `GeneratorStore`: 将生成器的状态存储到生成器对象中。

14. **类型转换节点 (Type Conversion Nodes):**
    - `Int32ToNumber`: 将 32 位整数转换为 Number 类型。
    - `Uint32ToNumber`: 将无符号 32 位整数转换为 Number 类型。
    - `Float64ToTagged`: 将 64 位浮点数转换为 Tagged 值 (可能是 Smi 或 HeapNumber)。
    - `Float64ToHeapNumberForField`: 将 64 位浮点数转换为 HeapNumber。
    - `HoleyFloat64ToTagged`: 将可能包含 `NaN` 的 64 位浮点数转换为 Tagged 值。
    - `Float64Round`: 对 64 位浮点数进行四舍五入。
    - `Int32AbsWithOverflow`: 计算可能溢出的 32 位整数的绝对值。
    - `Float64Abs`: 计算 64 位浮点数的绝对值。
    - `CheckedSmiTagFloat64`: 检查 64 位浮点数是否可以安全地转换为 Smi。

15. **内存存储节点 (Memory Store Nodes):**
    - `StoreFloat64`: 存储 64 位浮点数到内存。
    - `StoreTaggedFieldNoWriteBarrier`: 存储 Tagged 值到对象字段，不包含写屏障。

16. **字符串操作节点 (String Operation Nodes):**
    - `StringAt`: 获取字符串指定位置的字符。
    - `BuiltinStringPrototypeCharCodeOrCodePointAt`: 获取字符串指定位置的字符码点或字符编码。
    - `StringLength`: 获取字符串的长度。
    - `StringConcat`: 连接两个字符串。
    - `StringWrapperConcat`: 连接字符串或字符串包装对象。
    - `StringEqual`: 比较两个字符串是否相等。

17. **比较节点 (Comparison Nodes):**
    - `TaggedEqual`: 比较两个 Tagged 值是否相等。
    - `TaggedNotEqual`: 比较两个 Tagged 值是否不等。

18. **类型判断节点 (Type Check Nodes):**
    - `TestInstanceOf`: 实现 `instanceof` 运算符。
    - `TestTypeOf`: 实现 `typeof` 运算符。

19. **布尔值转换节点 (Boolean Conversion Nodes):**
    - `ToBoolean`: 将值转换为布尔值。
    - `ToBooleanLogicalNot`: 将值转换为布尔值并取反。

20. **其他类型转换节点 (Other Conversion Nodes):**
    - `ToName`: 将值转换为名称 (String 或 Symbol)。
    - `ToNumberOrNumeric`: 将值转换为 Number 或 Numeric 类型。

**与 JavaScript 功能的关系和示例:**

这些 IR 节点直接对应了 JavaScript 的各种操作符、语句和内置函数。以下是一些示例：

* **`CheckString`:** 对应 JavaScript 中对字符串类型的检查。
  ```javascript
  function isString(x) {
    if (typeof x === 'string') {
      return true;
    }
    return false;
  }
  ```

* **`ConvertReceiver`:**  对应函数调用中 `this` 值的处理。
  ```javascript
  function foo() {
    console.log(this); // this 的值取决于调用方式
  }

  foo(); // this 通常是全局对象 (window 或 undefined)
  const obj = { method: foo };
  obj.method(); // this 是 obj
  new foo(); // this 是新创建的对象
  ```

* **`CreateObjectLiteral`:** 对应对象字面量的创建。
  ```javascript
  const obj = { a: 1, b: 'hello' };
  ```

* **`StringConcat`:** 对应字符串连接操作符 `+`。
  ```javascript
  const str1 = "hello";
  const str2 = "world";
  const result = str1 + " " + str2;
  console.log(result); // "hello world"
  ```

* **`TestInstanceOf`:** 对应 `instanceof` 运算符。
  ```javascript
  class MyClass {}
  const obj = new MyClass();
  console.log(obj instanceof MyClass); // true
  ```

* **`ToBoolean`:** 对应 JavaScript 中的隐式布尔转换，例如在 `if` 语句中。
  ```javascript
  if ("hello") { // "hello" 会被转换为 true
    console.log("This will be printed.");
  }

  if (0) { // 0 会被转换为 false
    console.log("This will not be printed.");
  }
  ```

总的来说，这部分代码定义了 Maglev 编译器在执行 JavaScript 代码时所使用的基本操作单元，涵盖了类型检查、类型转换、对象操作、字符串操作、控制流等多个方面。这些节点会被 Maglev 编译器用于将 JavaScript 代码翻译成高效的机器码。

Prompt: 
```
这是目录为v8/src/maglev/maglev-ir.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
traints() {
  UseRegister(receiver_input());
}
void CheckString::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  if (check_type() == CheckType::kOmitHeapObjectCheck) {
    __ AssertNotSmi(object);
  } else {
    __ EmitEagerDeoptIfSmi(this, object, DeoptimizeReason::kNotAString);
  }
  __ JumpIfNotString(object,
                     __ GetDeoptLabel(this, DeoptimizeReason::kNotAString));
}

void CheckStringOrStringWrapper::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  set_temporaries_needed(1);
}

void CheckStringOrStringWrapper::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register object = ToRegister(receiver_input());

  if (check_type() == CheckType::kOmitHeapObjectCheck) {
    __ AssertNotSmi(object);
  } else {
    __ EmitEagerDeoptIfSmi(this, object,
                           DeoptimizeReason::kNotAStringOrStringWrapper);
  }

  auto deopt =
      __ GetDeoptLabel(this, DeoptimizeReason::kNotAStringOrStringWrapper);
  Label done;

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();

  __ JumpIfString(object, &done);
  __ JumpIfNotObjectType(object, InstanceType::JS_PRIMITIVE_WRAPPER_TYPE,
                         deopt);
  __ LoadMap(scratch, object);
  __ LoadBitField<Map::Bits2::ElementsKindBits>(
      scratch, FieldMemOperand(scratch, Map::kBitField2Offset));
  static_assert(FAST_STRING_WRAPPER_ELEMENTS + 1 ==
                SLOW_STRING_WRAPPER_ELEMENTS);
  __ CompareInt32AndJumpIf(scratch, FAST_STRING_WRAPPER_ELEMENTS, kLessThan,
                           deopt);
  __ CompareInt32AndJumpIf(scratch, SLOW_STRING_WRAPPER_ELEMENTS, kGreaterThan,
                           deopt);
  __ Jump(&done);
  __ bind(&done);
}

void CheckDetectableCallable::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  set_temporaries_needed(1);
}

void CheckDetectableCallable::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  auto deopt = __ GetDeoptLabel(this, DeoptimizeReason::kNotDetectableReceiver);
  __ JumpIfNotCallable(object, scratch, check_type(), deopt);
  __ JumpIfUndetectable(object, scratch, CheckType::kOmitHeapObjectCheck,
                        deopt);
}

void CheckNotHole::SetValueLocationConstraints() {
  UseRegister(object_input());
}
void CheckNotHole::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  __ CompareRootAndEmitEagerDeoptIf(ToRegister(object_input()),
                                    RootIndex::kTheHoleValue, kEqual,
                                    DeoptimizeReason::kHole, this);
}

void ConvertHoleToUndefined::SetValueLocationConstraints() {
  UseRegister(object_input());
  DefineSameAsFirst(this);
}
void ConvertHoleToUndefined::GenerateCode(MaglevAssembler* masm,
                                          const ProcessingState& state) {
  Label done;
  DCHECK_EQ(ToRegister(object_input()), ToRegister(result()));
  __ JumpIfNotRoot(ToRegister(object_input()), RootIndex::kTheHoleValue, &done);
  __ LoadRoot(ToRegister(result()), RootIndex::kUndefinedValue);
  __ bind(&done);
}

int ConvertReceiver::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kToObject>::type;
  return D::GetStackParameterCount();
}
void ConvertReceiver::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kToObject>::type;
  static_assert(D::GetRegisterParameter(D::kInput) == kReturnRegister0);
  UseFixed(receiver_input(), D::GetRegisterParameter(D::kInput));
  DefineAsFixed(this, kReturnRegister0);
}
void ConvertReceiver::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Label convert_to_object, done;
  Register receiver = ToRegister(receiver_input());
  __ JumpIfSmi(
      receiver, &convert_to_object,
      v8_flags.debug_code ? Label::Distance::kFar : Label::Distance::kNear);

  // If {receiver} is not primitive, no need to move it to {result}, since
  // they share the same register.
  DCHECK_EQ(receiver, ToRegister(result()));
  __ JumpIfJSAnyIsNotPrimitive(receiver, &done);

  compiler::JSHeapBroker* broker = masm->compilation_info()->broker();
  if (mode_ != ConvertReceiverMode::kNotNullOrUndefined) {
    Label convert_global_proxy;
    __ JumpIfRoot(receiver, RootIndex::kUndefinedValue, &convert_global_proxy,
                  Label::Distance::kNear);
    __ JumpIfNotRoot(
        receiver, RootIndex::kNullValue, &convert_to_object,
        v8_flags.debug_code ? Label::Distance::kFar : Label::Distance::kNear);
    __ bind(&convert_global_proxy);
    // Patch receiver to global proxy.
    __ Move(ToRegister(result()),
            native_context_.global_proxy_object(broker).object());
    __ Jump(&done);
  }

  __ bind(&convert_to_object);
  __ CallBuiltin<Builtin::kToObject>(native_context_.object(),
                                     receiver_input());
  __ bind(&done);
}

int CheckDerivedConstructResult::MaxCallStackArgs() const { return 0; }
void CheckDerivedConstructResult::SetValueLocationConstraints() {
  UseRegister(construct_result_input());
  DefineSameAsFirst(this);
}
void CheckDerivedConstructResult::GenerateCode(MaglevAssembler* masm,
                                               const ProcessingState& state) {
  Register construct_result = ToRegister(construct_result_input());

  DCHECK_EQ(construct_result, ToRegister(result()));

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label done, do_throw;

  __ CompareRoot(construct_result, RootIndex::kUndefinedValue);
  __ Assert(kNotEqual, AbortReason::kUnexpectedValue);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(construct_result, &do_throw, Label::Distance::kNear);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(construct_result, &done, Label::Distance::kNear);

  // Throw away the result of the constructor invocation and use the
  // implicit receiver as the result.
  __ bind(&do_throw);
  __ Jump(__ MakeDeferredCode(
      [](MaglevAssembler* masm, CheckDerivedConstructResult* node) {
        __ Move(kContextRegister, masm->native_context().object());
        __ CallRuntime(Runtime::kThrowConstructorReturnedNonObject);
        masm->DefineExceptionHandlerAndLazyDeoptPoint(node);
        __ Abort(AbortReason::kUnexpectedReturnFromThrow);
      },
      this));

  __ bind(&done);
}

int CheckConstructResult::MaxCallStackArgs() const { return 0; }
void CheckConstructResult::SetValueLocationConstraints() {
  UseRegister(construct_result_input());
  UseRegister(implicit_receiver_input());
  DefineSameAsFirst(this);
}
void CheckConstructResult::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register construct_result = ToRegister(construct_result_input());
  Register result_reg = ToRegister(result());

  DCHECK_EQ(construct_result, result_reg);

  // If the result is an object (in the ECMA sense), we should get rid
  // of the receiver and use the result; see ECMA-262 section 13.2.2-7
  // on page 74.
  Label done, use_receiver;

  // If the result is undefined, we'll use the implicit receiver.
  __ JumpIfRoot(construct_result, RootIndex::kUndefinedValue, &use_receiver,
                Label::Distance::kNear);

  // If the result is a smi, it is *not* an object in the ECMA sense.
  __ JumpIfSmi(construct_result, &use_receiver, Label::Distance::kNear);

  // Check if the type of the result is not an object in the ECMA sense.
  __ JumpIfJSAnyIsNotPrimitive(construct_result, &done, Label::Distance::kNear);

  // Throw away the result of the constructor invocation and use the
  // implicit receiver as the result.
  __ bind(&use_receiver);
  Register implicit_receiver = ToRegister(implicit_receiver_input());
  __ Move(result_reg, implicit_receiver);

  __ bind(&done);
}

int CreateObjectLiteral::MaxCallStackArgs() const {
  DCHECK_EQ(Runtime::FunctionForId(Runtime::kCreateObjectLiteral)->nargs, 4);
  return 4;
}
void CreateObjectLiteral::SetValueLocationConstraints() {
  DefineAsFixed(this, kReturnRegister0);
}
void CreateObjectLiteral::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  __ CallBuiltin<Builtin::kCreateObjectFromSlowBoilerplate>(
      masm->native_context().object(),              // context
      feedback().vector,                            // feedback vector
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      boilerplate_descriptor().object(),            // boilerplate descriptor
      Smi::FromInt(flags())                         // flags
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CreateShallowArrayLiteral::MaxCallStackArgs() const {
  using D =
      CallInterfaceDescriptorFor<Builtin::kCreateShallowArrayLiteral>::type;
  return D::GetStackParameterCount();
}
void CreateShallowArrayLiteral::SetValueLocationConstraints() {
  DefineAsFixed(this, kReturnRegister0);
}
void CreateShallowArrayLiteral::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  __ CallBuiltin<Builtin::kCreateShallowArrayLiteral>(
      masm->native_context().object(),              // context
      feedback().vector,                            // feedback vector
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      constant_elements().object(),                 // constant elements
      Smi::FromInt(flags())                         // flags
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CreateArrayLiteral::MaxCallStackArgs() const {
  DCHECK_EQ(Runtime::FunctionForId(Runtime::kCreateArrayLiteral)->nargs, 4);
  return 4;
}
void CreateArrayLiteral::SetValueLocationConstraints() {
  DefineAsFixed(this, kReturnRegister0);
}
void CreateArrayLiteral::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  __ CallBuiltin<Builtin::kCreateArrayFromSlowBoilerplate>(
      masm->native_context().object(),              // context
      feedback().vector,                            // feedback vector
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      constant_elements().object(),                 // boilerplate descriptor
      Smi::FromInt(flags())                         // flags
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CreateShallowObjectLiteral::MaxCallStackArgs() const {
  using D =
      CallInterfaceDescriptorFor<Builtin::kCreateShallowObjectLiteral>::type;
  return D::GetStackParameterCount();
}
void CreateShallowObjectLiteral::SetValueLocationConstraints() {
  DefineAsFixed(this, kReturnRegister0);
}
void CreateShallowObjectLiteral::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  __ CallBuiltin<Builtin::kCreateShallowObjectLiteral>(
      masm->native_context().object(),              // context
      feedback().vector,                            // feedback vector
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      boilerplate_descriptor().object(),            // desc
      Smi::FromInt(flags())                         // flags
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void AllocationBlock::SetValueLocationConstraints() { DefineAsRegister(this); }

void AllocationBlock::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  __ Allocate(register_snapshot(), ToRegister(result()), size(),
              allocation_type());
}

int CreateClosure::MaxCallStackArgs() const {
  DCHECK_EQ(Runtime::FunctionForId(pretenured() ? Runtime::kNewClosure_Tenured
                                                : Runtime::kNewClosure)
                ->nargs,
            2);
  return 2;
}
void CreateClosure::SetValueLocationConstraints() {
  UseFixed(context(), kContextRegister);
  DefineAsFixed(this, kReturnRegister0);
}
void CreateClosure::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  Runtime::FunctionId function_id =
      pretenured() ? Runtime::kNewClosure_Tenured : Runtime::kNewClosure;
  __ Push(shared_function_info().object(), feedback_cell().object());
  __ CallRuntime(function_id);
}

int FastCreateClosure::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kFastNewClosure>::type;
  return D::GetStackParameterCount();
}
void FastCreateClosure::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kFastNewClosure>::type;
  static_assert(D::HasContextParameter());
  UseFixed(context(), D::ContextRegister());
  DefineAsFixed(this, kReturnRegister0);
}
void FastCreateClosure::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  __ CallBuiltin<Builtin::kFastNewClosure>(
      context(),                        // context
      shared_function_info().object(),  // shared function info
      feedback_cell().object()          // feedback cell
  );
  masm->DefineLazyDeoptPoint(lazy_deopt_info());
}

int CreateFunctionContext::MaxCallStackArgs() const {
  if (scope_type() == FUNCTION_SCOPE) {
    using D = CallInterfaceDescriptorFor<
        Builtin::kFastNewFunctionContextFunction>::type;
    return D::GetStackParameterCount();
  } else {
    using D =
        CallInterfaceDescriptorFor<Builtin::kFastNewFunctionContextEval>::type;
    return D::GetStackParameterCount();
  }
}
void CreateFunctionContext::SetValueLocationConstraints() {
  DCHECK_LE(slot_count(),
            static_cast<uint32_t>(
                ConstructorBuiltins::MaximumFunctionContextSlots()));
  if (scope_type() == FUNCTION_SCOPE) {
    using D = CallInterfaceDescriptorFor<
        Builtin::kFastNewFunctionContextFunction>::type;
    static_assert(D::HasContextParameter());
    UseFixed(context(), D::ContextRegister());
  } else {
    DCHECK_EQ(scope_type(), ScopeType::EVAL_SCOPE);
    using D =
        CallInterfaceDescriptorFor<Builtin::kFastNewFunctionContextEval>::type;
    static_assert(D::HasContextParameter());
    UseFixed(context(), D::ContextRegister());
  }
  DefineAsFixed(this, kReturnRegister0);
}
void CreateFunctionContext::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  if (scope_type() == FUNCTION_SCOPE) {
    __ CallBuiltin<Builtin::kFastNewFunctionContextFunction>(
        context(),              // context
        scope_info().object(),  // scope info
        slot_count()            // slots
    );
  } else {
    __ CallBuiltin<Builtin::kFastNewFunctionContextEval>(
        context(),              // context
        scope_info().object(),  // scope info
        slot_count()            // slots
    );
  }
  masm->DefineLazyDeoptPoint(lazy_deopt_info());
}

int CreateRegExpLiteral::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kCreateRegExpLiteral>::type;
  return D::GetStackParameterCount();
}
void CreateRegExpLiteral::SetValueLocationConstraints() {
  DefineAsFixed(this, kReturnRegister0);
}
void CreateRegExpLiteral::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  __ CallBuiltin<Builtin::kCreateRegExpLiteral>(
      masm->native_context().object(),              // context
      feedback().vector,                            // feedback vector
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      pattern().object(),                           // pattern
      Smi::FromInt(flags())                         // flags
  );
  masm->DefineLazyDeoptPoint(lazy_deopt_info());
}

int GetTemplateObject::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kGetTemplateObject>::type;
  return D::GetStackParameterCount();
}
void GetTemplateObject::SetValueLocationConstraints() {
  using D = GetTemplateObjectDescriptor;
  UseFixed(description(), D::GetRegisterParameter(D::kDescription));
  DefineAsFixed(this, kReturnRegister0);
}
void GetTemplateObject::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  __ CallBuiltin<Builtin::kGetTemplateObject>(
      masm->native_context().object(),  // context
      shared_function_info_.object(),   // shared function info
      description(),                    // description
      feedback().index(),               // feedback slot
      feedback().vector                 // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int HasInPrototypeChain::MaxCallStackArgs() const {
  DCHECK_EQ(2, Runtime::FunctionForId(Runtime::kHasInPrototypeChain)->nargs);
  return 2;
}
void HasInPrototypeChain::SetValueLocationConstraints() {
  UseRegister(object());
  DefineAsRegister(this);
  set_temporaries_needed(2);
}
void HasInPrototypeChain::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object_reg = ToRegister(object());
  Register result_reg = ToRegister(result());

  Label return_false, return_true;
  ZoneLabelRef done(masm);

  __ JumpIfSmi(object_reg, &return_false,
               v8_flags.debug_code ? Label::kFar : Label::kNear);

  // Loop through the prototype chain looking for the {prototype}.
  Register map = temps.Acquire();
  __ LoadMap(map, object_reg);
  Label loop;
  {
    __ bind(&loop);
    Register scratch = temps.Acquire();
    // Check if we can determine the prototype directly from the {object_map}.
    ZoneLabelRef if_objectisdirect(masm);
    Register instance_type = scratch;
    Condition jump_cond = __ CompareInstanceTypeRange(
        map, instance_type, FIRST_TYPE, LAST_SPECIAL_RECEIVER_TYPE);
    __ JumpToDeferredIf(
        jump_cond,
        [](MaglevAssembler* masm, RegisterSnapshot snapshot,
           Register object_reg, Register map, Register instance_type,
           Register result_reg, HasInPrototypeChain* node,
           ZoneLabelRef if_objectisdirect, ZoneLabelRef done) {
          Label return_runtime;
          // The {object_map} is a special receiver map or a primitive map,
          // check if we need to use the if_objectisspecial path in the runtime.
          __ JumpIfEqual(instance_type, JS_PROXY_TYPE, &return_runtime);

          int mask = Map::Bits1::HasNamedInterceptorBit::kMask |
                     Map::Bits1::IsAccessCheckNeededBit::kMask;
          __ TestUint8AndJumpIfAllClear(
              FieldMemOperand(map, Map::kBitFieldOffset), mask,
              *if_objectisdirect);

          __ bind(&return_runtime);
          {
            snapshot.live_registers.clear(result_reg);
            SaveRegisterStateForCall save_register_state(masm, snapshot);
            __ Push(object_reg, node->prototype().object());
            __ Move(kContextRegister, masm->native_context().object());
            __ CallRuntime(Runtime::kHasInPrototypeChain, 2);
            masm->DefineExceptionHandlerPoint(node);
            save_register_state.DefineSafepointWithLazyDeopt(
                node->lazy_deopt_info());
            __ Move(result_reg, kReturnRegister0);
          }
          __ Jump(*done);
        },
        register_snapshot(), object_reg, map, instance_type, result_reg, this,
        if_objectisdirect, done);
    instance_type = Register::no_reg();

    __ bind(*if_objectisdirect);
    // Check the current {object} prototype.
    Register object_prototype = scratch;
    __ LoadTaggedField(object_prototype, map, Map::kPrototypeOffset);
    __ JumpIfRoot(object_prototype, RootIndex::kNullValue, &return_false,
                  v8_flags.debug_code ? Label::kFar : Label::kNear);
    __ CompareTaggedAndJumpIf(object_prototype, prototype().object(), kEqual,
                              &return_true, Label::kNear);

    // Continue with the prototype.
    __ AssertNotSmi(object_prototype);
    __ LoadMap(map, object_prototype);
    __ Jump(&loop);
  }

  __ bind(&return_true);
  __ LoadRoot(result_reg, RootIndex::kTrueValue);
  __ Jump(*done, Label::kNear);

  __ bind(&return_false);
  __ LoadRoot(result_reg, RootIndex::kFalseValue);
  __ bind(*done);
}

void DebugBreak::SetValueLocationConstraints() {}
void DebugBreak::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  __ DebugBreak();
}

int Abort::MaxCallStackArgs() const {
  DCHECK_EQ(Runtime::FunctionForId(Runtime::kAbort)->nargs, 1);
  return 1;
}
void Abort::SetValueLocationConstraints() {}
void Abort::GenerateCode(MaglevAssembler* masm, const ProcessingState& state) {
  __ Push(Smi::FromInt(static_cast<int>(reason())));
  __ CallRuntime(Runtime::kAbort, 1);
  __ Trap();
}

void LogicalNot::SetValueLocationConstraints() {
  UseAny(value());
  DefineAsRegister(this);
}
void LogicalNot::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  if (v8_flags.debug_code) {
    // LogicalNot expects either TrueValue or FalseValue.
    Label next;
    __ JumpIf(__ IsRootConstant(value(), RootIndex::kFalseValue), &next);
    __ JumpIf(__ IsRootConstant(value(), RootIndex::kTrueValue), &next);
    __ Abort(AbortReason::kUnexpectedValue);
    __ bind(&next);
  }

  Label return_false, done;
  __ JumpIf(__ IsRootConstant(value(), RootIndex::kTrueValue), &return_false);
  __ LoadRoot(ToRegister(result()), RootIndex::kTrueValue);
  __ Jump(&done);

  __ bind(&return_false);
  __ LoadRoot(ToRegister(result()), RootIndex::kFalseValue);

  __ bind(&done);
}

int LoadNamedGeneric::MaxCallStackArgs() const {
  return LoadWithVectorDescriptor::GetStackParameterCount();
}
void LoadNamedGeneric::SetValueLocationConstraints() {
  using D = LoadWithVectorDescriptor;
  UseFixed(context(), kContextRegister);
  UseFixed(object_input(), D::GetRegisterParameter(D::kReceiver));
  DefineAsFixed(this, kReturnRegister0);
}
void LoadNamedGeneric::GenerateCode(MaglevAssembler* masm,
                                    const ProcessingState& state) {
  __ CallBuiltin<Builtin::kLoadIC>(
      context(),                                    // context
      object_input(),                               // receiver
      name().object(),                              // name
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int LoadNamedFromSuperGeneric::MaxCallStackArgs() const {
  return LoadWithReceiverAndVectorDescriptor::GetStackParameterCount();
}
void LoadNamedFromSuperGeneric::SetValueLocationConstraints() {
  using D = LoadWithReceiverAndVectorDescriptor;
  UseFixed(context(), kContextRegister);
  UseFixed(receiver(), D::GetRegisterParameter(D::kReceiver));
  UseFixed(lookup_start_object(),
           D::GetRegisterParameter(D::kLookupStartObject));
  DefineAsFixed(this, kReturnRegister0);
}
void LoadNamedFromSuperGeneric::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  __ CallBuiltin<Builtin::kLoadSuperIC>(
      context(),                                    // context
      receiver(),                                   // receiver
      lookup_start_object(),                        // lookup start object
      name().object(),                              // name
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int SetNamedGeneric::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kStoreIC>::type;
  return D::GetStackParameterCount();
}
void SetNamedGeneric::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kStoreIC>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(object_input(), D::GetRegisterParameter(D::kReceiver));
  UseFixed(value_input(), D::GetRegisterParameter(D::kValue));
  DefineAsFixed(this, kReturnRegister0);
}
void SetNamedGeneric::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  __ CallBuiltin<Builtin::kStoreIC>(
      context(),                                    // context
      object_input(),                               // receiver
      name().object(),                              // name
      value_input(),                                // value
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int DefineNamedOwnGeneric::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kDefineNamedOwnIC>::type;
  return D::GetStackParameterCount();
}
void DefineNamedOwnGeneric::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kDefineNamedOwnIC>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(object_input(), D::GetRegisterParameter(D::kReceiver));
  UseFixed(value_input(), D::GetRegisterParameter(D::kValue));
  DefineAsFixed(this, kReturnRegister0);
}
void DefineNamedOwnGeneric::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  __ CallBuiltin<Builtin::kDefineNamedOwnIC>(
      context(),                                    // context
      object_input(),                               // receiver
      name().object(),                              // name
      value_input(),                                // value
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void UpdateJSArrayLength::SetValueLocationConstraints() {
  UseRegister(length_input());
  UseRegister(object_input());
  UseAndClobberRegister(index_input());
  DefineSameAsFirst(this);
}

void UpdateJSArrayLength::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  Register length = ToRegister(length_input());
  Register object = ToRegister(object_input());
  Register index = ToRegister(index_input());
  DCHECK_EQ(length, ToRegister(result()));

  Label done, tag_length;
  if (v8_flags.debug_code) {
    __ AssertObjectType(object, JS_ARRAY_TYPE, AbortReason::kUnexpectedValue);
    static_assert(Internals::IsValidSmi(FixedArray::kMaxLength),
                  "MaxLength not a Smi");
    __ CompareInt32AndAssert(index, FixedArray::kMaxLength, kUnsignedLessThan,
                             AbortReason::kUnexpectedValue);
  }
  __ CompareInt32AndJumpIf(index, length, kUnsignedLessThan, &tag_length,
                           Label::kNear);
  __ IncrementInt32(index);  // This cannot overflow.
  __ SmiTag(length, index);
  __ StoreTaggedSignedField(object, JSArray::kLengthOffset, length);
  __ Jump(&done, Label::kNear);
  __ bind(&tag_length);
  __ SmiTag(length);
  __ bind(&done);
}

void EnsureWritableFastElements::SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(object_input());
  set_temporaries_needed(1);
  DefineSameAsFirst(this);
}
void EnsureWritableFastElements::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register elements = ToRegister(elements_input());
  DCHECK_EQ(elements, ToRegister(result()));
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ EnsureWritableFastElements(register_snapshot(), elements, object, scratch);
}

void MaybeGrowFastElements::SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(object_input());
  UseRegister(index_input());
  UseRegister(elements_length_input());
  if (IsSmiOrObjectElementsKind(elements_kind())) {
    set_temporaries_needed(1);
  }
  DefineSameAsFirst(this);
}
void MaybeGrowFastElements::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  Register elements = ToRegister(elements_input());
  Register object = ToRegister(object_input());
  Register index = ToRegister(index_input());
  Register elements_length = ToRegister(elements_length_input());
  DCHECK_EQ(elements, ToRegister(result()));

  ZoneLabelRef done(masm);

  __ CompareInt32AndJumpIf(
      index, elements_length, kUnsignedGreaterThanEqual,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, ZoneLabelRef done, Register object,
             Register index, Register result_reg, MaybeGrowFastElements* node) {
            {
              RegisterSnapshot snapshot = node->register_snapshot();
              snapshot.live_registers.clear(result_reg);
              snapshot.live_tagged_registers.clear(result_reg);
              SaveRegisterStateForCall save_register_state(masm, snapshot);
              using D = GrowArrayElementsDescriptor;
              if (index == D::GetRegisterParameter(D::kObject)) {
                // That implies that the first parameter move will clobber the
                // index value. So we use the result register as temporary.
                // TODO(leszeks): Use parallel moves to resolve cases like this.
                __ SmiTag(result_reg, index);
                index = result_reg;
              } else {
                __ SmiTag(index);
              }
              if (IsDoubleElementsKind(node->elements_kind())) {
                __ CallBuiltin<Builtin::kGrowFastDoubleElements>(object, index);
              } else {
                __ CallBuiltin<Builtin::kGrowFastSmiOrObjectElements>(object,
                                                                      index);
              }
              save_register_state.DefineSafepoint();
              __ Move(result_reg, kReturnRegister0);
            }
            __ EmitEagerDeoptIfSmi(node, result_reg,
                                   DeoptimizeReason::kCouldNotGrowElements);
            __ Jump(*done);
          },
          done, object, index, elements, this));

  __ bind(*done);
}

void ExtendPropertiesBackingStore::SetValueLocationConstraints() {
  UseRegister(property_array_input());
  UseRegister(object_input());
  DefineAsRegister(this);
  set_temporaries_needed(2);
}

void ExtendPropertiesBackingStore::GenerateCode(MaglevAssembler* masm,
                                                const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register old_property_array = ToRegister(property_array_input());
  Register result_reg = ToRegister(result());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register new_property_array =
      result_reg == object || result_reg == old_property_array ? temps.Acquire()
                                                               : result_reg;
  Register scratch = temps.Acquire();
  DCHECK(!AreAliased(object, old_property_array, new_property_array, scratch));

  int new_length = old_length_ + JSObject::kFieldsAdded;

  // Allocate new PropertyArray.
  {
    RegisterSnapshot snapshot = register_snapshot();
    // old_property_array needs to be live, since we'll read data from it.
    // Object needs to be live, since we write the new property array into it.
    snapshot.live_registers.set(object);
    snapshot.live_registers.set(old_property_array);
    snapshot.live_tagged_registers.set(object);
    snapshot.live_tagged_registers.set(old_property_array);

    Register size_in_bytes = scratch;
    __ Move(size_in_bytes, PropertyArray::SizeFor(new_length));
    __ Allocate(snapshot, new_property_array, size_in_bytes,
                AllocationType::kYoung);
    __ SetMapAsRoot(new_property_array, RootIndex::kPropertyArrayMap);
  }

  // Copy existing properties over.
  {
    RegisterSnapshot snapshot = register_snapshot();
    snapshot.live_registers.set(object);
    snapshot.live_registers.set(old_property_array);
    snapshot.live_registers.set(new_property_array);
    snapshot.live_tagged_registers.set(object);
    snapshot.live_tagged_registers.set(old_property_array);
    snapshot.live_tagged_registers.set(new_property_array);

    for (int i = 0; i < old_length_; ++i) {
      __ LoadTaggedFieldWithoutDecompressing(
          scratch, old_property_array, PropertyArray::OffsetOfElementAt(i));

      __ StoreTaggedFieldWithWriteBarrier(
          new_property_array, PropertyArray::OffsetOfElementAt(i), scratch,
          snapshot, MaglevAssembler::kValueIsCompressed,
          MaglevAssembler::kValueCanBeSmi);
    }
  }

  // Initialize new properties to undefined.
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  for (int i = 0; i < JSObject::kFieldsAdded; ++i) {
    __ StoreTaggedFieldNoWriteBarrier(
        new_property_array, PropertyArray::OffsetOfElementAt(old_length_ + i),
        scratch);
  }

  // Read the hash.
  if (old_length_ == 0) {
    // The object might still have a hash, stored in properties_or_hash. If
    // properties_or_hash is a SMI, then it's the hash. It can also be an empty
    // PropertyArray.
    __ LoadTaggedField(scratch, object, JSObject::kPropertiesOrHashOffset);

    Label done;
    __ JumpIfSmi(scratch, &done);

    __ Move(scratch, PropertyArray::kNoHashSentinel);

    __ bind(&done);
    __ SmiUntag(scratch);
    __ ShiftLeft(scratch, PropertyArray::HashField::kShift);
  } else {
    __ LoadTaggedField(scratch, old_property_array,
                       PropertyArray::kLengthAndHashOffset);
    __ SmiUntag(scratch);
    __ AndInt32(scratch, PropertyArray::HashField::kMask);
  }

  // Add the new length and write the length-and-hash field.
  static_assert(PropertyArray::LengthField::kShift == 0);
  __ OrInt32(scratch, new_length);

  __ UncheckedSmiTagInt32(scratch, scratch);
  __ StoreTaggedFieldNoWriteBarrier(
      new_property_array, PropertyArray::kLengthAndHashOffset, scratch);

  {
    RegisterSnapshot snapshot = register_snapshot();
    // new_property_array needs to be live since we'll return it.
    snapshot.live_registers.set(new_property_array);
    snapshot.live_tagged_registers.set(new_property_array);

    __ StoreTaggedFieldWithWriteBarrier(
        object, JSObject::kPropertiesOrHashOffset, new_property_array, snapshot,
        MaglevAssembler::kValueIsDecompressed,
        MaglevAssembler::kValueCannotBeSmi);
  }
  if (result_reg != new_property_array) {
    __ Move(result_reg, new_property_array);
  }
}

int SetKeyedGeneric::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kKeyedStoreIC>::type;
  return D::GetStackParameterCount();
}
void SetKeyedGeneric::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kKeyedStoreIC>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(object_input(), D::GetRegisterParameter(D::kReceiver));
  UseFixed(key_input(), D::GetRegisterParameter(D::kName));
  UseFixed(value_input(), D::GetRegisterParameter(D::kValue));
  DefineAsFixed(this, kReturnRegister0);
}
void SetKeyedGeneric::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  __ CallBuiltin<Builtin::kKeyedStoreIC>(
      context(),                                    // context
      object_input(),                               // receiver
      key_input(),                                  // name
      value_input(),                                // value
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int DefineKeyedOwnGeneric::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kDefineKeyedOwnIC>::type;
  return D::GetStackParameterCount();
}
void DefineKeyedOwnGeneric::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kDefineKeyedOwnIC>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(object_input(), D::GetRegisterParameter(D::kReceiver));
  UseFixed(key_input(), D::GetRegisterParameter(D::kName));
  UseFixed(value_input(), D::GetRegisterParameter(D::kValue));
  UseFixed(flags_input(), D::GetRegisterParameter(D::kFlags));
  DefineAsFixed(this, kReturnRegister0);
}
void DefineKeyedOwnGeneric::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  __ CallBuiltin<Builtin::kDefineKeyedOwnIC>(
      context(),                                    // context
      object_input(),                               // receiver
      key_input(),                                  // name
      value_input(),                                // value
      flags_input(),                                // flags
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int StoreInArrayLiteralGeneric::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kStoreInArrayLiteralIC>::type;
  return D::GetStackParameterCount();
}
void StoreInArrayLiteralGeneric::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kStoreInArrayLiteralIC>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(object_input(), D::GetRegisterParameter(D::kReceiver));
  UseFixed(name_input(), D::GetRegisterParameter(D::kName));
  UseFixed(value_input(), D::GetRegisterParameter(D::kValue));
  DefineAsFixed(this, kReturnRegister0);
}
void StoreInArrayLiteralGeneric::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  __ CallBuiltin<Builtin::kStoreInArrayLiteralIC>(
      context(),                                    // context
      object_input(),                               // receiver
      name_input(),                                 // name
      value_input(),                                // value
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void GeneratorRestoreRegister::SetValueLocationConstraints() {
  UseRegister(array_input());
  UseRegister(stale_input());
  DefineAsRegister(this);
  set_temporaries_needed(1);
}
void GeneratorRestoreRegister::GenerateCode(MaglevAssembler* masm,
                                            const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register temp = temps.Acquire();
  Register array = ToRegister(array_input());
  Register stale = ToRegister(stale_input());
  Register result_reg = ToRegister(result());

  // The input and the output can alias, if that happens we use a temporary
  // register and a move at the end.
  Register value = (array == result_reg ? temp : result_reg);

  // Loads the current value in the generator register file.
  __ LoadTaggedField(value, array, FixedArray::OffsetOfElementAt(index()));

  // And trashs it with StaleRegisterConstant.
  DCHECK(stale_input().node()->Is<RootConstant>());
  __ StoreTaggedFieldNoWriteBarrier(
      array, FixedArray::OffsetOfElementAt(index()), stale);

  if (value != result_reg) {
    __ Move(result_reg, value);
  }
}

int GeneratorStore::MaxCallStackArgs() const {
  return WriteBarrierDescriptor::GetStackParameterCount();
}
void GeneratorStore::SetValueLocationConstraints() {
  UseAny(context_input());
  UseRegister(generator_input());
  for (int i = 0; i < num_parameters_and_registers(); i++) {
    UseAny(parameters_and_registers(i));
  }
  RequireSpecificTemporary(WriteBarrierDescriptor::ObjectRegister());
  RequireSpecificTemporary(WriteBarrierDescriptor::SlotAddressRegister());
}
void GeneratorStore::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  Register generator = ToRegister(generator_input());
  Register array = WriteBarrierDescriptor::ObjectRegister();
  __ LoadTaggedField(array, generator,
                     JSGeneratorObject::kParametersAndRegistersOffset);

  RegisterSnapshot register_snapshot_during_store = register_snapshot();
  // Include the array and generator registers in the register snapshot while
  // storing parameters and registers, to avoid the write barrier clobbering
  // them.
  register_snapshot_during_store.live_registers.set(array);
  register_snapshot_during_store.live_tagged_registers.set(array);
  register_snapshot_during_store.live_registers.set(generator);
  register_snapshot_during_store.live_tagged_registers.set(generator);
  for (int i = 0; i < num_parameters_and_registers(); i++) {
    // Use WriteBarrierDescriptor::SlotAddressRegister() as the temporary for
    // the value -- it'll be clobbered by StoreTaggedFieldWithWriteBarrier since
    // it's not in the register snapshot, but that's ok, and a clobberable value
    // register lets the write barrier emit slightly better code.
    Input value_input = parameters_and_registers(i);
    Register value = __ FromAnyToRegister(
        value_input, WriteBarrierDescriptor::SlotAddressRegister());
    // Include the value register in the live set, in case it is used by future
    // inputs.
    register_snapshot_during_store.live_registers.set(value);
    register_snapshot_during_store.live_tagged_registers.set(value);
    __ StoreTaggedFieldWithWriteBarrier(
        array, FixedArray::OffsetOfElementAt(i), value,
        register_snapshot_during_store,
        value_input.node()->decompresses_tagged_result()
            ? MaglevAssembler::kValueIsDecompressed
            : MaglevAssembler::kValueIsCompressed,
        MaglevAssembler::kValueCanBeSmi);
  }

  __ StoreTaggedSignedField(generator, JSGeneratorObject::kContinuationOffset,
                            Smi::FromInt(suspend_id()));
  __ StoreTaggedSignedField(generator,
                            JSGeneratorObject::kInputOrDebugPosOffset,
                            Smi::FromInt(bytecode_offset()));

  // Use WriteBarrierDescriptor::SlotAddressRegister() as the scratch
  // register, see comment above. At this point we no longer need to preserve
  // the array or generator registers, so use the original register snapshot.
  Register context = __ FromAnyToRegister(
      context_input(), WriteBarrierDescriptor::SlotAddressRegister());
  __ StoreTaggedFieldWithWriteBarrier(
      generator, JSGeneratorObject::kContextOffset, context,
      register_snapshot(),
      context_input().node()->decompresses_tagged_result()
          ? MaglevAssembler::kValueIsDecompressed
          : MaglevAssembler::kValueIsCompressed,
      MaglevAssembler::kValueCannotBeSmi);
}

int GetKeyedGeneric::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kKeyedLoadIC>::type;
  return D::GetStackParameterCount();
}
void GetKeyedGeneric::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kKeyedLoadIC>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(object_input(), D::GetRegisterParameter(D::kReceiver));
  UseFixed(key_input(), D::GetRegisterParameter(D::kName));
  DefineAsFixed(this, kReturnRegister0);
}
void GetKeyedGeneric::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  __ CallBuiltin<Builtin::kKeyedLoadIC>(
      context(),                                    // context
      object_input(),                               // receiver
      key_input(),                                  // name
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void Int32ToNumber::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void Int32ToNumber::GenerateCode(MaglevAssembler* masm,
                                 const ProcessingState& state) {
  Register object = ToRegister(result());
  Register value = ToRegister(input());
  ZoneLabelRef done(masm);
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  // Object is not allowed to alias value, because SmiTagInt32AndJumpIfFail will
  // clobber `object` even if the tagging fails, and we don't want it to clobber
  // `value`.
  bool input_output_alias = (object == value);
  Register res = object;
  if (input_output_alias) {
    res = temps.AcquireScratch();
  }
  __ SmiTagInt32AndJumpIfFail(
      res, value,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, Register object, Register value,
             Register scratch, ZoneLabelRef done, Int32ToNumber* node) {
            MaglevAssembler::TemporaryRegisterScope temps(masm);
            // AllocateHeapNumber needs a scratch register, and the res scratch
            // register isn't needed anymore, so return it to the pool.
            if (scratch.is_valid()) {
              temps.IncludeScratch(scratch);
            }
            DoubleRegister double_value = temps.AcquireScratchDouble();
            __ Int32ToDouble(double_value, value);
            __ AllocateHeapNumber(node->register_snapshot(), object,
                                  double_value);
            __ Jump(*done);
          },
          object, value, input_output_alias ? res : Register::no_reg(), done,
          this));
  if (input_output_alias) {
    __ Move(object, res);
  }
  __ bind(*done);
}

void Uint32ToNumber::SetValueLocationConstraints() {
  UseRegister(input());
#ifdef V8_TARGET_ARCH_X64
  // We emit slightly more efficient code if result is the same as input.
  DefineSameAsFirst(this);
#else
  DefineAsRegister(this);
#endif
}
void Uint32ToNumber::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  ZoneLabelRef done(masm);
  Register value = ToRegister(input());
  Register object = ToRegister(result());
  // Unlike Int32ToNumber, object is allowed to alias value here (indeed, the
  // code is better if it does). The difference is that Uint32 smi tagging first
  // does a range check, and doesn't clobber `object` on failure.
  __ SmiTagUint32AndJumpIfFail(
      object, value,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, Register object, Register value,
             ZoneLabelRef done, Uint32ToNumber* node) {
            MaglevAssembler::TemporaryRegisterScope temps(masm);
            DoubleRegister double_value = temps.AcquireScratchDouble();
            __ Uint32ToDouble(double_value, value);
            __ AllocateHeapNumber(node->register_snapshot(), object,
                                  double_value);
            __ Jump(*done);
          },
          object, value, done, this));
  __ bind(*done);
}

void Float64ToTagged::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void Float64ToTagged::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  Register object = ToRegister(result());
  Label box, done;
  if (canonicalize_smi()) {
    __ TryTruncateDoubleToInt32(object, value, &box);
    __ SmiTagInt32AndJumpIfFail(object, &box);
    __ Jump(&done, Label::kNear);
    __ bind(&box);
  }
  __ AllocateHeapNumber(register_snapshot(), object, value);
  if (canonicalize_smi()) {
    __ bind(&done);
  }
}

void Float64ToHeapNumberForField::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void Float64ToHeapNumberForField::GenerateCode(MaglevAssembler* masm,
                                               const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  Register object = ToRegister(result());
  __ AllocateHeapNumber(register_snapshot(), object, value);
}

void HoleyFloat64ToTagged::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void HoleyFloat64ToTagged::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  ZoneLabelRef done(masm);
  DoubleRegister value = ToDoubleRegister(input());
  Register object = ToRegister(result());
  Label box;
  if (canonicalize_smi()) {
    __ TryTruncateDoubleToInt32(object, value, &box);
    __ SmiTagInt32AndJumpIfFail(object, &box);
    __ Jump(*done, Label::kNear);
    __ bind(&box);
  }
  // Using return as scratch register.
  __ JumpIfHoleNan(
      value, ToRegister(result()),
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, Register object, ZoneLabelRef done) {
            // TODO(leszeks): Evaluate whether this is worth deferring.
            __ LoadRoot(object, RootIndex::kUndefinedValue);
            __ Jump(*done);
          },
          object, done));
  __ AllocateHeapNumber(register_snapshot(), object, value);
  __ bind(*done);
}

void Float64Round::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
  if (kind_ == Kind::kNearest) {
    set_double_temporaries_needed(1);
  }
}

void Int32AbsWithOverflow::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}

void Float64Abs::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}

void CheckedSmiTagFloat64::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void CheckedSmiTagFloat64::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  Register object = ToRegister(result());

  __ TryTruncateDoubleToInt32(
      object, value, __ GetDeoptLabel(this, DeoptimizeReason::kNotASmi));
  __ SmiTagInt32AndJumpIfFail(
      object, __ GetDeoptLabel(this, DeoptimizeReason::kNotASmi));
}

void StoreFloat64::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(value_input());
}
void StoreFloat64::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  Register object = ToRegister(object_input());
  DoubleRegister value = ToDoubleRegister(value_input());

  __ AssertNotSmi(object);
  __ StoreFloat64(FieldMemOperand(object, offset()), value);
}

void StoreTaggedFieldNoWriteBarrier::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(value_input());
}
void StoreTaggedFieldNoWriteBarrier::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register value = ToRegister(value_input());

  __ AssertNotSmi(object);
  __ StoreTaggedFieldNoWriteBarrier(object, offset(), value);
}

int StringAt::MaxCallStackArgs() const {
  DCHECK_EQ(Runtime::FunctionForId(Runtime::kStringCharCodeAt)->nargs, 2);
  return std::max(2, AllocateDescriptor::GetStackParameterCount());
}
void StringAt::SetValueLocationConstraints() {
  UseAndClobberRegister(string_input());
  UseAndClobberRegister(index_input());
  DefineAsRegister(this);
  set_temporaries_needed(1);
}
void StringAt::GenerateCode(MaglevAssembler* masm,
                            const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  Register result_string = ToRegister(result());
  Register string = ToRegister(string_input());
  Register index = ToRegister(index_input());
  Register char_code = string;

  ZoneLabelRef done(masm);
  Label cached_one_byte_string;

  RegisterSnapshot save_registers = register_snapshot();
  __ StringCharCodeOrCodePointAt(
      BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt, save_registers,
      char_code, string, index, scratch, Register::no_reg(),
      &cached_one_byte_string);
  __ StringFromCharCode(save_registers, &cached_one_byte_string, result_string,
                        char_code, scratch,
                        MaglevAssembler::CharCodeMaskMode::kValueIsInRange);
}

int BuiltinStringPrototypeCharCodeOrCodePointAt::MaxCallStackArgs() const {
  DCHECK_EQ(Runtime::FunctionForId(Runtime::kStringCharCodeAt)->nargs, 2);
  return 2;
}
void BuiltinStringPrototypeCharCodeOrCodePointAt::
    SetValueLocationConstraints() {
  UseAndClobberRegister(string_input());
  UseAndClobberRegister(index_input());
  DefineAsRegister(this);
  // TODO(victorgomes): Add a mode to the register allocator where we ensure
  // input cannot alias with output. We can then remove the second scratch.
  set_temporaries_needed(
      mode_ == BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt ? 2
                                                                         : 1);
}
void BuiltinStringPrototypeCharCodeOrCodePointAt::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch1 = temps.Acquire();
  Register scratch2 = Register::no_reg();
  if (mode_ == BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt) {
    scratch2 = temps.Acquire();
  }
  Register string = ToRegister(string_input());
  Register index = ToRegister(index_input());
  ZoneLabelRef done(masm);
  RegisterSnapshot save_registers = register_snapshot();
  __ StringCharCodeOrCodePointAt(mode_, save_registers, ToRegister(result()),
                                 string, index, scratch1, scratch2, *done);
  __ bind(*done);
}

void StringLength::SetValueLocationConstraints() {
  UseRegister(object_input());
  DefineAsRegister(this);
}
void StringLength::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  __ StringLength(ToRegister(result()), ToRegister(object_input()));
}

void StringConcat::SetValueLocationConstraints() {
  using D = StringAdd_CheckNoneDescriptor;
  UseFixed(lhs(), D::GetRegisterParameter(D::kLeft));
  UseFixed(rhs(), D::GetRegisterParameter(D::kRight));
  DefineAsFixed(this, kReturnRegister0);
}
void StringConcat::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  __ CallBuiltin<Builtin::kStringAdd_CheckNone>(
      masm->native_context().object(),  // context
      lhs(),                            // left
      rhs()                             // right
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
  DCHECK_EQ(kReturnRegister0, ToRegister(result()));
}

void StringWrapperConcat::SetValueLocationConstraints() {
  using D = StringAdd_CheckNoneDescriptor;
  UseFixed(lhs(), D::GetRegisterParameter(D::kLeft));
  UseFixed(rhs(), D::GetRegisterParameter(D::kRight));
  DefineAsFixed(this, kReturnRegister0);
}

void StringWrapperConcat::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);

  Register left = ToRegister(lhs());
  Label left_done;
  __ JumpIfString(left, &left_done);
  __ LoadTaggedField(left, left, JSPrimitiveWrapper::kValueOffset);
  __ Jump(&left_done);

  __ bind(&left_done);

  Register right = ToRegister(rhs());
  Label right_done;
  __ JumpIfString(right, &right_done);
  __ LoadTaggedField(right, right, JSPrimitiveWrapper::kValueOffset);
  __ Jump(&right_done);

  __ bind(&right_done);

  __ CallBuiltin<Builtin::kStringAdd_CheckNone>(
      masm->native_context().object(),  // context
      left,                             // left
      right                             // right
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
  DCHECK_EQ(kReturnRegister0, ToRegister(result()));
}

void StringEqual::SetValueLocationConstraints() {
  using D = StringEqualDescriptor;
  UseFixed(lhs(), D::GetRegisterParameter(D::kLeft));
  UseFixed(rhs(), D::GetRegisterParameter(D::kRight));
  set_temporaries_needed(1);
  RequireSpecificTemporary(D::GetRegisterParameter(D::kLength));
  DefineAsFixed(this, kReturnRegister0);
}
void StringEqual::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  using D = StringEqualDescriptor;
  Label done, if_equal, if_not_equal;
  Register left = ToRegister(lhs());
  Register right = ToRegister(rhs());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register left_length = temps.Acquire();
  Register right_length = D::GetRegisterParameter(D::kLength);

  __ CmpTagged(left, right);
  __ JumpIf(kEqual, &if_equal,
            // Debug checks in StringLength can make this jump too long for a
            // near jump.
            v8_flags.debug_code ? Label::kFar : Label::kNear);

  __ StringLength(left_length, left);
  __ StringLength(right_length, right);
  __ CompareInt32AndJumpIf(left_length, right_length, kNotEqual, &if_not_equal,
                           Label::Distance::kNear);

  // The inputs are already in the right registers. The |left| and |right|
  // inputs were required to come in in the left/right inputs of the builtin,
  // and the |length| input of the builtin is where we loaded the length of the
  // right string (which matches the length of the left string when we get
  // here).
  DCHECK_EQ(right_length, D::GetRegisterParameter(D::kLength));
  __ CallBuiltin<Builtin::kStringEqual>(lhs(), rhs(),
                                        D::GetRegisterParameter(D::kLength));
  masm->DefineLazyDeoptPoint(this->lazy_deopt_info());
  __ Jump(&done, Label::Distance::kNear);

  __ bind(&if_equal);
  __ LoadRoot(ToRegister(result()), RootIndex::kTrueValue);
  __ Jump(&done, Label::Distance::kNear);

  __ bind(&if_not_equal);
  __ LoadRoot(ToRegister(result()), RootIndex::kFalseValue);

  __ bind(&done);
}

void TaggedEqual::SetValueLocationConstraints() {
  UseRegister(lhs());
  UseRegister(rhs());
  DefineAsRegister(this);
}
void TaggedEqual::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  Label done, if_equal;
  __ CmpTagged(ToRegister(lhs()), ToRegister(rhs()));
  __ JumpIf(kEqual, &if_equal, Label::Distance::kNear);
  __ LoadRoot(ToRegister(result()), RootIndex::kFalseValue);
  __ Jump(&done);
  __ bind(&if_equal);
  __ LoadRoot(ToRegister(result()), RootIndex::kTrueValue);
  __ bind(&done);
}

void TaggedNotEqual::SetValueLocationConstraints() {
  UseRegister(lhs());
  UseRegister(rhs());
  DefineAsRegister(this);
}
void TaggedNotEqual::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  Label done, if_equal;
  __ CmpTagged(ToRegister(lhs()), ToRegister(rhs()));
  __ JumpIf(kEqual, &if_equal, Label::Distance::kNear);
  __ LoadRoot(ToRegister(result()), RootIndex::kTrueValue);
  __ Jump(&done);
  __ bind(&if_equal);
  __ LoadRoot(ToRegister(result()), RootIndex::kFalseValue);
  __ bind(&done);
}

int TestInstanceOf::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kInstanceOf_WithFeedback>::type;
  return D::GetStackParameterCount();
}
void TestInstanceOf::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kInstanceOf_WithFeedback>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(object(), D::GetRegisterParameter(D::kLeft));
  UseFixed(callable(), D::GetRegisterParameter(D::kRight));
  DefineAsFixed(this, kReturnRegister0);
}
void TestInstanceOf::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  __ CallBuiltin<Builtin::kInstanceOf_WithFeedback>(
      context(),           // context
      object(),            // left
      callable(),          // right
      feedback().index(),  // feedback slot
      feedback().vector    // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void TestTypeOf::SetValueLocationConstraints() {
  UseRegister(value());
  DefineAsRegister(this);
#ifdef V8_TARGET_ARCH_ARM
  set_temporaries_needed(1);
#endif
}
void TestTypeOf::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
#ifdef V8_TARGET_ARCH_ARM
  // Arm32 needs one extra scratch register for TestTypeOf, so take a maglev
  // temporary and allow it to be used as a macro assembler scratch register.
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  temps.IncludeScratch(temps.Acquire());
#endif
  Register object = ToRegister(value());
  Label is_true, is_false, done;
  __ TestTypeOf(object, literal_, &is_true, Label::Distance::kNear, true,
                &is_false, Label::Distance::kNear, false);
  // Fallthrough into true.
  __ bind(&is_true);
  __ LoadRoot(ToRegister(result()), RootIndex::kTrueValue);
  __ Jump(&done, Label::Distance::kNear);
  __ bind(&is_false);
  __ LoadRoot(ToRegister(result()), RootIndex::kFalseValue);
  __ bind(&done);
}

void ToBoolean::SetValueLocationConstraints() {
  UseRegister(value());
  DefineAsRegister(this);
}
void ToBoolean::GenerateCode(MaglevAssembler* masm,
                             const ProcessingState& state) {
  Register object = ToRegister(value());
  Register return_value = ToRegister(result());
  Label done;
  ZoneLabelRef object_is_true(masm), object_is_false(masm);
  // TODO(leszeks): We're likely to be calling this on an existing boolean --
  // maybe that's a case we should fast-path here and re-use that boolean value?
  __ ToBoolean(object, check_type(), object_is_true, object_is_false, true);
  __ bind(*object_is_true);
  __ LoadRoot(return_value, RootIndex::kTrueValue);
  __ Jump(&done);
  __ bind(*object_is_false);
  __ LoadRoot(return_value, RootIndex::kFalseValue);
  __ bind(&done);
}

void ToBooleanLogicalNot::SetValueLocationConstraints() {
  UseRegister(value());
  DefineAsRegister(this);
}
void ToBooleanLogicalNot::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  Register object = ToRegister(value());
  Register return_value = ToRegister(result());
  Label done;
  ZoneLabelRef object_is_true(masm), object_is_false(masm);
  __ ToBoolean(object, check_type(), object_is_true, object_is_false, true);
  __ bind(*object_is_true);
  __ LoadRoot(return_value, RootIndex::kFalseValue);
  __ Jump(&done);
  __ bind(*object_is_false);
  __ LoadRoot(return_value, RootIndex::kTrueValue);
  __ bind(&done);
}

int ToName::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kToName>::type;
  return D::GetStackParameterCount();
}
void ToName::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kToName>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(value_input(), D::GetRegisterParameter(D::kInput));
  DefineAsFixed(this, kReturnRegister0);
}
void ToName::GenerateCode(MaglevAssembler* masm, const ProcessingState& state) {
  __ CallBuiltin<Builtin::kToName>(context(),     // context
                                   value_input()  // input
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int ToNumberOrNumeric::MaxCallStackArgs() const {
  return TypeConversionDescriptor::GetStackParameterCount();
}
void ToNumberOrNumeric::SetValueLocationConstraints() {
  UseRegister(value_input());
  set_temporaries_needed(1);
  DefineAsRegister(this);
}
void ToNumberOrNumeric::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  ZoneLabelRef done(masm);
  Label move_and_return;
  Register object = ToRegister(value_input());
  Register result_reg = ToRegister(result());

  __ JumpIfSmi(object, &move_and_return, Label::kNear);
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ CompareMapWithRoot(object, RootIndex::kHeapNumberMap, scratch);
  __ JumpToDeferredIf(
      kNotEqual,
      [](MaglevAssembler* masm, Object::Conversion mode, Register object,
         Register result_reg, ToNumberOrNumeric* node, ZoneLabelRef done) {
        {
          RegisterSnapshot snapshot = node->register_snapshot();
          snapshot.live_registers.clear(result_reg);
          SaveRegisterStateForCall save_register_state(masm, snapshot);
          switch (mode) {
            case Object::Conversion::kToNumber:
              __ CallBuiltin<Builtin::kToNumber>(
                  masm->native_context().object(), object);
              break;
            case Object::Conversion::kToNumeric:
              __ CallBuiltin<Builtin::kToNumeric>(
                  masm->native_context().object(), object);
              break;
          }
          masm->DefineExceptionHandlerPoint(node);
          save_register_state.DefineSafepointWithLazyDeopt(
              node->lazy_deopt_info());
          __ Move(result_reg, kReturnRegister0);
        }
        __ Jump(*done);
      },
      mode(), object, result_reg, this, done);
  __ bind(&move_and_return);
  __ Move(result_reg, object);

  __ bind(*don
"""


```