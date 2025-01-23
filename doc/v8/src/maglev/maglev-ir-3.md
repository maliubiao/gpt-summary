Response: The user wants a summary of the C++ source code file `v8/src/maglev/maglev-ir.cc`.
They also want to know how it relates to JavaScript, with examples.
This is part 4 of a 5-part series, suggesting the file contains definitions for different parts of the Maglev Intermediate Representation (IR).

Based on the provided code, I can see definitions for various IR nodes related to:
- **Type conversion:** `ToObject`, `ToString`, `NumberToString`
- **Error handling:** `ThrowReferenceErrorIfHole`, `ThrowSuperNotCalledIfHole`, `ThrowSuperAlreadyCalledIfNotHole`, `ThrowIfNotCallable`, `ThrowIfNotSuperConstructor`
- **Number manipulation:** `TruncateUint32ToInt32`, `TruncateFloat64ToInt32`, `CheckedTruncateFloat64ToInt32`, `CheckedTruncateFloat64ToUint32`, `UnsafeTruncateFloat64ToInt32`, `CheckedUint32ToInt32`, `UnsafeTruncateUint32ToInt32`, `Int32ToUint8Clamped`, `Uint32ToUint8Clamped`, `Float64ToUint8Clamped`, `CheckedNumberToUint8Clamped`
- **Type checking:** `CheckNumber`, `CheckedInternalizedString`
- **Array manipulation:** `StoreFixedArrayElementWithWriteBarrier`, `StoreFixedArrayElementNoWriteBarrier`
- **Function calls:** `Call`, `CallForwardVarargs`, `CallSelf`, `CallKnownJSFunction`, `CallKnownApiFunction`, `CallBuiltin`, `CallCPPBuiltin`, `CallRuntime`, `CallWithSpread`, `CallWithArrayLike`, `Construct`, `ConstructWithSpread`
- **Message handling:** `SetPendingMessage`
- **Field access:** `StoreDoubleField`
- **Object property transitions:** `TransitionElementsKind`, `TransitionElementsKindOrCheckMap`
- **Typed array operations:** `CheckTypedArrayNotDetached`, `GetContinuationPreservedEmbedderData`, `SetContinuationPreservedEmbedderData`, `LoadSignedIntTypedArrayElement`, `LoadUnsignedIntTypedArrayElement`, `LoadDoubleTypedArrayElement`, `StoreIntTypedArrayElement`, `StoreDoubleTypedArrayElement`
- **Control flow:** `Jump`, `CheckpointedJump`, `TryOnStackReplacement`, `JumpLoop`, `BranchIfSmi`, `BranchIfRootConstant`, `BranchIfToBooleanTrue`

These nodes represent operations performed during the execution of JavaScript code. The `GenerateCode` methods within each node definition seem responsible for emitting machine code for the corresponding operation.

I will now structure the summary and provide JavaScript examples where applicable.
这个C++源代码文件 `v8/src/maglev/maglev-ir.cc` 的第 4 部分，主要定义了 Maglev 编译器中间表示 (IR) 中的多种操作节点 (Nodes)。这些节点代表了在执行 JavaScript 代码期间可能发生的各种操作，是 Maglev 编译器将 JavaScript 代码转换为机器码的关键抽象层。

以下是该部分代码功能的归纳：

**主要功能:**

该部分定义了大量 Maglev IR 节点，这些节点涵盖了以下几个主要的 JavaScript 功能领域：

1. **类型转换和检查:**
   - 定义了将 JavaScript 值转换为特定类型的节点，例如 `ToObject`（转换为对象）、`ToString`（转换为字符串）、`NumberToString`（转换为数字字符串）。
   - 定义了检查值类型的节点，例如 `CheckNumber`（检查是否为数字）、`CheckedInternalizedString`（检查是否为内部化字符串）。

2. **错误处理:**
   - 定义了在特定条件下抛出 JavaScript 错误的节点，例如 `ThrowReferenceErrorIfHole`（如果访问了未初始化的变量则抛出引用错误）、`ThrowIfNotCallable`（如果值不可调用则抛出错误）。

3. **数值操作:**
   - 定义了对数值进行转换和操作的节点，例如各种 `Truncate` 节点（截断浮点数或无符号整数为有符号整数）、各种 `ToUint8Clamped` 节点（将数值限制在 0-255 范围内）。

4. **数组和对象操作:**
   - 定义了操作数组元素的节点，例如 `StoreFixedArrayElementWithWriteBarrier` 和 `StoreFixedArrayElementNoWriteBarrier`（存储固定数组元素，带或不带写屏障）。
   - 定义了存储双精度浮点数字段的节点 `StoreDoubleField`。
   - 定义了对象属性转换相关的节点 `TransitionElementsKind` 和 `TransitionElementsKindOrCheckMap`。

5. **函数调用和构造:**
   - 定义了各种函数调用节点，例如 `Call`（普通调用）、`CallForwardVarargs`（转发可变参数的调用）、`CallSelf`（调用自身）、`CallKnownJSFunction`（调用已知的 JavaScript 函数）、`CallKnownApiFunction`（调用已知的 C++ API 函数）、`CallBuiltin`（调用内置函数）、`CallCPPBuiltin`（调用 C++ 内置函数）、`CallRuntime`（调用运行时函数）、`CallWithSpread`（使用展开语法的调用）、`CallWithArrayLike`（使用类数组对象的调用）。
   - 定义了对象构造节点 `Construct` 和 `ConstructWithSpread`。

6. **控制流:**
   - 定义了控制流跳转节点，例如 `Jump`（无条件跳转）、`CheckpointedJump`（带检查点的跳转）、`JumpLoop`（循环跳转）。
   - 定义了条件分支节点，例如 `BranchIfSmi`（如果值为 Smi 则分支）、`BranchIfRootConstant`（如果值等于根常量则分支）、`BranchIfToBooleanTrue`（如果转换为布尔值为真则分支）。
   - 定义了尝试栈上替换 (OSR) 的节点 `TryOnStackReplacement`。

7. **类型化数组操作:**
   - 定义了检查类型化数组是否已分离的节点 `CheckTypedArrayNotDetached`。
   - 定义了加载和存储类型化数组元素的节点，例如 `LoadSignedIntTypedArrayElement`、`LoadUnsignedIntTypedArrayElement`、`LoadDoubleTypedArrayElement`、`StoreIntTypedArrayElement`、`StoreDoubleTypedArrayElement`。

8. **其他操作:**
   - 定义了设置待处理消息的节点 `SetPendingMessage`。
   - 定义了获取和设置 continuation preserved embedder data 的节点 `GetContinuationPreservedEmbedderData` 和 `SetContinuationPreservedEmbedderData`。

**与 JavaScript 的关系以及 JavaScript 示例:**

这些 Maglev IR 节点直接对应着 JavaScript 语言的各种操作。Maglev 编译器会将 JavaScript 源代码解析成抽象语法树 (AST)，然后将 AST 转换为 Maglev IR。每个 IR 节点都代表了执行 JavaScript 代码的一个步骤。

以下是一些节点与 JavaScript 功能对应的示例：

**1. `ToObject` (转换为对象):**

```javascript
let primitiveValue = 10;
let objectValue = Object(primitiveValue); // 显式转换
console.log(typeof objectValue); // 输出 "object"

// 某些操作会隐式调用 ToObject
function foo(obj) {
  console.log(obj.toString());
}
foo(null); // null 会被转换为 Object(null)
```

**2. `ToString` (转换为字符串):**

```javascript
let numberValue = 123;
let stringValue = String(numberValue); // 显式转换
console.log(typeof stringValue); // 输出 "string"

// 模板字符串也会调用 ToString
let name = "World";
let greeting = `Hello, ${name}!`;
```

**3. `ThrowReferenceErrorIfHole` (抛出引用错误):**

```javascript
console.log(nonExistentVariable); // ReferenceError: nonExistentVariable is not defined

let initializedLater;
console.log(initializedLater); // 输出 undefined
// 在 'initializedLater' 赋值前访问会得到 'undefined'，
// 但在某些情况下，如果 V8 内部认为该变量应该已经被初始化但却是一个 "hole" (未初始化)，
// 则会抛出 ReferenceError。这种情况通常发生在临时死区 (TDZ) 内。
```

**4. `Call` (普通调用) 和 `CallKnownJSFunction` (调用已知的 JavaScript 函数):**

```javascript
function add(a, b) {
  return a + b;
}
let sum = add(5, 3); // 调用 add 函数

let obj = {
  method: function() {
    console.log("Method called");
  }
};
obj.method(); // 调用对象的方法
```

**5. `Construct` (对象构造):**

```javascript
class MyClass {
  constructor(name) {
    this.name = name;
  }
}
let instance = new MyClass("Example"); // 使用 new 关键字构造对象
console.log(instance.name); // 输出 "Example"
```

**6. `BranchIfSmi` (如果值为 Smi 则分支):**

```javascript
function processValue(value) {
  if (typeof value === 'number' && Number.isInteger(value) && value >= -2**31 && value < 2**31) {
    console.log("Value is a small integer (Smi)");
  } else {
    console.log("Value is not a small integer");
  }
}

processValue(10); // 输出 "Value is a small integer (Smi)"
processValue(2**31); // 输出 "Value is not a small integer"
```

**总结:**

`v8/src/maglev/maglev-ir.cc` 的这部分代码是 Maglev 编译器实现的关键组成部分。它定义了用于表示 JavaScript 各种操作的中间表示节点，这些节点使得编译器能够将高级的 JavaScript 代码转换为底层的机器码，从而实现高效的 JavaScript 执行。理解这些 IR 节点的功能有助于深入理解 V8 引擎的编译和执行过程。

### 提示词
```
这是目录为v8/src/maglev/maglev-ir.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
e);
}

int ToObject::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kToObject>::type;
  return D::GetStackParameterCount();
}
void ToObject::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kToObject>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(value_input(), D::GetRegisterParameter(D::kInput));
  DefineAsFixed(this, kReturnRegister0);
}
void ToObject::GenerateCode(MaglevAssembler* masm,
                            const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Label call_builtin, done;
  // Avoid the builtin call if {value} is a JSReceiver.
  if (check_type() == CheckType::kOmitHeapObjectCheck) {
    __ AssertNotSmi(value);
  } else {
    __ JumpIfSmi(value, &call_builtin, Label::Distance::kNear);
  }
  __ JumpIfJSAnyIsNotPrimitive(value, &done, Label::Distance::kNear);
  __ bind(&call_builtin);
  __ CallBuiltin<Builtin::kToObject>(context(),     // context
                                     value_input()  // input
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
  __ bind(&done);
}

int ToString::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kToString>::type;
  return D::GetStackParameterCount();
}
void ToString::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kToString>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(value_input(), D::GetRegisterParameter(D::kO));
  DefineAsFixed(this, kReturnRegister0);
}
void ToString::GenerateCode(MaglevAssembler* masm,
                            const ProcessingState& state) {
  Register value = ToRegister(value_input());
  Label call_builtin, done;
  // Avoid the builtin call if {value} is a string.
  __ JumpIfSmi(value, &call_builtin, Label::Distance::kNear);
  __ JumpIfString(value, &done, Label::Distance::kNear);
  if (mode() == kConvertSymbol) {
    __ JumpIfNotObjectType(value, SYMBOL_TYPE, &call_builtin,
                           Label::Distance::kNear);
    __ Push(value);
    __ CallRuntime(Runtime::kSymbolDescriptiveString, 1);
    __ Jump(&done, Label::kNear);
  }
  __ bind(&call_builtin);
  __ CallBuiltin<Builtin::kToString>(context(),     // context
                                     value_input()  // input
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
  __ bind(&done);
}

void NumberToString::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kNumberToString>::type;
  UseFixed(value_input(), D::GetRegisterParameter(D::kInput));
  DefineAsFixed(this, kReturnRegister0);
}
void NumberToString::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  __ CallBuiltin<Builtin::kNumberToString>(value_input());
  masm->DefineLazyDeoptPoint(this->lazy_deopt_info());
}

int ThrowReferenceErrorIfHole::MaxCallStackArgs() const { return 1; }
void ThrowReferenceErrorIfHole::SetValueLocationConstraints() {
  UseAny(value());
}
void ThrowReferenceErrorIfHole::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  __ JumpToDeferredIf(
      __ IsRootConstant(value(), RootIndex::kTheHoleValue),
      [](MaglevAssembler* masm, ThrowReferenceErrorIfHole* node) {
        __ Push(node->name().object());
        __ Move(kContextRegister, masm->native_context().object());
        __ CallRuntime(Runtime::kThrowAccessedUninitializedVariable, 1);
        masm->DefineExceptionHandlerAndLazyDeoptPoint(node);
        __ Abort(AbortReason::kUnexpectedReturnFromThrow);
      },
      this);
}

int ThrowSuperNotCalledIfHole::MaxCallStackArgs() const { return 0; }
void ThrowSuperNotCalledIfHole::SetValueLocationConstraints() {
  UseAny(value());
}
void ThrowSuperNotCalledIfHole::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  __ JumpToDeferredIf(
      __ IsRootConstant(value(), RootIndex::kTheHoleValue),
      [](MaglevAssembler* masm, ThrowSuperNotCalledIfHole* node) {
        __ Move(kContextRegister, masm->native_context().object());
        __ CallRuntime(Runtime::kThrowSuperNotCalled, 0);
        masm->DefineExceptionHandlerAndLazyDeoptPoint(node);
        __ Abort(AbortReason::kUnexpectedReturnFromThrow);
      },
      this);
}

int ThrowSuperAlreadyCalledIfNotHole::MaxCallStackArgs() const { return 0; }
void ThrowSuperAlreadyCalledIfNotHole::SetValueLocationConstraints() {
  UseAny(value());
}
void ThrowSuperAlreadyCalledIfNotHole::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  __ JumpToDeferredIf(
      NegateCondition(__ IsRootConstant(value(), RootIndex::kTheHoleValue)),
      [](MaglevAssembler* masm, ThrowSuperAlreadyCalledIfNotHole* node) {
        __ Move(kContextRegister, masm->native_context().object());
        __ CallRuntime(Runtime::kThrowSuperAlreadyCalledError, 0);
        masm->DefineExceptionHandlerAndLazyDeoptPoint(node);
        __ Abort(AbortReason::kUnexpectedReturnFromThrow);
      },
      this);
}

int ThrowIfNotCallable::MaxCallStackArgs() const { return 1; }
void ThrowIfNotCallable::SetValueLocationConstraints() {
  UseRegister(value());
  set_temporaries_needed(1);
}
void ThrowIfNotCallable::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  Label* if_not_callable = __ MakeDeferredCode(
      [](MaglevAssembler* masm, ThrowIfNotCallable* node) {
        __ Push(node->value());
        __ Move(kContextRegister, masm->native_context().object());
        __ CallRuntime(Runtime::kThrowCalledNonCallable, 1);
        masm->DefineExceptionHandlerAndLazyDeoptPoint(node);
        __ Abort(AbortReason::kUnexpectedReturnFromThrow);
      },
      this);

  Register value_reg = ToRegister(value());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ JumpIfNotCallable(value_reg, scratch, CheckType::kCheckHeapObject,
                       if_not_callable);
}

int ThrowIfNotSuperConstructor::MaxCallStackArgs() const { return 2; }
void ThrowIfNotSuperConstructor::SetValueLocationConstraints() {
  UseRegister(constructor());
  UseRegister(function());
  set_temporaries_needed(1);
}
void ThrowIfNotSuperConstructor::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ LoadMap(scratch, ToRegister(constructor()));
  static_assert(Map::kBitFieldOffsetEnd + 1 - Map::kBitFieldOffset == 1);
  __ TestUint8AndJumpIfAllClear(
      FieldMemOperand(scratch, Map::kBitFieldOffset),
      Map::Bits1::IsConstructorBit::kMask,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, ThrowIfNotSuperConstructor* node) {
            __ Push(ToRegister(node->constructor()),
                    ToRegister(node->function()));
            __ Move(kContextRegister, masm->native_context().object());
            __ CallRuntime(Runtime::kThrowNotSuperConstructor, 2);
            masm->DefineExceptionHandlerAndLazyDeoptPoint(node);
            __ Abort(AbortReason::kUnexpectedReturnFromThrow);
          },
          this));
}

void TruncateUint32ToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void TruncateUint32ToInt32::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  // No code emitted -- as far as the machine is concerned, int32 is uint32.
  DCHECK_EQ(ToRegister(input()), ToRegister(result()));
}

void TruncateFloat64ToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void TruncateFloat64ToInt32::GenerateCode(MaglevAssembler* masm,
                                          const ProcessingState& state) {
  __ TruncateDoubleToInt32(ToRegister(result()), ToDoubleRegister(input()));
}

void CheckedTruncateFloat64ToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void CheckedTruncateFloat64ToInt32::GenerateCode(MaglevAssembler* masm,
                                                 const ProcessingState& state) {
  __ TryTruncateDoubleToInt32(
      ToRegister(result()), ToDoubleRegister(input()),
      __ GetDeoptLabel(this, DeoptimizeReason::kNotInt32));
}

void CheckedTruncateFloat64ToUint32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void CheckedTruncateFloat64ToUint32::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  __ TryTruncateDoubleToUint32(
      ToRegister(result()), ToDoubleRegister(input()),
      __ GetDeoptLabel(this, DeoptimizeReason::kNotUint32));
}

void UnsafeTruncateFloat64ToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void UnsafeTruncateFloat64ToInt32::GenerateCode(MaglevAssembler* masm,
                                                const ProcessingState& state) {
#ifdef DEBUG
  Label fail, start;
  __ Jump(&start);
  __ bind(&fail);
  __ Abort(AbortReason::kFloat64IsNotAInt32);

  __ bind(&start);
  __ TryTruncateDoubleToInt32(ToRegister(result()), ToDoubleRegister(input()),
                              &fail);
#else
  // TODO(dmercadier): TruncateDoubleToInt32 does additional work when the
  // double doesn't fit in a 32-bit integer. This is not necessary for
  // UnsafeTruncateFloat64ToInt32 (since we statically know that it the double
  // fits in a 32-bit int) and could be instead just a Cvttsd2si (x64) or Fcvtzs
  // (arm64).
  __ TruncateDoubleToInt32(ToRegister(result()), ToDoubleRegister(input()));
#endif
}

void CheckedUint32ToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void CheckedUint32ToInt32::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register input_reg = ToRegister(input());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kNotInt32);
  __ CompareInt32AndJumpIf(input_reg, 0, kLessThan, fail);
}

void UnsafeTruncateUint32ToInt32::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void UnsafeTruncateUint32ToInt32::GenerateCode(MaglevAssembler* masm,
                                               const ProcessingState& state) {
#ifdef DEBUG
  Register input_reg = ToRegister(input());
  __ CompareInt32AndAssert(input_reg, 0, kGreaterThanEqual,
                           AbortReason::kUint32IsNotAInt32);
#endif
  // No code emitted -- as far as the machine is concerned, int32 is uint32.
  DCHECK_EQ(ToRegister(input()), ToRegister(result()));
}

void Int32ToUint8Clamped::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void Int32ToUint8Clamped::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  Register value = ToRegister(input());
  Register result_reg = ToRegister(result());
  DCHECK_EQ(value, result_reg);
  Label min, done;
  __ CompareInt32AndJumpIf(value, 0, kLessThanEqual, &min);
  __ CompareInt32AndJumpIf(value, 255, kLessThanEqual, &done);
  __ Move(result_reg, 255);
  __ Jump(&done, Label::Distance::kNear);
  __ bind(&min);
  __ Move(result_reg, 0);
  __ bind(&done);
}

void Uint32ToUint8Clamped::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
}
void Uint32ToUint8Clamped::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  Register value = ToRegister(input());
  DCHECK_EQ(value, ToRegister(result()));
  Label done;
  __ CompareInt32AndJumpIf(value, 255, kUnsignedLessThanEqual, &done,
                           Label::Distance::kNear);
  __ Move(value, 255);
  __ bind(&done);
}

void Float64ToUint8Clamped::SetValueLocationConstraints() {
  UseRegister(input());
  DefineAsRegister(this);
}
void Float64ToUint8Clamped::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  DoubleRegister value = ToDoubleRegister(input());
  Register result_reg = ToRegister(result());
  Label min, max, done;
  __ ToUint8Clamped(result_reg, value, &min, &max, &done);
  __ bind(&min);
  __ Move(result_reg, 0);
  __ Jump(&done, Label::Distance::kNear);
  __ bind(&max);
  __ Move(result_reg, 255);
  __ bind(&done);
}

void CheckNumber::SetValueLocationConstraints() {
  UseRegister(receiver_input());
}
void CheckNumber::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  Label done;
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  Register value = ToRegister(receiver_input());
  // If {value} is a Smi or a HeapNumber, we're done.
  __ JumpIfSmi(
      value, &done,
      v8_flags.debug_code ? Label::Distance::kFar : Label::Distance::kNear);
  if (mode() == Object::Conversion::kToNumeric) {
    __ LoadMapForCompare(scratch, value);
    __ CompareTaggedRoot(scratch, RootIndex::kHeapNumberMap);
    // Jump to done if it is a HeapNumber.
    __ JumpIf(
        kEqual, &done,
        v8_flags.debug_code ? Label::Distance::kFar : Label::Distance::kNear);
    // Check if it is a BigInt.
    __ CompareTaggedRootAndEmitEagerDeoptIf(
        scratch, RootIndex::kBigIntMap, kNotEqual,
        DeoptimizeReason::kNotANumber, this);
  } else {
    __ CompareMapWithRootAndEmitEagerDeoptIf(
        value, RootIndex::kHeapNumberMap, scratch, kNotEqual,
        DeoptimizeReason::kNotANumber, this);
  }
  __ bind(&done);
}

void CheckedInternalizedString::SetValueLocationConstraints() {
  UseRegister(object_input());
  DefineSameAsFirst(this);
}
void CheckedInternalizedString::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  Register object = ToRegister(object_input());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register instance_type = temps.AcquireScratch();
  if (check_type() == CheckType::kOmitHeapObjectCheck) {
    __ AssertNotSmi(object);
  } else {
    __ EmitEagerDeoptIfSmi(this, object, DeoptimizeReason::kWrongMap);
  }
  __ LoadInstanceType(instance_type, object);
  __ RecordComment("Test IsInternalizedString");
  // Go to the slow path if this is a non-string, or a non-internalised string.
  static_assert((kStringTag | kInternalizedTag) == 0);
  ZoneLabelRef done(masm);
  __ TestInt32AndJumpIfAnySet(
      instance_type, kIsNotStringMask | kIsNotInternalizedMask,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, ZoneLabelRef done,
             CheckedInternalizedString* node, Register object,
             Register instance_type) {
            __ RecordComment("Deferred Test IsThinString");
            // Deopt if this isn't a string.
            __ TestInt32AndJumpIfAnySet(
                instance_type, kIsNotStringMask,
                __ GetDeoptLabel(node, DeoptimizeReason::kWrongMap));
            // Deopt if this isn't a thin string.
            static_assert(base::bits::CountPopulation(kThinStringTagBit) == 1);
            __ TestInt32AndJumpIfAllClear(
                instance_type, kThinStringTagBit,
                __ GetDeoptLabel(node, DeoptimizeReason::kWrongMap));
            // Load internalized string from thin string.
            __ LoadTaggedField(object, object, offsetof(ThinString, actual_));
            if (v8_flags.debug_code) {
              __ RecordComment("DCHECK IsInternalizedString");
              Label checked;
              __ LoadInstanceType(instance_type, object);
              __ TestInt32AndJumpIfAllClear(
                  instance_type, kIsNotStringMask | kIsNotInternalizedMask,
                  &checked);
              __ Abort(AbortReason::kUnexpectedValue);
              __ bind(&checked);
            }
            __ Jump(*done);
          },
          done, this, object, instance_type));
  __ bind(*done);
}

void CheckedNumberToUint8Clamped::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
  set_temporaries_needed(1);
  set_double_temporaries_needed(1);
}
void CheckedNumberToUint8Clamped::GenerateCode(MaglevAssembler* masm,
                                               const ProcessingState& state) {
  Register value = ToRegister(input());
  Register result_reg = ToRegister(result());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  DoubleRegister double_value = temps.AcquireDouble();
  Label is_not_smi, min, max, done;
  // Check if Smi.
  __ JumpIfNotSmi(value, &is_not_smi);
  // If Smi, convert to Int32.
  __ SmiToInt32(value);
  // Clamp.
  __ CompareInt32AndJumpIf(value, 0, kLessThanEqual, &min);
  __ CompareInt32AndJumpIf(value, 255, kGreaterThanEqual, &max);
  __ Jump(&done);
  __ bind(&is_not_smi);
  // Check if HeapNumber, deopt otherwise.
  __ CompareMapWithRootAndEmitEagerDeoptIf(value, RootIndex::kHeapNumberMap,
                                           scratch, kNotEqual,
                                           DeoptimizeReason::kNotANumber, this);
  // If heap number, get double value.
  __ LoadHeapNumberValue(double_value, value);
  // Clamp.
  __ ToUint8Clamped(value, double_value, &min, &max, &done);
  __ bind(&min);
  __ Move(result_reg, 0);
  __ Jump(&done, Label::Distance::kNear);
  __ bind(&max);
  __ Move(result_reg, 255);
  __ bind(&done);
}

void StoreFixedArrayElementWithWriteBarrier::SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(index_input());
  UseRegister(value_input());
  RequireSpecificTemporary(WriteBarrierDescriptor::ObjectRegister());
  RequireSpecificTemporary(WriteBarrierDescriptor::SlotAddressRegister());
}
void StoreFixedArrayElementWithWriteBarrier::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register elements = ToRegister(elements_input());
  Register index = ToRegister(index_input());
  Register value = ToRegister(value_input());
  __ StoreFixedArrayElementWithWriteBarrier(elements, index, value,
                                            register_snapshot());
}

void StoreFixedArrayElementNoWriteBarrier::SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(index_input());
  UseRegister(value_input());
}
void StoreFixedArrayElementNoWriteBarrier::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register elements = ToRegister(elements_input());
  Register index = ToRegister(index_input());
  Register value = ToRegister(value_input());
  __ StoreFixedArrayElementNoWriteBarrier(elements, index, value);
}

// ---
// Arch agnostic call nodes
// ---

int Call::MaxCallStackArgs() const { return num_args(); }
void Call::SetValueLocationConstraints() {
  using D = CallTrampolineDescriptor;
  UseFixed(function(), D::GetRegisterParameter(D::kFunction));
  UseAny(arg(0));
  for (int i = 1; i < num_args(); i++) {
    UseAny(arg(i));
  }
  UseFixed(context(), kContextRegister);
  DefineAsFixed(this, kReturnRegister0);
}

void Call::GenerateCode(MaglevAssembler* masm, const ProcessingState& state) {
  __ PushReverse(args());

  uint32_t arg_count = num_args();
  if (target_type_ == TargetType::kAny) {
    switch (receiver_mode_) {
      case ConvertReceiverMode::kNullOrUndefined:
        __ CallBuiltin<Builtin::kCall_ReceiverIsNullOrUndefined>(
            context(), function(), arg_count);
        break;
      case ConvertReceiverMode::kNotNullOrUndefined:
        __ CallBuiltin<Builtin::kCall_ReceiverIsNotNullOrUndefined>(
            context(), function(), arg_count);
        break;
      case ConvertReceiverMode::kAny:
        __ CallBuiltin<Builtin::kCall_ReceiverIsAny>(context(), function(),
                                                     arg_count);
        break;
    }
  } else {
    DCHECK_EQ(TargetType::kJSFunction, target_type_);
    switch (receiver_mode_) {
      case ConvertReceiverMode::kNullOrUndefined:
        __ CallBuiltin<Builtin::kCallFunction_ReceiverIsNullOrUndefined>(
            context(), function(), arg_count);
        break;
      case ConvertReceiverMode::kNotNullOrUndefined:
        __ CallBuiltin<Builtin::kCallFunction_ReceiverIsNotNullOrUndefined>(
            context(), function(), arg_count);
        break;
      case ConvertReceiverMode::kAny:
        __ CallBuiltin<Builtin::kCallFunction_ReceiverIsAny>(
            context(), function(), arg_count);
        break;
    }
  }

  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CallForwardVarargs::MaxCallStackArgs() const { return num_args(); }
void CallForwardVarargs::SetValueLocationConstraints() {
  using D = CallTrampolineDescriptor;
  UseFixed(function(), D::GetRegisterParameter(D::kFunction));
  UseAny(arg(0));
  for (int i = 1; i < num_args(); i++) {
    UseAny(arg(i));
  }
  UseFixed(context(), kContextRegister);
  DefineAsFixed(this, kReturnRegister0);
}

void CallForwardVarargs::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  __ PushReverse(args());
  switch (target_type_) {
    case Call::TargetType::kJSFunction:
      __ CallBuiltin<Builtin::kCallFunctionForwardVarargs>(
          context(), function(), num_args(), start_index_);
      break;
    case Call::TargetType::kAny:
      __ CallBuiltin<Builtin::kCallForwardVarargs>(context(), function(),
                                                   num_args(), start_index_);
      break;
  }
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CallSelf::MaxCallStackArgs() const {
  int actual_parameter_count = num_args() + 1;
  return std::max(expected_parameter_count_, actual_parameter_count);
}
void CallSelf::SetValueLocationConstraints() {
  UseAny(receiver());
  for (int i = 0; i < num_args(); i++) {
    UseAny(arg(i));
  }
  UseFixed(closure(), kJavaScriptCallTargetRegister);
  UseFixed(new_target(), kJavaScriptCallNewTargetRegister);
  UseFixed(context(), kContextRegister);
  DefineAsFixed(this, kReturnRegister0);
  set_temporaries_needed(1);
}

void CallSelf::GenerateCode(MaglevAssembler* masm,
                            const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  int actual_parameter_count = num_args() + 1;
  if (actual_parameter_count < expected_parameter_count_) {
    int number_of_undefineds =
        expected_parameter_count_ - actual_parameter_count;
    __ LoadRoot(scratch, RootIndex::kUndefinedValue);
    __ PushReverse(receiver(), args(),
                   RepeatValue(scratch, number_of_undefineds));
  } else {
    __ PushReverse(receiver(), args());
  }
  DCHECK_EQ(kContextRegister, ToRegister(context()));
  DCHECK_EQ(kJavaScriptCallTargetRegister, ToRegister(closure()));
  __ Move(kJavaScriptCallArgCountRegister, actual_parameter_count);
  DCHECK(!shared_function_info().HasBuiltinId());
  __ CallSelf();
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CallKnownJSFunction::MaxCallStackArgs() const {
  int actual_parameter_count = num_args() + 1;
  return std::max(expected_parameter_count_, actual_parameter_count);
}
void CallKnownJSFunction::SetValueLocationConstraints() {
  UseAny(receiver());
  for (int i = 0; i < num_args(); i++) {
    UseAny(arg(i));
  }
  UseFixed(closure(), kJavaScriptCallTargetRegister);
  UseFixed(new_target(), kJavaScriptCallNewTargetRegister);
  UseFixed(context(), kContextRegister);
  DefineAsFixed(this, kReturnRegister0);
  set_temporaries_needed(1);
}

void CallKnownJSFunction::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  int actual_parameter_count = num_args() + 1;
  if (actual_parameter_count < expected_parameter_count_) {
    int number_of_undefineds =
        expected_parameter_count_ - actual_parameter_count;
    __ LoadRoot(scratch, RootIndex::kUndefinedValue);
    __ PushReverse(receiver(), args(),
                   RepeatValue(scratch, number_of_undefineds));
  } else {
    __ PushReverse(receiver(), args());
  }
  // From here on, we're going to do a call, so all registers are valid temps,
  // except for the ones we're going to write. This is needed in case one of the
  // helper methods below wants to use a temp and one of these is in the temp
  // list (in particular, this can happen on arm64 where cp is a temp register
  // by default).
  temps.SetAvailable(MaglevAssembler::GetAllocatableRegisters() -
                     RegList{kContextRegister, kJavaScriptCallCodeStartRegister,
                             kJavaScriptCallTargetRegister,
                             kJavaScriptCallNewTargetRegister,
                             kJavaScriptCallArgCountRegister});
  DCHECK_EQ(kContextRegister, ToRegister(context()));
  DCHECK_EQ(kJavaScriptCallTargetRegister, ToRegister(closure()));
  __ Move(kJavaScriptCallArgCountRegister, actual_parameter_count);
  if (shared_function_info().HasBuiltinId()) {
    // TODO(42204201) Here we should statically validate the parameter count.
    // However, for that, every builtin needs to know its expected parameter
    // count. See also issue 343498932.
    __ CallBuiltin(shared_function_info().builtin_id());
  } else {
    // TODO(42204201): Instead of validating the parameter count, we should
    // just hardcode the dispatch entry into the generated code. That way, it
    // will be guaranteed that the parameter count is correct. However, this
    // requires GC support to mark the dispatch entry as alive when embedded
    // into generated code.
    __ CallJSFunction(kJavaScriptCallTargetRegister, expected_parameter_count_);
  }
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CallKnownApiFunction::MaxCallStackArgs() const {
  int actual_parameter_count = num_args() + 1;
  return actual_parameter_count;
}

void CallKnownApiFunction::SetValueLocationConstraints() {
  if (api_holder_.has_value()) {
    UseAny(receiver());
  } else {
    // This is an "Api holder is receiver" case, ask register allocator to put
    // receiver value into the right register.
    UseFixed(receiver(), CallApiCallbackOptimizedDescriptor::HolderRegister());
  }
  for (int i = 0; i < num_args(); i++) {
    UseAny(arg(i));
  }
  UseFixed(context(), kContextRegister);

  DefineAsFixed(this, kReturnRegister0);

  if (inline_builtin()) {
    set_temporaries_needed(2);
  }
}

void CallKnownApiFunction::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  __ PushReverse(receiver(), args());

  // From here on, we're going to do a call, so all registers are valid temps,
  // except for the ones we're going to write. This is needed in case one of the
  // helper methods below wants to use a temp and one of these is in the temp
  // list (in particular, this can happen on arm64 where cp is a temp register
  // by default).
  temps.SetAvailable(
      kAllocatableGeneralRegisters -
      RegList{
          kContextRegister,
          CallApiCallbackOptimizedDescriptor::HolderRegister(),
          CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister(),
          CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister(),
          CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister()});
  DCHECK_EQ(kContextRegister, ToRegister(context()));

  if (inline_builtin()) {
    GenerateCallApiCallbackOptimizedInline(masm, state);
    return;
  }

  if (api_holder_.has_value()) {
    __ Move(CallApiCallbackOptimizedDescriptor::HolderRegister(),
            api_holder_.value().object());
  } else {
    // This is an "Api holder is receiver" case, register allocator was asked
    // to put receiver value into the right register.
    DCHECK_EQ(CallApiCallbackOptimizedDescriptor::HolderRegister(),
              ToRegister(receiver()));
  }
  __ Move(CallApiCallbackOptimizedDescriptor::ActualArgumentsCountRegister(),
          num_args());  // not including receiver

  __ Move(CallApiCallbackOptimizedDescriptor::FunctionTemplateInfoRegister(),
          i::Cast<HeapObject>(function_template_info_.object()));

  compiler::JSHeapBroker* broker = masm->compilation_info()->broker();
  ApiFunction function(function_template_info_.callback(broker));
  ExternalReference reference =
      ExternalReference::Create(&function, ExternalReference::DIRECT_API_CALL);
  __ Move(CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister(),
          reference);

  switch (mode()) {
    case kNoProfiling:
      __ CallBuiltin(Builtin::kCallApiCallbackOptimizedNoProfiling);
      break;
    case kNoProfilingInlined:
      UNREACHABLE();
    case kGeneric:
      __ CallBuiltin(Builtin::kCallApiCallbackOptimized);
      break;
  }
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void CallKnownApiFunction::GenerateCallApiCallbackOptimizedInline(
    MaglevAssembler* masm, const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  Register scratch2 = temps.Acquire();

  using FCA = FunctionCallbackArguments;
  using ER = ExternalReference;
  using FC = ApiCallbackExitFrameConstants;

  static_assert(FCA::kArgsLength == 6);
  static_assert(FCA::kNewTargetIndex == 5);
  static_assert(FCA::kTargetIndex == 4);
  static_assert(FCA::kReturnValueIndex == 3);
  static_assert(FCA::kContextIndex == 2);
  static_assert(FCA::kIsolateIndex == 1);
  static_assert(FCA::kHolderIndex == 0);

  // Set up FunctionCallbackInfo's implicit_args on the stack as follows:
  //
  // Target state:
  //   sp[0 * kSystemPointerSize]: kHolder   <= implicit_args_
  //   sp[1 * kSystemPointerSize]: kIsolate
  //   sp[2 * kSystemPointerSize]: kContext
  //   sp[3 * kSystemPointerSize]: undefined (kReturnValue)
  //   sp[4 * kSystemPointerSize]: kTarget
  //   sp[5 * kSystemPointerSize]: undefined (kNewTarget)
  // Existing state:
  //   sp[6 * kSystemPointerSize]:          <= FCA:::values_

  __ StoreRootRelative(IsolateData::topmost_script_having_context_offset(),
                       kContextRegister);

  ASM_CODE_COMMENT_STRING(masm, "inlined CallApiCallbackOptimized builtin");
  __ LoadRoot(scratch, RootIndex::kUndefinedValue);
  // kNewTarget, kTarget, kReturnValue, kContext
  __ Push(scratch, i::Cast<HeapObject>(function_template_info_.object()),
          scratch, kContextRegister);
  __ Move(scratch, ER::isolate_address());
  // kIsolate, kHolder
  if (api_holder_.has_value()) {
    __ Push(scratch, api_holder_.value().object());
  } else {
    // This is an "Api holder is receiver" case, register allocator was asked
    // to put receiver value into the right register.
    __ Push(scratch, receiver());
  }

  Register api_function_address =
      CallApiCallbackOptimizedDescriptor::ApiFunctionAddressRegister();

  compiler::JSHeapBroker* broker = masm->compilation_info()->broker();
  ApiFunction function(function_template_info_.callback(broker));
  ExternalReference reference =
      ExternalReference::Create(&function, ExternalReference::DIRECT_API_CALL);
  __ Move(api_function_address, reference);

  Label done, call_api_callback_builtin_inline;
  __ Call(&call_api_callback_builtin_inline);
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
  __ jmp(&done);

  //
  // Generate a CallApiCallback builtin inline.
  //
  __ bind(&call_api_callback_builtin_inline);

  FrameScope frame_scope(masm, StackFrame::MANUAL);
  __ EmitEnterExitFrame(FC::getExtraSlotsCountFrom<ExitFrameConstants>(),
                        StackFrame::API_CALLBACK_EXIT, api_function_address,
                        scratch2);

  Register fp = __ GetFramePointer();
#ifdef V8_TARGET_ARCH_ARM64
  // This is a workaround for performance regression observed on Apple Silicon
  // (https://crbug.com/347741609): reading argc value after the call via
  //   MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
  // is noticeably slower than using sp-based access:
  MemOperand argc_operand = ExitFrameStackSlotOperand(FCA::kLengthOffset);
#else
  // We don't enable this workaround for other configurations because
  // a) it's not possible to convert fp-based encoding to sp-based one:
  //    V8 guarantees stack pointer to be only kSystemPointerSize-aligned,
  //    while C function might require stack pointer to be 16-byte aligned on
  //    certain platforms,
  // b) local experiments on x64 didn't show improvements.
  MemOperand argc_operand = MemOperand(fp, FC::kFCIArgcOffset);
#endif  // V8_TARGET_ARCH_ARM64
  {
    ASM_CODE_COMMENT_STRING(masm, "Initialize v8::FunctionCallbackInfo");
    // FunctionCallbackInfo::length_.
    __ Move(scratch, num_args());  // not including receiver
    __ Move(argc_operand, scratch);

    // FunctionCallbackInfo::implicit_args_.
    __ LoadAddress(scratch, MemOperand(fp, FC::kImplicitArgsArrayOffset));
    __ Move(MemOperand(fp, FC::kFCIImplicitArgsOffset), scratch);

    // FunctionCallbackInfo::values_ (points at JS arguments on the stack).
    __ LoadAddress(scratch, MemOperand(fp, FC::kFirstArgumentOffset));
    __ Move(MemOperand(fp, FC::kFCIValuesOffset), scratch);
  }

  Register function_callback_info_arg = kCArgRegs[0];

  __ RecordComment("v8::FunctionCallback's argument.");
  __ LoadAddress(function_callback_info_arg,
                 MemOperand(fp, FC::kFunctionCallbackInfoOffset));

  DCHECK(!AreAliased(api_function_address, function_callback_info_arg));

  MemOperand return_value_operand = MemOperand(fp, FC::kReturnValueOffset);
  const int kSlotsToDropOnReturn =
      FC::kFunctionCallbackInfoArgsLength + kJSArgcReceiverSlots + num_args();

  const bool with_profiling = false;
  ExternalReference no_thunk_ref;
  Register no_thunk_arg = no_reg;

  CallApiFunctionAndReturn(masm, with_profiling, api_function_address,
                           no_thunk_ref, no_thunk_arg, kSlotsToDropOnReturn,
                           nullptr, return_value_operand);
  __ RecordComment("end of inlined CallApiCallbackOptimized builtin");

  __ bind(&done);
}

int CallBuiltin::MaxCallStackArgs() const {
  auto descriptor = Builtins::CallInterfaceDescriptorFor(builtin());
  if (!descriptor.AllowVarArgs()) {
    return descriptor.GetStackParameterCount();
  } else {
    int all_input_count = InputCountWithoutContext() + (has_feedback() ? 2 : 0);
    DCHECK_GE(all_input_count, descriptor.GetRegisterParameterCount());
    return all_input_count - descriptor.GetRegisterParameterCount();
  }
}

void CallBuiltin::SetValueLocationConstraints() {
  auto descriptor = Builtins::CallInterfaceDescriptorFor(builtin());
  bool has_context = descriptor.HasContextParameter();
  int i = 0;
  for (; i < InputsInRegisterCount(); i++) {
    UseFixed(input(i), descriptor.GetRegisterParameter(i));
  }
  for (; i < InputCountWithoutContext(); i++) {
    UseAny(input(i));
  }
  if (has_context) {
    UseFixed(input(i), kContextRegister);
  }
  DefineAsFixed(this, kReturnRegister0);
}

template <typename... Args>
void CallBuiltin::PushArguments(MaglevAssembler* masm, Args... extra_args) {
  auto descriptor = Builtins::CallInterfaceDescriptorFor(builtin());
  if (descriptor.GetStackArgumentOrder() == StackArgumentOrder::kDefault) {
    // In Default order we cannot have extra args (feedback).
    DCHECK_EQ(sizeof...(extra_args), 0);
    __ Push(stack_args());
  } else {
    DCHECK_EQ(descriptor.GetStackArgumentOrder(), StackArgumentOrder::kJS);
    __ PushReverse(extra_args..., stack_args());
  }
}

void CallBuiltin::PassFeedbackSlotInRegister(MaglevAssembler* masm) {
  DCHECK(has_feedback());
  auto descriptor = Builtins::CallInterfaceDescriptorFor(builtin());
  int slot_index = InputCountWithoutContext();
  switch (slot_type()) {
    case kTaggedIndex:
      __ Move(descriptor.GetRegisterParameter(slot_index),
              TaggedIndex::FromIntptr(feedback().index()));
      break;
    case kSmi:
      __ Move(descriptor.GetRegisterParameter(slot_index),
              Smi::FromInt(feedback().index()));
      break;
  }
}

void CallBuiltin::PushFeedbackAndArguments(MaglevAssembler* masm) {
  DCHECK(has_feedback());

  auto descriptor = Builtins::CallInterfaceDescriptorFor(builtin());
  int slot_index = InputCountWithoutContext();
  int vector_index = slot_index + 1;

  // There are three possibilities:
  // 1. Feedback slot and vector are in register.
  // 2. Feedback slot is in register and vector is on stack.
  // 3. Feedback slot and vector are on stack.
  if (vector_index < descriptor.GetRegisterParameterCount()) {
    PassFeedbackSlotInRegister(masm);
    __ Move(descriptor.GetRegisterParameter(vector_index), feedback().vector);
    PushArguments(masm);
  } else if (vector_index == descriptor.GetRegisterParameterCount()) {
    PassFeedbackSlotInRegister(masm);
    DCHECK_EQ(descriptor.GetStackArgumentOrder(), StackArgumentOrder::kJS);
    // Ensure that the builtin only expects the feedback vector on the stack and
    // potentional additional var args are passed through to another builtin.
    // This is required to align the stack correctly (e.g. on arm64).
    DCHECK_EQ(descriptor.GetStackParameterCount(), 1);
    PushArguments(masm);
    __ Push(feedback().vector);
  } else {
    int slot = feedback().index();
    Handle<FeedbackVector> vector = feedback().vector;
    switch (slot_type()) {
      case kTaggedIndex:
        PushArguments(masm, TaggedIndex::FromIntptr(slot), vector);
        break;
      case kSmi:
        PushArguments(masm, Smi::FromInt(slot), vector);
        break;
    }
  }
}

void CallBuiltin::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  if (has_feedback()) {
    PushFeedbackAndArguments(masm);
  } else {
    PushArguments(masm);
  }
  __ CallBuiltin(builtin());
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CallCPPBuiltin::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<kCEntry_Builtin>::type;
  return D::GetStackParameterCount() + num_args();
}

void CallCPPBuiltin::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<kCEntry_Builtin>::type;
  UseAny(target());
  UseAny(new_target());
  UseFixed(context(), kContextRegister);
  for (int i = 0; i < num_args(); i++) {
    UseAny(arg(i));
  }
  DefineAsFixed(this, kReturnRegister0);
  set_temporaries_needed(1);
  RequireSpecificTemporary(D::GetRegisterParameter(D::kArity));
  RequireSpecificTemporary(D::GetRegisterParameter(D::kCFunction));
}

void CallCPPBuiltin::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  using D = CallInterfaceDescriptorFor<kCEntry_Builtin>::type;
  constexpr Register kArityReg = D::GetRegisterParameter(D::kArity);
  constexpr Register kCFunctionReg = D::GetRegisterParameter(D::kCFunction);

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  __ LoadRoot(scratch, RootIndex::kTheHoleValue);

  // Push all arguments to the builtin (including the receiver).
  static_assert(BuiltinArguments::kReceiverIndex == 4);
  __ PushReverse(args());

  static_assert(BuiltinArguments::kNumExtraArgs == 4);
  static_assert(BuiltinArguments::kNewTargetIndex == 0);
  static_assert(BuiltinArguments::kTargetIndex == 1);
  static_assert(BuiltinArguments::kArgcIndex == 2);
  static_assert(BuiltinArguments::kPaddingIndex == 3);
  // Push stack arguments for CEntry.
  Tagged<Smi> tagged_argc = Smi::FromInt(BuiltinArguments::kNumExtraArgs +
                                         num_args());  // Includes receiver.
  __ Push(scratch /* padding */, tagged_argc, target(), new_target());

  // Move values to fixed registers after all arguments are pushed. Registers
  // for arguments and CEntry registers might overlap.
  __ Move(kArityReg, BuiltinArguments::kNumExtraArgs + num_args());
  ExternalReference builtin_address =
      ExternalReference::Create(Builtins::CppEntryOf(builtin()));
  __ Move(kCFunctionReg, builtin_address);

  DCHECK_EQ(Builtins::CallInterfaceDescriptorFor(builtin()).GetReturnCount(),
            1);
  __ CallBuiltin(Builtin::kCEntry_Return1_ArgvOnStack_BuiltinExit);
}

int CallRuntime::MaxCallStackArgs() const { return num_args(); }
void CallRuntime::SetValueLocationConstraints() {
  UseFixed(context(), kContextRegister);
  for (int i = 0; i < num_args(); i++) {
    UseAny(arg(i));
  }
  DefineAsFixed(this, kReturnRegister0);
}
void CallRuntime::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  DCHECK_EQ(ToRegister(context()), kContextRegister);
  __ Push(args());
  __ CallRuntime(function_id(), num_args());
  // TODO(victorgomes): Not sure if this is needed for all runtime calls.
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CallWithSpread::MaxCallStackArgs() const {
  int argc_no_spread = num_args() - 1;
  using D = CallInterfaceDescriptorFor<Builtin::kCallWithSpread>::type;
  return argc_no_spread + D::GetStackParameterCount();
}
void CallWithSpread::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kCallWithSpread>::type;
  UseFixed(function(), D::GetRegisterParameter(D::kTarget));
  UseFixed(spread(), D::GetRegisterParameter(D::kSpread));
  UseFixed(context(), kContextRegister);
  for (int i = 0; i < num_args() - 1; i++) {
    UseAny(arg(i));
  }
  DefineAsFixed(this, kReturnRegister0);
}
void CallWithSpread::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  __ CallBuiltin<Builtin::kCallWithSpread>(
      context(),             // context
      function(),            // target
      num_args_no_spread(),  // arguments count
      spread(),              // spread
      args_no_spread()       // pushed args
  );

  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int CallWithArrayLike::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kCallWithArrayLike>::type;
  return D::GetStackParameterCount();
}
void CallWithArrayLike::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kCallWithArrayLike>::type;
  UseFixed(function(), D::GetRegisterParameter(D::kTarget));
  UseAny(receiver());
  UseFixed(arguments_list(), D::GetRegisterParameter(D::kArgumentsList));
  UseFixed(context(), kContextRegister);
  DefineAsFixed(this, kReturnRegister0);
}
void CallWithArrayLike::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  // CallWithArrayLike is a weird builtin that expects a receiver as top of the
  // stack, but doesn't explicitly list it as an extra argument. Push it
  // manually, and assert that there are no other stack arguments.
  static_assert(
      CallInterfaceDescriptorFor<
          Builtin::kCallWithArrayLike>::type::GetStackParameterCount() == 0);
  __ Push(receiver());
  __ CallBuiltin<Builtin::kCallWithArrayLike>(
      context(),        // context
      function(),       // target
      arguments_list()  // arguments list
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

// ---
// Arch agnostic construct nodes
// ---

int Construct::MaxCallStackArgs() const {
  using D = Construct_WithFeedbackDescriptor;
  return num_args() + D::GetStackParameterCount();
}
void Construct::SetValueLocationConstraints() {
  using D = Construct_WithFeedbackDescriptor;
  UseFixed(function(), D::GetRegisterParameter(D::kTarget));
  UseFixed(new_target(), D::GetRegisterParameter(D::kNewTarget));
  UseFixed(context(), kContextRegister);
  for (int i = 0; i < num_args(); i++) {
    UseAny(arg(i));
  }
  DefineAsFixed(this, kReturnRegister0);
}
void Construct::GenerateCode(MaglevAssembler* masm,
                             const ProcessingState& state) {
  __ CallBuiltin<Builtin::kConstruct_WithFeedback>(
      context(),           // context
      function(),          // target
      new_target(),        // new target
      num_args(),          // actual arguments count
      feedback().index(),  // feedback slot
      feedback().vector,   // feedback vector
      args()               // args
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int ConstructWithSpread::MaxCallStackArgs() const {
  int argc_no_spread = num_args() - 1;
  using D = CallInterfaceDescriptorFor<
      Builtin::kConstructWithSpread_WithFeedback>::type;
  return argc_no_spread + D::GetStackParameterCount();
}
void ConstructWithSpread::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<
      Builtin::kConstructWithSpread_WithFeedback>::type;
  UseFixed(function(), D::GetRegisterParameter(D::kTarget));
  UseFixed(new_target(), D::GetRegisterParameter(D::kNewTarget));
  UseFixed(context(), kContextRegister);
  for (int i = 0; i < num_args() - 1; i++) {
    UseAny(arg(i));
  }
  UseFixed(spread(), D::GetRegisterParameter(D::kSpread));
  DefineAsFixed(this, kReturnRegister0);
}
void ConstructWithSpread::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  __ CallBuiltin<Builtin::kConstructWithSpread_WithFeedback>(
      context(),                                    // context
      function(),                                   // target
      new_target(),                                 // new target
      num_args_no_spread(),                         // actual arguments count
      spread(),                                     // spread
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector,                            // feedback vector
      args_no_spread()                              // args
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void SetPendingMessage::SetValueLocationConstraints() {
  UseRegister(value());
  DefineAsRegister(this);
}

void SetPendingMessage::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  Register new_message = ToRegister(value());
  Register return_value = ToRegister(result());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.AcquireScratch();
  MemOperand pending_message_operand = __ ExternalReferenceAsOperand(
      ExternalReference::address_of_pending_message(masm->isolate()), scratch);
  if (new_message != return_value) {
    __ Move(return_value, pending_message_operand);
    __ Move(pending_message_operand, new_message);
  } else {
    __ Move(scratch, pending_message_operand);
    __ Move(pending_message_operand, new_message);
    __ Move(return_value, scratch);
  }
}

void StoreDoubleField::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(value_input());
}
void StoreDoubleField::GenerateCode(MaglevAssembler* masm,
                                    const ProcessingState& state) {
  Register object = ToRegister(object_input());
  DoubleRegister value = ToDoubleRegister(value_input());

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register tmp = temps.AcquireScratch();

  __ AssertNotSmi(object);
  __ LoadTaggedField(tmp, object, offset());
  __ AssertNotSmi(tmp);
  __ StoreFloat64(FieldMemOperand(tmp, offsetof(HeapNumber, value_)), value);
}

namespace {

template <typename NodeT>
void GenerateTransitionElementsKind(
    MaglevAssembler* masm, NodeT* node, Register object, Register map,
    base::Vector<const compiler::MapRef> transition_sources,
    const compiler::MapRef transition_target, ZoneLabelRef done,
    std::optional<Register> result_opt) {
  DCHECK(!compiler::AnyMapIsHeapNumber(transition_sources));
  DCHECK(!IsHeapNumberMap(*transition_target.object()));

  for (const compiler::MapRef transition_source : transition_sources) {
    bool is_simple = IsSimpleMapChangeTransition(
        transition_source.elements_kind(), transition_target.elements_kind());

    // TODO(leszeks): If there are a lot of transition source maps, move the
    // source into a register and share the deferred code between maps.
    __ CompareTaggedAndJumpIf(
        map, transition_source.object(), kEqual,
        __ MakeDeferredCode(
            [](MaglevAssembler* masm, Register object, Register map,
               RegisterSnapshot register_snapshot,
               compiler::MapRef transition_target, bool is_simple,
               ZoneLabelRef done, std::optional<Register> result_opt) {
              if (is_simple) {
                __ MoveTagged(map, transition_target.object());
                __ StoreTaggedFieldWithWriteBarrier(
                    object, HeapObject::kMapOffset, map, register_snapshot,
                    MaglevAssembler::kValueIsCompressed,
                    MaglevAssembler::kValueCannotBeSmi);
              } else {
                SaveRegisterStateForCall save_state(masm, register_snapshot);
                __ Push(object, transition_target.object());
                __ Move(kContextRegister, masm->native_context().object());
                __ CallRuntime(Runtime::kTransitionElementsKind);
                save_state.DefineSafepoint();
              }
              if (result_opt) {
                __ MoveTagged(*result_opt, transition_target.object());
              }
              __ Jump(*done);
            },
            object, map, node->register_snapshot(), transition_target,
            is_simple, done, result_opt));
  }
}

}  // namespace

int TransitionElementsKind::MaxCallStackArgs() const {
  return std::max(WriteBarrierDescriptor::GetStackParameterCount(), 2);
}

void TransitionElementsKind::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(map_input());
  DefineAsRegister(this);
}

void TransitionElementsKind::GenerateCode(MaglevAssembler* masm,
                                          const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register map = ToRegister(map_input());
  Register result_register = ToRegister(result());

  ZoneLabelRef done(masm);

  __ AssertNotSmi(object);
  GenerateTransitionElementsKind(masm, this, object, map,
                                 base::VectorOf(transition_sources_),
                                 transition_target_, done, result_register);
  // No transition happened, return the original map.
  __ Move(result_register, map);
  __ Jump(*done);
  __ bind(*done);
}

int TransitionElementsKindOrCheckMap::MaxCallStackArgs() const {
  return std::max(WriteBarrierDescriptor::GetStackParameterCount(), 2);
}

void TransitionElementsKindOrCheckMap::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(map_input());
}

void TransitionElementsKindOrCheckMap::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register map = ToRegister(map_input());

  ZoneLabelRef done(masm);

  __ CompareTaggedAndJumpIf(map, transition_target_.object(), kEqual, *done);

  GenerateTransitionElementsKind(masm, this, object, map,
                                 base::VectorOf(transition_sources_),
                                 transition_target_, done, {});
  // If we didn't jump to 'done' yet, the transition failed.
  __ EmitEagerDeopt(this, DeoptimizeReason::kWrongMap);
  __ bind(*done);
}

void CheckTypedArrayNotDetached::SetValueLocationConstraints() {
  UseRegister(object_input());
  set_temporaries_needed(1);
}

void CheckTypedArrayNotDetached::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object = ToRegister(object_input());
  Register scratch = temps.Acquire();
  __ DeoptIfBufferDetached(object, scratch, this);
}

void GetContinuationPreservedEmbedderData::SetValueLocationConstraints() {
  DefineAsRegister(this);
}

void GetContinuationPreservedEmbedderData::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register result = ToRegister(this->result());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  MemOperand reference = __ ExternalReferenceAsOperand(
      IsolateFieldId::kContinuationPreservedEmbedderData);
  __ Move(result, reference);
}

void SetContinuationPreservedEmbedderData::SetValueLocationConstraints() {
  UseRegister(data_input());
}

void SetContinuationPreservedEmbedderData::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register data = ToRegister(data_input());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  MemOperand reference = __ ExternalReferenceAsOperand(
      IsolateFieldId::kContinuationPreservedEmbedderData);
  __ Move(reference, data);
}

namespace {

template <typename ResultReg, typename NodeT>
void GenerateTypedArrayLoad(MaglevAssembler* masm, NodeT* node, Register object,
                            Register index, ResultReg result_reg,
                            ElementsKind kind) {
  __ AssertNotSmi(object);
  if (v8_flags.debug_code) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    __ AssertObjectType(object, JS_TYPED_ARRAY_TYPE,
                        AbortReason::kUnexpectedValue);
  }

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();

  Register data_pointer = scratch;
  __ BuildTypedArrayDataPointer(data_pointer, object);

  int element_size = ElementsKindSize(kind);
  MemOperand operand =
      __ TypedArrayElementOperand(data_pointer, index, element_size);
  if constexpr (std::is_same_v<ResultReg, Register>) {
    if (IsSignedIntTypedArrayElementsKind(kind)) {
      __ LoadSignedField(result_reg, operand, element_size);
    } else {
      DCHECK(IsUnsignedIntTypedArrayElementsKind(kind));
      __ LoadUnsignedField(result_reg, operand, element_size);
    }
  } else {
#ifdef DEBUG
    bool result_reg_is_double = std::is_same_v<ResultReg, DoubleRegister>;
    DCHECK(result_reg_is_double);
    DCHECK(IsFloatTypedArrayElementsKind(kind));
#endif
    switch (kind) {
      case FLOAT32_ELEMENTS:
        __ LoadFloat32(result_reg, operand);
        break;
      case FLOAT64_ELEMENTS:
        __ LoadFloat64(result_reg, operand);
        break;
      default:
        UNREACHABLE();
    }
  }
}

template <typename ValueReg, typename NodeT>
void GenerateTypedArrayStore(MaglevAssembler* masm, NodeT* node,
                             Register object, Register index, ValueReg value,
                             ElementsKind kind) {
  __ AssertNotSmi(object);
  if (v8_flags.debug_code) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    __ AssertObjectType(object, JS_TYPED_ARRAY_TYPE,
                        AbortReason::kUnexpectedValue);
  }

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();

  Register data_pointer = scratch;
  __ BuildTypedArrayDataPointer(data_pointer, object);

  int element_size = ElementsKindSize(kind);
  MemOperand operand =
      __ TypedArrayElementOperand(data_pointer, index, element_size);
  if constexpr (std::is_same_v<ValueReg, Register>) {
    int element_size = ElementsKindSize(kind);
    __ StoreField(operand, value, element_size);
  } else {
#ifdef DEBUG
    bool value_is_double = std::is_same_v<ValueReg, DoubleRegister>;
    DCHECK(value_is_double);
    DCHECK(IsFloatTypedArrayElementsKind(kind));
#endif
    switch (kind) {
      case FLOAT32_ELEMENTS:
        __ StoreFloat32(operand, value);
        break;
      case FLOAT64_ELEMENTS:
        __ StoreFloat64(operand, value);
        break;
      default:
        UNREACHABLE();
    }
  }
}

}  // namespace

#define DEF_LOAD_TYPED_ARRAY(Name, ResultReg, ToResultReg)        \
  void Name::SetValueLocationConstraints() {                      \
    UseRegister(object_input());                                  \
    UseRegister(index_input());                                   \
    DefineAsRegister(this);                                       \
    set_temporaries_needed(1);                                    \
  }                                                               \
  void Name::GenerateCode(MaglevAssembler* masm,                  \
                          const ProcessingState& state) {         \
    Register object = ToRegister(object_input());                 \
    Register index = ToRegister(index_input());                   \
    ResultReg result_reg = ToResultReg(result());                 \
                                                                  \
    GenerateTypedArrayLoad(masm, this, object, index, result_reg, \
                           elements_kind_);                       \
  }

DEF_LOAD_TYPED_ARRAY(LoadSignedIntTypedArrayElement, Register, ToRegister)

DEF_LOAD_TYPED_ARRAY(LoadUnsignedIntTypedArrayElement, Register, ToRegister)

DEF_LOAD_TYPED_ARRAY(LoadDoubleTypedArrayElement, DoubleRegister,
                     ToDoubleRegister)
#undef DEF_LOAD_TYPED_ARRAY

#define DEF_STORE_TYPED_ARRAY(Name, ValueReg, ToValueReg)                      \
  void Name::SetValueLocationConstraints() {                                   \
    UseRegister(object_input());                                               \
    UseRegister(index_input());                                                \
    UseRegister(value_input());                                                \
    set_temporaries_needed(1);                                                 \
  }                                                                            \
  void Name::GenerateCode(MaglevAssembler* masm,                               \
                          const ProcessingState& state) {                      \
    Register object = ToRegister(object_input());                              \
    Register index = ToRegister(index_input());                                \
    ValueReg value = ToValueReg(value_input());                                \
                                                                               \
    GenerateTypedArrayStore(masm, this, object, index, value, elements_kind_); \
  }

DEF_STORE_TYPED_ARRAY(StoreIntTypedArrayElement, Register, ToRegister)

DEF_STORE_TYPED_ARRAY(StoreDoubleTypedArrayElement, DoubleRegister,
                      ToDoubleRegister)
#undef DEF_STORE_TYPED_ARRAY

// ---
// Arch agnostic control nodes
// ---

void Jump::SetValueLocationConstraints() {}
void Jump::GenerateCode(MaglevAssembler* masm, const ProcessingState& state) {
  // Avoid emitting a jump to the next block.
  if (target() != state.next_block()) {
    __ Jump(target()->label());
  }
}

void CheckpointedJump::SetValueLocationConstraints() {}
void CheckpointedJump::GenerateCode(MaglevAssembler* masm,
                                    const ProcessingState& state) {
  // Avoid emitting a jump to the next block.
  if (target() != state.next_block()) {
    __ Jump(target()->label());
  }
}

namespace {

void AttemptOnStackReplacement(MaglevAssembler* masm,
                               ZoneLabelRef no_code_for_osr,
                               TryOnStackReplacement* node, Register scratch0,
                               Register scratch1, int32_t loop_depth,
                               FeedbackSlot feedback_slot,
                               BytecodeOffset osr_offset) {
  // Two cases may cause us to attempt OSR, in the following order:
  //
  // 1) Presence of cached OSR Turbofan code.
  // 2) The OSR urgency exceeds the current loop depth - in that case, call
  //    into runtime to trigger a Turbofan OSR compilation. A non-zero return
  //    value means we should deopt into Ignition which will handle all further
  //    necessary steps (rewriting the stack frame, jumping to OSR'd code).
  //
  // See also: InterpreterAssembler::OnStackReplacement.

  __ AssertFeedbackVector(scratch0, scratch1);

  // Case 1).
  Label deopt;
  Register maybe_target_code = scratch1;
  __ TryLoadOptimizedOsrCode(scratch1, CodeKind::TURBOFAN_JS, scratch0,
                             feedback_slot, &deopt, Label::kFar);

  // Case 2).
  {
    __ LoadByte(scratch0,
                FieldMemOperand(scratch0, FeedbackVector::kOsrStateOffset));
    __ DecodeField<FeedbackVector::OsrUrgencyBits>(scratch0);
    __ JumpIfByte(kUnsignedLessThanEqual, scratch0, loop_depth,
                  *no_code_for_osr);

    // The osr_urgency exceeds the current loop_depth, signaling an OSR
    // request. Call into runtime to compile.
    {
      RegisterSnapshot snapshot = node->register_snapshot();
      DCHECK(!snapshot.live_registers.has(maybe_target_code));
      SaveRegisterStateForCall save_register_state(masm, snapshot);
      if (node->unit()->is_inline()) {
        // See comment in
        // MaglevGraphBuilder::ShouldEmitOsrInterruptBudgetChecks.
        CHECK(!node->unit()->is_osr());
        __ Push(Smi::FromInt(osr_offset.ToInt()), node->closure());
        __ Move(kContextRegister, masm->native_context().object());
        __ CallRuntime(Runtime::kCompileOptimizedOSRFromMaglevInlined, 2);
      } else {
        __ Push(Smi::FromInt(osr_offset.ToInt()));
        __ Move(kContextRegister, masm->native_context().object());
        __ CallRuntime(Runtime::kCompileOptimizedOSRFromMaglev, 1);
      }
      save_register_state.DefineSafepoint();
      __ Move(maybe_target_code, kReturnRegister0);
    }

    // A `0` return value means there is no OSR code available yet. Continue
    // execution in Maglev, OSR code will be picked up once it exists and is
    // cached on the feedback vector.
    __ CompareInt32AndJumpIf(maybe_target_code, 0, kEqual, *no_code_for_osr);
  }

  __ bind(&deopt);
  if (V8_LIKELY(v8_flags.turbofan)) {
    // None of the mutated input registers should be a register input into the
    // eager deopt info.
    DCHECK_REGLIST_EMPTY(
        RegList{scratch0, scratch1} &
        GetGeneralRegistersUsedAsInputs(node->eager_deopt_info()));
    __ EmitEagerDeopt(node, DeoptimizeReason::kPrepareForOnStackReplacement);
  } else {
    // Continue execution in Maglev. With TF disabled we cannot OSR and thus it
    // doesn't make sense to start the process. We do still perform all
    // remaining bookkeeping above though, to keep Maglev code behavior roughly
    // the same in both configurations.
    __ Jump(*no_code_for_osr);
  }
}

}  // namespace

int TryOnStackReplacement::MaxCallStackArgs() const {
  // For the kCompileOptimizedOSRFromMaglev call.
  if (unit()->is_inline()) return 2;
  return 1;
}
void TryOnStackReplacement::SetValueLocationConstraints() {
  UseAny(closure());
  set_temporaries_needed(2);
}
void TryOnStackReplacement::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch0 = temps.Acquire();
  Register scratch1 = temps.Acquire();

  const Register osr_state = scratch1;
  __ Move(scratch0, unit_->feedback().object());
  __ AssertFeedbackVector(scratch0, scratch1);
  __ LoadByte(osr_state,
              FieldMemOperand(scratch0, FeedbackVector::kOsrStateOffset));

  ZoneLabelRef no_code_for_osr(masm);

  if (v8_flags.maglev_osr) {
    // In case we use maglev_osr, we need to explicitly know if there is
    // turbofan code waiting for us (i.e., ignore the MaybeHasMaglevOsrCodeBit).
    __ DecodeField<
        base::BitFieldUnion<FeedbackVector::OsrUrgencyBits,
                            FeedbackVector::MaybeHasTurbofanOsrCodeBit>>(
        osr_state);
  }

  // The quick initial OSR check. If it passes, we proceed on to more
  // expensive OSR logic.
  static_assert(FeedbackVector::MaybeHasTurbofanOsrCodeBit::encode(true) >
                FeedbackVector::kMaxOsrUrgency);
  __ CompareInt32AndJumpIf(
      osr_state, loop_depth_, kUnsignedGreaterThan,
      __ MakeDeferredCode(AttemptOnStackReplacement, no_code_for_osr, this,
                          scratch0, scratch1, loop_depth_, feedback_slot_,
                          osr_offset_));
  __ bind(*no_code_for_osr);
}

void JumpLoop::SetValueLocationConstraints() {}
void JumpLoop::GenerateCode(MaglevAssembler* masm,
                            const ProcessingState& state) {
  __ Jump(target()->label());
}

void BranchIfSmi::SetValueLocationConstraints() {
  UseRegister(condition_input());
}
void BranchIfSmi::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  __ Branch(__ CheckSmi(ToRegister(condition_input())), if_true(), if_false(),
            state.next_block());
}

void BranchIfRootConstant::SetValueLocationConstraints() {
  UseRegister(condition_input());
}
void BranchIfRootConstant::GenerateCode(MaglevAssembler* masm,
                                        const ProcessingState& state) {
  __ CompareRoot(ToRegister(condition_input()), root_index());
  __ Branch(ConditionFor(Operation::kEqual), if_true(), if_false(),
            state.next_block());
}

void BranchIfToBooleanTrue::SetValueLocationConstraints() {
  // TODO(victorgomes): consider using any input instead.
  UseRegister(condition_input());
}
void BranchIfToBooleanTrue::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  // BasicBlocks are zone allocated and so safe to be casted to ZoneLabelRef.
  ZoneLabelRef true_label =
      ZoneLabelRef::UnsafeFromLabel
```