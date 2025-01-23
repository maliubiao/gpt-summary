Response: The user wants to understand the functionality of the provided C++ code snippet from `v8/src/baseline/baseline-compiler.cc`. This is the second part of the file. I need to summarize its purpose and illustrate its connection to JavaScript using examples if applicable.

This part of the code seems to define the `Visit` methods for various bytecode instructions. These methods are responsible for generating assembly code that corresponds to the execution of those bytecode instructions in the V8's baseline compiler. Many of these instructions relate to common JavaScript operations.

Plan:
1. Identify the main functionalities implemented in this part.
2. For each functionality, check if it directly relates to a JavaScript concept.
3. If a connection exists, provide a concise JavaScript example to illustrate it.
这个C++代码文件（`v8/src/baseline/baseline-compiler.cc` 的第二部分）是V8 JavaScript引擎中Baseline编译器的一部分，其主要功能是**将JavaScript字节码指令转换为底层的机器码指令**。  Baseline编译器是V8中一个相对简单且快速的编译器，它为JavaScript代码提供了一个初步的编译版本，以便代码可以快速开始执行。

具体来说，这部分代码定义了 `BaselineCompiler` 类的各种 `Visit` 方法。每个 `Visit` 方法都对应一个特定的JavaScript字节码指令，并负责生成执行该指令所需的机器码。

以下列举一些代码中涉及的JavaScript功能，并提供相应的JavaScript示例：

1. **类型判断 (TestTypeOf):**  判断变量的类型。

   ```javascript
   console.log(typeof 10);        // "number"
   console.log(typeof "hello");   // "string"
   console.log(typeof true);     // "boolean"
   console.log(typeof undefined);  // "undefined"
   console.log(typeof null);      // "object"
   console.log(typeof {});        // "object"
   console.log(typeof []);        // "object"
   console.log(typeof function(){}); // "function"
   ```

2. **类型转换 (ToName, ToNumber, ToNumeric, ToObject, ToString, ToBoolean):**  将值转换为特定的类型。

   ```javascript
   String(123);       // "123"
   Number("456");     // 456
   Boolean(0);       // false
   Object(1);        // Number {1}
   ```

3. **正则表达式字面量 (CreateRegExpLiteral):** 创建正则表达式对象。

   ```javascript
   const regex = /ab+c/;
   ```

4. **数组字面量 (CreateArrayLiteral, CreateEmptyArrayLiteral, CreateArrayFromIterable):** 创建数组。

   ```javascript
   const arr1 = [1, 2, 3];
   const arr2 = [];
   const arr3 = Array.from("abc"); // ['a', 'b', 'c']
   ```

5. **对象字面量 (CreateObjectLiteral, CreateEmptyObjectLiteral, CloneObject):** 创建对象。

   ```javascript
   const obj1 = { a: 1, b: 2 };
   const obj2 = {};
   const obj3 = { ...obj1 }; // 克隆对象
   ```

6. **模板字面量 (GetTemplateObject):** 创建模板字面量的对象表示。

   ```javascript
   const name = "World";
   const greeting = `Hello, ${name}!`;
   ```

7. **闭包 (CreateClosure):**  创建闭包函数。

   ```javascript
   function outer() {
     const message = "Hello";
     function inner() {
       console.log(message);
     }
     return inner;
   }
   const myClosure = outer();
   myClosure(); // 输出 "Hello"
   ```

8. **作用域 (CreateBlockContext, CreateCatchContext, CreateFunctionContext, CreateEvalContext, CreateWithContext):**  创建不同类型的作用域。这些在JavaScript代码中通常是隐式的，但在编译过程中需要明确创建。

   ```javascript
   // 块级作用域
   {
     let x = 10;
   }

   // catch 块作用域
   try {
     // ...
   } catch (error) {
     // error 存在于 catch 块的作用域中
   }

   // 函数作用域
   function myFunction() {
     const localVar = 5;
   }

   // eval 作用域 (不推荐使用)
   eval('var evalVar = 20;');

   // with 语句作用域 (不推荐使用)
   const myObject = { a: 1 };
   with (myObject) {
     console.log(a); // 访问 myObject.a
   }
   ```

9. **Arguments 对象 (CreateMappedArguments, CreateUnmappedArguments):** 创建函数中的 `arguments` 对象。

   ```javascript
   function foo() {
     console.log(arguments);
   }
   foo(1, 2, 3);
   ```

10. **剩余参数 (CreateRestParameter):** 创建剩余参数数组。

    ```javascript
    function bar(...rest) {
      console.log(rest);
    }
    bar(4, 5, 6); // 输出 [4, 5, 6]
    ```

11. **循环跳转 (JumpLoop):**  实现循环结构中的跳转。

    ```javascript
    for (let i = 0; i < 5; i++) {
      console.log(i);
    }
    ```

12. **条件跳转 (JumpIfNull, JumpIfNotNull, JumpIfUndefined, JumpIfNotUndefined, JumpIfUndefinedOrNull, JumpIfTrue, JumpIfFalse, JumpIfJSReceiver, JumpIfToBooleanTrue, JumpIfToBooleanFalse):**  实现条件语句中的跳转。

    ```javascript
    if (x === null) {
      // ...
    }
    if (y !== undefined) {
      // ...
    }
    ```

13. **Switch 语句 (SwitchOnSmiNoFeedback, SwitchOnGeneratorState):**  实现 `switch` 语句的逻辑。

    ```javascript
    switch (value) {
      case 1:
        // ...
        break;
      case 2:
        // ...
        break;
      default:
        // ...
    }
    ```

14. **For-In 循环 (ForInEnumerate, ForInPrepare, ForInNext, ForInStep):** 实现 `for...in` 循环遍历对象属性。

    ```javascript
    const obj = { a: 1, b: 2 };
    for (const key in obj) {
      console.log(key, obj[key]);
    }
    ```

15. **异常处理 (Throw, ReThrow, ThrowReferenceErrorIfHole, ThrowSuperNotCalledIfHole, ThrowSuperAlreadyCalledIfNotHole, ThrowIfNotSuperConstructor):**  处理 `throw` 语句和各种类型的错误。

    ```javascript
    function myFunction(value) {
      if (value < 0) {
        throw new Error("Value cannot be negative");
      }
      return value;
    }

    try {
      myFunction(-1);
    } catch (error) {
      console.error(error.message);
    }
    ```

16. **Generator 函数 (SwitchOnGeneratorState, SuspendGenerator, ResumeGenerator):**  处理生成器函数的执行状态和暂停/恢复。

    ```javascript
    function* myGenerator() {
      yield 1;
      yield 2;
      return 3;
    }

    const iterator = myGenerator();
    console.log(iterator.next()); // { value: 1, done: false }
    console.log(iterator.next()); // { value: 2, done: false }
    console.log(iterator.next()); // { value: 3, done: true }
    ```

17. **迭代器 (GetIterator):**  获取对象的迭代器。

    ```javascript
    const iterable = [1, 2, 3];
    const iterator = iterable[Symbol.iterator]();
    console.log(iterator.next()); // { value: 1, done: false }
    ```

18. **Debugger 语句 (Debugger):**  触发调试器的断点。

    ```javascript
    function myFunction() {
      debugger; // 代码执行到这里会暂停，允许开发者调试
      // ...
    }
    ```

19. **代码覆盖率 (IncBlockCounter):** 用于记录代码块的执行次数，通常用于代码覆盖率分析。

20. **中止执行 (Abort):**  立即终止程序执行。

21. **返回语句 (Return):**  从函数中返回值。

    ```javascript
    function add(a, b) {
      return a + b;
    }
    ```

总而言之，这部分C++代码是Baseline编译器实现JavaScript语义的关键组成部分，它将高级的JavaScript概念和操作转换为可以在机器上执行的低级指令。  每个 `Visit` 方法都针对特定的JavaScript语言特性，并生成相应的机器码来实现这些特性。

### 提示词
```
这是目录为v8/src/baseline/baseline-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
ap_bit_field, kInterpreterAccumulatorRegister);
      __ LoadWord8Field(map_bit_field, map_bit_field, Map::kBitFieldOffset);
      __ TestAndBranch(map_bit_field, Map::Bits1::IsCallableBit::kMask, kZero,
                       &not_callable, Label::kNear);
      __ TestAndBranch(map_bit_field, Map::Bits1::IsUndetectableBit::kMask,
                       kNotZero, &undetectable, Label::kNear);

      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&not_callable);
      __ Bind(&undetectable);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kObject: {
      Label is_smi, is_null, bad_instance_type, undetectable_or_callable;
      __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);

      // If the object is null, return true.
      __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kNullValue,
                    &is_null, Label::kNear);

      // If the object's instance type isn't within the range, return false.
      static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
      Register map = scratch_scope.AcquireScratch();
      __ JumpIfObjectType(kLessThan, kInterpreterAccumulatorRegister,
                          FIRST_JS_RECEIVER_TYPE, map, &bad_instance_type,
                          Label::kNear);

      // If the map is undetectable or callable, return false.
      Register map_bit_field = kInterpreterAccumulatorRegister;
      __ LoadWord8Field(map_bit_field, map, Map::kBitFieldOffset);
      __ TestAndBranch(map_bit_field,
                       Map::Bits1::IsUndetectableBit::kMask |
                           Map::Bits1::IsCallableBit::kMask,
                       kNotZero, &undetectable_or_callable, Label::kNear);

      __ Bind(&is_null);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kTrueValue);
      __ Jump(&done, Label::kNear);

      __ Bind(&is_smi);
      __ Bind(&bad_instance_type);
      __ Bind(&undetectable_or_callable);
      __ LoadRoot(kInterpreterAccumulatorRegister, RootIndex::kFalseValue);
      break;
    }
    case interpreter::TestTypeOfFlags::LiteralFlag::kOther:
    default:
      UNREACHABLE();
  }
  __ Bind(&done);
}

void BaselineCompiler::VisitToName() {
  CallBuiltin<Builtin::kToName>(kInterpreterAccumulatorRegister);
}

void BaselineCompiler::VisitToNumber() {
  CallBuiltin<Builtin::kToNumber_Baseline>(kInterpreterAccumulatorRegister,
                                           Index(0));
}

void BaselineCompiler::VisitToNumeric() {
  CallBuiltin<Builtin::kToNumeric_Baseline>(kInterpreterAccumulatorRegister,
                                            Index(0));
}

void BaselineCompiler::VisitToObject() {
  SaveAccumulatorScope save_accumulator(this, &basm_);
  CallBuiltin<Builtin::kToObject>(kInterpreterAccumulatorRegister);
  StoreRegister(0, kInterpreterAccumulatorRegister);
}

void BaselineCompiler::VisitToString() {
  CallBuiltin<Builtin::kToString>(kInterpreterAccumulatorRegister);
}

void BaselineCompiler::VisitToBoolean() {
  CallBuiltin<Builtin::kToBoolean>(kInterpreterAccumulatorRegister);
}

void BaselineCompiler::VisitCreateRegExpLiteral() {
  CallBuiltin<Builtin::kCreateRegExpLiteral>(
      FeedbackVector(),         // feedback vector
      IndexAsTagged(1),         // slot
      Constant<HeapObject>(0),  // pattern
      Flag16AsSmi(2));          // flags
}

void BaselineCompiler::VisitCreateArrayLiteral() {
  uint32_t flags = Flag8(2);
  int32_t flags_raw = static_cast<int32_t>(
      interpreter::CreateArrayLiteralFlags::FlagsBits::decode(flags));
  if (flags &
      interpreter::CreateArrayLiteralFlags::FastCloneSupportedBit::kMask) {
    CallBuiltin<Builtin::kCreateShallowArrayLiteral>(
        FeedbackVector(),          // feedback vector
        IndexAsTagged(1),          // slot
        Constant<HeapObject>(0),   // constant elements
        Smi::FromInt(flags_raw));  // flags
  } else {
    CallBuiltin<Builtin::kCreateArrayFromSlowBoilerplate>(
        FeedbackVector(),          // feedback vector
        IndexAsTagged(1),          // slot
        Constant<HeapObject>(0),   // constant elements
        Smi::FromInt(flags_raw));  // flags
  }
}

void BaselineCompiler::VisitCreateArrayFromIterable() {
  CallBuiltin<Builtin::kIterableToListWithSymbolLookup>(
      kInterpreterAccumulatorRegister);  // iterable
}

void BaselineCompiler::VisitCreateEmptyArrayLiteral() {
  CallBuiltin<Builtin::kCreateEmptyArrayLiteral>(FeedbackVector(),
                                                 IndexAsTagged(0));
}

void BaselineCompiler::VisitCreateObjectLiteral() {
  uint32_t flags = Flag8(2);
  int32_t flags_raw = static_cast<int32_t>(
      interpreter::CreateObjectLiteralFlags::FlagsBits::decode(flags));
  if (flags &
      interpreter::CreateObjectLiteralFlags::FastCloneSupportedBit::kMask) {
    CallBuiltin<Builtin::kCreateShallowObjectLiteral>(
        FeedbackVector(),                           // feedback vector
        IndexAsTagged(1),                           // slot
        Constant<ObjectBoilerplateDescription>(0),  // boilerplate
        Smi::FromInt(flags_raw));                   // flags
  } else {
    CallBuiltin<Builtin::kCreateObjectFromSlowBoilerplate>(
        FeedbackVector(),                           // feedback vector
        IndexAsTagged(1),                           // slot
        Constant<ObjectBoilerplateDescription>(0),  // boilerplate
        Smi::FromInt(flags_raw));                   // flags
  }
}

void BaselineCompiler::VisitCreateEmptyObjectLiteral() {
  CallBuiltin<Builtin::kCreateEmptyLiteralObject>();
}

void BaselineCompiler::VisitCloneObject() {
  uint32_t flags = Flag8(1);
  int32_t raw_flags =
      interpreter::CreateObjectLiteralFlags::FlagsBits::decode(flags);
  CallBuiltin<Builtin::kCloneObjectICBaseline>(
      RegisterOperand(0),       // source
      Smi::FromInt(raw_flags),  // flags
      IndexAsTagged(2));        // slot
}

void BaselineCompiler::VisitGetTemplateObject() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  CallBuiltin<Builtin::kGetTemplateObject>(
      shared_function_info_,    // shared function info
      Constant<HeapObject>(0),  // description
      Index(1),                 // slot
      FeedbackVector());        // feedback_vector
}

void BaselineCompiler::VisitCreateClosure() {
  Register feedback_cell =
      FastNewClosureBaselineDescriptor::GetRegisterParameter(
          FastNewClosureBaselineDescriptor::kFeedbackCell);
  LoadClosureFeedbackArray(feedback_cell);
  __ LoadFixedArrayElement(feedback_cell, feedback_cell, Index(1));

  uint32_t flags = Flag8(2);
  if (interpreter::CreateClosureFlags::FastNewClosureBit::decode(flags)) {
    CallBuiltin<Builtin::kFastNewClosureBaseline>(
        Constant<SharedFunctionInfo>(0), feedback_cell);
  } else {
    Runtime::FunctionId function_id =
        interpreter::CreateClosureFlags::PretenuredBit::decode(flags)
            ? Runtime::kNewClosure_Tenured
            : Runtime::kNewClosure;
    CallRuntime(function_id, Constant<SharedFunctionInfo>(0), feedback_cell);
  }
}

void BaselineCompiler::VisitCreateBlockContext() {
  CallRuntime(Runtime::kPushBlockContext, Constant<ScopeInfo>(0));
}

void BaselineCompiler::VisitCreateCatchContext() {
  CallRuntime(Runtime::kPushCatchContext,
              RegisterOperand(0),  // exception
              Constant<ScopeInfo>(1));
}

void BaselineCompiler::VisitCreateFunctionContext() {
  Handle<ScopeInfo> info = Constant<ScopeInfo>(0);
  uint32_t slot_count = Uint(1);
  DCHECK_LE(slot_count, ConstructorBuiltins::MaximumFunctionContextSlots());
  DCHECK_EQ(info->scope_type(), ScopeType::FUNCTION_SCOPE);
  CallBuiltin<Builtin::kFastNewFunctionContextFunction>(info, slot_count);
}

void BaselineCompiler::VisitCreateEvalContext() {
  Handle<ScopeInfo> info = Constant<ScopeInfo>(0);
  uint32_t slot_count = Uint(1);
  if (slot_count < static_cast<uint32_t>(
                       ConstructorBuiltins::MaximumFunctionContextSlots())) {
    DCHECK_EQ(info->scope_type(), ScopeType::EVAL_SCOPE);
    CallBuiltin<Builtin::kFastNewFunctionContextEval>(info, slot_count);
  } else {
    CallRuntime(Runtime::kNewFunctionContext, Constant<ScopeInfo>(0));
  }
}

void BaselineCompiler::VisitCreateWithContext() {
  CallRuntime(Runtime::kPushWithContext,
              RegisterOperand(0),  // object
              Constant<ScopeInfo>(1));
}

void BaselineCompiler::VisitCreateMappedArguments() {
  if (shared_function_info_->has_duplicate_parameters()) {
    CallRuntime(Runtime::kNewSloppyArguments, __ FunctionOperand());
  } else {
    CallBuiltin<Builtin::kFastNewSloppyArguments>(__ FunctionOperand());
  }
}

void BaselineCompiler::VisitCreateUnmappedArguments() {
  CallBuiltin<Builtin::kFastNewStrictArguments>(__ FunctionOperand());
}

void BaselineCompiler::VisitCreateRestParameter() {
  CallBuiltin<Builtin::kFastNewRestArguments>(__ FunctionOperand());
}

void BaselineCompiler::VisitJumpLoop() {
#ifndef V8_JITLESS
  Label osr_armed, osr_not_armed;
  using D = OnStackReplacementDescriptor;
  Register feedback_vector = Register::no_reg();
  Register osr_state = Register::no_reg();
  const int loop_depth = iterator().GetImmediateOperand(1);
  {
    ASM_CODE_COMMENT_STRING(&masm_, "OSR Check Armed");
    BaselineAssembler::ScratchRegisterScope temps(&basm_);
    feedback_vector = temps.AcquireScratch();
    osr_state = temps.AcquireScratch();
    LoadFeedbackVector(feedback_vector);
    __ LoadWord8Field(osr_state, feedback_vector,
                      FeedbackVector::kOsrStateOffset);
    static_assert(FeedbackVector::MaybeHasMaglevOsrCodeBit::encode(true) >
                  FeedbackVector::kMaxOsrUrgency);
    static_assert(FeedbackVector::MaybeHasTurbofanOsrCodeBit::encode(true) >
                  FeedbackVector::kMaxOsrUrgency);
    __ JumpIfByte(kUnsignedGreaterThan, osr_state, loop_depth, &osr_armed,
                  Label::kNear);
  }

  __ Bind(&osr_not_armed);
#endif  // !V8_JITLESS
  Label* label = &labels_[iterator().GetJumpTargetOffset()];
  int weight = iterator().GetRelativeJumpTargetOffset() -
               iterator().current_bytecode_size_without_prefix();
  // We can pass in the same label twice since it's a back edge and thus already
  // bound.
  DCHECK(label->is_bound());
  UpdateInterruptBudgetAndJumpToLabel(weight, label, label, kEnableStackCheck);

#ifndef V8_JITLESS
  {
    // In case we deopt during the above interrupt check then this part of the
    // jump loop is skipped. This is not a problem as nothing observable happens
    // here.
#ifdef DEBUG
    effect_state_.safe_to_skip = true;
#endif

    ASM_CODE_COMMENT_STRING(&masm_, "OSR Handle Armed");
    __ Bind(&osr_armed);
    Register maybe_target_code = D::MaybeTargetCodeRegister();
    Label osr;
    {
      BaselineAssembler::ScratchRegisterScope temps(&basm_);
      Register scratch0 = temps.AcquireScratch();
      Register scratch1 = temps.AcquireScratch();
      DCHECK_EQ(scratch0, feedback_vector);
      DCHECK_EQ(scratch1, osr_state);
      DCHECK(!AreAliased(maybe_target_code, scratch0, scratch1));
      __ TryLoadOptimizedOsrCode(maybe_target_code, scratch0,
                                 iterator().GetSlotOperand(2), &osr,
                                 Label::kNear);
      __ DecodeField<FeedbackVector::OsrUrgencyBits>(scratch1);
      __ JumpIfByte(kUnsignedLessThanEqual, scratch1, loop_depth,
                    &osr_not_armed, Label::kNear);
    }

    __ Bind(&osr);
    Label do_osr;
    int weight = bytecode_->length() * v8_flags.osr_to_tierup;
    __ Push(maybe_target_code);
    UpdateInterruptBudgetAndJumpToLabel(-weight, nullptr, &do_osr,
                                        kDisableStackCheck);
    __ Bind(&do_osr);
    __ Pop(maybe_target_code);
    CallBuiltin<Builtin::kBaselineOnStackReplacement>(maybe_target_code);
    __ AddToInterruptBudgetAndJumpIfNotExceeded(weight, nullptr);
    __ Jump(&osr_not_armed, Label::kNear);

#ifdef DEBUG
    effect_state_.safe_to_skip = false;
#endif
  }
#endif  // !V8_JITLESS
}

void BaselineCompiler::VisitJump() { __ Jump(BuildForwardJumpLabel()); }

void BaselineCompiler::VisitJumpConstant() { VisitJump(); }

void BaselineCompiler::VisitJumpIfNullConstant() { VisitJumpIfNull(); }

void BaselineCompiler::VisitJumpIfNotNullConstant() { VisitJumpIfNotNull(); }

void BaselineCompiler::VisitJumpIfUndefinedConstant() {
  VisitJumpIfUndefined();
}

void BaselineCompiler::VisitJumpIfNotUndefinedConstant() {
  VisitJumpIfNotUndefined();
}

void BaselineCompiler::VisitJumpIfUndefinedOrNullConstant() {
  VisitJumpIfUndefinedOrNull();
}

void BaselineCompiler::VisitJumpIfTrueConstant() { VisitJumpIfTrue(); }

void BaselineCompiler::VisitJumpIfFalseConstant() { VisitJumpIfFalse(); }

void BaselineCompiler::VisitJumpIfJSReceiverConstant() {
  VisitJumpIfJSReceiver();
}

void BaselineCompiler::VisitJumpIfForInDoneConstant() {
  VisitJumpIfForInDone();
}

void BaselineCompiler::VisitJumpIfToBooleanTrueConstant() {
  VisitJumpIfToBooleanTrue();
}

void BaselineCompiler::VisitJumpIfToBooleanFalseConstant() {
  VisitJumpIfToBooleanFalse();
}

void BaselineCompiler::VisitJumpIfToBooleanTrue() {
  Label dont_jump;
  JumpIfToBoolean(false, &dont_jump, Label::kNear);
  __ Jump(BuildForwardJumpLabel());
  __ Bind(&dont_jump);
}

void BaselineCompiler::VisitJumpIfToBooleanFalse() {
  Label dont_jump;
  JumpIfToBoolean(true, &dont_jump, Label::kNear);
  __ Jump(BuildForwardJumpLabel());
  __ Bind(&dont_jump);
}

void BaselineCompiler::VisitJumpIfTrue() { JumpIfRoot(RootIndex::kTrueValue); }

void BaselineCompiler::VisitJumpIfFalse() {
  JumpIfRoot(RootIndex::kFalseValue);
}

void BaselineCompiler::VisitJumpIfNull() { JumpIfRoot(RootIndex::kNullValue); }

void BaselineCompiler::VisitJumpIfNotNull() {
  JumpIfNotRoot(RootIndex::kNullValue);
}

void BaselineCompiler::VisitJumpIfUndefined() {
  JumpIfRoot(RootIndex::kUndefinedValue);
}

void BaselineCompiler::VisitJumpIfNotUndefined() {
  JumpIfNotRoot(RootIndex::kUndefinedValue);
}

void BaselineCompiler::VisitJumpIfUndefinedOrNull() {
  Label do_jump, dont_jump;
  __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kUndefinedValue,
                &do_jump);
  __ JumpIfNotRoot(kInterpreterAccumulatorRegister, RootIndex::kNullValue,
                   &dont_jump, Label::kNear);
  __ Bind(&do_jump);
  __ Jump(BuildForwardJumpLabel());
  __ Bind(&dont_jump);
}

void BaselineCompiler::VisitJumpIfJSReceiver() {
  Label is_smi, dont_jump;
  __ JumpIfSmi(kInterpreterAccumulatorRegister, &is_smi, Label::kNear);

#if V8_STATIC_ROOTS_BOOL
  __ JumpIfJSAnyIsPrimitive(kInterpreterAccumulatorRegister, &dont_jump,
                            Label::Distance::kNear);
#else
  __ JumpIfObjectTypeFast(kLessThan, kInterpreterAccumulatorRegister,
                          FIRST_JS_RECEIVER_TYPE, &dont_jump);
#endif
  __ Jump(BuildForwardJumpLabel());

  __ Bind(&is_smi);
  __ Bind(&dont_jump);
}

void BaselineCompiler::VisitJumpIfForInDone() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register index = scratch_scope.AcquireScratch();
  LoadRegister(index, 1);
  __ JumpIfTagged(kEqual, index, __ RegisterFrameOperand(RegisterOperand(2)),
                  BuildForwardJumpLabel());
}

void BaselineCompiler::VisitSwitchOnSmiNoFeedback() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  interpreter::JumpTableTargetOffsets offsets =
      iterator().GetJumpTableTargetOffsets();

  if (offsets.size() == 0) return;

  int case_value_base = (*offsets.begin()).case_value;

  std::unique_ptr<Label*[]> labels = std::make_unique<Label*[]>(offsets.size());
  for (interpreter::JumpTableTargetOffset offset : offsets) {
    labels[offset.case_value - case_value_base] =
        EnsureLabel(offset.target_offset);
  }
  Register case_value = scratch_scope.AcquireScratch();
  __ SmiUntag(case_value, kInterpreterAccumulatorRegister);
  __ Switch(case_value, case_value_base, labels.get(), offsets.size());
}

void BaselineCompiler::VisitForInEnumerate() {
  CallBuiltin<Builtin::kForInEnumerate>(RegisterOperand(0));
}

void BaselineCompiler::VisitForInPrepare() {
  StoreRegister(0, kInterpreterAccumulatorRegister);
  CallBuiltin<Builtin::kForInPrepare>(kInterpreterAccumulatorRegister,
                                      IndexAsTagged(1), FeedbackVector());
  interpreter::Register first = iterator().GetRegisterOperand(0);
  interpreter::Register second(first.index() + 1);
  interpreter::Register third(first.index() + 2);
  __ StoreRegister(second, kReturnRegister0);
  __ StoreRegister(third, kReturnRegister1);
}

void BaselineCompiler::VisitForInNext() {
  interpreter::Register cache_type, cache_array;
  std::tie(cache_type, cache_array) = iterator().GetRegisterPairOperand(2);
  CallBuiltin<Builtin::kForInNext>(Index(3),            // vector slot
                                   RegisterOperand(0),  // object
                                   cache_array,         // cache array
                                   cache_type,          // cache type
                                   RegisterOperand(1),  // index
                                   FeedbackVector());   // feedback vector
}

void BaselineCompiler::VisitForInStep() {
  __ IncrementSmi(__ RegisterFrameOperand(RegisterOperand(0)));
}

void BaselineCompiler::VisitSetPendingMessage() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register pending_message = scratch_scope.AcquireScratch();
  __ Move(pending_message,
          ExternalReference::address_of_pending_message(local_isolate_));
  Register tmp = scratch_scope.AcquireScratch();
  __ Move(tmp, kInterpreterAccumulatorRegister);
  __ Move(kInterpreterAccumulatorRegister, MemOperand(pending_message, 0));
  __ Move(MemOperand(pending_message, 0), tmp);
}

void BaselineCompiler::VisitThrow() {
  CallRuntime(Runtime::kThrow, kInterpreterAccumulatorRegister);
  __ Trap();
}

void BaselineCompiler::VisitReThrow() {
  CallRuntime(Runtime::kReThrow, kInterpreterAccumulatorRegister);
  __ Trap();
}

void BaselineCompiler::VisitReturn() {
  ASM_CODE_COMMENT_STRING(&masm_, "Return");
  int profiling_weight = iterator().current_offset() +
                         iterator().current_bytecode_size_without_prefix();
  int parameter_count = bytecode_->parameter_count();

  TailCallBuiltin<Builtin::kBaselineLeaveFrame>(parameter_count,
                                                -profiling_weight);
}

void BaselineCompiler::VisitThrowReferenceErrorIfHole() {
  Label done;
  __ JumpIfNotRoot(kInterpreterAccumulatorRegister, RootIndex::kTheHoleValue,
                   &done);
  CallRuntime(Runtime::kThrowAccessedUninitializedVariable, Constant<Name>(0));
  // Unreachable.
  __ Trap();
  __ Bind(&done);
}

void BaselineCompiler::VisitThrowSuperNotCalledIfHole() {
  Label done;
  __ JumpIfNotRoot(kInterpreterAccumulatorRegister, RootIndex::kTheHoleValue,
                   &done);
  CallRuntime(Runtime::kThrowSuperNotCalled);
  // Unreachable.
  __ Trap();
  __ Bind(&done);
}

void BaselineCompiler::VisitThrowSuperAlreadyCalledIfNotHole() {
  Label done;
  __ JumpIfRoot(kInterpreterAccumulatorRegister, RootIndex::kTheHoleValue,
                &done);
  CallRuntime(Runtime::kThrowSuperAlreadyCalledError);
  // Unreachable.
  __ Trap();
  __ Bind(&done);
}

void BaselineCompiler::VisitThrowIfNotSuperConstructor() {
  Label done;

  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register reg = scratch_scope.AcquireScratch();
  LoadRegister(reg, 0);
  Register map_bit_field = scratch_scope.AcquireScratch();
  __ LoadMap(map_bit_field, reg);
  __ LoadWord8Field(map_bit_field, map_bit_field, Map::kBitFieldOffset);
  __ TestAndBranch(map_bit_field, Map::Bits1::IsConstructorBit::kMask, kNotZero,
                   &done, Label::kNear);

  CallRuntime(Runtime::kThrowNotSuperConstructor, reg, __ FunctionOperand());

  __ Bind(&done);
}

void BaselineCompiler::VisitSwitchOnGeneratorState() {
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);

  Label fallthrough;

  Register generator_object = scratch_scope.AcquireScratch();
  LoadRegister(generator_object, 0);
  __ JumpIfRoot(generator_object, RootIndex::kUndefinedValue, &fallthrough);

  Register continuation = scratch_scope.AcquireScratch();
  __ LoadTaggedSignedFieldAndUntag(continuation, generator_object,
                                   JSGeneratorObject::kContinuationOffset);
  __ StoreTaggedSignedField(
      generator_object, JSGeneratorObject::kContinuationOffset,
      Smi::FromInt(JSGeneratorObject::kGeneratorExecuting));

  Register context = scratch_scope.AcquireScratch();
  __ LoadTaggedField(context, generator_object,
                     JSGeneratorObject::kContextOffset);
  __ StoreContext(context);

  interpreter::JumpTableTargetOffsets offsets =
      iterator().GetJumpTableTargetOffsets();

  if (0 < offsets.size()) {
    DCHECK_EQ(0, (*offsets.begin()).case_value);

    std::unique_ptr<Label*[]> labels =
        std::make_unique<Label*[]>(offsets.size());
    for (interpreter::JumpTableTargetOffset offset : offsets) {
      labels[offset.case_value] = EnsureLabel(offset.target_offset);
    }
    __ Switch(continuation, 0, labels.get(), offsets.size());
    // We should never fall through this switch.
    // TODO(v8:11429,leszeks): Maybe remove the fallthrough check in the Switch?
    __ Trap();
  }

  __ Bind(&fallthrough);
}

void BaselineCompiler::VisitSuspendGenerator() {
  DCHECK_EQ(iterator().GetRegisterOperand(1), interpreter::Register(0));
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register generator_object = scratch_scope.AcquireScratch();
  LoadRegister(generator_object, 0);
  {
    SaveAccumulatorScope accumulator_scope(this, &basm_);

    int bytecode_offset =
        BytecodeArray::kHeaderSize + iterator().current_offset();
    CallBuiltin<Builtin::kSuspendGeneratorBaseline>(
        generator_object,
        static_cast<int>(Uint(3)),  // suspend_id
        bytecode_offset,
        static_cast<int>(RegisterCount(2)));  // register_count
  }
  int parameter_count = bytecode_->parameter_count();

  TailCallBuiltin<Builtin::kBaselineLeaveFrame>(parameter_count, 0);
}

void BaselineCompiler::VisitResumeGenerator() {
  DCHECK_EQ(iterator().GetRegisterOperand(1), interpreter::Register(0));
  BaselineAssembler::ScratchRegisterScope scratch_scope(&basm_);
  Register generator_object = scratch_scope.AcquireScratch();
  LoadRegister(generator_object, 0);
  CallBuiltin<Builtin::kResumeGeneratorBaseline>(
      generator_object,
      static_cast<int>(RegisterCount(2)));  // register_count
}

void BaselineCompiler::VisitGetIterator() {
  CallBuiltin<Builtin::kGetIteratorBaseline>(RegisterOperand(0),  // receiver
                                             IndexAsTagged(1),    // load_slot
                                             IndexAsTagged(2));   // call_slot
}

void BaselineCompiler::VisitDebugger() {
  CallRuntime(Runtime::kHandleDebuggerStatement);
}

void BaselineCompiler::VisitIncBlockCounter() {
  SaveAccumulatorScope accumulator_scope(this, &basm_);
  CallBuiltin<Builtin::kIncBlockCounter>(__ FunctionOperand(),
                                         IndexAsSmi(0));  // coverage array slot
}

void BaselineCompiler::VisitAbort() {
  CallRuntime(Runtime::kAbort, Smi::FromInt(Index(0)));
  __ Trap();
}

void BaselineCompiler::VisitWide() {
  // Consumed by the BytecodeArrayIterator.
  UNREACHABLE();
}

void BaselineCompiler::VisitExtraWide() {
  // Consumed by the BytecodeArrayIterator.
  UNREACHABLE();
}

void BaselineCompiler::VisitIllegal() {
  // Not emitted in valid bytecode.
  UNREACHABLE();
}
#define DEBUG_BREAK(Name, ...) \
  void BaselineCompiler::Visit##Name() { UNREACHABLE(); }
DEBUG_BREAK_BYTECODE_LIST(DEBUG_BREAK)
#undef DEBUG_BREAK

SaveAccumulatorScope::SaveAccumulatorScope(BaselineCompiler* compiler,
                                           BaselineAssembler* assembler)
    :
#ifdef DEBUG
      compiler_(compiler),
#endif
      assembler_(assembler) {
#ifdef DEBUG
  DCHECK(!compiler_->effect_state_.accumulator_on_stack);
  compiler_->effect_state_.accumulator_on_stack = true;
#endif  // DEBUG
  ASM_CODE_COMMENT(assembler_->masm());
  assembler_->Push(kInterpreterAccumulatorRegister);
}

SaveAccumulatorScope::~SaveAccumulatorScope() {
#ifdef DEBUG
  DCHECK(compiler_->effect_state_.accumulator_on_stack);
  compiler_->effect_state_.accumulator_on_stack = false;
#endif  // DEBUG
  ASM_CODE_COMMENT(assembler_->masm());
  assembler_->Pop(kInterpreterAccumulatorRegister);
}

#undef RCS_BASELINE_SCOPE
#undef __

}  // namespace baseline
}  // namespace internal
}  // namespace v8
```