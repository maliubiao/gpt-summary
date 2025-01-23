Response: Let's break down the thought process for analyzing this C++ file and generating the summary and JavaScript examples.

1. **Understanding the Goal:** The request asks for a summary of the C++ file's functionality and its relation to JavaScript, illustrated with JavaScript examples.

2. **Initial Scan for Keywords:**  I'd first scan the file for obvious keywords and concepts related to generators and JavaScript execution. I'd look for:
    * `Generator` (appears frequently)
    * `AsyncModule`
    * `builtins` (part of the file path and class name)
    * `JSGeneratorObject`
    * `.next`, `.return`, `.throw` (standard generator methods)
    * `Resume`
    * `Suspend`
    * `Trampoline`
    * `Context`
    * `Bytecode`
    * `Builtin` (calls to built-in functions)
    * `Runtime` (calls to runtime functions)

3. **Identifying Key Classes and Functions:**  Based on the keywords, I'd identify the main class: `GeneratorBuiltinsAssembler`. The constructor and protected methods (`InnerResume`, `GeneratorPrototypeResume`, `LoadParameterCountWithoutReceiverFromBaseline`) would be noted as core components. The `TF_BUILTIN` macros immediately flag functions that are exposed as built-in JavaScript methods.

4. **Analyzing `InnerResume`:** This function seems central. I'd analyze its steps:
    * Checks if the generator is closed or running.
    * Stores the `resume_mode`.
    * Calls `Builtin::kResumeGeneratorTrampoline`. This suggests a mechanism for actually resuming execution.
    * Handles exceptions.
    * Wraps the result in `IteratorResult` if the generator is not suspended.
    * Handles the case where the generator is already closed.
    * Throws an error if the generator is already running.

5. **Understanding `GeneratorPrototypeResume`:** This function seems to be a wrapper around `InnerResume`, performing a type check to ensure the receiver is a `JSGeneratorObject`.

6. **Examining the `TF_BUILTIN` Functions:** I'd go through each `TF_BUILTIN` function, noting its name and how it relates to standard JavaScript generator methods or concepts:
    * `AsyncModuleEvaluate`:  Handles the initial evaluation of async modules, relating it to resuming an async function.
    * `GeneratorPrototypeNext`, `GeneratorPrototypeReturn`, `GeneratorPrototypeThrow`: These directly correspond to the JavaScript generator methods. They call `GeneratorPrototypeResume`.
    * `SuspendGeneratorBaseline`:  Handles suspending a generator's execution, storing its state (context, parameters, registers). The "Baseline" likely refers to a specific optimization tier.
    * `ResumeGeneratorBaseline`: Handles resuming a suspended generator, restoring its state.

7. **Connecting to JavaScript:**  As I analyzed the C++ code, I'd actively think about how these operations manifest in JavaScript.
    * `yield`:  Clearly related to the suspension and resumption logic.
    * `generator.next()`, `generator.return()`, `generator.throw()`: Direct mappings to the built-in functions.
    * `async function*`:  The `AsyncModuleEvaluate` and the mention of `JSAsyncFunctionObject` link to asynchronous generators.

8. **Formulating the Summary:**  Based on the analysis, I'd structure the summary to cover:
    * The file's purpose (implementing built-in generator methods).
    * The core functionality of `InnerResume` (the central logic).
    * How the other functions relate to `InnerResume`.
    * The role of `SuspendGeneratorBaseline` and `ResumeGeneratorBaseline` in the generator's lifecycle.
    * The connection to asynchronous modules.

9. **Creating JavaScript Examples:** For each key C++ function/concept, I'd create a corresponding JavaScript example to illustrate its effect. The examples should be simple and directly demonstrate the behavior being described in the C++ code. For instance:
    * `GeneratorPrototypeNext`: A basic generator with `yield` and calling `next()`.
    * `GeneratorPrototypeReturn`: Using `return()` to close a generator.
    * `GeneratorPrototypeThrow`: Using `throw()` to inject an error.
    * `AsyncModuleEvaluate`:  An example of an `async function*` to show the asynchronous nature.
    * `SuspendGeneratorBaseline` and `ResumeGeneratorBaseline`: While not directly callable from JavaScript, I'd explain how `yield` triggers these internal mechanisms.

10. **Refinement and Organization:** I'd review the summary and examples for clarity, accuracy, and completeness. I'd ensure the language is accessible and that the connection between the C++ code and JavaScript behavior is clear. I'd organize the information logically, starting with the general purpose and then delving into specifics.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the file is just about the basic `.next()`, `.return()`, `.throw()` methods.
* **Correction:**  Realizing the `AsyncModuleEvaluate` function and the mention of "baseline" suggests broader functionality related to the generator's lifecycle and even asynchronous generators.
* **Initial thought:** Focus only on the public built-in functions.
* **Correction:**  Recognizing the importance of `SuspendGeneratorBaseline` and `ResumeGeneratorBaseline` in understanding how generator state is managed internally. Even though not directly exposed to JavaScript, explaining their role is crucial for a complete understanding.
* **Ensuring Clarity of Examples:**  Making sure the JavaScript examples are concise and directly illustrate the corresponding C++ functionality. Avoiding overly complex scenarios.

By following this structured approach of scanning, analyzing key components, connecting to JavaScript, and refining, I can arrive at a comprehensive and accurate summary and relevant JavaScript examples.
这个C++源代码文件 `builtins-generator-gen.cc` 实现了 **V8 JavaScript 引擎中关于 Generator (生成器) 的内置函数**。它使用了 V8 的 CodeStubAssembler (CSA) 框架来生成高效的机器码。

**主要功能归纳:**

1. **实现 Generator 原型方法:**  该文件实现了 `Generator.prototype.next()`, `Generator.prototype.return(value)`, 和 `Generator.prototype.throw(exception)` 这三个核心的生成器原型方法。
2. **处理 Generator 的状态转换:**  它包含了处理生成器暂停、恢复和关闭的逻辑。这涉及到检查生成器的状态（例如是否已经关闭或正在运行），并根据调用的方法更新生成器的状态。
3. **与 Async Function 的关联:**  该文件还处理了 Async Modules 的 `evaluate` 方法，因为 Async Modules 在 V8 中是构建在 JSAsyncFunctionObjects 之上，而 JSAsyncFunctionObjects 又与 Generator 有相似的执行机制（基于 yield）。
4. **使用 Trampoline 进行恢复:**  它使用 `Builtin::kResumeGeneratorTrampoline` 这个内置函数来实际恢复生成器的执行。
5. **处理异常:**  它包含了在生成器执行过程中发生异常时的处理逻辑。
6. **存储和恢复生成器状态:**  `SuspendGeneratorBaseline` 和 `ResumeGeneratorBaseline` 这两个内置函数负责在生成器暂停时存储其上下文（参数、寄存器等），并在恢复时重新加载这些状态。这对于 `yield` 关键字的功能至关重要。

**与 JavaScript 的关系及 JavaScript 示例:**

这个 C++ 文件中定义的内置函数直接对应于 JavaScript 中 Generator 对象的方法和行为。

**1. `Generator.prototype.next()`:**

* **C++ 实现:** `TF_BUILTIN(GeneratorPrototypeNext, GeneratorBuiltinsAssembler)`
* **功能:**  恢复生成器的执行，直到遇到下一个 `yield` 表达式。
* **JavaScript 示例:**

```javascript
function* myGenerator() {
  yield 1;
  yield 2;
  return 3;
}

const generator = myGenerator();
console.log(generator.next()); // 输出: { value: 1, done: false }
console.log(generator.next()); // 输出: { value: 2, done: false }
console.log(generator.next()); // 输出: { value: 3, done: true }
console.log(generator.next()); // 输出: { value: undefined, done: true }
```

**2. `Generator.prototype.return(value)`:**

* **C++ 实现:** `TF_BUILTIN(GeneratorPrototypeReturn, GeneratorBuiltinsAssembler)`
* **功能:**  强制生成器结束执行，并返回指定的值。
* **JavaScript 示例:**

```javascript
function* myGenerator() {
  yield 1;
  yield 2;
}

const generator = myGenerator();
console.log(generator.next());       // 输出: { value: 1, done: false }
console.log(generator.return('done')); // 输出: { value: 'done', done: true }
console.log(generator.next());       // 输出: { value: undefined, done: true }
```

**3. `Generator.prototype.throw(exception)`:**

* **C++ 实现:** `TF_BUILTIN(GeneratorPrototypeThrow, GeneratorBuiltinsAssembler)`
* **功能:**  向生成器中抛出一个错误。
* **JavaScript 示例:**

```javascript
function* myGenerator() {
  try {
    yield 1;
    yield 2;
  } catch (e) {
    console.log('Caught:', e);
  }
}

const generator = myGenerator();
console.log(generator.next()); // 输出: { value: 1, done: false }
generator.throw(new Error('Something went wrong')); // 输出: Caught: Error: Something went wrong
console.log(generator.next()); // 生成器已经结束，输出: { value: undefined, done: true }
```

**4. `AsyncModuleEvaluate` (与 Async Function 关联):**

* **C++ 实现:** `TF_BUILTIN(AsyncModuleEvaluate, GeneratorBuiltinsAssembler)`
* **功能:**  启动异步模块的执行。由于异步函数使用了类似的生成器机制，这个内置函数也与生成器的恢复逻辑相关。
* **JavaScript 示例:**

```javascript
// 假设这是一个异步模块
async function* myAsyncGenerator() {
  console.log('Starting async generator');
  yield 1;
  console.log('After first yield');
  yield 2;
  return 3;
}

const asyncGenerator = myAsyncGenerator();
asyncGenerator.next().then(result => console.log(result));
// 输出: Starting async generator
// 输出: { value: 1, done: false } (可能在稍后)
asyncGenerator.next().then(result => console.log(result));
// 输出: After first yield
// 输出: { value: 2, done: false } (可能在稍后)
asyncGenerator.next().then(result => console.log(result));
// 输出: { value: 3, done: true } (可能在稍后)
```

**5. `SuspendGeneratorBaseline` 和 `ResumeGeneratorBaseline` (内部机制):**

* **C++ 实现:** `TF_BUILTIN(SuspendGeneratorBaseline, GeneratorBuiltinsAssembler)` 和 `TF_BUILTIN(ResumeGeneratorBaseline, GeneratorBuiltinsAssembler)`
* **功能:**  这两个函数是 V8 内部用于暂停和恢复生成器执行的关键机制。当 JavaScript 代码执行到 `yield` 关键字时，`SuspendGeneratorBaseline` 会被调用，保存生成器的当前状态。当调用 `next()`, `return()`, 或 `throw()` 时，`ResumeGeneratorBaseline` 会被调用，恢复之前保存的状态，继续执行。
* **JavaScript 示例 (隐式使用):**

```javascript
function* myGenerator() {
  console.log('Before yield');
  yield 1; // 这里会触发 SuspendGeneratorBaseline
  console.log('After yield'); // 下次 next() 调用会触发 ResumeGeneratorBaseline
  yield 2;
}

const generator = myGenerator();
generator.next(); // 输出: Before yield
generator.next(); // 输出: After yield
```

总而言之，`builtins-generator-gen.cc` 文件是 V8 引擎中实现 JavaScript Generator 功能的核心组成部分，它通过 C++ 代码和 CodeStubAssembler 框架高效地实现了生成器的方法和状态管理，使得 JavaScript 中的生成器能够正常运行。

### 提示词
```
这是目录为v8/src/builtins/builtins-generator-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/execution/isolate.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

class GeneratorBuiltinsAssembler : public CodeStubAssembler {
 public:
  explicit GeneratorBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

 protected:
  // Currently, AsyncModules in V8 are built on top of JSAsyncFunctionObjects
  // with an initial yield. Thus, we need some way to 'resume' the
  // underlying JSAsyncFunctionObject owned by an AsyncModule. To support this
  // the body of resume is factored out below, and shared by JSGeneratorObject
  // prototype methods as well as AsyncModuleEvaluate. The only difference
  // between AsyncModuleEvaluate and JSGeneratorObject::PrototypeNext is
  // the expected receiver.
  void InnerResume(CodeStubArguments* args, TNode<JSGeneratorObject> receiver,
                   TNode<Object> value, TNode<Context> context,
                   JSGeneratorObject::ResumeMode resume_mode,
                   char const* const method_name);
  void GeneratorPrototypeResume(CodeStubArguments* args, TNode<Object> receiver,
                                TNode<Object> value, TNode<Context> context,
                                JSGeneratorObject::ResumeMode resume_mode,
                                char const* const method_name);

  TNode<IntPtrT> LoadParameterCountWithoutReceiverFromBaseline();
};

TNode<IntPtrT>
GeneratorBuiltinsAssembler::LoadParameterCountWithoutReceiverFromBaseline() {
  auto parameter_count = LoadBytecodeArrayParameterCountWithoutReceiver(
      LoadBytecodeArrayFromBaseline());
  return Signed(ChangeUint32ToWord(parameter_count));
}

void GeneratorBuiltinsAssembler::InnerResume(
    CodeStubArguments* args, TNode<JSGeneratorObject> receiver,
    TNode<Object> value, TNode<Context> context,
    JSGeneratorObject::ResumeMode resume_mode, char const* const method_name) {
  // Check if the {receiver} is running or already closed.
  TNode<Smi> receiver_continuation =
      LoadObjectField<Smi>(receiver, JSGeneratorObject::kContinuationOffset);
  Label if_receiverisclosed(this, Label::kDeferred),
      if_receiverisrunning(this, Label::kDeferred);
  TNode<Smi> closed = SmiConstant(JSGeneratorObject::kGeneratorClosed);
  GotoIf(SmiEqual(receiver_continuation, closed), &if_receiverisclosed);
  DCHECK_LT(JSGeneratorObject::kGeneratorExecuting,
            JSGeneratorObject::kGeneratorClosed);
  GotoIf(SmiLessThan(receiver_continuation, closed), &if_receiverisrunning);

  // Remember the {resume_mode} for the {receiver}.
  StoreObjectFieldNoWriteBarrier(receiver, JSGeneratorObject::kResumeModeOffset,
                                 SmiConstant(resume_mode));

  // Resume the {receiver} using our trampoline.
  // Close the generator if there was an exception.
  TVARIABLE(Object, var_exception);
  Label if_exception(this, Label::kDeferred), if_final_return(this);
  TNode<Object> result;
  {
    compiler::ScopedExceptionHandler handler(this, &if_exception,
                                             &var_exception);
    result = CallBuiltin(Builtin::kResumeGeneratorTrampoline, context, value,
                         receiver);
  }

  // If the generator is not suspended (i.e., its state is 'executing'),
  // close it and wrap the return value in IteratorResult.
  TNode<Smi> result_continuation =
      LoadObjectField<Smi>(receiver, JSGeneratorObject::kContinuationOffset);

  // The generator function should not close the generator by itself, let's
  // check it is indeed not closed yet.
  CSA_DCHECK(this, SmiNotEqual(result_continuation, closed));

  TNode<Smi> executing = SmiConstant(JSGeneratorObject::kGeneratorExecuting);
  GotoIf(SmiEqual(result_continuation, executing), &if_final_return);

  args->PopAndReturn(result);

  BIND(&if_final_return);
  {
    // Close the generator.
    StoreObjectFieldNoWriteBarrier(
        receiver, JSGeneratorObject::kContinuationOffset, closed);
    // Return the wrapped result.
    args->PopAndReturn(CallBuiltin(Builtin::kCreateIterResultObject, context,
                                   result, TrueConstant()));
  }

  BIND(&if_receiverisclosed);
  {
    // The {receiver} is closed already.
    TNode<Object> builtin_result;
    switch (resume_mode) {
      case JSGeneratorObject::kNext:
        builtin_result = CallBuiltin(Builtin::kCreateIterResultObject, context,
                                     UndefinedConstant(), TrueConstant());
        break;
      case JSGeneratorObject::kReturn:
        builtin_result = CallBuiltin(Builtin::kCreateIterResultObject, context,
                                     value, TrueConstant());
        break;
      case JSGeneratorObject::kThrow:
        builtin_result = CallRuntime(Runtime::kThrow, context, value);
        break;
      case JSGeneratorObject::kRethrow:
        // Currently only async generators use this mode.
        UNREACHABLE();
    }
    args->PopAndReturn(builtin_result);
  }

  BIND(&if_receiverisrunning);
  { ThrowTypeError(context, MessageTemplate::kGeneratorRunning); }

  BIND(&if_exception);
  {
    StoreObjectFieldNoWriteBarrier(
        receiver, JSGeneratorObject::kContinuationOffset, closed);
    CallRuntime(Runtime::kReThrow, context, var_exception.value());
    Unreachable();
  }
}

void GeneratorBuiltinsAssembler::GeneratorPrototypeResume(
    CodeStubArguments* args, TNode<Object> receiver, TNode<Object> value,
    TNode<Context> context, JSGeneratorObject::ResumeMode resume_mode,
    char const* const method_name) {
  // Check if the {receiver} is actually a JSGeneratorObject.
  ThrowIfNotInstanceType(context, receiver, JS_GENERATOR_OBJECT_TYPE,
                         method_name);
  TNode<JSGeneratorObject> generator = CAST(receiver);
  InnerResume(args, generator, value, context, resume_mode, method_name);
}

TF_BUILTIN(AsyncModuleEvaluate, GeneratorBuiltinsAssembler) {
  const int kValueArg = 0;

  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  CodeStubArguments args(this, argc);

  TNode<Object> receiver = args.GetReceiver();
  TNode<Object> value = args.GetOptionalArgumentValue(kValueArg);
  auto context = Parameter<Context>(Descriptor::kContext);

  // AsyncModules act like JSAsyncFunctions. Thus we check here
  // that the {receiver} is a JSAsyncFunction.
  char const* const method_name = "[AsyncModule].evaluate";
  ThrowIfNotInstanceType(context, receiver, JS_ASYNC_FUNCTION_OBJECT_TYPE,
                         method_name);
  TNode<JSAsyncFunctionObject> async_function = CAST(receiver);
  InnerResume(&args, async_function, value, context, JSGeneratorObject::kNext,
              method_name);
}

// ES6 #sec-generator.prototype.next
TF_BUILTIN(GeneratorPrototypeNext, GeneratorBuiltinsAssembler) {
  const int kValueArg = 0;

  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  CodeStubArguments args(this, argc);

  TNode<Object> receiver = args.GetReceiver();
  TNode<Object> value = args.GetOptionalArgumentValue(kValueArg);
  auto context = Parameter<Context>(Descriptor::kContext);

  GeneratorPrototypeResume(&args, receiver, value, context,
                           JSGeneratorObject::kNext,
                           "[Generator].prototype.next");
}

// ES6 #sec-generator.prototype.return
TF_BUILTIN(GeneratorPrototypeReturn, GeneratorBuiltinsAssembler) {
  const int kValueArg = 0;

  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  CodeStubArguments args(this, argc);

  TNode<Object> receiver = args.GetReceiver();
  TNode<Object> value = args.GetOptionalArgumentValue(kValueArg);
  auto context = Parameter<Context>(Descriptor::kContext);

  GeneratorPrototypeResume(&args, receiver, value, context,
                           JSGeneratorObject::kReturn,
                           "[Generator].prototype.return");
}

// ES6 #sec-generator.prototype.throw
TF_BUILTIN(GeneratorPrototypeThrow, GeneratorBuiltinsAssembler) {
  const int kExceptionArg = 0;

  auto argc = UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount);
  CodeStubArguments args(this, argc);

  TNode<Object> receiver = args.GetReceiver();
  TNode<Object> exception = args.GetOptionalArgumentValue(kExceptionArg);
  auto context = Parameter<Context>(Descriptor::kContext);

  GeneratorPrototypeResume(&args, receiver, exception, context,
                           JSGeneratorObject::kThrow,
                           "[Generator].prototype.throw");
}

// TODO(cbruni): Merge with corresponding bytecode handler.
TF_BUILTIN(SuspendGeneratorBaseline, GeneratorBuiltinsAssembler) {
  auto generator = Parameter<JSGeneratorObject>(Descriptor::kGeneratorObject);
  auto context = LoadContextFromBaseline();
  StoreJSGeneratorObjectContext(generator, context);
  auto parameter_count = LoadParameterCountWithoutReceiverFromBaseline();
  auto suspend_id = SmiTag(UncheckedParameter<IntPtrT>(Descriptor::kSuspendId));
  StoreJSGeneratorObjectContinuation(generator, suspend_id);
  // Store the bytecode offset in the [input_or_debug_pos] field, to be used by
  // the inspector.
  auto bytecode_offset =
      SmiTag(UncheckedParameter<IntPtrT>(Descriptor::kBytecodeOffset));
  // Avoid the write barrier by using the generic helper.
  StoreObjectFieldNoWriteBarrier(
      generator, JSGeneratorObject::kInputOrDebugPosOffset, bytecode_offset);

  TNode<FixedArray> parameters_and_registers =
      LoadJSGeneratorObjectParametersAndRegisters(generator);
  auto parameters_and_registers_length =
      LoadAndUntagFixedArrayBaseLength(parameters_and_registers);

  // Copy over the function parameters
  auto parameter_base_index = IntPtrConstant(
      interpreter::Register::FromParameterIndex(0).ToOperand() + 1);
  CSA_CHECK(this,
            UintPtrLessThan(parameter_count, parameters_and_registers_length));
  auto parent_frame_pointer = LoadParentFramePointer();
  BuildFastLoop<IntPtrT>(
      IntPtrConstant(0), parameter_count,
      [=, this](TNode<IntPtrT> index) {
        auto reg_index = IntPtrAdd(parameter_base_index, index);
        TNode<Object> value = LoadFullTagged(parent_frame_pointer,
                                             TimesSystemPointerSize(reg_index));
        UnsafeStoreFixedArrayElement(parameters_and_registers, index, value);
      },
      1, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);

  // Iterate over register file and write values into array.
  // The mapping of register to array index must match that used in
  // BytecodeGraphBuilder::VisitResumeGenerator.
  auto register_base_index = IntPtrAdd(
      parameter_count, IntPtrConstant(interpreter::Register(0).ToOperand()));
  auto register_count = UncheckedParameter<IntPtrT>(Descriptor::kRegisterCount);
  auto end_index = IntPtrAdd(parameter_count, register_count);
  CSA_CHECK(this, UintPtrLessThan(end_index, parameters_and_registers_length));
  BuildFastLoop<IntPtrT>(
      parameter_count, end_index,
      [=, this](TNode<IntPtrT> index) {
        auto reg_index = IntPtrSub(register_base_index, index);
        TNode<Object> value = LoadFullTagged(parent_frame_pointer,
                                             TimesSystemPointerSize(reg_index));
        UnsafeStoreFixedArrayElement(parameters_and_registers, index, value);
      },
      1, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);

  // The return value is unused, defaulting to undefined.
  Return(UndefinedConstant());
}

// TODO(cbruni): Merge with corresponding bytecode handler.
TF_BUILTIN(ResumeGeneratorBaseline, GeneratorBuiltinsAssembler) {
  auto generator = Parameter<JSGeneratorObject>(Descriptor::kGeneratorObject);
  auto parameter_count = LoadParameterCountWithoutReceiverFromBaseline();

  TNode<FixedArray> parameters_and_registers =
      LoadJSGeneratorObjectParametersAndRegisters(generator);

  // Iterate over array and write values into register file.  Also erase the
  // array contents to not keep them alive artificially.
  auto register_base_index = IntPtrAdd(
      parameter_count, IntPtrConstant(interpreter::Register(0).ToOperand()));
  auto register_count = UncheckedParameter<IntPtrT>(Descriptor::kRegisterCount);
  auto end_index = IntPtrAdd(parameter_count, register_count);
  auto parameters_and_registers_length =
      LoadAndUntagFixedArrayBaseLength(parameters_and_registers);
  CSA_CHECK(this, UintPtrLessThan(end_index, parameters_and_registers_length));
  auto parent_frame_pointer = LoadParentFramePointer();
  BuildFastLoop<IntPtrT>(
      parameter_count, end_index,
      [=, this](TNode<IntPtrT> index) {
        TNode<Object> value =
            UnsafeLoadFixedArrayElement(parameters_and_registers, index);
        auto reg_index = IntPtrSub(register_base_index, index);
        StoreFullTaggedNoWriteBarrier(parent_frame_pointer,
                                      TimesSystemPointerSize(reg_index), value);
        UnsafeStoreFixedArrayElement(parameters_and_registers, index,
                                     StaleRegisterConstant(),
                                     SKIP_WRITE_BARRIER);
      },
      1, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);

  Return(LoadJSGeneratorObjectInputOrDebugPos(generator));
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```