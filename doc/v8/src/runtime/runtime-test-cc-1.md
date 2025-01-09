Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `v8/src/runtime/runtime-test.cc` file in the V8 JavaScript engine.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Purpose:** The file name `runtime-test.cc` strongly suggests that this code is related to *testing* the *runtime* functionality of V8. The prefix `RUNTIME_FUNCTION` further confirms this, as it defines functions callable from JavaScript within the V8 runtime.

2. **Analyze Individual `RUNTIME_FUNCTION` Blocks:**  Go through each `RUNTIME_FUNCTION` definition and try to understand its purpose. Look for keywords, function names, and operations performed.

3. **Group Similar Functionalities:**  Notice patterns and categorize the functions. For instance, several functions deal with optimization status (`Runtime_GetOptimizationStatus`), optimization control (`Runtime_DisableOptimizationFinalization`, `Runtime_WaitForBackgroundOptimization`, `Runtime_FinalizeOptimization`), and flushing compiled code (`Runtime_ForceFlush`). Others are related to debugging and printing (`Runtime_DebugPrint`, `Runtime_DebugTrace`, `Runtime_GlobalPrint`).

4. **Look for JavaScript Interaction:**  Some functions directly manipulate JavaScript objects or concepts. For example, `Runtime_GetFunctionForCurrentFrame` returns a JavaScript function, and functions like `Runtime_ClearFunctionFeedback` and those checking element kinds (`Runtime_HasFastElements`, etc.) interact with JavaScript object properties. The `Runtime_GetCallable` function is explicitly designed to create a callable object from JavaScript.

5. **Identify Testing-Specific Functions:**  Functions like `Runtime_SimulateNewspaceFull`, `Runtime_ScheduleGCInStackCheck`, `Runtime_TakeHeapSnapshot`, and `Runtime_SerializeDeserializeNow` are clearly intended for testing memory management, garbage collection, and snapshotting capabilities.

6. **Recognize Debugging and Introspection Tools:**  Functions such as `Runtime_DebugPrint`, `Runtime_DebugTrace`, `Runtime_DisassembleFunction`, `Runtime_SystemBreak`, `Runtime_TraceEnter`, and `Runtime_TraceExit` are standard debugging aids.

7. **Consider Error Handling and Control Flow:** Functions like `Runtime_Abort`, `Runtime_AbortJS`, and `Runtime_AbortCSADcheck` deal with controlled program termination, often used in debugging or testing scenarios when invariants are violated. `Runtime_SetForceSlowPath` allows forcing execution through slower code paths, likely for testing purposes.

8. **Infer Code Logic and Potential Inputs/Outputs:** For some functions, like `Runtime_GetOptimizationStatus`, try to understand the logic based on the conditions checked. Think about what inputs would lead to different status flags being set.

9. **Identify Potential User Errors:** Based on the function names and operations, consider common programming mistakes that could lead to these runtime functions being relevant (e.g., issues with object properties, incorrect function calls, memory management problems).

10. **Address Specific Instructions:**
    * **`.tq` extension:** The code explicitly checks for this and confirms it's not a Torque file.
    * **JavaScript examples:** For functions with JavaScript relevance, create simple JavaScript code snippets that demonstrate their use or the concepts they manipulate.
    * **Assumed inputs/outputs:** For logic-heavy functions, provide hypothetical inputs and the expected output based on the code.
    * **Common programming errors:** Give concrete examples of errors related to the function's domain.

11. **Synthesize the Summary:** Combine the categorized functionalities and specific observations into a concise summary, addressing the user's request for the functionality of the code snippet as the second part of a three-part series. Emphasize the testing nature of the code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus solely on individual function descriptions.
* **Correction:** Realized that grouping by functionality provides a higher-level understanding and is more useful for summarizing.
* **Initial thought:** Just list the function names.
* **Correction:** Recognized the need to explain *what* each function does.
* **Initial thought:**  Ignore the specific instructions about `.tq`, JavaScript examples, etc.
* **Correction:**  Remembered to address all parts of the user's prompt for a complete answer.

By following these steps, a comprehensive and accurate summary can be generated, as demonstrated in the provided good example answer.
好的，让我们来归纳一下这段代码的功能。

这段代码是 `v8/src/runtime/runtime-test.cc` 文件的一部分，它定义了一系列可以在 JavaScript 中调用的 **运行时函数 (Runtime Functions)**，主要用于 **测试和调试 V8 引擎的内部行为**。 由于文件后缀是 `.cc` 而不是 `.tq`，可以确定这不是 V8 Torque 源代码。

**这段代码的主要功能可以归纳为以下几点：**

1. **获取函数优化状态：**
   - `Runtime_GetOptimizationStatus`:  检查给定 JavaScript 函数的优化状态，例如是否正在进行优化、是否已优化、使用了哪些优化层（Baseline, Maglev, TurboFan）以及是否在调用栈上。

2. **控制函数优化流程：**
   - `Runtime_DisableOptimizationFinalization`:  禁用优化最终化，允许在后台完成的优化任务完成，但不立即安装优化后的代码。
   - `Runtime_WaitForBackgroundOptimization`:  等待所有后台优化任务完成。
   - `Runtime_FinalizeOptimization`:  强制完成优化最终化，安装所有待安装的优化代码。
   - `Runtime_ForceFlush`: 强制丢弃指定函数的已编译代码，使其回到未编译状态。

3. **获取当前调用帧的函数：**
   - `Runtime_GetFunctionForCurrentFrame`: 获取当前 JavaScript 调用帧对应的函数对象。

4. **创建特殊用途的对象：**
   - `Runtime_GetUndetectable`:  创建一个无法通过标准 JavaScript 检测手段（例如 `Object.keys()`）枚举其属性的对象。
   - `Runtime_GetCallable`: 创建一个可以像函数一样调用的对象，其内部调用会转发到全局对象上的指定函数。
   - `Runtime_GetAbstractModuleSource`: 获取用于创建抽象模块源的函数。

5. **清除函数反馈信息：**
   - `Runtime_ClearFunctionFeedback`: 清除指定函数的类型反馈信息，这会影响后续的优化决策。

6. **通知上下文已释放：**
   - `Runtime_NotifyContextDisposed`:  通知 V8 垃圾回收器一个 JavaScript 上下文已经被释放。

7. **设置分配超时：**
   - `Runtime_SetAllocationTimeout`: 设置堆分配的超时时间，以及控制是否启用内联分配（仅在 DEBUG 模式下）。

8. **模拟内存压力和垃圾回收：**
   - `Runtime_SimulateNewspaceFull`: 模拟新生代内存已满的情况，触发垃圾回收。
   - `Runtime_ScheduleGCInStackCheck`: 在栈检查时调度垃圾回收。
   - `Runtime_TakeHeapSnapshot`:  生成堆快照文件，用于内存分析。

9. **调试和打印工具：**
   - `Runtime_DebugPrint`: 打印对象的详细信息到标准输出或标准错误。
   - `Runtime_DebugPrintPtr`:  将地址转换为对象并打印其信息。
   - `Runtime_DebugPrintWord`: 打印 64 位整数值。
   - `Runtime_DebugPrintFloat`: 打印双精度浮点数值。
   - `Runtime_PrintWithNameForAssert`:  在断言失败时打印带有名称的对象信息。
   - `Runtime_DebugTrace`: 打印当前调用栈。
   - `Runtime_GlobalPrint`: 打印字符串到标准输出或标准错误。
   - `Runtime_SystemBreak`:  触发断点，方便调试。

10. **控制执行流程和断言：**
    - `Runtime_SetForceSlowPath`: 强制代码执行走较慢的路径，用于测试。
    - `Runtime_Abort`:  根据给定的原因中止程序执行。
    - `Runtime_AbortJS`:  根据给定的 JavaScript 字符串消息中止程序执行。
    - `Runtime_AbortCSADcheck`:  在 CSA 检查失败时中止程序执行。

11. **代码检查和分析：**
    - `Runtime_DisassembleFunction`:  反汇编指定 JavaScript 函数的代码（仅在 DEBUG 模式下）。
    - `Runtime_TraceEnter`: 在函数入口处打印跟踪信息。
    - `Runtime_TraceExit`:  在函数出口处打印跟踪信息和返回值。

12. **检查对象属性：**
    - `Runtime_HaveSameMap`: 检查两个对象是否拥有相同的 Map (对象布局描述符)。
    - `Runtime_InLargeObjectSpace`: 检查对象是否位于大对象堆空间。
    - `Runtime_HasElementsInALargeObjectSpace`: 检查数组的元素是否位于大对象堆空间。
    - `Runtime_HasCowElements`: 检查数组是否拥有写时复制 (COW) 元素。
    - `Runtime_InYoungGeneration`: 检查对象是否位于新生代堆空间。
    - `Runtime_PretenureAllocationSite`: 强制将指定对象所属的分配站点的对象分配到老生代。

13. **控制代码生成：**
    - `Runtime_DisallowCodegenFromStrings`:  禁止从字符串生成代码。

14. **正则表达式相关检查：**
    - `Runtime_RegexpHasBytecode`: 检查正则表达式是否已编译为字节码。
    - `Runtime_RegexpHasNativeCode`: 检查正则表达式是否已编译为本地机器码。
    - `Runtime_RegexpTypeTag`: 获取正则表达式的编译类型标签。
    - `Runtime_RegexpIsUnmodified`: 检查正则表达式是否未被修改。

15. **检查元素类型：**
    - `Runtime_HasFastElements`, `Runtime_HasSmiElements`, `Runtime_HasObjectElements`, `Runtime_HasSmiOrObjectElements`, `Runtime_HasDoubleElements`, `Runtime_HasHoleyElements`, `Runtime_HasDictionaryElements`, `Runtime_HasPackedElements`, `Runtime_HasSloppyArgumentsElements`:  检查对象的元素是否属于特定类型或具有特定属性。
    - `Runtime_HasFastProperties`: 检查对象是否具有快速属性。
    - `Runtime_HasFixedUint8Elements` 等一系列 `Runtime_HasFixed...Elements` 函数：检查对象是否具有特定类型的定型数组元素。

16. **检查保护器状态：**
    - `Runtime_IsConcatSpreadableProtector` 等一系列 `Runtime_...Protector` 函数：检查各种内置对象的原型链保护器是否完好，这些保护器用于优化。

17. **序列化和反序列化：**
    - `Runtime_SerializeDeserializeNow`: 将当前隔离区的状态序列化并反序列化，用于测试快照功能。

18. **堆对象验证：**
    - `Runtime_HeapObjectVerify`:  验证指定的堆对象是否有效（仅在 `VERIF` 宏定义开启时）。

**JavaScript 示例（与 `Runtime_GetOptimizationStatus` 相关）：**

```javascript
function myFunction() {
  return 1 + 1;
}

// 假设 V8 提供了访问运行时函数的机制（在测试环境中通常是这样）
// 这里的 'Runtime_GetOptimizationStatus' 是一个示例，
// 实际调用方式可能需要 V8 提供的特定 API

// 初始状态，可能未编译或仅有解释器版本
console.log(Runtime_GetOptimizationStatus(myFunction)); // 输出可能包含 kIsLazy 或 kInterpreted

// 多次调用后，可能被标记为优化
for (let i = 0; i < 10000; i++) {
  myFunction();
}
console.log(Runtime_GetOptimizationStatus(myFunction)); // 输出可能包含 kMarkedForOptimization 或 kMarkedForConcurrentOptimization

// 优化完成后
// ... 等待优化完成的机制 ...
console.log(Runtime_GetOptimizationStatus(myFunction)); // 输出可能包含 kOptimized 或 kTurboFanned
```

**代码逻辑推理和假设输入/输出（以 `Runtime_GetOptimizationStatus` 为例）：**

**假设输入:** 一个 JavaScript 函数对象 `myFunction`。

**可能的输出（`status` 是一个整数，每个 bit 位代表一个优化状态）：**

| 假设场景                                  | 可能的 `status` (二进制，部分位) | 含义                                                                                                                                |
| ----------------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 函数刚定义，未执行                        | `0b00000001`                  | `OptimizationStatus::kIsLazy` (函数未编译)                                                                                         |
| 函数正在被解释执行                      | `0b00000010`                  | `OptimizationStatus::kInterpreted` (使用解释器)                                                                                      |
| 函数被标记为需要优化（同步）            | `0b00000100`                  | `OptimizationStatus::kMarkedForOptimization`                                                                                         |
| 函数被标记为需要优化（并发）            | `0b00001000`                  | `OptimizationStatus::kMarkedForConcurrentOptimization`                                                                                 |
| 函数已使用 Baseline 编译器编译            | `0b00010000`                  | `OptimizationStatus::kBaseline`                                                                                                      |
| 函数已被 TurboFan 优化                   | `0b00100000`                  | `OptimizationStatus::kOptimized` 和 `OptimizationStatus::kTurboFanned`                                                                |
| 函数正在调用栈顶，且是被 TurboFan 优化的 | `0b00100000` + `0b0100000000` | `OptimizationStatus::kOptimized`, `OptimizationStatus::kTurboFanned` 和 `OptimizationStatus::kTopmostFrameIsTurboFanned`             |

**用户常见的编程错误示例（与 `Runtime_ForceFlush` 相关）：**

假设一个用户编写了如下代码，并遇到了性能问题，怀疑是由于错误的优化：

```javascript
function calculate(a, b) {
  // 一段复杂的计算逻辑
  for (let i = 0; i < 1000; i++) {
    a += Math.sin(b * i);
  }
  return a;
}

// 多次调用 calculate
for (let i = 0; i < 100000; i++) {
  calculate(i, 0.5);
}

// ... 后续代码 ...
```

用户可能错误地认为 `calculate` 函数被错误地优化了，想要强制 V8 重新优化。他们可能会尝试调用类似 `Runtime_ForceFlush(calculate)` 的方法（如果 V8 提供了这种直接暴露），希望清除已编译的代码。

**常见的错误是：**

1. **不理解 V8 的优化流程：** 盲目地认为优化是问题所在，而实际问题可能是算法效率低下或其他原因。
2. **过度干预优化：**  在不了解 V8 内部工作原理的情况下，尝试手动控制优化可能导致性能下降或不稳定。
3. **错误地使用调试/测试 API：** 这些运行时函数通常是为 V8 内部测试和调试设计的，直接在生产代码中使用可能会导致不可预测的行为。

总结来说，这段代码定义了一组强大的工具，用于深入了解和控制 V8 引擎的运行时行为，主要服务于 V8 的开发人员进行测试、调试和性能分析。它允许检查函数的优化状态、控制优化流程、模拟内存压力、打印内部信息以及进行各种底层的对象和代码检查。

Prompt: 
```
这是目录为v8/src/runtime/runtime-test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
                isolate, ConcurrencyMode::kConcurrent) == CodeKind::MAGLEV) {
      status |= static_cast<int>(
          OptimizationStatus::kMarkedForConcurrentMaglevOptimization);
    } else if (function->GetRequestedOptimizationIfAny(
                   isolate, ConcurrencyMode::kSynchronous) ==
               CodeKind::MAGLEV) {
      status |=
          static_cast<int>(OptimizationStatus::kMarkedForMaglevOptimization);
    } else if (function->GetRequestedOptimizationIfAny(
                   isolate, ConcurrencyMode::kConcurrent) ==
               CodeKind::TURBOFAN_JS) {
      status |= static_cast<int>(
          OptimizationStatus::kMarkedForConcurrentOptimization);
    } else if (function->GetRequestedOptimizationIfAny(
                   isolate, ConcurrencyMode::kSynchronous) ==
               CodeKind::TURBOFAN_JS) {
      status |= static_cast<int>(OptimizationStatus::kMarkedForOptimization);
    }
  }

  if (function->HasAttachedOptimizedCode(isolate)) {
    Tagged<Code> code = function->code(isolate);
    if (code->marked_for_deoptimization()) {
      status |= static_cast<int>(OptimizationStatus::kMarkedForDeoptimization);
    } else {
      status |= static_cast<int>(OptimizationStatus::kOptimized);
    }
    if (code->is_maglevved()) {
      status |= static_cast<int>(OptimizationStatus::kMaglevved);
    } else if (code->is_turbofanned()) {
      status |= static_cast<int>(OptimizationStatus::kTurboFanned);
    }
  }
  if (function->HasAttachedCodeKind(isolate, CodeKind::BASELINE)) {
    status |= static_cast<int>(OptimizationStatus::kBaseline);
  }
  if (function->ActiveTierIsIgnition(isolate)) {
    status |= static_cast<int>(OptimizationStatus::kInterpreted);
  }
  if (!function->is_compiled(isolate)) {
    status |= static_cast<int>(OptimizationStatus::kIsLazy);
  }

  // Additionally, detect activations of this frame on the stack, and report the
  // status of the topmost frame.
  JavaScriptFrame* frame = nullptr;
  JavaScriptStackFrameIterator it(isolate);
  while (!it.done()) {
    if (it.frame()->function() == *function) {
      frame = it.frame();
      break;
    }
    it.Advance();
  }
  if (frame != nullptr) {
    status |= static_cast<int>(OptimizationStatus::kIsExecuting);
    if (frame->is_turbofan()) {
      status |=
          static_cast<int>(OptimizationStatus::kTopmostFrameIsTurboFanned);
    } else if (frame->is_interpreted()) {
      status |=
          static_cast<int>(OptimizationStatus::kTopmostFrameIsInterpreted);
    } else if (frame->is_baseline()) {
      status |= static_cast<int>(OptimizationStatus::kTopmostFrameIsBaseline);
    } else if (frame->is_maglev()) {
      status |= static_cast<int>(OptimizationStatus::kTopmostFrameIsMaglev);
    }
  }

  return Smi::FromInt(status);
}

RUNTIME_FUNCTION(Runtime_GetFunctionForCurrentFrame) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 0);

  JavaScriptStackFrameIterator it(isolate);
  DCHECK(!it.done());
  return it.frame()->function();
}

RUNTIME_FUNCTION(Runtime_DisableOptimizationFinalization) {
  if (isolate->concurrent_recompilation_enabled()) {
    isolate->optimizing_compile_dispatcher()->AwaitCompileTasks();
    isolate->optimizing_compile_dispatcher()->InstallOptimizedFunctions();
    isolate->stack_guard()->ClearInstallCode();
    isolate->optimizing_compile_dispatcher()->set_finalize(false);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WaitForBackgroundOptimization) {
  if (isolate->concurrent_recompilation_enabled()) {
    isolate->optimizing_compile_dispatcher()->AwaitCompileTasks();
#if V8_ENABLE_MAGLEV
    if (isolate->maglev_concurrent_dispatcher()->is_enabled()) {
      isolate->maglev_concurrent_dispatcher()->AwaitCompileJobs();
    }
#endif  // V8_ENABLE_MAGLEV
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_FinalizeOptimization) {
  if (isolate->concurrent_recompilation_enabled()) {
    FinalizeOptimization(isolate);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ForceFlush) {
  HandleScope scope(isolate);
  if (args.length() != 1) return CrashUnlessFuzzing(isolate);

  Handle<Object> function_object = args.at(0);
  if (!IsJSFunction(*function_object)) return CrashUnlessFuzzing(isolate);
  auto function = Cast<JSFunction>(function_object);
  Tagged<SharedFunctionInfo> sfi = function->shared(isolate);

  // Don't try to flush functions that cannot be flushed.
  if (!sfi->CanDiscardCompiled()) {
    return CrashUnlessFuzzing(isolate);
  }

  // Don't flush functions that are active on the stack.
  for (JavaScriptStackFrameIterator it(isolate); !it.done(); it.Advance()) {
    std::vector<Tagged<SharedFunctionInfo>> infos;
    it.frame()->GetFunctions(&infos);
    for (auto it = infos.rbegin(); it != infos.rend(); ++it) {
      if ((*it) == sfi) return CrashUnlessFuzzing(isolate);
    }
  }

  SharedFunctionInfo::DiscardCompiled(isolate, handle(sfi, isolate));
  function->ResetIfCodeFlushed(isolate);
  return ReadOnlyRoots(isolate).undefined_value();
}

static void ReturnNull(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  info.GetReturnValue().SetNull();
}

RUNTIME_FUNCTION(Runtime_GetUndetectable) {
  HandleScope scope(isolate);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  Local<v8::ObjectTemplate> desc = v8::ObjectTemplate::New(v8_isolate);
  desc->MarkAsUndetectable();
  desc->SetCallAsFunctionHandler(ReturnNull);
  Local<v8::Object> obj =
      desc->NewInstance(v8_isolate->GetCurrentContext()).ToLocalChecked();
  return *Utils::OpenDirectHandle(*obj);
}

namespace {
// Does globalThis[target_function_name](...args).
void call_as_function(const v8::FunctionCallbackInfo<v8::Value>& info) {
  DCHECK(ValidateCallbackInfo(info));
  v8::Isolate* isolate = info.GetIsolate();
  auto context = isolate->GetCurrentContext();
  auto global = context->Global();
  auto target_function_name = info.Data().As<v8::String>();
  v8::Local<v8::Function> target;
  {
    Local<Value> result;
    if (!global->Get(context, target_function_name).ToLocal(&result)) {
      return;
    }
    if (!result->IsFunction()) {
      isolate->ThrowError("Target function is not callable");
      return;
    }
    target = result.As<Function>();
  }
  int argc = info.Length();
  v8::LocalVector<v8::Value> args(isolate, argc);
  for (int i = 0; i < argc; i++) {
    args[i] = info[i];
  }
  Local<Value> result;
  if (!target->Call(context, info.This(), argc, args.data()).ToLocal(&result)) {
    return;
  }
  info.GetReturnValue().Set(result);
}
}  // namespace

RUNTIME_FUNCTION(Runtime_GetAbstractModuleSource) {
  // This isn't exposed to fuzzers. Crash if the native context is been
  // modified.
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  Tagged<JSFunction> abstract_module_source_function =
      isolate->native_context()->abstract_module_source_function();
  CHECK(IsJSFunction(*abstract_module_source_function));
  return abstract_module_source_function;
}

// Returns a callable object which redirects [[Call]] requests to
// globalThis[target_function_name] function.
RUNTIME_FUNCTION(Runtime_GetCallable) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Handle<String> target_function_name = args.at<String>(0);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(v8_isolate);
  Local<v8::ObjectTemplate> instance_template = t->InstanceTemplate();
  instance_template->SetCallAsFunctionHandler(
      call_as_function, v8::Utils::ToLocal(target_function_name));
  v8_isolate->GetCurrentContext();
  Local<v8::Object> instance =
      t->GetFunction(v8_isolate->GetCurrentContext())
          .ToLocalChecked()
          ->NewInstance(v8_isolate->GetCurrentContext())
          .ToLocalChecked();
  return *Utils::OpenDirectHandle(*instance);
}

RUNTIME_FUNCTION(Runtime_ClearFunctionFeedback) {
  HandleScope scope(isolate);
  // This isn't exposed to fuzzers so doesn't need to handle invalid arguments.
  DCHECK_EQ(args.length(), 1);
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  function->ClearAllTypeFeedbackInfoForTesting();
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_NotifyContextDisposed) {
  HandleScope scope(isolate);
  isolate->heap()->NotifyContextDisposed(true);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetAllocationTimeout) {
  SealHandleScope shs(isolate);
  if (args.length() != 2 && args.length() != 3) {
    return CrashUnlessFuzzing(isolate);
  }
#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  CONVERT_INT32_ARG_FUZZ_SAFE(interval, 0);
  HeapAllocator::SetAllocationGcInterval(interval);
  CONVERT_INT32_ARG_FUZZ_SAFE(timeout, 1);
  isolate->heap()->set_allocation_timeout(timeout);
#endif
#ifdef DEBUG
  if (args.length() == 3) {
    // Enable/disable inline allocation if requested.
    CONVERT_BOOLEAN_ARG_FUZZ_SAFE(inline_allocation, 2);
    if (inline_allocation) {
      isolate->heap()->EnableInlineAllocation();
    } else {
      isolate->heap()->DisableInlineAllocation();
    }
  }
#endif
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

int FixedArrayLenFromSize(int size) {
  return std::min({(size - OFFSET_OF_DATA_START(FixedArray)) / kTaggedSize,
                   FixedArray::kMaxRegularLength});
}

void FillUpOneNewSpacePage(Isolate* isolate, Heap* heap,
                           SemiSpaceNewSpace* space) {
  DCHECK(!v8_flags.single_generation);
  heap->FreeMainThreadLinearAllocationAreas();
  PauseAllocationObserversScope pause_observers(heap);
  while (space->GetSpaceRemainingOnCurrentPageForTesting() > 0) {
    int space_remaining = space->GetSpaceRemainingOnCurrentPageForTesting();
    int length = FixedArrayLenFromSize(space_remaining);
    if (length > 0) {
      DirectHandle<FixedArray> padding =
          isolate->factory()->NewFixedArray(length, AllocationType::kYoung);
      DCHECK(heap->new_space()->Contains(*padding));
      space_remaining -= padding->Size();
    } else {
      // Not enough room to create another fixed array. Create a filler instead.
      space->FillCurrentPageForTesting();
    }
    heap->FreeMainThreadLinearAllocationAreas();
  }
}

}  // namespace

RUNTIME_FUNCTION(Runtime_SimulateNewspaceFull) {
  HandleScope scope(isolate);
  Heap* heap = isolate->heap();
  heap->FreeMainThreadLinearAllocationAreas();
  AlwaysAllocateScopeForTesting always_allocate(heap);
  if (v8_flags.minor_ms) {
    if (heap->minor_sweeping_in_progress()) {
      heap->EnsureYoungSweepingCompleted();
    }
    auto* space = heap->paged_new_space()->paged_space();
    space->AllocatePageUpToCapacityForTesting();
    space->ResetFreeList();
  } else {
    SemiSpaceNewSpace* space = heap->semi_space_new_space();
    do {
      FillUpOneNewSpacePage(isolate, heap, space);
    } while (space->AddFreshPage());
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ScheduleGCInStackCheck) {
  SealHandleScope shs(isolate);
  isolate->RequestInterrupt(
      [](v8::Isolate* isolate, void*) {
        isolate->RequestGarbageCollectionForTesting(
            v8::Isolate::kFullGarbageCollection);
      },
      nullptr);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_TakeHeapSnapshot) {
  if (v8_flags.fuzzing) {
    // We don't want to create snapshots in fuzzers.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  std::string filename = "heap.heapsnapshot";

  if (args.length() >= 1) {
    HandleScope hs(isolate);
    DirectHandle<String> filename_as_js_string = args.at<String>(0);
    std::unique_ptr<char[]> buffer = filename_as_js_string->ToCString();
    filename = std::string(buffer.get());
  }

  HeapProfiler* heap_profiler = isolate->heap_profiler();
  // Since this API is intended for V8 devs, we do not treat globals as roots
  // here on purpose.
  v8::HeapProfiler::HeapSnapshotOptions options;
  options.numerics_mode = v8::HeapProfiler::NumericsMode::kExposeNumericValues;
  options.snapshot_mode = v8::HeapProfiler::HeapSnapshotMode::kExposeInternals;
  heap_profiler->TakeSnapshotToFile(options, filename);
  return ReadOnlyRoots(isolate).undefined_value();
}

static void DebugPrintImpl(Tagged<MaybeObject> maybe_object, std::ostream& os) {
  if (maybe_object.IsCleared()) {
    os << "[weak cleared]";
  } else {
    Tagged<Object> object = maybe_object.GetHeapObjectOrSmi();
    bool weak = maybe_object.IsWeak();

#ifdef OBJECT_PRINT
    os << "DebugPrint: ";
    if (weak) os << "[weak] ";
    Print(object, os);
    if (IsHeapObject(object)) {
      Print(Cast<HeapObject>(object)->map(), os);
    }
#else
    if (weak) os << "[weak] ";
    // ShortPrint is available in release mode. Print is not.
    os << Brief(object);
#endif
  }
  os << std::endl;
}

RUNTIME_FUNCTION(Runtime_DebugPrint) {
  SealHandleScope shs(isolate);

  if (args.length() == 0) {
    // This runtime method has variable number of arguments, but if there is no
    // argument, undefined behavior may happen.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // This is exposed to tests / fuzzers; handle variable arguments gracefully.
  std::unique_ptr<std::ostream> output_stream(new StdoutStream());
  if (args.length() >= 2) {
    // Args: object, stream.
    if (IsSmi(args[1])) {
      int output_int = Cast<Smi>(args[1]).value();
      if (output_int == fileno(stderr)) {
        output_stream.reset(new StderrStream());
      }
    }
  }

  Tagged<MaybeObject> maybe_object(*args.address_of_arg_at(0));
  DebugPrintImpl(maybe_object, *output_stream);
  return args[0];
}

RUNTIME_FUNCTION(Runtime_DebugPrintPtr) {
  SealHandleScope shs(isolate);
  StdoutStream os;
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }

  Tagged<MaybeObject> maybe_object(*args.address_of_arg_at(0));
  if (!maybe_object.IsCleared()) {
    Tagged<Object> object = maybe_object.GetHeapObjectOrSmi();
    size_t pointer;
    if (Object::ToIntegerIndex(object, &pointer)) {
      Tagged<MaybeObject> from_pointer(static_cast<Address>(pointer));
      DebugPrintImpl(from_pointer, os);
    }
  }
  // We don't allow the converted pointer to leak out to JavaScript.
  return args[0];
}

RUNTIME_FUNCTION(Runtime_DebugPrintWord) {
  static constexpr int kNum16BitChunks = 4;
  SealHandleScope shs(isolate);

  // Args are: <bits 63-48>, <bits 47-32>, <bits 31-16>, <bits 15-0>, stream.
  if (args.length() != kNum16BitChunks + 1) {
    return CrashUnlessFuzzing(isolate);
  }

  uint64_t value = 0;
  for (int i = 0; i < kNum16BitChunks; ++i) {
    value <<= 16;
    CHECK(IsSmi(args[i]));
    uint32_t chunk = Cast<Smi>(args[i]).value();
    // We encode 16 bit per chunk only!
    CHECK_EQ(chunk & 0xFFFF0000, 0);
    value |= chunk;
  }

  if (!IsSmi(args[4]) || (Cast<Smi>(args[4]).value() == fileno(stderr))) {
    StderrStream os;
    os << "0x" << std::hex << value << std::dec << std::endl;
  } else {
    StdoutStream os;
    os << "0x" << std::hex << value << std::dec << std::endl;
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DebugPrintFloat) {
  static constexpr int kNum16BitChunks = 4;
  SealHandleScope shs(isolate);

  // Args are: <bits 63-48>, <bits 47-32>, <bits 31-16>, <bits 15-0>, stream.
  if (args.length() != kNum16BitChunks + 1) {
    return CrashUnlessFuzzing(isolate);
  }

  uint64_t value = 0;
  for (int i = 0; i < kNum16BitChunks; ++i) {
    value <<= 16;
    CHECK(IsSmi(args[i]));
    uint32_t chunk = Cast<Smi>(args[i]).value();
    // We encode 16 bit per chunk only!
    CHECK_EQ(chunk & 0xFFFF0000, 0);
    value |= chunk;
  }

  if (!IsSmi(args[4]) || (Cast<Smi>(args[4]).value() == fileno(stderr))) {
    StderrStream os;
    std::streamsize precision = os.precision();
    os << std::setprecision(20) << base::bit_cast<double>(value) << std::endl;
    os.precision(precision);
  } else {
    StdoutStream os;
    std::streamsize precision = os.precision();
    os << std::setprecision(20) << base::bit_cast<double>(value) << std::endl;
    os.precision(precision);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_PrintWithNameForAssert) {
  SealHandleScope shs(isolate);
  if (args.length() != 2) {
    return CrashUnlessFuzzing(isolate);
  }

  auto name = Cast<String>(args[0]);

  PrintF(" * ");
  StringCharacterStream stream(name);
  while (stream.HasMore()) {
    uint16_t character = stream.GetNext();
    PrintF("%c", character);
  }
  PrintF(": ");
  ShortPrint(args[1]);
  PrintF("\n");

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_DebugTrace) {
  SealHandleScope shs(isolate);
  isolate->PrintStack(stdout);
  return ReadOnlyRoots(isolate).undefined_value();
}

// This will not allocate (flatten the string), but it may run
// very slowly for very deeply nested ConsStrings.  For debugging use only.
RUNTIME_FUNCTION(Runtime_GlobalPrint) {
  SealHandleScope shs(isolate);

  // This is exposed to tests / fuzzers; handle variable arguments gracefully.
  FILE* output_stream = stdout;
  if (args.length() >= 2) {
    // Args: object, stream.
    if (IsSmi(args[1])) {
      int output_int = Cast<Smi>(args[1]).value();
      if (output_int == fileno(stderr)) {
        output_stream = stderr;
      }
    }
  }

  if (!IsString(args[0])) {
    return args[0];
  }

  auto string = Cast<String>(args[0]);
  StringCharacterStream stream(string);
  while (stream.HasMore()) {
    uint16_t character = stream.GetNext();
    PrintF(output_stream, "%c", character);
  }
  fflush(output_stream);
  return string;
}

RUNTIME_FUNCTION(Runtime_SystemBreak) {
  // The code below doesn't create handles, but when breaking here in GDB
  // having a handle scope might be useful.
  HandleScope scope(isolate);
  base::OS::DebugBreak();
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetForceSlowPath) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<Object> arg = args[0];
  if (IsTrue(arg, isolate)) {
    isolate->set_force_slow_path(true);
  } else {
    // This function is fuzzer exposed and as such we might not always have an
    // input that IsTrue or IsFalse. In these cases we assume that if !IsTrue
    // then it IsFalse when fuzzing.
    DCHECK(IsFalse(arg, isolate) || v8_flags.fuzzing);
    isolate->set_force_slow_path(false);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_Abort) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  int message_id = args.smi_value_at(0);
  const char* message = GetAbortReason(static_cast<AbortReason>(message_id));
  base::OS::PrintError("abort: %s\n", message);
  isolate->PrintStack(stderr);
  base::OS::Abort();
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_AbortJS) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<String> message = args.at<String>(0);
  if (v8_flags.disable_abortjs) {
    base::OS::PrintError("[disabled] abort: %s\n", message->ToCString().get());
    return Tagged<Object>();
  }
  base::OS::PrintError("abort: %s\n", message->ToCString().get());
  isolate->PrintStack(stderr);
  base::OS::Abort();
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_AbortCSADcheck) {
  HandleScope scope(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<String> message = args.at<String>(0);
  if (base::ControlledCrashesAreHarmless()) {
    base::OS::PrintError(
        "Safely terminating process due to CSA check failure\n");
    // Also prefix the error message (printed below). This has two purposes:
    // (1) it makes it clear that this error is deemed "safe" (2) it causes
    // fuzzers that pattern-match on stderr output to ignore these failures.
    base::OS::PrintError("The following harmless failure was encountered: %s\n",
                         message->ToCString().get());
  } else {
    base::OS::PrintError("abort: CSA_DCHECK failed: %s\n",
                         message->ToCString().get());
    isolate->PrintStack(stderr);
  }
  base::OS::Abort();
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_DisassembleFunction) {
  HandleScope scope(isolate);
#ifdef DEBUG
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  // Get the function and make sure it is compiled.
  Handle<JSFunction> func = args.at<JSFunction>(0);
  IsCompiledScope is_compiled_scope;
#ifndef V8_ENABLE_LEAPTIERING
  if (!func->is_compiled(isolate) && func->HasAvailableOptimizedCode(isolate)) {
    func->UpdateCode(func->feedback_vector()->optimized_code(isolate));
  }
#endif  // !V8_ENABLE_LEAPTIERING
  CHECK(func->shared()->is_compiled() ||
        Compiler::Compile(isolate, func, Compiler::KEEP_EXCEPTION,
                          &is_compiled_scope));
  StdoutStream os;
  Print(func->code(isolate), os);
  os << std::endl;
#endif  // DEBUG
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

int StackSize(Isolate* isolate) {
  int n = 0;
  for (JavaScriptStackFrameIterator it(isolate); !it.done(); it.Advance()) n++;
  return n;
}

void PrintIndentation(int stack_size) {
  const int max_display = 80;
  if (stack_size <= max_display) {
    PrintF("%4d:%*s", stack_size, stack_size, "");
  } else {
    PrintF("%4d:%*s", stack_size, max_display, "...");
  }
}

}  // namespace

RUNTIME_FUNCTION(Runtime_TraceEnter) {
  SealHandleScope shs(isolate);
  PrintIndentation(StackSize(isolate));
  JavaScriptFrame::PrintTop(isolate, stdout, true, false);
  PrintF(" {\n");
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_TraceExit) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<Object> obj = args[0];
  PrintIndentation(StackSize(isolate));
  PrintF("} -> ");
  ShortPrint(obj);
  PrintF("\n");
  return obj;  // return TOS
}

RUNTIME_FUNCTION(Runtime_HaveSameMap) {
  SealHandleScope shs(isolate);
  if (args.length() != 2) {
    return CrashUnlessFuzzing(isolate);
  }
  if (IsSmi(args[0]) || IsSmi(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto obj1 = Cast<HeapObject>(args[0]);
  auto obj2 = Cast<HeapObject>(args[1]);
  return isolate->heap()->ToBoolean(obj1->map() == obj2->map());
}

RUNTIME_FUNCTION(Runtime_InLargeObjectSpace) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsHeapObject(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto obj = Cast<HeapObject>(args[0]);
  return isolate->heap()->ToBoolean(
      isolate->heap()->new_lo_space()->Contains(obj) ||
      isolate->heap()->code_lo_space()->Contains(obj) ||
      isolate->heap()->lo_space()->Contains(obj));
}

RUNTIME_FUNCTION(Runtime_HasElementsInALargeObjectSpace) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsJSArray(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto array = Cast<JSArray>(args[0]);
  Tagged<FixedArrayBase> elements = array->elements();
  return isolate->heap()->ToBoolean(
      isolate->heap()->new_lo_space()->Contains(elements) ||
      isolate->heap()->lo_space()->Contains(elements));
}

RUNTIME_FUNCTION(Runtime_HasCowElements) {
  SealHandleScope shs(isolate);
  if (args.length() != 1 || !IsJSArray(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto array = Cast<JSArray>(args[0]);
  Tagged<FixedArrayBase> elements = array->elements();
  return isolate->heap()->ToBoolean(elements->IsCowArray());
}

RUNTIME_FUNCTION(Runtime_InYoungGeneration) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  Tagged<Object> obj = args[0];
  return isolate->heap()->ToBoolean(HeapLayout::InYoungGeneration(obj));
}

// Force pretenuring for the allocation site the passed object belongs to.
RUNTIME_FUNCTION(Runtime_PretenureAllocationSite) {
  DisallowGarbageCollection no_gc;

  if (args.length() != 1) return CrashUnlessFuzzing(isolate);
  Tagged<Object> arg = args[0];
  if (!IsJSObject(arg)) return CrashUnlessFuzzing(isolate);
  Tagged<JSObject> object = Cast<JSObject>(arg);

  Heap* heap = object->GetHeap();
  if (!v8_flags.sticky_mark_bits && !HeapLayout::InYoungGeneration(object)) {
    // Object is not in new space, thus there is no memento and nothing to do.
    return ReturnFuzzSafe(ReadOnlyRoots(isolate).false_value(), isolate);
  }

  PretenuringHandler* pretenuring_handler = heap->pretenuring_handler();
  Tagged<AllocationMemento> memento = PretenuringHandler::FindAllocationMemento<
      PretenuringHandler::kForRuntime>(heap, object->map(), object);
  if (memento.is_null())
    return ReturnFuzzSafe(ReadOnlyRoots(isolate).false_value(), isolate);
  Tagged<AllocationSite> site = memento->GetAllocationSite();
  pretenuring_handler->PretenureAllocationSiteOnNextCollection(site);
  return ReturnFuzzSafe(ReadOnlyRoots(isolate).true_value(), isolate);
}

namespace {

v8::ModifyCodeGenerationFromStringsResult DisallowCodegenFromStringsCallback(
    v8::Local<v8::Context> context, v8::Local<v8::Value> source,
    bool is_code_kind) {
  return {false, {}};
}

}  // namespace

RUNTIME_FUNCTION(Runtime_DisallowCodegenFromStrings) {
  SealHandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  bool flag = Cast<Boolean>(args[0])->ToBool(isolate);
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8_isolate->SetModifyCodeGenerationFromStringsCallback(
      flag ? DisallowCodegenFromStringsCallback : nullptr);
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_RegexpHasBytecode) {
  SealHandleScope shs(isolate);
  if (args.length() != 2 || !IsJSRegExp(args[0]) || !IsBoolean(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto regexp = args.at<JSRegExp>(0);
  bool is_latin1 = args.at<Boolean>(1)->ToBool(isolate);
  bool result = false;
  if (regexp->has_data()) {
    Tagged<RegExpData> data = regexp->data(isolate);
    if (data->type_tag() == RegExpData::Type::IRREGEXP) {
      result = Cast<IrRegExpData>(data)->has_bytecode(is_latin1);
    }
  }
  return isolate->heap()->ToBoolean(result);
}

RUNTIME_FUNCTION(Runtime_RegexpHasNativeCode) {
  SealHandleScope shs(isolate);
  if (args.length() != 2 || !IsJSRegExp(args[0]) || !IsBoolean(args[1])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto regexp = args.at<JSRegExp>(0);
  bool is_latin1 = args.at<Boolean>(1)->ToBool(isolate);
  bool result = false;
  if (regexp->has_data()) {
    Tagged<RegExpData> data = regexp->data(isolate);
    if (data->type_tag() == RegExpData::Type::IRREGEXP) {
      result = Cast<IrRegExpData>(data)->has_code(is_latin1);
    }
  }
  return isolate->heap()->ToBoolean(result);
}

RUNTIME_FUNCTION(Runtime_RegexpTypeTag) {
  HandleScope shs(isolate);
  if (args.length() != 1 || !IsJSRegExp(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  auto regexp = Cast<JSRegExp>(args[0]);
  const char* type_str;
  if (regexp->has_data()) {
    switch (regexp->data(isolate)->type_tag()) {
      case RegExpData::Type::ATOM:
        type_str = "ATOM";
        break;
      case RegExpData::Type::IRREGEXP:
        type_str = "IRREGEXP";
        break;
      case RegExpData::Type::EXPERIMENTAL:
        type_str = "EXPERIMENTAL";
        break;
      default:
        UNREACHABLE();
    }
  } else {
    type_str = "NOT_COMPILED";
  }
  return *isolate->factory()->NewStringFromAsciiChecked(type_str);
}

RUNTIME_FUNCTION(Runtime_RegexpIsUnmodified) {
  HandleScope shs(isolate);
  if (args.length() != 1 || !IsJSRegExp(args[0])) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<JSRegExp> regexp = args.at<JSRegExp>(0);
  return isolate->heap()->ToBoolean(
      RegExp::IsUnmodifiedRegExp(isolate, regexp));
}

#define ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(Name)    \
  RUNTIME_FUNCTION(Runtime_##Name) {                  \
    if (args.length() != 1 || !IsJSObject(args[0])) { \
      return CrashUnlessFuzzing(isolate);             \
    }                                                 \
    auto obj = args.at<JSObject>(0);                  \
    return isolate->heap()->ToBoolean(obj->Name());   \
  }

ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasFastElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasSmiElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasObjectElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasSmiOrObjectElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasDoubleElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasHoleyElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasDictionaryElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasPackedElements)
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasSloppyArgumentsElements)
// Properties test sitting with elements tests - not fooling anyone.
ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION(HasFastProperties)

#undef ELEMENTS_KIND_CHECK_RUNTIME_FUNCTION

#define FIXED_TYPED_ARRAYS_CHECK_RUNTIME_FUNCTION(Type, type, TYPE, ctype) \
  RUNTIME_FUNCTION(Runtime_HasFixed##Type##Elements) {                     \
    if (args.length() != 1 || !IsJSObject(args[0])) {                      \
      return CrashUnlessFuzzing(isolate);                                  \
    }                                                                      \
    auto obj = Cast<JSObject>(args[0]);                                    \
    return isolate->heap()->ToBoolean(obj->HasFixed##Type##Elements());    \
  }

TYPED_ARRAYS(FIXED_TYPED_ARRAYS_CHECK_RUNTIME_FUNCTION)

#undef FIXED_TYPED_ARRAYS_CHECK_RUNTIME_FUNCTION

RUNTIME_FUNCTION(Runtime_IsConcatSpreadableProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsIsConcatSpreadableLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_TypedArraySpeciesProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsTypedArraySpeciesLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_RegExpSpeciesProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsRegExpSpeciesLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_PromiseSpeciesProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsPromiseSpeciesLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_ArraySpeciesProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsArraySpeciesLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_MapIteratorProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsMapIteratorLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_SetIteratorProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsSetIteratorLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_StringIteratorProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsStringIteratorLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_ArrayIteratorProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsArrayIteratorLookupChainIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_NoElementsProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(Protectors::IsNoElementsIntact(isolate));
}

RUNTIME_FUNCTION(Runtime_StringWrapperToPrimitiveProtector) {
  SealHandleScope shs(isolate);
  return isolate->heap()->ToBoolean(
      Protectors::IsStringWrapperToPrimitiveIntact(isolate));
}

// For use by tests and fuzzers. It
//
// 1. serializes a snapshot of the current isolate,
// 2. deserializes the snapshot,
// 3. and runs VerifyHeap on the resulting isolate.
//
// The current isolate should not be modified by this call and can keep running
// once it completes.
RUNTIME_FUNCTION(Runtime_SerializeDeserializeNow) {
  // TODO(353971258): This function is not currently exposed to fuzzers.
  // Investigate if it should be.
  HandleScope scope(isolate);
  Snapshot::SerializeDeserializeAndVerifyForTesting(isolate,
                                                    isolate->native_context());
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_HeapObjectVerify) {
  HandleScope shs(isolate);
  if (args.length() != 1) {
    return CrashUnlessFuzzing(isolate);
  }
  DirectHandle<Object> object = args.at(0);
#ifdef VERIF
"""


```