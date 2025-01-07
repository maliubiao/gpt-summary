Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Understanding the Goal:** The initial request asks for a functional overview of the provided C++ code from `v8/src/execution/isolate.cc`. It also has specific constraints regarding Torque, JavaScript examples, logical deductions, common errors, and a summary.

2. **Initial Scan and Keyword Spotting:**  A quick read-through reveals recurring themes and important elements:
    * **Stack Frames:** The code heavily deals with different types of stack frames (JS, Stub, Interpreted, Baseline, Builtin, etc.).
    * **Exception Handling:**  Keywords like "exception," "handler," "catch," "throw," and "deoptimizer" are prominent.
    * **Bytecode:**  References to `BytecodeArray`, `BytecodeOffset`, and `InterpreterEnterAtBytecode` indicate interaction with V8's bytecode interpreter.
    * **Promises:**  Sections discuss `PromiseReaction`, `PromiseCapability`, and a `WalkPromiseTreeInternal` function, pointing to promise handling logic.
    * **Stack Traces:** Functions like `CaptureSimpleStackTrace`, `PrintCurrentStackTrace`, and discussions about `MessageLocation` suggest stack trace generation and formatting.
    * **Deoptimization:** The mention of `set_deoptimizer_lazy_throw` and `materialized_object_store_` signals involvement in deoptimization.

3. **Segmenting the Code by Functionality:**  Based on the keywords and structure, the code can be grouped into logical areas:
    * **Finding Exception Handlers:** The first large `for` loop iterates through stack frames to locate appropriate handlers for exceptions.
    * **Predicting Exception Catching:** The `StackFrameSummaryIterator` and related functions (`CatchPredictionFor`, `PredictExceptionFromBytecode`, `PredictException`, `PredictExceptionCatchAtFrame`) focus on determining if an exception will be caught at a particular frame.
    * **Stack Trace Generation:** Functions like `CaptureSimpleStackTrace` and `PrintCurrentStackTrace` clearly handle the creation and display of stack traces.
    * **Message Creation:** `CreateMessage` and `CreateMessageFromException` are responsible for creating `JSMessageObject` instances, often associated with errors or exceptions.
    * **Promise Rejection Tracking:** The `WalkPromiseTreeInternal` function and the subsequent bytecode analysis (`CallsCatchMethod`) are dedicated to identifying if and how promise rejections are handled.

4. **Detailed Analysis of Key Sections:**

    * **Exception Handler Search:**  This part needs closer examination of each `case` within the `switch` statement for different `StackFrame::Type`. The goal is to understand *how* the code determines the handler's location (offset, instruction start, etc.) based on the frame type. Pay attention to the logic for interpreted and optimized frames, as they have different mechanisms.
    * **Promise Tree Walking:**  Understanding the purpose of `WalkPromiseTreeInternal` is crucial. It recursively traverses the promise reaction chain to determine if a rejection is eventually handled. The logic within the `while` loop and the checks for `reject_handler` and `forwarding_handler` are important.
    * **Bytecode Analysis:** The `CallsCatchMethod` function requires understanding V8's bytecode instructions and how to iterate through them. The goal is to detect patterns indicating a `.catch()` call.

5. **Addressing Specific Requirements:**

    * **Function Listing:** This becomes a relatively straightforward task once the code is segmented. List the main functions and briefly describe their purpose.
    * **Torque:**  Scan the code for `.tq` extensions. Since none are found, state this explicitly.
    * **JavaScript Examples:**  For sections related to JavaScript functionality (like promises and error handling), create simple JavaScript snippets that demonstrate the concepts. For instance, a `try...catch` block for error handling and a `.catch()` on a promise.
    * **Logical Deductions (Assumptions and Outputs):** For key functions like the exception handler search, devise simple input scenarios (e.g., a specific stack frame type and exception state) and trace the code's execution to predict the output (e.g., the location of the handler).
    * **Common Programming Errors:** Think about typical mistakes developers make related to the functionality being analyzed. For example, forgetting to handle promise rejections or not using `try...catch` appropriately.
    * **Summary:**  Condense the main functionalities into a concise overview.

6. **Iterative Refinement:** After the initial analysis, review the findings for clarity, accuracy, and completeness. Ensure the JavaScript examples are clear and the logical deductions are well-reasoned. Check if all parts of the original request have been addressed.

**Self-Correction/Refinement Example during the Process:**

* **Initial thought:** "The exception handler search just finds the handler."
* **Realization after closer look:** "No, it handles different frame types differently. Interpreted frames need bytecode patching, optimized frames involve deoptimization, etc. I need to be more specific about these distinctions."

* **Initial thought (for promise handling):** "It just checks if there's a `.catch()`."
* **Realization after closer look:** "It's more complex. It walks the *entire promise reaction tree*, considers forwarding handlers, and even looks inside async functions. My explanation needs to reflect this deeper traversal."

By following this structured approach, combining initial scanning with detailed analysis, and continuously refining understanding, we can effectively dissect and explain the functionality of complex code snippets like the one provided.
好的，让我们来分析一下这段 `v8/src/execution/isolate.cc` 的代码片段的功能。

**核心功能：查找和处理异常处理程序 (Exception Handlers)**

这段代码的主要功能是在调用栈上查找合适的异常处理程序来处理抛出的异常。它遍历不同类型的栈帧，并根据栈帧的类型采取不同的策略来定位和激活异常处理逻辑。

**功能分解：**

1. **遍历栈帧 (Stack Frame Iteration):** 代码通过一个循环遍历当前的调用栈，逐个检查栈帧。

2. **区分栈帧类型 (Stack Frame Type Handling):**  使用 `switch` 语句根据栈帧的不同类型 (`StackFrame::Type`) 执行不同的处理逻辑：
   * **`StackFrame::JAVA_SCRIPT` (JavaScript帧):**
     * 查找与当前程序计数器 (`pc()`) 对应的异常处理表中的条目。
     * 如果找到，计算返回地址和栈指针，并返回 `FoundHandler` 结构体，其中包含了异常处理器的信息（上下文、入口地址、偏移量等）。
     * 如果是懒惰抛出异常（`set_deoptimizer_lazy_throw(true)`），则通知反优化器。
   * **`StackFrame::STUB` (桩帧):**
     * 检查是否可以通过 JavaScript 代码捕获异常 (`catchable_by_js`)。
     * 查找桩帧的异常处理表。
     * 如果找到，计算返回栈指针，并返回 `FoundHandler` 结构体。
   * **`StackFrame::INTERPRETED` 和 `StackFrame::BASELINE` (解释执行帧和基线编译帧):**
     * 检查是否可以通过 JavaScript 代码捕获异常。
     * 在字节码数组的异常处理表中查找范围。
     * 如果找到，计算返回栈指针，并调整解释执行帧的字节码偏移量，指向异常处理器的位置。
     * 对于基线编译帧，直接修改帧上的上下文寄存器。
     * 返回 `FoundHandler` 结构体。对于解释执行帧，还会调整 `visited_frames`。
   * **`StackFrame::BUILTIN` (内置函数帧):**
     * 对于内置函数帧，通常不期望找到 JavaScript 的异常处理程序。
   * **`StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH` (带有 catch 的 JavaScript 内置延续帧):**
     * 检查是否可以通过 JavaScript 代码捕获异常。
     * 将异常对象设置到帧上。
     * 计算返回栈指针，并返回 `FoundHandler` 结构体。
   * **`default`:** 其他类型的栈帧通常不能处理异常。

3. **反优化处理 (Deoptimization):**  对于优化的 JavaScript 帧 (`frame->is_optimized_js()`)，会移除与该帧关联的物化对象 (`materialized_object_store_->Remove`)。如果存在物化对象，则该代码应该被标记为需要反优化。

**关于 .tq 结尾：**

如果 `v8/src/execution/isolate.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种 V8 用于定义运行时内置函数和类型系统的领域特定语言。由于当前的文件名是 `.cc`，所以它是一个 C++ 源代码文件。

**与 JavaScript 的关系 (以及 JavaScript 示例):**

这段代码直接关联到 JavaScript 的异常处理机制。当 JavaScript 代码中抛出一个异常时（例如使用 `throw` 语句），V8 的运行时系统会调用类似这样的 C++ 代码来查找合适的 `catch` 块来处理这个异常。

**JavaScript 示例：**

```javascript
function potentiallyThrowingFunction() {
  // 模拟可能抛出异常的情况
  if (Math.random() < 0.5) {
    throw new Error("Something went wrong!");
  }
  console.log("Function executed successfully.");
}

function callerFunction() {
  try {
    potentiallyThrowingFunction();
  } catch (error) {
    console.error("Caught an error:", error.message);
    // 这里的代码对应着 C++ 中查找并执行异常处理程序的逻辑
  }
}

callerFunction();
```

在这个例子中：

* 当 `potentiallyThrowingFunction` 抛出异常时，V8 会遍历调用栈，从 `callerFunction` 的 `try...catch` 块开始寻找合适的异常处理程序。
* 上述 C++ 代码片段的核心任务就是实现这个查找过程，确定哪个 `catch` 块（或者 V8 内部的错误处理机制）应该接收并处理这个异常。

**代码逻辑推理 (假设输入与输出):**

**假设输入：**

* 一个 JavaScript 函数 `foo` 调用了另一个 JavaScript 函数 `bar`，`bar` 中抛出了一个 `Error` 对象。
* 当前的调用栈包含 `bar` 的栈帧（`StackFrame::JAVA_SCRIPT`）和 `foo` 的栈帧（`StackFrame::JAVA_SCRIPT`）。
* `foo` 函数中包含一个 `try...catch` 块来捕获 `bar` 抛出的异常。

**预期输出：**

1. 当异常在 `bar` 中抛出时，V8 开始遍历栈帧。
2. 首先检查 `bar` 的栈帧，查找其对应的异常处理表。如果 `bar` 函数内部没有 `try...catch`，则未找到处理程序。
3. 接着检查调用者 `foo` 的栈帧。V8 会在 `foo` 函数的异常处理表中找到与 `bar` 的调用位置相对应的 `try...catch` 块。
4. 代码会计算出 `foo` 函数中 `catch` 块的入口地址和相关的栈信息。
5. `FoundHandler` 结构体会被返回，其中包含了 `foo` 函数 `catch` 块的信息，使得 V8 可以跳转到 `catch` 块中执行异常处理逻辑。

**用户常见的编程错误：**

1. **未处理的 Promise 拒绝 (Unhandled Promise Rejection):**
   ```javascript
   // 忘记在 Promise 链的末尾添加 .catch()
   new Promise((resolve, reject) => {
     setTimeout(() => {
       reject("Promise rejected!");
     }, 100);
   });
   // 运行时可能看到 "UnhandledPromiseRejectionWarning"
   ```
   V8 的 Promise 处理逻辑会检测到未被捕获的拒绝，并可能触发警告或错误。

2. **在异步操作中抛出异常但未正确捕获:**
   ```javascript
   async function fetchData() {
     // 假设 fetch 可能失败
     const response = await fetch('invalid
Prompt: 
```
这是目录为v8/src/execution/isolate.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/isolate.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共9部分，请归纳一下它的功能

"""
the original
          // return address, but we make a note that we are throwing, so
          // that the deoptimizer can do the right thing.
          offset = static_cast<int>(frame->pc() - code->instruction_start());
          set_deoptimizer_lazy_throw(true);
        }

        return FoundHandler(
            Context(), code->InstructionStart(this, frame->pc()), offset,
            code->constant_pool(), return_sp, frame->fp(), visited_frames);
      }

      case StackFrame::STUB: {
#if V8_ENABLE_WEBASSEMBLY
        HandleStackSwitch(iter);
#endif
        // Some stubs are able to handle exceptions.
        if (!catchable_by_js) break;
        StubFrame* stub_frame = static_cast<StubFrame*>(frame);
#if V8_ENABLE_WEBASSEMBLY
        DCHECK_NULL(wasm::GetWasmCodeManager()->LookupCode(this, frame->pc()));
#endif  // V8_ENABLE_WEBASSEMBLY

        // The code might be a dynamically generated stub or a turbofanned
        // embedded builtin.
        Tagged<Code> code = stub_frame->LookupCode();
        if (!code->is_turbofanned() || !code->has_handler_table()) {
          break;
        }

        int offset = stub_frame->LookupExceptionHandlerInTable();
        if (offset < 0) break;

        // Compute the stack pointer from the frame pointer. This ensures
        // that argument slots on the stack are dropped as returning would.
        Address return_sp = frame->fp() +
                            StandardFrameConstants::kFixedFrameSizeAboveFp -
                            code->stack_slots() * kSystemPointerSize;

        return FoundHandler(
            Context(), code->InstructionStart(this, frame->pc()), offset,
            code->constant_pool(), return_sp, frame->fp(), visited_frames);
      }

      case StackFrame::INTERPRETED:
      case StackFrame::BASELINE: {
        // For interpreted frame we perform a range lookup in the handler table.
        if (!catchable_by_js) break;
        UnoptimizedJSFrame* js_frame = UnoptimizedJSFrame::cast(frame);
        int register_slots = UnoptimizedFrameConstants::RegisterStackSlotCount(
            js_frame->GetBytecodeArray()->register_count());
        int context_reg = 0;  // Will contain register index holding context.
        int offset =
            js_frame->LookupExceptionHandlerInTable(&context_reg, nullptr);
        if (offset < 0) break;
        // Compute the stack pointer from the frame pointer. This ensures that
        // argument slots on the stack are dropped as returning would.
        // Note: This is only needed for interpreted frames that have been
        //       materialized by the deoptimizer. If there is a handler frame
        //       in between then {frame->sp()} would already be correct.
        Address return_sp = frame->fp() -
                            InterpreterFrameConstants::kFixedFrameSizeFromFp -
                            register_slots * kSystemPointerSize;

        // Patch the bytecode offset in the interpreted frame to reflect the
        // position of the exception handler. The special builtin below will
        // take care of continuing to dispatch at that position. Also restore
        // the correct context for the handler from the interpreter register.
        Tagged<Context> context =
            Cast<Context>(js_frame->ReadInterpreterRegister(context_reg));
        DCHECK(IsContext(context));

        if (frame->is_baseline()) {
          BaselineFrame* sp_frame = BaselineFrame::cast(js_frame);
          Tagged<Code> code = sp_frame->LookupCode();
          intptr_t pc_offset = sp_frame->GetPCForBytecodeOffset(offset);
          // Patch the context register directly on the frame, so that we don't
          // need to have a context read + write in the baseline code.
          sp_frame->PatchContext(context);
          return FoundHandler(Context(), code->instruction_start(), pc_offset,
                              code->constant_pool(), return_sp, sp_frame->fp(),
                              visited_frames);
        } else {
          InterpretedFrame::cast(js_frame)->PatchBytecodeOffset(
              static_cast<int>(offset));

          Tagged<Code> code = *BUILTIN_CODE(this, InterpreterEnterAtBytecode);
          // We subtract a frame from visited_frames because otherwise the
          // shadow stack will drop the underlying interpreter entry trampoline
          // in which the handler runs.
          //
          // An interpreted frame cannot be the first frame we look at
          // because at a minimum, an exit frame into C++ has to separate
          // it and the context in which this C++ code runs.
          CHECK_GE(visited_frames, 1);
          return FoundHandler(context, code->instruction_start(), 0,
                              code->constant_pool(), return_sp, frame->fp(),
                              visited_frames - 1);
        }
      }

      case StackFrame::BUILTIN:
        // For builtin frames we are guaranteed not to find a handler.
        if (catchable_by_js) {
          CHECK_EQ(-1, BuiltinFrame::cast(frame)->LookupExceptionHandlerInTable(
                           nullptr, nullptr));
        }
        break;

      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH: {
        // Builtin continuation frames with catch can handle exceptions.
        if (!catchable_by_js) break;
        JavaScriptBuiltinContinuationWithCatchFrame* js_frame =
            JavaScriptBuiltinContinuationWithCatchFrame::cast(frame);
        js_frame->SetException(exception);

        // Reconstruct the stack pointer from the frame pointer.
        Address return_sp = js_frame->fp() - js_frame->GetSPToFPDelta();
        Tagged<Code> code = js_frame->LookupCode();
        return FoundHandler(Context(), code->instruction_start(), 0,
                            code->constant_pool(), return_sp, frame->fp(),
                            visited_frames);
      }

      default:
        // All other types can not handle exception.
        break;
    }

    if (frame->is_optimized_js()) {
      // Remove per-frame stored materialized objects.
      bool removed = materialized_object_store_->Remove(frame->fp());
      USE(removed);
      // If there were any materialized objects, the code should be
      // marked for deopt.
      DCHECK_IMPLIES(removed, frame->LookupCode()->marked_for_deoptimization());
    }
  }

  UNREACHABLE();
}  // namespace internal

namespace {

class StackFrameSummaryIterator {
 public:
  explicit StackFrameSummaryIterator(Isolate* isolate)
      : stack_iterator_(isolate), summaries_(), index_(0) {
    InitSummaries();
  }
  void Advance() {
    if (index_ == 0) {
      summaries_.clear();
      stack_iterator_.Advance();
      InitSummaries();
    } else {
      index_--;
    }
  }
  bool done() const { return stack_iterator_.done(); }
  StackFrame* frame() const { return stack_iterator_.frame(); }
  bool has_frame_summary() const { return index_ < summaries_.size(); }
  const FrameSummary& frame_summary() const {
    DCHECK(has_frame_summary());
    return summaries_[index_];
  }
  Isolate* isolate() const { return stack_iterator_.isolate(); }

 private:
  void InitSummaries() {
    if (!done() && frame()->is_javascript()) {
      JavaScriptFrame::cast(frame())->Summarize(&summaries_);
      DCHECK_GT(summaries_.size(), 0);
      index_ = summaries_.size() - 1;
    }
  }
  StackFrameIterator stack_iterator_;
  std::vector<FrameSummary> summaries_;
  size_t index_;
};

HandlerTable::CatchPrediction CatchPredictionFor(Builtin builtin_id) {
  switch (builtin_id) {
#define CASE(Name)       \
  case Builtin::k##Name: \
    return HandlerTable::PROMISE;
    BUILTIN_PROMISE_REJECTION_PREDICTION_LIST(CASE)
#undef CASE
    default:
      return HandlerTable::UNCAUGHT;
  }
}

HandlerTable::CatchPrediction PredictExceptionFromBytecode(
    Tagged<BytecodeArray> bytecode, int code_offset) {
  HandlerTable table(bytecode);
  int handler_index = table.LookupHandlerIndexForRange(code_offset);
  if (handler_index < 0) return HandlerTable::UNCAUGHT;
  return table.GetRangePrediction(handler_index);
}

HandlerTable::CatchPrediction PredictException(const FrameSummary& summary,
                                               Isolate* isolate) {
  if (!summary.IsJavaScript()) {
    // This can happen when WASM is inlined by TurboFan. For now we ignore
    // frames that are not JavaScript.
    // TODO(https://crbug.com/349588762): We should also check Wasm code
    // for exception handling.
    return HandlerTable::UNCAUGHT;
  }
  PtrComprCageBase cage_base(isolate);
  DirectHandle<AbstractCode> code = summary.AsJavaScript().abstract_code();
  if (code->kind(cage_base) == CodeKind::BUILTIN) {
    return CatchPredictionFor(code->GetCode()->builtin_id());
  }

  // Must have been constructed from a bytecode array.
  CHECK_EQ(CodeKind::INTERPRETED_FUNCTION, code->kind(cage_base));
  return PredictExceptionFromBytecode(code->GetBytecodeArray(),
                                      summary.code_offset());
}

HandlerTable::CatchPrediction PredictExceptionFromGenerator(
    DirectHandle<JSGeneratorObject> generator, Isolate* isolate) {
  return PredictExceptionFromBytecode(
      generator->function()->shared()->GetBytecodeArray(isolate),
      GetGeneratorBytecodeOffset(generator));
}

Isolate::CatchType ToCatchType(HandlerTable::CatchPrediction prediction) {
  switch (prediction) {
    case HandlerTable::UNCAUGHT:
      return Isolate::NOT_CAUGHT;
    case HandlerTable::CAUGHT:
      return Isolate::CAUGHT_BY_JAVASCRIPT;
    case HandlerTable::PROMISE:
      return Isolate::CAUGHT_BY_PROMISE;
    case HandlerTable::UNCAUGHT_ASYNC_AWAIT:
    case HandlerTable::ASYNC_AWAIT:
      return Isolate::CAUGHT_BY_ASYNC_AWAIT;
    default:
      UNREACHABLE();
  }
}

Isolate::CatchType PredictExceptionCatchAtFrame(
    const StackFrameSummaryIterator& iterator) {
  const StackFrame* frame = iterator.frame();
  switch (frame->type()) {
    case StackFrame::ENTRY:
    case StackFrame::CONSTRUCT_ENTRY: {
      Address external_handler =
          iterator.isolate()->thread_local_top()->try_catch_handler_address();
      Address entry_handler = frame->top_handler()->next_address();
      // The exception has been externally caught if and only if there is an
      // external handler which is on top of the top-most JS_ENTRY handler.
      if (external_handler != kNullAddress &&
          !iterator.isolate()->try_catch_handler()->IsVerbose()) {
        if (entry_handler == kNullAddress || entry_handler > external_handler) {
          return Isolate::CAUGHT_BY_EXTERNAL;
        }
      }
    } break;

    // For JavaScript frames we perform a lookup in the handler table.
    case StackFrame::INTERPRETED:
    case StackFrame::BASELINE:
    case StackFrame::TURBOFAN_JS:
    case StackFrame::MAGLEV:
    case StackFrame::BUILTIN: {
      DCHECK(iterator.has_frame_summary());
      return ToCatchType(
          PredictException(iterator.frame_summary(), iterator.isolate()));
    }

    case StackFrame::STUB: {
      Tagged<Code> code = *frame->LookupCode();
      if (code->kind() != CodeKind::BUILTIN || !code->has_handler_table() ||
          !code->is_turbofanned()) {
        break;
      }

      return ToCatchType(CatchPredictionFor(code->builtin_id()));
    }

    case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH: {
      Tagged<Code> code = *frame->LookupCode();
      return ToCatchType(CatchPredictionFor(code->builtin_id()));
    }

    default:
      // All other types can not handle exception.
      break;
  }
  return Isolate::NOT_CAUGHT;
}
}  // anonymous namespace

Isolate::CatchType Isolate::PredictExceptionCatcher() {
  if (TopExceptionHandlerType(Tagged<Object>()) ==
      ExceptionHandlerType::kExternalTryCatch) {
    return CAUGHT_BY_EXTERNAL;
  }

  // Search for an exception handler by performing a full walk over the stack.
  for (StackFrameSummaryIterator iter(this); !iter.done(); iter.Advance()) {
    Isolate::CatchType prediction = PredictExceptionCatchAtFrame(iter);
    if (prediction != NOT_CAUGHT) return prediction;
  }

  // Handler not found.
  return NOT_CAUGHT;
}

Tagged<Object> Isolate::ThrowIllegalOperation() {
  if (v8_flags.stack_trace_on_illegal) PrintStack(stdout);
  return Throw(ReadOnlyRoots(heap()).illegal_access_string());
}

void Isolate::PrintCurrentStackTrace(std::ostream& out) {
  DirectHandle<FixedArray> frames = CaptureSimpleStackTrace(
      this, FixedArray::kMaxLength, SKIP_NONE, factory()->undefined_value());

  IncrementalStringBuilder builder(this);
  for (int i = 0; i < frames->length(); ++i) {
    DirectHandle<CallSiteInfo> frame(Cast<CallSiteInfo>(frames->get(i)), this);
    SerializeCallSiteInfo(this, frame, &builder);
    if (i != frames->length() - 1) builder.AppendCharacter('\n');
  }

  DirectHandle<String> stack_trace = builder.Finish().ToHandleChecked();
  stack_trace->PrintOn(out);
}

bool Isolate::ComputeLocation(MessageLocation* target) {
  DebuggableStackFrameIterator it(this);
  if (it.done()) return false;
    // Compute the location from the function and the relocation info of the
    // baseline code. For optimized code this will use the deoptimization
    // information to get canonical location information.
#if V8_ENABLE_WEBASSEMBLY
  wasm::WasmCodeRefScope code_ref_scope;
#endif  // V8_ENABLE_WEBASSEMBLY
  FrameSummary summary = it.GetTopValidFrame();
  Handle<SharedFunctionInfo> shared;
  Handle<Object> script = summary.script();
  if (!IsScript(*script) ||
      IsUndefined(Cast<Script>(*script)->source(), this)) {
    return false;
  }

  if (summary.IsJavaScript()) {
    shared = handle(summary.AsJavaScript().function()->shared(), this);
  }
  if (summary.AreSourcePositionsAvailable()) {
    int pos = summary.SourcePosition();
    *target = MessageLocation(Cast<Script>(script), pos, pos + 1, shared);
  } else {
    *target =
        MessageLocation(Cast<Script>(script), shared, summary.code_offset());
  }
  return true;
}

bool Isolate::ComputeLocationFromException(MessageLocation* target,
                                           Handle<Object> exception) {
  if (!IsJSObject(*exception)) return false;

  Handle<Name> start_pos_symbol = factory()->error_start_pos_symbol();
  DirectHandle<Object> start_pos = JSReceiver::GetDataProperty(
      this, Cast<JSObject>(exception), start_pos_symbol);
  if (!IsSmi(*start_pos)) return false;
  int start_pos_value = Cast<Smi>(*start_pos).value();

  Handle<Name> end_pos_symbol = factory()->error_end_pos_symbol();
  DirectHandle<Object> end_pos = JSReceiver::GetDataProperty(
      this, Cast<JSObject>(exception), end_pos_symbol);
  if (!IsSmi(*end_pos)) return false;
  int end_pos_value = Cast<Smi>(*end_pos).value();

  Handle<Name> script_symbol = factory()->error_script_symbol();
  DirectHandle<Object> script = JSReceiver::GetDataProperty(
      this, Cast<JSObject>(exception), script_symbol);
  if (!IsScript(*script)) return false;

  Handle<Script> cast_script(Cast<Script>(*script), this);
  *target = MessageLocation(cast_script, start_pos_value, end_pos_value);
  return true;
}

bool Isolate::ComputeLocationFromSimpleStackTrace(MessageLocation* target,
                                                  Handle<Object> exception) {
  if (!IsJSReceiver(*exception)) {
    return false;
  }
  DirectHandle<FixedArray> call_site_infos =
      GetSimpleStackTrace(Cast<JSReceiver>(exception));
  for (int i = 0; i < call_site_infos->length(); ++i) {
    DirectHandle<CallSiteInfo> call_site_info(
        Cast<CallSiteInfo>(call_site_infos->get(i)), this);
    if (CallSiteInfo::ComputeLocation(call_site_info, target)) {
      return true;
    }
  }
  return false;
}

bool Isolate::ComputeLocationFromDetailedStackTrace(MessageLocation* target,
                                                    Handle<Object> exception) {
  if (!IsJSReceiver(*exception)) return false;

  Handle<StackTraceInfo> stack_trace =
      GetDetailedStackTrace(Cast<JSReceiver>(exception));
  if (stack_trace.is_null() || stack_trace->length() == 0) {
    return false;
  }

  DirectHandle<StackFrameInfo> info(stack_trace->get(0), this);
  const int pos = StackFrameInfo::GetSourcePosition(info);
  *target = MessageLocation(handle(info->script(), this), pos, pos + 1);
  return true;
}

Handle<JSMessageObject> Isolate::CreateMessage(Handle<Object> exception,
                                               MessageLocation* location) {
  Handle<StackTraceInfo> stack_trace;
  if (capture_stack_trace_for_uncaught_exceptions_) {
    if (IsJSObject(*exception)) {
      // First, check whether a stack trace is already present on this object.
      // It maybe an Error, or the embedder may have stored a stack trace using
      // Exception::CaptureStackTrace().
      // If the lookup fails, we fall through and capture the stack trace
      // at this throw site.
      stack_trace = GetDetailedStackTrace(Cast<JSObject>(exception));
    }
    if (stack_trace.is_null()) {
      // Not an error object, we capture stack and location at throw site.
      stack_trace = CaptureDetailedStackTrace(
          stack_trace_for_uncaught_exceptions_frame_limit_,
          stack_trace_for_uncaught_exceptions_options_);
    }
  }
  MessageLocation computed_location;
  if (location == nullptr &&
      (ComputeLocationFromException(&computed_location, exception) ||
       ComputeLocationFromSimpleStackTrace(&computed_location, exception) ||
       ComputeLocation(&computed_location))) {
    location = &computed_location;
  }

  return MessageHandler::MakeMessageObject(this,
                                           MessageTemplate::kUncaughtException,
                                           location, exception, stack_trace);
}

Handle<JSMessageObject> Isolate::CreateMessageFromException(
    Handle<Object> exception) {
  DirectHandle<StackTraceInfo> stack_trace;
  if (IsJSError(*exception)) {
    stack_trace = GetDetailedStackTrace(Cast<JSObject>(exception));
  }

  MessageLocation* location = nullptr;
  MessageLocation computed_location;
  if (ComputeLocationFromException(&computed_location, exception) ||
      ComputeLocationFromDetailedStackTrace(&computed_location, exception)) {
    location = &computed_location;
  }

  return MessageHandler::MakeMessageObject(this,
                                           MessageTemplate::kPlaceholderOnly,
                                           location, exception, stack_trace);
}

Isolate::ExceptionHandlerType Isolate::TopExceptionHandlerType(
    Tagged<Object> exception) {
  DCHECK_NE(ReadOnlyRoots(heap()).the_hole_value(), exception);

  Address js_handler = Isolate::handler(thread_local_top());
  Address external_handler = thread_local_top()->try_catch_handler_address();

  // A handler cannot be on top if it doesn't exist. For uncatchable exceptions,
  // the JavaScript handler cannot be on top.
  if (js_handler == kNullAddress || !is_catchable_by_javascript(exception)) {
    if (external_handler == kNullAddress) {
      return ExceptionHandlerType::kNone;
    }
    return ExceptionHandlerType::kExternalTryCatch;
  }

  if (external_handler == kNullAddress) {
    return ExceptionHandlerType::kJavaScriptHandler;
  }

  // The exception has been externally caught if and only if there is an
  // external handler which is on top of the top-most JS_ENTRY handler.
  //
  // Note, that finally clauses would re-throw an exception unless it's aborted
  // by jumps in control flow (like return, break, etc.) and we'll have another
  // chance to set proper v8::TryCatch later.
  DCHECK_NE(kNullAddress, external_handler);
  DCHECK_NE(kNullAddress, js_handler);
  if (external_handler < js_handler) {
    return ExceptionHandlerType::kExternalTryCatch;
  }
  return ExceptionHandlerType::kJavaScriptHandler;
}

std::vector<MemoryRange>* Isolate::GetCodePages() const {
  return code_pages_.load(std::memory_order_acquire);
}

void Isolate::SetCodePages(std::vector<MemoryRange>* new_code_pages) {
  code_pages_.store(new_code_pages, std::memory_order_release);
}

void Isolate::ReportPendingMessages(bool report) {
  Tagged<Object> exception_obj = exception();
  ExceptionHandlerType top_handler = TopExceptionHandlerType(exception_obj);

  // Try to propagate the exception to an external v8::TryCatch handler. If
  // propagation was unsuccessful, then we will get another chance at reporting
  // the pending message if the exception is re-thrown.
  bool has_been_propagated = PropagateExceptionToExternalTryCatch(top_handler);
  if (!has_been_propagated) return;
  if (!report) return;

  DCHECK(AllowExceptions::IsAllowed(this));

  // The embedder might run script in response to an exception.
  AllowJavascriptExecutionDebugOnly allow_script(this);

  // Clear the pending message object early to avoid endless recursion.
  Tagged<Object> message_obj = pending_message();
  clear_pending_message();

  // For uncatchable exceptions we do nothing. If needed, the exception and the
  // message have already been propagated to v8::TryCatch.
  if (!is_catchable_by_javascript(exception_obj)) return;

  // Determine whether the message needs to be reported to all message handlers
  // depending on whether the topmost external v8::TryCatch is verbose. We know
  // there's no JavaScript handler on top; if there was, we would've returned
  // early.
  DCHECK_NE(ExceptionHandlerType::kJavaScriptHandler, top_handler);

  bool should_report_exception;
  if (top_handler == ExceptionHandlerType::kExternalTryCatch) {
    should_report_exception = try_catch_handler()->is_verbose_;
  } else {
    should_report_exception = true;
  }

  // Actually report the pending message to all message handlers.
  if (!IsTheHole(message_obj, this) && should_report_exception) {
    HandleScope scope(this);
    DirectHandle<JSMessageObject> message(Cast<JSMessageObject>(message_obj),
                                          this);
    Handle<Script> script(message->script(), this);
    // Clear the exception and restore it afterwards, otherwise
    // CollectSourcePositions will abort.
    {
      ExceptionScope exception_scope(this);
      JSMessageObject::EnsureSourcePositionsAvailable(this, message);
    }
    int start_pos = message->GetStartPosition();
    int end_pos = message->GetEndPosition();
    MessageLocation location(script, start_pos, end_pos);
    MessageHandler::ReportMessage(this, &location, message);
  }
}

namespace {
bool ReceiverIsForwardingHandler(Isolate* isolate, Handle<JSReceiver> handler) {
  // Recurse to the forwarding Promise (e.g. return false) due to
  //  - await reaction forwarding to the throwaway Promise, which has
  //    a dependency edge to the outer Promise.
  //  - PromiseIdResolveHandler forwarding to the output of .then
  //  - Promise.all/Promise.race forwarding to a throwaway Promise, which
  //    has a dependency edge to the generated outer Promise.
  // Otherwise, this is a real reject handler for the Promise.
  Handle<Symbol> key = isolate->factory()->promise_forwarding_handler_symbol();
  DirectHandle<Object> forwarding_handler =
      JSReceiver::GetDataProperty(isolate, handler, key);
  return !IsUndefined(*forwarding_handler, isolate);
}

bool WalkPromiseTreeInternal(
    Isolate* isolate, Handle<JSPromise> promise,
    const std::function<void(Isolate::PromiseHandler)>& callback) {
  if (promise->status() != Promise::kPending) {
    // If a rejection reaches an exception that isn't pending, it will be
    // treated as caught.
    return true;
  }

  bool any_caught = false;
  bool any_uncaught = false;
  DirectHandle<Object> current(promise->reactions(), isolate);
  while (!IsSmi(*current)) {
    auto reaction = Cast<PromiseReaction>(current);
    Handle<HeapObject> promise_or_capability(reaction->promise_or_capability(),
                                             isolate);
    if (!IsUndefined(*promise_or_capability, isolate)) {
      if (!IsJSPromise(*promise_or_capability)) {
        promise_or_capability = handle(
            Cast<PromiseCapability>(promise_or_capability)->promise(), isolate);
      }
      if (IsJSPromise(*promise_or_capability)) {
        Handle<JSPromise> next_promise = Cast<JSPromise>(promise_or_capability);
        bool caught = false;
        Handle<JSReceiver> reject_handler;
        if (!IsUndefined(reaction->reject_handler(), isolate)) {
          reject_handler =
              handle(Cast<JSReceiver>(reaction->reject_handler()), isolate);
          if (!ReceiverIsForwardingHandler(isolate, reject_handler) &&
              !IsBuiltinForwardingRejectHandler(isolate, *reject_handler)) {
            caught = true;
          }
        }
        // Pass each handler to the callback
        Handle<JSGeneratorObject> async_function;
        if (TryGetAsyncGenerator(isolate, reaction).ToHandle(&async_function)) {
          caught = caught ||
                   PredictExceptionFromGenerator(async_function, isolate) ==
                       HandlerTable::CAUGHT;
          // Look at the async function, not the individual handlers
          callback({async_function->function()->shared(), true});
        } else {
          // Not an async function, look at individual handlers
          if (!IsUndefined(reaction->fulfill_handler(), isolate)) {
            Handle<JSReceiver> fulfill_handler(
                Cast<JSReceiver>(reaction->fulfill_handler()), isolate);
            if (!ReceiverIsForwardingHandler(isolate, fulfill_handler)) {
              if (IsBuiltinFunction(isolate, *fulfill_handler,
                                    Builtin::kPromiseThenFinally)) {
                // If this is the finally handler, get the wrapped callback
                // from the context to use instead
                DirectHandle<Context> context(
                    Cast<JSFunction>(reaction->fulfill_handler())->context(),
                    isolate);
                int const index =
                    PromiseBuiltins::PromiseFinallyContextSlot::kOnFinallySlot;
                fulfill_handler =
                    handle(Cast<JSReceiver>(context->get(index)), isolate);
              }
              if (IsJSFunction(*fulfill_handler)) {
                callback({Cast<JSFunction>(fulfill_handler)->shared(), true});
              }
            }
          }
          if (caught) {
            // We've already checked that this isn't undefined or
            // a forwarding handler
            if (IsJSFunction(*reject_handler)) {
              callback({Cast<JSFunction>(reject_handler)->shared(), true});
            }
          }
        }
        caught =
            caught || WalkPromiseTreeInternal(isolate, next_promise, callback);
        any_caught = any_caught || caught;
        any_uncaught = any_uncaught || !caught;
      }
    } else {
#if V8_ENABLE_WEBASSEMBLY
      Handle<WasmSuspenderObject> suspender;
      if (TryGetWasmSuspender(isolate, reaction->fulfill_handler())
              .ToHandle(&suspender)) {
        // If in the future we support Wasm exceptions or ignore listing in
        // Wasm, we will need to iterate through these frames. For now, we
        // only care about the resulting promise.
        Handle<JSPromise> next_promise = handle(suspender->promise(), isolate);
        bool caught = WalkPromiseTreeInternal(isolate, next_promise, callback);
        any_caught = any_caught || caught;
        any_uncaught = any_uncaught || !caught;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    current = direct_handle(reaction->next(), isolate);
  }

  bool caught = any_caught && !any_uncaught;

  if (!caught) {
    // If there is an outer promise, follow that to see if it is caught.
    Handle<Symbol> key = isolate->factory()->promise_handled_by_symbol();
    Handle<Object> outer_promise_obj =
        JSObject::GetDataProperty(isolate, promise, key);
    if (IsJSPromise(*outer_promise_obj)) {
      return WalkPromiseTreeInternal(
          isolate, Cast<JSPromise>(outer_promise_obj), callback);
    }
  }
  return caught;
}

// Helper functions to scan for calls to .catch.
using interpreter::Bytecode;
using interpreter::Bytecodes;

enum PromiseMethod { kThen, kCatch, kFinally, kInvalid };

// Requires the iterator to be on a GetNamedProperty instruction
PromiseMethod GetPromiseMethod(
    Isolate* isolate, const interpreter::BytecodeArrayIterator& iterator) {
  DirectHandle<Object> object = iterator.GetConstantForIndexOperand(1, isolate);
  if (!IsString(*object)) {
    return kInvalid;
  }
  auto str = Cast<String>(object);
  if (str->Equals(ReadOnlyRoots(isolate).then_string())) {
    return kThen;
  } else if (str->IsEqualTo(base::StaticCharVector("catch"))) {
    return kCatch;
  } else if (str->IsEqualTo(base::StaticCharVector("finally"))) {
    return kFinally;
  } else {
    return kInvalid;
  }
}

bool TouchesRegister(const interpreter::BytecodeArrayIterator& iterator,
                     int index) {
  Bytecode bytecode = iterator.current_bytecode();
  int num_operands = Bytecodes::NumberOfOperands(bytecode);
  const interpreter::OperandType* operand_types =
      Bytecodes::GetOperandTypes(bytecode);

  for (int i = 0; i < num_operands; ++i) {
    if (Bytecodes::IsRegisterOperandType(operand_types[i])) {
      int base_index = iterator.GetRegisterOperand(i).index();
      int num_registers;
      if (Bytecodes::IsRegisterListOperandType(operand_types[i])) {
        num_registers = iterator.GetRegisterCountOperand(++i);
      } else {
        num_registers =
            Bytecodes::GetNumberOfRegistersRepresentedBy(operand_types[i]);
      }

      if (base_index <= index && index < base_index + num_registers) {
        return true;
      }
    }
  }

  if (Bytecodes::WritesImplicitRegister(bytecode)) {
    return iterator.GetStarTargetRegister().index() == index;
  }

  return false;
}

bool CallsCatchMethod(Isolate* isolate, Handle<BytecodeArray> bytecode_array,
                      int offset) {
  interpreter::BytecodeArrayIterator iterator(bytecode_array, offset);

  while (!iterator.done()) {
    // We should be on a call instruction of some kind. While we could check
    // this, it may be difficult to create an exhaustive list of instructions
    // that could call, such as property getters, but at a minimum this
    // instruction should write to the accumulator.
    if (!Bytecodes::WritesAccumulator(iterator.current_bytecode())) {
      return false;
    }

    iterator.Advance();
    // While usually the next instruction is a Star, sometimes we store and
    // reload from context first.
    if (iterator.done()) {
      return false;
    }
    if (iterator.current_bytecode() == Bytecode::kStaCurrentContextSlot) {
      // Step over patterns like:
      //     StaCurrentContextSlot [x]
      //     LdaImmutableCurrentContextSlot [x]
      unsigned int slot = iterator.GetIndexOperand(0);
      iterator.Advance();
      if (!iterator.done() &&
          (iterator.current_bytecode() ==
               Bytecode::kLdaImmutableCurrentContextSlot ||
           iterator.current_bytecode() == Bytecode::kLdaCurrentContextSlot)) {
        if (iterator.GetIndexOperand(0) != slot) {
          return false;
        }
        iterator.Advance();
      }
    } else if (iterator.current_bytecode() == Bytecode::kStaContextSlot) {
      // Step over patterns like:
      //     StaContextSlot r_x [y] [z]
      //     LdaContextSlot r_x [y] [z]
      int context = iterator.GetRegisterOperand(0).index();
      unsigned int slot = iterator.GetIndexOperand(1);
      unsigned int depth = iterator.GetUnsignedImmediateOperand(2);
      iterator.Advance();
      if (!iterator.done() &&
          (iterator.current_bytecode() == Bytecode::kLdaImmutableContextSlot ||
           iterator.current_bytecode() == Bytecode::kLdaContextSlot)) {
        if (iterator.GetRegisterOperand(0).index() != context ||
            iterator.GetIndexOperand(1) != slot ||
            iterator.GetUnsignedImmediateOperand(2) != depth) {
          return false;
        }
        iterator.Advance();
      }
    } else if (iterator.current_bytecode() == Bytecode::kStaLookupSlot) {
      // Step over patterns like:
      //     StaLookupSlot [x] [_]
      //     LdaLookupSlot [x]
      unsigned int slot = iterator.GetIndexOperand(0);
      iterator.Advance();
      if (!iterator.done() &&
          (iterator.current_bytecode() == Bytecode::kLdaLookupSlot ||
           iterator.current_bytecode() ==
               Bytecode::kLdaLookupSlotInsideTypeof)) {
        if (iterator.GetIndexOperand(0) != slot) {
          return false;
        }
        iterator.Advance();
      }
    }

    // Next instruction should be a Star (store accumulator to register)
    if (iterator.done() || !Bytecodes::IsAnyStar(iterator.current_bytecode())) {
      return f
"""


```