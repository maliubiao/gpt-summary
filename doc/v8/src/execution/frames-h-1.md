Response:
The user wants a summary of the functionality of the C++ header file `v8/src/execution/frames.h`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file defines classes representing different types of stack frames in V8. This is crucial for understanding how V8 manages execution context.

2. **Categorize the frame types:**  Notice the inheritance structure and the different frame classes (e.g., `StackFrame`, `JavaScriptFrame`, `ExitFrame`, `WasmFrame`). Group them by their general function.

3. **Analyze key methods and members:**  Look for methods that reveal the purpose of each frame type (e.g., `GetBytecodeOffset`, `function`, `receiver`, `Summarize`).

4. **Consider the relationships between frame types:** How do different frames interact?  `StackFrameIterator` is a key component here.

5. **Check for JavaScript relevance:** Are there frame types specifically related to JavaScript execution?  `JavaScriptFrame`, `InterpretedFrame`, `OptimizedJSFrame` are obvious candidates.

6. **Address the `.tq` question:** Explain that `.h` indicates a C++ header file, not a Torque file.

7. **Look for programming errors:**  Are there common errors that relate to stack frames or the information they hold? (Though this header itself doesn't directly *cause* errors, understanding stack frames helps debug them).

8. **Structure the summary:** Organize the findings logically. Start with the overall purpose, then delve into specific frame types and their functions. Include details about iteration and debugging.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/execution/frames.h以.tq结尾，那它是个v8 torque源代码: Yes
* 如果它与javascript的功能有关系，请用javascript举例说明: Yes
* 如果有代码逻辑推理，请给出假设输入与输出: No - This file primarily defines data structures and accessors, not complex logic.
* 如果涉及用户常见的编程错误，请举例说明: Yes (related to debugging stack traces).
* 这是第2部分，共3部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

Imagine iterating through the code, focusing on keywords like `class`, inheritance (`:`), and method names. Think about how a debugger might use this information. Consider scenarios where different types of frames would be present (e.g., calling a built-in function, executing optimized code, handling exceptions).

**Key Learnings from Simulation:**

* The file is heavily focused on defining the structure of the call stack.
* Different frame types represent different execution contexts (JavaScript, built-in functions, C++ API calls, WebAssembly).
* Iterators are essential for traversing the stack.
* Information stored in frames is crucial for debugging and understanding program execution.

Strategizing complete. I will now generate the response following these steps.
## v8/src/execution/frames.h 功能归纳 (第 2 部分)

这是 `v8/src/execution/frames.h` 文件的第二部分，延续了对 V8 引擎中不同类型栈帧的定义。总的来说，这部分主要定义了各种 **退出帧 (Exit Frames)**、**桩帧 (Stub Frames)** 以及不同类型的 **JavaScript 帧 (JavaScript Frames)** 和 **WebAssembly 帧 (Wasm Frames)**。

**核心功能归纳:**

1. **定义不同类型的退出帧 (Exit Frames):**
   - **`ExitFrame`:**  作为所有退出帧的基类，用于表示从 V8 管理的代码 (例如 JavaScript) 过渡到非 V8 管理的代码 (例如 C++ 内置函数或外部 API 调用) 的帧。它提供了一些基础的功能，如计算调用者状态。
   - **`BuiltinExitFrame`:**  用于表示调用 C++ 内置函数（例如 `Math.acos`）的帧。它允许这些内置函数出现在堆栈跟踪中，并提供访问函数、接收者和参数的方法。
   - **`ApiCallbackExitFrame`:** 用于表示调用 V8 API 函数（例如 `v8::Function` 或 `v8::FunctionTemplate`）的帧。它的主要目的是支持对 API 函数抛出的异常进行预处理，并允许这些函数出现在堆栈跟踪中。
   - **`ApiAccessorExitFrame`:** 用于表示调用 V8 API 属性访问回调（`v8::AccessorGetterCallback` 或 `v8::AccessorSetterCallback`）的帧。它的主要目的是支持对这些回调中抛出的异常进行预处理。

2. **定义桩帧 (Stub Frame):**
   - **`StubFrame`:** 代表执行 V8 内部代码（通常是汇编代码 "stubs"）的帧。这些桩通常用于执行一些低级的操作，例如函数调用、对象分配等。它提供了访问代码对象和查找异常处理器的功能。

3. **定义不同类型的 JavaScript 帧 (JavaScript Frames):**
   - **`JavaScriptFrame`:** 作为所有 JavaScript 帧的基类，代表执行 JavaScript 代码的帧。
   - **`OptimizedJSFrame`:** 代表执行经过优化的 JavaScript 代码（例如 TurboFan 或 Maglev 编译的代码）的帧。它提供了访问共享函数信息、反优化数据、查找异常处理器以及确定返回地址的功能。
   - **`UnoptimizedJSFrame`:** 代表执行未优化的 JavaScript 代码（通过解释器或基线编译器执行）的帧。它提供了访问字节码偏移量、字节码数组和解释器寄存器的功能。
   - **`InterpretedFrame`:**  继承自 `UnoptimizedJSFrame`，代表正在通过解释器执行 JavaScript 字节码的帧。
   - **`BaselineFrame`:** 继承自 `UnoptimizedJSFrame`，代表正在执行由基线编译器生成的代码的帧。
   - **`MaglevFrame`:** 继承自 `OptimizedJSFrame`，代表正在执行由 Maglev 编译器生成的代码的帧。
   - **`TurbofanJSFrame`:** 继承自 `OptimizedJSFrame`，代表正在执行由 TurboFan 编译器生成的代码的帧。

4. **定义不同类型的 WebAssembly 帧 (Wasm Frames):**
   - **`WasmFrame`:** 代表执行 WebAssembly 代码的帧。它提供了访问 WebAssembly 实例、本地模块、函数索引、脚本信息等的功能。
   - **`WasmSegmentStartFrame`:**  一种特殊的 `WasmFrame`，用于标记为可增长堆栈分配的新堆栈段的开始。
   - **`WasmExitFrame`:** 代表从 WebAssembly 代码过渡到非 WebAssembly 代码的帧。
   - **`WasmInterpreterEntryFrame`:** 代表 WebAssembly 解释器入口的帧。
   - **`WasmDebugBreakFrame`:** 代表 WebAssembly 调试断点的帧。
   - **`WasmToJsFrame`:** 代表从 WebAssembly 调用 JavaScript 的帧。
   - **`WasmToJsFunctionFrame`:** 代表从 WebAssembly 调用 JavaScript 函数的帧。
   - **`JsToWasmFrame`:** 代表从 JavaScript 调用 WebAssembly 的帧。
   - **`CWasmEntryFrame`:** 代表 C++ WebAssembly 入口的帧。
   - **`WasmLiftoffSetupFrame`:** 代表 WebAssembly Liftoff 编译器设置阶段的帧。

5. **定义其他类型的帧:**
   - **`BuiltinFrame`:** 代表执行具有 JavaScript 链接的内置函数（例如 `Math.asin`）的帧。
   - **`InternalFrame`:** 代表 V8 内部使用的帧，例如用于处理函数调用的 `ConstructFrame` 和 `FastConstructFrame`。
   - **`ConstructFrame`:**  代表通过 `new` 关键字调用函数时创建的特殊 trampoline 帧。
   - **`FastConstructFrame`:**  `ConstructFrame` 的一种优化版本，避免将参数推入堆栈两次。
   - **`BuiltinContinuationFrame`:** 代表用于处理内置函数延续的帧。
   - **`JavaScriptBuiltinContinuationFrame`:** 代表用于处理 JavaScript 内置函数延续的帧。
   - **`JavaScriptBuiltinContinuationWithCatchFrame`:** 代表用于处理带有 `catch` 子句的 JavaScript 内置函数延续的帧。
   - **`IrregexpFrame`:** 代表执行正则表达式引擎的帧。
   - **`StackSwitchFrame`:** 代表堆栈切换的帧。

6. **定义栈帧迭代器 (Stack Frame Iterators):**
   - **`StackFrameIteratorBase`:**  作为所有栈帧迭代器的基类，提供遍历栈帧的基本功能。
   - **`StackFrameIterator`:**  用于遍历当前线程或指定线程的栈帧。
   - **`JavaScriptStackFrameIterator`:**  用于遍历栈上的 JavaScript 帧。
   - **`DebuggableStackFrameIterator`:** 用于遍历可调试的栈帧 (包括 Wasm 和可调试的 JS 帧)。
   - **`StackFrameIteratorForProfiler`:**  一种特殊的栈帧迭代器，用于在 profiler 中安全地遍历栈帧，即使在栈状态不完全一致的情况下也能工作。
   - **`StackFrameIteratorForProfilerForTesting`:**  用于测试的 `StackFrameIteratorForProfiler` 子类。

**与 JavaScript 的关系:**

大部分定义的帧类型都与 JavaScript 的执行直接相关，例如 `JavaScriptFrame` 的各种子类 (`InterpretedFrame`, `OptimizedJSFrame` 等)。 这些帧存储了执行 JavaScript 代码所需的上下文信息，例如当前执行的代码、变量、调用栈等。

**JavaScript 示例:**

```javascript
function foo() {
  bar();
}

function bar() {
  console.trace(); // 打印当前调用栈
}

foo();
```

当执行 `console.trace()` 时，V8 会遍历当前的调用栈，其中就包含不同类型的 JavaScript 帧，例如对应 `foo` 和 `bar` 函数的帧。  根据 V8 编译 `foo` 和 `bar` 的方式，这些帧可能是 `InterpretedFrame` (如果未优化) 或 `OptimizedJSFrame` (如果经过 TurboFan 或 Maglev 优化)。

**常见的编程错误 (与理解栈帧相关):**

理解栈帧对于调试至关重要。以下是一些与栈帧相关的常见编程错误，以及理解栈帧如何帮助诊断它们：

* **栈溢出 (Stack Overflow):**  当函数调用层级过深，导致栈空间被耗尽时发生。  栈帧记录了每次函数调用的信息，过多的栈帧会导致栈溢出。
  * **例子:** 递归函数没有正确的终止条件。

  ```javascript
  function recursiveFunction() {
    recursiveFunction(); // 缺少终止条件
  }
  recursiveFunction(); // 可能导致栈溢出
  ```

  通过查看栈跟踪信息，可以看到 `recursiveFunction` 被重复调用，从而诊断出问题。

* **未捕获的异常:** 当程序抛出异常但没有合适的 `try...catch` 块来处理时，异常会沿着调用栈向上冒泡。栈帧信息可以帮助确定异常抛出的位置以及调用路径。
  * **例子:** 访问未定义的变量。

  ```javascript
  function someFunction() {
    console.log(undefinedVariable); // 抛出 ReferenceError
  }
  someFunction();
  ```

  栈跟踪信息会显示异常是在 `someFunction` 中抛出的。

* **理解异步操作的调用栈:** 在异步编程中，回调函数的执行栈与触发异步操作的栈可能不同。理解栈帧的概念可以帮助理解异步操作的执行流程。
  * **例子:** 使用 `setTimeout`。

  ```javascript
  function first() {
    setTimeout(function second() {
      console.trace();
    }, 0);
  }
  first();
  ```

  `console.trace()` 打印的栈信息会显示 `second` 函数的执行栈，但不会包含 `first` 函数的完整调用栈，因为 `second` 是异步执行的。

**总结:**

`v8/src/execution/frames.h` 的这部分定义了 V8 引擎中各种类型的退出帧、桩帧以及 JavaScript 和 WebAssembly 代码执行时产生的栈帧。 这些定义是 V8 引擎管理执行上下文、进行调试、处理异常和进行性能分析的关键组成部分。理解不同类型的栈帧以及它们包含的信息，对于深入理解 V8 引擎的运行机制至关重要。

**由于这部分不包含复杂的代码逻辑推理，因此无法提供具体的假设输入和输出来进行推理。 这部分主要关注数据结构的定义。**

Prompt: 
```
这是目录为v8/src/execution/frames.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/frames.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
ting the first stack frame seen by an
  // iterator and the frames following entry frames.
  static Type GetStateForFramePointer(Address fp, State* state);
  static Address ComputeStackPointer(Address fp);
  static StackFrame::Type ComputeFrameType(Address fp);
  static void FillState(Address fp, Address sp, State* state);

 protected:
  inline explicit ExitFrame(StackFrameIteratorBase* iterator);

 private:
  void ComputeCallerState(State* state) const override;

  friend class StackFrameIteratorBase;
};

// Builtin exit frames are a special case of exit frames, which are used
// whenever C++ builtins (e.g., Math.acos) are called. Their main purpose is
// to allow such builtins to appear in stack traces.
class BuiltinExitFrame : public ExitFrame {
 public:
  Type type() const override { return BUILTIN_EXIT; }

  Tagged<JSFunction> function() const;

  Tagged<Object> receiver() const;
  Tagged<Object> GetParameter(int i) const;
  int ComputeParametersCount() const;
  Handle<FixedArray> GetParameters() const;

  // Check if this frame is a constructor frame invoked through 'new'.
  bool IsConstructor() const;

  void Print(StringStream* accumulator, PrintMode mode,
             int index) const override;

  // Summarize Frame
  void Summarize(std::vector<FrameSummary>* frames) const override;

 protected:
  inline explicit BuiltinExitFrame(StackFrameIteratorBase* iterator);

 private:
  inline Tagged<Object> receiver_slot_object() const;
  inline Tagged<Object> argc_slot_object() const;
  inline Tagged<Object> target_slot_object() const;
  inline Tagged<Object> new_target_slot_object() const;

  friend class StackFrameIteratorBase;
};

// Api callback exit frames are a special case of exit frames, which are used
// whenever an Api functions (such as v8::Function or v8::FunctionTemplate) are
// called. Their main purpose is to support preprocessing of exceptions thrown
// from Api functions and as a bonus it allows these functions to appear in
// stack traces (see v8_flags.experimental_stack_trace_frames).
class ApiCallbackExitFrame : public ExitFrame {
 public:
  Type type() const override { return API_CALLBACK_EXIT; }

  // In case function slot contains FunctionTemplateInfo, instantiate the
  // function, stores it in the function slot and returns JSFunction handle.
  Handle<JSFunction> GetFunction() const;

  Handle<FunctionTemplateInfo> GetFunctionTemplateInfo() const;

  inline Tagged<Object> receiver() const;
  inline Tagged<Object> GetParameter(int i) const;
  inline int ComputeParametersCount() const;
  Handle<FixedArray> GetParameters() const;

  inline Tagged<Object> context() const override;

  // Check if this frame is a constructor frame invoked through 'new'.
  inline bool IsConstructor() const;

  void Print(StringStream* accumulator, PrintMode mode,
             int index) const override;

  // Summarize Frame
  void Summarize(std::vector<FrameSummary>* frames) const override;

  static ApiCallbackExitFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_api_callback_exit());
    return static_cast<ApiCallbackExitFrame*>(frame);
  }

 protected:
  inline explicit ApiCallbackExitFrame(StackFrameIteratorBase* iterator);

 private:
  // ApiCallbackExitFrame might contain either FunctionTemplateInfo or
  // JSFunction in the function slot.
  inline Tagged<HeapObject> target() const;

  inline void set_target(Tagged<HeapObject> function) const;

  inline FullObjectSlot target_slot() const;

  friend class StackFrameIteratorBase;
};

// Api accessor exit frames are a special case of exit frames, which are used
// whenever an Api property accessor callbacks (v8::AccessorGetterCallback or
// v8::AccessorSetterCallback) are called. Their main purpose is to support
// preprocessing of exceptions thrown from these callbacks.
class ApiAccessorExitFrame : public ExitFrame {
 public:
  Type type() const override { return API_ACCESSOR_EXIT; }

  inline Tagged<Name> property_name() const;

  inline Tagged<Object> receiver() const;
  inline Tagged<Object> holder() const;

  void Print(StringStream* accumulator, PrintMode mode,
             int index) const override;

  // Summarize Frame
  void Summarize(std::vector<FrameSummary>* frames) const override;

  static ApiAccessorExitFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_api_accessor_exit());
    return static_cast<ApiAccessorExitFrame*>(frame);
  }

 protected:
  inline explicit ApiAccessorExitFrame(StackFrameIteratorBase* iterator);

 private:
  inline FullObjectSlot property_name_slot() const;
  inline FullObjectSlot receiver_slot() const;
  inline FullObjectSlot holder_slot() const;

  friend class StackFrameIteratorBase;
};

class StubFrame : public TypedFrame {
 public:
  Type type() const override { return STUB; }

  Tagged<HeapObject> unchecked_code() const override;

  // Lookup exception handler for current {pc}, returns -1 if none found. Only
  // TurboFan stub frames are supported.
  int LookupExceptionHandlerInTable();

  void Summarize(std::vector<FrameSummary>* frames) const override;

 protected:
  inline explicit StubFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class OptimizedJSFrame : public JavaScriptFrame {
 public:
  // Return a list with {SharedFunctionInfo} objects of this frame.
  // The functions are ordered bottom-to-top (i.e. functions.last()
  // is the top-most activation)
  void GetFunctions(
      std::vector<Tagged<SharedFunctionInfo>>* functions) const override;

  void Summarize(std::vector<FrameSummary>* frames) const override;

  Tagged<DeoptimizationData> GetDeoptimizationData(Tagged<Code> code,
                                                   int* deopt_index) const;

  static int StackSlotOffsetRelativeToFp(int slot_index);

  // Lookup exception handler for current {pc}, returns -1 if none found.
  int LookupExceptionHandlerInTable(
      int* data, HandlerTable::CatchPrediction* prediction) override;

  virtual int FindReturnPCForTrampoline(Tagged<Code> code,
                                        int trampoline_pc) const = 0;

 protected:
  inline explicit OptimizedJSFrame(StackFrameIteratorBase* iterator);
};

// An unoptimized frame is a JavaScript frame that is executing bytecode. It
// may be executing it using the interpreter, or via baseline code compiled from
// the bytecode.
class UnoptimizedJSFrame : public JavaScriptFrame {
 public:
  // Accessors.
  int position() const override;

  // Lookup exception handler for current {pc}, returns -1 if none found.
  int LookupExceptionHandlerInTable(
      int* data, HandlerTable::CatchPrediction* prediction) override;

  // Returns the current offset into the bytecode stream.
  virtual int GetBytecodeOffset() const = 0;

  // Returns the frame's current bytecode array.
  Tagged<BytecodeArray> GetBytecodeArray() const;

  // Access to the interpreter register file for this frame.
  Tagged<Object> ReadInterpreterRegister(int register_index) const;

  inline void SetFeedbackVector(Tagged<FeedbackVector> feedback_vector);

  // Build a list with summaries for this frame including all inlined frames.
  void Summarize(std::vector<FrameSummary>* frames) const override;

  static UnoptimizedJSFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_unoptimized_js());
    return static_cast<UnoptimizedJSFrame*>(frame);
  }

 protected:
  inline explicit UnoptimizedJSFrame(StackFrameIteratorBase* iterator);

  Address GetExpressionAddress(int n) const override;

 private:
  friend class StackFrameIteratorBase;
};

class InterpretedFrame : public UnoptimizedJSFrame {
 public:
  Type type() const override { return INTERPRETED; }

  // Returns the current offset into the bytecode stream.
  int GetBytecodeOffset() const override;

  // Updates the current offset into the bytecode stream, mainly used for stack
  // unwinding to continue execution at a different bytecode offset.
  void PatchBytecodeOffset(int new_offset);

  // Updates the frame's BytecodeArray with |bytecode_array|. Used by the
  // debugger to swap execution onto a BytecodeArray patched with breakpoints.
  void PatchBytecodeArray(Tagged<BytecodeArray> bytecode_array);

  static InterpretedFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_interpreted());
    return static_cast<InterpretedFrame*>(frame);
  }
  static const InterpretedFrame* cast(const StackFrame* frame) {
    DCHECK(frame->is_interpreted());
    return static_cast<const InterpretedFrame*>(frame);
  }

 protected:
  inline explicit InterpretedFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class BaselineFrame : public UnoptimizedJSFrame {
 public:
  Type type() const override { return BASELINE; }

  // Returns the current offset into the bytecode stream.
  int GetBytecodeOffset() const override;

  intptr_t GetPCForBytecodeOffset(int lookup_offset) const;

  void PatchContext(Tagged<Context> value);

  static BaselineFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_baseline());
    return static_cast<BaselineFrame*>(frame);
  }
  static const BaselineFrame* cast(const StackFrame* frame) {
    DCHECK(frame->is_baseline());
    return static_cast<const BaselineFrame*>(frame);
  }

 protected:
  inline explicit BaselineFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class MaglevFrame : public OptimizedJSFrame {
 public:
  Type type() const override { return MAGLEV; }

  static MaglevFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_maglev());
    return static_cast<MaglevFrame*>(frame);
  }

  void Iterate(RootVisitor* v) const override;

  int FindReturnPCForTrampoline(Tagged<Code> code,
                                int trampoline_pc) const override;

  Handle<JSFunction> GetInnermostFunction() const;
  BytecodeOffset GetBytecodeOffsetForOSR() const;

  static intptr_t StackGuardFrameSize(int register_input_count);

 protected:
  inline explicit MaglevFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class TurbofanJSFrame : public OptimizedJSFrame {
 public:
  Type type() const override { return TURBOFAN_JS; }

  int ComputeParametersCount() const override;

  void Iterate(RootVisitor* v) const override;

  int FindReturnPCForTrampoline(Tagged<Code> code,
                                int trampoline_pc) const override;

 protected:
  inline explicit TurbofanJSFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;

  Tagged<Object> StackSlotAt(int index) const;
};

// Builtin frames are built for builtins with JavaScript linkage, such as
// various standard library functions (i.e. Math.asin, Math.floor, etc.).
class BuiltinFrame final : public TypedFrameWithJSLinkage {
 public:
  Type type() const final { return BUILTIN; }

  static BuiltinFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_builtin());
    return static_cast<BuiltinFrame*>(frame);
  }

  Tagged<JSFunction> function() const override;
  int ComputeParametersCount() const override;

 protected:
  inline explicit BuiltinFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

#if V8_ENABLE_WEBASSEMBLY
class WasmFrame : public TypedFrame {
 public:
  Type type() const override { return WASM; }

  // Printing support.
  void Print(StringStream* accumulator, PrintMode mode,
             int index) const override;

  // Lookup exception handler for current {pc}, returns -1 if none found.
  int LookupExceptionHandlerInTable();

  void Iterate(RootVisitor* v) const override;

  // Accessors.
  virtual V8_EXPORT_PRIVATE Tagged<WasmInstanceObject> wasm_instance() const;
  virtual Tagged<WasmTrustedInstanceData> trusted_instance_data() const;
  V8_EXPORT_PRIVATE wasm::NativeModule* native_module() const;

  virtual wasm::WasmCode* wasm_code() const;
  int function_index() const;
  Tagged<Script> script() const;
  // Byte position in the module, or asm.js source position.
  int position() const override;
  Tagged<Object> context() const override;
  bool at_to_number_conversion() const;
  // Generated code byte offset in the function.
  int generated_code_offset() const;
  bool is_inspectable() const;

  void Summarize(std::vector<FrameSummary>* frames) const override;

  static WasmFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_wasm()
#ifdef V8_ENABLE_DRUMBRAKE
           && !frame->is_wasm_interpreter_entry()
#endif  // V8_ENABLE_DRUMBRAKE
    );
    return static_cast<WasmFrame*>(frame);
  }

 protected:
  inline explicit WasmFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
  Tagged<WasmModuleObject> module_object() const;
};

// WasmSegmentStartFrame is a regular Wasm frame moved to the
// beginning of a new stack segment allocated for growable stack.
// It requires special handling on return. To indicate that, the WASM frame type
// is replaced by WASM_SEGMENT_START.
class WasmSegmentStartFrame : public WasmFrame {
 public:
  // type() intentionally returns WASM frame type because WasmSegmentStartFrame
  // behaves exactly like regular WasmFrame in all scenarios.
  Type type() const override { return WASM; }

 protected:
  inline explicit WasmSegmentStartFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

// Wasm to C-API exit frame.
class WasmExitFrame : public WasmFrame {
 public:
  Type type() const override { return WASM_EXIT; }
  static Address ComputeStackPointer(Address fp);

 protected:
  inline explicit WasmExitFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

#if V8_ENABLE_DRUMBRAKE
class WasmInterpreterEntryFrame final : public WasmFrame {
 public:
  Type type() const override { return WASM_INTERPRETER_ENTRY; }

  // GC support.
  void Iterate(RootVisitor* v) const override;

  // Printing support.
  void Print(StringStream* accumulator, PrintMode mode,
             int index) const override;

  void Summarize(std::vector<FrameSummary>* frames) const override;

  // Determine the code for the frame.
  Tagged<HeapObject> unchecked_code() const override;

  // Accessors.
  Tagged<Tuple2> interpreter_object() const;
  V8_EXPORT_PRIVATE Tagged<WasmInstanceObject> wasm_instance() const override;
  Tagged<WasmTrustedInstanceData> trusted_instance_data() const override;

  wasm::WasmCode* wasm_code() const override { UNREACHABLE(); }
  int function_index(int inlined_function_index) const;
  int position() const override;
  Tagged<Object> context() const override;

  static WasmInterpreterEntryFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_wasm_interpreter_entry());
    return static_cast<WasmInterpreterEntryFrame*>(frame);
  }

 protected:
  inline explicit WasmInterpreterEntryFrame(StackFrameIteratorBase* iterator);

  Address GetCallerStackPointer() const override;

 private:
  friend class StackFrameIteratorBase;
  Tagged<WasmModuleObject> module_object() const;
};
#endif  // V8_ENABLE_DRUMBRAKE

class WasmDebugBreakFrame final : public TypedFrame {
 public:
  Type type() const override { return WASM_DEBUG_BREAK; }

  // GC support.
  void Iterate(RootVisitor* v) const override;

  void Print(StringStream* accumulator, PrintMode mode,
             int index) const override;

  static WasmDebugBreakFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_wasm_debug_break());
    return static_cast<WasmDebugBreakFrame*>(frame);
  }

 protected:
  inline explicit WasmDebugBreakFrame(StackFrameIteratorBase*);

 private:
  friend class StackFrameIteratorBase;
};

class WasmToJsFrame : public WasmFrame {
 public:
  Type type() const override { return WASM_TO_JS; }

#if V8_ENABLE_DRUMBRAKE
  void Iterate(RootVisitor* v) const override;
#endif  // V8_ENABLE_DRUMBRAKE

  int position() const override { return 0; }
  Tagged<WasmInstanceObject> wasm_instance() const override;
  Tagged<WasmTrustedInstanceData> trusted_instance_data() const override;

 protected:
  inline explicit WasmToJsFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class WasmToJsFunctionFrame : public TypedFrame {
 public:
  Type type() const override { return WASM_TO_JS_FUNCTION; }

 protected:
  inline explicit WasmToJsFunctionFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class JsToWasmFrame : public StubFrame {
 public:
  Type type() const override { return JS_TO_WASM; }

  void Iterate(RootVisitor* v) const override;

 protected:
  inline explicit JsToWasmFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class StackSwitchFrame : public ExitFrame {
 public:
  Type type() const override { return STACK_SWITCH; }
  void Iterate(RootVisitor* v) const override;
  static void GetStateForJumpBuffer(wasm::JumpBuffer* jmpbuf, State* state);

 protected:
  inline explicit StackSwitchFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class CWasmEntryFrame : public StubFrame {
 public:
  Type type() const override { return C_WASM_ENTRY; }

#if V8_ENABLE_DRUMBRAKE
  void Iterate(RootVisitor* v) const override;
#endif  // V8_ENABLE_DRUMBRAKE

 protected:
  inline explicit CWasmEntryFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
  Type GetCallerState(State* state) const override;
};

class WasmLiftoffSetupFrame : public TypedFrame {
 public:
  Type type() const override { return WASM_LIFTOFF_SETUP; }

  FullObjectSlot wasm_instance_data_slot() const;

  int GetDeclaredFunctionIndex() const;

  wasm::NativeModule* GetNativeModule() const;

  // Garbage collection support.
  void Iterate(RootVisitor* v) const override;

  static WasmLiftoffSetupFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_wasm_liftoff_setup());
    return static_cast<WasmLiftoffSetupFrame*>(frame);
  }

 protected:
  inline explicit WasmLiftoffSetupFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};
#endif  // V8_ENABLE_WEBASSEMBLY

class InternalFrame : public TypedFrame {
 public:
  Type type() const override { return INTERNAL; }

  // Garbage collection support.
  void Iterate(RootVisitor* v) const override;

  static InternalFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_internal());
    return static_cast<InternalFrame*>(frame);
  }

 protected:
  inline explicit InternalFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

// Construct frames are special trampoline frames introduced to handle
// function invocations through 'new'.
class ConstructFrame : public InternalFrame {
 public:
  Type type() const override { return CONSTRUCT; }

  static ConstructFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_construct());
    return static_cast<ConstructFrame*>(frame);
  }

  void Iterate(RootVisitor* v) const override;

 protected:
  inline explicit ConstructFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

// Fast construct frames are special construct trampoline frames that avoid
// pushing arguments to the stack twice.
class FastConstructFrame : public InternalFrame {
 public:
  Type type() const override { return FAST_CONSTRUCT; }

  static FastConstructFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_fast_construct());
    return static_cast<FastConstructFrame*>(frame);
  }

 protected:
  inline explicit FastConstructFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class BuiltinContinuationFrame : public InternalFrame {
 public:
  Type type() const override { return BUILTIN_CONTINUATION; }

  static BuiltinContinuationFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_builtin_continuation());
    return static_cast<BuiltinContinuationFrame*>(frame);
  }

 protected:
  inline explicit BuiltinContinuationFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class JavaScriptBuiltinContinuationFrame : public TypedFrameWithJSLinkage {
 public:
  Type type() const override { return JAVASCRIPT_BUILTIN_CONTINUATION; }

  static JavaScriptBuiltinContinuationFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_javascript_builtin_continuation());
    return static_cast<JavaScriptBuiltinContinuationFrame*>(frame);
  }

  Tagged<JSFunction> function() const override;
  int ComputeParametersCount() const override;
  intptr_t GetSPToFPDelta() const;

  Tagged<Object> context() const override;

 protected:
  inline explicit JavaScriptBuiltinContinuationFrame(
      StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class JavaScriptBuiltinContinuationWithCatchFrame
    : public JavaScriptBuiltinContinuationFrame {
 public:
  Type type() const override {
    return JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH;
  }

  static JavaScriptBuiltinContinuationWithCatchFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_javascript_builtin_with_catch_continuation());
    return static_cast<JavaScriptBuiltinContinuationWithCatchFrame*>(frame);
  }

  // Patch in the exception object at the appropriate location into the stack
  // frame.
  void SetException(Tagged<Object> exception);

 protected:
  inline explicit JavaScriptBuiltinContinuationWithCatchFrame(
      StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class IrregexpFrame : public TypedFrame {
 public:
  Type type() const override { return IRREGEXP; }

  void Iterate(RootVisitor* v) const override {
    // Irregexp frames should not be visited by GC because they are not visible
    // to any stack iterator except StackFrameIteratorForProfiler, which is not
    // used by GC.
    UNREACHABLE();
  }

  static IrregexpFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_irregexp());
    return static_cast<IrregexpFrame*>(frame);
  }

 protected:
  inline explicit IrregexpFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class StackFrameIteratorBase {
 public:
  StackFrameIteratorBase(const StackFrameIteratorBase&) = delete;
  StackFrameIteratorBase& operator=(const StackFrameIteratorBase&) = delete;

  Isolate* isolate() const { return isolate_; }
#if V8_ENABLE_WEBASSEMBLY
  wasm::StackMemory* wasm_stack() const { return wasm_stack_; }
#endif

  bool done() const { return frame_ == nullptr; }

#ifdef DEBUG
  // The StackFrameIteratorForProfiler is limited in functionality because it
  // may run at an arbitrary point in time where stack contents are not
  // guaranteed to be in a consistent state and heap accesses may be limited.
  virtual bool IsStackFrameIteratorForProfiler() const = 0;
#endif  // DEBUG
  virtual StackFrame::Type ComputeStackFrameType(
      StackFrame::State* state) const = 0;

 protected:
  // An iterator that iterates over a given thread's stack.
  explicit StackFrameIteratorBase(Isolate* isolate);

  Isolate* const isolate_;
  union {
    char uninitialized_;
#define DECLARE_SINGLETON(ignore, type) type type##_;
  STACK_FRAME_TYPE_LIST(DECLARE_SINGLETON)
#undef DECLARE_SINGLETON
  };
  StackFrame* frame_;
  StackHandler* handler_;
#if V8_ENABLE_WEBASSEMBLY
  // Stop at the end of the topmost (wasm) stack.
  bool first_stack_only_ = false;
  // // Current wasm stack being iterated.
  wasm::StackMemory* wasm_stack_ = nullptr;
  // See {StackFrameIterator::NoHandles}.
  std::optional<DisallowGarbageCollection> no_gc_;
  union {
    Handle<WasmContinuationObject> handle_;
    Tagged<WasmContinuationObject> obj_;
  } continuation_{Handle<WasmContinuationObject>::null()};
#endif

  StackHandler* handler() const {
    DCHECK(!done());
    return handler_;
  }

  // Update the current frame to the given state.
  void SetNewFrame(StackFrame::Type type, StackFrame::State* state);
  // A helper function, can set the frame to nullptr.
  void SetNewFrame(StackFrame::Type type);

 private:
  friend class StackFrame;
};

class StackFrameIterator : public StackFrameIteratorBase {
 public:
  // An iterator that iterates over the isolate's current thread's stack,
  V8_EXPORT_PRIVATE explicit StackFrameIterator(Isolate* isolate);
  // An iterator that iterates over a given thread's stack.
  V8_EXPORT_PRIVATE StackFrameIterator(Isolate* isolate, ThreadLocalTop* t);
  // Use this constructor to use the stack frame iterator without a handle
  // scope. This sets the {no_gc_} scope, and if the {continuation_} object is
  // used, it is unhandlified.
  struct NoHandles {};
  V8_EXPORT_PRIVATE StackFrameIterator(Isolate* isolate, ThreadLocalTop* top,
                                       NoHandles);
#if V8_ENABLE_WEBASSEMBLY
  // Depending on the use case, users of the StackFrameIterator should either:
  // - Use the default constructor, which iterates the active stack and its
  // ancestors, but not the suspended stacks.
  // - Or use the constructor below to iterate the topmost stack only, and
  // iterate the {Isolate::wasm_stacks()} list on the side to visit all
  // inactive stacks.
  struct FirstStackOnly {};
  V8_EXPORT_PRIVATE StackFrameIterator(Isolate* isolate, ThreadLocalTop* t,
                                       FirstStackOnly);
  // An iterator that iterates over a given wasm stack segment.
  V8_EXPORT_PRIVATE StackFrameIterator(Isolate* isolate,
                                       wasm::StackMemory* stack);
#endif

  StackFrameIterator(const StackFrameIterator&) = delete;
  StackFrameIterator& operator=(const StackFrameIterator&) = delete;

  StackFrame* frame() const {
    DCHECK(!done());
    return frame_;
  }
  V8_EXPORT_PRIVATE void Advance();
  StackFrame* Reframe();

#if V8_ENABLE_WEBASSEMBLY
  // Go to the first frame of this stack.
  void Reset(ThreadLocalTop* top, wasm::StackMemory* stack);
  Tagged<WasmContinuationObject> continuation();
  void set_continuation(Tagged<WasmContinuationObject> continuation);
#endif

#ifdef DEBUG
  bool IsStackFrameIteratorForProfiler() const override { return false; }
#endif  // DEBUG
  StackFrame::Type ComputeStackFrameType(
      StackFrame::State* state) const override;

 private:
  // Go back to the first frame.
  void Reset(ThreadLocalTop* top);
};

// A wrapper around StackFrameIterator that skips over all non-JS frames.
class JavaScriptStackFrameIterator final {
 public:
  explicit JavaScriptStackFrameIterator(Isolate* isolate) : iterator_(isolate) {
    if (!done()) Advance();
  }
  JavaScriptStackFrameIterator(Isolate* isolate, ThreadLocalTop* top)
      : iterator_(isolate, top) {
    if (!done()) Advance();
  }

  JavaScriptFrame* frame() const {
    return JavaScriptFrame::cast(iterator_.frame());
  }
  JavaScriptFrame* Reframe() {
    return JavaScriptFrame::cast(iterator_.Reframe());
  }
  bool done() const { return iterator_.done(); }

  V8_EXPORT_PRIVATE void Advance();

 private:
  StackFrameIterator iterator_;
};

// A wrapper around StackFrameIterator that skips over all non-debuggable
// frames (i.e. it iterates over Wasm and debuggable JS frames).
class V8_EXPORT_PRIVATE DebuggableStackFrameIterator {
 public:
  explicit DebuggableStackFrameIterator(Isolate* isolate);
  // Skip frames until the frame with the given id is reached.
  DebuggableStackFrameIterator(Isolate* isolate, StackFrameId id);

  bool done() const { return iterator_.done(); }
  void Advance();
  void AdvanceOneFrame() { iterator_.Advance(); }
  int FrameFunctionCount() const;

  inline CommonFrame* frame() const;
  inline CommonFrame* Reframe();

  inline bool is_javascript() const;
#if V8_ENABLE_WEBASSEMBLY
  inline bool is_wasm() const;
#if V8_ENABLE_DRUMBRAKE
  inline bool is_wasm_interpreter_entry() const;
#endif  // V8_ENABLE_DRUMBRAKE
#endif  // V8_ENABLE_WEBASSEMBLY
  inline JavaScriptFrame* javascript_frame() const;

  // Use this instead of FrameSummary::GetTop(javascript_frame) to keep
  // filtering behavior consistent with the rest of
  // DebuggableStackFrameIterator.
  FrameSummary GetTopValidFrame() const;

 private:
  StackFrameIterator iterator_;
  static bool IsValidFrame(StackFrame* frame);
};

// Similar to StackFrameIterator, but can be created and used at any time and
// any stack state. Currently, the only user is the profiler; if this ever
// changes, find another name for this class.
// IMPORTANT: Do not mark this class as V8_EXPORT_PRIVATE. The profiler creates
// instances of this class from a signal handler. If we use V8_EXPORT_PRIVATE
// "ld" inserts a symbol stub for the constructor call that may crash with
// a stackoverflow when called from a signal handler.
class StackFrameIteratorForProfiler : public StackFrameIteratorBase {
 public:
  StackFrameIteratorForProfiler(Isolate* isolate, Address pc, Address fp,
                                Address sp, Address lr, Address js_entry_sp);

  inline StackFrame* frame() const;
  void Advance();

  StackFrame::Type top_frame_type() const { return top_frame_type_; }

#ifdef DEBUG
  bool IsStackFrameIteratorForProfiler() const override { return true; }
#endif  // DEBUG
  StackFrame::Type ComputeStackFrameType(
      StackFrame::State* state) const override;

 private:
  void AdvanceOneFrame();

  bool IsValidStackAddress(Address addr) const {
#if V8_ENABLE_WEBASSEMBLY
    for (const std::unique_ptr<wasm::StackMemory>& stack : wasm_stacks_) {
      if (stack->Contains(addr)) return true;
    }
#endif
    return low_bound_ <= addr && addr <= high_bound_;
  }
  bool IsValidState(const StackFrame::State& frame) const;
  bool HasValidExitIfEntryFrame(const StackFrame* frame) const;
  bool IsValidExitFrame(Address fp) const;
  bool IsValidTop(ThreadLocalTop* top) const;
  static bool IsValidFrameType(StackFrame::Type type);

  StackFrame::Type GetCallerIfValid(StackFrame* frame,
                                    StackFrame::State* state);

  // Returns true if the pc points to a bytecode handler and the frame pointer
  // doesn't seem to be a bytecode handler's frame, which implies that the
  // bytecode handler has an elided frame. This is not precise and might give
  // false negatives since it relies on checks to the frame's type marker,
  // which might be uninitialized.
  bool IsNoFrameBytecodeHandlerPc(Isolate* isolate, Address pc,
                                  Address fp) const;

  const Address low_bound_;
  const Address high_bound_;
  StackFrame::Type top_frame_type_;
  ExternalCallbackScope* external_callback_scope_;
  Address top_link_register_;
#if V8_ENABLE_WEBASSEMBLY
  std::vector<std::unique_ptr<wasm::StackMemory>>& wasm_stacks_;
#endif
};

// We cannot export 'StackFrameIteratorForProfiler' for cctests since the
// linker inserted symbol stub may cuase a stack overflow
// (https://crbug.com/1449195).
// We subclass it and export the subclass instead.
class V8_EXPORT_PRIVATE StackFrameIteratorForProfilerForTesting
    : public StackFrameIteratorForProfiler {
 public:
  StackFrameIteratorForProfilerForTesting(Isolate* isolate, Address pc,
                                          Address fp, Address sp, Address lr,
                                          Address js_entry_sp);
  // Re-declare methods needed by the test. Otherwise we'd have to
  // export individual methods on the base class (which we don't want to risk).
  void Advance();
};

// Frame layout helper classes. Used by the deoptimizer and instruction
// selector.
// -------------------------------------------------------------------------

// How to calculate the frame layout information. Precise, when all information
// is available during deoptimization. Conservative, when an overapproximation
// is fine.
// TODO(jgruber): Investigate whether the conservative kind can be removed. It
// seems possible: 1. is_topmost should be known through the outer_state chain
// of FrameStateDescriptor; 2. the deopt_kind may be a property of the bailout
// id; 3. for continuation_mode, we only care whether it is a mode with catch,
// and that is likewise known at compile-time.
// There is nothing specific blocking this, the investigation just requires time
// and it is not that important to get the exact frame height at compile-time.
enum class FrameInfoKind {
  kPrecise,
  kConservative,
};

// Used by the deoptimizer. Corresponds to frame kinds:
enum class BuiltinContinuationMode {
  STUB,                        // BuiltinContinuationFrame
  JAVASCRIPT,                  // JavaScriptBuiltinContinuationFrame
  JAVASCRIPT_WITH_CATCH,       // JavaScriptBuiltinContinuationWithCatchFrame
  JAVASCRIPT_HANDLE_EXCEPTION  // JavaScriptBuiltinContinuationWithCatchFrame
};

class UnoptimizedFrameInfo {
 public:
  static UnoptimizedFrameInfo Precise(int parameters_count_with_
"""


```