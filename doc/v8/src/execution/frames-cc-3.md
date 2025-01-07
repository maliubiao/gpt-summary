Response:
The user wants a summary of the C++ source code file `v8/src/execution/frames.cc`.

Here's a breakdown of how to arrive at the summary:

1. **Identify the Core Purpose:** The file name `frames.cc` and the content strongly suggest it deals with the concept of "frames" in the V8 JavaScript engine. Specifically, it seems to be about representing and manipulating call stack frames.

2. **Analyze Key Classes and Structures:**  The code defines several classes related to frames:
    * `JavaScriptFrame`: Represents a JavaScript function call on the stack.
    * `CommonFrameWithJSLinkage`: A base class for frames that have a relationship with JavaScript code.
    * `JavaScriptBuiltinContinuationFrame`, `JavaScriptBuiltinContinuationWithCatchFrame`: Represent frames for built-in JavaScript functions.
    * `OptimizedJSFrame`, `MaglevFrame`, `TurbofanJSFrame`: Represent frames for optimized JavaScript code.
    * `UnoptimizedJSFrame`: Represents frames for unoptimized (interpreted) JavaScript code.
    * `InterpretedFrame`:  Likely a more general representation of an interpreted frame (though only `GetBytecodeOffset` is shown in this excerpt).
    * `FrameSummary`: A class to summarize the information of a frame. This is crucial for stack traces and debugging.

3. **Identify Key Functionalities:**  Within these classes, observe the defined methods and their purposes:
    * **Accessors:** `function()`, `receiver()`, `context()`, `script()`, `GetParameter()`, `GetParameters()`. These retrieve information associated with a frame.
    * **Information Retrieval:** `ComputeParametersCount()`, `GetActualArgumentCount()`, `GetActiveCodeAndOffset()`, `LookupCode()`, `GetBytecodeArray()`, `GetBytecodeOffset()`. These methods provide details about the function being executed in the frame.
    * **Stack Walking/Traversal:** `JavaScriptStackFrameIterator` (mentioned in `PrintTop`). While not defined in this excerpt, it's a key concept for navigating the call stack.
    * **Debugging/Profiling:** `PrintFunctionAndOffset()`, `PrintTop()`, `CollectFunctionAndOffsetForICStats()`, `CreateStackFrameInfo()`. These methods are for generating human-readable representations of the call stack and collecting performance data.
    * **Exception Handling:** `LookupExceptionHandlerInTable()`. This method helps locate error handlers on the stack.
    * **Deoptimization:**  Methods in `OptimizedJSFrame` related to `DeoptimizationData`. This is a critical process in V8 where optimized code needs to revert to interpreted code.
    * **Frame Summarization:** `Summarize()` methods in various frame classes. These populate the `FrameSummary` object.

4. **Infer Relationships and Hierarchy:** Notice the inheritance and composition patterns. `JavaScriptFrame` inherits from `CommonFrameWithJSLinkage`. `FrameSummary` appears to be a container holding different types of frame summaries (JavaScript, WASM, Builtin).

5. **Address Specific User Queries:**
    * **".tq" extension:** The code is `.cc`, not `.tq`, so it's C++, not Torque.
    * **JavaScript Relation:**  The entire file is deeply intertwined with JavaScript execution. The examples will focus on how these frames represent JavaScript function calls.
    * **Code Logic and Input/Output:**  Focus on methods that perform specific transformations or lookups, like `LookupExceptionHandlerInTable`.
    * **Common Programming Errors:**  Think about scenarios where stack traces are important for debugging.

6. **Structure the Summary:** Organize the findings into logical sections: Core Functionality, Key Concepts, Relation to JavaScript, etc.

7. **Refine and Elaborate:**  Expand on the initial points with more details from the code. For example, explain the purpose of different frame types and the information they hold.

By following these steps, we can generate a comprehensive and accurate summary of the provided C++ source code.
好的，根据你提供的 `v8/src/execution/frames.cc` 代码片段，以下是它的功能归纳：

**核心功能：**

这个代码文件的核心功能是 **定义和操作 JavaScript 函数调用的栈帧 (Stack Frames)**。它提供了表示不同类型栈帧的类，以及访问和操作这些栈帧信息的方法。这些栈帧用于追踪 JavaScript 代码的执行流程，支持错误处理、调试、性能分析等关键功能。

**具体功能点：**

1. **定义了不同类型的栈帧类：**
   - `JavaScriptFrame`: 代表一个标准的 JavaScript 函数调用帧。
   - `CommonFrameWithJSLinkage`:  一个基类，表示与 JavaScript 链接的通用帧，例如包含接收者 (receiver) 信息。
   - `JavaScriptBuiltinContinuationFrame`: 代表内置 JavaScript 函数的延续帧（用于异步操作）。
   - `JavaScriptBuiltinContinuationWithCatchFrame`: 代表带有 `catch` 子句的内置 JavaScript 函数的延续帧。
   - `OptimizedJSFrame`:  代表经过优化的 JavaScript 函数调用帧 (例如 Turbofan 或 Maglev 编译的代码)。
   - `UnoptimizedJSFrame`: 代表未优化的 JavaScript 函数调用帧（解释执行）。
   - `InterpretedFrame`:  代表解释器执行的帧。
   - `FrameSummary`:  用于汇总和提取栈帧的关键信息，方便进行栈回溯和分析。
   - `WasmFrameSummary`, `WasmInlinedFrameSummary`, `WasmInterpretedFrameSummary`: 代表 WebAssembly 相关的栈帧。
   - `BuiltinFrameSummary`: 代表内置函数的栈帧。

2. **提供了访问栈帧信息的接口：**
   - 获取函数 (`function()`, `unchecked_function()`)
   - 获取接收者 (`receiver()`)
   - 获取上下文 (`context()`)
   - 获取脚本 (`script()`)
   - 获取参数 (`GetParameter()`, `GetParameters()`, `ComputeParametersCount()`, `GetActualArgumentCount()`)
   - 获取代码对象和偏移量 (`GetActiveCodeAndOffset()`, `LookupCode()`)
   - 获取字节码数组和偏移量 (`GetBytecodeArray()`, `GetBytecodeOffset()`)
   - 判断是否为构造函数调用 (`IsConstructor()`)

3. **支持栈帧的打印和调试：**
   - `PrintFunctionAndOffset()`: 打印函数名和代码偏移量。
   - `PrintTop()`: 打印栈顶的 JavaScript 帧信息。
   - `CollectFunctionAndOffsetForICStats()`: 收集内联缓存 (IC) 统计信息。

4. **支持异常处理：**
   - `LookupExceptionHandlerInTable()`: 在帧的处理器表中查找异常处理器。

5. **支持优化的栈帧处理：**
   - `OptimizedJSFrame` 及其子类处理经过优化的代码的栈帧，包括 deoptimization（反优化）相关的信息和操作。
   - `GetDeoptimizationData()`: 获取反优化数据。
   - `GetFunctions()`: 获取优化帧中包含的函数信息。

6. **提供了帧信息汇总的功能：**
   - `FrameSummary` 类用于封装不同类型帧的通用信息，方便统一处理。
   - `Summarize()` 方法用于将栈帧信息汇总到 `FrameSummary` 对象中。
   - `CreateStackFrameInfo()`: 创建用于生成栈跟踪信息的对象。

**关于代码的特性：**

* **不是 Torque 源代码：**  `v8/src/execution/frames.cc` 以 `.cc` 结尾，因此是 C++ 源代码，而不是 Torque 源代码（Torque 源代码以 `.tq` 结尾）。
* **与 JavaScript 功能密切相关：**  这个文件是 V8 引擎执行 JavaScript 代码的核心部分，直接负责管理函数调用栈，因此与 JavaScript 的运行机制息息相关。

**JavaScript 举例说明：**

以下 JavaScript 代码的执行会涉及到 `v8/src/execution/frames.cc` 中的栈帧管理：

```javascript
function foo(a, b) {
  console.log(a + b);
  bar();
}

function bar() {
  throw new Error("Something went wrong!");
}

foo(1, 2);
```

当执行 `foo(1, 2)` 时，会创建一个 `JavaScriptFrame` 来记录这次函数调用。当 `bar()` 被调用时，会创建另一个 `JavaScriptFrame`。当 `bar()` 抛出错误时，V8 会遍历栈帧，查找合适的 `catch` 块（如果有）。`FrameSummary` 可以被用来生成错误堆栈信息，帮助开发者定位错误发生的位置。

**代码逻辑推理 (假设输入与输出)：**

假设我们有一个 `JavaScriptFrame` 对象 `frame`，它代表执行以下函数时的栈帧：

```javascript
function add(x, y) {
  return x + y;
}
```

**假设输入：**

* `frame` 是一个指向 `add` 函数调用栈帧的 `JavaScriptFrame` 实例。
* `add` 函数被调用时传入参数 `x = 5` 和 `y = 10`。

**可能的输出：**

* `frame->function()->name()` 可能返回 "add"。
* `frame->receiver()` 可能返回 `globalThis`（取决于调用方式）。
* `frame->ComputeParametersCount()` 可能返回 2。
* `frame->GetParameter(0)` 可能返回表示值 5 的 V8 对象。
* `frame->GetParameter(1)` 可能返回表示值 10 的 V8 对象。
* `frame->script()->name()` 可能返回包含 `add` 函数定义的脚本文件名。
* `frame->GetActiveCodeAndOffset()` 可能返回 `add` 函数对应的代码对象和当前的执行偏移量。

**用户常见的编程错误举例：**

1. **堆栈溢出 (Stack Overflow)：**  当函数递归调用过深时，会导致创建过多的栈帧，最终超出栈的容量限制。`frames.cc` 中的代码负责创建和管理这些栈帧，当栈溢出时，V8 会抛出错误。

   ```javascript
   function recursiveFunction() {
     recursiveFunction();
   }
   recursiveFunction(); // 可能导致 Stack Overflow
   ```

2. **未捕获的异常：** 当 JavaScript 代码抛出异常，并且没有 `try...catch` 块来处理它时，V8 会遍历栈帧来生成错误堆栈信息。`FrameSummary` 和相关方法在此过程中发挥作用。

   ```javascript
   function throwError() {
     throw new Error("An unhandled error!");
   }
   throwError(); // 导致未捕获的异常
   ```

**第 4 部分功能归纳：**

你提供的代码是 `v8/src/execution/frames.cc` 的一部分，它主要关注以下功能：

* **定义 `JavaScriptFrame` 类及其相关方法：**  用于表示和访问标准 JavaScript 函数调用帧的信息，例如函数、接收者、上下文、脚本、参数等。
* **定义 `CommonFrameWithJSLinkage` 类：** 作为与 JavaScript 链接的通用帧的基类，并提供访问接收者的方法。
* **实现基本的栈帧信息访问：**  例如获取函数、接收者、上下文等。
* **初步涉及栈帧的打印和调试功能：**  例如 `PrintFunctionAndOffset` 和 `PrintTop`，用于展示栈帧信息。
* **实现简单的异常处理查找功能：** `LookupExceptionHandlerInTable` 在非优化代码中查找异常处理器。

总的来说，这部分代码是构建 V8 引擎栈帧管理机制的基础，提供了表示和操作 JavaScript 函数调用栈的核心数据结构和方法。

Prompt: 
```
这是目录为v8/src/execution/frames.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/frames.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
mary summary(
      isolate(), receiver(), function(), *abstract_code, offset,
      IsConstructor(), *params);
  functions->push_back(summary);
}

Tagged<JSFunction> JavaScriptFrame::function() const {
  return Cast<JSFunction>(function_slot_object());
}

Tagged<Object> JavaScriptFrame::unchecked_function() const {
  // During deoptimization of an optimized function, we may have yet to
  // materialize some closures on the stack. The arguments marker object
  // marks this case.
  DCHECK(IsJSFunction(function_slot_object()) ||
         ReadOnlyRoots(isolate()).arguments_marker() == function_slot_object());
  return function_slot_object();
}

Tagged<Object> CommonFrameWithJSLinkage::receiver() const {
  // TODO(cbruni): document this better
  return GetParameter(-1);
}

Tagged<Object> JavaScriptFrame::context() const {
  const int offset = StandardFrameConstants::kContextOffset;
  Tagged<Object> maybe_result(Memory<Address>(fp() + offset));
  DCHECK(!IsSmi(maybe_result));
  return maybe_result;
}

Tagged<Script> JavaScriptFrame::script() const {
  return Cast<Script>(function()->shared()->script());
}

int CommonFrameWithJSLinkage::LookupExceptionHandlerInTable(
    int* stack_depth, HandlerTable::CatchPrediction* prediction) {
  if (DEBUG_BOOL) {
    Tagged<Code> code_lookup_result = LookupCode();
    CHECK(!code_lookup_result->has_handler_table());
    CHECK(!code_lookup_result->is_optimized_code() ||
          code_lookup_result->kind() == CodeKind::BASELINE);
  }
  return -1;
}

void JavaScriptFrame::PrintFunctionAndOffset(Isolate* isolate,
                                             Tagged<JSFunction> function,
                                             Tagged<AbstractCode> code,
                                             int code_offset, FILE* file,
                                             bool print_line_number) {
  PtrComprCageBase cage_base = GetPtrComprCageBase(function);
  PrintF(file, "%s", CodeKindToMarker(code->kind(cage_base)));
  function->PrintName(file);
  PrintF(file, "+%d", code_offset);
  if (print_line_number) {
    Tagged<SharedFunctionInfo> shared = function->shared();
    int source_pos = code->SourcePosition(isolate, code_offset);
    Tagged<Object> maybe_script = shared->script();
    if (IsScript(maybe_script)) {
      Tagged<Script> script = Cast<Script>(maybe_script);
      int line = script->GetLineNumber(source_pos) + 1;
      Tagged<Object> script_name_raw = script->name();
      if (IsString(script_name_raw)) {
        Tagged<String> script_name = Cast<String>(script->name());
        std::unique_ptr<char[]> c_script_name = script_name->ToCString();
        PrintF(file, " at %s:%d", c_script_name.get(), line);
      } else {
        PrintF(file, " at <unknown>:%d", line);
      }
    } else {
      PrintF(file, " at <unknown>:<unknown>");
    }
  }
}

void JavaScriptFrame::PrintTop(Isolate* isolate, FILE* file, bool print_args,
                               bool print_line_number) {
  // constructor calls
  DisallowGarbageCollection no_gc;
  JavaScriptStackFrameIterator it(isolate);
  while (!it.done()) {
    if (it.frame()->is_javascript()) {
      JavaScriptFrame* frame = it.frame();
      if (frame->IsConstructor()) PrintF(file, "new ");
      Tagged<JSFunction> function = frame->function();
      int code_offset = 0;
      Tagged<AbstractCode> code;
      std::tie(code, code_offset) = frame->GetActiveCodeAndOffset();
      PrintFunctionAndOffset(isolate, function, code, code_offset, file,
                             print_line_number);
      if (print_args) {
        // function arguments
        // (we are intentionally only printing the actually
        // supplied parameters, not all parameters required)
        PrintF(file, "(this=");
        ShortPrint(frame->receiver(), file);
        const int length = frame->ComputeParametersCount();
        for (int i = 0; i < length; i++) {
          PrintF(file, ", ");
          ShortPrint(frame->GetParameter(i), file);
        }
        PrintF(file, ")");
      }
      break;
    }
    it.Advance();
  }
}

// static
void JavaScriptFrame::CollectFunctionAndOffsetForICStats(
    Isolate* isolate, Tagged<JSFunction> function, Tagged<AbstractCode> code,
    int code_offset) {
  auto ic_stats = ICStats::instance();
  ICInfo& ic_info = ic_stats->Current();
  PtrComprCageBase cage_base = GetPtrComprCageBase(function);
  Tagged<SharedFunctionInfo> shared = function->shared(cage_base);

  ic_info.function_name = ic_stats->GetOrCacheFunctionName(isolate, function);
  ic_info.script_offset = code_offset;

  int source_pos = code->SourcePosition(isolate, code_offset);
  Tagged<Object> maybe_script = shared->script(cage_base, kAcquireLoad);
  if (IsScript(maybe_script, cage_base)) {
    Tagged<Script> script = Cast<Script>(maybe_script);
    Script::PositionInfo info;
    script->GetPositionInfo(source_pos, &info);
    ic_info.line_num = info.line + 1;
    ic_info.column_num = info.column + 1;
    ic_info.script_name = ic_stats->GetOrCacheScriptName(script);
  }
}

Tagged<Object> CommonFrameWithJSLinkage::GetParameter(int index) const {
  return Tagged<Object>(Memory<Address>(GetParameterSlot(index)));
}

int CommonFrameWithJSLinkage::ComputeParametersCount() const {
  DCHECK(!iterator_->IsStackFrameIteratorForProfiler() &&
         isolate()->heap()->gc_state() == Heap::NOT_IN_GC);
  return function()
      ->shared()
      ->internal_formal_parameter_count_without_receiver();
}

int JavaScriptFrame::GetActualArgumentCount() const {
  return static_cast<int>(
             Memory<intptr_t>(fp() + StandardFrameConstants::kArgCOffset)) -
         kJSArgcReceiverSlots;
}

Handle<FixedArray> CommonFrameWithJSLinkage::GetParameters() const {
  if (V8_LIKELY(!v8_flags.detailed_error_stack_trace)) {
    return isolate()->factory()->empty_fixed_array();
  }
  int param_count = ComputeParametersCount();
  Handle<FixedArray> parameters =
      isolate()->factory()->NewFixedArray(param_count);
  for (int i = 0; i < param_count; i++) {
    parameters->set(i, GetParameter(i));
  }

  return parameters;
}

Tagged<JSFunction> JavaScriptBuiltinContinuationFrame::function() const {
  const int offset = BuiltinContinuationFrameConstants::kFunctionOffset;
  return Cast<JSFunction>(Tagged<Object>(base::Memory<Address>(fp() + offset)));
}

int JavaScriptBuiltinContinuationFrame::ComputeParametersCount() const {
  // Assert that the first allocatable register is also the argument count
  // register.
  DCHECK_EQ(RegisterConfiguration::Default()->GetAllocatableGeneralCode(0),
            kJavaScriptCallArgCountRegister.code());
  Tagged<Object> argc_object(
      Memory<Address>(fp() + BuiltinContinuationFrameConstants::kArgCOffset));
  return Smi::ToInt(argc_object) - kJSArgcReceiverSlots;
}

intptr_t JavaScriptBuiltinContinuationFrame::GetSPToFPDelta() const {
  Address height_slot =
      fp() + BuiltinContinuationFrameConstants::kFrameSPtoFPDeltaAtDeoptimize;
  intptr_t height = Smi::ToInt(Tagged<Smi>(Memory<Address>(height_slot)));
  return height;
}

Tagged<Object> JavaScriptBuiltinContinuationFrame::context() const {
  return Tagged<Object>(Memory<Address>(
      fp() + BuiltinContinuationFrameConstants::kBuiltinContextOffset));
}

void JavaScriptBuiltinContinuationWithCatchFrame::SetException(
    Tagged<Object> exception) {
  int argc = ComputeParametersCount();
  Address exception_argument_slot =
      fp() + BuiltinContinuationFrameConstants::kFixedFrameSizeAboveFp +
      (argc - 1) * kSystemPointerSize;

  // Only allow setting exception if previous value was the hole.
  CHECK_EQ(ReadOnlyRoots(isolate()).the_hole_value(),
           Tagged<Object>(Memory<Address>(exception_argument_slot)));
  Memory<Address>(exception_argument_slot) = exception.ptr();
}

FrameSummary::JavaScriptFrameSummary::JavaScriptFrameSummary(
    Isolate* isolate, Tagged<Object> receiver, Tagged<JSFunction> function,
    Tagged<AbstractCode> abstract_code, int code_offset, bool is_constructor,
    Tagged<FixedArray> parameters)
    : FrameSummaryBase(isolate, FrameSummary::JAVASCRIPT),
      receiver_(receiver, isolate),
      function_(function, isolate),
      abstract_code_(abstract_code, isolate),
      code_offset_(code_offset),
      is_constructor_(is_constructor),
      parameters_(parameters, isolate) {
  DCHECK_IMPLIES(CodeKindIsOptimizedJSFunction(abstract_code->kind(isolate)),
                 // It might be an ApiCallbackBuiltin inlined into optimized
                 // code generated by Maglev.
                 (v8_flags.maglev_inline_api_calls &&
                  abstract_code->kind(isolate) == CodeKind::MAGLEV &&
                  function->shared()->IsApiFunction()));
}

void FrameSummary::EnsureSourcePositionsAvailable() {
  if (IsJavaScript()) {
    javascript_summary_.EnsureSourcePositionsAvailable();
  }
}

bool FrameSummary::AreSourcePositionsAvailable() const {
  if (IsJavaScript()) {
    return javascript_summary_.AreSourcePositionsAvailable();
  }
  return true;
}

void FrameSummary::JavaScriptFrameSummary::EnsureSourcePositionsAvailable() {
  Handle<SharedFunctionInfo> shared(function()->shared(), isolate());
  SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate(), shared);
}

bool FrameSummary::JavaScriptFrameSummary::AreSourcePositionsAvailable() const {
  return !v8_flags.enable_lazy_source_positions ||
         function()
             ->shared()
             ->GetBytecodeArray(isolate())
             ->HasSourcePositionTable();
}

bool FrameSummary::JavaScriptFrameSummary::is_subject_to_debugging() const {
  return function()->shared()->IsSubjectToDebugging();
}

int FrameSummary::JavaScriptFrameSummary::SourcePosition() const {
  return abstract_code()->SourcePosition(isolate(), code_offset());
}

int FrameSummary::JavaScriptFrameSummary::SourceStatementPosition() const {
  return abstract_code()->SourceStatementPosition(isolate(), code_offset());
}

Handle<Object> FrameSummary::JavaScriptFrameSummary::script() const {
  return handle(function_->shared()->script(), isolate());
}

Handle<Context> FrameSummary::JavaScriptFrameSummary::native_context() const {
  return handle(function_->native_context(), isolate());
}

Handle<StackFrameInfo>
FrameSummary::JavaScriptFrameSummary::CreateStackFrameInfo() const {
  Handle<SharedFunctionInfo> shared(function_->shared(), isolate());
  DirectHandle<Script> script(Cast<Script>(shared->script()), isolate());
  DirectHandle<String> function_name = JSFunction::GetDebugName(function_);
  if (function_name->length() == 0 &&
      script->compilation_type() == Script::CompilationType::kEval) {
    function_name = isolate()->factory()->eval_string();
  }
  int bytecode_offset = code_offset();
  if (bytecode_offset == kFunctionEntryBytecodeOffset) {
    // For the special function entry bytecode offset (-1), which signals
    // that the stack trace was captured while the function entry was
    // executing (i.e. during the interrupt check), we cannot store this
    // sentinel in the bit field, so we just eagerly lookup the source
    // position within the script.
    SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate(), shared);
    int source_position =
        abstract_code()->SourcePosition(isolate(), bytecode_offset);
    return isolate()->factory()->NewStackFrameInfo(
        script, source_position, function_name, is_constructor());
  }
  return isolate()->factory()->NewStackFrameInfo(
      shared, bytecode_offset, function_name, is_constructor());
}

#if V8_ENABLE_WEBASSEMBLY
FrameSummary::WasmFrameSummary::WasmFrameSummary(
    Isolate* isolate, Handle<WasmTrustedInstanceData> instance_data,
    wasm::WasmCode* code, int byte_offset, int function_index,
    bool at_to_number_conversion)
    : FrameSummaryBase(isolate, WASM),
      instance_data_(instance_data),
      at_to_number_conversion_(at_to_number_conversion),
      code_(code),
      byte_offset_(byte_offset),
      function_index_(function_index) {}

Handle<Object> FrameSummary::WasmFrameSummary::receiver() const {
  return isolate()->global_proxy();
}

uint32_t FrameSummary::WasmFrameSummary::function_index() const {
  return function_index_;
}

int FrameSummary::WasmFrameSummary::SourcePosition() const {
  const wasm::WasmModule* module = wasm_trusted_instance_data()->module();
  return GetSourcePosition(module, function_index(), code_offset(),
                           at_to_number_conversion());
}

Handle<Script> FrameSummary::WasmFrameSummary::script() const {
  return handle(wasm_instance()->module_object()->script(), isolate());
}

Handle<WasmInstanceObject> FrameSummary::WasmFrameSummary::wasm_instance()
    const {
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(instance_data_->has_instance_object());
  return handle(instance_data_->instance_object(), isolate());
}

Handle<Context> FrameSummary::WasmFrameSummary::native_context() const {
  return handle(wasm_trusted_instance_data()->native_context(), isolate());
}

Handle<StackFrameInfo> FrameSummary::WasmFrameSummary::CreateStackFrameInfo()
    const {
  DirectHandle<String> function_name =
      GetWasmFunctionDebugName(isolate(), instance_data_, function_index());
  return isolate()->factory()->NewStackFrameInfo(script(), SourcePosition(),
                                                 function_name, false);
}

FrameSummary::WasmInlinedFrameSummary::WasmInlinedFrameSummary(
    Isolate* isolate, Handle<WasmTrustedInstanceData> instance_data,
    int function_index, int op_wire_bytes_offset)
    : FrameSummaryBase(isolate, WASM_INLINED),
      instance_data_(instance_data),
      function_index_(function_index),
      op_wire_bytes_offset_(op_wire_bytes_offset) {}

Handle<WasmInstanceObject>
FrameSummary::WasmInlinedFrameSummary::wasm_instance() const {
  // TODO(42204563): Avoid crashing if the instance object is not available.
  CHECK(instance_data_->has_instance_object());
  return handle(instance_data_->instance_object(), isolate());
}

Handle<Object> FrameSummary::WasmInlinedFrameSummary::receiver() const {
  return isolate()->global_proxy();
}

uint32_t FrameSummary::WasmInlinedFrameSummary::function_index() const {
  return function_index_;
}

int FrameSummary::WasmInlinedFrameSummary::SourcePosition() const {
  const wasm::WasmModule* module = instance_data_->module();
  return GetSourcePosition(module, function_index(), code_offset(), false);
}

Handle<Script> FrameSummary::WasmInlinedFrameSummary::script() const {
  return handle(wasm_instance()->module_object()->script(), isolate());
}

Handle<Context> FrameSummary::WasmInlinedFrameSummary::native_context() const {
  return handle(wasm_trusted_instance_data()->native_context(), isolate());
}

Handle<StackFrameInfo>
FrameSummary::WasmInlinedFrameSummary::CreateStackFrameInfo() const {
  DirectHandle<String> function_name =
      GetWasmFunctionDebugName(isolate(), instance_data_, function_index());
  return isolate()->factory()->NewStackFrameInfo(script(), SourcePosition(),
                                                 function_name, false);
}

#if V8_ENABLE_DRUMBRAKE
FrameSummary::WasmInterpretedFrameSummary::WasmInterpretedFrameSummary(
    Isolate* isolate, Handle<WasmInstanceObject> instance,
    uint32_t function_index, int byte_offset)
    : FrameSummaryBase(isolate, WASM_INTERPRETED),
      wasm_instance_(instance),
      function_index_(function_index),
      byte_offset_(byte_offset) {}

Handle<Object> FrameSummary::WasmInterpretedFrameSummary::receiver() const {
  return wasm_instance_->GetIsolate()->global_proxy();
}

int FrameSummary::WasmInterpretedFrameSummary::SourcePosition() const {
  const wasm::WasmModule* module = wasm_instance()->module_object()->module();
  return GetSourcePosition(module, function_index(), byte_offset(),
                           false /*at_to_number_conversion*/);
}

Handle<WasmTrustedInstanceData>
FrameSummary::WasmInterpretedFrameSummary::instance_data() const {
  return handle(wasm_instance_->trusted_data(isolate()), isolate());
}

Handle<Script> FrameSummary::WasmInterpretedFrameSummary::script() const {
  return handle(wasm_instance()->module_object()->script(),
                wasm_instance()->GetIsolate());
}

Handle<Context> FrameSummary::WasmInterpretedFrameSummary::native_context()
    const {
  return handle(wasm_instance_->trusted_data(isolate())->native_context(),
                isolate());
}

Handle<StackFrameInfo>
FrameSummary::WasmInterpretedFrameSummary::CreateStackFrameInfo() const {
  Handle<String> function_name =
      GetWasmFunctionDebugName(isolate(), instance_data(), function_index());
  return isolate()->factory()->NewStackFrameInfo(script(), SourcePosition(),
                                                 function_name, false);
}
#endif  // V8_ENABLE_DRUMBRAKE

FrameSummary::BuiltinFrameSummary::BuiltinFrameSummary(Isolate* isolate,
                                                       Builtin builtin)
    : FrameSummaryBase(isolate, FrameSummary::BUILTIN), builtin_(builtin) {}

Handle<Object> FrameSummary::BuiltinFrameSummary::receiver() const {
  return isolate()->factory()->undefined_value();
}

Handle<Object> FrameSummary::BuiltinFrameSummary::script() const {
  return isolate()->factory()->undefined_value();
}

Handle<Context> FrameSummary::BuiltinFrameSummary::native_context() const {
  return isolate()->native_context();
}

Handle<StackFrameInfo> FrameSummary::BuiltinFrameSummary::CreateStackFrameInfo()
    const {
  DirectHandle<String> name_str =
      isolate()->factory()->NewStringFromAsciiChecked(
          Builtins::NameForStackTrace(isolate(), builtin_));
  return isolate()->factory()->NewStackFrameInfo(
      Cast<Script>(script()), SourcePosition(), name_str, false);
}

#endif  // V8_ENABLE_WEBASSEMBLY

FrameSummary::~FrameSummary() {
#define FRAME_SUMMARY_DESTR(kind, type, field, desc) \
  case kind:                                         \
    field.~type();                                   \
    break;
  switch (base_.kind()) {
    FRAME_SUMMARY_VARIANTS(FRAME_SUMMARY_DESTR)
    default:
      UNREACHABLE();
  }
#undef FRAME_SUMMARY_DESTR
}

FrameSummary FrameSummary::GetTop(const CommonFrame* frame) {
  std::vector<FrameSummary> frames;
  frame->Summarize(&frames);
  DCHECK_LT(0, frames.size());
  return frames.back();
}

FrameSummary FrameSummary::GetBottom(const CommonFrame* frame) {
  return Get(frame, 0);
}

FrameSummary FrameSummary::GetSingle(const CommonFrame* frame) {
  std::vector<FrameSummary> frames;
  frame->Summarize(&frames);
  DCHECK_EQ(1, frames.size());
  return frames.front();
}

FrameSummary FrameSummary::Get(const CommonFrame* frame, int index) {
  DCHECK_LE(0, index);
  std::vector<FrameSummary> frames;
  frame->Summarize(&frames);
  DCHECK_GT(frames.size(), index);
  return frames[index];
}

#if V8_ENABLE_WEBASSEMBLY
#ifdef V8_ENABLE_DRUMBRAKE
#define CASE_WASM_INTERPRETED(name) \
  case WASM_INTERPRETED:            \
    return wasm_interpreted_summary_.name();
#else  // V8_ENABLE_DRUMBRAKE
#define CASE_WASM_INTERPRETED(name)
#endif  // V8_ENABLE_DRUMBRAKE
#define FRAME_SUMMARY_DISPATCH(ret, name)    \
  ret FrameSummary::name() const {           \
    switch (base_.kind()) {                  \
      case JAVASCRIPT:                       \
        return javascript_summary_.name();   \
      case WASM:                             \
        return wasm_summary_.name();         \
      case WASM_INLINED:                     \
        return wasm_inlined_summary_.name(); \
      case BUILTIN:                          \
        return builtin_summary_.name();      \
        CASE_WASM_INTERPRETED(name)          \
      default:                               \
        UNREACHABLE();                       \
    }                                        \
  }
#else
#define FRAME_SUMMARY_DISPATCH(ret, name) \
  ret FrameSummary::name() const {        \
    DCHECK_EQ(JAVASCRIPT, base_.kind());  \
    return javascript_summary_.name();    \
  }
#endif  // V8_ENABLE_WEBASSEMBLY

FRAME_SUMMARY_DISPATCH(Handle<Object>, receiver)
FRAME_SUMMARY_DISPATCH(int, code_offset)
FRAME_SUMMARY_DISPATCH(bool, is_constructor)
FRAME_SUMMARY_DISPATCH(bool, is_subject_to_debugging)
FRAME_SUMMARY_DISPATCH(Handle<Object>, script)
FRAME_SUMMARY_DISPATCH(int, SourcePosition)
FRAME_SUMMARY_DISPATCH(int, SourceStatementPosition)
FRAME_SUMMARY_DISPATCH(Handle<Context>, native_context)
FRAME_SUMMARY_DISPATCH(Handle<StackFrameInfo>, CreateStackFrameInfo)

#undef CASE_WASM_INTERPRETED
#undef FRAME_SUMMARY_DISPATCH

void OptimizedJSFrame::Summarize(std::vector<FrameSummary>* frames) const {
  DCHECK(frames->empty());
  DCHECK(is_optimized());

  // Delegate to JS frame in absence of deoptimization info.
  // TODO(turbofan): Revisit once we support deoptimization across the board.
  DirectHandle<Code> code(LookupCode(), isolate());
  if (code->kind() == CodeKind::BUILTIN) {
    return JavaScriptFrame::Summarize(frames);
  }

  int deopt_index = SafepointEntry::kNoDeoptIndex;
  Tagged<DeoptimizationData> const data =
      GetDeoptimizationData(*code, &deopt_index);
  if (deopt_index == SafepointEntry::kNoDeoptIndex) {
    // Hack: For maglevved function entry, we don't emit lazy deopt information,
    // so create an extra special summary here.
    //
    // TODO(leszeks): Remove this hack, by having a maglev-specific frame
    // summary which is a bit more aware of maglev behaviour and can e.g. handle
    // more compact safepointed frame information for both function entry and
    // loop stack checks.
    if (code->is_maglevved()) {
      DCHECK(frames->empty());
      DirectHandle<AbstractCode> abstract_code(
          Cast<AbstractCode>(function()->shared()->GetBytecodeArray(isolate())),
          isolate());
      DirectHandle<FixedArray> params = GetParameters();
      FrameSummary::JavaScriptFrameSummary summary(
          isolate(), receiver(), function(), *abstract_code,
          kFunctionEntryBytecodeOffset, IsConstructor(), *params);
      frames->push_back(summary);
      return;
    }

    CHECK(data.is_null());
    FATAL(
        "Missing deoptimization information for OptimizedJSFrame::Summarize.");
  }

  // Prepare iteration over translation. We must not materialize values here
  // because we do not deoptimize the function.
  TranslatedState translated(this);
  translated.Prepare(fp());

  // We create the summary in reverse order because the frames
  // in the deoptimization translation are ordered bottom-to-top.
  bool is_constructor = IsConstructor();
  for (auto it = translated.begin(); it != translated.end(); it++) {
    if (it->kind() == TranslatedFrame::kUnoptimizedFunction ||
        it->kind() == TranslatedFrame::kJavaScriptBuiltinContinuation ||
        it->kind() ==
            TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch) {
      DirectHandle<SharedFunctionInfo> shared_info = it->shared_info();

      // The translation commands are ordered and the function is always
      // at the first position, and the receiver is next.
      TranslatedFrame::iterator translated_values = it->begin();

      // Get the correct function in the optimized frame.
      CHECK(!translated_values->IsMaterializedObject());
      DirectHandle<JSFunction> function =
          Cast<JSFunction>(translated_values->GetValue());
      translated_values++;

      // Get the correct receiver in the optimized frame.
      CHECK(!translated_values->IsMaterializedObject());
      DirectHandle<Object> receiver = translated_values->GetValue();
      translated_values++;

      // Determine the underlying code object and the position within it from
      // the translation corresponding to the frame type in question.
      DirectHandle<AbstractCode> abstract_code;
      unsigned code_offset;
      if (it->kind() == TranslatedFrame::kJavaScriptBuiltinContinuation ||
          it->kind() ==
              TranslatedFrame::kJavaScriptBuiltinContinuationWithCatch) {
        code_offset = 0;
        abstract_code = Cast<AbstractCode>(isolate()->builtins()->code_handle(
            Builtins::GetBuiltinFromBytecodeOffset(it->bytecode_offset())));
      } else {
        DCHECK_EQ(it->kind(), TranslatedFrame::kUnoptimizedFunction);
        code_offset = it->bytecode_offset().ToInt();
        abstract_code =
            direct_handle(shared_info->abstract_code(isolate()), isolate());
      }

      // Append full summary of the encountered JS frame.
      DirectHandle<FixedArray> params = GetParameters();
      FrameSummary::JavaScriptFrameSummary summary(
          isolate(), *receiver, *function, *abstract_code, code_offset,
          is_constructor, *params);
      frames->push_back(summary);
      is_constructor = false;
    } else if (it->kind() == TranslatedFrame::kConstructCreateStub ||
               it->kind() == TranslatedFrame::kConstructInvokeStub) {
      // The next encountered JS frame will be marked as a constructor call.
      DCHECK(!is_constructor);
      is_constructor = true;
#if V8_ENABLE_WEBASSEMBLY
    } else if (it->kind() == TranslatedFrame::kWasmInlinedIntoJS) {
      DirectHandle<SharedFunctionInfo> shared_info = it->shared_info();
      DCHECK_NE(isolate()->heap()->gc_state(), Heap::MARK_COMPACT);

      Tagged<WasmExportedFunctionData> function_data =
          shared_info->wasm_exported_function_data();
      Handle<WasmTrustedInstanceData> instance{function_data->instance_data(),
                                               isolate()};
      int func_index = function_data->function_index();
      FrameSummary::WasmInlinedFrameSummary summary(
          isolate(), instance, func_index, it->bytecode_offset().ToInt());
      frames->push_back(summary);
#endif  // V8_ENABLE_WEBASSEMBLY
    }
  }
}

int OptimizedJSFrame::LookupExceptionHandlerInTable(
    int* data, HandlerTable::CatchPrediction* prediction) {
  // We cannot perform exception prediction on optimized code. Instead, we need
  // to use FrameSummary to find the corresponding code offset in unoptimized
  // code to perform prediction there.
  DCHECK_NULL(prediction);
  Tagged<Code> code;
  int pc_offset = -1;
  std::tie(code, pc_offset) = LookupCodeAndOffset();

  HandlerTable table(code);
  if (table.NumberOfReturnEntries() == 0) return -1;

  DCHECK_NULL(data);  // Data is not used and will not return a value.

  // When the return pc has been replaced by a trampoline there won't be
  // a handler for this trampoline. Thus we need to use the return pc that
  // _used to be_ on the stack to get the right ExceptionHandler.
  if (CodeKindCanDeoptimize(code->kind())) {
    if (!code->marked_for_deoptimization()) {
      // Lazy deoptimize the function in case the handler table entry flags that
      // it wants to be lazily deoptimized on throw. This allows the optimizing
      // compiler to omit catch blocks that were never reached in practice.
      int optimized_exception_handler = table.LookupReturn(pc_offset);
      if (optimized_exception_handler != HandlerTable::kLazyDeopt) {
        return optimized_exception_handler;
      }
      Deoptimizer::DeoptimizeFunction(function(), code);
    }
    DCHECK(code->marked_for_deoptimization());
    pc_offset = FindReturnPCForTrampoline(code, pc_offset);
  }
  return table.LookupReturn(pc_offset);
}

int MaglevFrame::FindReturnPCForTrampoline(Tagged<Code> code,
                                           int trampoline_pc) const {
  DCHECK_EQ(code->kind(), CodeKind::MAGLEV);
  DCHECK(code->marked_for_deoptimization());
  MaglevSafepointTable safepoints(isolate(), pc(), code);
  return safepoints.find_return_pc(trampoline_pc);
}

int TurbofanJSFrame::FindReturnPCForTrampoline(Tagged<Code> code,
                                               int trampoline_pc) const {
  DCHECK_EQ(code->kind(), CodeKind::TURBOFAN_JS);
  DCHECK(code->marked_for_deoptimization());
  SafepointTable safepoints(isolate(), pc(), code);
  return safepoints.find_return_pc(trampoline_pc);
}

Tagged<DeoptimizationData> OptimizedJSFrame::GetDeoptimizationData(
    Tagged<Code> code, int* deopt_index) const {
  DCHECK(is_optimized());

  Address pc = maybe_unauthenticated_pc();

  DCHECK(code->contains(isolate(), pc));
  DCHECK(CodeKindCanDeoptimize(code->kind()));

  if (code->is_maglevved()) {
    MaglevSafepointEntry safepoint_entry =
        code->GetMaglevSafepointEntry(isolate(), pc);
    if (safepoint_entry.has_deoptimization_index()) {
      *deopt_index = safepoint_entry.deoptimization_index();
      return Cast<DeoptimizationData>(code->deoptimization_data());
    }
  } else {
    SafepointEntry safepoint_entry = code->GetSafepointEntry(isolate(), pc);
    if (safepoint_entry.has_deoptimization_index()) {
      *deopt_index = safepoint_entry.deoptimization_index();
      return Cast<DeoptimizationData>(code->deoptimization_data());
    }
  }
  *deopt_index = SafepointEntry::kNoDeoptIndex;
  return {};
}

void OptimizedJSFrame::GetFunctions(
    std::vector<Tagged<SharedFunctionInfo>>* functions) const {
  DCHECK(functions->empty());
  DCHECK(is_optimized());

  // Delegate to JS frame in absence of turbofan deoptimization.
  // TODO(turbofan): Revisit once we support deoptimization across the board.
  Tagged<Code> code = LookupCode();
  if (code->kind() == CodeKind::BUILTIN) {
    return JavaScriptFrame::GetFunctions(functions);
  }

  DisallowGarbageCollection no_gc;
  int deopt_index = SafepointEntry::kNoDeoptIndex;
  Tagged<DeoptimizationData> const data =
      GetDeoptimizationData(code, &deopt_index);
  DCHECK(!data.is_null());
  DCHECK_NE(SafepointEntry::kNoDeoptIndex, deopt_index);
  Tagged<DeoptimizationLiteralArray> const literal_array = data->LiteralArray();

  DeoptimizationFrameTranslation::Iterator it(
      data->FrameTranslation(), data->TranslationIndex(deopt_index).value());
  int jsframe_count = it.EnterBeginOpcode().js_frame_count;

  // We insert the frames in reverse order because the frames
  // in the deoptimization translation are ordered bottom-to-top.
  while (jsframe_count != 0) {
    TranslationOpcode opcode = it.SeekNextJSFrame();
    it.NextOperand();  // Skip bailout id.
    jsframe_count--;

    // The second operand of the frame points to the function.
    Tagged<Object> shared = literal_array->get(it.NextOperand());
    functions->push_back(Cast<SharedFunctionInfo>(shared));

    // Skip over remaining operands to advance to the next opcode.
    it.SkipOperands(TranslationOpcodeOperandCount(opcode) - 2);
  }
}

int OptimizedJSFrame::StackSlotOffsetRelativeToFp(int slot_index) {
  return StandardFrameConstants::kCallerSPOffset -
         ((slot_index + 1) * kSystemPointerSize);
}

int UnoptimizedJSFrame::position() const {
  Tagged<BytecodeArray> code = GetBytecodeArray();
  int code_offset = GetBytecodeOffset();
  return code->SourcePosition(code_offset);
}

int UnoptimizedJSFrame::LookupExceptionHandlerInTable(
    int* context_register, HandlerTable::CatchPrediction* prediction) {
  HandlerTable table(GetBytecodeArray());
  int handler_index = table.LookupHandlerIndexForRange(GetBytecodeOffset());
  if (handler_index != HandlerTable::kNoHandlerFound) {
    if (context_register) *context_register = table.GetRangeData(handler_index);
    if (prediction) *prediction = table.GetRangePrediction(handler_index);
    table.MarkHandlerUsed(handler_index);
    return table.GetRangeHandler(handler_index);
  }
  return handler_index;
}

Tagged<BytecodeArray> UnoptimizedJSFrame::GetBytecodeArray() const {
  const int index = UnoptimizedFrameConstants::kBytecodeArrayExpressionIndex;
  DCHECK_EQ(UnoptimizedFrameConstants::kBytecodeArrayFromFp,
            UnoptimizedFrameConstants::kExpressionsOffset -
                index * kSystemPointerSize);
  return Cast<BytecodeArray>(GetExpression(index));
}

Tagged<Object> UnoptimizedJSFrame::ReadInterpreterRegister(
    int register_index) const {
  const int index = UnoptimizedFrameConstants::kRegisterFileExpressionIndex;
  DCHECK_EQ(UnoptimizedFrameConstants::kRegisterFileFromFp,
            UnoptimizedFrameConstants::kExpressionsOffset -
                index * kSystemPointerSize);
  return GetExpression(index + register_index);
}

void UnoptimizedJSFrame::Summarize(std::vector<FrameSummary>* functions) const {
  DCHECK(functions->empty());
  DirectHandle<AbstractCode> abstract_code(
      Cast<AbstractCode>(GetBytecodeArray()), isolate());
  DirectHandle<FixedArray> params = GetParameters();
  FrameSummary::JavaScriptFrameSummary summary(
      isolate(), receiver(), function(), *abstract_code, GetBytecodeOffset(),
      IsConstructor(), *params);
  functions->push_back(summary);
}

int InterpretedFrame::GetBytecodeOffset() const {
  const int index = InterpreterFrameConstants::kBytecodeOffsetExpressionIndex;
  DCHECK_EQ(
"""


```