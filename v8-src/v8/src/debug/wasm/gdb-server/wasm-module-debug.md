Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality and relationship with JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and how it relates to JavaScript, providing a JavaScript example if applicable. The file path `v8/src/debug/wasm/gdb-server/wasm-module-debug.cc` immediately signals that this is about debugging WebAssembly within the V8 JavaScript engine, specifically through a GDB server interface.

2. **High-Level Overview:** The "gdb-server" part is crucial. GDB is a common debugger. This suggests the code provides functionality to inspect and manipulate WebAssembly modules while debugging them using GDB.

3. **Class Structure:** The code defines a class `WasmModuleDebug`. This class likely encapsulates the debugging logic for a specific WebAssembly module. The constructor takes `v8::Isolate*` and `Local<debug::WasmScript>`, indicating it needs the V8 isolate (the runtime environment) and a handle to the WebAssembly script being debugged.

4. **Method Analysis (Iterative Approach):**  Go through the methods of the `WasmModuleDebug` class and the free functions defined in the same namespace, understanding their purpose. Look for patterns and keywords that reveal functionality.

    * **`GetModuleName()`:**  Straightforward – retrieves the name of the WebAssembly module.
    * **`GetFirstWasmInstance()`:**  Finds the first instance of the WebAssembly module. This is important because WebAssembly modules can be instantiated multiple times.
    * **`GetLEB128Size()`:**  This deals with LEB128 encoding, a common encoding for variable-length integers in WebAssembly. It's used to calculate the size of encoded values.
    * **`ReturnPc()`:**  This function is interesting. It examines bytecode to determine the return address after a `call` or `call_indirect` instruction. This is crucial for stack unwinding during debugging.
    * **`GetCallStack()`:** This is a core debugging function. It iterates through the stack frames and extracts information (script ID, offset) for both JavaScript and WebAssembly frames. The logic for handling inlined functions (`Summarize`) is important. The `ReturnPc` function is used here for WebAssembly frames.
    * **`FindWasmFrame()`:**  Helps locate a specific WebAssembly frame within the call stack based on an index.
    * **`GetWasmInstance()`:**  Retrieves the `WasmInstanceObject` for a given frame.
    * **`GetWasmGlobal()`:** Gets the value of a WebAssembly global variable.
    * **`GetWasmLocal()`:** Gets the value of a WebAssembly local variable within a specific stack frame. It needs to find the correct frame first.
    * **`GetWasmStackValue()`:** Gets a value from the WebAssembly operand stack.
    * **`GetWasmMemory()`:** Reads data from the WebAssembly module's linear memory.
    * **`GetWasmData()`:** Reads data from the WebAssembly module's data segments (initialized memory).
    * **`GetWasmModuleBytes()`:** Reads raw bytes of the WebAssembly module itself.
    * **`AddBreakpoint()` and `RemoveBreakpoint()`:**  Functions for setting and removing breakpoints in the WebAssembly code.
    * **`PrepareStep()`:**  Initiates a single-step debugging action.
    * **`StoreValue()` and `GetWasmValue()`:** These are helper functions to convert and store WebAssembly values into a byte buffer. Note the types they handle (`i32`, `i64`, `f32`, `f64`, `s128`). The unsupported types are also informative.

5. **Identify Key Functionality Groups:** Based on the method analysis, group the functions by their purpose:

    * **Module Information:** `GetModuleName()`, `GetFirstWasmInstance()`
    * **Stack Inspection:** `GetCallStack()`, `FindWasmFrame()`, `GetWasmInstance()`
    * **Variable Inspection:** `GetWasmGlobal()`, `GetWasmLocal()`, `GetWasmStackValue()`
    * **Memory Inspection:** `GetWasmMemory()`, `GetWasmData()`
    * **Bytecode Inspection:** `GetWasmModuleBytes()`, `GetLEB128Size()`, `ReturnPc()`
    * **Breakpoint Management:** `AddBreakpoint()`, `RemoveBreakpoint()`
    * **Stepping:** `PrepareStep()`
    * **Value Handling:** `GetWasmValue()`

6. **Relate to JavaScript:** The key connection is that this C++ code is *part of* the V8 engine. V8 executes JavaScript, and JavaScript can load and execute WebAssembly. The debugging features implemented here are used when a developer is debugging WebAssembly code that's been loaded and called from JavaScript.

7. **JavaScript Example:**  The best way to illustrate the connection is with a simple example where JavaScript loads and runs WebAssembly, and a developer might want to debug the WebAssembly part. The example should show the interaction between the two. Consider scenarios where debugging would be useful, like inspecting variables or stepping through code.

8. **Structure the Explanation:** Organize the findings into a clear and logical explanation:

    * Start with a concise summary of the overall functionality.
    * Detail the purpose of the `WasmModuleDebug` class and its core responsibilities.
    * Explain the functionality of key methods, grouping them logically. Use clear and simple language.
    * Explicitly connect the C++ code to JavaScript's ability to load and run WebAssembly.
    * Provide a practical JavaScript example demonstrating the interaction.
    * Conclude by summarizing the importance of this code for debugging WebAssembly within the V8 environment.

9. **Refine and Review:**  Read through the explanation, ensuring it's accurate, clear, and addresses all parts of the request. Check for any jargon that needs further clarification. Ensure the JavaScript example is correct and easy to understand. For example, initially, I might have just described the methods individually. Grouping them by functionality makes the explanation more coherent. Similarly, the initial JavaScript example might have been too complex. Simplifying it to the core interaction is better.
这个C++源代码文件 `wasm-module-debug.cc` 的主要功能是**为GDB调试器提供调试WebAssembly模块的能力**。它属于V8 JavaScript引擎的一部分，专门处理WebAssembly相关的调试操作。

具体来说，这个文件实现了以下功能：

1. **模块信息获取:**
   - `GetModuleName()`: 获取WebAssembly模块的名称。
   - `GetFirstWasmInstance()`: 获取WebAssembly模块的第一个实例。

2. **调用栈信息获取:**
   - `GetCallStack()`: 获取当前执行的调用栈，包括JavaScript和WebAssembly帧。它能够识别并处理内联的函数调用，并提供代码偏移量等信息。
   - `FindWasmFrame()`: 在调用栈中查找特定的WebAssembly帧。
   - `GetWasmInstance()`: 根据帧索引获取对应的WebAssembly实例。

3. **变量和栈值获取:**
   - `GetWasmGlobal()`: 获取指定WebAssembly全局变量的值。
   - `GetWasmLocal()`: 获取指定WebAssembly局部变量的值。
   - `GetWasmStackValue()`: 获取WebAssembly操作数栈中指定位置的值。

4. **内存和数据段访问:**
   - `GetWasmMemory()`: 读取WebAssembly线性内存中的数据。
   - `GetWasmData()`: 读取WebAssembly数据段中的数据。

5. **模块字节码访问:**
   - `GetWasmModuleBytes()`: 获取WebAssembly模块的原始字节码。

6. **断点管理:**
   - `AddBreakpoint()`: 在WebAssembly代码的指定偏移量处设置断点。
   - `RemoveBreakpoint()`: 移除指定偏移量处的断点。

7. **单步执行:**
   - `PrepareStep()`: 准备进行单步执行。

8. **WebAssembly值处理:**
   - `GetWasmValue()`: 将`wasm::WasmValue`转换为字节数组，用于GDB传输。

**与JavaScript的功能关系：**

这个文件是V8引擎的一部分，而V8是执行JavaScript代码的引擎。当JavaScript代码加载并执行WebAssembly模块时，如果需要进行调试，这个文件提供的功能就派上了用场。

JavaScript可以通过WebAssembly API加载和运行`.wasm`文件。在调试过程中，开发者可能希望查看WebAssembly模块的内部状态，例如变量的值、调用栈信息、内存内容等。`wasm-module-debug.cc` 提供的功能正是为了满足这些需求，它允许调试器（如GDB）与正在运行的WebAssembly代码进行交互。

**JavaScript 举例说明:**

假设我们有一个简单的WebAssembly模块 `module.wasm`，它定义了一个全局变量和一个函数：

```wat
(module
  (global (mut i32) (i32.const 10))  ;; 定义一个可变的 i32 全局变量，初始值为 10
  (func $add (param $p1 i32) (result i32)
    global.get 0
    local.get 0
    i32.add
  )
  (export "add" (func $add))
)
```

在JavaScript中，我们可以加载并调用这个模块：

```javascript
async function loadAndRunWasm() {
  const response = await fetch('module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const result = instance.exports.add(5);
  console.log(result); // 输出 15 (10 + 5)
}

loadAndRunWasm();
```

当我们在调试这个JavaScript代码时，如果想在GDB中查看WebAssembly模块的全局变量的值，或者在 `add` 函数内部查看局部变量的值，`wasm-module-debug.cc` 中的函数就会被调用。

例如，当GDB连接到V8引擎并命中断点时，它可能会调用 `WasmModuleDebug::GetWasmGlobal()` 来获取全局变量的值。或者，当单步执行到 `add` 函数内部时，可能会调用 `WasmModuleDebug::GetWasmLocal()` 来查看参数 `$p1` 的值。`WasmModuleDebug::GetCallStack()` 则可以帮助我们了解当前的执行路径，包括JavaScript和WebAssembly的调用关系。

总而言之，`wasm-module-debug.cc` 是V8引擎中用于支持WebAssembly调试的关键组成部分，它提供了GDB调试器与正在运行的WebAssembly代码进行交互所需的底层功能。它使得开发者能够像调试本地代码一样调试WebAssembly，极大地提升了WebAssembly应用的开发体验。

Prompt: 
```
这是目录为v8/src/debug/wasm/gdb-server/wasm-module-debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/wasm/gdb-server/wasm-module-debug.h"

#include "src/api/api-inl.h"
#include "src/api/api.h"
#include "src/execution/frames-inl.h"
#include "src/execution/frames.h"
#include "src/objects/script.h"
#include "src/wasm/module-instantiate.h"
#include "src/wasm/wasm-debug.h"
#include "src/wasm/wasm-value.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace gdb_server {

WasmModuleDebug::WasmModuleDebug(v8::Isolate* isolate,
                                 Local<debug::WasmScript> wasm_script) {
  DCHECK_EQ(Script::Type::kWasm, Utils::OpenHandle(*wasm_script)->type());

  isolate_ = isolate;
  wasm_script_ = Global<debug::WasmScript>(isolate, wasm_script);
}

std::string WasmModuleDebug::GetModuleName() const {
  v8::Local<debug::WasmScript> wasm_script = wasm_script_.Get(isolate_);
  v8::Local<v8::String> name;
  std::string module_name;
  if (wasm_script->Name().ToLocal(&name)) {
    module_name = *(v8::String::Utf8Value(isolate_, name));
  }
  return module_name;
}

Handle<WasmInstanceObject> WasmModuleDebug::GetFirstWasmInstance() {
  v8::Local<debug::WasmScript> wasm_script = wasm_script_.Get(isolate_);
  Handle<Script> script = Utils::OpenHandle(*wasm_script);

  Handle<WeakArrayList> weak_instance_list(script->wasm_weak_instance_list(),
                                           GetIsolate());
  if (weak_instance_list->length() > 0) {
    Tagged<MaybeObject> maybe_instance = weak_instance_list->Get(0);
    if (maybe_instance.IsWeak()) {
      Handle<WasmInstanceObject> instance(
          Cast<WasmInstanceObject>(maybe_instance.GetHeapObjectAssumeWeak()),
          GetIsolate());
      return instance;
    }
  }
  return Handle<WasmInstanceObject>::null();
}

int GetLEB128Size(base::Vector<const uint8_t> module_bytes, int offset) {
  int index = offset;
  while (module_bytes[index] & 0x80) index++;
  return index + 1 - offset;
}

int ReturnPc(const NativeModule* native_module, int pc) {
  base::Vector<const uint8_t> wire_bytes = native_module->wire_bytes();
  uint8_t opcode = wire_bytes[pc];
  switch (opcode) {
    case kExprCallFunction: {
      // skip opcode
      pc++;
      // skip function index
      return pc + GetLEB128Size(wire_bytes, pc);
    }
    case kExprCallIndirect: {
      // skip opcode
      pc++;
      // skip signature index
      pc += GetLEB128Size(wire_bytes, pc);
      // skip table index
      return pc + GetLEB128Size(wire_bytes, pc);
    }
    default:
      UNREACHABLE();
  }
}

// static
std::vector<wasm_addr_t> WasmModuleDebug::GetCallStack(
    uint32_t debug_context_id, Isolate* isolate) {
  std::vector<wasm_addr_t> call_stack;
  for (StackFrameIterator frame_it(isolate); !frame_it.done();
       frame_it.Advance()) {
    StackFrame* const frame = frame_it.frame();
    switch (frame->type()) {
      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION:
      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH:
      case StackFrame::INTERPRETED:
      case StackFrame::BASELINE:
      case StackFrame::MAGLEV:
      case StackFrame::TURBOFAN_JS:
      case StackFrame::BUILTIN:
      case StackFrame::WASM: {
        // A standard frame may include many summarized frames, due to inlining.
        std::vector<FrameSummary> frames;
        CommonFrame::cast(frame)->Summarize(&frames);
        for (size_t i = frames.size(); i-- != 0;) {
          int offset = 0;
          Handle<Script> script;

          auto& summary = frames[i];
          if (summary.IsJavaScript()) {
            FrameSummary::JavaScriptFrameSummary const& javascript =
                summary.AsJavaScript();
            offset = javascript.code_offset();
            script = Cast<Script>(javascript.script());
          } else if (summary.IsWasm()) {
            FrameSummary::WasmFrameSummary const& wasm = summary.AsWasm();
            offset = GetWasmFunctionOffset(wasm.wasm_instance()->module(),
                                           wasm.function_index()) +
                     wasm.code_offset();
            script = wasm.script();

            bool zeroth_frame = call_stack.empty();
            if (!zeroth_frame) {
              const NativeModule* native_module =
                  wasm.wasm_instance()->module_object().native_module();
              offset = ReturnPc(native_module, offset);
            }
          }

          if (offset > 0) {
            call_stack.push_back(
                {debug_context_id << 16 | script->id(), uint32_t(offset)});
          }
        }
        break;
      }

      case StackFrame::BUILTIN_EXIT:
      default:
        // ignore the frame.
        break;
    }
  }
  if (call_stack.empty()) call_stack.push_back({1, 0});
  return call_stack;
}

// static
std::vector<FrameSummary> WasmModuleDebug::FindWasmFrame(
    DebuggableStackFrameIterator* frame_it, uint32_t* frame_index) {
  while (!frame_it->done()) {
    StackFrame* const frame = frame_it->frame();
    switch (frame->type()) {
      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION:
      case StackFrame::JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH:
      case StackFrame::INTERPRETED:
      case StackFrame::BASELINE:
      case StackFrame::MAGLEV:
      case StackFrame::TURBOFAN_JS:
      case StackFrame::BUILTIN:
      case StackFrame::WASM: {
        // A standard frame may include many summarized frames, due to inlining.
        std::vector<FrameSummary> frames;
        CommonFrame::cast(frame)->Summarize(&frames);
        const size_t frame_count = frames.size();
        DCHECK_GT(frame_count, 0);

        if (frame_count > *frame_index) {
#if V8_ENABLE_DRUMBRAKE
          if (frame_it->is_wasm() && !frame_it->is_wasm_interpreter_entry())
#else   // V8_ENABLE_DRUMBRAKE
          if (frame_it->is_wasm())
#endif  // V8_ENABLE_DRUMBRAKE
            return frames;
          else
            return {};
        } else {
          *frame_index -= frame_count;
          frame_it->Advance();
        }
        break;
      }

      case StackFrame::BUILTIN_EXIT:
      default:
        // ignore the frame.
        break;
    }
  }
  return {};
}

// static
Handle<WasmInstanceObject> WasmModuleDebug::GetWasmInstance(
    Isolate* isolate, uint32_t frame_index) {
  DebuggableStackFrameIterator frame_it(isolate);
  std::vector<FrameSummary> frames = FindWasmFrame(&frame_it, &frame_index);
  if (frames.empty()) {
    return Handle<WasmInstanceObject>::null();
  }

  int reversed_index = static_cast<int>(frames.size() - 1 - frame_index);
  const FrameSummary::WasmFrameSummary& summary =
      frames[reversed_index].AsWasm();
  return summary.wasm_instance();
}

// static
bool WasmModuleDebug::GetWasmGlobal(Isolate* isolate, uint32_t frame_index,
                                    uint32_t index, uint8_t* buffer,
                                    uint32_t buffer_size, uint32_t* size) {
  HandleScope handles(isolate);

  Handle<WasmInstanceObject> instance = GetWasmInstance(isolate, frame_index);
  if (!instance.is_null()) {
    Handle<WasmModuleObject> module_object(instance->module_object(), isolate);
    const wasm::WasmModule* module = module_object->module();
    if (index < module->globals.size()) {
      wasm::WasmValue wasm_value =
          WasmInstanceObject::GetGlobalValue(instance, module->globals[index]);
      return GetWasmValue(wasm_value, buffer, buffer_size, size);
    }
  }
  return false;
}

// static
bool WasmModuleDebug::GetWasmLocal(Isolate* isolate, uint32_t frame_index,
                                   uint32_t index, uint8_t* buffer,
                                   uint32_t buffer_size, uint32_t* size) {
  HandleScope handles(isolate);

  DebuggableStackFrameIterator frame_it(isolate);
  std::vector<FrameSummary> frames = FindWasmFrame(&frame_it, &frame_index);
  if (frames.empty()) {
    return false;
  }

  int reversed_index = static_cast<int>(frames.size() - 1 - frame_index);
  const FrameSummary& summary = frames[reversed_index];
  if (summary.IsWasm()) {
    Handle<WasmInstanceObject> instance = summary.AsWasm().wasm_instance();
    if (!instance.is_null()) {
      Handle<WasmModuleObject> module_object(instance->module_object(),
                                             isolate);
      wasm::NativeModule* native_module = module_object->native_module();
      DebugInfo* debug_info = native_module->GetDebugInfo();
      if (static_cast<uint32_t>(
              debug_info->GetNumLocals(frame_it.frame()->pc())) > index) {
        wasm::WasmValue wasm_value = debug_info->GetLocalValue(
            index, frame_it.frame()->pc(), frame_it.frame()->fp(),
            frame_it.frame()->callee_fp());
        return GetWasmValue(wasm_value, buffer, buffer_size, size);
      }
    }
  }
  return false;
}

// static
bool WasmModuleDebug::GetWasmStackValue(Isolate* isolate, uint32_t frame_index,
                                        uint32_t index, uint8_t* buffer,
                                        uint32_t buffer_size, uint32_t* size) {
  HandleScope handles(isolate);

  DebuggableStackFrameIterator frame_it(isolate);
  std::vector<FrameSummary> frames = FindWasmFrame(&frame_it, &frame_index);
  if (frames.empty()) {
    return false;
  }

  int reversed_index = static_cast<int>(frames.size() - 1 - frame_index);
  const FrameSummary& summary = frames[reversed_index];
  if (summary.IsWasm()) {
    Handle<WasmInstanceObject> instance = summary.AsWasm().wasm_instance();
    if (!instance.is_null()) {
      Handle<WasmModuleObject> module_object(instance->module_object(),
                                             isolate);
      wasm::NativeModule* native_module = module_object->native_module();
      DebugInfo* debug_info = native_module->GetDebugInfo();
      if (static_cast<uint32_t>(
              debug_info->GetStackDepth(frame_it.frame()->pc())) > index) {
        WasmValue wasm_value = debug_info->GetStackValue(
            index, frame_it.frame()->pc(), frame_it.frame()->fp(),
            frame_it.frame()->callee_fp());
        return GetWasmValue(wasm_value, buffer, buffer_size, size);
      }
    }
  }
  return false;
}

uint32_t WasmModuleDebug::GetWasmMemory(Isolate* isolate, uint32_t offset,
                                        uint8_t* buffer, uint32_t size) {
  HandleScope handles(isolate);

  uint32_t bytes_read = 0;
  Handle<WasmInstanceObject> instance = GetFirstWasmInstance();
  if (!instance.is_null()) {
    uint8_t* mem_start = instance->memory_start();
    size_t mem_size = instance->memory_size();
    if (static_cast<uint64_t>(offset) + size <= mem_size) {
      memcpy(buffer, mem_start + offset, size);
      bytes_read = size;
    } else if (offset < mem_size) {
      bytes_read = static_cast<uint32_t>(mem_size) - offset;
      memcpy(buffer, mem_start + offset, bytes_read);
    }
  }
  return bytes_read;
}

uint32_t WasmModuleDebug::GetWasmData(Isolate* isolate, uint32_t offset,
                                      uint8_t* buffer, uint32_t size) {
  HandleScope handles(isolate);

  uint32_t bytes_read = 0;
  Handle<WasmInstanceObject> instance = GetFirstWasmInstance();
  if (!instance.is_null()) {
    Handle<WasmModuleObject> module_object(instance->module_object(), isolate);
    const wasm::WasmModule* module = module_object->module();
    if (!module->data_segments.empty()) {
      const WasmDataSegment& segment = module->data_segments[0];
      uint32_t data_offset = EvalUint32InitExpr(instance, segment.dest_addr);
      offset += data_offset;

      uint8_t* mem_start = instance->memory_start();
      size_t mem_size = instance->memory_size();
      if (static_cast<uint64_t>(offset) + size <= mem_size) {
        memcpy(buffer, mem_start + offset, size);
        bytes_read = size;
      } else if (offset < mem_size) {
        bytes_read = static_cast<uint32_t>(mem_size) - offset;
        memcpy(buffer, mem_start + offset, bytes_read);
      }
    }
  }
  return bytes_read;
}

uint32_t WasmModuleDebug::GetWasmModuleBytes(wasm_addr_t wasm_addr,
                                             uint8_t* buffer, uint32_t size) {
  uint32_t bytes_read = 0;
  // Any instance will work.
  Handle<WasmInstanceObject> instance = GetFirstWasmInstance();
  if (!instance.is_null()) {
    Handle<WasmModuleObject> module_object(instance->module_object(),
                                           GetIsolate());
    wasm::NativeModule* native_module = module_object->native_module();
    const wasm::ModuleWireBytes wire_bytes(native_module->wire_bytes());
    uint32_t offset = wasm_addr.Offset();
    if (offset < wire_bytes.length()) {
      uint32_t module_size = static_cast<uint32_t>(wire_bytes.length());
      bytes_read = module_size - offset >= size ? size : module_size - offset;
      memcpy(buffer, wire_bytes.start() + offset, bytes_read);
    }
  }
  return bytes_read;
}

bool WasmModuleDebug::AddBreakpoint(uint32_t offset, int* breakpoint_id) {
  v8::Local<debug::WasmScript> wasm_script = wasm_script_.Get(isolate_);
  Handle<Script> script = Utils::OpenHandle(*wasm_script);
  Handle<String> condition = GetIsolate()->factory()->empty_string();
  int breakpoint_address = static_cast<int>(offset);
  return GetIsolate()->debug()->SetBreakPointForScript(
      script, condition, &breakpoint_address, breakpoint_id);
}

void WasmModuleDebug::RemoveBreakpoint(uint32_t offset, int breakpoint_id) {
  v8::Local<debug::WasmScript> wasm_script = wasm_script_.Get(isolate_);
  Handle<Script> script = Utils::OpenHandle(*wasm_script);
  GetIsolate()->debug()->RemoveBreakpointForWasmScript(script, breakpoint_id);
}

void WasmModuleDebug::PrepareStep() {
  i::Isolate* isolate = GetIsolate();
  DebugScope debug_scope(isolate->debug());
  debug::PrepareStep(reinterpret_cast<v8::Isolate*>(isolate),
                     debug::StepAction::StepInto);
}

template <typename T>
bool StoreValue(const T& value, uint8_t* buffer, uint32_t buffer_size,
                uint32_t* size) {
  *size = sizeof(value);
  if (*size > buffer_size) return false;
  memcpy(buffer, &value, *size);
  return true;
}

// static
bool WasmModuleDebug::GetWasmValue(const wasm::WasmValue& wasm_value,
                                   uint8_t* buffer, uint32_t buffer_size,
                                   uint32_t* size) {
  switch (wasm_value.type().kind()) {
    case wasm::kI32:
      return StoreValue(wasm_value.to_i32(), buffer, buffer_size, size);
    case wasm::kI64:
      return StoreValue(wasm_value.to_i64(), buffer, buffer_size, size);
    case wasm::kF32:
      return StoreValue(wasm_value.to_f32(), buffer, buffer_size, size);
    case wasm::kF64:
      return StoreValue(wasm_value.to_f64(), buffer, buffer_size, size);
    case wasm::kS128:
      return StoreValue(wasm_value.to_s128(), buffer, buffer_size, size);
    case wasm::kRef:
    case wasm::kRefNull:
    case wasm::kRtt:
    case wasm::kVoid:
    case wasm::kBottom:
      // Not supported
      return false;
  }
}

}  // namespace gdb_server
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```