Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Context:** The first step is to recognize the location of the file (`v8/src/debug/wasm/gdb-server/wasm-module-debug.cc`). This immediately tells us it's part of V8's debugging infrastructure, specifically for debugging WebAssembly modules through a GDB server. The `gdb-server` part is a strong hint about its purpose: facilitating interaction with a debugger like GDB.

2. **High-Level Overview:**  Read through the code, focusing on class names, method names, and included headers. This gives a general idea of what the code is doing. Key observations:
    * The class `WasmModuleDebug` is central.
    * It interacts with `v8::Isolate`, `debug::WasmScript`, `WasmInstanceObject`, `WasmModuleObject`, and `Script`. These are all core V8 and WebAssembly concepts.
    * The methods have names like `GetModuleName`, `GetFirstWasmInstance`, `GetCallStack`, `GetWasmGlobal`, `GetWasmLocal`, `GetWasmMemory`, `AddBreakpoint`, `RemoveBreakpoint`, etc. These clearly indicate debugging functionalities.

3. **Analyze Key Methods (Function by Function):**  Go through each significant method and understand its purpose and how it achieves it. This involves:

    * **Constructor (`WasmModuleDebug`):**  Initializes the object with an isolate and a `WasmScript`. Stores the `WasmScript` as a global handle.
    * **`GetModuleName`:** Retrieves the name of the Wasm module from the `WasmScript`.
    * **`GetFirstWasmInstance`:**  Crucial for accessing the runtime representation of the Wasm module. It gets the list of weak instances and returns the first one. The "weak" aspect is important for garbage collection.
    * **`GetLEB128Size`:** A utility function for decoding LEB128 encoded integers, common in the Wasm binary format. Recognize this as a low-level detail related to parsing.
    * **`ReturnPc`:**  This function is about calculating the return program counter address within the Wasm bytecode for `call` and `call_indirect` instructions. This is essential for accurate stack tracing.
    * **`GetCallStack`:**  The core of stack unwinding for Wasm. Iterates through V8 stack frames, identifies Wasm frames, and extracts relevant information (script ID, offset). Handles inlining by iterating through `FrameSummary` objects. The `ReturnPc` call within this function is key to adjusting the PC for returns.
    * **`FindWasmFrame`:**  Helps locate a specific Wasm frame within the call stack based on an index. Used by other methods that need to operate on a particular stack frame.
    * **`GetWasmInstance`:**  Retrieves the `WasmInstanceObject` for a given stack frame.
    * **`GetWasmGlobal`:**  Accesses the value of a global variable in a Wasm instance.
    * **`GetWasmLocal`:** Accesses the value of a local variable in a Wasm function at a specific stack frame. It uses `DebugInfo` to get local variable information.
    * **`GetWasmStackValue`:**  Accesses values on the Wasm operand stack. Again, relies on `DebugInfo`.
    * **`GetWasmMemory`:** Reads data from the Wasm linear memory.
    * **`GetWasmData`:**  Reads data from the initialized data segments of the Wasm module.
    * **`GetWasmModuleBytes`:**  Retrieves raw bytes from the Wasm module's binary code.
    * **`AddBreakpoint`:**  Sets a breakpoint at a specific offset in the Wasm module. Delegates to V8's debugger.
    * **`RemoveBreakpoint`:** Removes a breakpoint.
    * **`PrepareStep`:**  Initiates a single-step debugging action.
    * **`StoreValue` (template):** A helper for copying values into a buffer.
    * **`GetWasmValue`:**  A generic function to extract the value of a `WasmValue` into a byte buffer. Handles different Wasm value types.

4. **Identify Core Functionality:**  Based on the method analysis, summarize the main capabilities:
    * Accessing module information (name, instance).
    * Inspecting the call stack.
    * Accessing local variables, global variables, and stack values.
    * Reading Wasm memory and data segments.
    * Retrieving the raw Wasm bytecode.
    * Setting and removing breakpoints.
    * Stepping execution.

5. **Address Specific Questions:**  Now, address the specific points raised in the prompt:

    * **Functionality Listing:**  Compile the list of functions identified in the previous steps.
    * **`.tq` Extension:** Explain that `.tq` indicates Torque code and confirm that this file is C++, so it's not Torque.
    * **Relationship to JavaScript:**  Explain that while this is C++, it's part of V8, which executes JavaScript and WebAssembly. Show how JavaScript can interact with Wasm (instantiation, calling functions).
    * **Code Logic and Examples:** For functions with interesting logic (like `GetCallStack`, `ReturnPc`), provide a simplified example with input and expected output.
    * **Common Programming Errors:** Think about how a user interacting with a debugger might make mistakes. Examples: incorrect offset, buffer size issues, wrong frame index.

6. **Structure and Refine:**  Organize the information clearly with headings and bullet points. Use precise terminology. Ensure the JavaScript examples are correct and relevant. Double-check for any inconsistencies or errors in the analysis.

7. **Self-Correction/Refinement during the process:**

    * **Initial thought:** Maybe focus too much on individual lines. *Correction:* Shift focus to the higher-level purpose of each function and how they relate.
    * **Overlook details:** Miss the significance of "weak" in `GetFirstWasmInstance`. *Correction:* Realize this is about memory management and GC.
    * **Confuse concepts:**  Mix up Wasm offsets and byte offsets. *Correction:* Carefully distinguish between the two in explanations and examples.
    * **JavaScript example too complex:** Try to make the JavaScript example concise and directly related to the C++ code's purpose. *Correction:* Focus on the instantiation and basic interaction with the Wasm module.

By following this structured approach, combining code reading with an understanding of the underlying concepts (V8, WebAssembly, debugging), and addressing each part of the prompt systematically, we can arrive at a comprehensive and accurate analysis of the `wasm-module-debug.cc` file.
好的，让我们来分析一下 `v8/src/debug/wasm/gdb-server/wasm-module-debug.cc` 这个 V8 源代码文件的功能。

**功能概述**

这个 C++ 文件 `wasm-module-debug.cc` 的主要功能是为 V8 引擎提供 WebAssembly 模块的调试支持，特别是针对 GDB server 的场景。它提供了一系列方法，允许外部调试器（如 GDB）检查和操作 WebAssembly 模块的运行时状态。

**详细功能列表**

1. **模块信息获取:**
    *   `GetModuleName()`: 获取 WebAssembly 模块的名称。
    *   `GetFirstWasmInstance()`: 获取模块的第一个 WebAssembly 实例对象。

2. **调用栈信息获取:**
    *   `GetCallStack(uint32_t debug_context_id, Isolate* isolate)`: 获取当前执行的 WebAssembly 代码的调用栈信息，包括脚本 ID 和偏移量。
    *   `FindWasmFrame(DebuggableStackFrameIterator* frame_it, uint32_t* frame_index)`: 在调用栈中查找指定的 WebAssembly 帧。
    *   `GetWasmInstance(Isolate* isolate, uint32_t frame_index)`: 获取指定调用栈帧的 WebAssembly 实例。

3. **变量值获取:**
    *   `GetWasmGlobal(Isolate* isolate, uint32_t frame_index, uint32_t index, uint8_t* buffer, uint32_t buffer_size, uint32_t* size)`: 获取指定调用栈帧中 WebAssembly 全局变量的值。
    *   `GetWasmLocal(Isolate* isolate, uint32_t frame_index, uint32_t index, uint8_t* buffer, uint32_t buffer_size, uint32_t* size)`: 获取指定调用栈帧中 WebAssembly 局部变量的值。
    *   `GetWasmStackValue(Isolate* isolate, uint32_t frame_index, uint32_t index, uint8_t* buffer, uint32_t buffer_size, uint32_t* size)`: 获取指定调用栈帧中 WebAssembly 栈上的值。
    *   `GetWasmValue(const wasm::WasmValue& wasm_value, uint8_t* buffer, uint32_t buffer_size, uint32_t* size)`: 一个静态辅助方法，用于将 `wasm::WasmValue` 转换为字节数组。

4. **内存和数据段访问:**
    *   `GetWasmMemory(Isolate* isolate, uint32_t offset, uint8_t* buffer, uint32_t size)`: 读取 WebAssembly 线性内存中的数据。
    *   `GetWasmData(Isolate* isolate, uint32_t offset, uint8_t* buffer, uint32_t size)`: 读取 WebAssembly 数据段中的数据。
    *   `GetWasmModuleBytes(wasm_addr_t wasm_addr, uint8_t* buffer, uint32_t size)`: 读取 WebAssembly 模块的原始字节码。

5. **断点管理:**
    *   `AddBreakpoint(uint32_t offset, int* breakpoint_id)`: 在指定的 WebAssembly 代码偏移处设置断点。
    *   `RemoveBreakpoint(uint32_t offset, int breakpoint_id)`: 移除指定偏移处的断点。

6. **单步执行:**
    *   `PrepareStep()`:  准备进行单步执行。

7. **内部辅助函数:**
    *   `GetLEB128Size(base::Vector<const uint8_t> module_bytes, int offset)`: 计算 LEB128 编码的整数的大小。
    *   `ReturnPc(const NativeModule* native_module, int pc)`:  根据操作码计算返回地址的 PC 值，用于处理函数调用指令。
    *   `StoreValue` (模板函数): 将特定类型的值存储到字节缓冲区中。

**关于文件扩展名 `.tq`**

你说的很对。如果 `v8/src/debug/wasm/gdb-server/wasm-module-debug.cc` 的扩展名是 `.tq`，那么它将是 V8 的 Torque 源代码。Torque 是一种 V8 自有的领域特定语言，用于生成高效的运行时代码。但是，根据你提供的代码内容来看，这个文件是标准的 C++ 源代码 (`.cc`)。

**与 JavaScript 的关系**

虽然 `wasm-module-debug.cc` 是 C++ 代码，但它的功能与 JavaScript 的调试息息相关。当 JavaScript 代码执行 WebAssembly 模块时，V8 引擎会加载和运行 WebAssembly 代码。这个 C++ 文件提供的功能使得开发者可以使用 GDB 等调试器来检查 WebAssembly 模块在 V8 引擎中的运行时状态，这通常是在调试包含 WebAssembly 的 JavaScript 应用时进行的。

**JavaScript 示例**

假设我们有一个简单的 JavaScript 文件 `index.js`，它加载并执行一个 WebAssembly 模块：

```javascript
// index.js
async function runWasm() {
  const response = await fetch('module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const result = instance.exports.add(5, 10);
  console.log('Wasm result:', result);
}

runWasm();
```

以及一个简单的 WebAssembly 模块 `module.wasm`，它导出一个 `add` 函数。

当使用 GDB 连接到 V8 引擎并调试这个 JavaScript 程序时，`wasm-module-debug.cc` 提供的功能会被使用，例如：

*   **设置断点:** 可以在 `module.wasm` 的某个偏移量设置断点，当执行到该位置时，GDB 会中断程序。
*   **查看调用栈:** 可以查看当前 WebAssembly 代码的调用栈，了解函数的调用关系。
*   **查看局部变量和全局变量:** 可以检查 WebAssembly 函数的局部变量和全局变量的值。
*   **查看内存:** 可以查看 WebAssembly 线性内存中的数据。

**代码逻辑推理示例**

让我们看一个 `GetCallStack` 函数的简化逻辑推理：

**假设输入:**

*   `debug_context_id = 1`
*   V8 引擎当前执行的调用栈包含以下帧（简化表示）：
    1. JavaScript 函数 `runWasm`
    2. WebAssembly 函数 `add` (来自 `module.wasm`)

**预期输出:**

一个 `std::vector<wasm_addr_t>`，其中包含 WebAssembly 帧的信息。例如：

```
[{script_id: <module.wasm 的 script id>, offset: <add 函数的入口偏移量>}]
```

**解释:**

`GetCallStack` 函数会遍历当前的调用栈。当遇到 WebAssembly 帧时，它会提取该帧对应的脚本 ID 和代码偏移量。  `script_id` 可以通过 `script->id()` 获取，而 `offset` 需要从 `FrameSummary` 中获取，并可能需要根据是否为栈顶帧进行调整（通过 `ReturnPc`）。最终返回一个包含 WebAssembly 调用栈信息的向量。

**用户常见的编程错误示例**

在与 V8 和 WebAssembly 调试相关的场景中，用户可能会遇到以下编程错误：

1. **断点设置在错误的偏移量:**  用户可能不熟悉 WebAssembly 的字节码结构，导致断点设置在指令的中间或无效的位置，从而无法触发断点。

    ```c++
    // 错误示例：假设 'offset' 不是一个有效指令的起始位置
    wasm_module_debug->AddBreakpoint(offset, &breakpoint_id);
    ```

2. **访问越界的内存地址:**  在调试过程中，用户可能尝试读取超出 WebAssembly 线性内存范围的地址，导致错误。

    ```c++
    uint8_t buffer[10];
    uint32_t offset = 0xFFFFFFFF; // 假设超出内存大小
    uint32_t bytes_read = wasm_module_debug->GetWasmMemory(isolate, offset, buffer, 10);
    // bytes_read 可能为 0，或者程序可能崩溃
    ```

3. **使用错误的帧索引:**  在查看局部变量或栈值时，用户可能使用了错误的帧索引，导致访问到不相关的变量或导致错误。

    ```c++
    uint8_t buffer[32];
    uint32_t size;
    uint32_t frame_index = 100; // 假设调用栈深度小于 100
    bool success = WasmModuleDebug::GetWasmLocal(isolate, frame_index, 0, buffer, sizeof(buffer), &size);
    // success 可能为 false
    ```

4. **缓冲区大小不足:**  在读取变量值或内存时，提供的缓冲区可能太小，无法容纳实际的数据，导致数据被截断。

    ```c++
    uint8_t buffer[4]; // 假设要读取一个 64 位的整数
    uint32_t size;
    bool success = WasmModuleDebug::GetWasmGlobal(isolate, 0, global_index, buffer, sizeof(buffer), &size);
    // success 可能为 true，但 buffer 中的数据可能不完整
    ```

这些错误通常需要在调试过程中仔细检查偏移量、索引和缓冲区大小，并理解 WebAssembly 的内存模型和调用栈结构。`wasm-module-debug.cc` 提供的功能正是为了帮助开发者有效地进行这种检查和调试。

### 提示词
```
这是目录为v8/src/debug/wasm/gdb-server/wasm-module-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/wasm/gdb-server/wasm-module-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```