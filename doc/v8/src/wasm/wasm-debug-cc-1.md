Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Initial Scan for Keywords and Structure:**  I'd first quickly scan the code for obvious keywords related to debugging: `DebugInfo`, `Breakpoint`, `Step`, `WasmFrame`, `Script`, `Isolate`, `pc`, `fp`, etc. The presence of these strongly suggests the file's purpose is related to debugging WebAssembly code within V8. The overall structure with classes and methods also reinforces this.

2. **Focus on the `DebugInfo` Class:** The class named `DebugInfo` is central. I'd look at its public methods. These methods likely represent the primary functionalities exposed by this part of the debugging system. I'd make a list of these methods and try to infer their purpose from their names and arguments:

    * `GetNumLocals`:  Likely retrieves the number of local variables at a given program counter (`pc`).
    * `GetLocalValue`:  Retrieves the value of a specific local variable at a given `pc` and frame pointer (`fp`). The `debug_break_fp` argument hints at potential differences during breakpoint stops.
    * `GetStackDepth`:  Determines the current call stack depth at a given `pc`.
    * `GetStackValue`:  Retrieves a value from the call stack at a specific index.
    * `GetFunctionAtAddress`:  Maps a program counter to the corresponding WebAssembly function.
    * `SetBreakpoint`: Sets a breakpoint at a specific function index and offset.
    * `IsFrameBlackboxed`: Checks if a given call frame should be treated as "blackboxed" (not stepped into).
    * `PrepareStep`, `PrepareStepOutTo`, `ClearStepping`, `IsStepping`: These are clearly related to step-by-step debugging.
    * `RemoveBreakpoint`: Removes a breakpoint.
    * `RemoveDebugSideTables`:  Likely cleans up data structures used for debugging.
    * `GetDebugSideTableIfExists`: Retrieves debugging information associated with compiled code.
    * `RemoveIsolate`:  Handles cleanup when an isolate is destroyed.
    * `EstimateCurrentMemoryConsumption`: Provides an estimate of the memory used by this debugging component.

3. **Examine Helper Functions and Namespaces:** The code also has a nested anonymous namespace with functions like `FindNextBreakablePosition` and `SetBreakOnEntryFlag`. These appear to be utility functions supporting the main debugging logic. The `wasm` namespace at the top clearly indicates this code is specifically for WebAssembly debugging.

4. **Analyze `WasmScript` Static Methods:** The static methods within `WasmScript` (e.g., `SetBreakPoint`, `ClearBreakPoint`, `GetPossibleBreakpoints`, `CheckBreakPoints`, `AddBreakpointToInfo`) provide a higher-level interface for interacting with breakpoints. They operate on `Script` objects, which represent the compiled WebAssembly module.

5. **Look for Connections to JavaScript:**  The snippet mentions `Tagged<Script>`, which links to V8's internal representation of JavaScript scripts. The `SetBreakOnEntryFlag` function specifically updates properties on `WasmInstanceObject`, which are used when executing WebAssembly from JavaScript. This signifies an interaction between JavaScript debugging and WebAssembly debugging.

6. **Identify Potential User Errors:** The logic around setting breakpoints (finding breakable positions, handling on-entry breakpoints) suggests potential user errors like trying to set breakpoints at non-executable locations or misunderstanding how "break on entry" works.

7. **Trace Code Logic (Mental Execution):** For methods like `FindBreakpointInfoInsertPos` and `AddBreakpointToInfo`, I would mentally trace the execution with hypothetical inputs (e.g., an empty breakpoint list, a breakpoint in the middle, a breakpoint at the beginning/end). This helps understand the data structures and algorithms used.

8. **Infer Data Structures:**  The code uses `FixedArray` to store breakpoint information. The `BreakPointInfo` class likely holds details about breakpoints at a specific location. The structure of `DebugInfoImpl` with `per_isolate_data_` suggests that debugging information is managed per isolate.

9. **Formulate Functional Summary:** Based on the above analysis, I'd start summarizing the core functions of `wasm-debug.cc`. The key points would be: managing breakpoints, handling stepping, providing access to local variables and stack values, and interacting with the JavaScript debugging infrastructure.

10. **Address Specific Instructions:** Finally, I would go back to the original prompt and address each point specifically:

    * **Functionality List:**  Create a bulleted list based on the analysis of `DebugInfo` methods and `WasmScript` static methods.
    * **Torque Source:** Check the file extension. Since it's `.cc`, it's C++, not Torque.
    * **JavaScript Relationship:** Explain how `WasmScript` methods are used from the JavaScript debugging API and provide a simple JavaScript example of setting a breakpoint.
    * **Code Logic Inference:** Choose a method with clear logic (like `FindBreakpointInfoInsertPos`) and provide example inputs and the expected output.
    * **Common Programming Errors:**  Think about scenarios where users might misuse the debugging API, like trying to set breakpoints at invalid locations.
    * **Overall Summary:**  Synthesize the key functionalities into a concise summary.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file just handles breakpoint setting.
* **Correction:**  Looking at the `DebugInfo` class, it also handles stepping, accessing local/stack variables, indicating a broader debugging scope.
* **Initial thought:** The JavaScript interaction might be very complex.
* **Correction:** Focusing on the `WasmScript` methods called from the JavaScript debugging API clarifies the interaction. The example can be kept simple to illustrate the concept.

By following these steps, combining static analysis of the code with an understanding of debugging concepts, and iteratively refining the analysis, one can arrive at a comprehensive understanding of the `wasm-debug.cc` file.
好的，让我们来分析一下 `v8/src/wasm/wasm-debug.cc` 这个 V8 源代码文件的功能。

**文件功能归纳:**

`v8/src/wasm/wasm-debug.cc` 文件的主要功能是**为 WebAssembly (Wasm) 模块提供调试支持**。它实现了与 Wasm 代码断点管理、单步执行、检查局部变量和堆栈信息等调试功能相关的核心逻辑。

**具体功能点:**

1. **断点管理:**
   - `DebugInfo::SetBreakpoint`:  允许在指定的 Wasm 函数的特定偏移量处设置断点。
   - `DebugInfo::RemoveBreakpoint`:  移除已设置的断点。
   - `WasmScript::SetBreakPoint`, `WasmScript::SetBreakPointForFunction`, `WasmScript::SetInstrumentationBreakpoint`, `WasmScript::ClearBreakPoint`, `WasmScript::ClearBreakPointById`, `WasmScript::ClearAllBreakpoints`:  提供了更高级别的接口来管理 Wasm 脚本中的断点，例如根据源代码位置设置断点、设置入口断点、清除断点等。
   - `WasmScript::GetPossibleBreakpoints`:  获取指定代码范围内的所有可能的断点位置。
   - `WasmScript::CheckBreakPoints`:  当执行到某个位置时，检查是否命中了断点，并执行断点相关的操作（例如，检查条件断点）。

2. **单步执行控制:**
   - `DebugInfo::PrepareStep`:  为单步执行做准备。
   - `DebugInfo::PrepareStepOutTo`:  为跳出当前函数做准备。
   - `DebugInfo::ClearStepping`:  清除单步执行状态。
   - `DebugInfo::IsStepping`:  检查当前是否处于单步执行状态。

3. **运行时状态检查:**
   - `DebugInfo::GetNumLocals`:  获取程序计数器 (PC) 所在位置的局部变量数量。
   - `DebugInfo::GetLocalValue`:  获取指定局部变量在特定 PC 和栈帧指针 (FP) 处的值。
   - `DebugInfo::GetStackDepth`:  获取程序计数器 (PC) 处的调用栈深度。
   - `DebugInfo::GetStackValue`:  获取调用栈中指定索引处的值。
   - `DebugInfo::GetFunctionAtAddress`:  根据程序计数器 (PC) 获取对应的 Wasm 函数信息。

4. **其他调试辅助功能:**
   - `DebugInfo::IsFrameBlackboxed`:  判断给定的 Wasm 栈帧是否被标记为 "黑盒" (例如，不希望进入其内部进行调试)。
   - `DebugInfo::RemoveDebugSideTables`:  移除调试相关的辅助数据结构。
   - `DebugInfo::GetDebugSideTableIfExists`:  获取调试辅助表，如果存在。
   - `DebugInfo::EstimateCurrentMemoryConsumption`:  估计当前调试信息占用的内存。

5. **与 JavaScript 调试的集成:**
   - `WasmScript` 类的方法与 V8 的 JavaScript 调试基础设施紧密集成，允许通过 JavaScript 调试 API 来控制和检查 Wasm 代码。

**关于文件后缀 `.cc`:**

如果 `v8/src/wasm/wasm-debug.cc` 的后缀是 `.cc`，那么它是一个 **C++ 源代码文件**。V8 的大部分代码都是用 C++ 编写的。`.tq` 后缀通常用于 V8 的 Torque 语言，这是一种用于生成高效 TurboFan 代码的领域特定语言。

**与 JavaScript 的功能关系 (及示例):**

`v8/src/wasm/wasm-debug.cc` 中的功能是通过 V8 的 JavaScript 调试 API 暴露给开发者的。开发者可以使用 Chrome DevTools 或 Node.js 的调试器来与 Wasm 代码进行交互。

**JavaScript 示例:**

```javascript
// 假设你有一个编译好的 WebAssembly 模块实例
const wasmInstance = // ... 你的 Wasm 实例 ...

// 获取 Wasm 模块的 Script 对象 (V8 内部表示)
const script = wasmInstance.constructor.module.script;

// 在 Wasm 模块的指定位置设置断点 (假设偏移量 10 是一个有效的断点位置)
// 注意：实际操作中，你需要根据 Wasm 模块的结构来确定断点位置
script.setBreakpoint(10);

// 或者，你可以根据行列号设置断点 (如果 Source Map 可用)
// debugger; // 触发断点，然后可以在 DevTools 中设置断点

// 运行 Wasm 代码，当执行到断点时会暂停
wasmInstance.exports.someFunction();

// 在断点处，你可以在 DevTools 中检查局部变量、调用堆栈等。
```

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `WasmScript::SetBreakPoint` 函数，并且有以下输入：

* **`script`**: 一个指向已编译 Wasm 模块的 `Script` 对象的句柄。
* **`position`**:  一个整数，表示 Wasm 模块中的一个字节偏移量，例如 `100`。
* **`break_point`**: 一个指向新创建的 `BreakPoint` 对象的句柄。

**代码逻辑推断 (简化版):**

1. **查找函数:**  `GetContainingWasmFunction` 函数会被调用，根据 `position` (100) 找到该偏移量所在的 Wasm 函数。假设找到的函数索引是 `func_index = 2`。
2. **计算函数内偏移:** 计算 `position` 在函数内部的偏移量：`offset_in_func = 100 - function[2].code.offset()`。
3. **查找可断点位置:**  `FindNextBreakablePosition` 函数会被调用，根据 `func_index` 和 `offset_in_func` 找到下一个有效的可断点指令的偏移量。 假设返回值为 `breakable_offset = 5`。
4. **更新断点位置:** 原始的 `position` 可能会被更新为实际的可断点位置：`*position = function[2].code.offset() + 5`。
5. **设置断点 (DebugInfo):** 调用 `native_module->GetDebugInfo()->SetBreakpoint(2, 5, isolate)`，通知底层的调试信息管理器在函数索引 2 的偏移量 5 处设置断点。
6. **添加断点信息:**  调用 `AddBreakpointToInfo` 将断点信息添加到 `script` 对象的 `wasm_breakpoint_infos` 数组中，以便跟踪所有已设置的断点。

**输出:**  如果断点设置成功，`WasmScript::SetBreakPoint` 返回 `true`。当 Wasm 代码执行到函数 2 的偏移量 5 时，调试器会暂停执行。

**用户常见的编程错误举例:**

1. **尝试在无效位置设置断点:** 用户可能会尝试在 Wasm 指令之间或函数定义之外的位置设置断点。`FindNextBreakablePosition` 函数会尝试找到最近的可断点位置，如果找不到则断点设置会失败。
   ```javascript
   // 错误示例：假设偏移量 11 不是一个可断点的位置
   script.setBreakpoint(11); // 可能会失败
   ```

2. **不理解 Wasm 偏移量:**  用户可能不清楚 Wasm 模块的字节码结构，导致设置断点的偏移量不正确。工具（如 `wasm-objdump`）可以帮助理解 Wasm 模块的结构。

3. **在异步操作中设置断点:**  如果 Wasm 代码是通过异步操作调用的，用户可能需要在异步操作完成后的回调中检查断点是否命中。

4. **条件断点中的错误:**  如果条件断点中的 JavaScript 表达式有错误，可能会导致调试器行为异常或无法正常命中断点。

**总结 `v8/src/wasm/wasm-debug.cc` 的功能 (作为第 2 部分的归纳):**

作为第二部分，对 `v8/src/wasm/wasm-debug.cc` 的功能进行归纳，可以强调以下几点：

* **核心调试能力:** 该文件是 V8 中 WebAssembly 调试功能的核心实现，提供了设置、移除、管理断点以及控制单步执行的关键机制。
* **运行时检查:** 它允许调试器在运行时检查 Wasm 代码的状态，包括局部变量、堆栈信息以及当前执行的函数。
* **JavaScript 集成桥梁:**  `wasm-debug.cc` 通过 `WasmScript` 类的方法，将底层的 Wasm 调试功能与 V8 的 JavaScript 调试框架连接起来，使得开发者可以使用熟悉的 JavaScript 调试工具来调试 Wasm 代码。
* **底层实现细节:** 该文件包含了处理 Wasm 模块结构、查找可断点位置、管理断点信息等底层的实现细节。
* **为开发者提供支持:**  最终目标是为 WebAssembly 开发者提供强大的调试工具，帮助他们理解和调试自己的 Wasm 代码。

总而言之，`v8/src/wasm/wasm-debug.cc` 是 V8 引擎中实现 WebAssembly 调试支持的关键组件，负责处理与断点、单步执行和运行时状态检查相关的核心逻辑，并与 JavaScript 调试基础设施紧密集成。

Prompt: 
```
这是目录为v8/src/wasm/wasm-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ata> per_isolate_data_;
};

DebugInfo::DebugInfo(NativeModule* native_module)
    : impl_(std::make_unique<DebugInfoImpl>(native_module)) {}

DebugInfo::~DebugInfo() = default;

int DebugInfo::GetNumLocals(Address pc, Isolate* isolate) {
  return impl_->GetNumLocals(pc, isolate);
}

WasmValue DebugInfo::GetLocalValue(int local, Address pc, Address fp,
                                   Address debug_break_fp, Isolate* isolate) {
  return impl_->GetLocalValue(local, pc, fp, debug_break_fp, isolate);
}

int DebugInfo::GetStackDepth(Address pc, Isolate* isolate) {
  return impl_->GetStackDepth(pc, isolate);
}

WasmValue DebugInfo::GetStackValue(int index, Address pc, Address fp,
                                   Address debug_break_fp, Isolate* isolate) {
  return impl_->GetStackValue(index, pc, fp, debug_break_fp, isolate);
}

const wasm::WasmFunction& DebugInfo::GetFunctionAtAddress(Address pc,
                                                          Isolate* isolate) {
  return impl_->GetFunctionAtAddress(pc, isolate);
}

void DebugInfo::SetBreakpoint(int func_index, int offset,
                              Isolate* current_isolate) {
  impl_->SetBreakpoint(func_index, offset, current_isolate);
}

bool DebugInfo::IsFrameBlackboxed(WasmFrame* frame) {
  return impl_->IsFrameBlackboxed(frame);
}

bool DebugInfo::PrepareStep(WasmFrame* frame) {
  return impl_->PrepareStep(frame);
}

void DebugInfo::PrepareStepOutTo(WasmFrame* frame) {
  impl_->PrepareStepOutTo(frame);
}

void DebugInfo::ClearStepping(Isolate* isolate) {
  impl_->ClearStepping(isolate);
}

void DebugInfo::ClearStepping(WasmFrame* frame) { impl_->ClearStepping(frame); }

bool DebugInfo::IsStepping(WasmFrame* frame) {
  return impl_->IsStepping(frame);
}

void DebugInfo::RemoveBreakpoint(int func_index, int offset,
                                 Isolate* current_isolate) {
  impl_->RemoveBreakpoint(func_index, offset, current_isolate);
}

void DebugInfo::RemoveDebugSideTables(base::Vector<WasmCode* const> code) {
  impl_->RemoveDebugSideTables(code);
}

DebugSideTable* DebugInfo::GetDebugSideTableIfExists(
    const WasmCode* code) const {
  return impl_->GetDebugSideTableIfExists(code);
}

void DebugInfo::RemoveIsolate(Isolate* isolate) {
  return impl_->RemoveIsolate(isolate);
}

size_t DebugInfo::EstimateCurrentMemoryConsumption() const {
  return impl_->EstimateCurrentMemoryConsumption();
}

}  // namespace wasm

namespace {

// Return the next breakable position at or after {offset_in_func} in function
// {func_index}, or 0 if there is none.
// Note that 0 is never a breakable position in wasm, since the first uint8_t
// contains the locals count for the function.
int FindNextBreakablePosition(wasm::NativeModule* native_module, int func_index,
                              int offset_in_func) {
  Zone zone{wasm::GetWasmEngine()->allocator(), ZONE_NAME};
  wasm::BodyLocalDecls locals;
  const uint8_t* module_start = native_module->wire_bytes().begin();
  const wasm::WasmFunction& func =
      native_module->module()->functions[func_index];
  wasm::BytecodeIterator iterator(module_start + func.code.offset(),
                                  module_start + func.code.end_offset(),
                                  &locals, &zone);
  DCHECK_LT(0, locals.encoded_size);
  if (offset_in_func < 0) return 0;
  for (; iterator.has_next(); iterator.next()) {
    if (iterator.pc_offset() < static_cast<uint32_t>(offset_in_func)) continue;
    if (!wasm::WasmOpcodes::IsBreakable(iterator.current())) continue;
    return static_cast<int>(iterator.pc_offset());
  }
  return 0;
}

void SetBreakOnEntryFlag(Tagged<Script> script, bool enabled) {
  if (script->break_on_entry() == enabled) return;

  script->set_break_on_entry(enabled);
  // Update the "break_on_entry" flag on all live instances.
  i::Tagged<i::WeakArrayList> weak_instance_list =
      script->wasm_weak_instance_list();
  i::Isolate* isolate = script->GetIsolate();
  for (int i = 0; i < weak_instance_list->length(); ++i) {
    if (weak_instance_list->Get(i).IsCleared()) continue;
    i::Tagged<i::WasmInstanceObject> instance = i::Cast<i::WasmInstanceObject>(
        weak_instance_list->Get(i).GetHeapObject());
    instance->trusted_data(isolate)->set_break_on_entry(enabled);
  }
}
}  // namespace

// static
bool WasmScript::SetBreakPoint(DirectHandle<Script> script, int* position,
                               DirectHandle<BreakPoint> break_point) {
  DCHECK_NE(kOnEntryBreakpointPosition, *position);

  // Find the function for this breakpoint.
  const wasm::WasmModule* module = script->wasm_native_module()->module();
  int func_index = GetContainingWasmFunction(module, *position);
  if (func_index < 0) return false;
  const wasm::WasmFunction& func = module->functions[func_index];
  int offset_in_func = *position - func.code.offset();

  int breakable_offset = FindNextBreakablePosition(script->wasm_native_module(),
                                                   func_index, offset_in_func);
  if (breakable_offset == 0) return false;
  *position = func.code.offset() + breakable_offset;

  return WasmScript::SetBreakPointForFunction(script, func_index,
                                              breakable_offset, break_point);
}

// static
void WasmScript::SetInstrumentationBreakpoint(
    DirectHandle<Script> script, DirectHandle<BreakPoint> break_point) {
  // Special handling for on-entry breakpoints.
  AddBreakpointToInfo(script, kOnEntryBreakpointPosition, break_point);

  // Update the "break_on_entry" flag on all live instances.
  SetBreakOnEntryFlag(*script, true);
}

// static
bool WasmScript::SetBreakPointOnFirstBreakableForFunction(
    DirectHandle<Script> script, int func_index,
    DirectHandle<BreakPoint> break_point) {
  if (func_index < 0) return false;
  int offset_in_func = 0;

  int breakable_offset = FindNextBreakablePosition(script->wasm_native_module(),
                                                   func_index, offset_in_func);
  if (breakable_offset == 0) return false;
  return WasmScript::SetBreakPointForFunction(script, func_index,
                                              breakable_offset, break_point);
}

// static
bool WasmScript::SetBreakPointForFunction(
    DirectHandle<Script> script, int func_index, int offset,
    DirectHandle<BreakPoint> break_point) {
  Isolate* isolate = script->GetIsolate();

  DCHECK_LE(0, func_index);
  DCHECK_NE(0, offset);

  // Find the function for this breakpoint.
  wasm::NativeModule* native_module = script->wasm_native_module();
  const wasm::WasmModule* module = native_module->module();
  const wasm::WasmFunction& func = module->functions[func_index];

  // Insert new break point into {wasm_breakpoint_infos} of the script.
  AddBreakpointToInfo(script, func.code.offset() + offset, break_point);

  native_module->GetDebugInfo()->SetBreakpoint(func_index, offset, isolate);

  return true;
}

namespace {

int GetBreakpointPos(Isolate* isolate,
                     Tagged<Object> break_point_info_or_undef) {
  if (IsUndefined(break_point_info_or_undef, isolate)) return kMaxInt;
  return Cast<BreakPointInfo>(break_point_info_or_undef)->source_position();
}

int FindBreakpointInfoInsertPos(Isolate* isolate,
                                DirectHandle<FixedArray> breakpoint_infos,
                                int position) {
  // Find insert location via binary search, taking care of undefined values on
  // the right. {position} is either {kOnEntryBreakpointPosition} (which is -1),
  // or positive.
  DCHECK(position == WasmScript::kOnEntryBreakpointPosition || position > 0);

  int left = 0;                            // inclusive
  int right = breakpoint_infos->length();  // exclusive
  while (right - left > 1) {
    int mid = left + (right - left) / 2;
    Tagged<Object> mid_obj = breakpoint_infos->get(mid);
    if (GetBreakpointPos(isolate, mid_obj) <= position) {
      left = mid;
    } else {
      right = mid;
    }
  }

  int left_pos = GetBreakpointPos(isolate, breakpoint_infos->get(left));
  return left_pos < position ? left + 1 : left;
}

}  // namespace

// static
bool WasmScript::ClearBreakPoint(DirectHandle<Script> script, int position,
                                 DirectHandle<BreakPoint> break_point) {
  if (!script->has_wasm_breakpoint_infos()) return false;

  Isolate* isolate = script->GetIsolate();
  DirectHandle<FixedArray> breakpoint_infos(script->wasm_breakpoint_infos(),
                                            isolate);

  int pos = FindBreakpointInfoInsertPos(isolate, breakpoint_infos, position);

  // Does a BreakPointInfo object already exist for this position?
  if (pos == breakpoint_infos->length()) return false;

  DirectHandle<BreakPointInfo> info(
      Cast<BreakPointInfo>(breakpoint_infos->get(pos)), isolate);
  BreakPointInfo::ClearBreakPoint(isolate, info, break_point);

  // Check if there are no more breakpoints at this location.
  if (info->GetBreakPointCount(isolate) == 0) {
    // Update array by moving breakpoints up one position.
    for (int i = pos; i < breakpoint_infos->length() - 1; i++) {
      Tagged<Object> entry = breakpoint_infos->get(i + 1);
      breakpoint_infos->set(i, entry);
      if (IsUndefined(entry, isolate)) break;
    }
    // Make sure last array element is empty as a result.
    breakpoint_infos->set(breakpoint_infos->length() - 1,
                          ReadOnlyRoots{isolate}.undefined_value(),
                          SKIP_WRITE_BARRIER);
  }

  if (break_point->id() == v8::internal::Debug::kInstrumentationId) {
    // Special handling for instrumentation breakpoints.
    SetBreakOnEntryFlag(*script, false);
  } else {
    // Remove the breakpoint from DebugInfo and recompile.
    wasm::NativeModule* native_module = script->wasm_native_module();
    const wasm::WasmModule* module = native_module->module();
    int func_index = GetContainingWasmFunction(module, position);
    native_module->GetDebugInfo()->RemoveBreakpoint(func_index, position,
                                                    isolate);
  }

  return true;
}

// static
bool WasmScript::ClearBreakPointById(DirectHandle<Script> script,
                                     int breakpoint_id) {
  if (!script->has_wasm_breakpoint_infos()) {
    return false;
  }
  Isolate* isolate = script->GetIsolate();
  DirectHandle<FixedArray> breakpoint_infos(script->wasm_breakpoint_infos(),
                                            isolate);
  // If the array exists, it should not be empty.
  DCHECK_LT(0, breakpoint_infos->length());

  for (int i = 0, e = breakpoint_infos->length(); i < e; ++i) {
    DirectHandle<Object> obj(breakpoint_infos->get(i), isolate);
    if (IsUndefined(*obj, isolate)) {
      continue;
    }
    auto breakpoint_info = Cast<BreakPointInfo>(obj);
    Handle<BreakPoint> breakpoint;
    if (BreakPointInfo::GetBreakPointById(isolate, breakpoint_info,
                                          breakpoint_id)
            .ToHandle(&breakpoint)) {
      DCHECK(breakpoint->id() == breakpoint_id);
      return WasmScript::ClearBreakPoint(
          script, breakpoint_info->source_position(), breakpoint);
    }
  }
  return false;
}

// static
void WasmScript::ClearAllBreakpoints(Tagged<Script> script) {
  script->set_wasm_breakpoint_infos(
      ReadOnlyRoots(script->GetIsolate()).empty_fixed_array());
  SetBreakOnEntryFlag(script, false);
}

// static
void WasmScript::AddBreakpointToInfo(DirectHandle<Script> script, int position,
                                     DirectHandle<BreakPoint> break_point) {
  Isolate* isolate = script->GetIsolate();
  DirectHandle<FixedArray> breakpoint_infos;
  if (script->has_wasm_breakpoint_infos()) {
    breakpoint_infos = direct_handle(script->wasm_breakpoint_infos(), isolate);
  } else {
    breakpoint_infos =
        isolate->factory()->NewFixedArray(4, AllocationType::kOld);
    script->set_wasm_breakpoint_infos(*breakpoint_infos);
  }

  int insert_pos =
      FindBreakpointInfoInsertPos(isolate, breakpoint_infos, position);

  // If a BreakPointInfo object already exists for this position, add the new
  // breakpoint object and return.
  if (insert_pos < breakpoint_infos->length() &&
      GetBreakpointPos(isolate, breakpoint_infos->get(insert_pos)) ==
          position) {
    DirectHandle<BreakPointInfo> old_info(
        Cast<BreakPointInfo>(breakpoint_infos->get(insert_pos)), isolate);
    BreakPointInfo::SetBreakPoint(isolate, old_info, break_point);
    return;
  }

  // Enlarge break positions array if necessary.
  bool need_realloc = !IsUndefined(
      breakpoint_infos->get(breakpoint_infos->length() - 1), isolate);
  DirectHandle<FixedArray> new_breakpoint_infos = breakpoint_infos;
  if (need_realloc) {
    new_breakpoint_infos = isolate->factory()->NewFixedArray(
        2 * breakpoint_infos->length(), AllocationType::kOld);
    script->set_wasm_breakpoint_infos(*new_breakpoint_infos);
    // Copy over the entries [0, insert_pos).
    for (int i = 0; i < insert_pos; ++i)
      new_breakpoint_infos->set(i, breakpoint_infos->get(i));
  }

  // Move elements [insert_pos, ...] up by one.
  for (int i = breakpoint_infos->length() - 1; i >= insert_pos; --i) {
    Tagged<Object> entry = breakpoint_infos->get(i);
    if (IsUndefined(entry, isolate)) continue;
    new_breakpoint_infos->set(i + 1, entry);
  }

  // Generate new BreakpointInfo.
  DirectHandle<BreakPointInfo> breakpoint_info =
      isolate->factory()->NewBreakPointInfo(position);
  BreakPointInfo::SetBreakPoint(isolate, breakpoint_info, break_point);

  // Now insert new position at insert_pos.
  new_breakpoint_infos->set(insert_pos, *breakpoint_info);
}

// static
bool WasmScript::GetPossibleBreakpoints(
    wasm::NativeModule* native_module, const v8::debug::Location& start,
    const v8::debug::Location& end,
    std::vector<v8::debug::BreakLocation>* locations) {
  DisallowGarbageCollection no_gc;

  const wasm::WasmModule* module = native_module->module();
  const std::vector<wasm::WasmFunction>& functions = module->functions;

  if (start.GetLineNumber() != 0 || start.GetColumnNumber() < 0 ||
      (!end.IsEmpty() &&
       (end.GetLineNumber() != 0 || end.GetColumnNumber() < 0 ||
        end.GetColumnNumber() < start.GetColumnNumber())))
    return false;

  // start_func_index, start_offset and end_func_index is inclusive.
  // end_offset is exclusive.
  // start_offset and end_offset are module-relative byte offsets.
  // We set strict to false because offsets may be between functions.
  int start_func_index =
      GetNearestWasmFunction(module, start.GetColumnNumber());
  if (start_func_index < 0) return false;
  uint32_t start_offset = start.GetColumnNumber();
  int end_func_index;
  uint32_t end_offset;

  if (end.IsEmpty()) {
    // Default: everything till the end of the Script.
    end_func_index = static_cast<uint32_t>(functions.size() - 1);
    end_offset = functions[end_func_index].code.end_offset();
  } else {
    // If end is specified: Use it and check for valid input.
    end_offset = end.GetColumnNumber();
    end_func_index = GetNearestWasmFunction(module, end_offset);
    DCHECK_GE(end_func_index, start_func_index);
  }

  if (start_func_index == end_func_index &&
      start_offset > functions[end_func_index].code.end_offset())
    return false;
  Zone zone{wasm::GetWasmEngine()->allocator(), ZONE_NAME};
  const uint8_t* module_start = native_module->wire_bytes().begin();

  for (int func_idx = start_func_index; func_idx <= end_func_index;
       ++func_idx) {
    const wasm::WasmFunction& func = functions[func_idx];
    if (func.code.length() == 0) continue;

    wasm::BodyLocalDecls locals;
    wasm::BytecodeIterator iterator(module_start + func.code.offset(),
                                    module_start + func.code.end_offset(),
                                    &locals, &zone);
    DCHECK_LT(0u, locals.encoded_size);
    for (; iterator.has_next(); iterator.next()) {
      uint32_t total_offset = func.code.offset() + iterator.pc_offset();
      if (total_offset >= end_offset) {
        DCHECK_EQ(end_func_index, func_idx);
        break;
      }
      if (total_offset < start_offset) continue;
      if (!wasm::WasmOpcodes::IsBreakable(iterator.current())) continue;
      locations->emplace_back(0, total_offset, debug::kCommonBreakLocation);
    }
  }
  return true;
}

namespace {

bool CheckBreakPoint(Isolate* isolate, DirectHandle<BreakPoint> break_point,
                     StackFrameId frame_id) {
  if (break_point->condition()->length() == 0) return true;

  HandleScope scope(isolate);
  Handle<String> condition(break_point->condition(), isolate);
  Handle<Object> result;
  // The Wasm engine doesn't perform any sort of inlining.
  const int inlined_jsframe_index = 0;
  const bool throw_on_side_effect = false;
  if (!DebugEvaluate::Local(isolate, frame_id, inlined_jsframe_index, condition,
                            throw_on_side_effect)
           .ToHandle(&result)) {
    isolate->clear_exception();
    return false;
  }
  return Object::BooleanValue(*result, isolate);
}

}  // namespace

// static
MaybeHandle<FixedArray> WasmScript::CheckBreakPoints(
    Isolate* isolate, DirectHandle<Script> script, int position,
    StackFrameId frame_id) {
  if (!script->has_wasm_breakpoint_infos()) return {};

  DirectHandle<FixedArray> breakpoint_infos(script->wasm_breakpoint_infos(),
                                            isolate);
  int insert_pos =
      FindBreakpointInfoInsertPos(isolate, breakpoint_infos, position);
  if (insert_pos >= breakpoint_infos->length()) return {};

  DirectHandle<Object> maybe_breakpoint_info(breakpoint_infos->get(insert_pos),
                                             isolate);
  if (IsUndefined(*maybe_breakpoint_info, isolate)) return {};
  auto breakpoint_info = Cast<BreakPointInfo>(maybe_breakpoint_info);
  if (breakpoint_info->source_position() != position) return {};

  DirectHandle<Object> break_points(breakpoint_info->break_points(), isolate);
  if (!IsFixedArray(*break_points)) {
    if (!CheckBreakPoint(isolate, Cast<BreakPoint>(break_points), frame_id)) {
      // A breakpoint that doesn't break mutes traps. (Rule enables the
      // "Never Pause Here" feature.)
      isolate->debug()->SetMutedWasmLocation(script, position);
      return {};
    }
    // If breakpoint does fire, clear any prior muting behavior.
    isolate->debug()->ClearMutedLocation();
    Handle<FixedArray> break_points_hit = isolate->factory()->NewFixedArray(1);
    break_points_hit->set(0, *break_points);
    return break_points_hit;
  }

  auto array = Cast<FixedArray>(break_points);
  Handle<FixedArray> break_points_hit =
      isolate->factory()->NewFixedArray(array->length());
  int break_points_hit_count = 0;
  for (int i = 0; i < array->length(); ++i) {
    DirectHandle<BreakPoint> break_point(Cast<BreakPoint>(array->get(i)),
                                         isolate);
    if (CheckBreakPoint(isolate, break_point, frame_id)) {
      break_points_hit->set(break_points_hit_count++, *break_point);
    }
  }
  if (break_points_hit_count == 0) return {};
  break_points_hit->RightTrim(isolate, break_points_hit_count);
  return break_points_hit;
}

}  // namespace internal
}  // namespace v8

"""


```