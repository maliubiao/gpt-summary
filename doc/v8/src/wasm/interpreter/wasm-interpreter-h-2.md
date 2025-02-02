Response:
Let's break down the thought process for analyzing this C++ header file and fulfilling the user's request.

**1. Initial Scan and Keyword Identification:**

First, I scanned the code for immediately recognizable keywords and patterns. This helps to quickly get a general sense of the file's purpose. Keywords that stood out included:

* `namespace wasm`, `namespace internal`, `namespace v8`: This immediately tells us it's part of the V8 JavaScript engine's WebAssembly implementation.
* `WasmInterpreterRuntime`, `WasmBytecodeGenerator`, `InterpreterCode`:  These suggest components related to interpreting WebAssembly bytecode.
* `stack_`, `slots_`, `PushSlot`, `PopSlot`:  These clearly indicate a stack-based architecture or a mechanism for managing local variables and temporary values.
* `const_slots_`, `GetConstSlot`, `CreateConstSlot`:  These point to a system for handling constant values within the WebAssembly code.
* `i32_const_cache_`, `f32_const_cache_`, etc.: These are caches for different types of constants, optimizing lookups.
* `blocks_`, `current_block_index_`:  These likely deal with control flow structures like blocks, loops, and conditional statements.
* `code_`, `code_pc_map_`:  These are related to the generated bytecode and mapping offsets to program counters.
* `#ifdef V8_ENABLE_DRUMBRAKE_TRACING`:  This indicates debugging or tracing features.
* `Simd128`: This suggests support for SIMD (Single Instruction, Multiple Data) operations.
* `ValueType`, `HeapType`: These are type-related, important for WebAssembly's type system.
* `FunctionSig`:  This relates to function signatures (parameters and return types).

**2. High-Level Purpose Deduction:**

Based on the keywords, the file seems to be central to the *interpretation* of WebAssembly code within V8. It likely handles:

* **Bytecode Generation:**  The `WasmBytecodeGenerator` class strongly suggests this. It seems responsible for converting a higher-level representation of WebAssembly into a lower-level bytecode.
* **Stack Management:**  The `stack_` and related methods are crucial for executing stack-based bytecode.
* **Constant Handling:** The `const_slots_` and caching mechanisms are for efficient storage and retrieval of constants.
* **Control Flow:** The `blocks_` and related logic manage the execution of different code blocks.
* **Debugging/Tracing:** The `V8_ENABLE_DRUMBRAKE_TRACING` sections provide insights into debugging and performance analysis features.

**3. Detailed Analysis of Key Classes:**

* **`WasmBytecodeGenerator`:** This is the core of the file. I examined its members and methods in more detail. The methods like `PushConstSlot`, `PushSlot`, `PopSlot`, `CreateSlot`, `CopyToSlot`, and the constant caching mechanisms confirm its role in bytecode generation and stack management. The `blocks_` member and related variables point to control flow handling.
* **`ClearThreadInWasmScope`:**  This appears to be a utility class for managing the thread context when entering or leaving WebAssembly execution.
* **`InterpreterTracer` (under `V8_ENABLE_DRUMBRAKE_TRACING`):** This class is clearly for tracing the execution of the interpreter, useful for debugging and performance analysis.
* **`ShadowStack` (under `V8_ENABLE_DRUMBRAKE_TRACING`):** This seems like a debugging aid, mirroring the actual stack and providing additional information (like types) for debugging.

**4. Functionality Listing (based on the analysis):**

I systematically listed the functionalities based on the identified classes and their members/methods. I grouped related functionalities together for better organization.

**5. Torque Source Check:**

I checked for the `.tq` extension in the filename, as requested. Since it's `.h`, it's not a Torque file.

**6. Relationship to JavaScript:**

I considered how this C++ code relates to JavaScript. WebAssembly is executed within a JavaScript environment. Therefore, this code is responsible for *running* the WebAssembly code that might be loaded and executed by JavaScript. I then crafted a simple JavaScript example to illustrate this.

**7. Code Logic Inference (with Hypotheses):**

I focused on the `CreateConstSlot` function as a good example for illustrating code logic. I made assumptions about the input and followed the steps in the code to deduce the output and the function's purpose.

**8. Common Programming Errors:**

I thought about potential errors a *user* of WebAssembly (writing WebAssembly code) might make that would be handled or revealed by this interpreter code. Type mismatches and stack overflow/underflow are common WebAssembly errors, so I provided examples.

**9. Summarization:**

Finally, I summarized the main purpose of the header file based on the detailed analysis, emphasizing its role in interpreting WebAssembly bytecode and providing supporting functionalities.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file is just about bytecode representation.
* **Correction:** The presence of `WasmInterpreterRuntime` and the stack manipulation methods strongly suggest it's involved in the *execution* (interpretation) of that bytecode, not just its representation.
* **Initial thought:**  The tracing seems like a minor feature.
* **Refinement:** While behind a flag, the level of detail in `InterpreterTracer` and `ShadowStack` suggests it's an important tool for V8 developers debugging and understanding the interpreter.

By following this structured approach, combining keyword analysis, high-level deduction, detailed examination, and logical reasoning, I could effectively understand the purpose and functionality of the provided C++ header file and address all aspects of the user's request.This is the third part of the analysis of the V8 source code file `v8/src/wasm/interpreter/wasm-interpreter.h`. Let's continue breaking down its functionality.

Based on the provided code snippet, here's a breakdown of the functionalities:

**Core Functionalities within `WasmBytecodeGenerator` (continued from previous parts):**

* **Constant Slot Management (Advanced):**
    * **Caching of Constants:** The code utilizes hash maps (`i32_const_cache_`, `i64_const_cache_`, etc.) to store already created constant slots. This avoids redundant creation of slots for the same constant value, improving efficiency.
    * **Retrieving Existing Constant Slots:** The `GetI32ConstSlot`, `GetF32ConstSlot`, etc., functions check if a constant value already has an assigned slot index in the cache.
    * **Creating New Constant Slots (`CreateConstSlot`):**
        * Takes a constant value of a specific type as input.
        * Checks if a slot for this value already exists using the caches.
        * If not found, it allocates a new slot in the `const_slots_values_` vector.
        * It writes the constant value directly into the allocated memory.
        * It updates the corresponding cache with the new slot index.
        * **Important:** It appears `WasmRef` types are explicitly disallowed as constants using `UNREACHABLE()`. This suggests that reference types are handled differently in the constant pool.
    * **Pushing Constant Slots onto the Stack (`PushConstSlot`):**
        * Overloaded function:
            * Takes a constant value as input, calls `CreateConstSlot` to ensure the slot exists, and then pushes the *slot index* onto the `stack_`.
            * Takes a pre-existing slot index and directly pushes it onto the `stack_`.
* **Stack Manipulation:**
    * **Pushing Slots (`PushSlot`, `_PushSlot`):** Adds a slot index to the `stack_`. The `_PushSlot` variant also creates a new slot in the `slots_` array and pushes its index.
    * **Pushing a Copy of a Slot (`PushCopySlot`):** Duplicates a slot index from a given position onto the top of the stack.
    * **Popping Slots (`PopSlot`):** Removes the top slot index from the `stack_`. There's a comment about potential optimization by marking popped slots as invalid for later reuse.
    * **Copying to Slots (`CopyToSlot`, `CopyToSlotAndPop`):**  Copies data from a source slot to a destination slot on the stack. `CopyToSlotAndPop` does this and then pops the source slot.
    * **Setting Slot Types (`SetSlotType`):**  Updates the `value_type` of a slot at a specific stack index.
    * **Updating Stack Entries (`UpdateStack`):** Modifies the slot index at a specific position in the `stack_`. An overload also allows setting the slot's type.
    * **Accessing Stack Information (`stack_top_index`, `stack_size`):** Provides methods to get the index of the top of the stack and the current stack size.
* **Unreachable Code Handling:**
    * **`SetUnreachableMode()`:**  Flags the current instruction stream as unreachable. This is important for optimizations and correctness when dealing with control flow constructs like `br_table` or `if-else` where some branches might be statically known to be unreachable.
* **Function Argument Initialization (`InitSlotsForFunctionArgs`):** Creates slots for function arguments and generates the necessary instructions to initialize them. Handles both direct and indirect calls.
* **Instruction Handler Optimization (`TryCompactInstructionHandler`):**  Potentially tries to optimize the representation of instruction handlers.
* **Type Checking (`TypeCheckAlwaysSucceeds`, `TypeCheckAlwaysFails`):** Functions to determine if a type check will always succeed or fail based on the object's type and the expected type.
* **Internal Data Members:**
    * `const_slots_values_`: Stores the actual values of the constants.
    * `const_slot_offset_`: Keeps track of the next available offset in `const_slots_values_`.
    * Constant Caches (`i32_const_cache_`, etc.):  As described above.
    * `simd_immediates_`: Stores immediate SIMD values.
    * `slot_offset_`:  Likely manages the offset of slots within the stack frame (potential optimization opportunity mentioned in a comment).
    * `stack_`: The main stack holding slot indices.
    * `ref_slots_count_`: Tracks the number of reference type slots.
    * Metadata about the function being processed (`function_index_`, `wasm_code_`, `args_count_`, `return_count_`, `locals_count_`).
    * `code_`:  The generated bytecode.
    * `blocks_`, `current_block_index_`:  Manages control flow blocks.
    * `is_instruction_reachable_`, `unreachable_block_count_`:  Flags for tracking unreachable code.
    * `br_table_labels_`, `loop_end_code_offsets_`:  Data structures for handling branch tables and loops.
    * `module_`:  A pointer to the overall WebAssembly module.
    * `code_pc_map_`:  A map to translate code offsets to program counter values (likely for debugging or error reporting).
    * `last_instr_offset_`: Tracks the offset of the last processed instruction.
    * `eh_data_`:  Likely related to exception handling data generation.

**Additional Classes (related to debugging and context):**

* **`ClearThreadInWasmScope`:**
    * **Purpose:** This class is a RAII (Resource Acquisition Is Initialization) helper. When an instance of this class is created, it performs some action (likely clearing thread-local state related to WebAssembly execution) and when it goes out of scope (its destructor is called), it reverses that action.
    * **Functionality:**  The constructor `ClearThreadInWasmScope(Isolate* isolate)` takes a V8 `Isolate` pointer. The destructor `~ClearThreadInWasmScope()` likely restores the thread's state. This is important for ensuring proper context switching when entering and exiting WebAssembly code.
* **`InterpreterTracer` (under `#ifdef V8_ENABLE_DRUMBRAKE_TRACING`):**
    * **Purpose:**  Provides a mechanism for tracing the execution of the WebAssembly interpreter. This is crucial for debugging, performance analysis, and understanding the interpreter's behavior.
    * **Functionality:**
        * **Filtering:** Allows tracing only specific functions based on their index (`traced_functions_`).
        * **File Output:** Can redirect trace output to a file (`trace-*.dbt`). It manages file creation, closing, and chunking to avoid overly large files.
        * **Printing:** Offers a `PrintF` method for formatted output.
        * **File Size Check:** Periodically checks the trace file size and creates a new chunk if it exceeds a limit.
* **`ShadowStack` (under `#ifdef V8_ENABLE_DRUMBRAKE_TRACING`):**
    * **Purpose:**  Appears to be a debugging aid that maintains a "shadow" stack alongside the actual interpreter stack. This shadow stack can store additional information (like value types) that might not be directly available in the primary stack.
    * **Functionality:**
        * **Tracing Stack Operations:** Methods like `TracePop`, `TracePush`, `TracePushCopy`, and `TraceUpdate` mirror the actual stack operations and update the shadow stack accordingly.
        * **Tracing Slot Types:** `TraceSetSlotType` records the type of a slot.
        * **Printing:**  The `Print` method allows dumping the contents of the shadow stack for debugging purposes, showing value types and slot offsets.

**Is `v8/src/wasm/interpreter/wasm-interpreter.h` a Torque source file?**

No, the file ends with `.h`, which is the standard extension for C++ header files. Torque source files typically end with `.tq`.

**Relationship to JavaScript and Examples:**

This C++ code is the *implementation* of the WebAssembly interpreter within the V8 JavaScript engine. When JavaScript code loads and executes WebAssembly, this C++ code is responsible for actually running the WebAssembly instructions.

**JavaScript Example:**

```javascript
// Load a WebAssembly module (assuming you have a .wasm file)
fetch('my_wasm_module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;
    // Call a function exported from the WebAssembly module
    const result = instance.exports.add(5, 10);
    console.log(result); // Output: 15
  });
```

**Explanation:**

1. The JavaScript code uses the `WebAssembly` API to load and instantiate a WebAssembly module.
2. When `instance.exports.add(5, 10)` is called, the V8 engine (specifically the WebAssembly interpreter implemented by code like in `wasm-interpreter.h`) takes over.
3. The interpreter will:
    * Locate the `add` function within the WebAssembly module's bytecode.
    * Use the `WasmBytecodeGenerator` (or its runtime equivalent) to fetch and process the instructions for the `add` function.
    * Use the stack (`stack_`) to store operands (5 and 10).
    * Execute the WebAssembly instructions (likely an `i32.add`).
    * Store the result (15) back on the stack.
    * Return the result to the JavaScript environment.

**Code Logic Inference Example:**

Let's consider the `CreateConstSlot<int32_t>(int32_t value)` function:

**Assumptions:**

* **Input:** `value = 100`
* The `i32_const_cache_` is initially empty.
* `const_slot_offset_` is initially 0.
* `slots_` is initially empty.
* `const_slots_values_` has enough capacity.

**Output and Steps:**

1. `slot_index = GetConstSlot(value);`  calls `GetI32ConstSlot(100)`.
2. `GetI32ConstSlot(100)` checks `i32_const_cache_`. Since it's empty, the `if` condition fails, and it returns `UINT_MAX`.
3. `slot_index == UINT_MAX` is true.
4. `offset = const_slot_offset_ * sizeof(uint32_t);`  `offset = 0 * 4 = 0`.
5. `DCHECK_LE(offset + sizeof(T), const_slots_values_.size());` (Assertion - assumes enough space).
6. `slot_index = static_cast<uint32_t>(slots_.size());` `slot_index = 0`.
7. `slots_.push_back({value_type<int32_t>(), const_slots_start() + const_slot_offset_, 0});` A new slot is added to `slots_` with type `i32`, offset `const_slots_start() + 0`, and initial flags 0.
8. `base::WriteUnalignedValue<int32_t>(reinterpret_cast<Address>(const_slots_values_.data() + offset), value);` The value `100` is written to the beginning of `const_slots_values_`.
9. `const_slot_offset_ += sizeof(T) / kSlotSize;` Assuming `kSlotSize` is `sizeof(uint32_t)`, then `const_slot_offset_` becomes `0 + 4 / 4 = 1`.
10. The function returns `slot_index`, which is `0`.

**Common Programming Errors (from a WebAssembly developer's perspective) that this code handles or relates to:**

1. **Type Mismatches:** If the WebAssembly code attempts to push a value of the wrong type onto the stack where a specific type is expected, the `SetSlotType` and other type-related checks within this code would detect this error during interpretation.

   **Example (Conceptual WebAssembly):**

   ```wasm
   (local $my_int i32)
   f32.const 3.14  // Push a float onto the stack
   local.set $my_int // Attempt to store the float in an i32 local
   ```

   The interpreter code would likely detect the type mismatch when `local.set` is executed.

2. **Stack Overflow/Underflow:**  Incorrect WebAssembly code might try to pop more values from the stack than are present or push an excessive number of values, leading to stack overflow. The `PushSlot` and `PopSlot` operations, along with stack size checks, are crucial for detecting these errors.

   **Example (Conceptual WebAssembly):**

   ```wasm
   i32.const 10
   i32.const 20
   i32.add
   i32.add  // Error: Only one value left on the stack
   ```

   The second `i32.add` would try to pop two values when only one is available, which the interpreter's stack management would catch.

3. **Using Uninitialized Locals:** While not directly shown in this snippet, the `InitSlotsForFunctionArgs` and the general slot allocation mechanism ensure that locals are typically initialized (or at least have slots allocated) before being used. However, bugs in WebAssembly code could still lead to accessing uninitialized values, which might manifest as unexpected behavior during interpretation.

**Summary of Functionality:**

This header file defines the core components and data structures for the **V8 WebAssembly interpreter's bytecode generation and execution**. It encompasses:

* **Bytecode Generation:** The `WasmBytecodeGenerator` class is responsible for translating a higher-level representation of WebAssembly code into a lower-level bytecode format suitable for interpretation.
* **Stack Management:**  It implements a stack-based virtual machine, managing the operand stack for executing WebAssembly instructions.
* **Constant Pool:** It provides mechanisms for efficiently storing and retrieving constant values.
* **Control Flow:** It handles the execution of control flow constructs like blocks, loops, and conditional branches.
* **Debugging and Tracing:**  Features for tracing the interpreter's execution and maintaining shadow stacks for debugging are included (under specific flags).
* **Context Management:**  Utilities like `ClearThreadInWasmScope` ensure proper thread context when running WebAssembly.

In essence, this file is a crucial part of V8's ability to run WebAssembly code, acting as the bridge between the compiled WebAssembly binary and the actual execution of its instructions.

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
rn UINT_MAX;
  }
  inline uint32_t GetF32ConstSlot(float value) {
    auto it = f32_const_cache_.find(value);
    if (it != f32_const_cache_.end()) {
      return it->second;
    }
    return UINT_MAX;
  }
  inline uint32_t GetF64ConstSlot(double value) {
    auto it = f64_const_cache_.find(value);
    if (it != f64_const_cache_.end()) {
      return it->second;
    }
    return UINT_MAX;
  }
  inline uint32_t GetS128ConstSlot(Simd128 value) {
    auto it = s128_const_cache_.find(reinterpret_cast<Simd128&>(value));
    if (it != s128_const_cache_.end()) {
      return it->second;
    }
    return UINT_MAX;
  }

  template <typename T>
  inline uint32_t CreateConstSlot(T value) {
    if constexpr (std::is_same_v<T, WasmRef>) {
      UNREACHABLE();
    }
    uint32_t slot_index = GetConstSlot(value);
    if (slot_index == UINT_MAX) {
      uint32_t offset = const_slot_offset_ * sizeof(uint32_t);
      DCHECK_LE(offset + sizeof(T), const_slots_values_.size());

      slot_index = static_cast<uint32_t>(slots_.size());
      slots_.push_back(
          {value_type<T>(), const_slots_start() + const_slot_offset_, 0});
      base::WriteUnalignedValue<T>(
          reinterpret_cast<Address>(const_slots_values_.data() + offset),
          value);
      const_slot_offset_ += sizeof(T) / kSlotSize;
    }
    return slot_index;
  }

  template <typename T>
  inline uint32_t PushConstSlot(T value) {
    uint32_t new_slot_index = CreateConstSlot(value);
    PushConstSlot(new_slot_index);
    return new_slot_index;
  }
  inline void PushConstSlot(uint32_t slot_index);
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  void TracePushConstSlot(uint32_t slot_index);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  inline void PushSlot(uint32_t slot_index) {
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_bytecode_generator &&
        v8_flags.trace_drumbrake_execution_verbose) {
      printf("    push - slot[%d] = %d\n", stack_size(), slot_index);
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

    stack_.push_back(slot_index);
  }

  inline uint32_t _PushSlot(ValueType value_type) {
    PushSlot(static_cast<uint32_t>(slots_.size()));
    return CreateSlot(value_type);
  }

  inline void PushCopySlot(uint32_t from);
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  void TracePushCopySlot(uint32_t from);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  inline uint32_t PopSlot() {
    // TODO(paolosev@microsoft.com) - We should try to mark as 'invalid' and
    // later reuse slots in the stack once we are sure they won't be referred
    // again, which should be the case once a slot is popped. This could make
    // the stack frame size smaller, especially for large Wasm functions.
    uint32_t slot_offset = slots_[stack_.back()].slot_offset;

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    if (v8_flags.trace_drumbrake_bytecode_generator &&
        v8_flags.trace_drumbrake_execution_verbose) {
      printf("    pop  - slot[%d] = %d\n", stack_size() - 1, stack_.back());
    }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

    stack_.pop_back();
    return slot_offset;
  }

  void CopyToSlot(ValueType value_type, uint32_t from_slot_index,
                  uint32_t to_stack_index, bool copy_from_reg);
  void CopyToSlotAndPop(ValueType value_type, uint32_t to, bool is_tee,
                        bool copy_from_reg);

  inline void SetSlotType(uint32_t stack_index, ValueType type) {
    DCHECK_LT(stack_index, stack_.size());

    uint32_t slot_index = stack_[stack_index];
    slots_[slot_index].value_type = type;

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
    TraceSetSlotType(stack_index, type);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
  }

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  void TraceSetSlotType(uint32_t stack_index, ValueType typo);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  inline void UpdateStack(uint32_t index, uint32_t slot_index) {
    DCHECK_LT(index, stack_.size());
    stack_[index] = slot_index;
  }
  inline void UpdateStack(uint32_t index, uint32_t slot_index,
                          ValueType value_type) {
    DCHECK_LT(index, stack_.size());
    stack_[index] = slot_index;
    SetSlotType(index, value_type);
  }

  inline uint32_t stack_top_index() const {
    DCHECK(!stack_.empty());
    return static_cast<uint32_t>(stack_.size() - 1);
  }
  inline uint32_t stack_size() const {
    return static_cast<uint32_t>(stack_.size());
  }

  inline void SetUnreachableMode() {
    is_instruction_reachable_ = false;
    unreachable_block_count_ = 1;

    CHECK_GE(current_block_index_, 0);
    blocks_[current_block_index_].is_unreachable_ = true;
  }

  // Create slots for arguments and generates run-time commands to initialize
  // their values.
  void InitSlotsForFunctionArgs(const FunctionSig* sig, bool is_indirect_call);

  bool TryCompactInstructionHandler(InstructionHandler func_addr);

  bool TypeCheckAlwaysSucceeds(ValueType obj_type, HeapType type) const;
  bool TypeCheckAlwaysFails(ValueType obj_type, HeapType expected_type,
                            bool null_succeeds) const;

  std::vector<uint8_t> const_slots_values_;
  uint32_t const_slot_offset_;
  std::unordered_map<int32_t, uint32_t> i32_const_cache_;
  std::unordered_map<int64_t, uint32_t> i64_const_cache_;
  std::unordered_map<float, uint32_t> f32_const_cache_;
  std::unordered_map<double, uint32_t> f64_const_cache_;

  struct Simd128Hash {
    size_t operator()(const Simd128& s128) const;
  };
  std::unordered_map<Simd128, uint32_t, Simd128Hash> s128_const_cache_;

  std::vector<Simd128> simd_immediates_;
  uint32_t slot_offset_;  // TODO(paolosev@microsoft.com): manage holes
  std::vector<uint32_t> stack_;
  uint32_t ref_slots_count_;

  uint32_t function_index_;
  InterpreterCode* wasm_code_;
  uint32_t args_count_;
  uint32_t args_slots_size_;
  uint32_t return_count_;
  uint32_t rets_slots_size_;
  uint32_t locals_count_;

  std::vector<uint8_t> code_;

  std::vector<BlockData> blocks_;
  int32_t current_block_index_;

  bool is_instruction_reachable_;
  uint32_t unreachable_block_count_;
#ifdef DEBUG
  bool was_current_instruction_reachable_;
#endif  // DEBUG

  base::SmallVector<uint32_t, 8> br_table_labels_;
  base::SmallVector<uint32_t, 16> loop_end_code_offsets_;

  const WasmModule* module_;

  // TODO(paolosev@microsoft.com) - Using a map is relatively slow because of
  // all the insertions that cause a ~10% performance hit in the generation of
  // the interpreter bytecode. The bytecode generation time is not a huge factor
  // when we run in purely jitless mode, because it is almost always dwarfed by
  // the interpreter execution time. It could be an important factor, however,
  // if we implemented a multi-tier strategy with the interpreter as a first
  // tier. It would probably be better to replace this with a plain vector and
  // use binary search for lookups.
  std::map<CodeOffset, pc_t> code_pc_map_;

  static const CodeOffset kInvalidCodeOffset = (CodeOffset)-1;
  CodeOffset last_instr_offset_;

  WasmEHDataGenerator eh_data_;

  WasmBytecodeGenerator(const WasmBytecodeGenerator&) = delete;
  WasmBytecodeGenerator& operator=(const WasmBytecodeGenerator&) = delete;
};

// TODO(paolosev@microsoft.com) Duplicated from src/runtime/runtime-wasm.cc
class V8_NODISCARD ClearThreadInWasmScope {
 public:
  explicit ClearThreadInWasmScope(Isolate* isolate);
  ~ClearThreadInWasmScope();

 private:
  Isolate* isolate_;
};

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
class InterpreterTracer final : public Malloced {
 public:
  explicit InterpreterTracer(int isolate_id)
      : isolate_id_(isolate_id),
        file_(nullptr),
        current_chunk_index_(0),
        write_count_(0) {
    if (0 != strcmp(v8_flags.trace_drumbrake_filter.value(), "*")) {
      std::stringstream s(v8_flags.trace_drumbrake_filter.value());
      for (int i; s >> i;) {
        traced_functions_.insert(i);
        if (s.peek() == ',') s.ignore();
      }
    }

    OpenFile();
  }

  ~InterpreterTracer() { CloseFile(); }

  void OpenFile() {
    if (!ShouldRedirect()) {
      file_ = stdout;
      return;
    }

    if (isolate_id_ >= 0) {
      base::SNPrintF(filename_, "trace-%d-%d-%d.dbt",
                     base::OS::GetCurrentProcessId(), isolate_id_,
                     current_chunk_index_);
    } else {
      base::SNPrintF(filename_, "trace-%d-%d.dbt",
                     base::OS::GetCurrentProcessId(), current_chunk_index_);
    }
    WriteChars(filename_.begin(), "", 0, false);

    if (file_ == nullptr) {
      file_ = base::OS::FOpen(filename_.begin(), "w");
      CHECK_WITH_MSG(file_ != nullptr, "could not open file.");
    }
  }

  void CloseFile() {
    if (!ShouldRedirect()) {
      return;
    }

    DCHECK_NOT_NULL(file_);
    base::Fclose(file_);
    file_ = nullptr;
  }

  bool ShouldTraceFunction(int function_index) const {
    return traced_functions_.empty() ||
           traced_functions_.find(function_index) != traced_functions_.end();
  }

  void PrintF(const char* format, ...);

  void CheckFileSize() {
    if (!ShouldRedirect()) {
      return;
    }

    ::fflush(file_);
    if (++write_count_ >= kWriteCountCheckInterval) {
      write_count_ = 0;
      ::fseek(file_, 0L, SEEK_END);
      if (::ftell(file_) > kMaxFileSize) {
        CloseFile();
        current_chunk_index_ = (current_chunk_index_ + 1) % kFileChunksCount;
        OpenFile();
      }
    }
  }

  FILE* file() const { return file_; }

 private:
  static bool ShouldRedirect() { return v8_flags.redirect_drumbrake_traces; }

  int isolate_id_;
  base::EmbeddedVector<char, 128> filename_;
  FILE* file_;
  std::unordered_set<int> traced_functions_;
  int current_chunk_index_;
  int64_t write_count_;

  static const int64_t kWriteCountCheckInterval = 1000;
  static const int kFileChunksCount = 10;
  static const int64_t kMaxFileSize = 100 * MB;
};

class ShadowStack {
 public:
  void TracePop() { stack_.pop_back(); }

  void TraceSetSlotType(uint32_t index, uint32_t type) {
    if (stack_.size() <= index) stack_.resize(index + 1);
    stack_[index].type_ = ValueType::FromRawBitField(type);
  }

  template <typename T>
  void TracePush(uint32_t slot_offset) {
    stack_.push_back({value_type<T>(), slot_offset});
  }

  void TracePushCopy(uint32_t index) { stack_.push_back(stack_[index]); }

  void TraceUpdate(uint32_t stack_index, uint32_t slot_offset) {
    if (stack_.size() <= stack_index) stack_.resize(stack_index + 1);
    stack_[stack_index].slot_offset_ = slot_offset;
  }

  void Print(WasmInterpreterRuntime* wasm_runtime, const uint32_t* sp,
             size_t start_params, size_t start_locals, size_t start_stack,
             RegMode reg_mode, int64_t r0, double fp0) const;

  struct Slot {
    static void Print(WasmInterpreterRuntime* wasm_runtime, ValueType type,
                      size_t index, char kind, const uint8_t* addr);
    void Print(WasmInterpreterRuntime* wasm_runtime, size_t index, char kind,
               const uint8_t* addr) const {
      return Print(wasm_runtime, type_, index, kind, addr);
    }

    ValueType type_;
    uint32_t slot_offset_;
  };

 private:
  std::vector<Slot> stack_;
};
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

}  // namespace wasm
}  // namespace internal
}  // namespace v8

#endif  // V8_WASM_INTERPRETER_WASM_INTERPRETER_H_
```