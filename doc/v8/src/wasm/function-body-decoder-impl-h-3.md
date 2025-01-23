Response:
My thinking process to answer the request about the `function-body-decoder-impl.h` file goes like this:

1. **Identify the Core Purpose:** The filename itself, `function-body-decoder-impl.h`, strongly suggests its primary function: decoding the body of a WebAssembly function. The `.h` extension indicates a header file in C++, likely containing class declarations and inline function implementations. The `impl` suffix often signifies implementation details that might not be part of the public interface.

2. **Scan for Key Classes and Methods:** I'd quickly scan the provided code for prominent class names and methods. The `WasmFullDecoder` class stands out as the main actor. Its `Decode()` method is a clear entry point for the decoding process. I'd also look for helper classes or structs, like `Control`, `Value`, and immediate value extractors (e.g., `BlockTypeImmediate`, `BranchDepthImmediate`).

3. **Deconstruct the Decoding Process (High-Level):** I'd infer the general flow by observing the `Decode()` method. It seems to involve:
    * Initializing locals.
    * Iterating through the bytecode (`while (this->pc_ < this->end_)`).
    * Reading opcodes.
    * Dispatching to opcode-specific handlers.
    * Managing a stack (`stack_`) and a control flow stack (`control_`).
    * Potentially handling errors.

4. **Analyze Specific Code Sections:**  I would focus on important code blocks:
    * **Opcode Handling (`switch` statement in `DecodeWasmOpcode`):**  This reveals the range of supported WebAssembly instructions, including regular opcodes, Asm.js compatibility opcodes, SIMD, numeric, atomic, and garbage collection opcodes. The `FOREACH_*_OPCODE` macros are hints of a table-driven or macro-generated approach to opcode dispatch.
    * **Control Flow Management:** The `Control` class and the logic around `Block`, `If`, `Loop`, `Try`, `Catch`, `End`, etc., are crucial for understanding how the decoder handles structured control flow in WebAssembly.
    * **Stack Management:** The `stack_` and the `Push()` and `Pop()` operations indicate how the decoder tracks the operands of WebAssembly instructions.
    * **Error Handling:** The `DecodeError()` calls and the `ValidationTag` template parameter point to a validation phase during decoding.

5. **Consider the Template Parameters:** The `ValidationTag` and `Interface` template parameters are important. `ValidationTag` suggests that the decoder can operate in different modes, likely with or without validation. `Interface` hints at a separation of concerns, where the actual actions performed during decoding are delegated to an external interface (like a compiler or interpreter).

6. **Address Specific Questions:** Now, I'd systematically address each part of the request:

    * **Functionality:**  Summarize the core purpose and key mechanisms observed.
    * **Torque:** Check the file extension. In this case, it's `.h`, not `.tq`.
    * **JavaScript Relationship:** Look for connections to JavaScript concepts. WebAssembly's interaction with JavaScript via imports, exports, and shared memory would be relevant. I'd try to find examples of how WebAssembly functions are called from JavaScript and how data is exchanged.
    * **Code Logic Inference:**  Choose a simple opcode (like `i32.const` or `local.get`) and trace its execution flow through the decoder. Hypothesize input bytecode and predict the resulting state of the stack and control flow.
    * **Common Programming Errors:** Think about common mistakes developers make when writing WebAssembly (e.g., type mismatches, stack underflow/overflow, incorrect branching). Relate these errors back to the decoder's role in detecting or preventing them.
    * **Summarize Functionality (Part 4):**  Focus on the aspects covered in the provided code snippet, which seems to be primarily about opcode decoding and dispatch, especially for control flow and string operations.

7. **Structure the Answer:** Organize the findings logically, using clear headings and bullet points. Provide code examples where requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "Is this just about parsing?"  **Correction:** It's more than just parsing; it's about interpreting the structure and semantics of the WebAssembly bytecode, including validation and building an internal representation (implicitly through the `Interface`).
* **Realization:** The `Interface` is a crucial abstraction. I need to emphasize that the decoder *drives* the decoding process, but the `Interface` defines *what happens* during that process (e.g., generating code, interpreting instructions).
* **Considering the audience:**  The explanation should be understandable to someone with some knowledge of compilers or virtual machines, but maybe not deep expertise in the V8 internals. Avoid overly technical jargon where possible, or explain it clearly.

By following this kind of systematic analysis, I can extract the essential information from the code snippet and provide a comprehensive answer to the user's request.
这是一个V8源代码文件，路径为 `v8/src/wasm/function-body-decoder-impl.h`。从内容来看，它是一个C++头文件，包含了 `WasmFullDecoder` 类的实现细节。

**功能归纳:**

这个文件的主要功能是**实现 WebAssembly 函数体的解码**。它负责读取 WebAssembly 的字节码，并将其转换为 V8 内部可以理解和执行的形式。

更具体地说，`WasmFullDecoder` 类负责：

1. **读取和解析字节码:** 逐字节读取 WebAssembly 函数体的字节码。
2. **识别操作码:**  识别当前字节或字节序列代表的 WebAssembly 操作码（例如 `i32.const`, `local.get`, `if`, `loop` 等）。
3. **解码操作数:**  对于需要操作数的操作码，解码后续的字节以获取操作数的值或索引。例如，解码 `local.get` 指令后的局部变量索引。
4. **维护栈和控制流:**  使用 `stack_` 维护 WebAssembly 的操作数栈，使用 `control_` 维护控制流结构（如块、循环、条件语句）。
5. **类型检查 (可选):**  根据 `ValidationTag` 模板参数，可以进行类型检查，确保操作的类型符合预期。
6. **调用接口:**  通过 `interface_` 成员变量调用外部接口的方法，将解码后的信息传递出去。这个接口的具体实现会根据 V8 的不同使用场景而有所不同，例如，Liftoff 编译器或 TurboFan 编译器。
7. **处理控制流指令:**  正确处理 `block`, `loop`, `if`, `else`, `end`, `br`, `br_if`, `return` 等控制流指令，维护控制流栈的正确状态。
8. **处理异常 (EH) 指令:**  支持 WebAssembly 的异常处理机制，处理 `try`, `catch`, `throw` 等指令。
9. **处理各种操作码:**  包含了大量针对不同 WebAssembly 操作码的处理逻辑，涵盖了数值运算、内存访问、局部变量访问、全局变量访问、函数调用、表操作、SIMD 指令、原子操作、GC 操作以及字符串操作等。

**关于文件扩展名和 Torque:**

`v8/src/wasm/function-body-decoder-impl.h` 以 `.h` 结尾，说明它是一个 **C++ 头文件**，而不是 Torque 源代码。Torque 源代码的文件通常以 `.tq` 结尾。

**与 JavaScript 的关系:**

`function-body-decoder-impl.h` 直接参与了 V8 执行 JavaScript 代码的过程。当 JavaScript 代码调用 WebAssembly 模块中的函数时，V8 会使用这个解码器来解析和执行 WebAssembly 的字节码。

**JavaScript 示例:**

```javascript
// 创建一个 WebAssembly 模块的 ArrayBuffer
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // wasm 头部
  0x01, 0x07, 0x01, 0x60, 0x00, 0x01, 0x7f,       // 类型段：定义一个接受 0 个参数并返回 i32 的函数类型
  0x03, 0x02, 0x01, 0x00,                         // 函数段：定义一个函数，使用上面的函数类型
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x41, 0x05, 0x6a, 0x0b // 代码段：函数体，包含 local.get 0, i32.const 5, i32.mul, end
]);

WebAssembly.instantiate(wasmCode).then(module => {
  const addFive = module.instance.exports.addFive;
  // addFive 函数的 WebAssembly 代码会被 function-body-decoder-impl.h 中的代码解码
  console.log(addFive()); // 输出解码后的结果
});
```

在这个例子中，`WebAssembly.instantiate` 会编译和实例化 WebAssembly 代码。在编译阶段，`function-body-decoder-impl.h` 中定义的解码器会被用来解析 `wasmCode` 中函数 `addFive` 的字节码。

**代码逻辑推理:**

假设输入的字节码序列是（对应于简单的 `i32.const 5` 指令）：

```
0x41 0x05
```

根据代码，解码过程会如下：

1. 读取第一个字节 `0x41`。
2. 在 `switch` 语句中匹配到 `kExprI32Const`。
3. 执行 `DecodeI32Const` 方法。
4. `DecodeI32Const` 方法会读取后续的 LEB128 编码的操作数 `0x05`，解码得到整数 `5`。
5. 调用 `interface_.ConstI32(this, value)` (假设 `interface_` 实现了这个方法)，将常量值 `5` 推入操作数栈。
6. `DecodeI32Const` 返回操作码和操作数的总长度 `1 + 1 = 2`。
7. 解码器将程序计数器 `pc_` 增加 `2`。

**假设输入与输出 (基于上面的例子):**

**假设输入:**

* `pc_` 指向字节码 `0x41`。
* 当前操作数栈为空。
* `ValidationTag` 为某种验证模式。

**输出:**

* 操作数栈顶会增加一个类型为 `kWasmI32`，值为 `5` 的元素。
* `pc_` 会向前移动 2 个字节。
* 如果验证失败，可能会调用 `decoder->DecodeError`。

**用户常见的编程错误:**

在编写 WebAssembly 代码时，常见的错误可能包括：

1. **类型不匹配:**  例如，尝试将一个浮点数赋值给一个整数类型的局部变量，或者在需要整数的地方使用了引用类型。解码器在验证模式下可以检测到这些错误。
   ```c++
   // 假设 WebAssembly 代码尝试将 f32.const 的结果赋给 i32 局部变量
   case kExprF32Const: {
     // ...
     Value value = ...; // f32 类型
     interface_.LocalSet(this, local_index, value); // 如果 local_index 对应的局部变量是 i32 类型，这里会类型不匹配
     break;
   }
   ```

2. **栈溢出或下溢:**  执行操作时，操作数栈中的元素不足或过多。例如，执行二元操作时，栈中少于两个元素。
   ```c++
   case kExprI32Add: {
     if (!VALIDATE(stack_.size() >= 2)) {
       decoder->DecodeError(pc, "stack underflow");
       return 1;
     }
     Value right = Pop();
     Value left = Pop();
     // ...
     break;
   }
   ```

3. **访问越界:** 访问不存在的局部变量、全局变量或内存地址。解码器在验证阶段可以检查局部变量和全局变量的索引是否有效。内存访问的越界检查通常在运行时进行，但解码器会解析内存访问指令的操作数。
   ```c++
   case kExprLocalGet: {
     LocalIndexImmediate imm(decoder, pc + length, validate);
     if (!VALIDATE(imm.index < decoder->num_locals())) {
       decoder->DecodeError(pc, "invalid local index");
       return length + imm.length;
     }
     // ...
     break;
   }
   ```

4. **控制流错误:**  例如，`end` 指令与之前的控制流指令不匹配，或者 `br` 指令的目标深度无效。
   ```c++
   DECODE(End) {
     // ...
     if (!VALIDATE(!control_.empty())) {
       this->DecodeError("unexpected end");
       return 1;
     }
     // ...
   }

   DECODE(Br) {
     BranchDepthImmediate imm(this, this->pc_ + 1, validate);
     if (!this->Validate(this->pc_ + 1, imm, control_.size())) return 0;
     // ...
   }
   ```

**第 4 部分功能归纳:**

在这部分代码中，主要关注的是 **解码各种 WebAssembly 操作码**，特别是：

* **立即数操作:** 解码内存索引和字符串常量立即数。
* **字符串操作:** 虽然这里只是返回长度，但表明解码器需要识别这些字符串相关的操作码，后续的接口调用可能会处理这些操作。
* **ASM.js 兼容操作码:**  预留了处理 ASM.js 兼容操作码的位置。
* **前缀操作码:**  声明了 SIMD、数值、原子和 GC 前缀操作码的处理，但具体处理逻辑在其他地方。
* **默认情况和错误处理:**  当遇到未知的 GC 操作码时，会报错。

总而言之，这部分代码负责识别和初步处理各种 WebAssembly 指令，并为后续的执行或编译阶段做好准备。它体现了 WebAssembly 解码器需要处理的指令种类繁多，涵盖了各种不同的操作类型。

### 提示词
```
这是目录为v8/src/wasm/function-body-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-body-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共9部分，请归纳一下它的功能
```

### 源代码
```c
ndexImmediate imm(decoder, pc + length, validate);
            (ios.MemoryIndex(imm), ...);
            return length + imm.length;
          }
          case kExprStringConst: {
            StringConstImmediate imm(decoder, pc + length, validate);
            (ios.StringConst(imm), ...);
            return length + imm.length;
          }
          case kExprStringMeasureUtf8:
          case kExprStringMeasureWtf8:
          case kExprStringNewUtf8Array:
          case kExprStringNewUtf8ArrayTry:
          case kExprStringNewLossyUtf8Array:
          case kExprStringNewWtf8Array:
          case kExprStringEncodeUtf8Array:
          case kExprStringEncodeLossyUtf8Array:
          case kExprStringEncodeWtf8Array:
          case kExprStringMeasureWtf16:
          case kExprStringConcat:
          case kExprStringEq:
          case kExprStringIsUSVSequence:
          case kExprStringAsWtf8:
          case kExprStringViewWtf8Advance:
          case kExprStringViewWtf8Slice:
          case kExprStringAsWtf16:
          case kExprStringViewWtf16Length:
          case kExprStringViewWtf16GetCodeunit:
          case kExprStringViewWtf16Slice:
          case kExprStringAsIter:
          case kExprStringViewIterNext:
          case kExprStringViewIterAdvance:
          case kExprStringViewIterRewind:
          case kExprStringViewIterSlice:
          case kExprStringNewWtf16Array:
          case kExprStringEncodeWtf16Array:
          case kExprStringCompare:
          case kExprStringFromCodePoint:
          case kExprStringHash:
            return length;
          default:
            // This path is only possible if we are validating.
            V8_ASSUME(ValidationTag::validate);
            decoder->DecodeError(pc, "invalid gc opcode");
            return length;
        }
      }

        // clang-format off
      /********** Asmjs opcodes **********/
      FOREACH_ASMJS_COMPAT_OPCODE(DECLARE_OPCODE_CASE)
        return 1;

      // Prefixed opcodes (already handled, included here for completeness of
      // switch)
      FOREACH_SIMD_OPCODE(DECLARE_OPCODE_CASE)
      FOREACH_NUMERIC_OPCODE(DECLARE_OPCODE_CASE)
      FOREACH_ATOMIC_OPCODE(DECLARE_OPCODE_CASE)
      FOREACH_ATOMIC_0_OPERAND_OPCODE(DECLARE_OPCODE_CASE)
      FOREACH_GC_OPCODE(DECLARE_OPCODE_CASE)
        UNREACHABLE();
        // clang-format on
#undef DECLARE_OPCODE_CASE
    }
    // Invalid modules will reach this point.
    if (ValidationTag::validate) {
      decoder->DecodeError(pc, "invalid opcode");
    }
    return 1;
  }

  static constexpr ValidationTag validate = {};

  Zone* const zone_;

  ValueType* local_types_ = nullptr;
  uint32_t num_locals_ = 0;

  const WasmModule* module_;
  const WasmEnabledFeatures enabled_;
  WasmDetectedFeatures* detected_;
  const FunctionSig* sig_;
  bool is_shared_;
  const std::pair<uint32_t, uint32_t>* current_inst_trace_;
};

// Only call this in contexts where {current_code_reachable_and_ok_} is known to
// hold.
#define CALL_INTERFACE(name, ...)                         \
  do {                                                    \
    DCHECK(!control_.empty());                            \
    DCHECK(current_code_reachable_and_ok_);               \
    DCHECK_EQ(current_code_reachable_and_ok_,             \
              this->ok() && control_.back().reachable()); \
    interface_.name(this, ##__VA_ARGS__);                 \
  } while (false)
#define CALL_INTERFACE_IF_OK_AND_REACHABLE(name, ...)     \
  do {                                                    \
    DCHECK(!control_.empty());                            \
    DCHECK_EQ(current_code_reachable_and_ok_,             \
              this->ok() && control_.back().reachable()); \
    if (V8_LIKELY(current_code_reachable_and_ok_)) {      \
      interface_.name(this, ##__VA_ARGS__);               \
    }                                                     \
  } while (false)
#define CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(name, ...)    \
  do {                                                          \
    DCHECK(!control_.empty());                                  \
    if (VALIDATE(this->ok()) &&                                 \
        (control_.size() == 1 || control_at(1)->reachable())) { \
      interface_.name(this, ##__VA_ARGS__);                     \
    }                                                           \
  } while (false)

// An empty class used in place of a {base::SmallVector} for cases where the
// content is not needed afterwards.
// This is used for implementations which set {kUsesPoppedArgs} to {false}.
class NoVector {
 public:
  // Construct from anything; {NoVector} is always empty.
  template <typename... Ts>
  explicit NoVector(Ts&&...) V8_NOEXCEPT {}

  constexpr std::nullptr_t data() const { return nullptr; }
};

template <typename ValidationTag, typename Interface,
          DecodingMode decoding_mode = kFunctionBody>
class WasmFullDecoder : public WasmDecoder<ValidationTag, decoding_mode> {
  using Value = typename Interface::Value;
  using Control = typename Interface::Control;
  using ArgVector = base::Vector<Value>;
  using PoppedArgVector =
      std::conditional_t<Interface::kUsesPoppedArgs,
                         base::SmallVector<Value, 8>, NoVector>;
  using ReturnVector = base::SmallVector<Value, 2>;

  // All Value types should be trivially copyable for performance. We push, pop,
  // and store them in local variables.
  ASSERT_TRIVIALLY_COPYABLE(Value);

 public:
  template <typename... InterfaceArgs>
  WasmFullDecoder(Zone* zone, const WasmModule* module,
                  WasmEnabledFeatures enabled, WasmDetectedFeatures* detected,
                  const FunctionBody& body, InterfaceArgs&&... interface_args)
      : WasmDecoder<ValidationTag, decoding_mode>(
            zone, module, enabled, detected, body.sig, body.is_shared,
            body.start, body.end, body.offset),
        interface_(std::forward<InterfaceArgs>(interface_args)...),
        stack_(16, zone),
        control_(16, zone) {}

  ~WasmFullDecoder() {
    control_.Reset(this->zone_);
    stack_.Reset(this->zone_);
    locals_initializers_stack_.Reset(this->zone_);
  }

  Interface& interface() { return interface_; }

  void Decode() {
    DCHECK(stack_.empty());
    DCHECK(control_.empty());
    DCHECK_LE(this->pc_, this->end_);
    DCHECK_EQ(this->num_locals(), 0);

    locals_offset_ = this->pc_offset();
    uint32_t locals_length = this->DecodeLocals(this->pc());
    if (!VALIDATE(this->ok())) return TraceFailed();
    this->consume_bytes(locals_length);
    int non_defaultable = 0;
    uint32_t params_count =
        static_cast<uint32_t>(this->sig_->parameter_count());
    for (uint32_t index = params_count; index < this->num_locals(); index++) {
      if (!this->local_type(index).is_defaultable()) non_defaultable++;
      // We need this because reference locals are initialized with null, and
      // later we run a lowering step for null based on {detected_}.
      if (this->local_type(index).is_reference()) {
        this->detected_->add_reftypes();
      }
    }
    this->InitializeInitializedLocalsTracking(non_defaultable);

    // Cannot use CALL_INTERFACE_* macros because control is empty.
    interface().StartFunction(this);
    DecodeFunctionBody();
    // Decoding can fail even without validation, e.g. due to missing Liftoff
    // support.
    if (this->failed()) return TraceFailed();

    if (!VALIDATE(control_.empty())) {
      if (control_.size() > 1) {
        this->DecodeError(control_.back().pc(),
                          "unterminated control structure");
      } else {
        this->DecodeError("function body must end with \"end\" opcode");
      }
      return TraceFailed();
    }
    // Cannot use CALL_INTERFACE_* macros because control is empty.
    interface().FinishFunction(this);
    if (this->failed()) return TraceFailed();

    DCHECK(stack_.empty());
    TRACE("wasm-decode ok\n\n");
  }

  void TraceFailed() {
    if (this->error_.offset()) {
      TRACE("wasm-error module+%-6d func+%d: %s\n\n", this->error_.offset(),
            this->GetBufferRelativeOffset(this->error_.offset()),
            this->error_.message().c_str());
    } else {
      TRACE("wasm-error: %s\n\n", this->error_.message().c_str());
    }
  }

  const char* SafeOpcodeNameAt(const uint8_t* pc) {
    if (!pc) return "<null>";
    if (pc >= this->end_) return "<end>";
    WasmOpcode opcode = static_cast<WasmOpcode>(*pc);
    if (!WasmOpcodes::IsPrefixOpcode(opcode)) {
      return WasmOpcodes::OpcodeName(static_cast<WasmOpcode>(opcode));
    }
    opcode = this->template read_prefixed_opcode<Decoder::FullValidationTag>(pc)
                 .first;
    return WasmOpcodes::OpcodeName(opcode);
  }

  WasmCodePosition position() const {
    int offset = static_cast<int>(this->pc_ - this->start_);
    DCHECK_EQ(this->pc_ - this->start_, offset);  // overflows cannot happen
    return offset;
  }

  uint32_t control_depth() const {
    return static_cast<uint32_t>(control_.size());
  }

  Control* control_at(uint32_t depth) {
    DCHECK_GT(control_.size(), depth);
    return control_.end() - 1 - depth;
  }

  uint32_t stack_size() const { return stack_.size(); }

  Value* stack_value(uint32_t depth) const {
    DCHECK_LT(0, depth);
    DCHECK_GE(stack_.size(), depth);
    return stack_.end() - depth;
  }

  int32_t current_catch() const { return current_catch_; }

  uint32_t control_depth_of_current_catch() const {
    return control_depth() - 1 - current_catch();
  }

  uint32_t pc_relative_offset() const {
    return this->pc_offset() - locals_offset_;
  }

  bool is_local_initialized(uint32_t local_index) {
    DCHECK_GT(this->num_locals_, local_index);
    if (!has_nondefaultable_locals_) return true;
    return initialized_locals_[local_index];
  }

  void set_local_initialized(uint32_t local_index) {
    DCHECK_GT(this->num_locals_, local_index);
    if (!has_nondefaultable_locals_) return;
    // This implicitly covers defaultable locals too (which are always
    // initialized).
    if (is_local_initialized(local_index)) return;
    initialized_locals_[local_index] = true;
    locals_initializers_stack_.push(local_index);
  }

  uint32_t locals_initialization_stack_depth() const {
    return static_cast<uint32_t>(locals_initializers_stack_.size());
  }

  void RollbackLocalsInitialization(Control* c) {
    if (!has_nondefaultable_locals_) return;
    uint32_t previous_stack_height = c->init_stack_depth;
    while (locals_initializers_stack_.size() > previous_stack_height) {
      uint32_t local_index = locals_initializers_stack_.back();
      locals_initializers_stack_.pop();
      initialized_locals_[local_index] = false;
    }
  }

  void InitializeInitializedLocalsTracking(int non_defaultable_locals) {
    has_nondefaultable_locals_ = non_defaultable_locals > 0;
    if (!has_nondefaultable_locals_) return;
    initialized_locals_ =
        this->zone_->template AllocateArray<bool>(this->num_locals_);
    // Parameters are always initialized.
    const size_t num_params = this->sig_->parameter_count();
    std::fill_n(initialized_locals_, num_params, true);
    // Locals are initialized if they are defaultable.
    for (size_t i = num_params; i < this->num_locals_; i++) {
      initialized_locals_[i] = this->local_types_[i].is_defaultable();
    }
    DCHECK(locals_initializers_stack_.empty());
    locals_initializers_stack_.EnsureMoreCapacity(non_defaultable_locals,
                                                  this->zone_);
  }

  void DecodeFunctionBody() {
    TRACE("wasm-decode %p...%p (module+%u, %d bytes)\n", this->start(),
          this->end(), this->pc_offset(),
          static_cast<int>(this->end() - this->start()));

    // Set up initial function block.
    {
      DCHECK(control_.empty());
      constexpr uint32_t kStackDepth = 0;
      constexpr uint32_t kInitStackDepth = 0;
      control_.EnsureMoreCapacity(1, this->zone_);
      control_.emplace_back(this->zone_, kControlBlock, kStackDepth,
                            kInitStackDepth, this->pc_, kReachable);
      Control* c = &control_.back();
      if constexpr (decoding_mode == kFunctionBody) {
        InitMerge(&c->start_merge, 0, nullptr);
        InitMerge(&c->end_merge,
                  static_cast<uint32_t>(this->sig_->return_count()),
                  [this](uint32_t i) {
                    return Value{this->pc_, this->sig_->GetReturn(i)};
                  });
      } else {
        DCHECK_EQ(this->sig_->parameter_count(), 0);
        DCHECK_EQ(this->sig_->return_count(), 1);
        c->start_merge.arity = 0;
        c->end_merge.arity = 1;
        c->end_merge.vals.first = Value{this->pc_, this->sig_->GetReturn(0)};
      }
      CALL_INTERFACE_IF_OK_AND_REACHABLE(StartFunctionBody, c);
    }

    if (V8_LIKELY(this->current_inst_trace_->first == 0)) {
      // Decode the function body.
      while (this->pc_ < this->end_) {
        // Most operations only grow the stack by at least one element (unary
        // and binary operations, local.get, constants, ...). Thus check that
        // there is enough space for those operations centrally, and avoid any
        // bounds checks in those operations.
        stack_.EnsureMoreCapacity(1, this->zone_);
        uint8_t first_byte = *this->pc_;
        WasmOpcode opcode = static_cast<WasmOpcode>(first_byte);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(NextInstruction, opcode);
        int len;
        // Allowing two of the most common decoding functions to get inlined
        // appears to be the sweet spot.
        // Handling _all_ opcodes via a giant switch-statement has been tried
        // and found to be slower than calling through the handler table.
        if (opcode == kExprLocalGet) {
          len = WasmFullDecoder::DecodeLocalGet(this, opcode);
        } else if (opcode == kExprI32Const) {
          len = WasmFullDecoder::DecodeI32Const(this, opcode);
        } else {
          OpcodeHandler handler = GetOpcodeHandler(first_byte);
          len = (*handler)(this, opcode);
        }
        this->pc_ += len;
      }

    } else {
      // Decode the function body.
      while (this->pc_ < this->end_) {
        DCHECK(this->current_inst_trace_->first == 0 ||
               this->current_inst_trace_->first >= this->pc_offset());
        if (V8_UNLIKELY(this->current_inst_trace_->first ==
                        this->pc_offset())) {
          TRACE("Emit trace at 0x%x with ID[0x%x]\n", this->pc_offset(),
                this->current_inst_trace_->second);
          CALL_INTERFACE_IF_OK_AND_REACHABLE(TraceInstruction,
                                             this->current_inst_trace_->second);
          this->current_inst_trace_++;
        }

        // Most operations only grow the stack by at least one element (unary
        // and binary operations, local.get, constants, ...). Thus check that
        // there is enough space for those operations centrally, and avoid any
        // bounds checks in those operations.
        stack_.EnsureMoreCapacity(1, this->zone_);
        uint8_t first_byte = *this->pc_;
        WasmOpcode opcode = static_cast<WasmOpcode>(first_byte);
        CALL_INTERFACE_IF_OK_AND_REACHABLE(NextInstruction, opcode);
        OpcodeHandler handler = GetOpcodeHandler(first_byte);
        int len = (*handler)(this, opcode);
        this->pc_ += len;
      }
    }

    // Even without validation, compilation could fail because of bailouts,
    // e.g., unsupported operations in Liftoff or the decoder for Wasm-in-JS
    // inlining. In those cases, {pc_} did not necessarily advance until {end_}.
    if (this->pc_ != this->end_) {
      // `DecodeError` is only available when validating, hence this guard.
      if constexpr (ValidationTag::validate) {
        this->DecodeError("Beyond end of code");
      }
    }
  }

  bool HasCatchAll(Control* block) const {
    DCHECK(block->is_try_table());
    return std::any_of(block->catch_cases.begin(), block->catch_cases.end(),
                       [](const struct CatchCase& catch_case) {
                         return catch_case.kind == kCatchAll ||
                                catch_case.kind == kCatchAllRef;
                       });
  }

 private:
  uint32_t locals_offset_ = 0;
  Interface interface_;

  // The value stack, stored as individual pointers for maximum performance.
  FastZoneVector<Value> stack_;

  // Indicates whether the local with the given index is currently initialized.
  // Entries for defaultable locals are meaningless; we have a byte for each
  // local because we expect that the effort required to densify this bit
  // vector would more than offset the memory savings.
  bool* initialized_locals_;
  // Keeps track of initializing assignments to non-defaultable locals that
  // happened, so they can be discarded at the end of the current block.
  // Contains no duplicates, so the size of this stack is bounded (and pre-
  // allocated) to the number of non-defaultable locals in the function.
  FastZoneVector<uint32_t> locals_initializers_stack_;

  // Control stack (blocks, loops, ifs, ...).
  FastZoneVector<Control> control_;

  // Controls whether code should be generated for the current block (basically
  // a cache for {ok() && control_.back().reachable()}).
  bool current_code_reachable_and_ok_ = true;

  // Performance optimization: bail out of any functions dealing with non-
  // defaultable locals early when there are no such locals anyway.
  bool has_nondefaultable_locals_ = true;

  // Depth of the current try block.
  int32_t current_catch_ = -1;

  static Value UnreachableValue(const uint8_t* pc) {
    return Value{pc, kWasmBottom};
  }

  void SetSucceedingCodeDynamicallyUnreachable() {
    Control* current = &control_.back();
    if (current->reachable()) {
      current->reachability = kSpecOnlyReachable;
      current_code_reachable_and_ok_ = false;
    }
  }

  // Mark that the current try-catch block might throw.
  // We only generate catch handlers for blocks that might throw.
  void MarkMightThrow() {
    if (!current_code_reachable_and_ok_ || current_catch() == -1) return;
    control_at(control_depth_of_current_catch())->might_throw = true;
  }

  V8_INLINE ValueType TableAddressType(const WasmTable* table) {
    return table->is_table64() ? kWasmI64 : kWasmI32;
  }

  V8_INLINE ValueType MemoryAddressType(const WasmMemory* memory) {
    return memory->is_memory64() ? kWasmI64 : kWasmI32;
  }

  V8_INLINE MemoryAccessImmediate
  MakeMemoryAccessImmediate(uint32_t pc_offset, uint32_t max_alignment) {
    return MemoryAccessImmediate(this, this->pc_ + pc_offset, max_alignment,
                                 this->enabled_.has_memory64(), validate);
  }

#ifdef DEBUG
  class TraceLine {
   public:
    explicit TraceLine(WasmFullDecoder* decoder) : decoder_(decoder) {
      WasmOpcode opcode = static_cast<WasmOpcode>(*decoder->pc());
      if (!WasmOpcodes::IsPrefixOpcode(opcode)) AppendOpcode(opcode);
    }

    void AppendOpcode(WasmOpcode opcode) {
      DCHECK(!WasmOpcodes::IsPrefixOpcode(opcode));
      Append(TRACE_INST_FORMAT, decoder_->startrel(decoder_->pc_),
             WasmOpcodes::OpcodeName(opcode));
    }

    ~TraceLine() {
      if (!v8_flags.trace_wasm_decoder) return;
      AppendStackState();
      PrintF("%.*s\n", len_, buffer_);
    }

    // Appends a formatted string.
    PRINTF_FORMAT(2, 3)
    void Append(const char* format, ...) {
      if (!v8_flags.trace_wasm_decoder) return;
      va_list va_args;
      va_start(va_args, format);
      size_t remaining_len = kMaxLen - len_;
      base::Vector<char> remaining_msg_space(buffer_ + len_, remaining_len);
      int len = base::VSNPrintF(remaining_msg_space, format, va_args);
      va_end(va_args);
      len_ += len < 0 ? remaining_len : len;
    }

   private:
    void AppendStackState() {
      DCHECK(v8_flags.trace_wasm_decoder);
      Append(" ");
      for (Control& c : decoder_->control_) {
        switch (c.kind) {
          case kControlIf:
            Append("I");
            break;
          case kControlBlock:
            Append("B");
            break;
          case kControlLoop:
            Append("L");
            break;
          case kControlTry:
            Append("T");
            break;
          case kControlTryTable:
            Append("T");
            break;
          case kControlIfElse:
            Append("E");
            break;
          case kControlTryCatch:
            Append("C");
            break;
          case kControlTryCatchAll:
            Append("A");
            break;
        }
        if (c.start_merge.arity) Append("%u-", c.start_merge.arity);
        Append("%u", c.end_merge.arity);
        if (!c.reachable()) Append("%c", c.unreachable() ? '*' : '#');
      }
      Append(" | ");
      for (uint32_t i = 0; i < decoder_->stack_.size(); ++i) {
        Value& val = decoder_->stack_[i];
        Append(" %c", val.type.short_name());
      }
    }

    static constexpr int kMaxLen = 512;

    char buffer_[kMaxLen];
    int len_ = 0;
    WasmFullDecoder* const decoder_;
  };
#else
  class TraceLine {
   public:
    explicit TraceLine(WasmFullDecoder*) {}

    void AppendOpcode(WasmOpcode) {}

    PRINTF_FORMAT(2, 3)
    void Append(const char* format, ...) {}
  };
#endif

#define DECODE(name)                                                     \
  static int Decode##name(WasmFullDecoder* decoder, WasmOpcode opcode) { \
    TraceLine trace_msg(decoder);                                        \
    return decoder->Decode##name##Impl(&trace_msg, opcode);              \
  }                                                                      \
  V8_INLINE int Decode##name##Impl(TraceLine* trace_msg, WasmOpcode opcode)

  DECODE(Nop) { return 1; }

  DECODE(NopForTestingUnsupportedInLiftoff) {
    if (!VALIDATE(v8_flags.enable_testing_opcode_in_wasm)) {
      this->DecodeError("Invalid opcode 0x%x", opcode);
      return 0;
    }
    CALL_INTERFACE_IF_OK_AND_REACHABLE(NopForTestingUnsupportedInLiftoff);
    // Return {0} if we failed, to not advance the pc past the end.
    if (this->failed()) {
      DCHECK_EQ(this->pc_, this->end_);
      return 0;
    }
    return 1;
  }

#define BUILD_SIMPLE_OPCODE(op, _, sig, ...) \
  DECODE(op) { return BuildSimpleOperator_##sig(kExpr##op); }
  FOREACH_SIMPLE_NON_CONST_OPCODE(BUILD_SIMPLE_OPCODE)
#undef BUILD_SIMPLE_OPCODE

#define BUILD_SIMPLE_OPCODE(op, _, sig, ...)              \
  DECODE(op) {                                            \
    if constexpr (decoding_mode == kConstantExpression) { \
      this->detected_->add_extended_const();              \
    }                                                     \
    return BuildSimpleOperator_##sig(kExpr##op);          \
  }
  FOREACH_SIMPLE_EXTENDED_CONST_OPCODE(BUILD_SIMPLE_OPCODE)
#undef BUILD_SIMPLE_OPCODE

  DECODE(Block) {
    BlockTypeImmediate imm(this->enabled_, this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    Control* block = PushControl(kControlBlock, imm);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Block, block);
    return 1 + imm.length;
  }

  DECODE(Rethrow) {
    CHECK_PROTOTYPE_OPCODE(legacy_eh);
    BranchDepthImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm, control_.size())) return 0;
    Control* c = control_at(imm.depth);
    if (!VALIDATE(c->is_try_catchall() || c->is_try_catch())) {
      this->error("rethrow not targeting catch or catch-all");
      return 0;
    }
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Rethrow, c);
    MarkMightThrow();
    EndControl();
    return 1 + imm.length;
  }

  DECODE(Throw) {
    // This instruction is the same for legacy EH and exnref.
    // Count it as exnref if exnref is enabled so that we have an accurate eh
    // count for the deprecation plans.
    this->detected_->Add(this->enabled_.has_exnref()
                             ? WasmDetectedFeature::exnref
                             : WasmDetectedFeature::legacy_eh);
    TagIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    PoppedArgVector args = PopArgs(imm.tag->ToFunctionSig());
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Throw, imm, args.data());
    MarkMightThrow();
    EndControl();
    return 1 + imm.length;
  }

  DECODE(Try) {
    CHECK_PROTOTYPE_OPCODE(legacy_eh);
    BlockTypeImmediate imm(this->enabled_, this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    Control* try_block = PushControl(kControlTry, imm);
    try_block->previous_catch = current_catch_;
    current_catch_ = static_cast<int>(control_depth() - 1);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(Try, try_block);
    return 1 + imm.length;
  }

  DECODE(Catch) {
    CHECK_PROTOTYPE_OPCODE(legacy_eh);
    TagIndexImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm)) return 0;
    DCHECK(!control_.empty());
    Control* c = &control_.back();
    if (!VALIDATE(c->is_try())) {
      this->DecodeError("catch does not match a try");
      return 0;
    }
    if (!VALIDATE(!c->is_try_catchall())) {
      this->DecodeError("catch after catch-all for try");
      return 0;
    }
    FallThrough();
    c->kind = kControlTryCatch;
    stack_.shrink_to(c->stack_depth);
    c->reachability = control_at(1)->innerReachability();
    current_code_reachable_and_ok_ = VALIDATE(this->ok()) && c->reachable();
    RollbackLocalsInitialization(c);
    const WasmTagSig* sig = imm.tag->sig;
    stack_.EnsureMoreCapacity(static_cast<int>(sig->parameter_count()),
                              this->zone_);
    for (ValueType type : sig->parameters()) Push(type);
    base::Vector<Value> values(stack_.begin() + c->stack_depth,
                               sig->parameter_count());
    current_catch_ = c->previous_catch;  // Pop try scope.
    // If there is a throwing instruction in `c`, generate the header for a
    // catch block. Otherwise, the catch block is unreachable.
    if (c->might_throw) {
      CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(CatchException, imm, c, values);
    } else {
      SetSucceedingCodeDynamicallyUnreachable();
    }
    return 1 + imm.length;
  }

  DECODE(Delegate) {
    CHECK_PROTOTYPE_OPCODE(legacy_eh);
    BranchDepthImmediate imm(this, this->pc_ + 1, validate);
    // -1 because the current try block is not included in the count.
    if (!this->Validate(this->pc_ + 1, imm, control_depth() - 1)) return 0;
    Control* c = &control_.back();
    if (!VALIDATE(c->is_incomplete_try())) {
      this->DecodeError("delegate does not match a try");
      return 0;
    }
    // +1 because the current try block is not included in the count.
    uint32_t target_depth = imm.depth + 1;
    while (target_depth < control_depth() - 1 &&
           (!control_at(target_depth)->is_try() ||
            control_at(target_depth)->is_try_catch() ||
            control_at(target_depth)->is_try_catchall())) {
      target_depth++;
    }
    FallThrough();
    if (c->might_throw) {
      CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(Delegate, target_depth, c);
      // Delegate propagates the `might_throw` status to the delegated-to block.
      if (control_at(1)->reachable() && target_depth != control_depth() - 1) {
        control_at(target_depth)->might_throw = true;
      }
    }
    current_catch_ = c->previous_catch;
    EndControl();
    PopControl();
    return 1 + imm.length;
  }

  DECODE(CatchAll) {
    CHECK_PROTOTYPE_OPCODE(legacy_eh);
    DCHECK(!control_.empty());
    Control* c = &control_.back();
    if (!VALIDATE(c->is_try())) {
      this->DecodeError("catch-all does not match a try");
      return 0;
    }
    if (!VALIDATE(!c->is_try_catchall())) {
      this->error("catch-all already present for try");
      return 0;
    }
    FallThrough();
    c->kind = kControlTryCatchAll;
    c->reachability = control_at(1)->innerReachability();
    current_code_reachable_and_ok_ = VALIDATE(this->ok()) && c->reachable();
    RollbackLocalsInitialization(c);
    current_catch_ = c->previous_catch;  // Pop try scope.
    // If there is a throwing instruction in `c`, generate the header for a
    // catch block. Otherwise, the catch block is unreachable.
    if (c->might_throw) {
      CALL_INTERFACE_IF_OK_AND_PARENT_REACHABLE(CatchAll, c);
    } else {
      SetSucceedingCodeDynamicallyUnreachable();
    }
    stack_.shrink_to(c->stack_depth);
    return 1;
  }

  DECODE(TryTable) {
    CHECK_PROTOTYPE_OPCODE(exnref);
    BlockTypeImmediate block_imm(this->enabled_, this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, block_imm)) return 0;
    Control* try_block = PushControl(kControlTryTable, block_imm);
    TryTableImmediate try_table_imm(this, this->pc_ + 1 + block_imm.length,
                                    validate);
    if (try_table_imm.table_count > 0) {
      try_block->previous_catch = current_catch_;
      current_catch_ = static_cast<int>(control_depth() - 1);
    }
    if (!this->Validate(this->pc_ + 2, try_table_imm)) return 0;
    TryTableIterator<ValidationTag> try_table_iterator(this, try_table_imm);
    try_block->catch_cases = this->zone_->template AllocateVector<CatchCase>(
        try_table_imm.table_count);
    int i = 0;
    while (try_table_iterator.has_next()) {
      CatchCase catch_case = try_table_iterator.next();
      if (!VALIDATE(catch_case.kind <= kLastCatchKind)) {
        this->DecodeError("invalid catch kind in try table");
        return 0;
      }
      if ((catch_case.kind == kCatch || catch_case.kind == kCatchRef) &&
          !this->Validate(this->pc_, catch_case.maybe_tag.tag_imm)) {
        return 0;
      }
      catch_case.br_imm.depth += 1;
      if (!this->Validate(this->pc_, catch_case.br_imm, control_.size())) {
        return 0;
      }

      uint32_t stack_size = stack_.size();
      uint32_t push_count = 0;
      if (catch_case.kind == kCatch || catch_case.kind == kCatchRef) {
        const WasmTagSig* sig = catch_case.maybe_tag.tag_imm.tag->sig;
        stack_.EnsureMoreCapacity(static_cast<int>(sig->parameter_count()),
                                  this->zone_);
        for (ValueType type : sig->parameters()) Push(type);
        push_count += sig->parameter_count();
      }
      if (catch_case.kind == kCatchRef || catch_case.kind == kCatchAllRef) {
        stack_.EnsureMoreCapacity(1, this->zone_);
        Push(ValueType::Ref(HeapType::kExn));
        push_count += 1;
      }
      Control* target = control_at(catch_case.br_imm.depth);
      if (!VALIDATE(push_count == target->br_merge()->arity)) {
        this->DecodeError(
            "catch kind generates %d operand%s, target block expects %d",
            push_count, push_count != 1 ? "s" : "", target->br_merge()->arity);
        return 0;
      }
      if (!VALIDATE(
              (TypeCheckBranch<PushBranchValues::kYes, RewriteStackTypes::kNo>(
                  target)))) {
        return 0;
      }
      stack_.shrink_to(stack_size);
      DCHECK_LT(i, try_table_imm.table_count);
      try_block->catch_cases[i] = catch_case;
      ++i;
    }
    CALL_INTERFACE_IF_OK_AND_REACHABLE(TryTable, try_block);
    return 1 + block_imm.length + try_table_iterator.length();
  }

  DECODE(ThrowRef) {
    CHECK_PROTOTYPE_OPCODE(exnref);
    Value value = Pop(kWasmExnRef);
    CALL_INTERFACE_IF_OK_AND_REACHABLE(ThrowRef, &value);
    MarkMightThrow();
    EndControl();
    return 1;
  }

  DECODE(BrOnNull) {
    this->detected_->add_typed_funcref();
    BranchDepthImmediate imm(this, this->pc_ + 1, validate);
    if (!this->Validate(this->pc_ + 1, imm, control_.size())) return 0;
    Value ref_object = Pop();
    Control* c = control_at(imm.depth);
    if (!VALIDATE(
            (TypeCheckBranch<PushBranchValues::kYes, RewriteStackTypes::kYes>(
                c)))) {
      return 0;
    }
    switch (ref_object.type.kind()) {
      case kBottom:
        // We are in a polymorphic stack. Leave the stack as it is.
        DCHECK(!current_code_reachable_and_ok_);
        [[fallthrough]];
      case kRef:
        // For a non-nullable value, we won't take the branch, and can leave
        // the stack as it is.
        Push(ref_object);
        break;
      case kRefNull: {
        Value* result = Push(ValueType::Ref(ref_object.type.heap_type()));
        // The result of br_on_null has the same value as the argument (but a
        // non-nullable type).
        if (V8_LIKELY(current_code_reachable_and_ok_)) {
          CALL_INTERFACE(BrOnNull, ref_object, imm.depth, false, result);
          c->br_merge()->reached = true;
        }
        break;
      }
      default:
        PopTypeErro
```