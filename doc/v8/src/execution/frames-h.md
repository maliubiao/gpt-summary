Response:
The user wants a summary of the provided C++ header file `v8/src/execution/frames.h`. I need to identify the main functionalities defined in this file.

Based on the content, the file seems to define the structure and hierarchy of stack frames used by the V8 JavaScript engine during execution. It outlines different types of frames representing various stages and types of code execution.

Here's a breakdown of the key areas:

1. **Frame Hierarchy:** Defines a class hierarchy for different types of execution frames (JavaScript, Wasm, Builtin, etc.).
2. **StackFrame Class:**  An abstract base class representing a generic stack frame with common properties and methods.
3. **Specific Frame Types:**  Derived classes from `StackFrame` represent specific frame types like `JavaScriptFrame`, `WasmFrame`, `EntryFrame`, `ExitFrame`, etc., each with its own characteristics and methods.
4. **Frame Summaries:** Defines classes for summarizing frame information, useful for debugging and profiling.
5. **StackHandler:** A class to manage stack handlers.
6. **Type System:**  Defines an enum `Type` to represent different stack frame types.
7. **Utilities:** Includes helper functions for converting between frame types and markers, checking frame types, and accessing frame data.
```javascript
// 假设我们有一个简单的 JavaScript 函数
function add(a, b) {
  return a + b;
}

// 当我们调用这个函数时，V8 引擎会在执行栈上创建一个 JavaScriptFrame。
add(5, 3);
```

## 功能归纳：v8/src/execution/frames.h (第 1 部分)

`v8/src/execution/frames.h` 文件是 V8 JavaScript 引擎中定义 **执行栈帧 (Execution Stack Frames)** 结构和操作的核心头文件。它主要负责以下功能：

1. **定义栈帧类型体系:**  它建立了一个详细的类继承层次结构，用于表示 V8 引擎在执行不同类型的代码时创建的各种栈帧。这些类型包括：
    * **JavaScript 代码帧:**  例如 `JavaScriptFrame`、`InterpretedFrame`、`OptimizedJSFrame` 等，用于执行 JavaScript 代码。
    * **WebAssembly 代码帧:** 例如 `WasmFrame`、`JsToWasmFrame` 等，用于执行 WebAssembly 代码。
    * **内置函数帧:** `BuiltinFrame`，用于执行 V8 引擎内置的函数。
    * **入口和出口帧:** `EntryFrame` 和 `ExitFrame`，用于在 C++ 和 JavaScript 之间切换执行。
    * **其他内部帧:**  用于引擎内部操作，如构造函数调用、异常处理等。

2. **定义通用栈帧接口 (`StackFrame`):** 它定义了一个抽象基类 `StackFrame`，所有具体的栈帧类型都继承自它。`StackFrame` 类提供了访问栈帧通用属性和行为的方法，例如：
    * 获取栈指针 (`sp`) 和帧指针 (`fp`)。
    * 获取程序计数器 (`pc`)。
    * 获取栈帧类型。
    * 查找与栈帧关联的代码对象。
    * 遍历栈帧内容进行垃圾回收。
    * 打印栈帧信息。

3. **定义特定栈帧类型的接口:**  它为每种特定的栈帧类型定义了具体的类，这些类继承自 `StackFrame` 或其子类，并添加了该类型栈帧特有的属性和方法。例如，`JavaScriptFrame` 提供了访问函数、接收者 (receiver)、参数和上下文的方法。

4. **提供栈帧迭代器支持:**  虽然这部分代码本身没有直接包含迭代器的定义，但作为栈帧结构的基础，它为 V8 引擎实现栈帧迭代器（如 `StackFrameIterator`）提供了必要的类型信息和结构。

5. **定义栈处理机制 (`StackHandler`):**  定义了 `StackHandler` 类，用于管理执行栈上的异常处理程序。

6. **定义帧摘要 (`FrameSummary`):**  提供了 `FrameSummary` 类及其子类，用于提取和概括栈帧的关键信息，方便调试、分析和性能监控。

**关于 .tq 结尾:**

根据您的描述，如果 `v8/src/execution/frames.h` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 用于定义高效内置函数的领域特定语言。然而，您提供的文件内容表明它是一个 `.h` (C++ 头文件)，而不是 Torque 文件。

**与 JavaScript 功能的关系及示例:**

`v8/src/execution/frames.h` 中定义的栈帧结构是 V8 引擎执行 JavaScript 代码的基础。每当 JavaScript 函数被调用时，V8 都会在执行栈上创建一个或多个栈帧来跟踪执行状态。

例如，当执行以下 JavaScript 代码时：

```javascript
function foo(x) {
  return bar(x + 1);
}

function bar(y) {
  return y * 2;
}

foo(5);
```

V8 引擎会创建一系列栈帧：

1. **进入 `foo` 函数时:** 创建一个 `JavaScriptFrame` 或其子类（如 `InterpretedFrame` 或 `OptimizedJSFrame`），用于存储 `foo` 函数的局部变量、参数以及执行状态。
2. **调用 `bar` 函数时:**  在 `foo` 函数的栈帧之上，创建一个新的 `JavaScriptFrame` 或其子类，用于存储 `bar` 函数的信息。
3. **`bar` 函数执行完毕返回时:** `bar` 函数的栈帧会被弹出。
4. **`foo` 函数执行完毕返回时:** `foo` 函数的栈帧会被弹出。

`v8/src/execution/frames.h` 中定义的结构使得 V8 能够有效地管理函数调用、变量作用域、异常处理以及其他与 JavaScript 执行相关的任务。

**代码逻辑推理 (假设输入与输出):**

由于这是一个头文件，主要定义的是数据结构和接口，直接进行代码逻辑推理比较困难。  我们可以假设一个场景，例如 V8 引擎在遇到函数调用时需要确定要创建的栈帧类型。

**假设输入:**
* 当前执行的代码类型是 JavaScript。
* 调用的是一个未优化的普通 JavaScript 函数。

**推理:**
V8 引擎会检查当前的执行上下文和被调用函数的属性，根据 `v8/src/execution/frames.h` 中定义的类型体系，最终决定创建一个 `InterpretedFrame` 类型的栈帧。

**输出:**
V8 引擎在执行栈上分配内存，并按照 `InterpretedFrame` 的结构初始化该栈帧，包括设置栈指针、帧指针、程序计数器等。

**用户常见的编程错误 (与栈帧相关的间接影响):**

虽然开发者不会直接操作栈帧，但一些常见的编程错误会导致栈帧溢出或与栈帧相关的错误：

1. **无限递归:**  如果一个函数无限次地调用自身而没有终止条件，每次调用都会创建一个新的栈帧，最终导致栈空间耗尽，抛出 "RangeError: Maximum call stack size exceeded" 错误。

   ```javascript
   function recursiveFunction() {
     recursiveFunction();
   }
   recursiveFunction(); // 抛出错误
   ```

2. **非常深的调用栈:**  即使不是无限递归，过多的函数嵌套调用也可能导致栈溢出。

   ```javascript
   function a() { b(); }
   function b() { c(); }
   // ... 很多层调用
   function z() { /* 一些操作 */ }
   a(); // 如果调用链太深，可能抛出错误
   ```

**总结:**

`v8/src/execution/frames.h` 是 V8 引擎中至关重要的头文件，它定义了执行栈帧的结构和类型体系，为 V8 引擎管理 JavaScript 和 WebAssembly 代码的执行提供了基础框架。它定义了各种类型的栈帧，方便引擎在执行不同类型的代码时进行跟踪和管理，并为实现栈帧迭代、异常处理和性能分析等功能提供了必要的接口和数据结构。

### 提示词
```
这是目录为v8/src/execution/frames.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/frames.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_EXECUTION_FRAMES_H_
#define V8_EXECUTION_FRAMES_H_

#include "include/v8-initialization.h"
#include "src/base/bounds.h"
#include "src/codegen/handler-table.h"
#include "src/codegen/safepoint-table.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/objects/code.h"
#include "src/objects/deoptimization-data.h"
#include "src/objects/objects.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/stacks.h"
#include "src/wasm/wasm-code-manager.h"
#endif  // V8_ENABLE_WEBASSEMBLY

//
// Frame inheritance hierarchy (please keep in sync with frame-constants.h):
// - CommonFrame
//   - CommonFrameWithJSLinkage
//     - JavaScriptFrame (aka StandardFrame)
//       - UnoptimizedJSFrame
//         - InterpretedFrame
//         - BaselineFrame
//       - OptimizedJSFrame
//         - MaglevFrame
//         - TurbofanJSFrame
//     - TypedFrameWithJSLinkage
//       - BuiltinFrame
//       - JavaScriptBuiltinContinuationFrame
//         - JavaScriptBuiltinContinuationWithCatchFrame
//   - TurbofanStubWithContextFrame
//   - TypedFrame
//     - NativeFrame
//     - EntryFrame
//       - ConstructEntryFrame
//     - ExitFrame
//       - BuiltinExitFrame
//     - StubFrame
//       - JsToWasmFrame
//       - CWasmEntryFrame
//     - Internal
//       - ConstructFrame
//       - FastConstructFrame
//       - BuiltinContinuationFrame
//     - WasmFrame
//       - WasmExitFrame
//       - WasmToJsFrame
//       - WasmInterpreterEntryFrame (#if V8_ENABLE_DRUMBRAKE)
//     - WasmDebugBreakFrame
//     - WasmLiftoffSetupFrame
//     - IrregexpFrame

namespace v8 {
namespace internal {
namespace wasm {
class WasmCode;
struct JumpBuffer;
class StackMemory;
}  // namespace wasm

class AbstractCode;
class Debug;
class ExternalCallbackScope;
class InnerPointerToCodeCache;
class Isolate;
class ObjectVisitor;
class Register;
class RootVisitor;
class StackFrameInfo;
class StackFrameIteratorBase;
class StringStream;
class ThreadLocalTop;
class WasmInstanceObject;
class WasmModuleObject;

#if V8_ENABLE_DRUMBRAKE
class Tuple2;
#endif  // V8_ENABLE_DRUMBRAKE

class StackHandlerConstants : public AllStatic {
 public:
  static const int kNextOffset = 0 * kSystemPointerSize;
  static const int kPaddingOffset = 1 * kSystemPointerSize;

  static const int kSize = kPaddingOffset + kSystemPointerSize;
  static const int kSlotCount = kSize >> kSystemPointerSizeLog2;
};

class StackHandler {
 public:
  // Get the address of this stack handler.
  inline Address address() const;

  // Get the next stack handler in the chain.
  inline StackHandler* next() const;

  // Get the next stack handler, as an Address. This is safe to use even
  // when the next handler is null.
  inline Address next_address() const;

  // Conversion support.
  static inline StackHandler* FromAddress(Address address);

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(StackHandler);
};

#define STACK_FRAME_TYPE_LIST(V)                                          \
  V(ENTRY, EntryFrame)                                                    \
  V(CONSTRUCT_ENTRY, ConstructEntryFrame)                                 \
  V(EXIT, ExitFrame)                                                      \
  IF_WASM(V, WASM, WasmFrame)                                             \
  IF_WASM(V, WASM_TO_JS, WasmToJsFrame)                                   \
  IF_WASM(V, WASM_TO_JS_FUNCTION, WasmToJsFunctionFrame)                  \
  IF_WASM(V, JS_TO_WASM, JsToWasmFrame)                                   \
  IF_WASM(V, STACK_SWITCH, StackSwitchFrame)                              \
  IF_WASM_DRUMBRAKE(V, WASM_INTERPRETER_ENTRY, WasmInterpreterEntryFrame) \
  IF_WASM(V, WASM_DEBUG_BREAK, WasmDebugBreakFrame)                       \
  IF_WASM(V, C_WASM_ENTRY, CWasmEntryFrame)                               \
  IF_WASM(V, WASM_EXIT, WasmExitFrame)                                    \
  IF_WASM(V, WASM_LIFTOFF_SETUP, WasmLiftoffSetupFrame)                   \
  IF_WASM(V, WASM_SEGMENT_START, WasmSegmentStartFrame)                   \
  V(INTERPRETED, InterpretedFrame)                                        \
  V(BASELINE, BaselineFrame)                                              \
  V(MAGLEV, MaglevFrame)                                                  \
  V(TURBOFAN_JS, TurbofanJSFrame)                                         \
  V(STUB, StubFrame)                                                      \
  V(TURBOFAN_STUB_WITH_CONTEXT, TurbofanStubWithContextFrame)             \
  V(BUILTIN_CONTINUATION, BuiltinContinuationFrame)                       \
  V(JAVASCRIPT_BUILTIN_CONTINUATION, JavaScriptBuiltinContinuationFrame)  \
  V(JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH,                           \
    JavaScriptBuiltinContinuationWithCatchFrame)                          \
  V(INTERNAL, InternalFrame)                                              \
  V(CONSTRUCT, ConstructFrame)                                            \
  V(FAST_CONSTRUCT, FastConstructFrame)                                   \
  V(BUILTIN, BuiltinFrame)                                                \
  V(BUILTIN_EXIT, BuiltinExitFrame)                                       \
  V(API_CALLBACK_EXIT, ApiCallbackExitFrame)                              \
  V(API_ACCESSOR_EXIT, ApiAccessorExitFrame)                              \
  V(NATIVE, NativeFrame)                                                  \
  V(IRREGEXP, IrregexpFrame)

// Abstract base class for all stack frames.
class StackFrame {
 public:
#define DECLARE_TYPE(type, ignore) type,
  enum Type {
    NO_FRAME_TYPE = 0,
    STACK_FRAME_TYPE_LIST(DECLARE_TYPE) NUMBER_OF_TYPES,
    // Used by FrameScope to indicate that the stack frame is constructed
    // manually and the FrameScope does not need to emit code.
    MANUAL
  };
#undef DECLARE_TYPE

  // Used to mark the outermost JS entry frame.
  //
  // The mark is an opaque value that should be pushed onto the stack directly,
  // carefully crafted to not be interpreted as a tagged pointer.
  enum JsFrameMarker {
    INNER_JSENTRY_FRAME = (0 << kSmiTagSize) | kSmiTag,
    OUTERMOST_JSENTRY_FRAME = (1 << kSmiTagSize) | kSmiTag
  };
  static_assert((INNER_JSENTRY_FRAME & kHeapObjectTagMask) != kHeapObjectTag);
  static_assert((OUTERMOST_JSENTRY_FRAME & kHeapObjectTagMask) !=
                kHeapObjectTag);

  struct State {
    Address sp = kNullAddress;
    Address fp = kNullAddress;
    Address* pc_address = nullptr;
    Address callee_fp = kNullAddress;
    Address callee_pc = kNullAddress;
    Address* constant_pool_address = nullptr;
    bool is_profiler_entry_frame = false;
    bool is_stack_exit_frame = false;
  };

  // Convert a stack frame type to a marker that can be stored on the stack.
  //
  // The marker is an opaque value, not intended to be interpreted in any way
  // except being checked by IsTypeMarker or converted by MarkerToType.
  // It has the same tagging as Smis, so any marker value that does not pass
  // IsTypeMarker can instead be interpreted as a tagged pointer.
  //
  // Note that the marker is not a Smi: Smis on 64-bit architectures are stored
  // in the top 32 bits of a 64-bit value, which in turn makes them expensive
  // (in terms of code/instruction size) to push as immediates onto the stack.
  static constexpr int32_t TypeToMarker(Type type) {
    DCHECK_GE(type, 0);
    return (type << kSmiTagSize) | kSmiTag;
  }

  // Convert a marker back to a stack frame type.
  //
  // Unlike the return value of TypeToMarker, this takes an intptr_t, as that is
  // the type of the value on the stack.
  static constexpr Type MarkerToType(intptr_t marker) {
    DCHECK(IsTypeMarker(marker));
    return static_cast<Type>(marker >> kSmiTagSize);
  }

  // Check if a marker is a stack frame type marker.
  //
  // Returns true if the given marker is tagged as a stack frame type marker,
  // and should be converted back to a stack frame type using MarkerToType.
  static constexpr bool IsTypeMarker(uintptr_t function_or_marker) {
    static_assert(kSmiTag == 0);
    static_assert((std::numeric_limits<uintptr_t>::max() >> kSmiTagSize) >
                  Type::NUMBER_OF_TYPES);
    return (function_or_marker & kSmiTagMask) == kSmiTag &&
           function_or_marker < (Type::NUMBER_OF_TYPES << kSmiTagSize);
  }

  // Copy constructor; it breaks the connection to host iterator
  // (as an iterator usually lives on stack).
  StackFrame(const StackFrame& original) V8_NOEXCEPT
      : iterator_(nullptr),
        isolate_(original.isolate_),
        state_(original.state_) {}

  // Type testers.
  bool is_entry() const { return type() == ENTRY; }
  bool is_construct_entry() const { return type() == CONSTRUCT_ENTRY; }
  bool is_exit() const { return type() == EXIT; }
  bool is_optimized_js() const {
    static_assert(TURBOFAN_JS == MAGLEV + 1);
    return base::IsInRange(type(), MAGLEV, TURBOFAN_JS);
  }
  bool is_unoptimized_js() const {
    static_assert(BASELINE == INTERPRETED + 1);
    return base::IsInRange(type(), INTERPRETED, BASELINE);
  }
  bool is_interpreted() const { return type() == INTERPRETED; }
  bool is_baseline() const { return type() == BASELINE; }
  bool is_maglev() const { return type() == MAGLEV; }
  bool is_turbofan_js() const { return type() == TURBOFAN_JS; }
#if V8_ENABLE_WEBASSEMBLY
  bool is_wasm() const {
    return this->type() == WASM || this->type() == WASM_SEGMENT_START
#ifdef V8_ENABLE_DRUMBRAKE
           || this->type() == WASM_INTERPRETER_ENTRY
#endif  // V8_ENABLE_DRUMBRAKE
        ;
  }
  bool is_c_wasm_entry() const { return type() == C_WASM_ENTRY; }
  bool is_wasm_liftoff_setup() const { return type() == WASM_LIFTOFF_SETUP; }
#if V8_ENABLE_DRUMBRAKE
  bool is_wasm_interpreter_entry() const {
    return type() == WASM_INTERPRETER_ENTRY;
  }
#endif  // V8_ENABLE_DRUMBRAKE
  bool is_wasm_debug_break() const { return type() == WASM_DEBUG_BREAK; }
  bool is_wasm_to_js() const {
    return type() == WASM_TO_JS || type() == WASM_TO_JS_FUNCTION;
  }
  bool is_js_to_wasm() const { return type() == JS_TO_WASM; }
#endif  // V8_ENABLE_WEBASSEMBLY
  bool is_builtin() const { return type() == BUILTIN; }
  bool is_internal() const { return type() == INTERNAL; }
  bool is_builtin_continuation() const {
    return type() == BUILTIN_CONTINUATION;
  }
  bool is_javascript_builtin_continuation() const {
    return type() == JAVASCRIPT_BUILTIN_CONTINUATION;
  }
  bool is_javascript_builtin_with_catch_continuation() const {
    return type() == JAVASCRIPT_BUILTIN_CONTINUATION_WITH_CATCH;
  }
  bool is_construct() const { return type() == CONSTRUCT; }
  bool is_fast_construct() const { return type() == FAST_CONSTRUCT; }
  bool is_builtin_exit() const { return type() == BUILTIN_EXIT; }
  bool is_api_accessor_exit() const { return type() == API_ACCESSOR_EXIT; }
  bool is_api_callback_exit() const { return type() == API_CALLBACK_EXIT; }
  bool is_irregexp() const { return type() == IRREGEXP; }

  static bool IsJavaScript(Type t) {
    static_assert(INTERPRETED + 1 == BASELINE);
    static_assert(BASELINE + 1 == MAGLEV);
    static_assert(MAGLEV + 1 == TURBOFAN_JS);
    return t >= INTERPRETED && t <= TURBOFAN_JS;
  }
  bool is_javascript() const { return IsJavaScript(type()); }

  // Accessors.
  Address sp() const {
    DCHECK(!InFastCCall());
    return state_.sp;
  }
  Address fp() const { return state_.fp; }
  Address callee_fp() const { return state_.callee_fp; }
  Address callee_pc() const { return state_.callee_pc; }
  Address caller_sp() const { return GetCallerStackPointer(); }
  inline Address pc() const;
  bool is_profiler_entry_frame() const {
    return state_.is_profiler_entry_frame;
  }
  bool is_stack_exit_frame() const { return state_.is_stack_exit_frame; }

  // Skip authentication of the PC, when using CFI. Used in the profiler, where
  // in certain corner-cases we do not use an address on the stack, which would
  // be signed, as the PC of the frame.
  inline Address unauthenticated_pc() const;
  static inline Address unauthenticated_pc(Address* pc_address);

  // Conditionally calls either pc() or unauthenticated_pc() based on whether
  // this is fast C call stack frame.
  inline Address maybe_unauthenticated_pc() const;
  static inline Address maybe_unauthenticated_pc(Address* pc_address);

  // If the stack pointer is missing, this is a fast C call frame. For such
  // frames we cannot compute a stack pointer because of the missing ExitFrame.
  bool InFastCCall() const { return state_.sp == kNullAddress; }

  Address constant_pool() const { return *constant_pool_address(); }
  void set_constant_pool(Address constant_pool) {
    *constant_pool_address() = constant_pool;
  }

  Address* pc_address() const { return state_.pc_address; }

  Address* constant_pool_address() const {
    return state_.constant_pool_address;
  }

  // Get the id of this stack frame.
  StackFrameId id() const { return static_cast<StackFrameId>(caller_sp()); }

  // Get the top handler from the current stack iterator.
  inline StackHandler* top_handler() const;

  // Get the type of this frame.
  virtual Type type() const = 0;

  // Get the code associated with this frame. The result might be a Code object
  // or an empty value.
  // This method is used by Isolate::PushStackTraceAndDie() for collecting a
  // stack trace on fatal error and thus it might be called in the middle of GC
  // and should be as safe as possible.
  virtual Tagged<HeapObject> unchecked_code() const = 0;

  // Search for the code associated with this frame.
  V8_EXPORT_PRIVATE Tagged<Code> LookupCode() const;
  V8_EXPORT_PRIVATE std::pair<Tagged<Code>, int> LookupCodeAndOffset() const;
  V8_EXPORT_PRIVATE Tagged<GcSafeCode> GcSafeLookupCode() const;
  V8_EXPORT_PRIVATE std::pair<Tagged<GcSafeCode>, int>
  GcSafeLookupCodeAndOffset() const;

  virtual void Iterate(RootVisitor* v) const = 0;
  void IteratePc(RootVisitor* v, Address* constant_pool_address,
                 Tagged<GcSafeCode> holder) const;

  // Sets a callback function for return-address rewriting profilers
  // to resolve the location of a return address to the location of the
  // profiler's stashed return address.
  static void SetReturnAddressLocationResolver(
      ReturnAddressLocationResolver resolver);

  static inline Address ReadPC(Address* pc_address);

  // Resolves pc_address through the resolution address function if one is set.
  static inline Address* ResolveReturnAddressLocation(Address* pc_address);

  // Printing support.
  enum PrintMode { OVERVIEW, DETAILS };
  virtual void Print(StringStream* accumulator, PrintMode mode,
                     int index) const;

  Isolate* isolate() const { return isolate_; }

  void operator=(const StackFrame& original) = delete;

 protected:
  inline explicit StackFrame(StackFrameIteratorBase* iterator);

  // Compute the stack pointer for the calling frame.
  virtual Address GetCallerStackPointer() const = 0;

  const StackFrameIteratorBase* const iterator_;

 private:
  Isolate* const isolate_;
  State state_;

  static ReturnAddressLocationResolver return_address_location_resolver_;

  // Fill in the state of the calling frame.
  virtual void ComputeCallerState(State* state) const = 0;

  // Get the type and the state of the calling frame.
  virtual Type GetCallerState(State* state) const;

  static const intptr_t kIsolateTag = 1;

  friend class StackFrameIterator;
  friend class StackFrameIteratorBase;
  friend class StackHandlerIterator;
  friend class StackFrameIteratorForProfiler;
};

class CommonFrame;

class V8_EXPORT_PRIVATE FrameSummary {
 public:
// Subclasses for the different summary kinds:
#define FRAME_SUMMARY_VARIANTS(F)                                          \
  F(JAVASCRIPT, JavaScriptFrameSummary, javascript_summary_, JavaScript)   \
  IF_WASM(F, BUILTIN, BuiltinFrameSummary, builtin_summary_, Builtin)      \
  IF_WASM(F, WASM, WasmFrameSummary, wasm_summary_, Wasm)                  \
  IF_WASM_DRUMBRAKE(F, WASM_INTERPRETED, WasmInterpretedFrameSummary,      \
                    wasm_interpreted_summary_, WasmInterpreted)            \
  IF_WASM(F, WASM_INLINED, WasmInlinedFrameSummary, wasm_inlined_summary_, \
          WasmInlined)

#define FRAME_SUMMARY_KIND(kind, type, field, desc) kind,
  enum Kind { FRAME_SUMMARY_VARIANTS(FRAME_SUMMARY_KIND) };
#undef FRAME_SUMMARY_KIND

  class FrameSummaryBase {
   public:
    FrameSummaryBase(Isolate* isolate, Kind kind)
        : isolate_(isolate), kind_(kind) {}
    Isolate* isolate() const { return isolate_; }
    Kind kind() const { return kind_; }

   private:
    Isolate* isolate_;
    Kind kind_;
  };

  class JavaScriptFrameSummary : public FrameSummaryBase {
   public:
    JavaScriptFrameSummary(Isolate* isolate, Tagged<Object> receiver,
                           Tagged<JSFunction> function,
                           Tagged<AbstractCode> abstract_code, int code_offset,
                           bool is_constructor, Tagged<FixedArray> parameters);

    void EnsureSourcePositionsAvailable();
    bool AreSourcePositionsAvailable() const;

    Handle<Object> receiver() const { return receiver_; }
    Handle<JSFunction> function() const { return function_; }
    Handle<AbstractCode> abstract_code() const { return abstract_code_; }
    int code_offset() const { return code_offset_; }
    bool is_constructor() const { return is_constructor_; }
    Handle<FixedArray> parameters() const { return parameters_; }
    bool is_subject_to_debugging() const;
    int SourcePosition() const;
    int SourceStatementPosition() const;
    Handle<Object> script() const;
    Handle<Context> native_context() const;
    Handle<StackFrameInfo> CreateStackFrameInfo() const;

   private:
    Handle<Object> receiver_;
    Handle<JSFunction> function_;
    Handle<AbstractCode> abstract_code_;
    int code_offset_;
    bool is_constructor_;
    Handle<FixedArray> parameters_;
  };

#if V8_ENABLE_WEBASSEMBLY
  class WasmFrameSummary : public FrameSummaryBase {
   public:
    WasmFrameSummary(Isolate* isolate,
                     Handle<WasmTrustedInstanceData> instance_data,
                     wasm::WasmCode* code, int byte_offset, int function_index,
                     bool at_to_number_conversion);

    Handle<Object> receiver() const;
    uint32_t function_index() const;
    wasm::WasmCode* code() const { return code_; }
    // Returns the wire bytes offset relative to the function entry.
    int code_offset() const { return byte_offset_; }
    bool is_constructor() const { return false; }
    bool is_subject_to_debugging() const { return true; }
    int SourcePosition() const;
    int SourceStatementPosition() const { return SourcePosition(); }
    Handle<Script> script() const;
    Handle<WasmInstanceObject> wasm_instance() const;
    Handle<WasmTrustedInstanceData> wasm_trusted_instance_data() const {
      return instance_data_;
    }
    Handle<Context> native_context() const;
    bool at_to_number_conversion() const { return at_to_number_conversion_; }
    Handle<StackFrameInfo> CreateStackFrameInfo() const;

   private:
    Handle<WasmTrustedInstanceData> instance_data_;
    bool at_to_number_conversion_;
    wasm::WasmCode* code_;
    int byte_offset_;
    int function_index_;
  };

  // Summary of a wasm frame inlined into JavaScript. (Wasm frames inlined into
  // wasm are expressed by a WasmFrameSummary.)
  class WasmInlinedFrameSummary : public FrameSummaryBase {
   public:
    WasmInlinedFrameSummary(Isolate* isolate,
                            Handle<WasmTrustedInstanceData> instance_data,
                            int function_index, int op_wire_bytes_offset);

    Handle<WasmInstanceObject> wasm_instance() const;
    Handle<WasmTrustedInstanceData> wasm_trusted_instance_data() const {
      return instance_data_;
    }
    Handle<Object> receiver() const;
    uint32_t function_index() const;
    int code_offset() const { return op_wire_bytes_offset_; }
    bool is_constructor() const { return false; }
    bool is_subject_to_debugging() const { return true; }
    Handle<Script> script() const;
    int SourcePosition() const;
    int SourceStatementPosition() const { return SourcePosition(); }
    Handle<Context> native_context() const;
    Handle<StackFrameInfo> CreateStackFrameInfo() const;

   private:
    Handle<WasmTrustedInstanceData> instance_data_;
    int function_index_;
    int op_wire_bytes_offset_;  // relative to function offset.
  };

  class BuiltinFrameSummary : public FrameSummaryBase {
   public:
    BuiltinFrameSummary(Isolate*, Builtin);

    Builtin builtin() const { return builtin_; }

    Handle<Object> receiver() const;
    int code_offset() const { return 0; }
    bool is_constructor() const { return false; }
    bool is_subject_to_debugging() const { return false; }
    Handle<Object> script() const;
    int SourcePosition() const { return kNoSourcePosition; }
    int SourceStatementPosition() const { return 0; }
    Handle<Context> native_context() const;
    Handle<StackFrameInfo> CreateStackFrameInfo() const;

   private:
    Builtin builtin_;
  };

#if V8_ENABLE_DRUMBRAKE
  class WasmInterpretedFrameSummary : public FrameSummaryBase {
   public:
    WasmInterpretedFrameSummary(Isolate*, Handle<WasmInstanceObject>,
                                uint32_t function_index, int byte_offset);
    Handle<WasmInstanceObject> wasm_instance() const { return wasm_instance_; }
    Handle<WasmTrustedInstanceData> instance_data() const;
    uint32_t function_index() const { return function_index_; }
    int byte_offset() const { return byte_offset_; }

    Handle<Object> receiver() const;
    int code_offset() const { return byte_offset_; }
    bool is_constructor() const { return false; }
    bool is_subject_to_debugging() const { return true; }
    int SourcePosition() const;
    int SourceStatementPosition() const { return SourcePosition(); }
    Handle<Script> script() const;
    Handle<Context> native_context() const;
    Handle<StackFrameInfo> CreateStackFrameInfo() const;

   private:
    Handle<WasmInstanceObject> wasm_instance_;
    uint32_t function_index_;
    int byte_offset_;
  };
#endif  // V8_ENABLE_DRUMBRAKE
#endif  // V8_ENABLE_WEBASSEMBLY

#define FRAME_SUMMARY_CONS(kind, type, field, desc) \
  FrameSummary(type summ) : field(summ) {}  // NOLINT
  FRAME_SUMMARY_VARIANTS(FRAME_SUMMARY_CONS)
#undef FRAME_SUMMARY_CONS

  ~FrameSummary();

  static FrameSummary GetTop(const CommonFrame* frame);
  static FrameSummary GetBottom(const CommonFrame* frame);
  static FrameSummary GetSingle(const CommonFrame* frame);
  static FrameSummary Get(const CommonFrame* frame, int index);

  void EnsureSourcePositionsAvailable();
  bool AreSourcePositionsAvailable() const;

  // Dispatched accessors.
  Handle<Object> receiver() const;
  int code_offset() const;
  bool is_constructor() const;
  bool is_subject_to_debugging() const;
  Handle<Object> script() const;
  int SourcePosition() const;
  int SourceStatementPosition() const;
  Handle<Context> native_context() const;
  Handle<StackFrameInfo> CreateStackFrameInfo() const;

#define FRAME_SUMMARY_CAST(kind_, type, field, desc)      \
  bool Is##desc() const { return base_.kind() == kind_; } \
  const type& As##desc() const {                          \
    DCHECK_EQ(base_.kind(), kind_);                       \
    return field;                                         \
  }
  FRAME_SUMMARY_VARIANTS(FRAME_SUMMARY_CAST)
#undef FRAME_SUMMARY_CAST

 private:
#define FRAME_SUMMARY_FIELD(kind, type, field, desc) type field;
  union {
    FrameSummaryBase base_;
    FRAME_SUMMARY_VARIANTS(FRAME_SUMMARY_FIELD)
  };
#undef FRAME_SUMMARY_FIELD
};

class CommonFrame : public StackFrame {
 public:
  // Accessors.
  virtual Tagged<Object> context()
      const;  // TODO(victorgomes): CommonFrames don't have context.
  virtual int position() const;

  // Access the expressions in the stack frame including locals.
  inline Tagged<Object> GetExpression(int index) const;
  inline void SetExpression(int index, Tagged<Object> value);
  int ComputeExpressionsCount() const;

  Address GetCallerStackPointer() const override;

  // Build a list with summaries for this frame including all inlined frames.
  // The functions are ordered bottom-to-top (i.e. summaries.last() is the
  // top-most activation; caller comes before callee).
  virtual void Summarize(std::vector<FrameSummary>* frames) const;

  static CommonFrame* cast(StackFrame* frame) {
    // It is always safe to cast to common.
    return static_cast<CommonFrame*>(frame);
  }

 protected:
  inline explicit CommonFrame(StackFrameIteratorBase* iterator);

  bool HasTaggedOutgoingParams(Tagged<GcSafeCode> code_lookup) const;

  void ComputeCallerState(State* state) const override;

  // Accessors.
  inline Address caller_fp() const;
  inline Address caller_pc() const;

  // Iterate over expression stack including stack handlers, locals,
  // and parts of the fixed part including context and code fields.
  void IterateExpressions(RootVisitor* v) const;

  void IterateTurbofanJSOptimizedFrame(RootVisitor* v) const;

  // Returns the address of the n'th expression stack element.
  virtual Address GetExpressionAddress(int n) const;
};

// This frame is used for TF-optimized code without JS linkage, but
// contains the context instead of a type marker.
class TurbofanStubWithContextFrame : public CommonFrame {
 public:
  Type type() const override { return TURBOFAN_STUB_WITH_CONTEXT; }

  Tagged<HeapObject> unchecked_code() const override;
  void Iterate(RootVisitor* v) const override;

 protected:
  inline explicit TurbofanStubWithContextFrame(
      StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

class TypedFrame : public CommonFrame {
 public:
  Tagged<HeapObject> unchecked_code() const override { return {}; }
  void Iterate(RootVisitor* v) const override;

  void IterateParamsOfGenericWasmToJSWrapper(RootVisitor* v) const;
  void IterateParamsOfOptimizedWasmToJSWrapper(RootVisitor* v) const;

 protected:
  inline explicit TypedFrame(StackFrameIteratorBase* iterator);
};

class CommonFrameWithJSLinkage : public CommonFrame {
 public:
  // Accessors.
  virtual Tagged<JSFunction> function() const = 0;

  // Access the parameters.
  virtual Tagged<Object> receiver() const;
  virtual Tagged<Object> GetParameter(int index) const;
  virtual int ComputeParametersCount() const;
  Handle<FixedArray> GetParameters() const;
  virtual int GetActualArgumentCount() const;

  Tagged<HeapObject> unchecked_code() const override;

  // Lookup exception handler for current {pc}, returns -1 if none found. Also
  // returns data associated with the handler site specific to the frame type:
  //  - OptimizedJSFrame  : Data is not used and will not return a value.
  //  - UnoptimizedJSFrame: Data is the register index holding the context.
  virtual int LookupExceptionHandlerInTable(
      int* data, HandlerTable::CatchPrediction* prediction);

  // Check if this frame is a constructor frame invoked through 'new'.
  virtual bool IsConstructor() const;

  // Summarize Frame
  void Summarize(std::vector<FrameSummary>* frames) const override;

 protected:
  inline explicit CommonFrameWithJSLinkage(StackFrameIteratorBase* iterator);

  // Determines if the standard frame for the given frame pointer is a
  // construct frame.
  static inline bool IsConstructFrame(Address fp);
  inline Address GetParameterSlot(int index) const;
};

class TypedFrameWithJSLinkage : public CommonFrameWithJSLinkage {
 public:
  void Iterate(RootVisitor* v) const override;

 protected:
  inline explicit TypedFrameWithJSLinkage(StackFrameIteratorBase* iterator);
};

class JavaScriptFrame : public CommonFrameWithJSLinkage {
 public:
  Type type() const override = 0;

  // Accessors.
  Tagged<JSFunction> function() const override;
  Tagged<Object> unchecked_function() const;
  Tagged<Script> script() const;
  Tagged<Object> context() const override;
  int GetActualArgumentCount() const override;

  inline void set_receiver(Tagged<Object> value);

  // Debugger access.
  void SetParameterValue(int index, Tagged<Object> value) const;

  // Check if this frame is a constructor frame invoked through 'new'.
  bool IsConstructor() const override;

  // Garbage collection support.
  void Iterate(RootVisitor* v) const override;

  // Printing support.
  void Print(StringStream* accumulator, PrintMode mode,
             int index) const override;

  // Return a list with {SharedFunctionInfo} objects of this frame.
  virtual void GetFunctions(
      std::vector<Tagged<SharedFunctionInfo>>* functions) const;

  void GetFunctions(std::vector<Handle<SharedFunctionInfo>>* functions) const;

  // Returns {AbstractCode, code offset} pair for this frame's PC value.
  std::tuple<Tagged<AbstractCode>, int> GetActiveCodeAndOffset() const;

  // Architecture-specific register description.
  static Register fp_register();
  static Register context_register();
  static Register constant_pool_pointer_register();

  bool is_unoptimized() const { return is_unoptimized_js(); }
  bool is_optimized() const { return is_optimized_js(); }
  bool is_turbofan() const { return is_turbofan_js(); }

  static JavaScriptFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_javascript());
    return static_cast<JavaScriptFrame*>(frame);
  }

  static void PrintFunctionAndOffset(Isolate* isolate,
                                     Tagged<JSFunction> function,
                                     Tagged<AbstractCode> code, int code_offset,
                                     FILE* file, bool print_line_number);

  static void PrintTop(Isolate* isolate, FILE* file, bool print_args,
                       bool print_line_number);

  static void CollectFunctionAndOffsetForICStats(Isolate* isolate,
                                                 Tagged<JSFunction> function,
                                                 Tagged<AbstractCode> code,
                                                 int code_offset);

 protected:
  inline explicit JavaScriptFrame(StackFrameIteratorBase* iterator);

  Address GetCallerStackPointer() const override;

  virtual void PrintFrameKind(StringStream* accumulator) const {}

 private:
  inline Tagged<Object> function_slot_object() const;

  friend class StackFrameIteratorBase;
};

class NativeFrame : public TypedFrame {
 public:
  Type type() const override { return NATIVE; }

  // Garbage collection support.
  void Iterate(RootVisitor* v) const override {}

 protected:
  inline explicit NativeFrame(StackFrameIteratorBase* iterator);

 private:
  void ComputeCallerState(State* state) const override;

  friend class StackFrameIteratorBase;
};

// Entry frames are used to enter JavaScript execution from C.
class EntryFrame : public TypedFrame {
 public:
  Type type() const override { return ENTRY; }

  Tagged<HeapObject> unchecked_code() const override;

  // Garbage collection support.
  void Iterate(RootVisitor* v) const override;

  static EntryFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_entry());
    return static_cast<EntryFrame*>(frame);
  }

 protected:
  inline explicit EntryFrame(StackFrameIteratorBase* iterator);

  // The caller stack pointer for entry frames is always zero. The
  // real information about the caller frame is available through the
  // link to the top exit frame.
  Address GetCallerStackPointer() const override { return 0; }

 private:
  void ComputeCallerState(State* state) const override;
  Type GetCallerState(State* state) const override;

  friend class StackFrameIteratorBase;
};

class ConstructEntryFrame : public EntryFrame {
 public:
  Type type() const override { return CONSTRUCT_ENTRY; }

  Tagged<HeapObject> unchecked_code() const override;

  static ConstructEntryFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_construct_entry());
    return static_cast<ConstructEntryFrame*>(frame);
  }

 protected:
  inline explicit ConstructEntryFrame(StackFrameIteratorBase* iterator);

 private:
  friend class StackFrameIteratorBase;
};

// Exit frames are used to exit JavaScript execution and go to C, or to switch
// out of the current stack for wasm stack-switching.
class ExitFrame : public TypedFrame {
 public:
  Type type() const override { return EXIT; }

  // Garbage collection support.
  void Iterate(RootVisitor* v) const override;

  static ExitFrame* cast(StackFrame* frame) {
    DCHECK(frame->is_exit());
    return static_cast<ExitFrame*>(frame);
  }

  // Compute the state and type of an exit frame given a frame
  // pointer. Used when construc
```