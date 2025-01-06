Response: Let's break down the thought process for analyzing this Torque file.

1. **Understand the Goal:** The core request is to summarize the functionality of the provided Torque code. This means identifying its main purpose, key data structures, and how it interacts with JavaScript and WebAssembly.

2. **Initial Scan for Keywords:**  A quick skim reveals important terms like "wasm," "JSToWasm," "WasmToJS," "wrapper," "promise," "arguments," "return," "parameter," "stack," "registers," "types," and "BigInt." These keywords give strong hints about the file's function. The filename `js-to-wasm.tq` is also a big clue.

3. **Identify Key Data Structures:** The code defines several `struct` types like `Int64AsInt32Pair`, `ReturnSlotAllocator`, and `LocationAllocator`. These are crucial for understanding how data is managed. Focus on what these structures *do* rather than just their names. For instance, `ReturnSlotAllocator` clearly manages stack space for return values.

4. **Analyze Global Constants and Enums:**  The file defines numerous `constexpr` constants and `enum` types. These are configuration parameters and type definitions. Understanding `kWasmI32Type`, `kWasmF64Type`, `ValueKind::kRef`, `Promise::kPromise`, and `HeapType::kExtern` is essential for grasping the types being handled. Pay attention to the comments associated with these constants, as they often explain their purpose (e.g., offsets within data structures).

5. **Examine External Runtime and Builtin Declarations:**  The `extern runtime` and `extern builtin` declarations indicate interactions with other parts of the V8 engine. Names like `WasmGenericJSToWasmObject`, `TierUpJSToWasmWrapper`, `JSToWasmWrapperAsm`, and `WasmReturnPromiseOnSuspendAsm` suggest specific steps in the JSToWasm transition. Note that these are *declarations*; the actual implementation is elsewhere.

6. **Focus on Macros and Functions:**  Macros like `Bitcast`, `RefCast`, `TruncateBigIntToI64`, `HandleF32Params`, `JSToWasmObject`, `WasmToJSObject`, and `JSToWasmWrapperHelper` contain the core logic. Pay attention to their parameters and return types. `JSToWasmWrapperHelper` appears to be the main entry point for the JSToWasm transition.

7. **Trace the Execution Flow (Conceptual):**  Imagine how the `JSToWasmWrapper` function would be called. It gets a JavaScript function (`target`) and arguments. It then needs to prepare the data for the WebAssembly call. The code clearly deals with:
    * Extracting signature information (`sig`).
    * Allocating space for parameters (`paramBuffer`).
    * Converting JavaScript values to WebAssembly types.
    * Handling different return types (single vs. multiple).
    * Dealing with Promises.
    * Calling the assembly-level wrapper (`JSToWasmWrapperAsm`).
    * Processing return values (`JSToWasmHandleReturns`).

8. **Identify JavaScript Interaction Points:** Look for places where JavaScript values are being converted to WebAssembly types (e.g., `WasmTaggedToFloat32`, `TruncateBigIntToI64`, `JSToWasmObject`) and vice versa (e.g., `WasmToJSObject`, `I64ToBigInt`). This is where the connection between the two worlds is made.

9. **Look for Potential Issues (Programming Errors):** The code includes checks and type conversions that suggest potential error scenarios. For example, the `JSToWasmObject` macro throws `TypeError` in several cases, indicating possible mismatches between JavaScript values and expected WebAssembly types. The BigInt handling also hints at potential truncation issues.

10. **Construct Examples (Mental or Written):** Once you understand the core functionality, start thinking about concrete JavaScript examples that would trigger this code. This helps solidify your understanding. Think about different parameter types, return types, and scenarios involving Promises.

11. **Structure the Summary:** Organize the findings into logical sections. Start with a high-level overview, then delve into specific aspects like parameter handling, return value handling, and error scenarios. Use clear and concise language.

12. **Refine and Elaborate:**  Review the summary for clarity and completeness. Add details where necessary, but avoid getting bogged down in low-level implementation details unless they are crucial to understanding the overall functionality. For example, mentioning the stack and register allocation is important, but describing the exact bit manipulation might not be necessary for a general summary.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This file just converts JavaScript to WebAssembly."
* **Correction:** "It's more than just conversion. It also handles parameter passing, return value marshalling, Promise integration, and optimization (tier-up)."

* **Initial thought:** "The `LocationAllocator` is just for memory allocation."
* **Correction:** "It's specifically for allocating memory in registers and on the stack for WebAssembly function calls, taking into account platform-specific register usage."

* **Initial thought:**  "The `JSToWasmWrapperAsm` is where the WebAssembly is called."
* **Correction:** "It *transitions* to the assembly code that performs the actual call. The `call_target` points to the WebAssembly function."

By following this iterative process of scanning, analyzing, connecting, and refining, you can arrive at a comprehensive and accurate summary of the Torque code's functionality.
这个v8 torque文件 `v8/src/builtins/js-to-wasm.tq` 的主要功能是 **定义了将 JavaScript 代码调用 WebAssembly 模块中导出的函数时所需的样板代码 (boilerplate code) 和辅助函数。**  它负责在 JavaScript 和 WebAssembly 之间进行数据类型的转换、参数的传递、返回值的处理，并处理异步调用（Promise）。

以下是更详细的归纳：

**核心功能:**

1. **JavaScript 到 WebAssembly 的桥梁:**  它定义了 `JSToWasmWrapper` 这个 JavaScript 内置函数 (builtin)，该函数作为 JavaScript 调用 WebAssembly 导出函数的入口点。
2. **参数处理:**
   - **参数类型转换:**  负责将 JavaScript 的值转换为 WebAssembly 期望的类型 (例如，JavaScript Number 到 wasm i32/f64，JavaScript BigInt 到 wasm i64，JavaScript 对象到 wasm 的引用类型)。
   - **参数传递:**  根据 WebAssembly 函数的签名，将转换后的参数放置到寄存器或栈上的正确位置，以便 WebAssembly 代码可以访问。
3. **返回值处理:**
   - **返回值类型转换:**  负责将 WebAssembly 函数返回的值转换为 JavaScript 的值。
   - **多返回值处理:**  支持 WebAssembly 函数返回多个值的情况，并将这些值组合成一个 JavaScript 数组。
4. **异步调用 (Promise 支持):**  定义了 `WasmPromising` 和 `WasmStressSwitch` 这两个内置函数，用于处理返回 Promise 的 WebAssembly 异步函数调用。
5. **优化 (Wrapper Tier-Up):**  实现了 wrapper 的分层优化 (`TierUpJSToWasmWrapper`)，当一个 JavaScript 到 WebAssembly 的 wrapper 函数被频繁调用时，会触发优化，生成更高效的调用代码。
6. **数据结构定义:** 定义了一些关键的数据结构，用于管理参数和返回值的分配，例如 `ReturnSlotAllocator` 和 `LocationAllocator`。
7. **平台差异处理:** 代码中包含了一些针对不同 CPU 架构 (32-bit vs 64-bit, 大端 vs 小端) 的特殊处理逻辑。

**与 JavaScript 功能的关系 (通过 JavaScript 示例):**

假设我们有一个名为 `my_wasm_module.wasm` 的 WebAssembly 模块，其中导出了一个名为 `add` 的函数，该函数接受两个 i32 类型的参数并返回一个 i32 类型的值。

```javascript
// 加载 WebAssembly 模块 (简化示例)
const wasmModule = await WebAssembly.instantiateStreaming(fetch('my_wasm_module.wasm'));
const addWasm = wasmModule.instance.exports.add;

// 调用 WebAssembly 函数
const result = addWasm(5, 10);
console.log(result); // 输出 15
```

在这个例子中，当我们调用 `addWasm(5, 10)` 时，V8 引擎内部会使用 `JSToWasmWrapper` (或者其优化的版本) 来处理这个调用。 `js-to-wasm.tq` 中的代码会负责：

- 将 JavaScript 的数字 `5` 和 `10` 转换为 WebAssembly 的 i32 类型。
- 将这两个 i32 类型的参数传递给 WebAssembly 的 `add` 函数。
- 在 WebAssembly 函数执行完毕后，将返回的 i32 类型的值转换回 JavaScript 的数字。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 WebAssembly 函数，其签名是接受一个 `i32` 和一个 `f64` 类型的参数，并返回一个 `f32` 类型的值。

**假设输入 (JavaScript 调用):**

```javascript
const wasmModule = await WebAssembly.instantiateStreaming(fetch('my_wasm_module.wasm'));
const myWasmFunc = wasmModule.instance.exports.myFunc;
const input1 = 10; // JavaScript Number, 将被转换为 i32
const input2 = 3.14; // JavaScript Number, 将被转换为 f64
const result = myWasmFunc(input1, input2);
```

**`js-to-wasm.tq` 的处理逻辑 (简化):**

1. `JSToWasmWrapper` 被调用。
2. 从 `myWasmFunc` 的元数据中获取 WebAssembly 函数的签名信息 (参数类型 `i32`, `f64`，返回值类型 `f32`)。
3. 使用 `LocationAllocatorForParams` 分配参数的存储空间 (可能在寄存器或栈上)。
4. 将 JavaScript 的 `input1` (值为 10) 转换为 i32，并存储到分配的第一个参数的位置。
5. 将 JavaScript 的 `input2` (值为 3.14) 转换为 f64，并存储到分配的第二个参数的位置。
6. 调用底层的汇编代码 (`JSToWasmWrapperAsm`)，将参数传递给 WebAssembly 函数。
7. WebAssembly 函数执行并返回一个 f32 类型的值。
8. `JSToWasmHandleReturns` 被调用。
9. 从寄存器或栈上读取返回的 f32 值。
10. 将 WebAssembly 的 f32 值转换回 JavaScript 的 Number 类型。

**假设输出 (JavaScript):**

`result` 变量将包含 WebAssembly 函数返回的 f32 值 (以 JavaScript Number 的形式)。

**用户常见的编程错误:**

1. **参数类型不匹配:**  用户在 JavaScript 中传递的参数类型与 WebAssembly 函数期望的类型不一致。 例如，WebAssembly 期望一个 `i32`，但 JavaScript 传递了一个字符串。

   ```javascript
   // 假设 wasmFunc 期望一个 i32 参数
   myWasmFunc("hello"); // 可能会导致类型错误或非预期的行为
   ```
   `js-to-wasm.tq` 中的 `JSToWasmObject` 宏会进行一些类型检查，如果类型不匹配，可能会抛出 `TypeError`。

2. **返回值类型理解错误:** 用户假设 WebAssembly 函数返回某种类型，但实际返回的是另一种类型，导致 JavaScript 无法正确解析返回值。

3. **BigInt 使用不当 (32 位平台):** 在 32 位平台上处理 wasm i64 类型时，需要特别注意 JavaScript 的 `Number` 类型无法精确表示 64 位整数。用户可能会错误地将 wasm i64 返回值当作普通的 JavaScript `Number` 使用，导致精度丢失。

   ```javascript
   // 假设 wasmFunc 返回一个 i64 大的值
   const largeValue = myWasmFunc();
   console.log(largeValue); // 在 32 位平台上可能会显示不精确的值
   ```
   V8 会尝试将 wasm i64 转换为 JavaScript 的 `BigInt` 类型，但在某些情况下，用户可能没有意识到这一点。

4. **异步 WebAssembly 函数处理不当:**  用户调用了返回 Promise 的 WebAssembly 函数，但没有正确地处理 Promise 的 resolve 或 reject。

   ```javascript
   // 假设 wasmAsyncFunc 返回一个 Promise
   const promise = wasmAsyncFunc();
   // 如果没有 .then() 或 await，可能无法获取异步操作的结果
   ```
   `js-to-wasm.tq` 中的 `WasmPromising` 和 `WasmStressSwitch` 内置函数负责处理这些异步场景。

总而言之，`v8/src/builtins/js-to-wasm.tq` 是 V8 引擎中连接 JavaScript 和 WebAssembly 的关键组件，它定义了类型转换、参数传递、返回值处理以及异步调用所需的底层机制，确保了 JavaScript 代码能够安全有效地调用 WebAssembly 模块的功能。

Prompt: 
```
这是目录为v8/src/builtins/js-to-wasm.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/wasm/wasm-linkage.h'

namespace runtime {
extern runtime WasmGenericJSToWasmObject(
    Context, WasmTrustedInstanceData|Undefined, JSAny, Smi): JSAny;
extern runtime WasmGenericWasmToJSObject(Context, Object): JSAny;
extern runtime TierUpJSToWasmWrapper(NoContext, WasmExportedFunctionData):
    JSAny;
extern runtime WasmAllocateSuspender(Context): JSAny;
}  // namespace runtime

namespace wasm {
extern builtin JSToWasmWrapperAsm(
    RawPtr<intptr>, WasmImportData|WasmTrustedInstanceData, JSAny): JSAny;
extern builtin WasmReturnPromiseOnSuspendAsm(
    RawPtr<intptr>, WasmImportData|WasmTrustedInstanceData, JSAny): JSAny;
extern builtin JSToWasmStressSwitchStacksAsm(
    RawPtr<intptr>, WasmImportData|WasmTrustedInstanceData, JSAny): JSAny;

extern macro UniqueIntPtrConstant(constexpr intptr): intptr;

const kWasmExportedFunctionDataSignatureOffset:
    constexpr int32 generates 'WasmExportedFunctionData::kSigOffset';

const kWasmReturnCountOffset:
    constexpr intptr generates 'wasm::FunctionSig::kReturnCountOffset';

const kWasmParameterCountOffset: constexpr intptr
    generates 'wasm::FunctionSig::kParameterCountOffset';

const kWasmSigTypesOffset:
    constexpr intptr generates 'wasm::FunctionSig::kRepsOffset';

// This constant should only be loaded as a `UniqueIntPtrConstant` to avoid
// problems with PGO.
// `- 1` because of the instance parameter.
const kNumGPRegisterParameters:
    constexpr intptr generates 'arraysize(wasm::kGpParamRegisters) - 1';

// This constant should only be loaded as a `UniqueIntPtrConstant` to avoid
// problems with PGO.
const kNumFPRegisterParameters:
    constexpr intptr generates 'arraysize(wasm::kFpParamRegisters)';

const kNumGPRegisterReturns:
    constexpr intptr generates 'arraysize(wasm::kGpReturnRegisters)';

const kNumFPRegisterReturns:
    constexpr intptr generates 'arraysize(wasm::kFpReturnRegisters)';

const kWasmI32Type:
    constexpr int32 generates 'wasm::kWasmI32.raw_bit_field()';
const kWasmI64Type:
    constexpr int32 generates 'wasm::kWasmI64.raw_bit_field()';
const kWasmF32Type:
    constexpr int32 generates 'wasm::kWasmF32.raw_bit_field()';
const kWasmF64Type:
    constexpr int32 generates 'wasm::kWasmF64.raw_bit_field()';

const kIsFpAlwaysDouble:
    constexpr bool generates 'wasm::kIsFpAlwaysDouble';
const kIsBigEndian: constexpr bool generates 'wasm::kIsBigEndian';
const kIsBigEndianOnSim:
    constexpr bool generates 'wasm::kIsBigEndianOnSim';

extern enum ValueKind extends int32 constexpr 'wasm::ValueKind' {
  kRef,
  kRefNull,
  ...
}

extern enum Promise extends int32 constexpr 'wasm::Promise' {
  kPromise,
  kNoPromise,
  kStressSwitch
}

extern enum HeapType extends int32
    constexpr 'wasm::HeapType::Representation' {
  kExtern,
  kNoExtern,
  kString,
  kEq,
  kI31,
  kStruct,
  kArray,
  kAny,
  kNone,
  kFunc,
  kNoFunc,
  kExn,
  kNoExn,
  ...
}

const kWrapperBufferReturnCount: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferReturnCount';
const kWrapperBufferRefReturnCount: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferRefReturnCount';
const kWrapperBufferSigRepresentationArray: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferSigRepresentationArray'
    ;
const kWrapperBufferStackReturnBufferSize: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferSize'
    ;
const kWrapperBufferCallTarget: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferCallTarget';
const kWrapperBufferParamStart: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferParamStart';
const kWrapperBufferParamEnd: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferParamEnd';
const kWrapperBufferStackReturnBufferStart: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferStackReturnBufferStart'
    ;
const kWrapperBufferFPReturnRegister1: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister1'
    ;
const kWrapperBufferFPReturnRegister2: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferFPReturnRegister2'
    ;
const kWrapperBufferGPReturnRegister1: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister1'
    ;
const kWrapperBufferGPReturnRegister2: constexpr intptr
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferGPReturnRegister2'
    ;
const kWrapperBufferSize: constexpr int32
    generates 'JSToWasmWrapperFrameConstants::kWrapperBufferSize';

const kValueTypeKindBits: constexpr int32
    generates 'wasm::ValueType::kKindBits';
const kValueTypeKindBitsMask: constexpr int32
    generates 'wasm::kWasmValueKindBitsMask';
const kValueTypeHeapTypeMask: constexpr int32
    generates 'wasm::kWasmHeapTypeBitsMask';

macro Bitcast<To: type, From: type>(i: From): To {
  return i;
}

extern macro BitcastFloat32ToInt32(float32): uint32;
extern macro BitcastInt32ToFloat32(int32): float32;

Bitcast<uint32, float32>(v: float32): uint32 {
  return BitcastFloat32ToInt32(v);
}

macro RefCast<To: type>(i: &intptr):
  &To {
  return torque_internal::unsafe::NewReference<To>(i.object, i.offset);
}

macro TruncateBigIntToI64(context: Context, input: JSAny): intptr {
  // This is only safe to use on 64-bit platforms.
  dcheck(Is64());
  const bigint = ToBigInt(context, input);

  if (bigint::ReadBigIntLength(bigint) == 0) {
    return 0;
  }

  const digit = bigint::LoadBigIntDigit(bigint, 0);
  if (bigint::ReadBigIntSign(bigint) == bigint::kPositiveSign) {
    // Note that even though the bigint is positive according to its sign, the
    // result of `Signed(digit)` can be negative if the most significant bit is
    // set. This is intentional and follows the specification of `ToBigInt64()`.
    return Signed(digit);
  }
  return 0 - Signed(digit);
}

@export
struct Int64AsInt32Pair {
  low: uintptr;
  high: uintptr;
}

// This is only safe to use on 32-bit platforms.
extern macro BigIntToRawBytes(BigInt): Int64AsInt32Pair;

// The ReturnSlotAllocator calculates the size of the space needed on the stack
// for return values.
struct ReturnSlotAllocator {
  macro AllocStack(): void {
    if constexpr (Is64()) {
      this.stackSlots++;
    } else {
      if (this.hasSmallSlot) {
        this.hasSmallSlot = false;
        this.smallSlotLast = false;
      } else {
        this.stackSlots += 2;
        this.hasSmallSlot = true;
        this.smallSlotLast = true;
      }
    }
    return;
  }

  macro AllocGP(): void {
    if (this.remainingGPRegs > 0) {
      this.remainingGPRegs--;
      return;
    }
    this.AllocStack();
  }

  macro AllocFP32(): void {
    if (this.remainingFPRegs > 0) {
      this.remainingFPRegs--;
      return;
    }
    this.AllocStack();
  }

  macro AllocFP64(): void {
    if (this.remainingFPRegs > 0) {
      this.remainingFPRegs--;
      return;
    }
    if constexpr (Is64()) {
      this.stackSlots++;
    } else {
      this.stackSlots += 2;
      this.smallSlotLast = false;
    }
  }

  macro GetSize(): intptr {
    if (this.smallSlotLast) {
      return this.stackSlots - 1;
    } else {
      return this.stackSlots;
    }
  }

  // For references we start a new section on the stack, no old slots are
  // filled.
  macro StartRefs(): void {
    if (!this.smallSlotLast) {
      this.hasSmallSlot = false;
    }
  }

  remainingGPRegs: intptr;
  remainingFPRegs: intptr;
  // Even on 32-bit platforms we always allocate 64-bit stack space at a time to
  // preserve alignment. If we allocate a 64-bit slot for a 32-bit type, then we
  // remember the second half of the 64-bit slot as `smallSlot` so that it can
  // be used for the next 32-bit type.
  hasSmallSlot: bool;
  // If the {smallSlot} is in the middle of the whole allocated stack space,
  // then it is part of the overall stack space size. However, if the hole is at
  // the border of the whole allocated stack space, then we have to subtract it
  // from the overall stack space size. This flag keeps track of whether the
  // hole is in the middle (false) or at the border (true).
  smallSlotLast: bool;
  stackSlots: intptr;
}

macro NewReturnSlotAllocator(): ReturnSlotAllocator {
  let result: ReturnSlotAllocator;
  result.remainingGPRegs = kNumGPRegisterReturns;
  result.remainingFPRegs = kNumFPRegisterReturns;
  result.stackSlots = 0;
  result.hasSmallSlot = false;
  result.smallSlotLast = false;
  return result;
}

struct LocationAllocator {
  macro GetStackSlot(): &intptr {
    if constexpr (Is64()) {
      const result = torque_internal::unsafe::NewReference<intptr>(
          this.object, this.nextStack);
      this.nextStack += torque_internal::SizeOf<intptr>();
      return result;
    } else {
      if (this.smallSlot != 0) {
        const result = torque_internal::unsafe::NewReference<intptr>(
            this.object, this.smallSlot);
        this.smallSlot = 0;
        this.smallSlotLast = false;
        return result;
      }
      const result = torque_internal::unsafe::NewReference<intptr>(
          this.object, this.nextStack);
      this.smallSlot = this.nextStack + torque_internal::SizeOf<intptr>();
      this.nextStack = this.smallSlot + torque_internal::SizeOf<intptr>();
      this.smallSlotLast = true;
      return result;
    }
  }

  macro GetGPSlot(): &intptr {
    if (this.remainingGPRegs-- > 0) {
      const result = torque_internal::unsafe::NewReference<intptr>(
          this.object, this.nextGPReg);
      this.nextGPReg += torque_internal::SizeOf<intptr>();
      return result;
    }
    return this.GetStackSlot();
  }

  macro GetFP32Slot(): &intptr {
    if (this.remainingFPRegs-- > 0) {
      const result = torque_internal::unsafe::NewReference<intptr>(
          this.object, this.nextFPReg);
      this.nextFPReg += torque_internal::SizeOf<float64>();
      return result;
    }
    return this.GetStackSlot();
  }

  macro GetRemainingFPRegs(): intptr {
    return this.remainingFPRegs;
  }

  macro GetFP64Slot(): &intptr {
    if (this.remainingFPRegs-- > 0) {
      const result = torque_internal::unsafe::NewReference<intptr>(
          this.object, this.nextFPReg);
      this.nextFPReg += torque_internal::SizeOf<float64>();
      return result;
    }
    if constexpr (Is64()) {
      return this.GetStackSlot();
    } else {
      const result = torque_internal::unsafe::NewReference<intptr>(
          this.object, this.nextStack);
      this.nextStack = this.nextStack + 2 * torque_internal::SizeOf<intptr>();
      this.smallSlotLast = false;
      return result;
    }
  }

  // For references we start a new section on the stack, no old slots are
  // filled.
  macro StartRefs(): void {
    if (!this.smallSlotLast) {
      this.smallSlot = 0;
    }
  }

  macro GetStackEnd(): RawPtr {
    let offset = this.nextStack;
    if (this.smallSlotLast) {
      offset -= torque_internal::SizeOf<intptr>();
    }
    return torque_internal::unsafe::GCUnsafeReferenceToRawPtr(
        this.object, offset);
  }

  macro GetAlignedStackEnd(alignment: intptr): RawPtr {
    let offset = this.nextStack;
    if (this.smallSlotLast) {
      offset -= torque_internal::SizeOf<intptr>();
    }
    const stackSize = offset - this.stackStart;
    if (stackSize % alignment != 0) {
      offset += alignment - (stackSize % alignment);
    }
    return torque_internal::unsafe::GCUnsafeReferenceToRawPtr(
        this.object, offset);
  }

  object: HeapObject|TaggedZeroPattern;
  remainingGPRegs: intptr;
  remainingFPRegs: intptr;
  nextGPReg: intptr;
  nextFPReg: intptr;
  nextStack: intptr;
  stackStart: intptr;
  // Even on 32-bit platforms we always allocate 64-bit stack space at a time to
  // preserve alignment. If we allocate a 64-bit slot for a 32-bit type, then we
  // remember the second half of the 64-bit slot as `smallSlot` so that it can
  // be used for the next 32-bit type.
  smallSlot: intptr;
  // If the {smallSlot} is in the middle of the whole allocated stack space,
  // then it is part of the overall stack space size. However, if the hole is at
  // the border of the whole allocated stack space, then we have to subtract it
  // from the overall stack space size. This flag keeps track of whether the
  // hole is in the middle (false) or at the border (true).
  smallSlotLast: bool;
}

macro LocationAllocatorForParams(paramBuffer: &intptr): LocationAllocator {
  let result: LocationAllocator;
  result.object = paramBuffer.object;
  result.remainingGPRegs = UniqueIntPtrConstant(kNumGPRegisterParameters);
  result.remainingFPRegs = UniqueIntPtrConstant(kNumFPRegisterParameters);
  result.nextGPReg = paramBuffer.offset;
  result.nextFPReg = result.remainingGPRegs * torque_internal::SizeOf<intptr>();
  if constexpr (!Is64()) {
    // Add padding to provide 8-byte alignment for float64 values.
    result.nextFPReg += (result.nextFPReg & torque_internal::SizeOf<intptr>());
  }
  dcheck(result.nextFPReg % 8 == 0);
  result.nextFPReg += paramBuffer.offset;
  result.nextStack = result.nextFPReg +
      result.remainingFPRegs * torque_internal::SizeOf<float64>();
  result.stackStart = result.nextStack;
  result.smallSlot = 0;
  result.smallSlotLast = false;
  return result;
}

macro LocationAllocatorForReturns(
    gpRegs: RawPtr, fpRegs: RawPtr, stack: RawPtr): LocationAllocator {
  let result: LocationAllocator;
  result.object = kZeroBitPattern;
  result.remainingGPRegs = kNumGPRegisterReturns;
  result.remainingFPRegs = kNumFPRegisterReturns;
  result.nextGPReg = Convert<intptr>(gpRegs) + kHeapObjectTag;
  result.nextFPReg = Convert<intptr>(fpRegs) + kHeapObjectTag;
  result.nextStack = Convert<intptr>(stack) + kHeapObjectTag;
  result.stackStart = result.nextStack;
  result.smallSlot = 0;
  result.smallSlotLast = false;
  return result;
}

macro JSToWasmObject(
    context: NativeContext,
    trustedInstanceDataOrUndefined: WasmTrustedInstanceData|Undefined,
    targetType: int32, value: JSAny): Object {
  const heapType = (targetType >> kValueTypeKindBits) & kValueTypeHeapTypeMask;
  const kind = targetType & kValueTypeKindBitsMask;
  if (heapType == HeapType::kExtern) {
    if (kind == ValueKind::kRef && value == Null) {
      ThrowTypeError(MessageTemplate::kWasmTrapJSTypeError);
    }
    return value;
  }
  if (heapType == HeapType::kString) {
    if (TaggedIsSmi(value)) {
      ThrowTypeError(MessageTemplate::kWasmTrapJSTypeError);
    }
    if (IsString(UnsafeCast<HeapObject>(value))) {
      return value;
    }
    if (value == Null) {
      if (kind == ValueKind::kRef) {
        ThrowTypeError(MessageTemplate::kWasmTrapJSTypeError);
      } else {
        dcheck(kind == ValueKind::kRefNull);
        return kWasmNull;
      }
    }

    ThrowTypeError(MessageTemplate::kWasmTrapJSTypeError);
  }
  return runtime::WasmGenericJSToWasmObject(
      context, trustedInstanceDataOrUndefined, value, Convert<Smi>(targetType));
}

// macro for handling platform specific f32 params.
macro HandleF32Params(
    context: NativeContext, locationAllocator: LocationAllocator,
    toRef: &intptr, param: JSAny): void {
  if constexpr (kIsFpAlwaysDouble) {
    if (locationAllocator.GetRemainingFPRegs() >= 0) {
      *RefCast<float64>(toRef) =
          ChangeFloat32ToFloat64(WasmTaggedToFloat32(param));
    } else {
      *RefCast<float32>(toRef) = WasmTaggedToFloat32(param);
    }
  } else if constexpr (kIsBigEndian) {
    *toRef = Convert<intptr>(Bitcast<uint32>(WasmTaggedToFloat32(param))) << 32;
  } else if constexpr (kIsBigEndianOnSim) {
    if (locationAllocator.GetRemainingFPRegs() >= 0) {
      *toRef = Convert<intptr>(Bitcast<uint32>(WasmTaggedToFloat32(param)))
          << 32;
    } else {
      *toRef = Convert<intptr>(Bitcast<uint32>(WasmTaggedToFloat32(param)));
    }
  }
}

macro JSToWasmWrapperHelper(
    context: NativeContext, _receiver: JSAny, target: JSFunction,
    arguments: Arguments, promise: constexpr Promise): JSAny {
  const functionData = target.shared_function_info.wasm_exported_function_data;

  // Trigger a wrapper tier-up when this function got called often enough.
  const switchStack =
      promise == Promise::kPromise || promise == Promise::kStressSwitch;
  if constexpr (!switchStack) {
    const budget: Smi =
        UnsafeCast<Smi>(functionData.wrapper_budget.value) - SmiConstant(1);
    functionData.wrapper_budget.value = budget;
    if (budget == SmiConstant(0)) {
      runtime::TierUpJSToWasmWrapper(kNoContext, functionData);
    }
  }

  const sig = functionData.sig;
  const implicitArg: WasmImportData|WasmTrustedInstanceData =
      functionData.internal.implicit_arg;
  const trustedInstanceData: WasmTrustedInstanceData =
      functionData.instance_data;

  const paramCount =
      TruncateIntPtrToInt32(*GetRefAt<intptr>(sig, kWasmParameterCountOffset));

  const returnCount =
      TruncateIntPtrToInt32(*GetRefAt<intptr>(sig, kWasmReturnCountOffset));

  const reps = *GetRefAt<RawPtr>(sig, kWasmSigTypesOffset);

  const sigTypes = torque_internal::unsafe::NewOffHeapConstSlice(
      %RawDownCast<RawPtr<int32>>(reps),
      Convert<intptr>(paramCount + returnCount));

  // If the return count is greater than 1, then the return values are returned
  // as a JSArray. After returning from the call to wasm, the return values are
  // stored on an area of the stack the GC does not know about. To avoid a GC
  // while references are still stored in this area of the stack, we allocate
  // the result JSArray already now before the call to wasm.
  let resultArray: JSAny = Undefined;
  let returnSize: intptr = 0;
  let hasRefReturns: bool = false;
  if (returnCount > 1) {
    resultArray = WasmAllocateJSArray(Convert<Smi>(returnCount));

    // We have to calculate the size of the stack area where the wasm function
    // will store the return values for multi-return.
    const returnTypes =
        Subslice(sigTypes, Convert<intptr>(0), Convert<intptr>(returnCount))
        otherwise unreachable;
    let allocator = NewReturnSlotAllocator();

    let retIt = returnTypes.Iterator();
    while (!retIt.Empty()) {
      const retType = retIt.NextNotEmpty();
      if (retType == kWasmI32Type) {
        allocator.AllocGP();
      } else if (retType == kWasmI64Type) {
        allocator.AllocGP();
        if constexpr (!Is64()) {
          // On 32-bit platforms I64 values are stored as two I32 values.
          allocator.AllocGP();
        }
      } else if (retType == kWasmF32Type) {
        allocator.AllocFP32();
      } else if (retType == kWasmF64Type) {
        allocator.AllocFP64();
      } else {
        const retKind = retType & kValueTypeKindBitsMask;
        dcheck(retKind == ValueKind::kRef || retKind == ValueKind::kRefNull);
        // Reference return values will be processed later.
        hasRefReturns = true;
      }
    }
    // Second round: reference values.
    if (hasRefReturns) {
      allocator.StartRefs();
      retIt = returnTypes.Iterator();
      while (!retIt.Empty()) {
        const retType = retIt.NextNotEmpty();
        const retKind = retType & kValueTypeKindBitsMask;
        if (retKind == ValueKind::kRef || retKind == ValueKind::kRefNull) {
          allocator.AllocGP();
        }
      }
    }
    returnSize = allocator.GetSize();
  }

  const paramTypes = Subslice(
      sigTypes, Convert<intptr>(returnCount), Convert<intptr>(paramCount))
      otherwise unreachable;

  let paramBuffer: &intptr;

  // 10 here is an arbitrary number. The analysis of signatures of exported
  // functions of big modules showed that most signatures have a low number of
  // I32 parameters. We picked a cutoff point where for most signatures the
  // pre-allocated stack slots are sufficient without making these stack slots
  // overly big.
  if (paramCount <= 10) {
    // Performance optimization: we pre-allocate a stack area with 18
    // 8-byte slots, and use this area when it is sufficient for all
    // parameters. If the stack area is too small, we allocate a byte array
    // below. The stack area is big enough for 10 parameters. The 10 parameters
    // need 18 * 8 bytes because some segments of the stack area are reserved
    // for register parameters, and there may e.g. be no FP parameters passed
    // by register, so all 8 FP register slots would remain empty.
    const stackSlots = %RawDownCast<RawPtr<intptr>>(
        StackSlotPtr(144, torque_internal::SizeOf<float64>()));
    paramBuffer = torque_internal::unsafe::NewOffHeapReference(stackSlots);
  } else {
    // We have to estimate the size of the byte array such that it can store
    // all converted parameters. The size is the sum of sizes of the segments
    // for the gp registers, fp registers, and stack slots. The sizes of
    // the register segments are fixed, but for the size of the stack segment
    // we have to guess the number of parameters on the stack. On ia32 it can
    // happen that only a single parameter fits completely into a register, and
    // all other parameters end up at least partially on the stack (e.g. for a
    // signature with only I64 parameters). To make the calculation simpler, we
    // just assume that all parameters are on the stack.
    const kSlotSize: intptr = torque_internal::SizeOf<float64>();
    const bufferSize = UniqueIntPtrConstant(kNumGPRegisterParameters) *
            Convert<intptr>(torque_internal::SizeOf<intptr>()) +
        UniqueIntPtrConstant(kNumFPRegisterParameters) * kSlotSize +
        Convert<intptr>(paramCount) * kSlotSize;
    const slice = &AllocateByteArray(Convert<uintptr>(bufferSize)).values;
    paramBuffer = torque_internal::unsafe::NewReference<intptr>(
        slice.object, slice.offset);
  }

  let locationAllocator = LocationAllocatorForParams(paramBuffer);
  let hasRefParam: bool = false;
  // A storage for converted reference parameters, so that they don't get
  // garbage collected if the conversion of primitive parameters causes a GC.
  // The storage gets allocated lazily when the first reference parameter gets
  // converted to avoid performance regressions for signatures without tagged
  // parameters. An old implementation used the `arguments` array as the storage
  // for converted reference parameters, but this does not work because then
  // converted reference parameters can be accessed from JavaScript using
  // `Function.prototype.arguments`.
  let convertedTagged: FixedArray|Smi = Convert<Smi>(0);

  let paramTypeIndex: int32 = 0;
  for (let paramIndex: int32 = 0; paramTypeIndex < paramCount; paramIndex++) {
    const param = arguments[Convert<intptr>(paramIndex)];
    const paramType = *paramTypes.UncheckedAtIndex(
        Convert<intptr>(paramTypeIndex++));
    if (paramType == kWasmI32Type) {
      let toRef = locationAllocator.GetGPSlot();
      typeswitch (param) {
        case (smiParam: Smi): {
          *toRef = Convert<intptr>(SmiToInt32(smiParam));
        }
        case (heapParam: JSAnyNotSmi): {
          *toRef = Convert<intptr>(WasmTaggedNonSmiToInt32(heapParam));
        }
      }
    } else if (paramType == kWasmF32Type) {
      let toRef = locationAllocator.GetFP32Slot();
      if constexpr (kIsFpAlwaysDouble || kIsBigEndian || kIsBigEndianOnSim) {
        HandleF32Params(context, locationAllocator, toRef, param);
      } else {
        *toRef = Convert<intptr>(Bitcast<uint32>(WasmTaggedToFloat32(param)));
      }
    } else if (paramType == kWasmF64Type) {
      let toRef = locationAllocator.GetFP64Slot();
      *RefCast<float64>(toRef) = ChangeTaggedToFloat64(param);
    } else if (paramType == kWasmI64Type) {
      if constexpr (Is64()) {
        let toRef = locationAllocator.GetGPSlot();
        const v = TruncateBigIntToI64(context, param);
        *toRef = v;
      } else {
        let toLowRef = locationAllocator.GetGPSlot();
        let toHighRef = locationAllocator.GetGPSlot();
        const bigIntVal = ToBigInt(context, param);
        const pair = BigIntToRawBytes(bigIntVal);
        *toLowRef = Signed(pair.low);
        *toHighRef = Signed(pair.high);
      }
    } else {
      const paramKind = paramType & kValueTypeKindBitsMask;
      dcheck(paramKind == ValueKind::kRef || paramKind == ValueKind::kRefNull);
      // The byte array where we store converted parameters is not GC-safe.
      // Therefore we can only copy references into this array once no GC can
      // happen anymore. Any conversion of a primitive type can execute
      // arbitrary JavaScript code and therefore also trigger GC. Therefore
      // references get copied into the array only after all parameters of
      // primitive types are finished. For now we write the converted parameter
      // back to the stack.
      hasRefParam = true;
      if (TaggedIsSmi(convertedTagged)) {
        convertedTagged =
            WasmAllocateZeroedFixedArray(Convert<intptr>(paramCount));
      }
      UnsafeCast<FixedArray>(convertedTagged)
          .objects[Convert<intptr>(paramIndex)] =
          JSToWasmObject(context, trustedInstanceData, paramType, param);
    }
  }
  let suspender: JSAny = Undefined;
  if constexpr (switchStack) {
    suspender = runtime::WasmAllocateSuspender(context);
    if (promise == Promise::kStressSwitch) {
      // In case we have a non-JSPI test where an import returns a Promise,
      // we don't want the import to try and suspend the wasm stack. Clear the
      // "resume" field as a way to signal this to the import.
      UnsafeCast<WasmSuspenderObject>(suspender).resume = Undefined;
    }
  }
  if (hasRefParam) {
    // Iterate over all parameters again and handle all those with ref types.
    let k: int32 = 0;
    // For stack switching k and paramIndex diverges,
    // because a suspender is not passed to wrapper as param.
    let paramIndex: int32 = 0;
    locationAllocator.StartRefs();

    // We are not using a `for` loop here because Torque does not support
    // `continue` in `for` loops.
    while (k < paramCount) {
      const paramType = *paramTypes.UncheckedAtIndex(Convert<intptr>(k));
      const paramKind = paramType & kValueTypeKindBitsMask;
      if (paramKind != ValueKind::kRef && paramKind != ValueKind::kRefNull) {
        k++;
        paramIndex++;
        continue;
      }
      const param = UnsafeCast<FixedArray>(convertedTagged)
                        .objects[Convert<intptr>(paramIndex++)];
      let toRef = locationAllocator.GetGPSlot();
      *toRef = BitcastTaggedToWord(param);
      k++;
    }
  }
  const paramStart = paramBuffer.GCUnsafeRawPtr();
  const paramEnd = locationAllocator.GetStackEnd();

  const callTarget = functionData.internal.call_target;

  // We construct a state that will be passed to `JSToWasmWrapperAsm`
  // and `JSToWasmHandleReturns`. There are too many parameters to pass
  // everything through registers. The stack area also contains slots for
  // values that get passed from `JSToWasmWrapperAsm` and
  // `WasmReturnPromiseOnSuspendAsm` to `JSToWasmHandleReturns`.
  const wrapperBuffer = %RawDownCast<RawPtr<intptr>>(
      StackSlotPtr(kWrapperBufferSize, torque_internal::SizeOf<intptr>()));

  *GetRefAt<int32>(wrapperBuffer, kWrapperBufferReturnCount) = returnCount;
  *GetRefAt<bool>(wrapperBuffer, kWrapperBufferRefReturnCount) = hasRefReturns;
  *GetRefAt<RawPtr>(wrapperBuffer, kWrapperBufferSigRepresentationArray) = reps;
  *GetRefAt<intptr>(wrapperBuffer, kWrapperBufferStackReturnBufferSize) =
      returnSize;
  *GetRefAt<WasmCodePointer>(wrapperBuffer, kWrapperBufferCallTarget) =
      callTarget;
  *GetRefAt<RawPtr<intptr>>(wrapperBuffer, kWrapperBufferParamStart) =
      paramStart;
  *GetRefAt<RawPtr>(wrapperBuffer, kWrapperBufferParamEnd) = paramEnd;

  // Both `trustedInstanceData` and `resultArray` get passed separately as
  // parameters to make them GC-safe. They get passed over the stack so that
  // they get scanned by the GC as part of the outgoing parameters of this
  // Torque builtin.
  let result: JSAny;
  if constexpr (promise == Promise::kPromise) {
    result =
        WasmReturnPromiseOnSuspendAsm(wrapperBuffer, implicitArg, resultArray);
  } else if (promise == Promise::kNoPromise) {
    result = JSToWasmWrapperAsm(wrapperBuffer, implicitArg, resultArray);
  } else if (promise == Promise::kStressSwitch) {
    result =
        JSToWasmStressSwitchStacksAsm(wrapperBuffer, implicitArg, resultArray);
  } else {
    unreachable;
  }
  return result;
}

transitioning javascript builtin JSToWasmWrapper(
    js-implicit context: NativeContext, receiver: JSAny, target: JSFunction,
    dispatchHandle: DispatchHandle)(...arguments): JSAny {
  // This is a generic builtin that can be installed on functions with different
  // parameter counts, so we need to support that.
  SetSupportsDynamicParameterCount(target, dispatchHandle);

  return JSToWasmWrapperHelper(
      context, receiver, target, arguments, Promise::kNoPromise);
}

transitioning javascript builtin WasmPromising(
    js-implicit context: NativeContext, receiver: JSAny, target: JSFunction,
    dispatchHandle: DispatchHandle)(...arguments): JSAny {
  // This is a generic builtin that can be installed on functions with different
  // parameter counts, so we need to support that.
  SetSupportsDynamicParameterCount(target, dispatchHandle);

  return JSToWasmWrapperHelper(
      context, receiver, target, arguments, Promise::kPromise);
}

transitioning javascript builtin WasmStressSwitch(
    js-implicit context: NativeContext, receiver: JSAny, target: JSFunction,
    dispatchHandle: DispatchHandle)(...arguments): JSAny {
  // This is a generic builtin that can be installed on functions with different
  // parameter counts, so we need to support that.
  SetSupportsDynamicParameterCount(target, dispatchHandle);

  return JSToWasmWrapperHelper(
      context, receiver, target, arguments, Promise::kStressSwitch);
}

macro WasmToJSObject(context: NativeContext, value: Object, retType: int32):
    JSAny {
  const paramKind = retType & kValueTypeKindBitsMask;
  const heapType = (retType >> kValueTypeKindBits) & kValueTypeHeapTypeMask;
  if (paramKind == ValueKind::kRef) {
    if (heapType == HeapType::kEq || heapType == HeapType::kI31 ||
        heapType == HeapType::kStruct || heapType == HeapType::kArray ||
        heapType == HeapType::kAny || heapType == HeapType::kExtern ||
        heapType == HeapType::kString || heapType == HeapType::kNone ||
        heapType == HeapType::kNoFunc || heapType == HeapType::kNoExtern ||
        heapType == HeapType::kExn || heapType == HeapType::kNoExn) {
      return UnsafeCast<JSAny>(value);
    }
    // TODO(ahaas): This is overly pessimistic: all module-defined struct and
    // array types can be passed to JS as-is as well; and for function types we
    // could at least support the fast path where the WasmExternalFunction has
    // already been created.
    return runtime::WasmGenericWasmToJSObject(context, value);
  } else {
    dcheck(paramKind == ValueKind::kRefNull);
    if (heapType == HeapType::kExtern || heapType == HeapType::kNoExtern ||
        heapType == HeapType::kExn || heapType == HeapType::kNoExn) {
      return UnsafeCast<JSAny>(value);
    }
    if (value == kWasmNull) {
      return Null;
    }
    if (heapType == HeapType::kEq || heapType == HeapType::kStruct ||
        heapType == HeapType::kArray || heapType == HeapType::kString ||
        heapType == HeapType::kI31 || heapType == HeapType::kAny) {
      return UnsafeCast<JSAny>(value);
    }
    // TODO(ahaas): This is overly pessimistic: all module-defined struct and
    // array types can be passed to JS as-is as well; and for function types we
    // could at least support the fast path where the WasmExternalFunction has
    // already been created.
    return runtime::WasmGenericWasmToJSObject(context, value);
  }
}

builtin JSToWasmHandleReturns(
    jsContext: NativeContext, resultArray: JSArray,
    wrapperBuffer: RawPtr<intptr>): JSAny {
  const returnCount = *GetRefAt<int32>(
      wrapperBuffer, kWrapperBufferReturnCount);
  if (returnCount == 0) {
    return Undefined;
  }
  if (returnCount == 1) {
    const reps = *GetRefAt<RawPtr>(
        wrapperBuffer, kWrapperBufferSigRepresentationArray);
    const retType = *GetRefAt<int32>(reps, 0);
    if (retType == kWasmI32Type) {
      let ret: int32;
      if constexpr (kIsBigEndian) {
        ret = TruncateInt64ToInt32(*GetRefAt<int64>(
            wrapperBuffer, kWrapperBufferGPReturnRegister1));
      } else {
        ret = *GetRefAt<int32>(wrapperBuffer, kWrapperBufferGPReturnRegister1);
      }
      const result = Convert<Number>(ret);
      return result;
    } else if (retType == kWasmF32Type) {
      if constexpr (kIsFpAlwaysDouble) {
        return Convert<Number>(TruncateFloat64ToFloat32(*GetRefAt<float64>(
            wrapperBuffer, kWrapperBufferFPReturnRegister1)));
      } else if constexpr (kIsBigEndianOnSim) {
        return Convert<Number>(BitcastInt32ToFloat32(
            TruncateInt64ToInt32(*GetRefAt<int64>(
                                     wrapperBuffer,
                                     kWrapperBufferFPReturnRegister1) >>
                32)));
      } else {
        const resultRef =
            GetRefAt<float32>(wrapperBuffer, kWrapperBufferFPReturnRegister1);
        return Convert<Number>(*resultRef);
      }
    } else if (retType == kWasmF64Type) {
      const resultRef =
          GetRefAt<float64>(wrapperBuffer, kWrapperBufferFPReturnRegister1);
      return Convert<Number>(*resultRef);
    } else if (retType == kWasmI64Type) {
      if constexpr (Is64()) {
        const ret = *GetRefAt<intptr>(
            wrapperBuffer, kWrapperBufferGPReturnRegister1);
        return I64ToBigInt(ret);
      } else {
        const lowWord = *GetRefAt<intptr>(
            wrapperBuffer, kWrapperBufferGPReturnRegister1);
        const highWord = *GetRefAt<intptr>(
            wrapperBuffer, kWrapperBufferGPReturnRegister2);
        return I32PairToBigInt(lowWord, highWord);
      }
    } else {
      const ptr = %RawDownCast<RawPtr<uintptr>>(
          wrapperBuffer + kWrapperBufferGPReturnRegister1);
      const rawRef = *GetRefAt<uintptr>(ptr, 0);
      const value = BitcastWordToTagged(rawRef);
      return WasmToJSObject(jsContext, value, retType);
    }
  }

  // Multi return.
  const fixedArray: FixedArray = UnsafeCast<FixedArray>(resultArray.elements);
  const returnBuffer = *GetRefAt<RawPtr>(
      wrapperBuffer, kWrapperBufferStackReturnBufferStart);
  let locationAllocator = LocationAllocatorForReturns(
      wrapperBuffer + kWrapperBufferGPReturnRegister1,
      wrapperBuffer + kWrapperBufferFPReturnRegister1, returnBuffer);

  const reps = *GetRefAt<RawPtr>(
      wrapperBuffer, kWrapperBufferSigRepresentationArray);

  const retTypes = torque_internal::unsafe::NewOffHeapConstSlice(
      %RawDownCast<RawPtr<int32>>(reps), Convert<intptr>(returnCount));

  const hasRefReturns = *GetRefAt<bool>(
      wrapperBuffer, kWrapperBufferRefReturnCount);

  if (hasRefReturns) {
    // We first process all references and copy them in the the result array to
    // put them into a location that is known to the GC. The processing of
    // references does not trigger a GC, but the allocation of HeapNumbers and
    // BigInts for primitive types may trigger a GC.

    // First skip over the locations of non-ref return values:
    for (let k: intptr = 0; k < Convert<intptr>(returnCount); k++) {
      const retType = *retTypes.UncheckedAtIndex(k);
      if (retType == kWasmI32Type) {
        locationAllocator.GetGPSlot();
      } else if (retType == kWasmF32Type) {
        locationAllocator.GetFP32Slot();
      } else if (retType == kWasmI64Type) {
        locationAllocator.GetGPSlot();
        if constexpr (!Is64()) {
          locationAllocator.GetGPSlot();
        }
      } else if (retType == kWasmF64Type) {
        locationAllocator.GetFP64Slot();
      }
    }
    // Then copy the references.
    locationAllocator.StartRefs();
    for (let k: intptr = 0; k < Convert<intptr>(returnCount); k++) {
      const retType = *retTypes.UncheckedAtIndex(k);
      const retKind = retType & kValueTypeKindBitsMask;
      if (retKind == ValueKind::kRef || retKind == ValueKind::kRefNull) {
        const slot = locationAllocator.GetGPSlot();
        const rawRef = *slot;
        const value: Object = BitcastWordToTagged(rawRef);
        // Store the wasm object in the JSArray to make it GC safe. The
        // transformation will happen later in a second loop.
        fixedArray.objects[k] = value;
      }
    }
  }

  locationAllocator = LocationAllocatorForReturns(
      wrapperBuffer + kWrapperBufferGPReturnRegister1,
      wrapperBuffer + kWrapperBufferFPReturnRegister1, returnBuffer);

  for (let k: intptr = 0; k < Convert<intptr>(returnCount); k++) {
    const retType = *retTypes.UncheckedAtIndex(k);
    if (retType == kWasmI32Type) {
      const slot = locationAllocator.GetGPSlot();
      let val: int32;
      if constexpr (kIsBigEndian) {
        val = TruncateInt64ToInt32(*RefCast<int64>(slot));
      } else {
        val = *RefCast<int32>(slot);
      }
      fixedArray.objects[k] = Convert<Number>(val);
    } else if (retType == kWasmF32Type) {
      const slot = locationAllocator.GetFP32Slot();
      let val: float32;
      if constexpr (kIsFpAlwaysDouble) {
        if (locationAllocator.GetRemainingFPRegs() >= 0) {
          val = TruncateFloat64ToFloat32(*RefCast<float64>(slot));
        } else {
          val = *RefCast<float32>(slot);
        }
      } else if constexpr (kIsBigEndianOnSim) {
        if (locationAllocator.GetRemainingFPRegs() >= 0) {
          val = BitcastInt32ToFloat32(
              TruncateInt64ToInt32(*RefCast<int64>(slot) >> 32));
        } else {
          val = *RefCast<float32>(slot);
        }
      } else {
        val = *RefCast<float32>(slot);
      }
      fixedArray.objects[k] = Convert<Number>(val);
    } else if (retType == kWasmI64Type) {
      if constexpr (Is64()) {
        const slot = locationAllocator.GetGPSlot();
        const val = *slot;
        fixedArray.objects[k] = I64ToBigInt(val);
      } else {
        const lowWordSlot = locationAllocator.GetGPSlot();
        const highWordSlot = locationAllocator.GetGPSlot();
        const lowWord = *lowWordSlot;
        const highWord = *highWordSlot;
        fixedArray.objects[k] = I32PairToBigInt(lowWord, highWord);
      }
    } else if (retType == kWasmF64Type) {
      const slot = locationAllocator.GetFP64Slot();
      const val = *RefCast<float64>(slot);
      fixedArray.objects[k] = Convert<Number>(val);
    } else {
      const value = fixedArray.objects[k];
      fixedArray.objects[k] = WasmToJSObject(jsContext, value, retType);
    }
  }

  return resultArray;
}
}  // namespace wasm

"""

```