Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Core Goal:**

The filename "pointer-auth-arm64.cc" immediately suggests that this code is related to pointer authentication on ARM64 architecture. The presence of `#if defined(USE_SIMULATOR)` strongly hints that this is *simulation* code, likely used in a development or testing environment where actual hardware features aren't available.

**2. Identifying Key Components and Data Structures:**

Scanning the code reveals the `Simulator` namespace and a nested `internal` namespace. Within `Simulator`, the `PACKey` struct is defined, suggesting different keys are used. The constant `kPACKeyIB` provides an example.

**3. Deconstructing Individual Functions:**

The next step is to analyze each function individually, understanding its purpose and how it manipulates data:

* **`GetNibble`:**  Extracts a 4-bit value (nibble) from a 64-bit integer at a specific position. This points towards bit manipulation being a core part of the functionality.

* **`PACCellShuffle` and `PACCellInvShuffle`:** These functions take a 64-bit integer and rearrange its nibbles according to predefined patterns. The "Inv" suffix suggests an inverse operation. This shuffling indicates some form of scrambling or mixing of data.

* **`RotCell`:**  Rotates the bits within a nibble. This is another bit manipulation operation.

* **`PACMult`:** This function performs a more complex transformation, applying `RotCell` and XOR operations on different parts of the input. The name suggests multiplication, but it's a bitwise operation mimicking multiplicative properties in a finite field (though not strictly mathematical multiplication).

* **`PACSub` and `PACInvSub`:** These functions perform substitution using lookup tables. Again, the "Inv" suffix signifies the inverse operation. Substitution is a common technique in cryptography.

* **`TweakCellInvRot` and `TweakCellRot`:**  These functions operate on smaller "cells" (likely not just nibbles, based on the bit shifts involved) and perform rotations and XORs. They seem related to a "tweak" value.

* **`TweakInvShuffle` and `TweakShuffle`:** Similar to the `PACCellShuffle` functions, these rearrange bits based on predefined patterns, specifically for the "tweak" value.

* **`ComputePAC`:** This is the central function. It takes `data`, `context`, and `key` as input. It uses the previously defined functions (`PACSub`, `PACMult`, `PACCellShuffle`, `TweakShuffle`, etc.) in a specific sequence, along with round constants (`RC`) and an alpha constant. The structure with loops and round keys strongly suggests a cryptographic algorithm, specifically a block cipher. The comment mentioning "QARMA" confirms this.

* **`CalculatePACMask`:** This function calculates a bitmask based on the pointer value, pointer type, and TTBR (Translation Table Base Register). This mask is likely used to isolate the pointer authentication code bits.

* **`AuthPAC`:** This function attempts to *authenticate* a pointer. It calculates the expected PAC using `ComputePAC` and compares it to the PAC embedded in the pointer. If they don't match, it indicates a potential tampering. It also includes error handling logic.

* **`AddPAC`:** This function *adds* a Pointer Authentication Code (PAC) to a pointer. It computes the PAC using `ComputePAC` and inserts it into specific bits of the pointer.

* **`StripPAC`:** This function *removes* or strips the PAC from a pointer.

**4. Connecting to JavaScript (if applicable):**

The question asks if the code relates to JavaScript functionality. Pointer authentication is a security feature at a low level. While JavaScript doesn't directly expose these functions, V8 (the JavaScript engine) uses this code internally for security. The connection is indirect; these mechanisms protect V8's internal data structures and code execution. A simple JavaScript example demonstrating the *impact* (not direct usage) could be showing how memory corruption or unauthorized access could be prevented due to such mechanisms.

**5. Code Logic Inference and Examples:**

For functions like `PACCellShuffle`, `PACSub`, etc.,  providing example input and output helps illustrate their behavior. The `ComputePAC` function is more complex, but understanding its steps is key.

**6. Identifying Potential Programming Errors:**

The `AuthPAC` function explicitly mentions a "Pointer authentication failure."  This points to a common error: trying to use a pointer that has been tampered with or has an invalid PAC. This could happen due to memory corruption bugs.

**7. Considering the `.tq` Extension:**

The question asks about the `.tq` extension. Knowing that Torque is V8's internal type system and code generation language, the answer explains that this C++ file is *not* a Torque file.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "Is this encryption?"  While related, it's specifically *pointer authentication*, a slightly different security mechanism focused on verifying the origin and integrity of pointers.
* **Deeper dive into `ComputePAC`:** Recognizing the iterative structure, round constants, and non-linear operations immediately suggests a block cipher-like algorithm. The comment about QARMA confirms this.
* **Understanding the "context":** Recognizing that the `context` parameter in `ComputePAC`, `AddPAC`, and `AuthPAC` allows for more fine-grained pointer authentication based on the execution environment.
* **Clarifying the JavaScript connection:**  Emphasizing that the connection is internal and focused on security within the V8 engine, not direct JavaScript API usage.
好的，让我们来分析一下 `v8/src/execution/arm64/pointer-auth-arm64.cc` 这个 V8 源代码文件的功能。

**文件功能概述:**

`v8/src/execution/arm64/pointer-auth-arm64.cc` 文件实现了在 ARM64 架构上的指针认证 (Pointer Authentication) 功能的软件模拟。由于文件名中包含了 `arm64` 和 `simulator`，并且代码被 `#if defined(USE_SIMULATOR)` 包裹，可以确定这段代码是在 V8 的模拟器环境下使用的。

指针认证是一种硬件安全特性，旨在防止恶意软件篡改函数指针和返回地址，从而提升程序的安全性。在没有硬件支持的情况下，V8 通过这段代码模拟了指针认证的加签 (signing) 和验签 (authentication) 过程。

**具体功能分解:**

1. **模拟 PAC 密钥 (PAC Keys):**
   - 定义了用于模拟的 PAC 密钥 `kPACKeyIB`。在真实的硬件环境中，PAC 密钥由硬件安全模块管理，软件无法直接访问。

2. **核心 PAC 计算函数 (`ComputePAC`):**
   -  实现了 `Simulator::ComputePAC` 函数，该函数模拟了 PAC 的计算过程。这个模拟基于 QARMA 块密码算法。
   -  它接收原始数据 (`data`)，上下文信息 (`context`) 和 PAC 密钥 (`key`) 作为输入。
   -  通过一系列的位运算、轮函数 (round functions) 和密钥混合操作，生成 PAC 值。

3. **辅助计算函数:**
   -  **Nibble 操作:** `GetNibble` 用于提取 64 位数据中的一个 4 位 (nibble)。
   -  **Cell 混淆/逆混淆:** `PACCellShuffle` 和 `PACCellInvShuffle` 用于对数据的 4 位单元 (cell) 进行重排。
   -  **Cell 旋转:** `RotCell` 用于旋转 4 位单元内的比特。
   -  **乘法混合:** `PACMult` 模拟了一种乘法混合操作。
   -  **Substitution/逆 Substitution:** `PACSub` 和 `PACInvSub` 使用查找表进行替换操作。
   -  **Tweak 操作:** `TweakCellRot`, `TweakInvRot`, `TweakShuffle`, `TweakInvShuffle` 用于处理上下文信息 (tweak)，参与 PAC 的计算过程。

4. **PAC Mask 计算 (`CalculatePACMask`):**
   -  `Simulator::CalculatePACMask` 函数用于计算 PAC 的掩码 (mask)。这个掩码定义了指针中用于存储 PAC 值的比特位。

5. **添加 PAC (`AddPAC`):**
   -  `Simulator::AddPAC` 函数模拟了向指针添加 PAC 的过程。
   -  它计算出 PAC 值，并将该值插入到指针的特定比特位中。
   -  其中还包含一些模拟的保护逻辑，例如，如果指针的 PAC 区域不是全 0 或全 1，则会进行一些额外的异或操作。

6. **认证 PAC (`AuthPAC`):**
   -  `Simulator::AuthPAC` 函数模拟了验证指针 PAC 的过程。
   -  它使用相同的密钥和上下文信息重新计算指针的 PAC。
   -  将计算出的 PAC 与指针中已有的 PAC 进行比较。
   -  如果 PAC 不匹配，则表明指针可能被篡改。在模拟器中，可以配置成直接终止程序 (`FATAL`)，或者在指针中设置一个错误码。

7. **剥离 PAC (`StripPAC`):**
   -  `Simulator::StripPAC` 函数模拟了从指针中移除 PAC 的过程，恢复到原始的未签名指针。

**关于 `.tq` 结尾:**

如果 `v8/src/execution/arm64/pointer-auth-arm64.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 自研的一种类型化中间语言，用于生成高效的 C++ 代码。然而，根据你提供的文件名，它以 `.cc` 结尾，所以这是一个标准的 C++ 源代码文件。

**与 JavaScript 的功能关系:**

虽然这段 C++ 代码本身不是直接用 JavaScript 编写的，但它对 JavaScript 的安全执行至关重要。V8 引擎使用此代码（在模拟环境下）来测试和开发指针认证功能。

在支持指针认证的 ARM64 硬件上，当 V8 执行 JavaScript 代码时，引擎内部会将关键的函数指针和返回地址进行签名。当调用这些指针时，硬件会自动验证其签名。如果签名不匹配，硬件会触发异常，从而阻止恶意代码执行。

在模拟器环境下，这段 C++ 代码模拟了这一过程，确保 V8 的开发和测试能够在没有实际硬件支持的情况下进行。

**JavaScript 示例 (说明间接关系):**

虽然 JavaScript 代码本身无法直接操作指针认证，但可以想象一下，如果缺少这样的安全机制，恶意 JavaScript 代码可能会尝试覆盖 V8 引擎内部的函数指针，从而劫持程序的执行流程。

例如，假设 V8 内部有一个函数 `foo` 的指针，恶意代码试图将其替换为指向恶意函数 `bar` 的指针：

```javascript
// 这是一个概念性的例子，实际 JavaScript 无法直接操作指针
// 假设 V8 内部有类似的操作，但受到指针认证保护

// 恶意代码尝试修改 V8 内部的函数指针
try {
  // 尝试访问并修改 V8 内部的某个对象的属性，该属性存储了函数指针
  // 这通常是不允许的，会触发安全机制
  V8InternalObject.functionPointer = maliciousFunction;
} catch (e) {
  console.error("尝试修改函数指针被阻止:", e);
}

function foo() {
  console.log("执行了正常的函数 foo");
}

function maliciousFunction() {
  console.log("执行了恶意的函数 bar");
  // 执行其他恶意操作
}

// 如果没有指针认证，调用 foo 可能会执行 maliciousFunction
foo();
```

在没有指针认证的情况下，上述恶意代码可能有机会成功替换函数指针，导致程序执行恶意代码。而指针认证的存在，可以在硬件层面或模拟层面阻止这种篡改。

**代码逻辑推理与假设输入输出:**

让我们以 `PACCellShuffle` 函数为例进行代码逻辑推理：

**函数:** `uint64_t PACCellShuffle(uint64_t in_data)`

**假设输入:** `in_data = 0x123456789ABCDEF0` (十六进制)

**逻辑推理:**

1. `PACCellShuffle` 函数根据 `in_positions` 数组定义的顺序，从 `in_data` 中提取每个 nibble (4 位)。
2. `in_positions` 数组是 `{52, 24, 44, 0,  28, 48, 4,  40, 32, 12, 56, 20, 8,  36, 16, 60}`。这些数字表示从 `in_data` 的哪个比特位开始提取 nibble (从右向左，第 0 位是最低位)。
3. 例如，对于第一个 nibble (i=0)，`in_positions[0] = 52`，意味着提取 `in_data` 的第 52 到 55 位（即 `0x9`）。然后将其放置到 `out_data` 的最低 4 位。
4. 对于第二个 nibble (i=1)，`in_positions[1] = 24`，意味着提取 `in_data` 的第 24 到 27 位（即 `0x7`）。然后将其放置到 `out_data` 的第 4 到 7 位。
5. 依此类推，直到处理完所有 16 个 nibble。

**预期输出:**

根据 `in_positions` 的排列，我们可以手动模拟：

- `in_data` 的 nibbles (从右到左): `0`, `F`, `E`, `D`, `C`, `B`, `A`, `9`, `8`, `7`, `6`, `5`, `4`, `3`, `2`, `1`

- 根据 `in_positions` 提取并重排:
    - 位 52-55 (0x9) -> 输出位 0-3
    - 位 24-27 (0x7) -> 输出位 4-7
    - 位 44-47 (0xB) -> 输出位 8-11
    - 位 0-3  (0x0) -> 输出位 12-15
    - ...以此类推

手动推算比较繁琐，但理解其核心是根据预定义的顺序重新排列 nibble。实际运行时，`PACCellShuffle(0x123456789ABCDEF0)` 的输出将是一个经过混淆的 64 位值。

**涉及用户常见的编程错误 (与指针认证相关):**

虽然用户通常不会直接编写这段底层的 C++ 代码，但了解指针认证可以帮助理解一些与内存安全相关的编程错误，尤其是在使用 C/C++ 等底层语言开发时。

1. **悬挂指针 (Dangling Pointer):**
   - 指针指向的内存已经被释放，但指针仍然存在。如果程序尝试通过已签名的悬挂指针进行函数调用，即使签名验证通过，访问的也是无效内存，可能导致崩溃或安全漏洞。
   - **例子:**
     ```c++
     int* ptr = new int(10);
     int (*func_ptr)() = nullptr;

     // 假设某个操作将 ptr 转换为已签名的函数指针并赋值给 func_ptr
     // (在实际 V8 内部，这个过程会更复杂)

     delete ptr; // 内存被释放

     // 尝试通过已签名的悬挂指针调用函数 (模拟)
     if (func_ptr) {
       // 即使签名可能验证通过，访问的内存也是无效的
       // func_ptr(); // 可能会崩溃
     }
     ```

2. **野指针 (Wild Pointer):**
   - 指针未初始化或指向未知内存区域。如果野指针被错误地签名，并且后续被调用，签名验证可能通过（如果碰巧 PAC 值匹配），但执行的代码是不可预测的。
   - **例子:**
     ```c++
     int* wild_ptr; // 未初始化的指针
     int (*func_ptr)() = nullptr;

     // 错误地将野指针签名并赋值给 func_ptr (模拟)
     // ...

     if (func_ptr) {
       // 调用 func_ptr，执行位置不可预测
       // func_ptr(); // 可能会崩溃或执行错误代码
     }
     ```

3. **缓冲区溢出 (Buffer Overflow) 导致指针覆盖:**
   - 虽然指针认证可以保护函数指针本身不被随意修改，但在某些情况下，缓冲区溢出可能覆盖存储函数指针的内存区域。如果覆盖后的值恰好是一个有效的、带有正确签名的指针（这不太可能，但理论上存在），则可能绕过指针认证。然而，指针认证大大降低了利用缓冲区溢出劫持控制流的风险。

4. **类型混淆 (Type Confusion) 导致的错误指针使用:**
   - 如果由于类型混淆，一个指向错误类型对象的指针被签名并作为函数指针调用，即使签名验证通过，也可能导致程序行为异常或崩溃。

总而言之，`v8/src/execution/arm64/pointer-auth-arm64.cc` 文件是 V8 在 ARM64 模拟器环境下实现指针认证功能的核心代码，它通过模拟 PAC 的计算和验证过程，增强了 V8 的安全性，防止恶意代码篡改关键的程序执行路径。虽然 JavaScript 开发者不会直接操作这些代码，但这些底层的安全机制对于确保 JavaScript 代码的安全执行至关重要。

### 提示词
```
这是目录为v8/src/execution/arm64/pointer-auth-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/pointer-auth-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/arm64/simulator-arm64.h"

#if defined(USE_SIMULATOR)

namespace v8 {
namespace internal {

// Randomly generated example key for simulating only.
const Simulator::PACKey Simulator::kPACKeyIB = {0xeebb163b474e04c8,
                                                0x5267ac6fc280fb7c, 1};

namespace {

uint64_t GetNibble(uint64_t in_data, int position) {
  return (in_data >> position) & 0xf;
}

uint64_t PACCellShuffle(uint64_t in_data) {
  static int in_positions[16] = {52, 24, 44, 0,  28, 48, 4,  40,
                                 32, 12, 56, 20, 8,  36, 16, 60};
  uint64_t out_data = 0;
  for (int i = 0; i < 16; ++i) {
    out_data |= GetNibble(in_data, in_positions[i]) << (4 * i);
  }
  return out_data;
}

uint64_t PACCellInvShuffle(uint64_t in_data) {
  static int in_positions[16] = {12, 24, 48, 36, 56, 44, 4,  16,
                                 32, 52, 28, 8,  20, 0,  40, 60};
  uint64_t out_data = 0;
  for (int i = 0; i < 16; ++i) {
    out_data |= GetNibble(in_data, in_positions[i]) << (4 * i);
  }
  return out_data;
}

uint64_t RotCell(uint64_t in_cell, int amount) {
  DCHECK((amount >= 1) && (amount <= 3));

  in_cell &= 0xf;
  uint8_t temp = in_cell << 4 | in_cell;
  return static_cast<uint64_t>((temp >> (4 - amount)) & 0xf);
}

uint64_t PACMult(uint64_t s_input) {
  uint8_t t0;
  uint8_t t1;
  uint8_t t2;
  uint8_t t3;
  uint64_t s_output = 0;

  for (int i = 0; i < 4; ++i) {
    uint8_t s12 = (s_input >> (4 * (i + 12))) & 0xf;
    uint8_t s8 = (s_input >> (4 * (i + 8))) & 0xf;
    uint8_t s4 = (s_input >> (4 * (i + 4))) & 0xf;
    uint8_t s0 = (s_input >> (4 * (i + 0))) & 0xf;

    t0 = RotCell(s8, 1) ^ RotCell(s4, 2) ^ RotCell(s0, 1);
    t1 = RotCell(s12, 1) ^ RotCell(s4, 1) ^ RotCell(s0, 2);
    t2 = RotCell(s12, 2) ^ RotCell(s8, 1) ^ RotCell(s0, 1);
    t3 = RotCell(s12, 1) ^ RotCell(s8, 2) ^ RotCell(s4, 1);

    s_output |= static_cast<uint64_t>(t3) << (4 * (i + 0));
    s_output |= static_cast<uint64_t>(t2) << (4 * (i + 4));
    s_output |= static_cast<uint64_t>(t1) << (4 * (i + 8));
    s_output |= static_cast<uint64_t>(t0) << (4 * (i + 12));
  }
  return s_output;
}

uint64_t PACSub(uint64_t t_input) {
  uint64_t t_output = 0;
  uint8_t substitutions[16] = {0xb, 0x6, 0x8, 0xf, 0xc, 0x0, 0x9, 0xe,
                               0x3, 0x7, 0x4, 0x5, 0xd, 0x2, 0x1, 0xa};
  for (int i = 0; i < 16; ++i) {
    unsigned index = ((t_input >> (4 * i)) & 0xf);
    t_output |= static_cast<uint64_t>(substitutions[index]) << (4 * i);
  }
  return t_output;
}

uint64_t PACInvSub(uint64_t t_input) {
  uint64_t t_output = 0;
  uint8_t substitutions[16] = {0x5, 0xe, 0xd, 0x8, 0xa, 0xb, 0x1, 0x9,
                               0x2, 0x6, 0xf, 0x0, 0x4, 0xc, 0x7, 0x3};
  for (int i = 0; i < 16; ++i) {
    unsigned index = ((t_input >> (4 * i)) & 0xf);
    t_output |= static_cast<uint64_t>(substitutions[index]) << (4 * i);
  }
  return t_output;
}

uint64_t TweakCellInvRot(uint64_t in_cell) {
  uint64_t out_cell = 0;
  out_cell |= (in_cell & 0x7) << 1;
  out_cell |= (in_cell & 0x1) ^ ((in_cell >> 3) & 0x1);
  return out_cell;
}

uint64_t TweakInvShuffle(uint64_t in_data) {
  uint64_t out_data = 0;
  out_data |= TweakCellInvRot(in_data >> 48) << 0;
  out_data |= ((in_data >> 52) & 0xf) << 4;
  out_data |= ((in_data >> 20) & 0xff) << 8;
  out_data |= ((in_data >> 0) & 0xff) << 16;
  out_data |= TweakCellInvRot(in_data >> 8) << 24;
  out_data |= ((in_data >> 12) & 0xf) << 28;
  out_data |= TweakCellInvRot(in_data >> 28) << 32;
  out_data |= TweakCellInvRot(in_data >> 60) << 36;
  out_data |= TweakCellInvRot(in_data >> 56) << 40;
  out_data |= TweakCellInvRot(in_data >> 16) << 44;
  out_data |= ((in_data >> 32) & 0xfff) << 48;
  out_data |= TweakCellInvRot(in_data >> 44) << 60;
  return out_data;
}

uint64_t TweakCellRot(uint64_t in_cell) {
  uint64_t out_cell = 0;
  out_cell |= ((in_cell & 0x1) ^ ((in_cell >> 1) & 0x1)) << 3;
  out_cell |= (in_cell >> 0x1) & 0x7;
  return out_cell;
}

uint64_t TweakShuffle(uint64_t in_data) {
  uint64_t out_data = 0;
  out_data |= ((in_data >> 16) & 0xff) << 0;
  out_data |= TweakCellRot(in_data >> 24) << 8;
  out_data |= ((in_data >> 28) & 0xf) << 12;
  out_data |= TweakCellRot(in_data >> 44) << 16;
  out_data |= ((in_data >> 8) & 0xff) << 20;
  out_data |= TweakCellRot(in_data >> 32) << 28;
  out_data |= ((in_data >> 48) & 0xfff) << 32;
  out_data |= TweakCellRot(in_data >> 60) << 44;
  out_data |= TweakCellRot(in_data >> 0) << 48;
  out_data |= ((in_data >> 4) & 0xf) << 52;
  out_data |= TweakCellRot(in_data >> 40) << 56;
  out_data |= TweakCellRot(in_data >> 36) << 60;
  return out_data;
}

}  // namespace

// For a description of QARMA see:
// The QARMA Block Cipher Family, Roberto Avanzi, Qualcomm Product Security
// Initiative.
// The pseudocode is available in ARM DDI 0487D.b, J1-6946.
uint64_t Simulator::ComputePAC(uint64_t data, uint64_t context, PACKey key) {
  uint64_t key0 = key.high;
  uint64_t key1 = key.low;
  const uint64_t RC[5] = {0x0000000000000000, 0x13198a2e03707344,
                          0xa4093822299f31d0, 0x082efa98ec4e6c89,
                          0x452821e638d01377};
  const uint64_t Alpha = 0xc0ac29B7c97c50dd;

  uint64_t modk0 = ((key0 & 0x1) << 63) | ((key0 >> 2) << 1) |
                   ((key0 >> 63) ^ ((key0 >> 1) & 0x1));
  uint64_t running_mod = context;
  uint64_t working_val = data ^ key0;
  uint64_t round_key;
  for (int i = 0; i < 5; ++i) {
    round_key = key1 ^ running_mod;
    working_val ^= round_key;
    working_val ^= RC[i];
    if (i > 0) {
      working_val = PACCellShuffle(working_val);
      working_val = PACMult(working_val);
    }
    working_val = PACSub(working_val);
    running_mod = TweakShuffle(running_mod);
  }

  round_key = modk0 ^ running_mod;
  working_val ^= round_key;
  working_val = PACCellShuffle(working_val);
  working_val = PACMult(working_val);
  working_val = PACSub(working_val);
  working_val = PACCellShuffle(working_val);
  working_val = PACMult(working_val);
  working_val ^= key1;
  working_val = PACCellInvShuffle(working_val);
  working_val = PACInvSub(working_val);
  working_val = PACMult(working_val);
  working_val = PACCellInvShuffle(working_val);
  working_val ^= key0;
  working_val ^= running_mod;

  for (int i = 0; i < 5; ++i) {
    working_val = PACInvSub(working_val);
    if (i < 4) {
      working_val = PACMult(working_val);
      working_val = PACCellInvShuffle(working_val);
    }
    running_mod = TweakInvShuffle(running_mod);
    round_key = key1 ^ running_mod;
    working_val ^= RC[4 - i];
    working_val ^= round_key;
    working_val ^= Alpha;
  }

  return working_val ^ modk0;
}

// The TTBR is selected by bit 63 or 55 depending on TBI for pointers without
// codes, but is always 55 once a PAC code is added to a pointer. For this
// reason, it must be calculated at the call site.
uint64_t Simulator::CalculatePACMask(uint64_t ptr, PointerType type, int ttbr) {
  int bottom_pac_bit = GetBottomPACBit(ptr, ttbr);
  int top_pac_bit = GetTopPACBit(ptr, type);
  return unsigned_bitextract_64(top_pac_bit, bottom_pac_bit,
                                0xffffffffffffffff & ~kTTBRMask)
         << bottom_pac_bit;
}

uint64_t Simulator::AuthPAC(uint64_t ptr, uint64_t context, PACKey key,
                            PointerType type) {
  DCHECK((key.number == 0) || (key.number == 1));

  uint64_t pac_mask = CalculatePACMask(ptr, type, (ptr >> 55) & 1);
  uint64_t original_ptr =
      ((ptr & kTTBRMask) == 0) ? (ptr & ~pac_mask) : (ptr | pac_mask);

  uint64_t pac = ComputePAC(original_ptr, context, key);

  uint64_t error_code = UINT64_C(1) << key.number;
  if ((pac & pac_mask) == (ptr & pac_mask)) {
    return original_ptr;
  } else {
    int error_lsb = GetTopPACBit(ptr, type) - 2;
    uint64_t error_mask = UINT64_C(0x3) << error_lsb;
    if (v8_flags.sim_abort_on_bad_auth) {
      FATAL("Pointer authentication failure.");
    }
    return (original_ptr & ~error_mask) | (error_code << error_lsb);
  }
}

uint64_t Simulator::AddPAC(uint64_t ptr, uint64_t context, PACKey key,
                           PointerType type) {
  int top_pac_bit = GetTopPACBit(ptr, type);

  DCHECK(HasTBI(ptr, type));
  int ttbr = (ptr >> 55) & 1;
  uint64_t pac_mask = CalculatePACMask(ptr, type, ttbr);
  uint64_t ext_ptr = (ttbr == 0) ? (ptr & ~pac_mask) : (ptr | pac_mask);

  uint64_t pac = ComputePAC(ext_ptr, context, key);

  // If the pointer isn't all zeroes or all ones in the PAC bitfield, corrupt
  // the resulting code.
  if (((ptr & (pac_mask | kTTBRMask)) != 0x0) &&
      ((~ptr & (pac_mask | kTTBRMask)) != 0x0)) {
    pac ^= UINT64_C(1) << (top_pac_bit - 1);
  }

  uint64_t ttbr_shifted = static_cast<uint64_t>(ttbr) << 55;
  return (pac & pac_mask) | ttbr_shifted | (ptr & ~pac_mask);
}

uint64_t Simulator::StripPAC(uint64_t ptr, PointerType type) {
  uint64_t pac_mask = CalculatePACMask(ptr, type, (ptr >> 55) & 1);
  return ((ptr & kTTBRMask) == 0) ? (ptr & ~pac_mask) : (ptr | pac_mask);
}

}  // namespace internal
}  // namespace v8

#endif  // USE_SIMULATOR
```