Response: The user wants a summary of the C++ code in `v8/test/cctest/test-assembler-arm.cc`.
This is the first part of a three-part file.

The code seems to be testing the ARM assembler in V8. It defines various `TEST` functions, each exercising a different set of ARM instructions. These tests involve:

1. **Basic arithmetic and control flow:**  Testing `add`, `mov`, `b`, `teq`, `mul`, `sub`.
2. **Memory access:** Testing `ldr`, `str`, `ldrsb`, `strb`, `ldrsh`, `strh`, `stm`, `ldm`.
3. **VFP (Floating Point) instructions:** Testing `vldr`, `vstr`, `vadd`, `vmla`, `vmls`, `vmov`, `vcvt`, `vabs`, `vneg`, and multi-load/store variants.
4. **ARMv7 bitfield instructions:** Testing `ubfx`, `sbfx`, `bfc`, `bfi`.
5. **Saturating instructions:** Testing `usat`.
6. **VFP rounding modes:** Testing `vcvt` with different rounding modes.
7. **Carry flag instructions:** Testing `adc`.
8. **Label chaining.**
9. **VFP registers d16-d31.**
10. **VFP canonicalized NaN mode.**
11. **NEON (SIMD) instructions:**  Testing a wide range of NEON instructions for data manipulation, arithmetic, comparisons, and data arrangement.

The file seems to be a comprehensive suite of unit tests for the ARM assembler within the V8 JavaScript engine.

If the code is related to JavaScript, it's at a very low level. The assembler code generated here is likely used by the V8 engine to implement JavaScript functionality for ARM architectures. For example, the floating-point instructions are crucial for handling JavaScript numbers. The NEON instructions are used for optimizing array operations and other data-intensive tasks.

Let's create a simple JavaScript example that might involve some of these low-level operations.
这个C++源代码文件（`v8/test/cctest/test-assembler-arm.cc` 的第一部分）是V8 JavaScript引擎的测试套件的一部分，专门用于测试**ARM架构的汇编器（assembler）**的功能。

**主要功能归纳：**

* **测试ARM汇编指令的正确性:**  文件中定义了多个名为 `TEST` 的函数，每个函数都生成一段ARM汇编代码，然后执行这段代码，并检查执行结果是否符合预期。 这些测试涵盖了各种类型的ARM指令，例如：
    * **基本算术运算:** 加法 (`add`)、减法 (`sub`)、乘法 (`mul`)。
    * **数据移动:**  加载 (`ldr`)、存储 (`str`)、移动 (`mov`)。
    * **控制流:** 跳转 (`b`)、条件跳转 (`beq`, `bne`)、比较 (`teq`)。
    * **内存操作:**  加载/存储不同大小的数据（字节、半字、字）。
    * **VFP（Vector Floating Point）浮点运算:**  加载/存储浮点数、浮点数的加减乘除、绝对值、取反、类型转换、舍入模式等。
    * **ARMv7 特有的位域操作指令。**
    * **饱和运算指令。**
    * **使用进位标志的指令。**
    * **NEON（Advanced SIMD）指令:**  用于并行处理数据的指令，例如向量的加载/存储、算术运算、比较、数据重排等。
* **测试汇编器的代码生成能力:**  通过生成和执行代码，间接地测试汇编器是否能正确地将C++代码转化为机器码。
* **为V8引擎在ARM架构上的运行提供保障:**  这些测试确保了V8引擎在ARM处理器上生成正确的机器码，从而保证JavaScript代码在ARM设备上的高效和正确执行。

**与JavaScript的功能关系及JavaScript示例：**

虽然这个C++文件直接操作的是底层的汇编指令，但它与JavaScript的功能息息相关。 V8引擎需要将JavaScript代码编译成可以在目标平台上执行的机器码。 在ARM架构上，V8的codegen模块会使用这里的汇编器来生成这些机器码。

例如，JavaScript中的数值运算最终会被转化为底层的机器指令。 文件中对VFP浮点指令的测试，就直接关系到JavaScript中`Number`类型的运算。 对NEON指令的测试，则关系到JavaScript中对数组等数据结构进行高性能操作的能力。

**JavaScript 示例 (体现浮点运算和可能的底层SIMD优化):**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(3.14, 2.71);
console.log(result); // 输出 5.85

function multiplyArray(arr, scalar) {
  const newArr = [];
  for (let i = 0; i < arr.length; i++) {
    newArr.push(arr[i] * scalar);
  }
  return newArr;
}

const numbers = [1, 2, 3, 4];
const multipliedNumbers = multiplyArray(numbers, 2);
console.log(multipliedNumbers); // 输出 [2, 4, 6, 8]
```

**说明:**

1. **`add(3.14, 2.71)`:**  这个简单的JavaScript加法运算，在V8引擎底层，尤其是在ARM架构上，很可能会使用到测试文件中测试的VFP浮点加法指令（如 `vadd`）。
2. **`multiplyArray(numbers, 2)`:**  这个数组乘法操作，V8引擎可能会利用NEON指令进行优化，例如一次性处理数组中的多个元素，这与测试文件中对NEON乘法指令（如 `vmul`）的测试相关。  虽然JavaScript代码本身没有显式地使用SIMD，但V8引擎在编译和优化时可能会选择使用这些底层指令来提升性能。

总而言之， `v8/test/cctest/test-assembler-arm.cc` 的第一部分是V8引擎在ARM架构上正确执行JavaScript代码的基石，它通过细致的汇编指令测试，确保了代码生成的正确性和性能。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <iostream>

#include "src/base/numbers/double.h"
#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/utils/ostreams.h"
#include "test/cctest/assembler-helper-arm.h"
#include "test/cctest/cctest.h"
#include "test/common/value-helper.h"

namespace v8 {
namespace internal {
namespace test_assembler_arm {

using base::RandomNumberGenerator;

#define __ assm.

TEST(0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  __ add(r0, r0, Operand(r1));
  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(3, 4, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(7, res);
}


TEST(1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  Label L, C;

  __ mov(r1, Operand(r0));
  __ mov(r0, Operand::Zero());
  __ b(&C);

  __ bind(&L);
  __ add(r0, r0, Operand(r1));
  __ sub(r1, r1, Operand(1));

  __ bind(&C);
  __ teq(r1, Operand::Zero());
  __ b(ne, &L);
  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(100, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(5050, res);
}


TEST(2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  Label L, C;

  __ mov(r1, Operand(r0));
  __ mov(r0, Operand(1));
  __ b(&C);

  __ bind(&L);
  __ mul(r0, r1, r0);
  __ sub(r1, r1, Operand(1));

  __ bind(&C);
  __ teq(r1, Operand::Zero());
  __ b(ne, &L);
  __ mov(pc, Operand(lr));

  // some relocated stuff here, not executed
  __ RecordComment("dead code, just testing relocations");
  __ mov(r0, Operand(isolate->factory()->true_value()));
  __ RecordComment("dead code, just testing immediate operands");
  __ mov(r0, Operand(-1));
  __ mov(r0, Operand(0xFF000000));
  __ mov(r0, Operand(0xF0F0F0F0));
  __ mov(r0, Operand(0xFFF0FFFF));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(10, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(3628800, res);
}


TEST(3) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int i;
    char c;
    int16_t s;
  };
  T t;

  Assembler assm(AssemblerOptions{});

  __ mov(ip, Operand(sp));
  __ stm(db_w, sp, {r4, fp, lr});
  __ sub(fp, ip, Operand(4));
  __ mov(r4, Operand(r0));
  __ ldr(r0, MemOperand(r4, offsetof(T, i)));
  __ mov(r2, Operand(r0, ASR, 1));
  __ str(r2, MemOperand(r4, offsetof(T, i)));
  __ ldrsb(r2, MemOperand(r4, offsetof(T, c)));
  __ add(r0, r2, Operand(r0));
  __ mov(r2, Operand(r2, LSL, 2));
  __ strb(r2, MemOperand(r4, offsetof(T, c)));
  __ ldrsh(r2, MemOperand(r4, offsetof(T, s)));
  __ add(r0, r2, Operand(r0));
  __ mov(r2, Operand(r2, ASR, 3));
  __ strh(r2, MemOperand(r4, offsetof(T, s)));
  __ ldm(ia_w, sp, {r4, fp, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  t.i = 100000;
  t.c = 10;
  t.s = 1000;
  int res = reinterpret_cast<int>(f.Call(&t, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(101010, res);
  CHECK_EQ(100000/2, t.i);
  CHECK_EQ(10*4, t.c);
  CHECK_EQ(1000/8, t.s);
}


TEST(4) {
  // Test the VFP floating point instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
    int i;
    double j;
    double m;
    double n;
    float o;
    float p;
    float x;
    float y;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(VFPv3)) {
    CpuFeatureScope scope(&assm, VFPv3);

    __ mov(ip, Operand(sp));
    __ stm(db_w, sp, {r4, fp, lr});
    __ sub(fp, ip, Operand(4));

    __ mov(r4, Operand(r0));
    __ vldr(d6, r4, offsetof(T, a));
    __ vldr(d7, r4, offsetof(T, b));
    __ vadd(d5, d6, d7);
    __ vstr(d5, r4, offsetof(T, c));

    __ vmla(d5, d6, d7);
    __ vmls(d5, d5, d6);

    __ vmov(r2, r3, d5);
    __ vmov(d4, r2, r3);
    __ vstr(d4, r4, offsetof(T, b));

    // Load t.x and t.y, switch values, and store back to the struct.
    __ vldr(s0, r4, offsetof(T, x));
    __ vldr(s1, r4, offsetof(T, y));
    __ vmov(s2, s0);
    __ vmov(s0, s1);
    __ vmov(s1, s2);
    __ vstr(s0, r4, offsetof(T, x));
    __ vstr(s1, r4, offsetof(T, y));

    // Move a literal into a register that can be encoded in the instruction.
    __ vmov(d4, base::Double(1.0));
    __ vstr(d4, r4, offsetof(T, e));

    // Move a literal into a register that requires 64 bits to encode.
    // 0x3FF0000010000000 = 1.000000059604644775390625
    __ vmov(d4, base::Double(1.000000059604644775390625));
    __ vstr(d4, r4, offsetof(T, d));

    // Convert from floating point to integer.
    __ vmov(d4, base::Double(2.0));
    __ vcvt_s32_f64(s1, d4);
    __ vstr(s1, r4, offsetof(T, i));

    // Convert from integer to floating point.
    __ mov(lr, Operand(42));
    __ vmov(s1, lr);
    __ vcvt_f64_s32(d4, s1);
    __ vstr(d4, r4, offsetof(T, f));

    // Convert from fixed point to floating point.
    __ mov(lr, Operand(2468));
    __ vmov(s8, lr);
    __ vcvt_f64_s32(d4, 2);
    __ vstr(d4, r4, offsetof(T, j));

    // Test vabs.
    __ vldr(d1, r4, offsetof(T, g));
    __ vabs(d0, d1);
    __ vstr(d0, r4, offsetof(T, g));
    __ vldr(d2, r4, offsetof(T, h));
    __ vabs(d0, d2);
    __ vstr(d0, r4, offsetof(T, h));

    // Test vneg.
    __ vldr(d1, r4, offsetof(T, m));
    __ vneg(d0, d1);
    __ vstr(d0, r4, offsetof(T, m));
    __ vldr(d1, r4, offsetof(T, n));
    __ vneg(d0, d1);
    __ vstr(d0, r4, offsetof(T, n));

    // Test vmov for single-precision immediates.
    __ vmov(s0, Float32(0.25f));
    __ vstr(s0, r4, offsetof(T, o));
    __ vmov(s0, Float32(-16.0f));
    __ vstr(s0, r4, offsetof(T, p));

    __ ldm(ia_w, sp, {r4, fp, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    t.a = 1.5;
    t.b = 2.75;
    t.c = 17.17;
    t.d = 0.0;
    t.e = 0.0;
    t.f = 0.0;
    t.g = -2718.2818;
    t.h = 31415926.5;
    t.i = 0;
    t.j = 0;
    t.m = -2718.2818;
    t.n = 123.456;
    t.x = 4.5;
    t.y = 9.0;
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(-16.0f, t.p);
    CHECK_EQ(0.25f, t.o);
    CHECK_EQ(-123.456, t.n);
    CHECK_EQ(2718.2818, t.m);
    CHECK_EQ(2, t.i);
    CHECK_EQ(2718.2818, t.g);
    CHECK_EQ(31415926.5, t.h);
    CHECK_EQ(617.0, t.j);
    CHECK_EQ(42.0, t.f);
    CHECK_EQ(1.0, t.e);
    CHECK_EQ(1.000000059604644775390625, t.d);
    CHECK_EQ(4.25, t.c);
    CHECK_EQ(-4.1875, t.b);
    CHECK_EQ(1.5, t.a);
    CHECK_EQ(4.5f, t.y);
    CHECK_EQ(9.0f, t.x);
  }
}


TEST(5) {
  // Test the ARMv7 bitfield instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(ARMv7)) {
    CpuFeatureScope scope(&assm, ARMv7);
    // On entry, r0 = 0xAAAAAAAA = 0b10..10101010.
    __ ubfx(r0, r0, 1, 12);  // 0b00..010101010101 = 0x555
    __ sbfx(r0, r0, 0, 5);   // 0b11..111111110101 = -11
    __ bfc(r0, 1, 3);        // 0b11..111111110001 = -15
    __ mov(r1, Operand(7));
    __ bfi(r0, r1, 3, 3);    // 0b11..111111111001 = -7
    __ mov(pc, Operand(lr));

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
    int res = reinterpret_cast<int>(f.Call(0xAAAAAAAA, 0, 0, 0, 0));
    ::printf("f() = %d\n", res);
    CHECK_EQ(-7, res);
  }
}


TEST(6) {
  // Test saturating instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  __ usat(r1, 8, Operand(r0));           // Sat 0xFFFF to 0-255 = 0xFF.
  __ usat(r2, 12, Operand(r0, ASR, 9));  // Sat (0xFFFF>>9) to 0-4095 = 0x7F.
  __ usat(r3, 1, Operand(r0, LSL, 16));  // Sat (0xFFFF<<16) to 0-1 = 0x0.
  __ add(r0, r1, Operand(r2));
  __ add(r0, r0, Operand(r3));
  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(0xFFFF, 0, 0, 0, 0));
  ::printf("f() = %d\n", res);
  CHECK_EQ(382, res);
}


enum VCVTTypes {
  s32_f64,
  u32_f64
};

static void TestRoundingMode(VCVTTypes types,
                             VFPRoundingMode mode,
                             double value,
                             int expected,
                             bool expected_exception = false) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});

  Label wrong_exception;

  __ vmrs(r1);
  // Set custom FPSCR.
  __ bic(r2, r1, Operand(kVFPRoundingModeMask | kVFPExceptionMask));
  __ orr(r2, r2, Operand(mode));
  __ vmsr(r2);

  // Load value, convert, and move back result to r0 if everything went well.
  __ vmov(d1, base::Double(value));
  switch (types) {
    case s32_f64:
      __ vcvt_s32_f64(s0, d1, kFPSCRRounding);
      break;

    case u32_f64:
      __ vcvt_u32_f64(s0, d1, kFPSCRRounding);
      break;

    default:
      UNREACHABLE();
  }
  // Check for vfp exceptions
  __ vmrs(r2);
  __ tst(r2, Operand(kVFPExceptionMask));
  // Check that we behaved as expected.
  __ b(&wrong_exception, expected_exception ? eq : ne);
  // There was no exception. Retrieve the result and return.
  __ vmov(r0, s0);
  __ mov(pc, Operand(lr));

  // The exception behaviour is not what we expected.
  // Load a special value and return.
  __ bind(&wrong_exception);
  __ mov(r0, Operand(11223344));
  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_iiiii>::FromCode(isolate, *code);
  int res = reinterpret_cast<int>(f.Call(0, 0, 0, 0, 0));
  ::printf("res = %d\n", res);
  CHECK_EQ(expected, res);
}


TEST(7) {
  CcTest::InitializeVM();
  // Test vfp rounding modes.

  // s32_f64 (double to integer).

  TestRoundingMode(s32_f64, RN,  0, 0);
  TestRoundingMode(s32_f64, RN,  0.5, 0);
  TestRoundingMode(s32_f64, RN, -0.5, 0);
  TestRoundingMode(s32_f64, RN,  1.5, 2);
  TestRoundingMode(s32_f64, RN, -1.5, -2);
  TestRoundingMode(s32_f64, RN,  123.7, 124);
  TestRoundingMode(s32_f64, RN, -123.7, -124);
  TestRoundingMode(s32_f64, RN,  123456.2,  123456);
  TestRoundingMode(s32_f64, RN, -123456.2, -123456);
  TestRoundingMode(s32_f64, RN, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(s32_f64, RN, (kMaxInt + 0.49), kMaxInt);
  TestRoundingMode(s32_f64, RN, (kMaxInt + 1.0), kMaxInt, true);
  TestRoundingMode(s32_f64, RN, (kMaxInt + 0.5), kMaxInt, true);
  TestRoundingMode(s32_f64, RN, static_cast<double>(kMinInt), kMinInt);
  TestRoundingMode(s32_f64, RN, (kMinInt - 0.5), kMinInt);
  TestRoundingMode(s32_f64, RN, (kMinInt - 1.0), kMinInt, true);
  TestRoundingMode(s32_f64, RN, (kMinInt - 0.51), kMinInt, true);

  TestRoundingMode(s32_f64, RM,  0, 0);
  TestRoundingMode(s32_f64, RM,  0.5, 0);
  TestRoundingMode(s32_f64, RM, -0.5, -1);
  TestRoundingMode(s32_f64, RM,  123.7, 123);
  TestRoundingMode(s32_f64, RM, -123.7, -124);
  TestRoundingMode(s32_f64, RM,  123456.2,  123456);
  TestRoundingMode(s32_f64, RM, -123456.2, -123457);
  TestRoundingMode(s32_f64, RM, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(s32_f64, RM, (kMaxInt + 0.5), kMaxInt);
  TestRoundingMode(s32_f64, RM, (kMaxInt + 1.0), kMaxInt, true);
  TestRoundingMode(s32_f64, RM, static_cast<double>(kMinInt), kMinInt);
  TestRoundingMode(s32_f64, RM, (kMinInt - 0.5), kMinInt, true);
  TestRoundingMode(s32_f64, RM, (kMinInt + 0.5), kMinInt);

  TestRoundingMode(s32_f64, RZ,  0, 0);
  TestRoundingMode(s32_f64, RZ,  0.5, 0);
  TestRoundingMode(s32_f64, RZ, -0.5, 0);
  TestRoundingMode(s32_f64, RZ,  123.7,  123);
  TestRoundingMode(s32_f64, RZ, -123.7, -123);
  TestRoundingMode(s32_f64, RZ,  123456.2,  123456);
  TestRoundingMode(s32_f64, RZ, -123456.2, -123456);
  TestRoundingMode(s32_f64, RZ, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(s32_f64, RZ, (kMaxInt + 0.5), kMaxInt);
  TestRoundingMode(s32_f64, RZ, (kMaxInt + 1.0), kMaxInt, true);
  TestRoundingMode(s32_f64, RZ, static_cast<double>(kMinInt), kMinInt);
  TestRoundingMode(s32_f64, RZ, (kMinInt - 0.5), kMinInt);
  TestRoundingMode(s32_f64, RZ, (kMinInt - 1.0), kMinInt, true);


  // u32_f64 (double to integer).

  // Negative values.
  TestRoundingMode(u32_f64, RN, -0.5, 0);
  TestRoundingMode(u32_f64, RN, -123456.7, 0, true);
  TestRoundingMode(u32_f64, RN, static_cast<double>(kMinInt), 0, true);
  TestRoundingMode(u32_f64, RN, kMinInt - 1.0, 0, true);

  TestRoundingMode(u32_f64, RM, -0.5, 0, true);
  TestRoundingMode(u32_f64, RM, -123456.7, 0, true);
  TestRoundingMode(u32_f64, RM, static_cast<double>(kMinInt), 0, true);
  TestRoundingMode(u32_f64, RM, kMinInt - 1.0, 0, true);

  TestRoundingMode(u32_f64, RZ, -0.5, 0);
  TestRoundingMode(u32_f64, RZ, -123456.7, 0, true);
  TestRoundingMode(u32_f64, RZ, static_cast<double>(kMinInt), 0, true);
  TestRoundingMode(u32_f64, RZ, kMinInt - 1.0, 0, true);

  // Positive values.
  // kMaxInt is the maximum *signed* integer: 0x7FFFFFFF.
  static const uint32_t kMaxUInt = 0xFFFFFFFFu;
  TestRoundingMode(u32_f64, RZ,  0, 0);
  TestRoundingMode(u32_f64, RZ,  0.5, 0);
  TestRoundingMode(u32_f64, RZ,  123.7,  123);
  TestRoundingMode(u32_f64, RZ,  123456.2,  123456);
  TestRoundingMode(u32_f64, RZ, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(u32_f64, RZ, (kMaxInt + 0.5), kMaxInt);
  TestRoundingMode(u32_f64, RZ, (kMaxInt + 1.0),
                                static_cast<uint32_t>(kMaxInt) + 1);
  TestRoundingMode(u32_f64, RZ, (kMaxUInt + 0.5), kMaxUInt);
  TestRoundingMode(u32_f64, RZ, (kMaxUInt + 1.0), kMaxUInt, true);

  TestRoundingMode(u32_f64, RM,  0, 0);
  TestRoundingMode(u32_f64, RM,  0.5, 0);
  TestRoundingMode(u32_f64, RM,  123.7, 123);
  TestRoundingMode(u32_f64, RM,  123456.2,  123456);
  TestRoundingMode(u32_f64, RM, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(u32_f64, RM, (kMaxInt + 0.5), kMaxInt);
  TestRoundingMode(u32_f64, RM, (kMaxInt + 1.0),
                                static_cast<uint32_t>(kMaxInt) + 1);
  TestRoundingMode(u32_f64, RM, (kMaxUInt + 0.5), kMaxUInt);
  TestRoundingMode(u32_f64, RM, (kMaxUInt + 1.0), kMaxUInt, true);

  TestRoundingMode(u32_f64, RN,  0, 0);
  TestRoundingMode(u32_f64, RN,  0.5, 0);
  TestRoundingMode(u32_f64, RN,  1.5, 2);
  TestRoundingMode(u32_f64, RN,  123.7, 124);
  TestRoundingMode(u32_f64, RN,  123456.2,  123456);
  TestRoundingMode(u32_f64, RN, static_cast<double>(kMaxInt), kMaxInt);
  TestRoundingMode(u32_f64, RN, (kMaxInt + 0.49), kMaxInt);
  TestRoundingMode(u32_f64, RN, (kMaxInt + 0.5),
                                static_cast<uint32_t>(kMaxInt) + 1);
  TestRoundingMode(u32_f64, RN, (kMaxUInt + 0.49), kMaxUInt);
  TestRoundingMode(u32_f64, RN, (kMaxUInt + 0.5), kMaxUInt, true);
  TestRoundingMode(u32_f64, RN, (kMaxUInt + 1.0), kMaxUInt, true);
}


TEST(8) {
  // Test VFP multi load/store with ia_w.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct D {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
  };
  D d;

  struct F {
    float a;
    float b;
    float c;
    float d;
    float e;
    float f;
    float g;
    float h;
  };
  F f;

  // Create a function that uses vldm/vstm to move some double and
  // single precision values around in memory.
  Assembler assm(AssemblerOptions{});

  __ mov(ip, Operand(sp));
  __ stm(db_w, sp, {r4, fp, lr});
  __ sub(fp, ip, Operand(4));

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, a))));
  __ vldm(ia_w, r4, d0, d3);
  __ vldm(ia_w, r4, d4, d7);

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, a))));
  __ vstm(ia_w, r4, d6, d7);
  __ vstm(ia_w, r4, d0, d5);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, a))));
  __ vldm(ia_w, r4, s0, s3);
  __ vldm(ia_w, r4, s4, s7);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, a))));
  __ vstm(ia_w, r4, s6, s7);
  __ vstm(ia_w, r4, s0, s5);

  __ ldm(ia_w, sp, {r4, fp, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto fn = GeneratedCode<F_ppiii>::FromCode(isolate, *code);
  d.a = 1.1;
  d.b = 2.2;
  d.c = 3.3;
  d.d = 4.4;
  d.e = 5.5;
  d.f = 6.6;
  d.g = 7.7;
  d.h = 8.8;

  f.a = 1.0;
  f.b = 2.0;
  f.c = 3.0;
  f.d = 4.0;
  f.e = 5.0;
  f.f = 6.0;
  f.g = 7.0;
  f.h = 8.0;

  fn.Call(&d, &f, 0, 0, 0);

  CHECK_EQ(7.7, d.a);
  CHECK_EQ(8.8, d.b);
  CHECK_EQ(1.1, d.c);
  CHECK_EQ(2.2, d.d);
  CHECK_EQ(3.3, d.e);
  CHECK_EQ(4.4, d.f);
  CHECK_EQ(5.5, d.g);
  CHECK_EQ(6.6, d.h);

  CHECK_EQ(7.0f, f.a);
  CHECK_EQ(8.0f, f.b);
  CHECK_EQ(1.0f, f.c);
  CHECK_EQ(2.0f, f.d);
  CHECK_EQ(3.0f, f.e);
  CHECK_EQ(4.0f, f.f);
  CHECK_EQ(5.0f, f.g);
  CHECK_EQ(6.0f, f.h);
}


TEST(9) {
  // Test VFP multi load/store with ia.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct D {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
  };
  D d;

  struct F {
    float a;
    float b;
    float c;
    float d;
    float e;
    float f;
    float g;
    float h;
  };
  F f;

  // Create a function that uses vldm/vstm to move some double and
  // single precision values around in memory.
  Assembler assm(AssemblerOptions{});

  __ mov(ip, Operand(sp));
  __ stm(db_w, sp, {r4, fp, lr});
  __ sub(fp, ip, Operand(4));

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, a))));
  __ vldm(ia, r4, d0, d3);
  __ add(r4, r4, Operand(4 * 8));
  __ vldm(ia, r4, d4, d7);

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, a))));
  __ vstm(ia, r4, d6, d7);
  __ add(r4, r4, Operand(2 * 8));
  __ vstm(ia, r4, d0, d5);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, a))));
  __ vldm(ia, r4, s0, s3);
  __ add(r4, r4, Operand(4 * 4));
  __ vldm(ia, r4, s4, s7);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, a))));
  __ vstm(ia, r4, s6, s7);
  __ add(r4, r4, Operand(2 * 4));
  __ vstm(ia, r4, s0, s5);

  __ ldm(ia_w, sp, {r4, fp, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto fn = GeneratedCode<F_ppiii>::FromCode(isolate, *code);
  d.a = 1.1;
  d.b = 2.2;
  d.c = 3.3;
  d.d = 4.4;
  d.e = 5.5;
  d.f = 6.6;
  d.g = 7.7;
  d.h = 8.8;

  f.a = 1.0;
  f.b = 2.0;
  f.c = 3.0;
  f.d = 4.0;
  f.e = 5.0;
  f.f = 6.0;
  f.g = 7.0;
  f.h = 8.0;

  fn.Call(&d, &f, 0, 0, 0);

  CHECK_EQ(7.7, d.a);
  CHECK_EQ(8.8, d.b);
  CHECK_EQ(1.1, d.c);
  CHECK_EQ(2.2, d.d);
  CHECK_EQ(3.3, d.e);
  CHECK_EQ(4.4, d.f);
  CHECK_EQ(5.5, d.g);
  CHECK_EQ(6.6, d.h);

  CHECK_EQ(7.0f, f.a);
  CHECK_EQ(8.0f, f.b);
  CHECK_EQ(1.0f, f.c);
  CHECK_EQ(2.0f, f.d);
  CHECK_EQ(3.0f, f.e);
  CHECK_EQ(4.0f, f.f);
  CHECK_EQ(5.0f, f.g);
  CHECK_EQ(6.0f, f.h);
}


TEST(10) {
  // Test VFP multi load/store with db_w.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct D {
    double a;
    double b;
    double c;
    double d;
    double e;
    double f;
    double g;
    double h;
  };
  D d;

  struct F {
    float a;
    float b;
    float c;
    float d;
    float e;
    float f;
    float g;
    float h;
  };
  F f;

  // Create a function that uses vldm/vstm to move some double and
  // single precision values around in memory.
  Assembler assm(AssemblerOptions{});

  __ mov(ip, Operand(sp));
  __ stm(db_w, sp, {r4, fp, lr});
  __ sub(fp, ip, Operand(4));

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, h)) + 8));
  __ vldm(db_w, r4, d4, d7);
  __ vldm(db_w, r4, d0, d3);

  __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(D, h)) + 8));
  __ vstm(db_w, r4, d0, d5);
  __ vstm(db_w, r4, d6, d7);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, h)) + 4));
  __ vldm(db_w, r4, s4, s7);
  __ vldm(db_w, r4, s0, s3);

  __ add(r4, r1, Operand(static_cast<int32_t>(offsetof(F, h)) + 4));
  __ vstm(db_w, r4, s0, s5);
  __ vstm(db_w, r4, s6, s7);

  __ ldm(ia_w, sp, {r4, fp, pc});

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto fn = GeneratedCode<F_ppiii>::FromCode(isolate, *code);
  d.a = 1.1;
  d.b = 2.2;
  d.c = 3.3;
  d.d = 4.4;
  d.e = 5.5;
  d.f = 6.6;
  d.g = 7.7;
  d.h = 8.8;

  f.a = 1.0;
  f.b = 2.0;
  f.c = 3.0;
  f.d = 4.0;
  f.e = 5.0;
  f.f = 6.0;
  f.g = 7.0;
  f.h = 8.0;

  fn.Call(&d, &f, 0, 0, 0);

  CHECK_EQ(7.7, d.a);
  CHECK_EQ(8.8, d.b);
  CHECK_EQ(1.1, d.c);
  CHECK_EQ(2.2, d.d);
  CHECK_EQ(3.3, d.e);
  CHECK_EQ(4.4, d.f);
  CHECK_EQ(5.5, d.g);
  CHECK_EQ(6.6, d.h);

  CHECK_EQ(7.0f, f.a);
  CHECK_EQ(8.0f, f.b);
  CHECK_EQ(1.0f, f.c);
  CHECK_EQ(2.0f, f.d);
  CHECK_EQ(3.0f, f.e);
  CHECK_EQ(4.0f, f.f);
  CHECK_EQ(5.0f, f.g);
  CHECK_EQ(6.0f, f.h);
}


TEST(11) {
  // Test instructions using the carry flag.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct I {
    int32_t a;
    int32_t b;
    int32_t c;
    int32_t d;
  };
  I i;

  i.a = 0xABCD0001;
  i.b = 0xABCD0000;

  Assembler assm(AssemblerOptions{});

  // Test HeapObject untagging.
  __ ldr(r1, MemOperand(r0, offsetof(I, a)));
  __ mov(r1, Operand(r1, ASR, 1), SetCC);
  __ adc(r1, r1, Operand(r1), LeaveCC, cs);
  __ str(r1, MemOperand(r0, offsetof(I, a)));

  __ ldr(r2, MemOperand(r0, offsetof(I, b)));
  __ mov(r2, Operand(r2, ASR, 1), SetCC);
  __ adc(r2, r2, Operand(r2), LeaveCC, cs);
  __ str(r2, MemOperand(r0, offsetof(I, b)));

  // Test corner cases.
  __ mov(r1, Operand(0xFFFFFFFF));
  __ mov(r2, Operand::Zero());
  __ mov(r3, Operand(r1, ASR, 1), SetCC);  // Set the carry.
  __ adc(r3, r1, Operand(r2));
  __ str(r3, MemOperand(r0, offsetof(I, c)));

  __ mov(r1, Operand(0xFFFFFFFF));
  __ mov(r2, Operand::Zero());
  __ mov(r3, Operand(r2, ASR, 1), SetCC);  // Unset the carry.
  __ adc(r3, r1, Operand(r2));
  __ str(r3, MemOperand(r0, offsetof(I, d)));

  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  f.Call(&i, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0xABCD0001), i.a);
  CHECK_EQ(static_cast<int32_t>(0xABCD0000) >> 1, i.b);
  CHECK_EQ(0x00000000, i.c);
  CHECK_EQ(static_cast<int32_t>(0xFFFFFFFF), i.d);
}


TEST(12) {
  // Test chaining of label usages within instructions (issue 1644).
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  Assembler assm(AssemblerOptions{});
  Label target;
  __ b(eq, &target);
  __ b(ne, &target);
  __ bind(&target);
  __ nop();
}


TEST(13) {
  // Test VFP instructions using registers d16-d31.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  if (!CpuFeatures::IsSupported(VFP32DREGS)) {
    return;
  }

  struct T {
    double a;
    double b;
    double c;
    double x;
    double y;
    double z;
    double i;
    double j;
    double k;
    uint32_t low;
    uint32_t high;
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles and floats.
  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(VFPv3)) {
    CpuFeatureScope scope(&assm, VFPv3);

    __ stm(db_w, sp, {r4, lr});

    // Load a, b, c into d16, d17, d18.
    __ mov(r4, Operand(r0));
    __ vldr(d16, r4, offsetof(T, a));
    __ vldr(d17, r4, offsetof(T, b));
    __ vldr(d18, r4, offsetof(T, c));

    __ vneg(d25, d16);
    __ vadd(d25, d25, d17);
    __ vsub(d25, d25, d18);
    __ vmul(d25, d25, d25);
    __ vdiv(d25, d25, d18);

    __ vmov(d16, d25);
    __ vsqrt(d17, d25);
    __ vneg(d17, d17);
    __ vabs(d17, d17);
    __ vmla(d18, d16, d17);

    // Store d16, d17, d18 into a, b, c.
    __ mov(r4, Operand(r0));
    __ vstr(d16, r4, offsetof(T, a));
    __ vstr(d17, r4, offsetof(T, b));
    __ vstr(d18, r4, offsetof(T, c));

    // Load x, y, z into d29-d31.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, x))));
    __ vldm(ia_w, r4, d29, d31);

    // Swap d29 and d30 via r registers.
    __ vmov(r1, r2, d29);
    __ vmov(d29, d30);
    __ vmov(d30, r1, r2);

    // Convert to and from integer.
    __ vcvt_s32_f64(s1, d31);
    __ vcvt_f64_u32(d31, s1);

    // Store d29-d31 into x, y, z.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, x))));
    __ vstm(ia_w, r4, d29, d31);

    // Move constants into d20, d21, d22 and store into i, j, k.
    __ vmov(d20, base::Double(14.7610017472335499));
    __ vmov(d21, base::Double(16.0));
    __ mov(r1, Operand(372106121));
    __ mov(r2, Operand(1079146608));
    __ vmov(NeonS32, d22, 0, r1);
    __ vmov(NeonS32, d22, 1, r2);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, i))));
    __ vstm(ia_w, r4, d20, d22);
    // Move d22 into low and high.
    __ vmov(NeonS32, r4, d22, 0);
    __ str(r4, MemOperand(r0, offsetof(T, low)));
    __ vmov(NeonS32, r4, d22, 1);
    __ str(r4, MemOperand(r0, offsetof(T, high)));

    __ ldm(ia_w, sp, {r4, pc});

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
    StdoutStream os;
    Print(*code, os);
#endif
    auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
    t.a = 1.5;
    t.b = 2.75;
    t.c = 17.17;
    t.x = 1.5;
    t.y = 2.75;
    t.z = 17.17;
    f.Call(&t, 0, 0, 0, 0);
    CHECK_EQ(14.7610017472335499, t.a);
    CHECK_EQ(3.84200491244266251, t.b);
    CHECK_EQ(73.8818412254460241, t.c);
    CHECK_EQ(2.75, t.x);
    CHECK_EQ(1.5, t.y);
    CHECK_EQ(17.0, t.z);
    CHECK_EQ(14.7610017472335499, t.i);
    CHECK_EQ(16.0, t.j);
    CHECK_EQ(73.8818412254460241, t.k);
    CHECK_EQ(372106121u, t.low);
    CHECK_EQ(1079146608u, t.high);
  }
}


TEST(14) {
  // Test the VFP Canonicalized Nan mode.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double left;
    double right;
    double add_result;
    double sub_result;
    double mul_result;
    double div_result;
  };
  T t;

  // Create a function that makes the four basic operations.
  Assembler assm(AssemblerOptions{});

  // Ensure FPSCR state (as JSEntry does).
  Label fpscr_done;
  __ vmrs(r1);
  __ tst(r1, Operand(kVFPDefaultNaNModeControlBit));
  __ b(ne, &fpscr_done);
  __ orr(r1, r1, Operand(kVFPDefaultNaNModeControlBit));
  __ vmsr(r1);
  __ bind(&fpscr_done);

  __ vldr(d0, r0, offsetof(T, left));
  __ vldr(d1, r0, offsetof(T, right));
  __ vadd(d2, d0, d1);
  __ vstr(d2, r0, offsetof(T, add_result));
  __ vsub(d2, d0, d1);
  __ vstr(d2, r0, offsetof(T, sub_result));
  __ vmul(d2, d0, d1);
  __ vstr(d2, r0, offsetof(T, mul_result));
  __ vdiv(d2, d0, d1);
  __ vstr(d2, r0, offsetof(T, div_result));

  __ mov(pc, Operand(lr));

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef DEBUG
  StdoutStream os;
  Print(*code, os);
#endif
  auto f = GeneratedCode<F_piiii>::FromCode(isolate, *code);
  t.left = base::bit_cast<double>(kHoleNanInt64);
  t.right = 1;
  t.add_result = 0;
  t.sub_result = 0;
  t.mul_result = 0;
  t.div_result = 0;
  f.Call(&t, 0, 0, 0, 0);
  const uint32_t kArmNanUpper32 = 0x7FF80000;
  const uint32_t kArmNanLower32 = 0x00000000;
#ifdef DEBUG
  const uint64_t kArmNanInt64 =
      (static_cast<uint64_t>(kArmNanUpper32) << 32) | kArmNanLower32;
  CHECK_NE(kArmNanInt64, kHoleNanInt64);
#endif
  // With VFP2 the sign of the canonicalized Nan is undefined. So
  // we remove the sign bit for the upper tests.
  CHECK_EQ(kArmNanUpper32,
           (base::bit_cast<int64_t>(t.add_result) >> 32) & 0x7FFFFFFF);
  CHECK_EQ(kArmNanLower32, base::bit_cast<int64_t>(t.add_result) & 0xFFFFFFFFu);
  CHECK_EQ(kArmNanUpper32,
           (base::bit_cast<int64_t>(t.sub_result) >> 32) & 0x7FFFFFFF);
  CHECK_EQ(kArmNanLower32, base::bit_cast<int64_t>(t.sub_result) & 0xFFFFFFFFu);
  CHECK_EQ(kArmNanUpper32,
           (base::bit_cast<int64_t>(t.mul_result) >> 32) & 0x7FFFFFFF);
  CHECK_EQ(kArmNanLower32, base::bit_cast<int64_t>(t.mul_result) & 0xFFFFFFFFu);
  CHECK_EQ(kArmNanUpper32,
           (base::bit_cast<int64_t>(t.div_result) >> 32) & 0x7FFFFFFF);
  CHECK_EQ(kArmNanLower32, base::bit_cast<int64_t>(t.div_result) & 0xFFFFFFFFu);
}

#define CHECK_EQ_SPLAT(field, ex) \
  CHECK_EQ(ex, t.field[0]);       \
  CHECK_EQ(ex, t.field[1]);       \
  CHECK_EQ(ex, t.field[2]);       \
  CHECK_EQ(ex, t.field[3]);

#define CHECK_EQ_32X2(field, ex0, ex1) \
  CHECK_EQ(ex0, t.field[0]);           \
  CHECK_EQ(ex1, t.field[1]);

#define CHECK_EQ_32X4(field, ex0, ex1, ex2, ex3) \
  CHECK_EQ(ex0, t.field[0]);                     \
  CHECK_EQ(ex1, t.field[1]);                     \
  CHECK_EQ(ex2, t.field[2]);                     \
  CHECK_EQ(ex3, t.field[3]);

#define CHECK_ESTIMATE(expected, tolerance, value) \
  CHECK_LT((expected) - (tolerance), value);       \
  CHECK_GT((expected) + (tolerance), value);

#define CHECK_ESTIMATE_SPLAT(field, ex, tol) \
  CHECK_ESTIMATE(ex, tol, t.field[0]);       \
  CHECK_ESTIMATE(ex, tol, t.field[1]);       \
  CHECK_ESTIMATE(ex, tol, t.field[2]);       \
  CHECK_ESTIMATE(ex, tol, t.field[3]);

#define INT32_TO_FLOAT(val) \
  std::round(static_cast<float>(base::bit_cast<int32_t>(val)))
#define UINT32_TO_FLOAT(val) \
  std::round(static_cast<float>(base::bit_cast<uint32_t>(val)))

TEST(15) {
  // Test the Neon instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    uint32_t src0;
    uint32_t src1;
    uint32_t src2;
    uint32_t src3;
    uint32_t src4;
    uint32_t src5;
    uint32_t src6;
    uint32_t src7;
    uint32_t dst0;
    uint32_t dst1;
    uint32_t dst2;
    uint32_t dst3;
    uint32_t dst4;
    uint32_t dst5;
    uint32_t dst6;
    uint32_t dst7;
    uint32_t srcA0;
    uint32_t srcA1;
    uint32_t dstA0;
    uint32_t dstA1;
    uint32_t dstA2;
    uint32_t dstA3;
    uint32_t lane_test[4];
    uint64_t vmov_to_scalar1, vmov_to_scalar2;
    uint32_t vmov_from_scalar_s8, vmov_from_scalar_u8;
    uint32_t vmov_from_scalar_s16, vmov_from_scalar_u16;
    uint32_t vmov_from_scalar_32;
    uint32_t vmov[4], vmvn[4];
    uint32_t vmovl_s8[4], vmovl_u16[4], vmovl_s32[4];
    uint32_t vqmovn_s8[2], vqmovn_u16[2], vqmovn_s32[2];
    int32_t vcvt_s32_f32[4];
    uint32_t vcvt_u32_f32[4];
    float vcvt_f32_s32[4], vcvt_f32_u32[4];
    uint32_t vdup8[4], vdup16[4], vdup32[4];
    float vabsf[4], vnegf[4];
    uint32_t vclt0_s8[4], vclt0_s16[4], vclt0_s32[4];
    uint32_t vabs_s8[4], vabs_s16[4], vabs_s32[4];
    uint32_t vneg_s8[4], vneg_s16[4], vneg_s32[4];
    uint32_t veor[4], vand[4], vorr[4];
    float vdupf[4], vaddf[4], vpaddf[2], vsubf[4], vmulf[4];
    uint32_t vdupf_16[2], vdupf_8[4];
    uint32_t vmin_s8[4], vmin_u16[4], vmin_s32[4];
    uint32_t vmax_s8[4], vmax_u16[4], vmax_s32[4];
    uint32_t vpadd_i8[2], vpadd_i16[2], vpadd_i32[2];
    uint32_t vpadal_s8[4], vpadal_s16[4], vpadal_s32[4];
    uint32_t vpadal_u8[4], vpadal_u16[4], vpadal_u32[4];
    uint32_t vpaddl_s8[4], vpaddl_s16[4], vpaddl_s32[4];
    uint32_t vpaddl_u8[4], vpaddl_u16[4], vpaddl_u32[4];
    uint32_t vpmin_s8[2], vpmin_u16[2], vpmin_s32[2];
    uint32_t vpmax_s8[2], vpmax_u16[2], vpmax_s32[2];
    uint32_t vadd8[4], vadd16[4], vadd32[4];
    uint32_t vqadd_s8[4], vqadd_u16[4], vqadd_s32[4];
    uint32_t vsub8[4], vsub16[4], vsub32[4];
    uint32_t vqsub_u8[4], vqsub_s16[4], vqsub_u32[4];
    uint32_t vmul8[4], vmul16[4], vmul32[4];
    uint32_t vshl8[4], vshl16[4], vshl32[4];
    uint32_t vshr_s8[4], vshr_u16[4], vshr_s32[4];
    uint32_t vshr_s8_d[2], vshr_u16_d[2], vshr_s32_d[2];
    uint32_t vsli_64[2], vsri_64[2], vsli_32[2], vsri_32[2];
    uint32_t vsra_64[2], vsra_32[2], vsra_16[2];
    uint32_t vceq[4], vceqf[4], vcgef[4], vcgtf[4];
    uint32_t vcge_s8[4], vcge_u16[4], vcge_s32[4];
    uint32_t vcgt_s8[4], vcgt_u16[4], vcgt_s32[4];
    float vrecpe[4], vrecps[4], vrsqrte[4], vrsqrts[4];
    float vminf[4], vmaxf[4];
    uint32_t vtst[4], vbsl[4];
    uint32_t vext[4];
    uint32_t vzip8a[4], vzip8b[4], vzip16a[4], vzip16b[4], vzip32a[4],
        vzip32b[4];
    uint32_t vzipd8a[2], vzipd8b[2], vzipd16a[2], vzipd16b[2];
    uint32_t vuzp8a[4], vuzp8b[4], vuzp16a[4], vuzp16b[4], vuzp32a[4],
        vuzp32b[4];
    uint32_t vuzpd8a[2], vuzpd8b[2], vuzpd16a[2], vuzpd16b[2];
    uint32_t vrev64_32[4], vrev64_16[4], vrev64_8[4];
    uint32_t vrev32_16[4], vrev32_8[4], vrev16_8[4];
    uint32_t vtrn8a[4], vtrn8b[4], vtrn16a[4], vtrn16b[4], vtrn32a[4],
        vtrn32b[4];
    uint32_t vtrnd8a[2], vtrnd8b[2], vtrnd16a[2], vtrnd16b[2], vtrnd32a[2],
        vtrnd32b[2];
    uint32_t vtbl[2], vtbx[2];
  };
  T t;

  // Create a function that accepts &t, and loads, manipulates, and stores
  // the doubles, floats, and SIMD values.
  Assembler assm(AssemblerOptions{});

  if (CpuFeatures::IsSupported(NEON)) {
    CpuFeatureScope scope(&assm, NEON);

    __ stm(db_w, sp, {r4, r5, lr});
    // Move 32 bytes with neon.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, src0))));
    __ vld1(Neon8, NeonListOperand(d0, 4), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, dst0))));
    __ vst1(Neon8, NeonListOperand(d0, 4), NeonMemOperand(r4));

    // Expand 8 bytes into 8 words(16 bits).
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, srcA0))));
    __ vld1(Neon8, NeonListOperand(d0), NeonMemOperand(r4));
    __ vmovl(NeonU8, q0, d0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, dstA0))));
    __ vst1(Neon8, NeonListOperand(d0, 2), NeonMemOperand(r4));

    // The same expansion, but with different source and destination registers.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, srcA0))));
    __ vld1(Neon8, NeonListOperand(d1), NeonMemOperand(r4));
    __ vmovl(NeonS8, q1, d1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmovl_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vmovl(NeonU16, q2, d3);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmovl_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vmovl(NeonS32, q3, d4);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmovl_s32))));
    __ vst1(Neon8, NeonListOperand(q3), NeonMemOperand(r4));
    // Narrow what we widened.
    __ vqmovn(NeonU16, NeonU16, d0, q2);
    __ vstr(d0, r0, offsetof(T, vqmovn_u16));
    __ vmov(d1, d0);
    __ vqmovn(NeonS8, NeonS8, d2, q0);
    __ vstr(d2, r0, offsetof(T, vqmovn_s8));
    __ vqmovn(NeonS32, NeonS32, d4, q3);
    __ vstr(d4, r0, offsetof(T, vqmovn_s32));

    // ARM core register to scalar.
    __ mov(r4, Operand(0xFFFFFFF8));
    __ vmov(d0, base::Double(0.0));
    __ vmov(NeonS8, d0, 1, r4);
    __ vmov(NeonS16, d0, 1, r4);
    __ vmov(NeonS32, d0, 1, r4);
    __ vstr(d0, r0, offsetof(T, vmov_to_scalar1));
    __ vmov(d0, base::Double(0.0));
    __ vmov(NeonS8, d0, 3, r4);
    __ vmov(NeonS16, d0, 3, r4);
    __ vstr(d0, r0, offsetof(T, vmov_to_scalar2));

    // Scalar to ARM core register.
    __ mov(r4, Operand(0xFFFFFF00));
    __ mov(r5, Operand(0xFFFFFFFF));
    __ vmov(d0, r4, r5);
    __ vmov(NeonS8, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_s8)));
    __ vmov(NeonU8, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_u8)));
    __ vmov(NeonS16, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_s16)));
    __ vmov(NeonU16, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_u16)));
    __ vmov(NeonS32, r4, d0, 1);
    __ str(r4, MemOperand(r0, offsetof(T, vmov_from_scalar_32)));

    // vmov for q-registers.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmov))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vmvn.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmvn(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmvn))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vcvt for q-registers.
    __ vmov(s0, Float32(-1.5f));
    __ vmov(s1, Float32(-1.0f));
    __ vmov(s2, Float32(1.0f));
    __ vmov(s3, Float32(1.5f));
    __ vcvt_s32_f32(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcvt_s32_f32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vcvt_u32_f32(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcvt_u32_f32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(kMinInt));
    __ mov(r5, Operand(kMaxInt));
    __ vmov(d0, r4, r5);
    __ mov(r4, Operand(kMaxUInt32));
    __ mov(r5, Operand(kMinInt + 1));
    __ vmov(d1, r4, r5);  // q0 = [kMinInt, kMaxInt, kMaxUInt32, kMinInt + 1]
    __ vcvt_f32_s32(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcvt_f32_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vcvt_f32_u32(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcvt_f32_u32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vdup (from register).
    __ mov(r4, Operand(0xA));
    __ vdup(Neon8, q0, r4);
    __ vdup(Neon16, q1, r4);
    __ vdup(Neon32, q2, r4);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdup8))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdup16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdup32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vdup (from scalar).
    __ vmov(s0, Float32(-1.0f));
    __ vdup(Neon32, q1, d0, 0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdupf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vdup(Neon16, d2, d0, 1);
    __ vstr(d2, r0, offsetof(T, vdupf_16));
    __ vdup(Neon8, q1, d0, 3);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vdupf_8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vabs (float).
    __ vmov(s0, Float32(-1.0f));
    __ vmov(s1, Float32(-0.0f));
    __ vmov(s2, Float32(0.0f));
    __ vmov(s3, Float32(1.0f));
    __ vabs(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vabsf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vneg (float).
    __ vneg(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vnegf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vabs (integer).
    __ mov(r4, Operand(0x7F7F7F7F));
    __ mov(r5, Operand(0x01010101));
    __ vmov(d0, r4, r5);
    __ mov(r4, Operand(0xFFFFFFFF));
    __ mov(r5, Operand(0x80808080));
    __ vmov(d1, r4, r5);
    __ vabs(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vabs_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vabs(Neon16, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vabs_s16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vabs(Neon32, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vabs_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vneg (integer).
    __ vneg(Neon8, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vneg_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vneg(Neon16, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vneg_s16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vneg(Neon32, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vneg_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // veor.
    __ mov(r4, Operand(0xAA));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x55));
    __ vdup(Neon16, q1, r4);
    __ veor(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, veor))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vand.
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0xFE));
    __ vdup(Neon16, q1, r4);
    __ vand(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vand))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vorr.
    __ mov(r4, Operand(0xAA));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x55));
    __ vdup(Neon16, q1, r4);
    __ vorr(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vorr))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vmin (float).
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q1, d2, 0);
    __ vmin(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vminf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vmax (float).
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q1, d2, 0);
    __ vmax(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmaxf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vadd (float).
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vdup(Neon32, q1, d2, 0);
    __ vadd(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vaddf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vpadd (float).
    __ vmov(s0, Float32(1.0f));
    __ vmov(s1, Float32(2.0f));
    __ vmov(s2, Float32(3.0f));
    __ vmov(s3, Float32(4.0f));
    __ vpadd(d2, d0, d1);
    __ vstr(d2, r0, offsetof(T, vpaddf));
    // vsub (float).
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q1, d2, 0);
    __ vsub(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vsubf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vmul (float).
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vdup(Neon32, q1, d2, 0);
    __ vmul(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmulf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vrecpe.
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vrecpe(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrecpe))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vrecps.
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(1.5f));
    __ vdup(Neon32, q1, d2, 0);
    __ vrecps(q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrecps))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vrsqrte.
    __ vmov(s4, Float32(4.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vrsqrte(q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrsqrte))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vrsqrts.
    __ vmov(s4, Float32(2.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vmov(s4, Float32(2.5f));
    __ vdup(Neon32, q1, d2, 0);
    __ vrsqrts(q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vrsqrts))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vceq (float).
    __ vmov(s4, Float32(1.0f));
    __ vdup(Neon32, q0, d2, 0);
    __ vdup(Neon32, q1, d2, 0);
    __ vceq(q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vceqf))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    // vcge (float).
    __ vmov(s0, Float32(1.0f));
    __ vmov(s1, Float32(-1.0f));
    __ vmov(s2, Float32(-0.0f));
    __ vmov(s3, Float32(0.0f));
    __ vdup(Neon32, q1, d1, 1);
    __ vcge(q2, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgef))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vcgt(q2, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgtf))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vmin/vmax integer.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vmin(NeonS8, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmin_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vmax(NeonS8, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmax_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vmin(NeonU16, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmin_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vmax(NeonU16, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmax_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon32, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vmin(NeonS32, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmin_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vmax(NeonS32, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmax_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpadd integer.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vpadd(Neon8, d0, d0, d2);
    __ vstr(d0, r0, offsetof(T, vpadd_i8));
    __ vpadd(Neon16, d0, d0, d2);
    __ vstr(d0, r0, offsetof(T, vpadd_i16));
    __ vpadd(Neon32, d0, d0, d2);
    __ vstr(d0, r0, offsetof(T, vpadd_i32));

    // vpadal signed.
    __ mov(r4, Operand(0x81));
    __ vdup(Neon8, q0, r4);

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonS8, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonS16, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_s16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonS32, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpadal unsigned.
    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonU8, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_u8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonU16, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q2, r4);
    __ vpadal(NeonU32, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpadal_u32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpaddl signed.
    __ mov(r4, Operand(0x81));
    __ vdup(Neon8, q0, r4);

    __ vpaddl(NeonS8, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ vpaddl(NeonS16, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_s16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ vpaddl(NeonS32, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpaddl unsigned.
    __ vpaddl(NeonU8, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_u8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ vpaddl(NeonU16, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    __ vpaddl(NeonU32, q2, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vpaddl_u32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vpmin/vpmax integer.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vpmin(NeonS8, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmin_s8));
    __ vpmax(NeonS8, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmax_s8));
    __ mov(r4, Operand(0xFFFF));
    __ vdup(Neon32, q0, r4);
    __ vdup(Neon16, q1, r4);
    __ vpmin(NeonU16, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmin_u16));
    __ vpmax(NeonU16, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmax_u16));
    __ mov(r4, Operand(0xFF));
    __ veor(q0, q0, q0);
    __ vmov(s0, r4);
    __ vdup(Neon8, q1, r4);
    __ vpmin(NeonS32, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmin_s32));
    __ vpmax(NeonS32, d4, d0, d2);
    __ vstr(d4, r0, offsetof(T, vpmax_s32));

    // vadd (integer).
    __ mov(r4, Operand(0x81));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x82));
    __ vdup(Neon8, q1, r4);
    __ vadd(Neon8, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vadd8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x8001));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x8002));
    __ vdup(Neon16, q1, r4);
    __ vadd(Neon16, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vadd16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x80000001));
    __ vdup(Neon32, q0, r4);
    __ mov(r4, Operand(0x80000002));
    __ vdup(Neon32, q1, r4);
    __ vadd(Neon32, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vadd32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vqadd.
    __ mov(r4, Operand(0x81));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x82));
    __ vdup(Neon8, q1, r4);
    __ vqadd(NeonS8, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqadd_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x8000));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon16, q1, r4);
    __ vqadd(NeonU16, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqadd_u16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x80000001));
    __ vdup(Neon32, q0, r4);
    __ mov(r4, Operand(0x80000002));
    __ vdup(Neon32, q1, r4);
    __ vqadd(NeonS32, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqadd_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vsub (integer).
    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x03));
    __ vdup(Neon8, q1, r4);
    __ vsub(Neon8, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vsub8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x0001));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x0003));
    __ vdup(Neon16, q1, r4);
    __ vsub(Neon16, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vsub16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x00000001));
    __ vdup(Neon32, q0, r4);
    __ mov(r4, Operand(0x00000003));
    __ vdup(Neon32, q1, r4);
    __ vsub(Neon32, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vsub32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vqsub.
    __ mov(r4, Operand(0x7F));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x3F));
    __ vdup(Neon8, q1, r4);
    __ vqsub(NeonU8, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqsub_u8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x8000));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x7FFF));
    __ vdup(Neon16, q1, r4);
    __ vqsub(NeonS16, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqsub_s16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x80000001));
    __ vdup(Neon32, q0, r4);
    __ mov(r4, Operand(0x80000000));
    __ vdup(Neon32, q1, r4);
    __ vqsub(NeonU32, q1, q1, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vqsub_u32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vmul (integer).
    __ mov(r4, Operand(0x02));
    __ vdup(Neon8, q0, r4);
    __ vmul(Neon8, q1, q0, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmul8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x0002));
    __ vdup(Neon16, q0, r4);
    __ vmul(Neon16, q1, q0, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmul16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ mov(r4, Operand(0x00000002));
    __ vdup(Neon32, q0, r4);
    __ vmul(Neon32, q1, q0, q0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vmul32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vshl.
    __ mov(r4, Operand(0x55));
    __ vdup(Neon8, q0, r4);
    __ vshl(NeonS8, q1, q0, 1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshl8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshl(NeonU16, q1, q0, 9);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshl16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshl(NeonS32, q1, q0, 17);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshl32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vshr.s, vshr.u.
    __ mov(r4, Operand(0x80));
    __ vdup(Neon8, q0, r4);
    __ vshr(NeonS8, q1, q0, 1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshr(NeonU16, q1, q0, 9);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_u16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshr(NeonS32, q1, q0, 17);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vshr.s, vshr.u with d registers.
    __ mov(r4, Operand(0x80));
    __ vdup(Neon8, q0, r4);
    __ vshr(NeonS8, d1, d0, 1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_s8_d))));
    __ vst1(Neon8, NeonListOperand(d1), NeonMemOperand(r4));
    __ vshr(NeonU16, d2, d0, 9);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_u16_d))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ vshr(NeonS32, d2, d0, 17);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vshr_s32_d))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vsli, vsri.
    __ mov(r4, Operand(0xFFFFFFFF));
    __ mov(r5, Operand(0x1));
    __ vmov(d0, r4, r5);
    __ vmov(d1, r5, r5);
    __ vsli(Neon64, d1, d0, 32);
    __ vstr(d1, r0, offsetof(T, vsli_64));
    __ vmov(d0, r5, r4);
    __ vmov(d1, r5, r5);
    __ vsri(Neon64, d1, d0, 32);
    __ vstr(d1, r0, offsetof(T, vsri_64));
    __ vmov(d0, r4, r5);
    __ vmov(d1, r5, r5);
    __ vsli(Neon32, d1, d0, 16);
    __ vstr(d1, r0, offsetof(T, vsli_32));
    __ vmov(d0, r5, r4);
    __ vmov(d1, r5, r5);
    __ vsri(Neon32, d1, d0, 16);
    __ vstr(d1, r0, offsetof(T, vsri_32));

    // vsra.
    __ vmov(d0, r4, r5);
    // Check same dst and src registers.
    __ vsra(NeonU64, d0, d0, 1);
    __ vstr(d0, r0, offsetof(T, vsra_64));
    __ vmov(d0, r4, r5);
    __ vmov(d1, r5, r4);
    __ vsra(NeonS32, d1, d0, 16);
    __ vstr(d1, r0, offsetof(T, vsra_32));
    __ vmov(d0, r4, r5);
    __ vmov(d1, r5, r4);
    __ vsra(NeonU16, d1, d0, 2);
    __ vstr(d1, r0, offsetof(T, vsra_16));

    // vceq.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon8, q0, r4);
    __ vdup(Neon16, q1, r4);
    __ vceq(Neon8, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vceq))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vcge/vcgt (integer).
    __ mov(r4, Operand(0x03));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vcge(NeonS8, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcge_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vcgt(NeonS8, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgt_s8))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon16, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vcge(NeonU16, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcge_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vcgt(NeonU16, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgt_u16))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ mov(r4, Operand(0xFF));
    __ vdup(Neon32, q0, r4);
    __ vdup(Neon8, q1, r4);
    __ vcge(NeonS32, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcge_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));
    __ vcgt(NeonS32, q2, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vcgt_s32))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vclt #0 (signed integer).
    __ mov(r4, Operand(0x7F80807F));
    __ mov(r5, Operand(0xFF01FF01));
    __ vmov(d0, r4, r5);
    __ mov(r4, Operand(0xFF0000FF));
    __ mov(r5, Operand(0x00800080));
    __ vmov(d1, r4, r5);

    __ vclt(Neon8, q1, q0, 0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vclt0_s8))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    __ vclt(Neon16, q1, q0, 0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vclt0_s16))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    __ vclt(Neon32, q1, q0, 0);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vclt0_s32))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vtst.
    __ mov(r4, Operand(0x03));
    __ vdup(Neon8, q0, r4);
    __ mov(r4, Operand(0x02));
    __ vdup(Neon16, q1, r4);
    __ vtst(Neon8, q1, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vtst))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));

    // vbsl.
    __ mov(r4, Operand(0x00FF));
    __ vdup(Neon16, q0, r4);
    __ mov(r4, Operand(0x01));
    __ vdup(Neon8, q1, r4);
    __ mov(r4, Operand(0x02));
    __ vdup(Neon8, q2, r4);
    __ vbsl(q0, q1, q2);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vbsl))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));

    // vext.
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vext(q2, q0, q1, 3);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vext))));
    __ vst1(Neon8, NeonListOperand(q2), NeonMemOperand(r4));

    // vzip (q-register).
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vzip(Neon8, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip8a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip8b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vzip(Neon16, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip16a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip16b))));
    __ vst1(Neon8, NeonListOperand(q1), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, lane_test))));
    __ vld1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ vmov(q1, q0);
    __ vzip(Neon32, q0, q1);
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip32a))));
    __ vst1(Neon8, NeonListOperand(q0), NeonMemOperand(r4));
    __ add(r4, r0, Operand(static_cast<int32_t>(offsetof(T, vzip32b))));
    __ vst1(Neon8,
"""


```