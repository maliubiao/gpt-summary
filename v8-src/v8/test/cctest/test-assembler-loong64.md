Response: 
Prompt: 
```
这是目录为v8/test/cctest/test-assembler-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
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

#include "src/base/utils/random-number-generator.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disassembler.h"
#include "src/execution/simulator.h"
#include "src/heap/factory.h"
#include "src/init/v8.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {

// Define these function prototypes to match JSEntryFunction in execution.cc.
// TODO(LOONG64): Refine these signatures per test case.
using F1 = void*(int x, int p1, int p2, int p3, int p4);
using F2 = void*(int x, int y, int p2, int p3, int p4);
using F3 = void*(void* p, int p1, int p2, int p3, int p4);
using F4 = void*(int64_t x, int64_t y, int64_t p2, int64_t p3, int64_t p4);
using F5 = void*(void* p0, void* p1, int p2, int p3, int p4);

#define __ assm.
// v0->a2, v1->a3
TEST(LA0) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Addition.
  __ addi_d(a2, a0, 0xC);

  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0xAB0, 0, 0, 0, 0));
  CHECK_EQ(0xABCL, res);
}

TEST(LA1) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  Label L, C;

  __ ori(a1, a0, 0);
  __ ori(a2, zero_reg, 0);
  __ b(&C);

  __ bind(&L);
  __ add_d(a2, a2, a1);
  __ addi_d(a1, a1, -1);

  __ bind(&C);
  __ ori(a3, a1, 0);

  __ Branch(&L, ne, a3, Operand((int64_t)0));

  __ or_(a0, a2, zero_reg);
  __ or_(a1, a3, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F1>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(50, 0, 0, 0, 0));
  CHECK_EQ(1275L, res);
}

TEST(LA2) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  __ ori(a4, zero_reg, 0);  // 00000000
  __ lu12i_w(a4, 0x12345);  // 12345000
  __ ori(a4, a4, 0);        // 12345000
  __ ori(a2, a4, 0xF0F);    // 12345F0F
  __ Branch(&error, ne, a2, Operand(0x12345F0F));

  __ ori(a4, zero_reg, 0);
  __ lu32i_d(a4, 0x12345);  // 1 2345 0000 0000
  __ ori(a4, a4, 0xFFF);    // 1 2345 0000 0FFF
  __ addi_d(a2, a4, 1);
  __ Branch(&error, ne, a2, Operand(0x1234500001000));

  __ ori(a4, zero_reg, 0);
  __ lu52i_d(a4, zero_reg, 0x123);  // 1230 0000 0000 0000
  __ ori(a4, a4, 0xFFF);            // 123F 0000 0000 0FFF
  __ addi_d(a2, a4, 1);             // 1230 0000 0000 1000
  __ Branch(&error, ne, a2, Operand(0x1230000000001000));

  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(LA3) {
  // Test 32bit calculate instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  __ li(a4, 0x00000004);
  __ li(a5, 0x00001234);
  __ li(a6, 0x12345678);
  __ li(a7, 0x7FFFFFFF);
  __ li(t0, static_cast<int32_t>(0xFFFFFFFC));
  __ li(t1, static_cast<int32_t>(0xFFFFEDCC));
  __ li(t2, static_cast<int32_t>(0xEDCBA988));
  __ li(t3, static_cast<int32_t>(0x80000000));

  __ ori(a2, zero_reg, 0);  // 0x00000000
  __ add_w(a2, a4, a5);     // 0x00001238
  __ sub_w(a2, a2, a4);     // 0x00001234
  __ Branch(&error, ne, a2, Operand(0x00001234));
  __ ori(a3, zero_reg, 0);  // 0x00000000
  __ add_w(a3, a7, a4);  // 32bit addu result is sign-extended into 64bit reg.
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFF80000003));

  __ sub_w(a3, t3, a4);  // 0x7FFFFFFC
  __ Branch(&error, ne, a3, Operand(0x7FFFFFFC));

  __ ori(a2, zero_reg, 0);         // 0x00000000
  __ ori(a3, zero_reg, 0);         // 0x00000000
  __ addi_w(a2, zero_reg, 0x421);  // 0x00007421
  __ addi_w(a2, a2, -0x1);         // 0x00007420
  __ addi_w(a2, a2, -0x20);        // 0x00007400
  __ Branch(&error, ne, a2, Operand(0x0000400));
  __ addi_w(a3, a7, 0x1);  // 0x80000000 - result is sign-extended.
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFF80000000));

  __ ori(a2, zero_reg, 0);   // 0x00000000
  __ ori(a3, zero_reg, 0);   // 0x00000000
  __ alsl_w(a2, a6, a4, 3);  // 0xFFFFFFFF91A2B3C4
  __ alsl_w(a2, a2, a4, 2);  // 0x468ACF14
  __ Branch(&error, ne, a2, Operand(0x468acf14));
  __ ori(a0, zero_reg, 31);
  __ alsl_wu(a3, a6, a4, 3);  // 0x91A2B3C4
  __ alsl_wu(a3, a3, a7, 1);  // 0xFFFFFFFFA3456787
  __ Branch(&error, ne, a3, Operand(0xA3456787));

  __ ori(a2, zero_reg, 0);
  __ ori(a3, zero_reg, 0);
  __ mul_w(a2, a5, a7);
  __ div_w(a2, a2, a4);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFFB73));
  __ mul_w(a3, a4, t1);
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFFFFFFB730));
  __ div_w(a3, t3, a4);
  __ Branch(&error, ne, a3, Operand(0xFFFFFFFFE0000000));

  __ ori(a2, zero_reg, 0);
  __ mulh_w(a2, a4, t1);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFFFFF));
  __ mulh_w(a2, a4, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ mulh_wu(a2, a4, t1);
  __ Branch(&error, ne, a2, Operand(0x3));
  __ mulh_wu(a2, a4, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ mulw_d_w(a2, a4, t1);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFB730));
  __ mulw_d_w(a2, a4, a6);
  __ Branch(&error, ne, a2, Operand(0x48D159E0));

  __ ori(a2, zero_reg, 0);
  __ mulw_d_wu(a2, a4, t1);
  __ Branch(&error, ne, a2, Operand(0x3FFFFB730));  //========0xFFFFB730
  __ ori(a2, zero_reg, 81);
  __ mulw_d_wu(a2, a4, a6);
  __ Branch(&error, ne, a2, Operand(0x48D159E0));

  __ ori(a2, zero_reg, 0);
  __ div_wu(a2, a7, a5);
  __ Branch(&error, ne, a2, Operand(0x70821));
  __ div_wu(a2, t0, a5);
  __ Branch(&error, ne, a2, Operand(0xE1042));
  __ div_wu(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x1));

  __ ori(a2, zero_reg, 0);
  __ mod_w(a2, a6, a5);
  __ Branch(&error, ne, a2, Operand(0xDA8));
  __ ori(a2, zero_reg, 0);
  __ mod_w(a2, t2, a5);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFF258));
  __ ori(a2, zero_reg, 0);
  __ mod_w(a2, t2, t1);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFFFFFF258));

  __ ori(a2, zero_reg, 0);
  __ mod_wu(a2, a6, a5);
  __ Branch(&error, ne, a2, Operand(0xDA8));
  __ mod_wu(a2, t2, a5);
  __ Branch(&error, ne, a2, Operand(0xF0));
  __ mod_wu(a2, t2, t1);
  __ Branch(&error, ne, a2, Operand(0xFFFFFFFFEDCBA988));

  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(LA4) {
  // Test 64bit calculate instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  __ li(a4, 0x17312);
  __ li(a5, 0x1012131415161718);
  __ li(a6, 0x51F4B764A26E7412);
  __ li(a7, 0x7FFFFFFFFFFFFFFF);
  __ li(t0, static_cast<int64_t>(0xFFFFFFFFFFFFF547));
  __ li(t1, static_cast<int64_t>(0xDF6B8F35A10E205C));
  __ li(t2, static_cast<int64_t>(0x81F25A87C4236841));
  __ li(t3, static_cast<int64_t>(0x8000000000000000));

  __ ori(a2, zero_reg, 0);
  __ add_d(a2, a4, a5);
  __ sub_d(a2, a2, a4);
  __ Branch(&error, ne, a2, Operand(0x1012131415161718));
  __ ori(a3, zero_reg, 0);
  __ add_d(a3, a6, a7);  //溢出
  __ Branch(&error, ne, a3, Operand(0xd1f4b764a26e7411));
  __ sub_d(a3, t3, a4);  //溢出
  __ Branch(&error, ne, a3, Operand(0x7ffffffffffe8cee));

  __ ori(a2, zero_reg, 0);
  __ addi_d(a2, a5, 0x412);  //正值
  __ Branch(&error, ne, a2, Operand(0x1012131415161b2a));
  __ addi_d(a2, a7, 0x547);  //负值
  __ Branch(&error, ne, a2, Operand(0x8000000000000546));

  __ ori(t4, zero_reg, 0);
  __ addu16i_d(a2, t4, 0x1234);
  __ Branch(&error, ne, a2, Operand(0x12340000));
  __ addu16i_d(a2, a2, 0x9876);
  __ Branch(&error, ne, a2, Operand(0xffffffffaaaa0000));

  __ ori(a2, zero_reg, 0);
  __ alsl_d(a2, t2, t0, 3);
  __ Branch(&error, ne, a2, Operand(0xf92d43e211b374f));

  __ ori(a2, zero_reg, 0);
  __ mul_d(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0xdbe6a8729a547fb0));
  __ mul_d(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x57ad69f40f870584));
  __ mul_d(a2, a4, t0);
  __ Branch(&error, ne, a2, Operand(0xfffffffff07523fe));

  __ ori(a2, zero_reg, 0);
  __ mulh_d(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x52514c6c6b54467));
  __ mulh_d(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x15d));

  __ ori(a2, zero_reg, 0);
  __ mulh_du(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x52514c6c6b54467));
  __ mulh_du(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xdf6b8f35a10e1700));
  __ mulh_du(a2, a4, t0);
  __ Branch(&error, ne, a2, Operand(0x17311));

  __ ori(a2, zero_reg, 0);
  __ div_d(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ div_d(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ div_d(a2, t1, a4);
  __ Branch(&error, ne, a2, Operand(0xffffe985f631e6d9));

  __ ori(a2, zero_reg, 0);
  __ div_du(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ div_du(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ div_du(a2, t1, a4);
  __ Branch(&error, ne, a2, Operand(0x9a22ffd3973d));

  __ ori(a2, zero_reg, 0);
  __ mod_d(a2, a6, a4);
  __ Branch(&error, ne, a2, Operand(0x13558));
  __ mod_d(a2, t2, t0);
  __ Branch(&error, ne, a2, Operand(0xfffffffffffffb0a));
  __ mod_d(a2, t1, a4);
  __ Branch(&error, ne, a2, Operand(0xffffffffffff6a1a));

  __ ori(a2, zero_reg, 0);
  __ mod_du(a2, a6, a4);
  __ Branch(&error, ne, a2, Operand(0x13558));
  __ mod_du(a2, t2, t0);
  __ Branch(&error, ne, a2, Operand(0x81f25a87c4236841));
  __ mod_du(a2, t1, a4);
  __ Branch(&error, ne, a2, Operand(0x1712));

  // Everything was correctly executed. Load the expected result.
  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  __ li(a2, 0x666);
  // Got an error. Return a wrong result.

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(LA5) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label exit, error;

  __ li(a4, 0x17312);
  __ li(a5, 0x1012131415161718);
  __ li(a6, 0x51F4B764A26E7412);
  __ li(a7, 0x7FFFFFFFFFFFFFFF);
  __ li(t0, static_cast<int64_t>(0xFFFFFFFFFFFFF547));
  __ li(t1, static_cast<int64_t>(0xDF6B8F35A10E205C));
  __ li(t2, static_cast<int64_t>(0x81F25A87C4236841));
  __ li(t3, static_cast<int64_t>(0x8000000000000000));

  __ ori(a2, zero_reg, 0);
  __ slt(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ slt(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ slt(a2, t1, t1);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ sltu(a2, a5, a6);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ sltu(a2, a7, t0);
  __ Branch(&error, ne, a2, Operand(0x1));
  __ sltu(a2, t1, t1);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ slti(a2, a5, 0x123);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ slti(a2, t0, 0x123);
  __ Branch(&error, ne, a2, Operand(0x1));

  __ ori(a2, zero_reg, 0);
  __ sltui(a2, a5, 0x123);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));
  __ sltui(a2, t0, 0x123);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ and_(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0x1310));
  __ and_(a2, a6, a7);
  __ Branch(&error, ne, a2, Operand(0x51F4B764A26E7412));

  __ ori(a2, zero_reg, 0);
  __ or_(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xfffffffffffff55f));
  __ or_(a2, t2, t3);
  __ Branch(&error, ne, a2, Operand(0x81f25a87c4236841));

  __ ori(a2, zero_reg, 0);
  __ nor(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0xefedecebeae888e5));
  __ nor(a2, a6, a7);
  __ Branch(&error, ne, a2, Operand(0x8000000000000000));

  __ ori(a2, zero_reg, 0);
  __ xor_(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0x209470ca5ef1d51b));
  __ xor_(a2, t2, t3);
  __ Branch(&error, ne, a2, Operand(0x1f25a87c4236841));

  __ ori(a2, zero_reg, 0);
  __ andn(a2, a4, a5);
  __ Branch(&error, ne, a2, Operand(0x16002));
  __ andn(a2, a6, a7);
  __ Branch(&error, ne, a2, Operand(static_cast<int64_t>(0)));

  __ ori(a2, zero_reg, 0);
  __ orn(a2, t0, t1);
  __ Branch(&error, ne, a2, Operand(0xffffffffffffffe7));
  __ orn(a2, t2, t3);
  __ Branch(&error, ne, a2, Operand(0xffffffffffffffff));

  __ ori(a2, zero_reg, 0);
  __ andi(a2, a4, 0x123);
  __ Branch(&error, ne, a2, Operand(0x102));
  __ andi(a2, a6, 0xDCB);
  __ Branch(&error, ne, a2, Operand(0x402));

  __ ori(a2, zero_reg, 0);
  __ xori(a2, t0, 0x123);
  __ Branch(&error, ne, a2, Operand(0xfffffffffffff464));
  __ xori(a2, t2, 0xDCB);
  __ Branch(&error, ne, a2, Operand(0x81f25a87c423658a));

  // Everything was correctly executed. Load the expected result.
  __ li(a2, 0x31415926);
  __ b(&exit);

  __ bind(&error);
  // Got an error. Return a wrong result.
  __ li(a2, 0x666);

  __ bind(&exit);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(0, 0, 0, 0, 0));

  CHECK_EQ(0x31415926L, res);
}

TEST(LA6) {
  // Test loads and stores instruction.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct T {
    int64_t si1;
    int64_t si2;
    int64_t si3;
    int64_t result_ld_b_si1;
    int64_t result_ld_b_si2;
    int64_t result_ld_h_si1;
    int64_t result_ld_h_si2;
    int64_t result_ld_w_si1;
    int64_t result_ld_w_si2;
    int64_t result_ld_d_si1;
    int64_t result_ld_d_si3;
    int64_t result_ld_bu_si2;
    int64_t result_ld_hu_si2;
    int64_t result_ld_wu_si2;
    int64_t result_st_b;
    int64_t result_st_h;
    int64_t result_st_w;
  };
  T t;

  // Ld_b
  __ Ld_b(a4, MemOperand(a0, offsetof(T, si1)));
  __ St_d(a4, MemOperand(a0, offsetof(T, result_ld_b_si1)));

  __ Ld_b(a4, MemOperand(a0, offsetof(T, si2)));
  __ St_d(a4, MemOperand(a0, offsetof(T, result_ld_b_si2)));

  // Ld_h
  __ Ld_h(a5, MemOperand(a0, offsetof(T, si1)));
  __ St_d(a5, MemOperand(a0, offsetof(T, result_ld_h_si1)));

  __ Ld_h(a5, MemOperand(a0, offsetof(T, si2)));
  __ St_d(a5, MemOperand(a0, offsetof(T, result_ld_h_si2)));

  // Ld_w
  __ Ld_w(a6, MemOperand(a0, offsetof(T, si1)));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_ld_w_si1)));

  __ Ld_w(a6, MemOperand(a0, offsetof(T, si2)));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_ld_w_si2)));

  // Ld_d
  __ Ld_d(a7, MemOperand(a0, offsetof(T, si1)));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_ld_d_si1)));

  __ Ld_d(a7, MemOperand(a0, offsetof(T, si3)));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_ld_d_si3)));

  // Ld_bu
  __ Ld_bu(t0, MemOperand(a0, offsetof(T, si2)));
  __ St_d(t0, MemOperand(a0, offsetof(T, result_ld_bu_si2)));

  // Ld_hu
  __ Ld_hu(t1, MemOperand(a0, offsetof(T, si2)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_ld_hu_si2)));

  // Ld_wu
  __ Ld_wu(t2, MemOperand(a0, offsetof(T, si2)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_ld_wu_si2)));

  // St
  __ li(t4, 0x11111111);

  // St_b
  __ Ld_d(t5, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t5, MemOperand(a0, offsetof(T, result_st_b)));
  __ St_b(t4, MemOperand(a0, offsetof(T, result_st_b)));

  // St_h
  __ Ld_d(t6, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t6, MemOperand(a0, offsetof(T, result_st_h)));
  __ St_h(t4, MemOperand(a0, offsetof(T, result_st_h)));

  // St_w
  __ Ld_d(t7, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t7, MemOperand(a0, offsetof(T, result_st_w)));
  __ St_w(t4, MemOperand(a0, offsetof(T, result_st_w)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.si1 = 0x11223344;
  t.si2 = 0x99AABBCC;
  t.si3 = 0x1122334455667788;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x44), t.result_ld_b_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFFFFFFFCC), t.result_ld_b_si2);

  CHECK_EQ(static_cast<int64_t>(0x3344), t.result_ld_h_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFFFFFBBCC), t.result_ld_h_si2);

  CHECK_EQ(static_cast<int64_t>(0x11223344), t.result_ld_w_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCC), t.result_ld_w_si2);

  CHECK_EQ(static_cast<int64_t>(0x11223344), t.result_ld_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x1122334455667788), t.result_ld_d_si3);

  CHECK_EQ(static_cast<int64_t>(0xCC), t.result_ld_bu_si2);
  CHECK_EQ(static_cast<int64_t>(0xBBCC), t.result_ld_hu_si2);
  CHECK_EQ(static_cast<int64_t>(0x99AABBCC), t.result_ld_wu_si2);

  CHECK_EQ(static_cast<int64_t>(0x1122334455667711), t.result_st_b);
  CHECK_EQ(static_cast<int64_t>(0x1122334455661111), t.result_st_h);
  CHECK_EQ(static_cast<int64_t>(0x1122334411111111), t.result_st_w);
}

TEST(LA7) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct T {
    int64_t si1;
    int64_t si2;
    int64_t si3;
    int64_t result_ldx_b_si1;
    int64_t result_ldx_b_si2;
    int64_t result_ldx_h_si1;
    int64_t result_ldx_h_si2;
    int64_t result_ldx_w_si1;
    int64_t result_ldx_w_si2;
    int64_t result_ldx_d_si1;
    int64_t result_ldx_d_si3;
    int64_t result_ldx_bu_si2;
    int64_t result_ldx_hu_si2;
    int64_t result_ldx_wu_si2;
    int64_t result_stx_b;
    int64_t result_stx_h;
    int64_t result_stx_w;
  };
  T t;

  // ldx_b
  __ li(a2, static_cast<int64_t>(offsetof(T, si1)));
  __ Ld_b(a4, MemOperand(a0, a2));
  __ St_d(a4, MemOperand(a0, offsetof(T, result_ldx_b_si1)));

  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_b(a4, MemOperand(a0, a2));
  __ St_d(a4, MemOperand(a0, offsetof(T, result_ldx_b_si2)));

  // ldx_h
  __ li(a2, static_cast<int64_t>(offsetof(T, si1)));
  __ Ld_h(a5, MemOperand(a0, a2));
  __ St_d(a5, MemOperand(a0, offsetof(T, result_ldx_h_si1)));

  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_h(a5, MemOperand(a0, a2));
  __ St_d(a5, MemOperand(a0, offsetof(T, result_ldx_h_si2)));

  // ldx_w
  __ li(a2, static_cast<int64_t>(offsetof(T, si1)));
  __ Ld_w(a6, MemOperand(a0, a2));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_ldx_w_si1)));

  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_w(a6, MemOperand(a0, a2));
  __ St_d(a6, MemOperand(a0, offsetof(T, result_ldx_w_si2)));

  // Ld_d
  __ li(a2, static_cast<int64_t>(offsetof(T, si1)));
  __ Ld_d(a7, MemOperand(a0, a2));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_ldx_d_si1)));

  __ li(a2, static_cast<int64_t>(offsetof(T, si3)));
  __ Ld_d(a7, MemOperand(a0, a2));
  __ St_d(a7, MemOperand(a0, offsetof(T, result_ldx_d_si3)));

  // Ld_bu
  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_bu(t0, MemOperand(a0, a2));
  __ St_d(t0, MemOperand(a0, offsetof(T, result_ldx_bu_si2)));

  // Ld_hu
  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_hu(t1, MemOperand(a0, a2));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_ldx_hu_si2)));

  // Ld_wu
  __ li(a2, static_cast<int64_t>(offsetof(T, si2)));
  __ Ld_wu(t2, MemOperand(a0, a2));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_ldx_wu_si2)));

  // St
  __ li(t4, 0x11111111);

  // St_b
  __ Ld_d(t5, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t5, MemOperand(a0, offsetof(T, result_stx_b)));
  __ li(a2, static_cast<int64_t>(offsetof(T, result_stx_b)));
  __ St_b(t4, MemOperand(a0, a2));

  // St_h
  __ Ld_d(t6, MemOperand(a0, offsetof(T, si3)));
  __ St_d(t6, MemOperand(a0, offsetof(T, result_stx_h)));
  __ li(a2, static_cast<int64_t>(offsetof(T, result_stx_h)));
  __ St_h(t4, MemOperand(a0, a2));

  // St_w
  __ Ld_d(t7, MemOperand(a0, offsetof(T, si3)));
  __ li(a2, static_cast<int64_t>(offsetof(T, result_stx_w)));
  __ St_d(t7, MemOperand(a0, a2));
  __ li(a3, static_cast<int64_t>(offsetof(T, result_stx_w)));
  __ St_w(t4, MemOperand(a0, a3));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.si1 = 0x11223344;
  t.si2 = 0x99AABBCC;
  t.si3 = 0x1122334455667788;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x44), t.result_ldx_b_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFFFFFFFCC), t.result_ldx_b_si2);

  CHECK_EQ(static_cast<int64_t>(0x3344), t.result_ldx_h_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFFFFFFBBCC), t.result_ldx_h_si2);

  CHECK_EQ(static_cast<int64_t>(0x11223344), t.result_ldx_w_si1);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCC), t.result_ldx_w_si2);

  CHECK_EQ(static_cast<int64_t>(0x11223344), t.result_ldx_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x1122334455667788), t.result_ldx_d_si3);

  CHECK_EQ(static_cast<int64_t>(0xCC), t.result_ldx_bu_si2);
  CHECK_EQ(static_cast<int64_t>(0xBBCC), t.result_ldx_hu_si2);
  CHECK_EQ(static_cast<int64_t>(0x99AABBCC), t.result_ldx_wu_si2);

  CHECK_EQ(static_cast<int64_t>(0x1122334455667711), t.result_stx_b);
  CHECK_EQ(static_cast<int64_t>(0x1122334455661111), t.result_stx_h);
  CHECK_EQ(static_cast<int64_t>(0x1122334411111111), t.result_stx_w);
}

TEST(LDPTR_STPTR) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  int64_t test[10];

  __ ldptr_w(a4, a0, 0);
  __ stptr_d(a4, a0, 24);  // test[3]

  __ ldptr_w(a5, a0, 8);   // test[1]
  __ stptr_d(a5, a0, 32);  // test[4]

  __ ldptr_d(a6, a0, 16);  // test[2]
  __ stptr_d(a6, a0, 40);  // test[5]

  __ li(t0, 0x11111111);

  __ stptr_d(a6, a0, 48);  // test[6]
  __ stptr_w(t0, a0, 48);  // test[6]

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  test[0] = 0x11223344;
  test[1] = 0x99AABBCC;
  test[2] = 0x1122334455667788;
  f.Call(&test, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x11223344), test[3]);
  CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCC), test[4]);
  CHECK_EQ(static_cast<int64_t>(0x1122334455667788), test[5]);
  CHECK_EQ(static_cast<int64_t>(0x1122334411111111), test[6]);
}

TEST(LA8) {
  // Test 32bit shift instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int32_t input;
    int32_t result_sll_w_0;
    int32_t result_sll_w_8;
    int32_t result_sll_w_10;
    int32_t result_sll_w_31;
    int32_t result_srl_w_0;
    int32_t result_srl_w_8;
    int32_t result_srl_w_10;
    int32_t result_srl_w_31;
    int32_t result_sra_w_0;
    int32_t result_sra_w_8;
    int32_t result_sra_w_10;
    int32_t result_sra_w_31;
    int32_t result_rotr_w_0;
    int32_t result_rotr_w_8;
    int32_t result_slli_w_0;
    int32_t result_slli_w_8;
    int32_t result_slli_w_10;
    int32_t result_slli_w_31;
    int32_t result_srli_w_0;
    int32_t result_srli_w_8;
    int32_t result_srli_w_10;
    int32_t result_srli_w_31;
    int32_t result_srai_w_0;
    int32_t result_srai_w_8;
    int32_t result_srai_w_10;
    int32_t result_srai_w_31;
    int32_t result_rotri_w_0;
    int32_t result_rotri_w_8;
    int32_t result_rotri_w_10;
    int32_t result_rotri_w_31;
  };
  T t;
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Ld_w(a4, MemOperand(a0, offsetof(T, input)));

  // sll_w
  __ li(a5, 0);
  __ sll_w(t0, a4, a5);
  __ li(a5, 0x8);
  __ sll_w(t1, a4, a5);
  __ li(a5, 0xA);
  __ sll_w(t2, a4, a5);
  __ li(a5, 0x1F);
  __ sll_w(t3, a4, a5);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_sll_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_sll_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_sll_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_sll_w_31)));

  // srl_w
  __ li(a5, 0x0);
  __ srl_w(t0, a4, a5);
  __ li(a5, 0x8);
  __ srl_w(t1, a4, a5);
  __ li(a5, 0xA);
  __ srl_w(t2, a4, a5);
  __ li(a5, 0x1F);
  __ srl_w(t3, a4, a5);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_srl_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_srl_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_srl_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_srl_w_31)));

  // sra_w
  __ li(a5, 0x0);
  __ sra_w(t0, a4, a5);
  __ li(a5, 0x8);
  __ sra_w(t1, a4, a5);

  __ li(a6, static_cast<int32_t>(0x80000000));
  __ add_w(a6, a6, a4);
  __ li(a5, 0xA);
  __ sra_w(t2, a6, a5);
  __ li(a5, 0x1F);
  __ sra_w(t3, a6, a5);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_sra_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_sra_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_sra_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_sra_w_31)));

  // rotr
  __ li(a5, 0x0);
  __ rotr_w(t0, a4, a5);
  __ li(a6, 0x8);
  __ rotr_w(t1, a4, a6);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_rotr_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_rotr_w_8)));

  // slli_w
  __ slli_w(t0, a4, 0);
  __ slli_w(t1, a4, 0x8);
  __ slli_w(t2, a4, 0xA);
  __ slli_w(t3, a4, 0x1F);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_slli_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_slli_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_slli_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_slli_w_31)));

  // srli_w
  __ srli_w(t0, a4, 0);
  __ srli_w(t1, a4, 0x8);
  __ srli_w(t2, a4, 0xA);
  __ srli_w(t3, a4, 0x1F);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_srli_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_srli_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_srli_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_srli_w_31)));

  // srai_w
  __ srai_w(t0, a4, 0);
  __ srai_w(t1, a4, 0x8);

  __ li(a6, static_cast<int32_t>(0x80000000));
  __ add_w(a6, a6, a4);
  __ srai_w(t2, a6, 0xA);
  __ srai_w(t3, a6, 0x1F);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_srai_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_srai_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_srai_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_srai_w_31)));

  // rotri_w
  __ rotri_w(t0, a4, 0);
  __ rotri_w(t1, a4, 0x8);
  __ rotri_w(t2, a4, 0xA);
  __ rotri_w(t3, a4, 0x1F);

  __ St_w(t0, MemOperand(a0, offsetof(T, result_rotri_w_0)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_rotri_w_8)));
  __ St_w(t2, MemOperand(a0, offsetof(T, result_rotri_w_10)));
  __ St_w(t3, MemOperand(a0, offsetof(T, result_rotri_w_31)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.input = 0x12345678;
  f.Call(&t, 0x0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_sll_w_0);
  CHECK_EQ(static_cast<int32_t>(0x34567800), t.result_sll_w_8);
  CHECK_EQ(static_cast<int32_t>(0xD159E000), t.result_sll_w_10);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_sll_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_srl_w_0);
  CHECK_EQ(static_cast<int32_t>(0x123456), t.result_srl_w_8);
  CHECK_EQ(static_cast<int32_t>(0x48D15), t.result_srl_w_10);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_srl_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_sra_w_0);
  CHECK_EQ(static_cast<int32_t>(0x123456), t.result_sra_w_8);
  CHECK_EQ(static_cast<int32_t>(0xFFE48D15), t.result_sra_w_10);
  CHECK_EQ(static_cast<int32_t>(0xFFFFFFFF), t.result_sra_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_rotr_w_0);
  CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotr_w_8);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_slli_w_0);
  CHECK_EQ(static_cast<int32_t>(0x34567800), t.result_slli_w_8);
  CHECK_EQ(static_cast<int32_t>(0xD159E000), t.result_slli_w_10);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_slli_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_srli_w_0);
  CHECK_EQ(static_cast<int32_t>(0x123456), t.result_srli_w_8);
  CHECK_EQ(static_cast<int32_t>(0x48D15), t.result_srli_w_10);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_srli_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_srai_w_0);
  CHECK_EQ(static_cast<int32_t>(0x123456), t.result_srai_w_8);
  CHECK_EQ(static_cast<int32_t>(0xFFE48D15), t.result_srai_w_10);
  CHECK_EQ(static_cast<int32_t>(0xFFFFFFFF), t.result_srai_w_31);

  CHECK_EQ(static_cast<int32_t>(0x12345678), t.result_rotri_w_0);
  CHECK_EQ(static_cast<int32_t>(0x78123456), t.result_rotri_w_8);
  CHECK_EQ(static_cast<int32_t>(0x9E048D15), t.result_rotri_w_10);
  CHECK_EQ(static_cast<int32_t>(0x2468ACF0), t.result_rotri_w_31);
}

TEST(LA9) {
  // Test 64bit shift instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int64_t input;
    int64_t result_sll_d_0;
    int64_t result_sll_d_13;
    int64_t result_sll_d_30;
    int64_t result_sll_d_63;
    int64_t result_srl_d_0;
    int64_t result_srl_d_13;
    int64_t result_srl_d_30;
    int64_t result_srl_d_63;
    int64_t result_sra_d_0;
    int64_t result_sra_d_13;
    int64_t result_sra_d_30;
    int64_t result_sra_d_63;
    int64_t result_rotr_d_0;
    int64_t result_rotr_d_13;
    int64_t result_slli_d_0;
    int64_t result_slli_d_13;
    int64_t result_slli_d_30;
    int64_t result_slli_d_63;
    int64_t result_srli_d_0;
    int64_t result_srli_d_13;
    int64_t result_srli_d_30;
    int64_t result_srli_d_63;
    int64_t result_srai_d_0;
    int64_t result_srai_d_13;
    int64_t result_srai_d_30;
    int64_t result_srai_d_63;
    int64_t result_rotri_d_0;
    int64_t result_rotri_d_13;
    int64_t result_rotri_d_30;
    int64_t result_rotri_d_63;
  };

  T t;
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Ld_d(a4, MemOperand(a0, offsetof(T, input)));

  // sll_d
  __ li(a5, 0);
  __ sll_d(t0, a4, a5);
  __ li(a5, 0xD);
  __ sll_d(t1, a4, a5);
  __ li(a5, 0x1E);
  __ sll_d(t2, a4, a5);
  __ li(a5, 0x3F);
  __ sll_d(t3, a4, a5);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_sll_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_sll_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_sll_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_sll_d_63)));

  // srl_d
  __ li(a5, 0x0);
  __ srl_d(t0, a4, a5);
  __ li(a5, 0xD);
  __ srl_d(t1, a4, a5);
  __ li(a5, 0x1E);
  __ srl_d(t2, a4, a5);
  __ li(a5, 0x3F);
  __ srl_d(t3, a4, a5);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_srl_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_srl_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_srl_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_srl_d_63)));

  // sra_d
  __ li(a5, 0x0);
  __ sra_d(t0, a4, a5);
  __ li(a5, 0xD);
  __ sra_d(t1, a4, a5);

  __ li(a6, static_cast<int64_t>(0x8000000000000000));
  __ add_d(a6, a6, a4);
  __ li(a5, 0x1E);
  __ sra_d(t2, a6, a5);
  __ li(a5, 0x3F);
  __ sra_d(t3, a6, a5);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_sra_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_sra_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_sra_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_sra_d_63)));

  // rotr
  __ li(a5, 0x0);
  __ rotr_d(t0, a4, a5);
  __ li(a6, 0xD);
  __ rotr_d(t1, a4, a6);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_rotr_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_rotr_d_13)));

  // slli_d
  __ slli_d(t0, a4, 0);
  __ slli_d(t1, a4, 0xD);
  __ slli_d(t2, a4, 0x1E);
  __ slli_d(t3, a4, 0x3F);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_slli_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_slli_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_slli_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_slli_d_63)));

  // srli_d
  __ srli_d(t0, a4, 0);
  __ srli_d(t1, a4, 0xD);
  __ srli_d(t2, a4, 0x1E);
  __ srli_d(t3, a4, 0x3F);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_srli_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_srli_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_srli_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_srli_d_63)));

  // srai_d
  __ srai_d(t0, a4, 0);
  __ srai_d(t1, a4, 0xD);

  __ li(a6, static_cast<int64_t>(0x8000000000000000));
  __ add_d(a6, a6, a4);
  __ srai_d(t2, a6, 0x1E);
  __ srai_d(t3, a6, 0x3F);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_srai_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_srai_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_srai_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_srai_d_63)));

  // rotri_d
  __ rotri_d(t0, a4, 0);
  __ rotri_d(t1, a4, 0xD);
  __ rotri_d(t2, a4, 0x1E);
  __ rotri_d(t3, a4, 0x3F);

  __ St_d(t0, MemOperand(a0, offsetof(T, result_rotri_d_0)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_rotri_d_13)));
  __ St_d(t2, MemOperand(a0, offsetof(T, result_rotri_d_30)));
  __ St_d(t3, MemOperand(a0, offsetof(T, result_rotri_d_63)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.input = 0x51F4B764A26E7412;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_sll_d_0);
  CHECK_EQ(static_cast<int64_t>(0x96ec944dce824000), t.result_sll_d_13);
  CHECK_EQ(static_cast<int64_t>(0x289b9d0480000000), t.result_sll_d_30);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_sll_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_srl_d_0);
  CHECK_EQ(static_cast<int64_t>(0x28fa5bb251373), t.result_srl_d_13);
  CHECK_EQ(static_cast<int64_t>(0x147d2dd92), t.result_srl_d_30);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_srl_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_sra_d_0);
  CHECK_EQ(static_cast<int64_t>(0x28fa5bb251373), t.result_sra_d_13);
  CHECK_EQ(static_cast<int64_t>(0xffffffff47d2dd92), t.result_sra_d_30);
  CHECK_EQ(static_cast<int64_t>(0xffffffffffffffff), t.result_sra_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_rotr_d_0);
  CHECK_EQ(static_cast<int64_t>(0xa0928fa5bb251373), t.result_rotr_d_13);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_slli_d_0);
  CHECK_EQ(static_cast<int64_t>(0x96ec944dce824000), t.result_slli_d_13);
  CHECK_EQ(static_cast<int64_t>(0x289b9d0480000000), t.result_slli_d_30);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_slli_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_srli_d_0);
  CHECK_EQ(static_cast<int64_t>(0x28fa5bb251373), t.result_srli_d_13);
  CHECK_EQ(static_cast<int64_t>(0x147d2dd92), t.result_srli_d_30);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_srli_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_srai_d_0);
  CHECK_EQ(static_cast<int64_t>(0x28fa5bb251373), t.result_srai_d_13);
  CHECK_EQ(static_cast<int64_t>(0xffffffff47d2dd92), t.result_srai_d_30);
  CHECK_EQ(static_cast<int64_t>(0xffffffffffffffff), t.result_srai_d_63);

  CHECK_EQ(static_cast<int64_t>(0x51f4b764a26e7412), t.result_rotri_d_0);
  CHECK_EQ(static_cast<int64_t>(0xa0928fa5bb251373), t.result_rotri_d_13);
  CHECK_EQ(static_cast<int64_t>(0x89b9d04947d2dd92), t.result_rotri_d_30);
  CHECK_EQ(static_cast<int64_t>(0xa3e96ec944dce824), t.result_rotri_d_63);
}

TEST(LA10) {
  // Test 32bit bit operation instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct T {
    int64_t si1;
    int64_t si2;
    int32_t result_ext_w_b_si1;
    int32_t result_ext_w_b_si2;
    int32_t result_ext_w_h_si1;
    int32_t result_ext_w_h_si2;
    int32_t result_clo_w_si1;
    int32_t result_clo_w_si2;
    int32_t result_clz_w_si1;
    int32_t result_clz_w_si2;
    int32_t result_cto_w_si1;
    int32_t result_cto_w_si2;
    int32_t result_ctz_w_si1;
    int32_t result_ctz_w_si2;
    int32_t result_bytepick_w_si1;
    int32_t result_bytepick_w_si2;
    int32_t result_revb_2h_si1;
    int32_t result_revb_2h_si2;
    int32_t result_bitrev_4b_si1;
    int32_t result_bitrev_4b_si2;
    int32_t result_bitrev_w_si1;
    int32_t result_bitrev_w_si2;
    int32_t result_bstrins_w_si1;
    int32_t result_bstrins_w_si2;
    int32_t result_bstrpick_w_si1;
    int32_t result_bstrpick_w_si2;
  };
  T t;

  __ Ld_d(a4, MemOperand(a0, offsetof(T, si1)));
  __ Ld_d(a5, MemOperand(a0, offsetof(T, si2)));

  // ext_w_b
  __ ext_w_b(t0, a4);
  __ ext_w_b(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_ext_w_b_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_ext_w_b_si2)));

  // ext_w_h
  __ ext_w_h(t0, a4);
  __ ext_w_h(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_ext_w_h_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_ext_w_h_si2)));

  /*    //clo_w
    __ clo_w(t0, a4);
    __ clo_w(t1, a5);
    __ St_w(t0, MemOperand(a0, offsetof(T, result_clo_w_si1)));
    __ St_w(t1, MemOperand(a0, offsetof(T, result_clo_w_si2)));*/

  // clz_w
  __ clz_w(t0, a4);
  __ clz_w(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_clz_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_clz_w_si2)));

  /*    //cto_w
    __ cto_w(t0, a4);
    __ cto_w(t1, a5);
    __ St_w(t0, MemOperand(a0, offsetof(T, result_cto_w_si1)));
    __ St_w(t1, MemOperand(a0, offsetof(T, result_cto_w_si2)));*/

  // ctz_w
  __ ctz_w(t0, a4);
  __ ctz_w(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_ctz_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_ctz_w_si2)));

  // bytepick_w
  __ bytepick_w(t0, a4, a5, 0);
  __ bytepick_w(t1, a5, a4, 2);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bytepick_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bytepick_w_si2)));

  // revb_2h
  __ revb_2h(t0, a4);
  __ revb_2h(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_revb_2h_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_revb_2h_si2)));

  // bitrev
  __ bitrev_4b(t0, a4);
  __ bitrev_4b(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bitrev_4b_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bitrev_4b_si2)));

  // bitrev_w
  __ bitrev_w(t0, a4);
  __ bitrev_w(t1, a5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bitrev_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bitrev_w_si2)));

  // bstrins
  __ or_(t0, zero_reg, zero_reg);
  __ or_(t1, zero_reg, zero_reg);
  __ bstrins_w(t0, a4, 0xD, 0x4);
  __ bstrins_w(t1, a5, 0x16, 0x5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bstrins_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bstrins_w_si2)));

  // bstrpick
  __ or_(t0, zero_reg, zero_reg);
  __ or_(t1, zero_reg, zero_reg);
  __ bstrpick_w(t0, a4, 0xD, 0x4);
  __ bstrpick_w(t1, a5, 0x16, 0x5);
  __ St_w(t0, MemOperand(a0, offsetof(T, result_bstrpick_w_si1)));
  __ St_w(t1, MemOperand(a0, offsetof(T, result_bstrpick_w_si2)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.si1 = 0x51F4B764A26E7412;
  t.si2 = 0x81F25A87C423B891;
  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(static_cast<int32_t>(0x12), t.result_ext_w_b_si1);
  CHECK_EQ(static_cast<int32_t>(0xffffff91), t.result_ext_w_b_si2);
  CHECK_EQ(static_cast<int32_t>(0x7412), t.result_ext_w_h_si1);
  CHECK_EQ(static_cast<int32_t>(0xffffb891), t.result_ext_w_h_si2);
  //    CHECK_EQ(static_cast<int32_t>(0x1), t.result_clo_w_si1);
  //    CHECK_EQ(static_cast<int32_t>(0x2), t.result_clo_w_si2);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_clz_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_clz_w_si2);
  //    CHECK_EQ(static_cast<int32_t>(0x0), t.result_cto_w_si1);
  //    CHECK_EQ(static_cast<int32_t>(0x1), t.result_cto_w_si2);
  CHECK_EQ(static_cast<int32_t>(0x1), t.result_ctz_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x0), t.result_ctz_w_si2);
  CHECK_EQ(static_cast<int32_t>(0xc423b891), t.result_bytepick_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x7412c423),
           t.result_bytepick_w_si2);  // 0xffffc423
  CHECK_EQ(static_cast<int32_t>(0x6ea21274), t.result_revb_2h_si1);
  CHECK_EQ(static_cast<int32_t>(0x23c491b8), t.result_revb_2h_si2);
  CHECK_EQ(static_cast<int32_t>(0x45762e48), t.result_bitrev_4b_si1);
  CHECK_EQ(static_cast<int32_t>(0x23c41d89), t.result_bitrev_4b_si2);
  CHECK_EQ(static_cast<int32_t>(0x482e7645), t.result_bitrev_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x891dc423), t.result_bitrev_w_si2);
  CHECK_EQ(static_cast<int32_t>(0x120), t.result_bstrins_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x771220), t.result_bstrins_w_si2);
  CHECK_EQ(static_cast<int32_t>(0x341), t.result_bstrpick_w_si1);
  CHECK_EQ(static_cast<int32_t>(0x11dc4), t.result_bstrpick_w_si2);
}

TEST(LA11) {
  // Test 64bit bit operation instructions.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  struct T {
    int64_t si1;
    int64_t si2;
    int64_t result_clo_d_si1;
    int64_t result_clo_d_si2;
    int64_t result_clz_d_si1;
    int64_t result_clz_d_si2;
    int64_t result_cto_d_si1;
    int64_t result_cto_d_si2;
    int64_t result_ctz_d_si1;
    int64_t result_ctz_d_si2;
    int64_t result_bytepick_d_si1;
    int64_t result_bytepick_d_si2;
    int64_t result_revb_4h_si1;
    int64_t result_revb_4h_si2;
    int64_t result_revb_2w_si1;
    int64_t result_revb_2w_si2;
    int64_t result_revb_d_si1;
    int64_t result_revb_d_si2;
    int64_t result_revh_2w_si1;
    int64_t result_revh_2w_si2;
    int64_t result_revh_d_si1;
    int64_t result_revh_d_si2;
    int64_t result_bitrev_8b_si1;
    int64_t result_bitrev_8b_si2;
    int64_t result_bitrev_d_si1;
    int64_t result_bitrev_d_si2;
    int64_t result_bstrins_d_si1;
    int64_t result_bstrins_d_si2;
    int64_t result_bstrpick_d_si1;
    int64_t result_bstrpick_d_si2;
    int64_t result_maskeqz_si1;
    int64_t result_maskeqz_si2;
    int64_t result_masknez_si1;
    int64_t result_masknez_si2;
  };

  T t;

  __ Ld_d(a4, MemOperand(a0, offsetof(T, si1)));
  __ Ld_d(a5, MemOperand(a0, offsetof(T, si2)));

  /*    //clo_d
    __ clo_d(t0, a4);
    __ clo_d(t1, a5);
    __ St_w(t0, MemOperand(a0, offsetof(T, result_clo_d_si1)));
    __ St_w(t1, MemOperand(a0, offsetof(T, result_clo_d_si2)));*/

  // clz_d
  __ or_(t0, zero_reg, zero_reg);
  __ clz_d(t0, a4);
  __ clz_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_clz_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_clz_d_si2)));

  /*    //cto_d
    __ cto_d(t0, a4);
    __ cto_d(t1, a5);
    __ St_w(t0, MemOperand(a0, offsetof(T, result_cto_d_si1)));
    __ St_w(t1, MemOperand(a0, offsetof(T, result_cto_d_si2)));*/

  // ctz_d
  __ ctz_d(t0, a4);
  __ ctz_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_ctz_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_ctz_d_si2)));

  // bytepick_d
  __ bytepick_d(t0, a4, a5, 0);
  __ bytepick_d(t1, a5, a4, 5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bytepick_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bytepick_d_si2)));

  // revb_4h
  __ revb_4h(t0, a4);
  __ revb_4h(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revb_4h_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revb_4h_si2)));

  // revb_2w
  __ revb_2w(t0, a4);
  __ revb_2w(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revb_2w_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revb_2w_si2)));

  // revb_d
  __ revb_d(t0, a4);
  __ revb_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revb_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revb_d_si2)));

  // revh_2w
  __ revh_2w(t0, a4);
  __ revh_2w(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revh_2w_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revh_2w_si2)));

  // revh_d
  __ revh_d(t0, a4);
  __ revh_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_revh_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_revh_d_si2)));

  // bitrev_8b
  __ bitrev_8b(t0, a4);
  __ bitrev_8b(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bitrev_8b_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bitrev_8b_si2)));

  // bitrev_d
  __ bitrev_d(t0, a4);
  __ bitrev_d(t1, a5);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bitrev_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bitrev_d_si2)));

  // bstrins_d
  __ or_(t0, zero_reg, zero_reg);
  __ or_(t1, zero_reg, zero_reg);
  __ bstrins_d(t0, a4, 5, 0);
  __ bstrins_d(t1, a5, 39, 12);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bstrins_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bstrins_d_si2)));

  // bstrpick_d
  __ or_(t0, zero_reg, zero_reg);
  __ or_(t1, zero_reg, zero_reg);
  __ bstrpick_d(t0, a4, 5, 0);
  __ bstrpick_d(t1, a5, 63, 48);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_bstrpick_d_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_bstrpick_d_si2)));

  // maskeqz
  __ maskeqz(t0, a4, a4);
  __ maskeqz(t1, a5, zero_reg);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_maskeqz_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_maskeqz_si2)));

  // masknez
  __ masknez(t0, a4, a4);
  __ masknez(t1, a5, zero_reg);
  __ St_d(t0, MemOperand(a0, offsetof(T, result_masknez_si1)));
  __ St_d(t1, MemOperand(a0, offsetof(T, result_masknez_si2)));

  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.si1 = 0x10C021098B710CDE;
  t.si2 = 0xFB8017FF781A15C3;
  f.Call(&t, 0, 0, 0, 0);

  //    CHECK_EQ(static_cast<int64_t>(0x0), t.result_clo_d_si1);
  //    CHECK_EQ(static_cast<int64_t>(0x5), t.result_clo_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x3), t.result_clz_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_clz_d_si2);
  //    CHECK_EQ(static_cast<int64_t>(0x0), t.result_cto_d_si1);
  //    CHECK_EQ(static_cast<int64_t>(0x2), t.result_cto_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x1), t.result_ctz_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x0), t.result_ctz_d_si2);
  CHECK_EQ(static_cast<int64_t>(0xfb8017ff781a15c3), t.result_bytepick_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x710cdefb8017ff78), t.result_bytepick_d_si2);
  CHECK_EQ(static_cast<int64_t>(0xc0100921718bde0c), t.result_revb_4h_si1);
  CHECK_EQ(static_cast<int64_t>(0x80fbff171a78c315), t.result_revb_4h_si2);
  CHECK_EQ(static_cast<int64_t>(0x921c010de0c718b), t.result_revb_2w_si1);
  CHECK_EQ(static_cast<int64_t>(0xff1780fbc3151a78), t.result_revb_2w_si2);
  CHECK_EQ(static_cast<int64_t>(0xde0c718b0921c010), t.result_revb_d_si1);
  CHECK_EQ(static_cast<int64_t>(0xc3151a78ff1780fb), t.result_revb_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x210910c00cde8b71), t.result_revh_2w_si1);
  CHECK_EQ(static_cast<int64_t>(0x17fffb8015c3781a), t.result_revh_2w_si2);
  CHECK_EQ(static_cast<int64_t>(0xcde8b71210910c0), t.result_revh_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x15c3781a17fffb80), t.result_revh_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x8038490d18e307b), t.result_bitrev_8b_si1);
  CHECK_EQ(static_cast<int64_t>(0xdf01e8ff1e58a8c3), t.result_bitrev_8b_si2);
  CHECK_EQ(static_cast<int64_t>(0x7b308ed190840308), t.result_bitrev_d_si1);
  CHECK_EQ(static_cast<int64_t>(0xc3a8581effe801df), t.result_bitrev_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x1e), t.result_bstrins_d_si1);
  CHECK_EQ(static_cast<int64_t>(0x81a15c3000), t.result_bstrins_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x1e), t.result_bstrpick_d_si1);
  CHECK_EQ(static_cast<int64_t>(0xfb80), t.result_bstrpick_d_si2);
  CHECK_EQ(static_cast<int64_t>(0x10C021098B710CDE), t.result_maskeqz_si1);
  CHECK_EQ(static_cast<int64_t>(0), t.result_maskeqz_si2);
  CHECK_EQ(static_cast<int64_t>(0), t.result_masknez_si1);
  CHECK_EQ(static_cast<int64_t>(0xFB8017FF781A15C3), t.result_masknez_si2);
}

uint64_t run_beq(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ beq(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BEQ) {
  CcTest::InitializeVM();
  struct TestCaseBeq {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBeq tc[] = {
    // value1, value2, offset, expected_res
    {       0,      0,    -6,          0x3 },
    {       1,      1,    -3,         0x30 },
    {      -2,     -2,     3,        0x300 },
    {       3,     -3,     6,            0 },
    {       4,      4,     6,        0x700 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBeq);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_beq(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bne(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bne(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BNE) {
  CcTest::InitializeVM();
  struct TestCaseBne {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBne tc[] = {
    // value1, value2, offset, expected_res
    {       1,     -1,    -6,          0x3 },
    {       2,     -2,    -3,         0x30 },
    {       3,     -3,     3,        0x300 },
    {       4,     -4,     6,        0x700 },
    {       0,      0,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBne);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bne(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_blt(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ blt(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BLT) {
  CcTest::InitializeVM();
  struct TestCaseBlt {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBlt tc[] = {
    // value1, value2, offset, expected_res
    {      -1,      1,    -6,          0x3 },
    {      -2,      2,    -3,         0x30 },
    {      -3,      3,     3,        0x300 },
    {      -4,      4,     6,        0x700 },
    {       5,     -5,     6,            0 },
    {       0,      0,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBlt);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_blt(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bge(uint64_t value1, uint64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bge(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BGE) {
  CcTest::InitializeVM();
  struct TestCaseBge {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBge tc[] = {
    // value1, value2, offset, expected_res
    {       0,      0,    -6,          0x3 },
    {       1,      1,    -3,         0x30 },
    {       2,     -2,     3,        0x300 },
    {       3,     -3,     6,        0x700 },
    {      -4,      4,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBge);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bge(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bltu(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bltu(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BLTU) {
  CcTest::InitializeVM();
  struct TestCaseBltu {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBltu tc[] = {
    // value1, value2, offset, expected_res
    {       0,      1,    -6,          0x3 },
    {       1,     -1,    -3,         0x30 },
    {       2,     -2,     3,        0x300 },
    {       3,     -3,     6,        0x700 },
    {       4,      4,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBltu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bltu(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bgeu(int64_t value1, int64_t value2, int16_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bgeu(a0, a1, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value1, value2, 0, 0, 0));

  return res;
}

TEST(BGEU) {
  CcTest::InitializeVM();
  struct TestCaseBgeu {
    int64_t value1;
    int64_t value2;
    int16_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBgeu tc[] = {
    // value1, value2, offset, expected_res
    {       0,      0,    -6,          0x3 },
    {      -1,      1,    -3,         0x30 },
    {      -2,      2,     3,        0x300 },
    {      -3,      3,     6,        0x700 },
    {       4,     -4,     6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBgeu);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_bgeu(tc[i].value1, tc[i].value2, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_beqz(int64_t value, int32_t offset) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(&L);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(&L);

  // Block 3 (Main)
  __ bind(&main_block);
  __ beqz(a0, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(&L);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(&L);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value, 0, 0, 0, 0));

  return res;
}

TEST(BEQZ) {
  CcTest::InitializeVM();
  struct TestCaseBeqz {
    int64_t value;
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format off
  struct TestCaseBeqz tc[] = {
    // value, offset, expected_res
    {      0,     -6,          0x3 },
    {      0,     -3,         0x30 },
    {      0,      3,        0x300 },
    {      0,      6,        0x700 },
    {      1,      6,            0 },
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseBeqz);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    uint64_t res = run_beqz(tc[i].value, tc[i].offset);
    CHECK_EQ(tc[i].expected_res, res);
  }
}

uint64_t run_bnez_b(int64_t value, int32_t offset) {
  // bnez, b.
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  Label main_block, L;
  __ li(a2, 0l);
  __ b(&main_block);
  // Block 1
  __ addi_d(a2, a2, 0x1);
  __ addi_d(a2, a2, 0x2);
  __ b(5);

  // Block 2
  __ addi_d(a2, a2, 0x10);
  __ addi_d(a2, a2, 0x20);
  __ b(2);

  // Block 3 (Main)
  __ bind(&main_block);
  __ bnez(a0, offset);
  __ bind(&L);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  // Block 4
  __ addi_d(a2, a2, 0x100);
  __ addi_d(a2, a2, 0x200);
  __ b(-4);

  // Block 5
  __ addi_d(a2, a2, 0x300);
  __ addi_d(a2, a2, 0x400);
  __ b(-7);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F2>::FromCode(isolate, *code);
  uint64_t res = reinterpret_cast<uint64_t>(f.Call(value, 0, 0, 0, 0));

  return res;
}

TEST(BNEZ_B) {
  CcTest::InitializeVM();
  struct TestCaseBnez {
    int64_t value;
    int32_t offset;
    uint64_t expected_res;
  };

  // clang-format 
"""


```