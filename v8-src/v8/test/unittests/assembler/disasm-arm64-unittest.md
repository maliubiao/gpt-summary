Response: 
Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2013 the V8 project authors. All rights reserved.
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

#include "src/diagnostics/arm64/disasm-arm64.h"

#include <stdio.h>

#include <cstring>

#include "src/codegen/arm64/assembler-arm64.h"
#include "src/codegen/arm64/decoder-arm64-inl.h"
#include "src/codegen/arm64/utils-arm64.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/execution/frames-inl.h"
#include "src/init/v8.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using DisasmArm64Test = TestWithIsolate;

#define EXP_SIZE (256)
#define INSTR_SIZE (1024)
#define SET_UP_MASM()                                                         \
  HandleScope scope(isolate());                                               \
  uint8_t* buf = static_cast<uint8_t*>(malloc(INSTR_SIZE));                   \
  uint32_t encoding = 0;                                                      \
  MacroAssembler* assm =                                                      \
      new MacroAssembler((isolate()), v8::internal::CodeObjectRequired::kYes, \
                         ExternalAssemblerBuffer(buf, INSTR_SIZE));           \
  Decoder<DispatchingDecoderVisitor>* decoder =                               \
      new Decoder<DispatchingDecoderVisitor>();                               \
  DisassemblingDecoder* disasm = new DisassemblingDecoder();                  \
  decoder->AppendVisitor(disasm)

#define SET_UP_ASM()                                                          \
  HandleScope scope(isolate());                                               \
  uint8_t* buf = static_cast<uint8_t*>(malloc(INSTR_SIZE));                   \
  uint32_t encoding = 0;                                                      \
  Assembler* assm = new Assembler(isolate()->allocator(), AssemblerOptions{}, \
                                  ExternalAssemblerBuffer(buf, INSTR_SIZE));  \
  Decoder<DispatchingDecoderVisitor>* decoder =                               \
      new Decoder<DispatchingDecoderVisitor>();                               \
  DisassemblingDecoder* disasm = new DisassemblingDecoder();                  \
  decoder->AppendVisitor(disasm)

#define COMPARE(ASM, EXP)                                                \
  assm->Reset();                                                         \
  assm->ASM;                                                             \
  {                                                                      \
    CodeDesc desc;                                                       \
    assm->GetCode(isolate(), &desc);                                     \
  }                                                                      \
  decoder->Decode(reinterpret_cast<Instruction*>(buf));                  \
  encoding = *reinterpret_cast<uint32_t*>(buf);                          \
  if (strcmp(disasm->GetOutput(), EXP) != 0) {                           \
    printf("%u : Encoding: %08" PRIx32 "\nExpected: %s\nFound:    %s\n", \
           __LINE__, encoding, EXP, disasm->GetOutput());                \
    abort();                                                             \
  }

#define COMPARE_PREFIX(ASM, EXP)                                         \
  assm->Reset();                                                         \
  assm->ASM;                                                             \
  {                                                                      \
    CodeDesc desc;                                                       \
    assm->GetCode(isolate(), &desc);                                     \
  }                                                                      \
  decoder->Decode(reinterpret_cast<Instruction*>(buf));                  \
  encoding = *reinterpret_cast<uint32_t*>(buf);                          \
  if (strncmp(disasm->GetOutput(), EXP, strlen(EXP)) != 0) {             \
    printf("%u : Encoding: %08" PRIx32 "\nExpected: %s\nFound:    %s\n", \
           __LINE__, encoding, EXP, disasm->GetOutput());                \
    abort();                                                             \
  }

#define CLEANUP() \
  delete disasm;  \
  delete decoder; \
  delete assm;    \
  free(buf)

TEST_F(DisasmArm64Test, bootstrap) {
  SET_UP_ASM();

  // Instructions generated by C compiler, disassembled by objdump, and
  // reformatted to suit our disassembly style.
  COMPARE(dci(0xa9ba7bfd), "stp fp, lr, [sp, #-96]!");
  COMPARE(dci(0x910003fd), "mov fp, sp");
  COMPARE(dci(0x9100e3a0), "add x0, fp, #0x38 (56)");
  COMPARE(dci(0xb900001f), "str wzr, [x0]");
  COMPARE(dci(0x528000e1), "movz w1, #0x7");
  COMPARE(dci(0xb9001c01), "str w1, [x0, #28]");
  COMPARE(dci(0x390043a0), "strb w0, [fp, #16]");
  COMPARE(dci(0x790027a0), "strh w0, [fp, #18]");
  COMPARE(dci(0xb9400400), "ldr w0, [x0, #4]");
  COMPARE(dci(0x0b000021), "add w1, w1, w0");
  COMPARE(dci(0x531b6800), "lsl w0, w0, #5");
  COMPARE(dci(0x521e0400), "eor w0, w0, #0xc");
  COMPARE(dci(0x72af0f00), "movk w0, #0x7878, lsl #16");
  COMPARE(dci(0xd360fc00), "lsr x0, x0, #32");
  COMPARE(dci(0x13037c01), "asr w1, w0, #3");
  COMPARE(dci(0x4b000021), "sub w1, w1, w0");
  COMPARE(dci(0x2a0103e0), "mov w0, w1");
  COMPARE(dci(0x93407c00), "sxtw x0, w0");
  COMPARE(dci(0x2a000020), "orr w0, w1, w0");
  COMPARE(dci(0xa8c67bfd), "ldp fp, lr, [sp], #96");

  CLEANUP();
}

TEST_F(DisasmArm64Test, mov_mvn) {
  SET_UP_MASM();

  COMPARE(Mov(w0, Operand(0x1234)), "movz w0, #0x1234");
  COMPARE(Mov(x1, Operand(0x1234)), "movz x1, #0x1234");
  COMPARE(Mov(w2, Operand(w3)), "mov w2, w3");
  COMPARE(Mov(x4, Operand(x5)), "mov x4, x5");
  COMPARE(Mov(w6, Operand(w7, LSL, 5)), "lsl w6, w7, #5");
  COMPARE(Mov(x8, Operand(x9, ASR, 42)), "asr x8, x9, #42");
  COMPARE(Mov(w10, Operand(w11, UXTB)), "uxtb w10, w11");
  COMPARE(Mov(x12, Operand(x13, UXTB, 1)), "ubfiz x12, x13, #1, #8");
  COMPARE(Mov(w14, Operand(w15, SXTH, 2)), "sbfiz w14, w15, #2, #16");
  COMPARE(Mov(x16, Operand(x20, SXTW, 3)), "sbfiz x16, x20, #3, #32");

  COMPARE(Mov(x0, sp), "mov x0, sp");
  COMPARE(Mov(w0, wsp), "mov w0, wsp");
  COMPARE(Mov(x0, xzr), "mov x0, xzr");
  COMPARE(Mov(w0, wzr), "mov w0, wzr");
  COMPARE(mov(x0, sp), "mov x0, sp");
  COMPARE(mov(w0, wsp), "mov w0, wsp");
  COMPARE(mov(x0, xzr), "mov x0, xzr");
  COMPARE(mov(w0, wzr), "mov w0, wzr");

  COMPARE(Mvn(w0, Operand(0x1)), "movn w0, #0x1");
  COMPARE(Mvn(x1, Operand(0xfff)), "movn x1, #0xfff");
  COMPARE(Mvn(w2, Operand(w3)), "mvn w2, w3");
  COMPARE(Mvn(x4, Operand(x5)), "mvn x4, x5");
  COMPARE(Mvn(w6, Operand(w7, LSL, 12)), "mvn w6, w7, lsl #12");
  COMPARE(Mvn(x8, Operand(x9, ASR, 63)), "mvn x8, x9, asr #63");

  CLEANUP();
}

TEST_F(DisasmArm64Test, move_immediate) {
  SET_UP_ASM();

  COMPARE(movz(w0, 0x1234), "movz w0, #0x1234");
  COMPARE(movz(x1, 0xabcd0000), "movz x1, #0xabcd0000");
  COMPARE(movz(x2, 0x555500000000), "movz x2, #0x555500000000");
  COMPARE(movz(x3, 0xaaaa000000000000), "movz x3, #0xaaaa000000000000");
  COMPARE(movz(x4, 0xabcd, 16), "movz x4, #0xabcd0000");
  COMPARE(movz(x5, 0x5555, 32), "movz x5, #0x555500000000");
  COMPARE(movz(x6, 0xaaaa, 48), "movz x6, #0xaaaa000000000000");

  COMPARE(movk(w7, 0x1234), "movk w7, #0x1234");
  COMPARE(movk(x8, 0xabcd0000), "movk x8, #0xabcd, lsl #16");
  COMPARE(movk(x9, 0x555500000000), "movk x9, #0x5555, lsl #32");
  COMPARE(movk(x10, 0xaaaa000000000000), "movk x10, #0xaaaa, lsl #48");
  COMPARE(movk(w11, 0xabcd, 16), "movk w11, #0xabcd, lsl #16");
  COMPARE(movk(x12, 0x5555, 32), "movk x12, #0x5555, lsl #32");
  COMPARE(movk(x13, 0xaaaa, 48), "movk x13, #0xaaaa, lsl #48");

  COMPARE(movn(w14, 0x1234), "movn w14, #0x1234");
  COMPARE(movn(x15, 0xabcd0000), "movn x15, #0xabcd0000");
  COMPARE(movn(x16, 0x555500000000), "movn x16, #0x555500000000");
  COMPARE(movn(x17, 0xaaaa000000000000), "movn x17, #0xaaaa000000000000");
  COMPARE(movn(w18, 0xabcd, 16), "movn w18, #0xabcd0000");
  COMPARE(movn(x19, 0x5555, 32), "movn x19, #0x555500000000");
  COMPARE(movn(x20, 0xaaaa, 48), "movn x20, #0xaaaa000000000000");

  COMPARE(movk(w21, 0), "movk w21, #0x0");
  COMPARE(movk(x22, 0, 0), "movk x22, #0x0");
  COMPARE(movk(w23, 0, 16), "movk w23, #0x0, lsl #16");
  COMPARE(movk(x24, 0, 32), "movk x24, #0x0, lsl #32");
  COMPARE(movk(x25, 0, 48), "movk x25, #0x0, lsl #48");

  CLEANUP();
}

TEST_F(DisasmArm64Test, move_immediate_2) {
  SET_UP_MASM();

  // Move instructions expected for certain immediates. This is really a macro
  // assembler test, to ensure it generates immediates efficiently.
  COMPARE(Mov(w0, 0), "movz w0, #0x0");
  COMPARE(Mov(w0, 0x0000ffff), "movz w0, #0xffff");
  COMPARE(Mov(w0, 0x00010000), "movz w0, #0x10000");
  COMPARE(Mov(w0, 0xffff0000), "movz w0, #0xffff0000");
  COMPARE(Mov(w0, 0x0001ffff), "movn w0, #0xfffe0000");
  COMPARE(Mov(w0, 0xffff8000), "movn w0, #0x7fff");
  COMPARE(Mov(w0, 0xfffffffe), "movn w0, #0x1");
  COMPARE(Mov(w0, 0xffffffff), "movn w0, #0x0");
  COMPARE(Mov(w0, 0x00ffff00), "mov w0, #0xffff00");
  COMPARE(Mov(w0, 0xfffe7fff), "mov w0, #0xfffe7fff");
  COMPARE(Mov(w0, 0xfffeffff), "movn w0, #0x10000");
  COMPARE(Mov(w0, 0xffff7fff), "movn w0, #0x8000");

  COMPARE(Mov(x0, 0), "movz x0, #0x0");
  COMPARE(Mov(x0, 0x0000ffff), "movz x0, #0xffff");
  COMPARE(Mov(x0, 0x00010000), "movz x0, #0x10000");
  COMPARE(Mov(x0, 0xffff0000), "movz x0, #0xffff0000");
  COMPARE(Mov(x0, 0x0001ffff), "mov x0, #0x1ffff");
  COMPARE(Mov(x0, 0xffff8000), "mov x0, #0xffff8000");
  COMPARE(Mov(x0, 0xfffffffe), "mov x0, #0xfffffffe");
  COMPARE(Mov(x0, 0xffffffff), "mov x0, #0xffffffff");
  COMPARE(Mov(x0, 0x00ffff00), "mov x0, #0xffff00");
  COMPARE(Mov(x0, 0xffff000000000000), "movz x0, #0xffff000000000000");
  COMPARE(Mov(x0, 0x0000ffff00000000), "movz x0, #0xffff00000000");
  COMPARE(Mov(x0, 0x00000000ffff0000), "movz x0, #0xffff0000");
  COMPARE(Mov(x0, 0xffffffffffff0000), "movn x0, #0xffff");
  COMPARE(Mov(x0, 0xffffffff0000ffff), "movn x0, #0xffff0000");
  COMPARE(Mov(x0, 0xffff0000ffffffff), "movn x0, #0xffff00000000");
  COMPARE(Mov(x0, 0x0000ffffffffffff), "movn x0, #0xffff000000000000");
  COMPARE(Mov(x0, 0xfffe7fffffffffff), "mov x0, #0xfffe7fffffffffff");
  COMPARE(Mov(x0, 0xfffeffffffffffff), "movn x0, #0x1000000000000");
  COMPARE(Mov(x0, 0xffff7fffffffffff), "movn x0, #0x800000000000");
  COMPARE(Mov(x0, 0xfffffffe7fffffff), "mov x0, #0xfffffffe7fffffff");
  COMPARE(Mov(x0, 0xfffffffeffffffff), "movn x0, #0x100000000");
  COMPARE(Mov(x0, 0xffffffff7fffffff), "movn x0, #0x80000000");
  COMPARE(Mov(x0, 0xfffffffffffe7fff), "mov x0, #0xfffffffffffe7fff");
  COMPARE(Mov(x0, 0xfffffffffffeffff), "movn x0, #0x10000");
  COMPARE(Mov(x0, 0xffffffffffff7fff), "movn x0, #0x8000");
  COMPARE(Mov(x0, 0xffffffffffffffff), "movn x0, #0x0");

  COMPARE(Movk(w0, 0x1234, 0), "movk w0, #0x1234");
  COMPARE(Movk(x1, 0x2345, 0), "movk x1, #0x2345");
  COMPARE(Movk(w2, 0x3456, 16), "movk w2, #0x3456, lsl #16");
  COMPARE(Movk(x3, 0x4567, 16), "movk x3, #0x4567, lsl #16");
  COMPARE(Movk(x4, 0x5678, 32), "movk x4, #0x5678, lsl #32");
  COMPARE(Movk(x5, 0x6789, 48), "movk x5, #0x6789, lsl #48");

  CLEANUP();
}

TEST_F(DisasmArm64Test, add_immediate) {
  SET_UP_ASM();

  COMPARE(add(w0, w1, Operand(0xff)), "add w0, w1, #0xff (255)");
  COMPARE(add(x2, x3, Operand(0x3ff)), "add x2, x3, #0x3ff (1023)");
  COMPARE(add(w4, w5, Operand(0xfff)), "add w4, w5, #0xfff (4095)");
  COMPARE(add(x6, x7, Operand(0x1000)), "add x6, x7, #0x1000 (4096)");
  COMPARE(add(w8, w9, Operand(0xff000)), "add w8, w9, #0xff000 (1044480)");
  COMPARE(add(x10, x11, Operand(0x3ff000)),
          "add x10, x11, #0x3ff000 (4190208)");
  COMPARE(add(w12, w13, Operand(0xfff000)),
          "add w12, w13, #0xfff000 (16773120)");
  COMPARE(adds(w14, w15, Operand(0xff)), "adds w14, w15, #0xff (255)");
  COMPARE(adds(x16, x17, Operand(0xaa000)), "adds x16, x17, #0xaa000 (696320)");
  COMPARE(cmn(w18, Operand(0xff)), "cmn w18, #0xff (255)");
  COMPARE(cmn(x19, Operand(0xff000)), "cmn x19, #0xff000 (1044480)");
  COMPARE(add(w0, wsp, Operand(0)), "mov w0, wsp");
  COMPARE(add(sp, x0, Operand(0)), "mov sp, x0");

  COMPARE(add(w1, wsp, Operand(8)), "add w1, wsp, #0x8 (8)");
  COMPARE(add(x2, sp, Operand(16)), "add x2, sp, #0x10 (16)");
  COMPARE(add(wsp, wsp, Operand(42)), "add wsp, wsp, #0x2a (42)");
  COMPARE(cmn(sp, Operand(24)), "cmn sp, #0x18 (24)");
  COMPARE(adds(wzr, wsp, Operand(9)), "cmn wsp, #0x9 (9)");

  CLEANUP();
}

TEST_F(DisasmArm64Test, sub_immediate) {
  SET_UP_ASM();

  COMPARE(sub(w0, w1, Operand(0xff)), "sub w0, w1, #0xff (255)");
  COMPARE(sub(x2, x3, Operand(0x3ff)), "sub x2, x3, #0x3ff (1023)");
  COMPARE(sub(w4, w5, Operand(0xfff)), "sub w4, w5, #0xfff (4095)");
  COMPARE(sub(x6, x7, Operand(0x1000)), "sub x6, x7, #0x1000 (4096)");
  COMPARE(sub(w8, w9, Operand(0xff000)), "sub w8, w9, #0xff000 (1044480)");
  COMPARE(sub(x10, x11, Operand(0x3ff000)),
          "sub x10, x11, #0x3ff000 (4190208)");
  COMPARE(sub(w12, w13, Operand(0xfff000)),
          "sub w12, w13, #0xfff000 (16773120)");
  COMPARE(subs(w14, w15, Operand(0xff)), "subs w14, w15, #0xff (255)");
  COMPARE(subs(x16, x17, Operand(0xaa000)), "subs x16, x17, #0xaa000 (696320)");
  COMPARE(cmp(w18, Operand(0xff)), "cmp w18, #0xff (255)");
  COMPARE(cmp(x19, Operand(0xff000)), "cmp x19, #0xff000 (1044480)");

  COMPARE(add(w1, wsp, Operand(8)), "add w1, wsp, #0x8 (8)");
  COMPARE(add(x2, sp, Operand(16)), "add x2, sp, #0x10 (16)");
  COMPARE(add(wsp, wsp, Operand(42)), "add wsp, wsp, #0x2a (42)");
  COMPARE(cmn(sp, Operand(24)), "cmn sp, #0x18 (24)");
  COMPARE(adds(wzr, wsp, Operand(9)), "cmn wsp, #0x9 (9)");

  CLEANUP();
}

TEST_F(DisasmArm64Test, add_shifted) {
  SET_UP_ASM();

  COMPARE(add(w0, w1, Operand(w2)), "add w0, w1, w2");
  COMPARE(add(x3, x4, Operand(x5)), "add x3, x4, x5");
  COMPARE(add(w6, w7, Operand(w8, LSL, 1)), "add w6, w7, w8, lsl #1");
  COMPARE(add(x9, x10, Operand(x11, LSL, 2)), "add x9, x10, x11, lsl #2");
  COMPARE(add(w12, w13, Operand(w14, LSR, 3)), "add w12, w13, w14, lsr #3");
  COMPARE(add(x15, x16, Operand(x17, LSR, 4)), "add x15, x16, x17, lsr #4");
  COMPARE(add(w18, w19, Operand(w20, ASR, 5)), "add w18, w19, w20, asr #5");
  COMPARE(add(x21, x22, Operand(x23, ASR, 6)), "add x21, x22, x23, asr #6");
  COMPARE(cmn(w24, Operand(w25)), "cmn w24, w25");
  COMPARE(cmn(x26, Operand(cp, LSL, 63)), "cmn x26, cp, lsl #63");

  COMPARE(add(x0, sp, Operand(x1)), "add x0, sp, x1");
  COMPARE(add(w2, wsp, Operand(w3)), "add w2, wsp, w3");
  COMPARE(add(x4, sp, Operand(x5, LSL, 1)), "add x4, sp, x5, lsl #1");
  COMPARE(add(x4, xzr, Operand(x5, LSL, 1)), "add x4, xzr, x5, lsl #1");
  COMPARE(add(w6, wsp, Operand(w7, LSL, 3)), "add w6, wsp, w7, lsl #3");
  COMPARE(adds(xzr, sp, Operand(x8, LSL, 4)), "cmn sp, x8, lsl #4");
  COMPARE(adds(xzr, xzr, Operand(x8, LSL, 5)), "cmn xzr, x8, lsl #5");

  CLEANUP();
}

TEST_F(DisasmArm64Test, sub_shifted) {
  SET_UP_ASM();

  COMPARE(sub(w0, w1, Operand(w2)), "sub w0, w1, w2");
  COMPARE(sub(x3, x4, Operand(x5)), "sub x3, x4, x5");
  COMPARE(sub(w6, w7, Operand(w8, LSL, 1)), "sub w6, w7, w8, lsl #1");
  COMPARE(sub(x9, x10, Operand(x11, LSL, 2)), "sub x9, x10, x11, lsl #2");
  COMPARE(sub(w12, w13, Operand(w14, LSR, 3)), "sub w12, w13, w14, lsr #3");
  COMPARE(sub(x15, x16, Operand(x17, LSR, 4)), "sub x15, x16, x17, lsr #4");
  COMPARE(sub(w18, w19, Operand(w20, ASR, 5)), "sub w18, w19, w20, asr #5");
  COMPARE(sub(x21, x22, Operand(x23, ASR, 6)), "sub x21, x22, x23, asr #6");
  COMPARE(cmp(w24, Operand(w25)), "cmp w24, w25");
  COMPARE(cmp(x26, Operand(cp, LSL, 63)), "cmp x26, cp, lsl #63");
  COMPARE(neg(w28, Operand(w29)), "neg w28, w29");
  COMPARE(neg(lr, Operand(x0, LSR, 62)), "neg lr, x0, lsr #62");
  COMPARE(negs(w1, Operand(w2)), "negs w1, w2");
  COMPARE(negs(x3, Operand(x4, ASR, 61)), "negs x3, x4, asr #61");

  COMPARE(sub(x0, sp, Operand(x1)), "sub x0, sp, x1");
  COMPARE(sub(w2, wsp, Operand(w3)), "sub w2, wsp, w3");
  COMPARE(sub(x4, sp, Operand(x5, LSL, 1)), "sub x4, sp, x5, lsl #1");
  COMPARE(sub(x4, xzr, Operand(x5, LSL, 1)), "neg x4, x5, lsl #1");
  COMPARE(sub(w6, wsp, Operand(w7, LSL, 3)), "sub w6, wsp, w7, lsl #3");
  COMPARE(subs(xzr, sp, Operand(x8, LSL, 4)), "cmp sp, x8, lsl #4");
  COMPARE(subs(xzr, xzr, Operand(x8, LSL, 5)), "cmp xzr, x8, lsl #5");

  CLEANUP();
}

TEST_F(DisasmArm64Test, add_extended) {
  SET_UP_ASM();

  COMPARE(add(w0, w1, Operand(w2, UXTB)), "add w0, w1, w2, uxtb");
  COMPARE(adds(x3, x4, Operand(w5, UXTB, 1)), "adds x3, x4, w5, uxtb #1");
  COMPARE(add(w6, w7, Operand(w8, UXTH, 2)), "add w6, w7, w8, uxth #2");
  COMPARE(adds(x9, x10, Operand(x11, UXTW, 3)), "adds x9, x10, w11, uxtw #3");
  COMPARE(add(x12, x13, Operand(x14, UXTX, 4)), "add x12, x13, x14, uxtx #4");
  COMPARE(adds(w15, w16, Operand(w17, SXTB, 4)), "adds w15, w16, w17, sxtb #4");
  COMPARE(add(x18, x19, Operand(x20, SXTB, 3)), "add x18, x19, w20, sxtb #3");
  COMPARE(adds(w21, w22, Operand(w23, SXTH, 2)), "adds w21, w22, w23, sxth #2");
  COMPARE(add(x24, x25, Operand(x26, SXTW, 1)), "add x24, x25, w26, sxtw #1");
  COMPARE(adds(cp, x28, Operand(fp, SXTX)), "adds cp, x28, fp, sxtx");
  COMPARE(cmn(w0, Operand(w1, UXTB, 2)), "cmn w0, w1, uxtb #2");
  COMPARE(cmn(x2, Operand(x3, SXTH, 4)), "cmn x2, w3, sxth #4");

  COMPARE(add(w0, wsp, Operand(w1, UXTB)), "add w0, wsp, w1, uxtb");
  COMPARE(add(x2, sp, Operand(x3, UXTH, 1)), "add x2, sp, w3, uxth #1");
  COMPARE(add(wsp, wsp, Operand(w4, UXTW, 2)), "add wsp, wsp, w4, lsl #2");
  COMPARE(cmn(sp, Operand(xzr, UXTX, 3)), "cmn sp, xzr, lsl #3");
  COMPARE(cmn(sp, Operand(xzr, LSL, 4)), "cmn sp, xzr, lsl #4");

  CLEANUP();
}

TEST_F(DisasmArm64Test, sub_extended) {
  SET_UP_ASM();

  COMPARE(sub(w0, w1, Operand(w2, UXTB)), "sub w0, w1, w2, uxtb");
  COMPARE(subs(x3, x4, Operand(w5, UXTB, 1)), "subs x3, x4, w5, uxtb #1");
  COMPARE(sub(w6, w7, Operand(w8, UXTH, 2)), "sub w6, w7, w8, uxth #2");
  COMPARE(subs(x9, x10, Operand(x11, UXTW, 3)), "subs x9, x10, w11, uxtw #3");
  COMPARE(sub(x12, x13, Operand(x14, UXTX, 4)), "sub x12, x13, x14, uxtx #4");
  COMPARE(subs(w15, w16, Operand(w17, SXTB, 4)), "subs w15, w16, w17, sxtb #4");
  COMPARE(sub(x18, x19, Operand(x20, SXTB, 3)), "sub x18, x19, w20, sxtb #3");
  COMPARE(subs(w21, w22, Operand(w23, SXTH, 2)), "subs w21, w22, w23, sxth #2");
  COMPARE(sub(x24, x25, Operand(x26, SXTW, 1)), "sub x24, x25, w26, sxtw #1");
  COMPARE(subs(cp, x28, Operand(fp, SXTX)), "subs cp, x28, fp, sxtx");
  COMPARE(cmp(w0, Operand(w1, SXTB, 1)), "cmp w0, w1, sxtb #1");
  COMPARE(cmp(x2, Operand(x3, UXTH, 3)), "cmp x2, w3, uxth #3");

  COMPARE(sub(w0, wsp, Operand(w1, UXTB)), "sub w0, wsp, w1, uxtb");
  COMPARE(sub(x2, sp, Operand(x3, UXTH, 1)), "sub x2, sp, w3, uxth #1");
  COMPARE(sub(wsp, wsp, Operand(w4, UXTW, 2)), "sub wsp, wsp, w4, lsl #2");
  COMPARE(cmp(sp, Operand(xzr, UXTX, 3)), "cmp sp, xzr, lsl #3");
  COMPARE(cmp(sp, Operand(xzr, LSL, 4)), "cmp sp, xzr, lsl #4");

  CLEANUP();
}

TEST_F(DisasmArm64Test, adc_subc_ngc) {
  SET_UP_ASM();

  COMPARE(adc(w0, w1, Operand(w2)), "adc w0, w1, w2");
  COMPARE(adc(x3, x4, Operand(x5)), "adc x3, x4, x5");
  COMPARE(adcs(w6, w7, Operand(w8)), "adcs w6, w7, w8");
  COMPARE(adcs(x9, x10, Operand(x11)), "adcs x9, x10, x11");
  COMPARE(sbc(w12, w13, Operand(w14)), "sbc w12, w13, w14");
  COMPARE(sbc(x15, x16, Operand(x17)), "sbc x15, x16, x17");
  COMPARE(sbcs(w18, w19, Operand(w20)), "sbcs w18, w19, w20");
  COMPARE(sbcs(x21, x22, Operand(x23)), "sbcs x21, x22, x23");
  COMPARE(ngc(w24, Operand(w25)), "ngc w24, w25");
  COMPARE(ngc(x26, Operand(cp)), "ngc x26, cp");
  COMPARE(ngcs(w28, Operand(w29)), "ngcs w28, w29");
  COMPARE(ngcs(lr, Operand(x0)), "ngcs lr, x0");

  CLEANUP();
}

TEST_F(DisasmArm64Test, mul_and_div) {
  SET_UP_ASM();

  COMPARE(mul(w0, w1, w2), "mul w0, w1, w2");
  COMPARE(mul(x3, x4, x5), "mul x3, x4, x5");
  COMPARE(mul(w30, w0, w1), "mul w30, w0, w1");
  COMPARE(mul(lr, x0, x1), "mul lr, x0, x1");
  COMPARE(mneg(w0, w1, w2), "mneg w0, w1, w2");
  COMPARE(mneg(x3, x4, x5), "mneg x3, x4, x5");
  COMPARE(mneg(w30, w0, w1), "mneg w30, w0, w1");
  COMPARE(mneg(lr, x0, x1), "mneg lr, x0, x1");
  COMPARE(smull(x0, w0, w1), "smull x0, w0, w1");
  COMPARE(smull(lr, w30, w0), "smull lr, w30, w0");
  COMPARE(smulh(x0, x1, x2), "smulh x0, x1, x2");

  COMPARE(madd(w0, w1, w2, w3), "madd w0, w1, w2, w3");
  COMPARE(madd(x4, x5, x6, x7), "madd x4, x5, x6, x7");
  COMPARE(madd(w8, w9, w10, wzr), "mul w8, w9, w10");
  COMPARE(madd(x11, x12, x13, xzr), "mul x11, x12, x13");
  COMPARE(msub(w14, w15, w16, w17), "msub w14, w15, w16, w17");
  COMPARE(msub(x18, x19, x20, x21), "msub x18, x19, x20, x21");
  COMPARE(msub(w22, w23, w24, wzr), "mneg w22, w23, w24");
  COMPARE(msub(x25, x26, x0, xzr), "mneg x25, x26, x0");

  COMPARE(sdiv(w0, w1, w2), "sdiv w0, w1, w2");
  COMPARE(sdiv(x3, x4, x5), "sdiv x3, x4, x5");
  COMPARE(udiv(w6, w7, w8), "udiv w6, w7, w8");
  COMPARE(udiv(x9, x10, x11), "udiv x9, x10, x11");

  CLEANUP();
}

TEST_F(DisasmArm64Test, maddl_msubl) {
  SET_UP_ASM();

  COMPARE(smaddl(x0, w1, w2, x3), "smaddl x0, w1, w2, x3");
  COMPARE(smaddl(x25, w21, w22, x16), "smaddl x25, w21, w22, x16");
  COMPARE(umaddl(x0, w1, w2, x3), "umaddl x0, w1, w2, x3");
  COMPARE(umaddl(x25, w21, w22, x16), "umaddl x25, w21, w22, x16");

  COMPARE(smsubl(x0, w1, w2, x3), "smsubl x0, w1, w2, x3");
  COMPARE(smsubl(x25, w21, w22, x16), "smsubl x25, w21, w22, x16");
  COMPARE(umsubl(x0, w1, w2, x3), "umsubl x0, w1, w2, x3");
  COMPARE(umsubl(x25, w21, w22, x16), "umsubl x25, w21, w22, x16");

  CLEANUP();
}

TEST_F(DisasmArm64Test, dp_1_source) {
  SET_UP_ASM();

  COMPARE(rbit(w0, w1), "rbit w0, w1");
  COMPARE(rbit(x2, x3), "rbit x2, x3");
  COMPARE(rev16(w4, w5), "rev16 w4, w5");
  COMPARE(rev16(x6, x7), "rev16 x6, x7");
  COMPARE(rev32(x8, x9), "rev32 x8, x9");
  COMPARE(rev(w10, w11), "rev w10, w11");
  COMPARE(rev(x12, x13), "rev x12, x13");
  COMPARE(clz(w14, w15), "clz w14, w15");
  COMPARE(clz(x16, x17), "clz x16, x17");
  COMPARE(cls(w18, w19), "cls w18, w19");
  COMPARE(cls(x20, x21), "cls x20, x21");

  CLEANUP();
}

TEST_F(DisasmArm64Test, bitfield) {
  SET_UP_ASM();

  COMPARE(sxtb(w0, w1), "sxtb w0, w1");
  COMPARE(sxtb(x2, x3), "sxtb x2, w3");
  COMPARE(sxth(w4, w5), "sxth w4, w5");
  COMPARE(sxth(x6, x7), "sxth x6, w7");
  COMPARE(sxtw(x8, x9), "sxtw x8, w9");
  COMPARE(sxtb(x0, w1), "sxtb x0, w1");
  COMPARE(sxth(x2, w3), "sxth x2, w3");
  COMPARE(sxtw(x4, w5), "sxtw x4, w5");

  COMPARE(uxtb(w10, w11), "uxtb w10, w11");
  COMPARE(uxtb(x12, x13), "uxtb x12, w13");
  COMPARE(uxth(w14, w15), "uxth w14, w15");
  COMPARE(uxth(x16, x17), "uxth x16, w17");
  COMPARE(uxtw(x18, x19), "ubfx x18, x19, #0, #32");

  COMPARE(asr(w20, w21, 10), "asr w20, w21, #10");
  COMPARE(asr(x22, x23, 20), "asr x22, x23, #20");
  COMPARE(lsr(w24, w25, 10), "lsr w24, w25, #10");
  COMPARE(lsr(x26, cp, 20), "lsr x26, cp, #20");
  COMPARE(lsl(w28, w29, 10), "lsl w28, w29, #10");
  COMPARE(lsl(lr, x0, 20), "lsl lr, x0, #20");

  COMPARE(sbfiz(w1, w2, 1, 20), "sbfiz w1, w2, #1, #20");
  COMPARE(sbfiz(x3, x4, 2, 19), "sbfiz x3, x4, #2, #19");
  COMPARE(sbfx(w5, w6, 3, 18), "sbfx w5, w6, #3, #18");
  COMPARE(sbfx(x7, x8, 4, 17), "sbfx x7, x8, #4, #17");
  COMPARE(bfi(w9, w10, 5, 16), "bfi w9, w10, #5, #16");
  COMPARE(bfi(x11, x12, 6, 15), "bfi x11, x12, #6, #15");
  COMPARE(bfxil(w13, w14, 7, 14), "bfxil w13, w14, #7, #14");
  COMPARE(bfxil(x15, x16, 8, 13), "bfxil x15, x16, #8, #13");
  COMPARE(ubfiz(w17, w18, 9, 12), "ubfiz w17, w18, #9, #12");
  COMPARE(ubfiz(x19, x20, 10, 11), "ubfiz x19, x20, #10, #11");
  COMPARE(ubfx(w21, w22, 11, 10), "ubfx w21, w22, #11, #10");
  COMPARE(ubfx(x23, x24, 12, 9), "ubfx x23, x24, #12, #9");

  CLEANUP();
}

TEST_F(DisasmArm64Test, extract) {
  SET_UP_ASM();

  COMPARE(extr(w0, w1, w2, 0), "extr w0, w1, w2, #0");
  COMPARE(extr(x3, x4, x5, 1), "extr x3, x4, x5, #1");
  COMPARE(extr(w6, w7, w8, 31), "extr w6, w7, w8, #31");
  COMPARE(extr(x9, x10, x11, 63), "extr x9, x10, x11, #63");
  COMPARE(extr(w12, w13, w13, 10), "ror w12, w13, #10");
  COMPARE(extr(x14, x15, x15, 42), "ror x14, x15, #42");

  CLEANUP();
}

TEST_F(DisasmArm64Test, logical_immediate) {
  SET_UP_ASM();
#define RESULT_SIZE (256)

  char result[RESULT_SIZE];

  // Test immediate encoding - 64-bit destination.
  // 64-bit patterns.
  uint64_t value = 0x7fffffff;
  for (int i = 0; i < 64; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 32-bit patterns.
  value = 0x00003fff00003fffL;
  for (int i = 0; i < 32; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 16-bit patterns.
  value = 0x001f001f001f001fL;
  for (int i = 0; i < 16; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 8-bit patterns.
  value = 0x0e0e0e0e0e0e0e0eL;
  for (int i = 0; i < 8; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 4-bit patterns.
  value = 0x6666666666666666L;
  for (int i = 0; i < 4; i++) {
    snprintf(result, RESULT_SIZE, "and x0, x0, #0x%" PRIx64, value);
    COMPARE(and_(x0, x0, Operand(value)), result);
    value = ((value & 1) << 63) | (value >> 1);  // Rotate right 1 bit.
  }

  // 2-bit patterns.
  COMPARE(and_(x0, x0, Operand(0x5555555555555555L)),
          "and x0, x0, #0x5555555555555555");
  COMPARE(and_(x0, x0, Operand(0xaaaaaaaaaaaaaaaaL)),
          "and x0, x0, #0xaaaaaaaaaaaaaaaa");

  // Test immediate encoding - 32-bit destination.
  COMPARE(and_(w0, w0, Operand(0xff8007ff)),
          "and w0, w0, #0xff8007ff");  // 32-bit pattern.
  COMPARE(and_(w0, w0, Operand(0xf87ff87f)),
          "and w0, w0, #0xf87ff87f");  // 16-bit pattern.
  COMPARE(and_(w0, w0, Operand(0x87878787)),
          "and w0, w0, #0x87878787");  // 8-bit pattern.
  COMPARE(and_(w0, w0, Operand(0x66666666)),
          "and w0, w0, #0x66666666");  // 4-bit pattern.
  COMPARE(and_(w0, w0, Operand(0x55555555)),
          "and w0, w0, #0x55555555");  // 2-bit pattern.

  // Test other instructions.
  COMPARE(tst(w1, Operand(0x11111111)), "tst w1, #0x11111111");
  COMPARE(tst(x2, Operand(0x8888888888888888L)), "tst x2, #0x8888888888888888");
  COMPARE(orr(w7, w8, Operand(0xaaaaaaaa)), "orr w7, w8, #0xaaaaaaaa");
  COMPARE(orr(x9, x10, Operand(0x5555555555555555L)),
          "orr x9, x10, #0x5555555555555555");
  COMPARE(eor(w15, w16, Operand(0x00000001)), "eor w15, w16, #0x1");
  COMPARE(eor(x17, x18, Operand(0x0000000000000003L)), "eor x17, x18, #0x3");
  COMPARE(ands(w23, w24, Operand(0x0000000f)), "ands w23, w24, #0xf");
  COMPARE(ands(x25, x26, Operand(0x800000000000000fL)),
          "ands x25, x26, #0x800000000000000f");

  // Test inverse.
  COMPARE(bic(w3, w4, Operand(0x20202020)), "and w3, w4, #0xdfdfdfdf");
  COMPARE(bic(x5, x6, Operand(0x4040404040404040L)),
          "and x5, x6, #0xbfbfbfbfbfbfbfbf");
  COMPARE(orn(w11, w12, Operand(0x40004000)), "orr w11, w12, #0xbfffbfff");
  COMPARE(orn(x13, x14, Operand(0x8181818181818181L)),
          "orr x13, x14, #0x7e7e7e7e7e7e7e7e");
  COMPARE(eon(w19, w20, Operand(0x80000001)), "eor w19, w20, #0x7ffffffe");
  COMPARE(eon(x21, x22, Operand(0xc000000000000003L)),
          "eor x21, x22, #0x3ffffffffffffffc");
  COMPARE(bics(w27, w28, Operand(0xfffffff7)), "ands w27, w28, #0x8");
  COMPARE(bics(fp, x0, Operand(0xfffffffeffffffffL)),
          "ands fp, x0, #0x100000000");

  // Test stack pointer.
  COMPARE(and_(wsp, wzr, Operand(7)), "and wsp, wzr, #0x7");
  COMPARE(ands(xzr, xzr, Operand(7)), "tst xzr, #0x7");
  COMPARE(orr(sp, xzr, Operand(15)), "orr sp, xzr, #0xf");
  COMPARE(eor(wsp, w0, Operand(31)), "eor wsp, w0, #0x1f");

  // Test move aliases.
  COMPARE(orr(w0, wzr, Operand(0x00000780)), "orr w0, wzr, #0x780");
  COMPARE(orr(w1, wzr, Operand(0x00007800)), "orr w1, wzr, #0x7800");
  COMPARE(orr(w2, wzr, Operand(0x00078000)), "mov w2, #0x78000");
  COMPARE(orr(w3, wzr, Operand(0x00780000)), "orr w3, wzr, #0x780000");
  COMPARE(orr(w4, wzr, Operand(0x07800000)), "orr w4, wzr, #0x7800000");
  COMPARE(orr(x5, xzr, Operand(0xffffffffffffc001UL)),
          "orr x5, xzr, #0xffffffffffffc001");
  COMPARE(orr(x6, xzr, Operand(0xfffffffffffc001fUL)),
          "mov x6, #0xfffffffffffc001f");
  COMPARE(orr(x7, xzr, Operand(0xffffffffffc001ffUL)),
          "mov x7, #0xffffffffffc001ff");
  COMPARE(orr(x8, xzr, Operand(0xfffffffffc001fffUL)),
          "mov x8, #0xfffffffffc001fff");
  COMPARE(orr(x9, xzr, Operand(0xffffffffc001ffffUL)),
          "orr x9, xzr, #0xffffffffc001ffff");

  CLEANUP();
}

TEST_F(DisasmArm64Test, logical_shifted) {
  SET_UP_ASM();

  COMPARE(and_(w0, w1, Operand(w2)), "and w0, w1, w2");
  COMPARE(and_(x3, x4, Operand(x5, LSL, 1)), "and x3, x4, x5, lsl #1");
  COMPARE(and_(w6, w7, Operand(w8, LSR, 2)), "and w6, w7, w8, lsr #2");
  COMPARE(and_(x9, x10, Operand(x11, ASR, 3)), "and x9, x10, x11, asr #3");
  COMPARE(and_(w12, w13, Operand(w14, ROR, 4)), "and w12, w13, w14, ror #4");

  COMPARE(bic(w15, w16, Operand(w17)), "bic w15, w16, w17");
  COMPARE(bic(x18, x19, Operand(x20, LSL, 5)), "bic x18, x19, x20, lsl #5");
  COMPARE(bic(w21, w22, Operand(w23, LSR, 6)), "bic w21, w22, w23, lsr #6");
  COMPARE(bic(x24, x25, Operand(x26, ASR, 7)), "bic x24, x25, x26, asr #7");
  COMPARE(bic(w27, w28, Operand(w29, ROR, 8)), "bic w27, w28, w29, ror #8");

  COMPARE(orr(w0, w1, Operand(w2)), "orr w0, w1, w2");
  COMPARE(orr(x3, x4, Operand(x5, LSL, 9)), "orr x3, x4, x5, lsl #9");
  COMPARE(orr(w6, w7, Operand(w8, LSR, 10)), "orr w6, w7, w8, lsr #10");
  COMPARE(orr(x9, x10, Operand(x11, ASR, 11)), "orr x9, x10, x11, asr #11");
  COMPARE(orr(w12, w13, Operand(w14, ROR, 12)), "orr w12, w13, w14, ror #12");

  COMPARE(orn(w15, w16, Operand(w17)), "orn w15, w16, w17");
  COMPARE(orn(x18, x19, Operand(x20, LSL, 13)), "orn x18, x19, x20, lsl #13");
  COMPARE(orn(w21, w22, Operand(w23, LSR, 14)), "orn w21, w22, w23, lsr #14");
  COMPARE(orn(x24, x25, Operand(x26, ASR, 15)), "orn x24, x25, x26, asr #15");
  COMPARE(orn(w27, w28, Operand(w29, ROR, 16)), "orn w27, w28, w29, ror #16");

  COMPARE(eor(w0, w1, Operand(w2)), "eor w0, w1, w2");
  COMPARE(eor(x3, x4, Operand(x5, LSL, 17)), "eor x3, x4, x5, lsl #17");
  COMPARE(eor(w6, w7, Operand(w8, LSR, 18)), "eor w6, w7, w8, lsr #18");
  COMPARE(eor(x9, x10, Operand(x11, ASR, 19)), "eor x9, x10, x11, asr #19");
  COMPARE(eor(w12, w13, Operand(w14, ROR, 20)), "eor w12, w13, w14, ror #20");

  COMPARE(eon(w15, w16, Operand(w17)), "eon w15, w16, w17");
  COMPARE(eon(x18, x19, Operand(x20, LSL, 21)), "eon x18, x19, x20, lsl #21");
  COMPARE(eon(w21, w22, Operand(w23, LSR, 22)), "eon w21, w22, w23, lsr #22");
  COMPARE(eon(x24, x25, Operand(x26, ASR, 23)), "eon x24, x25, x26, asr #23");
  COMPARE(eon(w27, w28, Operand(w29, ROR, 24)), "eon w27, w28, w29, ror #24");

  COMPARE(ands(w0, w1, Operand(w2)), "ands w0, w1, w2");
  COMPARE(ands(x3, x4, Operand(x5, LSL, 1)), "ands x3, x4, x5, lsl #1");
  COMPARE(ands(w6, w7, Operand(w8, LSR, 2)), "ands w6, w7, w8, lsr #2");
  COMPARE(ands(x9, x10, Operand(x11, ASR, 3)), "ands x9, x10, x11, asr #3");
  COMPARE(ands(w12, w13, Operand(w14, ROR, 4)), "ands w12, w13, w14, ror #4");

  COMPARE(bics(w15, w16, Operand(w17)), "bics w15, w16, w17");
  COMPARE(bics(x18, x19, Operand(x20, LSL, 5)), "bics x18, x19, x20, lsl #5");
  COMPARE(bics(w21, w22, Operand(w23, LSR, 6)), "bics w21, w22, w23, lsr #6");
  COMPARE(bics(x24, x25, Operand(x26, ASR, 7)), "bics x24, x25, x26, asr #7");
  COMPARE(bics(w27, w28, Operand(w29, ROR, 8)), "bics w27, w28, w29, ror #8");

  COMPARE(tst(w0, Operand(w1)), "tst w0, w1");
  COMPARE(tst(w2, Operand(w3, ROR, 10)), "tst w2, w3, ror #10");
  COMPARE(tst(x0, Operand(x1)), "tst x0, x1");
  COMPARE(tst(x2, Operand(x3, ROR, 42)), "tst x2, x3, ror #42");

  COMPARE(orn(w0, wzr, Operand(w1)), "mvn w0, w1");
  COMPARE(orn(w2, wzr, Operand(w3, ASR, 5)), "mvn w2, w3, asr #5");
  COMPARE(orn(x0, xzr, Operand(x1)), "mvn x0, x1");
  COMPARE(orn(x2, xzr, Operand(x3, ASR, 42)), "mvn x2, x3, asr #42");

  COMPARE(orr(w0, wzr, Operand(w1)), "mov w0, w1");
  COMPARE(orr(x0, xzr, Operand(x1)), "mov x0, x1");
  COMPARE(orr(w16, wzr, Operand(w17, LSL, 1)), "orr w16, wzr, w17, lsl #1");
  COMPARE(orr(x16, xzr, Operand(x17, ASR, 2)), "orr x16, xzr, x17, asr #2");

  CLEANUP();
}

TEST_F(DisasmArm64Test, dp_2_source) {
  SET_UP_ASM();

  COMPARE(lslv(w0, w1, w2), "lsl w0, w1, w2");
  COMPARE(lslv(x3, x4, x5), "lsl x3, x4, x5");
  COMPARE(lsrv(w6, w7, w8), "lsr w6, w7, w8");
  COMPARE(lsrv(x9, x10, x11), "lsr x9, x10, x11");
  COMPARE(asrv(w12, w13, w14), "asr w12, w13, w14");
  COMPARE(asrv(x15, x16, x17), "asr x15, x16, x17");
  COMPARE(rorv(w18, w19, w20), "ror w18, w19, w20");
  COMPARE(rorv(x21, x22, x23), "ror x21, x22, x23");

  CLEANUP();
}

TEST_F(DisasmArm64Test, adr) {
  SET_UP_ASM();

  char expected[100];
  snprintf(expected, sizeof(expected), "adr x0, #+0x0 (addr %p)", buf);
  COMPARE(adr(x0, 0), expected);
  snprintf(expected, sizeof(expected), "adr x0, #+0x1 (addr %p)", buf + 1);
  COMPARE(adr(x0, 1), expected);
  snprintf(expected, sizeof(expected), "adr x0, #-0x1 (addr %p)", buf - 1);
  COMPARE(adr(x0, -1), expected);
  COMPARE_PREFIX(adr(x0, 0), "adr x0, #+0x0");
  COMPARE_PREFIX(adr(x1, 1), "adr x1, #+0x1");
  COMPARE_PREFIX(adr(x2, -1), "adr x2, #-0x1");
  COMPARE_PREFIX(adr(x3, 4), "adr x3, #+0x4");
  COMPARE_PREFIX(adr(x4, -4), "adr x4, #-0x4");
  COMPARE_PREFIX(adr(x5, 0x000fffff), "adr x5, #+0xfffff");
  COMPARE_PREFIX(adr(x6, -0x00100000), "adr x6, #-0x100000");
  COMPARE_PREFIX(adr(xzr, 0), "adr xzr, #+0x0");

  CLEANUP();
}

TEST_F(DisasmArm64Test, branch) {
  SET_UP_ASM();

#define INST_OFF(x) ((x) >> kInstrSizeLog2)
  COMPARE_PREFIX(b(INST_OFF(0x4)), "b #+0x4");
  COMPARE_PREFIX(b(INST_OFF(-0x4)), "b #-0x4");
  COMPARE_PREFIX(b(INST_OFF(0x7fffffc)), "b #+0x7fffffc");
  COMPARE_PREFIX(b(INST_OFF(-0x8000000)), "b #-0x8000000");
  COMPARE_PREFIX(b(INST_OFF(0xffffc), eq), "b.eq #+0xffffc");
  COMPARE_PREFIX(b(INST_OFF(-0x100000), mi), "b.mi #-0x100000");
  COMPARE_PREFIX(bl(INST_OFF(0x4)), "bl #+0x4");
  COMPARE_PREFIX(bl(INST_OFF(-0x4)), "bl #-0x4");
  COMPARE_PREFIX(bl(INST_OFF(0xffffc)), "bl #+0xffffc");
  COMPARE_PREFIX(bl(INST_OFF(-0x100000)), "bl #-0x100000");
  COMPARE_PREFIX(cbz(w0, INST_OFF(0xffffc)), "cbz w0, #+0xffffc");
  COMPARE_PREFIX(cbz(x1, INST_OFF(-0x100000)), "cbz x1, #-0x100000");
  COMPARE_PREFIX(cbnz(w2, INST_OFF(0xffffc)), "cbnz w2, #+0xffffc");
  COMPARE_PREFIX(cbnz(x3, INST_OFF(-0x100000)), "cbnz x3, #-0x100000");
  COMPARE_PREFIX(tbz(w4, 0, INST_OFF(0x7ffc)), "tbz w4, #0, #+0x7ffc");
  COMPARE_PREFIX(tbz(x5, 63, INST_OFF(-0x8000)), "tbz x5, #63, #-0x8000");
  COMPARE_PREFIX(tbz(w6, 31, INST_OFF(0)), "tbz w6, #31, #+0x0");
  COMPARE_PREFIX(tbz(x7, 31, INST_OFF(0x4)), "tbz w7, #31, #+0x4");
  COMPARE_PREFIX(tbz(x8, 32, INST_OFF(0x8)), "tbz x8, #32, #+0x8");
  COMPARE_PREFIX(tbnz(w8, 0, INST_OFF(0x7ffc)), "tbnz w8, #0, #+0x7ffc");
  COMPARE_PREFIX(tbnz(x9, 63, INST_OFF(-0x8000)), "tbnz x9, #63, #-0x8000");
  COMPARE_PREFIX(tbnz(w10, 31, INST_OFF(0)), "tbnz w10, #31, #+0x0");
  COMPARE_PREFIX(tbnz(x11, 31, INST_OFF(0x4)), "tbnz w11, #31, #+0x4");
  COMPARE_PREFIX(tbnz(x12, 32, INST_OFF(0x8)), "tbnz x12, #32, #+0x8");
#undef INST_OFF
  COMPARE(br(x0), "br x0");
  COMPARE(blr(x1), "blr x1");
  COMPARE(ret(x2), "ret x2");
  COMPARE(ret(lr), "ret");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store) {
  SET_UP_ASM();

  COMPARE(ldr(w0, MemOperand(x1)), "ldr w0, [x1]");
  COMPARE(ldr(w2, MemOperand(x3, 4)), "ldr w2, [x3, #4]");
  COMPARE(ldr(w4, MemOperand(x5, 16380)), "ldr w4, [x5, #16380]");
  COMPARE(ldr(x6, MemOperand(x7)), "ldr x6, [x7]");
  COMPARE(ldr(x8, MemOperand(x9, 8)), "ldr x8, [x9, #8]");
  COMPARE(ldr(x10, MemOperand(x11, 32760)), "ldr x10, [x11, #32760]");
  COMPARE(str(w12, MemOperand(x13)), "str w12, [x13]");
  COMPARE(str(w14, MemOperand(x15, 4)), "str w14, [x15, #4]");
  COMPARE(str(w16, MemOperand(x17, 16380)), "str w16, [x17, #16380]");
  COMPARE(str(x18, MemOperand(x19)), "str x18, [x19]");
  COMPARE(str(x20, MemOperand(x21, 8)), "str x20, [x21, #8]");
  COMPARE(str(x22, MemOperand(x23, 32760)), "str x22, [x23, #32760]");

  COMPARE(ldr(w0, MemOperand(x1, 4, PreIndex)), "ldr w0, [x1, #4]!");
  COMPARE(ldr(w2, MemOperand(x3, 255, PreIndex)), "ldr w2, [x3, #255]!");
  COMPARE(ldr(w4, MemOperand(x5, -256, PreIndex)), "ldr w4, [x5, #-256]!");
  COMPARE(ldr(x6, MemOperand(x7, 8, PreIndex)), "ldr x6, [x7, #8]!");
  COMPARE(ldr(x8, MemOperand(x9, 255, PreIndex)), "ldr x8, [x9, #255]!");
  COMPARE(ldr(x10, MemOperand(x11, -256, PreIndex)), "ldr x10, [x11, #-256]!");
  COMPARE(str(w12, MemOperand(x13, 4, PreIndex)), "str w12, [x13, #4]!");
  COMPARE(str(w14, MemOperand(x15, 255, PreIndex)), "str w14, [x15, #255]!");
  COMPARE(str(w16, MemOperand(x17, -256, PreIndex)), "str w16, [x17, #-256]!");
  COMPARE(str(x18, MemOperand(x19, 8, PreIndex)), "str x18, [x19, #8]!");
  COMPARE(str(x20, MemOperand(x21, 255, PreIndex)), "str x20, [x21, #255]!");
  COMPARE(str(x22, MemOperand(x23, -256, PreIndex)), "str x22, [x23, #-256]!");

  COMPARE(ldr(w0, MemOperand(x1, 4, PostIndex)), "ldr w0, [x1], #4");
  COMPARE(ldr(w2, MemOperand(x3, 255, PostIndex)), "ldr w2, [x3], #255");
  COMPARE(ldr(w4, MemOperand(x5, -256, PostIndex)), "ldr w4, [x5], #-256");
  COMPARE(ldr(x6, MemOperand(x7, 8, PostIndex)), "ldr x6, [x7], #8");
  COMPARE(ldr(x8, MemOperand(x9, 255, PostIndex)), "ldr x8, [x9], #255");
  COMPARE(ldr(x10, MemOperand(x11, -256, PostIndex)), "ldr x10, [x11], #-256");
  COMPARE(str(w12, MemOperand(x13, 4, PostIndex)), "str w12, [x13], #4");
  COMPARE(str(w14, MemOperand(x15, 255, PostIndex)), "str w14, [x15], #255");
  COMPARE(str(w16, MemOperand(x17, -256, PostIndex)), "str w16, [x17], #-256");
  COMPARE(str(x18, MemOperand(x19, 8, PostIndex)), "str x18, [x19], #8");
  COMPARE(str(x20, MemOperand(x21, 255, PostIndex)), "str x20, [x21], #255");
  COMPARE(str(x22, MemOperand(x23, -256, PostIndex)), "str x22, [x23], #-256");

  COMPARE(ldr(w24, MemOperand(x28)), "ldr w24, [x28]");
  COMPARE(ldr(x25, MemOperand(x28, 8)), "ldr x25, [x28, #8]");
  COMPARE(str(w26, MemOperand(x28, 4, PreIndex)), "str w26, [x28, #4]!");
  COMPARE(str(cp, MemOperand(x28, -8, PostIndex)), "str cp, [x28], #-8");

  COMPARE(ldrsw(x0, MemOperand(x1)), "ldrsw x0, [x1]");
  COMPARE(ldrsw(x2, MemOperand(x3, 8)), "ldrsw x2, [x3, #8]");
  COMPARE(ldrsw(x4, MemOperand(x5, 42, PreIndex)), "ldrsw x4, [x5, #42]!");
  COMPARE(ldrsw(x6, MemOperand(x7, -11, PostIndex)), "ldrsw x6, [x7], #-11");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_regoffset) {
  SET_UP_ASM();

  COMPARE(ldr(w0, MemOperand(x1, w2, UXTW)), "ldr w0, [x1, w2, uxtw]");
  COMPARE(ldr(w3, MemOperand(x4, w5, UXTW, 2)), "ldr w3, [x4, w5, uxtw #2]");
  COMPARE(ldr(w6, MemOperand(x7, x8)), "ldr w6, [x7, x8]");
  COMPARE(ldr(w9, MemOperand(x10, x11, LSL, 2)), "ldr w9, [x10, x11, lsl #2]");
  COMPARE(ldr(w12, MemOperand(x13, w14, SXTW)), "ldr w12, [x13, w14, sxtw]");
  COMPARE(ldr(w15, MemOperand(x16, w17, SXTW, 2)),
          "ldr w15, [x16, w17, sxtw #2]");
  COMPARE(ldr(w18, MemOperand(x19, x20, SXTX)), "ldr w18, [x19, x20, sxtx]");
  COMPARE(ldr(w21, MemOperand(x22, x23, SXTX, 2)),
          "ldr w21, [x22, x23, sxtx #2]");
  COMPARE(ldr(x0, MemOperand(x1, w2, UXTW)), "ldr x0, [x1, w2, uxtw]");
  COMPARE(ldr(x3, MemOperand(x4, w5, UXTW, 3)), "ldr x3, [x4, w5, uxtw #3]");
  COMPARE(ldr(x6, MemOperand(x7, x8)), "ldr x6, [x7, x8]");
  COMPARE(ldr(x9, MemOperand(x10, x11, LSL, 3)), "ldr x9, [x10, x11, lsl #3]");
  COMPARE(ldr(x12, MemOperand(x13, w14, SXTW)), "ldr x12, [x13, w14, sxtw]");
  COMPARE(ldr(x15, MemOperand(x16, w17, SXTW, 3)),
          "ldr x15, [x16, w17, sxtw #3]");
  COMPARE(ldr(x18, MemOperand(x19, x20, SXTX)), "ldr x18, [x19, x20, sxtx]");
  COMPARE(ldr(x21, MemOperand(x22, x23, SXTX, 3)),
          "ldr x21, [x22, x23, sxtx #3]");

  COMPARE(str(w0, MemOperand(x1, w2, UXTW)), "str w0, [x1, w2, uxtw]");
  COMPARE(str(w3, MemOperand(x4, w5, UXTW, 2)), "str w3, [x4, w5, uxtw #2]");
  COMPARE(str(w6, MemOperand(x7, x8)), "str w6, [x7, x8]");
  COMPARE(str(w9, MemOperand(x10, x11, LSL, 2)), "str w9, [x10, x11, lsl #2]");
  COMPARE(str(w12, MemOperand(x13, w14, SXTW)), "str w12, [x13, w14, sxtw]");
  COMPARE(str(w15, MemOperand(x16, w17, SXTW, 2)),
          "str w15, [x16, w17, sxtw #2]");
  COMPARE(str(w18, MemOperand(x19, x20, SXTX)), "str w18, [x19, x20, sxtx]");
  COMPARE(str(w21, MemOperand(x22, x23, SXTX, 2)),
          "str w21, [x22, x23, sxtx #2]");
  COMPARE(str(x0, MemOperand(x1, w2, UXTW)), "str x0, [x1, w2, uxtw]");
  COMPARE(str(x3, MemOperand(x4, w5, UXTW, 3)), "str x3, [x4, w5, uxtw #3]");
  COMPARE(str(x6, MemOperand(x7, x8)), "str x6, [x7, x8]");
  COMPARE(str(x9, MemOperand(x10, x11, LSL, 3)), "str x9, [x10, x11, lsl #3]");
  COMPARE(str(x12, MemOperand(x13, w14, SXTW)), "str x12, [x13, w14, sxtw]");
  COMPARE(str(x15, MemOperand(x16, w17, SXTW, 3)),
          "str x15, [x16, w17, sxtw #3]");
  COMPARE(str(x18, MemOperand(x19, x20, SXTX)), "str x18, [x19, x20, sxtx]");
  COMPARE(str(x21, MemOperand(x22, x23, SXTX, 3)),
          "str x21, [x22, x23, sxtx #3]");

  COMPARE(ldrb(w0, MemOperand(x1, w2, UXTW)), "ldrb w0, [x1, w2, uxtw]");
  COMPARE(ldrb(w6, MemOperand(x7, x8)), "ldrb w6, [x7, x8]");
  COMPARE(ldrb(w12, MemOperand(x13, w14, SXTW)), "ldrb w12, [x13, w14, sxtw]");
  COMPARE(ldrb(w18, MemOperand(x19, x20, SXTX)), "ldrb w18, [x19, x20, sxtx]");
  COMPARE(strb(w0, MemOperand(x1, w2, UXTW)), "strb w0, [x1, w2, uxtw]");
  COMPARE(strb(w6, MemOperand(x7, x8)), "strb w6, [x7, x8]");
  COMPARE(strb(w12, MemOperand(x13, w14, SXTW)), "strb w12, [x13, w14, sxtw]");
  COMPARE(strb(w18, MemOperand(x19, x20, SXTX)), "strb w18, [x19, x20, sxtx]");

  COMPARE(ldrh(w0, MemOperand(x1, w2, UXTW)), "ldrh w0, [x1, w2, uxtw]");
  COMPARE(ldrh(w3, MemOperand(x4, w5, UXTW, 1)), "ldrh w3, [x4, w5, uxtw #1]");
  COMPARE(ldrh(w6, MemOperand(x7, x8)), "ldrh w6, [x7, x8]");
  COMPARE(ldrh(w9, MemOperand(x10, x11, LSL, 1)),
          "ldrh w9, [x10, x11, lsl #1]");
  COMPARE(ldrh(w12, MemOperand(x13, w14, SXTW)), "ldrh w12, [x13, w14, sxtw]");
  COMPARE(ldrh(w15, MemOperand(x16, w17, SXTW, 1)),
          "ldrh w15, [x16, w17, sxtw #1]");
  COMPARE(ldrh(w18, MemOperand(x19, x20, SXTX)), "ldrh w18, [x19, x20, sxtx]");
  COMPARE(ldrh(w21, MemOperand(x22, x23, SXTX, 1)),
          "ldrh w21, [x22, x23, sxtx #1]");
  COMPARE(strh(w0, MemOperand(x1, w2, UXTW)), "strh w0, [x1, w2, uxtw]");
  COMPARE(strh(w3, MemOperand(x4, w5, UXTW, 1)), "strh w3, [x4, w5, uxtw #1]");
  COMPARE(strh(w6, MemOperand(x7, x8)), "strh w6, [x7, x8]");
  COMPARE(strh(w9, MemOperand(x10, x11, LSL, 1)),
          "strh w9, [x10, x11, lsl #1]");
  COMPARE(strh(w12, MemOperand(x13, w14, SXTW)), "strh w12, [x13, w14, sxtw]");
  COMPARE(strh(w15, MemOperand(x16, w17, SXTW, 1)),
          "strh w15, [x16, w17, sxtw #1]");
  COMPARE(strh(w18, MemOperand(x19, x20, SXTX)), "strh w18, [x19, x20, sxtx]");
  COMPARE(strh(w21, MemOperand(x22, x23, SXTX, 1)),
          "strh w21, [x22, x23, sxtx #1]");

  COMPARE(ldr(x0, MemOperand(x28, wzr, SXTW)), "ldr x0, [x28, wzr, sxtw]");
  COMPARE(str(x1, MemOperand(x28, xzr)), "str x1, [x28, xzr]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_byte) {
  SET_UP_ASM();

  COMPARE(ldrb(w0, MemOperand(x1)), "ldrb w0, [x1]");
  COMPARE(ldrb(x2, MemOperand(x3)), "ldrb w2, [x3]");
  COMPARE(ldrb(w4, MemOperand(x5, 4095)), "ldrb w4, [x5, #4095]");
  COMPARE(ldrb(w6, MemOperand(x7, 255, PreIndex)), "ldrb w6, [x7, #255]!");
  COMPARE(ldrb(w8, MemOperand(x9, -256, PreIndex)), "ldrb w8, [x9, #-256]!");
  COMPARE(ldrb(w10, MemOperand(x11, 255, PostIndex)), "ldrb w10, [x11], #255");
  COMPARE(ldrb(w12, MemOperand(x13, -256, PostIndex)),
          "ldrb w12, [x13], #-256");
  COMPARE(strb(w14, MemOperand(x15)), "strb w14, [x15]");
  COMPARE(strb(x16, MemOperand(x17)), "strb w16, [x17]");
  COMPARE(strb(w18, MemOperand(x19, 4095)), "strb w18, [x19, #4095]");
  COMPARE(strb(w20, MemOperand(x21, 255, PreIndex)), "strb w20, [x21, #255]!");
  COMPARE(strb(w22, MemOperand(x23, -256, PreIndex)),
          "strb w22, [x23, #-256]!");
  COMPARE(strb(w24, MemOperand(x25, 255, PostIndex)), "strb w24, [x25], #255");
  COMPARE(strb(w26, MemOperand(cp, -256, PostIndex)), "strb w26, [cp], #-256");
  COMPARE(ldrb(w28, MemOperand(x28, 3, PostIndex)), "ldrb w28, [x28], #3");
  COMPARE(strb(fp, MemOperand(x28, -42, PreIndex)), "strb w29, [x28, #-42]!");
  COMPARE(ldrsb(w0, MemOperand(x1)), "ldrsb w0, [x1]");
  COMPARE(ldrsb(x2, MemOperand(x3, 8)), "ldrsb x2, [x3, #8]");
  COMPARE(ldrsb(w4, MemOperand(x5, 42, PreIndex)), "ldrsb w4, [x5, #42]!");
  COMPARE(ldrsb(x6, MemOperand(x7, -11, PostIndex)), "ldrsb x6, [x7], #-11");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_half) {
  SET_UP_ASM();

  COMPARE(ldrh(w0, MemOperand(x1)), "ldrh w0, [x1]");
  COMPARE(ldrh(x2, MemOperand(x3)), "ldrh w2, [x3]");
  COMPARE(ldrh(w4, MemOperand(x5, 8190)), "ldrh w4, [x5, #8190]");
  COMPARE(ldrh(w6, MemOperand(x7, 255, PreIndex)), "ldrh w6, [x7, #255]!");
  COMPARE(ldrh(w8, MemOperand(x9, -256, PreIndex)), "ldrh w8, [x9, #-256]!");
  COMPARE(ldrh(w10, MemOperand(x11, 255, PostIndex)), "ldrh w10, [x11], #255");
  COMPARE(ldrh(w12, MemOperand(x13, -256, PostIndex)),
          "ldrh w12, [x13], #-256");
  COMPARE(strh(w14, MemOperand(x15)), "strh w14, [x15]");
  COMPARE(strh(x16, MemOperand(x17)), "strh w16, [x17]");
  COMPARE(strh(w18, MemOperand(x19, 8190)), "strh w18, [x19, #8190]");
  COMPARE(strh(w20, MemOperand(x21, 255, PreIndex)), "strh w20, [x21, #255]!");
  COMPARE(strh(w22, MemOperand(x23, -256, PreIndex)),
          "strh w22, [x23, #-256]!");
  COMPARE(strh(w24, MemOperand(x25, 255, PostIndex)), "strh w24, [x25], #255");
  COMPARE(strh(w26, MemOperand(cp, -256, PostIndex)), "strh w26, [cp], #-256");
  COMPARE(ldrh(w28, MemOperand(x28, 3, PostIndex)), "ldrh w28, [x28], #3");
  COMPARE(strh(fp, MemOperand(x28, -42, PreIndex)), "strh w29, [x28, #-42]!");
  COMPARE(ldrh(w30, MemOperand(x0, 255)), "ldurh w30, [x0, #255]");
  COMPARE(ldrh(x1, MemOperand(x2, -256)), "ldurh w1, [x2, #-256]");
  COMPARE(strh(w3, MemOperand(x4, 255)), "sturh w3, [x4, #255]");
  COMPARE(strh(x5, MemOperand(x6, -256)), "sturh w5, [x6, #-256]");
  COMPARE(ldrsh(w0, MemOperand(x1)), "ldrsh w0, [x1]");
  COMPARE(ldrsh(w2, MemOperand(x3, 8)), "ldrsh w2, [x3, #8]");
  COMPARE(ldrsh(w4, MemOperand(x5, 42, PreIndex)), "ldrsh w4, [x5, #42]!");
  COMPARE(ldrsh(x6, MemOperand(x7, -11, PostIndex)), "ldrsh x6, [x7], #-11");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_v_offset) {
  SET_UP_ASM();

  COMPARE(ldr(s0, MemOperand(x1)), "ldr s0, [x1]");
  COMPARE(ldr(s2, MemOperand(x3, 4)), "ldr s2, [x3, #4]");
  COMPARE(ldr(s4, MemOperand(x5, 16380)), "ldr s4, [x5, #16380]");
  COMPARE(ldr(d6, MemOperand(x7)), "ldr d6, [x7]");
  COMPARE(ldr(d8, MemOperand(x9, 8)), "ldr d8, [x9, #8]");
  COMPARE(ldr(d10, MemOperand(x11, 32760)), "ldr d10, [x11, #32760]");
  COMPARE(str(s12, MemOperand(x13)), "str s12, [x13]");
  COMPARE(str(s14, MemOperand(x15, 4)), "str s14, [x15, #4]");
  COMPARE(str(s16, MemOperand(x17, 16380)), "str s16, [x17, #16380]");
  COMPARE(str(d18, MemOperand(x19)), "str d18, [x19]");
  COMPARE(str(d20, MemOperand(x21, 8)), "str d20, [x21, #8]");
  COMPARE(str(d22, MemOperand(x23, 32760)), "str d22, [x23, #32760]");

  COMPARE(ldr(b0, MemOperand(x1)), "ldr b0, [x1]");
  COMPARE(ldr(b2, MemOperand(x3, 1)), "ldr b2, [x3, #1]");
  COMPARE(ldr(b4, MemOperand(x5, 4095)), "ldr b4, [x5, #4095]");
  COMPARE(ldr(h6, MemOperand(x7)), "ldr h6, [x7]");
  COMPARE(ldr(h8, MemOperand(x9, 2)), "ldr h8, [x9, #2]");
  COMPARE(ldr(h10, MemOperand(x11, 8190)), "ldr h10, [x11, #8190]");
  COMPARE(ldr(q12, MemOperand(x13)), "ldr q12, [x13]");
  COMPARE(ldr(q14, MemOperand(x15, 16)), "ldr q14, [x15, #16]");
  COMPARE(ldr(q16, MemOperand(x17, 65520)), "ldr q16, [x17, #65520]");
  COMPARE(str(b18, MemOperand(x19)), "str b18, [x19]");
  COMPARE(str(b20, MemOperand(x21, 1)), "str b20, [x21, #1]");
  COMPARE(str(b22, MemOperand(x23, 4095)), "str b22, [x23, #4095]");
  COMPARE(str(h24, MemOperand(x25)), "str h24, [x25]");
  COMPARE(str(h26, MemOperand(x27, 2)), "str h26, [cp, #2]");
  COMPARE(str(h28, MemOperand(x29, 8190)), "str h28, [fp, #8190]");
  COMPARE(str(q30, MemOperand(x30)), "str q30, [lr]");
  COMPARE(str(q31, MemOperand(x1, 16)), "str q31, [x1, #16]");
  COMPARE(str(q0, MemOperand(x3, 65520)), "str q0, [x3, #65520]");

  COMPARE(ldr(s24, MemOperand(sp)), "ldr s24, [sp]");
  COMPARE(ldr(d25, MemOperand(sp, 8)), "ldr d25, [sp, #8]");
  COMPARE(ldr(b26, MemOperand(sp, 1)), "ldr b26, [sp, #1]");
  COMPARE(ldr(h27, MemOperand(sp, 2)), "ldr h27, [sp, #2]");
  COMPARE(ldr(q28, MemOperand(sp, 16)), "ldr q28, [sp, #16]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_v_pre) {
  SET_UP_ASM();

  COMPARE(ldr(s0, MemOperand(x1, 4, PreIndex)), "ldr s0, [x1, #4]!");
  COMPARE(ldr(s2, MemOperand(x3, 255, PreIndex)), "ldr s2, [x3, #255]!");
  COMPARE(ldr(s4, MemOperand(x5, -256, PreIndex)), "ldr s4, [x5, #-256]!");
  COMPARE(ldr(d6, MemOperand(x7, 8, PreIndex)), "ldr d6, [x7, #8]!");
  COMPARE(ldr(d8, MemOperand(x9, 255, PreIndex)), "ldr d8, [x9, #255]!");
  COMPARE(ldr(d10, MemOperand(x11, -256, PreIndex)), "ldr d10, [x11, #-256]!");

  COMPARE(str(s12, MemOperand(x13, 4, PreIndex)), "str s12, [x13, #4]!");
  COMPARE(str(s14, MemOperand(x15, 255, PreIndex)), "str s14, [x15, #255]!");
  COMPARE(str(s16, MemOperand(x17, -256, PreIndex)), "str s16, [x17, #-256]!");
  COMPARE(str(d18, MemOperand(x19, 8, PreIndex)), "str d18, [x19, #8]!");
  COMPARE(str(d20, MemOperand(x21, 255, PreIndex)), "str d20, [x21, #255]!");
  COMPARE(str(d22, MemOperand(x23, -256, PreIndex)), "str d22, [x23, #-256]!");

  COMPARE(ldr(b0, MemOperand(x1, 1, PreIndex)), "ldr b0, [x1, #1]!");
  COMPARE(ldr(b2, MemOperand(x3, 255, PreIndex)), "ldr b2, [x3, #255]!");
  COMPARE(ldr(b4, MemOperand(x5, -256, PreIndex)), "ldr b4, [x5, #-256]!");
  COMPARE(ldr(h6, MemOperand(x7, 2, PreIndex)), "ldr h6, [x7, #2]!");
  COMPARE(ldr(h8, MemOperand(x9, 255, PreIndex)), "ldr h8, [x9, #255]!");
  COMPARE(ldr(h10, MemOperand(x11, -256, PreIndex)), "ldr h10, [x11, #-256]!");
  COMPARE(ldr(q12, MemOperand(x13, 16, PreIndex)), "ldr q12, [x13, #16]!");
  COMPARE(ldr(q14, MemOperand(x15, 255, PreIndex)), "ldr q14, [x15, #255]!");
  COMPARE(ldr(q16, MemOperand(x17, -256, PreIndex)), "ldr q16, [x17, #-256]!");

  COMPARE(str(b18, MemOperand(x19, 1, PreIndex)), "str b18, [x19, #1]!");
  COMPARE(str(b20, MemOperand(x21, 255, PreIndex)), "str b20, [x21, #255]!");
  COMPARE(str(b22, MemOperand(x23, -256, PreIndex)), "str b22, [x23, #-256]!");
  COMPARE(str(h24, MemOperand(x25, 2, PreIndex)), "str h24, [x25, #2]!");
  COMPARE(str(h26, MemOperand(x27, 255, PreIndex)), "str h26, [cp, #255]!");
  COMPARE(str(h28, MemOperand(x29, -256, PreIndex)), "str h28, [fp, #-256]!");
  COMPARE(str(q30, MemOperand(x1, 16, PreIndex)), "str q30, [x1, #16]!");
  COMPARE(str(q31, MemOperand(x3, 255, PreIndex)), "str q31, [x3, #255]!");
  COMPARE(str(q0, MemOperand(x5, -256, PreIndex)), "str q0, [x5, #-256]!");

  COMPARE(str(b24, MemOperand(sp, 1, PreIndex)), "str b24, [sp, #1]!");
  COMPARE(str(h25, MemOperand(sp, -2, PreIndex)), "str h25, [sp, #-2]!");
  COMPARE(str(s26, MemOperand(sp, 4, PreIndex)), "str s26, [sp, #4]!");
  COMPARE(str(d27, MemOperand(sp, -8, PreIndex)), "str d27, [sp, #-8]!");
  COMPARE(str(q28, MemOperand(sp, 16, PreIndex)), "str q28, [sp, #16]!");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_v_post) {
  SET_UP_ASM();

  COMPARE(ldr(s0, MemOperand(x1, 4, PostIndex)), "ldr s0, [x1], #4");
  COMPARE(ldr(s2, MemOperand(x3, 255, PostIndex)), "ldr s2, [x3], #255");
  COMPARE(ldr(s4, MemOperand(x5, -256, PostIndex)), "ldr s4, [x5], #-256");
  COMPARE(ldr(d6, MemOperand(x7, 8, PostIndex)), "ldr d6, [x7], #8");
  COMPARE(ldr(d8, MemOperand(x9, 255, PostIndex)), "ldr d8, [x9], #255");
  COMPARE(ldr(d10, MemOperand(x11, -256, PostIndex)), "ldr d10, [x11], #-256");

  COMPARE(str(s12, MemOperand(x13, 4, PostIndex)), "str s12, [x13], #4");
  COMPARE(str(s14, MemOperand(x15, 255, PostIndex)), "str s14, [x15], #255");
  COMPARE(str(s16, MemOperand(x17, -256, PostIndex)), "str s16, [x17], #-256");
  COMPARE(str(d18, MemOperand(x19, 8, PostIndex)), "str d18, [x19], #8");
  COMPARE(str(d20, MemOperand(x21, 255, PostIndex)), "str d20, [x21], #255");
  COMPARE(str(d22, MemOperand(x23, -256, PostIndex)), "str d22, [x23], #-256");

  COMPARE(ldr(b0, MemOperand(x1, 4, PostIndex)), "ldr b0, [x1], #4");
  COMPARE(ldr(b2, MemOperand(x3, 255, PostIndex)), "ldr b2, [x3], #255");
  COMPARE(ldr(b4, MemOperand(x5, -256, PostIndex)), "ldr b4, [x5], #-256");
  COMPARE(ldr(h6, MemOperand(x7, 8, PostIndex)), "ldr h6, [x7], #8");
  COMPARE(ldr(h8, MemOperand(x9, 255, PostIndex)), "ldr h8, [x9], #255");
  COMPARE(ldr(h10, MemOperand(x11, -256, PostIndex)), "ldr h10, [x11], #-256");
  COMPARE(ldr(q12, MemOperand(x13, 8, PostIndex)), "ldr q12, [x13], #8");
  COMPARE(ldr(q14, MemOperand(x15, 255, PostIndex)), "ldr q14, [x15], #255");
  COMPARE(ldr(q16, MemOperand(x17, -256, PostIndex)), "ldr q16, [x17], #-256");

  COMPARE(str(b18, MemOperand(x19, 4, PostIndex)), "str b18, [x19], #4");
  COMPARE(str(b20, MemOperand(x21, 255, PostIndex)), "str b20, [x21], #255");
  COMPARE(str(b22, MemOperand(x23, -256, PostIndex)), "str b22, [x23], #-256");
  COMPARE(str(h24, MemOperand(x25, 8, PostIndex)), "str h24, [x25], #8");
  COMPARE(str(h26, MemOperand(x27, 255, PostIndex)), "str h26, [cp], #255");
  COMPARE(str(h28, MemOperand(x29, -256, PostIndex)), "str h28, [fp], #-256");
  COMPARE(str(q30, MemOperand(x1, 8, PostIndex)), "str q30, [x1], #8");
  COMPARE(str(q31, MemOperand(x3, 255, PostIndex)), "str q31, [x3], #255");
  COMPARE(str(q0, MemOperand(x5, -256, PostIndex)), "str q0, [x5], #-256");

  COMPARE(ldr(b24, MemOperand(sp, -1, PreIndex)), "ldr b24, [sp, #-1]!");
  COMPARE(ldr(h25, MemOperand(sp, 2, PreIndex)), "ldr h25, [sp, #2]!");
  COMPARE(ldr(s26, MemOperand(sp, -4, PreIndex)), "ldr s26, [sp, #-4]!");
  COMPARE(ldr(d27, MemOperand(sp, 8, PreIndex)), "ldr d27, [sp, #8]!");
  COMPARE(ldr(q28, MemOperand(sp, -16, PreIndex)), "ldr q28, [sp, #-16]!");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_v_regoffset) {
  SET_UP_ASM();

  COMPARE(ldr(b0, MemOperand(x1, x2)), "ldr b0, [x1, x2]");
  COMPARE(ldr(b1, MemOperand(x2, w3, UXTW)), "ldr b1, [x2, w3, uxtw]");
  COMPARE(ldr(b2, MemOperand(x3, w4, SXTW)), "ldr b2, [x3, w4, sxtw]");
  // We can't assemble this instruction, but we check it disassembles correctly.
  COMPARE(dci(0x3c657883), "ldr b3, [x4, x5, lsl #0]");
  COMPARE(ldr(b30, MemOperand(sp, xzr)), "ldr b30, [sp, xzr]");
  COMPARE(ldr(b31, MemOperand(sp, wzr, UXTW)), "ldr b31, [sp, wzr, uxtw]");

  COMPARE(ldr(h0, MemOperand(x1, x2)), "ldr h0, [x1, x2]");
  COMPARE(ldr(h1, MemOperand(x2, w3, UXTW)), "ldr h1, [x2, w3, uxtw]");
  COMPARE(ldr(h2, MemOperand(x3, w4, SXTW)), "ldr h2, [x3, w4, sxtw]");
  COMPARE(ldr(h3, MemOperand(x4, w5, UXTW, 1)), "ldr h3, [x4, w5, uxtw #1]");
  COMPARE(ldr(h4, MemOperand(x5, w5, SXTW, 1)), "ldr h4, [x5, w5, sxtw #1]");
  COMPARE(ldr(h30, MemOperand(sp, xzr)), "ldr h30, [sp, xzr]");
  COMPARE(ldr(h31, MemOperand(sp, wzr, SXTW, 1)),
          "ldr h31, [sp, wzr, sxtw #1]");

  COMPARE(ldr(s0, MemOperand(x1, x2)), "ldr s0, [x1, x2]");
  COMPARE(ldr(s1, MemOperand(x2, w3, UXTW)), "ldr s1, [x2, w3, uxtw]");
  COMPARE(ldr(s2, MemOperand(x3, w4, SXTW)), "ldr s2, [x3, w4, sxtw]");
  COMPARE(ldr(s3, MemOperand(x4, w5, UXTW, 2)), "ldr s3, [x4, w5, uxtw #2]");
  COMPARE(ldr(s4, MemOperand(x5, w5, SXTW, 2)), "ldr s4, [x5, w5, sxtw #2]");
  COMPARE(ldr(s30, MemOperand(sp, xzr)), "ldr s30, [sp, xzr]");
  COMPARE(ldr(s31, MemOperand(sp, wzr, SXTW, 2)),
          "ldr s31, [sp, wzr, sxtw #2]");

  COMPARE(ldr(d0, MemOperand(x1, x2)), "ldr d0, [x1, x2]");
  COMPARE(ldr(d1, MemOperand(x2, w3, UXTW)), "ldr d1, [x2, w3, uxtw]");
  COMPARE(ldr(d2, MemOperand(x3, w4, SXTW)), "ldr d2, [x3, w4, sxtw]");
  COMPARE(ldr(d3, MemOperand(x4, w5, UXTW, 3)), "ldr d3, [x4, w5, uxtw #3]");
  COMPARE(ldr(d4, MemOperand(x5, w5, SXTW, 3)), "ldr d4, [x5, w5, sxtw #3]");
  COMPARE(ldr(d30, MemOperand(sp, xzr)), "ldr d30, [sp, xzr]");
  COMPARE(ldr(d31, MemOperand(sp, wzr, SXTW, 3)),
          "ldr d31, [sp, wzr, sxtw #3]");

  COMPARE(ldr(q0, MemOperand(x1, x2)), "ldr q0, [x1, x2]");
  COMPARE(ldr(q1, MemOperand(x2, w3, UXTW)), "ldr q1, [x2, w3, uxtw]");
  COMPARE(ldr(q2, MemOperand(x3, w4, SXTW)), "ldr q2, [x3, w4, sxtw]");
  COMPARE(ldr(q3, MemOperand(x4, w5, UXTW, 4)), "ldr q3, [x4, w5, uxtw #4]");
  COMPARE(ldr(q4, MemOperand(x5, w5, SXTW, 4)), "ldr q4, [x5, w5, sxtw #4]");
  COMPARE(ldr(q30, MemOperand(sp, xzr)), "ldr q30, [sp, xzr]");
  COMPARE(ldr(q31, MemOperand(sp, wzr, SXTW, 4)),
          "ldr q31, [sp, wzr, sxtw #4]");

  COMPARE(str(b0, MemOperand(x1, x2)), "str b0, [x1, x2]");
  COMPARE(str(b1, MemOperand(x2, w3, UXTW)), "str b1, [x2, w3, uxtw]");
  COMPARE(str(b2, MemOperand(x3, w4, SXTW)), "str b2, [x3, w4, sxtw]");
  // We can't assemble this instruction, but we check it disassembles correctly.
  COMPARE(dci(0x3c257883), "str b3, [x4, x5, lsl #0]");
  COMPARE(str(b30, MemOperand(sp, xzr)), "str b30, [sp, xzr]");
  COMPARE(str(b31, MemOperand(sp, wzr, UXTW)), "str b31, [sp, wzr, uxtw]");

  COMPARE(str(h0, MemOperand(x1, x2)), "str h0, [x1, x2]");
  COMPARE(str(h1, MemOperand(x2, w3, UXTW)), "str h1, [x2, w3, uxtw]");
  COMPARE(str(h2, MemOperand(x3, w4, SXTW)), "str h2, [x3, w4, sxtw]");
  COMPARE(str(h3, MemOperand(x4, w5, UXTW, 1)), "str h3, [x4, w5, uxtw #1]");
  COMPARE(str(h4, MemOperand(x5, w5, SXTW, 1)), "str h4, [x5, w5, sxtw #1]");
  COMPARE(str(h30, MemOperand(sp, xzr)), "str h30, [sp, xzr]");
  COMPARE(str(h31, MemOperand(sp, wzr, SXTW, 1)),
          "str h31, [sp, wzr, sxtw #1]");

  COMPARE(str(s0, MemOperand(x1, x2)), "str s0, [x1, x2]");
  COMPARE(str(s1, MemOperand(x2, w3, UXTW)), "str s1, [x2, w3, uxtw]");
  COMPARE(str(s2, MemOperand(x3, w4, SXTW)), "str s2, [x3, w4, sxtw]");
  COMPARE(str(s3, MemOperand(x4, w5, UXTW, 2)), "str s3, [x4, w5, uxtw #2]");
  COMPARE(str(s4, MemOperand(x5, w5, SXTW, 2)), "str s4, [x5, w5, sxtw #2]");
  COMPARE(str(s30, MemOperand(sp, xzr)), "str s30, [sp, xzr]");
  COMPARE(str(s31, MemOperand(sp, wzr, SXTW, 2)),
          "str s31, [sp, wzr, sxtw #2]");

  COMPARE(str(d0, MemOperand(x1, x2)), "str d0, [x1, x2]");
  COMPARE(str(d1, MemOperand(x2, w3, UXTW)), "str d1, [x2, w3, uxtw]");
  COMPARE(str(d2, MemOperand(x3, w4, SXTW)), "str d2, [x3, w4, sxtw]");
  COMPARE(str(d3, MemOperand(x4, w5, UXTW, 3)), "str d3, [x4, w5, uxtw #3]");
  COMPARE(str(d4, MemOperand(x5, w5, SXTW, 3)), "str d4, [x5, w5, sxtw #3]");
  COMPARE(str(d30, MemOperand(sp, xzr)), "str d30, [sp, xzr]");
  COMPARE(str(d31, MemOperand(sp, wzr, SXTW, 3)),
          "str d31, [sp, wzr, sxtw #3]");

  COMPARE(str(q0, MemOperand(x1, x2)), "str q0, [x1, x2]");
  COMPARE(str(q1, MemOperand(x2, w3, UXTW)), "str q1, [x2, w3, uxtw]");
  COMPARE(str(q2, MemOperand(x3, w4, SXTW)), "str q2, [x3, w4, sxtw]");
  COMPARE(str(q3, MemOperand(x4, w5, UXTW, 4)), "str q3, [x4, w5, uxtw #4]");
  COMPARE(str(q4, MemOperand(x5, w5, SXTW, 4)), "str q4, [x5, w5, sxtw #4]");
  COMPARE(str(q30, MemOperand(sp, xzr)), "str q30, [sp, xzr]");
  COMPARE(str(q31, MemOperand(sp, wzr, SXTW, 4)),
          "str q31, [sp, wzr, sxtw #4]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_unscaled) {
  SET_UP_ASM();

  COMPARE(ldr(w0, MemOperand(x1, 1)), "ldur w0, [x1, #1]");
  COMPARE(ldr(w2, MemOperand(x3, -1)), "ldur w2, [x3, #-1]");
  COMPARE(ldr(w4, MemOperand(x5, 255)), "ldur w4, [x5, #255]");
  COMPARE(ldr(w6, MemOperand(x7, -256)), "ldur w6, [x7, #-256]");
  COMPARE(ldr(x8, MemOperand(x9, 1)), "ldur x8, [x9, #1]");
  COMPARE(ldr(x10, MemOperand(x11, -1)), "ldur x10, [x11, #-1]");
  COMPARE(ldr(x12, MemOperand(x13, 255)), "ldur x12, [x13, #255]");
  COMPARE(ldr(x14, MemOperand(x15, -256)), "ldur x14, [x15, #-256]");
  COMPARE(str(w16, MemOperand(x17, 1)), "stur w16, [x17, #1]");
  COMPARE(str(w18, MemOperand(x19, -1)), "stur w18, [x19, #-1]");
  COMPARE(str(w20, MemOperand(x21, 255)), "stur w20, [x21, #255]");
  COMPARE(str(w22, MemOperand(x23, -256)), "stur w22, [x23, #-256]");
  COMPARE(str(x24, MemOperand(x25, 1)), "stur x24, [x25, #1]");
  COMPARE(str(x26, MemOperand(x27, -1)), "stur x26, [cp, #-1]");
  COMPARE(str(x28, MemOperand(x29, 255)), "stur x28, [fp, #255]");
  COMPARE(str(x30, MemOperand(x0, -256)), "stur lr, [x0, #-256]");
  COMPARE(ldr(w0, MemOperand(sp, 1)), "ldur w0, [sp, #1]");
  COMPARE(str(x1, MemOperand(sp, -1)), "stur x1, [sp, #-1]");
  COMPARE(ldrb(w2, MemOperand(x3, -2)), "ldurb w2, [x3, #-2]");
  COMPARE(ldrsb(w4, MemOperand(x5, -3)), "ldursb w4, [x5, #-3]");
  COMPARE(ldrsb(x6, MemOperand(x7, -4)), "ldursb x6, [x7, #-4]");
  COMPARE(ldrh(w8, MemOperand(x9, -5)), "ldurh w8, [x9, #-5]");
  COMPARE(ldrsh(w10, MemOperand(x11, -6)), "ldursh w10, [x11, #-6]");
  COMPARE(ldrsh(x12, MemOperand(x13, -7)), "ldursh x12, [x13, #-7]");
  COMPARE(ldrsw(x14, MemOperand(x15, -8)), "ldursw x14, [x15, #-8]");

  COMPARE(ldr(b0, MemOperand(x1, -1)), "ldur b0, [x1, #-1]");
  COMPARE(ldr(h2, MemOperand(x3, -1)), "ldur h2, [x3, #-1]");
  COMPARE(ldr(s4, MemOperand(x5, 255)), "ldur s4, [x5, #255]");
  COMPARE(ldr(d6, MemOperand(x7, -256)), "ldur d6, [x7, #-256]");
  COMPARE(ldr(q8, MemOperand(x9, 1)), "ldur q8, [x9, #1]");
  COMPARE(str(b16, MemOperand(x17, -1)), "stur b16, [x17, #-1]");
  COMPARE(str(h18, MemOperand(x19, -1)), "stur h18, [x19, #-1]");
  COMPARE(str(s20, MemOperand(x21, 255)), "stur s20, [x21, #255]");
  COMPARE(str(d22, MemOperand(x23, -256)), "stur d22, [x23, #-256]");
  COMPARE(str(q24, MemOperand(x25, 1)), "stur q24, [x25, #1]");

  CLEANUP();
}

TEST_F(DisasmArm64Test, load_store_pair) {
  SET_UP_ASM();

  COMPARE(ldp(w0, w1, MemOperand(x2)), "ldp w0, w1, [x2]");
  COMPARE(ldp(x3, x4, MemOperand(x5)), "ldp x3, x4, [x5]");
  COMPARE(ldp(w6, w7, MemOperand(x8, 4)), "ldp w6, w7, [x8, #4]");
  COMPARE(ldp(x9, x10, MemOperand(x11, 8)), "ldp x9, x10, [x11, #8]");
  COMPARE(ldp(w12, w13, MemOperand(x14, 252)), "ldp w12, w13, [x14, #252]");
  COMPARE(ldp(x15, x16, MemOperand(x17, 504)), "ldp x15, x16, [x17, #504]");
  COMPARE(ldp(w18, w19, MemOperand(x20, -256)), "ldp w18, w19, [x20, #-256]");
  COMPARE(ldp(x21, x22, MemOperand(x23, -512)), "ldp x21, x22, [x23, #-512]");
  COMPARE(ldp(w24, w25, MemOperand(x26, 252, PreIndex)),
          "ldp w24, w25, [x26, #252]!");
  COMPARE(ldp(cp, x28, MemOperand(fp, 504, PreIndex)),
          "ldp cp, x28, [fp, #504]!");
  COMPARE(ldp(w30, w0, MemOperand(x1, -256, PreIndex)),
          "ldp w30, w0, [x1, #-256]!");
  COMPARE(ldp(x2, x3, MemOperand(x4, -512, PreIndex)),
          "ldp x2, x3, [x4, #-512]!");
  COMPARE(ldp(w5, w6, MemOperand(x7, 252, PostIndex)),
          "ldp w5, w6, [x7], #252");
  COMPARE(ldp(x8, x9, MemOperand(x10, 504, PostIndex)),
          "ldp x8, x9, [x10], #504");
  COMPARE(ldp(w11, w12, MemOperand(x13, -256, PostIndex)),
          "ldp w11, w12, [x13], #-256");
  COMPARE(ldp(x14, x15, MemOperand(x16, -512, PostIndex)),
          "ldp x14, x15, [x16], #-512");

  COMPARE(ldp(s17, s18, MemOperand(x19)), "ldp s17, s18, [x19]");
  COMPARE(ldp(s20, s21, MemOperand(x22, 252)), "ldp s20, s21, [x22, #252]");
  COMPARE(ldp(s23, s24, MemOperand(x25, -256)), "ldp s23, s24, [x25, #-256]");
  COMPARE(ldp(s26, s27, MemOperand(x28, 252, PreIndex)),
          "ldp s26, s27, [x28, #252]!");
"""


```