Response:
The user wants to understand the functionality of the C++ code in `v8/test/cctest/wasm/test-run-wasm.cc`. They have several specific questions about the code. I need to go through the code and address each of these points.

1. **List the functionalities:** I need to identify the main purpose and different test cases covered in the code. It appears to be testing various WebAssembly instructions and their behavior within the V8 engine.

2. **Check for Torque source:**  I need to see if the filename ends with `.tq`. In this case, it ends with `.cc`, so it's not a Torque file.

3. **Relation to Javascript and examples:** I need to determine if the tested WebAssembly functionalities have corresponding features in Javascript and provide examples if they do. Wasm operations often have direct or analogous Javascript operations.

4. **Code logic reasoning with input/output:** For specific test cases, I need to analyze the WebAssembly code, predict the output given certain inputs, and explain the reasoning.

5. **Common programming errors:** I need to identify test cases that might highlight common programming mistakes users could make when writing WebAssembly or interacting with it.

6. **Summarize the functionality:** Finally, I need to provide a concise summary of the overall purpose of the code based on the identified functionalities.

**Plan:**
- Read through the code and identify the different `WASM_EXEC_TEST` macros. Each of these represents a test case.
- For each test case, determine the WebAssembly instruction(s) being tested.
- Analyze the input values and expected output for each test.
- If a test case relates to a Javascript feature, provide an equivalent Javascript example.
- Identify test cases that demonstrate potential pitfalls or common errors.
- Group similar functionalities and summarize the overall purpose.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "src/base/overflowing-math.h"
#include "src/utils/utils.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8::internal::wasm {

// for even shorter tests.
#define B1(a) WASM_BLOCK(a)
#define B2(a, b) WASM_BLOCK(a, b)
#define RET(x) x, kExprReturn
#define RET_I8(x) WASM_I32V_2(x), kExprReturn

WASM_EXEC_TEST(Int32Const) {
  WasmRunner<int32_t> r(execution_tier);
  const int32_t kExpectedValue = 0x11223344;
  // return(kExpectedValue)
  r.Build({WASM_I32V_5(kExpectedValue)});
  CHECK_EQ(kExpectedValue, r.Call());
}

WASM_EXEC_TEST(Int32Const_many) {
  FOR_INT32_INPUTS(i) {
    WasmRunner<int32_t> r(execution_tier);
    const int32_t kExpectedValue = i;
    // return(kExpectedValue)
    r.Build({WASM_I32V(kExpectedValue)});
    CHECK_EQ(kExpectedValue, r.Call());
  }
}

WASM_EXEC_TEST(GraphTrimming) {
  // This WebAssembly code requires graph trimming in the TurboFan compiler.
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({kExprLocalGet, 0, kExprLocalGet, 0, kExprLocalGet, 0, kExprI32RemS,
           kExprI32Eq, kExprLocalGet, 0, kExprI32DivS, kExprUnreachable});
  r.Call(1);
}

WASM_EXEC_TEST(Int32Param0) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // return(local[0])
  r.Build({WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Int32Param0_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // local[0]
  r.Build({WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Int32Param1) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // local[1]
  r.Build({WASM_LOCAL_GET(1)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(-111, i)); }
}

WASM_EXEC_TEST(Int32Add) {
  WasmRunner<int32_t> r(execution_tier);
  // 11 + 44
  r.Build({WASM_I32_ADD(WASM_I32V_1(11), WASM_I32V_1(44))});
  CHECK_EQ(55, r.Call());
}

WASM_EXEC_TEST(Int32Add_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // p0 + 13
  r.Build({WASM_I32_ADD(WASM_I32V_1(13), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(base::AddWithWraparound(i, 13), r.Call(i)); }
}

WASM_EXEC_TEST(Int32Add_P_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // p0 + 13
  r.Build({WASM_I32_ADD(WASM_I32V_1(13), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(base::AddWithWraparound(i, 13), r.Call(i)); }
}

static void RunInt32AddTest(TestExecutionTier execution_tier,
                            const uint8_t* code, size_t size) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.builder().AddSignature(sigs.ii_v());
  r.builder().AddSignature(sigs.iii_v());
  r.Build(base::VectorOf(code, size));
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = static_cast<int32_t>(static_cast<uint32_t>(i) +
                                              static_cast<uint32_t>(j));
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(Int32Add_P2) {
  static const uint8_t code[] = {
      WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_block1) {
  static const uint8_t code[] = {
      WASM_BLOCK_X(1, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_block2) {
  static const uint8_t code[] = {
      WASM_BLOCK_X(1, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), kExprBr, DEPTH_0),
      kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_multi_if) {
  static const uint8_t code[] = {
      WASM_IF_ELSE_X(1, WASM_LOCAL_GET(0),
                     WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                     WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
      kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Float32Add) {
  WasmRunner<int32_t> r(execution_tier);
  // int(11.5f + 44.5f)
  r.Build(
      {WASM_I32_SCONVERT_F32(WASM_F32_ADD(WASM_F32(11.5f), WASM_F32(44.5f)))});
  CHECK_EQ(56, r.Call());
}

WASM_EXEC_TEST(Float64Add) {
  WasmRunner<int32_t> r(execution_tier);
  // return int(13.5d + 43.5d)
  r.Build(
      {WASM_I32_SCONVERT_F64(WASM_F64_ADD(WASM_F64(13.5), WASM_F64(43.5)))});
  CHECK_EQ(57, r.Call());
}

// clang-format messes up the FOR_INT32_INPUTS macros.
// clang-format off
template<typename ctype>
static void TestInt32Binop(TestExecutionTier execution_tier, WasmOpcode opcode,
                           ctype(*expected)(ctype, ctype)) {
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      WasmRunner<ctype> r(execution_tier);
      // Apply {opcode} on two constants.
      r.Build({WASM_BINOP(opcode, WASM_I32V(i), WASM_I32V(j))});
      CHECK_EQ(expected(i, j), r.Call());
    }
  }
  {
    WasmRunner<ctype, ctype, ctype> r(execution_tier);
    // Apply {opcode} on two parameters.
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        CHECK_EQ(expected(i, j), r.Call(i, j));
      }
    }
  }
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter.
    r.Build({WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0))});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(expected(i, j), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant.
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j))});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(expected(i, j), r.Call(i));
    }
  }
  auto to_bool = [](ctype value) -> ctype {
    return value == static_cast<ctype>(0xDEADBEEF) ? value : !!value;
  };
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter, followed by {if}.
    r.Build({WASM_IF(WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0)),
                     WASM_RETURN(WASM_ONE)),
             WASM_ZERO});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant, followed by {if}.
    r.Build({WASM_IF(WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j)),
                     WASM_RETURN(WASM_ONE)),
             WASM_ZERO});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(i));
    }
  }
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter, followed by {br_if}.
    r.Build({WASM_BR_IFD(0, WASM_ONE,
                         WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0))),
             WASM_ZERO});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant, followed by {br_if}.
    r.Build({WASM_BR_IFD(0, WASM_ONE,
                         WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j))),
             WASM_ZERO});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(i));
    }
  }
}
// clang-format on

#define WASM_I32_BINOP_TEST(expr, ctype, expected)                             \
  WASM_EXEC_TEST(I32Binop_##expr) {                                            \
    TestInt32Binop<ctype>(execution_tier, kExprI32##expr,                      \
                          [](ctype a, ctype b) -> ctype { return expected; }); \
  }

WASM_I32_BINOP_TEST(Add, int32_t, base::AddWithWraparound(a, b))
WASM_I32_BINOP_TEST(Sub, int32_t, base::SubWithWraparound(a, b))
WASM_I32_BINOP_TEST(Mul, int32_t, base::MulWithWraparound(a, b))
WASM_I32_BINOP_TEST(DivS, int32_t,
                    (a == kMinInt && b == -1) || b == 0
                        ? static_cast<int32_t>(0xDEADBEEF)
                        : a / b)
WASM_I32_BINOP_TEST(DivU, uint32_t, b == 0 ? 0xDEADBEEF : a / b)
WASM_I32_BINOP_TEST(RemS, int32_t, b == 0 ? 0xDEADBEEF : b == -1 ? 0 : a % b)
WASM_I32_BINOP_TEST(RemU, uint32_t, b == 0 ? 0xDEADBEEF : a % b)
WASM_I32_BINOP_TEST(And, int32_t, a& b)
WASM_I32_BINOP_TEST(Ior, int32_t, a | b)
WASM_I32_BINOP_TEST(Xor, int32_t, a ^ b)
WASM_I32_BINOP_TEST(Shl, int32_t, base::ShlWithWraparound(a, b))
WASM_I32_BINOP_TEST(ShrU, uint32_t, a >> (b & 0x1F))
WASM_I32_BINOP_TEST(ShrS, int32_t, a >> (b & 0x1F))
WASM_I32_BINOP_TEST(Ror, uint32_t, (a >> (b & 0x1F)) | (a << ((32 - b) & 0x1F)))
WASM_I32_BINOP_TEST(Rol, uint32_t, (a << (b & 0x1F)) | (a >> ((32 - b) & 0x1F)))
WASM_I32_BINOP_TEST(Eq, int32_t, a == b)
WASM_I32_BINOP_TEST(Ne, int32_t, a != b)
WASM_I32_BINOP_TEST(LtS, int32_t, a < b)
WASM_I32_BINOP_TEST(LeS, int32_t, a <= b)
WASM_I32_BINOP_TEST(LtU, uint32_t, a < b)
WASM_I32_BINOP_TEST(LeU, uint32_t, a <= b)
WASM_I32_BINOP_TEST(GtS, int32_t, a > b)
WASM_I32_BINOP_TEST(GeS, int32_t, a >= b)
WASM_I32_BINOP_TEST(GtU, uint32_t, a > b)
WASM_I32_BINOP_TEST(GeU, uint32_t, a >= b)

#undef WASM_I32_BINOP_TEST

void TestInt32Unop(TestExecutionTier execution_tier, WasmOpcode opcode,
                   int32_t expected, int32_t a) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return op K
    r.Build({WASM_UNOP(opcode, WASM_I32V(a))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    // return op a
    r.Build({WASM_UNOP(opcode, WASM_LOCAL_GET(0))});
    CHECK_EQ(expected, r.Call(a));
  }
}

WASM_EXEC_TEST(Int32Clz) {
  TestInt32Unop(execution_tier, kExprI32Clz, 0, 0x80001000);
  TestInt32Unop(execution_tier, kExprI32Clz, 1, 0x40000500);
  TestInt32Unop(execution_tier, kExprI32Clz, 2, 0x20000300);
  TestInt32Unop(execution_tier, kExprI32Clz, 3, 0x10000003);
  TestInt32Unop(execution_tier, kExprI32Clz, 4, 0x08050000);
  TestInt32Unop(execution_tier, kExprI32Clz, 5, 0x04006000);
  TestInt32Unop(execution_tier, kExprI32Clz, 6, 0x02000000);
  TestInt32Unop(execution_tier, kExprI32Clz, 7, 0x010000A0);
  TestInt32Unop(execution_tier, kExprI32Clz, 8, 0x00800C00);
  TestInt32Unop(execution_tier, kExprI32Clz, 9, 0x00400000);
  TestInt32Unop(execution_tier, kExprI32Clz, 10, 0x0020000D);
  TestInt32Unop(execution_tier, kExprI32Clz, 11, 0x00100F00);
  TestInt32Unop(execution_tier, kExprI32Clz, 12, 0x00080000);
  TestInt32Unop(execution_tier, kExprI32Clz, 13, 0x00041000);
  TestInt32Unop(execution_tier, kExprI32Clz, 14, 0x00020020);
  TestInt32Unop(execution_tier, kExprI32Clz, 15, 0x00010300);
  TestInt32Unop(execution_tier, kExprI32Clz, 16, 0x00008040);
  TestInt32Unop(execution_tier, kExprI32Clz, 17, 0x00004005);
  TestInt32Unop(execution_tier, kExprI32Clz, 18, 0x00002050);
  TestInt32Unop(execution_tier, kExprI32Clz, 19, 0x00001700);
  TestInt32Unop(execution_tier, kExprI32Clz, 20, 0x00000870);
  TestInt32Unop(execution_tier, kExprI32Clz, 21, 0x00000405);
  TestInt32Unop(execution_tier, kExprI32Clz, 22, 0x00000203);
  TestInt32Unop(execution_tier, kExprI32Clz, 23, 0x00000101);
  TestInt32Unop(execution_tier, kExprI32Clz, 24, 0x00000089);
  TestInt32Unop(execution_tier, kExprI32Clz, 25, 0x00000041);
  TestInt32Unop(execution_tier, kExprI32Clz, 26, 0x00000022);
  TestInt32Unop(execution_tier, kExprI32Clz, 27, 0x00000013);
  TestInt32Unop(execution_tier, kExprI32Clz, 28, 0x00000008);
  TestInt32Unop(execution_tier, kExprI32Clz, 29, 0x00000004);
  TestInt32Unop(execution_tier, kExprI32Clz, 30, 0x00000002);
  TestInt32Unop(execution_tier, kExprI32Clz, 31, 0x00000001);
  TestInt32Unop(execution_tier, kExprI32Clz, 32, 0x00000000);
}

WASM_EXEC_TEST(Int32Ctz) {
  TestInt32Unop(execution_tier, kExprI32Ctz, 32, 0x00000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 31, 0x80000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 30, 0x40000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 29, 0x20000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 28, 0x10000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 27, 0xA8000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 26, 0xF4000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 25, 0x62000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 24, 0x91000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 23, 0xCD800000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 22, 0x09400000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 21, 0xAF200000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 20, 0xAC100000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 19, 0xE0B80000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 18, 0x9CE40000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 17, 0xC7920000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 16, 0xB8F10000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 15, 0x3B9F8000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 14, 0xDB4C4000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 13, 0xE9A32000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 12, 0xFCA61000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 11, 0x6C8A7800);
  TestInt32Unop(execution_tier, kExprI32Ctz, 10, 0x8CE5A400);
  TestInt32Unop(execution_tier, kExprI32Ctz, 9, 0xCB7D0200);
  TestInt32Unop(execution_tier, kExprI32Ctz, 8, 0xCB4DC100);
  TestInt32Unop(execution_tier, kExprI32Ctz, 7, 0xDFBEC580);
  TestInt32Unop(execution_tier, kExprI32Ctz, 6, 0x27A9DB40);
  TestInt32Unop(execution_tier, kExprI32Ctz, 5, 0xDE3BCB20);
  TestInt32Unop(execution_tier, kExprI32Ctz, 4, 0xD7E8A610);
  TestInt32Unop(execution_tier, kExprI32Ctz, 3, 0x9AFDBC88);
  TestInt32Unop(execution_tier, kExprI32Ctz, 2, 0x9AFDBC84);
  TestInt32Unop(execution_tier, kExprI32Ctz, 1, 0x9AFDBC82);
  TestInt32Unop(execution_tier, kExprI32Ctz, 0, 0x9AFDBC81);
}

WASM_EXEC_TEST(Int32Popcnt) {
  TestInt32Unop(execution_tier, kExprI32Popcnt, 32, 0xFFFFFFFF);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 0, 0x00000000);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 1, 0x00008000);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 13, 0x12345678);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 19, 0xFEDCBA09);
}

WASM_EXEC_TEST(I32Eqz) {
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, 1);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, -1);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, -827343);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, 8888888);
  TestInt32Unop(execution_tier, kExprI32Eqz, 1, 0);
}

WASM_EXEC_TEST(Int32DivS_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(0, r.Call(0, 100));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, -1));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(Int32RemS_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_REMS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(33, r.Call(133, 100));
  CHECK_EQ(0, r.Call(kMin, -1));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(Int32DivU_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_DIVU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(0, r.Call(0, 100));
  CHECK_EQ(0, r.Call(kMin, -1));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "src/base/overflowing-math.h"
#include "src/utils/utils.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8::internal::wasm {

// for even shorter tests.
#define B1(a) WASM_BLOCK(a)
#define B2(a, b) WASM_BLOCK(a, b)
#define RET(x) x, kExprReturn
#define RET_I8(x) WASM_I32V_2(x), kExprReturn

WASM_EXEC_TEST(Int32Const) {
  WasmRunner<int32_t> r(execution_tier);
  const int32_t kExpectedValue = 0x11223344;
  // return(kExpectedValue)
  r.Build({WASM_I32V_5(kExpectedValue)});
  CHECK_EQ(kExpectedValue, r.Call());
}

WASM_EXEC_TEST(Int32Const_many) {
  FOR_INT32_INPUTS(i) {
    WasmRunner<int32_t> r(execution_tier);
    const int32_t kExpectedValue = i;
    // return(kExpectedValue)
    r.Build({WASM_I32V(kExpectedValue)});
    CHECK_EQ(kExpectedValue, r.Call());
  }
}

WASM_EXEC_TEST(GraphTrimming) {
  // This WebAssembly code requires graph trimming in the TurboFan compiler.
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({kExprLocalGet, 0, kExprLocalGet, 0, kExprLocalGet, 0, kExprI32RemS,
           kExprI32Eq, kExprLocalGet, 0, kExprI32DivS, kExprUnreachable});
  r.Call(1);
}

WASM_EXEC_TEST(Int32Param0) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // return(local[0])
  r.Build({WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Int32Param0_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // local[0]
  r.Build({WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Int32Param1) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // local[1]
  r.Build({WASM_LOCAL_GET(1)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(-111, i)); }
}

WASM_EXEC_TEST(Int32Add) {
  WasmRunner<int32_t> r(execution_tier);
  // 11 + 44
  r.Build({WASM_I32_ADD(WASM_I32V_1(11), WASM_I32V_1(44))});
  CHECK_EQ(55, r.Call());
}

WASM_EXEC_TEST(Int32Add_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // p0 + 13
  r.Build({WASM_I32_ADD(WASM_I32V_1(13), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(base::AddWithWraparound(i, 13), r.Call(i)); }
}

WASM_EXEC_TEST(Int32Add_P_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // p0 + 13
  r.Build({WASM_I32_ADD(WASM_I32V_1(13), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(base::AddWithWraparound(i, 13), r.Call(i)); }
}

static void RunInt32AddTest(TestExecutionTier execution_tier,
                            const uint8_t* code, size_t size) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.builder().AddSignature(sigs.ii_v());
  r.builder().AddSignature(sigs.iii_v());
  r.Build(base::VectorOf(code, size));
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = static_cast<int32_t>(static_cast<uint32_t>(i) +
                                              static_cast<uint32_t>(j));
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(Int32Add_P2) {
  static const uint8_t code[] = {
      WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_block1) {
  static const uint8_t code[] = {
      WASM_BLOCK_X(1, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_block2) {
  static const uint8_t code[] = {
      WASM_BLOCK_X(1, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), kExprBr, DEPTH_0),
      kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_multi_if) {
  static const uint8_t code[] = {
      WASM_IF_ELSE_X(1, WASM_LOCAL_GET(0),
                     WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                     WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
      kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Float32Add) {
  WasmRunner<int32_t> r(execution_tier);
  // int(11.5f + 44.5f)
  r.Build(
      {WASM_I32_SCONVERT_F32(WASM_F32_ADD(WASM_F32(11.5f), WASM_F32(44.5f)))});
  CHECK_EQ(56, r.Call());
}

WASM_EXEC_TEST(Float64Add) {
  WasmRunner<int32_t> r(execution_tier);
  // return int(13.5d + 43.5d)
  r.Build(
      {WASM_I32_SCONVERT_F64(WASM_F64_ADD(WASM_F64(13.5), WASM_F64(43.5)))});
  CHECK_EQ(57, r.Call());
}

// clang-format messes up the FOR_INT32_INPUTS macros.
// clang-format off
template<typename ctype>
static void TestInt32Binop(TestExecutionTier execution_tier, WasmOpcode opcode,
                           ctype(*expected)(ctype, ctype)) {
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      WasmRunner<ctype> r(execution_tier);
      // Apply {opcode} on two constants.
      r.Build({WASM_BINOP(opcode, WASM_I32V(i), WASM_I32V(j))});
      CHECK_EQ(expected(i, j), r.Call());
    }
  }
  {
    WasmRunner<ctype, ctype, ctype> r(execution_tier);
    // Apply {opcode} on two parameters.
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        CHECK_EQ(expected(i, j), r.Call(i, j));
      }
    }
  }
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter.
    r.Build({WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0))});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(expected(i, j), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant.
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j))});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(expected(i, j), r.Call(i));
    }
  }
  auto to_bool = [](ctype value) -> ctype {
    return value == static_cast<ctype>(0xDEADBEEF) ? value : !!value;
  };
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter, followed by {if}.
    r.Build({WASM_IF(WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0)),
                     WASM_RETURN(WASM_ONE)),
             WASM_ZERO});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant, followed by {if}.
    r.Build({WASM_IF(WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j)),
                     WASM_RETURN(WASM_ONE)),
             WASM_ZERO});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(i));
    }
  }
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter, followed by {br_if}.
    r.Build({WASM_BR_IFD(0, WASM_ONE,
                         WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0))),
             WASM_ZERO});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant, followed by {br_if}.
    r.Build({WASM_BR_IFD(0, WASM_ONE,
                         WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j))),
             WASM_ZERO});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(i));
    }
  }
}
// clang-format on

#define WASM_I32_BINOP_TEST(expr, ctype, expected)                             \
  WASM_EXEC_TEST(I32Binop_##expr) {                                            \
    TestInt32Binop<ctype>(execution_tier, kExprI32##expr,                      \
                          [](ctype a, ctype b) -> ctype { return expected; }); \
  }

WASM_I32_BINOP_TEST(Add, int32_t, base::AddWithWraparound(a, b))
WASM_I32_BINOP_TEST(Sub, int32_t, base::SubWithWraparound(a, b))
WASM_I32_BINOP_TEST(Mul, int32_t, base::MulWithWraparound(a, b))
WASM_I32_BINOP_TEST(DivS, int32_t,
                    (a == kMinInt && b == -1) || b == 0
                        ? static_cast<int32_t>(0xDEADBEEF)
                        : a / b)
WASM_I32_BINOP_TEST(DivU, uint32_t, b == 0 ? 0xDEADBEEF : a / b)
WASM_I32_BINOP_TEST(RemS, int32_t, b == 0 ? 0xDEADBEEF : b == -1 ? 0 : a % b)
WASM_I32_BINOP_TEST(RemU, uint32_t, b == 0 ? 0xDEADBEEF : a % b)
WASM_I32_BINOP_TEST(And, int32_t, a& b)
WASM_I32_BINOP_TEST(Ior, int32_t, a | b)
WASM_I32_BINOP_TEST(Xor, int32_t, a ^ b)
WASM_I32_BINOP_TEST(Shl, int32_t, base::ShlWithWraparound(a, b))
WASM_I32_BINOP_TEST(ShrU, uint32_t, a >> (b & 0x1F))
WASM_I32_BINOP_TEST(ShrS, int32_t, a >> (b & 0x1F))
WASM_I32_BINOP_TEST(Ror, uint32_t, (a >> (b & 0x1F)) | (a << ((32 - b) & 0x1F)))
WASM_I32_BINOP_TEST(Rol, uint32_t, (a << (b & 0x1F)) | (a >> ((32 - b) & 0x1F)))
WASM_I32_BINOP_TEST(Eq, int32_t, a == b)
WASM_I32_BINOP_TEST(Ne, int32_t, a != b)
WASM_I32_BINOP_TEST(LtS, int32_t, a < b)
WASM_I32_BINOP_TEST(LeS, int32_t, a <= b)
WASM_I32_BINOP_TEST(LtU, uint32_t, a < b)
WASM_I32_BINOP_TEST(LeU, uint32_t, a <= b)
WASM_I32_BINOP_TEST(GtS, int32_t, a > b)
WASM_I32_BINOP_TEST(GeS, int32_t, a >= b)
WASM_I32_BINOP_TEST(GtU, uint32_t, a > b)
WASM_I32_BINOP_TEST(GeU, uint32_t, a >= b)

#undef WASM_I32_BINOP_TEST

void TestInt32Unop(TestExecutionTier execution_tier, WasmOpcode opcode,
                   int32_t expected, int32_t a) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return op K
    r.Build({WASM_UNOP(opcode, WASM_I32V(a))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    // return op a
    r.Build({WASM_UNOP(opcode, WASM_LOCAL_GET(0))});
    CHECK_EQ(expected, r.Call(a));
  }
}

WASM_EXEC_TEST(Int32Clz) {
  TestInt32Unop(execution_tier, kExprI32Clz, 0, 0x80001000);
  TestInt32Unop(execution_tier, kExprI32Clz, 1, 0x40000500);
  TestInt32Unop(execution_tier, kExprI32Clz, 2, 0x20000300);
  TestInt32Unop(execution_tier, kExprI32Clz, 3, 0x10000003);
  TestInt32Unop(execution_tier, kExprI32Clz, 4, 0x08050000);
  TestInt32Unop(execution_tier, kExprI32Clz, 5, 0x04006000);
  TestInt32Unop(execution_tier, kExprI32Clz, 6, 0x02000000);
  TestInt32Unop(execution_tier, kExprI32Clz, 7, 0x010000A0);
  TestInt32Unop(execution_tier, kExprI32Clz, 8, 0x00800C00);
  TestInt32Unop(execution_tier, kExprI32Clz, 9, 0x00400000);
  TestInt32Unop(execution_tier, kExprI32Clz, 10, 0x0020000D);
  TestInt32Unop(execution_tier, kExprI32Clz, 11, 0x00100F00);
  TestInt32Unop(execution_tier, kExprI32Clz, 12, 0x00080000);
  TestInt32Unop(execution_tier, kExprI32Clz, 13, 0x00041000);
  TestInt32Unop(execution_tier, kExprI32Clz, 14, 0x00020020);
  TestInt32Unop(execution_tier, kExprI32Clz, 15, 0x00010300);
  TestInt32Unop(execution_tier, kExprI32Clz, 16, 0x00008040);
  TestInt32Unop(execution_tier, kExprI32Clz, 17, 0x00004005);
  TestInt32Unop(execution_tier, kExprI32Clz, 18, 0x00002050);
  TestInt32Unop(execution_tier, kExprI32Clz, 19, 0x00001700);
  TestInt32Unop(execution_tier, kExprI32Clz, 20, 0x00000870);
  TestInt32Unop(execution_tier, kExprI32Clz, 21, 0x00000405);
  TestInt32Unop(execution_tier, kExprI32Clz, 22, 0x00000203);
  TestInt32Unop(execution_tier, kExprI32Clz, 23, 0x00000101);
  TestInt32Unop(execution_tier, kExprI32Clz, 24, 0x00000089);
  TestInt32Unop(execution_tier, kExprI32Clz, 25, 0x00000041);
  TestInt32Unop(execution_tier, kExprI32Clz, 26, 0x00000022);
  TestInt32Unop(execution_tier, kExprI32Clz, 27, 0x00000013);
  TestInt32Unop(execution_tier, kExprI32Clz, 28, 0x00000008);
  TestInt32Unop(execution_tier, kExprI32Clz, 29, 0x00000004);
  TestInt32Unop(execution_tier, kExprI32Clz, 30, 0x00000002);
  TestInt32Unop(execution_tier, kExprI32Clz, 31, 0x00000001);
  TestInt32Unop(execution_tier, kExprI32Clz, 32, 0x00000000);
}

WASM_EXEC_TEST(Int32Ctz) {
  TestInt32Unop(execution_tier, kExprI32Ctz, 32, 0x00000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 31, 0x80000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 30, 0x40000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 29, 0x20000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 28, 0x10000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 27, 0xA8000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 26, 0xF4000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 25, 0x62000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 24, 0x91000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 23, 0xCD800000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 22, 0x09400000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 21, 0xAF200000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 20, 0xAC100000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 19, 0xE0B80000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 18, 0x9CE40000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 17, 0xC7920000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 16, 0xB8F10000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 15, 0x3B9F8000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 14, 0xDB4C4000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 13, 0xE9A32000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 12, 0xFCA61000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 11, 0x6C8A7800);
  TestInt32Unop(execution_tier, kExprI32Ctz, 10, 0x8CE5A400);
  TestInt32Unop(execution_tier, kExprI32Ctz, 9, 0xCB7D0200);
  TestInt32Unop(execution_tier, kExprI32Ctz, 8, 0xCB4DC100);
  TestInt32Unop(execution_tier, kExprI32Ctz, 7, 0xDFBEC580);
  TestInt32Unop(execution_tier, kExprI32Ctz, 6, 0x27A9DB40);
  TestInt32Unop(execution_tier, kExprI32Ctz, 5, 0xDE3BCB20);
  TestInt32Unop(execution_tier, kExprI32Ctz, 4, 0xD7E8A610);
  TestInt32Unop(execution_tier, kExprI32Ctz, 3, 0x9AFDBC88);
  TestInt32Unop(execution_tier, kExprI32Ctz, 2, 0x9AFDBC84);
  TestInt32Unop(execution_tier, kExprI32Ctz, 1, 0x9AFDBC82);
  TestInt32Unop(execution_tier, kExprI32Ctz, 0, 0x9AFDBC81);
}

WASM_EXEC_TEST(Int32Popcnt) {
  TestInt32Unop(execution_tier, kExprI32Popcnt, 32, 0xFFFFFFFF);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 0, 0x00000000);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 1, 0x00008000);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 13, 0x12345678);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 19, 0xFEDCBA09);
}

WASM_EXEC_TEST(I32Eqz) {
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, 1);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, -1);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, -827343);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, 8888888);
  TestInt32Unop(execution_tier, kExprI32Eqz, 1, 0);
}


WASM_EXEC_TEST(Int32DivS_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(0, r.Call(0, 100));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, -1));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(Int32RemS_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_REMS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(33, r.Call(133, 100));
  CHECK_EQ(0, r.Call(kMin, -1));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(Int32DivU_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_DIVU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(0, r.Call(0, 100));
  CHECK_EQ(0, r.Call(kMin, -1));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(Int32RemU_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_REMU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  CHECK_EQ(17, r.Call(217, 100));
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
  CHECK_EQ(kMin, r.Call(kMin, -1));
}

WASM_EXEC_TEST(Int32DivS_byzero_const) {
  for (int8_t denom = -2; denom < 8; ++denom) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    r.Build({WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_I32V_1(denom))});
    for (int32_t val = -7; val < 8; ++val) {
      if (denom == 0) {
        CHECK_TRAP(r.Call(val));
      } else {
        CHECK_EQ(val / denom, r.Call(val));
      }
    }
  }
}

WASM_EXEC_TEST(Int32DivU_byzero_const) {
  for (uint32_t denom = 0xFFFFFFFE; denom < 8; ++denom) {
    WasmRunner<uint32_t, uint32_t> r(execution_tier);
    r.Build({WASM_I32_DIVU(WASM_LOCAL_GET(0), WASM_I32V_1(denom))});

    for (uint32_t val = 0xFFFFFFF0; val < 8; ++val) {
      if (denom == 0) {
        CHECK_TRAP(r.Call(val));
      } else {
        CHECK_EQ(val / denom, r.Call(val));
      }
    }
  }
}

WASM_EXEC_TEST(Int32DivS_trap_effect) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);

  r.Build({WASM_IF_ELSE_I(
      WASM_LOCAL_GET(0),
      WASM_I32_DIVS(WASM_BLOCK_I(WASM_STORE_MEM(MachineType::Int8(), WASM_ZERO,
                                                WASM_LOCAL_GET(0)),
                                 WASM_LOCAL_GET(0)),
                    WASM_LOCAL_GET(1)),
      WASM_I32_DIVS(WASM_BLOCK_I(WASM_STORE_MEM(MachineType::Int8(), WASM_ZERO,
                                                WASM_LOCAL_GET(0)),
                                 WASM_LOCAL_GET(0)),
                    WASM_LOCAL_GET(1)))});
  CHECK_EQ(0, r.Call(0, 100));
  CHECK_TRAP(r.Call(8, 0));
  CHECK_TRAP(r.Call(4, 0));
  CHECK_TRAP(r.Call(0, 0));
}

void TestFloat32Binop(TestExecutionTier execution_tier, WasmOpcode opcode,
                      int32_t expected, float a, float b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return K op K
    r.Build({WASM_BINOP(opcode, WASM_F32(a), WASM_F32(b))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, float, float> r(execution_tier);
    // return a op b
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestFloat32BinopWithConvert(TestExecutionTier execution_tier,
                                 WasmOpcode opcode, int32_t expected, float a,
                                 float b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return int(K op K)
    r.Build(
        {WASM_I32_SCONVERT_F32(WASM_BINOP(opcode, WASM_F32(a), WASM_F32(b)))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, float, float> r(execution_tier);
    // return int(a op b)
    r.Build({WASM_I32_SCONVERT_F32(
        WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestFloat32UnopWithConvert(TestExecutionTier execution_tier,
                                WasmOpcode opcode, int32_t expected, float a) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return int(op(K))
    r.Build({WASM_I32_SCONVERT_F32(WASM_UNOP(opcode, WASM_F32(a)))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, float> r(execution_tier);
    // return int(op(a))
    r.Build({WASM_I32_SCONVERT_F32(WASM_UNOP(opcode, WASM_LOCAL_GET(0)))});
    CHECK_EQ(expected, r.Call(a));
  }
}

void TestFloat64Binop(TestExecutionTier execution_tier, WasmOpcode opcode,
                      int32_t expected, double a, double b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return K op K
    r.Build({WASM_BINOP(opcode, WASM_F64(a), WASM_F64(b))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, double, double> r(execution_tier);
    // return a op b
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestFloat64BinopWithConvert(TestExecutionTier execution_tier,
                                 WasmOpcode opcode, int32_t expected, double a,
                                 double b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return int(K op K)
    r.Build(
        {WASM_I32_SCONVERT_F64(WASM_BINOP(opcode, WASM_F64(a), WASM_F64(b)))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, double, double> r(execution_tier);
    r.Build({WASM_I32_SCONVERT_F64(
        WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestFloat64UnopWithConvert(TestExecutionTier execution_tier,
                                WasmOpcode opcode, int32_t expected, double a) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return int(op(K))
    r.Build({WASM_I32_SCONVERT_F64(WASM_UNOP(opcode, WASM_F64(a)))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, double> r(execution_tier);
    // return int(op(a))
    r.Build({WASM_I32_SCONVERT_F64(WASM_UNOP(opcode, WASM_LOCAL_GET(0)))});
    CHECK_EQ(expected, r.Call(a));
  }
}

WASM_EXEC_TEST(Float32Binops) {
  TestFloat32Binop(execution_tier, kExprF32Eq, 1, 8.125f, 8.125f);
  TestFloat32Binop(execution_tier, kExprF32Ne, 1, 8.125f, 8.127f);
  TestFloat32Binop(execution_tier, kExprF32Lt, 1, -9.5f, -9.0f);
  TestFloat32Binop(execution_tier, kExprF32Le, 1, -1111.0f, -1111.0f);
  TestFloat32Binop(execution_tier, kExprF32Gt, 1, -9.0f, -9.5f);
  TestFloat32Binop(execution_tier, kExprF32Ge, 1, -1111.0f, -1111.0f);

  TestFloat32BinopWithConvert(execution_tier, kExprF32Add, 10, 3.5f, 6.5f);
  TestFloat32BinopWithConvert(execution_tier, kExprF32Sub, 2, 44.5f, 42.5f);
  TestFloat32BinopWithConvert(execution_tier, kExprF32Mul, -66, -132.1f, 0.5f);
  TestFloat32BinopWithConvert(execution_tier, kExprF32Div, 11, 22.1f, 2.0f);
}

WASM_EXEC_TEST(Float32Unops) {
  TestFloat32UnopWithConvert(execution_tier, kExprF32Abs, 8, 8.125f);
  TestFloat32UnopWithConvert(execution_tier, kExprF32Abs, 9, -9.125f);
  TestFloat32UnopWithConvert(execution_tier, kExprF32Neg, -213, 213.125f);
  TestFloat32UnopWithConvert(execution_tier, kExprF32Sqrt, 12, 144.4f);
}

WASM_EXEC_TEST(Float64Binops) {
  TestFloat64Binop(execution_tier, kExprF64Eq, 1, 16.25, 16.25);
  TestFloat64Binop(execution_tier, kExprF64Ne, 1, 16.25, 16.15);
  TestFloat64Binop(execution_tier, kExprF64Lt, 1, -32.4, 11.7);
  TestFloat64Binop(execution_tier, kExprF64Le, 1, -88.9, -88.9);
  TestFloat64Binop(execution_tier, kExprF64Gt, 1, 11.7, -32.4);
  TestFloat64Binop(execution_tier, kExprF64Ge, 1, -88.9, -88.9);

  TestFloat64BinopWithConvert(execution_tier, kExprF64Add, 100, 43.5, 56.5);
  TestFloat64BinopWithConvert(execution_tier, kExprF64Sub, 200, 12200.1,
                              12000.1);
  TestFloat64BinopWithConvert(execution_tier, kExprF64Mul, -33, 134, -0.25);
  TestFloat64BinopWithConvert(execution_tier, kExprF64Div, -1111, -2222.3, 2);
}

WASM_EXEC_TEST(Float64Unops) {
  TestFloat64UnopWithConvert(execution_tier, kExprF64Abs, 108, 108.125);
  TestFloat64UnopWithConvert(execution_tier, kExprF64Abs, 209, -209.125);
  TestFloat64UnopWithConvert(execution_tier, kExprF64Neg, -209, 209.125);
  TestFloat64UnopWithConvert(execution_tier, kExprF64Sqrt, 13, 169.4);
}

WASM_EXEC_TEST(Float32Neg) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_NEG(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    CHECK_EQ(0x80000000,
             base::bit_cast<uint32_t>(i) ^ base::bit_cast<uint32_t>(r.Call(i)));
  }
}

WASM_EXEC_TEST(Float64Neg) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_NEG(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    CHECK_EQ(0x8000000000000000,
             base::bit_cast<uint64_t>(i) ^ base::bit_cast<uint64_t>(r.Call(i)));
  }
}

WASM_EXEC_TEST(IfElse_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // if (p0) return 11; else return 22;
  r.Build({WASM_IF_ELSE_I(WASM_LOCAL_GET(0),   // --
                          WASM_I32V_1(11),     // --
                          WASM_I32V_1(22))});  // --
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(If_empty1) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOCAL_GET(0), kExprIf, kVoidCode, kExprEnd, WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i - 9, i)); }
}

WASM_EXEC_TEST(IfElse_empty1) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOCAL_GET(0), kExprIf, kVoidCode, kExprElse, kExprEnd,
           WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i - 8, i)); }
}

WASM_EXEC_TEST(IfElse_empty2) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOCAL_GET(0), kExprIf, kVoidCode, WASM_NOP, kExprElse, kExprEnd,
           WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i - 7, i)); }
}

WASM_EXEC_TEST(IfElse_empty3) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOCAL_GET(0), kExprIf, kVoidCode, kExprElse, WASM_NOP, kExprEnd,
           WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i - 6, i)); }
}

WASM_EXEC_TEST(If_chain1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // if (p0) 13; if (p0) 14; 15
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_NOP),
           WASM_IF(WASM_LOCAL_GET(0), WASM_NOP), WASM_I32V_1(15)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(15, r.Call(i)); }
}

WASM_EXEC_TEST(If_chain_set) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // if (p0) p1 = 73; if (p0) p1 = 74; p1
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_LOCAL_SET(1, WASM_I32V_2(73))),
           WASM_IF(WASM_LOCAL_GET(0), WASM_LOCAL_SET(1, WASM_I32V_2(74))),
           WASM_LOCAL_GET(1)});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 74 : i;
    CHECK_EQ(expected, r.Call(i, i));
  }
}

WASM_EXEC_TEST(IfElse_Unreachable1) {
  WasmRunner<int32_t> r(execution_tier);
  // 0 ? unreachable : 27
  r.Build({WASM_IF_ELSE_I(WASM_ZERO,           // --
                          WASM_UNREACHABLE,    // --
                          WASM_I32V_1(27))});  // --
  CHECK_EQ(27, r.Call());
}

WASM_EXEC_TEST(IfElse_Unreachable2) {
  WasmRunner<int32_t> r(execution_tier);
  // 1 ? 28 : unreachable
  r.Build({WASM_IF_ELSE_I(WASM_I32V_1(1),       // --
                          WASM_I32V_1(28),      // --
                          WASM_UNREACHABLE)});  // --
  CHECK_EQ(28, r.Call());
}

WASM_EXEC_TEST(Return12) {
  WasmRunner<int32_t> r(execution_tier);

  r.Build({RET_I8(12)});
  CHECK_EQ(12, r.Call());
}

WASM_EXEC_TEST(Return17) {
  WasmRunner<int32_t> r(execution_tier);

  r.Build({WASM_BLOCK(RET_I8(17)), WASM_ZERO});
  CHECK_EQ(17, r.Call());
}

WASM_EXEC_TEST(Return_I32) {
  WasmRunner<int32_t, int32_t> r(execution_tier);

  r.Build({RET(WASM_LOCAL_GET(0))});

  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Return_F32) {
  WasmRunner<float, float> r(execution_tier);

  r.Build({RET(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    float expect = i;
    float result = r.Call(expect);
    if (std::isnan(expect)) {
      CHECK(std::isnan(result));
    } else {
      CHECK_EQ(expect, result);
    }
  }
}

WASM_EXEC_TEST(Return_F64) {
  WasmRunner<double, double> r(execution_tier);

  r.Build({RET(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    double expect = i;
    double result = r.Call(expect);
    if (std::isnan(expect)) {
      CHECK(std::isnan(result));
    } else {
      CHECK_EQ(expect, result);
    }
  }
}

WASM_EXEC_TEST(Select_float_parameters) {
  WasmRunner<float, float, float, int32_t> r(execution_tier);
  r.Build(
      {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_LOCAL_GET(2))});
  CHECK_FLOAT_EQ(2.0f, r.Call(2.0f, 1.0f, 1));
}

WASM_EXEC_TEST(Select_s128_parameters) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* g0 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g1 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* output = r.builder().AddGlobal<int32_t>(kWasmS128);
  // select(v128(0, 1, 2, 3), v128(4, 5, 6, 7), 1) == v128(0, 1, 2, 3)
  for (int i = 0; i < 4; i++) {
    LANE(g0, i) = i;
    LANE(g1, i) = i + 4;
  }
  r.Build(
      {WASM_GLOBAL_SET(2, WASM_SELECT(WASM_GLOBAL_GET(0), WASM_GLOBAL_GET(1),
                                      WASM_LOCAL_GET(0))),
       WASM_ONE});
  r.Call(1);
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(i, LANE(output, i));
  }
}

WASM_EXEC_TEST(SelectWithType_float_parameters) {
  WasmRunner<float, float, float, int32_t> r(execution_tier);
  r.Build(
      {WASM_SELECT_F(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_LOCAL_GET(2))});
  CHECK_FLOAT_EQ(2.0f, r.Call(2.0f, 1.0f, 1));
  CHECK_FLOAT_EQ(1.0f, r.Call(2.0f, 1.0f, 0));
}

WASM_EXEC_TEST(Select_double_parameters) {
  WasmRunner<double, double, double, int32_t> r(execution_tier);
  r.Build(
      {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_LOCAL_GET(2))});
  CHECK_FLOAT_EQ(2.0f, r.Call(2.0f, 1.0f, 1));
  CHECK_FLOAT_EQ(1.0f, r.Call(2.0f, 1.0f, 0));
}

WASM_EXEC_TEST(SelectWithType_double_parameters) {
  WasmRunner<double, double, double, int32_t> r(execution_tier);
  r.Build(
      {WASM_SELECT_D(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_LOCAL_GET(2))});
  CHECK_FLOAT_EQ(2.0f, r.Call(2.0f, 1.0f, 1));
  CHECK_FLOAT_EQ(1.0f, r.Call(2.0f, 1.0f, 0));
}

WASM_EXEC_TEST(Select) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // return select(11, 22, a);
  r.Build({WASM_SELECT(WASM_I32V_1(11), WASM_I32V_1(22), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(SelectWithType) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // return select(11, 22, a);
  r.Build({WASM_SELECT_I(WASM_I32V_1(11), WASM_I32V_1(22), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select_strict1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // select(a=0, a=1, a=2); return a
  r.Build({WASM_SELECT(WASM_LOCAL_TEE(0, WASM_ZERO),
                       WASM_LOCAL_TEE(0, WASM_I32V_1(1)),
                       WASM_LOCAL_TEE(0, WASM_I32V_1(2))),
           WASM_DROP, WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(2, r.Call(i)); }
}

WASM_EXEC_TEST(SelectWithType_strict1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // select(a=0, a=1, a=2); return a
  r.Build({WASM_SELECT_I(WASM_LOCAL_TEE(0, WASM_ZERO),
                         WASM_LOCAL_TEE(0, WASM_I32V_1(1)),
                         WASM_LOCAL_TEE(0, WASM_I32V_1(2))),
           WASM_DROP, WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(2, r.Call(i)); }
}

WASM_EXEC_TEST(Select_strict2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmI32);
  // select(b=5, c=6, a)
  r.Build({WASM_SELECT(WASM_LOCAL_TEE(1, WASM_I32V_1(5)),
                       WASM_LOCAL_TEE(2, WASM_I32V_1(6)), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 5 : 6;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(SelectWithType_strict2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmI32);
  // select(b=5, c=6, a)
  r.Build(
      {WASM_SELECT_I(WASM_LOCAL_TEE(1, WASM_I32V_1(5)),
                     WASM_LOCAL_TEE(2, WASM_I32V_1(6)), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 5 : 6;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select_strict3) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmI32);
  // select(b=5, c=6, a=b)
  r.Build({WASM_SELECT(WASM_LOCAL_TEE(1, WASM_I32V_1(5)),
                       WASM_LOCAL_TEE(2, WASM_I32V_1(6)),
                       WASM_LOCAL_TEE(0, WASM_LOCAL_GET(1)))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = 5;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(SelectWithType_strict3) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmI32);
  // select(b=5, c=6, a=b)
  r.Build({WASM_SELECT_I(WASM_LOCAL_TEE(1, WASM_I32V_1(5)),
                         WASM_LOCAL_TEE(2, WASM_I32V_1(6)),
                         WASM_LOCAL_TEE(0, WASM_LOCAL_GET(1)))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = 5;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select64) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  // return select(11, 22, a);
  r.Build({WASM_SELECT(WASM_I64V_1(11), 
"""


```