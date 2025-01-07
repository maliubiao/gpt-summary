Response:

Prompt: 
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/riscv/simulator-riscv.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共10部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Copyright(c) 2010 - 2017,
//     The Regents of the University of California(Regents).All Rights Reserved.
//
//     Redistribution and use in source and binary forms,
//     with or without modification,
//     are permitted provided that the following
//     conditions are met : 1. Redistributions of source code must retain the
//     above copyright notice, this list of conditions and the following
//     disclaimer.2. Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following disclaimer in
//     the
//             documentation and /
//         or
//         other materials provided with the distribution.3. Neither the name of
//         the Regents nor the names of its contributors may be used to endorse
//         or
//         promote products derived from
//         this software without specific prior written permission.
//
//         IN NO EVENT SHALL REGENTS BE LIABLE TO ANY PARTY FOR DIRECT,
//     INDIRECT, SPECIAL,
//     INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS,
//     ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
//     EVEN IF REGENTS HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//     REGENTS SPECIFICALLY DISCLAIMS ANY WARRANTIES,
//     INCLUDING, BUT NOT LIMITED TO,
//     THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//     PARTICULAR PURPOSE.THE SOFTWARE AND ACCOMPANYING DOCUMENTATION,
//     IF ANY,
//     PROVIDED HEREUNDER IS PROVIDED
//     "AS IS".REGENTS HAS NO OBLIGATION TO PROVIDE MAINTENANCE,
//     SUPPORT, UPDATES, ENHANCEMENTS,
//     OR MODIFICATIONS.

// The original source code covered by the above license above has been
// modified significantly by the v8 project authors.

#include "src/execution/riscv/simulator-riscv.h"

// Only build the simulator if not compiling for real RISCV hardware.
#if defined(USE_SIMULATOR)

#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>

#include "src/base/bits.h"
#include "src/base/overflowing-math.h"
#include "src/base/vector.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/constants-arch.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/disasm.h"
#include "src/heap/combined-heap.h"
#include "src/runtime/runtime-utils.h"
#include "src/utils/ostreams.h"
#include "src/utils/utils.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/trap-handler/trap-handler-simulator.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#if V8_TARGET_ARCH_RISCV64
#define REGIx_FORMAT PRIx64
#define REGId_FORMAT PRId64
#elif V8_TARGET_ARCH_RISCV32
#define REGIx_FORMAT PRIx32
#define REGId_FORMAT PRId32
#endif

// The following code about RVV was based from:
//   https://github.com/riscv/riscv-isa-sim
// Copyright (c) 2010-2017, The Regents of the University of California
// (Regents).  All Rights Reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the Regents nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.

// IN NO EVENT SHALL REGENTS BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
// SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS,
// ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
// REGENTS HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// REGENTS SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE. THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED
// HEREUNDER IS PROVIDED "AS IS". REGENTS HAS NO OBLIGATION TO PROVIDE
// MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
#ifdef CAN_USE_RVV_INSTRUCTIONS
static inline bool is_aligned(const unsigned val, const unsigned pos) {
  return pos ? (val & (pos - 1)) == 0 : true;
}

static inline bool is_overlapped(const int astart, int asize, const int bstart,
                                 int bsize) {
  asize = asize == 0 ? 1 : asize;
  bsize = bsize == 0 ? 1 : bsize;

  const int aend = astart + asize;
  const int bend = bstart + bsize;

  return std::max(aend, bend) - std::min(astart, bstart) < asize + bsize;
}
static inline bool is_overlapped_widen(const int astart, int asize,
                                       const int bstart, int bsize) {
  asize = asize == 0 ? 1 : asize;
  bsize = bsize == 0 ? 1 : bsize;

  const int aend = astart + asize;
  const int bend = bstart + bsize;

  if (astart < bstart && is_overlapped(astart, asize, bstart, bsize) &&
      !is_overlapped(astart, asize, bstart + bsize, bsize)) {
    return false;
  } else {
    return std::max(aend, bend) - std::min(astart, bstart) < asize + bsize;
  }
}

#ifdef DEBUG
#define require_align(val, pos)                  \
  if (!is_aligned(val, pos)) {                   \
    std::cout << val << " " << pos << std::endl; \
  }                                              \
  CHECK_EQ(is_aligned(val, pos), true)
#else
#define require_align(val, pos) CHECK_EQ(is_aligned(val, pos), true)
#endif

// RVV
// The following code about RVV was based from:
//   https://github.com/riscv/riscv-isa-sim
// Copyright (c) 2010-2017, The Regents of the University of California
// (Regents).  All Rights Reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the Regents nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.

// IN NO EVENT SHALL REGENTS BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
// SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS,
// ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
// REGENTS HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// REGENTS SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE. THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED
// HEREUNDER IS PROVIDED "AS IS". REGENTS HAS NO OBLIGATION TO PROVIDE
// MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
template <uint64_t N>
struct type_usew_t;
template <>
struct type_usew_t<8> {
  using type = uint8_t;
};

template <>
struct type_usew_t<16> {
  using type = uint16_t;
};

template <>
struct type_usew_t<32> {
  using type = uint32_t;
};

template <>
struct type_usew_t<64> {
  using type = uint64_t;
};

template <>
struct type_usew_t<128> {
  using type = __uint128_t;
};
template <uint64_t N>
struct type_sew_t;

template <>
struct type_sew_t<8> {
  using type = int8_t;
};

template <>
struct type_sew_t<16> {
  using type = int16_t;
};

template <>
struct type_sew_t<32> {
  using type = int32_t;
};

template <>
struct type_sew_t<64> {
  using type = int64_t;
};

template <>
struct type_sew_t<128> {
  using type = __int128_t;
};

#define VV_PARAMS(x)                                                       \
  type_sew_t<x>::type& vd =                                                \
      Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);                  \
  type_sew_t<x>::type vs1 = Rvvelt<type_sew_t<x>::type>(rvv_vs1_reg(), i); \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define VV_UPARAMS(x)                                                        \
  type_usew_t<x>::type& vd =                                                 \
      Rvvelt<type_usew_t<x>::type>(rvv_vd_reg(), i, true);                   \
  type_usew_t<x>::type vs1 = Rvvelt<type_usew_t<x>::type>(rvv_vs1_reg(), i); \
  type_usew_t<x>::type vs2 = Rvvelt<type_usew_t<x>::type>(rvv_vs2_reg(), i);

#define VX_PARAMS(x)                                                        \
  type_sew_t<x>::type& vd =                                                 \
      Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);                   \
  type_sew_t<x>::type rs1 = (type_sew_t<x>::type)(get_register(rs1_reg())); \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define VX_UPARAMS(x)                                                         \
  type_usew_t<x>::type& vd =                                                  \
      Rvvelt<type_usew_t<x>::type>(rvv_vd_reg(), i, true);                    \
  type_usew_t<x>::type rs1 = (type_usew_t<x>::type)(get_register(rs1_reg())); \
  type_usew_t<x>::type vs2 = Rvvelt<type_usew_t<x>::type>(rvv_vs2_reg(), i);

#define VI_PARAMS(x)                                                    \
  type_sew_t<x>::type& vd =                                             \
      Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);               \
  type_sew_t<x>::type simm5 = (type_sew_t<x>::type)(instr_.RvvSimm5()); \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define VI_UPARAMS(x)                                                     \
  type_usew_t<x>::type& vd =                                              \
      Rvvelt<type_usew_t<x>::type>(rvv_vd_reg(), i, true);                \
  type_usew_t<x>::type uimm5 = (type_usew_t<x>::type)(instr_.RvvUimm5()); \
  type_usew_t<x>::type vs2 = Rvvelt<type_usew_t<x>::type>(rvv_vs2_reg(), i);

#define VN_PARAMS(x)                                                    \
  constexpr int half_x = x >> 1;                                        \
  type_sew_t<half_x>::type& vd =                                        \
      Rvvelt<type_sew_t<half_x>::type>(rvv_vd_reg(), i, true);          \
  type_sew_t<x>::type uimm5 = (type_sew_t<x>::type)(instr_.RvvUimm5()); \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define VN_UPARAMS(x)                                                     \
  constexpr int half_x = x >> 1;                                          \
  type_usew_t<half_x>::type& vd =                                         \
      Rvvelt<type_usew_t<half_x>::type>(rvv_vd_reg(), i, true);           \
  type_usew_t<x>::type uimm5 = (type_usew_t<x>::type)(instr_.RvvUimm5()); \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define VXI_PARAMS(x)                                                       \
  type_sew_t<x>::type& vd =                                                 \
      Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);                   \
  type_sew_t<x>::type vs1 = Rvvelt<type_sew_t<x>::type>(rvv_vs1_reg(), i);  \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);  \
  type_sew_t<x>::type rs1 = (type_sew_t<x>::type)(get_register(rs1_reg())); \
  type_sew_t<x>::type simm5 = (type_sew_t<x>::type)(instr_.RvvSimm5());

#define VI_XI_SLIDEDOWN_PARAMS(x, off)                           \
  auto& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true); \
  auto vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i + off);

#define VI_XI_SLIDEUP_PARAMS(x, offset)                          \
  auto& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true); \
  auto vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i - offset);

#define VX_SLIDE1DOWN_PARAMS(x, off)                                          \
  auto& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);              \
  if ((i + off) == rvv_vlmax()) {                                             \
    type_sew_t<x>::type src = (type_sew_t<x>::type)(get_register(rs1_reg())); \
    vd = src;                                                                 \
  } else {                                                                    \
    auto src = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i + off);           \
    vd = src;                                                                 \
  }

#define VX_SLIDE1UP_PARAMS(x, offset)                                         \
  auto& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);              \
  if (i == 0 && rvv_vstart() == 0) {                                          \
    type_sew_t<x>::type src = (type_sew_t<x>::type)(get_register(rs1_reg())); \
    vd = src;                                                                 \
  } else {                                                                    \
    auto src = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i - offset);        \
    vd = src;                                                                 \
  }

#define VF_SLIDE1DOWN_PARAMS(x, offset)                                \
  auto& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);       \
  if ((i + offset) == rvv_vlmax()) {                                   \
    auto src = base::bit_cast<type_sew_t<x>::type>(                    \
        get_fpu_register_Float##x(rs1_reg()).get_bits());              \
    vd = src;                                                          \
  } else {                                                             \
    auto src = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i + offset); \
    vd = src;                                                          \
  }

#define VF_SLIDE1UP_PARAMS(x, offset)                                  \
  auto& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);       \
  if (i == rvv_vstart() && i == 0) {                                   \
    auto src = base::bit_cast<type_sew_t<x>::type>(                    \
        get_fpu_register_Float##x(rs1_reg()).get_bits());              \
    vd = src;                                                          \
  } else {                                                             \
    auto src = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i - offset); \
    vd = src;                                                          \
  }

/* Vector Integer Extension */
#define VI_VIE_PARAMS(x, scale)                                  \
  if ((x / scale) < 8) UNREACHABLE();                            \
  auto& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true); \
  auto vs2 = Rvvelt<type_sew_t<x / scale>::type>(rvv_vs2_reg(), i);

#define VI_VIE_UPARAMS(x, scale)                                 \
  if ((x / scale) < 8) UNREACHABLE();                            \
  auto& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true); \
  auto vs2 = Rvvelt<type_usew_t<x / scale>::type>(rvv_vs2_reg(), i);

#define require_noover(astart, asize, bstart, bsize) \
  CHECK_EQ(!is_overlapped(astart, asize, bstart, bsize), true)
#define require_noover_widen(astart, asize, bstart, bsize) \
  CHECK_EQ(!is_overlapped_widen(astart, asize, bstart, bsize), true)

#define RVV_VI_GENERAL_LOOP_BASE \
  for (uint64_t i = rvv_vstart(); i < rvv_vl(); i++) {
#define RVV_VI_LOOP_END \
  set_rvv_vstart(0);    \
  }

#define RVV_VI_MASK_VARS       \
  const uint8_t midx = i / 64; \
  const uint8_t mpos = i % 64;

#define RVV_VI_LOOP_MASK_SKIP(BODY)                               \
  RVV_VI_MASK_VARS                                                \
  if (instr_.RvvVM() == 0) {                                      \
    bool skip = ((Rvvelt<uint64_t>(0, midx) >> mpos) & 0x1) == 0; \
    if (skip) {                                                   \
      continue;                                                   \
    }                                                             \
  }

#define RVV_VI_VV_LOOP(BODY)      \
  RVV_VI_GENERAL_LOOP_BASE        \
  RVV_VI_LOOP_MASK_SKIP()         \
  if (rvv_vsew() == E8) {         \
    VV_PARAMS(8);                 \
    BODY                          \
  } else if (rvv_vsew() == E16) { \
    VV_PARAMS(16);                \
    BODY                          \
  } else if (rvv_vsew() == E32) { \
    VV_PARAMS(32);                \
    BODY                          \
  } else if (rvv_vsew() == E64) { \
    VV_PARAMS(64);                \
    BODY                          \
  } else {                        \
    UNREACHABLE();                \
  }                               \
  RVV_VI_LOOP_END                 \
  rvv_trace_vd();

#define RVV_VI_VV_ULOOP(BODY)     \
  RVV_VI_GENERAL_LOOP_BASE        \
  RVV_VI_LOOP_MASK_SKIP()         \
  if (rvv_vsew() == E8) {         \
    VV_UPARAMS(8);                \
    BODY                          \
  } else if (rvv_vsew() == E16) { \
    VV_UPARAMS(16);               \
    BODY                          \
  } else if (rvv_vsew() == E32) { \
    VV_UPARAMS(32);               \
    BODY                          \
  } else if (rvv_vsew() == E64) { \
    VV_UPARAMS(64);               \
    BODY                          \
  } else {                        \
    UNREACHABLE();                \
  }                               \
  RVV_VI_LOOP_END                 \
  rvv_trace_vd();

#define RVV_VI_VX_LOOP(BODY)      \
  RVV_VI_GENERAL_LOOP_BASE        \
  RVV_VI_LOOP_MASK_SKIP()         \
  if (rvv_vsew() == E8) {         \
    VX_PARAMS(8);                 \
    BODY                          \
  } else if (rvv_vsew() == E16) { \
    VX_PARAMS(16);                \
    BODY                          \
  } else if (rvv_vsew() == E32) { \
    VX_PARAMS(32);                \
    BODY                          \
  } else if (rvv_vsew() == E64) { \
    VX_PARAMS(64);                \
    BODY                          \
  } else {                        \
    UNREACHABLE();                \
  }                               \
  RVV_VI_LOOP_END                 \
  rvv_trace_vd();

#define RVV_VI_VX_ULOOP(BODY)     \
  RVV_VI_GENERAL_LOOP_BASE        \
  RVV_VI_LOOP_MASK_SKIP()         \
  if (rvv_vsew() == E8) {         \
    VX_UPARAMS(8);                \
    BODY                          \
  } else if (rvv_vsew() == E16) { \
    VX_UPARAMS(16);               \
    BODY                          \
  } else if (rvv_vsew() == E32) { \
    VX_UPARAMS(32);               \
    BODY                          \
  } else if (rvv_vsew() == E64) { \
    VX_UPARAMS(64);               \
    BODY                          \
  } else {                        \
    UNREACHABLE();                \
  }                               \
  RVV_VI_LOOP_END                 \
  rvv_trace_vd();

#define RVV_VI_VI_LOOP(BODY)      \
  RVV_VI_GENERAL_LOOP_BASE        \
  RVV_VI_LOOP_MASK_SKIP()         \
  if (rvv_vsew() == E8) {         \
    VI_PARAMS(8);                 \
    BODY                          \
  } else if (rvv_vsew() == E16) { \
    VI_PARAMS(16);                \
    BODY                          \
  } else if (rvv_vsew() == E32) { \
    VI_PARAMS(32);                \
    BODY                          \
  } else if (rvv_vsew() == E64) { \
    VI_PARAMS(64);                \
    BODY                          \
  } else {                        \
    UNREACHABLE();                \
  }                               \
  RVV_VI_LOOP_END                 \
  rvv_trace_vd();

#define RVV_VI_VI_ULOOP(BODY)     \
  RVV_VI_GENERAL_LOOP_BASE        \
  RVV_VI_LOOP_MASK_SKIP()         \
  if (rvv_vsew() == E8) {         \
    VI_UPARAMS(8);                \
    BODY                          \
  } else if (rvv_vsew() == E16) { \
    VI_UPARAMS(16);               \
    BODY                          \
  } else if (rvv_vsew() == E32) { \
    VI_UPARAMS(32);               \
    BODY                          \
  } else if (rvv_vsew() == E64) { \
    VI_UPARAMS(64);               \
    BODY                          \
  } else {                        \
    UNREACHABLE();                \
  }                               \
  RVV_VI_LOOP_END                 \
  rvv_trace_vd();

// widen operation loop

#define VI_WIDE_CHECK_COMMON                     \
  CHECK_LE(rvv_vflmul(), 4);                     \
  CHECK_LE(rvv_vsew() * 2, kRvvELEN);            \
  require_align(rvv_vd_reg(), rvv_vflmul() * 2); \
  require_vm;

#define VI_NARROW_CHECK_COMMON                    \
  CHECK_LE(rvv_vflmul(), 4);                      \
  CHECK_LE(rvv_vsew() * 2, kRvvELEN);             \
  require_align(rvv_vs2_reg(), rvv_vflmul() * 2); \
  require_align(rvv_vd_reg(), rvv_vflmul());      \
  require_vm;

#define RVV_VI_CHECK_SLIDE(is_over)           \
  require_align(rvv_vs2_reg(), rvv_vflmul()); \
  require_align(rvv_vd_reg(), rvv_vflmul());  \
  require_vm;                                 \
  if (is_over) require(rvv_vd_reg() != rvv_vs2_reg());

#define RVV_VI_CHECK_DDS(is_rs)                                           \
  VI_WIDE_CHECK_COMMON;                                                   \
  require_align(rvv_vs2_reg(), rvv_vflmul() * 2);                         \
  if (is_rs) {                                                            \
    require_align(rvv_vs1_reg(), rvv_vflmul());                           \
    if (rvv_vflmul() < 1) {                                               \
      require_noover(rvv_vd_reg(), rvv_vflmul() * 2, rvv_vs1_reg(),       \
                     rvv_vflmul());                                       \
    } else {                                                              \
      require_noover_widen(rvv_vd_reg(), rvv_vflmul() * 2, rvv_vs1_reg(), \
                           rvv_vflmul());                                 \
    }                                                                     \
  }

#define RVV_VI_CHECK_DSS(is_vs1)                                          \
  VI_WIDE_CHECK_COMMON;                                                   \
  require_align(rvv_vs2_reg(), rvv_vflmul());                             \
  if (rvv_vflmul() < 1) {                                                 \
    require_noover(rvv_vd_reg(), rvv_vflmul() * 2, rvv_vs2_reg(),         \
                   rvv_vflmul());                                         \
  } else {                                                                \
    require_noover_widen(rvv_vd_reg(), rvv_vflmul() * 2, rvv_vs2_reg(),   \
                         rvv_vflmul());                                   \
  }                                                                       \
  if (is_vs1) {                                                           \
    require_align(rvv_vs1_reg(), rvv_vflmul());                           \
    if (rvv_vflmul() < 1) {                                               \
      require_noover(rvv_vd_reg(), rvv_vflmul() * 2, rvv_vs1_reg(),       \
                     rvv_vflmul());                                       \
    } else {                                                              \
      require_noover_widen(rvv_vd_reg(), rvv_vflmul() * 2, rvv_vs1_reg(), \
                           rvv_vflmul());                                 \
    }                                                                     \
  }

#define RVV_VI_CHECK_SDS(is_vs1)                              \
  VI_NARROW_CHECK_COMMON;                                     \
  if (rvv_vd_reg() != rvv_vs2_reg())                          \
    require_noover(rvv_vd_reg(), rvv_vflmul(), rvv_vs2_reg(), \
                   rvv_vflmul() * 2);                         \
  if (is_vs1) require_align(rvv_vs1_reg(), rvv_vflmul());

#define RVV_VI_VV_LOOP_WIDEN(BODY) \
  RVV_VI_GENERAL_LOOP_BASE         \
  RVV_VI_LOOP_MASK_SKIP()          \
  if (rvv_vsew() == E8) {          \
    VV_PARAMS(8);                  \
    BODY;                          \
  } else if (rvv_vsew() == E16) {  \
    VV_PARAMS(16);                 \
    BODY;                          \
  } else if (rvv_vsew() == E32) {  \
    VV_PARAMS(32);                 \
    BODY;                          \
  }                                \
  RVV_VI_LOOP_END                  \
  rvv_trace_vd();

#define RVV_VI_VX_LOOP_WIDEN(BODY) \
  RVV_VI_GENERAL_LOOP_BASE         \
  if (rvv_vsew() == E8) {          \
    VX_PARAMS(8);                  \
    BODY;                          \
  } else if (rvv_vsew() == E16) {  \
    VX_PARAMS(16);                 \
    BODY;                          \
  } else if (rvv_vsew() == E32) {  \
    VX_PARAMS(32);                 \
    BODY;                          \
  }                                \
  RVV_VI_LOOP_END                  \
  rvv_trace_vd();

#define VI_WIDE_OP_AND_ASSIGN(var0, var1, var2, op0, op1, sign)                \
  switch (rvv_vsew()) {                                                        \
    case E8: {                                                                 \
      Rvvelt<uint16_t>(rvv_vd_reg(), i, true) =                                \
          op1((sign##16_t)(sign##8_t)var0 op0(sign##16_t)(sign##8_t) var1) +   \
          var2;                                                                \
    } break;                                                                   \
    case E16: {                                                                \
      Rvvelt<uint32_t>(rvv_vd_reg(), i, true) =                                \
          op1((sign##32_t)(sign##16_t)var0 op0(sign##32_t)(sign##16_t) var1) + \
          var2;                                                                \
    } break;                                                                   \
    default: {                                                                 \
      Rvvelt<uint64_t>(rvv_vd_reg(), i, true) =                                \
          op1((sign##64_t)(sign##32_t)var0 op0(sign##64_t)(sign##32_t) var1) + \
          var2;                                                                \
    } break;                                                                   \
  }

#define VI_WIDE_WVX_OP(var0, op0, sign)                              \
  switch (rvv_vsew()) {                                              \
    case E8: {                                                       \
      sign##16_t & vd_w = Rvvelt<sign##16_t>(rvv_vd_reg(), i, true); \
      sign##16_t vs2_w = Rvvelt<sign##16_t>(rvv_vs2_reg(), i);       \
      vd_w = vs2_w op0(sign##16_t)(sign##8_t) var0;                  \
    } break;                                                         \
    case E16: {                                                      \
      sign##32_t & vd_w = Rvvelt<sign##32_t>(rvv_vd_reg(), i, true); \
      sign##32_t vs2_w = Rvvelt<sign##32_t>(rvv_vs2_reg(), i);       \
      vd_w = vs2_w op0(sign##32_t)(sign##16_t) var0;                 \
    } break;                                                         \
    default: {                                                       \
      sign##64_t & vd_w = Rvvelt<sign##64_t>(rvv_vd_reg(), i, true); \
      sign##64_t vs2_w = Rvvelt<sign##64_t>(rvv_vs2_reg(), i);       \
      vd_w = vs2_w op0(sign##64_t)(sign##32_t) var0;                 \
    } break;                                                         \
  }

#define RVV_VI_VVXI_MERGE_LOOP(BODY) \
  RVV_VI_GENERAL_LOOP_BASE           \
  if (rvv_vsew() == E8) {            \
    VXI_PARAMS(8);                   \
    BODY;                            \
  } else if (rvv_vsew() == E16) {    \
    VXI_PARAMS(16);                  \
    BODY;                            \
  } else if (rvv_vsew() == E32) {    \
    VXI_PARAMS(32);                  \
    BODY;                            \
  } else if (rvv_vsew() == E64) {    \
    VXI_PARAMS(64);                  \
    BODY;                            \
  }                                  \
  RVV_VI_LOOP_END                    \
  rvv_trace_vd();

#define VV_WITH_CARRY_PARAMS(x)                                            \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i); \
  type_sew_t<x>::type vs1 = Rvvelt<type_sew_t<x>::type>(rvv_vs1_reg(), i); \
  type_sew_t<x>::type& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);

#define XI_WITH_CARRY_PARAMS(x)                                             \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);  \
  type_sew_t<x>::type rs1 = (type_sew_t<x>::type)(get_register(rs1_reg())); \
  type_sew_t<x>::type simm5 = (type_sew_t<x>::type)instr_.RvvSimm5();       \
  type_sew_t<x>::type& vd = Rvvelt<type_sew_t<x>::type>(rvv_vd_reg(), i, true);

// carry/borrow bit loop
#define RVV_VI_VV_LOOP_WITH_CARRY(BODY) \
  CHECK_NE(rvv_vd_reg(), 0);            \
  RVV_VI_GENERAL_LOOP_BASE              \
  RVV_VI_MASK_VARS                      \
  if (rvv_vsew() == E8) {               \
    VV_WITH_CARRY_PARAMS(8)             \
    BODY;                               \
  } else if (rvv_vsew() == E16) {       \
    VV_WITH_CARRY_PARAMS(16)            \
    BODY;                               \
  } else if (rvv_vsew() == E32) {       \
    VV_WITH_CARRY_PARAMS(32)            \
    BODY;                               \
  } else if (rvv_vsew() == E64) {       \
    VV_WITH_CARRY_PARAMS(64)            \
    BODY;                               \
  }                                     \
  RVV_VI_LOOP_END

#define RVV_VI_XI_LOOP_WITH_CARRY(BODY) \
  CHECK_NE(rvv_vd_reg(), 0);            \
  RVV_VI_GENERAL_LOOP_BASE              \
  RVV_VI_MASK_VARS                      \
  if (rvv_vsew() == E8) {               \
    XI_WITH_CARRY_PARAMS(8)             \
    BODY;                               \
  } else if (rvv_vsew() == E16) {       \
    XI_WITH_CARRY_PARAMS(16)            \
    BODY;                               \
  } else if (rvv_vsew() == E32) {       \
    XI_WITH_CARRY_PARAMS(32)            \
    BODY;                               \
  } else if (rvv_vsew() == E64) {       \
    XI_WITH_CARRY_PARAMS(64)            \
    BODY;                               \
  }                                     \
  RVV_VI_LOOP_END

#define VV_CMP_PARAMS(x)                                                   \
  type_sew_t<x>::type vs1 = Rvvelt<type_sew_t<x>::type>(rvv_vs1_reg(), i); \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define VX_CMP_PARAMS(x)                                                    \
  type_sew_t<x>::type rs1 = (type_sew_t<x>::type)(get_register(rs1_reg())); \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define VI_CMP_PARAMS(x)                                              \
  type_sew_t<x>::type simm5 = (type_sew_t<x>::type)instr_.RvvSimm5(); \
  type_sew_t<x>::type vs2 = Rvvelt<type_sew_t<x>::type>(rvv_vs2_reg(), i);

#define VV_UCMP_PARAMS(x)                                                    \
  type_usew_t<x>::type vs1 = Rvvelt<type_usew_t<x>::type>(rvv_vs1_reg(), i); \
  type_usew_t<x>::type vs2 = Rvvelt<type_usew_t<x>::type>(rvv_vs2_reg(), i);

#define VX_UCMP_PARAMS(x)                                 \
  type_usew_t<x>::type rs1 =                              \
      (type_sew_t<x>::type)(get_register(rvv_vs1_reg())); \
  type_usew_t<x>::type vs2 = Rvvelt<type_usew_t<x>::type>(rvv_vs2_reg(), i);

#define VI_UCMP_PARAMS(x)                                               \
  type_usew_t<x>::type uimm5 = (type_usew_t<x>::type)instr_.RvvUimm5(); \
  type_usew_t<x>::type vs2 = Rvvelt<type_usew_t<x>::type>(rvv_vs2_reg(), i);

#define float32_t float
#define float64_t double

#define RVV_VI_LOOP_CMP_BASE                                    \
  CHECK(rvv_vsew() >= E8 && rvv_vsew() <= E64);                 \
  for (reg_t i = rvv_vstart(); i < rvv_vl(); ++i) {             \
    RVV_VI_LOOP_MASK_SKIP();                                    \
    uint64_t mmask = uint64_t(1) << mpos;                       \
    uint64_t& vdi = Rvvelt<uint64_t>(rvv_vd_reg(), midx, true); \
    uint64_t res = 0;

#define RVV_VI_LOOP_CMP_END                         \
  vdi = (vdi & ~mmask) | (((res) << mpos) & mmask); \
  }                                                 \
  rvv_trace_vd();                                   \
  set_rvv_vstart(0);

// comparision result to masking register
#define RVV_VI_VV_LOOP_CMP(BODY) 
"""


```