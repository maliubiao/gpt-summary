Response: 
Prompt: 
```
这是目录为v8/src/strings/unicode.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file was generated at 2014-10-08 15:25:47.940335

#include "src/strings/unicode.h"

#include <stdio.h>
#include <stdlib.h>

#include <vector>

#include "src/strings/unicode-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/third_party/utf8-decoder/generalized-utf8-decoder.h"
#endif

#ifdef V8_INTL_SUPPORT
#include "unicode/uchar.h"
#endif

namespace unibrow {

#ifndef V8_INTL_SUPPORT
static const int kStartBit = (1 << 30);
static const int kChunkBits = (1 << 13);
#endif  // !V8_INTL_SUPPORT

static const uchar kSentinel = static_cast<uchar>(-1);

/**
 * \file
 * Implementations of functions for working with Unicode.
 */

using int16_t = signed short;     // NOLINT
using uint16_t = unsigned short;  // NOLINT
using int32_t = int;              // NOLINT

#ifndef V8_INTL_SUPPORT
// All access to the character table should go through this function.
template <int D>
static inline uchar TableGet(const int32_t* table, int index) {
  return table[D * index];
}

static inline uchar GetEntry(int32_t entry) { return entry & (kStartBit - 1); }

static inline bool IsStart(int32_t entry) { return (entry & kStartBit) != 0; }

/**
 * Look up a character in the Unicode table using a mix of binary and
 * interpolation search.  For a uniformly distributed array
 * interpolation search beats binary search by a wide margin.  However,
 * in this case interpolation search degenerates because of some very
 * high values in the lower end of the table so this function uses a
 * combination.  The average number of steps to look up the information
 * about a character is around 10, slightly higher if there is no
 * information available about the character.
 */
static bool LookupPredicate(const int32_t* table, uint16_t size, uchar chr) {
  static const int kEntryDist = 1;
  uint16_t value = chr & (kChunkBits - 1);
  unsigned int low = 0;
  unsigned int high = size - 1;
  while (high != low) {
    unsigned int mid = low + ((high - low) >> 1);
    uchar current_value = GetEntry(TableGet<kEntryDist>(table, mid));
    // If we've found an entry less than or equal to this one, and the
    // next one is not also less than this one, we've arrived.
    if ((current_value <= value) &&
        (mid + 1 == size ||
         GetEntry(TableGet<kEntryDist>(table, mid + 1)) > value)) {
      low = mid;
      break;
    } else if (current_value < value) {
      low = mid + 1;
    } else if (current_value > value) {
      // If we've just checked the bottom-most value and it's not
      // the one we're looking for, we're done.
      if (mid == 0) break;
      high = mid - 1;
    }
  }
  int32_t field = TableGet<kEntryDist>(table, low);
  uchar entry = GetEntry(field);
  bool is_start = IsStart(field);
  return (entry == value) || (entry < value && is_start);
}
#endif  // !V8_INTL_SUPPORT

template <int kW>
struct MultiCharacterSpecialCase {
  static const uchar kEndOfEncoding = kSentinel;
  uchar chars[kW];
};

#ifndef V8_INTL_SUPPORT
// Look up the mapping for the given character in the specified table,
// which is of the specified length and uses the specified special case
// mapping for multi-char mappings.  The next parameter is the character
// following the one to map.  The result will be written in to the result
// buffer and the number of characters written will be returned.  Finally,
// if the allow_caching_ptr is non-null then false will be stored in
// it if the result contains multiple characters or depends on the
// context.
// If ranges are linear, a match between a start and end point is
// offset by the distance between the match and the start. Otherwise
// the result is the same as for the start point on the entire range.
template <bool ranges_are_linear, int kW>
static int LookupMapping(const int32_t* table, uint16_t size,
                         const MultiCharacterSpecialCase<kW>* multi_chars,
                         uchar chr, uchar next, uchar* result,
                         bool* allow_caching_ptr) {
  static const int kEntryDist = 2;
  uint16_t key = chr & (kChunkBits - 1);
  uint16_t chunk_start = chr - key;
  unsigned int low = 0;
  unsigned int high = size - 1;
  while (high != low) {
    unsigned int mid = low + ((high - low) >> 1);
    uchar current_value = GetEntry(TableGet<kEntryDist>(table, mid));
    // If we've found an entry less than or equal to this one, and the next one
    // is not also less than this one, we've arrived.
    if ((current_value <= key) &&
        (mid + 1 == size ||
         GetEntry(TableGet<kEntryDist>(table, mid + 1)) > key)) {
      low = mid;
      break;
    } else if (current_value < key) {
      low = mid + 1;
    } else if (current_value > key) {
      // If we've just checked the bottom-most value and it's not
      // the one we're looking for, we're done.
      if (mid == 0) break;
      high = mid - 1;
    }
  }
  int32_t field = TableGet<kEntryDist>(table, low);
  uchar entry = GetEntry(field);
  bool is_start = IsStart(field);
  bool found = (entry == key) || (entry < key && is_start);
  if (found) {
    int32_t value = table[2 * low + 1];
    if (value == 0) {
      // 0 means not present
      return 0;
    } else if ((value & 3) == 0) {
      // Low bits 0 means a constant offset from the given character.
      if (ranges_are_linear) {
        result[0] = chr + (value >> 2);
      } else {
        result[0] = entry + chunk_start + (value >> 2);
      }
      return 1;
    } else if ((value & 3) == 1) {
      // Low bits 1 means a special case mapping
      if (allow_caching_ptr) *allow_caching_ptr = false;
      const MultiCharacterSpecialCase<kW>& mapping = multi_chars[value >> 2];
      int length = 0;
      for (length = 0; length < kW; length++) {
        uchar mapped = mapping.chars[length];
        if (mapped == MultiCharacterSpecialCase<kW>::kEndOfEncoding) break;
        if (ranges_are_linear) {
          result[length] = mapped + (key - entry);
        } else {
          result[length] = mapped;
        }
      }
      return length;
    } else {
      // Low bits 2 means a really really special case
      if (allow_caching_ptr) *allow_caching_ptr = false;
      // The cases of this switch are defined in unicode.py in the
      // really_special_cases mapping.
      switch (value >> 2) {
        case 1:
          // Really special case 1: upper case sigma.  This letter
          // converts to two different lower case sigmas depending on
          // whether or not it occurs at the end of a word.
          if (next != 0 && Letter::Is(next)) {
            result[0] = 0x03C3;
          } else {
            result[0] = 0x03C2;
          }
          return 1;
        default:
          return 0;
      }
      return -1;
    }
  } else {
    return 0;
  }
}
#endif  // !V8_INTL_SUPPORT

// This method decodes an UTF-8 value according to RFC 3629 and
// https://encoding.spec.whatwg.org/#utf-8-decoder .
uchar Utf8::CalculateValue(const uint8_t* str, size_t max_length,
                           size_t* cursor) {
  DCHECK_GT(max_length, 0);
  DCHECK_GT(str[0], kMaxOneByteChar);

  State state = State::kAccept;
  Utf8IncrementalBuffer buffer = 0;
  uchar t;

  const uint8_t* start = str;
  const uint8_t* end = str + max_length;

  do {
    t = ValueOfIncremental(&str, &state, &buffer);
  } while (str < end && t == kIncomplete);

  *cursor += str - start;
  return (state == State::kAccept) ? t : kBadChar;
}

// Finishes the incremental decoding, ensuring that if an unfinished sequence
// is left that it is replaced by a replacement char.
uchar Utf8::ValueOfIncrementalFinish(State* state) {
  if (*state == State::kAccept) {
    return kBufferEmpty;
  } else {
    DCHECK_GT(*state, State::kAccept);
    *state = State::kAccept;
    return kBadChar;
  }
}

bool Utf8::ValidateEncoding(const uint8_t* bytes, size_t length) {
  State state = State::kAccept;
  Utf8IncrementalBuffer throw_away = 0;
  for (size_t i = 0; i < length && state != State::kReject; i++) {
    Utf8DfaDecoder::Decode(bytes[i], &state, &throw_away);
  }
  return state == State::kAccept;
}

// static
void Utf16::ReplaceUnpairedSurrogates(const uint16_t* source_code_units,
                                      uint16_t* dest_code_units,
                                      size_t length) {
  // U+FFFD (REPLACEMENT CHARACTER)
  constexpr uint16_t kReplacement = 0xFFFD;

  for (size_t i = 0; i < length; i++) {
    const uint16_t source_code_unit = source_code_units[i];
    const size_t copy_index = i;
    uint16_t dest_code_unit = source_code_unit;
    if (IsLeadSurrogate(source_code_unit)) {
      // The current code unit is a leading surrogate. If it's not followed by a
      // trailing surrogate, replace it with the replacement character.
      if (i == length - 1 || !IsTrailSurrogate(source_code_units[i + 1])) {
        dest_code_unit = kReplacement;
      } else {
        // Copy the paired trailing surrogate. The paired leading surrogate will
        // be copied below.
        ++i;
        dest_code_units[i] = source_code_units[i];
      }
    } else if (IsTrailSurrogate(source_code_unit)) {
      // All paired trailing surrogates are skipped above, so this branch is
      // only for those that are unpaired.
      dest_code_unit = kReplacement;
    }
    dest_code_units[copy_index] = dest_code_unit;
  }
}

#if V8_ENABLE_WEBASSEMBLY
bool Wtf8::ValidateEncoding(const uint8_t* bytes, size_t length) {
  using State = GeneralizedUtf8DfaDecoder::State;
  auto state = State::kAccept;
  uint32_t current = 0;
  uint32_t previous = 0;
  for (size_t i = 0; i < length; i++) {
    GeneralizedUtf8DfaDecoder::Decode(bytes[i], &state, &current);
    if (state == State::kReject) return false;
    if (state == State::kAccept) {
      if (Utf16::IsTrailSurrogate(current) &&
          Utf16::IsLeadSurrogate(previous)) {
        return false;
      }
      previous = current;
      current = 0;
    }
  }
  return state == State::kAccept;
}

// Precondition: valid WTF-8.
void Wtf8::ScanForSurrogates(v8::base::Vector<const uint8_t> wtf8,
                             std::vector<size_t>* surrogate_offsets) {
  // A surrogate codepoint is encoded in a three-byte sequence:
  //
  //   0xED [0xA0,0xBF] [0x80,0xBF]
  //
  // If the first byte is 0xED, you already have a 50% chance of the value being
  // a surrogate; you just have to check the second byte.  (There are
  // three-byte non-surrogates starting with 0xED whose second byte is in
  // [0x80,0x9F].)  Could speed this up with SWAR; most likely case is that no
  // byte in the array is 0xED.
  const uint8_t kWtf8SurrogateFirstByte = 0xED;
  const uint8_t kWtf8SurrogateSecondByteHighBit = 0x20;

  for (size_t i = 0; i < wtf8.size(); i++) {
    if (wtf8[i] == kWtf8SurrogateFirstByte &&
        (wtf8[i + 1] & kWtf8SurrogateSecondByteHighBit)) {
      // Record the byte offset of the encoded surrogate.
      surrogate_offsets->push_back(i);
    }
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Uppercase:            point.category == 'Lu'
// TODO(jshin): Check if it's ok to exclude Other_Uppercase characters.
#ifdef V8_INTL_SUPPORT
bool Uppercase::Is(uchar c) { return static_cast<bool>(u_isupper(c)); }
#else
static const uint16_t kUppercaseTable0Size = 455;
static const int32_t kUppercaseTable0[455] = {
    1073741889, 90,         1073742016, 214,        1073742040, 222,
    256,        258,        260,        262,        264,        266,
    268,        270,        272,        274,        276,        278,
    280,        282,        284,        286,        288,        290,
    292,        294,        296,        298,        300,        302,
    304,        306,        308,        310,        313,        315,
    317,        319,        321,        323,        325,        327,
    330,        332,        334,        336,        338,        340,
    342,        344,        346,        348,        350,        352,
    354,        356,        358,        360,        362,        364,
    366,        368,        370,        372,        374,        1073742200,
    377,        379,        381,        1073742209, 386,        388,
    1073742214, 391,        1073742217, 395,        1073742222, 401,
    1073742227, 404,        1073742230, 408,        1073742236, 413,
    1073742239, 416,        418,        420,        1073742246, 423,
    425,        428,        1073742254, 431,        1073742257, 435,
    437,        1073742263, 440,        444,        452,        455,
    458,        461,        463,        465,        467,        469,
    471,        473,        475,        478,        480,        482,
    484,        486,        488,        490,        492,        494,
    497,        500,        1073742326, 504,        506,        508,
    510,        512,        514,        516,        518,        520,
    522,        524,        526,        528,        530,        532,
    534,        536,        538,        540,        542,        544,
    546,        548,        550,        552,        554,        556,
    558,        560,        562,        1073742394, 571,        1073742397,
    574,        577,        1073742403, 582,        584,        586,
    588,        590,        880,        882,        886,        895,
    902,        1073742728, 906,        908,        1073742734, 911,
    1073742737, 929,        1073742755, 939,        975,        1073742802,
    980,        984,        986,        988,        990,        992,
    994,        996,        998,        1000,       1002,       1004,
    1006,       1012,       1015,       1073742841, 1018,       1073742845,
    1071,       1120,       1122,       1124,       1126,       1128,
    1130,       1132,       1134,       1136,       1138,       1140,
    1142,       1144,       1146,       1148,       1150,       1152,
    1162,       1164,       1166,       1168,       1170,       1172,
    1174,       1176,       1178,       1180,       1182,       1184,
    1186,       1188,       1190,       1192,       1194,       1196,
    1198,       1200,       1202,       1204,       1206,       1208,
    1210,       1212,       1214,       1073743040, 1217,       1219,
    1221,       1223,       1225,       1227,       1229,       1232,
    1234,       1236,       1238,       1240,       1242,       1244,
    1246,       1248,       1250,       1252,       1254,       1256,
    1258,       1260,       1262,       1264,       1266,       1268,
    1270,       1272,       1274,       1276,       1278,       1280,
    1282,       1284,       1286,       1288,       1290,       1292,
    1294,       1296,       1298,       1300,       1302,       1304,
    1306,       1308,       1310,       1312,       1314,       1316,
    1318,       1320,       1322,       1324,       1326,       1073743153,
    1366,       1073746080, 4293,       4295,       4301,       7680,
    7682,       7684,       7686,       7688,       7690,       7692,
    7694,       7696,       7698,       7700,       7702,       7704,
    7706,       7708,       7710,       7712,       7714,       7716,
    7718,       7720,       7722,       7724,       7726,       7728,
    7730,       7732,       7734,       7736,       7738,       7740,
    7742,       7744,       7746,       7748,       7750,       7752,
    7754,       7756,       7758,       7760,       7762,       7764,
    7766,       7768,       7770,       7772,       7774,       7776,
    7778,       7780,       7782,       7784,       7786,       7788,
    7790,       7792,       7794,       7796,       7798,       7800,
    7802,       7804,       7806,       7808,       7810,       7812,
    7814,       7816,       7818,       7820,       7822,       7824,
    7826,       7828,       7838,       7840,       7842,       7844,
    7846,       7848,       7850,       7852,       7854,       7856,
    7858,       7860,       7862,       7864,       7866,       7868,
    7870,       7872,       7874,       7876,       7878,       7880,
    7882,       7884,       7886,       7888,       7890,       7892,
    7894,       7896,       7898,       7900,       7902,       7904,
    7906,       7908,       7910,       7912,       7914,       7916,
    7918,       7920,       7922,       7924,       7926,       7928,
    7930,       7932,       7934,       1073749768, 7951,       1073749784,
    7965,       1073749800, 7983,       1073749816, 7999,       1073749832,
    8013,       8025,       8027,       8029,       8031,       1073749864,
    8047,       1073749944, 8123,       1073749960, 8139,       1073749976,
    8155,       1073749992, 8172,       1073750008, 8187};
static const uint16_t kUppercaseTable1Size = 86;
static const int32_t kUppercaseTable1[86] = {
    258,        263,  1073742091, 269,  1073742096, 274,        277,
    1073742105, 285,  292,        294,  296,        1073742122, 301,
    1073742128, 307,  1073742142, 319,  325,        387,        1073744896,
    3118,       3168, 1073744994, 3172, 3175,       3177,       3179,
    1073745005, 3184, 3186,       3189, 1073745022, 3200,       3202,
    3204,       3206, 3208,       3210, 3212,       3214,       3216,
    3218,       3220, 3222,       3224, 3226,       3228,       3230,
    3232,       3234, 3236,       3238, 3240,       3242,       3244,
    3246,       3248, 3250,       3252, 3254,       3256,       3258,
    3260,       3262, 3264,       3266, 3268,       3270,       3272,
    3274,       3276, 3278,       3280, 3282,       3284,       3286,
    3288,       3290, 3292,       3294, 3296,       3298,       3307,
    3309,       3314};
static const uint16_t kUppercaseTable5Size = 101;
static const int32_t kUppercaseTable5[101] = {
    1600, 1602, 1604, 1606, 1608, 1610, 1612, 1614,       1616, 1618,
    1620, 1622, 1624, 1626, 1628, 1630, 1632, 1634,       1636, 1638,
    1640, 1642, 1644, 1664, 1666, 1668, 1670, 1672,       1674, 1676,
    1678, 1680, 1682, 1684, 1686, 1688, 1690, 1826,       1828, 1830,
    1832, 1834, 1836, 1838, 1842, 1844, 1846, 1848,       1850, 1852,
    1854, 1856, 1858, 1860, 1862, 1864, 1866, 1868,       1870, 1872,
    1874, 1876, 1878, 1880, 1882, 1884, 1886, 1888,       1890, 1892,
    1894, 1896, 1898, 1900, 1902, 1913, 1915, 1073743741, 1918, 1920,
    1922, 1924, 1926, 1931, 1933, 1936, 1938, 1942,       1944, 1946,
    1948, 1950, 1952, 1954, 1956, 1958, 1960, 1073743786, 1965, 1073743792,
    1969};
static const uint16_t kUppercaseTable7Size = 2;
static const int32_t kUppercaseTable7[2] = {1073749793, 7994};
bool Uppercase::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kUppercaseTable0, kUppercaseTable0Size, c);
    case 1:
      return LookupPredicate(kUppercaseTable1, kUppercaseTable1Size, c);
    case 5:
      return LookupPredicate(kUppercaseTable5, kUppercaseTable5Size, c);
    case 7:
      return LookupPredicate(kUppercaseTable7, kUppercaseTable7Size, c);
    default:
      return false;
  }
}
#endif  // V8_INTL_SUPPORT

// Letter:               point.category in ['Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Nl']
#ifdef V8_INTL_SUPPORT
bool Letter::Is(uchar c) { return static_cast<bool>(u_isalpha(c)); }
#else
static const uint16_t kLetterTable0Size = 431;
static const int32_t kLetterTable0[431] = {
    1073741889, 90,         1073741921, 122,        170,        181,
    186,        1073742016, 214,        1073742040, 246,        1073742072,
    705,        1073742534, 721,        1073742560, 740,        748,
    750,        1073742704, 884,        1073742710, 887,        1073742714,
    893,        895,        902,        1073742728, 906,        908,
    1073742734, 929,        1073742755, 1013,       1073742839, 1153,
    1073742986, 1327,       1073743153, 1366,       1369,       1073743201,
    1415,       1073743312, 1514,       1073743344, 1522,       1073743392,
    1610,       1073743470, 1647,       1073743473, 1747,       1749,
    1073743589, 1766,       1073743598, 1775,       1073743610, 1788,
    1791,       1808,       1073743634, 1839,       1073743693, 1957,
    1969,       1073743818, 2026,       1073743860, 2037,       2042,
    1073743872, 2069,       2074,       2084,       2088,       1073743936,
    2136,       1073744032, 2226,       1073744132, 2361,       2365,
    2384,       1073744216, 2401,       1073744241, 2432,       1073744261,
    2444,       1073744271, 2448,       1073744275, 2472,       1073744298,
    2480,       2482,       1073744310, 2489,       2493,       2510,
    1073744348, 2525,       1073744351, 2529,       1073744368, 2545,
    1073744389, 2570,       1073744399, 2576,       1073744403, 2600,
    1073744426, 2608,       1073744434, 2611,       1073744437, 2614,
    1073744440, 2617,       1073744473, 2652,       2654,       1073744498,
    2676,       1073744517, 2701,       1073744527, 2705,       1073744531,
    2728,       1073744554, 2736,       1073744562, 2739,       1073744565,
    2745,       2749,       2768,       1073744608, 2785,       1073744645,
    2828,       1073744655, 2832,       1073744659, 2856,       1073744682,
    2864,       1073744690, 2867,       1073744693, 2873,       2877,
    1073744732, 2909,       1073744735, 2913,       2929,       2947,
    1073744773, 2954,       1073744782, 2960,       1073744786, 2965,
    1073744793, 2970,       2972,       1073744798, 2975,       1073744803,
    2980,       1073744808, 2986,       1073744814, 3001,       3024,
    1073744901, 3084,       1073744910, 3088,       1073744914, 3112,
    1073744938, 3129,       3133,       1073744984, 3161,       1073744992,
    3169,       1073745029, 3212,       1073745038, 3216,       1073745042,
    3240,       1073745066, 3251,       1073745077, 3257,       3261,
    3294,       1073745120, 3297,       1073745137, 3314,       1073745157,
    3340,       1073745166, 3344,       1073745170, 3386,       3389,
    3406,       1073745248, 3425,       1073745274, 3455,       1073745285,
    3478,       1073745306, 3505,       1073745331, 3515,       3517,
    1073745344, 3526,       1073745409, 3632,       1073745458, 3635,
    1073745472, 3654,       1073745537, 3714,       3716,       1073745543,
    3720,       3722,       3725,       1073745556, 3735,       1073745561,
    3743,       1073745569, 3747,       3749,       3751,       1073745578,
    3755,       1073745581, 3760,       1073745586, 3763,       3773,
    1073745600, 3780,       3782,       1073745628, 3807,       3840,
    1073745728, 3911,       1073745737, 3948,       1073745800, 3980,
    1073745920, 4138,       4159,       1073746000, 4181,       1073746010,
    4189,       4193,       1073746021, 4198,       1073746030, 4208,
    1073746037, 4225,       4238,       1073746080, 4293,       4295,
    4301,       1073746128, 4346,       1073746172, 4680,       1073746506,
    4685,       1073746512, 4694,       4696,       1073746522, 4701,
    1073746528, 4744,       1073746570, 4749,       1073746576, 4784,
    1073746610, 4789,       1073746616, 4798,       4800,       1073746626,
    4805,       1073746632, 4822,       1073746648, 4880,       1073746706,
    4885,       1073746712, 4954,       1073746816, 5007,       1073746848,
    5108,       1073746945, 5740,       1073747567, 5759,       1073747585,
    5786,       1073747616, 5866,       1073747694, 5880,       1073747712,
    5900,       1073747726, 5905,       1073747744, 5937,       1073747776,
    5969,       1073747808, 5996,       1073747822, 6000,       1073747840,
    6067,       6103,       6108,       1073748000, 6263,       1073748096,
    6312,       6314,       1073748144, 6389,       1073748224, 6430,
    1073748304, 6509,       1073748336, 6516,       1073748352, 6571,
    1073748417, 6599,       1073748480, 6678,       1073748512, 6740,
    6823,       1073748741, 6963,       1073748805, 6987,       1073748867,
    7072,       1073748910, 7087,       1073748922, 7141,       1073748992,
    7203,       1073749069, 7247,       1073749082, 7293,       1073749225,
    7404,       1073749230, 7409,       1073749237, 7414,       1073749248,
    7615,       1073749504, 7957,       1073749784, 7965,       1073749792,
    8005,       1073749832, 8013,       1073749840, 8023,       8025,
    8027,       8029,       1073749855, 8061,       1073749888, 8116,
    1073749942, 8124,       8126,       1073749954, 8132,       1073749958,
    8140,       1073749968, 8147,       1073749974, 8155,       1073749984,
    8172,       1073750002, 8180,       1073750006, 8188};
static const uint16_t kLetterTable1Size = 87;
static const int32_t kLetterTable1[87] = {
    113,        127,        1073741968, 156,        258,        263,
    1073742090, 275,        277,        1073742105, 285,        292,
    294,        296,        1073742122, 301,        1073742127, 313,
    1073742140, 319,        1073742149, 329,        334,        1073742176,
    392,        1073744896, 3118,       1073744944, 3166,       1073744992,
    3300,       1073745131, 3310,       1073745138, 3315,       1073745152,
    3365,       3367,       3373,       1073745200, 3431,       3439,
    1073745280, 3478,       1073745312, 3494,       1073745320, 3502,
    1073745328, 3510,       1073745336, 3518,       1073745344, 3526,
    1073745352, 3534,       1073745360, 3542,       1073745368, 3550,
    3631,       1073745925, 4103,       1073745953, 4137,       1073745969,
    4149,       1073745976, 4156,       1073745985, 4246,       1073746077,
    4255,       1073746081, 4346,       1073746172, 4351,       1073746181,
    4397,       1073746225, 4494,       1073746336, 4538,       1073746416,
    4607,       1073746944, 8191};
static const uint16_t kLetterTable2Size = 4;
static const int32_t kLetterTable2[4] = {1073741824, 3509, 1073745408, 8191};
static const uint16_t kLetterTable3Size = 2;
static const int32_t kLetterTable3[2] = {1073741824, 8191};
static const uint16_t kLetterTable4Size = 2;
static const int32_t kLetterTable4[2] = {1073741824, 8140};
static const uint16_t kLetterTable5Size = 100;
static const int32_t kLetterTable5[100] = {
    1073741824, 1164,       1073743056, 1277,       1073743104, 1548,
    1073743376, 1567,       1073743402, 1579,       1073743424, 1646,
    1073743487, 1693,       1073743520, 1775,       1073743639, 1823,
    1073743650, 1928,       1073743755, 1934,       1073743760, 1965,
    1073743792, 1969,       1073743863, 2049,       1073743875, 2053,
    1073743879, 2058,       1073743884, 2082,       1073743936, 2163,
    1073744002, 2227,       1073744114, 2295,       2299,       1073744138,
    2341,       1073744176, 2374,       1073744224, 2428,       1073744260,
    2482,       2511,       1073744352, 2532,       1073744358, 2543,
    1073744378, 2558,       1073744384, 2600,       1073744448, 2626,
    1073744452, 2635,       1073744480, 2678,       2682,       1073744510,
    2735,       2737,       1073744565, 2742,       1073744569, 2749,
    2752,       2754,       1073744603, 2781,       1073744608, 2794,
    1073744626, 2804,       1073744641, 2822,       1073744649, 2830,
    1073744657, 2838,       1073744672, 2854,       1073744680, 2862,
    1073744688, 2906,       1073744732, 2911,       1073744740, 2917,
    1073744832, 3042,       1073744896, 8191};
static const uint16_t kLetterTable6Size = 6;
static const int32_t kLetterTable6[6] = {1073741824, 6051,       1073747888,
                                         6086,       1073747915, 6139};
static const uint16_t kLetterTable7Size = 48;
static const int32_t kLetterTable7[48] = {
    1073748224, 6765,       1073748592, 6873,       1073748736, 6918,
    1073748755, 6935,       6941,       1073748767, 6952,       1073748778,
    6966,       1073748792, 6972,       6974,       1073748800, 6977,
    1073748803, 6980,       1073748806, 7089,       1073748947, 7485,
    1073749328, 7567,       1073749394, 7623,       1073749488, 7675,
    1073749616, 7796,       1073749622, 7932,       1073749793, 7994,
    1073749825, 8026,       1073749862, 8126,       1073749954, 8135,
    1073749962, 8143,       1073749970, 8151,       1073749978, 8156};
bool Letter::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kLetterTable0, kLetterTable0Size, c);
    case 1:
      return LookupPredicate(kLetterTable1, kLetterTable1Size, c);
    case 2:
      return LookupPredicate(kLetterTable2, kLetterTable2Size, c);
    case 3:
      return LookupPredicate(kLetterTable3, kLetterTable3Size, c);
    case 4:
      return LookupPredicate(kLetterTable4, kLetterTable4Size, c);
    case 5:
      return LookupPredicate(kLetterTable5, kLetterTable5Size, c);
    case 6:
      return LookupPredicate(kLetterTable6, kLetterTable6Size, c);
    case 7:
      return LookupPredicate(kLetterTable7, kLetterTable7Size, c);
    default:
      return false;
  }
}
#endif

#ifndef V8_INTL_SUPPORT
// ID_Start:             ((point.category in ['Lu', 'Ll', 'Lt', 'Lm', 'Lo',
// 'Nl'] or 'Other_ID_Start' in point.properties) and ('Pattern_Syntax' not in
// point.properties) and ('Pattern_White_Space' not in point.properties)) or
// ('JS_ID_Start' in point.properties)

static const uint16_t kID_StartTable0Size = 434;
static const int32_t kID_StartTable0[434] = {
    36,         1073741889, 90,         92,         95,         1073741921,
    122,        170,        181,        186,        1073742016, 214,
    1073742040, 246,        1073742072, 705,        1073742534, 721,
    1073742560, 740,        748,        750,        1073742704, 884,
    1073742710, 887,        1073742714, 893,        895,        902,
    1073742728, 906,        908,        1073742734, 929,        1073742755,
    1013,       1073742839, 1153,       1073742986, 1327,       1073743153,
    1366,       1369,       1073743201, 1415,       1073743312, 1514,
    1073743344, 1522,       1073743392, 1610,       1073743470, 1647,
    1073743473, 1747,       1749,       1073743589, 1766,       1073743598,
    1775,       1073743610, 1788,       1791,       1808,       1073743634,
    1839,       1073743693, 1957,       1969,       1073743818, 2026,
    1073743860, 2037,       2042,       1073743872, 2069,       2074,
    2084,       2088,       1073743936, 2136,       1073744032, 2226,
    1073744132, 2361,       2365,       2384,       1073744216, 2401,
    1073744241, 2432,       1073744261, 2444,       1073744271, 2448,
    1073744275, 2472,       1073744298, 2480,       2482,       1073744310,
    2489,       2493,       2510,       1073744348, 2525,       1073744351,
    2529,       1073744368, 2545,       1073744389, 2570,       1073744399,
    2576,       1073744403, 2600,       1073744426, 2608,       1073744434,
    2611,       1073744437, 2614,       1073744440, 2617,       1073744473,
    2652,       2654,       1073744498, 2676,       1073744517, 2701,
    1073744527, 2705,       1073744531, 2728,       1073744554, 2736,
    1073744562, 2739,       1073744565, 2745,       2749,       2768,
    1073744608, 2785,       1073744645, 2828,       1073744655, 2832,
    1073744659, 2856,       1073744682, 2864,       1073744690, 2867,
    1073744693, 2873,       2877,       1073744732, 2909,       1073744735,
    2913,       2929,       2947,       1073744773, 2954,       1073744782,
    2960,       1073744786, 2965,       1073744793, 2970,       2972,
    1073744798, 2975,       1073744803, 2980,       1073744808, 2986,
    1073744814, 3001,       3024,       1073744901, 3084,       1073744910,
    3088,       1073744914, 3112,       1073744938, 3129,       3133,
    1073744984, 3161,       1073744992, 3169,       1073745029, 3212,
    1073745038, 3216,       1073745042, 3240,       1073745066, 3251,
    1073745077, 3257,       3261,       3294,       1073745120, 3297,
    1073745137, 3314,       1073745157, 3340,       1073745166, 3344,
    1073745170, 3386,       3389,       3406,       1073745248, 3425,
    1073745274, 3455,       1073745285, 3478,       1073745306, 3505,
    1073745331, 3515,       3517,       1073745344, 3526,       1073745409,
    3632,       1073745458, 3635,       1073745472, 3654,       1073745537,
    3714,       3716,       1073745543, 3720,       3722,       3725,
    1073745556, 3735,       1073745561, 3743,       1073745569, 3747,
    3749,       3751,       1073745578, 3755,       1073745581, 3760,
    1073745586, 3763,       3773,       1073745600, 3780,       3782,
    1073745628, 3807,       3840,       1073745728, 3911,       1073745737,
    3948,       1073745800, 3980,       1073745920, 4138,       4159,
    1073746000, 4181,       1073746010, 4189,       4193,       1073746021,
    4198,       1073746030, 4208,       1073746037, 4225,       4238,
    1073746080, 4293,       4295,       4301,       1073746128, 4346,
    1073746172, 4680,       1073746506, 4685,       1073746512, 4694,
    4696,       1073746522, 4701,       1073746528, 4744,       1073746570,
    4749,       1073746576, 4784,       1073746610, 4789,       1073746616,
    4798,       4800,       1073746626, 4805,       1073746632, 4822,
    1073746648, 4880,       1073746706, 4885,       1073746712, 4954,
    1073746816, 5007,       1073746848, 5108,       1073746945, 5740,
    1073747567, 5759,       1073747585, 5786,       1073747616, 5866,
    1073747694, 5880,       1073747712, 5900,       1073747726, 5905,
    1073747744, 5937,       1073747776, 5969,       1073747808, 5996,
    1073747822, 6000,       1073747840, 6067,       6103,       6108,
    1073748000, 6263,       1073748096, 6312,       6314,       1073748144,
    6389,       1073748224, 6430,       1073748304, 6509,       1073748336,
    6516,       1073748352, 6571,       1073748417, 6599,       1073748480,
    6678,       1073748512, 6740,       6823,       1073748741, 6963,
    1073748805, 6987,       1073748867, 7072,       1073748910, 7087,
    1073748922, 7141,       1073748992, 7203,       1073749069, 7247,
    1073749082, 7293,       1073749225, 7404,       1073749230, 7409,
    1073749237, 7414,       1073749248, 7615,       1073749504, 7957,
    1073749784, 7965,       1073749792, 8005,       1073749832, 8013,
    1073749840, 8023,       8025,       8027,       8029,       1073749855,
    8061,       1073749888, 8116,       1073749942, 8124,       8126,
    1073749954, 8132,       1073749958, 8140,       1073749968, 8147,
    1073749974, 8155,       1073749984, 8172,       1073750002, 8180,
    1073750006, 8188};
static const uint16_t kID_StartTable1Size = 84;
static const int32_t kID_StartTable1[84] = {
    113,        127,        1073741968, 156,        258,        263,
    1073742090, 275,        277,        1073742104, 285,        292,
    294,        296,        1073742122, 313,        1073742140, 319,
    1073742149, 329,        334,        1073742176, 392,        1073744896,
    3118,       1073744944, 3166,       1073744992, 3300,       1073745131,
    3310,       1073745138, 3315,       1073745152, 3365,       3367,
    3373,       1073745200, 3431,       3439,       1073745280, 3478,
    1073745312, 3494,       1073745320, 3502,       1073745328, 3510,
    1073745336, 3518,       1073745344, 3526,       1073745352, 3534,
    1073745360, 3542,       1073745368, 3550,       1073745925, 4103,
    1073745953, 4137,       1073745969, 4149,       1073745976, 4156,
    1073745985, 4246,       1073746075, 4255,       1073746081, 4346,
    1073746172, 4351,       1073746181, 4397,       1073746225, 4494,
    1073746336, 4538,       1073746416, 4607,       1073746944, 8191};
static const uint16_t kID_StartTable2Size = 4;
static const int32_t kID_StartTable2[4] = {1073741824, 3509, 1073745408, 8191};
static const uint16_t kID_StartTable3Size = 2;
static const int32_t kID_StartTable3[2] = {1073741824, 8191};
static const uint16_t kID_StartTable4Size = 2;
static const int32_t kID_StartTable4[2] = {1073741824, 8140};
static const uint16_t kID_StartTable5Size = 100;
static const int32_t kID_StartTable5[100] = {
    1073741824, 1164,       1073743056, 1277,       1073743104, 1548,
    1073743376, 1567,       1073743402, 1579,       1073743424, 1646,
    1073743487, 1693,       1073743520, 1775,       1073743639, 1823,
    1073743650, 1928,       1073743755, 1934,       1073743760, 1965,
    1073743792, 1969,       1073743863, 2049,       1073743875, 2053,
    1073743879, 2058,       1073743884, 2082,       1073743936, 2163,
    1073744002, 2227,       1073744114, 2295,       2299,       1073744138,
    2341,       1073744176, 2374,       1073744224, 2428,       1073744260,
    2482,       2511,       1073744352, 2532,       1073744358, 2543,
    1073744378, 2558,       1073744384, 2600,       1073744448, 2626,
    1073744452, 2635,       1073744480, 2678,       2682,       1073744510,
    2735,       2737,       1073744565, 2742,       1073744569, 2749,
    2752,       2754,       1073744603, 2781,       1073744608, 2794,
    1073744626, 2804,       1073744641, 2822,       1073744649, 2830,
    1073744657, 2838,       1073744672, 2854,       1073744680, 2862,
    1073744688, 2906,       1073744732, 2911,       1073744740, 2917,
    1073744832, 3042,       1073744896, 8191};
static const uint16_t kID_StartTable6Size = 6;
static const int32_t kID_StartTable6[6] = {1073741824, 6051,       1073747888,
                                           6086,       1073747915, 6139};
static const uint16_t kID_StartTable7Size = 48;
static const int32_t kID_StartTable7[48] = {
    1073748224, 6765,       1073748592, 6873,       1073748736, 6918,
    1073748755, 6935,       6941,       1073748767, 6952,       1073748778,
    6966,       1073748792, 6972,       6974,       1073748800, 6977,
    1073748803, 6980,       1073748806, 7089,       1073748947, 7485,
    1073749328, 7567,       1073749394, 7623,       1073749488, 7675,
    1073749616, 7796,       1073749622, 7932,       1073749793, 7994,
    1073749825, 8026,       1073749862, 8126,       1073749954, 8135,
    1073749962, 8143,       1073749970, 8151,       1073749978, 8156};
bool ID_Start::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kID_StartTable0, kID_StartTable0Size, c);
    case 1:
      return LookupPredicate(kID_StartTable1, kID_StartTable1Size, c);
    case 2:
      return LookupPredicate(kID_StartTable2, kID_StartTable2Size, c);
    case 3:
      return LookupPredicate(kID_StartTable3, kID_StartTable3Size, c);
    case 4:
      return LookupPredicate(kID_StartTable4, kID_StartTable4Size, c);
    case 5:
      return LookupPredicate(kID_StartTable5, kID_StartTable5Size, c);
    case 6:
      return LookupPredicate(kID_StartTable6, kID_StartTable6Size, c);
    case 7:
      return LookupPredicate(kID_StartTable7, kID_StartTable7Size, c);
    default:
      return false;
  }
}

// ID_Continue:          point.category in ['Nd', 'Mn', 'Mc', 'Pc'] or
// 'Other_ID_Continue' in point.properties or 'JS_ID_Continue' in
// point.properties

static const uint16_t kID_ContinueTable0Size = 315;
static const int32_t kID_ContinueTable0[315] = {
    1073741872, 57,         95,         183,        1073742592, 879,
    903,        1073742979, 1159,       1073743249, 1469,       1471,
    1073743297, 1474,       1073743300, 1477,       1479,       1073743376,
    1562,       1073743435, 1641,       1648,       1073743574, 1756,
    1073743583, 1764,       1073743591, 1768,       1073743594, 1773,
    1073743600, 1785,       1809,       1073743664, 1866,       1073743782,
    1968,       1073743808, 1993,       1073743851, 2035,       1073743894,
    2073,       1073743899, 2083,       1073743909, 2087,       1073743913,
    2093,       1073743961, 2139,       1073744100, 2307,       1073744186,
    2364,       1073744190, 2383,       1073744209, 2391,       1073744226,
    2403,       1073744230, 2415,       1073744257, 2435,       2492,
    1073744318, 2500,       1073744327, 2504,       1073744331, 2509,
    2519,       1073744354, 2531,       1073744358, 2543,       1073744385,
    2563,       2620,       1073744446, 2626,       1073744455, 2632,
    1073744459, 2637,       2641,       1073744486, 2673,       2677,
    1073744513, 2691,       2748,       1073744574, 2757,       1073744583,
    2761,       1073744587, 2765,       1073744610, 2787,       1073744614,
    2799,       1073744641, 2819,       2876,       1073744702, 2884,
    1073744711, 2888,       1073744715, 2893,       1073744726, 2903,
    1073744738, 2915,       1073744742, 2927,       2946,       1073744830,
    3010,       1073744838, 3016,       1073744842, 3021,       3031,
    1073744870, 3055,       1073744896, 3075,       1073744958, 3140,
    1073744966, 3144,       1073744970, 3149,       1073744981, 3158,
    1073744994, 3171,       1073744998, 3183,       1073745025, 3203,
    3260,       1073745086, 3268,       1073745094, 3272,       1073745098,
    3277,       1073745109, 3286,       1073745122, 3299,       1073745126,
    3311,       1073745153, 3331,       1073745214, 3396,       1073745222,
    3400,       1073745226, 3405,       3415,       1073745250, 3427,
    1073745254, 3439,       1073745282, 3459,       3530,       1073745359,
    3540,       3542,       1073745368, 3551,       1073745382, 3567,
    1073745394, 3571,       3633,       1073745460, 3642,       1073745479,
    3662,       1073745488, 3673,       3761,       1073745588, 3769,
    1073745595, 3772,       1073745608, 3789,       1073745616, 3801,
    1073745688, 3865,       1073745696, 3881,       3893,       3895,
    3897,       1073745726, 3903,       1073745777, 3972,       1073745798,
    3975,       1073745805, 3991,       1073745817, 4028,       4038,
    1073745963, 4158,       1073745984, 4169,       1073746006, 4185,
    1073746014, 4192,       1073746018, 4196,       1073746023, 4205,
    1073746033, 4212,       1073746050, 4237,       1073746063, 4253,
    1073746781, 4959,       1073746793, 4977,       1073747730, 5908,
    1073747762, 5940,       1073747794, 5971,       1073747826, 6003,
    1073747892, 6099,       6109,       1073747936, 6121,       1073747979,
    6157,       1073747984, 6169,       6313,       1073748256, 6443,
    1073748272, 6459,       1073748294, 6479,       1073748400, 6592,
    1073748424, 6601,       1073748432, 6618,       1073748503, 6683,
    1073748565, 6750,       1073748576, 6780,       1073748607, 6793,
    1073748624, 6809,       1073748656, 6845,       1073748736, 6916,
    1073748788, 6980,       1073748816, 7001,       1073748843, 7027,
    1073748864, 7042,       1073748897, 7085,       1073748912, 7097,
    1073748966, 7155,       1073749028, 7223,       1073749056, 7241,
    1073749072, 7257,       1073749200, 7378,       1073749204, 7400,
    7405,       1073749234, 7412,       1073749240, 7417,       1073749440,
    7669,       1073749500, 7679};
static const uint16_t kID_ContinueTable1Size = 19;
static const int32_t kID_ContinueTable1[19] = {
    1073741836, 13,   1073741887, 64,         84,
    1073742032, 220,  225,        1073742053, 240,
    1073745135, 3313, 3455,       1073745376, 3583,
    1073745962, 4143, 1073746073, 4250};
static const uint16_t kID_ContinueTable5Size = 63;
static const int32_t kID_ContinueTable5[63] = {
    1073743392, 1577,       1647,       1073743476, 1661,       1695,
    1073743600, 1777,       2050,       2054,       2059,       1073743907,
    2087,       1073744000, 2177,       1073744052, 2244,       1073744080,
    2265,       1073744096, 2289,       1073744128, 2313,       1073744166,
    2349,       1073744199, 2387,       1073744256, 2435,       1073744307,
    2496,       1073744336, 2521,       2533,       1073744368, 2553,
    1073744425, 2614,       2627,       1073744460, 2637,       1073744464,
    2649,       1073744507, 2685,       2736,       1073744562, 2740,
    1073744567, 2744,       1073744574, 2751,       2753,       1073744619,
    2799,       1073744629, 2806,       1073744867, 3050,       1073744876,
    3053,       1073744880, 3065};
static const uint16_t kID_ContinueTable7Size = 12;
static const int32_t kID_ContinueTable7[12] = {
    6942, 1073749504, 7695, 1073749536, 7725, 1073749555,
    7732, 1073749581, 7759, 1073749776, 7961, 7999};
bool ID_Continue::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kID_ContinueTable0, kID_ContinueTable0Size, c);
    case 1:
      return LookupPredicate(kID_ContinueTable1, kID_ContinueTable1Size, c);
    case 5:
      return LookupPredicate(kID_ContinueTable5, kID_ContinueTable5Size, c);
    case 7:
      return LookupPredicate(kID_ContinueTable7, kID_ContinueTable7Size, c);
    default:
      return false;
  }
}

// WhiteSpace:           (point.category == 'Zs') or ('JS_White_Space' in
// point.properties)

static const uint16_t kWhiteSpaceTable0Size = 6;
static const int32_t kWhiteSpaceTable0[6] = {9, 1073741835, 12, 32, 160, 5760};
static const uint16_t kWhiteSpaceTable1Size = 5;
static const int32_t kWhiteSpaceTable1[5] = {1073741824, 10, 47, 95, 4096};
static const uint16_t kWhiteSpaceTable7Size = 1;
static const int32_t kWhiteSpaceTable7[1] = {7935};
bool WhiteSpace::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kWhiteSpaceTable0, kWhiteSpaceTable0Size, c);
    case 1:
      return LookupPredicate(kWhiteSpaceTable1, kWhiteSpaceTable1Size, c);
    case 7:
      return LookupPredicate(kWhiteSpaceTable7, kWhiteSpaceTable7Size, c);
    default:
      return false;
  }
}
#endif  // !V8_INTL_SUPPORT

#ifndef V8_INTL_SUPPORT
static const MultiCharacterSpecialCase<2> kToLowercaseMultiStrings0[2] = {
    {{105, 775}}, {{kSentinel}}};
static const uint16_t kToLowercaseTable0Size = 488;
static const int32_t kToLowercaseTable0[976] = {
    1073741889, 128,   90,         128,   1073742016, 128,   214,        128,
    1073742040, 128,   222,        128,   256,        4,     258,        4,
    260,        4,     262,        4,     264,        4,     266,        4,
    268,        4,     270,        4,     272,        4,     274,        4,
    276,        4,     278,        4,     280,        4,     282,        4,
    284,        4,     286,        4,     288,        4,     290,        4,
    292,        4,     294,        4,     296,        4,     298,        4,
    300,        4,     302,        4,     304,        1,     306,        4,
    308,        4,     310,        4,     313,        4,     315,        4,
    317,        4,     319,        4,     321,        4,     323,        4,
    325,        4,     327,        4,     330,        4,     332,        4,
    334,        4,     336,        4,     338,        4,     340,        4,
    342,        4,     344,        4,     346,        4,     348,        4,
    350,        4,     352,        4,     354,        4,     356,        4,
    358,        4,     360,        4,     362,        4,     364,        4,
    366,        4,     368,        4,     370,        4,     372,        4,
    374,        4,     376,        -484,  377,        4,     379,        4,
    381,        4,     385,        840,   386,        4,     388,        4,
    390,        824,   391,        4,     1073742217, 820,   394,        820,
    395,        4,     398,        316,   399,        808,   400,        812,
    401,        4,     403,        820,   404,        828,   406,        844,
    407,        836,   408,        4,     412,        844,   413,        852,
    415,        856,   416,        4,     418,        4,     420,        4,
    422,        872,   423,        4,     425,        872,   428,        4,
    430,        872,   431,        4,     1073742257, 868,   434,        868,
    435,        4,     437,        4,     439,        876,   440,        4,
    444,        4,     452,        8,     453,        4,     455,        8,
    456,        4,     458,        8,     459,        4,     461,        4,
    463,        4,     465,        4,     467,        4,     469,        4,
    471,        4,     473,        4,     475,        4,     478,        4,
    480,        4,     482,        4,     484,        4,     486,        4,
    488,        4,     490,        4,     492,        4,     494,        4,
    497,        8,     498,        4,     500,        4,     502,        -388,
    503,        -224,  504,        4,     506,        4,     508,        4,
    510,        4,     512,        4,     514,        4,     516,        4,
    518,        4,     520,        4,     522,        4,     524,        4,
    526,        4,     528,        4,     530,        4,     532,        4,
    534,        4,     536,        4,     538,        4,     540,        4,
    542,        4,     544,        -520,  546,        4,     548,        4,
    550,        4,     552,        4,     554,        4,     556,        4,
    558,        4,     560,        4,     562,        4,     570,        43180,
    571,        4,     573,        -652,  574,        43168, 577,        4,
    579,        -780,  580,        276,   581,        284,   582,        4,
    584,        4,     586,        4,     588,        4,     590,        4,
    880,        4,     882,        4,     886,        4,     895,        464,
    902,        152,   1073742728, 148,   906,        148,   908,        256,
    1073742734, 252,   911,        252,   1073742737, 128,   929,        128,
    931,        6,     1073742756, 128,   939,        128,   975,        32,
    984,        4,     986,        4,     988,        4,     990,        4,
    992,        4,     994,        4,     996,        4,     998,        4,
    1000,       4,     1002,       4,     1004,       4,     1006,       4,
    1012,       -240,  1015,       4,     1017,       -28,   1018,       4,
    1073742845, -520,  1023,       -520,  1073742848, 320,   1039,       320,
    1073742864, 128,   1071,       128,   1120,       4,     1122,       4,
    1124,       4,     1126,       4,     1128,       4,     1130,       4,
    1132,       4,     1134,       4,     1136,       4,     1138,       4,
    1140,       4,     1142,       4,     1144,       4,     1146,       4,
    1148,       4,     1150,       4,     1152,       4,     1162,       4,
    1164,       4,     1166,       4,     1168,       4,     1170,       4,
    1172,       4,     1174,       4,     1176,       4,     1178,       4,
    1180,       4,     1182,       4,     1184,       4,     1186,       4,
    1188,       4,     1190,       4,     1192,       4,     1194,       4,
    1196,       4,     1198,       4,     1200,       4,     1202,       4,
    1204,       4,     1206,       4,     1208,       4,     1210,       4,
    1212,       4,     1214,       4,     1216,       60,    1217,       4,
    1219,       4,     1221,       4,     1223,       4,     1225,       4,
    1227,       4,     1229,       4,     1232,       4,     1234,       4,
    1236,       4,     1238,       4,     1240,       4,     1242,       4,
    1244,       4,     1246,       4,     1248,       4,     1250,       4,
    1252,       4,     1254,       4,     1256,       4,     1258,       4,
    1260,       4,     1262,       4,     1264,       4,     1266,       4,
    1268,       4,     1270,       4,     1272,       4,     1274,       4,
    1276,       4,     1278,       4,     1280,       4,     1282,       4,
    1284,       4,     1286,       4,     1288,       4,     1290,       4,
    1292,       4,     1294,       4,     1296,       4,     1298,       4,
    1300,       4,     1302,       4,     1304,       4,     1306,       4,
    1308,       4,     1310,       4,     1312,       4,     1314,       4,
    1316,       4,     1318,       4,     1320,       4,     1322,       4,
    1324,       4,     1326,       4,     1073743153, 192,   1366,       192,
    1073746080, 29056, 4293,       29056, 4295,       29056, 4301,       29056,
    7680,       4,     7682,       4,     7684,       4,     7686,       4,
    7688,       4,     7690,       4,     7692,       4,     7694,       4,
    7696,       4,     7698,       4,     7700,       4,     7702,       4,
    7704,       4,     7706,       4,     7708,       4,     7710,       4,
    7712,       4,     7714,       4,     7716,       4,     7718,       4,
    7720,       4,     7722,       4,     7724,       4,     7726,       4,
    7728,       4,     7730,       4,     7732,       4,     7734,       4,
    7736,       4,     7738,       4,     7740,       4,     7742,       4,
    7744,       4,     7746,       4,     7748,       4,     7750,       4,
    7752,       4,     7754,       4,     7756,       4,     7758,       4,
    7760,       4,     7762,       4,     7764,       4,     7766,       4,
    7768,       4,     7770,       4,     7772,       4,     7774,       4,
    7776,       4,     7778,       4,     7780,       4,     7782,       4,
    7784,       4,     7786,       4,     7788,       4,     7790,       4,
    7792,       4,     7794,       4,     7796,       4,     7798,       4,
    7800,       4,     7802,       4,     7804,       4,     7806,       4,
    7808,       4,     7810,       4,     7812,       4,     7814,       4,
    7816,       4,     7818,       4,     7820,       4,     7822,       4,
    7824,       4,     7826,       4,     7828,       4,     7838,       -30460,
    7840,       4,     7842,       4,     7844,       4,     7846,       4,
    7848,       4,     7850,       4,     7852,       4,     7854,       4,
    7856,       4,     7858,       4,     7860,       4,     7862,       4,
    7864,       4,     7866,       4,     7868,       4,     7870,       4,
    7872,       4,     7874,       4,     7876,       4,     7878,       4,
    7880,       4,     7882,       4,     7884,       4,     7886,       4,
    7888,       4,     7890,       4,     7892,       4,     7894,       4,
    7896,       4,     7898,       4,     7900,       4,     7902,       4,
    7904,       4,     7906,       4,     7908,       4,     7910,       4,
    7912,       4,     7914,       4,     7916,       4,     7918,       4,
    7920,       4,     7922,       4,     7924,       4,     7926,       4,
    7928,       4,     7930,       4,     7932,       4,     7934,       4,
    1073749768, -32,   7951,       -32,   1073749784, -32,   7965,       -32,
    1073749800, -32,   7983,       -32,   1073749816, -32,   7999,       -32,
    1073749832, -32,   8013,       -32,   8025,       -32,   8027,       -32,
    8029,       -32,   8031,       -32,   1073749864, -32,   8047,       -32,
    1073749896, -32,   8079,       -32,   1073749912, -32,   8095,       -32,
    1073749928, -32,   8111,       -32,   1073749944, -32,   8121,       -32,
    1073749946, -296,  8123,       -296,  8124,       -36,   1073749960, -344,
    8139,       -344,  8140,       -36,   1073749976, -32,   8153,       -32,
    1073749978, -400,  8155,       -400,  1073749992, -32,   8169,       -32,
    1073749994, -448,  8171,       -448,  8172,       -28,   1073750008, -512,
    8185,       -512,  1073750010, -504,  8187,       -504,  8188,       -36};
static const uint16_t kToLowercaseMultiStrings0Size = 2;
static const MultiCharacterSpecialCase<1> kToLowercaseMultiStrings1[1] = {
    {{kSentinel}}};
static const uint16_t kToLowercaseTable1Size = 79;
static const int32_t kToLowercaseTable1[158] = {
    294,        -30068, 298,        -33532, 299,  -33048, 306,        112,
    1073742176, 64,     367,        64,     387,  4,      1073743030, 104,
    1231,       104,    1073744896, 192,    3118, 192,    3168,       4,
    3170,       -42972, 3171,       -15256, 3172, -42908, 3175,       4,
    3177,       4,      3179,       4,      3181, -43120, 3182,       -42996,
    3183,       -43132, 3184,       -43128, 3186, 4,      3189,       4,
    1073745022, -43260, 3199,       -43260, 3200, 4,      3202,       4,
    3204,       4,      3206,       4,      3208, 4,      3210,       4,
    3212,       4,      3214,       4,      3216, 4,      3218,       4,
    3220,       4,      3222,       4,      3224, 4,      3226,       4,
    3228,       4,      3230,       4,      3232, 4,      3234,       4,
    3236,       4,      3238,       4,      3240, 4,      3242,       4,
    3244,       4,      3246,       4,      3248, 4,      3250,       4,
    3252,       4,      3254,       4,      3256, 4,      3258,       4,
    3260,       4,      3262,       4,      3264, 4,      3266,       4,
    3268,       4,      3270,       4,      3272, 4,      3274,       4,
    3276,       4,      3278,       4,      3280, 4,      3282,       4,
    3284,       4,      3286,       4,      3288, 4,      3290,       4,
    3292,       4,      3294,       4,      3296, 4,      3298,       4,
    3307,       4,      3309,       4,      3314, 4};
static const uint16_t kToLowercaseMultiStrings1Size = 1;
static const MultiCharacterSpecialCase<1> kToLowercaseMultiStrings5[1] = {
    {{kSentinel}}};
static const uint16_t kToLowercaseTable5Size = 103;
static const int32_t kToLowercaseTable5[206] = {
    1600, 4,       1602, 4,       1604, 4,       1606, 4,       1608, 4,
    1610, 4,       1612, 4,       1614, 4,       1616, 4,       1618, 4,
    1620, 4,       1622, 4,       1624, 4,       1626, 4,       1628, 4,
    1630, 4,       1632, 4,       1634, 4,       1636, 4,       1638, 4,
    1640, 4,       1642, 4,       1644, 4,       1664, 4,       1666, 4,
    1668, 4,       1670, 4,       1672, 4,       1674, 4,       1676, 4,
    1678, 4,       1680, 4,       1682, 4,       1684, 4,       1686, 4,
    1688, 4,       1690, 4,       1826, 4,       1828, 4,       1830, 4,
    1832, 4,       1834, 4,       1836, 4,       1838, 4,       1842, 4,
    1844, 4,       1846, 4,       1848, 4,       1850, 4,       1852, 4,
    1854, 4,       1856, 4,       1858, 4,       1860, 4,       1862, 4,
    1864, 4,       1866, 4,       1868, 4,       1870, 4,       1872, 4,
    1874, 4,       1876, 4,       1878, 4,       1880, 4,       1882, 4,
    1884, 4,       1886, 4,       1888, 4,       1890, 4,       1892, 4,
    1894, 4,       1896, 4,       1898, 4,       1900, 4,       1902, 4,
    1913, 4,       1915, 4,       1917, -141328, 1918, 4,       1920, 4,
    1922, 4,       1924, 4,       1926, 4,       1931, 4,       1933, -169120,
    1936, 4,       1938, 4,       1942, 4,       1944, 4,       1946, 4,
    1948, 4,       1950, 4,       1952, 4,       1954, 4,       1956, 4,
    1958, 4,       1960, 4,       1962, -169232, 1963, -169276, 1964, -169260,
    1965, -169220, 1968, -169032, 1969, -169128};
static const uint16_t kToLowercaseMultiStrings5Size = 1;
static const MultiCharacterSpecialCase<1> kToLowercaseMultiStrings7[1] = {
    {{kSentinel}}};
static const uint16_t kToLowercaseTable7Size = 2;
static const int32_t kToLowercaseTable7[4] = {1073749793, 128, 7994, 128};
static const uint16_t kToLowercaseMultiStrings7Size = 1;
int ToLowercase::Convert(uchar c, uchar n, uchar* result,
                         bool* allow_caching_ptr) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupMapping<true>(kToLowercaseTable0, kToLowercaseTable0Size,
                                 kToLowercaseMultiStrings0, c, n, result,
                                 allow_caching_ptr);
    case 1:
      return LookupMapping<true>(kToLowercaseTable1, kToLowercaseTable1Size,
                                 kToLowercaseMultiStrings1, c, n, result,
                                 allow_caching_ptr);
    case 5:
      return LookupMapping<true>(kToLowercaseTable5, kToLowercaseTable5Size,
                                 kToLowercaseMultiStrings5, c, n, result,
                                 allow_caching_ptr);
    case 7:
      return LookupMapping<true>(kToLowercaseTable7, kToLowercaseTable7Size,
                                 kToLowercaseMultiStrings7, c, n, result,
                                 allow_caching_ptr);
    default:
      return 0;
  }
}

static const MultiCharacterSpecialCase<3> kToUppercaseMultiStrings0[62] = {
    {{83, 83, kSentinel}},    {{700, 78, kSentinel}},
    {{74, 780, kSentinel}},   {{921, 776, 769}},
    {{933, 776, 769}},        {{1333, 1362, kSentinel}},
    {{72, 817, kSentinel}},   {{84, 776, kSentinel}},
    {{87, 778, kSentinel}},   {{89, 778, kSentinel}},
    {{65, 702, kSentinel}},   {{933, 787, kSentinel}},
    {{933, 787, 768}},        {{933, 787, 769}},
    {{933, 787, 834}},        {{7944, 921, kSentinel}},
    {{7945, 921, kSentinel}}, {{7946, 921, kSentinel}},
    {{7947, 921, kSentinel}}, {{7948, 921, kSentinel}},
    {{7949, 921, kSentinel}}, {{7950, 921, kSentinel}},
    {{7951, 921, kSentinel}}, {{7976, 921, kSentinel}},
    {{7977, 921, kSentinel}}, {{7978, 921, kSentinel}},
    {{7979, 921, kSentinel}}, {{7980, 921, kSentinel}},
    {{7981, 921, kSentinel}}, {{7982, 921, kSentinel}},
    {{7983, 921, kSentinel}}, {{8040, 921, kSentinel}},
    {{8041, 921, kSentinel}}, {{8042, 921, kSentinel}},
    {{8043, 921, kSentinel}}, {{8044, 921, kSentinel}},
    {{8045, 921, kSentinel}}, {{8046, 921, kSentinel}},
    {{8047, 921, kSentinel}}, {{8122, 921, kSentinel}},
    {{913, 921, kSentinel}},  {{902, 921, kSentinel}},
    {{913, 834, kSentinel}},  {{913, 834, 921}},
    {{8138, 921, kSentinel}}, {{919, 921, kSentinel}},
    {{905, 921, kSentinel}},  {{919, 834, kSentinel}},
    {{919, 834, 921}},        {{921, 776, 768}},
    {{921, 834, kSentinel}},  {{921, 776, 834}},
    {{933, 776, 768}},        {{929, 787, kSentinel}},
    {{933, 834, kSentinel}},  {{933, 776, 834}},
    {{8186, 921, kSentinel}}, {{937, 921, kSentinel}},
    {{911, 921, kSentinel}},  {{937, 834, kSentinel}},
    {{937, 834, 921}},        {{kSentinel}}};
static const uint16_t kToUppercaseTable0Size = 590;
static const int32_t kToUppercaseTable0[1180] = {
    1073741921, -128,   122,        -128,   181,        2972,
    223,        1,      1073742048, -128,   246,        -128,
    1073742072, -128,   254,        -128,   255,        484,
    257,        -4,     259,        -4,     261,        -4,
    263,        -4,     265,        -4,     267,        -4,
    269,        -4,     271,        -4,     273,        -4,
    275,        -4,     277,        -4,     279,        -4,
    281,        -4,     283,        -4,     285,        -4,
    287,        -4,     289,        -4,     291,        -4,
    293,        -4,     295,        -4,     297,        -4,
    299,        -4,     301,        -4,     303,        -4,
    305,        -928,   307,        -4,     309,        -4,
    311,        -4,     314,        -4,     316,        -4,
    318,        -4,     320,        -4,     322,        -4,
    324,        -4,     326,        -4,     328,        -4,
    329,        5,      331,        -4,     333,        -4,
    335,        -4,     337,        -4,     339,        -4,
    341,        -4,     343,        -4,     345,        -4,
    347,        -4,     349,        -4,     351,        -4,
    353,        -4,     355,        -4,     357,        -4,
    359,        -4,     361,        -4,     363,        -4,
    365,        -4,     367,        -4,     369,        -4,
    371,        -4,     373,        -4,     375,        -4,
    378,        -4,     380,        -4,     382,        -4,
    383,        -1200,  384,        780,    387,        -4,
    389,        -4,     392,        -4,     396,        -4,
    402,        -4,     405,        388,    409,        -4,
    410,        652,    414,        520,    417,        -4,
    419,        -4,     421,        -4,     424,        -4,
    429,        -4,     432,        -4,     436,        -4,
    438,        -4,     441,        -4,     445,        -4,
    447,        224,    453,        -4,     454,        -8,
    456,        -4,     457,        -8,     459,        -4,
    460,        -8,     462,        -4,     464,        -4,
    466,        -4,     468,        -4,     470,        -4,
    472,        -4,     474,        -4,     476,        -4,
    477,        -316,   479,        -4,     481,        -4,
    483,        -4,     485,        -4,     487,        -4,
    489,        -4,     491,        -4,     493,        -4,
    495,        -4,     496,        9,      498,        -4,
    499,        -8,     501,        -4,     505,        -4,
    507,        -4,     509,        -4,     511,        -4,
    513,        -4,     515,        -4,     517,        -4,
    519,        -4,     521,        -4,     523,        -4,
    525,        -4,     527,        -4,     529,        -4,
    531,        -4,     533,        -4,     535,        -4,
    537,        -4,     539,        -4,     541,        -4,
    543,        -4,     547,        -4,     549,        -4,
    551,        -4,     553,        -4,     555,        -4,
    557,        -4,     559,        -4,     561,        -4,
    563,        -4,     572,        -4,     1073742399, 43260,
    576,        43260,  578,        -4,     583,        -4,
    585,        -4,     587,        -4,     589,        -4,
    591,        -4,     592,        43132,  593,        43120,
    594,        43128,  595,        -840,   596,        -824,
    1073742422, -820,   599,        -820,   601,        -808,
    603,        -812,   604,        169276, 608,        -820,
    609,        169260, 611,        -828,   613,        169120,
    614,        169232,
"""


```