Response:
The user wants a summary of the functionality of the provided code snippet. This is part 4 of a 5-part series analyzing the `sin_intel_data.handroid` file, which is a data file used in the bionic math library for testing the sine function.

The code snippet is a C++-like representation of a data array. Each element in the array seems to be a structure or pair of double-precision floating-point numbers. These pairs likely represent input and expected output values for testing the `sin` function.

**Plan:**

1. **Identify the data structure:** The code snippet shows an array of pairs of floating-point numbers.
2. **Infer the purpose:** Given the file path (`bionic/tests/math_data/sin_intel_data.handroid`), the data is likely used for testing the `sin` function. The pairs probably represent (input, expected output) for the sine function.
3. **Summarize the functionality:** The main function of this code snippet is to provide test data for the sine function in the bionic math library.
这是目录为 `bionic/tests/math_data/sin_intel_data.handroid` 的源代码文件的一部分，它属于 Android 的 C 库 (bionic) 的数学库测试数据。

**归纳一下它的功能:**

这段代码定义了一个用于测试 `sin` 函数的数据表。  这个数据表包含了大量的条目（Entry），每个条目都包含两个 `double` 类型的浮点数。

**具体来说，这段代码的功能是:**

* **提供 `sin` 函数的测试用例:**  数据表中的每一对浮点数，很可能第一个数是 `sin` 函数的输入值（以十六进制浮点数表示），第二个数是对于该输入的预期输出值。
* **覆盖不同的输入范围和特殊情况:**  从数据条目的数值来看，输入值涵盖了正数、负数、零以及非常小和非常大的数值，同时也包含了像 `NaN` (Not a Number) 和无穷大这样的特殊情况的测试（虽然这段代码片段中没有直接体现，但整个文件很可能有）。
* **用于验证 `sin` 函数的精度和正确性:**  这些数据被用于测试 bionic 库中 `sin` 函数的实现是否符合预期的精度和行为。测试框架会用这些输入值调用 `sin` 函数，并将实际输出与数据表中提供的预期输出进行比较，以判断 `sin` 函数是否正确。

**与其他部分的关系 (结合上下文):**

整个 `sin_intel_data.handroid` 文件很可能是一个大型的测试数据集，用于全面地测试 `sin` 函数在各种情况下的表现。  之前和之后的部分可能包含更多不同范围和精度的测试数据，以及可能包含特殊值的测试用例。

**总结:**

这段代码是 Android bionic 库中用于测试 `sin` 函数正确性的关键组成部分。它定义了一系列输入值及其对应的预期输出值，帮助开发者验证 `sin` 函数的实现是否准确可靠。

Prompt: 
```
这是目录为bionic/tests/math_data/sin_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第4部分，共5部分，请归纳一下它的功能

"""
67082f337c5daf5ffc56e2p-1,
    -0x1.594317acc4efap-1
  },
  { // Entry 1070
    0x1.6888a4e134b2def5bea51f4cd7d647c6p-1,
    0x1.8ffffffffffffp-1
  },
  { // Entry 1071
    -0x1.6888a4e134b2def5bea51f4cd7d647c6p-1,
    -0x1.8ffffffffffffp-1
  },
  { // Entry 1072
    0x1.6888a4e134b2ea520b226eca8694b3a2p-1,
    0x1.9p-1
  },
  { // Entry 1073
    -0x1.6888a4e134b2ea520b226eca8694b3a2p-1,
    -0x1.9p-1
  },
  { // Entry 1074
    0x1.6888a4e134b2f5ae579fbe4834f8fd55p-1,
    0x1.9000000000001p-1
  },
  { // Entry 1075
    -0x1.6888a4e134b2f5ae579fbe4834f8fd55p-1,
    -0x1.9000000000001p-1
  },
  { // Entry 1076
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 1077
    0.0,
    0x1.0p-1074
  },
  { // Entry 1078
    -0.0,
    -0.0
  },
  { // Entry 1079
    0.0,
    0x1.0p-1074
  },
  { // Entry 1080
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 1081
    0x1.91f65f10dd812a0b95ff71871ab48207p-5,
    0x1.921fb54442d17p-5
  },
  { // Entry 1082
    -0x1.91f65f10dd812a0b95ff71871ab48207p-5,
    -0x1.921fb54442d17p-5
  },
  { // Entry 1083
    0x1.91f65f10dd813a06a6f12e3dd9a6a41ep-5,
    0x1.921fb54442d18p-5
  },
  { // Entry 1084
    -0x1.91f65f10dd813a06a6f12e3dd9a6a41ep-5,
    -0x1.921fb54442d18p-5
  },
  { // Entry 1085
    0x1.91f65f10dd814a01b7e2eaf4989861b7p-5,
    0x1.921fb54442d19p-5
  },
  { // Entry 1086
    -0x1.91f65f10dd814a01b7e2eaf4989861b7p-5,
    -0x1.921fb54442d19p-5
  },
  { // Entry 1087
    0x1.917a6bc29b42a9cd2e787ee00ca8f8e3p-4,
    0x1.921fb54442d17p-4
  },
  { // Entry 1088
    -0x1.917a6bc29b42a9cd2e787ee00ca8f8e3p-4,
    -0x1.921fb54442d17p-4
  },
  { // Entry 1089
    0x1.917a6bc29b42b9b9754a67729f79346bp-4,
    0x1.921fb54442d18p-4
  },
  { // Entry 1090
    -0x1.917a6bc29b42b9b9754a67729f79346bp-4,
    -0x1.921fb54442d18p-4
  },
  { // Entry 1091
    0x1.917a6bc29b42c9a5bc1c50053247de78p-4,
    0x1.921fb54442d19p-4
  },
  { // Entry 1092
    -0x1.917a6bc29b42c9a5bc1c50053247de78p-4,
    -0x1.921fb54442d19p-4
  },
  { // Entry 1093
    0x1.8f8b83c69a60975f98453886f953a0e5p-3,
    0x1.921fb54442d17p-3
  },
  { // Entry 1094
    -0x1.8f8b83c69a60975f98453886f953a0e5p-3,
    -0x1.921fb54442d17p-3
  },
  { // Entry 1095
    0x1.8f8b83c69a60a710e42d3435516ddaccp-3,
    0x1.921fb54442d18p-3
  },
  { // Entry 1096
    -0x1.8f8b83c69a60a710e42d3435516ddaccp-3,
    -0x1.921fb54442d18p-3
  },
  { // Entry 1097
    0x1.8f8b83c69a60b6c230152fe3a981d686p-3,
    0x1.921fb54442d19p-3
  },
  { // Entry 1098
    -0x1.8f8b83c69a60b6c230152fe3a981d686p-3,
    -0x1.921fb54442d19p-3
  },
  { // Entry 1099
    0x1.87de2a6aea961a3e9dedea57fe7e6514p-2,
    0x1.921fb54442d17p-2
  },
  { // Entry 1100
    -0x1.87de2a6aea961a3e9dedea57fe7e6514p-2,
    -0x1.921fb54442d17p-2
  },
  { // Entry 1101
    0x1.87de2a6aea962906d3d5839ea1a5bcf0p-2,
    0x1.921fb54442d18p-2
  },
  { // Entry 1102
    -0x1.87de2a6aea962906d3d5839ea1a5bcf0p-2,
    -0x1.921fb54442d18p-2
  },
  { // Entry 1103
    0x1.87de2a6aea9637cf09bd1ce544b496eap-2,
    0x1.921fb54442d19p-2
  },
  { // Entry 1104
    -0x1.87de2a6aea9637cf09bd1ce544b496eap-2,
    -0x1.921fb54442d19p-2
  },
  { // Entry 1105
    0x1.6a09e667f3bcba99afb0135729457874p-1,
    0x1.921fb54442d17p-1
  },
  { // Entry 1106
    -0x1.6a09e667f3bcba99afb0135729457874p-1,
    -0x1.921fb54442d17p-1
  },
  { // Entry 1107
    0x1.6a09e667f3bcc5e9fee352f50fd3f4e9p-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 1108
    -0x1.6a09e667f3bcc5e9fee352f50fd3f4e9p-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 1109
    0x1.6a09e667f3bcd13a4e169292f607eee5p-1,
    0x1.921fb54442d19p-1
  },
  { // Entry 1110
    -0x1.6a09e667f3bcd13a4e169292f607eee5p-1,
    -0x1.921fb54442d19p-1
  },
  { // Entry 1111
    0x1.fffffffffffffffffffffffffe5f56ffp-1,
    0x1.921fb54442d17p0
  },
  { // Entry 1112
    -0x1.fffffffffffffffffffffffffe5f56ffp-1,
    -0x1.921fb54442d17p0
  },
  { // Entry 1113
    0x1.ffffffffffffffffffffffffffec8831p-1,
    0x1.921fb54442d18p0
  },
  { // Entry 1114
    -0x1.ffffffffffffffffffffffffffec8831p-1,
    -0x1.921fb54442d18p0
  },
  { // Entry 1115
    0x1.ffffffffffffffffffffffffff79b963p-1,
    0x1.921fb54442d19p0
  },
  { // Entry 1116
    -0x1.ffffffffffffffffffffffffff79b963p-1,
    -0x1.921fb54442d19p0
  },
  { // Entry 1117
    0x1.469898cc51701b839a252049bfaeed42p-51,
    0x1.921fb54442d17p1
  },
  { // Entry 1118
    -0x1.469898cc51701b839a252049bfaeed42p-51,
    -0x1.921fb54442d17p1
  },
  { // Entry 1119
    0x1.1a62633145c06e0e689481270436e2edp-53,
    0x1.921fb54442d18p1
  },
  { // Entry 1120
    -0x1.1a62633145c06e0e689481270436e2edp-53,
    -0x1.921fb54442d18p1
  },
  { // Entry 1121
    -0x1.72cece675d1fc8f8cbb5bf6c7d5bbc5cp-52,
    0x1.921fb54442d19p1
  },
  { // Entry 1122
    0x1.72cece675d1fc8f8cbb5bf6c7d5bbc5cp-52,
    -0x1.921fb54442d19p1
  },
  { // Entry 1123
    -0x1.469898cc51701b839a252049bb87ce1bp-50,
    0x1.921fb54442d17p2
  },
  { // Entry 1124
    0x1.469898cc51701b839a252049bb87ce1bp-50,
    -0x1.921fb54442d17p2
  },
  { // Entry 1125
    -0x1.1a62633145c06e0e68948127040bf003p-52,
    0x1.921fb54442d18p2
  },
  { // Entry 1126
    0x1.1a62633145c06e0e68948127040bf003p-52,
    -0x1.921fb54442d18p2
  },
  { // Entry 1127
    0x1.72cece675d1fc8f8cbb5bf6c7bd6bf4dp-51,
    0x1.921fb54442d19p2
  },
  { // Entry 1128
    -0x1.72cece675d1fc8f8cbb5bf6c7bd6bf4dp-51,
    -0x1.921fb54442d19p2
  },
  { // Entry 1129
    -0x1.469898cc51701b839a252049aaeb5182p-49,
    0x1.921fb54442d17p3
  },
  { // Entry 1130
    0x1.469898cc51701b839a252049aaeb5182p-49,
    -0x1.921fb54442d17p3
  },
  { // Entry 1131
    -0x1.1a62633145c06e0e689481270360245cp-51,
    0x1.921fb54442d18p3
  },
  { // Entry 1132
    0x1.1a62633145c06e0e689481270360245cp-51,
    -0x1.921fb54442d18p3
  },
  { // Entry 1133
    0x1.72cece675d1fc8f8cbb5bf6c75c2cb0ep-50,
    0x1.921fb54442d19p3
  },
  { // Entry 1134
    -0x1.72cece675d1fc8f8cbb5bf6c75c2cb0ep-50,
    -0x1.921fb54442d19p3
  },
  { // Entry 1135
    -0x1.469898cc51701b839a25204968795f1cp-48,
    0x1.921fb54442d17p4
  },
  { // Entry 1136
    0x1.469898cc51701b839a25204968795f1cp-48,
    -0x1.921fb54442d17p4
  },
  { // Entry 1137
    -0x1.1a62633145c06e0e6894812700b0f5bfp-50,
    0x1.921fb54442d18p4
  },
  { // Entry 1138
    0x1.1a62633145c06e0e6894812700b0f5bfp-50,
    -0x1.921fb54442d18p4
  },
  { // Entry 1139
    0x1.72cece675d1fc8f8cbb5bf6c5d72fa11p-49,
    0x1.921fb54442d19p4
  },
  { // Entry 1140
    -0x1.72cece675d1fc8f8cbb5bf6c5d72fa11p-49,
    -0x1.921fb54442d19p4
  },
  { // Entry 1141
    -0x1.469898cc51701b839a2520485eb19584p-47,
    0x1.921fb54442d17p5
  },
  { // Entry 1142
    0x1.469898cc51701b839a2520485eb19584p-47,
    -0x1.921fb54442d17p5
  },
  { // Entry 1143
    -0x1.1a62633145c06e0e68948126f5f43b4cp-49,
    0x1.921fb54442d18p5
  },
  { // Entry 1144
    0x1.1a62633145c06e0e68948126f5f43b4cp-49,
    -0x1.921fb54442d18p5
  },
  { // Entry 1145
    0x1.72cece675d1fc8f8cbb5bf6bfc33b61fp-48,
    0x1.921fb54442d19p5
  },
  { // Entry 1146
    -0x1.72cece675d1fc8f8cbb5bf6bfc33b61fp-48,
    -0x1.921fb54442d19p5
  },
  { // Entry 1147
    -0x1.469898cc51701b839a25204437926f25p-46,
    0x1.921fb54442d17p6
  },
  { // Entry 1148
    0x1.469898cc51701b839a25204437926f25p-46,
    -0x1.921fb54442d17p6
  },
  { // Entry 1149
    -0x1.1a62633145c06e0e68948126cb01517dp-48,
    0x1.921fb54442d18p6
  },
  { // Entry 1150
    0x1.1a62633145c06e0e68948126cb01517dp-48,
    -0x1.921fb54442d18p6
  },
  { // Entry 1151
    0x1.72cece675d1fc8f8cbb5bf6a7736a658p-47,
    0x1.921fb54442d19p6
  },
  { // Entry 1152
    -0x1.72cece675d1fc8f8cbb5bf6a7736a658p-47,
    -0x1.921fb54442d19p6
  },
  { // Entry 1153
    -0x1.469898cc51701b839a2520339b15d5aap-45,
    0x1.921fb54442d17p7
  },
  { // Entry 1154
    0x1.469898cc51701b839a2520339b15d5aap-45,
    -0x1.921fb54442d17p7
  },
  { // Entry 1155
    -0x1.1a62633145c06e0e689481261f35aa43p-47,
    0x1.921fb54442d18p7
  },
  { // Entry 1156
    0x1.1a62633145c06e0e689481261f35aa43p-47,
    -0x1.921fb54442d18p7
  },
  { // Entry 1157
    0x1.72cece675d1fc8f8cbb5bf646342673ap-46,
    0x1.921fb54442d19p7
  },
  { // Entry 1158
    -0x1.72cece675d1fc8f8cbb5bf646342673ap-46,
    -0x1.921fb54442d19p7
  },
  { // Entry 1159
    0x1.6a09e667f3bcffa60c0f53340fd24904p-1,
    0x1.2d97c7f3321d1p1
  },
  { // Entry 1160
    -0x1.6a09e667f3bcffa60c0f53340fd24904p-1,
    -0x1.2d97c7f3321d1p1
  },
  { // Entry 1161
    0x1.6a09e667f3bcd264cf4254bc7ab0c9fap-1,
    0x1.2d97c7f3321d2p1
  },
  { // Entry 1162
    -0x1.6a09e667f3bcd264cf4254bc7ab0c9fap-1,
    -0x1.2d97c7f3321d2p1
  },
  { // Entry 1163
    0x1.6a09e667f3bca52392755644dfe72357p-1,
    0x1.2d97c7f3321d3p1
  },
  { // Entry 1164
    -0x1.6a09e667f3bca52392755644dfe72357p-1,
    -0x1.2d97c7f3321d3p1
  },
  { // Entry 1165
    -0x1.6a09e667f3bc8c2df1b752b606a0a472p-1,
    0x1.f6a7a2955385dp1
  },
  { // Entry 1166
    0x1.6a09e667f3bc8c2df1b752b606a0a472p-1,
    -0x1.f6a7a2955385dp1
  },
  { // Entry 1167
    -0x1.6a09e667f3bcb96f2e84512da488ff2dp-1,
    0x1.f6a7a2955385ep1
  },
  { // Entry 1168
    0x1.6a09e667f3bcb96f2e84512da488ff2dp-1,
    -0x1.f6a7a2955385ep1
  },
  { // Entry 1169
    -0x1.6a09e667f3bce6b06b514fa53cc9324fp-1,
    0x1.f6a7a2955385fp1
  },
  { // Entry 1170
    0x1.6a09e667f3bce6b06b514fa53cc9324fp-1,
    -0x1.f6a7a2955385fp1
  },
  { // Entry 1171
    -0x1.ffffffffffffffffffffffffe8b27b6ap-1,
    0x1.2d97c7f3321d1p2
  },
  { // Entry 1172
    0x1.ffffffffffffffffffffffffe8b27b6ap-1,
    -0x1.2d97c7f3321d1p2
  },
  { // Entry 1173
    -0x1.ffffffffffffffffffffffffff50c9bdp-1,
    0x1.2d97c7f3321d2p2
  },
  { // Entry 1174
    0x1.ffffffffffffffffffffffffff50c9bdp-1,
    -0x1.2d97c7f3321d2p2
  },
  { // Entry 1175
    -0x1.fffffffffffffffffffffffff5ef1810p-1,
    0x1.2d97c7f3321d3p2
  },
  { // Entry 1176
    0x1.fffffffffffffffffffffffff5ef1810p-1,
    -0x1.2d97c7f3321d3p2
  },
  { // Entry 1177
    -0x1.6a09e667f3bd3962193b5373069ba0c2p-1,
    0x1.5fdbbe9bba774p2
  },
  { // Entry 1178
    0x1.6a09e667f3bd3962193b5373069ba0c2p-1,
    -0x1.5fdbbe9bba774p2
  },
  { // Entry 1179
    -0x1.6a09e667f3bcdedf9fa15683e51f7e60p-1,
    0x1.5fdbbe9bba775p2
  },
  { // Entry 1180
    0x1.6a09e667f3bcdedf9fa15683e51f7e60p-1,
    -0x1.5fdbbe9bba775p2
  },
  { // Entry 1181
    -0x1.6a09e667f3bc845d26075994ad02bd98p-1,
    0x1.5fdbbe9bba776p2
  },
  { // Entry 1182
    0x1.6a09e667f3bc845d26075994ad02bd98p-1,
    -0x1.5fdbbe9bba776p2
  },
  { // Entry 1183
    0x1.6a09e667f3bc5271e48b5276f438579fp-1,
    0x1.c463abeccb2bap2
  },
  { // Entry 1184
    -0x1.6a09e667f3bc5271e48b5276f438579fp-1,
    -0x1.c463abeccb2bap2
  },
  { // Entry 1185
    0x1.6a09e667f3bcacf45e254f6638cfe8c6p-1,
    0x1.c463abeccb2bbp2
  },
  { // Entry 1186
    -0x1.6a09e667f3bcacf45e254f6638cfe8c6p-1,
    -0x1.c463abeccb2bbp2
  },
  { // Entry 1187
    0x1.6a09e667f3bd0776d7bf4c5566c6db87p-1,
    0x1.c463abeccb2bcp2
  },
  { // Entry 1188
    -0x1.6a09e667f3bd0776d7bf4c5566c6db87p-1,
    -0x1.c463abeccb2bcp2
  },
  { // Entry 1189
    0x1.ffffffffffffffffffffffffe31174f5p-1,
    0x1.f6a7a2955385dp2
  },
  { // Entry 1190
    -0x1.ffffffffffffffffffffffffe31174f5p-1,
    -0x1.f6a7a2955385dp2
  },
  { // Entry 1191
    0x1.fffffffffffffffffffffffffe194cd4p-1,
    0x1.f6a7a2955385ep2
  },
  { // Entry 1192
    -0x1.fffffffffffffffffffffffffe194cd4p-1,
    -0x1.f6a7a2955385ep2
  },
  { // Entry 1193
    0x1.fffffffffffffffffffffffff92124b4p-1,
    0x1.f6a7a2955385fp2
  },
  { // Entry 1194
    -0x1.fffffffffffffffffffffffff92124b4p-1,
    -0x1.f6a7a2955385fp2
  },
  { // Entry 1195
    0x1.6a09e667f3bdfae1dcce4f18665681c6p-1,
    0x1.1475cc9eedeffp3
  },
  { // Entry 1196
    -0x1.6a09e667f3bdfae1dcce4f18665681c6p-1,
    -0x1.1475cc9eedeffp3
  },
  { // Entry 1197
    0x1.6a09e667f3bd45dce99a553a6d7d8065p-1,
    0x1.1475cc9eedfp3
  },
  { // Entry 1198
    -0x1.6a09e667f3bd45dce99a553a6d7d8065p-1,
    -0x1.1475cc9eedfp3
  },
  { // Entry 1199
    0x1.6a09e667f3bc90d7f6665b5c1a22056ap-1,
    0x1.1475cc9eedf01p3
  },
  { // Entry 1200
    -0x1.6a09e667f3bc90d7f6665b5c1a22056ap-1,
    -0x1.1475cc9eedf01p3
  },
  { // Entry 1201
    0x1.34f272993d1414a2b39bd8373e0d6b94p-49,
    0x1.2d97c7f3321d1p3
  },
  { // Entry 1202
    -0x1.34f272993d1414a2b39bd8373e0d6b94p-49,
    -0x1.2d97c7f3321d1p3
  },
  { // Entry 1203
    0x1.a79394c9e8a0a5159cdec1ba85a688bdp-52,
    0x1.2d97c7f3321d2p3
  },
  { // Entry 1204
    -0x1.a79394c9e8a0a5159cdec1ba85a688bdp-52,
    -0x1.2d97c7f3321d2p3
  },
  { // Entry 1205
    -0x1.961b1acd85d7d6ba98c84f9153c0cc16p-50,
    0x1.2d97c7f3321d3p3
  },
  { // Entry 1206
    0x1.961b1acd85d7d6ba98c84f9153c0cc16p-50,
    -0x1.2d97c7f3321d3p3
  },
  { // Entry 1207
    -0x1.6a09e667f3bb90f220f856d0b1a406c3p-1,
    0x1.46b9c347764a2p3
  },
  { // Entry 1208
    0x1.6a09e667f3bb90f220f856d0b1a406c3p-1,
    -0x1.46b9c347764a2p3
  },
  { // Entry 1209
    -0x1.6a09e667f3bc45f7142c50af84f26c75p-1,
    0x1.46b9c347764a3p3
  },
  { // Entry 1210
    0x1.6a09e667f3bc45f7142c50af84f26c75p-1,
    -0x1.46b9c347764a3p3
  },
  { // Entry 1211
    -0x1.6a09e667f3bcfafc07604a8dfdbe588dp-1,
    0x1.46b9c347764a4p3
  },
  { // Entry 1212
    0x1.6a09e667f3bcfafc07604a8dfdbe588dp-1,
    -0x1.46b9c347764a4p3
  },
  { // Entry 1213
    -0x1.ffffffffffffffffffffffff9d634e9fp-1,
    0x1.5fdbbe9bba774p3
  },
  { // Entry 1214
    0x1.ffffffffffffffffffffffff9d634e9fp-1,
    -0x1.5fdbbe9bba774p3
  },
  { // Entry 1215
    -0x1.fffffffffffffffffffffffffc461178p-1,
    0x1.5fdbbe9bba775p3
  },
  { // Entry 1216
    0x1.fffffffffffffffffffffffffc461178p-1,
    -0x1.5fdbbe9bba775p3
  },
  { // Entry 1217
    -0x1.ffffffffffffffffffffffffdb28d451p-1,
    0x1.5fdbbe9bba776p3
  },
  { // Entry 1218
    0x1.ffffffffffffffffffffffffdb28d451p-1,
    -0x1.5fdbbe9bba776p3
  },
  { // Entry 1219
    -0x1.6a09e667f3be075cad2d50dfc68cd88fp-1,
    0x1.78fdb9effea45p3
  },
  { // Entry 1220
    0x1.6a09e667f3be075cad2d50dfc68cd88fp-1,
    -0x1.78fdb9effea45p3
  },
  { // Entry 1221
    -0x1.6a09e667f3bd5257b9f95701d3f13f5dp-1,
    0x1.78fdb9effea46p3
  },
  { // Entry 1222
    0x1.6a09e667f3bd5257b9f95701d3f13f5dp-1,
    -0x1.78fdb9effea46p3
  },
  { // Entry 1223
    -0x1.6a09e667f3bc9d52c6c55d2386d32c92p-1,
    0x1.78fdb9effea47p3
  },
  { // Entry 1224
    0x1.6a09e667f3bc9d52c6c55d2386d32c92p-1,
    -0x1.78fdb9effea47p3
  },
  { // Entry 1225
    0x1.6a09e667f3bb8477509955093bb292bep-1,
    0x1.ab41b09886fe8p3
  },
  { // Entry 1226
    -0x1.6a09e667f3bb8477509955093bb292bep-1,
    -0x1.ab41b09886fe8p3
  },
  { // Entry 1227
    0x1.6a09e667f3bc397c43cd4ee8153e60a0p-1,
    0x1.ab41b09886fe9p3
  },
  { // Entry 1228
    -0x1.6a09e667f3bc397c43cd4ee8153e60a0p-1,
    -0x1.ab41b09886fe9p3
  },
  { // Entry 1229
    0x1.6a09e667f3bcee81370148c69447b4e7p-1,
    0x1.ab41b09886feap3
  },
  { // Entry 1230
    -0x1.6a09e667f3bcee81370148c69447b4e7p-1,
    -0x1.ab41b09886feap3
  },
  { // Entry 1231
    0x1.ffffffffffffffffffffffff922141b4p-1,
    0x1.c463abeccb2bap3
  },
  { // Entry 1232
    -0x1.ffffffffffffffffffffffff922141b4p-1,
    -0x1.c463abeccb2bap3
  },
  { // Entry 1233
    0x1.fffffffffffffffffffffffff9d717a7p-1,
    0x1.c463abeccb2bbp3
  },
  { // Entry 1234
    -0x1.fffffffffffffffffffffffff9d717a7p-1,
    -0x1.c463abeccb2bbp3
  },
  { // Entry 1235
    0x1.ffffffffffffffffffffffffe18ced9ap-1,
    0x1.c463abeccb2bcp3
  },
  { // Entry 1236
    -0x1.ffffffffffffffffffffffffe18ced9ap-1,
    -0x1.c463abeccb2bcp3
  },
  { // Entry 1237
    0x1.6a09e667f3be13d77d8c52a726550eacp-1,
    0x1.dd85a7410f58bp3
  },
  { // Entry 1238
    -0x1.6a09e667f3be13d77d8c52a726550eacp-1,
    -0x1.dd85a7410f58bp3
  },
  { // Entry 1239
    0x1.6a09e667f3bd5ed28a5858c939f6ddaap-1,
    0x1.dd85a7410f58cp3
  },
  { // Entry 1240
    -0x1.6a09e667f3bd5ed28a5858c939f6ddaap-1,
    -0x1.dd85a7410f58cp3
  },
  { // Entry 1241
    0x1.6a09e667f3bca9cd97245eeaf316330ep-1,
    0x1.dd85a7410f58dp3
  },
  { // Entry 1242
    -0x1.6a09e667f3bca9cd97245eeaf316330ep-1,
    -0x1.dd85a7410f58dp3
  },
  { // Entry 1243
    0x1.583ebeff65cc226480ae685c1765dec1p-49,
    0x1.f6a7a2955385dp3
  },
  { // Entry 1244
    -0x1.583ebeff65cc226480ae685c1765dec1p-49,
    -0x1.f6a7a2955385dp3
  },
  { // Entry 1245
    0x1.60fafbfd9730899202b9a170c3971e86p-51,
    0x1.f6a7a2955385ep3
  },
  { // Entry 1246
    -0x1.60fafbfd9730899202b9a170c3971e86p-51,
    -0x1.f6a7a2955385ep3
  },
  { // Entry 1247
    -0x1.4f8282013467bb36fea32f479753fe7ap-50,
    0x1.f6a7a2955385fp3
  },
  { // Entry 1248
    0x1.4f8282013467bb36fea32f479753fe7ap-50,
    -0x1.f6a7a2955385fp3
  },
  { // Entry 1249
    -0x1.6a09e667f3ba0df299d25f82f639251fp-1,
    0x1.07e4cef4cbd96p4
  },
  { // Entry 1250
    0x1.6a09e667f3ba0df299d25f82f639251fp-1,
    -0x1.07e4cef4cbd96p4
  },
  { // Entry 1251
    -0x1.6a09e667f3bb77fc803a5341c552fe0fp-1,
    0x1.07e4cef4cbd97p4
  },
  { // Entry 1252
    0x1.6a09e667f3bb77fc803a5341c552fe0fp-1,
    -0x1.07e4cef4cbd97p4
  },
  { // Entry 1253
    -0x1.6a09e667f3bce20666a246ff2a62f097p-1,
    0x1.07e4cef4cbd98p4
  },
  { // Entry 1254
    0x1.6a09e667f3bce20666a246ff2a62f097p-1,
    -0x1.07e4cef4cbd98p4
  },
  { // Entry 1255
    -0x1.fffffffffffffffffffffffd2531a43dp-1,
    0x1.1475cc9eedeffp4
  },
  { // Entry 1256
    0x1.fffffffffffffffffffffffd2531a43dp-1,
    -0x1.1475cc9eedeffp4
  },
  { // Entry 1257
    -0x1.ffffffffffffffffffffffff86437656p-1,
    0x1.1475cc9eedfp4
  },
  { // Entry 1258
    0x1.ffffffffffffffffffffffff86437656p-1,
    -0x1.1475cc9eedfp4
  },
  { // Entry 1259
    -0x1.ffffffffffffffffffffffffe755486fp-1,
    0x1.1475cc9eedf01p4
  },
  { // Entry 1260
    0x1.ffffffffffffffffffffffffe755486fp-1,
    -0x1.1475cc9eedf01p4
  },
  { // Entry 1261
    -0x1.6a09e667f3bed557411f4e4c114d7357p-1,
    0x1.2106ca4910068p4
  },
  { // Entry 1262
    0x1.6a09e667f3bed557411f4e4c114d7357p-1,
    -0x1.2106ca4910068p4
  },
  { // Entry 1263
    -0x1.6a09e667f3bd6b4d5ab75a909f8e5b4cp-1,
    0x1.2106ca4910069p4
  },
  { // Entry 1264
    0x1.6a09e667f3bd6b4d5ab75a909f8e5b4cp-1,
    -0x1.2106ca4910069p4
  },
  { // Entry 1265
    -0x1.6a09e667f3bc0143744f66d3c3c55cd9p-1,
    0x1.2106ca491006ap4
  },
  { // Entry 1266
    0x1.6a09e667f3bc0143744f66d3c3c55cd9p-1,
    -0x1.2106ca491006ap4
  },
  { // Entry 1267
    -0x1.34f272993d1414a2b39bd83705cec120p-48,
    0x1.2d97c7f3321d1p4
  },
  { // Entry 1268
    0x1.34f272993d1414a2b39bd83705cec120p-48,
    -0x1.2d97c7f3321d1p4
  },
  { // Entry 1269
    -0x1.a79394c9e8a0a5159cdec1ba8362b968p-51,
    0x1.2d97c7f3321d2p4
  },
  { // Entry 1270
    0x1.a79394c9e8a0a5159cdec1ba8362b968p-51,
    -0x1.2d97c7f3321d2p4
  },
  { // Entry 1271
    0x1.961b1acd85d7d6ba98c84f9133d10abep-49,
    0x1.2d97c7f3321d3p4
  },
  { // Entry 1272
    -0x1.961b1acd85d7d6ba98c84f9133d10abep-49,
    -0x1.2d97c7f3321d3p4
  },
  { // Entry 1273
    0x1.6a09e667f3ba0177c9735dbb72f09f65p-1,
    0x1.3a28c59d54339p4
  },
  { // Entry 1274
    -0x1.6a09e667f3ba0177c9735dbb72f09f65p-1,
    -0x1.3a28c59d54339p4
  },
  { // Entry 1275
    0x1.6a09e667f3bb6b81afdb517a4e8548b4p-1,
    0x1.3a28c59d5433ap4
  },
  { // Entry 1276
    -0x1.6a09e667f3bb6b81afdb517a4e8548b4p-1,
    -0x1.3a28c59d5433ap4
  },
  { // Entry 1277
    0x1.6a09e667f3bcd58b96434537c0100b9bp-1,
    0x1.3a28c59d5433bp4
  },
  { // Entry 1278
    -0x1.6a09e667f3bcd58b96434537c0100b9bp-1,
    -0x1.3a28c59d5433bp4
  },
  { // Entry 1279
    0x1.fffffffffffffffffffffffd0711f437p-1,
    0x1.46b9c347764a2p4
  },
  { // Entry 1280
    -0x1.fffffffffffffffffffffffd0711f437p-1,
    -0x1.46b9c347764a2p4
  },
  { // Entry 1281
    0x1.ffffffffffffffffffffffff79c9ec83p-1,
    0x1.46b9c347764a3p4
  },
  { // Entry 1282
    -0x1.ffffffffffffffffffffffff79c9ec83p-1,
    -0x1.46b9c347764a3p4
  },
  { // Entry 1283
    0x1.ffffffffffffffffffffffffec81e4cfp-1,
    0x1.46b9c347764a4p4
  },
  { // Entry 1284
    -0x1.ffffffffffffffffffffffffec81e4cfp-1,
    -0x1.46b9c347764a4p4
  },
  { // Entry 1285
    0x1.6a09e667f3bee1d2117e501369fbffefp-1,
    0x1.534ac0f19860bp4
  },
  { // Entry 1286
    -0x1.6a09e667f3bee1d2117e501369fbffefp-1,
    -0x1.534ac0f19860bp4
  },
  { // Entry 1287
    0x1.6a09e667f3bd77c82b165c5804b7b843p-1,
    0x1.534ac0f19860cp4
  },
  { // Entry 1288
    -0x1.6a09e667f3bd77c82b165c5804b7b843p-1,
    -0x1.534ac0f19860cp4
  },
  { // Entry 1289
    0x1.6a09e667f3bc0dbe44ae689b35698a2fp-1,
    0x1.534ac0f19860dp4
  },
  { // Entry 1290
    -0x1.6a09e667f3bc0dbe44ae689b35698a2fp-1,
    -0x1.534ac0f19860dp4
  },
  { // Entry 1291
    0x1.3dc585b2c742181326e07c40375464dep-48,
    0x1.5fdbbe9bba774p4
  },
  { // Entry 1292
    -0x1.3dc585b2c742181326e07c40375464dep-48,
    -0x1.5fdbbe9bba774p4
  },
  { // Entry 1293
    0x1.ee2c2d963a10c0993703e20442ad7b8dp-51,
    0x1.5fdbbe9bba775p4
  },
  { // Entry 1294
    -0x1.ee2c2d963a10c0993703e20442ad7b8dp-51,
    -0x1.5fdbbe9bba775p4
  },
  { // Entry 1295
    -0x1.8474f49a717bcfd9b23f077ec8dd175bp-49,
    0x1.5fdbbe9bba776p4
  },
  { // Entry 1296
    0x1.8474f49a717bcfd9b23f077ec8dd175bp-49,
    -0x1.5fdbbe9bba776p4
  },
  { // Entry 1297
    -0x1.6a09e667f3b9f4fcf9145bf3ef39f901p-1,
    0x1.6c6cbc45dc8dcp4
  },
  { // Entry 1298
    0x1.6a09e667f3b9f4fcf9145bf3ef39f901p-1,
    -0x1.6c6cbc45dc8dcp4
  },
  { // Entry 1299
    -0x1.6a09e667f3bb5f06df7c4fb2d74972aep-1,
    0x1.6c6cbc45dc8ddp4
  },
  { // Entry 1300
    0x1.6a09e667f3bb5f06df7c4fb2d74972aep-1,
    -0x1.6c6cbc45dc8ddp4
  },
  { // Entry 1301
    -0x1.6a09e667f3bcc910c5e44370554f05f4p-1,
    0x1.6c6cbc45dc8dep4
  },
  { // Entry 1302
    0x1.6a09e667f3bcc910c5e44370554f05f4p-1,
    -0x1.6c6cbc45dc8dep4
  },
  { // Entry 1303
    -0x1.fffffffffffffffffffffffce85685bdp-1,
    0x1.78fdb9effea45p4
  },
  { // Entry 1304
    0x1.fffffffffffffffffffffffce85685bdp-1,
    -0x1.78fdb9effea45p4
  },
  { // Entry 1305
    -0x1.ffffffffffffffffffffffff6cb4a43dp-1,
    0x1.78fdb9effea46p4
  },
  { // Entry 1306
    0x1.ffffffffffffffffffffffff6cb4a43dp-1,
    -0x1.78fdb9effea46p4
  },
  { // Entry 1307
    -0x1.fffffffffffffffffffffffff112c2bcp-1,
    0x1.78fdb9effea47p4
  },
  { // Entry 1308
    0x1.fffffffffffffffffffffffff112c2bcp-1,
    -0x1.78fdb9effea47p4
  },
  { // Entry 1309
    -0x1.6a09e667f3beee4ce1dd51dac23c6bdcp-1,
    0x1.858eb79a20baep4
  },
  { // Entry 1310
    0x1.6a09e667f3beee4ce1dd51dac23c6bdcp-1,
    -0x1.858eb79a20baep4
  },
  { // Entry 1311
    -0x1.6a09e667f3bd8442fb755e1f6972f48fp-1,
    0x1.858eb79a20bafp4
  },
  { // Entry 1312
    0x1.6a09e667f3bd8442fb755e1f6972f48fp-1,
    -0x1.858eb79a20bafp4
  },
  { // Entry 1313
    -0x1.6a09e667f3bc1a39150d6a62a69f96dap-1,
    0x1.858eb79a20bb0p4
  },
  { // Entry 1314
    0x1.6a09e667f3bc1a39150d6a62a69f96dap-1,
    -0x1.858eb79a20bb0p4
  },
  { // Entry 1315
    0x1.fa7299b17573d373c615096572a0de04p-1,
    0x1.fffffffffffffp62
  },
  { // Entry 1316
    -0x1.fa7299b17573d373c615096572a0de04p-1,
    -0x1.fffffffffffffp62
  },
  { // Entry 1317
    0x1.fff6dfd42dc54430bc0576b00a88bd94p-1,
    0x1.0p63
  },
  { // Entry 1318
    -0x1.fff6dfd42dc54430bc0576b00a88bd94p-1,
    -0x1.0p63
  },
  { // Entry 1319
    0x1.e456b818e7396b45989978d4b7ebf7b3p-1,
    0x1.0000000000001p63
  },
  { // Entry 1320
    -0x1.e456b818e7396b45989978d4b7ebf7b3p-1,
    -0x1.0000000000001p63
  },
  { // Entry 1321
    -0x1.86dcca0d689e7b56ef79481be4a645c6p-1,
    0x1.fffffffffffffp26
  },
  { // Entry 1322
    0x1.86dcca0d689e7b56ef79481be4a645c6p-1,
    -0x1.fffffffffffffp26
  },
  { // Entry 1323
    -0x1.86dcc9babb0a40ee875cab3b9e892757p-1,
    0x1.0p27
  },
  { // Entry 1324
    0x1.86dcc9babb0a40ee875cab3b9e892757p-1,
    -0x1.0p27
  },
  { // Entry 1325
    -0x1.86dcc9155fe182d4515599426bb14b94p-1,
    0x1.0000000000001p27
  },
  { // Entry 1326
    0x1.86dcc9155fe182d4515599426bb14b94p-1,
    -0x1.0000000000001p27
  },
  { // Entry 1327
    -0x1.8f22f84d42da1f57469dfaac44a8b73ap-1,
    0x1.fffffffffffffp23
  },
  { // Entry 1328
    0x1.8f22f84d42da1f57469dfaac44a8b73ap-1,
    -0x1.fffffffffffffp23
  },
  { // Entry 1329
    -0x1.8f22f8433d6edfe9a4aff9622517caa9p-1,
    0x1.0p24
  },
  { // Entry 1330
    0x1.8f22f8433d6edfe9a4aff9622517caa9p-1,
    -0x1.0p24
  },
  { // Entry 1331
    -0x1.8f22f82f32985fe30699c6e12d9dfce2p-1,
    0x1.0000000000001p24
  },
  { // Entry 1332
    0x1.8f22f82f32985fe30699c6e12d9dfce2p-1,
    -0x1.0000000000001p24
  },
  { // Entry 1333
    -0x1.837b9dddc1eabd379d729f575fc1144cp-1,
    0x1.fffffffffffffp1
  },
  { // Entry 1334
    0x1.837b9dddc1eabd379d729f575fc1144cp-1,
    -0x1.fffffffffffffp1
  },
  { // Entry 1335
    -0x1.837b9dddc1eae70ce98055a0e450d93cp-1,
    0x1.0p2
  },
  { // Entry 1336
    0x1.837b9dddc1eae70ce98055a0e450d93cp-1,
    -0x1.0p2
  },
  { // Entry 1337
    -0x1.837b9dddc1eb3ab7819bc233db4697b5p-1,
    0x1.0000000000001p2
  },
  { // Entry 1338
    0x1.837b9dddc1eb3ab7819bc233db4697b5p-1,
    -0x1.0000000000001p2
  },
  { // Entry 1339
    0x1.d18f6ead1b446b4bcb73c2390b330d75p-1,
    0x1.fffffffffffffp0
  },
  { // Entry 1340
    -0x1.d18f6ead1b446b4bcb73c2390b330d75p-1,
    -0x1.fffffffffffffp0
  },
  { // Entry 1341
    0x1.d18f6ead1b445dfab848188009c9bb95p-1,
    0x1.0p1
  },
  { // Entry 1342
    -0x1.d18f6ead1b445dfab848188009c9bb95p-1,
    -0x1.0p1
  },
  { // Entry 1343
    0x1.d18f6ead1b44435891f0c50e01826988p-1,
    0x1.0000000000001p1
  },
  { // Entry 1344
    -0x1.d18f6ead1b44435891f0c50e01826988p-1,
    -0x1.0000000000001p1
  },
  { // Entry 1345
    0x1.aed548f090ced79c79cbf790441f8197p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 1346
    -0x1.aed548f090ced79c79cbf790441f8197p-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 1347
    0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    0x1.0p0
  },
  { // Entry 1348
    -0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    -0x1.0p0
  },
  { // Entry 1349
    0x1.aed548f090cef18bb5e3871a14d94609p-1,
    0x1.0000000000001p0
  },
  { // Entry 1350
    -0x1.aed548f090cef18bb5e3871a14d94609p-1,
    -0x1.0000000000001p0
  },
  { // Entry 1351
    0x1.eaee8744b05ef07cd0b9089130598314p-2,
    0x1.fffffffffffffp-2
  },
  { // Entry 1352
    -0x1.eaee8744b05ef07cd0b9089130598314p-2,
    -0x1.fffffffffffffp-2
  },
  { // Entry 1353
    0x1.eaee8744b05efe8764bc364fd837b666p-2,
    0x1.0p-1
  },
  { // Entry 1354
    -0x1.eaee8744b05efe8764bc364fd837b666p-2,
    -0x1.0p-1
  },
  { // Entry 1355
    0x1.eaee8744b05f1a9c8cc291cd27981051p-2,
    0x1.0000000000001p-1
  },
  { // Entry 1356
    -0x1.eaee8744b05f1a9c8cc291cd27981051p-2,
    -0x1.0000000000001p-1
  },
  { // Entry 1357
    0x1.faaeed4f31575c27f39c1d7c012a4413p-3,
    0x1.fffffffffffffp-3
  },
  { // Entry 1358
    -0x1.faaeed4f31575c27f39c1d7c012a4413p-3,
    -0x1.fffffffffffffp-3
  },
  { // Entry 1359
    0x1.faaeed4f31576ba89debdc7351e8b1aep-3,
    0x1.0p-2
  },
  { // Entry 1360
    -0x1.faaeed4f31576ba89debdc7351e8b1aep-3,
    -0x1.0p-2
  },
  { // Entry 1361
    0x1.faaeed4f31578aa9f28b5a61f34dccb1p-3,
    0x1.0000000000001p-2
  },
  { // Entry 1362
    -0x1.faaeed4f31578aa9f28b5a61f34dccb1p-3,
    -0x1.0000000000001p-2
  },
  { // Entry 1363
    0x1.feaaeee86ee34cc05eff28740ee7b469p-4,
    0x1.fffffffffffffp-4
  },
  { // Entry 1364
    -0x1.feaaeee86ee34cc05eff28740ee7b469p-4,
    -0x1.fffffffffffffp-4
  },
  { // Entry 1365
    0x1.feaaeee86ee35ca069a86721f89f85a5p-4,
    0x1.0p-3
  },
  { // Entry 1366
    -0x1.feaaeee86ee35ca069a86721f89f85a5p-4,
    -0x1.0p-3
  },
  { // Entry 1367
    0x1.feaaeee86ee37c607efae47dcc092c1cp-4,
    0x1.0000000000001p-3
  },
  { // Entry 1368
    -0x1.feaaeee86ee37c607efae47dcc092c1cp-4,
    -0x1.0000000000001p-3
  },
  { // Entry 1369
    0x1.ffaaaeeed4ed9b53a408c0f2bc02c8f9p-5,
    0x1.fffffffffffffp-5
  },
  { // Entry 1370
    -0x1.ffaaaeeed4ed9b53a408c0f2bc02c8f9p-5,
    -0x1.fffffffffffffp-5
  },
  { // Entry 1371
    0x1.ffaaaeeed4edab4ba4b365ed25a9595fp-5,
    0x1.0p-4
  },
  { // Entry 1372
    -0x1.ffaaaeeed4edab4ba4b365ed25a9595fp-5,
    -0x1.0p-4
  },
  { // Entry 1373
    0x1.ffaaaeeed4edcb3ba608afe1f8f4fa6bp-5,
    0x1.0000000000001p-4
  },
  { // Entry 1374
    -0x1.ffaaaeeed4edcb3ba608afe1f8f4fa6bp-5,
    -0x1.0000000000001p-4
  },
  { // Entry 1375
    0x1.ffeaaaeeee86d8ccfe368cd95e38f003p-6,
    0x1.fffffffffffffp-6
  },
  { // Entry 1376
    -0x1.ffeaaaeeee86d8ccfe368cd95e38f003p-6,
    -0x1.fffffffffffffp-6
  },
  { // Entry 1377
    0x1.ffeaaaeeee86e8cafe41376d47919579p-6,
    0x1.0p-5
  },
  { // Entry 1378
    -0x1.ffeaaaeeee86e8cafe41376d47919579p-6,
    -0x1.0p-5
  },
  { // Entry 1379
    0x1.ffeaaaeeee8708c6fe568c951a428069p-6,
    0x1.0000000000001p-5
  },
  { // Entry 1380
    -0x1.ffeaaaeeee8708c6fe568c951a428069p-6,
    -0x1.0000000000001p-5
  },
  { // Entry 1381
    0x1.fffaaaaeeeed3ed5c9c5ab6538f9cce0p-7,
    0x1.fffffffffffffp-7
  },
  { // Entry 1382
    -0x1.fffaaaaeeeed3ed5c9c5ab6538f9cce0p-7,
    -0x1.fffffffffffffp-7
  },
  { // Entry 1383
    0x1.fffaaaaeeeed4ed549c6560f889ee531p-7,
    0x1.0p-6
  },
  { // Entry 1384
    -0x1.fffaaaaeeeed4ed549c6560f889ee531p-7,
    -0x1.0p-6
  },
  { // Entry 1385
    0x1.fffaaaaeeeed6ed449c7ab6427e8fdd4p-7,
    0x1.0000000000001p-6
  },
  { // Entry 1386
    -0x1.fffaaaaeeeed6ed449c7ab6427e8fdd4p-7,
    -0x1.0000000000001p-6
  },
  { // Entry 1387
    0x1.fffffffaaaaa9aaeeeef6eed4ed442a4p-15,
    0x1.fffffffffffffp-15
  },
  { // Entry 1388
    -0x1.fffffffaaaaa9aaeeeef6eed4ed442a4p-15,
    -0x1.fffffffffffffp-15
  },
  { // Entry 1389
    0x1.fffffffaaaaaaaaeeeeeeeed4ed4ed4fp-15,
    0x1.0p-14
  },
  { // Entry 1390
    -0x1.fffffffaaaaaaaaeeeeeeeed4ed4ed4fp-15,
    -0x1.0p-14
  },
  { // Entry 1391
    0x1.fffffffaaaaacaaeeeedeeed4ed642a4p-15,
    0x1.0000000000001p-14
  },
  { // Entry 1392
    -0x1.fffffffaaaaacaaeeeedeeed4ed642a4p-15,
    -0x1.0000000000001p-14
  },
  { // Entry 1393
    0x1.ffffffffffffeeaaaaaaaaaaaacaeeeep-28,
    0x1.fffffffffffffp-28
  },
  { // Entry 1394
    -0x1.ffffffffffffeeaaaaaaaaaaaacaeeeep-28,
    -0x1.fffffffffffffp-28
  },
  { // Entry 1395
    0x1.fffffffffffffeaaaaaaaaaaaaaaeeeep-28,
    0x1.0p-27
  },
  { // Entry 1396
    -0x1.fffffffffffffeaaaaaaaaaaaaaaeeeep-28,
    -0x1.0p-27
  },
  { // Entry 1397
    0x1.0000000000000f555555555555357777p-27,
    0x1.0000000000001p-27
  },
  { // Entry 1398
    -0x1.0000000000000f555555555555357777p-27,
    -0x1.0000000000001p-27
  },
  { // Entry 1399
    0x1.ffffffffffffeffaaaaaaaaaaaab2aaep-31,
    0x1.fffffffffffffp-31
  },
  { // Entry 1400
    -0x1.ffffffffffffeffaaaaaaaaaaaab2aaep-31,
    -0x1.fffffffffffffp-31
  },
  { // Entry 1401
    0x1.fffffffffffffffaaaaaaaaaaaaaaaaep-31,
    0x1.0p-30
  },
  { // Entry 1402
    -0x1.fffffffffffffffaaaaaaaaaaaaaaaaep-31,
    -0x1.0p-30
  },
  { // Entry 1403
    0x1.0000000000000ffd555555555554d557p-30,
    0x1.0000000000001p-30
  },
  { // Entry 1404
    -0x1.0000000000000ffd555555555554d557p-30,
    -0x1.0000000000001p-30
  },
  { // Entry 1405
    -0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffffffffffffp1023
  },
  { // Entry 1406
    0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    0x1.fffffffffffffp1023
  },
  { // Entry 1407
    0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    0x1.fffffffffffffp1023
  },
  { // Entry 1408
    -0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffffffffffffp1023
  },
  { // Entry 1409
    0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    0x1.fffffffffffffp1023
  },
  { // Entry 1410
    -0x1.452fc98b34e96b61139b09a7c84a44bdp-8,
    -0x1.fffffffffffffp1023
  },
  { // Entry 1411
    0x1.daa3677c6ee8a22eb6c4b12ca10ce021p-1,
    0x1.ffffffffffffep1023
  },
  { // Entry 1412
    -0x1.daa3677c6ee8a22eb6c4b12ca10ce021p-1,
    -0x1.ffffffffffffep1023
  },
  { // Entry 1413
    0x1.1a62633145c06e0e689481270436e2edp-53,
    0x1.921fb54442d18p1
  },
  { // Entry 1414
    -0x1.1a62633145c06e0e689481270436e2edp-53,
    -0x1.921fb54442d18p1
  },
  { // Entry 1415
    0x1.ffffffffffffffffffffffffffec8831p-1,
    0x1.921fb54442d18p0
  },
  { // Entry 1416
    -0x1.ffffffffffffffffffffffffffec8831p-1,
    -0x1.921fb54442d18p0
  },
  { // Entry 1417
    0x1.aed548f090cef18bb5e3871a14d94609p-1,
    0x1.0000000000001p0
  },
  { // Entry 1418
    -0x1.aed548f090cef18bb5e3871a14d94609p-1,
    -0x1.0000000000001p0
  },
  { // Entry 1419
    0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    0x1.0p0
  },
  { // Entry 1420
    -0x1.aed548f090cee0418dd3d2138a1e7865p-1,
    -0x1.0p0
  },
  { // Entry 1421
    0x1.aed548f090ced79c79cbf790441f8197p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 1422
    -0x1.aed548f090ced79c79cbf790441f8197p-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 1423
    0x1.6a09e667f3bcc5e9fee352f50fd3f4e9p-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 1424
    -0x1.6a09e667f3bcc5e9fee352f50fd3f4e9p-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 1425
    0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.0000000000001p-1022
  
"""


```