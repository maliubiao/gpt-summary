Response:
The user wants a summary of the functionality of the provided C source code file, which is located in `bionic/tests/math_data/cos_intel_data.handroid`. This file is part of Android's Bionic library.

Here's a plan to address the user's request:

1. **Identify the core purpose of the file:** Analyze the data structure and the values to understand what kind of information it holds.
2. **Connect to the broader context:** Explain how this data relates to the cosine function and potentially to Intel-specific optimizations.
3. **Summarize the file's function:**  Concise description of what the data represents and its likely use.
好的，这是第 4 部分，让我们来归纳一下 `bionic/tests/math_data/cos_intel_data.handroid` 这个文件的功能。

**功能归纳:**

这个文件是一个包含了大量预先计算好的双精度浮点数值对的测试数据集合，专门用于测试 Android Bionic 库中 `cos` 函数在特定条件下的实现，特别是针对 Intel 架构优化的版本。

**更详细的解释:**

* **测试数据：** 文件中的内容是一系列以 C++ 结构体 `{double input, double expected_output}` 形式存在的数据对。每一对数据都代表了一个 `cos` 函数的输入值 (`input`) 和在理想情况下应该返回的精确输出值 (`expected_output`)。
* **针对性测试：**  这些数据并非随机生成，而是经过精心选择，可能覆盖了 `cos` 函数的各种输入范围，包括：
    * 非常接近 0 的值
    * 接近 π/2 的值
    * 非常大或非常小的值（通过科学计数法中的指数部分体现，例如 `p-52` 表示乘以 2 的 -52 次方）
    * 正数和负数
* **验证准确性：**  这些预先计算好的精确值作为“黄金标准”，可以用来验证 Bionic 库中 `cos` 函数的实现是否正确，尤其是在不同硬件架构和特定优化下。通过将 `cos` 函数的计算结果与这些预期值进行比较，可以评估其精度和正确性。
* **Intel 架构特定：** 文件名中的 `intel_data` 表明这些数据可能特别关注了 Intel 架构下的浮点运算特性和潜在的优化。这可能是为了确保在 Intel 处理器上，Bionic 的 `cos` 函数能够提供高精度和性能。
* **自动化测试：**  这个文件很可能是 Bionic 库自动化测试套件的一部分。在编译和测试 Bionic 库时，测试框架会读取这些数据，将输入值传递给 `cos` 函数，并将函数的输出与预期输出进行比较，从而自动检测潜在的错误或精度问题。

**与 Android 功能的关系举例：**

例如，在 Android 系统中进行图形渲染、物理模拟或者任何需要精确三角函数计算的场景时，都会调用 Bionic 库中的 `cos` 函数。这个文件中的测试数据可以确保在运行这些 Android 功能时，`cos` 函数的计算结果是准确可靠的，尤其是在使用 Intel 处理器的 Android 设备上。

**总结来说，`cos_intel_data.handroid` 文件是 Android Bionic 库中 `cos` 函数质量保证的关键组成部分，它提供了一组用于验证该函数在 Intel 架构下实现正确性和精度的标准测试数据。**

### 提示词
```
这是目录为bionic/tests/math_data/cos_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
,
    -0x1.921fb54442d17p-1
  },
  { // Entry 1069
    0x1.6a09e667f3bccc276712d3d8c5502387p-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 1070
    0x1.6a09e667f3bccc276712d3d8c5502387p-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 1071
    0x1.6a09e667f3bcc0d717df943adef39253p-1,
    0x1.921fb54442d19p-1
  },
  { // Entry 1072
    0x1.6a09e667f3bcc0d717df943adef39253p-1,
    -0x1.921fb54442d19p-1
  },
  { // Entry 1073
    0x1.469898cc51701b839a252049c0b8b50bp-52,
    0x1.921fb54442d17p0
  },
  { // Entry 1074
    0x1.469898cc51701b839a252049c0b8b50bp-52,
    -0x1.921fb54442d17p0
  },
  { // Entry 1075
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    0x1.921fb54442d18p0
  },
  { // Entry 1076
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    -0x1.921fb54442d18p0
  },
  { // Entry 1077
    -0x1.72cece675d1fc8f8cbb5bf6c7dbcfba0p-53,
    0x1.921fb54442d19p0
  },
  { // Entry 1078
    -0x1.72cece675d1fc8f8cbb5bf6c7dbcfba0p-53,
    -0x1.921fb54442d19p0
  },
  { // Entry 1079
    -0x1.fffffffffffffffffffffffff97d5bffp-1,
    0x1.921fb54442d17p1
  },
  { // Entry 1080
    -0x1.fffffffffffffffffffffffff97d5bffp-1,
    -0x1.921fb54442d17p1
  },
  { // Entry 1081
    -0x1.ffffffffffffffffffffffffffb220c5p-1,
    0x1.921fb54442d18p1
  },
  { // Entry 1082
    -0x1.ffffffffffffffffffffffffffb220c5p-1,
    -0x1.921fb54442d18p1
  },
  { // Entry 1083
    -0x1.fffffffffffffffffffffffffde6e58cp-1,
    0x1.921fb54442d19p1
  },
  { // Entry 1084
    -0x1.fffffffffffffffffffffffffde6e58cp-1,
    -0x1.921fb54442d19p1
  },
  { // Entry 1085
    0x1.ffffffffffffffffffffffffe5f56ffep-1,
    0x1.921fb54442d17p2
  },
  { // Entry 1086
    0x1.ffffffffffffffffffffffffe5f56ffep-1,
    -0x1.921fb54442d17p2
  },
  { // Entry 1087
    0x1.fffffffffffffffffffffffffec88317p-1,
    0x1.921fb54442d18p2
  },
  { // Entry 1088
    0x1.fffffffffffffffffffffffffec88317p-1,
    -0x1.921fb54442d18p2
  },
  { // Entry 1089
    0x1.fffffffffffffffffffffffff79b9631p-1,
    0x1.921fb54442d19p2
  },
  { // Entry 1090
    0x1.fffffffffffffffffffffffff79b9631p-1,
    -0x1.921fb54442d19p2
  },
  { // Entry 1091
    0x1.ffffffffffffffffffffffff97d5bff8p-1,
    0x1.921fb54442d17p3
  },
  { // Entry 1092
    0x1.ffffffffffffffffffffffff97d5bff8p-1,
    -0x1.921fb54442d17p3
  },
  { // Entry 1093
    0x1.fffffffffffffffffffffffffb220c5ep-1,
    0x1.921fb54442d18p3
  },
  { // Entry 1094
    0x1.fffffffffffffffffffffffffb220c5ep-1,
    -0x1.921fb54442d18p3
  },
  { // Entry 1095
    0x1.ffffffffffffffffffffffffde6e58c4p-1,
    0x1.921fb54442d19p3
  },
  { // Entry 1096
    0x1.ffffffffffffffffffffffffde6e58c4p-1,
    -0x1.921fb54442d19p3
  },
  { // Entry 1097
    0x1.fffffffffffffffffffffffe5f56ffe1p-1,
    0x1.921fb54442d17p4
  },
  { // Entry 1098
    0x1.fffffffffffffffffffffffe5f56ffe1p-1,
    -0x1.921fb54442d17p4
  },
  { // Entry 1099
    0x1.ffffffffffffffffffffffffec88317ap-1,
    0x1.921fb54442d18p4
  },
  { // Entry 1100
    0x1.ffffffffffffffffffffffffec88317ap-1,
    -0x1.921fb54442d18p4
  },
  { // Entry 1101
    0x1.ffffffffffffffffffffffff79b96313p-1,
    0x1.921fb54442d19p4
  },
  { // Entry 1102
    0x1.ffffffffffffffffffffffff79b96313p-1,
    -0x1.921fb54442d19p4
  },
  { // Entry 1103
    0x1.fffffffffffffffffffffff97d5bff87p-1,
    0x1.921fb54442d17p5
  },
  { // Entry 1104
    0x1.fffffffffffffffffffffff97d5bff87p-1,
    -0x1.921fb54442d17p5
  },
  { // Entry 1105
    0x1.ffffffffffffffffffffffffb220c5e9p-1,
    0x1.921fb54442d18p5
  },
  { // Entry 1106
    0x1.ffffffffffffffffffffffffb220c5e9p-1,
    -0x1.921fb54442d18p5
  },
  { // Entry 1107
    0x1.fffffffffffffffffffffffde6e58c4cp-1,
    0x1.921fb54442d19p5
  },
  { // Entry 1108
    0x1.fffffffffffffffffffffffde6e58c4cp-1,
    -0x1.921fb54442d19p5
  },
  { // Entry 1109
    0x1.ffffffffffffffffffffffe5f56ffe1dp-1,
    0x1.921fb54442d17p6
  },
  { // Entry 1110
    0x1.ffffffffffffffffffffffe5f56ffe1dp-1,
    -0x1.921fb54442d17p6
  },
  { // Entry 1111
    0x1.fffffffffffffffffffffffec88317a7p-1,
    0x1.921fb54442d18p6
  },
  { // Entry 1112
    0x1.fffffffffffffffffffffffec88317a7p-1,
    -0x1.921fb54442d18p6
  },
  { // Entry 1113
    0x1.fffffffffffffffffffffff79b963131p-1,
    0x1.921fb54442d19p6
  },
  { // Entry 1114
    0x1.fffffffffffffffffffffff79b963131p-1,
    -0x1.921fb54442d19p6
  },
  { // Entry 1115
    0x1.ffffffffffffffffffffff97d5bff874p-1,
    0x1.921fb54442d17p7
  },
  { // Entry 1116
    0x1.ffffffffffffffffffffff97d5bff874p-1,
    -0x1.921fb54442d17p7
  },
  { // Entry 1117
    0x1.fffffffffffffffffffffffb220c5e9dp-1,
    0x1.921fb54442d18p7
  },
  { // Entry 1118
    0x1.fffffffffffffffffffffffb220c5e9dp-1,
    -0x1.921fb54442d18p7
  },
  { // Entry 1119
    0x1.ffffffffffffffffffffffde6e58c4c6p-1,
    0x1.921fb54442d19p7
  },
  { // Entry 1120
    0x1.ffffffffffffffffffffffde6e58c4c6p-1,
    -0x1.921fb54442d19p7
  },
  { // Entry 1121
    -0x1.6a09e667f3bc926b59e6d399bd1b906cp-1,
    0x1.2d97c7f3321d1p1
  },
  { // Entry 1122
    -0x1.6a09e667f3bc926b59e6d399bd1b906cp-1,
    -0x1.2d97c7f3321d1p1
  },
  { // Entry 1123
    -0x1.6a09e667f3bcbfac96b3d2115a3c3e21p-1,
    0x1.2d97c7f3321d2p1
  },
  { // Entry 1124
    -0x1.6a09e667f3bcbfac96b3d2115a3c3e21p-1,
    -0x1.2d97c7f3321d2p1
  },
  { // Entry 1125
    -0x1.6a09e667f3bcecedd380d088f1b4c43cp-1,
    0x1.2d97c7f3321d3p1
  },
  { // Entry 1126
    -0x1.6a09e667f3bcecedd380d088f1b4c43cp-1,
    -0x1.2d97c7f3321d3p1
  },
  { // Entry 1127
    -0x1.6a09e667f3bd05e3743ed417c44fba46p-1,
    0x1.f6a7a2955385dp1
  },
  { // Entry 1128
    -0x1.6a09e667f3bd05e3743ed417c44fba46p-1,
    -0x1.f6a7a2955385dp1
  },
  { // Entry 1129
    -0x1.6a09e667f3bcd8a23771d5a02ff5e843p-1,
    0x1.f6a7a2955385ep1
  },
  { // Entry 1130
    -0x1.6a09e667f3bcd8a23771d5a02ff5e843p-1,
    -0x1.f6a7a2955385ep1
  },
  { // Entry 1131
    -0x1.6a09e667f3bcab60faa4d72895f3eea5p-1,
    0x1.f6a7a2955385fp1
  },
  { // Entry 1132
    -0x1.6a09e667f3bcab60faa4d72895f3eea5p-1,
    -0x1.f6a7a2955385fp1
  },
  { // Entry 1133
    -0x1.34f272993d1414a2b39bd8374c1d1631p-50,
    0x1.2d97c7f3321d1p2
  },
  { // Entry 1134
    -0x1.34f272993d1414a2b39bd8374c1d1631p-50,
    -0x1.2d97c7f3321d1p2
  },
  { // Entry 1135
    -0x1.a79394c9e8a0a5159cdec1ba86377c92p-53,
    0x1.2d97c7f3321d2p2
  },
  { // Entry 1136
    -0x1.a79394c9e8a0a5159cdec1ba86377c92p-53,
    -0x1.2d97c7f3321d2p2
  },
  { // Entry 1137
    0x1.961b1acd85d7d6ba98c84f915bbcbc6cp-51,
    0x1.2d97c7f3321d3p2
  },
  { // Entry 1138
    0x1.961b1acd85d7d6ba98c84f915bbcbc6cp-51,
    -0x1.2d97c7f3321d3p2
  },
  { // Entry 1139
    0x1.6a09e667f3bc58af4cbad35aabb200f4p-1,
    0x1.5fdbbe9bba774p2
  },
  { // Entry 1140
    0x1.6a09e667f3bc58af4cbad35aabb200f4p-1,
    -0x1.5fdbbe9bba774p2
  },
  { // Entry 1141
    0x1.6a09e667f3bcb331c654d049eeba380fp-1,
    0x1.5fdbbe9bba775p2
  },
  { // Entry 1142
    0x1.6a09e667f3bcb331c654d049eeba380fp-1,
    -0x1.5fdbbe9bba775p2
  },
  { // Entry 1143
    0x1.6a09e667f3bd0db43feecd391b21d0c4p-1,
    0x1.5fdbbe9bba776p2
  },
  { // Entry 1144
    0x1.6a09e667f3bd0db43feecd391b21d0c4p-1,
    -0x1.5fdbbe9bba776p2
  },
  { // Entry 1145
    0x1.6a09e667f3bd3f9f816ad456ba1a54a9p-1,
    0x1.c463abeccb2bap2
  },
  { // Entry 1146
    0x1.6a09e667f3bd3f9f816ad456ba1a54a9p-1,
    -0x1.c463abeccb2bap2
  },
  { // Entry 1147
    0x1.6a09e667f3bce51d07d0d7679a2d8c53p-1,
    0x1.c463abeccb2bbp2
  },
  { // Entry 1148
    0x1.6a09e667f3bce51d07d0d7679a2d8c53p-1,
    -0x1.c463abeccb2bbp2
  },
  { // Entry 1149
    0x1.6a09e667f3bc8a9a8e36da7863a02597p-1,
    0x1.c463abeccb2bcp2
  },
  { // Entry 1150
    0x1.6a09e667f3bc8a9a8e36da7863a02597p-1,
    -0x1.c463abeccb2bcp2
  },
  { // Entry 1151
    0x1.583ebeff65cc226480ae685c2ad9afdap-50,
    0x1.f6a7a2955385dp2
  },
  { // Entry 1152
    0x1.583ebeff65cc226480ae685c2ad9afdap-50,
    -0x1.f6a7a2955385dp2
  },
  { // Entry 1153
    0x1.60fafbfd9730899202b9a170c4e6a849p-52,
    0x1.f6a7a2955385ep2
  },
  { // Entry 1154
    0x1.60fafbfd9730899202b9a170c4e6a849p-52,
    -0x1.f6a7a2955385ep2
  },
  { // Entry 1155
    -0x1.4f8282013467bb36fea32f479bd48f4ap-51,
    0x1.f6a7a2955385fp2
  },
  { // Entry 1156
    -0x1.4f8282013467bb36fea32f479bd48f4ap-51,
    -0x1.f6a7a2955385fp2
  },
  { // Entry 1157
    -0x1.6a09e667f3bb972f8927d7b46c737485p-1,
    0x1.1475cc9eedeffp3
  },
  { // Entry 1158
    -0x1.6a09e667f3bb972f8927d7b46c737485p-1,
    -0x1.1475cc9eedeffp3
  },
  { // Entry 1159
    -0x1.6a09e667f3bc4c347c5bd1933ca3261fp-1,
    0x1.1475cc9eedfp3
  },
  { // Entry 1160
    -0x1.6a09e667f3bc4c347c5bd1933ca3261fp-1,
    -0x1.1475cc9eedfp3
  },
  { // Entry 1161
    -0x1.6a09e667f3bd01396f8fcb71b2505e1fp-1,
    0x1.1475cc9eedf01p3
  },
  { // Entry 1162
    -0x1.6a09e667f3bd01396f8fcb71b2505e1fp-1,
    -0x1.1475cc9eedf01p3
  },
  { // Entry 1163
    -0x1.ffffffffffffffffffffffffa2c9eda8p-1,
    0x1.2d97c7f3321d1p3
  },
  { // Entry 1164
    -0x1.ffffffffffffffffffffffffa2c9eda8p-1,
    -0x1.2d97c7f3321d1p3
  },
  { // Entry 1165
    -0x1.fffffffffffffffffffffffffd4326f5p-1,
    0x1.2d97c7f3321d2p3
  },
  { // Entry 1166
    -0x1.fffffffffffffffffffffffffd4326f5p-1,
    -0x1.2d97c7f3321d2p3
  },
  { // Entry 1167
    -0x1.ffffffffffffffffffffffffd7bc6041p-1,
    0x1.2d97c7f3321d3p3
  },
  { // Entry 1168
    -0x1.ffffffffffffffffffffffffd7bc6041p-1,
    -0x1.2d97c7f3321d3p3
  },
  { // Entry 1169
    -0x1.6a09e667f3be011f44fdcffc167f7140p-1,
    0x1.46b9c347764a2p3
  },
  { // Entry 1170
    -0x1.6a09e667f3be011f44fdcffc167f7140p-1,
    -0x1.46b9c347764a2p3
  },
  { // Entry 1171
    -0x1.6a09e667f3bd4c1a51c9d61e20c523f7p-1,
    0x1.46b9c347764a3p3
  },
  { // Entry 1172
    -0x1.6a09e667f3bd4c1a51c9d61e20c523f7p-1,
    -0x1.46b9c347764a3p3
  },
  { // Entry 1173
    -0x1.6a09e667f3bc97155e95dc3fd0885d14p-1,
    0x1.46b9c347764a4p3
  },
  { // Entry 1174
    -0x1.6a09e667f3bc97155e95dc3fd0885d14p-1,
    -0x1.46b9c347764a4p3
  },
  { // Entry 1175
    -0x1.3dc585b2c742181326e07c40748873bbp-49,
    0x1.5fdbbe9bba774p3
  },
  { // Entry 1176
    -0x1.3dc585b2c742181326e07c40748873bbp-49,
    -0x1.5fdbbe9bba774p3
  },
  { // Entry 1177
    -0x1.ee2c2d963a10c0993703e20446463301p-52,
    0x1.5fdbbe9bba775p3
  },
  { // Entry 1178
    -0x1.ee2c2d963a10c0993703e20446463301p-52,
    -0x1.5fdbbe9bba775p3
  },
  { // Entry 1179
    0x1.8474f49a717bcfd9b23f077ee4d090cfp-50,
    0x1.5fdbbe9bba776p3
  },
  { // Entry 1180
    0x1.8474f49a717bcfd9b23f077ee4d090cfp-50,
    -0x1.5fdbbe9bba776p3
  },
  { // Entry 1181
    0x1.6a09e667f3bb8ab4b8c8d5ecf6b910d6p-1,
    0x1.78fdb9effea45p3
  },
  { // Entry 1182
    0x1.6a09e667f3bb8ab4b8c8d5ecf6b910d6p-1,
    -0x1.78fdb9effea45p3
  },
  { // Entry 1183
    0x1.6a09e667f3bc3fb9abfccfcbcd262aa0p-1,
    0x1.78fdb9effea46p3
  },
  { // Entry 1184
    0x1.6a09e667f3bc3fb9abfccfcbcd262aa0p-1,
    -0x1.78fdb9effea46p3
  },
  { // Entry 1185
    0x1.6a09e667f3bcf4be9f30c9aa4910cacfp-1,
    0x1.78fdb9effea47p3
  },
  { // Entry 1186
    0x1.6a09e667f3bcf4be9f30c9aa4910cacfp-1,
    -0x1.78fdb9effea47p3
  },
  { // Entry 1187
    0x1.6a09e667f3be0d9a155cd1c3767eb7b3p-1,
    0x1.ab41b09886fe8p3
  },
  { // Entry 1188
    0x1.6a09e667f3be0d9a155cd1c3767eb7b3p-1,
    -0x1.ab41b09886fe8p3
  },
  { // Entry 1189
    0x1.6a09e667f3bd58952228d7e58701d299p-1,
    0x1.ab41b09886fe9p3
  },
  { // Entry 1190
    0x1.6a09e667f3bd58952228d7e58701d299p-1,
    -0x1.ab41b09886fe9p3
  },
  { // Entry 1191
    0x1.6a09e667f3bca3902ef4de073d0273e6p-1,
    0x1.ab41b09886feap3
  },
  { // Entry 1192
    0x1.6a09e667f3bca3902ef4de073d0273e6p-1,
    -0x1.ab41b09886feap3
  },
  { // Entry 1193
    0x1.4f6babe5db9e1ef40d69c452e135591dp-49,
    0x1.c463abeccb2bap3
  },
  { // Entry 1194
    0x1.4f6babe5db9e1ef40d69c452e135591dp-49,
    -0x1.c463abeccb2bap3
  },
  { // Entry 1195
    0x1.3daeaf976e787bd035a7114be387b5c3p-51,
    0x1.c463abeccb2bbp3
  },
  { // Entry 1196
    0x1.3daeaf976e787bd035a7114be387b5c3p-51,
    -0x1.c463abeccb2bbp3
  },
  { // Entry 1197
    -0x1.6128a83448c3c217e52c775a0698d26ap-50,
    0x1.c463abeccb2bcp3
  },
  { // Entry 1198
    -0x1.6128a83448c3c217e52c775a0698d26ap-50,
    -0x1.c463abeccb2bcp3
  },
  { // Entry 1199
    -0x1.6a09e667f3bb7e39e869d42580908c7cp-1,
    0x1.dd85a7410f58bp3
  },
  { // Entry 1200
    -0x1.6a09e667f3bb7e39e869d42580908c7cp-1,
    -0x1.dd85a7410f58bp3
  },
  { // Entry 1201
    -0x1.6a09e667f3bc333edb9dce045d3b0e75p-1,
    0x1.dd85a7410f58cp3
  },
  { // Entry 1202
    -0x1.6a09e667f3bc333edb9dce045d3b0e75p-1,
    -0x1.dd85a7410f58cp3
  },
  { // Entry 1203
    -0x1.6a09e667f3bce843ced1c7e2df6316d4p-1,
    0x1.dd85a7410f58dp3
  },
  { // Entry 1204
    -0x1.6a09e667f3bce843ced1c7e2df6316d4p-1,
    -0x1.dd85a7410f58dp3
  },
  { // Entry 1205
    -0x1.ffffffffffffffffffffffff8c45d3d4p-1,
    0x1.f6a7a2955385dp3
  },
  { // Entry 1206
    -0x1.ffffffffffffffffffffffff8c45d3d4p-1,
    -0x1.f6a7a2955385dp3
  },
  { // Entry 1207
    -0x1.fffffffffffffffffffffffff8653353p-1,
    0x1.f6a7a2955385ep3
  },
  { // Entry 1208
    -0x1.fffffffffffffffffffffffff8653353p-1,
    -0x1.f6a7a2955385ep3
  },
  { // Entry 1209
    -0x1.ffffffffffffffffffffffffe48492d3p-1,
    0x1.f6a7a2955385fp3
  },
  { // Entry 1210
    -0x1.ffffffffffffffffffffffffe48492d3p-1,
    -0x1.f6a7a2955385fp3
  },
  { // Entry 1211
    -0x1.6a09e667f3bf841ecc23c74599076a81p-1,
    0x1.07e4cef4cbd96p4
  },
  { // Entry 1212
    -0x1.6a09e667f3bf841ecc23c74599076a81p-1,
    -0x1.07e4cef4cbd96p4
  },
  { // Entry 1213
    -0x1.6a09e667f3be1a14e5bbd38ad60fdd7bp-1,
    0x1.07e4cef4cbd97p4
  },
  { // Entry 1214
    -0x1.6a09e667f3be1a14e5bbd38ad60fdd7bp-1,
    -0x1.07e4cef4cbd97p4
  },
  { // Entry 1215
    -0x1.6a09e667f3bcb00aff53dfcea90e6a0cp-1,
    0x1.07e4cef4cbd98p4
  },
  { // Entry 1216
    -0x1.6a09e667f3bcb00aff53dfcea90e6a0cp-1,
    -0x1.07e4cef4cbd98p4
  },
  { // Entry 1217
    -0x1.b088e90c77fd12ea79f98631e6f0b74bp-48,
    0x1.1475cc9eedeffp4
  },
  { // Entry 1218
    -0x1.b088e90c77fd12ea79f98631e6f0b74bp-48,
    -0x1.1475cc9eedeffp4
  },
  { // Entry 1219
    -0x1.6111d218effa25d4f3f30c654d7c36a1p-49,
    0x1.1475cc9eedfp4
  },
  { // Entry 1220
    -0x1.6111d218effa25d4f3f30c654d7c36a1p-49,
    -0x1.1475cc9eedfp4
  },
  { // Entry 1221
    0x1.3ddc5bce200bb4561819e73527f5a6d7p-50,
    0x1.1475cc9eedf01p4
  },
  { // Entry 1222
    0x1.3ddc5bce200bb4561819e73527f5a6d7p-50,
    -0x1.1475cc9eedf01p4
  },
  { // Entry 1223
    0x1.6a09e667f3babcba24d6d87ecc8f83b4p-1,
    0x1.2106ca4910068p4
  },
  { // Entry 1224
    0x1.6a09e667f3babcba24d6d87ecc8f83b4p-1,
    -0x1.2106ca4910068p4
  },
  { // Entry 1225
    0x1.6a09e667f3bc26c40b3ecc3cece1d1a0p-1,
    0x1.2106ca4910069p4
  },
  { // Entry 1226
    0x1.6a09e667f3bc26c40b3ecc3cece1d1a0p-1,
    -0x1.2106ca4910069p4
  },
  { // Entry 1227
    0x1.6a09e667f3bd90cdf1a6bff9a32a3923p-1,
    0x1.2106ca491006ap4
  },
  { // Entry 1228
    0x1.6a09e667f3bd90cdf1a6bff9a32a3923p-1,
    -0x1.2106ca491006ap4
  },
  { // Entry 1229
    0x1.fffffffffffffffffffffffe8b27b6a2p-1,
    0x1.2d97c7f3321d1p4
  },
  { // Entry 1230
    0x1.fffffffffffffffffffffffe8b27b6a2p-1,
    -0x1.2d97c7f3321d1p4
  },
  { // Entry 1231
    0x1.fffffffffffffffffffffffff50c9bd4p-1,
    0x1.2d97c7f3321d2p4
  },
  { // Entry 1232
    0x1.fffffffffffffffffffffffff50c9bd4p-1,
    -0x1.2d97c7f3321d2p4
  },
  { // Entry 1233
    0x1.ffffffffffffffffffffffff5ef18107p-1,
    0x1.2d97c7f3321d3p4
  },
  { // Entry 1234
    0x1.ffffffffffffffffffffffff5ef18107p-1,
    -0x1.2d97c7f3321d3p4
  },
  { // Entry 1235
    0x1.6a09e667f3bf90999c82c90cebaf9f3fp-1,
    0x1.3a28c59d54339p4
  },
  { // Entry 1236
    0x1.6a09e667f3bf90999c82c90cebaf9f3fp-1,
    -0x1.3a28c59d54339p4
  },
  { // Entry 1237
    0x1.6a09e667f3be268fb61ad5523532e298p-1,
    0x1.3a28c59d5433ap4
  },
  { // Entry 1238
    0x1.6a09e667f3be268fb61ad5523532e298p-1,
    -0x1.3a28c59d5433ap4
  },
  { // Entry 1239
    0x1.6a09e667f3bcbc85cfb2e19614ac3f88p-1,
    0x1.3a28c59d5433bp4
  },
  { // Entry 1240
    0x1.6a09e667f3bcbc85cfb2e19614ac3f88p-1,
    -0x1.3a28c59d5433bp4
  },
  { // Entry 1241
    0x1.b95bfc26022b165aed3e2a3b12382479p-48,
    0x1.46b9c347764a2p4
  },
  { // Entry 1242
    0x1.b95bfc26022b165aed3e2a3b12382479p-48,
    -0x1.46b9c347764a2p4
  },
  { // Entry 1243
    0x1.72b7f84c04562cb5da7c5477b957adebp-49,
    0x1.46b9c347764a3p4
  },
  { // Entry 1244
    0x1.72b7f84c04562cb5da7c5477b957adebp-49,
    -0x1.46b9c347764a3p4
  },
  { // Entry 1245
    -0x1.1a900f67f753a6944b07571048f1cad2p-50,
    0x1.46b9c347764a4p4
  },
  { // Entry 1246
    -0x1.1a900f67f753a6944b07571048f1cad2p-50,
    -0x1.46b9c347764a4p4
  },
  { // Entry 1247
    -0x1.6a09e667f3bab03f5477d6b74f4d55d5p-1,
    0x1.534ac0f19860bp4
  },
  { // Entry 1248
    -0x1.6a09e667f3bab03f5477d6b74f4d55d5p-1,
    -0x1.534ac0f19860bp4
  },
  { // Entry 1249
    -0x1.6a09e667f3bc1a493adfca757c1a741fp-1,
    0x1.534ac0f19860cp4
  },
  { // Entry 1250
    -0x1.6a09e667f3bc1a493adfca757c1a741fp-1,
    -0x1.534ac0f19860cp4
  },
  { // Entry 1251
    -0x1.6a09e667f3bd84532147be323eddac01p-1,
    0x1.534ac0f19860dp4
  },
  { // Entry 1252
    -0x1.6a09e667f3bd84532147be323eddac01p-1,
    -0x1.534ac0f19860dp4
  },
  { // Entry 1253
    -0x1.fffffffffffffffffffffffe758d3a7cp-1,
    0x1.5fdbbe9bba774p4
  },
  { // Entry 1254
    -0x1.fffffffffffffffffffffffe758d3a7cp-1,
    -0x1.5fdbbe9bba774p4
  },
  { // Entry 1255
    -0x1.fffffffffffffffffffffffff11845e1p-1,
    0x1.5fdbbe9bba775p4
  },
  { // Entry 1256
    -0x1.fffffffffffffffffffffffff11845e1p-1,
    -0x1.5fdbbe9bba775p4
  },
  { // Entry 1257
    -0x1.ffffffffffffffffffffffff6ca35147p-1,
    0x1.5fdbbe9bba776p4
  },
  { // Entry 1258
    -0x1.ffffffffffffffffffffffff6ca35147p-1,
    -0x1.5fdbbe9bba776p4
  },
  { // Entry 1259
    -0x1.6a09e667f3bf9d146ce1cad43de9b352p-1,
    0x1.6c6cbc45dc8dcp4
  },
  { // Entry 1260
    -0x1.6a09e667f3bf9d146ce1cad43de9b352p-1,
    -0x1.6c6cbc45dc8dcp4
  },
  { // Entry 1261
    -0x1.6a09e667f3be330a8679d71993e7c709p-1,
    0x1.6c6cbc45dc8ddp4
  },
  { // Entry 1262
    -0x1.6a09e667f3be330a8679d71993e7c709p-1,
    -0x1.6c6cbc45dc8ddp4
  },
  { // Entry 1263
    -0x1.6a09e667f3bcc900a011e35d7fdbf459p-1,
    0x1.6c6cbc45dc8dep4
  },
  { // Entry 1264
    -0x1.6a09e667f3bcc900a011e35d7fdbf459p-1,
    -0x1.6c6cbc45dc8dep4
  },
  { // Entry 1265
    -0x1.c22f0f3f8c5919cb6082ce443cf95022p-48,
    0x1.78fdb9effea45p4
  },
  { // Entry 1266
    -0x1.c22f0f3f8c5919cb6082ce443cf95022p-48,
    -0x1.78fdb9effea45p4
  },
  { // Entry 1267
    -0x1.845e1e7f18b23396c1059c8a24c2609cp-49,
    0x1.78fdb9effea46p4
  },
  { // Entry 1268
    -0x1.845e1e7f18b23396c1059c8a24c2609cp-49,
    -0x1.78fdb9effea46p4
  },
  { // Entry 1269
    0x1.ee8786039d3731a4fbe98dd6d32ff62ap-51,
    0x1.78fdb9effea47p4
  },
  { // Entry 1270
    0x1.ee8786039d3731a4fbe98dd6d32ff62ap-51,
    -0x1.78fdb9effea47p4
  },
  { // Entry 1271
    0x1.6a09e667f3baa3c48418d4efd19d074ap-1,
    0x1.858eb79a20baep4
  },
  { // Entry 1272
    0x1.6a09e667f3baa3c48418d4efd19d074ap-1,
    -0x1.858eb79a20baep4
  },
  { // Entry 1273
    0x1.6a09e667f3bc0dce6a80c8ae0ae4f5f3p-1,
    0x1.858eb79a20bafp4
  },
  { // Entry 1274
    0x1.6a09e667f3bc0dce6a80c8ae0ae4f5f3p-1,
    -0x1.858eb79a20bafp4
  },
  { // Entry 1275
    0x1.6a09e667f3bd77d850e8bc6ada22fe34p-1,
    0x1.858eb79a20bb0p4
  },
  { // Entry 1276
    0x1.6a09e667f3bd77d850e8bc6ada22fe34p-1,
    -0x1.858eb79a20bb0p4
  },
  { // Entry 1277
    -0x1.2ccaf641d4261ea3ccd8d2a102dc3066p-3,
    0x1.fffffffffffffp62
  },
  { // Entry 1278
    -0x1.2ccaf641d4261ea3ccd8d2a102dc3066p-3,
    -0x1.fffffffffffffp62
  },
  { // Entry 1279
    0x1.82aa375b3c33e70663731bab4beb6ed3p-7,
    0x1.0p63
  },
  { // Entry 1280
    0x1.82aa375b3c33e70663731bab4beb6ed3p-7,
    -0x1.0p63
  },
  { // Entry 1281
    0x1.4c0622a6e35ddefd5f2b7700716a581fp-2,
    0x1.0000000000001p63
  },
  { // Entry 1282
    0x1.4c0622a6e35ddefd5f2b7700716a581fp-2,
    -0x1.0000000000001p63
  },
  { // Entry 1283
    0x1.4ab650b8c60734385375e22603fcdb10p-1,
    0x1.fffffffffffffp26
  },
  { // Entry 1284
    0x1.4ab650b8c60734385375e22603fcdb10p-1,
    -0x1.fffffffffffffp26
  },
  { // Entry 1285
    0x1.4ab6511a7d39ad3cc88ded1e775ca147p-1,
    0x1.0p27
  },
  { // Entry 1286
    0x1.4ab6511a7d39ad3cc88ded1e775ca147p-1,
    -0x1.0p27
  },
  { // Entry 1287
    0x1.4ab651ddeb9e61438382f02167ade4afp-1,
    0x1.0000000000001p27
  },
  { // Entry 1288
    0x1.4ab651ddeb9e61438382f02167ade4afp-1,
    -0x1.0000000000001p27
  },
  { // Entry 1289
    0x1.40ad67e777b1df0195189f50a8c26345p-1,
    0x1.fffffffffffffp23
  },
  { // Entry 1290
    0x1.40ad67e777b1df0195189f50a8c26345p-1,
    -0x1.fffffffffffffp23
  },
  { // Entry 1291
    0x1.40ad67f3f0c9a143963c9c96dbce3f8ap-1,
    0x1.0p24
  },
  { // Entry 1292
    0x1.40ad67f3f0c9a143963c9c96dbce3f8ap-1,
    -0x1.0p24
  },
  { // Entry 1293
    0x1.40ad680ce2f924d716769d1064bc8defp-1,
    0x1.0000000000001p24
  },
  { // Entry 1294
    0x1.40ad680ce2f924d716769d1064bc8defp-1,
    -0x1.0000000000001p24
  },
  { // Entry 1295
    -0x1.4eaa606db24c3cb5e15d7b19d5ee73a1p-1,
    0x1.fffffffffffffp1
  },
  { // Entry 1296
    -0x1.4eaa606db24c3cb5e15d7b19d5ee73a1p-1,
    -0x1.fffffffffffffp1
  },
  { // Entry 1297
    -0x1.4eaa606db24c0c466da1c2dc7baa2b32p-1,
    0x1.0p2
  },
  { // Entry 1298
    -0x1.4eaa606db24c0c466da1c2dc7baa2b32p-1,
    -0x1.0p2
  },
  { // Entry 1299
    -0x1.4eaa606db24bab67862a5261b7719dcfp-1,
    0x1.0000000000001p2
  },
  { // Entry 1300
    -0x1.4eaa606db24bab67862a5261b7719dcfp-1,
    -0x1.0000000000001p2
  },
  { // Entry 1301
    -0x1.aa2265753720101145230952e61c6f2cp-2,
    0x1.fffffffffffffp0
  },
  { // Entry 1302
    -0x1.aa2265753720101145230952e61c6f2cp-2,
    -0x1.fffffffffffffp0
  },
  { // Entry 1303
    -0x1.aa22657537204a4332f8acbb72b0d768p-2,
    0x1.0p1
  },
  { // Entry 1304
    -0x1.aa22657537204a4332f8acbb72b0d768p-2,
    -0x1.0p1
  },
  { // Entry 1305
    -0x1.aa2265753720bea70ea3f38c86db40afp-2,
    0x1.0000000000001p1
  },
  { // Entry 1306
    -0x1.aa2265753720bea70ea3f38c86db40afp-2,
    -0x1.0000000000001p1
  },
  { // Entry 1307
    0x1.14a280fb5068c69a2ed45fb547c2f271p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 1308
    0x1.14a280fb5068c69a2ed45fb547c2f271p-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 1309
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    0x1.0p0
  },
  { // Entry 1310
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    -0x1.0p0
  },
  { // Entry 1311
    0x1.14a280fb50689e362ffdd221e2551035p-1,
    0x1.0000000000001p0
  },
  { // Entry 1312
    0x1.14a280fb50689e362ffdd221e2551035p-1,
    -0x1.0000000000001p0
  },
  { // Entry 1313
    0x1.c1528065b7d4fdb158c9c4a6b3e4b740p-1,
    0x1.fffffffffffffp-2
  },
  { // Entry 1314
    0x1.c1528065b7d4fdb158c9c4a6b3e4b740p-1,
    -0x1.fffffffffffffp-2
  },
  { // Entry 1315
    0x1.c1528065b7d4f9db7bbb3b45f5f5b30ap-1,
    0x1.0p-1
  },
  { // Entry 1316
    0x1.c1528065b7d4f9db7bbb3b45f5f5b30ap-1,
    -0x1.0p-1
  },
  { // Entry 1317
    0x1.c1528065b7d4f22fc19e288479c36b27p-1,
    0x1.0000000000001p-1
  },
  { // Entry 1318
    0x1.c1528065b7d4f22fc19e288479c36b27p-1,
    -0x1.0000000000001p-1
  },
  { // Entry 1319
    0x1.f01549f7deea184c5f1d210b6adbe56cp-1,
    0x1.fffffffffffffp-3
  },
  { // Entry 1320
    0x1.f01549f7deea184c5f1d210b6adbe56cp-1,
    -0x1.fffffffffffffp-3
  },
  { // Entry 1321
    0x1.f01549f7deea174f07a67972bf29f148p-1,
    0x1.0p-2
  },
  { // Entry 1322
    0x1.f01549f7deea174f07a67972bf29f148p-1,
    -0x1.0p-2
  },
  { // Entry 1323
    0x1.f01549f7deea155458b92a4167aec7ffp-1,
    0x1.0000000000001p-2
  },
  { // Entry 1324
    0x1.f01549f7deea155458b92a4167aec7ffp-1,
    -0x1.0000000000001p-2
  },
  { // Entry 1325
    0x1.fc015527d5bd371a12320249ca4dafd7p-1,
    0x1.fffffffffffffp-4
  },
  { // Entry 1326
    0x1.fc015527d5bd371a12320249ca4dafd7p-1,
    -0x1.fffffffffffffp-4
  },
  { // Entry 1327
    0x1.fc015527d5bd36da3cd4253bede319cap-1,
    0x1.0p-3
  },
  { // Entry 1328
    0x1.fc015527d5bd36da3cd4253bede319cap-1,
    -0x1.0p-3
  },
  { // Entry 1329
    0x1.fc015527d5bd365a92186b203507f9adp-1,
    0x1.0000000000001p-3
  },
  { // Entry 1330
    0x1.fc015527d5bd365a92186b203507f9adp-1,
    -0x1.0000000000001p-3
  },
  { // Entry 1331
    0x1.ff0015549f4d34da0b745dc7433145efp-1,
    0x1.fffffffffffffp-5
  },
  { // Entry 1332
    0x1.ff0015549f4d34da0b745dc7433145efp-1,
    -0x1.fffffffffffffp-5
  },
  { // Entry 1333
    0x1.ff0015549f4d34ca0e1ee6509bc42b71p-1,
    0x1.0p-4
  },
  { // Entry 1334
    0x1.ff0015549f4d34ca0e1ee6509bc42b71p-1,
    -0x1.0p-4
  },
  { // Entry 1335
    0x1.ff0015549f4d34aa1373f7634ce87737p-1,
    0x1.0000000000001p-4
  },
  { // Entry 1336
    0x1.ff0015549f4d34aa1373f7634ce87737p-1,
    -0x1.0000000000001p-4
  },
  { // Entry 1337
    0x1.ffc00155527d2b16aeb09fb70636a10ap-1,
    0x1.fffffffffffffp-6
  },
  { // Entry 1338
    0x1.ffc00155527d2b16aeb09fb70636a10ap-1,
    -0x1.fffffffffffffp-6
  },
  { // Entry 1339
    0x1.ffc00155527d2b12aedb49d92928df72p-1,
    0x1.0p-5
  },
  { // Entry 1340
    0x1.ffc00155527d2b12aedb49d92928df72p-1,
    -0x1.0p-5
  },
  { // Entry 1341
    0x1.ffc00155527d2b0aaf309e1d6f0cfc4ep-1,
    0x1.0000000000001p-5
  },
  { // Entry 1342
    0x1.ffc00155527d2b0aaf309e1d6f0cfc4ep-1,
    -0x1.0000000000001p-5
  },
  { // Entry 1343
    0x1.fff000155549f4a38a2563ef344c3ff4p-1,
    0x1.fffffffffffffp-7
  },
  { // Entry 1344
    0x1.fff000155549f4a38a2563ef344c3ff4p-1,
    -0x1.fffffffffffffp-7
  },
  { // Entry 1345
    0x1.fff000155549f4a28a280e97bcd59c8ap-1,
    0x1.0p-6
  },
  { // Entry 1346
    0x1.fff000155549f4a28a280e97bcd59c8ap-1,
    -0x1.0p-6
  },
  { // Entry 1347
    0x1.fff000155549f4a08a2d63e8cde83db5p-1,
    0x1.0000000000001p-6
  },
  { // Entry 1348
    0x1.fff000155549f4a08a2d63e8cde83db5p-1,
    -0x1.0000000000001p-6
  },
  { // Entry 1349
    0x1.fffffff00000001555565549f49c9f4dp-1,
    0x1.fffffffffffffp-15
  },
  { // Entry 1350
    0x1.fffffff00000001555565549f49c9f4dp-1,
    -0x1.fffffffffffffp-15
  },
  { // Entry 1351
    0x1.fffffff00000001555555549f49f49f7p-1,
    0x1.0p-14
  },
  { // Entry 1352
    0x1.fffffff00000001555555549f49f49f7p-1,
    -0x1.0p-14
  },
  { // Entry 1353
    0x1.fffffff00000001555535549f4a49f4dp-1,
    0x1.0000000000001p-14
  },
  { // Entry 1354
    0x1.fffffff00000001555535549f4a49f4dp-1,
    -0x1.0000000000001p-14
  },
  { // Entry 1355
    0x1.fffffffffffffc000000000000415555p-1,
    0x1.fffffffffffffp-28
  },
  { // Entry 1356
    0x1.fffffffffffffc000000000000415555p-1,
    -0x1.fffffffffffffp-28
  },
  { // Entry 1357
    0x1.fffffffffffffc000000000000015555p-1,
    0x1.0p-27
  },
  { // Entry 1358
    0x1.fffffffffffffc000000000000015555p-1,
    -0x1.0p-27
  },
  { // Entry 1359
    0x1.fffffffffffffbffffffffffff815555p-1,
    0x1.0000000000001p-27
  },
  { // Entry 1360
    0x1.fffffffffffffbffffffffffff815555p-1,
    -0x1.0000000000001p-27
  },
  { // Entry 1361
    0x1.fffffffffffffff00000000000010015p-1,
    0x1.fffffffffffffp-31
  },
  { // Entry 1362
    0x1.fffffffffffffff00000000000010015p-1,
    -0x1.fffffffffffffp-31
  },
  { // Entry 1363
    0x1.fffffffffffffff00000000000000015p-1,
    0x1.0p-30
  },
  { // Entry 1364
    0x1.fffffffffffffff00000000000000015p-1,
    -0x1.0p-30
  },
  { // Entry 1365
    0x1.ffffffffffffffeffffffffffffe0015p-1,
    0x1.0000000000001p-30
  },
  { // Entry 1366
    0x1.ffffffffffffffeffffffffffffe0015p-1,
    -0x1.0000000000001p-30
  },
  { // Entry 1367
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    -0x1.fffffffffffffp1023
  },
  { // Entry 1368
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    0x1.fffffffffffffp1023
  },
  { // Entry 1369
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    0x1.fffffffffffffp1023
  },
  { // Entry 1370
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    -0x1.fffffffffffffp1023
  },
  { // Entry 1371
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    0x1.fffffffffffffp1023
  },
  { // Entry 1372
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    -0x1.fffffffffffffp1023
  },
  { // Entry 1373
    0x1.7ffdfb4c5308f777cf774c733b256695p-2,
    0x1.ffffffffffffep1023
  },
  { // Entry 1374
    0x1.7ffdfb4c5308f777cf774c733b256695p-2,
    -0x1.ffffffffffffep1023
  },
  { // Entry 1375
    -0x1.ffffffffffffffffffffffffffb220c5p-1,
    0x1.921fb54442d18p1
  },
  { // Entry 1376
    -0x1.ffffffffffffffffffffffffffb220c5p-1,
    -0x1.921fb54442d18p1
  },
  { // Entry 1377
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    0x1.921fb54442d18p0
  },
  { // Entry 1378
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    -0x1.921fb54442d18p0
  },
  { // Entry 1379
    0x1.14a280fb50689e362ffdd221e2551035p-1,
    0x1.0000000000001p0
  },
  { // Entry 1380
    0x1.14a280fb50689e362ffdd221e2551035p-1,
    -0x1.0000000000001p0
  },
  { // Entry 1381
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    0x1.0p0
  },
  { // Entry 1382
    0x1.14a280fb5068b923848cdb2ed0e37a53p-1,
    -0x1.0p0
  },
  { // Entry 1383
    0x1.14a280fb5068c69a2ed45fb547c2f271p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 1384
    0x1.14a280fb5068c69a2ed45fb547c2f271p-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 1385
    0x1.6a09e667f3bccc276712d3d8c5502387p-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 1386
    0x1.6a09e667f3bccc276712d3d8c5502387p-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 1387
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p-1022
  },
  { // Entry 1388
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p-1022
  },
  { // Entry 1389
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1022
  },
  { // Entry 1390
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1022
  },
  { // Entry 1391
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep-1023
  },
  { // Entry 1392
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 1393
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 1394
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 1395
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1073
  },
  { // Entry 1396
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1073
  },
  { // Entry 1397
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074
  },
  { // Entry 1398
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 1399
    0x1.p0,
    0.0
  },
  { // Entry 1400
    0x1.p0,
    -0.0
  },
};
```