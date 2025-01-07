Response:
The user wants to understand the functionality of the `atanf_intel_data.handroid` file within the Android bionic library. This is the third part of a three-part question. Since this is the final part, the main goal is to summarize the file's purpose.

Based on the file content itself (a large array of floating-point pairs), it seems like this file contains test data for the `atanf` function. Each entry likely represents an input value for `atanf` and the expected output value.

Therefore, the primary function of this file is to provide test cases for verifying the correctness of the `atanf` implementation in the bionic math library.好的，这是第三部分，让我们来归纳一下 `bionic/tests/math_data/atanf_intel_data.handroid` 文件的功能。

**功能归纳:**

`bionic/tests/math_data/atanf_intel_data.handroid` 文件是 Android Bionic 库中用于测试 `atanf` 函数（单精度浮点数的反正切函数）的数据文件。

**具体来说，它的主要功能是:**

1. **提供 `atanf` 函数的测试用例:**  文件中包含一个 C++ 结构体数组，每个结构体包含一对单精度浮点数。
   - 第一个浮点数是 `atanf` 函数的输入值。
   - 第二个浮点数是对于该输入值，`atanf` 函数的预期输出值。

2. **用于验证 `atanf` 函数的正确性:**  这些测试用例被用于 Bionic 库的测试套件中，以确保 `atanf` 函数的实现符合标准，能够针对各种输入值返回正确的反正切值。这些测试用例覆盖了各种不同的输入范围，包括正数、负数、零、非常小和非常大的数，以及一些特殊值（例如接近或等于机器精度的值）。

**与 Android 功能的关系：**

这个文件直接关系到 Android 系统中数学运算的正确性。`atanf` 函数是 C 标准库 `<math.h>` 中的一部分，广泛用于各种应用程序和系统组件中，进行角度计算、信号处理、图形渲染等。确保 `atanf` 函数的正确性对于保证 Android 系统的稳定性和应用程序的正确运行至关重要。

**总结：**

`atanf_intel_data.handroid` 文件是 Android Bionic 库中用于测试 `atanf` 函数的核心数据，它通过提供大量的输入和预期输出值，帮助开发者验证 `atanf` 函数实现的准确性，从而确保 Android 系统底层数学运算的可靠性。 它的存在是为了保证 Android 平台上的数学计算能够得到正确的结果，这对于依赖这些计算的应用程序和系统组件至关重要。

这就是对 `bionic/tests/math_data/atanf_intel_data.handroid` 文件功能的归纳。

Prompt: 
```
这是目录为bionic/tests/math_data/atanf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共3部分，请归纳一下它的功能

"""
  },
  { // Entry 771
    0x1.7dcb7c4be6b4be644d7db098c68e6e5ep0,
    0x1.921fb4p3
  },
  { // Entry 772
    -0x1.7dcb7c4be6b4be644d7db098c68e6e5ep0,
    -0x1.921fb4p3
  },
  { // Entry 773
    0x1.7dcb7c65ad1b3ccb7360f1b9b77bc510p0,
    0x1.921fb6p3
  },
  { // Entry 774
    -0x1.7dcb7c65ad1b3ccb7360f1b9b77bc510p0,
    -0x1.921fb6p3
  },
  { // Entry 775
    0x1.7dcb7c7f738179f9a5848bd2f6ea74p0,
    0x1.921fb8p3
  },
  { // Entry 776
    -0x1.7dcb7c7f738179f9a5848bd2f6ea74p0,
    -0x1.921fb8p3
  },
  { // Entry 777
    0x1.87f17cf56d5854572d8ed4b6d7629cb7p0,
    0x1.921fb4p4
  },
  { // Entry 778
    -0x1.87f17cf56d5854572d8ed4b6d7629cb7p0,
    -0x1.921fb4p4
  },
  { // Entry 779
    0x1.87f17d026030951388edff604c5b31acp0,
    0x1.921fb6p4
  },
  { // Entry 780
    -0x1.87f17d026030951388edff604c5b31acp0,
    -0x1.921fb6p4
  },
  { // Entry 781
    0x1.87f17d0f5308b4e40d66884bfda71f16p0,
    0x1.921fb8p4
  },
  { // Entry 782
    -0x1.87f17d0f5308b4e40d66884bfda71f16p0,
    -0x1.921fb8p4
  },
  { // Entry 783
    0x1.8d08152ac2c9f80510b67fe8688fe00bp0,
    0x1.921fb4p5
  },
  { // Entry 784
    -0x1.8d08152ac2c9f80510b67fe8688fe00bp0,
    -0x1.921fb4p5
  },
  { // Entry 785
    0x1.8d0815313e2db1236b7416aaf31784edp0,
    0x1.921fb6p5
  },
  { // Entry 786
    -0x1.8d0815313e2db1236b7416aaf31784edp0,
    -0x1.921fb6p5
  },
  { // Entry 787
    0x1.8d081537b99159c1d87b49089b46259bp0,
    0x1.921fb8p5
  },
  { // Entry 788
    -0x1.8d081537b99159c1d87b49089b46259bp0,
    -0x1.921fb8p5
  },
  { // Entry 789
    0x1.8f93d4b57dde1ae888776df959240a29p0,
    0x1.921fb4p6
  },
  { // Entry 790
    -0x1.8f93d4b57dde1ae888776df959240a29p0,
    -0x1.921fb4p6
  },
  { // Entry 791
    0x1.8f93d4b8bbcf027a20c8f2f1496ed581p0,
    0x1.921fb6p6
  },
  { // Entry 792
    -0x1.8f93d4b8bbcf027a20c8f2f1496ed581p0,
    -0x1.921fb6p6
  },
  { // Entry 793
    0x1.8f93d4bbf9bfe1ca81404ffb114601efp0,
    0x1.921fb8p6
  },
  { // Entry 794
    -0x1.8f93d4bbf9bfe1ca81404ffb114601efp0,
    -0x1.921fb8p6
  },
  { // Entry 795
    0x1.90d9c2ec819f17b4d8062df65c79686ep0,
    0x1.921fb4p7
  },
  { // Entry 796
    -0x1.90d9c2ec819f17b4d8062df65c79686ep0,
    -0x1.921fb4p7
  },
  { // Entry 797
    0x1.90d9c2ee209f6d9d910babe7f62e7a71p0,
    0x1.921fb6p7
  },
  { // Entry 798
    -0x1.90d9c2ee209f6d9d910babe7f62e7a71p0,
    -0x1.921fb6p7
  },
  { // Entry 799
    0x1.90d9c2efbf9fbf6585fe7f879e30cb27p0,
    0x1.921fb8p7
  },
  { // Entry 800
    -0x1.90d9c2efbf9fbf6585fe7f879e30cb27p0,
    -0x1.921fb8p7
  },
  { // Entry 801
    0x1.2b5f4a1f186a4f4cce84633d4e88c6e3p0,
    0x1.2d97c4p1
  },
  { // Entry 802
    -0x1.2b5f4a1f186a4f4cce84633d4e88c6e3p0,
    -0x1.2d97c4p1
  },
  { // Entry 803
    0x1.2b5f4abb6450cfe394b11d0190b012a2p0,
    0x1.2d97c6p1
  },
  { // Entry 804
    -0x1.2b5f4abb6450cfe394b11d0190b012a2p0,
    -0x1.2d97c6p1
  },
  { // Entry 805
    0x1.2b5f4b57b0358ecd5c4ef2cf8eeca8b5p0,
    0x1.2d97c8p1
  },
  { // Entry 806
    -0x1.2b5f4b57b0358ecd5c4ef2cf8eeca8b5p0,
    -0x1.2d97c8p1
  },
  { // Entry 807
    0x1.524a69ac739be8aa44819da2c46ddeffp0,
    0x1.f6a7a0p1
  },
  { // Entry 808
    -0x1.524a69ac739be8aa44819da2c46ddeffp0,
    -0x1.f6a7a0p1
  },
  { // Entry 809
    0x1.524a69eacf4f30dd7930094c2c5422fap0,
    0x1.f6a7a2p1
  },
  { // Entry 810
    -0x1.524a69eacf4f30dd7930094c2c5422fap0,
    -0x1.f6a7a2p1
  },
  { // Entry 811
    0x1.524a6a292b0201c41df76f9856ea793ep0,
    0x1.f6a7a4p1
  },
  { // Entry 812
    -0x1.524a6a292b0201c41df76f9856ea793ep0,
    -0x1.f6a7a4p1
  },
  { // Entry 813
    0x1.5c97d2cf4d47c39e1d3362c5c6cb465ep0,
    0x1.2d97c4p2
  },
  { // Entry 814
    -0x1.5c97d2cf4d47c39e1d3362c5c6cb465ep0,
    -0x1.2d97c4p2
  },
  { // Entry 815
    0x1.5c97d3278d78828714e1db373c01c428p0,
    0x1.2d97c6p2
  },
  { // Entry 816
    -0x1.5c97d3278d78828714e1db373c01c428p0,
    -0x1.2d97c6p2
  },
  { // Entry 817
    0x1.5c97d37fcda822b612cc305acdb3719ap0,
    0x1.2d97c8p2
  },
  { // Entry 818
    -0x1.5c97d37fcda822b612cc305acdb3719ap0,
    -0x1.2d97c8p2
  },
  { // Entry 819
    0x1.64102f6fe89978879ec1eb938127f347p0,
    0x1.5fdbbcp2
  },
  { // Entry 820
    -0x1.64102f6fe89978879ec1eb938127f347p0,
    -0x1.5fdbbcp2
  },
  { // Entry 821
    0x1.64102fb17ee4bd784c0bc3c4b87b12dbp0,
    0x1.5fdbbep2
  },
  { // Entry 822
    -0x1.64102fb17ee4bd784c0bc3c4b87b12dbp0,
    -0x1.5fdbbep2
  },
  { // Entry 823
    0x1.64102ff3152f49a5b25bbbed0e298789p0,
    0x1.5fdbc0p2
  },
  { // Entry 824
    -0x1.64102ff3152f49a5b25bbbed0e298789p0,
    -0x1.5fdbc0p2
  },
  { // Entry 825
    0x1.6e256157f08af28f8fbcb2f100b427b2p0,
    0x1.c463a8p2
  },
  { // Entry 826
    -0x1.6e256157f08af28f8fbcb2f100b427b2p0,
    -0x1.c463a8p2
  },
  { // Entry 827
    0x1.6e2561801fc98949e471b87dd9e165adp0,
    0x1.c463aap2
  },
  { // Entry 828
    -0x1.6e2561801fc98949e471b87dd9e165adp0,
    -0x1.c463aap2
  },
  { // Entry 829
    0x1.6e2561a84f07c6d78f351f778ca48ee1p0,
    0x1.c463acp2
  },
  { // Entry 830
    -0x1.6e2561a84f07c6d78f351f778ca48ee1p0,
    -0x1.c463acp2
  },
  { // Entry 831
    0x1.71b40fe4d6264f6dcb5aa93d81eee334p0,
    0x1.f6a7a0p2
  },
  { // Entry 832
    -0x1.71b40fe4d6264f6dcb5aa93d81eee334p0,
    -0x1.f6a7a0p2
  },
  { // Entry 833
    0x1.71b4100581ff6df4d0e43adc1c6df394p0,
    0x1.f6a7a2p2
  },
  { // Entry 834
    -0x1.71b4100581ff6df4d0e43adc1c6df394p0,
    -0x1.f6a7a2p2
  },
  { // Entry 835
    0x1.71b410262dd84afcf6128b00223864d4p0,
    0x1.f6a7a4p2
  },
  { // Entry 836
    -0x1.71b410262dd84afcf6128b00223864d4p0,
    -0x1.f6a7a4p2
  },
  { // Entry 837
    0x1.749f95c28655e27185bdf7611bf6dabap0,
    0x1.1475cap3
  },
  { // Entry 838
    -0x1.749f95c28655e27185bdf7611bf6dabap0,
    -0x1.1475cap3
  },
  { // Entry 839
    0x1.749f95f8ad42bfc84cd821638d05272ep0,
    0x1.1475ccp3
  },
  { // Entry 840
    -0x1.749f95f8ad42bfc84cd821638d05272ep0,
    -0x1.1475ccp3
  },
  { // Entry 841
    0x1.749f962ed42ed732156103090043fe20p0,
    0x1.1475cep3
  },
  { // Entry 842
    -0x1.749f962ed42ed732156103090043fe20p0,
    -0x1.1475cep3
  },
  { // Entry 843
    0x1.77100a61d11bd3683ef7f13e0e2d3714p0,
    0x1.2d97c4p3
  },
  { // Entry 844
    -0x1.77100a61d11bd3683ef7f13e0e2d3714p0,
    -0x1.2d97c4p3
  },
  { // Entry 845
    0x1.77100a8f6a77d25e60c8ac6b368ced7cp0,
    0x1.2d97c6p3
  },
  { // Entry 846
    -0x1.77100a8f6a77d25e60c8ac6b368ced7cp0,
    -0x1.2d97c6p3
  },
  { // Entry 847
    0x1.77100abd03d3383b200c349a288d0858p0,
    0x1.2d97c8p3
  },
  { // Entry 848
    -0x1.77100abd03d3383b200c349a288d0858p0,
    -0x1.2d97c8p3
  },
  { // Entry 849
    0x1.79216b54e7690f5dc60c9f9ad18c2fe4p0,
    0x1.46b9c0p3
  },
  { // Entry 850
    -0x1.79216b54e7690f5dc60c9f9ad18c2fe4p0,
    -0x1.46b9c0p3
  },
  { // Entry 851
    0x1.79216b7bd2590ebc8160a2e2288b213cp0,
    0x1.46b9c2p3
  },
  { // Entry 852
    -0x1.79216b7bd2590ebc8160a2e2288b213cp0,
    -0x1.46b9c2p3
  },
  { // Entry 853
    0x1.79216ba2bd48954acc47fb24366389dcp0,
    0x1.46b9c4p3
  },
  { // Entry 854
    -0x1.79216ba2bd48954acc47fb24366389dcp0,
    -0x1.46b9c4p3
  },
  { // Entry 855
    0x1.7ae7d7b9fff1b8fc1a190cb09ec19212p0,
    0x1.5fdbbcp3
  },
  { // Entry 856
    -0x1.7ae7d7b9fff1b8fc1a190cb09ec19212p0,
    -0x1.5fdbbcp3
  },
  { // Entry 857
    0x1.7ae7d7db99b1b48f74a47550dd2775fbp0,
    0x1.5fdbbep3
  },
  { // Entry 858
    -0x1.7ae7d7db99b1b48f74a47550dd2775fbp0,
    -0x1.5fdbbep3
  },
  { // Entry 859
    0x1.7ae7d7fd33714f26d256bae7b8da269cp0,
    0x1.5fdbc0p3
  },
  { // Entry 860
    -0x1.7ae7d7fd33714f26d256bae7b8da269cp0,
    -0x1.5fdbc0p3
  },
  { // Entry 861
    0x1.7c72243c821084a80ce5911f6e3dea5dp0,
    0x1.78fdb6p3
  },
  { // Entry 862
    -0x1.7c72243c821084a80ce5911f6e3dea5dp0,
    -0x1.78fdb6p3
  },
  { // Entry 863
    0x1.7c722459cf137ac258c3b7237604e08ep0,
    0x1.78fdb8p3
  },
  { // Entry 864
    -0x1.7c722459cf137ac258c3b7237604e08ep0,
    -0x1.78fdb8p3
  },
  { // Entry 865
    0x1.7c7224771c1621d7d010891cc6cbd91ep0,
    0x1.78fdbap3
  },
  { // Entry 866
    -0x1.7c7224771c1621d7d010891cc6cbd91ep0,
    -0x1.78fdbap3
  },
  { // Entry 867
    0x1.7efc70fef0079d0f48b6d9402b26d905p0,
    0x1.ab41aep3
  },
  { // Entry 868
    -0x1.7efc70fef0079d0f48b6d9402b26d905p0,
    -0x1.ab41aep3
  },
  { // Entry 869
    0x1.7efc7115c92ed7b4199c4707127cb54bp0,
    0x1.ab41b0p3
  },
  { // Entry 870
    -0x1.7efc7115c92ed7b4199c4707127cb54bp0,
    -0x1.ab41b0p3
  },
  { // Entry 871
    0x1.7efc712ca255dbe487b8a2707e7c0319p0,
    0x1.ab41b2p3
  },
  { // Entry 872
    -0x1.7efc712ca255dbe487b8a2707e7c0319p0,
    -0x1.ab41b2p3
  },
  { // Entry 873
    0x1.800bb137f9715ad622aff2aea130dce0p0,
    0x1.c463a8p3
  },
  { // Entry 874
    -0x1.800bb137f9715ad622aff2aea130dce0p0,
    -0x1.c463a8p3
  },
  { // Entry 875
    0x1.800bb14c5de3a50924516807a2acf3fep0,
    0x1.c463aap3
  },
  { // Entry 876
    -0x1.800bb14c5de3a50924516807a2acf3fep0,
    -0x1.c463aap3
  },
  { // Entry 877
    0x1.800bb160c255c14e4e27ff1409d422e3p0,
    0x1.c463acp3
  },
  { // Entry 878
    -0x1.800bb160c255c14e4e27ff1409d422e3p0,
    -0x1.c463acp3
  },
  { // Entry 879
    0x1.80fe86936790bcf875c5fe2fb547d565p0,
    0x1.dd85a4p3
  },
  { // Entry 880
    -0x1.80fe86936790bcf875c5fe2fb547d565p0,
    -0x1.dd85a4p3
  },
  { // Entry 881
    0x1.80fe86a5b758117d0d5619d06ab27318p0,
    0x1.dd85a6p3
  },
  { // Entry 882
    -0x1.80fe86a5b758117d0d5619d06ab27318p0,
    -0x1.dd85a6p3
  },
  { // Entry 883
    0x1.80fe86b8071f3eea18b5b73ff7f2e4a9p0,
    0x1.dd85a8p3
  },
  { // Entry 884
    -0x1.80fe86b8071f3eea18b5b73ff7f2e4a9p0,
    -0x1.dd85a8p3
  },
  { // Entry 885
    0x1.81d92dd9caf1328bc6b375143237cb0fp0,
    0x1.f6a7a0p3
  },
  { // Entry 886
    -0x1.81d92dd9caf1328bc6b375143237cb0fp0,
    -0x1.f6a7a0p3
  },
  { // Entry 887
    0x1.81d92dea5381d18436c91dc15fbc646dp0,
    0x1.f6a7a2p3
  },
  { // Entry 888
    -0x1.81d92dea5381d18436c91dc15fbc646dp0,
    -0x1.f6a7a2p3
  },
  { // Entry 889
    0x1.81d92dfadc124ef0f2477e36e6f68f74p0,
    0x1.f6a7a4p3
  },
  { // Entry 890
    -0x1.81d92dfadc124ef0f2477e36e6f68f74p0,
    -0x1.f6a7a4p3
  },
  { // Entry 891
    0x1.829f168f2426e5aaade6af4c5fde890ap0,
    0x1.07e4ccp4
  },
  { // Entry 892
    -0x1.829f168f2426e5aaade6af4c5fde890ap0,
    -0x1.07e4ccp4
  },
  { // Entry 893
    0x1.829f16ad2528616b825b97261b82b069p0,
    0x1.07e4cep4
  },
  { // Entry 894
    -0x1.829f16ad2528616b825b97261b82b069p0,
    -0x1.07e4cep4
  },
  { // Entry 895
    0x1.829f16cb2629692c853c96842a0be987p0,
    0x1.07e4d0p4
  },
  { // Entry 896
    -0x1.829f16cb2629692c853c96842a0be987p0,
    -0x1.07e4d0p4
  },
  { // Entry 897
    0x1.835311a12459455ac82eb15660927ea8p0,
    0x1.1475cap4
  },
  { // Entry 898
    -0x1.835311a12459455ac82eb15660927ea8p0,
    -0x1.1475cap4
  },
  { // Entry 899
    0x1.835311bc7d3a944a470489a7e4d79c89p0,
    0x1.1475ccp4
  },
  { // Entry 900
    -0x1.835311bc7d3a944a470489a7e4d79c89p0,
    -0x1.1475ccp4
  },
  { // Entry 901
    0x1.835311d7d61b7e454afbda6fc3780f9bp0,
    0x1.1475cep4
  },
  { // Entry 902
    -0x1.835311d7d61b7e454afbda6fc3780f9bp0,
    -0x1.1475cep4
  },
  { // Entry 903
    0x1.83f772fb8c656bf286bfb98e1b6c2297p0,
    0x1.2106c8p4
  },
  { // Entry 904
    -0x1.83f772fb8c656bf286bfb98e1b6c2297p0,
    -0x1.2106c8p4
  },
  { // Entry 905
    0x1.83f77314938eb6f209e9d6f162ceb218p0,
    0x1.2106cap4
  },
  { // Entry 906
    -0x1.83f77314938eb6f209e9d6f162ceb218p0,
    -0x1.2106cap4
  },
  { // Entry 907
    0x1.83f7732d9ab7a98acc60db819db81050p0,
    0x1.2106ccp4
  },
  { // Entry 908
    -0x1.83f7732d9ab7a98acc60db819db81050p0,
    -0x1.2106ccp4
  },
  { // Entry 909
    0x1.848e2bbf112b7c2876657a2a86df9912p0,
    0x1.2d97c4p4
  },
  { // Entry 910
    -0x1.848e2bbf112b7c2876657a2a86df9912p0,
    -0x1.2d97c4p4
  },
  { // Entry 911
    0x1.848e2bd60efe2b9612b5fc806fd418d9p0,
    0x1.2d97c6p4
  },
  { // Entry 912
    -0x1.848e2bd60efe2b9612b5fc806fd418d9p0,
    -0x1.2d97c6p4
  },
  { // Entry 913
    0x1.848e2bed0cd08d2b9a9efc0954153c48p0,
    0x1.2d97c8p4
  },
  { // Entry 914
    -0x1.848e2bed0cd08d2b9a9efc0954153c48p0,
    -0x1.2d97c8p4
  },
  { // Entry 915
    0x1.8518de24fb5e23b2ff0cc417b338f410p0,
    0x1.3a28c2p4
  },
  { // Entry 916
    -0x1.8518de24fb5e23b2ff0cc417b338f410p0,
    -0x1.3a28c2p4
  },
  { // Entry 917
    0x1.8518de3a2cef8f1d8eb840c195f7aec6p0,
    0x1.3a28c4p4
  },
  { // Entry 918
    -0x1.8518de3a2cef8f1d8eb840c195f7aec6p0,
    -0x1.3a28c4p4
  },
  { // Entry 919
    0x1.8518de4f5e80b5a144ccb442286993f2p0,
    0x1.3a28c6p4
  },
  { // Entry 920
    -0x1.8518de4f5e80b5a144ccb442286993f2p0,
    -0x1.3a28c6p4
  },
  { // Entry 921
    0x1.8598ec14f4559fb7ce6f97f8b0ce9772p0,
    0x1.46b9c0p4
  },
  { // Entry 922
    -0x1.8598ec14f4559fb7ce6f97f8b0ce9772p0,
    -0x1.46b9c0p4
  },
  { // Entry 923
    0x1.8598ec288d8e61a24f31637379503fc5p0,
    0x1.46b9c2p4
  },
  { // Entry 924
    -0x1.8598ec288d8e61a24f31637379503fc5p0,
    -0x1.46b9c2p4
  },
  { // Entry 925
    0x1.8598ec3c26c6e645d117b0b4d0b90716p0,
    0x1.46b9c4p4
  },
  { // Entry 926
    -0x1.8598ec3c26c6e645d117b0b4d0b90716p0,
    -0x1.46b9c4p4
  },
  { // Entry 927
    0x1.860f835398d37040ddc2d7017bf92099p0,
    0x1.534abep4
  },
  { // Entry 928
    -0x1.860f835398d37040ddc2d7017bf92099p0,
    -0x1.534abep4
  },
  { // Entry 929
    0x1.860f8365c617d586a14b44930af2704ap0,
    0x1.534ac0p4
  },
  { // Entry 930
    -0x1.860f8365c617d586a14b44930af2704ap0,
    -0x1.534ac0p4
  },
  { // Entry 931
    0x1.860f8377f35c040fc41230db2834a379p0,
    0x1.534ac2p4
  },
  { // Entry 932
    -0x1.860f8377f35c040fc41230db2834a379p0,
    -0x1.534ac2p4
  },
  { // Entry 933
    0x1.867da6b26f9ac2fa4c1d70b7532cb6aep0,
    0x1.5fdbbcp4
  },
  { // Entry 934
    -0x1.867da6b26f9ac2fa4c1d70b7532cb6aep0,
    -0x1.5fdbbcp4
  },
  { // Entry 935
    0x1.867da6c3571aaf0e97b75fd8102e312ap0,
    0x1.5fdbbep4
  },
  { // Entry 936
    -0x1.867da6c3571aaf0e97b75fd8102e312ap0,
    -0x1.5fdbbep4
  },
  { // Entry 937
    0x1.867da6d43e9a6a0ab844221559e0ca4ep0,
    0x1.5fdbc0p4
  },
  { // Entry 938
    -0x1.867da6d43e9a6a0ab844221559e0ca4ep0,
    -0x1.5fdbc0p4
  },
  { // Entry 939
    0x1.86e4356f9805898eff739bee09b0eb2bp0,
    0x1.6c6cbap4
  },
  { // Entry 940
    -0x1.86e4356f9805898eff739bee09b0eb2bp0,
    -0x1.6c6cbap4
  },
  { // Entry 941
    0x1.86e4357f5ac86b81453a4b9f1ab42ac2p0,
    0x1.6c6cbcp4
  },
  { // Entry 942
    -0x1.86e4357f5ac86b81453a4b9f1ab42ac2p0,
    -0x1.6c6cbcp4
  },
  { // Entry 943
    0x1.86e4358f1d8b21400c5273ab23322cc4p0,
    0x1.6c6cbep4
  },
  { // Entry 944
    -0x1.86e4358f1d8b21400c5273ab23322cc4p0,
    -0x1.6c6cbep4
  },
  { // Entry 945
    0x1.8743f10efa639eaaf405e83f84a991bbp0,
    0x1.78fdb6p4
  },
  { // Entry 946
    -0x1.8743f10efa639eaaf405e83f84a991bbp0,
    -0x1.78fdb6p4
  },
  { // Entry 947
    0x1.8743f11db5201e00fba3693129ceaaadp0,
    0x1.78fdb8p4
  },
  { // Entry 948
    -0x1.8743f11db5201e00fba3693129ceaaadp0,
    -0x1.78fdb8p4
  },
  { // Entry 949
    0x1.8743f12c6fdc75672ff29ccd6d6423ccp0,
    0x1.78fdbap4
  },
  { // Entry 950
    -0x1.8743f12c6fdc75672ff29ccd6d6423ccp0,
    -0x1.78fdbap4
  },
  { // Entry 951
    0x1.879d825ab3fe49f711b2fa09df2c5726p0,
    0x1.858eb4p4
  },
  { // Entry 952
    -0x1.879d825ab3fe49f711b2fa09df2c5726p0,
    -0x1.858eb4p4
  },
  { // Entry 953
    0x1.879d82687fc876212b8475e64de596a4p0,
    0x1.858eb6p4
  },
  { // Entry 954
    -0x1.879d82687fc876212b8475e64de596a4p0,
    -0x1.858eb6p4
  },
  { // Entry 955
    0x1.879d82764b927e1728ed144f2db217ebp0,
    0x1.858eb8p4
  },
  { // Entry 956
    -0x1.879d82764b927e1728ed144f2db217ebp0,
    -0x1.858eb8p4
  },
  { // Entry 957
    0x1.921fb54442d18467898cc31701b639a2p0,
    0x1.fffffep62
  },
  { // Entry 958
    -0x1.921fb54442d18467898cc31701b639a2p0,
    -0x1.fffffep62
  },
  { // Entry 959
    0x1.921fb54442d18467898cc51701b839a2p0,
    0x1.p63
  },
  { // Entry 960
    -0x1.921fb54442d18467898cc51701b839a2p0,
    -0x1.p63
  },
  { // Entry 961
    0x1.921fb54442d18467898cc91701b039a2p0,
    0x1.000002p63
  },
  { // Entry 962
    -0x1.921fb54442d18467898cc91701b039a2p0,
    -0x1.000002p63
  },
  { // Entry 963
    0x1.921fb52442d16469896cefc18ce2e42dp0,
    0x1.fffffep26
  },
  { // Entry 964
    -0x1.921fb52442d16469896cefc18ce2e42dp0,
    -0x1.fffffep26
  },
  { // Entry 965
    0x1.921fb52442d18469898cefc1ac62e44cp0,
    0x1.p27
  },
  { // Entry 966
    -0x1.921fb52442d18469898cefc1ac62e44cp0,
    -0x1.p27
  },
  { // Entry 967
    0x1.921fb52442d1c469890cefc2ab62e250p0,
    0x1.000002p27
  },
  { // Entry 968
    -0x1.921fb52442d1c469890cefc2ab62e250p0,
    -0x1.000002p27
  },
  { // Entry 969
    0x1.921fb44442d0846988e21a6c570d8fc4p0,
    0x1.fffffep23
  },
  { // Entry 970
    -0x1.921fb44442d0846988e21a6c570d8fc4p0,
    -0x1.fffffep23
  },
  { // Entry 971
    0x1.921fb44442d1846989e21a6c570d8ec4p0,
    0x1.p24
  },
  { // Entry 972
    -0x1.921fb44442d1846989e21a6c570d8ec4p0,
    -0x1.p24
  },
  { // Entry 973
    0x1.921fb44442d3846985e21a72570d86c4p0,
    0x1.000002p24
  },
  { // Entry 974
    -0x1.921fb44442d3846985e21a72570d86c4p0,
    -0x1.000002p24
  },
  { // Entry 975
    0x1.5368c915ad9354b6c80847a9f514bb75p0,
    0x1.fffffep1
  },
  { // Entry 976
    -0x1.5368c915ad9354b6c80847a9f514bb75p0,
    -0x1.fffffep1
  },
  { // Entry 977
    0x1.5368c951e9cfc9a42e1add5983cfb3a8p0,
    0x1.p2
  },
  { // Entry 978
    -0x1.5368c951e9cfc9a42e1add5983cfb3a8p0,
    -0x1.p2
  },
  { // Entry 979
    0x1.5368c9ca62475f5801ace2839c235895p0,
    0x1.000002p2
  },
  { // Entry 980
    -0x1.5368c9ca62475f5801ace2839c235895p0,
    -0x1.000002p2
  },
  { // Entry 981
    0x1.1b6e18c8557d8e74e5d9704acf91aa45p0,
    0x1.fffffep0
  },
  { // Entry 982
    -0x1.1b6e18c8557d8e74e5d9704acf91aa45p0,
    -0x1.fffffep0
  },
  { // Entry 983
    0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    0x1.p1
  },
  { // Entry 984
    -0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    -0x1.p1
  },
  { // Entry 985
    0x1.1b6e19fb88afcbe58bcd268e23897be3p0,
    0x1.000002p1
  },
  { // Entry 986
    -0x1.1b6e19fb88afcbe58bcd268e23897be3p0,
    -0x1.000002p1
  },
  { // Entry 987
    0x1.921fb44442d1046989621a6c570d8f04p-1,
    0x1.fffffep-1
  },
  { // Entry 988
    -0x1.921fb44442d1046989621a6c570d8f04p-1,
    -0x1.fffffep-1
  },
  { // Entry 989
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p0
  },
  { // Entry 990
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p0
  },
  { // Entry 991
    0x1.921fb74442cf84698ae21a6c570d8d5ep-1,
    0x1.000002p0
  },
  { // Entry 992
    -0x1.921fb74442cf84698ae21a6c570d8d5ep-1,
    -0x1.000002p0
  },
  { // Entry 993
    0x1.dac66ebc821b0b05c115b007ee262f78p-2,
    0x1.fffffep-2
  },
  { // Entry 994
    -0x1.dac66ebc821b0b05c115b007ee262f78p-2,
    -0x1.fffffep-2
  },
  { // Entry 995
    0x1.dac670561bb4f68adfc88bd978751a06p-2,
    0x1.p-1
  },
  { // Entry 996
    -0x1.dac670561bb4f68adfc88bd978751a06p-2,
    -0x1.p-1
  },
  { // Entry 997
    0x1.dac673894ee6e20ffe552cf613035e41p-2,
    0x1.000002p-1
  },
  { // Entry 998
    -0x1.dac673894ee6e20ffe552cf613035e41p-2,
    -0x1.000002p-1
  },
  { // Entry 999
    0x1.f5b75db0e62bd7f064e3887809ade7efp-3,
    0x1.fffffep-3
  },
  { // Entry 1000
    -0x1.f5b75db0e62bd7f064e3887809ade7efp-3,
    -0x1.fffffep-3
  },
  { // Entry 1001
    0x1.f5b75f92c80dd62adb8f3debef442fcbp-3,
    0x1.p-2
  },
  { // Entry 1002
    -0x1.f5b75f92c80dd62adb8f3debef442fcbp-3,
    -0x1.p-2
  },
  { // Entry 1003
    0x1.f5b763568bd1288c4bd4fecdaee28fb5p-3,
    0x1.000002p-2
  },
  { // Entry 1004
    -0x1.f5b763568bd1288c4bd4fecdaee28fb5p-3,
    -0x1.000002p-2
  },
  { // Entry 1005
    0x1.fd5ba7b2a374dc8497123b64b398aae2p-4,
    0x1.fffffep-4
  },
  { // Entry 1006
    -0x1.fd5ba7b2a374dc8497123b64b398aae2p-4,
    -0x1.fffffep-4
  },
  { // Entry 1007
    0x1.fd5ba9aac2f6dc65912f313e7d111defp-4,
    0x1.p-3
  },
  { // Entry 1008
    -0x1.fd5ba9aac2f6dc65912f313e7d111defp-4,
    -0x1.p-3
  },
  { // Entry 1009
    0x1.fd5bad9b01faad9eb46ef9bda99d4fdap-4,
    0x1.000002p-3
  },
  { // Entry 1010
    -0x1.fd5bad9b01faad9eb46ef9bda99d4fdap-4,
    -0x1.000002p-3
  },
  { // Entry 1011
    0x1.ff55b974cde098738e59c07aa48dd110p-5,
    0x1.fffffep-5
  },
  { // Entry 1012
    -0x1.ff55b974cde098738e59c07aa48dd110p-5,
    -0x1.fffffep-5
  },
  { // Entry 1013
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.p-4
  },
  { // Entry 1014
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.p-4
  },
  { // Entry 1015
    0x1.ff55bf6ed3da98798265cc3f27c896c7p-5,
    0x1.000002p-4
  },
  { // Entry 1016
    -0x1.ff55bf6ed3da98798265cc3f27c896c7p-5,
    -0x1.000002p-4
  },
  { // Entry 1017
    0x1.ffd559bb174252032fa3014c0671336cp-6,
    0x1.fffffep-6
  },
  { // Entry 1018
    -0x1.ffd559bb174252032fa3014c0671336cp-6,
    -0x1.fffffep-6
  },
  { // Entry 1019
    0x1.ffd55bba97624a84ef3aeedbb518c427p-6,
    0x1.p-5
  },
  { // Entry 1020
    -0x1.ffd55bba97624a84ef3aeedbb518c427p-6,
    -0x1.p-5
  },
  { // Entry 1021
    0x1.ffd55fb997a23889edd9fb6b2758a63ep-6,
    0x1.000002p-5
  },
  { // Entry 1022
    -0x1.ffd55fb997a23889edd9fb6b2758a63ep-6,
    -0x1.000002p-5
  },
  { // Entry 1023
    0x1.fff553bbd727ab77d118772cd6b96490p-7,
    0x1.fffffep-7
  },
  { // Entry 1024
    -0x1.fff553bbd727ab77d118772cd6b96490p-7,
    -0x1.fffffep-7
  },
  { // Entry 1025
    0x1.fff555bbb729ab77cf18ac802beec090p-7,
    0x1.p-6
  },
  { // Entry 1026
    -0x1.fff555bbb729ab77cf18ac802beec090p-7,
    -0x1.p-6
  },
  { // Entry 1027
    0x1.fff559bb772daab7e316976eceda5473p-7,
    0x1.000002p-6
  },
  { // Entry 1028
    -0x1.fff559bb772daab7e316976eceda5473p-7,
    -0x1.000002p-6
  },
  { // Entry 1029
    0x1.fffffdf5555575bbbb99b72981620cfcp-15,
    0x1.fffffep-15
  },
  { // Entry 1030
    -0x1.fffffdf5555575bbbb99b72981620cfcp-15,
    -0x1.fffffep-15
  },
  { // Entry 1031
    0x1.fffffff5555555bbbbbbb72972976256p-15,
    0x1.p-14
  },
  { // Entry 1032
    -0x1.fffffff5555555bbbbbbb72972976256p-15,
    -0x1.p-14
  },
  { // Entry 1033
    0x1.000001faaaaa8adddd9fdb949681068fp-14,
    0x1.000002p-14
  },
  { // Entry 1034
    -0x1.000001faaaaa8adddd9fdb949681068fp-14,
    -0x1.000002p-14
  },
  { // Entry 1035
    0x1.fffffdfffffffd55555d55554d5bbbbep-28,
    0x1.fffffep-28
  },
  { // Entry 1036
    -0x1.fffffdfffffffd55555d55554d5bbbbep-28,
    -0x1.fffffep-28
  },
  { // Entry 1037
    0x1.fffffffffffffd5555555555555bbbbbp-28,
    0x1.p-27
  },
  { // Entry 1038
    -0x1.fffffffffffffd5555555555555bbbbbp-28,
    -0x1.p-27
  },
  { // Entry 1039
    0x1.000001fffffffeaaaaa2aaaa9aadddd3p-27,
    0x1.000002p-27
  },
  { // Entry 1040
    -0x1.000001fffffffeaaaaa2aaaa9aadddd3p-27,
    -0x1.000002p-27
  },
  { // Entry 1041
    0x1.fffffdfffffffff555557555553555bbp-31,
    0x1.fffffep-31
  },
  { // Entry 1042
    -0x1.fffffdfffffffff555557555553555bbp-31,
    -0x1.fffffep-31
  },
  { // Entry 1043
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.p-30
  },
  { // Entry 1044
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.p-30
  },
  { // Entry 1045
    0x1.000001fffffffffaaaaa8aaaaa6aaaddp-30,
    0x1.000002p-30
  },
  { // Entry 1046
    -0x1.000001fffffffffaaaaa8aaaaa6aaaddp-30,
    -0x1.000002p-30
  },
  { // Entry 1047
    -0x1.921fb54442d18469898cc51701b839a1p0,
    -0x1.fffffep127
  },
  { // Entry 1048
    0x1.921fb54442d18469898cc51701b839a1p0,
    0x1.fffffep127
  },
  { // Entry 1049
    0x1.921fb54442d18469898cc51701b839a1p0,
    0x1.fffffep127
  },
  { // Entry 1050
    -0x1.921fb54442d18469898cc51701b839a1p0,
    -0x1.fffffep127
  },
  { // Entry 1051
    0x1.921fb54442d18469898cc51701b839a2p0,
    HUGE_VALF
  },
  { // Entry 1052
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -HUGE_VALF
  },
  { // Entry 1053
    0x1.921fb54442d18469898cc51701b839a1p0,
    0x1.fffffep127
  },
  { // Entry 1054
    -0x1.921fb54442d18469898cc51701b839a1p0,
    -0x1.fffffep127
  },
  { // Entry 1055
    0x1.921fb54442d18469898cc51701b839a1p0,
    0x1.fffffcp127
  },
  { // Entry 1056
    -0x1.921fb54442d18469898cc51701b839a1p0,
    -0x1.fffffcp127
  },
  { // Entry 1057
    0x1.433b8a54b916d7eb27cee6293066e9f6p0,
    0x1.921fb6p1
  },
  { // Entry 1058
    -0x1.433b8a54b916d7eb27cee6293066e9f6p0,
    -0x1.921fb6p1
  },
  { // Entry 1059
    0x1.00fe98b4f50d8b3c36b9e2a180d97eeap0,
    0x1.921fb6p0
  },
  { // Entry 1060
    -0x1.00fe98b4f50d8b3c36b9e2a180d97eeap0,
    -0x1.921fb6p0
  },
  { // Entry 1061
    0x1.921fb74442cf84698ae21a6c570d8d5ep-1,
    0x1.000002p0
  },
  { // Entry 1062
    -0x1.921fb74442cf84698ae21a6c570d8d5ep-1,
    -0x1.000002p0
  },
  { // Entry 1063
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p0
  },
  { // Entry 1064
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p0
  },
  { // Entry 1065
    0x1.921fb44442d1046989621a6c570d8f04p-1,
    0x1.fffffep-1
  },
  { // Entry 1066
    -0x1.921fb44442d1046989621a6c570d8f04p-1,
    -0x1.fffffep-1
  },
  { // Entry 1067
    0x1.54e04c79ed9a93b01c6a9062dbd8e0ffp-1,
    0x1.921fb6p-1
  },
  { // Entry 1068
    -0x1.54e04c79ed9a93b01c6a9062dbd8e0ffp-1,
    -0x1.921fb6p-1
  },
  { // Entry 1069
    0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.000002p-126
  },
  { // Entry 1070
    -0x1.000001ffffffffffffffffffffffffffp-126,
    -0x1.000002p-126
  },
  { // Entry 1071
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-126
  },
  { // Entry 1072
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-126
  },
  { // Entry 1073
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127
  },
  { // Entry 1074
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1075
    0x1.fffff7ffffffffffffffffffffffffffp-127,
    0x1.fffff8p-127
  },
  { // Entry 1076
    -0x1.fffff7ffffffffffffffffffffffffffp-127,
    -0x1.fffff8p-127
  },
  { // Entry 1077
    0x1.ffffffffffffffffffffffffffffffffp-149,
    0x1.p-148
  },
  { // Entry 1078
    -0x1.ffffffffffffffffffffffffffffffffp-149,
    -0x1.p-148
  },
  { // Entry 1079
    0.0f,
    0x1.p-149
  },
  { // Entry 1080
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1081
    0.0,
    0.0f
  },
  { // Entry 1082
    -0.0,
    -0.0f
  }
};

"""


```