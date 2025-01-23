Response:
The user wants a summary of the functionality of the provided code snippet.
This is the third part of a five-part request, suggesting the previous parts contained related information.
The code appears to be a data table. Each entry in the table is a pair of floating-point numbers.
The file path `bionic/tests/math_data/sin_intel_data.handroid` strongly suggests this data is used for testing the `sin` function in Android's math library. The `intel_data` part might imply this data is specifically designed or collected from Intel architectures for accuracy verification.

Therefore, the primary function of this code is to provide test data for verifying the implementation of the sine function. The pairs of numbers likely represent input values and their corresponding expected sine values.
这个代码片段是 `bionic/tests/math_data/sin_intel_data.handroid` 文件的一部分，它主要的功能是 **提供一组用于测试正弦函数 (`sin`) 实现的测试数据**。

具体来说，这个代码片段包含一个数组，数组中的每个元素都是一个结构体，结构体包含两个 `double` 类型的浮点数。

*   **第一个浮点数**：很可能是正弦函数的 **输入值** (以十六进制浮点数表示)。
*   **第二个浮点数**：很可能是对应输入值的 **预期正弦值** (同样以十六进制浮点数表示)。

**归纳一下它的功能：**

这个代码片段的核心功能是 **为 Android Bionic 库中的正弦函数提供一组预先计算好的、用于验证其正确性的测试用例数据**。这些数据可能来源于 Intel 平台，用于确保在不同架构上的精度。

由于这是第3部分，结合文件路径和数据内容，可以推断出整个文件（以及可能的前后几部分）的目的是为了提供一个全面的测试数据集，覆盖正弦函数在不同输入范围和精度要求下的行为，从而确保 Android 系统中正弦函数实现的准确性和可靠性。

### 提示词
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
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
9eb93595d8194ab917fp-1,
    -0x1.6885b7d7e8a30p-1
  },
  { // Entry 712
    0x1.4b75ba096fa549eb93595d8194ab917fp-1,
    0x1.6885b7d7e8a30p-1
  },
  { // Entry 713
    -0x1.3aacff95a3122b15f372bfd2fdf9a75fp-1,
    -0x1.52e1f6ad9c280p-1
  },
  { // Entry 714
    0x1.3aacff95a3122b15f372bfd2fdf9a75fp-1,
    0x1.52e1f6ad9c280p-1
  },
  { // Entry 715
    -0x1.295463e769284a5aed17a443392f38f3p-1,
    -0x1.3d3e35834fad0p-1
  },
  { // Entry 716
    0x1.295463e769284a5aed17a443392f38f3p-1,
    0x1.3d3e35834fad0p-1
  },
  { // Entry 717
    -0x1.fc769b77e588495a6f642ca24e4ed3fcp-2,
    -0x1.0a0b02501c799p-1
  },
  { // Entry 718
    0x1.fc769b77e588495a6f642ca24e4ed3fcp-2,
    0x1.0a0b02501c799p-1
  },
  { // Entry 719
    -0x1.c853c78462de46b5743315612f8b5a7cp-2,
    -0x1.d8f7208e6b82cp-2
  },
  { // Entry 720
    0x1.c853c78462de46b5743315612f8b5a7cp-2,
    0x1.d8f7208e6b82cp-2
  },
  { // Entry 721
    -0x1.92aba90aaf27249de49c78fc643c8b72p-2,
    -0x1.9dd83c7c9e126p-2
  },
  { // Entry 722
    0x1.92aba90aaf27249de49c78fc643c8b72p-2,
    0x1.9dd83c7c9e126p-2
  },
  { // Entry 723
    -0x1.5bac064658f39460c83113c0a0097a0cp-2,
    -0x1.62b9586ad0a20p-2
  },
  { // Entry 724
    0x1.5bac064658f39460c83113c0a0097a0cp-2,
    0x1.62b9586ad0a20p-2
  },
  { // Entry 725
    -0x1.2383ca8078e58477cd5fb1d9de031dcep-2,
    -0x1.279a74590331ap-2
  },
  { // Entry 726
    0x1.2383ca8078e58477cd5fb1d9de031dcep-2,
    0x1.279a74590331ap-2
  },
  { // Entry 727
    -0x1.d4c5bc11d2371af2fe25ef5ede2766a3p-3,
    -0x1.d8f7208e6b829p-3
  },
  { // Entry 728
    0x1.d4c5bc11d2371af2fe25ef5ede2766a3p-3,
    0x1.d8f7208e6b829p-3
  },
  { // Entry 729
    -0x1.60f3faaf43023d3c7863ae06d4d59774p-3,
    -0x1.62b9586ad0a1ep-3
  },
  { // Entry 730
    0x1.60f3faaf43023d3c7863ae06d4d59774p-3,
    0x1.62b9586ad0a1ep-3
  },
  { // Entry 731
    -0x1.d7ea3de45a9d6563ac005c0c5bad8c50p-4,
    -0x1.d8f7208e6b826p-4
  },
  { // Entry 732
    0x1.d7ea3de45a9d6563ac005c0c5bad8c50p-4,
    0x1.d8f7208e6b826p-4
  },
  { // Entry 733
    -0x1.d8b3df489987a6fe0eead008e720aa22p-5,
    -0x1.d8f7208e6b82dp-5
  },
  { // Entry 734
    0x1.d8b3df489987a6fe0eead008e720aa22p-5,
    0x1.d8f7208e6b82dp-5
  },
  { // Entry 735
    0x1.d8b3df489987a6fe0eead008e720aa22p-5,
    0x1.d8f7208e6b82dp-5
  },
  { // Entry 736
    -0x1.d8b3df489987a6fe0eead008e720aa22p-5,
    -0x1.d8f7208e6b82dp-5
  },
  { // Entry 737
    0x1.d7ea3de45a9dd4a4bccd1a8c048faf4cp-4,
    0x1.d8f7208e6b82dp-4
  },
  { // Entry 738
    -0x1.d7ea3de45a9dd4a4bccd1a8c048faf4cp-4,
    -0x1.d8f7208e6b82dp-4
  },
  { // Entry 739
    0x1.60f3faaf43027c4752f564f9d0818fe8p-3,
    0x1.62b9586ad0a22p-3
  },
  { // Entry 740
    -0x1.60f3faaf43027c4752f564f9d0818fe8p-3,
    -0x1.62b9586ad0a22p-3
  },
  { // Entry 741
    0x1.d4c5bc11d23759400642e5a1efdc0f85p-3,
    0x1.d8f7208e6b82dp-3
  },
  { // Entry 742
    -0x1.d4c5bc11d23759400642e5a1efdc0f85p-3,
    -0x1.d8f7208e6b82dp-3
  },
  { // Entry 743
    0x1.2383ca8078e5a324d52c1530742cd4f5p-2,
    0x1.279a74590331cp-2
  },
  { // Entry 744
    -0x1.2383ca8078e5a324d52c1530742cd4f5p-2,
    -0x1.279a74590331cp-2
  },
  { // Entry 745
    0x1.5bac064658f3b27a28572bea256195efp-2,
    0x1.62b9586ad0a22p-2
  },
  { // Entry 746
    -0x1.5bac064658f3b27a28572bea256195efp-2,
    -0x1.62b9586ad0a22p-2
  },
  { // Entry 747
    0x1.92aba90aaf274209efaed08e34071e3bp-2,
    0x1.9dd83c7c9e128p-2
  },
  { // Entry 748
    -0x1.92aba90aaf274209efaed08e34071e3bp-2,
    -0x1.9dd83c7c9e128p-2
  },
  { // Entry 749
    0x1.c853c78462de635b10a2b93afd75da26p-2,
    0x1.d8f7208e6b82ep-2
  },
  { // Entry 750
    -0x1.c853c78462de635b10a2b93afd75da26p-2,
    -0x1.d8f7208e6b82ep-2
  },
  { // Entry 751
    0x1.fc769b77e588495a6f642ca24e4ed3fcp-2,
    0x1.0a0b02501c799p-1
  },
  { // Entry 752
    -0x1.fc769b77e588495a6f642ca24e4ed3fcp-2,
    -0x1.0a0b02501c799p-1
  },
  { // Entry 753
    0x1.295463e769281640ae026f50fc45e301p-1,
    0x1.3d3e35834faccp-1
  },
  { // Entry 754
    -0x1.295463e769281640ae026f50fc45e301p-1,
    -0x1.3d3e35834faccp-1
  },
  { // Entry 755
    0x1.3aacff95a311f899a0e279535e81c4ecp-1,
    0x1.52e1f6ad9c27cp-1
  },
  { // Entry 756
    -0x1.3aacff95a311f899a0e279535e81c4ecp-1,
    -0x1.52e1f6ad9c27cp-1
  },
  { // Entry 757
    0x1.4b75ba096fa5192442b7950f960f8006p-1,
    0x1.6885b7d7e8a2cp-1
  },
  { // Entry 758
    -0x1.4b75ba096fa5192442b7950f960f8006p-1,
    -0x1.6885b7d7e8a2cp-1
  },
  { // Entry 759
    0x1.5ba6e6a8e706245f97e28af3ddb700f6p-1,
    0x1.7e297902351dcp-1
  },
  { // Entry 760
    -0x1.5ba6e6a8e706245f97e28af3ddb700f6p-1,
    -0x1.7e297902351dcp-1
  },
  { // Entry 761
    0x1.6b391e25bc269ea1c1a40de62fbc03b4p-1,
    0x1.93cd3a2c8198cp-1
  },
  { // Entry 762
    -0x1.6b391e25bc269ea1c1a40de62fbc03b4p-1,
    -0x1.93cd3a2c8198cp-1
  },
  { // Entry 763
    0x1.7a2541dfd4e727b86dd309664186ec6bp-1,
    0x1.a970fb56ce13cp-1
  },
  { // Entry 764
    -0x1.7a2541dfd4e727b86dd309664186ec6bp-1,
    -0x1.a970fb56ce13cp-1
  },
  { // Entry 765
    0x1.88647f26a6e0cd95cb991f7ffe61a02ep-1,
    0x1.bf14bc811a8ecp-1
  },
  { // Entry 766
    -0x1.88647f26a6e0cd95cb991f7ffe61a02ep-1,
    -0x1.bf14bc811a8ecp-1
  },
  { // Entry 767
    0x1.95f05257dbcb384a5e326857376dd801p-1,
    0x1.d4b87dab6709cp-1
  },
  { // Entry 768
    -0x1.95f05257dbcb384a5e326857376dd801p-1,
    -0x1.d4b87dab6709cp-1
  },
  { // Entry 769
    0x1.a2c289d9d0558764921a4de355f9448cp-1,
    0x1.ea5c3ed5b384cp-1
  },
  { // Entry 770
    -0x1.a2c289d9d0558764921a4de355f9448cp-1,
    -0x1.ea5c3ed5b384cp-1
  },
  { // Entry 771
    0x1.c1e9883373d7ecc48c92dc8875505f7ep-1,
    0x1.12bd9173c07abp0
  },
  { // Entry 772
    -0x1.c1e9883373d7ecc48c92dc8875505f7ep-1,
    -0x1.12bd9173c07abp0
  },
  { // Entry 773
    0x1.d294d1f96c7ef26e203c5b309a55671fp-1,
    0x1.257b22e780f56p0
  },
  { // Entry 774
    -0x1.d294d1f96c7ef26e203c5b309a55671fp-1,
    -0x1.257b22e780f56p0
  },
  { // Entry 775
    0x1.e0c04a94e17335d073052a0394b9e1c3p-1,
    0x1.3838b45b41701p0
  },
  { // Entry 776
    -0x1.e0c04a94e17335d073052a0394b9e1c3p-1,
    -0x1.3838b45b41701p0
  },
  { // Entry 777
    0x1.ec5883b7b6cf70a577dd9160d0f8e9d5p-1,
    0x1.4af645cf01eacp0
  },
  { // Entry 778
    -0x1.ec5883b7b6cf70a577dd9160d0f8e9d5p-1,
    -0x1.4af645cf01eacp0
  },
  { // Entry 779
    0x1.f54d971881ad82629bd84d214194e8ddp-1,
    0x1.5db3d742c2657p0
  },
  { // Entry 780
    -0x1.f54d971881ad82629bd84d214194e8ddp-1,
    -0x1.5db3d742c2657p0
  },
  { // Entry 781
    0x1.fb933c40107fe83fd16c1789e27f69f7p-1,
    0x1.707168b682e02p0
  },
  { // Entry 782
    -0x1.fb933c40107fe83fd16c1789e27f69f7p-1,
    -0x1.707168b682e02p0
  },
  { // Entry 783
    0x1.ff20d961624e77daef329b4029c362dep-1,
    0x1.832efa2a435adp0
  },
  { // Entry 784
    -0x1.ff20d961624e77daef329b4029c362dep-1,
    -0x1.832efa2a435adp0
  },
  { // Entry 785
    0x1.fff18f24f3e4b69592294f206d7b32c2p-1,
    0x1.95ec8b9e03d58p0
  },
  { // Entry 786
    -0x1.fff18f24f3e4b69592294f206d7b32c2p-1,
    -0x1.95ec8b9e03d58p0
  },
  { // Entry 787
    0x1.fe043f57369d6a52fa33f0119ec4da19p-1,
    0x1.a8aa1d11c44ffp0
  },
  { // Entry 788
    -0x1.fe043f57369d6a52fa33f0119ec4da19p-1,
    -0x1.a8aa1d11c44ffp0
  },
  { // Entry 789
    0x1.b3d3695acc4136b2d44714f9b38419b4p-1,
    0x1.04aff6d330942p0
  },
  { // Entry 790
    -0x1.b3d3695acc4136b2d44714f9b38419b4p-1,
    -0x1.04aff6d330942p0
  },
  { // Entry 791
    0x1.b3d41972dc8063994f63413d5e4d8e4bp-1,
    0x1.04b09e98dcdb4p0
  },
  { // Entry 792
    -0x1.b3d41972dc8063994f63413d5e4d8e4bp-1,
    -0x1.04b09e98dcdb4p0
  },
  { // Entry 793
    0x1.b3d4c98a318fb66f821d7286ae7dce7bp-1,
    0x1.04b1465e89226p0
  },
  { // Entry 794
    -0x1.b3d4c98a318fb66f821d7286ae7dce7bp-1,
    -0x1.04b1465e89226p0
  },
  { // Entry 795
    0x1.b3d579a0cb6ee393ff75b58ffe16d13fp-1,
    0x1.04b1ee2435698p0
  },
  { // Entry 796
    -0x1.b3d579a0cb6ee393ff75b58ffe16d13fp-1,
    -0x1.04b1ee2435698p0
  },
  { // Entry 797
    0x1.b3d629b6aa1d9f65aad1a2fc932c8bcbp-1,
    0x1.04b295e9e1b0ap0
  },
  { // Entry 798
    -0x1.b3d629b6aa1d9f65aad1a2fc932c8bcbp-1,
    -0x1.04b295e9e1b0ap0
  },
  { // Entry 799
    0x1.b3d6d9cbcd9b9e43b7fc7fd428a44dd8p-1,
    0x1.04b33daf8df7cp0
  },
  { // Entry 800
    -0x1.b3d6d9cbcd9b9e43b7fc7fd428a44dd8p-1,
    -0x1.04b33daf8df7cp0
  },
  { // Entry 801
    0x1.b3d789e035e8948dab275dfe546c5b08p-1,
    0x1.04b3e5753a3eep0
  },
  { // Entry 802
    -0x1.b3d789e035e8948dab275dfe546c5b08p-1,
    -0x1.04b3e5753a3eep0
  },
  { // Entry 803
    0x1.b3d839f3e30436a358e93cbdcb2bb367p-1,
    0x1.04b48d3ae6860p0
  },
  { // Entry 804
    -0x1.b3d839f3e30436a358e93cbdcb2bb367p-1,
    -0x1.04b48d3ae6860p0
  },
  { // Entry 805
    0x1.b3d8ea06d4ee0684f5741ec777ed88e0p-1,
    0x1.04b5350092ccfp0
  },
  { // Entry 806
    -0x1.b3d8ea06d4ee0684f5741ec777ed88e0p-1,
    -0x1.04b5350092ccfp0
  },
  { // Entry 807
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 808
    0.0,
    0x1.0p-1074
  },
  { // Entry 809
    -0.0,
    -0.0
  },
  { // Entry 810
    0.0,
    0x1.0p-1074
  },
  { // Entry 811
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 812
    0x1.1773d561fd5065d0e9607a728a39eed2p-1,
    0x1.279a74590331bp-1
  },
  { // Entry 813
    -0x1.1773d561fd5065d0e9607a728a39eed2p-1,
    -0x1.279a74590331bp-1
  },
  { // Entry 814
    0x1.1773d561fd507338ff9c088d80c680dbp-1,
    0x1.279a74590331cp-1
  },
  { // Entry 815
    -0x1.1773d561fd507338ff9c088d80c680dbp-1,
    -0x1.279a74590331cp-1
  },
  { // Entry 816
    0x1.1773d561fd5080a115d796a8770d35efp-1,
    0x1.279a74590331dp-1
  },
  { // Entry 817
    -0x1.1773d561fd5080a115d796a8770d35efp-1,
    -0x1.279a74590331dp-1
  },
  { // Entry 818
    0x1.f95b8e7107418c11c94d4a54a9da9b7ap-1,
    0x1.bb67ae8584ca9p0
  },
  { // Entry 819
    -0x1.f95b8e7107418c11c94d4a54a9da9b7ap-1,
    -0x1.bb67ae8584ca9p0
  },
  { // Entry 820
    0x1.f95b8e71074186ee81d5ff89d8fae545p-1,
    0x1.bb67ae8584caap0
  },
  { // Entry 821
    -0x1.f95b8e71074186ee81d5ff89d8fae545p-1,
    -0x1.bb67ae8584caap0
  },
  { // Entry 822
    0x1.f95b8e71074181cb3a5eb4bf0621d381p-1,
    0x1.bb67ae8584cabp0
  },
  { // Entry 823
    -0x1.f95b8e71074181cb3a5eb4bf0621d381p-1,
    -0x1.bb67ae8584cabp0
  },
  { // Entry 824
    0x1.b1d8305321615ac938cff02be9f25085p-2,
    0x1.bffffffffffffp-2
  },
  { // Entry 825
    -0x1.b1d8305321615ac938cff02be9f25085p-2,
    -0x1.bffffffffffffp-2
  },
  { // Entry 826
    0x1.b1d83053216169476f4d1982b9b14ab1p-2,
    0x1.cp-2
  },
  { // Entry 827
    -0x1.b1d83053216169476f4d1982b9b14ab1p-2,
    -0x1.cp-2
  },
  { // Entry 828
    0x1.b1d83053216177c5a5ca42d98955275ap-2,
    0x1.c000000000001p-2
  },
  { // Entry 829
    -0x1.b1d83053216177c5a5ca42d98955275ap-2,
    -0x1.c000000000001p-2
  },
  { // Entry 830
    0x1.44eb381cf3869ea71ccb36863e4ea65bp-1,
    0x1.5ffffffffffffp-1
  },
  { // Entry 831
    -0x1.44eb381cf3869ea71ccb36863e4ea65bp-1,
    -0x1.5ffffffffffffp-1
  },
  { // Entry 832
    0x1.44eb381cf386ab04a4f8656abea80b83p-1,
    0x1.6p-1
  },
  { // Entry 833
    -0x1.44eb381cf386ab04a4f8656abea80b83p-1,
    -0x1.6p-1
  },
  { // Entry 834
    0x1.44eb381cf386b7622d25944f3eb035dcp-1,
    0x1.6000000000001p-1
  },
  { // Entry 835
    -0x1.44eb381cf386b7622d25944f3eb035dcp-1,
    -0x1.6000000000001p-1
  },
  { // Entry 836
    0x1.dad902fa8ac864fd8afa0bdc609ded19p-1,
    0x1.2ffffffffffffp0
  },
  { // Entry 837
    -0x1.dad902fa8ac864fd8afa0bdc609ded19p-1,
    -0x1.2ffffffffffffp0
  },
  { // Entry 838
    0x1.dad902fa8ac870f52f1b843ac83bc3edp-1,
    0x1.3p0
  },
  { // Entry 839
    -0x1.dad902fa8ac870f52f1b843ac83bc3edp-1,
    -0x1.3p0
  },
  { // Entry 840
    0x1.dad902fa8ac87cecd33cfc992dfec1bep-1,
    0x1.3000000000001p0
  },
  { // Entry 841
    -0x1.dad902fa8ac87cecd33cfc992dfec1bep-1,
    -0x1.3000000000001p0
  },
  { // Entry 842
    0x1.4b707a7acdecf90a188d0230fad3ad58p-1,
    0x1.37fffffffffffp1
  },
  { // Entry 843
    -0x1.4b707a7acdecf90a188d0230fad3ad58p-1,
    -0x1.37fffffffffffp1
  },
  { // Entry 844
    0x1.4b707a7acdecc84239463e78b312fa10p-1,
    0x1.380p1
  },
  { // Entry 845
    -0x1.4b707a7acdecc84239463e78b312fa10p-1,
    -0x1.380p1
  },
  { // Entry 846
    0x1.4b707a7acdec977a59ff7ac0662484ddp-1,
    0x1.3800000000001p1
  },
  { // Entry 847
    -0x1.4b707a7acdec977a59ff7ac0662484ddp-1,
    -0x1.3800000000001p1
  },
  { // Entry 848
    0x1.066e7eb76f5c6678fd8325a81f1925c6p-4,
    0x1.069c8b46b3792p-4
  },
  { // Entry 849
    -0x1.066e7eb76f5c6678fd8325a81f1925c6p-4,
    -0x1.069c8b46b3792p-4
  },
  { // Entry 850
    0x1.05e4761ab8d8f0a7dba834000f236650p-3,
    0x1.069c8b46b3792p-3
  },
  { // Entry 851
    -0x1.05e4761ab8d8f0a7dba834000f236650p-3,
    -0x1.069c8b46b3792p-3
  },
  { // Entry 852
    0x1.877e2cd4f6fd9ba498e327053032734fp-3,
    0x1.89ead0ea0d35bp-3
  },
  { // Entry 853
    -0x1.877e2cd4f6fd9ba498e327053032734fp-3,
    -0x1.89ead0ea0d35bp-3
  },
  { // Entry 854
    0x1.03be06f97cbee47698539f977cadbe7ep-2,
    0x1.069c8b46b3792p-2
  },
  { // Entry 855
    -0x1.03be06f97cbee47698539f977cadbe7ep-2,
    -0x1.069c8b46b3792p-2
  },
  { // Entry 856
    0x1.42abba8c72fbb8ca96f79aa4bb03584ep-2,
    0x1.4843ae1860576p-2
  },
  { // Entry 857
    -0x1.42abba8c72fbb8ca96f79aa4bb03584ep-2,
    -0x1.4843ae1860576p-2
  },
  { // Entry 858
    0x1.8045fe64e62dc3d686d976d7d5a7c689p-2,
    0x1.89ead0ea0d35ap-2
  },
  { // Entry 859
    -0x1.8045fe64e62dc3d686d976d7d5a7c689p-2,
    -0x1.89ead0ea0d35ap-2
  },
  { // Entry 860
    0x1.bc4c04d71abbeea5ab064ecfbf54c613p-2,
    0x1.cb91f3bbba13ep-2
  },
  { // Entry 861
    -0x1.bc4c04d71abbeea5ab064ecfbf54c613p-2,
    -0x1.cb91f3bbba13ep-2
  },
  { // Entry 862
    0x1.f67ea975b86a01510e6bde3778138934p-2,
    0x1.069c8b46b3791p-1
  },
  { // Entry 863
    -0x1.f67ea975b86a01510e6bde3778138934p-2,
    -0x1.069c8b46b3791p-1
  },
  { // Entry 864
    0x1.175059bf0d42524ecb0bf4243b55973dp-1,
    0x1.27701caf89e83p-1
  },
  { // Entry 865
    -0x1.175059bf0d42524ecb0bf4243b55973dp-1,
    -0x1.27701caf89e83p-1
  },
  { // Entry 866
    0x1.323b8b1fb4ba21dd12cce820e156a4fcp-1,
    0x1.4843ae1860575p-1
  },
  { // Entry 867
    -0x1.323b8b1fb4ba21dd12cce820e156a4fcp-1,
    -0x1.4843ae1860575p-1
  },
  { // Entry 868
    0x1.4be4979c5efb306c1a77024032849b52p-1,
    0x1.69173f8136c67p-1
  },
  { // Entry 869
    -0x1.4be4979c5efb306c1a77024032849b52p-1,
    -0x1.69173f8136c67p-1
  },
  { // Entry 870
    0x1.643080d67acc1332c64a85612cacafb9p-1,
    0x1.89ead0ea0d359p-1
  },
  { // Entry 871
    -0x1.643080d67acc1332c64a85612cacafb9p-1,
    -0x1.89ead0ea0d359p-1
  },
  { // Entry 872
    0x1.7b05b7b6c612e5b08d5efe49a46e21a1p-1,
    0x1.aabe6252e3a4bp-1
  },
  { // Entry 873
    -0x1.7b05b7b6c612e5b08d5efe49a46e21a1p-1,
    -0x1.aabe6252e3a4bp-1
  },
  { // Entry 874
    0x1.904c37505de48fa8e76287960fd44594p-1,
    0x1.cb91f3bbba13dp-1
  },
  { // Entry 875
    -0x1.904c37505de48fa8e76287960fd44594p-1,
    -0x1.cb91f3bbba13dp-1
  },
  { // Entry 876
    0x1.a3ed9e252938a14c79c575639c15a91dp-1,
    0x1.ec6585249082fp-1
  },
  { // Entry 877
    -0x1.a3ed9e252938a14c79c575639c15a91dp-1,
    -0x1.ec6585249082fp-1
  },
  { // Entry 878
    0x1.b5d545b109bf935594036798cf40c9b0p-1,
    0x1.069c8b46b3791p0
  },
  { // Entry 879
    -0x1.b5d545b109bf935594036798cf40c9b0p-1,
    -0x1.069c8b46b3791p0
  },
  { // Entry 880
    0x1.c5f058230e7fd14d3e5e315349f699efp-1,
    0x1.170653fb1eb0ap0
  },
  { // Entry 881
    -0x1.c5f058230e7fd14d3e5e315349f699efp-1,
    -0x1.170653fb1eb0ap0
  },
  { // Entry 882
    0x1.d42de42dce1346a03d1f6abf0eba9022p-1,
    0x1.27701caf89e83p0
  },
  { // Entry 883
    -0x1.d42de42dce1346a03d1f6abf0eba9022p-1,
    -0x1.27701caf89e83p0
  },
  { // Entry 884
    0x1.e07eeeda109cb504afcca860d4b5dd32p-1,
    0x1.37d9e563f51fcp0
  },
  { // Entry 885
    -0x1.e07eeeda109cb504afcca860d4b5dd32p-1,
    -0x1.37d9e563f51fcp0
  },
  { // Entry 886
    0x1.ead6834909b93371faf3beaddbd60eddp-1,
    0x1.4843ae1860575p0
  },
  { // Entry 887
    -0x1.ead6834909b93371faf3beaddbd60eddp-1,
    -0x1.4843ae1860575p0
  },
  { // Entry 888
    0x1.f329c0558e967e4cab58d0fa572d62d2p-1,
    0x1.58ad76cccb8eep0
  },
  { // Entry 889
    -0x1.f329c0558e967e4cab58d0fa572d62d2p-1,
    -0x1.58ad76cccb8eep0
  },
  { // Entry 890
    0x1.f96fe405f1ac5dc9cf343508067bfcaep-1,
    0x1.69173f8136c67p0
  },
  { // Entry 891
    -0x1.f96fe405f1ac5dc9cf343508067bfcaep-1,
    -0x1.69173f8136c67p0
  },
  { // Entry 892
    0x1.fda254c27a01f4786c149d6a7779cc3ap-1,
    0x1.79810835a1fe0p0
  },
  { // Entry 893
    -0x1.fda254c27a01f4786c149d6a7779cc3ap-1,
    -0x1.79810835a1fe0p0
  },
  { // Entry 894
    0x1.ffbca846c4fc997f1a381420208884e0p-1,
    0x1.89ead0ea0d359p0
  },
  { // Entry 895
    -0x1.ffbca846c4fc997f1a381420208884e0p-1,
    -0x1.89ead0ea0d359p0
  },
  { // Entry 896
    0x1.ffbca846c4fc9f30bfb458ef2091c8eep-1,
    0x1.9a54999e786d2p0
  },
  { // Entry 897
    -0x1.ffbca846c4fc9f30bfb458ef2091c8eep-1,
    -0x1.9a54999e786d2p0
  },
  { // Entry 898
    0x1.fda254c27a0205875f271435f827160cp-1,
    0x1.aabe6252e3a4bp0
  },
  { // Entry 899
    -0x1.fda254c27a0205875f271435f827160cp-1,
    -0x1.aabe6252e3a4bp0
  },
  { // Entry 900
    0x1.f96fe405f1ac7a241e02e58b0cbf3ae7p-1,
    0x1.bb282b074edc4p0
  },
  { // Entry 901
    -0x1.f96fe405f1ac7a241e02e58b0cbf3ae7p-1,
    -0x1.bb282b074edc4p0
  },
  { // Entry 902
    0x1.f329c0558e96a5d48272ad4c49ec53b8p-1,
    0x1.cb91f3bbba13dp0
  },
  { // Entry 903
    -0x1.f329c0558e96a5d48272ad4c49ec53b8p-1,
    -0x1.cb91f3bbba13dp0
  },
  { // Entry 904
    0x1.ead6834909b965fdc4b0ceffc0f285c6p-1,
    0x1.dbfbbc70254b6p0
  },
  { // Entry 905
    -0x1.ead6834909b965fdc4b0ceffc0f285c6p-1,
    -0x1.dbfbbc70254b6p0
  },
  { // Entry 906
    0x1.e07eeeda109cf25f400cd5f46acec887p-1,
    0x1.ec6585249082fp0
  },
  { // Entry 907
    -0x1.e07eeeda109cf25f400cd5f46acec887p-1,
    -0x1.ec6585249082fp0
  },
  { // Entry 908
    0x1.d42de42dce138e890939e56c439ded90p-1,
    0x1.fccf4dd8fbba8p0
  },
  { // Entry 909
    -0x1.d42de42dce138e890939e56c439ded90p-1,
    -0x1.fccf4dd8fbba8p0
  },
  { // Entry 910
    0x1.c5f058230e8014ab83ece0c3a638c079p-1,
    0x1.069c8b46b3791p1
  },
  { // Entry 911
    -0x1.c5f058230e8014ab83ece0c3a638c079p-1,
    -0x1.069c8b46b3791p1
  },
  { // Entry 912
    0x1.b5d545b109bfce3fc4d77001afe2f2b6p-1,
    0x1.0ed16fa0e914ep1
  },
  { // Entry 913
    -0x1.b5d545b109bfce3fc4d77001afe2f2b6p-1,
    -0x1.0ed16fa0e914ep1
  },
  { // Entry 914
    0x1.a3ed9e252938d92a5553b3c09d2bddd3p-1,
    0x1.170653fb1eb0bp1
  },
  { // Entry 915
    -0x1.a3ed9e252938d92a5553b3c09d2bddd3p-1,
    -0x1.170653fb1eb0bp1
  },
  { // Entry 916
    0x1.904c37505de4b8975dd2730e196ddfc3p-1,
    0x1.1f3b3855544c8p1
  },
  { // Entry 917
    -0x1.904c37505de4b8975dd2730e196ddfc3p-1,
    -0x1.1f3b3855544c8p1
  },
  { // Entry 918
    0x1.7b05b7b6c612fc4fda3812b1f1348389p-1,
    0x1.27701caf89e85p1
  },
  { // Entry 919
    -0x1.7b05b7b6c612fc4fda3812b1f1348389p-1,
    -0x1.27701caf89e85p1
  },
  { // Entry 920
    0x1.643080d67acc14620672dda6241ea305p-1,
    0x1.2fa50109bf842p1
  },
  { // Entry 921
    -0x1.643080d67acc14620672dda6241ea305p-1,
    -0x1.2fa50109bf842p1
  },
  { // Entry 922
    0x1.4be4979c5efb194fc82ac367fedf93bcp-1,
    0x1.37d9e563f51ffp1
  },
  { // Entry 923
    -0x1.4be4979c5efb194fc82ac367fedf93bcp-1,
    -0x1.37d9e563f51ffp1
  },
  { // Entry 924
    0x1.323b8b1fb4b9efe5075ede8049a85c3dp-1,
    0x1.400ec9be2abbcp1
  },
  { // Entry 925
    -0x1.323b8b1fb4b9efe5075ede8049a85c3dp-1,
    -0x1.400ec9be2abbcp1
  },
  { // Entry 926
    0x1.175059bf0d42033bbcf598c88b176e61p-1,
    0x1.4843ae1860579p1
  },
  { // Entry 927
    -0x1.175059bf0d42033bbcf598c88b176e61p-1,
    -0x1.4843ae1860579p1
  },
  { // Entry 928
    0x1.f67ea975b8692521f77d6754b302c5c4p-2,
    0x1.5078927295f36p1
  },
  { // Entry 929
    -0x1.f67ea975b8692521f77d6754b302c5c4p-2,
    -0x1.5078927295f36p1
  },
  { // Entry 930
    0x1.bc4c04d71abad14efc29a66342ada723p-2,
    0x1.58ad76cccb8f3p1
  },
  { // Entry 931
    -0x1.bc4c04d71abad14efc29a66342ada723p-2,
    -0x1.58ad76cccb8f3p1
  },
  { // Entry 932
    0x1.8045fe64e62c62f57f077ea251e2f2dcp-2,
    0x1.60e25b27012b0p1
  },
  { // Entry 933
    -0x1.8045fe64e62c62f57f077ea251e2f2dcp-2,
    -0x1.60e25b27012b0p1
  },
  { // Entry 934
    0x1.42abba8c72fa12be920b316627512e41p-2,
    0x1.69173f8136c6dp1
  },
  { // Entry 935
    -0x1.42abba8c72fa12be920b316627512e41p-2,
    -0x1.69173f8136c6dp1
  },
  { // Entry 936
    0x1.03be06f97cbcf866021e5a5c62c6b07ep-2,
    0x1.714c23db6c62ap1
  },
  { // Entry 937
    -0x1.03be06f97cbcf866021e5a5c62c6b07ep-2,
    -0x1.714c23db6c62ap1
  },
  { // Entry 938
    0x1.877e2cd4f6f94710f2776775b01c73dbp-3,
    0x1.79810835a1fe7p1
  },
  { // Entry 939
    -0x1.877e2cd4f6f94710f2776775b01c73dbp-3,
    -0x1.79810835a1fe7p1
  },
  { // Entry 940
    0x1.05e4761ab8d421719567717f76712867p-3,
    0x1.81b5ec8fd79a4p1
  },
  { // Entry 941
    -0x1.05e4761ab8d421719567717f76712867p-3,
    -0x1.81b5ec8fd79a4p1
  },
  { // Entry 942
    0x1.066e7eb76f5dd2ea19b6991e8a1a3634p-4,
    0x1.89ead0ea0d35bp1
  },
  { // Entry 943
    -0x1.066e7eb76f5dd2ea19b6991e8a1a3634p-4,
    -0x1.89ead0ea0d35bp1
  },
  { // Entry 944
    0x1.03be06f97cbf09cc0badbdae803d7b4ep-2,
    -0x1.81b5ec8fd799fp2
  },
  { // Entry 945
    -0x1.03be06f97cbf09cc0badbdae803d7b4ep-2,
    0x1.81b5ec8fd799fp2
  },
  { // Entry 946
    0x1.f67ea975b86a22f2348778824f95d84ap-2,
    -0x1.714c23db6c626p2
  },
  { // Entry 947
    -0x1.f67ea975b86a22f2348778824f95d84ap-2,
    0x1.714c23db6c626p2
  },
  { // Entry 948
    0x1.643080d67acc210fa27e9247a8286220p-1,
    -0x1.60e25b27012adp2
  },
  { // Entry 949
    -0x1.643080d67acc210fa27e9247a8286220p-1,
    0x1.60e25b27012adp2
  },
  { // Entry 950
    0x1.b5d545b109bf950b419702972b94f8fap-1,
    -0x1.5078927295f34p2
  },
  { // Entry 951
    -0x1.b5d545b109bf950b419702972b94f8fap-1,
    0x1.5078927295f34p2
  },
  { // Entry 952
    0x1.ead6834909b9346234dbb601d0486cf2p-1,
    -0x1.400ec9be2abbbp2
  },
  { // Entry 953
    -0x1.ead6834909b9346234dbb601d0486cf2p-1,
    0x1.400ec9be2abbbp2
  },
  { // Entry 954
    0x1.ffbca846c4fc999a29dc1d6b2d7cb413p-1,
    -0x1.2fa50109bf842p2
  },
  { // Entry 955
    -0x1.ffbca846c4fc999a29dc1d6b2d7cb413p-1,
    0x1.2fa50109bf842p2
  },
  { // Entry 956
    0x1.f329c0558e96a518a2af3ae7800a5b65p-1,
    -0x1.1f3b3855544c9p2
  },
  { // Entry 957
    -0x1.f329c0558e96a518a2af3ae7800a5b65p-1,
    0x1.1f3b3855544c9p2
  },
  { // Entry 958
    0x1.c5f058230e8021f21bd0ac2c0f6809a9p-1,
    -0x1.0ed16fa0e9150p2
  },
  { // Entry 959
    -0x1.c5f058230e8021f21bd0ac2c0f6809a9p-1,
    0x1.0ed16fa0e9150p2
  },
  { // Entry 960
    0x1.7b05b7b6c61365a9ac9e908b8e5d3ce4p-1,
    -0x1.fccf4dd8fbbaep1
  },
  { // Entry 961
    -0x1.7b05b7b6c61365a9ac9e908b8e5d3ce4p-1,
    0x1.fccf4dd8fbbaep1
  },
  { // Entry 962
    0x1.175059bf0d42f1d6b391f07f96f2353dp-1,
    -0x1.dbfbbc70254bcp1
  },
  { // Entry 963
    -0x1.175059bf0d42f1d6b391f07f96f2353dp-1,
    0x1.dbfbbc70254bcp1
  },
  { // Entry 964
    0x1.42abba8c72fd22194793246b8d19960ap-2,
    -0x1.bb282b074edcap1
  },
  { // Entry 965
    -0x1.42abba8c72fd22194793246b8d19960ap-2,
    0x1.bb282b074edcap1
  },
  { // Entry 966
    0x1.066e7eb76f62b5f4563de26dca890017p-4,
    -0x1.9a54999e786d8p1
  },
  { // Entry 967
    -0x1.066e7eb76f62b5f4563de26dca890017p-4,
    0x1.9a54999e786d8p1
  },
  { // Entry 968
    -0x1.877e2cd4f6fa42586875c5250a169e48p-3,
    -0x1.79810835a1fe6p1
  },
  { // Entry 969
    0x1.877e2cd4f6fa42586875c5250a169e48p-3,
    0x1.79810835a1fe6p1
  },
  { // Entry 970
    -0x1.bc4c04d71aba5dfc098278f168bbd962p-2,
    -0x1.58ad76cccb8f4p1
  },
  { // Entry 971
    0x1.bc4c04d71aba5dfc098278f168bbd962p-2,
    0x1.58ad76cccb8f4p1
  },
  { // Entry 972
    -0x1.4be4979c5efa871d30ae1cfa66389199p-1,
    -0x1.37d9e563f5202p1
  },
  { // Entry 973
    0x1.4be4979c5efa871d30ae1cfa66389199p-1,
    0x1.37d9e563f5202p1
  },
  { // Entry 974
    -0x1.a3ed9e25293822168958cce1e09f7c11p-1,
    -0x1.170653fb1eb10p1
  },
  { // Entry 975
    0x1.a3ed9e25293822168958cce1e09f7c11p-1,
    0x1.170653fb1eb10p1
  },
  { // Entry 976
    -0x1.e07eeeda109c62b340dc36e92169648dp-1,
    -0x1.ec6585249083cp0
  },
  { // Entry 977
    0x1.e07eeeda109c62b340dc36e92169648dp-1,
    0x1.ec6585249083cp0
  },
  { // Entry 978
    -0x1.fda254c27a01dd954db3aea505e49453p-1,
    -0x1.aabe6252e3a58p0
  },
  { // Entry 979
    0x1.fda254c27a01dd954db3aea505e49453p-1,
    0x1.aabe6252e3a58p0
  },
  { // Entry 980
    -0x1.f96fe405f1aca02e8f4fd433e59aa973p-1,
    -0x1.69173f8136c74p0
  },
  { // Entry 981
    0x1.f96fe405f1aca02e8f4fd433e59aa973p-1,
    0x1.69173f8136c74p0
  },
  { // Entry 982
    -0x1.d42de42dce13ef040bb1040e3148d7dep-1,
    -0x1.27701caf89e90p0
  },
  { // Entry 983
    0x1.d42de42dce13ef040bb1040e3148d7dep-1,
    0x1.27701caf89e90p0
  },
  { // Entry 984
    -0x1.904c37505de5930812e3a2a94feaa51bp-1,
    -0x1.cb91f3bbba157p-1
  },
  { // Entry 985
    0x1.904c37505de5930812e3a2a94feaa51bp-1,
    0x1.cb91f3bbba157p-1
  },
  { // Entry 986
    -0x1.323b8b1fb4bb626dd40cacd74963ac6cp-1,
    -0x1.4843ae186058ep-1
  },
  { // Entry 987
    0x1.323b8b1fb4bb626dd40cacd74963ac6cp-1,
    0x1.4843ae186058ep-1
  },
  { // Entry 988
    -0x1.8045fe64e6308bb5c6ce35f834b93c63p-2,
    -0x1.89ead0ea0d38ap-2
  },
  { // Entry 989
    0x1.8045fe64e6308bb5c6ce35f834b93c63p-2,
    0x1.89ead0ea0d38ap-2
  },
  { // Entry 990
    -0x1.05e4761ab8dec44ed0fa30d335049c40p-3,
    -0x1.069c8b46b37f0p-3
  },
  { // Entry 991
    0x1.05e4761ab8dec44ed0fa30d335049c40p-3,
    0x1.069c8b46b37f0p-3
  },
  { // Entry 992
    0x1.05e4761ab8d31d00e656372c5c04aa6ep-3,
    0x1.069c8b46b3734p-3
  },
  { // Entry 993
    -0x1.05e4761ab8d31d00e656372c5c04aa6ep-3,
    -0x1.069c8b46b3734p-3
  },
  { // Entry 994
    0x1.8045fe64e62b19a094399502afb76e5cp-2,
    0x1.89ead0ea0d32cp-2
  },
  { // Entry 995
    -0x1.8045fe64e62b19a094399502afb76e5cp-2,
    -0x1.89ead0ea0d32cp-2
  },
  { // Entry 996
    0x1.323b8b1fb4b907c416d23b04e0ec0e72p-1,
    0x1.4843ae186055fp-1
  },
  { // Entry 997
    -0x1.323b8b1fb4b907c416d23b04e0ec0e72p-1,
    -0x1.4843ae186055fp-1
  },
  { // Entry 998
    0x1.904c37505de3be2ace17ca5487750231p-1,
    0x1.cb91f3bbba128p-1
  },
  { // Entry 999
    -0x1.904c37505de3be2ace17ca5487750231p-1,
    -0x1.cb91f3bbba128p-1
  },
  { // Entry 1000
    0x1.d42de42dce12b82466f2fcb63b294751p-1,
    0x1.27701caf89e78p0
  },
  { // Entry 1001
    -0x1.d42de42dce12b82466f2fcb63b294751p-1,
    -0x1.27701caf89e78p0
  },
  { // Entry 1002
    0x1.f96fe405f1ac259bf192fd1cf64e2f12p-1,
    0x1.69173f8136c5cp0
  },
  { // Entry 1003
    -0x1.f96fe405f1ac259bf192fd1cf64e2f12p-1,
    -0x1.69173f8136c5cp0
  },
  { // Entry 1004
    0x1.fda254c27a02275432d77dd6f9704644p-1,
    0x1.aabe6252e3a40p0
  },
  { // Entry 1005
    -0x1.fda254c27a02275432d77dd6f9704644p-1,
    -0x1.aabe6252e3a40p0
  },
  { // Entry 1006
    0x1.e07eeeda109d6bf0c935fa10b1280c6dp-1,
    0x1.ec65852490824p0
  },
  { // Entry 1007
    -0x1.e07eeeda109d6bf0c935fa10b1280c6dp-1,
    -0x1.ec65852490824p0
  },
  { // Entry 1008
    0x1.a3ed9e252939d9793fb2f6f75e5c76e7p-1,
    0x1.170653fb1eb04p1
  },
  { // Entry 1009
    -0x1.a3ed9e252939d9793fb2f6f75e5c76e7p-1,
    -0x1.170653fb1eb04p1
  },
  { // Entry 1010
    0x1.4be4979c5efccfe78ea0b6afb0cbba37p-1,
    0x1.37d9e563f51f6p1
  },
  { // Entry 1011
    -0x1.4be4979c5efccfe78ea0b6afb0cbba37p-1,
    -0x1.37d9e563f51f6p1
  },
  { // Entry 1012
    0x1.bc4c04d71abfc5df69589a45d5e3196ep-2,
    0x1.58ad76cccb8e8p1
  },
  { // Entry 1013
    -0x1.bc4c04d71abfc5df69589a45d5e3196ep-2,
    -0x1.58ad76cccb8e8p1
  },
  { // Entry 1014
    0x1.877e2cd4f70609b1f062295b64aed4bdp-3,
    0x1.79810835a1fdap1
  },
  { // Entry 1015
    -0x1.877e2cd4f70609b1f062295b64aed4bdp-3,
    -0x1.79810835a1fdap1
  },
  { // Entry 1016
    -0x1.066e7eb76f4ac293f46486dc328d450bp-4,
    0x1.9a54999e786ccp1
  },
  { // Entry 1017
    0x1.066e7eb76f4ac293f46486dc328d450bp-4,
    -0x1.9a54999e786ccp1
  },
  { // Entry 1018
    -0x1.42abba8c72f770595ffe3135a0e0ad83p-2,
    0x1.bb282b074edbep1
  },
  { // Entry 1019
    0x1.42abba8c72f770595ffe3135a0e0ad83p-2,
    -0x1.bb282b074edbep1
  },
  { // Entry 1020
    -0x1.175059bf0d406e2fe014e880dd29cfacp-1,
    0x1.dbfbbc70254b0p1
  },
  { // Entry 1021
    0x1.175059bf0d406e2fe014e880dd29cfacp-1,
    -0x1.dbfbbc70254b0p1
  },
  { // Entry 1022
    -0x1.7b05b7b6c6116155f0dc551e316e1e0bp-1,
    0x1.fccf4dd8fbba2p1
  },
  { // Entry 1023
    0x1.7b05b7b6c6116155f0dc551e316e1e0bp-1,
    -0x1.fccf4dd8fbba2p1
  },
  { // Entry 1024
    -0x1.c5f058230e7ebeb7616779e16fa9b537p-1,
    0x1.0ed16fa0e914ap2
  },
  { // Entry 1025
    0x1.c5f058230e7ebeb7616779e16fa9b537p-1,
    -0x1.0ed16fa0e914ap2
  },
  { // Entry 1026
    -0x1.f329c0558e95fa333d5d2d44d654777cp-1,
    0x1.1f3b3855544c3p2
  },
  { // Entry 1027
    0x1.f329c0558e95fa333d5d2d44d654777cp-1,
    -0x1.1f3b3855544c3p2
  },
  { // Entry 1028
    -0x1.ffbca846c4fcb237c2947b35b037a2p-1,
    0x1.2fa50109bf83cp2
  },
  { // Entry 1029
    0x1.ffbca846c4fcb237c2947b35b037a2p-1,
    -0x1.2fa50109bf83cp2
  },
  { // Entry 1030
    -0x1.ead6834909ba0ee69b31e1970df1bb8bp-1,
    0x1.400ec9be2abb5p2
  },
  { // Entry 1031
    0x1.ead6834909ba0ee69b31e1970df1bb8bp-1,
    -0x1.400ec9be2abb5p2
  },
  { // Entry 1032
    -0x1.b5d545b109c1232b61dd28d8035d95cbp-1,
    0x1.5078927295f2ep2
  },
  { // Entry 1033
    0x1.b5d545b109c1232b61dd28d8035d95cbp-1,
    -0x1.5078927295f2ep2
  },
  { // Entry 1034
    -0x1.643080d67ace48c0dd1fe3a06bbc4bf5p-1,
    0x1.60e25b27012a7p2
  },
  { // Entry 1035
    0x1.643080d67ace48c0dd1fe3a06bbc4bf5p-1,
    -0x1.60e25b27012a7p2
  },
  { // Entry 1036
    -0x1.f67ea975b86f5d4aa92716cc077473a7p-2,
    0x1.714c23db6c620p2
  },
  { // Entry 1037
    0x1.f67ea975b86f5d4aa92716cc077473a7p-2,
    -0x1.714c23db6c620p2
  },
  { // Entry 1038
    -0x1.03be06f97cc4d78fdccbca1d40e86011p-2,
    0x1.81b5ec8fd7999p2
  },
  { // Entry 1039
    0x1.03be06f97cc4d78fdccbca1d40e86011p-2,
    -0x1.81b5ec8fd7999p2
  },
  { // Entry 1040
    0x1.efb26ef930c4c3fa3245963c1dcec0a6p-5,
    0x1.effffffffffffp-5
  },
  { // Entry 1041
    -0x1.efb26ef930c4c3fa3245963c1dcec0a6p-5,
    -0x1.effffffffffffp-5
  },
  { // Entry 1042
    0x1.efb26ef930c4d3f2b0dbe1931ba5ae64p-5,
    0x1.fp-5
  },
  { // Entry 1043
    -0x1.efb26ef930c4d3f2b0dbe1931ba5ae64p-5,
    -0x1.fp-5
  },
  { // Entry 1044
    0x1.efb26ef930c4e3eb2f722cea197c2036p-5,
    0x1.f000000000001p-5
  },
  { // Entry 1045
    -0x1.efb26ef930c4e3eb2f722cea197c2036p-5,
    -0x1.f000000000001p-5
  },
  { // Entry 1046
    0x1.f6baaa131de633ad4e0e7d6465d12a05p-4,
    0x1.f7fffffffffffp-4
  },
  { // Entry 1047
    -0x1.f6baaa131de633ad4e0e7d6465d12a05p-4,
    -0x1.f7fffffffffffp-4
  },
  { // Entry 1048
    0x1.f6baaa131de6438e5611279864fe7663p-4,
    0x1.f80p-4
  },
  { // Entry 1049
    -0x1.f6baaa131de6438e5611279864fe7663p-4,
    -0x1.f80p-4
  },
  { // Entry 1050
    0x1.f6baaa131de6536f5e13d1cc6429cc07p-4,
    0x1.f800000000001p-4
  },
  { // Entry 1051
    -0x1.f6baaa131de6536f5e13d1cc6429cc07p-4,
    -0x1.f800000000001p-4
  },
  { // Entry 1052
    0x1.4a8c3b4e9c7ff00a36e061a0d2295093p-3,
    0x1.4bfffffffffffp-3
  },
  { // Entry 1053
    -0x1.4a8c3b4e9c7ff00a36e061a0d2295093p-3,
    -0x1.4bfffffffffffp-3
  },
  { // Entry 1054
    0x1.4a8c3b4e9c7fffd48305f44a42f5f50fp-3,
    0x1.4c0p-3
  },
  { // Entry 1055
    -0x1.4a8c3b4e9c7fffd48305f44a42f5f50fp-3,
    -0x1.4c0p-3
  },
  { // Entry 1056
    0x1.4a8c3b4e9c800f9ecf2b86f3b3bd6f5ap-3,
    0x1.4c00000000001p-3
  },
  { // Entry 1057
    -0x1.4a8c3b4e9c800f9ecf2b86f3b3bd6f5ap-3,
    -0x1.4c00000000001p-3
  },
  { // Entry 1058
    0x1.2e9cd95baba325fe6067233d4496aaacp-2,
    0x1.3333333333332p-2
  },
  { // Entry 1059
    -0x1.2e9cd95baba325fe6067233d4496aaacp-2,
    -0x1.3333333333332p-2
  },
  { // Entry 1060
    0x1.2e9cd95baba335476f513ac221d078c7p-2,
    0x1.3333333333333p-2
  },
  { // Entry 1061
    -0x1.2e9cd95baba335476f513ac221d078c7p-2,
    -0x1.3333333333333p-2
  },
  { // Entry 1062
    0x1.2e9cd95baba344907e3b5246fef75d15p-2,
    0x1.3333333333334p-2
  },
  { // Entry 1063
    -0x1.2e9cd95baba344907e3b5246fef75d15p-2,
    -0x1.3333333333334p-2
  },
  { // Entry 1064
    0x1.3faefc7a5466ef3045c3f1be716ad568p-1,
    0x1.594317acc4ef8p-1
  },
  { // Entry 1065
    -0x1.3faefc7a5466ef3045c3f1be716ad568p-1,
    -0x1.594317acc4ef8p-1
  },
  { // Entry 1066
    0x1.3faefc7a5466fbafbca027b6e8db8c04p-1,
    0x1.594317acc4ef9p-1
  },
  { // Entry 1067
    -0x1.3faefc7a5466fbafbca027b6e8db8c04p-1,
    -0x1.594317acc4ef9p-1
  },
  { // Entry 1068
    0x1.3faefc7a5467082f337c5daf5ffc56e2p-1,
    0x1.594317acc4efap-1
  },
  { // Entry 1069
    -0x1.3faefc7a54
```