Response:
The user is asking for a summary of the functionality of a C source code file. The file appears to contain a large array of floating-point number pairs. Based on the file path `bionic/tests/math_data/tan_intel_data.handroid`, the data likely represents input-output pairs for the tangent function, possibly used for testing the `tan()` implementation in Android's Bionic libc.

**Plan:**

1. **Identify the core functionality:** The file stores test data for the tangent function.
2. **Explain the data format:** Each entry seems to be an input angle (likely in radians) and the corresponding tangent value. The hexadecimal floating-point representation needs to be mentioned.
3. **Relate to Android:** The data is used to test the `tan()` function within Android's `libm.so`.
4. **Mention the purpose of the data:**  It helps ensure the accuracy of the `tan()` implementation across different architectures.
5. **Infer potential usage:** The data is used in unit tests.
6. **Avoid detailed explanations of libc functions, dynamic linker, etc.,** as the prompt explicitly mentions this is part 3 of 4 and those were likely covered in previous parts.
7. **Focus on summarizing the provided data.**
这个代码片段是 `bionic/tests/math_data/tan_intel_data.handroid` 文件的一部分，这个文件隶属于 Android 的 Bionic 库，专门用于数学函数的测试。

**这个代码片段的主要功能是：**

**存储了一系列用于测试 `tan()` 函数的输入和预期输出值对。**

具体来说，它定义了一个匿名结构体数组，每个结构体包含两个 `double` 类型的浮点数。第一个浮点数代表 `tan()` 函数的输入角度（以弧度为单位），第二个浮点数代表该角度对应的正切值的预期结果。

**归纳一下它的功能：**

这段代码是 Android Bionic 库中用于测试 `tan()` 函数精度的测试数据。它提供了一组预先计算好的输入角度和对应的精确正切值，用于验证 `tan()` 函数的实现是否正确，并确保其在各种输入值下都能产生符合预期的结果。这对于保证 Android 系统底层数学运算的准确性至关重要。

### 提示词
```
这是目录为bionic/tests/math_data/tan_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
c51cdcbe2p-1,
    0x1.69173f8136c67p-1
  },
  { // Entry 721
    -0x1.b3df386f18227ebcee905fdc51cdcbe2p-1,
    -0x1.69173f8136c67p-1
  },
  { // Entry 722
    0x1.efd82742d778c18a8c969be0cf0902b3p-1,
    0x1.89ead0ea0d359p-1
  },
  { // Entry 723
    -0x1.efd82742d778c18a8c969be0cf0902b3p-1,
    -0x1.89ead0ea0d359p-1
  },
  { // Entry 724
    0x1.19e26b5ecd5c040a1d80c1583f78f7d7p0,
    0x1.aabe6252e3a4bp-1
  },
  { // Entry 725
    -0x1.19e26b5ecd5c040a1d80c1583f78f7d7p0,
    -0x1.aabe6252e3a4bp-1
  },
  { // Entry 726
    0x1.41038b70be0fa1478f98a2e9f266550ap0,
    0x1.cb91f3bbba13dp-1
  },
  { // Entry 727
    -0x1.41038b70be0fa1478f98a2e9f266550ap0,
    -0x1.cb91f3bbba13dp-1
  },
  { // Entry 728
    0x1.6efec8c1e493b517efe5eb92464fdf42p0,
    0x1.ec6585249082fp-1
  },
  { // Entry 729
    -0x1.6efec8c1e493b517efe5eb92464fdf42p0,
    -0x1.ec6585249082fp-1
  },
  { // Entry 730
    0x1.a64c7c9d653462d8ded3e658fe4efbcbp0,
    0x1.069c8b46b3791p0
  },
  { // Entry 731
    -0x1.a64c7c9d653462d8ded3e658fe4efbcbp0,
    -0x1.069c8b46b3791p0
  },
  { // Entry 732
    0x1.eab43e0e5e87c26fd432e06301e19e15p0,
    0x1.170653fb1eb0ap0
  },
  { // Entry 733
    -0x1.eab43e0e5e87c26fd432e06301e19e15p0,
    -0x1.170653fb1eb0ap0
  },
  { // Entry 734
    0x1.21277b97c01376e361988250b56364cfp1,
    0x1.27701caf89e83p0
  },
  { // Entry 735
    -0x1.21277b97c01376e361988250b56364cfp1,
    -0x1.27701caf89e83p0
  },
  { // Entry 736
    0x1.5bd13dda077cce249db2794d69407504p1,
    0x1.37d9e563f51fcp0
  },
  { // Entry 737
    -0x1.5bd13dda077cce249db2794d69407504p1,
    -0x1.37d9e563f51fcp0
  },
  { // Entry 738
    0x1.af4643e9371f88e78c24d83bd6b8e23ep1,
    0x1.4843ae1860575p0
  },
  { // Entry 739
    -0x1.af4643e9371f88e78c24d83bd6b8e23ep1,
    -0x1.4843ae1860575p0
  },
  { // Entry 740
    0x1.1866fe845e759d14da478c6cf6f2be65p2,
    0x1.58ad76cccb8eep0
  },
  { // Entry 741
    -0x1.1866fe845e759d14da478c6cf6f2be65p2,
    -0x1.58ad76cccb8eep0
  },
  { // Entry 742
    0x1.8bdcd54bd5980b3a80cefc914c481475p2,
    0x1.69173f8136c67p0
  },
  { // Entry 743
    -0x1.8bdcd54bd5980b3a80cefc914c481475p2,
    -0x1.69173f8136c67p0
  },
  { // Entry 744
    0x1.4bb6a64e0625b974cded615056ffd61cp3,
    0x1.79810835a1fe0p0
  },
  { // Entry 745
    -0x1.4bb6a64e0625b974cded615056ffd61cp3,
    -0x1.79810835a1fe0p0
  },
  { // Entry 746
    0x1.f2f05cfb656a39f6f2a90f7911b24051p4,
    0x1.89ead0ea0d359p0
  },
  { // Entry 747
    -0x1.f2f05cfb656a39f6f2a90f7911b24051p4,
    -0x1.89ead0ea0d359p0
  },
  { // Entry 748
    -0x1.f2f05cfb657f55f2bc6d204377a68543p4,
    0x1.9a54999e786d2p0
  },
  { // Entry 749
    0x1.f2f05cfb657f55f2bc6d204377a68543p4,
    -0x1.9a54999e786d2p0
  },
  { // Entry 750
    -0x1.4bb6a64e062a6da35870cfb33595fbe6p3,
    0x1.aabe6252e3a4bp0
  },
  { // Entry 751
    0x1.4bb6a64e062a6da35870cfb33595fbe6p3,
    -0x1.aabe6252e3a4bp0
  },
  { // Entry 752
    -0x1.8bdcd54bd59b73028e5f27649ca67cbap2,
    0x1.bb282b074edc4p0
  },
  { // Entry 753
    0x1.8bdcd54bd59b73028e5f27649ca67cbap2,
    -0x1.bb282b074edc4p0
  },
  { // Entry 754
    -0x1.1866fe845e775d8c8f8bf9165647f6cbp2,
    0x1.cb91f3bbba13dp0
  },
  { // Entry 755
    0x1.1866fe845e775d8c8f8bf9165647f6cbp2,
    -0x1.cb91f3bbba13dp0
  },
  { // Entry 756
    -0x1.af4643e93721ad8095dd27f0827e13e0p1,
    0x1.dbfbbc70254b6p0
  },
  { // Entry 757
    0x1.af4643e93721ad8095dd27f0827e13e0p1,
    -0x1.dbfbbc70254b6p0
  },
  { // Entry 758
    -0x1.5bd13dda077e427d0c9dc6c0e5d3b1b5p1,
    0x1.ec6585249082fp0
  },
  { // Entry 759
    0x1.5bd13dda077e427d0c9dc6c0e5d3b1b5p1,
    -0x1.ec6585249082fp0
  },
  { // Entry 760
    -0x1.21277b97c01485f17bacdb804375ebcdp1,
    0x1.fccf4dd8fbba8p0
  },
  { // Entry 761
    0x1.21277b97c01485f17bacdb804375ebcdp1,
    -0x1.fccf4dd8fbba8p0
  },
  { // Entry 762
    -0x1.eab43e0e5e8916d4c08349abe9e2abd3p0,
    0x1.069c8b46b3791p1
  },
  { // Entry 763
    0x1.eab43e0e5e8916d4c08349abe9e2abd3p0,
    -0x1.069c8b46b3791p1
  },
  { // Entry 764
    -0x1.a64c7c9d6535364d605bb9e5315072ffp0,
    0x1.0ed16fa0e914ep1
  },
  { // Entry 765
    0x1.a64c7c9d6535364d605bb9e5315072ffp0,
    -0x1.0ed16fa0e914ep1
  },
  { // Entry 766
    -0x1.6efec8c1e4944a425541219364a15078p0,
    0x1.170653fb1eb0bp1
  },
  { // Entry 767
    0x1.6efec8c1e4944a425541219364a15078p0,
    -0x1.170653fb1eb0bp1
  },
  { // Entry 768
    -0x1.41038b70be0ff5b7c4d8f06b0d4cf525p0,
    0x1.1f3b3855544c8p1
  },
  { // Entry 769
    0x1.41038b70be0ff5b7c4d8f06b0d4cf525p0,
    -0x1.1f3b3855544c8p1
  },
  { // Entry 770
    -0x1.19e26b5ecd5c294348ba17fec5454792p0,
    0x1.27701caf89e85p1
  },
  { // Entry 771
    0x1.19e26b5ecd5c294348ba17fec5454792p0,
    -0x1.27701caf89e85p1
  },
  { // Entry 772
    -0x1.efd82742d778c4bca07e1e86cbc604b0p-1,
    0x1.2fa50109bf842p1
  },
  { // Entry 773
    0x1.efd82742d778c4bca07e1e86cbc604b0p-1,
    -0x1.2fa50109bf842p1
  },
  { // Entry 774
    -0x1.b3df386f18224a6403e55c16b36ef17fp-1,
    0x1.37d9e563f51ffp1
  },
  { // Entry 775
    0x1.b3df386f18224a6403e55c16b36ef17fp-1,
    -0x1.37d9e563f51ffp1
  },
  { // Entry 776
    -0x1.7e1d936f4d60f1e6f88b4a24df9c65f4p-1,
    0x1.400ec9be2abbcp1
  },
  { // Entry 777
    0x1.7e1d936f4d60f1e6f88b4a24df9c65f4p-1,
    -0x1.400ec9be2abbcp1
  },
  { // Entry 778
    -0x1.4d466accad48574188835130e68e9badp-1,
    0x1.4843ae1860579p1
  },
  { // Entry 779
    0x1.4d466accad48574188835130e68e9badp-1,
    -0x1.4843ae1860579p1
  },
  { // Entry 780
    -0x1.205a6009d5e33774fa98f9f616acc80fp-1,
    0x1.5078927295f36p1
  },
  { // Entry 781
    0x1.205a6009d5e33774fa98f9f616acc80fp-1,
    -0x1.5078927295f36p1
  },
  { // Entry 782
    -0x1.ed21e59972aef64a06e553f18d646093p-2,
    0x1.58ad76cccb8f3p1
  },
  { // Entry 783
    0x1.ed21e59972aef64a06e553f18d646093p-2,
    -0x1.58ad76cccb8f3p1
  },
  { // Entry 784
    -0x1.9e9257e6b6284f73cd1e2eae3220f313p-2,
    0x1.60e25b27012b0p1
  },
  { // Entry 785
    0x1.9e9257e6b6284f73cd1e2eae3220f313p-2,
    -0x1.60e25b27012b0p1
  },
  { // Entry 786
    -0x1.53fdcdfd37ee55bc1cd1604b6ab13b5fp-2,
    0x1.69173f8136c6dp1
  },
  { // Entry 787
    0x1.53fdcdfd37ee55bc1cd1604b6ab13b5fp-2,
    -0x1.69173f8136c6dp1
  },
  { // Entry 788
    -0x1.0c864083d1e5aaa6815a85e25c662e97p-2,
    0x1.714c23db6c62ap1
  },
  { // Entry 789
    0x1.0c864083d1e5aaa6815a85e25c662e97p-2,
    -0x1.714c23db6c62ap1
  },
  { // Entry 790
    -0x1.8ed9142fc913f450dccdbdd27ed11a40p-3,
    0x1.79810835a1fe7p1
  },
  { // Entry 791
    0x1.8ed9142fc913f450dccdbdd27ed11a40p-3,
    -0x1.79810835a1fe7p1
  },
  { // Entry 792
    -0x1.080f73b0704cf570818a65d1a12d5be1p-3,
    0x1.81b5ec8fd79a4p1
  },
  { // Entry 793
    0x1.080f73b0704cf570818a65d1a12d5be1p-3,
    -0x1.81b5ec8fd79a4p1
  },
  { // Entry 794
    -0x1.06f8d014bf09ab85f2a19d80da5a2c0bp-4,
    0x1.89ead0ea0d35bp1
  },
  { // Entry 795
    0x1.06f8d014bf09ab85f2a19d80da5a2c0bp-4,
    -0x1.89ead0ea0d35bp1
  },
  { // Entry 796
    0x1.0c864083d1e7f3955b12071e0644418bp-2,
    -0x1.81b5ec8fd799fp2
  },
  { // Entry 797
    -0x1.0c864083d1e7f3955b12071e0644418bp-2,
    0x1.81b5ec8fd799fp2
  },
  { // Entry 798
    0x1.205a6009d5e3f74da3a372ac15721ef6p-1,
    -0x1.714c23db6c626p2
  },
  { // Entry 799
    -0x1.205a6009d5e3f74da3a372ac15721ef6p-1,
    0x1.714c23db6c626p2
  },
  { // Entry 800
    0x1.efd82742d778e6f04adefc3d21f8be96p-1,
    -0x1.60e25b27012adp2
  },
  { // Entry 801
    -0x1.efd82742d778e6f04adefc3d21f8be96p-1,
    0x1.60e25b27012adp2
  },
  { // Entry 802
    0x1.a64c7c9d653468fbc5260dca501ddb81p0,
    -0x1.5078927295f34p2
  },
  { // Entry 803
    -0x1.a64c7c9d653468fbc5260dca501ddb81p0,
    0x1.5078927295f34p2
  },
  { // Entry 804
    0x1.af4643e9371f9316d3254b8619eda484p1,
    -0x1.400ec9be2abbbp2
  },
  { // Entry 805
    -0x1.af4643e9371f9316d3254b8619eda484p1,
    0x1.400ec9be2abbbp2
  },
  { // Entry 806
    0x1.f2f05cfb656a9e4a085b027d18603230p4,
    -0x1.2fa50109bf842p2
  },
  { // Entry 807
    -0x1.f2f05cfb656a9e4a085b027d18603230p4,
    0x1.2fa50109bf842p2
  },
  { // Entry 808
    -0x1.1866fe845e7755392a0adff56a688eaap2,
    -0x1.1f3b3855544c9p2
  },
  { // Entry 809
    0x1.1866fe845e7755392a0adff56a688eaap2,
    0x1.1f3b3855544c9p2
  },
  { // Entry 810
    -0x1.eab43e0e5e8959e8f5ac6c4f9d9a833bp0,
    -0x1.0ed16fa0e9150p2
  },
  { // Entry 811
    0x1.eab43e0e5e8959e8f5ac6c4f9d9a833bp0,
    0x1.0ed16fa0e9150p2
  },
  { // Entry 812
    -0x1.19e26b5ecd5cd69c30c3dc5d9ffde986p0,
    -0x1.fccf4dd8fbbaep1
  },
  { // Entry 813
    0x1.19e26b5ecd5cd69c30c3dc5d9ffde986p0,
    0x1.fccf4dd8fbbaep1
  },
  { // Entry 814
    -0x1.4d466accad49ec96935caa2a35e439f0p-1,
    -0x1.dbfbbc70254bcp1
  },
  { // Entry 815
    0x1.4d466accad49ec96935caa2a35e439f0p-1,
    0x1.dbfbbc70254bcp1
  },
  { // Entry 816
    -0x1.53fdcdfd37f1ea216e815758ed02a557p-2,
    -0x1.bb282b074edcap1
  },
  { // Entry 817
    0x1.53fdcdfd37f1ea216e815758ed02a557p-2,
    0x1.bb282b074edcap1
  },
  { // Entry 818
    -0x1.06f8d014bf0e964e634f37bcdbf64491p-4,
    -0x1.9a54999e786d8p1
  },
  { // Entry 819
    0x1.06f8d014bf0e964e634f37bcdbf64491p-4,
    0x1.9a54999e786d8p1
  },
  { // Entry 820
    0x1.8ed9142fc914fe067b991d11d70859b8p-3,
    -0x1.79810835a1fe6p1
  },
  { // Entry 821
    -0x1.8ed9142fc914fe067b991d11d70859b8p-3,
    0x1.79810835a1fe6p1
  },
  { // Entry 822
    0x1.ed21e59972ae589aaa4ee3d80c3b7defp-2,
    -0x1.58ad76cccb8f4p1
  },
  { // Entry 823
    -0x1.ed21e59972ae589aaa4ee3d80c3b7defp-2,
    0x1.58ad76cccb8f4p1
  },
  { // Entry 824
    0x1.b3df386f1820ff3df290f036db46f13bp-1,
    -0x1.37d9e563f5202p1
  },
  { // Entry 825
    -0x1.b3df386f1820ff3df290f036db46f13bp-1,
    0x1.37d9e563f5202p1
  },
  { // Entry 826
    0x1.6efec8c1e492616fe2fec0b764fa6eb4p0,
    -0x1.170653fb1eb10p1
  },
  { // Entry 827
    -0x1.6efec8c1e492616fe2fec0b764fa6eb4p0,
    0x1.170653fb1eb10p1
  },
  { // Entry 828
    0x1.5bd13dda077ada91927ab73cedaa828dp1,
    -0x1.ec6585249083cp0
  },
  { // Entry 829
    -0x1.5bd13dda077ada91927ab73cedaa828dp1,
    0x1.ec6585249083cp0
  },
  { // Entry 830
    0x1.4bb6a64e061f69cf7409931383cc80a1p3,
    -0x1.aabe6252e3a58p0
  },
  { // Entry 831
    -0x1.4bb6a64e061f69cf7409931383cc80a1p3,
    0x1.aabe6252e3a58p0
  },
  { // Entry 832
    -0x1.8bdcd54bd5a004acf922c49a8d5e28a2p2,
    -0x1.69173f8136c74p0
  },
  { // Entry 833
    0x1.8bdcd54bd5a004acf922c49a8d5e28a2p2,
    0x1.69173f8136c74p0
  },
  { // Entry 834
    -0x1.21277b97c015f19de7b238252e56e63fp1,
    -0x1.27701caf89e90p0
  },
  { // Entry 835
    0x1.21277b97c015f19de7b238252e56e63fp1,
    0x1.27701caf89e90p0
  },
  { // Entry 836
    -0x1.41038b70be11b85798a271ac3d209ea7p0,
    -0x1.cb91f3bbba157p-1
  },
  { // Entry 837
    0x1.41038b70be11b85798a271ac3d209ea7p0,
    0x1.cb91f3bbba157p-1
  },
  { // Entry 838
    -0x1.7e1d936f4d63c1c7806657d8b838836ep-1,
    -0x1.4843ae186058ep-1
  },
  { // Entry 839
    0x1.7e1d936f4d63c1c7806657d8b838836ep-1,
    0x1.4843ae186058ep-1
  },
  { // Entry 840
    -0x1.9e9257e6b62d886f74e348bdc142599cp-2,
    -0x1.89ead0ea0d38ap-2
  },
  { // Entry 841
    0x1.9e9257e6b62d886f74e348bdc142599cp-2,
    0x1.89ead0ea0d38ap-2
  },
  { // Entry 842
    -0x1.080f73b07057dc7bf0df6de1d3ae1a3bp-3,
    -0x1.069c8b46b37f0p-3
  },
  { // Entry 843
    0x1.080f73b07057dc7bf0df6de1d3ae1a3bp-3,
    0x1.069c8b46b37f0p-3
  },
  { // Entry 844
    0x1.080f73b0704bea7a56d4f88ecf3d5cd3p-3,
    0x1.069c8b46b3734p-3
  },
  { // Entry 845
    -0x1.080f73b0704bea7a56d4f88ecf3d5cd3p-3,
    -0x1.069c8b46b3734p-3
  },
  { // Entry 846
    0x1.9e9257e6b626b1eb1136bd7853311543p-2,
    0x1.89ead0ea0d32cp-2
  },
  { // Entry 847
    -0x1.9e9257e6b626b1eb1136bd7853311543p-2,
    -0x1.89ead0ea0d32cp-2
  },
  { // Entry 848
    0x1.7e1d936f4d5f2eebbbf3d62963106afap-1,
    0x1.4843ae186055fp-1
  },
  { // Entry 849
    -0x1.7e1d936f4d5f2eebbbf3d62963106afap-1,
    -0x1.4843ae186055fp-1
  },
  { // Entry 850
    0x1.41038b70be0df11d1224683c6f865584p0,
    0x1.cb91f3bbba128p-1
  },
  { // Entry 851
    -0x1.41038b70be0df11d1224683c6f865584p0,
    -0x1.cb91f3bbba128p-1
  },
  { // Entry 852
    0x1.21277b97c0115dcf6647ad68f4cb4ad0p1,
    0x1.27701caf89e78p0
  },
  { // Entry 853
    -0x1.21277b97c0115dcf6647ad68f4cb4ad0p1,
    -0x1.27701caf89e78p0
  },
  { // Entry 854
    0x1.8bdcd54bd5914bd9a4d6dd659c2f6606p2,
    0x1.69173f8136c5cp0
  },
  { // Entry 855
    -0x1.8bdcd54bd5914bd9a4d6dd659c2f6606p2,
    -0x1.69173f8136c5cp0
  },
  { // Entry 856
    -0x1.4bb6a64e0633bfa56879660655c38767p3,
    0x1.aabe6252e3a40p0
  },
  { // Entry 857
    0x1.4bb6a64e0633bfa56879660655c38767p3,
    -0x1.aabe6252e3a40p0
  },
  { // Entry 858
    -0x1.5bd13dda078124444c940f013be7c402p1,
    0x1.ec65852490824p0
  },
  { // Entry 859
    0x1.5bd13dda078124444c940f013be7c402p1,
    -0x1.ec65852490824p0
  },
  { // Entry 860
    -0x1.6efec8c1e496f69c286adc66bd586eafp0,
    0x1.170653fb1eb04p1
  },
  { // Entry 861
    0x1.6efec8c1e496f69c286adc66bd586eafp0,
    -0x1.170653fb1eb04p1
  },
  { // Entry 862
    -0x1.b3df386f18262bd637e29fbb30806b2cp-1,
    0x1.37d9e563f51f6p1
  },
  { // Entry 863
    0x1.b3df386f18262bd637e29fbb30806b2cp-1,
    -0x1.37d9e563f51f6p1
  },
  { // Entry 864
    -0x1.ed21e59972b5bcd3015c250eff1c69b9p-2,
    0x1.58ad76cccb8e8p1
  },
  { // Entry 865
    0x1.ed21e59972b5bcd3015c250eff1c69b9p-2,
    -0x1.58ad76cccb8e8p1
  },
  { // Entry 866
    -0x1.8ed9142fc9217289ed21940deaafe878p-3,
    0x1.79810835a1fdap1
  },
  { // Entry 867
    0x1.8ed9142fc9217289ed21940deaafe878p-3,
    -0x1.79810835a1fdap1
  },
  { // Entry 868
    0x1.06f8d014bef67cfb2db560f5a414c88bp-4,
    0x1.9a54999e786ccp1
  },
  { // Entry 869
    -0x1.06f8d014bef67cfb2db560f5a414c88bp-4,
    -0x1.9a54999e786ccp1
  },
  { // Entry 870
    0x1.53fdcdfd37eb40cd9e504df431b502d0p-2,
    0x1.bb282b074edbep1
  },
  { // Entry 871
    -0x1.53fdcdfd37eb40cd9e504df431b502d0p-2,
    -0x1.bb282b074edbep1
  },
  { // Entry 872
    0x1.4d466accad45a72e5f735eb2f6adf9ffp-1,
    0x1.dbfbbc70254b0p1
  },
  { // Entry 873
    -0x1.4d466accad45a72e5f735eb2f6adf9ffp-1,
    -0x1.dbfbbc70254b0p1
  },
  { // Entry 874
    0x1.19e26b5ecd598507ecd00d81ec775683p0,
    0x1.fccf4dd8fbba2p1
  },
  { // Entry 875
    -0x1.19e26b5ecd598507ecd00d81ec775683p0,
    -0x1.fccf4dd8fbba2p1
  },
  { // Entry 876
    0x1.eab43e0e5e8257073afaecab386154a1p0,
    0x1.0ed16fa0e914ap2
  },
  { // Entry 877
    -0x1.eab43e0e5e8257073afaecab386154a1p0,
    -0x1.0ed16fa0e914ap2
  },
  { // Entry 878
    0x1.1866fe845e6fc27064e2b123a7724e75p2,
    0x1.1f3b3855544c3p2
  },
  { // Entry 879
    -0x1.1866fe845e6fc27064e2b123a7724e75p2,
    -0x1.1f3b3855544c3p2
  },
  { // Entry 880
    -0x1.f2f05cfb65c5e06b1ae88c48b4b755cep4,
    0x1.2fa50109bf83cp2
  },
  { // Entry 881
    0x1.f2f05cfb65c5e06b1ae88c48b4b755cep4,
    -0x1.2fa50109bf83cp2
  },
  { // Entry 882
    -0x1.af4643e93728d6bfd702c33405dcce7dp1,
    0x1.400ec9be2abb5p2
  },
  { // Entry 883
    0x1.af4643e93728d6bfd702c33405dcce7dp1,
    -0x1.400ec9be2abb5p2
  },
  { // Entry 884
    -0x1.a64c7c9d6539fdec27afc380b9f752c0p0,
    0x1.5078927295f2ep2
  },
  { // Entry 885
    0x1.a64c7c9d6539fdec27afc380b9f752c0p0,
    -0x1.5078927295f2ep2
  },
  { // Entry 886
    -0x1.efd82742d77eb73c81a00f568621f63cp-1,
    0x1.60e25b27012a7p2
  },
  { // Entry 887
    0x1.efd82742d77eb73c81a00f568621f63cp-1,
    -0x1.60e25b27012a7p2
  },
  { // Entry 888
    -0x1.205a6009d5e7eae63da1cbd57129eeffp-1,
    0x1.714c23db6c620p2
  },
  { // Entry 889
    0x1.205a6009d5e7eae63da1cbd57129eeffp-1,
    -0x1.714c23db6c620p2
  },
  { // Entry 890
    -0x1.0c864083d1ee5d34de2060c8629d4951p-2,
    0x1.81b5ec8fd7999p2
  },
  { // Entry 891
    0x1.0c864083d1ee5d34de2060c8629d4951p-2,
    -0x1.81b5ec8fd7999p2
  },
  { // Entry 892
    0x1.f09b63aa81fc36da509c3e410607ffe7p-5,
    0x1.effffffffffffp-5
  },
  { // Entry 893
    -0x1.f09b63aa81fc36da509c3e410607ffe7p-5,
    -0x1.effffffffffffp-5
  },
  { // Entry 894
    0x1.f09b63aa81fc46e95e06405b41e8b4ccp-5,
    0x1.fp-5
  },
  { // Entry 895
    -0x1.f09b63aa81fc46e95e06405b41e8b4ccp-5,
    -0x1.fp-5
  },
  { // Entry 896
    0x1.f09b63aa81fc56f86b7042757dca62e8p-5,
    0x1.f000000000001p-5
  },
  { // Entry 897
    -0x1.f09b63aa81fc56f86b7042757dca62e8p-5,
    -0x1.f000000000001p-5
  },
  { // Entry 898
    0x1.fa8f21c8a33aecf4af77754ef90a67b8p-4,
    0x1.f7fffffffffffp-4
  },
  { // Entry 899
    -0x1.fa8f21c8a33aecf4af77754ef90a67b8p-4,
    -0x1.f7fffffffffffp-4
  },
  { // Entry 900
    0x1.fa8f21c8a33afd3355198e8d7716a811p-4,
    0x1.f80p-4
  },
  { // Entry 901
    -0x1.fa8f21c8a33afd3355198e8d7716a811p-4,
    -0x1.f80p-4
  },
  { // Entry 902
    0x1.fa8f21c8a33b0d71fabba7cbf526ed07p-4,
    0x1.f800000000001p-4
  },
  { // Entry 903
    -0x1.fa8f21c8a33b0d71fabba7cbf526ed07p-4,
    -0x1.f800000000001p-4
  },
  { // Entry 904
    0x1.4ef06cb4f0a869ef00df8ec5582dfa31p-3,
    0x1.4bfffffffffffp-3
  },
  { // Entry 905
    -0x1.4ef06cb4f0a869ef00df8ec5582dfa31p-3,
    -0x1.4bfffffffffffp-3
  },
  { // Entry 906
    0x1.4ef06cb4f0a87a5c8eeeebceb12a22b4p-3,
    0x1.4c0p-3
  },
  { // Entry 907
    -0x1.4ef06cb4f0a87a5c8eeeebceb12a22b4p-3,
    -0x1.4c0p-3
  },
  { // Entry 908
    0x1.4ef06cb4f0a88aca1cfe48d80a310a65p-3,
    0x1.4c00000000001p-3
  },
  { // Entry 909
    -0x1.4ef06cb4f0a88aca1cfe48d80a310a65p-3,
    -0x1.4c00000000001p-3
  },
  { // Entry 910
    0x1.3cc2a44e2999668cb092a09b73b2de50p-2,
    0x1.3333333333332p-2
  },
  { // Entry 911
    -0x1.3cc2a44e2999668cb092a09b73b2de50p-2,
    -0x1.3333333333332p-2
  },
  { // Entry 912
    0x1.3cc2a44e29997814a1ac3f0211c7641fp-2,
    0x1.3333333333333p-2
  },
  { // Entry 913
    -0x1.3cc2a44e29997814a1ac3f0211c7641fp-2,
    -0x1.3333333333333p-2
  },
  { // Entry 914
    0x1.3cc2a44e2999899c92c5dd68b0074c31p-2,
    0x1.3333333333334p-2
  },
  { // Entry 915
    -0x1.3cc2a44e2999899c92c5dd68b0074c31p-2,
    -0x1.3333333333334p-2
  },
  { // Entry 916
    0x1.9943711dc2ce83d21cdb285aced817adp-1,
    0x1.594317acc4ef8p-1
  },
  { // Entry 917
    -0x1.9943711dc2ce83d21cdb285aced817adp-1,
    -0x1.594317acc4ef8p-1
  },
  { // Entry 918
    0x1.9943711dc2ce9e0b3f1ffe5aec0ac20dp-1,
    0x1.594317acc4ef9p-1
  },
  { // Entry 919
    -0x1.9943711dc2ce9e0b3f1ffe5aec0ac20dp-1,
    -0x1.594317acc4ef9p-1
  },
  { // Entry 920
    0x1.9943711dc2ceb8446164d45b0a8ccdeep-1,
    0x1.594317acc4efap-1
  },
  { // Entry 921
    -0x1.9943711dc2ceb8446164d45b0a8ccdeep-1,
    -0x1.594317acc4efap-1
  },
  { // Entry 922
    0x1.fbc511df5917d57d231d7ad434da5f94p-1,
    0x1.8ffffffffffffp-1
  },
  { // Entry 923
    -0x1.fbc511df5917d57d231d7ad434da5f94p-1,
    -0x1.8ffffffffffffp-1
  },
  { // Entry 924
    0x1.fbc511df5917f539bbcf778bc1a22249p-1,
    0x1.9p-1
  },
  { // Entry 925
    -0x1.fbc511df5917f539bbcf778bc1a22249p-1,
    -0x1.9p-1
  },
  { // Entry 926
    0x1.fbc511df591814f65481744350617c85p-1,
    0x1.9000000000001p-1
  },
  { // Entry 927
    -0x1.fbc511df591814f65481744350617c85p-1,
    -0x1.9000000000001p-1
  },
  { // Entry 928
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 929
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 930
    -0.0,
    -0.0
  },
  { // Entry 931
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 932
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 933
    0x1.927278a3b1160bbf8e0bb309da4247c5p-5,
    0x1.921fb54442d17p-5
  },
  { // Entry 934
    -0x1.927278a3b1160bbf8e0bb309da4247c5p-5,
    -0x1.921fb54442d17p-5
  },
  { // Entry 935
    0x1.927278a3b1161bc970ba8b50e575f97fp-5,
    0x1.921fb54442d18p-5
  },
  { // Entry 936
    -0x1.927278a3b1161bc970ba8b50e575f97fp-5,
    -0x1.921fb54442d18p-5
  },
  { // Entry 937
    0x1.927278a3b1162bd353696397f0aa74eep-5,
    0x1.921fb54442d19p-5
  },
  { // Entry 938
    -0x1.927278a3b1162bd353696397f0aa74eep-5,
    -0x1.921fb54442d19p-5
  },
  { // Entry 939
    0x1.936bb8c5b2da118306fa9b5d6d8ed2c1p-4,
    0x1.921fb54442d17p-4
  },
  { // Entry 940
    -0x1.936bb8c5b2da118306fa9b5d6d8ed2c1p-4,
    -0x1.921fb54442d17p-4
  },
  { // Entry 941
    0x1.936bb8c5b2da21aac2bfec84293e5d4dp-4,
    0x1.921fb54442d18p-4
  },
  { // Entry 942
    -0x1.936bb8c5b2da21aac2bfec84293e5d4dp-4,
    -0x1.921fb54442d18p-4
  },
  { // Entry 943
    0x1.936bb8c5b2da31d27e853daae4f11684p-4,
    0x1.921fb54442d19p-4
  },
  { // Entry 944
    -0x1.936bb8c5b2da31d27e853daae4f11684p-4,
    -0x1.921fb54442d19p-4
  },
  { // Entry 945
    0x1.975f5e0553156b438ca7d752d37d0873p-3,
    0x1.921fb54442d17p-3
  },
  { // Entry 946
    -0x1.975f5e0553156b438ca7d752d37d0873p-3,
    -0x1.921fb54442d17p-3
  },
  { // Entry 947
    0x1.975f5e0553157be59cbff648fdef2c08p-3,
    0x1.921fb54442d18p-3
  },
  { // Entry 948
    -0x1.975f5e0553157be59cbff648fdef2c08p-3,
    -0x1.921fb54442d18p-3
  },
  { // Entry 949
    0x1.975f5e0553158c87acd8153f286e8b8ap-3,
    0x1.921fb54442d19p-3
  },
  { // Entry 950
    -0x1.975f5e0553158c87acd8153f286e8b8ap-3,
    -0x1.921fb54442d19p-3
  },
  { // Entry 951
    0x1.a827999fcef30c38b2e5397ea7c10eadp-2,
    0x1.921fb54442d17p-2
  },
  { // Entry 952
    -0x1.a827999fcef30c38b2e5397ea7c10eadp-2,
    -0x1.921fb54442d17p-2
  },
  { // Entry 953
    0x1.a827999fcef31ef776183b070e6fc84ep-2,
    0x1.921fb54442d18p-2
  },
  { // Entry 954
    -0x1.a827999fcef31ef776183b070e6fc84ep-2,
    -0x1.921fb54442d18p-2
  },
  { // Entry 955
    0x1.a827999fcef331b6394b3c8f755c9fa3p-2,
    0x1.921fb54442d19p-2
  },
  { // Entry 956
    -0x1.a827999fcef331b6394b3c8f755c9fa3p-2,
    -0x1.921fb54442d19p-2
  },
  { // Entry 957
    0x1.ffffffffffffd72cece675d1fe3035bbp-1,
    0x1.921fb54442d17p-1
  },
  { // Entry 958
    -0x1.ffffffffffffd72cece675d1fe3035bbp-1,
    -0x1.921fb54442d17p-1
  },
  { // Entry 959
    0x1.fffffffffffff72cece675d1fca30489p-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 960
    -0x1.fffffffffffff72cece675d1fca30489p-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 961
    0x1.0000000000000b9676733ae8fe8ae9acp0,
    0x1.921fb54442d19p-1
  },
  { // Entry 962
    -0x1.0000000000000b9676733ae8fe8ae9acp0,
    -0x1.921fb54442d19p-1
  },
  { // Entry 963
    0x1.9153d9443ed0b3b43ddab6ae573aa23dp51,
    0x1.921fb54442d17p0
  },
  { // Entry 964
    -0x1.9153d9443ed0b3b43ddab6ae573aa23dp51,
    -0x1.921fb54442d17p0
  },
  { // Entry 965
    0x1.d02967c31cdb4e0c38d01b655d5e0aafp53,
    0x1.921fb54442d18p0
  },
  { // Entry 966
    -0x1.d02967c31cdb4e0c38d01b655d5e0aafp53,
    -0x1.921fb54442d18p0
  },
  { // Entry 967
    -0x1.617a15494767a04882c320317f3e4cecp52,
    0x1.921fb54442d19p0
  },
  { // Entry 968
    0x1.617a15494767a04882c320317f3e4cecp52,
    -0x1.921fb54442d19p0
  },
  { // Entry 969
    -0x1.469898cc51701b839a252049c3d60c68p-51,
    0x1.921fb54442d17p1
  },
  { // Entry 970
    0x1.469898cc51701b839a252049c3d60c68p-51,
    -0x1.921fb54442d17p1
  },
  { // Entry 971
    -0x1.1a62633145c06e0e689481270461d5d7p-53,
    0x1.921fb54442d18p1
  },
  { // Entry 972
    0x1.1a62633145c06e0e689481270461d5d7p-53,
    -0x1.921fb54442d18p1
  },
  { // Entry 973
    0x1.72cece675d1fc8f8cbb5bf6c7ee0b96cp-52,
    0x1.921fb54442d19p1
  },
  { // Entry 974
    -0x1.72cece675d1fc8f8cbb5bf6c7ee0b96cp-52,
    -0x1.921fb54442d19p1
  },
  { // Entry 975
    -0x1.469898cc51701b839a252049cc244ab5p-50,
    0x1.921fb54442d17p2
  },
  { // Entry 976
    0x1.469898cc51701b839a252049cc244ab5p-50,
    -0x1.921fb54442d17p2
  },
  { // Entry 977
    -0x1.1a62633145c06e0e6894812704b7bbabp-52,
    0x1.921fb54442d18p2
  },
  { // Entry 978
    0x1.1a62633145c06e0e6894812704b7bbabp-52,
    -0x1.921fb54442d18p2
  },
  { // Entry 979
    0x1.72cece675d1fc8f8cbb5bf6c81eab38cp-51,
    0x1.921fb54442d19p2
  },
  { // Entry 980
    -0x1.72cece675d1fc8f8cbb5bf6c81eab38cp-51,
    -0x1.921fb54442d19p2
  },
  { // Entry 981
    -0x1.469898cc51701b839a252049ed5d43e8p-49,
    0x1.921fb54442d17p3
  },
  { // Entry 982
    0x1.469898cc51701b839a252049ed5d43e8p-49,
    -0x1.921fb54442d17p3
  },
  { // Entry 983
    -0x1.1a62633145c06e0e68948127060f52f9p-51,
    0x1.921fb54442d18p3
  },
  { // Entry 984
    0x1.1a62633145c06e0e68948127060f52f9p-51,
    -0x1.921fb54442d18p3
  },
  { // Entry 985
    0x1.72cece675d1fc8f8cbb5bf6c8e129c0ap-50,
    0x1.921fb54442d19p3
  },
  { // Entry 986
    -0x1.72cece675d1fc8f8cbb5bf6c8e129c0ap-50,
    -0x1.921fb54442d19p3
  },
  { // Entry 987
    -0x1.469898cc51701b839a25204a724128b4p-48,
    0x1.921fb54442d17p4
  },
  { // Entry 988
    0x1.469898cc51701b839a25204a724128b4p-48,
    -0x1.921fb54442d17p4
  },
  { // Entry 989
    -0x1.1a62633145c06e0e689481270b6db033p-50,
    0x1.921fb54442d18p4
  },
  { // Entry 990
    0x1.1a62633145c06e0e689481270b6db033p-50,
    -0x1.921fb54442d18p4
  },
  { // Entry 991
    0x1.72cece675d1fc8f8cbb5bf6cbeb23e03p-49,
    0x1.921fb54442d19p4
  },
  { // Entry 992
    -0x1.72cece675d1fc8f8cbb5bf6cbeb23e03p-49,
    -0x1.921fb54442d19p4
  },
  { // Entry 993
    -0x1.469898cc51701b839a25204c85d0bbe3p-47,
    0x1.921fb54442d17p5
  },
  { // Entry 994
    0x1.469898cc51701b839a25204c85d0bbe3p-47,
    -0x1.921fb54442d17p5
  },
  { // Entry 995
    -0x1.1a62633145c06e0e6894812720e7251ap-49,
    0x1.921fb54442d18p5
  },
  { // Entry 996
    0x1.1a62633145c06e0e6894812720e7251ap-49,
    -0x1.921fb54442d18p5
  },
  { // Entry 997
    0x1.72cece675d1fc8f8cbb5bf6d8130c5e7p-48,
    0x1.921fb54442d19p5
  },
  { // Entry 998
    -0x1.72cece675d1fc8f8cbb5bf6d8130c5e7p-48,
    -0x1.921fb54442d19p5
  },
  { // Entry 999
    -0x1.469898cc51701b839a252054d40f08a0p-46,
    0x1.921fb54442d17p6
  },
  { // Entry 1000
    0x1.469898cc51701b839a252054d40f08a0p-46,
    -0x1.921fb54442d17p6
  },
  { // Entry 1001
    -0x1.1a62633145c06e0e6894812776ccf8b7p-48,
    0x1.921fb54442d18p6
  },
  { // Entry 1002
    0x1.1a62633145c06e0e6894812776ccf8b7p-48,
    -0x1.921fb54442d18p6
  },
  { // Entry 1003
    0x1.72cece675d1fc8f8cbb5bf708b2ae576p-47,
    0x1.921fb54442d19p6
  },
  { // Entry 1004
    -0x1.72cece675d1fc8f8cbb5bf708b2ae576p-47,
    -0x1.921fb54442d19p6
  },
  { // Entry 1005
    -0x1.469898cc51701b839a2520760d083b97p-45,
    0x1.921fb54442d17p7
  },
  { // Entry 1006
    0x1.469898cc51701b839a2520760d083b97p-45,
    -0x1.921fb54442d17p7
  },
  { // Entry 1007
    -0x1.1a62633145c06e0e68948128ce64472bp-47,
    0x1.921fb54442d18p7
  },
  { // Entry 1008
    0x1.1a62633145c06e0e68948128ce64472bp-47,
    -0x1.921fb54442d18p7
  },
  { // Entry 1009
    0x1.72cece675d1fc8f8cbb5bf7cb31363b1p-46,
    0x1.921fb54442d19p7
  },
  { // Entry 1010
    -0x1.72cece675d1fc8f8cbb5bf7cb31363b1p-46,
    -0x1.921fb54442d19p7
  },
  { // Entry 1011
    -0x1.0000000000004d3c9ca64f4510cf6f31p0,
    0x1.2d97c7f3321d1p1
  },
  { // Entry 1012
    0x1.0000000000004d3c9ca64f4510cf6f31p0,
    -0x1.2d97c7f3321d1p1
  },
  { // Entry 1013
    -0x1.0000000000000d3c9ca64f4505804808p0,
    0x1.2d97c7f3321d2p1
  },
  { // Entry 1014
    0x1.0000000000000d3c9ca64f4505804808p0,
    -0x1.2d97c7f3321d2p1
  },
  { // Entry 1015
    -0x1.ffffffffffff9a79394c9e8a146241bdp-1,
    0x1.2d97c7f3321d3p1
  },
  { // Entry 1016
    0x1.ffffffffffff9a79394c9e8a146241bdp-1,
    -0x1.2d97c7f3321d3p1
  },
  { // Entry 1017
    0x1.ffffffffffff53e0a0804d1a0bbc4ab3p-1,
    0x1.f6a7a2955385dp1
  },
  { // Entry 1018
    -0x1.ffffffffffff53e0a0804d1a0bbc4ab3p-1,
    -0x1.f6a7a2955385dp1
  },
  { // Entry 1019
    0x1.ffffffffffffd3e0a0804d19f0b472d3p-1,
    0x1.f6a7a2955385ep1
  },
  { // Entry 1020
    -0x1.ffffffffffffd3e0a0804d19f0b472d3p-1,
    -0x1.f6a7a2955385ep1
  },
  { // Entry 1021
    0x1.00000000000029f05040268cfad64d79p0,
    0x1.f6a7a2955385fp1
  },
  { // Entry 1022
    -0x1.00000000000029f05040268cfad64d79p0,
    -0x1.f6a7a2955385fp1
  },
  { // Entry 1023
    0x1.a8410087262e3f41859fa73567f9244dp49,
    0x1.2d97c7f3321d1p2
  },
  { // Entry 1024
    -0x1.a8410087262e3f41859fa73567f9244dp49,
    -0x1.2d97c7f3321d1p2
  },
  { // Entry 1025
    0x1.3570efd76892340825e0124393554697p52,
    0x1.2d97c7f3321d2p2
  },
  { // Entry 1026
    -0x1.3570efd76892340825e0124393554697p52,
    -0x1.2d97c7f3321d2p2
  },
  { // Entry 1027
    -0x1.42c0d64d5de5178afe06452a1a1b8667p50,
    0x1.2d97c7f3321d3p2
  },
  { // Entry 1028
    0x1.42c0d64d5de5178afe06452a1a1b8667p50,
    -0x1.2d97c7f3321d3p2
  },
  { // Entry 1029
    -0x1.0000000000009ee2c2d963a13d57ec20p0,
    0x1.5fdbbe9bba774p2
  },
  { // Entry 1030
    0x1.0000000000009ee2c2d963a13d57ec20p0,
    -0x1.5fdbbe9bba774p2
  },
  { // Entry 1031
    -0x1.0000000000001ee2c2d963a10de68ab4p0,
    0x1.5fdbbe9bba775p2
  },
  { // Entry 1032
    0x1.0000000000001ee2c2d963a10de68ab4p0,
    -0x1.5fdbbe9bba775p2
  },
  { // Entry 1033
    -0x1.ffffffffffff3dc585b2c7423cea528ep-1,
    0x1.5fdbbe9bba776p2
  },
  { // Entry 1034
    0x1.ffffffffffff3dc585b2c7423cea528ep-1,
    -0x1.5fdbbe9bba776p2
  },
  { // Entry 1035
    0x1.fffffffffffeb094541a24624eeab0e1p-1,
    0x1.c463abeccb2bap2
  },
  { // Entry 1036
    -0x1.fffffffffffeb094541a24624eeab0e1p-1,
    -0x1.c463abeccb2bap2
  },
  { // Entry 1037
    0x1.ffffffffffffb094541a2461e734daeep-1,
    0x1.c463abeccb2bbp2
  },
  { // Entry 1038
    -0x1.ffffffffffffb094541a2461e734daeep-1,
    -0x1.c463abeccb2bbp2
  },
  { // Entry 1039
    0x1.000000000000584a2a0d1230ffbf827dp0,
    0x1.c463abeccb2bcp2
  },
  { // Entry 1040
    -0x1.000000000000584a2a0d1230ffbf827dp0,
    -0x1.c463abeccb2bcp2
  },
  { // Entry 1041
    0x1.7cc080f8958567f05c40ac5f6d310de8p49,
    0x1.f6a7a2955385dp2
  },
  { // Entry 1042
    -0x1.7cc080f8958567f05c40ac5f6d310de8p49,
    -0x1.f6a7a2955385dp2
  },
  { // Entry 1043
    0x1.735453027d7c3e702d73491de369536fp51,
    0x1.f6a7a2955385ep2
  },
  { // Entry 1044
    -0x1.735453027d7c3e702d73491de369536fp51,
    -0x1.f6a7a2955385ep2
  },
  { // Entry 1045
    -0x1.86aa4a3a127a3add9a8e76993733b4a7p50,
    0x1.f6a7a2955385fp2
  },
  { // Entry 1046
    0x1.86aa4a3a127a3add9a8e76993733b4a7p50,
    -0x1.f6a7a2955385fp2
  },
  { // Entry 1047
    -0x1.000000000001b088e90c77fe8051a7dap0,
    0x1.1475cc9eedeffp3
  },
  { // Entry 1048
    0x1.000000000001b088e90c77fe8051a7dap0,
    -0x1.1475cc9eedeffp3
  },
  { // Entry 1049
    -0x1.000000000000b088e90c77fd4fc8becep0,
    0x1.1475cc9eedfp3
  },
  { // Entry 1050
    0x1.000000000000b088e90c77fd4fc8becep0,
    -0x1.1475cc9eedfp3
  },
  { // Entry 1051
    -0x1.ffffffffffff6111d218effa3e7fab83p-1,
    0x1.1475cc9eedf01p3
  },
  { // Entry 1052
    0x1.ffffffffffff6111d218effa3e7fab83p-1,
    -0x1.1475cc9eedf01p3
  },
  { // Entry 1053
    -0x1.34f272993d1414a2b39bd837764c1608p-49,
    0x1.2d97c7f3321d1p3
  },
  { // Entry 1054
    0x1.34f272993d1414a2b39bd837764c1608p-49,
    -0x1.2d97c7f3321d1p3
  },
  { // Entry 1055
    -0x1.a79394c9e8a0a5159cdec1ba87ea5811p-52,
    0x1.2d97c7f3321d2p3
  },
  { // Entry 1056
    0x1.a79394c9e8a0a5159cdec1ba87ea5811p-52,
    -0x1.2d97c7f3321d2p3
  },
  { // Entry 1057
    0x1.961b1acd85d7d6ba98c84f9173b08d6fp-50,
    0x1.2d97c7f3321d3p3
  },
  { // Entry 1058
    -0x1.961b1acd85d7d6ba98c84f9173b08d6fp-50,
    -0x1.2d97c7f3321d3p3
  },
  { // Entry 1059
    0x1.fffffffffffc8d4807b3fbaccc38314bp-1,
    0x1.46b9c347764a2p3
  },
  { // Entry 1060
    -0x1.fffffffffffc8d4807b3fbaccc38314bp-1,
    -0x1.46b9c347764a2p3
  },
  { // Entry 1061
    0x1.fffffffffffe8d4807b3fbaa598038ffp-1,
    0x1.46b9c347764a3p3
  },
  { // Entry 1062
    -0x1.fffffffffffe8d4807b3fbaa598038ffp-1,
    -0x1.46b9c347764a3p3
  },
  { // Entry 1063
    0x1.00000000000046a403d9fdd4f3642059p0,
    0x1.46b9c347764a4p3
  },
  { // Entry 1064
    -0x1.00000000000046a403d9fdd4f3642059p0,
    -0x1.46b9c347764a4p3
  },
  { // Entry 1065
    0x1.9c78eea78baa6e13eccc94c421c4f5acp48,
    0x1.5fdbbe9bba774p3
  },
  { // Entry 1066
    -0x1.9c78eea78baa6e13eccc94c421c4f5acp48,
    -0x1.5fdbbe9bba774p3
  },
  { // Entry 1067
    0x1.093c3b4aebeb0806fbe4a1f0c660ba3bp51,
    0x1.5fdbbe9bba775p3
  },
  { // Entry 1068
    -0x1.093c3b4aebeb0806fbe4a1f0c660ba3bp51,
    -0x1.5fdbbe9bba775p3
  },
  { // Entry 1069
    -0x1.516ac961421855fb759fc2facb4e9f5bp49,
    0x1.5fdbbe9bba776p3
  },
  { // Entry 1070
    0x1.516ac961421855fb759fc2facb4e9f5bp49,
    -0x1.5fdbbe9bba776p3
  },
  { // Entry 1071
    -0x1.000000000001c22f0f3f8c5aa5a01da3p0,
    0x1.78fdb9effea45p3
  },
  { // Entry 1072
    0x1.000000000001c22f0f3f8c5aa5a01da3p0,
    -0x1.78fdb9effea45p3
  },
  { // Entry 1073
    -0x1.000000000000c22f0f3f8c5963710e64p0,
    0x1.78fdb9effea46p3
  },
  { // Entry 1074
    0x1.000000000000c22f0f3f8c5963710e64p0,
    -0x1.78fdb9effea46p3
  },
  { // Entry 1075
    -0x1.ffffffffffff845e1e7f18b24283fe49p-1,
    0x1.78fdb9effea47p3
  },
  { // Entry 1076
    0x1.ffffffffffff845e1e7f18b24283fe49p-1,
    -0x1.78fdb9effea47p3
  },
  { // Entry 1077
    0x1.fffffffffffc69fbbb4dd2f4fc88ffa1p-1,
    0x1.ab41b09886fe8p3
  },
  { // Entry 1078
    -0x1.fffffffffffc69fbbb4dd2f4fc88ffa1p-1,
    -0x1.a
```