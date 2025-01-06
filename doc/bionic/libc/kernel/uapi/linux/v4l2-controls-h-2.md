Response:
The user wants a summary of the provided C header file. This file defines structures and constants related to V4L2 (Video4Linux2) controls, specifically for video codecs like HEVC, VP9, and AV1. It seems to be part of the Android Bionic library.

Here's a breakdown of how to address the prompt:

1. **Identify the main purpose:** The file defines structures and constants for controlling video codec parameters within the V4L2 framework.
2. **List the key functionalities:**  Focus on the types of controls defined (HEVC, VP9, AV1 related parameters, HDR metadata).
3. **Relate to Android:** Explain how these controls are relevant to Android's multimedia framework (camera, video playback).
4. **Explain libc functions (not applicable here):** This file mainly defines data structures and macros, not libc functions.
5. **Explain dynamic linker functionality (not applicable here):** No dynamic linking is involved in this header file.
6. **Provide examples of logical reasoning (not directly applicable):** The content is declarative. However, we can infer the purpose of the structures and flags.
7. **Mention common user/programming errors:** Incorrectly setting control values can lead to decoding issues or unexpected behavior.
8. **Explain how Android framework/NDK reaches here:**  Describe the path from Android's media APIs down to the kernel V4L2 drivers.
9. **Give Frida hook examples:** Demonstrate how to inspect and modify these control values at runtime.
10. **Summarize the functionality:**  Provide a concise overview of the file's purpose.
这是目录为 `bionic/libc/kernel/uapi/linux/v4l2-controls.handroid bionic` 的源代码文件的第三部分，延续了前两部分的内容，主要定义了用于控制视频编解码器（特别是 HEVC, VP9 和 AV1）参数的结构体和宏定义。由于是第三部分，它继续完善了前面定义的概念，并引入了新的编解码器相关的控制。

**功能归纳:**

该文件的主要功能是为 Android 系统中使用的 V4L2 框架定义了用于控制硬件视频编解码器的各种参数。 这些参数涵盖了不同的视频编解码标准，包括：

* **HEVC (H.265):** 定义了序列参数集 (SPS)、图像参数集 (PPS)、解码图像缓冲区 (DPB)、预测权重表、以及条带参数的控制结构。
* **VP9:** 定义了环路滤波、量化、分段、帧级别参数以及压缩头部信息的控制结构。
* **AV1:** 定义了序列、瓦片组、全局运动、环路恢复、约束方向增强滤波 (CDEF)、分段、环路滤波、量化、瓦片信息、帧级别参数以及电影颗粒的控制结构。
* **色彩信息 (Colorimetry):** 定义了 HDR10 的内容光照级别信息 (CLL) 和母带显示器信息。

**与 Android 功能的关系及举例说明:**

这些定义直接关系到 Android 设备的摄像头和视频编解码能力。Android 的多媒体框架需要与底层的硬件编解码器交互，而这些结构体和宏定义就是交互的接口。

* **摄像头预览和录制:** 当 Android 应用使用 Camera API 进行预览或录制视频时，框架会使用 V4L2 接口与摄像头驱动进行通信。驱动会读取或设置这些控制参数，例如 HEVC 的 SPS 和 PPS，来配置编码器如何压缩视频数据。
* **视频解码:** 当 Android 设备播放 HEVC、VP9 或 AV1 格式的视频时，解码器需要知道如何解析和解码比特流。这些控制结构（例如 AV1 的帧级别参数）会被用来传递解码所需的配置信息。
* **HDR 支持:**  `v4l2_ctrl_hdr10_cll_info` 和 `v4l2_ctrl_hdr10_mastering_display` 结构体定义了 HDR10 元数据，这对于支持高动态范围视频的显示至关重要。Android 系统会读取这些信息来正确渲染 HDR 内容。

**libc 函数的功能实现:**

这个头文件本身并没有实现任何 libc 函数。它只是定义了数据结构和宏，供其他 C/C++ 代码使用。

**dynamic linker 的功能 (不适用):**

这个头文件不涉及动态链接。它定义的是静态的数据结构和宏。

**逻辑推理 (不适用):**

这个文件主要是声明性的，没有复杂的逻辑推理。

**用户或编程常见的使用错误举例:**

* **控制参数取值错误:**  例如，设置了一个超出 HEVC 规范允许范围的 `log2_max_pic_order_cnt_lsb_minus4` 值，可能会导致编码或解码失败。
* **不正确的标志位使用:** 错误地设置了 VP9 的 `V4L2_VP9_FRAME_FLAG_KEY_FRAME` 标志，可能会导致解码器无法正确识别关键帧。
* **对编解码器特性的误解:** 假设所有设备都支持 AV1 的所有特性，并在控制结构中使用了某些标志，但在不支持的硬件上运行会导致错误。

**Android framework 或 NDK 如何到达这里，给出 Frida hook 示例:**

1. **Android Framework (Java 层):**
   -  应用程序使用 `android.hardware.camera2` 或 `android.media` 等 API 进行视频录制或播放。
   -  Framework 层会将这些请求转换为底层的操作。

2. **MediaCodec (Java/Native 桥接):**
   -  `MediaCodec` 类负责编解码操作。它在 Native 层有对应的实现。

3. **libstagefright (Native 层):**
   -  `libstagefright` 是 Android 的多媒体框架的核心部分。它会调用硬件编解码器的接口。

4. **V4L2 接口 (Kernel 驱动):**
   -  `libstagefright` 通过 ioctl 系统调用与 V4L2 驱动进行交互。
   -  传递给 ioctl 的参数会涉及到这里定义的结构体，例如 `v4l2_control` 结构体，其 `value` 字段可能包含这些编解码器特定的结构体数据。

**Frida Hook 示例:**

假设我们要 hook 设置 HEVC SPS 的过程，可以尝试以下 Frida 脚本：

```javascript
// 假设我们知道相关的 ioctl 命令，例如 VIDIOC_S_CTRL
const VIDIOC_S_CTRL = 0x40085601; // 示例值，可能需要根据具体 Android 版本和驱动调整

Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
  onEnter: function(args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();

    if (request === VIDIOC_S_CTRL) {
      const v4l2_ctrl_ptr = ptr(args[2]);
      const id = v4l2_ctrl_ptr.readU32();

      // 假设 HEVC SPS 的 control ID 是一个特定的值，例如 V4L2_CID_STATELESS_HEVC_SPS
      const V4L2_CID_STATELESS_HEVC_SPS = 0xXXXXXXXX; // 需要替换为实际值

      if (id === V4L2_CID_STATELESS_HEVC_SPS) {
        console.log("ioctl called with VIDIOC_S_CTRL and HEVC SPS data!");
        const sps_data_ptr = v4l2_ctrl_ptr.add(4); // 假设 value 字段紧跟 id
        const sps = sps_data_ptr.readByteArray(100); // 读取部分 SPS 数据，大小需要根据实际情况调整
        console.log("HEVC SPS Data:", hexdump(sps));

        // 可以修改 SPS 的值
        // sps_data_ptr.writeU8(newValue);
      }
    }
  },
  onLeave: function(retval) {}
});
```

**重要提示:**

* **ioctl 命令和 Control ID:**  `VIDIOC_S_CTRL` 和 `V4L2_CID_STATELESS_HEVC_SPS` 的实际值可能需要根据具体的 Android 版本、设备和摄像头驱动进行查找。可以使用 `adb logcat` 或反编译相关库来找到这些值。
* **结构体偏移:**  示例中假设 `value` 字段紧跟 `id`，实际情况可能需要根据 `v4l2_control` 结构体的定义进行调整。
* **权限:**  Hook 系统调用可能需要 root 权限。

**总结:**

这个头文件的第三部分延续了前两部分的功能，为 Android 系统中 V4L2 框架下 HEVC、VP9 和 AV1 视频编解码器的控制提供了详细的结构体和宏定义。 这些定义是 Android 多媒体框架与底层硬件交互的关键，直接影响着摄像头、视频播放等功能。理解这些定义对于进行底层的多媒体开发和调试至关重要。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/v4l2-controls.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
AG_STRONG_INTRA_SMOOTHING_ENABLED (1ULL << 8)
struct v4l2_ctrl_hevc_sps {
  __u8 video_parameter_set_id;
  __u8 seq_parameter_set_id;
  __u16 pic_width_in_luma_samples;
  __u16 pic_height_in_luma_samples;
  __u8 bit_depth_luma_minus8;
  __u8 bit_depth_chroma_minus8;
  __u8 log2_max_pic_order_cnt_lsb_minus4;
  __u8 sps_max_dec_pic_buffering_minus1;
  __u8 sps_max_num_reorder_pics;
  __u8 sps_max_latency_increase_plus1;
  __u8 log2_min_luma_coding_block_size_minus3;
  __u8 log2_diff_max_min_luma_coding_block_size;
  __u8 log2_min_luma_transform_block_size_minus2;
  __u8 log2_diff_max_min_luma_transform_block_size;
  __u8 max_transform_hierarchy_depth_inter;
  __u8 max_transform_hierarchy_depth_intra;
  __u8 pcm_sample_bit_depth_luma_minus1;
  __u8 pcm_sample_bit_depth_chroma_minus1;
  __u8 log2_min_pcm_luma_coding_block_size_minus3;
  __u8 log2_diff_max_min_pcm_luma_coding_block_size;
  __u8 num_short_term_ref_pic_sets;
  __u8 num_long_term_ref_pics_sps;
  __u8 chroma_format_idc;
  __u8 sps_max_sub_layers_minus1;
  __u8 reserved[6];
  __u64 flags;
};
#define V4L2_HEVC_PPS_FLAG_DEPENDENT_SLICE_SEGMENT_ENABLED (1ULL << 0)
#define V4L2_HEVC_PPS_FLAG_OUTPUT_FLAG_PRESENT (1ULL << 1)
#define V4L2_HEVC_PPS_FLAG_SIGN_DATA_HIDING_ENABLED (1ULL << 2)
#define V4L2_HEVC_PPS_FLAG_CABAC_INIT_PRESENT (1ULL << 3)
#define V4L2_HEVC_PPS_FLAG_CONSTRAINED_INTRA_PRED (1ULL << 4)
#define V4L2_HEVC_PPS_FLAG_TRANSFORM_SKIP_ENABLED (1ULL << 5)
#define V4L2_HEVC_PPS_FLAG_CU_QP_DELTA_ENABLED (1ULL << 6)
#define V4L2_HEVC_PPS_FLAG_PPS_SLICE_CHROMA_QP_OFFSETS_PRESENT (1ULL << 7)
#define V4L2_HEVC_PPS_FLAG_WEIGHTED_PRED (1ULL << 8)
#define V4L2_HEVC_PPS_FLAG_WEIGHTED_BIPRED (1ULL << 9)
#define V4L2_HEVC_PPS_FLAG_TRANSQUANT_BYPASS_ENABLED (1ULL << 10)
#define V4L2_HEVC_PPS_FLAG_TILES_ENABLED (1ULL << 11)
#define V4L2_HEVC_PPS_FLAG_ENTROPY_CODING_SYNC_ENABLED (1ULL << 12)
#define V4L2_HEVC_PPS_FLAG_LOOP_FILTER_ACROSS_TILES_ENABLED (1ULL << 13)
#define V4L2_HEVC_PPS_FLAG_PPS_LOOP_FILTER_ACROSS_SLICES_ENABLED (1ULL << 14)
#define V4L2_HEVC_PPS_FLAG_DEBLOCKING_FILTER_OVERRIDE_ENABLED (1ULL << 15)
#define V4L2_HEVC_PPS_FLAG_PPS_DISABLE_DEBLOCKING_FILTER (1ULL << 16)
#define V4L2_HEVC_PPS_FLAG_LISTS_MODIFICATION_PRESENT (1ULL << 17)
#define V4L2_HEVC_PPS_FLAG_SLICE_SEGMENT_HEADER_EXTENSION_PRESENT (1ULL << 18)
#define V4L2_HEVC_PPS_FLAG_DEBLOCKING_FILTER_CONTROL_PRESENT (1ULL << 19)
#define V4L2_HEVC_PPS_FLAG_UNIFORM_SPACING (1ULL << 20)
struct v4l2_ctrl_hevc_pps {
  __u8 pic_parameter_set_id;
  __u8 num_extra_slice_header_bits;
  __u8 num_ref_idx_l0_default_active_minus1;
  __u8 num_ref_idx_l1_default_active_minus1;
  __s8 init_qp_minus26;
  __u8 diff_cu_qp_delta_depth;
  __s8 pps_cb_qp_offset;
  __s8 pps_cr_qp_offset;
  __u8 num_tile_columns_minus1;
  __u8 num_tile_rows_minus1;
  __u8 column_width_minus1[20];
  __u8 row_height_minus1[22];
  __s8 pps_beta_offset_div2;
  __s8 pps_tc_offset_div2;
  __u8 log2_parallel_merge_level_minus2;
  __u8 reserved;
  __u64 flags;
};
#define V4L2_HEVC_DPB_ENTRY_LONG_TERM_REFERENCE 0x01
#define V4L2_HEVC_SEI_PIC_STRUCT_FRAME 0
#define V4L2_HEVC_SEI_PIC_STRUCT_TOP_FIELD 1
#define V4L2_HEVC_SEI_PIC_STRUCT_BOTTOM_FIELD 2
#define V4L2_HEVC_SEI_PIC_STRUCT_TOP_BOTTOM 3
#define V4L2_HEVC_SEI_PIC_STRUCT_BOTTOM_TOP 4
#define V4L2_HEVC_SEI_PIC_STRUCT_TOP_BOTTOM_TOP 5
#define V4L2_HEVC_SEI_PIC_STRUCT_BOTTOM_TOP_BOTTOM 6
#define V4L2_HEVC_SEI_PIC_STRUCT_FRAME_DOUBLING 7
#define V4L2_HEVC_SEI_PIC_STRUCT_FRAME_TRIPLING 8
#define V4L2_HEVC_SEI_PIC_STRUCT_TOP_PAIRED_PREVIOUS_BOTTOM 9
#define V4L2_HEVC_SEI_PIC_STRUCT_BOTTOM_PAIRED_PREVIOUS_TOP 10
#define V4L2_HEVC_SEI_PIC_STRUCT_TOP_PAIRED_NEXT_BOTTOM 11
#define V4L2_HEVC_SEI_PIC_STRUCT_BOTTOM_PAIRED_NEXT_TOP 12
#define V4L2_HEVC_DPB_ENTRIES_NUM_MAX 16
struct v4l2_hevc_dpb_entry {
  __u64 timestamp;
  __u8 flags;
  __u8 field_pic;
  __u16 reserved;
  __s32 pic_order_cnt_val;
};
struct v4l2_hevc_pred_weight_table {
  __s8 delta_luma_weight_l0[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __s8 luma_offset_l0[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __s8 delta_chroma_weight_l0[V4L2_HEVC_DPB_ENTRIES_NUM_MAX][2];
  __s8 chroma_offset_l0[V4L2_HEVC_DPB_ENTRIES_NUM_MAX][2];
  __s8 delta_luma_weight_l1[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __s8 luma_offset_l1[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __s8 delta_chroma_weight_l1[V4L2_HEVC_DPB_ENTRIES_NUM_MAX][2];
  __s8 chroma_offset_l1[V4L2_HEVC_DPB_ENTRIES_NUM_MAX][2];
  __u8 luma_log2_weight_denom;
  __s8 delta_chroma_log2_weight_denom;
};
#define V4L2_HEVC_SLICE_PARAMS_FLAG_SLICE_SAO_LUMA (1ULL << 0)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_SLICE_SAO_CHROMA (1ULL << 1)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_SLICE_TEMPORAL_MVP_ENABLED (1ULL << 2)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_MVD_L1_ZERO (1ULL << 3)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_CABAC_INIT (1ULL << 4)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_COLLOCATED_FROM_L0 (1ULL << 5)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_USE_INTEGER_MV (1ULL << 6)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_SLICE_DEBLOCKING_FILTER_DISABLED (1ULL << 7)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_SLICE_LOOP_FILTER_ACROSS_SLICES_ENABLED (1ULL << 8)
#define V4L2_HEVC_SLICE_PARAMS_FLAG_DEPENDENT_SLICE_SEGMENT (1ULL << 9)
struct v4l2_ctrl_hevc_slice_params {
  __u32 bit_size;
  __u32 data_byte_offset;
  __u32 num_entry_point_offsets;
  __u8 nal_unit_type;
  __u8 nuh_temporal_id_plus1;
  __u8 slice_type;
  __u8 colour_plane_id;
  __s32 slice_pic_order_cnt;
  __u8 num_ref_idx_l0_active_minus1;
  __u8 num_ref_idx_l1_active_minus1;
  __u8 collocated_ref_idx;
  __u8 five_minus_max_num_merge_cand;
  __s8 slice_qp_delta;
  __s8 slice_cb_qp_offset;
  __s8 slice_cr_qp_offset;
  __s8 slice_act_y_qp_offset;
  __s8 slice_act_cb_qp_offset;
  __s8 slice_act_cr_qp_offset;
  __s8 slice_beta_offset_div2;
  __s8 slice_tc_offset_div2;
  __u8 pic_struct;
  __u8 reserved0[3];
  __u32 slice_segment_addr;
  __u8 ref_idx_l0[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __u8 ref_idx_l1[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __u16 short_term_ref_pic_set_size;
  __u16 long_term_ref_pic_set_size;
  struct v4l2_hevc_pred_weight_table pred_weight_table;
  __u8 reserved1[2];
  __u64 flags;
};
#define V4L2_HEVC_DECODE_PARAM_FLAG_IRAP_PIC 0x1
#define V4L2_HEVC_DECODE_PARAM_FLAG_IDR_PIC 0x2
#define V4L2_HEVC_DECODE_PARAM_FLAG_NO_OUTPUT_OF_PRIOR 0x4
struct v4l2_ctrl_hevc_decode_params {
  __s32 pic_order_cnt_val;
  __u16 short_term_ref_pic_set_size;
  __u16 long_term_ref_pic_set_size;
  __u8 num_active_dpb_entries;
  __u8 num_poc_st_curr_before;
  __u8 num_poc_st_curr_after;
  __u8 num_poc_lt_curr;
  __u8 poc_st_curr_before[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __u8 poc_st_curr_after[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __u8 poc_lt_curr[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __u8 num_delta_pocs_of_ref_rps_idx;
  __u8 reserved[3];
  struct v4l2_hevc_dpb_entry dpb[V4L2_HEVC_DPB_ENTRIES_NUM_MAX];
  __u64 flags;
};
struct v4l2_ctrl_hevc_scaling_matrix {
  __u8 scaling_list_4x4[6][16];
  __u8 scaling_list_8x8[6][64];
  __u8 scaling_list_16x16[6][64];
  __u8 scaling_list_32x32[2][64];
  __u8 scaling_list_dc_coef_16x16[6];
  __u8 scaling_list_dc_coef_32x32[2];
};
#define V4L2_CID_COLORIMETRY_CLASS_BASE (V4L2_CTRL_CLASS_COLORIMETRY | 0x900)
#define V4L2_CID_COLORIMETRY_CLASS (V4L2_CTRL_CLASS_COLORIMETRY | 1)
#define V4L2_CID_COLORIMETRY_HDR10_CLL_INFO (V4L2_CID_COLORIMETRY_CLASS_BASE + 0)
struct v4l2_ctrl_hdr10_cll_info {
  __u16 max_content_light_level;
  __u16 max_pic_average_light_level;
};
#define V4L2_CID_COLORIMETRY_HDR10_MASTERING_DISPLAY (V4L2_CID_COLORIMETRY_CLASS_BASE + 1)
#define V4L2_HDR10_MASTERING_PRIMARIES_X_LOW 5
#define V4L2_HDR10_MASTERING_PRIMARIES_X_HIGH 37000
#define V4L2_HDR10_MASTERING_PRIMARIES_Y_LOW 5
#define V4L2_HDR10_MASTERING_PRIMARIES_Y_HIGH 42000
#define V4L2_HDR10_MASTERING_WHITE_POINT_X_LOW 5
#define V4L2_HDR10_MASTERING_WHITE_POINT_X_HIGH 37000
#define V4L2_HDR10_MASTERING_WHITE_POINT_Y_LOW 5
#define V4L2_HDR10_MASTERING_WHITE_POINT_Y_HIGH 42000
#define V4L2_HDR10_MASTERING_MAX_LUMA_LOW 50000
#define V4L2_HDR10_MASTERING_MAX_LUMA_HIGH 100000000
#define V4L2_HDR10_MASTERING_MIN_LUMA_LOW 1
#define V4L2_HDR10_MASTERING_MIN_LUMA_HIGH 50000
struct v4l2_ctrl_hdr10_mastering_display {
  __u16 display_primaries_x[3];
  __u16 display_primaries_y[3];
  __u16 white_point_x;
  __u16 white_point_y;
  __u32 max_display_mastering_luminance;
  __u32 min_display_mastering_luminance;
};
#define V4L2_VP9_LOOP_FILTER_FLAG_DELTA_ENABLED 0x1
#define V4L2_VP9_LOOP_FILTER_FLAG_DELTA_UPDATE 0x2
struct v4l2_vp9_loop_filter {
  __s8 ref_deltas[4];
  __s8 mode_deltas[2];
  __u8 level;
  __u8 sharpness;
  __u8 flags;
  __u8 reserved[7];
};
struct v4l2_vp9_quantization {
  __u8 base_q_idx;
  __s8 delta_q_y_dc;
  __s8 delta_q_uv_dc;
  __s8 delta_q_uv_ac;
  __u8 reserved[4];
};
#define V4L2_VP9_SEGMENTATION_FLAG_ENABLED 0x01
#define V4L2_VP9_SEGMENTATION_FLAG_UPDATE_MAP 0x02
#define V4L2_VP9_SEGMENTATION_FLAG_TEMPORAL_UPDATE 0x04
#define V4L2_VP9_SEGMENTATION_FLAG_UPDATE_DATA 0x08
#define V4L2_VP9_SEGMENTATION_FLAG_ABS_OR_DELTA_UPDATE 0x10
#define V4L2_VP9_SEG_LVL_ALT_Q 0
#define V4L2_VP9_SEG_LVL_ALT_L 1
#define V4L2_VP9_SEG_LVL_REF_FRAME 2
#define V4L2_VP9_SEG_LVL_SKIP 3
#define V4L2_VP9_SEG_LVL_MAX 4
#define V4L2_VP9_SEGMENT_FEATURE_ENABLED(id) (1 << (id))
#define V4L2_VP9_SEGMENT_FEATURE_ENABLED_MASK 0xf
struct v4l2_vp9_segmentation {
  __s16 feature_data[8][4];
  __u8 feature_enabled[8];
  __u8 tree_probs[7];
  __u8 pred_probs[3];
  __u8 flags;
  __u8 reserved[5];
};
#define V4L2_VP9_FRAME_FLAG_KEY_FRAME 0x001
#define V4L2_VP9_FRAME_FLAG_SHOW_FRAME 0x002
#define V4L2_VP9_FRAME_FLAG_ERROR_RESILIENT 0x004
#define V4L2_VP9_FRAME_FLAG_INTRA_ONLY 0x008
#define V4L2_VP9_FRAME_FLAG_ALLOW_HIGH_PREC_MV 0x010
#define V4L2_VP9_FRAME_FLAG_REFRESH_FRAME_CTX 0x020
#define V4L2_VP9_FRAME_FLAG_PARALLEL_DEC_MODE 0x040
#define V4L2_VP9_FRAME_FLAG_X_SUBSAMPLING 0x080
#define V4L2_VP9_FRAME_FLAG_Y_SUBSAMPLING 0x100
#define V4L2_VP9_FRAME_FLAG_COLOR_RANGE_FULL_SWING 0x200
#define V4L2_VP9_SIGN_BIAS_LAST 0x1
#define V4L2_VP9_SIGN_BIAS_GOLDEN 0x2
#define V4L2_VP9_SIGN_BIAS_ALT 0x4
#define V4L2_VP9_RESET_FRAME_CTX_NONE 0
#define V4L2_VP9_RESET_FRAME_CTX_SPEC 1
#define V4L2_VP9_RESET_FRAME_CTX_ALL 2
#define V4L2_VP9_INTERP_FILTER_EIGHTTAP 0
#define V4L2_VP9_INTERP_FILTER_EIGHTTAP_SMOOTH 1
#define V4L2_VP9_INTERP_FILTER_EIGHTTAP_SHARP 2
#define V4L2_VP9_INTERP_FILTER_BILINEAR 3
#define V4L2_VP9_INTERP_FILTER_SWITCHABLE 4
#define V4L2_VP9_REFERENCE_MODE_SINGLE_REFERENCE 0
#define V4L2_VP9_REFERENCE_MODE_COMPOUND_REFERENCE 1
#define V4L2_VP9_REFERENCE_MODE_SELECT 2
#define V4L2_VP9_PROFILE_MAX 3
#define V4L2_CID_STATELESS_VP9_FRAME (V4L2_CID_CODEC_STATELESS_BASE + 300)
struct v4l2_ctrl_vp9_frame {
  struct v4l2_vp9_loop_filter lf;
  struct v4l2_vp9_quantization quant;
  struct v4l2_vp9_segmentation seg;
  __u32 flags;
  __u16 compressed_header_size;
  __u16 uncompressed_header_size;
  __u16 frame_width_minus_1;
  __u16 frame_height_minus_1;
  __u16 render_width_minus_1;
  __u16 render_height_minus_1;
  __u64 last_frame_ts;
  __u64 golden_frame_ts;
  __u64 alt_frame_ts;
  __u8 ref_frame_sign_bias;
  __u8 reset_frame_context;
  __u8 frame_context_idx;
  __u8 profile;
  __u8 bit_depth;
  __u8 interpolation_filter;
  __u8 tile_cols_log2;
  __u8 tile_rows_log2;
  __u8 reference_mode;
  __u8 reserved[7];
};
#define V4L2_VP9_NUM_FRAME_CTX 4
struct v4l2_vp9_mv_probs {
  __u8 joint[3];
  __u8 sign[2];
  __u8 classes[2][10];
  __u8 class0_bit[2];
  __u8 bits[2][10];
  __u8 class0_fr[2][2][3];
  __u8 fr[2][3];
  __u8 class0_hp[2];
  __u8 hp[2];
};
#define V4L2_CID_STATELESS_VP9_COMPRESSED_HDR (V4L2_CID_CODEC_STATELESS_BASE + 301)
#define V4L2_VP9_TX_MODE_ONLY_4X4 0
#define V4L2_VP9_TX_MODE_ALLOW_8X8 1
#define V4L2_VP9_TX_MODE_ALLOW_16X16 2
#define V4L2_VP9_TX_MODE_ALLOW_32X32 3
#define V4L2_VP9_TX_MODE_SELECT 4
struct v4l2_ctrl_vp9_compressed_hdr {
  __u8 tx_mode;
  __u8 tx8[2][1];
  __u8 tx16[2][2];
  __u8 tx32[2][3];
  __u8 coef[4][2][2][6][6][3];
  __u8 skip[3];
  __u8 inter_mode[7][3];
  __u8 interp_filter[4][2];
  __u8 is_inter[4];
  __u8 comp_mode[5];
  __u8 single_ref[5][2];
  __u8 comp_ref[5];
  __u8 y_mode[4][9];
  __u8 uv_mode[10][9];
  __u8 partition[16][3];
  struct v4l2_vp9_mv_probs mv;
};
#define V4L2_AV1_TOTAL_REFS_PER_FRAME 8
#define V4L2_AV1_CDEF_MAX 8
#define V4L2_AV1_NUM_PLANES_MAX 3
#define V4L2_AV1_MAX_SEGMENTS 8
#define V4L2_AV1_MAX_OPERATING_POINTS (1 << 5)
#define V4L2_AV1_REFS_PER_FRAME 7
#define V4L2_AV1_MAX_NUM_Y_POINTS (1 << 4)
#define V4L2_AV1_MAX_NUM_CB_POINTS (1 << 4)
#define V4L2_AV1_MAX_NUM_CR_POINTS (1 << 4)
#define V4L2_AV1_AR_COEFFS_SIZE 25
#define V4L2_AV1_MAX_NUM_PLANES 3
#define V4L2_AV1_MAX_TILE_COLS 64
#define V4L2_AV1_MAX_TILE_ROWS 64
#define V4L2_AV1_MAX_TILE_COUNT 512
#define V4L2_AV1_SEQUENCE_FLAG_STILL_PICTURE 0x00000001
#define V4L2_AV1_SEQUENCE_FLAG_USE_128X128_SUPERBLOCK 0x00000002
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_FILTER_INTRA 0x00000004
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_INTRA_EDGE_FILTER 0x00000008
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_INTERINTRA_COMPOUND 0x00000010
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_MASKED_COMPOUND 0x00000020
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_WARPED_MOTION 0x00000040
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_DUAL_FILTER 0x00000080
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_ORDER_HINT 0x00000100
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_JNT_COMP 0x00000200
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_REF_FRAME_MVS 0x00000400
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_SUPERRES 0x00000800
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_CDEF 0x00001000
#define V4L2_AV1_SEQUENCE_FLAG_ENABLE_RESTORATION 0x00002000
#define V4L2_AV1_SEQUENCE_FLAG_MONO_CHROME 0x00004000
#define V4L2_AV1_SEQUENCE_FLAG_COLOR_RANGE 0x00008000
#define V4L2_AV1_SEQUENCE_FLAG_SUBSAMPLING_X 0x00010000
#define V4L2_AV1_SEQUENCE_FLAG_SUBSAMPLING_Y 0x00020000
#define V4L2_AV1_SEQUENCE_FLAG_FILM_GRAIN_PARAMS_PRESENT 0x00040000
#define V4L2_AV1_SEQUENCE_FLAG_SEPARATE_UV_DELTA_Q 0x00080000
#define V4L2_CID_STATELESS_AV1_SEQUENCE (V4L2_CID_CODEC_STATELESS_BASE + 500)
struct v4l2_ctrl_av1_sequence {
  __u32 flags;
  __u8 seq_profile;
  __u8 order_hint_bits;
  __u8 bit_depth;
  __u8 reserved;
  __u16 max_frame_width_minus_1;
  __u16 max_frame_height_minus_1;
};
#define V4L2_CID_STATELESS_AV1_TILE_GROUP_ENTRY (V4L2_CID_CODEC_STATELESS_BASE + 501)
struct v4l2_ctrl_av1_tile_group_entry {
  __u32 tile_offset;
  __u32 tile_size;
  __u32 tile_row;
  __u32 tile_col;
};
enum v4l2_av1_warp_model {
  V4L2_AV1_WARP_MODEL_IDENTITY = 0,
  V4L2_AV1_WARP_MODEL_TRANSLATION = 1,
  V4L2_AV1_WARP_MODEL_ROTZOOM = 2,
  V4L2_AV1_WARP_MODEL_AFFINE = 3,
};
enum v4l2_av1_reference_frame {
  V4L2_AV1_REF_INTRA_FRAME = 0,
  V4L2_AV1_REF_LAST_FRAME = 1,
  V4L2_AV1_REF_LAST2_FRAME = 2,
  V4L2_AV1_REF_LAST3_FRAME = 3,
  V4L2_AV1_REF_GOLDEN_FRAME = 4,
  V4L2_AV1_REF_BWDREF_FRAME = 5,
  V4L2_AV1_REF_ALTREF2_FRAME = 6,
  V4L2_AV1_REF_ALTREF_FRAME = 7,
};
#define V4L2_AV1_GLOBAL_MOTION_IS_INVALID(ref) (1 << (ref))
#define V4L2_AV1_GLOBAL_MOTION_FLAG_IS_GLOBAL 0x1
#define V4L2_AV1_GLOBAL_MOTION_FLAG_IS_ROT_ZOOM 0x2
#define V4L2_AV1_GLOBAL_MOTION_FLAG_IS_TRANSLATION 0x4
struct v4l2_av1_global_motion {
  __u8 flags[V4L2_AV1_TOTAL_REFS_PER_FRAME];
  enum v4l2_av1_warp_model type[V4L2_AV1_TOTAL_REFS_PER_FRAME];
  __s32 params[V4L2_AV1_TOTAL_REFS_PER_FRAME][6];
  __u8 invalid;
  __u8 reserved[3];
};
enum v4l2_av1_frame_restoration_type {
  V4L2_AV1_FRAME_RESTORE_NONE = 0,
  V4L2_AV1_FRAME_RESTORE_WIENER = 1,
  V4L2_AV1_FRAME_RESTORE_SGRPROJ = 2,
  V4L2_AV1_FRAME_RESTORE_SWITCHABLE = 3,
};
#define V4L2_AV1_LOOP_RESTORATION_FLAG_USES_LR 0x1
#define V4L2_AV1_LOOP_RESTORATION_FLAG_USES_CHROMA_LR 0x2
struct v4l2_av1_loop_restoration {
  __u8 flags;
  __u8 lr_unit_shift;
  __u8 lr_uv_shift;
  __u8 reserved;
  enum v4l2_av1_frame_restoration_type frame_restoration_type[V4L2_AV1_NUM_PLANES_MAX];
  __u32 loop_restoration_size[V4L2_AV1_MAX_NUM_PLANES];
};
struct v4l2_av1_cdef {
  __u8 damping_minus_3;
  __u8 bits;
  __u8 y_pri_strength[V4L2_AV1_CDEF_MAX];
  __u8 y_sec_strength[V4L2_AV1_CDEF_MAX];
  __u8 uv_pri_strength[V4L2_AV1_CDEF_MAX];
  __u8 uv_sec_strength[V4L2_AV1_CDEF_MAX];
};
#define V4L2_AV1_SEGMENTATION_FLAG_ENABLED 0x1
#define V4L2_AV1_SEGMENTATION_FLAG_UPDATE_MAP 0x2
#define V4L2_AV1_SEGMENTATION_FLAG_TEMPORAL_UPDATE 0x4
#define V4L2_AV1_SEGMENTATION_FLAG_UPDATE_DATA 0x8
#define V4L2_AV1_SEGMENTATION_FLAG_SEG_ID_PRE_SKIP 0x10
enum v4l2_av1_segment_feature {
  V4L2_AV1_SEG_LVL_ALT_Q = 0,
  V4L2_AV1_SEG_LVL_ALT_LF_Y_V = 1,
  V4L2_AV1_SEG_LVL_REF_FRAME = 5,
  V4L2_AV1_SEG_LVL_REF_SKIP = 6,
  V4L2_AV1_SEG_LVL_REF_GLOBALMV = 7,
  V4L2_AV1_SEG_LVL_MAX = 8
};
#define V4L2_AV1_SEGMENT_FEATURE_ENABLED(id) (1 << (id))
struct v4l2_av1_segmentation {
  __u8 flags;
  __u8 last_active_seg_id;
  __u8 feature_enabled[V4L2_AV1_MAX_SEGMENTS];
  __s16 feature_data[V4L2_AV1_MAX_SEGMENTS][V4L2_AV1_SEG_LVL_MAX];
};
#define V4L2_AV1_LOOP_FILTER_FLAG_DELTA_ENABLED 0x1
#define V4L2_AV1_LOOP_FILTER_FLAG_DELTA_UPDATE 0x2
#define V4L2_AV1_LOOP_FILTER_FLAG_DELTA_LF_PRESENT 0x4
#define V4L2_AV1_LOOP_FILTER_FLAG_DELTA_LF_MULTI 0x8
struct v4l2_av1_loop_filter {
  __u8 flags;
  __u8 level[4];
  __u8 sharpness;
  __s8 ref_deltas[V4L2_AV1_TOTAL_REFS_PER_FRAME];
  __s8 mode_deltas[2];
  __u8 delta_lf_res;
};
#define V4L2_AV1_QUANTIZATION_FLAG_DIFF_UV_DELTA 0x1
#define V4L2_AV1_QUANTIZATION_FLAG_USING_QMATRIX 0x2
#define V4L2_AV1_QUANTIZATION_FLAG_DELTA_Q_PRESENT 0x4
struct v4l2_av1_quantization {
  __u8 flags;
  __u8 base_q_idx;
  __s8 delta_q_y_dc;
  __s8 delta_q_u_dc;
  __s8 delta_q_u_ac;
  __s8 delta_q_v_dc;
  __s8 delta_q_v_ac;
  __u8 qm_y;
  __u8 qm_u;
  __u8 qm_v;
  __u8 delta_q_res;
};
#define V4L2_AV1_TILE_INFO_FLAG_UNIFORM_TILE_SPACING 0x1
struct v4l2_av1_tile_info {
  __u8 flags;
  __u8 context_update_tile_id;
  __u8 tile_cols;
  __u8 tile_rows;
  __u32 mi_col_starts[V4L2_AV1_MAX_TILE_COLS + 1];
  __u32 mi_row_starts[V4L2_AV1_MAX_TILE_ROWS + 1];
  __u32 width_in_sbs_minus_1[V4L2_AV1_MAX_TILE_COLS];
  __u32 height_in_sbs_minus_1[V4L2_AV1_MAX_TILE_ROWS];
  __u8 tile_size_bytes;
  __u8 reserved[3];
};
enum v4l2_av1_frame_type {
  V4L2_AV1_KEY_FRAME = 0,
  V4L2_AV1_INTER_FRAME = 1,
  V4L2_AV1_INTRA_ONLY_FRAME = 2,
  V4L2_AV1_SWITCH_FRAME = 3
};
enum v4l2_av1_interpolation_filter {
  V4L2_AV1_INTERPOLATION_FILTER_EIGHTTAP = 0,
  V4L2_AV1_INTERPOLATION_FILTER_EIGHTTAP_SMOOTH = 1,
  V4L2_AV1_INTERPOLATION_FILTER_EIGHTTAP_SHARP = 2,
  V4L2_AV1_INTERPOLATION_FILTER_BILINEAR = 3,
  V4L2_AV1_INTERPOLATION_FILTER_SWITCHABLE = 4,
};
enum v4l2_av1_tx_mode {
  V4L2_AV1_TX_MODE_ONLY_4X4 = 0,
  V4L2_AV1_TX_MODE_LARGEST = 1,
  V4L2_AV1_TX_MODE_SELECT = 2
};
#define V4L2_AV1_FRAME_FLAG_SHOW_FRAME 0x00000001
#define V4L2_AV1_FRAME_FLAG_SHOWABLE_FRAME 0x00000002
#define V4L2_AV1_FRAME_FLAG_ERROR_RESILIENT_MODE 0x00000004
#define V4L2_AV1_FRAME_FLAG_DISABLE_CDF_UPDATE 0x00000008
#define V4L2_AV1_FRAME_FLAG_ALLOW_SCREEN_CONTENT_TOOLS 0x00000010
#define V4L2_AV1_FRAME_FLAG_FORCE_INTEGER_MV 0x00000020
#define V4L2_AV1_FRAME_FLAG_ALLOW_INTRABC 0x00000040
#define V4L2_AV1_FRAME_FLAG_USE_SUPERRES 0x00000080
#define V4L2_AV1_FRAME_FLAG_ALLOW_HIGH_PRECISION_MV 0x00000100
#define V4L2_AV1_FRAME_FLAG_IS_MOTION_MODE_SWITCHABLE 0x00000200
#define V4L2_AV1_FRAME_FLAG_USE_REF_FRAME_MVS 0x00000400
#define V4L2_AV1_FRAME_FLAG_DISABLE_FRAME_END_UPDATE_CDF 0x00000800
#define V4L2_AV1_FRAME_FLAG_ALLOW_WARPED_MOTION 0x00001000
#define V4L2_AV1_FRAME_FLAG_REFERENCE_SELECT 0x00002000
#define V4L2_AV1_FRAME_FLAG_REDUCED_TX_SET 0x00004000
#define V4L2_AV1_FRAME_FLAG_SKIP_MODE_ALLOWED 0x00008000
#define V4L2_AV1_FRAME_FLAG_SKIP_MODE_PRESENT 0x00010000
#define V4L2_AV1_FRAME_FLAG_FRAME_SIZE_OVERRIDE 0x00020000
#define V4L2_AV1_FRAME_FLAG_BUFFER_REMOVAL_TIME_PRESENT 0x00040000
#define V4L2_AV1_FRAME_FLAG_FRAME_REFS_SHORT_SIGNALING 0x00080000
#define V4L2_CID_STATELESS_AV1_FRAME (V4L2_CID_CODEC_STATELESS_BASE + 502)
struct v4l2_ctrl_av1_frame {
  struct v4l2_av1_tile_info tile_info;
  struct v4l2_av1_quantization quantization;
  __u8 superres_denom;
  struct v4l2_av1_segmentation segmentation;
  struct v4l2_av1_loop_filter loop_filter;
  struct v4l2_av1_cdef cdef;
  __u8 skip_mode_frame[2];
  __u8 primary_ref_frame;
  struct v4l2_av1_loop_restoration loop_restoration;
  struct v4l2_av1_global_motion global_motion;
  __u32 flags;
  enum v4l2_av1_frame_type frame_type;
  __u32 order_hint;
  __u32 upscaled_width;
  enum v4l2_av1_interpolation_filter interpolation_filter;
  enum v4l2_av1_tx_mode tx_mode;
  __u32 frame_width_minus_1;
  __u32 frame_height_minus_1;
  __u16 render_width_minus_1;
  __u16 render_height_minus_1;
  __u32 current_frame_id;
  __u32 buffer_removal_time[V4L2_AV1_MAX_OPERATING_POINTS];
  __u8 reserved[4];
  __u32 order_hints[V4L2_AV1_TOTAL_REFS_PER_FRAME];
  __u64 reference_frame_ts[V4L2_AV1_TOTAL_REFS_PER_FRAME];
  __s8 ref_frame_idx[V4L2_AV1_REFS_PER_FRAME];
  __u8 refresh_frame_flags;
};
#define V4L2_AV1_FILM_GRAIN_FLAG_APPLY_GRAIN 0x1
#define V4L2_AV1_FILM_GRAIN_FLAG_UPDATE_GRAIN 0x2
#define V4L2_AV1_FILM_GRAIN_FLAG_CHROMA_SCALING_FROM_LUMA 0x4
#define V4L2_AV1_FILM_GRAIN_FLAG_OVERLAP 0x8
#define V4L2_AV1_FILM_GRAIN_FLAG_CLIP_TO_RESTRICTED_RANGE 0x10
#define V4L2_CID_STATELESS_AV1_FILM_GRAIN (V4L2_CID_CODEC_STATELESS_BASE + 505)
struct v4l2_ctrl_av1_film_grain {
  __u8 flags;
  __u8 cr_mult;
  __u16 grain_seed;
  __u8 film_grain_params_ref_idx;
  __u8 num_y_points;
  __u8 point_y_value[V4L2_AV1_MAX_NUM_Y_POINTS];
  __u8 point_y_scaling[V4L2_AV1_MAX_NUM_Y_POINTS];
  __u8 num_cb_points;
  __u8 point_cb_value[V4L2_AV1_MAX_NUM_CB_POINTS];
  __u8 point_cb_scaling[V4L2_AV1_MAX_NUM_CB_POINTS];
  __u8 num_cr_points;
  __u8 point_cr_value[V4L2_AV1_MAX_NUM_CR_POINTS];
  __u8 point_cr_scaling[V4L2_AV1_MAX_NUM_CR_POINTS];
  __u8 grain_scaling_minus_8;
  __u8 ar_coeff_lag;
  __u8 ar_coeffs_y_plus_128[V4L2_AV1_AR_COEFFS_SIZE];
  __u8 ar_coeffs_cb_plus_128[V4L2_AV1_AR_COEFFS_SIZE];
  __u8 ar_coeffs_cr_plus_128[V4L2_AV1_AR_COEFFS_SIZE];
  __u8 ar_coeff_shift_minus_6;
  __u8 grain_scale_shift;
  __u8 cb_mult;
  __u8 cb_luma_mult;
  __u8 cr_luma_mult;
  __u16 cb_offset;
  __u16 cr_offset;
  __u8 reserved[4];
};
#define V4L2_CTRL_CLASS_MPEG V4L2_CTRL_CLASS_CODEC
#define V4L2_CID_MPEG_CLASS V4L2_CID_CODEC_CLASS
#define V4L2_CID_MPEG_BASE V4L2_CID_CODEC_BASE
#define V4L2_CID_MPEG_CX2341X_BASE V4L2_CID_CODEC_CX2341X_BASE
#define V4L2_CID_MPEG_MFC51_BASE V4L2_CID_CODEC_MFC51_BASE
#endif

"""


```