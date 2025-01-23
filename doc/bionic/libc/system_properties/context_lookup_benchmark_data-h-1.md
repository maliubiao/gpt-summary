Response:
The user is asking for a summary of the functionality of a data file used for benchmarking system property lookups in Android's bionic library.

Here's a plan to address the request:

1. **Identify the core purpose:** The file is used for benchmarking property lookups.
2. **Explain the data structure:** The file lists system properties with their associated security contexts and types.
3. **Highlight the relationship to Android functionality:**  These properties control various aspects of the Android system.
4. **Summarize the types of properties:** Categorize the properties based on the Android subsystems they relate to (e.g., boot, build, USB, etc.).
5. **Focus on the benchmarking aspect:**  Emphasize that this data is used to measure the efficiency of property lookups.
6. **Keep it concise:** Since this is part 2 of the request, avoid repeating detailed explanations from part 1.
这是提供的 `bionic/libc/system_properties/context_lookup_benchmark_data.handroid` 文件的内容，该文件是用于系统属性上下文查找基准测试的数据。

**功能归纳:**

这个文件的主要功能是提供一组预定义的Android系统属性，用于性能测试和基准评估。 具体来说，它包含了一系列键值对，其中：

* **键 (key):**  代表一个Android系统属性的名称，例如 `ro.build.version.sdk` 或 `sys.usb.config`。
* **值 (value):**  描述了该属性的期望安全上下文、类型（例如 `string`, `int`, `bool`, `enum`）以及是否为精确匹配 (`exact`) 或前缀匹配 (`prefix`)。

这个文件的目的是创建一个用于测试 `libc` 中系统属性查找性能的静态数据集。 通过加载和查询这些预定义的属性，可以衡量属性查找操作的效率。

**与 Android 功能的关系举例:**

文件中的每个属性都对应着Android系统的特定功能或配置。以下是一些例子：

* **`ro.build.version.sdk u:object_r:build_prop:s0 exact int`**:  这个属性代表设备的Android SDK版本。它被Android Framework和应用程序用于确定设备的API级别，从而判断哪些功能可用。例如，一个应用可能检查这个属性来决定是否可以使用特定的新的API。
* **`sys.usb.config u:object_r:usb_control_prop:s0 exact string`**: 这个属性用于配置USB功能，例如将设备设置为MTP（媒体传输协议）或PTP（图片传输协议）模式。当用户连接USB线时，系统会读取并设置这个属性来控制USB的行为。
* **`wifi.interface u:object_r:wifi_hal_prop:s0 exact string`**: 这个属性指示当前活动的WiFi接口名称。 WiFi服务会读取这个属性来确定与哪个网络接口进行交互。
* **`persist.sys.locale u:object_r:exported_system_prop:s0 exact string`**: 这个属性存储了用户设置的系统语言环境。 Android Framework 会读取这个属性来显示正确的本地化文本。
* **`init.svc.zygote u:object_r:init_service_status_prop:s0 exact string`**: 这个属性指示 `zygote` 进程的当前状态（例如，是否正在运行）。Android的进程管理机制会监控这些 `init.svc.*` 属性来管理系统服务的生命周期。

**总结:**

总而言之，`context_lookup_benchmark_data.handroid` 文件是一个静态的系统属性数据库，它定义了一系列具有安全上下文和类型信息的属性。这个文件的核心功能是作为基准测试的输入数据，用于评估 Android 系统中系统属性查找的性能。 文件中的每个条目都代表了 Android 操作系统中一个具体的配置或状态，影响着系统的各个方面。 通过使用这个文件进行测试，开发者可以了解属性查找机制的效率，并在必要时进行优化。

### 提示词
```
这是目录为bionic/libc/system_properties/context_lookup_benchmark_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
ragemanager_config_prop:s0 exact bool

ro.vehicle.hal u:object_r:vehicle_hal_prop:s0 exact string

ro.vendor.build.security_patch u:object_r:vendor_security_patch_level_prop:s0 exact string

ro.zram.mark_idle_delay_mins    u:object_r:zram_config_prop:s0 exact int
ro.zram.first_wb_delay_mins     u:object_r:zram_config_prop:s0 exact int
ro.zram.periodic_wb_delay_hours u:object_r:zram_config_prop:s0 exact int
zram.force_writeback            u:object_r:zram_config_prop:s0 exact bool
persist.sys.zram_enabled        u:object_r:zram_control_prop:s0 exact bool

sendbug.preferred.domain u:object_r:sendbug_config_prop:s0 exact string

persist.sys.usb.usbradio.config u:object_r:usb_control_prop:s0 exact string

sys.usb.config     u:object_r:usb_control_prop:s0 exact string
sys.usb.configfs   u:object_r:usb_control_prop:s0 exact int
sys.usb.controller u:object_r:usb_control_prop:s0 exact string
sys.usb.state      u:object_r:usb_control_prop:s0 exact string

sys.usb.mtp.device_type u:object_r:usb_config_prop:s0 exact int

sys.usb.config. u:object_r:usb_prop:s0

sys.usb.ffs.aio_compat u:object_r:ffs_config_prop:s0 exact bool
sys.usb.ffs.max_read   u:object_r:ffs_config_prop:s0 exact int
sys.usb.ffs.max_write  u:object_r:ffs_config_prop:s0 exact int

sys.usb.ffs.ready     u:object_r:ffs_control_prop:s0 exact bool
sys.usb.ffs.mtp.ready u:object_r:ffs_control_prop:s0 exact bool

tombstoned.max_tombstone_count u:object_r:tombstone_config_prop:s0 exact int

vold.post_fs_data_done u:object_r:vold_config_prop:s0 exact int

apexd.status u:object_r:apexd_prop:s0 exact enum starting activated ready

dev.bootcomplete   u:object_r:boot_status_prop:s0 exact bool
sys.boot_completed u:object_r:boot_status_prop:s0 exact bool

persist.sys.device_provisioned u:object_r:provisioned_prop:s0 exact string

persist.sys.theme               u:object_r:theme_prop:s0 exact string

sys.retaildemo.enabled u:object_r:retaildemo_prop:s0 exact int

sys.user.0.ce_available u:object_r:exported3_system_prop:s0 exact bool

aac_drc_boost            u:object_r:aac_drc_prop:s0 exact int
aac_drc_cut              u:object_r:aac_drc_prop:s0 exact int
aac_drc_enc_target_level u:object_r:aac_drc_prop:s0 exact int
aac_drc_heavy            u:object_r:aac_drc_prop:s0 exact int
aac_drc_reference_level  u:object_r:aac_drc_prop:s0 exact int
ro.aac_drc_effect_type   u:object_r:aac_drc_prop:s0 exact int

build.version.extensions. u:object_r:module_sdkextensions_prop:s0 prefix int

drm.64bit.enabled            u:object_r:mediadrm_config_prop:s0 exact bool
media.mediadrmservice.enable u:object_r:mediadrm_config_prop:s0 exact bool

drm.service.enabled u:object_r:drm_service_config_prop:s0 exact bool

dumpstate.dry_run u:object_r:exported_dumpstate_prop:s0 exact bool
dumpstate.unroot  u:object_r:exported_dumpstate_prop:s0 exact bool
persist.dumpstate.verbose_logging.enabled u:object_r:hal_dumpstate_config_prop:s0 exact bool

hal.instrumentation.enable u:object_r:hal_instrumentation_prop:s0 exact bool

# default contexts only accessible by coredomain
init.svc. u:object_r:init_service_status_private_prop:s0 prefix string

# vendor-init-readable init service props
init.svc.bugreport      u:object_r:init_service_status_prop:s0 exact string
init.svc.bugreportd     u:object_r:init_service_status_prop:s0 exact string
init.svc.console        u:object_r:init_service_status_prop:s0 exact string
init.svc.dumpstatez     u:object_r:init_service_status_prop:s0 exact string
init.svc.mediadrm       u:object_r:init_service_status_prop:s0 exact string
init.svc.statsd         u:object_r:init_service_status_prop:s0 exact string
init.svc.surfaceflinger u:object_r:init_service_status_prop:s0 exact string
init.svc.tombstoned     u:object_r:init_service_status_prop:s0 exact string
init.svc.zygote         u:object_r:init_service_status_prop:s0 exact string

libc.debug.malloc.options u:object_r:libc_debug_prop:s0 exact string
libc.debug.malloc.program u:object_r:libc_debug_prop:s0 exact string
libc.debug.hooks.enable   u:object_r:libc_debug_prop:s0 exact string

net.redirect_socket_calls.hooked u:object_r:socket_hook_prop:s0 exact bool

persist.sys.locale       u:object_r:exported_system_prop:s0 exact string
persist.sys.timezone     u:object_r:exported_system_prop:s0 exact string
persist.sys.test_harness u:object_r:test_harness_prop:s0 exact bool

ro.arch u:object_r:build_prop:s0 exact string

# ro.boot. properties are set based on kernel commandline arguments, which are vendor owned.
ro.boot.                   u:object_r:bootloader_prop:s0
ro.boot.avb_version        u:object_r:bootloader_prop:s0 exact string
ro.boot.baseband           u:object_r:bootloader_prop:s0 exact string
ro.boot.bootdevice         u:object_r:bootloader_prop:s0 exact string
ro.boot.bootloader         u:object_r:bootloader_prop:s0 exact string
ro.boot.boottime           u:object_r:bootloader_prop:s0 exact string
ro.boot.console            u:object_r:bootloader_prop:s0 exact string
ro.boot.hardware           u:object_r:bootloader_prop:s0 exact string
ro.boot.hardware.color     u:object_r:bootloader_prop:s0 exact string
ro.boot.hardware.sku       u:object_r:bootloader_prop:s0 exact string
ro.boot.keymaster          u:object_r:bootloader_prop:s0 exact string
ro.boot.mode               u:object_r:bootloader_prop:s0 exact string
ro.boot.revision           u:object_r:bootloader_prop:s0 exact string
ro.boot.vbmeta.avb_version u:object_r:bootloader_prop:s0 exact string
ro.boot.verifiedbootstate  u:object_r:bootloader_prop:s0 exact string
ro.boot.veritymode         u:object_r:bootloader_prop:s0 exact string

# These ro.X properties are set to values of ro.boot.X by property_service.
ro.baseband   u:object_r:bootloader_prop:s0 exact string
ro.bootloader u:object_r:bootloader_prop:s0 exact string
ro.bootmode   u:object_r:bootloader_prop:s0 exact string
ro.hardware   u:object_r:bootloader_prop:s0 exact string
ro.revision   u:object_r:bootloader_prop:s0 exact string

ro.boot.dynamic_partitions          u:object_r:exported_default_prop:s0 exact string
ro.boot.dynamic_partitions_retrofit u:object_r:exported_default_prop:s0 exact string

ro.build.date                        u:object_r:build_prop:s0 exact string
ro.build.date.utc                    u:object_r:build_prop:s0 exact int
ro.build.description                 u:object_r:build_prop:s0 exact string
ro.build.display.id                  u:object_r:build_prop:s0 exact string
ro.build.host                        u:object_r:build_prop:s0 exact string
ro.build.id                          u:object_r:build_prop:s0 exact string
ro.build.product                     u:object_r:build_prop:s0 exact string
ro.build.system_root_image           u:object_r:build_prop:s0 exact bool
ro.build.tags                        u:object_r:build_prop:s0 exact string
ro.build.type                        u:object_r:build_prop:s0 exact string
ro.build.user                        u:object_r:build_prop:s0 exact string
ro.build.version.base_os             u:object_r:build_prop:s0 exact string
ro.build.version.codename            u:object_r:build_prop:s0 exact string
ro.build.version.incremental         u:object_r:build_prop:s0 exact string
ro.build.version.preview_sdk         u:object_r:build_prop:s0 exact int
ro.build.version.release             u:object_r:build_prop:s0 exact string
ro.build.version.release_or_codename u:object_r:build_prop:s0 exact string
ro.build.version.sdk                 u:object_r:build_prop:s0 exact int
ro.build.version.security_patch      u:object_r:build_prop:s0 exact string

ro.debuggable u:object_r:build_prop:s0 exact bool

ro.product.cpu.abi       u:object_r:build_prop:s0 exact string
ro.product.cpu.abilist   u:object_r:build_prop:s0 exact string
ro.product.cpu.abilist32 u:object_r:build_prop:s0 exact string
ro.product.cpu.abilist64 u:object_r:build_prop:s0 exact string

ro.adb.secure u:object_r:build_prop:s0 exact bool
ro.secure     u:object_r:build_prop:s0 exact int

# These 5 properties are set by property_service
ro.product.brand         u:object_r:build_prop:s0 exact string
ro.product.device        u:object_r:build_prop:s0 exact string
ro.product.manufacturer  u:object_r:build_prop:s0 exact string
ro.product.model         u:object_r:build_prop:s0 exact string
ro.product.name          u:object_r:build_prop:s0 exact string

# Sanitizer properties
ro.sanitize.address          u:object_r:build_prop:s0 exact bool
ro.sanitize.cfi              u:object_r:build_prop:s0 exact bool
ro.sanitize.default-ub       u:object_r:build_prop:s0 exact bool
ro.sanitize.fuzzer           u:object_r:build_prop:s0 exact bool
ro.sanitize.hwaddress        u:object_r:build_prop:s0 exact bool
ro.sanitize.integer_overflow u:object_r:build_prop:s0 exact bool
ro.sanitize.safe-stack       u:object_r:build_prop:s0 exact bool
ro.sanitize.scudo            u:object_r:build_prop:s0 exact bool
ro.sanitize.thread           u:object_r:build_prop:s0 exact bool
ro.sanitize.undefined        u:object_r:build_prop:s0 exact bool

# All odm build props are set by /odm/build.prop
ro.odm.build.date                u:object_r:build_odm_prop:s0 exact string
ro.odm.build.date.utc            u:object_r:build_odm_prop:s0 exact int
ro.odm.build.fingerprint         u:object_r:build_odm_prop:s0 exact string
ro.odm.build.version.incremental u:object_r:build_odm_prop:s0 exact string

ro.product.odm.brand        u:object_r:build_odm_prop:s0 exact string
ro.product.odm.device       u:object_r:build_odm_prop:s0 exact string
ro.product.odm.manufacturer u:object_r:build_odm_prop:s0 exact string
ro.product.odm.model        u:object_r:build_odm_prop:s0 exact string
ro.product.odm.name         u:object_r:build_odm_prop:s0 exact string

# All vendor_dlkm build props are set by /vendor_dlkm/etc/build.prop
ro.vendor_dlkm.build.date                u:object_r:build_vendor_prop:s0 exact string
ro.vendor_dlkm.build.date.utc            u:object_r:build_vendor_prop:s0 exact int
ro.vendor_dlkm.build.fingerprint         u:object_r:build_vendor_prop:s0 exact string
ro.vendor_dlkm.build.version.incremental u:object_r:build_vendor_prop:s0 exact string

# All odm_dlkm build props are set by /odm_dlkm/etc/build.prop
ro.odm_dlkm.build.date                u:object_r:build_vendor_prop:s0 exact string
ro.odm_dlkm.build.date.utc            u:object_r:build_vendor_prop:s0 exact int
ro.odm_dlkm.build.fingerprint         u:object_r:build_vendor_prop:s0 exact string
ro.odm_dlkm.build.version.incremental u:object_r:build_vendor_prop:s0 exact string

# All vendor build props are set by /vendor/build.prop
ro.vendor.build.date                u:object_r:build_vendor_prop:s0 exact string
ro.vendor.build.date.utc            u:object_r:build_vendor_prop:s0 exact int
ro.vendor.build.fingerprint         u:object_r:build_vendor_prop:s0 exact string
ro.vendor.build.version.incremental u:object_r:build_vendor_prop:s0 exact string
ro.vendor.build.version.sdk         u:object_r:build_vendor_prop:s0 exact int

ro.product.board               u:object_r:build_vendor_prop:s0 exact string
ro.product.first_api_level     u:object_r:build_vendor_prop:s0 exact int
ro.product.vendor.brand        u:object_r:build_vendor_prop:s0 exact string
ro.product.vendor.device       u:object_r:build_vendor_prop:s0 exact string
ro.product.vendor.manufacturer u:object_r:build_vendor_prop:s0 exact string
ro.product.vendor.model        u:object_r:build_vendor_prop:s0 exact string
ro.product.vendor.name         u:object_r:build_vendor_prop:s0 exact string

ro.crypto.state u:object_r:vold_status_prop:s0 exact enum encrypted unencrypted unsupported
ro.crypto.type  u:object_r:vold_status_prop:s0 exact enum block file none

ro.property_service.version u:object_r:property_service_version_prop:s0 exact int

ro.vendor.redirect_socket_calls u:object_r:vendor_socket_hook_prop:s0 exact bool

service.bootanim.exit u:object_r:exported_system_prop:s0 exact int

sys.init.userspace_reboot.in_progress u:object_r:userspace_reboot_exported_prop:s0 exact bool
sys.use_memfd                         u:object_r:use_memfd_prop:s0 exact bool

vold.decrypt u:object_r:vold_status_prop:s0 exact string

aaudio.hw_burst_min_usec     u:object_r:aaudio_config_prop:s0 exact int
aaudio.minimum_sleep_usec    u:object_r:aaudio_config_prop:s0 exact int
aaudio.mixer_bursts          u:object_r:aaudio_config_prop:s0 exact int
aaudio.mmap_exclusive_policy u:object_r:aaudio_config_prop:s0 exact int
aaudio.mmap_policy           u:object_r:aaudio_config_prop:s0 exact int
aaudio.wakeup_delay_usec     u:object_r:aaudio_config_prop:s0 exact int

persist.rcs.supported u:object_r:exported_default_prop:s0 exact int

ro.bionic.2nd_arch        u:object_r:cpu_variant_prop:s0 exact string
ro.bionic.2nd_cpu_variant u:object_r:cpu_variant_prop:s0 exact string
ro.bionic.arch            u:object_r:cpu_variant_prop:s0 exact string
ro.bionic.cpu_variant     u:object_r:cpu_variant_prop:s0 exact string

ro.board.platform u:object_r:exported_default_prop:s0 exact string

ro.boot.fake_battery         u:object_r:exported_default_prop:s0 exact int
ro.boot.fstab_suffix         u:object_r:exported_default_prop:s0 exact string
ro.boot.hardware.revision    u:object_r:exported_default_prop:s0 exact string
ro.boot.product.hardware.sku u:object_r:exported_default_prop:s0 exact string
ro.boot.product.vendor.sku   u:object_r:exported_default_prop:s0 exact string
ro.boot.slot_suffix          u:object_r:exported_default_prop:s0 exact string

ro.boringcrypto.hwrand u:object_r:exported_default_prop:s0 exact bool

ro.build.ab_update         u:object_r:exported_default_prop:s0 exact string
ro.build.expect.baseband   u:object_r:exported_default_prop:s0 exact string
ro.build.expect.bootloader u:object_r:exported_default_prop:s0 exact string

ro.carrier u:object_r:exported_default_prop:s0 exact string

ro.config.low_ram           u:object_r:exported_config_prop:s0 exact bool
ro.config.vc_call_vol_steps u:object_r:exported_config_prop:s0 exact int

ro.frp.pst u:object_r:exported_default_prop:s0 exact string

ro.hardware.activity_recognition u:object_r:exported_default_prop:s0 exact string
ro.hardware.audio                u:object_r:exported_default_prop:s0 exact string
ro.hardware.audio.a2dp           u:object_r:exported_default_prop:s0 exact string
ro.hardware.audio.hearing_aid    u:object_r:exported_default_prop:s0 exact string
ro.hardware.audio.primary        u:object_r:exported_default_prop:s0 exact string
ro.hardware.audio.usb            u:object_r:exported_default_prop:s0 exact string
ro.hardware.audio_policy         u:object_r:exported_default_prop:s0 exact string
ro.hardware.bootctrl             u:object_r:exported_default_prop:s0 exact string
ro.hardware.camera               u:object_r:exported_default_prop:s0 exact string
ro.hardware.consumerir           u:object_r:exported_default_prop:s0 exact string
ro.hardware.context_hub          u:object_r:exported_default_prop:s0 exact string
ro.hardware.egl                  u:object_r:exported_default_prop:s0 exact string
ro.hardware.fingerprint          u:object_r:exported_default_prop:s0 exact string
ro.hardware.flp                  u:object_r:exported_default_prop:s0 exact string
ro.hardware.gatekeeper           u:object_r:exported_default_prop:s0 exact string
ro.hardware.gps                  u:object_r:exported_default_prop:s0 exact string
ro.hardware.gralloc              u:object_r:exported_default_prop:s0 exact string
ro.hardware.hdmi_cec             u:object_r:exported_default_prop:s0 exact string
ro.hardware.hwcomposer           u:object_r:exported_default_prop:s0 exact string
ro.hardware.input                u:object_r:exported_default_prop:s0 exact string
ro.hardware.keystore             u:object_r:exported_default_prop:s0 exact string
ro.hardware.keystore_desede      u:object_r:exported_default_prop:s0 exact string
ro.hardware.lights               u:object_r:exported_default_prop:s0 exact string
ro.hardware.local_time           u:object_r:exported_default_prop:s0 exact string
ro.hardware.memtrack             u:object_r:exported_default_prop:s0 exact string
ro.hardware.nfc                  u:object_r:exported_default_prop:s0 exact string
ro.hardware.nfc_nci              u:object_r:exported_default_prop:s0 exact string
ro.hardware.nfc_tag              u:object_r:exported_default_prop:s0 exact string
ro.hardware.nvram                u:object_r:exported_default_prop:s0 exact string
ro.hardware.power                u:object_r:exported_default_prop:s0 exact string
ro.hardware.radio                u:object_r:exported_default_prop:s0 exact string
ro.hardware.sensors              u:object_r:exported_default_prop:s0 exact string
ro.hardware.sound_trigger        u:object_r:exported_default_prop:s0 exact string
ro.hardware.thermal              u:object_r:exported_default_prop:s0 exact string
ro.hardware.tv_input             u:object_r:exported_default_prop:s0 exact string
ro.hardware.type                 u:object_r:exported_default_prop:s0 exact string
ro.hardware.vehicle              u:object_r:exported_default_prop:s0 exact string
ro.hardware.vibrator             u:object_r:exported_default_prop:s0 exact string
ro.hardware.virtual_device       u:object_r:exported_default_prop:s0 exact string
ro.hardware.vulkan               u:object_r:exported_default_prop:s0 exact string

ro.hwui.use_vulkan u:object_r:exported_default_prop:s0 exact bool

ro.kernel.qemu             u:object_r:exported_default_prop:s0 exact bool
ro.kernel.qemu.            u:object_r:exported_default_prop:s0
ro.kernel.android.bootanim u:object_r:exported_default_prop:s0 exact int

ro.oem.key1 u:object_r:exported_default_prop:s0 exact string

ro.product.vndk.version u:object_r:vndk_prop:s0 exact string

ro.vndk.lite    u:object_r:vndk_prop:s0 exact bool
ro.vndk.version u:object_r:vndk_prop:s0 exact string

ro.vts.coverage u:object_r:vts_config_prop:s0 exact int

vts.native_server.on u:object_r:vts_status_prop:s0 exact bool

wifi.active.interface     u:object_r:wifi_hal_prop:s0 exact string
wifi.aware.interface      u:object_r:wifi_hal_prop:s0 exact string
wifi.concurrent.interface u:object_r:wifi_hal_prop:s0 exact string
wifi.direct.interface     u:object_r:wifi_hal_prop:s0 exact string
wifi.interface            u:object_r:wifi_hal_prop:s0 exact string
wlan.driver.status        u:object_r:wifi_hal_prop:s0 exact enum ok unloaded

ro.boot.wificountrycode u:object_r:wifi_config_prop:s0 exact string

ro.apex.updatable u:object_r:exported_default_prop:s0 exact bool

# Property to enable incremental feature
ro.incremental.enable      u:object_r:incremental_prop:s0

# Properties to configure userspace reboot.
init.userspace_reboot.is_supported u:object_r:userspace_reboot_config_prop:s0 exact bool
init.userspace_reboot.sigkill.timeoutmillis u:object_r:userspace_reboot_config_prop:s0 exact int
init.userspace_reboot.sigterm.timeoutmillis u:object_r:userspace_reboot_config_prop:s0 exact int
init.userspace_reboot.started.timeoutmillis u:object_r:userspace_reboot_config_prop:s0 exact int
init.userspace_reboot.userdata_remount.timeoutmillis u:object_r:userspace_reboot_config_prop:s0 exact int
init.userspace_reboot.watchdog.timeoutmillis u:object_r:userspace_reboot_config_prop:s0 exact int

sys.shutdown.requested u:object_r:exported_system_prop:s0 exact string

# surfaceflinger properties
ro.surface_flinger.default_composition_dataspace          u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.default_composition_pixel_format       u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.force_hwc_copy_for_virtual_displays    u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.has_HDR_display                        u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.has_wide_color_display                 u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.max_frame_buffer_acquired_buffers      u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.max_graphics_height                    u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.max_graphics_width                     u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.max_virtual_display_dimension          u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.primary_display_orientation            u:object_r:surfaceflinger_prop:s0 exact enum ORIENTATION_0 ORIENTATION_180 ORIENTATION_270 ORIENTATION_90
ro.surface_flinger.present_time_offset_from_vsync_ns      u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.running_without_sync_framework         u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.start_graphics_allocator_service       u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.use_color_management                   u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.use_context_priority                   u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.use_vr_flinger                         u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.vsync_event_phase_offset_ns            u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.vsync_sf_event_phase_offset_ns         u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.wcg_composition_dataspace              u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.wcg_composition_pixel_format           u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.display_primary_red                    u:object_r:surfaceflinger_prop:s0 exact string
ro.surface_flinger.display_primary_green                  u:object_r:surfaceflinger_prop:s0 exact string
ro.surface_flinger.display_primary_blue                   u:object_r:surfaceflinger_prop:s0 exact string
ro.surface_flinger.display_primary_white                  u:object_r:surfaceflinger_prop:s0 exact string
ro.surface_flinger.protected_contents                     u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.set_idle_timer_ms                      u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.set_touch_timer_ms                     u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.set_display_power_timer_ms             u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.support_kernel_idle_timer              u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.use_smart_90_for_video                 u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.use_content_detection_for_refresh_rate u:object_r:surfaceflinger_prop:s0 exact bool
ro.surface_flinger.color_space_agnostic_dataspace         u:object_r:surfaceflinger_prop:s0 exact int
ro.surface_flinger.refresh_rate_switching                 u:object_r:surfaceflinger_prop:s0 exact bool

ro.sf.disable_triple_buffer u:object_r:surfaceflinger_prop:s0 exact bool
ro.sf.lcd_density           u:object_r:surfaceflinger_prop:s0 exact int

persist.sys.sf.color_mode       u:object_r:surfaceflinger_color_prop:s0 exact int
persist.sys.sf.color_saturation u:object_r:surfaceflinger_color_prop:s0 exact string
persist.sys.sf.native_mode      u:object_r:surfaceflinger_color_prop:s0 exact int

# Binder cache properties.  These are world-readable
cache_key.app_inactive                   u:object_r:binder_cache_system_server_prop:s0
cache_key.is_compat_change_enabled       u:object_r:binder_cache_system_server_prop:s0
cache_key.get_packages_for_uid           u:object_r:binder_cache_system_server_prop:s0
cache_key.has_system_feature             u:object_r:binder_cache_system_server_prop:s0
cache_key.is_interactive                 u:object_r:binder_cache_system_server_prop:s0
cache_key.is_power_save_mode             u:object_r:binder_cache_system_server_prop:s0
cache_key.is_user_unlocked               u:object_r:binder_cache_system_server_prop:s0
cache_key.volume_list                    u:object_r:binder_cache_system_server_prop:s0
cache_key.display_info                   u:object_r:binder_cache_system_server_prop:s0
cache_key.location_enabled               u:object_r:binder_cache_system_server_prop:s0
cache_key.package_info                   u:object_r:binder_cache_system_server_prop:s0

cache_key.bluetooth.                     u:object_r:binder_cache_bluetooth_server_prop:s0 prefix string
cache_key.system_server.                 u:object_r:binder_cache_system_server_prop:s0 prefix string
cache_key.telephony.                     u:object_r:binder_cache_telephony_server_prop:s0 prefix string

gsm.sim.operator.numeric       u:object_r:telephony_status_prop:s0 exact string
persist.radio.airplane_mode_on u:object_r:telephony_status_prop:s0 exact bool

ro.com.android.dataroaming        u:object_r:telephony_config_prop:s0 exact bool
ro.com.android.prov_mobiledata    u:object_r:telephony_config_prop:s0 exact bool
ro.radio.noril                    u:object_r:telephony_config_prop:s0 exact string
ro.telephony.call_ring.multiple   u:object_r:telephony_config_prop:s0 exact bool
ro.telephony.default_cdma_sub     u:object_r:telephony_config_prop:s0 exact int
ro.telephony.default_network      u:object_r:telephony_config_prop:s0 exact string
ro.telephony.iwlan_operation_mode u:object_r:telephony_config_prop:s0 exact enum default legacy AP-assisted
telephony.active_modems.max_count u:object_r:telephony_config_prop:s0 exact int
telephony.lteOnCdmaDevice         u:object_r:telephony_config_prop:s0 exact int
persist.dbg.volte_avail_ovr       u:object_r:telephony_config_prop:s0 exact int
persist.dbg.vt_avail_ovr          u:object_r:telephony_config_prop:s0 exact int
persist.dbg.wfc_avail_ovr         u:object_r:telephony_config_prop:s0 exact int

# System locale list filter configuration
ro.localization.locale_filter u:object_r:localization_prop:s0 exact string

# Graphics related properties
ro.opengles.version u:object_r:graphics_config_prop:s0 exact int

ro.gfx.driver.0        u:object_r:graphics_config_prop:s0 exact string
ro.gfx.driver.1        u:object_r:graphics_config_prop:s0 exact string
ro.gfx.angle.supported u:object_r:graphics_config_prop:s0 exact bool

graphics.gpu.profiler.support          u:object_r:graphics_config_prop:s0 exact bool
graphics.gpu.profiler.vulkan_layer_apk u:object_r:graphics_config_prop:s0 exact string
    )";
```