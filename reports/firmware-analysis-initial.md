# Analisis awal firmware POCO F6

Tanggal pemeriksaan: 5 November 2026  
Paket: `OS3.0.304.0.WNPIDXM`, Indonesia, Android 16, codename `peridot`.

> **Status terbaru uji boot (5 Nov 2026):** Belum boot penuh ke Android/UI. Setelah menambahkan `/soc` ke DTB virtual turunan, kernel stok 6.1.138, first-stage init, second-stage init, serta pemasangan partisi dinamis AVB berhasil berjalan di QEMU. Init menemukan NVMe di jalur yang sesuai konfigurasi POCO dan `mount_all --early` sukses. Guest belum mencapai Zygote atau System Server; beberapa partisi placeholder kosong gagal dipasang dan layanan qseecom berulang kali abort karena layanan Qualcomm tidak tersedia. Run terbaru berhenti pada batas 240 detik tanpa kernel panic. Detail konfigurasi, bukti serial, dan rencana diagnosis ada di [laporan perkembangan boot](boot-progress-2026-11-05.md). Catatan dan log lama di bawah merupakan riwayat tahap awal; status exit 127 tersebut sudah tidak mewakili run terbaru. Firmware sumber tetap tidak berubah.

## Integritas file

- Fastboot ROM `.tgz`, 8.726.487.729 byte.
- MD5: `6178d39ec1ebe2323d444fada5516f3b` — cocok dengan nilai yang dipublikasikan untuk paket ini.
- SHA-256: `3e3772c6539ba4387d8c97ea9d2e42c28efa5d1b658db0e80e9ae2a9dbf5efdc`.
- Archive berisi 113 item dengan ukuran total sebelum kompresi 10.736.397.272 byte.
- ROM sumber hanya dibaca; tidak diekstrak atau diubah. Tidak ada image yang di-flash.

## Image yang ditemukan

| Image | Ukuran di archive | Temuan awal |
|---|---:|---|
| `boot.img` | 100.663.296 B | Android boot header v4; kernel 35.432.960 B; ramdisk 0 B. Payload memiliki magic Linux ARM64 `ARM\x64` pada offset standar. String kernel menunjukkan Linux `6.1.138-android14-11-g0c3d559bcd85-ab14529422`. |
| `vendor_boot.img` | 100.663.296 B | Vendor boot header v4; page size 4.096 B; vendor ramdisk 33.004.692 B. Awalan ramdisk menunjukkan kompresi bergaya LZ4. |
| `init_boot.img` | 8.388.608 B | Android boot header v4; kernel 0 B; ramdisk 2.309.006 B. |
| `dtbo.img` | 20.971.520 B | Image berawalan magic DT table (`d7 b7 ab 1e`). Device tree belum diekstrak/didekode. |
| `super.img` | 8.000.661.404 B | Android sparse v1.0; blok 4.096 B; 156 chunks; ukuran expanded 9.126.805.504 B. Metadata partisi logis belum dibaca. |
| `vbmeta.img` | 8.192 B | AVB 1.0, SHA256_RSA2048; rantai berisi `boot`, `recovery`, dan `vbmeta_system`; menandai `init_boot`, `vendor_boot`, dan sejumlah partisi dinamis. |
| `vbmeta_system.img` | 4.096 B | AVB 1.0, SHA256_RSA2048; memuat descriptor hashtree `system`, `system_ext`, dan `product`. |

Archive juga berisi skrip flash untuk perangkat fisik. Skrip tersebut tidak digunakan dan tidak boleh dijalankan untuk investigasi QEMU.

## Kelayakan QEMU saat ini

Status: **firmware stock belum terbukti dapat boot di QEMU `virt`; kemungkinan perlu kernel/ramdisk dan integrasi platform yang berbeda.** `boot.img` membawa kernel ARM64 tetapi tidak membawa ramdisk. `vendor_boot.img` dan `init_boot.img` membawa ramdisk terpisah. Header saja belum menunjukkan bahwa kernel menyediakan UART PL011, GIC/PSCI yang diharapkan, virtio block, atau device tree QEMU.

QEMU `virt` adalah platform virtual generik, bukan emulasi board/SoC Xiaomi. Karena itu, arsitektur ARM64 yang cocok belum cukup untuk menjalankan kernel, DTB, HAL, dan layanan vendor POCO F6. Dokumentasi QEMU menjelaskan bahwa image yang ditujukan untuk satu board ARM biasanya tidak berjalan pada board lain tanpa dukungan platform yang sesuai: [QEMU ARM system emulator](https://www.qemu.org/docs/master/system/target-arm.html).

Konfigurasi kernel tertanam berhasil didekode dari blob gzip `IKCFG_ST`/`IKCFG_ED` (205.452 byte). Opsi yang relevan:

- Aktif: `CONFIG_SERIAL_AMBA_PL011_CONSOLE`, `CONFIG_ARM_GIC_V3`, `CONFIG_ARM_PSCI_FW`, `CONFIG_PCI`, `CONFIG_PCI_HOST_GENERIC`, `CONFIG_BLK_DEV_NVME`, `CONFIG_NVME_CORE`, `CONFIG_EROFS_FS`, dan `CONFIG_F2FS_FS`.
- Tidak aktif: `CONFIG_VIRTIO_BLK`, `CONFIG_VIRTIO_PCI`, dan `CONFIG_VIRTIO_MMIO`.
- Kernel config berisi baris built-in `console=ttynull`, tetapi mengizinkan argumen bootloader ditambahkan (`CONFIG_CMDLINE_EXTEND=y`).

Karena itu, storage QEMU melalui NVMe PCI lebih menjanjikan untuk diuji daripada virtio block. QEMU `virt` memiliki PCIe; kernel ini mengaktifkan generic PCI host dan NVMe. Jalur ini tetap membutuhkan penyesuaian first-stage fstab dan pembuktian bahwa kernel/DTB dapat mulai.

Ramdisk `vendor_boot` berisi `first_stage_ramdisk/fstab.qcom`, daftar modul Qualcomm/SoC (`ufs_qcom`, `pinctrl-pineapple`, `clk-qcom`, `msm_geni_serial`, `msm_drm`, Gunyah, dan lainnya), serta path partisi `/dev/block/bootdevice/by-name/...`. Fstab memasang `system`, `system_ext`, `product`, dan `mi_ext` sebagai partisi logical dengan AVB pada first stage; modem, DSP, Bluetooth firmware, userdata, dan metadata juga merujuk nama partisi fisik Xiaomi. Ini hambatan nyata pada layout QEMU.

Metadata `super.img` berhasil dibaca langsung dari Android sparse stream. LP metadata version 10.2, 3 slot metadata, logical block 4096 B, satu block device `super` berukuran 9.126.805.504 B. Group `qti_dynamic_partitions_a` memuat partisi `_a` aktif; partisi `_b` tercatat berukuran nol. Ukuran logical aktif: `system_a` 716.955.648 B, `system_ext_a` 630.308.864 B, `vendor_a` 430.030.848 B, `product_a` 3.420.237.824 B, `odm_a` 1.915.416.576 B, `mi_ext_a` 865.320.960 B, `system_dlkm_a` 14.934.016 B, dan `vendor_dlkm_a` 30.294.016 B.

### Uji host QEMU

- QEMU 11.1.0 terpasang di `D:\git\HyperOS-QEMU-Lab\tools\qemu\qemu-system-aarch64.exe`.
- QEMU mengenali mesin `virt` (alias `virt-11.1`). Preflight `virt`, CPU `max`, RAM 4 GiB berhasil membuat DTB valid di `analysis/qemu-virt.dtb` (FDT magic `0xd00dfeed`). Ini memvalidasi QEMU dan konfigurasi mesin, **bukan** boot Android.
- Host terdeteksi Windows 10, Ryzen 5 7535HS, 12 logical processor, RAM fisik sekitar 7,2 GiB. Build ini hanya menawarkan akselerator `tcg`; belum ada akselerasi hardware untuk guest ARM64. Multi-threaded TCG adalah optimisasi emulasi yang tersedia, namun tidak mengatasi ketidakcocokan driver atau SoC.
- Belum ada boot Android penuh atau perubahan `boot.img`. Parameter guest 4 GiB berada di bawah total RAM host, tetapi menyisakan kira-kira 3,2 GiB untuk Windows dan proses host; eksperimen diagnosis saat ini memakai 2 GiB RAM dan 2 vCPU.
- Log QEMU menunjukkan urutan command line efektif: built-in `console=ttynull ...` kemudian argumen eksternal `console=ttyAMA0,115200 earlycon=pl011,mmio32,0x9000000 ...`. Dengan `CONFIG_CMDLINE_EXTEND=y`, kedua bagian tampak dalam log tersebut dan serial PL011 tetap mengeluarkan pesan.
- Uji tanpa initrd: log lengkap mencapai panic rootfs sekitar 3,12 detik guest-time.
- `init_boot` ramdisk sendiri memuat `/init`, tetapi tidak menyertakan fstab QCOM. Dengan vendor ramdisk, stok `modules.load` memuat `gunyah_qcom` yang fatal di QEMU. Skrip `tools/make_qemu_virt_ramdisk.ps1` membuat salinan CPIO untuk eksperimen dengan baris modul Gunyah dikecualikan; sumber CPIO tidak berubah.
- `tools/build_qemu_test_disk.ps1` membuat disk kerja sparse 16 GiB dengan GPT, salinan partisi boot, metadata, vbmeta, dan `super`; Android sparse `super.img` serta `metadata.img` diekspansi ke ukuran logis ketika dimasukkan. NVMe PCI ditemukan sebagai `/dev/block/nvme0n1` dengan 10 partisi GPT. Menetapkan `androidboot.boot_devices=4010000000.pcie` membuat nama `/dev/block/by-name` dikenali dan init menemukan `super`.
- `tools/run_qemu_stage2.ps1` menjalankan eksperimen 2 GiB/2 vCPU dan membuat overlay QCOW2 baru di atas raw disk dasar supaya percobaan tidak menulis ke disk dasar.
- Init berhasil membaca metadata LP dari `super` dan membuat device-mapper untuk `odm_a`, `product_a`, dan `system_a`. Uji paling akhir mengecualikan baris metadata dari fstab salinan karena image metadata pada tahap uji sebelumnya menuntut `resize.f2fs`, yang tidak tersedia dalam ramdisk. CPIO kerja juga melewati semua modul vendor agar driver Qualcomm tidak mengganggu; partisi sistem tetap memakai flag AVB dari fstab.
- Setelah `system_a` dibuat, PID 1 keluar dengan kode 127 lalu kernel panic. Log tidak mengungkap apakah gagal verifikasi AVB, mount EROFS, atau `exec` ke `/system/bin/init`; jangan simpulkan penyebabnya sebelum mendapatkan log tahap pertama yang lebih rinci. **Belum ada boot framework/UI.**
- `avbtool.py` dari AOSP `platform/external/avb` membaca struktur AVB secara offline. Pemeriksaan signature RSA/SHA-256 pada kedua vbmeta berhasil dengan key tertanam; public-key SHA-1 `vbmeta_system` cocok dengan key descriptor rantai parent (`cb646ab4d06eb30d6b9602b8ea0148e9bf354dd5`). Root digest yang dihitung dari payload EROFS dan seluruh byte hashtree `system_a` cocok dengan descriptor `vbmeta_system`; payload dan tree `vendor_a` juga cocok dengan descriptor `vbmeta`. Ini memvalidasi konsistensi internal untuk kedua partisi, bukan autentikasi root-of-trust Xiaomi dari sumber independen. Hashtree partisi lainnya belum dibandingkan.
- Metadata AVB mengonfirmasi campuran generasi: `system`, `system_ext`, dan `product` ber-OS version 16; descriptor `vendor`, `odm`, `vendor_boot`, dan `init_boot` mengidentifikasi Android 14. EROFS `system` membenarkan Android 16/API 36; EROFS `vendor` membenarkan Android 14/API 34. Ini risiko kompatibilitas framework/vendor yang harus diperiksa lewat VINTF dan properti filesystem.
- Parser EROFS offline berhasil membaca dan mendekompresi `system/bin/init`, `system/bin/bootstrap/linker64`, `system/build.prop`, dan `vendor/build.prop` dari salinan `system_a`/`vendor_a`. Semua library langsung yang tercatat pada `DT_NEEDED` untuk system init ditemukan di image system. Ini memastikan berkas EROFS ada dan dapat didekode host; belum membuktikan kernel guest berhasil memasang EROFS atau dynamic linker berhasil menjalankan init.

## Yang belum diperiksa

- VINTF penuh, properti tambahan, serta analisis layanan init dari partisi EROFS.
- Menangkap sebab PID 1 keluar 127 setelah pemetaan `system_a`; menilai AVB dan mount EROFS tanpa mematikan verifikasi secara luas.
- Analisis penuh DTBO serta kecocokan hashtree AVB terhadap image partisi; pemeriksaan signature/rantai internal sudah lolos.
- Boot Android penuh/framework belum tercapai; QEMU hanya menyediakan TCG.

## Batas penggunaan

Paket ini hanya untuk analisis offline. Jangan jalankan skrip `flash_all*.bat`/`.sh`, jangan ubah firmware perangkat, dan jangan menonaktifkan AVB, dm-verity, atau SELinux secara membabi buta. Target QEMU yang direncanakan: `virt`, RAM 4 GiB, disk virtual 16 GiB.
