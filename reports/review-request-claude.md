# Permintaan review teknis: HyperOS POCO F6 di QEMU ARM64 virt

Tolong lakukan review teknis independen atas proyek reverse-engineering dan virtualisasi berikut. Prioritaskan analisis yang dapat dibuktikan dan langkah eksperimen yang bisa dijalankan pada Windows. Jangan menganggap ROM pasti dapat boot.

## Tujuan

Menilai dan, bila realistis, mengadaptasi firmware HyperOS resmi POCO F6 (peridot) agar bisa mencapai tahap boot yang dapat diamati di QEMU AArch64 dengan mesin virt. Host proyek adalah laptop Windows 10, AMD Ryzen 5 7535HS, 12 logical processor, RAM fisik sekitar 7,2 GiB. Target awal guest 4 GiB RAM dan disk virtual 16 GiB.

Pengguna ingin eksperimen dilakukan di laptop Windows melalui QEMU. Fokus modifikasi yang dibicarakan adalah boot.img bila perubahan kernel/boot image memang dibutuhkan. Firmware sumber wajib dipertahankan. Tidak boleh ada flashing atau perubahan pada ponsel fisik.

## Paket ROM dan integritas

- Model/codename: POCO F6 / peridot; ROM Indonesia.
- Paket: OS3.0.304.0.WNPIDXM.
- Arsip: peridot_id_global_images_OS3.0.304.0.WNPIDXM_20260721.0000.00_16.0_id_6178d39ec1 (1).tgz.
- Ukuran: 8.726.487.729 byte.
- MD5 terhitung cocok dengan checksum paket: 6178d39ec1ebe2323d444fada5516f3b.
- SHA-256: 3e3772c6539ba4387d8c97ea9d2e42c28efa5d1b658db0e80e9ae2a9dbf5efdc.
- Arsip sumber hanya dibaca; tidak ada image yang di-flash.

Ada perbedaan metadata yang perlu diverifikasi: metadata/nama paket menyebut Android 16.0, tetapi system/etc/ramdisk/build.prop dari ramdisk init_boot melaporkan Android 14 / API 34 dan fingerprint POCO/peridot_global/peridot:14/UKQ1.240624.001/OS3.0.304.0.WNPIDXM:user/release-keys. Mohon sarankan properti/artifact lain yang sebaiknya diperiksa untuk memastikan versi platform sebenarnya.

## Hasil pemeriksaan image

- boot.img: Android boot header v4, kernel ARM64 35.432.960 byte, ramdisk kosong. Kernel string: 6.1.138-android14-11-g0c3d559bcd85-ab14529422.
- Hash kernel hasil ekstraksi untuk analisis: SHA-256 97b2c53022e8c0bd0b279c4c592a196126a6eb0a93647c2957b39dcd5f2dc1c9.
- vendor_boot.img: header v4, vendor ramdisk 33.004.692 byte, LZ4 legacy. Ramdisk hasil decode berisi 348 CPIO entries.
- init_boot.img: header v4, ramdisk 2.309.006 byte, LZ4 legacy.
- dtbo.img: 20.971.520 byte, Android DT table magic. Payload/overlay belum dianalisis penuh.
- super.img: Android sparse v1.0, expanded 9.126.805.504 byte. Metadata LP v10.2, slot metadata 3, block 4096 byte, satu block device bernama super.
- Partisi logical aktif _a: system_a 716.955.648 B, system_ext_a 630.308.864 B, vendor_a 430.030.848 B, product_a 3.420.237.824 B, odm_a 1.915.416.576 B, mi_ext_a 865.320.960 B, system_dlkm_a 14.934.016 B, vendor_dlkm_a 30.294.016 B. Partisi _b tercatat 0 byte.
- Salinan analisis system_a dan vendor_a diawali magic EROFS 0xe0f5e1e2.
- vbmeta.img memiliki magic AVB0. Rantai AVB belum diverifikasi; jangan menonaktifkan AVB/dm-verity secara membabi buta.

## Temuan kernel dan perangkat virtual

Konfigurasi kernel tertanam ditemukan dan didekode dari blob IKCFG_ST/IKCFG_ED ke analysis/kernel.config.

Opsi penting:

- Aktif: CONFIG_SERIAL_AMBA_PL011_CONSOLE, CONFIG_ARM_GIC_V3, CONFIG_ARM_PSCI_FW, CONFIG_PCI, CONFIG_PCI_HOST_GENERIC, CONFIG_BLK_DEV_NVME, CONFIG_NVME_CORE, CONFIG_EROFS_FS, CONFIG_F2FS_FS.
- Tidak aktif: CONFIG_VIRTIO_BLK, CONFIG_VIRTIO_PCI, CONFIG_VIRTIO_MMIO.
- Built-in command line: console=ttynull stack_depot_disable=on cgroup_disable=pressure kasan.page_alloc.sample=10 kasan.stacktrace=off kvm-arm.mode=protected bootconfig ioremap_guard; CONFIG_CMDLINE_EXTEND=y.

Kernel tampaknya bisa memakai PCI NVMe generik bila QEMU menyajikan disk NVMe. Itu hanya kemungkinan untuk diuji; belum dibuktikan bahwa driver NVMe terdaftar/memuat cukup dini untuk first-stage init.

QEMU 11.1.0 terpasang di D:\git\HyperOS-QEMU-Lab\tools\qemu\qemu-system-aarch64.exe. virt tersedia. Build QEMU pada host hanya melaporkan akselerator tcg, tanpa KVM/HVF/WHPX untuk guest ARM64; TCG multi-thread bisa dipakai, tetapi performanya mungkin lambat. QEMU berhasil membuat DTB virt valid 1 MiB; string DTB mencakup pl011@9000000/arm,pl011.

## Hambatan vendor yang sudah tampak

- vendor_boot berisi first_stage_ramdisk/fstab.qcom.
- Fstab merujuk /dev/block/bootdevice/by-name/... untuk partisi fisik Qualcomm (antara lain modem, DSP, firmware Bluetooth, userdata, metadata) dan mengatur first-stage mount partisi logical seperti system, system_ext, product, mi_ext dengan AVB.
- Daftar modul mencakup banyak dependensi Qualcomm/board nyata seperti ufs_qcom, pinctrl-pineapple, clk-qcom, msm_geni_serial, msm_drm, Gunyah, dan lainnya.
- QEMU virt tidak menyediakan SoC/perangkat POCO itu. Kebutuhan init, HAL, firmware, dan device node bisa mencegah boot framework walaupun kernel hidup.

## Percobaan yang sudah dilakukan

- QEMU virt, CPU max, 2 vCPU, RAM 2 GiB, kernel stok hasil ekstraksi dan argumen earlycon PL011 yang dikutip utuh lewat Windows process launcher. Kernel menghasilkan log serial dan berjalan sekitar 3 detik guest-time, lalu panic `VFS: Unable to mount root fs on unknown-block(0,0)`. Root filesystem memang tidak diberikan; ini membuktikan eksekusi kernel dan console, bukan kegagalan kompatibilitas PL011.
- Dengan `init_boot` CPIO terdekode sebagai `-initrd`, kernel menjalankan Android init tahap pertama. Init mencatat `ReadFstabFromDt(): failed`, `ReadDefaultFstab(): failed to find device default fstab`, kemudian gagal membuat FirstStageMount karena ramdisk itu sendiri tidak menyertakan fstab perangkat.
- Dengan CPIO hasil konkatenasi salinan `init_boot` + `vendor_boot`, init membaca/menemukan ramdisk vendor lalu mulai memuat modul. Sekitar 8,5 detik guest-time kernel mengalami fatal undefined-instruction Oops pada `init_module+0x34/0xfcc [gunyah_qcom]`, kemudian panic. Crash terjadi saat modul vendor POCO dimuat, sebelum bukti first-stage mount.
- Hash SHA-256 CPIO gabungan sementara: AF3B2890925747E9963ACE223CD89DE43B99EBEC963BA4A672A366D8340CA860 (file kerja turunan, 69.888.512 byte; dua CPIO hasil decode dikonkatenasi, sumber tidak disentuh).
- Belum ada Android boot berhasil atau `boot.img` modifikasi. Hasil terbaik sejauh ini: kernel + PL011 + Android init tahap pertama sudah hidup di QEMU; vendor ramdisk stok memuat driver yang crash di platform virt.
- Satu percobaan UART sebelumnya gagal sebelum VM mulai karena opsi tracing QEMU salah format dan satu peluncuran Windows memecah argumen `-append`. Keduanya bukan bukti kernel gagal; eksperimen di atas memakai command line yang diteruskan dengan benar.

## Pertanyaan yang perlu dijawab

1. Dengan bukti di atas, apakah peluang realistisnya hanya mencapai kernel/initramfs, first-stage init, atau framework Android? Jelaskan batas yang paling mungkin dan jangan menjanjikan boot penuh.
2. Apakah benar argumen bootloader dapat menimpa console=ttynull karena CONFIG_CMDLINE_EXTEND=y? Berikan bentuk command line/earlycon PL011 yang tepat untuk kernel ARM64 ini di QEMU virt, dan cara membuktikan kernel menulis ke UART (opsi trace/event QEMU yang benar atau metode alternatif).
3. Apakah raw Image yang diekstrak dari Android boot.img aman diuji dengan QEMU -kernel langsung? Periksa persyaratan boot protocol ARM64 (alamat load/alignment, DTB placement, entry registers, EL, PSCI, Image header flags). Apakah lebih tepat membangun/ubah Android boot image dan mem-boot melalui UEFI/bootloader Android?
4. Apa kombinasi CPU, GIC, PSCI, DTB, RAM, dan command line QEMU yang paling tepat untuk langkah diagnosis ini? Host hanya TCG dan punya sekitar 7,2 GiB RAM; target awal 4 GiB guest.
5. Jalur storage virtual apa yang layak: NVMe PCI, raw disk, atau custom initramfs? Apakah kernel GKI dengan NVMe aktif cukup untuk first-stage mount, dan perubahan fstab apa yang diperlukan tanpa mengubah file sumber?
6. Bagaimana cara aman menyajikan partisi EROFS/dynamic partitions dari sparse super.img ke guest untuk eksperimen? Apakah lebih masuk akal membuat salinan disk turunan dan metadata LP tetap utuh daripada memecah partisi? Beri format dan tata letak konkret, termasuk batas disk virtual 16 GiB.
7. Untuk tahap awal, apakah sebaiknya pakai ramdisk Android asli (init_boot + vendor ramdisk), ramdisk diagnostik kecil, atau hanya kernel? Jelaskan apa yang dapat dibuktikan di tiap tahap. Hindari membuat driver atau vendor library palsu.
8. Periksa risiko kecocokan Android 14/API34 vs label paket 16.0. Artifact/properti apa yang paling andal untuk menetapkan versi userspace sebenarnya?
9. Berikan urutan eksperimen bertahap yang paling informatif dan dapat dibatalkan, serta output/log yang harus disimpan tiap langkah. Sebutkan titik berhenti jika hambatan hardware Qualcomm membuat boot lanjutan tidak realistis.
10. Review apakah ada kekeliruan pada kesimpulan kernel, fstab, LP metadata, atau boot test di atas. Bedakan fakta yang didukung bukti dari hipotesis.

## Batas keselamatan proyek

- ROM sumber dan image asli harus tetap tidak berubah; semua eksperimen harus menggunakan salinan di folder analysis/ atau output turunan terpisah.
- Jangan flash/ubah apa pun pada ponsel POCO F6 fisik atau bootloader-nya.
- Jangan menonaktifkan AVB, dm-verity, atau SELinux secara menyeluruh tanpa diagnosis spesifik dan penjelasan konsekuensi.
- Jangan membuat-buat driver, firmware, HAL, atau pustaka proprietary yang hilang.
- Setiap perubahan image yang diusulkan harus punya alasan, perintah, input/output, hash, dan metode validasi.
- Sasaran utama adalah memperoleh diagnosis teknis yang jujur. “Kernel berjalan”, “first-stage init berjalan”, dan “Android boot penuh” adalah hasil yang berbeda.

## Bentuk jawaban yang diminta

Susun jawaban dalam urutan: (A) penilaian kelayakan, (B) masalah/ketidakpastian terbesar, (C) tiga eksperimen berikutnya dengan command line Windows/QEMU konkret, (D) perubahan yang mungkin diperlukan pada kernel/DT/fstab/ramdisk dan cara memvalidasinya, (E) kriteria stop/go. Tolong tunjukkan jika suatu asumsi di brief ini salah dan jelaskan bukti atau sumber primer yang mendukung koreksi.

## Lokasi artefak lokal

Folder proyek: D:\git\HyperOS-QEMU-Lab.

- Laporan awal: reports\firmware-analysis-initial.md
- Kernel config: analysis\kernel.config
- Kernel hasil ekstraksi (baca saja): analysis\stock-kernel-extracted.bin
- Ramdisk terurai: analysis\init_boot-ramdisk-decoded.cpio, analysis\vendor_boot-ramdisk-decoded.cpio
- DTB virt: analysis\qemu-virt.dtb
- Instruksi kernel: analysis\qemu-instructions.log

File image di atas adalah salinan/hasil analisis. ROM arsip asli tetap disimpan terpisah di firmware\.

