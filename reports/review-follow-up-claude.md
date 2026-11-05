# Review lanjutan untuk Claude: PID 1 keluar setelah system_a dibuat

Tolong review bukti terbaru proyek HyperOS POCO F6 di QEMU AArch64 `virt`. Fokus pada diagnosis teknis dari bukti yang ada. Jangan menyarankan menonaktifkan AVB/dm-verity/SELinux secara membabi buta, mengubah firmware fisik, atau mengarang driver/library.

## Target dan batasan

- Host Windows 10, Ryzen 5 7535HS, 12 logical processor, RAM sekitar 7,2 GiB.
- QEMU 11.1.0 di Windows; target AArch64 `virt`, saat ini TCG saja.
- ROM POCO F6 `peridot`, Indonesia, OS3.0.304.0.WNPIDXM; Android 16 pada `system`/`product`, Android 14 pada `vendor`/`init_boot`/`vendor_boot`.
- Firmware sumber tidak diubah. Pengujian hanya di QEMU dengan file salinan lokal; tidak ada flashing atau modifikasi perangkat fisik.

## Progres yang sudah dibuktikan

1. Kernel stok berjalan di QEMU `virt`, PL011 console aktif, dan kernel mendeteksi PCI NVMe.
2. Kernel config memiliki PL011, GICv3, PSCI, PCI generic host, NVMe, EROFS, device mapper, dan dm-verity built-in. Virtio block/pci/mmio tidak aktif.
3. Ramdisk `init_boot` + `vendor_boot` stok menabrak illegal instruction saat mencoba memuat `gunyah_qcom`. Untuk mengisolasi first stage, CPIO kerja tidak mengautoloader modul vendor; image sumbernya tetap utuh.
4. Disk kerja GPT/NVMe 16 GiB terdeteksi sebagai `/dev/block/nvme0n1`, dengan 10 partisi. Android sparse `super.img` diekspansi ke ukuran logis. Properti `androidboot.boot_devices=4010000000.pcie`, `androidboot.slot_suffix=_a`, `androidboot.hardware=qcom`, dan `androidboot.fstab_suffix=qcom` membuat init menemukan by-name partitions/fstab.
5. Init membaca metadata LP dan membuat logical mappings `odm_a` (`dm-0`), `product_a` (`dm-1`), dan `system_a` (`dm-2`).
6. Uji terakhir melewati modul vendor dan menghapus baris metadata dari fstab **hanya di CPIO diagnostik** karena `resize.f2fs` tidak ada; semua entri system tetap membawa flag AVB pada fstab. Sesudah `system_a` dibuat, PID 1 keluar dengan status `0x00007f00` (exit 127), lalu kernel panic `Attempted to kill init!`.
7. Belum ada pesan `Failed to mount required partitions early`, error AVB eksplisit, atau tampilan Android. Belum diketahui apakah init gagal memasang image EROFS, mengakses `/system/bin/init`, atau ada sebab first-stage lain.
8. `system_a` hasil ekstraksi dari `super` berukuran 716,955,648 byte dan memiliki magic EROFS `0xe0f5e1e2` pada offset 1024. Logical size cocok dengan metadata LP.
9. `avbtool.py` AOSP berhasil membaca kedua vbmeta. Signature RSA/SHA-256 masing-masing diverifikasi dengan public key yang tertanam; key SHA-1 `vbmeta_system` sama dengan yang dirujuk descriptor chain pada parent `vbmeta`. Root digest sistem yang dihitung dari `system_a` sama dengan descriptor AVB; seluruh tree bytes sistem cocok persis pada `tree_offset=703447040`, `tree_size=5545984`. Hal yang sama untuk vendor: root digest dan semua tree bytes cocok, `image_size=421892096`, tree offset `421892096`, ukuran `3330048`. FEC bytes belum divalidasi. Key embedded belum dibandingkan dengan trust root Xiaomi eksternal.
10. EROFS/LZ4 `system_a` berhasil dibaca host: berkas `system/bin/init` ada (AArch64 ET_DYN, 3,336,928 byte); `PT_INTERP` menunjuk `/system/bin/bootstrap/linker64`, yang juga ada. Semua 22 entri `DT_NEEDED` langsung ditemukan sebagai berkas dalam `system/lib64` atau `system/lib64/bootstrap`. Jadi hilangnya `/system/bin/init`, linker, atau library direct tidak didukung bukti saat ini; guest tetap belum terbukti berhasil mount/exec.
11. `system/build.prop`: Android 16 / API 36. `vendor/build.prop`: Android 14 / API 34. Fstab vendor memuat `vendor`, `vendor_dlkm`, `system_dlkm`, dan `odm` sebagai logical partitions bertanda `first_stage_mount`, tetapi log panic hanya memperlihatkan pembuatan `odm_a`, `product_a`, `system_a` sebelum exit 127.

Catatan sumber AOSP: beberapa versi Android init mempunyai jalur `first_stage_console` yang dapat berakhir `_exit(127)`. Namun command line efektif **tidak** memuat `androidboot.first_stage_console=...`, kernel mengatakan tidak menemukan payload bootconfig, dan pencarian strings pada `/init` dari init_boot (3,008,080 byte) tidak menemukan `first_stage_console`/`FirstStageConsole`. Jadi itu hanya contoh mengapa angka 127 sendiri tidak cukup; bukan dugaan utama tanpa bukti tambahan.

## Artefak lokal

- Log terakhir: `analysis/qemu-stage2-20261105-114522.stdout.log`.
- Log sebelumnya: `analysis/qemu-virt-stage2-test.stdout.log`.
- Ramdisk uji: `analysis/qemu-virt-stage2-ramdisk.cpio`.
- Kernel: `analysis/stock-kernel-extracted.bin`.
- Disk dasar 16 GiB: `analysis/hyperos-virt-test-16g.raw`.
- Launcher repeatable dengan overlay QCOW2 agar disk dasar tidak tertulis: `tools/run_qemu_stage2.ps1`.
- Pembuat disk: `tools/build_qemu_test_disk.ps1`.

## Pertanyaan

1. Dengan EROFS `system_a` yang valid, `/system/bin/init`, PT_INTERP, dan semua library direct tersedia, apa sumber paling mungkin PID 1 keluar status 127 sesudah `system_a` dibuat? Bagaimana menjelaskan bahwa belum ada `vendor_a`/`system_ext_a` pada log sebelum exit?
2. Apa eksperimen berikutnya yang paling informatif untuk membedakan error `first_stage_mount`, verifikasi AVB/hashtree, EROFS guest mount, dynamic linker, dan kegagalan exec `/system/bin/init`, tanpa mematikan AVB/dm-verity secara luas?
3. Log init apa yang dapat diaktifkan melalui kernel cmdline/bootconfig atau perubahan sementara minimal pada CPIO diagnostik agar pesan first-stage error tampil di serial PL011? Sebutkan perubahan dan dampak spesifiknya.
4. Apakah descriptor hashtree AVB sistem cocok dengan tata letak logical partition `system_a` yang diekstrak dari `super`? Bagaimana memverifikasi root digest, tree offset, FEC, ukuran payload, dan chain descriptor dengan tool yang tersedia?
5. Apakah realistis melanjutkan menuju second-stage init/framework dengan kernel stok ini, atau bukti yang ada sudah menunjuk hambatan struktural? Berikan urutan kerja kecil berikutnya dan stopping criteria yang jujur.

Mohon jawab ringkas dengan langkah diagnosis yang bisa langsung dijalankan di Windows/QEMU. Jangan klaim Android berhasil boot; sejauh ini hanya kernel dan first-stage init yang terbukti berjalan.
