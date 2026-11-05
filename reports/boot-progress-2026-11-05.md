# Perkembangan boot HyperOS POCO F6 di QEMU

Pembaruan: 5 November 2026  
Firmware: HyperOS `OS3.0.304.0.WNPIDXM`, POCO F6 (`peridot`), Android 16 system / Android 14 vendor.

## Hasil terbaru — patch v6

- Uji QEMU terakhir: mesin `virt`, kernel stok 6.1.138, RAM guest 2 GiB, 4 vCPU, NVMe virtual 16 GiB, ramdisk QEMU v6, dan overlay QCOW2 turunan. Jumlah core bukan batas tetap proyek.
- Perbaikan v6 mempertahankan SELinux enforcing. File contexts QEMU memberi label yang cocok pada NVMe userdata (`nvme0n1p18`), metadata (`p6`), dan misc (`p11`); fstab `/data` dalam salinan vendor menghapus ketergantungan enkripsi hardware/UFS; skrip `vendor_modprobe.sh` melewati penantian modul Qualcomm.
- Hasil terukur: `make_f2fs` selesai dengan `format successful`; fs_mgr memasang `/data` sebagai F2FS; event `post-fs-data` mulai. Hambatan selanjutnya: `keystore2` abort empat kali, lalu init memicu reboot ke bootloader. Belum ada bukti Zygote, System Server, `sys.boot_completed`, atau UI.
- Audit SELinux melihat root filesystem `/data` sebagai `unlabeled`. System init memiliki perintah stok `restorecon /data`, sehingga alasan label tidak pulih masih perlu dipastikan. Penyebab crash `keystore2` juga belum diketahui; kemungkinan KeyMint tidak boleh dianggap terbukti tanpa log tambahan.
- Hash disk uji dasar sebelum dan sesudah pembuatan overlay v6 identik (`90e93797ee5fe8be713424f65b48fb5f5067dffbc4b7b59881bb397c939e9022`). Image firmware sumber tidak diubah. Pengecualian AVB hanya untuk vendor di ramdisk QEMU karena isi vendor test-overlay diubah; 10 baris AVB lain tetap.
- Artefak utama: `analysis/qemu-vendor-modprobe-test-v6.json`, `analysis/hyperos-virt-test-16g-vendor-modprobe-test-v6.qcow2`, `analysis/qemu-virt-vendor-modprobe-test-ramdisk-v6.cpio`, serta log `analysis/qemu-avb-20261105-165007.serial.log` dan konfigurasi run `analysis/qemu-avb-20261105-165007.json`.

## Jawaban singkat

**Belum boot penuh ke Android yang bisa dipakai.** Kernel stok sudah berjalan di QEMU `virt`, Android first-stage dan second-stage init berjalan, partisi dinamis utama berhasil dipasang dengan verifikasi AVB aktif, dan init melewati hambatan nama jalur NVMe. Guest belum mencapai Zygote, System Server, `sys.boot_completed`, atau UI.

## Uji sebelumnya (historis, sebelum patch v6)

- Mesin QEMU `virt`, 2 GiB RAM, 2 vCPU, storage virtual 16 GiB melalui NVMe PCI. RAM 2 GiB dipakai karena Windows saat pemeriksaan memiliki total RAM sekitar 7,2 GiB dan ruang bebas sekitar 1,9 GiB.
- Kernel stok 6.1.138, CPIO kerja gabungan, serta disk uji yang berisi salinan partisi ROM dan partisi placeholder kosong. Disk uji dasar asli tidak ditulis langsung; runner memakai overlay QCOW2 terpisah.
- DTB QEMU turunan `analysis/qemu-virt-soc.dtb` memindahkan node PCIe host ke bawah `/soc`, agar jalur sysfs dan `/dev/block/platform/soc/4010000000.pcie` sesuai dengan asumsi init POCO. DTB QEMU awal `analysis/qemu-virt.dtb` tidak diubah.
- QEMU menyelesaikan first stage pada 3,00 detik guest-time dan memulai second stage pada 19,70 detik. Perintah `wait /dev/block/platform/soc/4010000000.pcie` sukses tanpa jeda pada 52,36 detik.
- `mount_all /vendor/etc/fstab.qcom --early` sukses pada 69,76 detik. `system`, `vendor`, `product`, `odm`, `system_ext`, `mi_ext`, `system_dlkm`, dan `vendor_dlkm` termount lewat mapping device-mapper/EROFS dengan tabel dm-verity yang terbentuk. Digest AVB yang sama dari firmware digunakan; AVB/dm-verity tidak dimatikan.
- Uji dihentikan oleh batas waktu 240 detik. Tidak ada kernel panic di log ini, tetapi juga tidak ada eksekusi Zygote/System Server atau boot selesai.

Log serial: `analysis/qemu-avb-20261105-142509.serial.log`  
Metadata run: `analysis/qemu-avb-20261105-142509.json`  
Runner: `tools/run_qemu_trace.ps1`  
DTB turunan: `analysis/qemu-virt-soc.dtb` (SHA-256 `402f2c5340390d8f6ff780788775b7a55eb3c1c96d7c2fb11ee9f0dbc3a182b5`).

Perintah uji terakhir:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\run_qemu_trace.ps1 `
  -MemoryGiB 2 -CpuCount 2 -TimeoutSeconds 240 `
  -RamdiskPath .\analysis\qemu-virt-stage2-ramdisk.cpio `
  -DtbPath .\analysis\qemu-virt-soc.dtb `
  -BaseDiskPath .\analysis\hyperos-virt-test-16g-qemu-placeholders.raw `
  -FstabSuffix qcom -BootDevice '4010000000.pcie' `
  -BootDevices 'soc/4010000000.pcie'
```

## Penghalang yang terlihat di log

1. Partisi placeholder `persist`, `modem_a`, `modemfirmware_a`, `dsp_a`, `bluetooth_a`, `qmcs`, dan `spunvm` tidak berisi filesystem POCO. Mount ext4/VFAT gagal; dua partisi bertanda formattable juga gagal diformat dalam konteks uji. Placeholder tersebut hanya nol, bukan firmware atau driver buatan.
2. `vendor.qseecomd` keluar dengan status 255 dan `qseecom-service` berulang kali abort karena instance `vendor.qti.hardware.qseecom.IQSEECom/default` tidak tersedia di manifest layanan. Ini cocok dengan lingkungan tanpa Qualcomm Secure Execution Environment.
3. Setelah event `post-fs` pada 72,56 detik, log tidak menunjukkan event `late-fs`, `post-fs-data`, Zygote, ataupun System Server sebelum batas waktu. Penyebab penghambat berikutnya belum dipastikan; ini menjadi titik diagnosis berikut.
4. Banyak layanan vendor mengharapkan perangkat SoC POCO yang tidak ada di QEMU. Contohnya layanan qseecom dan sebagian pemuatan modul Qualcomm. Menghapus layanan secara massal atau mengubah SELinux/AVB belum dibenarkan oleh bukti.

## Root, UBL, dan Magisk

- **Root/Magisk belum ada dan belum diuji.** Guest saat ini belum mencapai Android framework, jadi belum ada shell Android atau aplikasi Magisk yang dapat diverifikasi.
- **UBL perangkat Xiaomi fisik tidak menjadi bagian dari boot QEMU.** QEMU menjalankan kernel secara langsung, bukan bootloader POCO. Tidak ada partisi fisik yang akan dibuka atau di-flash.
- Setelah Android boot stabil, Magisk dapat dinilai pada salinan image yang memuat ramdisk. Image sumber POCO memiliki kernel tanpa ramdisk di `boot.img`, sementara ramdisk generik ada pada `init_boot.img`; runner saat ini memakai CPIO gabungan yang sudah disesuaikan untuk diagnosis. Patch harus mengikuti layout itu dan memeriksa hubungan AVB sebelum dipakai. Panduan Magisk resmi menyebut partisi yang memuat ramdisk (`boot.img`, `init_boot.img`, atau `vendor_boot.img`) sebagai image yang perlu dipatch, serta mensyaratkan bootloader terbuka pada pemasangan perangkat biasa: [Panduan instalasi Magisk](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md).

## Integritas dan perubahan

- Paket firmware sumber tetap diperlakukan read-only. Image turunan, disk uji, DTB QEMU, dan overlay berada di folder `analysis`; skrip runner tidak meng-flash perangkat.
- Tidak ada perubahan pada `boot.img`, `init_boot.img`, `vendor_boot.img`, `super.img`, `vbmeta.img`, atau partisi bootloader sumber.
- Hanya DTB untuk mesin virtual yang diubah. Halaman AOSP menjelaskan bahwa ueventd membangun jalur symlink blok dari lokasi perangkat di sysfs dan parameter `androidboot.boot_devices`; perubahan `/soc` menyesuaikan jalur QEMU agar cocok dengan asumsi init POCO: [Dokumentasi ueventd AOSP Android 16](https://android.googlesource.com/platform/system/core/%2Bshow/android16-release/init/README.ueventd.md).
- Salinan disk dengan placeholder dibuat terpisah. `analysis/hyperos-virt-test-16g.raw` dan seluruh image ROM sumber tidak ditimpa oleh run terbaru.

## Langkah berikut

1. Temukan tindakan atau layanan yang menghentikan urutan init setelah `post-fs`; tambah logging terarah tanpa menonaktifkan SELinux atau verifikasi image secara luas.
2. Putuskan apakah image filesystem asli untuk partisi fisik tersedia dalam paket firmware. Jika tidak, biarkan mount perangkat yang tidak tersedia dilewati secara terkontrol di salinan lingkungan uji; jangan mengisi partisi dengan data palsu.
3. Uji konfigurasi 4 GiB setelah ruang memori host cukup; hasil saat ini memakai 2 GiB untuk diagnosis.
4. Setelah UI/framework atau setidaknya Zygote berhasil, lanjutkan pemeriksaan root/Magisk dalam disk dan image virtual salinan. Jangan flash POCO fisik.
