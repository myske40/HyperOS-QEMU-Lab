# HyperOS QEMU Lab — POCO F6 (peridot)

> **Project status / Status proyek: NOT BOOTED TO ANDROID FRAMEWORK / BELUM BOOT KE FRAMEWORK ANDROID.**
>
> This repository documents an experimental attempt to boot the original POCO F6 HyperOS ARM64 firmware in QEMU AArch64 `virt`. It is a research log, not a working ROM port. No Zygote, Android System Server, `sys.boot_completed`, or UI has been observed.
>
> Repositori ini mendokumentasikan percobaan menjalankan firmware HyperOS ARM64 asli POCO F6 pada QEMU AArch64 `virt`. Ini catatan riset, bukan port ROM yang sudah berfungsi. Belum ada Zygote, Android System Server, `sys.boot_completed`, atau tampilan UI yang berhasil dicapai.

## English

### Goal and scope

The goal came from the user's request to run the downloaded POCO F6 (`peridot`) HyperOS firmware on a Windows laptop through QEMU, preserving the original firmware and using only derived QEMU images/overlays. The target was Android framework startup on AArch64 `virt`, with a virtual 16 GiB disk. Four vCPUs were used in later runs; guest RAM was reduced from the initial 4 GiB target to 3 GiB after the host showed low free memory. No physical phone was flashed or modified.

The conversation clarified that this was **ROM virtualization/adaptation**, not a Qualcomm phone port, and that earlier mentions of “four cores”, root, bootloader unlock, and Magisk were not the central goal. The work therefore focused on booting the vendor firmware in QEMU; it did not claim root, UBL, or Magisk support.

### What was done

- Identified and inspected the firmware partitions and Android boot artifacts, including boot/ramdisk, dynamic partitions, fstab, init configuration, VINTF declarations, SELinux contexts, and the stock kernel configuration.
- Built derived QEMU test overlays and modified only copies. Source firmware and the base disk were kept read-only; AVB, dm-verity, and SELinux policy were not disabled or weakened.
- Created Windows launch/analysis scripts, patch builders, run manifests, integrity checks, raw serial captures, and reviewer handoff bundles.
- Tested QEMU AArch64 `virt` with the stock kernel, 4 vCPUs, CPU `max,pauth-impdef=on`, a 16 GiB virtual NVMe disk, and 3 GiB guest RAM for the final run.
- Documented failed approaches rather than hiding them: private init service-property access was denied, changing a no-fatal property was denied, and attempts to read/execute logcat from the init domain were blocked by SELinux.

### Boot progress and blockers

The experiments reached the stock kernel and Android init, mounted the dynamic `super` partitions, and eventually formatted/mounted virtual `/data` as F2FS and entered `post-fs-data`. This is partial boot progress; it is not an Android framework boot.

Runs v6 through v10 repeatedly showed `keystore2` aborting with SIGABRT and init rebooting the guest. The v10 raw serial log records five exits at guest uptimes 217.825603, 229.671152, 244.268809, 254.554462, and 265.038049 seconds; the guest rebooted at 266.266225 seconds. There is no evidence of Zygote, System Server, `sys.boot_completed`, or UI.

The v10 one-shot diagnostic service did not appear in the serial log, so the panic was not captured. The root of `/data` was observed with an `unlabeled` target context in an AVC involving `hypsys_ssi_default`; that is direct evidence of a labeling issue at that observation, but it does **not** prove that this caused the `keystore2` abort. The available logs do not distinguish a keystore database/`/data` failure from a missing or nonfunctional KeyMint service. Do not replace KeyMint or alter labels/policy without direct evidence.

Other hardware-specific Qualcomm services and graphics remain untested as later boot blockers because the keystore failure comes first. No substitute drivers or vendor libraries were fabricated.

### Timeline from the project chat

1. The project began as a request to analyze HyperOS firmware and investigate QEMU AArch64 `virt` compatibility.
2. The target was clarified as POCO F6 (`peridot`) HyperOS on Windows; the user downloaded the ROM manually after the direct download was too slow.
3. The QEMU launcher, firmware analysis, derived disk/overlay workflow, and boot attempts were developed. The user repeatedly requested that the work continue until boot or a technically supported stopping point.
4. The user corrected the scope to virtualization/adaptation of the ROM, not a physical-device port. They also requested AI-review handoffs and small reviewer packages.
5. Reviewer feedback was used to separate direct log evidence from hypotheses, reject the newline theory for vendor file contexts, and avoid an unjustified “drop-in AOSP KeyMint” assumption.
6. v6–v10 attempted incremental storage, init, and diagnostic changes. SELinux denials and repeated `keystore2` aborts were recorded without weakening policy.
7. The final v10 QEMU run ended in a guest reboot, not a framework boot. The user asked for a public GitHub record before deleting the local project.

Elapsed time from the Codex project thread start (2026-11-05 09:37 WIB) to completion of the v10 QEMU run (about 20:27 WIB) was approximately **10 h 50 min**, including idle time, waiting, and earlier runs. This is elapsed wall-clock time, not active labor. The v10 QEMU run itself took about **270.6 seconds** on the host.

### Artifacts and safety

The repository is intended to contain documentation, scripts, small text/config extracts, manifests, and raw serial logs only. It must not contain original firmware images, `super.img`, vendor/system images, base disks, large QCOW2/raw overlays, extracted binary firmware, private keys, or credentials. The downloaded firmware remains copyrighted by its owner and is not redistributed here.

No physical-device flashing was performed. Do not weaken AVB, dm-verity, or SELinux. Keep source firmware and base disks read-only; make experiments only on derived images/overlays.

### Current next step

The next technically justified step is a new, earlier diagnostic trigger that is not the failed v9/v10 trigger path, capturing unfiltered logcat/tombstone and `/data` labels before the first `keystore2` abort. Make one change per run and stop if the logs show the next proprietary blocker cannot be replaced. No further QEMU run has been performed after v10.

## Bahasa Indonesia

### Tujuan dan batas pekerjaan

Tujuan proyek berasal dari permintaan pengguna untuk menjalankan firmware HyperOS POCO F6 (`peridot`) yang sudah diunduh pada laptop Windows melalui QEMU, sambil mempertahankan firmware sumber dan hanya memakai image/overlay turunan untuk QEMU. Targetnya adalah memulai framework Android pada AArch64 `virt` dengan disk virtual 16 GiB. Run belakangan memakai 4 vCPU; RAM guest diturunkan dari target awal 4 GiB menjadi 3 GiB karena RAM kosong host rendah. Tidak ada flashing atau modifikasi pada HP fisik.

Percakapan memperjelas bahwa tujuannya adalah **virtualisasi/adaptasi ROM**, bukan port untuk HP Qualcomm fisik. Penyebutan awal tentang “empat core”, root, unlock bootloader, dan Magisk bukan tujuan utama. Karena itu pekerjaan berfokus pada boot firmware vendor di QEMU; proyek ini tidak mengklaim dukungan root, UBL, atau Magisk.

### Pekerjaan yang dilakukan

- Mengidentifikasi dan memeriksa partisi firmware serta artefak boot Android, termasuk boot/ramdisk, partisi dinamis, fstab, konfigurasi init, deklarasi VINTF, konteks SELinux, dan konfigurasi kernel stok.
- Membuat overlay uji QEMU turunan dan mengubah salinannya saja. Firmware sumber dan disk dasar tetap read-only; AVB, dm-verity, dan policy SELinux tidak dimatikan atau dilonggarkan.
- Membuat skrip Windows untuk menjalankan/menganalisis QEMU, pembuat patch, manifest run, pemeriksaan integritas, rekaman serial mentah, dan paket handoff untuk peninjau.
- Menguji QEMU AArch64 `virt` dengan kernel stok, 4 vCPU, CPU `max,pauth-impdef=on`, disk NVMe virtual 16 GiB, dan RAM guest 3 GiB pada run terakhir.
- Mencatat pendekatan yang gagal: akses properti service init privat ditolak, perubahan properti no-fatal ditolak, dan percobaan membaca/menjalankan logcat dari domain init diblokir SELinux.

### Kemajuan boot dan penghalang

Eksperimen mencapai kernel stok dan Android init, me-mount partisi dinamis `super`, lalu akhirnya memformat/me-mount `/data` virtual sebagai F2FS dan masuk ke `post-fs-data`. Ini kemajuan boot sebagian, bukan boot framework Android.

Run v6 sampai v10 berulang kali menunjukkan `keystore2` abort dengan SIGABRT dan init me-reboot guest. Log serial mentah v10 mencatat lima exit pada uptime guest 217.825603, 229.671152, 244.268809, 254.554462, dan 265.038049 detik; guest reboot pada 266.266225 detik. Tidak ada bukti Zygote, System Server, `sys.boot_completed`, atau UI.

Layanan diagnostik one-shot v10 tidak muncul di log serial sehingga panic tidak tertangkap. Root `/data` terlihat dengan target context `unlabeled` pada sebuah AVC yang melibatkan `hypsys_ssi_default`; ini bukti langsung bahwa ada masalah label pada pengamatan tersebut, tetapi **belum membuktikan** bahwa hal itu menyebabkan abort `keystore2`. Log yang tersedia belum membedakan kegagalan database/`/data` dari layanan KeyMint yang tidak ada atau tidak berfungsi. Jangan mengganti KeyMint atau mengubah label/policy tanpa bukti langsung.

Layanan Qualcomm spesifik perangkat keras lain dan grafis belum diuji sebagai penghalang boot berikutnya karena kegagalan keystore terjadi lebih dulu. Tidak ada driver pengganti atau library vendor yang dibuat-buat.

### Kronologi dari chat proyek

1. Proyek dimulai dari permintaan menganalisis firmware HyperOS dan menyelidiki kompatibilitas QEMU AArch64 `virt`.
2. Target diperjelas menjadi HyperOS POCO F6 (`peridot`) pada Windows; pengguna mengunduh ROM secara manual karena unduhan langsung terlalu lambat.
3. Launcher QEMU, analisis firmware, alur disk/overlay turunan, dan percobaan boot disiapkan. Pengguna beberapa kali meminta agar pekerjaan diteruskan sampai berhasil boot atau ada alasan teknis yang kuat untuk berhenti.
4. Pengguna meluruskan bahwa tujuannya virtualisasi/adaptasi ROM, bukan port ke perangkat fisik. Pengguna juga meminta handoff untuk tinjauan AI lain dan paket kecil untuk peninjau.
5. Masukan peninjau digunakan untuk memisahkan bukti log langsung dari hipotesis, menggugurkan dugaan newline pada vendor file contexts, dan menghindari asumsi tanpa bukti bahwa KeyMint AOSP dapat langsung menggantikan KeyMint QTI.
6. v6–v10 mencoba perubahan bertahap pada storage, init, dan diagnostik. Denial SELinux serta abort `keystore2` dicatat tanpa melonggarkan policy.
7. Run QEMU v10 berakhir dengan guest reboot, bukan boot framework. Pengguna meminta dokumentasi publik di GitHub sebelum folder proyek lokal dihapus.

Waktu elapsed dari awal thread proyek Codex (2026-11-05 pukul 09:37 WIB) sampai run QEMU v10 selesai (sekitar pukul 20:27 WIB) kira-kira **10 jam 50 menit**, termasuk jeda, waktu menunggu, dan run sebelumnya. Ini durasi jam dinding, bukan waktu kerja aktif. Run QEMU v10 sendiri berjalan sekitar **270,6 detik** di host.

### Artefak dan keamanan

Repositori ini seharusnya hanya berisi dokumentasi, skrip, ekstrak teks/konfigurasi kecil, manifest, dan log serial mentah. Jangan masukkan image firmware asli, `super.img`, image vendor/system, disk dasar, overlay QCOW2/raw besar, firmware biner hasil ekstrak, private key, atau kredensial. Firmware yang diunduh tetap merupakan hak cipta pemiliknya dan tidak didistribusikan di sini.

Tidak ada flashing perangkat fisik. Jangan melonggarkan AVB, dm-verity, atau SELinux. Firmware sumber dan disk dasar harus tetap read-only; eksperimen hanya dilakukan pada image/overlay turunan.

### Langkah teknis berikutnya

Langkah teknis yang masuk akal adalah trigger diagnostik lebih awal yang tidak mengulang jalur trigger v9/v10 yang gagal, untuk menangkap logcat/tombstone tanpa filter dan label `/data` sebelum abort `keystore2` pertama. Ubah satu hal per run dan berhenti jika log membuktikan penghalang proprietary berikutnya tidak punya pengganti. Belum ada run QEMU setelah v10.
