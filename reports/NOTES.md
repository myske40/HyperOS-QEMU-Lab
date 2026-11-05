# HyperOS QEMU reviewer bundle — v6 through v9

## Scope and integrity

This ZIP contains full unfiltered serial logs for runs v6–v9, settings and patch manifests, patch builder sources and their RC/shell additions, small text-only firmware extracts, the reviewer handoff and addenda, and SHA-256 checksums. It excludes the firmware archive, `super.img`, partition images, raw or QCOW2 disks, CPIO archives, kernels, and Qualcomm/NXP proprietary binaries.

Firmware source SHA-256: `3e3772c6539ba4387d8c97ea9d2e42c28efa5d1b658db0e80e9ae2a9dbf5efdc` (source-only; not included). The v9 manifest records baseline raw disk hash `90e93797ee5fe8be713424f65b48fb5f5067dffbc4b7b59881bb397c939e9022` both before and after patch preparation. No source firmware or baseline disk was modified. No SELinux or dm-verity policy was relaxed. The v8-derived test ramdisk keeps the documented targeted vendor AVB fstab exception; v9 does not change that ramdisk.

## Firmware and Task A findings

- The supplied magic-byte detector identifies `system_a` and `vendor_a` as EROFS and `super.img` as Android sparse. Reading `odm_a` through the sparse logical-partition view identifies it as one linear EROFS extent: sector `2048`, `3741048` sectors, `1915416576` bytes.
- 153 requested small configuration files were extracted read-only. `/vendor/etc/vintf/manifest.xml` is absent; VINTF declarations are in fragments under `/vendor/etc/vintf/manifest/`.
- Those fragments declare `IKeyMintDevice/default`, `IBootControl/default`, and `IQSEECom`. ODM separately declares `IKeyMintDevice/strongbox` and includes its NXP service rc. The existence of declarations does not prove those services start or function under QEMU.
- The addendum's earlier statement that those declarations were absent is superseded by the extraction evidence in this bundle.

## Run history and evidence

- **v6:** five keystore2 SIGABRT exits (PIDs 329, 392, 432, 457, 492); init then performed the critical-process reboot. The serial log does not contain the keystore2 panic message.
- **v7:** init rejected the private `init.svc.keystore2` property trigger as unexported. This invalidates that diagnostic attempt.
- **v8:** five keystore2 SIGABRT exits (PIDs 330, 392, 433, 458, 496). The attempted `init.svc_debug.no_fatal.keystore2` property write from `u:r:vendor_init:s0` to `default_prop` was denied by SELinux. The post-fs-data logcat hook has no start record. The stock log does not contain a successful `restorecon /data` line; timing alone is not proof that it ran.
- **v9:** diagnostic-only change: start the logcat service from vendor `on init`, before keystore2. That action ran, but SELinux denied init's `{getattr}` access to `/system/bin/logcat` (exact raw AVC is in the full log). No policy was loosened. Five keystore2 SIGABRT exits were observed (PIDs 332, 392, 432, 463, 502); init rebooted at about 190.4 s guest time and QEMU exited with code 0 before the 1800 s timeout.

## v9 result and remaining unknowns

- The v6 and v8 raw logs show `exec 7 (/system/bin/vdc keymaster earlyBootEnded)` as started/waiting, then `vdc()++ keymaster earlyBootEnded` and `Waited 0ms for vold`. Neither run has an exec-7 exit line before the critical-process reboot. Servicemanager repeatedly reports that `android.security.maintenance` could not be found. This strongly supports an init queue stall at that exec, but the log does not explicitly prove causation or replace checking Android 16 init source. The init `took ... succeeded` line records spawn, not completion.


The v9 log also records stock `restorecon /data/misc /data/misc/keystore ... succeeded` at 157.702 s, but it does not provide the keystore2 panic text. The single v9 logcat start attempt failed with this denial: `audit: avc: denied { getattr } ... comm="init" path="/system/bin/logcat" scontext=u:r:init:s0 tcontext=u:object_r:logcat_exec:s0 tclass=file permissive=0`; init then logs `Command 'start qemu-logcat' ... failed: Could not start service: Cannot find '/system/bin/logcat': Permission denied`. This is recorded as a policy denial; no policy change was made.


The failure is still not distinguished between a keystore database/label problem and a missing or nonfunctional KeyMint service. Do not replace KeyMint or alter labels/policy until a diagnostic captures the panic or another direct proof identifies the cause. No Zygote, System Server, or `sys.boot_completed` evidence appears in v6–v9.

Run configuration: QEMU AArch64 `virt`, CPU `max,pauth-impdef=on`, `4` vCPUs, `3` GiB guest RAM, 16 GiB test disk, NVMe, POCO QEMU DTB, timeout `1800` seconds. The host had about 0.81 GiB free physical memory at launch, so this attempt used 3 GiB instead of the 4 GiB target to reduce memory pressure.

## v9 versus v8 image diff

- Effective patch payloads that differ: vendor_init_target_inode_block, vendor_init_target_data. Both are pieces of the same `/vendor/etc/init/hw/init.target.rc` replacement (inode metadata block and RC data block); the EROFS superblock CRC and eight-block allocation are unchanged.
- The v9 and v8 first-stage ramdisk files are byte-identical; v9 reuses the v8 fstab metadata timestamp.
- The v9 overlay's other vendor payload hashes and source base-disk hash match v8. See `configs/v9-v8-effective-diff.json` and both manifests.

## Source documents

`reviewer-supplied/HANDOFF-ADDENDUM-v9-latest.md` is the latest reviewer addendum; it supersedes the earlier addendum where they conflict. `previous-handoff/AI-REQUEST.md` is the handoff included for the prior reviewer. The two v9 builder scripts are retained separately: the reviewer-supplied file as received and the local builder used for the validated v9 image.

`SHA256SUMS.txt` contains hashes for every other file in this ZIP plus source-only firmware/super/disk hashes. It does not hash itself because a file cannot contain its own stable checksum.

## v10 — shell-domain diagnostic (5 November 2026)

**Satu perubahan:** mengganti hook v9 yang mengeksekusi `logcat` langsung dari domain `init` dengan layanan one-shot `qemu-keystore-diagnostic`, `seclabel u:r:shell:s0`, memakai console serial. Ia dimaksudkan untuk mencetak logcat, tombstone, label `/data`, serta menjalankan `restorecon -n -v /data` tanpa mengubah label. Tidak ada perubahan policy SELinux, AVB, atau dm-verity. Builder: `tools/make_qemu_vendor_modprobe_patch_v10.py`.

**Validasi sebelum boot:** pembacaan balik EROFS mengembalikan script, fstab, contexts, dan RC persis; seluruh payload QCOW2 lulus pembacaan balik byte demi byte melalui `qemu-io`. Dibanding manifest v9, payload yang berubah hanya `vendor_init_target_inode_block` dan `vendor_init_target_data` untuk RC tersebut. Hash vendor/super source sama dengan v9; hash disk dasar sebelum/sesudah pembuatan v10 cocok, dan ramdisk identik dengan v9. Image sumber dan disk dasar dibuka read-only.

**Run:** QEMU `virt`, RAM guest 3 GiB, 4 vCPU, `max,pauth-impdef=on`, timeout 1800 s. QEMU keluar `0` sebelum timeout setelah guest memulai reboot ke bootloader; ini bukan keberhasilan Android. Log mentah penuh: `analysis/qemu-avb-20261105-202244.serial.log` (333506 byte; SHA-256 `E69A9B72FA0A7ED776607B50D3D9F3AF246A47EB12A98362541F832E11C3BC80`). Metadata: `analysis/qemu-avb-20261105-202244.json`.

**Hasil langsung:** lima exit SIGABRT `keystore2` di uptime guest 217.825603, 229.671152, 244.268809, 254.554462, dan 265.038049 s. Init melaporkan critical process keluar empat kali pada 265.091973 s; reboot bootloader pada 266.266225 s. Tidak ada Zygote, System Server, atau `sys.boot_completed`. Tidak ada marker layanan v10 maupun pesan panic KeyMint/database di serial. Jadi v10 tidak berhasil membedakan H1 dan H2.

**Bukti label:** AVC menyebut proses `hypsys_ssi_default` dan `tcontext=u:object_r:unlabeled:s0` ketika mencari root directory di userdata. Itu bukti root `/data` masih terlihat unlabeled pada saat AVC, tetapi tidak membuktikan sebab abort `keystore2`. Tidak ada baris sukses eksplisit untuk `restorecon /data` di serial v10.

**Mengapa hook tidak memberi data (inferensi):** system `post-fs-data` mulai pada 223.216703 s; init mulai `exec 7 (/system/bin/vdc keymaster earlyBootEnded)` pada 229.159682 s. Tidak ada baris `start qemu-keystore-diagnostic`, marker logcat, atau pemrosesan action vendor `post-fs-data` sebelum reboot. Urutan ini mendukung bahwa trigger vendor tertunda/tidak sempat diproses; belum ada verifikasi source Android init yang membuktikan secara pasti mekanismenya. Jangan mengulang trigger yang sama. Jalur berikut perlu mulai sebelum antrean post-fs-data tersendat, tetapi pengguna meminta sesi dihentikan setelah run ini sehingga tidak ada percobaan berikutnya.

**Push dan penghapusan:** pengguna meminta laporan didorong ke GitHub akun `myske40` sebelum penghapusan bila diagnosis gagal. Direktori belum menjadi repo Git dan belum memiliki remote; tidak ada repo proyek terpilih dan GitHub CLI tidak terpasang. Folder proyek belum dihapus. Penghapusan harus menunggu URL repo yang sesuai atau tujuan repo lain yang dikonfirmasi, kemudian verifikasi push.

Durasi historis: timestamp thread Codex dari 5 Nov 2026 09:37:13 WIB hingga run v10 selesai sekitar 20:27:14 WIB adalah kira-kira 10 jam 50 menit elapsed (termasuk jeda dan menunggu, bukan jam kerja aktif). Run QEMU v10 sendiri berjalan 270,6 detik di host dan mencapai 266,3 detik guest sebelum reboot.
