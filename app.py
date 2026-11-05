from __future__ import annotations

import hashlib
import os
import platform
import queue
import shutil
import struct
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_NAME = "HyperOS QEMU Lab"
BOOT_NAMES = {"boot.img", "vendor_boot.img", "init_boot.img", "recovery.img"}


@dataclass
class ImageInfo:
    path: Path
    size: int
    kind: str
    notes: str
    sha256: str


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{size} B"
        value /= 1024
    return f"{size} B"


def inspect_header(path: Path) -> tuple[str, str]:
    try:
        with path.open("rb") as stream:
            head = stream.read(4096)
            if head.startswith(b"ANDROID!"):
                version = struct.unpack_from("<I", head, 40)[0] if len(head) >= 44 else None
                if version is not None and version >= 3:
                    ksize, rsize, os_version, hsize = struct.unpack_from("<IIII", head, 8)
                    note = f"Android boot header v{version}; kernel={human_size(ksize)}, ramdisk={human_size(rsize)}, header={hsize} B"
                else:
                    ksize, rsize = struct.unpack_from("<II", head, 8)
                    note = f"Android legacy boot image; kernel={human_size(ksize)}, ramdisk={human_size(rsize)}"
                return "Android boot image", note
            if head.startswith(b"VNDRBOOT"):
                version, page_size, kernel_addr, ramdisk_addr, ramdisk_size = struct.unpack_from("<IIIII", head, 8)
                return "Android vendor_boot image", f"vendor_boot header v{version}; page={page_size} B, vendor ramdisk={human_size(ramdisk_size)}"
            if len(head) >= 28 and struct.unpack_from("<I", head, 0)[0] == 0xED26FF3A:
                major, minor, file_hdr, chunk_hdr, block_size, blocks, chunks = struct.unpack_from("<HHHHIII", head, 4)
                return "Android sparse image", f"sparse v{major}.{minor}; block={block_size} B, expanded={human_size(block_size * blocks)}, chunks={chunks}"
            if head[:4] == b"QFI\xfb":
                return "QCOW2 virtual disk", "QEMU copy-on-write disk image"
            if head[:8] == b"EFI PART":
                return "GPT partition table", "GPT header detected at file offset 0"
            if len(head) >= 2 and head[:2] == b"\x1f\x8b":
                return "Gzip stream", "Compressed data; inspect container contents before treating as a firmware image"
            if len(head) >= 4 and head[:4] == b"PK\x03\x04":
                return "ZIP archive", "Archive container; inspect entries without extracting over source files"
            if len(head) >= 1082 and head[1080:1082] == b"\x53\xef":
                return "ext filesystem (likely ext4)", "ext superblock magic detected at offset 1080"
            if len(head) >= 1028 and struct.unpack_from("<I", head, 1024)[0] == 0xE0F5E1E2:
                return "EROFS filesystem", "EROFS superblock magic detected at offset 1024"
            if path.name.lower() == "super.img" or head[:4] == b"gDla":
                return "Android super container (possible)", "Candidate only; verify with Android logical-partition metadata tools"
            if path.stat().st_size >= 64:
                stream.seek(-64, os.SEEK_END)
                if stream.read(4) == b"AVBf":
                    return "Android image with AVB footer", "AVB footer magic detected in the final 64-byte footer"
    except (OSError, struct.error) as exc:
        return "Unreadable", str(exc)
    return "Unknown / needs deeper inspection", "No recognized signature in the initial header bytes"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_file(path: Path) -> ImageInfo:
    kind, notes = inspect_header(path)
    return ImageInfo(path, path.stat().st_size, kind, notes, sha256_file(path))


def environment_report() -> list[str]:
    qemu = shutil.which("qemu-system-aarch64")
    return [
        f"Host: {platform.system()} {platform.release()} ({platform.machine()})",
        f"Python: {platform.python_version()}",
        f"QEMU AArch64: {qemu or 'belum terpasang / tidak ditemukan di PATH'}",
        "GUI: Tkinter tersedia (aplikasi berjalan lokal, tanpa server)",
    ]


class HyperOSLab(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1120x720")
        self.minsize(900, 580)
        self.configure(bg="#f4f6f8")
        self.folder: Path | None = None
        self.results: list[ImageInfo] = []
        self.events: queue.Queue = queue.Queue()
        self._build_ui()
        self.after(150, self._poll_events)

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#f4f6f8")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("TLabel", background="#f4f6f8", foreground="#17212b", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 21, "bold"), foreground="#142638")
        style.configure("Sub.TLabel", font=("Segoe UI", 10), foreground="#536575")
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 8))
        style.configure("Treeview", rowheight=29, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        outer = ttk.Frame(self, padding=22)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="HyperOS QEMU Lab", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Pemeriksa firmware Android ARM64 yang berjalan lokal dan hanya membaca file sumber.", style="Sub.TLabel").pack(anchor="w", pady=(3, 16))

        top = ttk.Frame(outer, style="Card.TFrame", padding=14)
        top.pack(fill="x", pady=(0, 12))
        self.path_label = ttk.Label(top, text="Pilih folder firmware untuk memulai", style="Sub.TLabel")
        self.path_label.pack(side="left", fill="x", expand=True)
        self.scan_button = ttk.Button(top, text="Pilih folder firmware…", command=self._choose_folder)
        self.scan_button.pack(side="right")

        env = ttk.Frame(outer, style="Card.TFrame", padding=12)
        env.pack(fill="x", pady=(0, 12))
        self.env_label = ttk.Label(env, text="  •  ".join(environment_report()), style="Sub.TLabel", wraplength=1030)
        self.env_label.pack(anchor="w")

        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(0, 8))
        self.status = ttk.Label(bar, text="Belum ada analisis.", style="Sub.TLabel")
        self.status.pack(side="left", fill="x", expand=True)
        self.save_button = ttk.Button(bar, text="Simpan laporan…", command=self._save_report, state="disabled")
        self.save_button.pack(side="right")

        table_frame = ttk.Frame(outer, style="Card.TFrame", padding=8)
        table_frame.pack(fill="both", expand=True)
        columns = ("name", "size", "kind", "hash")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings")
        for key, label in (("name", "File"), ("size", "Ukuran"), ("kind", "Format terdeteksi"), ("hash", "SHA-256")):
            self.table.heading(key, text=label)
        self.table.column("name", width=230, anchor="w")
        self.table.column("size", width=100, anchor="e")
        self.table.column("kind", width=240, anchor="w")
        self.table.column("hash", width=360, anchor="w")
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        foot = ttk.Label(outer, text="Analisis header dan hash bukan bukti bahwa image dapat boot. File sumber tidak dimodifikasi.", style="Sub.TLabel")
        foot.pack(anchor="w", pady=(10, 0))

    def _choose_folder(self) -> None:
        chosen = filedialog.askdirectory(title="Pilih folder firmware HyperOS")
        if not chosen:
            return
        self.folder = Path(chosen)
        self.path_label.configure(text=str(self.folder))
        self.scan_button.configure(state="disabled", text="Menganalisis…")
        self.save_button.configure(state="disabled")
        self.status.configure(text="Membaca nama, ukuran, header, dan SHA-256. File sumber tidak akan ditulis.")
        for item in self.table.get_children():
            self.table.delete(item)
        self.results = []
        threading.Thread(target=self._scan_worker, args=(self.folder,), daemon=True).start()

    def _scan_worker(self, folder: Path) -> None:
        try:
            files = [p for p in folder.rglob("*") if p.is_file()]
            files.sort(key=lambda p: str(p).lower())
            for index, path in enumerate(files, 1):
                self.events.put(("progress", index, len(files), path.name))
                try:
                    info = inspect_file(path)
                    self.events.put(("item", info))
                except (OSError, PermissionError) as exc:
                    self.events.put(("error", path, str(exc)))
            self.events.put(("done", len(files)))
        except Exception as exc:  # keep UI responsive and surface filesystem errors
            self.events.put(("fatal", str(exc)))

    def _poll_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "progress":
                    _, index, total, name = event
                    self.status.configure(text=f"Memeriksa {index}/{total}: {name}")
                elif event[0] == "item":
                    info: ImageInfo = event[1]
                    self.results.append(info)
                    self.table.insert("", "end", values=(info.path.name, human_size(info.size), info.kind, info.sha256))
                elif event[0] == "error":
                    self.status.configure(text=f"Lewati file yang tidak dapat dibaca: {event[1].name}")
                elif event[0] == "fatal":
                    messagebox.showerror("Analisis gagal", event[1])
                    self._finish_scan()
                elif event[0] == "done":
                    self.status.configure(text=f"Selesai: {len(self.results)} file dibaca. Tidak ada file sumber yang diubah.")
                    self._finish_scan()
        except queue.Empty:
            pass
        self.after(150, self._poll_events)

    def _finish_scan(self) -> None:
        self.scan_button.configure(state="normal", text="Pilih folder firmware…")
        if self.results:
            self.save_button.configure(state="normal")

    def _make_report(self) -> str:
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        lines = [
            "# Laporan awal HyperOS QEMU Lab",
            "",
            f"- Waktu analisis: {stamp}",
            f"- Folder sumber: `{self.folder}`",
            "- Metode: inspeksi header awal dan SHA-256; sumber dibuka hanya untuk dibaca.",
            "",
            "## Lingkungan laptop",
            *[f"- {item}" for item in environment_report()],
            "",
            "## Inventaris image dan file",
            "| File | Ukuran | Format terdeteksi | Catatan | SHA-256 |",
            "|---|---:|---|---|---|",
        ]
        for item in self.results:
            relative = item.path.relative_to(self.folder) if self.folder else item.path.name
            safe = str(relative).replace("|", "\\|")
            lines.append(f"| `{safe}` | {human_size(item.size)} | {item.kind} | {item.notes.replace('|', '\\|')} | `{item.sha256}` |")
        lines += [
            "",
            "## Batas kesimpulan",
            "Deteksi tanda tangan dan hash tidak mengekstrak filesystem, memvalidasi AVB, memeriksa seluruh metadata `super`, atau membuktikan kompatibilitas kernel/HAL. Hasil `Unknown` berarti perlu pemeriksaan format lebih lanjut; bukan berarti file rusak.",
            "",
            "## Status QEMU",
            "QEMU AArch64 belum ditemukan pada PATH saat laporan dibuat. Aplikasi ini tidak mencoba boot otomatis dan tidak mengubah image. Setelah QEMU dan artefak boot yang sesuai tersedia, konfigurasi harus diturunkan dari hasil analisis kernel, ramdisk, device tree, serta tata letak partisi.",
            "",
            "## Target investigasi",
            "QEMU AArch64 `virt`, RAM awal 4 GiB, disk virtual 16 GiB. Mesin `virt` tidak meniru SoC Xiaomi; dukungan ARM64 saja tidak cukup untuk menyimpulkan firmware dapat boot.",
            "",
        ]
        return "\n".join(lines)

    def _save_report(self) -> None:
        if not self.folder:
            return
        target = filedialog.asksaveasfilename(title="Simpan laporan", initialdir=str(self.folder), initialfile="hyperos-firmware-analysis.md", defaultextension=".md", filetypes=[("Markdown", "*.md"), ("Text", "*.txt")])
        if not target:
            return
        try:
            Path(target).write_text(self._make_report(), encoding="utf-8")
            messagebox.showinfo("Laporan tersimpan", f"Laporan disimpan di:\n{target}")
        except OSError as exc:
            messagebox.showerror("Gagal menyimpan", str(exc))


if __name__ == "__main__":
    HyperOSLab().mainloop()
