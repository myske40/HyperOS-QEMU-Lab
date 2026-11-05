package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"strings"

	"github.com/erofs/go-erofs"
)

func main() {
	image := flag.String("img", "", "EROFS image path")
	inside := flag.String("path", ".", "Path inside the filesystem image")
	out := flag.String("out", "", "Copy a file from the image to this host path")
	flag.Parse()
	if *image == "" {
		log.Fatal("-img is required")
	}
	f, err := os.Open(*image)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	img, err := erofs.Open(f)
	if err != nil {
		log.Fatal(err)
	}
	name := strings.TrimPrefix(path.Clean("/"+*inside), "/")
	info, err := fs.Stat(img, name)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("EROFS OK: %s mode=%s size=%d\n", "/"+name, info.Mode(), info.Size())
	if info.IsDir() {
		entries, err := fs.ReadDir(img, name)
		if err != nil {
			log.Fatal(err)
		}
		for _, entry := range entries {
			kind := "file"
			if entry.IsDir() {
				kind = "dir"
			}
			child, err := entry.Info()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\t%d\t%s\n", kind, child.Size(), entry.Name())
		}
		return
	}
	if *out == "" {
		data, err := fs.ReadFile(img, name)
		if err != nil {
			log.Fatal(err)
		}
		_, err = os.Stdout.Write(data)
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	src, err := img.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	defer src.Close()
	dst, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		log.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Extracted to %s\n", *out)
}
