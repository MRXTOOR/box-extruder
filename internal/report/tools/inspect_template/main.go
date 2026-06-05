//go:build ignore

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

func main() {
	path := "internal/report/templates/enterprise-reference.docx"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	zr, _ := zip.OpenReader(path)
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		s := string(b)
		// first 12000 chars of body
		i := strings.Index(s, "<w:body>")
		if i >= 0 {
			end := i + 15000
			if end > len(s) {
				end = len(s)
			}
			fmt.Println(s[i:end])
		}
		re := regexp.MustCompile(`<w:tblPr>.*?</w:tblPr>`)
		m := re.FindString(s[strings.Index(s, "Тип анализа")-500:])
		fmt.Println("\n=== findings tblPr ===\n", m)
	}
}
