package report

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
)

var (
	templateShellOnce sync.Once
	templateDocOpen   string // <?xml … <w:body>
	templateDocClose  string // </w:body> … </w:document>
)

func loadTemplateDocumentShell() {
	templateShellOnce.Do(func() {
		zr, err := zip.NewReader(bytes.NewReader(enterpriseReferenceDocx), int64(len(enterpriseReferenceDocx)))
		if err != nil {
			return
		}
		for _, f := range zr.File {
			if f.Name != "word/document.xml" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return
			}
			s := string(b)
			bodyStart := strings.Index(s, "<w:body>")
			bodyEnd := strings.Index(s, "</w:body>")
			if bodyStart < 0 || bodyEnd < 0 {
				return
			}
			templateDocOpen = s[:bodyStart+len("<w:body>")]
			templateDocClose = s[bodyEnd:]
		}
	})
}

// cloneDocxWithDocument copies the corporate template package and replaces word/document.xml.
func cloneDocxWithDocument(documentXML []byte, outPath string) error {
	zr, err := zip.NewReader(bytes.NewReader(enterpriseReferenceDocx), int64(len(enterpriseReferenceDocx)))
	if err != nil {
		return err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	for _, zf := range zr.File {
		name := zf.Name
		var data []byte
		if name == "word/document.xml" {
			data = documentXML
		} else {
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			data, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return err
			}
		}
		hdr := zf.FileHeader
		w, err := zw.CreateHeader(&hdr)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return zw.Close()
}
