package report

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

//go:embed templates/enterprise-reference.docx
var enterpriseReferenceDocx []byte

var (
	refDocOnce sync.Once
	refDocPath string
	refDocErr  error
)

// EnterpriseReferenceDocPath returns a filesystem path to the corporate Word
// reference template (styles/colours matching SAST/SCA reports).
func EnterpriseReferenceDocPath() (string, error) {
	refDocOnce.Do(func() {
		sum := sha256.Sum256(enterpriseReferenceDocx)
		name := fmt.Sprintf("dast-enterprise-ref-%x.docx", sum[:8])
		path := filepath.Join(os.TempDir(), name)
		if st, err := os.Stat(path); err == nil && st.Size() == int64(len(enterpriseReferenceDocx)) {
			refDocPath = path
			return
		}
		refDocErr = os.WriteFile(path, enterpriseReferenceDocx, 0o644)
		if refDocErr == nil {
			refDocPath = path
		}
	})
	return refDocPath, refDocErr
}

// ResolveEnterpriseReferenceDoc prefers an explicit templateRef, else embedded corporate template.
func ResolveEnterpriseReferenceDoc(templateRef, workDir string) string {
	if p := ResolveReferenceDoc(templateRef, workDir); p != "" {
		return p
	}
	p, err := EnterpriseReferenceDocPath()
	if err != nil {
		return ""
	}
	return p
}
