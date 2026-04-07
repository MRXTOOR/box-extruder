package exitcode

import (
	"testing"
	"time"

	"github.com/box-extruder/dast/internal/model"
)

func TestFromFindings_confirmedHigh(t *testing.T) {
	t.Setenv("DAST_FAIL_ON_SEVERITY", "HIGH")
	fs := []model.Finding{{
		LifecycleStatus: model.LifecycleConfirmed,
		Severity:        model.SeverityHigh,
	}}
	if FromFindings(fs) != 1 {
		t.Fatal()
	}
}

func TestFromFindings_infoOnly(t *testing.T) {
	t.Setenv("DAST_FAIL_ON_SEVERITY", "HIGH")
	fs := []model.Finding{{
		LifecycleStatus: model.LifecycleConfirmed,
		Severity:        model.SeverityInfo,
	}}
	if FromFindings(fs) != 0 {
		t.Fatal()
	}
}

func TestFromFindings_unconfirmedIgnored(t *testing.T) {
	t.Setenv("DAST_FAIL_ON_SEVERITY", "HIGH")
	fs := []model.Finding{{
		LifecycleStatus: model.LifecycleUnconfirmed,
		Severity:        model.SeverityHigh,
	}}
	if FromFindings(fs) != 0 {
		t.Fatal()
	}
}

func TestFromFindings_mediumThreshold(t *testing.T) {
	t.Setenv("DAST_FAIL_ON_SEVERITY", "MEDIUM")
	fs := []model.Finding{{
		LifecycleStatus: model.LifecycleConfirmed,
		Severity:        model.SeverityMedium,
		FirstSeenAt:     time.Now().UTC(),
	}}
	if FromFindings(fs) != 1 {
		t.Fatal()
	}
}
