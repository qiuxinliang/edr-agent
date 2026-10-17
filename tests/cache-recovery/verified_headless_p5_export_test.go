// Private explicit Go file-list overlay consumer. No production registration,
// transport, signing or builder implementation is added here.
package installer

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const p5Source = "694a4f47cfd55a7c98f8dab62617520c0c6251b1"
const p5Version = "3.2.695"
const p5Arch = "arm64"
const p5Max = 256 << 20

var p5SHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

type p5File struct {
	Path  string `json:"path"`
	SHA   string `json:"sha256"`
	Bytes int64  `json:"bytes"`
}
type p5Binding struct {
	Schema       string `json:"schema"`
	PreparedOnly *bool  `json:"prepared_only"`
	Source       string `json:"source_sha"`
	Version      string `json:"version"`
	Arch         string `json:"arch"`
	AgentSHA     string `json:"agent_sha256"`
	RuntimeSHA   string `json:"runtime_identity_sha256"`
	OwnerSHA     string `json:"builder_owner_sha256"`
	Headless     p5File `json:"headless"`
	Preflight    p5File `json:"preflight"`
}
type p5Package struct {
	Type string `json:"packageType"`
	SHA  string `json:"sha256"`
}
type p5Preflight struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	Data      struct {
		Valid    bool        `json:"valid"`
		Ready    bool        `json:"upgradeReady"`
		Blockers []string    `json:"upgradeBlockers"`
		Version  string      `json:"version"`
		Arch     string      `json:"arch"`
		Platform string      `json:"platform"`
		AgentSHA string      `json:"binarySha256"`
		Mode     string      `json:"signatureMode"`
		Trusted  bool        `json:"trustedSigner"`
		Policy   string      `json:"policySnapshot"`
		Packages []p5Package `json:"packages"`
	} `json:"data"`
}

func p5Hash(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func p5JSON(raw []byte, out any) error {
	// encoding/json otherwise silently accepts duplicate object keys. Check every
	// object before the typed decode; a second document/unknown field is refused.
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		v, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate_json_key")
				}
				seen[s] = true
				if e = walk(); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := walk(); e != nil {
					return e
				}
			}
		default:
			return errors.New("json_delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("json_trailing_document")
	}
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	return typed.Decode(out)
}
func p5Bounded(path string, cap int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute_local_file_required")
	}
	// Reject UNC/device paths and all symlink/junction ancestors. No network path.
	if strings.HasPrefix(path, `\\`) {
		return nil, errors.New("network_path_refused")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		if s.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("reparse_path_refused")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	before, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > cap {
		return nil, errors.New("file_bound")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, before.Size()+1))
	if e != nil {
		return nil, e
	}
	after, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) != before.Size() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("input_changed")
	}
	return raw, nil
}
func p5Pinned(f p5File, cap int64) ([]byte, error) {
	if !p5SHA.MatchString(f.SHA) || f.Bytes < 1 || f.Bytes > cap {
		return nil, errors.New("pin_shape")
	}
	raw, e := p5Bounded(f.Path, cap)
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) != f.Bytes || p5Hash(raw) != f.SHA {
		return nil, errors.New("pin_mismatch")
	}
	return raw, nil
}
func p5BuildVerified(b p5Binding, headless, receipt, owner []byte) ([]byte, error) {
	if b.Schema != "edr.private-verified-headless-p5-input.v1" || b.PreparedOnly == nil || *b.PreparedOnly || b.Source != p5Source || b.Version != p5Version || b.Arch != p5Arch {
		return nil, errors.New("actual_inputs_UNBOUND")
	}
	if !p5SHA.MatchString(b.AgentSHA) || !p5SHA.MatchString(b.RuntimeSHA) || !p5SHA.MatchString(b.OwnerSHA) || p5Hash(owner) != b.OwnerSHA {
		return nil, errors.New("source_owner_pin")
	}
	if int64(len(headless)) != b.Headless.Bytes || p5Hash(headless) != b.Headless.SHA || int64(len(receipt)) != b.Preflight.Bytes || p5Hash(receipt) != b.Preflight.SHA {
		return nil, errors.New("input_content_pin")
	}
	var p p5Preflight
	if e := p5JSON(receipt, &p); e != nil {
		return nil, e
	}
	if p.Code != "OK" || !p.Data.Valid || !p.Data.Ready || len(p.Data.Blockers) != 0 || p.Data.Version != b.Version || p.Data.Arch != b.Arch || p.Data.Platform != "windows" || p.Data.AgentSHA != b.AgentSHA {
		return nil, errors.New("actual_preflight_not_bound_ready")
	}
	allowUnsigned := false
	switch {
	case p.Data.Mode == "unsigned_integrity" && !p.Data.Trusted && p.Data.Policy == "optional-signing-v1":
		allowUnsigned = true
	case p.Data.Mode == "signed_trusted" && p.Data.Trusted && p.Data.Policy == "required-signing-v1":
	default:
		return nil, errors.New("preflight_signature_policy")
	}
	if len(p.Data.Packages) != 2 {
		return nil, errors.New("preflight_package_count")
	}
	want := ""
	seen := map[string]bool{}
	for _, x := range p.Data.Packages {
		if seen[x.Type] || !p5SHA.MatchString(x.SHA) {
			return nil, errors.New("preflight_package_identity")
		}
		seen[x.Type] = true
		switch x.Type {
		case "headless":
			if x.SHA != b.Headless.SHA {
				return nil, errors.New("preflight_headless_pin")
			}
		case "full_installer":
			want = x.SHA
		default:
			return nil, errors.New("preflight_unexpected_package")
		}
	}
	if !seen["headless"] || !seen["full_installer"] {
		return nil, errors.New("preflight_missing_p5")
	}
	// The one and only builder remains the original production source file.
	out, e := BuildHeadlessFullInstaller(headless, b.Version, b.Arch, b.AgentSHA, b.RuntimeSHA, allowUnsigned)
	if e != nil {
		return nil, e
	}
	if len(out) < 1 || len(out) > p5Max || p5Hash(out) != want {
		return nil, errors.New("real_preflight_p5_sha_mismatch")
	}
	return out, nil
}
func p5WriteExclusive(path string, body []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(body); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func p5Export(bindingPath, bindingSHA, ownerPath string) (string, error) {
	raw, e := p5Bounded(bindingPath, 16384)
	if e != nil {
		return "", e
	}
	if !p5SHA.MatchString(bindingSHA) || p5Hash(raw) != bindingSHA {
		return "", errors.New("binding_pin")
	}
	var b p5Binding
	if e = p5JSON(raw, &b); e != nil {
		return "", e
	}
	if b.PreparedOnly == nil || *b.PreparedOnly {
		return "", errors.New("actual_inputs_UNBOUND")
	}
	headless, e := p5Pinned(b.Headless, p5Max)
	if e != nil {
		return "", e
	}
	receipt, e := p5Pinned(b.Preflight, 65536)
	if e != nil {
		return "", e
	}
	owner, e := p5Bounded(ownerPath, 65536)
	if e != nil {
		return "", e
	}
	body, e := p5BuildVerified(b, headless, receipt, owner)
	if e != nil {
		return "", e
	}
	output := filepath.Join(filepath.Dir(bindingPath), "verified-p5-3.2.695-arm64.zip")
	if e = p5WriteExclusive(output, body); e != nil {
		return "", e
	}
	return p5Hash(body), nil
}
func TestPrivateP5Export695(t *testing.T) {
	sum, e := p5Export(os.Getenv("EDR_P5_EXPORT_BINDING"), os.Getenv("EDR_P5_EXPORT_BINDING_SHA256"), os.Getenv("EDR_P5_EXPORT_OWNER"))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("actual_original_owner_p5_sha256=%s catalog_written=false endpoint_task_created=false", sum)
}
func p5SyntheticFixture(t *testing.T) (p5Binding, []byte, []byte, []byte) {
	t.Helper()
	setup, e := p5Bounded(os.Getenv("EDR_P5_SYNTHETIC_SETUP"), 16<<20)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := p5Bounded(os.Getenv("EDR_P5_EXPORT_OWNER"), 65536)
	if e != nil {
		t.Fatal(e)
	}
	// These are labelled synthetic unit inputs, NOT a receipt from an API call.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, x := range []struct {
		name string
		body []byte
	}{{"VERSION", []byte(p5Version + "\n")}, {"edr_agent_setup.exe", setup}} {
		f, e := w.Create(x.name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(x.body); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	headless := buf.Bytes()
	no := false
	b := p5Binding{Schema: "edr.private-verified-headless-p5-input.v1", PreparedOnly: &no, Source: p5Source, Version: p5Version, Arch: p5Arch, AgentSHA: strings.Repeat("a", 64), RuntimeSHA: strings.Repeat("b", 64), OwnerSHA: p5Hash(owner), Headless: p5File{SHA: p5Hash(headless), Bytes: int64(len(headless))}}
	out, e := BuildHeadlessFullInstaller(headless, b.Version, b.Arch, b.AgentSHA, b.RuntimeSHA, true)
	if e != nil {
		t.Fatal(e)
	}
	var p p5Preflight
	p.Code = "OK"
	p.Message = "synthetic unit fixture only"
	p.Data.Valid = true
	p.Data.Ready = true
	p.Data.Platform = "windows"
	p.Data.Version = b.Version
	p.Data.Arch = b.Arch
	p.Data.AgentSHA = b.AgentSHA
	p.Data.Mode = "unsigned_integrity"
	p.Data.Policy = "optional-signing-v1"
	p.Data.Packages = []p5Package{{Type: "headless", SHA: b.Headless.SHA}, {Type: "full_installer", SHA: p5Hash(out)}}
	receipt, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	b.Preflight = p5File{SHA: p5Hash(receipt), Bytes: int64(len(receipt))}
	return b, headless, receipt, owner
}
func TestPrivateP5SyntheticContracts(t *testing.T) {
	b, h, r, o := p5SyntheticFixture(t)
	t.Run("original_owner_transport_and_determinism", func(t *testing.T) {
		a, e := p5BuildVerified(b, h, r, o)
		if e != nil {
			t.Fatal(e)
		}
		c, e := p5BuildVerified(b, h, r, o)
		if e != nil || !bytes.Equal(a, c) {
			t.Fatal("original_owner_not_deterministic")
		}
		z, e := zip.NewReader(bytes.NewReader(a), int64(len(a)))
		if e != nil {
			t.Fatal(e)
		}
		if len(z.File) != 2 || z.File[0].Name != "FDSecuritySetup.exe" || z.File[1].Name != "setup-ui-manifest.json" {
			t.Fatal("protocol5_entry_contract")
		}
		f, e := z.File[0].Open()
		if e != nil {
			t.Fatal(e)
		}
		actual, e := io.ReadAll(f)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		original, _ := p5Bounded(os.Getenv("EDR_P5_SYNTHETIC_SETUP"), 16<<20)
		if !bytes.Equal(actual, original) {
			t.Fatal("installer_bytes_changed")
		}
	})
	t.Run("UNBOUND_refuses_before_file_read", func(t *testing.T) {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "input.json")
		yes := true
		copy := b
		copy.PreparedOnly = &yes
		raw, _ := json.Marshal(copy)
		os.WriteFile(p, raw, 0600)
		_, e := p5Export(p, p5Hash(raw), "/definitely-not-an-owner")
		if e == nil || e.Error() != "actual_inputs_UNBOUND" {
			t.Fatal(e)
		}
		if _, e = os.Stat(filepath.Join(filepath.Dir(p), "verified-p5-3.2.695-arm64.zip")); !os.IsNotExist(e) {
			t.Fatal("unexpected_output")
		}
	})
	for _, name := range []string{"owner_hash", "headless_hash", "receipt_hash", "source", "arch", "version"} {
		t.Run(name, func(t *testing.T) {
			c := b
			switch name {
			case "owner_hash":
				c.OwnerSHA = strings.Repeat("0", 64)
			case "headless_hash":
				c.Headless.SHA = strings.Repeat("0", 64)
			case "receipt_hash":
				c.Preflight.SHA = strings.Repeat("0", 64)
			case "source":
				c.Source = strings.Repeat("0", 40)
			case "arch":
				c.Arch = "amd64"
			case "version":
				c.Version = "3.2.694"
			}
			if _, e := p5BuildVerified(c, h, r, o); e == nil {
				t.Fatal("accepted_bad_binding")
			}
		})
	}
	for _, name := range []string{"not_valid", "not_ready", "blocker", "policy", "wrong_p5", "missing_package", "duplicate_package", "receipt_version", "receipt_agent"} {
		t.Run(name, func(t *testing.T) {
			var p p5Preflight
			json.Unmarshal(r, &p)
			switch name {
			case "not_valid":
				p.Data.Valid = false
			case "not_ready":
				p.Data.Ready = false
			case "blocker":
				p.Data.Blockers = []string{"synthetic_not_ready"}
			case "policy":
				p.Data.Policy = "required-signing-v1"
			case "wrong_p5":
				p.Data.Packages[1].SHA = strings.Repeat("0", 64)
			case "missing_package":
				p.Data.Packages = p.Data.Packages[:1]
			case "duplicate_package":
				p.Data.Packages[1] = p.Data.Packages[0]
			case "receipt_version":
				p.Data.Version = "3.2.694"
			case "receipt_agent":
				p.Data.AgentSHA = strings.Repeat("0", 64)
			}
			raw, _ := json.Marshal(p)
			c := b
			c.Preflight = p5File{SHA: p5Hash(raw), Bytes: int64(len(raw))}
			if _, e := p5BuildVerified(c, h, raw, o); e == nil {
				t.Fatal("accepted_bad_preflight")
			}
		})
	}
	t.Run("duplicate_json_rejected", func(t *testing.T) {
		raw := bytes.Replace(r, []byte(`"code":"OK"`), []byte(`"code":"OK","code":"OK"`), 1)
		c := b
		c.Preflight = p5File{SHA: p5Hash(raw), Bytes: int64(len(raw))}
		if _, e := p5BuildVerified(c, h, raw, o); e == nil {
			t.Fatal("duplicate_accepted")
		}
	})
	t.Run("exclusive_output_preserves_existing", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "out.zip")
		os.WriteFile(p, []byte("existing synthetic"), 0600)
		if e := p5WriteExclusive(p, []byte("new synthetic")); e == nil {
			t.Fatal("overwrote")
		}
		raw, _ := os.ReadFile(p)
		if string(raw) != "existing synthetic" {
			t.Fatal("changed")
		}
	})
	t.Run("original_owner_rejects_invalid_PE", func(t *testing.T) {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		for _, x := range []struct{ n, s string }{{"VERSION", p5Version}, {"edr_agent_setup.exe", "not a PE"}} {
			f, _ := w.Create(x.n)
			f.Write([]byte(x.s))
		}
		w.Close()
		if _, e := BuildHeadlessFullInstaller(buf.Bytes(), p5Version, p5Arch, b.AgentSHA, b.RuntimeSHA, true); e == nil {
			t.Fatal("invalid_PE_accepted")
		}
	})
	t.Log("synthetic_only=true actual695_inputs_consumed=false actual_preflight_received=false network_or_catalog_or_endpoint=false")
}
