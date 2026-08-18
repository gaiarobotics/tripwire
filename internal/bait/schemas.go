package bait

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// tokenLifetime is how far ahead a rendered token expires. It only has to
// outlast the refresh interval by enough that a decoy never looks abandoned.
const tokenLifetime = 365 * 24 * time.Hour

// Every schema below embeds the install fingerprint in at least one value that
// `fingerprintPattern` matches verbatim — lower-case, dashes intact. That is
// what makes a leaked token traceable and what IsOurs recognises before it
// overwrites anything, so a schema that only carries a mangled copy (upper-cased
// into an AWS key id, say) has to carry an unmangled one somewhere too.

func render(kind Kind, fp string, now time.Time) ([]byte, error) {
	expiry := now.Add(tokenLifetime)
	switch kind {
	case KindClaude:
		return renderJSON(map[string]any{
			"claudeAiOauth": map[string]any{
				"accessToken":  "sk-ant-oat01-" + fp + "-0000000000000000000000",
				"refreshToken": "sk-ant-ort01-" + fp + "-0000000000000000000000",
				"expiresAt":    expiry.UnixMilli(),
				"scopes":       []string{"user:inference", "user:profile"},
			},
		})
	case KindCodex:
		return renderJSON(map[string]any{
			"OPENAI_API_KEY": "sk-proj-" + fp + "-0000000000000000000000",
			"tokens": map[string]any{
				"access_token":  fp + ".0000000000000000",
				"refresh_token": fp + ".1111111111111111",
				"account_id":    fp,
			},
			"last_refresh": now.UTC().Format(time.RFC3339),
		})
	case KindAWS:
		return renderAWS(fp, expiry), nil
	case KindGCP:
		return renderGCP(fp)
	case KindNPM:
		return renderNPM(fp), nil
	case KindPyPI:
		return renderPyPI(fp), nil
	case KindGitHub:
		return renderGitHub(fp), nil
	}
	return nil, fmt.Errorf("unknown decoy kind %d", kind)
}

func renderJSON(doc any) ([]byte, error) { return json.MarshalIndent(doc, "", "  ") }

// Character sets the various credential formats draw their tokens from. Padding
// a token with characters its format cannot contain would be as much of a tell
// as leaving it short.
const (
	alphaNum    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	alphaB64    = alphaNum + "+/"
	alphaB64URL = alphaNum + "-_"
	alphaHex    = "0123456789abcdef"
	alphaDigit  = "0123456789"
)

// extend pads a token body out to the width its format uses. Real keys are
// fixed-width and look random, so a short token — or a hundred characters of
// zeros in a key that should be base64 — is the first thing a careful reader
// notices. The filler is derived from the fingerprint rather than drawn from a
// random source, so a refresh rewrites the same bytes and never looks like a
// key that quietly rotates itself.
func extend(body string, n int, alphabet, seed string) string {
	if len(body) >= n {
		return body
	}
	out := []byte(body)
	for i := 0; len(out) < n; i++ {
		sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%d", seed, i))
		for _, b := range sum {
			if len(out) == n {
				break
			}
			out = append(out, alphabet[int(b)%len(alphabet)])
		}
	}
	return string(out)
}

// fpHex returns the fingerprint's hex body, without the "tw-" prefix.
func fpHex(fp string) string { return strings.TrimPrefix(fp, "tw-") }

// renderAWS writes a shared-credentials file: INI, one profile, an id/secret
// pair of the right widths plus a session token that expires in the future.
func renderAWS(fp string, expiry time.Time) []byte {
	var b strings.Builder
	b.WriteString("[default]\n")
	// A real access key id is 20 chars of upper-case alphanumerics, so the
	// fingerprint rides in it upper-cased; the secret carries the greppable copy.
	fmt.Fprintf(&b, "aws_access_key_id = AKIA%s\n", strings.ToUpper(fpHex(fp)))
	fmt.Fprintf(&b, "aws_secret_access_key = %s\n", extend(fp, 40, alphaB64, fp+"/aws-secret"))
	fmt.Fprintf(&b, "aws_session_token = %s\n", extend("FwoGZXIvYXdzE"+fp, 148, alphaB64, fp+"/aws-session"))
	fmt.Fprintf(&b, "x_security_token_expires = %s\n", expiry.UTC().Format(time.RFC3339))
	b.WriteString("region = us-east-1\n")
	return []byte(b.String())
}

// renderGCP writes a service-account key. Service-account keys carry no expiry
// — the real ones do not either, so there is no stale-token tell to avoid.
func renderGCP(fp string) ([]byte, error) {
	const project = "svc-platform-prod"
	account := "ci-deploy-" + fp
	email := account + "@" + project + ".iam.gserviceaccount.com"
	return renderJSON(map[string]any{
		"type": "service_account",
		// A key id is 40 hex chars; the fingerprint's own hex body starts it.
		"private_key_id":              extend(fpHex(fp), 40, alphaHex, fp+"/gcp-key-id"),
		"project_id":                  project,
		"private_key":                 fakePEM(fp),
		"client_email":                email,
		"client_id":                   extend("1", 21, alphaDigit, fp+"/gcp-client-id"),
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/" + account + "%40" + project + ".iam.gserviceaccount.com",
		"universe_domain":             "googleapis.com",
	})
}

// fakePEM builds a PEM block the size of a 2048-bit RSA key. The body is
// deliberately padding rather than a real key, and deliberately does not carry
// the fingerprint: a PEM body is strict base64, and a "tw-" in it would be the
// one thing in the file that could not be a real key.
func fakePEM(fp string) string {
	const header = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC"
	body := extend(header, 1600, alphaB64, fp+"/gcp-private-key")
	var b strings.Builder
	b.WriteString("-----BEGIN PRIVATE KEY-----\n")
	for i := 0; i < len(body); i += 64 {
		end := min(i+64, len(body))
		b.WriteString(body[i:end])
		b.WriteByte('\n')
	}
	b.WriteString("-----END PRIVATE KEY-----\n")
	return b.String()
}

// renderNPM writes an npmrc. Auth tokens are `npm_` plus 36 alphanumerics.
func renderNPM(fp string) []byte {
	var b strings.Builder
	b.WriteString("registry=https://registry.npmjs.org/\n")
	fmt.Fprintf(&b, "//registry.npmjs.org/:_authToken=npm_%s\n", extend(fp, 36, alphaNum, fp+"/npm"))
	b.WriteString("//registry.npmjs.org/:always-auth=true\n")
	b.WriteString("audit=false\n")
	return []byte(b.String())
}

// renderPyPI writes a pip.conf whose index url carries an upload token. PyPI
// tokens are base64url, so the fingerprint's dash needs no mangling here.
func renderPyPI(fp string) []byte {
	token := "pypi-AgEIcHlwaS5vcmc" + extend(fp, 156, alphaB64URL, fp+"/pypi")
	var b strings.Builder
	b.WriteString("[global]\n")
	fmt.Fprintf(&b, "index-url = https://__token__:%s@pypi.org/simple\n", token)
	b.WriteString("trusted-host = pypi.org\n")
	b.WriteString("timeout = 30\n")
	return []byte(b.String())
}

// renderGitHub writes a gh CLI hosts.yml. gh stores an OAuth token — `gho_`
// plus 36 characters — under both the host and the per-user section.
func renderGitHub(fp string) []byte {
	const user = "ci-deploy"
	token := "gho_" + extend(fp, 36, alphaNum, fp+"/github")
	var b strings.Builder
	b.WriteString("github.com:\n")
	fmt.Fprintf(&b, "    user: %s\n", user)
	fmt.Fprintf(&b, "    oauth_token: %s\n", token)
	b.WriteString("    git_protocol: https\n")
	b.WriteString("    users:\n")
	fmt.Fprintf(&b, "        %s:\n", user)
	fmt.Fprintf(&b, "            oauth_token: %s\n", token)
	return []byte(b.String())
}
