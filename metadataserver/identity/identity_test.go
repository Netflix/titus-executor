package identity

import (
	"crypto"
	"crypto/tls"
	"testing"

	"gotest.tools/assert"
)

var sigTests = []struct {
	name      string
	certBytes []byte
	keyBytes  []byte
	data      []byte
}{
	{
		name:      "RSA",
		certBytes: testRSACert,
		keyBytes:  testRSAKey,
		data:      []byte("rsatest"),
	},
	{
		name:      "ECDSA",
		certBytes: testECDSACert,
		keyBytes:  testECDSAKey,
		data:      []byte("rsatest"),
	},
}

func TestSignVerify(t *testing.T) {
	for _, tc := range sigTests {
		test := tc
		t.Run(test.name, func(t *testing.T) {
			cert, err := tls.X509KeyPair(test.certBytes, test.keyBytes)
			assert.NilError(t, err)

			signer, err := NewSigner(cert)
			assert.NilError(t, err)

			data := test.data
			sig, err := signer.Sign(data)
			assert.NilError(t, err)

			valid := Verify(data, sig)
			assert.Assert(t, valid)

			pub := cert.PrivateKey.(crypto.Signer).Public()
			valid = VerifyWithPublicKey(data, pub, sig.GetSignature())
			assert.Assert(t, valid)

			stringSig, err := signer.SignString(data)
			assert.NilError(t, err)

			valid = VerifyStringSig(data, stringSig)
			assert.Assert(t, valid)
		})
	}
}

var testRSACert = []byte(`
-----BEGIN CERTIFICATE-----
MIICxTCCAa2gAwIBAgIBATANBgkqhkiG9w0BAQsFADAmMRcwFQYDVQQDDA5tZXRh
ZGF0YXNlcnZlcjELMAkGA1UEBhMCVVMwHhcNMjAwMzE1MDAyNjI4WhcNMzkwNTE0
MDAyNjI4WjAmMRcwFQYDVQQDDA5tZXRhZGF0YXNlcnZlcjELMAkGA1UEBhMCVVMw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJndM8B2s5i6Jt48mmWhrO
apPL7J9sogNzerlOgC0juoNWNnay8aebIakXOJuPDVhOhJ5dW8Al4SUoD2Oel8bp
QXm0pTTupddHta8u4n8dZLJksB3ZW1NlrhGiLqNI4CjSur7T5yFWiyVL+Cc/4w14
+6G7ZL+atBUjh/E8mKs7GOO5K5W8tbj7j1/qB+ZSoIZShEMktbkZGL8WaQikjSvs
gAw89jvPy6ssGdvKhDtDG3Uy/kV6QiFwruNMLWZYjG051yKHtaA158wDG5AUpl3P
C3yhmZsW6tn2Vo6TTA0CXqcV2LrtcA2kCNUpws1ytA+TxrP7PlXs6TBNsnRn6Net
AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIfhmFwxTypICKbTgzRJFnr5gguVYCr5
gQeXY7la1x0zjZ/XNgw/y18wlQfcKfODYgQuzBUiwXY4iCejyId8UpmngLePvhCh
CHLzeFStpV6izR3nCT/d6iBJV8qoiflo/0PsRY6PjVB1Bf+GE5VEDe7fcIAmaMKd
XLrFFbLNjArZBns+74gfQD1+YPSfICowpvAZNDBK8Qzr+s9wR79NA2VN9t+Bk8gd
eJ241MbmATYADt2tMXoSBfU3MqT7acwhLF53eXuCJj5nfFj8BOhK+44ox/XfnkwZ
gRc23rsSoM9yv8BlFaFHRyBdUr8J9p0zRCE/UFV982bO3RSeqzpPuBU=
-----END CERTIFICATE-----
`)
var testRSAKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJndM8B2s5i6Jt
48mmWhrOapPL7J9sogNzerlOgC0juoNWNnay8aebIakXOJuPDVhOhJ5dW8Al4SUo
D2Oel8bpQXm0pTTupddHta8u4n8dZLJksB3ZW1NlrhGiLqNI4CjSur7T5yFWiyVL
+Cc/4w14+6G7ZL+atBUjh/E8mKs7GOO5K5W8tbj7j1/qB+ZSoIZShEMktbkZGL8W
aQikjSvsgAw89jvPy6ssGdvKhDtDG3Uy/kV6QiFwruNMLWZYjG051yKHtaA158wD
G5AUpl3PC3yhmZsW6tn2Vo6TTA0CXqcV2LrtcA2kCNUpws1ytA+TxrP7PlXs6TBN
snRn6NetAgMBAAECggEALyuKsT+3GXaO4RDrK81m+iY7P/mzbvIUxp7O3gvlA7fu
ZGxHpyQcp5HfgrxOwNBJec1TU9pUgUhErjOzhfZSpl4YQGhqku8gB/n864Y4YUMe
7am6whC42VA5de1dbH5tbqgcX21zAlF5v2VmoW7YxxZwR2yR23sIexCiIyBA54lH
5gxEg89bk+Wzw0LFRQnLQIbyXI+fRQCHn3yD9VqE2/GVgUieWSs1HJKmH0r++rZF
55zx0x8VGyutRVOx4h3FAoLOu9NaGdAY4nRxoM6WJQE6cYb/Edt9h64e2EczRHLO
C3+uDzZ/E0fzASMfQR4wJn88ZBvL7h/EtAtjQgUgwQKBgQDlopbu4K21w0hAKmSJ
PHzs5GiSEO+W7DtG+ta6/cM36yl9pojpTIVJtS2ifgW9KI9xfVkUXgykIUSQH9Qk
xL3LrkQ1tuYagJnNJKbn0A+aObbi6CcPkD0EiRLO8DfZGOOr6B1AicwT03EEeHfE
+WeBnoz/aXF3xtTIlcj+aYKm3QKBgQDgw7cvu20VcpejTA82BWAM/pvebozrSPfF
iyYOPgNvGOOH2DlWSiYJLf+hMvbEIbSPDm/smvd1wmeHf5y86fsoPnVE05SrieRI
DhnDRyPLybMb8NIep2CO3doJj3GTEYhuDxD8WlCbmljmXM8kYrOyscReHJ/fEX+h
PULyTjMfEQKBgD7V37Eb38yl1AZi00HOQGzeD1MwuS62E35XsxxVxe5uNdtBD6Ov
IaXKouMc0tsw1xd58j8lgRYEWGuLmhQ5lam/VMDR/GLyH6PHzLgP8cUE1+t9FPso
P9oW3AOuLcoFCn+Gs0Jusl4WdI2BnVxT1qPcS760Dq10xdLhUa90FaEtAoGAAuek
o3JJq6BKg2rFO46AOkrEGvDU02mjAiOVP1Pf2Xy53BSYURwuN6onhp7Q/6Hr4nlu
SuGJ1zTG/8JPdUWU4GVGQLh3UGw8zg2YmaR+uvCFZxQKsyi4n8AQRFVdQ2hTmhCJ
yKkmJ4ysH3YNm0vHRMT1Y7389vYT7zKKffUyxfECgYEAwjBLZh6ihb4wBhUURQYY
VIki0anlVP72JyWGXNCkZJ5FgEVE8xZH8LI0VtNAVv4VqMekGgML9XBaEt8a1Hb6
FD4Hc2+MrRK4EycE75QHkaDZSvcgfBvjB3/xDH79kfhrSisrTk5tPMHAYx+NdNyn
qc8IKzrYvANEXiS+xRcutaE=
-----END PRIVATE KEY-----
`)

var testECDSACert = []byte(`
-----BEGIN CERTIFICATE-----
MIIBXjCB5QIJAIUYFG0PELLTMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDm1ldGFk
YXRhc2VydmVyMB4XDTIwMDMxNTAxMDc0OFoXDTM2MDgxODAxMDc0OFowGTEXMBUG
A1UEAwwObWV0YWRhdGFzZXJ2ZXIwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQSuBPO
/RMvUg3a6IZog7GRw86eGDdRIbIVOLWVHIx3HYYjrWUu4mHv/oUgnTuuFMq0/nxI
82ud4t2H+TUULsDyP4A+tu0T1rZAEQgfwHs+/cJH6oZH78vURAVpuvn4QVcwCgYI
KoZIzj0EAwIDaAAwZQIwVYE+SeowiEL5/tT0wCSKVii+pIHH1nJWPmOzbJT/FMVo
92lqwfoSPnF6YA9AK8p1AjEA2CKVqjYvWBy8zOxMYqhgTac+THZssYU9z3maxJ7d
iHXb2PoNiX9b41LRQvbdY9Z/
-----END CERTIFICATE-----
`)
var testECDSAKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDYNgm9nrgFWDooPDJO
1tN2IaMg4Q5VOjFKZ9Ltt6tVBQHznHRffq1balHIKHKxvXahZANiAAQSuBPO/RMv
Ug3a6IZog7GRw86eGDdRIbIVOLWVHIx3HYYjrWUu4mHv/oUgnTuuFMq0/nxI82ud
4t2H+TUULsDyP4A+tu0T1rZAEQgfwHs+/cJH6oZH78vURAVpuvn4QVc=
-----END PRIVATE KEY-----
`)
