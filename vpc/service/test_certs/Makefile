ALL: test-dnsname.crt test-leaf-expired.crt

test-key.key:
	openssl genrsa -out $@ 2048


test-goodcn.crt: test-goodcn.csr test-CA.key test-CA.pem
	openssl x509 -req -in test-goodcn.csr -CA test-CA.pem -CAkey test-CA.key -CAcreateserial -out $@ -days 100000 -sha256


test-leaf-expired.crt: test-leaf-expired.csr test-CA.key test-CA.pem
	# Note on OSX you must have a local copy of the openssl binary, not in /usr/bin for this to work
	faketime '-356d' /bin/bash -c 'openssl x509 -req -in test-leaf-expired.csr -CA test-CA.pem -CAkey test-CA.key -CAcreateserial -out $@ -days 1 -sha256'


test-dnsname.csr: dnsname.csr.txt test-key.key
	openssl req -new -nodes -key test-key.key -out $@ -config dnsname.csr.txt
test-dnsname.crt: test-dnsname.csr test-CA.key test-CA.pem
	openssl x509 -req -in test-dnsname.csr -CA test-CA.pem -CAkey test-CA.key -CAcreateserial -out $@ -days 100000 -sha256 -extensions 'v3_req' -extfile dnsname.csr.txt
