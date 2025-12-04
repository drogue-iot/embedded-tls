# Create CA private key and certificate
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -new -x509 -sha256 -key ca-key.pem -days 10000 -out ca-cert.pem

# Create private key, certificate signing request (CSR) and certificate for intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out im-key.pem
openssl req -new -sha256 -key im-key.pem -out im.csr
openssl x509 -req -in im.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out im-cert.pem -days 10000 -sha256

# Create private key, certificate signing request (CSR) and certificate for client
openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
openssl req -new -sha256 -key client-key.pem -out client.csr
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 10000 -sha256

# Create private key, certificate signing request (CSR) and certificate for server
openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
openssl req -new -sha256 -key server-key.pem -out server.csr
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 10000 -sha256

# Create private key, certificate signing request (CSR) and certificate from immediate for server with hostname
openssl ecparam -name prime256v1 -genkey -noout -out im-server-key.pem
openssl req -new -sha256 -key im-server-key.pem -out im-server.csr -subj "/CN=localhost"
openssl x509 -req -in im-server.csr -CA im-cert.pem -CAkey im-key.pem -CAcreateserial -out im-server-cert.pem -days 10000 -sha256
cat im-server-cert.pem im-cert.pem > chain-cert.pem
