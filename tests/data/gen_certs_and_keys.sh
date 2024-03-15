# Create CA private key and certificate
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -new -x509 -sha256 -key ca-key.pem -days 10000 -out ca-cert.pem


# Create private key, certificate signing request (CSR) and certificate for client
openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
openssl req -new -sha256 -key client-key.pem -out client.csr
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 1000 -sha256

# Create private key, certificate signing request (CSR) and certificate for server
openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
openssl req -new -sha256 -key server-key.pem -out server.csr
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 10000 -sha256
