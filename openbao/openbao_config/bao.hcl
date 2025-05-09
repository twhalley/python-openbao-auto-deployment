listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_cert_file = "/opt/openbao/openbao_ssl/selfsigned.crt"
  tls_key_file  = "/opt/openbao/openbao_ssl/selfsigned.key"
}

storage "file" {
  path = "/opt/openbao/openbao_data"
}

cluster_addr  = "https://127.0.0.1:8201"
api_addr      = "https://127.0.0.1:8200"
disable_mlock = true # (Optional) Disables mlock syscall to lock memory (not recommended for production).

# Storage configuration
// storage "raft" {
//   path = "/opt/openbao/raft/"
//   node_id = "node_1"
// }