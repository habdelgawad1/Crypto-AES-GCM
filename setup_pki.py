"""Run ONCE before starting the server/client:  python setup_pki.py

Creates three RSA key pairs and the files each side needs:
  ca_root.json      CA public key           -> client (the pre-trusted root certificate)
  server_cert.json  server public key,
                    signed by the CA        -> server (sent to the client during handshake)
  server_key.json   server private key      -> server only
  client_key.json   client private key      -> client only
  truststore.json   client public key(s)    -> server (list of allowed transaction signers)
"""
from pki import create_certificate, generate_rsa_keypair, save_json

print("generating keys (takes a few seconds) ...")
ca_n, ca_e, ca_d = generate_rsa_keypair()
server_n, server_e, server_d = generate_rsa_keypair()
client_n, client_e, client_d = generate_rsa_keypair()

# The CA private key (ca_d) is only used here to sign the server certificate, then thrown away.
save_json("ca_root.json", {"n": ca_n, "e": ca_e})
save_json("server_cert.json", create_certificate("leg-bank-server", server_n, server_e, ca_n, ca_d))
save_json("server_key.json", {"n": server_n, "d": server_d})
save_json("client_key.json", {"id": "alice", "n": client_n, "d": client_d})
save_json("truststore.json", {"alice": {"n": client_n, "e": client_e}})
print("done")
