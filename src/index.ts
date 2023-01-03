import crypto, { webcrypto } from "node:crypto";
import { WebSocketServer } from "ws";
import { IncomingPayload, OpCodes, OutgoingPayload } from "./interfaces";

const wss = new WebSocketServer({ port: 3020 });
const { subtle } = webcrypto;

wss.on("listening", () => {
  console.log("Remote auth server listening on port 3020");
});

wss.on("connection", function connection(ws) {
  ws.sendJson = function (data: OutgoingPayload) {
    this.send(JSON.stringify(data));
  };

  // random timeout between 1.7 and 1.9 minutes in ms
  const timeoutMs = Math.floor(Math.random() * 120000 + 100000);

  // close the connection after the timeout
  setTimeout(() => {
    ws.close(4003, "Handshake Timeout");
  }, timeoutMs);

  // send the hello op
  ws.sendJson({
    op: OpCodes.HELLO,
    timeout_ms: timeoutMs,
    heartbeat_interval: 41250,
  });

  ws.on("message", async function message(data) {
    try {
      const payload = JSON.parse(data.toString()) as IncomingPayload;
      switch (payload.op) {
        case OpCodes.INIT:
          // After receiving an init packet from the client, the server sends a nonce_proof packet containing a nonce encrypted using the public key provided in the init packet.

          console.log("INIT", payload.encoded_public_key);
          // generate a SHA-256 digest of the public key
          ws.fingerprint = crypto
            .createHash("sha256")
            .update(Buffer.from(payload.encoded_public_key, "base64"))
            .digest()
            .toString("base64url");
          // import the public key
          ws.public_key = await subtle.importKey(
            "spki",
            Buffer.from(payload.encoded_public_key, "base64"),
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
          );
          // generate a nonce
          const nonce = crypto.randomBytes(16);
          // save a sha-267 digest of the nonce for later verification
          ws.nonce = crypto
            .createHash("sha256")
            .update(nonce)
            .digest()
            .toString("base64url");
          // encrypt the nonce
          const encryptedNonce = await subtle.encrypt(
            "RSA-OAEP",
            ws.public_key,
            nonce
          );
          // send the nonce as a base64 string
          ws.sendJson({
            op: OpCodes.NONCE_PROOF,
            encrypted_nonce: Buffer.from(encryptedNonce).toString("base64"),
          });
          break;
        case OpCodes.NONCE_PROOF:
          // After the client receives a nonce_proof packet from the server, the client sends back a nonce_proof packet of its own containing a SHA-256 digest of the decrypted data encoded as base64-url.

          console.log("NONCE_PROOF", payload.proof);
          // verify the proof
          if (payload.proof === ws.nonce) {
            console.log("proof verified");
            // send the fingerprint
            ws.sendJson({
              op: OpCodes.PENDING_REMOTE_INIT,
              fingerprint: ws.fingerprint,
            });
          } else {
            console.log("proof failed");
          }
          break;
        case OpCodes.HEARTBEAT:
          // send a heartbeat ack
          console.log("HEARTBEAT");
          ws.sendJson({
            op: OpCodes.HEARTBEAT_ACK,
          });
          break;
        default:
          console.log("unknown op", payload);
          break;
      }
    } catch (e) {
      // to catch JSON parse errors
      console.log(e);
    }
  });
});

declare module "ws" {
  interface WebSocket {
    public_key: CryptoKey;
    nonce: string; // base64-url-encoded SHA-256 digest of the nonce
    fingerprint: string; // base64-url-encoded SHA-256 digest of the public key

    sendJson: (data: OutgoingPayload) => void;
  }
}
