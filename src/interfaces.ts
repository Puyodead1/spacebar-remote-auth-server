export enum OpCodes {
  HELLO = "hello",
  INIT = "init",
  NONCE_PROOF = "nonce_proof",
  PENDING_REMOTE_INIT = "pending_remote_init",
  PENDING_TICKET = "pending_ticket",
  PENDING_LOGIN = "pending_login",
  HEARTBEAT = "heartbeat",
  HEARTBEAT_ACK = "heartbeat_ack",
}

export interface Hello {
  op: OpCodes.HELLO;
  timeout_ms: number; // Time in milliseconds until the server will close the websocket and invalidate the login QR code
  heartbeat_interval: number; // Time in milliseconds between when a client should send heartbeats
}

export interface Init {
  op: OpCodes.INIT;
  encoded_public_key: string; // base64-encoded spki-encoded public ke
}

export interface NonceProofServer {
  op: OpCodes.NONCE_PROOF;
  encrypted_nonce: string; // base64-encoded encrypted nonce
}

export interface NonceProofClient {
  op: OpCodes.NONCE_PROOF;
  proof: string; // base64-url-encoded SHA-256 digest of data decrypted from the `encrypted_nonce` parameter
}

export interface PendingRemoteInit {
  op: OpCodes.PENDING_REMOTE_INIT;
  fingerprint: string; // used by mobile to uniquely identify a login request
}

export interface User {
  id: string; // User ID
  discriminator: string; // User Discriminator
  avatar: string; // User avatar hash
  username: string; // Username
}

export interface PendingTicket {
  op: OpCodes.PENDING_TICKET;
  encrypted_user_payload: string; // Encrypted user data
}

export interface PendingLogin {
  op: OpCodes.PENDING_LOGIN;
  ticket: unknown; // remote auth ticket
}

export interface TicketReponse {
  encrypted_token: string; // Encrypted user token
}

export interface Heartbeat {
  op: OpCodes.HEARTBEAT;
}

export interface HeartbeatAck {
  op: OpCodes.HEARTBEAT_ACK;
}

export type IncomingPayload = Init | NonceProofClient | Heartbeat;

export type OutgoingPayload =
  | Hello
  | NonceProofServer
  | PendingRemoteInit
  | PendingTicket
  | PendingLogin
  | HeartbeatAck;
