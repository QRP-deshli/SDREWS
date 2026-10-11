// certs.h
// TUKE - Nikita Kuropatkin
// Self-signed certificate (public) for HTTPS server

#ifndef CERTS_H
#define CERTS_H

/* ============================================================
 * X.509 SERVER CERTIFICATE (ECDSA P-256)
 * ------------------------------------------------------------
 * This is your public "Digital ID" that your Pico sends to the 
 * web browser during the TLS handshake. 
 * ============================================================ */
const char srv_crt_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBYDCCAQagAwIBAgIUS8QXCUrogzXyx6LVD8gUScdELv0wCgYIKoZIzj0EAwIw\n"
"FjEUMBIGA1UEAwwLcGljbzItaHR0cHMwHhcNMjYxMDA0MjEzMDE5WhcNMzYxMDAx\n"
"MjEzMDE5WjAWMRQwEgYDVQQDDAtwaWNvMi1odHRwczBZMBMGByqGSM49AgEGCCqG\n"
"SM49AwEHA0IABCG5lULvaZ5605cVLDIdrZbHes4njjuyhx+AcWMegOX9DZBDaL2h\n"
"qkf16eXB5ti7VIBK3JLuaGeisYU/NvkbfpSjMjAwMB0GA1UdDgQWBBRYJlMIAgBq\n"
"jbWMBEq3TD/rZKgx1TAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUC\n"
"IQDcOYMXCW7YPfWS01E6DRLBL0fNmoMArti5qSmJa9/dtgIgIgGOLDD1xuAm6BDH\n"
"uqkxykeHoJ8JgrpGT+8rlJIzOSI=\n"
"-----END CERTIFICATE-----\n";

/* The private key is NOT stored here. It is read from OTP at boot (see otp_keys.c). */

#endif // CERTS_H
