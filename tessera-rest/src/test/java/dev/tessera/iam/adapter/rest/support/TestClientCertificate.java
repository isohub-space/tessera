package dev.tessera.iam.adapter.rest.support;

/**
 * A fixed self-signed X.509 certificate a confidential client presents for mTLS
 * sender-constraining (RFC 8705), plus its expected {@code x5t#S256} thumbprint. Generated
 * once offline (a throwaway key) and embedded so tests need no runtime certificate authority.
 */
public final class TestClientCertificate {

    private TestClientCertificate() {
    }

    /** PEM of the client certificate the gateway would forward in {@code X-Client-Certificate}. */
    public static final String PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDHTCCAgWgAwIBAgIUEFKAHfKftTFHNnmMp2xL3eeQBsowDQYJKoZIhvcNAQEL
            BQAwHjEcMBoGA1UEAwwTdGVzc2VyYS10ZXN0LWNsaWVudDAeFw0yNjA3MTgxMzU0
            MTBaFw0zNjA3MTUxMzU0MTBaMB4xHDAaBgNVBAMME3Rlc3NlcmEtdGVzdC1jbGll
            bnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDt9xtHor37dMPh8wfT
            IU1J12/SOcE+IAbmLdw5BmrobDD+Za8iVcg5LBWt2T/hJHUCDSNMiE1iqQyoKBqg
            5Qvt5QiLJRDLtE4YPdlo6Qfuh9CXa5uvFqbV6yn2isAsGX0FKkbaD73TgBKTWHil
            k5BFfdFZZlHmaUutsIDuxvrT7WJAT4Xdv7d+EMIpsm9kCISfU1faFZXj0s3pqPkw
            7LsF6YsFguqCVITrPXsE50AEoBnfKjpMarMXnHqVTb5lFGX6NwICn0FxNKgSWy4h
            8raWm+sLItKa3geF95UpnIoI/AY3EMQUaqYBM6uUQ4NB1c0OgEpuyphTgYlrUOUa
            Bj/NAgMBAAGjUzBRMB0GA1UdDgQWBBQz2Kk1ftnXOkr7kkzUGwvYMKFlgjAfBgNV
            HSMEGDAWgBQz2Kk1ftnXOkr7kkzUGwvYMKFlgjAPBgNVHRMBAf8EBTADAQH/MA0G
            CSqGSIb3DQEBCwUAA4IBAQDdQSxMbG1/LDBUsfnDGM5ZxtzqgikRGuWKGUal9E4O
            MRSg6hb25qvtmCg9j0MOsDoR1Ie7iaU+Ahj5aWlDHHiNcz6NwmoxS8fowyYBKN4i
            zVzIqjcSeskh9hSA3SheQonxDriYQsMP5ZYniWW0Vfms0kpimuio8bMK6ozfB+ZF
            bOHPirSa0is0mAVU3u+ZDqqfA6j6GFDAm6bvhM9NNWB4GWjIWqcyQ1m2eTnGOj8g
            TAcabReHQxBbecvbGd8HW7sruv37tFo5vwBcwxwBLQyXfkmXDTVq66bz/UswnwaA
            p9DHY5A2ZD1XOTyU5uuIhbRTcq4xuMB1jK+eGjiEEyNv
            -----END CERTIFICATE-----
            """;

    /** The base64url SHA-256 thumbprint of {@link #PEM} — the expected cnf["x5t#S256"]. */
    public static final String X5T_S256 = "ureRCzB9LMVCbnN1t6K0PapuPDcDttrim5GO3cpHLzs";
}
