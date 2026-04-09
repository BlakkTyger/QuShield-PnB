# ALGOs and LIBRARIES RESEARCH

1. subfinder (Go binary, call via Python subprocess)
2. dnspython in Python for live A/AAAA/CNAME resolution to get IP addresses.
3. sslyze
4. For deep certificate parsing, use cryptography (PyCA) to extract signature algorithm OIDs, OCSP endpoints, SAN fields, and key sizes.
5. differentiator. liboqs is a C library for quantum-safe cryptographic algorithms, released under the MIT License, and uses a common API for post-quantum key encapsulation and signature algorithms, making it easy to switch between algorithms
6. liboqs-python offers a Python 3 wrapper for the Open Quantum Safe liboqs C library and defines three main classes: KeyEncapsulation, Signature, and StatefulSignature, providing post-quantum key encapsulation as well as stateless and stateful signatures. 
7. For TLS-level PQC detection, use the oqs-provider: it provides algorithms for TLS operations via OpenSSL 3, and also provides hybrid algorithms, combining classic and quantum-safe methods . You can check if a server supports X25519Kyber768 (Google's hybrid) during the TLS handshake.
8. Use geoip2 (MaxMind's Python library) with the free GeoLite2-City database for offline lookups, and ipinfo.io for richer org/ASN data. Both give you lat/lng + country + city + ASN/ISP, which feeds your map visualization.
9. Use NetworkX to model the domain graph (domain → IP → certificate → cipher → PQC risk). Serialize to JSON for the frontend (D3.js force graph or Vis.js). Store scan results in PostgreSQL with SQLAlchemy.
10. Geolocation: geoip2 + MaxMind GeoLite2 DB, ipinfo.io API