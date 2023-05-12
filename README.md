## Revocation feature

4 configurations are supported:
- Static store set at service start-up
- In memory store in actix AppState for monoservice with small list
- DB store for monoservice with larger list
- Distributed for multiservices architecture with a dedicated revocation management service 

### Static list

TODO

### In memory store

TODO

### DB store 

TODO

### Distributed

For multiservice architecture a dedicated service responsible of revocation management is the recommanded implementation.

This service will store in DB the token revocation ids in the format below:
- first revocation id from revocation_identifiers()
- associated public key
- optionnaly a ttl:
  - from datalog via a check
  - private key rotation date

The revocation service exposes via API the token revocation ids list so that other services can fetch it on start-up.

Long polling is used so that revocation service can push new token revocation ids to services.