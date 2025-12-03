# eudi-wallet-demo Helm chart

This chart targets the AWS sandbox `wallet-demo` namespace. It deploys Keycloak (with the bundled `wallet-demo` realm) and the wallet under `/wallet`, fronted by an AWS ALB ingress (HTTP).

## Required values only
- `keycloak.publicHost` (external host for Keycloak)
- `wallet.publicBaseUrl`, `wallet.keycloakBaseUrl`, `wallet.keycloakRealm`
- Images: `wallet.image.repository/tag`, `keycloak.image.repository/tag`
- Wallet env flags under `wallet.env` (DID, verifier config, header sizes, etc.)
- Realm/config/keys provided via `--set-file` flags (no in-chart defaults)

Everything else is fixed to the AWS ALB HTTP setup used in the sandbox (no TLS in the ingress; ALB name and subnets are inlined).

## Build/push the wallet image
```
mvn spring-boot:build-image -Dspring-boot.build-image.imageName=<repo>:<tag>
docker push <repo>:<tag>
```

## Install/upgrade
```
helm upgrade --install wallet-demo charts/eudi-wallet-demo \
  --set keycloak.publicHost=<public-host> \
  --set wallet.publicBaseUrl=<https-url-to-wallet> \
  --set wallet.keycloakBaseUrl=<https-url-to-keycloak> \
  --set wallet.image.repository=<wallet-image-repo> \
  --set wallet.image.tag=<wallet-image-tag> \
  --set keycloak.image.repository=<keycloak-image-repo> \
  --set keycloak.image.tag=<keycloak-image-tag> \
  --set-file keycloak.realmJson=config/keycloak/realm-export.json \
  --set-file wallet.files.walletKeys=config/wallet-keys.json \
  --set-file wallet.files.verifierKeys=config/verifier-keys.json \
  --set-file wallet.files.mockIssuerKeys=config/mock-issuer-keys.json \
  --set-file wallet.files.mockIssuerConfigurations=config/mock-issuer-configurations.json
```
