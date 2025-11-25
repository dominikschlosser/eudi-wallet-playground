## Agent Notes

- After making changes, always run the full test suite (`mvn verify`) to ensure both unit and integration tests (including the Testcontainers-based flow) pass.
- If java doesnt seem to be installed, check sdkman
- Never skip tests (`-DskipTests` or `-DskipITs`) when running Maven. Always use the full `mvn verify`.
- Before modifying OID4VP/OID4VC flows, download the latest OpenID4VP 1.0 spec from https://openid.net/specs/openid-4-verifiable-presentations-1_0.html and check that changes remain compliant.
- Prefer normal imports over fully qualified class names in code; avoid inline `java.util.*` etc. by adding appropriate imports.
- Never remove existing tests without asking first
- Keycloak Code might be there for lookup under ../keycloak or ../keycloak-orig
