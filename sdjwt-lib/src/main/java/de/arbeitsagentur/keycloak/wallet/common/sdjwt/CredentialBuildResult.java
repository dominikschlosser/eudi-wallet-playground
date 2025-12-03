package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import java.util.List;
import java.util.Map;

/**
 * Normalized result for building an SD-JWT credential.
 */
public record CredentialBuildResult(String encoded,
                                    List<String> disclosures,
                                    Map<String, Object> decoded,
                                    String vct,
                                    String format) {
}
