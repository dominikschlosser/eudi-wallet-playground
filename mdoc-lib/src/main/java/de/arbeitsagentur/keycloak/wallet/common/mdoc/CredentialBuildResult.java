package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import java.util.List;
import java.util.Map;

/**
 * Normalized result for building an mDoc credential.
 */
public record CredentialBuildResult(String encoded,
                                    List<String> disclosures,
                                    Map<String, Object> decoded,
                                    String vct,
                                    String format) {
}
