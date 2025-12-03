package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

/**
 * Optional sink for collecting verification steps during SD-JWT verification.
 */
public interface VerificationStepSink {
    default void add(String title) {
        add(title, title, null);
    }

    default void add(String title, String description, String specLink) {
        // no-op by default
    }
}
