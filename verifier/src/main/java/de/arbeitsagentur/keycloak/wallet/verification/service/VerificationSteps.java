package de.arbeitsagentur.keycloak.wallet.verification.service;

import java.util.ArrayList;
import java.util.List;

/**
 * Collects verification steps for UI/debugging and implements both sd-jwt and mDoc step sinks.
 */
public class VerificationSteps implements
        de.arbeitsagentur.keycloak.wallet.common.sdjwt.VerificationStepSink,
        de.arbeitsagentur.keycloak.wallet.common.mdoc.VerificationStepSink {
    private final List<String> titles = new ArrayList<>();
    private final List<StepDetail> details = new ArrayList<>();

    @Override
    public void add(String title) {
        add(title, title, null);
    }

    @Override
    public void add(String title, String description, String specLink) {
        titles.add(title);
        details.add(new StepDetail(title, description, specLink));
    }

    public List<String> titles() {
        return titles;
    }

    public List<StepDetail> details() {
        return details;
    }

    public record StepDetail(String title, String detail, String specLink) {
    }
}
