package de.arbeitsagentur.keycloak.wallet.verification.service;

import java.util.ArrayList;
import java.util.List;

public class VerificationSteps {
    private final List<String> titles = new ArrayList<>();
    private final List<StepDetail> details = new ArrayList<>();

    public void add(String title) {
        add(title, title, null);
    }

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
