package org.digidoc4j.impl.asic.manifest;

public class ManifestErrorMessage {

    private String errorMessage = "";
    private String signatureId = "";

    public ManifestErrorMessage(String errorMessage, String signatureId) {
        this.errorMessage = errorMessage;
        this.signatureId = signatureId;
    }

    public ManifestErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getSignatureId() {
        return signatureId;
    }

    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }
}
