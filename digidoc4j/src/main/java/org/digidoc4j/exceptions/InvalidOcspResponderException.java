package org.digidoc4j.exceptions;

public class InvalidOcspResponderException extends DigiDoc4JException {
    public static final String MESSAGE = "OCSP Responder does not meet TM requirements";

    public InvalidOcspResponderException() {
        super(MESSAGE);
    }
}
