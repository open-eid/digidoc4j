package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.Notary;
import org.digidoc4j.ddoc.Signature;

/**
 * Interface for notary functions
 * @author  Veiko Sinivee
 * @version 1.0
 */
public interface NotaryFactory
{
    /**
     * initializes the implementation class
     */
    void init()
            throws DigiDocException;

    /**
     * Check the response and parse it's data
     * @param not initial Notary object that contains only the
     * raw bytes of an OCSP response
     * @returns Notary object with data parsed from OCSP response
     */
    Notary parseAndVerifyResponse(Signature sig, Notary not)
            throws DigiDocException;

}