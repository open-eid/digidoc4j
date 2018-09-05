package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.DigiDocException;

/**
 * Interface for canonicalization functions
 * @author  Veiko Sinivee
 * @version 1.0
 */
public interface CanonicalizationFactory {

    /**
     * initializes the implementation class
     */
    void init() throws DigiDocException;

    /**
     * Canonicalizes XML fragment using the
     * xml-c14n-20010315 algorithm
     * @param data input data
     * @param uri canonicalization algorithm
     * @returns canonicalized XML
     * @throws DigiDocException for all errors
     */
    byte[] canonicalize(byte[] data, String uri) throws DigiDocException;

}
