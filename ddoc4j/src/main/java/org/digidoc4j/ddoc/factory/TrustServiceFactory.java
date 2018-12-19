package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.DigiDocException;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Interface for TSL
 * @author  Veiko Sinivee
 * @version 1.0
 */
public interface TrustServiceFactory {

    /**
     * initializes the implementation class
     */
    void init()
            throws DigiDocException;

    /**
     * Finds direct CA cert for given user cert
     * @param cert user cert
     * @param bUseLocal use also ca certs registered in local config file
     * @return CA cert or null if not found
     * @deprecated use findCaForCert(X509Certificate cert, boolean bUseLocal, Date dtSigning)
     */
    X509Certificate findCaForCert(X509Certificate cert, boolean bUseLocal);

    /**
     * Finds direct CA cert for given user cert
     * @param cert user cert
     * @param bUseLocal use also ca certs registered in local config file
     * @param dtSigning signing timestamp. Used to pick correct ca if many of them apply
     * @return CA cert or null if not found
     */
    X509Certificate findCaForCert(X509Certificate cert, boolean bUseLocal, Date dtSigning);

    /**
     * Finds direct OCSP cert for given ocsp responder id
     * @param cn OCSP responder-id
     * @param bUseLocal use also ca certs registered in local config file
     * @param serialNr serial number or NULL
     * @return OCSP cert or null if not found
     */
    X509Certificate[] findOcspsByCNAndNr(String cn, boolean bUseLocal, String serialNr);

}

