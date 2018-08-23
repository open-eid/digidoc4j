package ee.sk.digidoc.factory;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.Signature;
import ee.sk.digidoc.TimestampInfo;
import org.bouncycastle.tsp.TimeStampResponse;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * Interface for timestamp functions
 * @author  Veiko Sinivee
 * @version 1.0
 */
public interface TimestampFactory {

    /**
     * initializes the implementation class
     */
    public void init()
            throws DigiDocException;

    /**
     * Verifies this one timestamp
     * @param ts TimestampInfo object
     * @param tsaCert TSA certificate
     * @returns result of verification
     */
    public boolean verifyTimestamp(TimestampInfo ts, X509Certificate tsaCert)
            throws DigiDocException;

    /**
     * Verifies all timestamps in this signature and
     * return a list of errors.
     * @param sig signature to verify timestamps
     * @return list of errors. Empty if no errors.
     * @throws DigiDocException
     */
    public ArrayList verifySignaturesTimestamps(Signature sig);
    //	throws DigiDocException;

    /**
     * Generates a TS request and sends it to server. Returns answer if obtained
     * @param algorithm digest algorithm
     * @param digest digest value
     * @param url TSA server utl
     * @return response
     */
    public TimeStampResponse requestTimestamp(String algorithm, byte[] digest, String url);

}
