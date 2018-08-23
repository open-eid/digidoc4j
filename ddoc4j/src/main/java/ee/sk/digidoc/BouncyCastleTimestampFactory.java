package ee.sk.digidoc;

import ee.sk.digidoc.factory.HttpAuthenticator;
import ee.sk.digidoc.factory.TimestampFactory;
import ee.sk.utils.ConfigManager;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

/**
 * Implements the TimestampFactory by using
 * BouncyCastle JCE toolkit
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class BouncyCastleTimestampFactory implements TimestampFactory
{
    /** log4j logger object */
    private Logger m_logger = null;

    /**
     * Creates new BouncyCastleTimestampFactory
     */
    public BouncyCastleTimestampFactory() {
        m_logger = LoggerFactory.getLogger(ee.sk.digidoc.factory.BouncyCastleTimestampFactory.class);
    }


    /**
     * initializes the implementation class
     */
    public void init()
            throws DigiDocException
    {
    }

    /**
     * Verifies this one timestamp
     * @param ts TimestampInfo object
     * @param tsaCert TSA certificate
     * @returns result of verification
     */
    public boolean verifyTimestamp(TimestampInfo ts, X509Certificate tsaCert)
            throws DigiDocException
    {
        boolean bOk = false;

        TimeStampToken tstok = ts.getTimeStampToken();
        if(m_logger.isDebugEnabled())
            m_logger.debug("Verifying TS: " + ts.getId() + " nr: " + ts.getSerialNumber() + " msg-imprint: " +
                    Base64Util.encode(tstok.getTimeStampInfo().getMessageImprintDigest()) + " real digest: " + Base64Util.encode(ts.getHash()));
        if(!SignedDoc.compareDigests(ts.getMessageImprint(), ts.getHash())) {
            m_logger.error("TS digest: " + Base64Util.encode(ts.getMessageImprint()) + " real digest: " + Base64Util.encode(ts.getHash()));
            throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY,
                    "Bad digest for timestamp: " + ts.getId(), null);
        }
        if(tstok != null) {

            if(m_logger.isDebugEnabled())
                m_logger.debug("TS: " + tstok.getTimeStampInfo().getSerialNumber());
            try {
                //TODO: fixme
                //tstok.validate(tsaCert, "BC");
                bOk = true;
            } catch(Exception ex) {
                bOk = false;
                m_logger.error("Timestamp verification error: " + ex);
                throw new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY, "Invalid timestamp: " + ex.getMessage(), ex);
            }
        }

        return bOk;
    }

    private int findTSAIndex(Signature sig, String cn) {
        int idx = 0;
        // hack - just look at first TSA
        if(m_logger.isDebugEnabled())
            m_logger.debug("Cearch index for: " + cn);
        int nTsas = ConfigManager.instance().getIntProperty("DIGIDOC_TSA_COUNT", 0);
        for(int i = 0; i < nTsas; i++) {
            String s1 = ConfigManager.instance().getProperty("DIGIDOC_TSA" + (i+1) + "_CN");
            if(s1 != null && s1.equals(cn))
                return i+1;
        }
        return idx;
    }

    private X509Certificate findTSACert(int idx)
            throws DigiDocException
    {
        return SignedDoc.readCertificate(ConfigManager.instance().getProperty("DIGIDOC_TSA" + idx + "_CERT"));
    }

    private X509Certificate findTSACACert(int idx)
            throws DigiDocException
    {
        String fname = ConfigManager.instance().getProperty("DIGIDOC_TSA" + idx + "_CA_CERT");
        if(m_logger.isDebugEnabled())
            m_logger.debug("Read ca cert: " + fname);
        return SignedDoc.readCertificate(fname);
    }

    /**
     * Verifies all timestamps in this signature and
     * return a list of errors.
     * @param sig signature to verify timestamps
     * @return list of errors. Empty if no errors.
     * @throws DigiDocException
     */
    public ArrayList verifySignaturesTimestamps(Signature sig)
    //	throws DigiDocException
    {
        Date d1 = null, d2 = null;
        ArrayList errs = new ArrayList();
        ArrayList tsaCerts = sig.findTSACerts();
        for(int t = 0; t < sig.countTimestampInfos(); t++)  {
            TimestampInfo ts = sig.getTimestampInfo(t);
            if(ts == null) break;
            if(ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIGNATURE)
                d1 = ts.getTime();
            if(ts.getType() == TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS)
                d2 = ts.getTime();
            boolean bVerified = false;
            DigiDocException ex2 = null;
            for(int j = 0; j < tsaCerts.size(); j++) {
                X509Certificate tsaCert = (X509Certificate)tsaCerts.get(j);
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Verifying TS: " + ts.getId() + " with: " +
                            SignedDoc.getCommonName(tsaCert.getSubjectDN().getName()));
                // try verifying with all possible TSA certs
                try {
                    if(verifyTimestamp(ts, tsaCert)) {
                        bVerified = true;
                        if(m_logger.isDebugEnabled())
                            m_logger.debug("TS: " + ts.getId() + " - OK");
                        break;
                    } else {
                        m_logger.error("TS: " + ts.getId() + " - NOK");
                    }
                } catch(DigiDocException ex) {
                    ex2 = ex;
                    m_logger.error("TS: " + ts.getId() + " - ERROR: " + ex);
                    //ex.printStackTrace(System.err);
                }
            }
            if(!bVerified) {
                errs.add(ex2);
            }
        }
        // now check that SignatureTimeStamp is before SigAndRefsTimeStamp
        if(d1 != null && d2 != null) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("SignatureTimeStamp: " + d1 + " SigAndRefsTimeStamp: " + d2);
            if(d1.after(d2)) {
                DigiDocException ex = new DigiDocException(DigiDocException.ERR_TIMESTAMP_VERIFY, "SignatureTimeStamp time must be before SigAndRefsTimeStamp time!", null);
                errs.add(ex);
            }
        }
        return errs;
    }

    /**
     * Generates a TS request and sends it to server. Returns answer if obtained
     * @param algorithm digest algorithm
     * @param digest digest value
     * @param url TSA server utl
     * @return response
     */
    public TimeStampResponse requestTimestamp(String algorithm, byte[] digest, String url)
    {
        try {
            if(m_logger.isDebugEnabled())
                m_logger.debug("TS req: " + algorithm + " dig-len: " + ((digest != null) ? digest.length : 0) + " url: " + url + " digest: " + Base64Util.encode(digest));
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            gen.setCertReq(true);
            TimeStampRequest req = gen.generate(algorithm, digest);
            if(m_logger.isDebugEnabled())
                m_logger.debug("TS req nonce: " + ((req.getNonce() != null) ? req.getNonce().toString() : "NULL") +
                        " msg-imprint: " + ((req.getMessageImprintDigest() != null) ? Base64Util.encode(req.getMessageImprintDigest()) : "NULL"));
            URL uUrl = new URL(url);
            // http authentication
            String ocspAuth = ConfigManager.instance().getProperty("DIGIDOC_OCSP_AUTH");
            if(ocspAuth != null) {
                String ocspAuthUser = ConfigManager.instance().getProperty("DIGIDOC_OCSP_AUTH_USER");
                String ocspAuthPasswd = ConfigManager.instance().getProperty("DIGIDOC_OCSP_AUTH_PASSWD");
                if(m_logger.isDebugEnabled())
                    m_logger.debug("OCSP http auth: " + ocspAuthUser + "/" + ocspAuthPasswd);
                HttpAuthenticator auth = new HttpAuthenticator(ocspAuthUser, ocspAuthPasswd);
                Authenticator.setDefault(auth);
            }
            if(m_logger.isDebugEnabled())
                m_logger.debug("Connecting to: " + url);
            URLConnection con = uUrl.openConnection();
            if(m_logger.isDebugEnabled())
                m_logger.debug("Conn opened: " + ((con != null) ? "OK" : "NULL"));
            con.setAllowUserInteraction(false);
            con.setUseCaches(false);
            con.setDoOutput(true);
            con.setDoInput(true);
            // send the OCSP request
            con.setRequestProperty("Content-Type", "application/timestamp-query");
            //con.setRequestProperty("Content-Type", "application/timestamp-request");
            OutputStream os = con.getOutputStream();
            if(m_logger.isDebugEnabled())
                m_logger.debug("OS: " + ((os != null) ? "OK" : "NULL"));
            if(os != null) {
                os.write(req.getEncoded());
                os.close();
            }
            if(m_logger.isDebugEnabled())
                m_logger.debug("Wrote: " + req.getEncoded().length);
            // read the response
            InputStream is = con.getInputStream();
            int cl = con.getContentLength();
            byte[] bresp = null;
            if(m_logger.isDebugEnabled())
                m_logger.debug("Recv: " + cl + " bytes");
            if(cl > 0) {
                int avail = 0;
                do {
                    avail = is.available();
                    byte[] data = new byte[avail];
                    int rc = is.read(data);
                    if(bresp == null) {
                        bresp = new byte[rc];
                        System.arraycopy(data, 0, bresp, 0, rc);
                    } else {
                        byte[] tmp = new byte[bresp.length + rc];
                        System.arraycopy(bresp, 0, tmp, 0, bresp.length);
                        System.arraycopy(data, 0, tmp, bresp.length, rc);
                        bresp = tmp;
                    }
                    cl -= rc;
                } while(cl > 0);
            }
            is.close();
            if(m_logger.isDebugEnabled())
                m_logger.debug("Received: " + ((bresp != null) ? bresp.length : 0) + " bytes");
            TimeStampResponse resp = ((bresp != null) ? new TimeStampResponse(bresp) : null);
            if(m_logger.isDebugEnabled() && resp != null && resp.getTimeStampToken() != null && resp.getTimeStampToken().getTimeStampInfo() != null)
                m_logger.debug("TS resp: " + resp.getTimeStampToken().getTimeStampInfo().getSerialNumber().toString() + " msg-imprint: " + Base64Util.encode(resp.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest()));

            return resp;
        } catch(Exception ex) {
            m_logger.error("Timestamp getting error: " + ex);

        }
        return null;
    }

    public TimeStampToken readTsTok(byte[] data)
    {
        try {
            ASN1InputStream aIn = new ASN1InputStream(data);
            //ContentInfo            info = ContentInfo.getInstance(aIn.readObject());
            CMSSignedData cmsD = new CMSSignedData(aIn);
            TimeStampToken tstok = new TimeStampToken(cmsD);
            if(m_logger.isDebugEnabled() && tstok != null && tstok.getTimeStampInfo() != null)
                m_logger.debug("TSTok: " + tstok.getTimeStampInfo().getSerialNumber().toString() + " hash: " + Base64Util.encode(tstok.getTimeStampInfo().getMessageImprintDigest()));
            return tstok;
        } catch(Exception ex) {
            m_logger.error("Timestamp getting error: " + ex);

        }
        return null;
    }


}
