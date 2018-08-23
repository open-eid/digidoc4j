package ee.sk.digidoc.factory;

import ee.sk.digidoc.*;
import ee.sk.utils.ConfigManager;
import ee.sk.utils.ConvertUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

/**
 * Factory class to handle generating signature elements according to
 * required signature type and version or in case of bdoc the profile
 * @author Veiko Sinivee
 */
public class DigiDocGenFactory {
    //private SignedDoc m_sdoc;
    private static Logger m_logger = LoggerFactory.getLogger(DigiDocGenFactory.class);
    private static final String DIGI_OID_TEST = "1.3.6.1.4.1.10015.3.2.1";
    private static final String DIGI_OID_LIVE1 = "1.3.6.1.4.1.10015.1.2.3.1";
    private static final String DIGI_OID_LIVE2 = "1.3.6.1.4.1.10015.1.2.3.2";
    private static final String DIGI_OID_LIVE_TEST = "1.3.6.1.4.1.10015.1.2";
    private static final String DIGI_OID_TEST_TEST = "1.3.6.1.4.1.10015.3.2";
    private static final int PRE2011_KEYLEN = 162;
    private static final String RMID_OID_TEST = "1.3.6.1.4.1.10015.3.3.1";
    private static final String ASUTUSE_OID_TEST = "1.3.6.1.4.1.10015.3.7.1";
    private static final String MID_OID_TEST = "1.3.6.1.4.1.10015.3.11.1";

    public static final String BDOC_210_OID = "urn:oid:1.3.6.1.4.1.10015.1000.3.2.1";
    public static final String BDOC_210_DIGEST_VALUE = "3Tl1oILSvOAWomdI9VeWV6IA/32eSXRUri9kPEz1IVs=";
    public static final String BDOC_210_DIGEST_HEX = "dd3975a082d2bce016a26748f5579657a200ff7d9e497454ae2f643c4cf5215b";
    public static final String BDOC_210_DIGEST_METHOD = SignedDoc.SHA256_DIGEST_ALGORITHM_1;
    public static final String BDOC_210_SPURI = "https://www.sk.ee/repository/bdoc-spec21.pdf";

    public static final String[] TEST_OIDS_PREFS = {
            "1.3.6.1.4.1.10015.3.7", "1.3.6.1.4.1.10015.7", // tempel test
            "1.3.6.1.4.1.10015.3.3", "1.3.6.1.4.1.10015.3.11", // mid test
            "1.3.6.1.4.1.10015.3.2", // digi-id test
            "1.3.6.1.4.1.10015.3.1" // est-eid test

    };

	/*
	1.3.6.1.4.1.10015.3.1.1 TEST-SK v?ljastatavate sertifikaatide sertifitseerimispoliitika versioon 1.0 1.3.6.1.4.1.10015.1.1.3.2 testsertifikaadid (ID-kaart)
	1.3.6.1.4.1.10015.3.2.1 TEST-SK v?ljastatavate sertifikaatide sertifitseerimispoliitika versioon 1.0 Eneli Kirme 1.3.6.1.4.1.10015.1.2.3.2 testsertifikaadid (digi-ID)
	1.3.6.1.4.1.10015.3.3.1 TEST-SK v?ljastatavate sertifikaatide sertifitseerimispoliitika versioon 1.0 Eneli Kirme 1.3.6.1.4.1.10015.1.3.1.1 testsertifikaadid (rMID)
	1.3.6.1.4.1.10015.3.7.1 TEST-SK v?ljastatavate sertifikaatide sertifitseerimispoliitika versioon 1.0 Eneli Kirme 1.3.6.1.4.1.10015.7.1.2.2 testsertifikaadid (asutuse serdid)
	1.3.6.1.4.1.10015.3.11.1 TEST-SK v?ljastatavate sertifikaatide sertifitseerimispoliitika versioon 1.0 Eneli Kirme 1.3.6.1.4.1.10015.11.1.2 testsertifikaadid (MID)
	*/
	/*public DigiDocGenFactory(SignedDoc sdoc)
	{
		m_sdoc = sdoc;
	}*/



    private static boolean certHasPolicy(X509Certificate cert, String sOid)
    {
        try {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Read cert policies: " + cert.getSerialNumber().toString());
            ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
            ASN1InputStream aIn = new ASN1InputStream(bIn);
            ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure obj = new X509CertificateStructure(seq);
            TBSCertificateStructure tbsCert = obj.getTBSCertificate();
            if (tbsCert.getVersion() == 3) {
                X509Extensions ext = tbsCert.getExtensions();
                if (ext != null) {
                    Enumeration en = ext.oids();
                    while (en.hasMoreElements()) {
                        Object o = en.nextElement();
                        if(o instanceof ASN1ObjectIdentifier) {
                            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)o;
                            //if(m_logger.isDebugEnabled())
                            //	m_logger.debug("Oid: " + oid.getId());
                            X509Extension extVal = ext.getExtension(oid);
                            ASN1OctetString oct = extVal.getValue();
                            ASN1InputStream extIn = new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()));
                            //if (oid.equals(X509Extensions.CertificatePolicies)) { // bc 146 ja jdk 1.6 puhul - X509Extension.certificatePolicies
                            if(oid.equals(X509Extension.certificatePolicies)) { // bc 146 ja jdk 1.6 puhul - X509Extension.certificatePolicies
                                ASN1Sequence cp = (ASN1Sequence)extIn.readObject();
                                for (int i = 0; i != cp.size(); i++) {
                                    PolicyInformation pol = PolicyInformation.getInstance(cp.getObjectAt(i));
                                    //DERObjectIdentifier dOid = null;
                                    if(pol != null) {
                                        String sId = pol.getPolicyIdentifier().getId();   //getPolicyIdentifier();
                                        if(sId != null) {
                                            if(m_logger.isDebugEnabled())
                                                m_logger.debug("Policy: " + sId);
                                            if(sId.startsWith(sOid))
                                                return true;
                                        }
                                    }
                                }
                            }
                        } // instanceof
                    }
                }

            }
        } catch(Exception ex) {
            m_logger.error("Error reading cert policies: " + ex);
        }
        return false;
    }



    public static boolean is2011Card(X509Certificate cert) {
        return ((cert != null) &&  (cert.getPublicKey() instanceof RSAPublicKey) &&
                ((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() == 2048);
    }

    public static boolean isDigiIdCard(X509Certificate cert) {
        return ((cert != null) &&  (cert.getPublicKey() instanceof RSAPublicKey) &&
                (((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() == 1024) &&
                //cert.getPublicKey().getEncoded().length > PRE2011_KEYLEN);
                (certHasPolicy(cert, DIGI_OID_LIVE_TEST) || certHasPolicy(cert, DIGI_OID_TEST_TEST) ||
                        certHasPolicy(cert, RMID_OID_TEST)|| certHasPolicy(cert, ASUTUSE_OID_TEST) ||
                        certHasPolicy(cert, MID_OID_TEST)));
    }

    public static boolean isPre2011IdCard(X509Certificate cert) {
        return ((cert != null) && (cert.getPublicKey() instanceof RSAPublicKey) &&
                (((RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() == 1024) &&
                //cert.getPublicKey().getEncoded().length <= PRE2011_KEYLEN);
                !certHasPolicy(cert, DIGI_OID_LIVE_TEST) && !certHasPolicy(cert, DIGI_OID_TEST_TEST));
    }

    public static boolean isTestCard(X509Certificate cert) {
        if(cert != null) {
            String cn = ConvertUtils.getCommonName(cert.getSubjectDN().getName());
            //if(cn != null && cn.indexOf("TEST") != -1)
            //	return true;
            for(int i = 0; i < TEST_OIDS_PREFS.length; i++) {
                String sOid = TEST_OIDS_PREFS[i];
                if(i == 1) {
                    if(certHasPolicy(cert, sOid) && cn != null && cn.indexOf("TEST") != -1)
                        return true;
                } else {
                    if(certHasPolicy(cert, sOid))
                        return true;
                }
            }
        }
        return false;
    }

    public static boolean isEcPubKey(X509Certificate cert)
    {
        return ((cert != null) && (cert.getPublicKey().getAlgorithm().equals("EC"))); //instanceof sun.security.ec.ECPublicKey));
    }

    /**
     * Create new SignedDoc object
     * @param format - SK-XML, DIGIDOC-XML, BDOC
     * @param version - 1.0, 1.1, 1.2, 1.3, bdoc has only 1.0 and 1.1
     * @param profile - BES, T, C-L, TM, TS, TM-A, TS-A
     */
    public static SignedDoc createSignedDoc(String format, String version, String profile)
            throws DigiDocException
    {
        String ver = version;
        if(format != null && format.equals(SignedDoc.FORMAT_BDOC)) {
            ver = SignedDoc.BDOC_VERSION_2_1;
            // if profile is not set then lookup default profile from config
            // if not set in config use TM as default
            if(profile == null || profile.trim().length() == 0)
                profile = ConfigManager.instance().getStringProperty("DIGIDOC_DEFAULT_PROFILE", SignedDoc.BDOC_PROFILE_TM);
        }
        if(format != null && (format.equals(SignedDoc.FORMAT_SK_XML) || format.equals(SignedDoc.FORMAT_DIGIDOC_XML))) {
            if(ver == null)
                ver = SignedDoc.VERSION_1_3;
            profile = SignedDoc.BDOC_PROFILE_TM; // in ddoc format we used only TM
        }
        if(m_logger.isDebugEnabled())
            m_logger.debug("Creating digidoc: " + format + " / " + ver + " / " + profile);
        SignedDoc sdoc = new SignedDoc(format, ver);
        sdoc.setProfile(profile);
        return sdoc;
    }

    private static void registerCert(X509Certificate cert, int type, String id, Signature sig)
            throws DigiDocException
    {
        String sid = id;
        if(sid != null) sid = sid.replace(" ", "_");
        CertValue cval = new CertValue(sid, cert, type, sig);
        sig.addCertValue(cval);
        CertID cid = new CertID(sig, cert, type);
        sig.addCertID(cid);
        if(type != CertID.CERTID_TYPE_SIGNER)
            cid.setUri("#" + cval.getId());
    }

    /**
     * Adds a new uncomplete signature to signed doc
     * @param sdoc SignedDoc object
     * @param profile new signature profile. Use NULL for default
     * @param cert signers certificate
     * @param claimedRoles signers claimed roles
     * @param adr signers address
     * @param sId new signature id, Use NULL for default value
     * @param sSigMethod signature method uri - ddoc: SignedDoc.RSA_SHA1_SIGNATURE_METHOD, bdoc: depends on card type. Use null for default value
     * @param sDigType digest type (all other hashes but SignedInfo). Use null for default type
     * @return new Signature object
     */
    public static Signature prepareXadesBES(SignedDoc sdoc, String profile,
                                            X509Certificate cert, String[] claimedRoles, SignatureProductionPlace adr,
                                            String sId, String sSigMethod, String sDigType)
            throws DigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Prepare signature in sdoc: " + sdoc.getFormat() + "/" + sdoc.getVersion() + "/" + sdoc.getProfile() +
                    " profile: " + profile + " signer: " + ((cert != null) ? SignedDoc.getCommonName(cert.getSubjectDN().getName()) : "unknown") +
                    " id " + sId);
        // count roles
        if(claimedRoles != null && claimedRoles.length > 1) {
            m_logger.error("Currently supports no more than 1 ClaimedRole");
            throw new DigiDocException(DigiDocException.ERR_UNSUPPORTED, "Currently supports no more than 1 ClaimedRole", null);
        }
        // cannot proceed if cert has not been read
        if(cert == null) {
            m_logger.error("Signers certificate missing during signature preparation!");
            throw new DigiDocException(DigiDocException.ERR_SIGNERS_CERT, "Signers certificate missing during signature preparation!", null);
        }
        boolean bCheckNonRepu = ConfigManager.instance().getBooleanProperty("KEY_USAGE_CHECK", true);
        if(bCheckNonRepu && !ConfigManager.isSignatureKey(cert)) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Signers cert does not have non-repudiation bit set!");
            throw new DigiDocException(DigiDocException.ERR_SIGNERS_CERT_NONREPUD, "Signers cert does not have non-repudiation bit set!", null);
        }
        Signature sig = new Signature(sdoc);
        sig.setId(sId != null ? sId : sdoc.getNewSignatureId());
        if(profile != null) { // use new profile for this signature
            sig.setProfile(profile);
            if(sdoc.getProfile() == null || sdoc.getProfile().equals(SignedDoc.BDOC_PROFILE_BES))
                sdoc.setProfile(profile); // change also container to new profile
        } else // use default profile
            sig.setProfile(sdoc.getProfile());

        // create SignedInfo block
        SignedInfo si = new SignedInfo(sig, ((sSigMethod != null) ? sSigMethod : SignedDoc.RSA_SHA1_SIGNATURE_METHOD), SignedDoc.CANONICALIZATION_METHOD_20010315);
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) &&
                sdoc.getVersion().equals(SignedDoc.BDOC_VERSION_2_1)) {
            si.setCanonicalizationMethod(SignedDoc.CANONICALIZATION_METHOD_1_1);
            sdoc.setDefaultNsPref(SignedDoc.FORMAT_BDOC);
        }
        if(m_logger.isDebugEnabled())
            m_logger.debug("Signer: " + cert.getSubjectDN().getName() + " EC key: " + isEcPubKey(cert) + " pre-2011: " + isPre2011IdCard(cert) + " digi-id: " + isDigiIdCard(cert) + " 2011: " + is2011Card(cert));
        if(sSigMethod == null) { // default values
            if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
                if(isPre2011IdCard(cert)) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Generating rsa-sha224 signature for pre-2011 card");
                    si.setSignatureMethod(SignedDoc.RSA_SHA224_SIGNATURE_METHOD);
                } else {
                    String dType = ConfigManager.instance().getStringProperty("DIGIDOC_DIGEST_TYPE", "SHA-256");
                    String sSigMeth = ConfigManager.digType2SigMeth(dType, isEcPubKey(cert));
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Generating digest: " + dType + " and signature: " + sSigMeth);
                    if(sSigMeth != null)
                        si.setSignatureMethod(sSigMeth);
                    else
                        throw new DigiDocException(DigiDocException.ERR_DIGEST_ALGORITHM, "Invalid digest type: " + dType, null);
                }
            }
        }
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            si.setId(sig.getId() + "-SignedInfo");
        // SignedDataObjectProperties
        SignedDataObjectProperties sdop = new SignedDataObjectProperties();
        // add DataFile references
        for(int i = 0; i < sdoc.countDataFiles(); i++) {
            DataFile df = sdoc.getDataFile(i);
            if(!df.isDigestsCalculated())
                df.calculateFileSizeAndDigest(null);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Add ref for df: " + df.getId());
            Reference ref = new Reference(si, df, sDigType);
            if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
                ref.setId(sig.getId() + "-ref-" + i);
            si.addReference(ref);
            if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) &&
                    sdoc.getVersion().equals(SignedDoc.BDOC_VERSION_2_1)) {
                DataObjectFormat dof = new DataObjectFormat("#"+ref.getId());
                dof.setMimeType(df.getMimeType());
                sdop.addDataObjectFormat(dof);
            }
        }
        // manifest.xml reference - bdoc 2.1-s ei allkirjasta manifest.xml-i
        // create key info
        KeyInfo ki = new KeyInfo(cert);
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            ki.setId(sig.getId() + "-KeyInfo");
        sig.setKeyInfo(ki);
        ki.setSignature(sig);
        registerCert(cert, CertValue.CERTVAL_TYPE_SIGNER, null, sig);
        if(m_logger.isDebugEnabled())
            m_logger.debug("Signer cert: " + cert.getSubjectDN().getName());
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
            // first lookup in TSL-s
            X509Certificate ca = tslFac.findCaForCert(cert, true, null);
            if(ca != null) {
                String caId = sig.getId() + "-CA_CERT" + sig.countCertValues();
                registerCert(ca, CertValue.CERTVAL_TYPE_CA, caId, sig);
            }
            // TODO: maybe copy local CA certs to signature until the first ca that is in TSL?
        }
        // create signed properties
        SignedProperties sp = new SignedProperties(sig, cert, claimedRoles, adr);
        sig.setSignedProperties(sp);
        // bdoc 2.0 nonce policy
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) &&
                sdoc.getVersion().equals(SignedDoc.BDOC_VERSION_2_1) &&
                (sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TM) ||
                        sig.getProfile().equals(SignedDoc.BDOC_PROFILE_BES) ||
                        sig.getProfile().equals(SignedDoc.BDOC_PROFILE_CL) ||
                        sig.getProfile().equals(SignedDoc.BDOC_PROFILE_TMA))) {
            sp.setSignedDataObjectProperties(sdop);
            Identifier id1 = new Identifier(Identifier.OIDAsURN);
            ObjectIdentifier oid1 = new ObjectIdentifier(id1);
            SignaturePolicyId spi1 = new SignaturePolicyId(oid1);
            spi1.setDigestAlgorithm(BDOC_210_DIGEST_METHOD);
            if(sdoc.getVersion().equals(SignedDoc.BDOC_VERSION_2_1)) {
                id1.setUri(BDOC_210_OID);
                spi1.setDigestValue(ConvertUtils.hex2bin(BDOC_210_DIGEST_HEX));
                spi1.addSigPolicyQualifier(new SpUri(BDOC_210_SPURI));
            }
            SignaturePolicyIdentifier spid1 = new SignaturePolicyIdentifier(spi1);
            sp.setSignaturePolicyIdentifier(spid1);
        } else {
            SignaturePolicyIdentifier spid1 = new SignaturePolicyIdentifier(null);
            sp.setSignaturePolicyIdentifier(spid1);
        }
        Reference ref = new Reference(si, sp, sDigType);
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC))
            ref.setId(sig.getId() + "-ref-sp");
        ref.setType(SignedDoc.SIGNEDPROPERTIES_TYPE);
        si.addReference(ref);
        sig.setSignedInfo(si);
        sdoc.addSignature(sig);
        if(m_logger.isDebugEnabled())
            m_logger.debug("Prepared signature: " + sig.getId() + "/" + sig.getProfile());

        return sig;
    }

    /**
     * Finalizes XAdES BES signature form by setting binary signature value
     * @param sig Signature object
     * @param sigVal signature value
     * @return completed signature
     * @throws DigiDocException
     */
    public static Signature finalizeXadesBES(Signature sig, byte[] sigVal)
            throws DigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Finalize XAdES-BES sigval: " + ((sigVal != null) ? sigVal.length : 0) + " bytes");
        if(sigVal != null)
            sig.setSignatureValue(sigVal);
        return sig;
    }

    public static Signature finalizeXadesT(SignedDoc sdoc, Signature sig)
            throws DigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Finalize XAdES-T: " + sig.getId() + " profile: " + sig.getProfile());
        UnsignedProperties usp = new UnsignedProperties(sig);
        sig.setUnsignedProperties(usp);
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            DigiDocXmlGenFactory genFac = new DigiDocXmlGenFactory(sdoc);
            TimestampFactory tsFac = ConfigManager.instance().getTimestampFactory();
            // get <SignatureValueTimeStamp>
            StringBuffer sb = new StringBuffer();
            String tsaUrl = ConfigManager.instance().getProperty("DIGIDOC_TSA_URL");
            genFac.signatureValue2xml(sb, sig.getSignatureValue(), true);
            String sSigValXml = sb.toString().trim();
            byte[] hash = SignedDoc.digestOfType(sSigValXml.getBytes(),
                    (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE));
            if(m_logger.isDebugEnabled())
                m_logger.debug("Get sig-val-ts for: " + Base64Util.encode(hash) + " uri: " + tsaUrl +
                        " DATA:\n---\n" + sSigValXml + "\n---\n");
            TimeStampResponse tresp = tsFac.requestTimestamp(TSPAlgorithms.SHA1.getId(), hash, tsaUrl);
            if(tresp != null) {
                TimestampInfo ti = new TimestampInfo(sig.getId() + "-T0", sig, TimestampInfo.TIMESTAMP_TYPE_SIGNATURE, hash, tresp);
                ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-SIG"));
                sig.addTimestampInfo(ti);
                try {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Timestamp: " + Base64Util.encode(tresp.getEncoded()));
                } catch(Exception ex) {}
                //sb = new StringBuffer();
                //genFac.timestampInfo2xml(sb, ti, true);
                //String sToXml = sb.toString();
                // TODO: add TSA refs and certs ? Not in TSL yet!
                sig.setProfile(SignedDoc.BDOC_PROFILE_T);
                try {
                    X509Certificate cert = SignedDoc.readCertificate(new java.io.File("/Users/veiko/workspace/jdigidoc/trunk/iaik-tsa.crt"));

        	  /*Store st = tresp.getTimeStampToken().getCertificates();
        	  if(st  != null) {
        		  SignerInformationStore  signers = st.getSignerInfos();
        		  Collection              c = signers.getSigners();
        		  Iterator                it = c.iterator();

        		  while (it.hasNext())
        		  {
        		      SignerInformation   signer = (SignerInformation)it.next();
        		      Collection          certCollection = certStore.getMatches(signer.getSID());

        		      Iterator              certIt = certCollection.iterator();
        		      X509CertificateHolder cert = (X509CertificateHolder)certIt.next();


        		  }
        	  }*/
                }catch(Exception ex) {
                    m_logger.error("Error ts: " + ex);
                }
            }
        }
        return sig;
    }

    public static Signature finalizeXadesC(SignedDoc sdoc, Signature sig)
            throws DigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Finalize XAdES-C: " + sig.getId() + " profile: " + sig.getProfile());
        CompleteRevocationRefs rrefs = new CompleteRevocationRefs();
        CompleteCertificateRefs crefs = new CompleteCertificateRefs();
        UnsignedProperties usp = sig.getUnsignedProperties();
        if(usp == null) {
            usp = new UnsignedProperties(sig);
            sig.setUnsignedProperties(usp);
        }
        usp.setCompleteCertificateRefs(crefs);
        usp.setCompleteRevocationRefs(rrefs);
        rrefs.setUnsignedProperties(usp);
        crefs.setUnsignedProperties(usp);
        sig.setUnsignedProperties(usp);
        sig.setProfile(SignedDoc.BDOC_PROFILE_CL);
        // TODO: update certs and refs

        return sig;
    }

    public static String getUserInfo(String format, String formatVer)
    {
        StringBuffer sb = null;
        try {
            sb = new StringBuffer("LIB ");
            sb.append(SignedDoc.LIB_NAME);
            sb.append("/");
            sb.append(SignedDoc.LIB_VERSION);
            if(format != null && formatVer != null) {
                sb.append(" format: ");
                sb.append(format);
                sb.append("/");
                sb.append(formatVer);
            }
            sb.append(" Java: ");
            sb.append(System.getProperty("java.version"));
            sb.append("/");
            sb.append(System.getProperty("java.vendor"));
            sb.append(" OS: ");
            sb.append(System.getProperty("os.name"));
            sb.append("/");
            sb.append(System.getProperty("os.arch"));
            sb.append("/");
            sb.append(System.getProperty("os.version"));
            sb.append(" JVM: ");
            sb.append(System.getProperty("java.vm.name"));
            sb.append("/");
            sb.append(System.getProperty("java.vm.vendor"));
            sb.append("/");
            sb.append(System.getProperty("java.vm.version"));
        } catch(Throwable ex) {
            m_logger.error("Error reading java system properties: " + ex);
        }
        return ((sb != null) ? sb.toString() : null);
    }

    public static Signature finalizeXadesXL_TM(SignedDoc sdoc, Signature sig)
            throws DigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Finalize XAdES-TM: " + sig.getId() + " profile: " + sig.getProfile());
        NotaryFactory notFac = ConfigManager.instance().getNotaryFactory();
        X509Certificate cert = sig.getKeyInfo().getSignersCertificate();
        TrustServiceFactory tslFac = ConfigManager.instance().getTslFactory();
        String ocspUrl = tslFac.findOcspUrlForCert(cert, 0, true);
        if(ocspUrl == null)
            ocspUrl = ConfigManager.instance().getProperty("DIGIDOC_OCSP_RESPONDER_URL");
        X509Certificate caCert = tslFac.findCaForCert(cert, true, null);
        if(m_logger.isDebugEnabled())
            m_logger.debug("Get confirmation for cert: " +
                    ((cert != null) ? ConvertUtils.getCommonName(cert.getSubjectDN().getName()) : "NULL") +
                    " CA: " + ((caCert != null) ? ConvertUtils.getCommonName(caCert.getSubjectDN().getName()) : "NULL") +
                    " URL: " + ((ocspUrl != null) ? ocspUrl : "NONE"));
        Notary not = notFac.getConfirmation(sig, cert, caCert, null, ocspUrl);
        if(m_logger.isDebugEnabled())
            m_logger.debug("Resp-id: " + ((not != null) ? not.getResponderId() : "NULL"));
        String sRespId = null;
        if(not != null)
            sRespId = ConvertUtils.getCommonName(not.getResponderId());
        //if(sRespId != null && sRespId.startsWith("byName: ")) sRespId = sRespId.substring("byName: ".length());
        //if(sRespId != null && sRespId.startsWith("byKey: ")) sRespId = sRespId.substring("byKey: ".length());
        X509Certificate rcert = null;
        if(not != null)
            rcert = notFac.getNotaryCert(sRespId, not.getCertNr());
        if(m_logger.isDebugEnabled())
            m_logger.debug("Find responder cert by: " + sRespId + " and nr: " + ((not != null) ? not.getCertNr() : "NULL") +
                    " found: " + ((rcert != null) ? "OK" : "NO") + " format: " + sdoc.getFormat());
        // if the request was successful then
        // create new data memebers
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) && (rcert != null)) {
            X509Certificate rcacert = tslFac.findCaForCert(rcert, true, null);
            if(m_logger.isDebugEnabled())
                m_logger.debug("Register responders CA: " + ((rcacert != null) ? rcacert.getSubjectDN().getName() : "NULL"));
            if(rcacert != null) {
                String caId = not.getId() + "-CA_CERT" + sig.countCertValues();
                registerCert(rcacert, CertID.CERTID_TYPE_RESPONDER_CA, caId, sig);
            } else {
                m_logger.error("Responder ca not found for resp-id: " + sRespId);
            }
        }
        // add notary to list
        //sig.getUnsignedProperties().addNotary(not);
        // add ocsp ref for this notary
        OcspRef orf = new OcspRef("#" + not.getId(), not.getResponderId(), not.getProducedAt(),
                (sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_ALGORITHM_1 : SignedDoc.SHA1_DIGEST_ALGORITHM),
                SignedDoc.digestOfType(not.getOcspResponseData(), (sdoc.getFormat().
                        equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE)));
        sig.getUnsignedProperties().getCompleteRevocationRefs().addOcspRef(orf);
        // mark status
        sig.setProfile(SignedDoc.BDOC_PROFILE_TM);
        // change profile
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) && sig.getPath() != null) {
            if(m_logger.isDebugEnabled())
                m_logger.debug("Find signature: " + sig.getPath());
            ManifestFileEntry mfe = sdoc.findManifestEntryByPath(sig.getPath());
            if(mfe != null) {
                mfe.setMediaType(SignedDoc.MIME_SIGNATURE_BDOC_ + sdoc.getVersion() + "/" + sig.getProfile());
                if(m_logger.isDebugEnabled())
                    m_logger.debug("Change signature: " + sig.getPath() + " type: " + mfe.getMediaType());
            }
        }
        // TODO: update certs and refs
        return sig;
    }

    public static Signature finalizeXadesXL_TS(SignedDoc sdoc, Signature sig)
            throws DigiDocException
    {
        if(m_logger.isDebugEnabled())
            m_logger.debug("Finalize XAdES-TS: " + sig.getId() + " profile: " + sig.getProfile());
        if(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC)) {
            DigiDocXmlGenFactory genFac = new DigiDocXmlGenFactory(sdoc);
            TimestampFactory tsFac = ConfigManager.instance().getTimestampFactory();
            String sTsaCert = ConfigManager.instance().getStringProperty("DIGIDOC_TSA_CRT", null);
            if(sTsaCert != null) {
                if(m_logger.isDebugEnabled())
                    m_logger.debug("TSA cert: " + sTsaCert);
                X509Certificate tsaCrt = SignedDoc.readCertificate(sTsaCert);
                if(tsaCrt != null) {
                    if(m_logger.isDebugEnabled())
                        m_logger.debug("Add tsa cert: " + tsaCrt.getSubjectDN().getName());
                    registerCert(tsaCrt, CertID.CERTID_TYPE_TSA, sig.getId() + "-TSA", sig);
                }
            }
            sig.setProfile(SignedDoc.BDOC_PROFILE_TS);
            // get <SigAndRefsTimeStamp>
        /* SignAndRefsTimestam not used in bdoc 2.0 any more
        StringBuffer sb = new StringBuffer();
        String tsaUrl = ConfigManager.instance().getProperty("DIGIDOC_TSA_URL");
        genFac.signatureValue2xml(sb, sig.getSignatureValue(), true);
        //String sSigValXml = sb.toString().trim();
        genFac.completeCertificateRefs2xml(sb, sig.getUnsignedProperties().getCompleteCertificateRefs(), sig, true);
        genFac.completeRevocationRefs2xml(sb, sig.getUnsignedProperties().getCompleteRevocationRefs(), sig, true);
        String sSigAndRefsDat = sb.toString().trim();
        byte[] hash = SignedDoc.digestOfType(sSigAndRefsDat.getBytes(),
        		(sdoc.getFormat().equals(SignedDoc.FORMAT_BDOC) ? SignedDoc.SHA256_DIGEST_TYPE : SignedDoc.SHA1_DIGEST_TYPE));
        if(m_logger.isDebugEnabled())
        	m_logger.debug("Get sig-val-ts for: " + Base64Util.encode(hash) + " uri: " + tsaUrl +
        			" DATA:\n---\n" + sSigAndRefsDat + "\n---\n");
        TimeStampResponse tresp = tsFac.requestTimestamp(TSPAlgorithms.SHA1.getId(), hash, tsaUrl);
        if(tresp != null) {
          TimestampInfo ti = new TimestampInfo(sig.getId() + "-T1", sig, TimestampInfo.TIMESTAMP_TYPE_SIG_AND_REFS, hash, tresp);
          ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-SIG"));
          ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-T0"));
          ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-CERTREFS"));
          ti.addIncludeInfo(new IncludeInfo("#" + sig.getId() + "-REVOCREFS"));
          sig.addTimestampInfo(ti);
          sig.setProfile(SignedDoc.BDOC_PROFILE_TS);
        }*/
        }
        return sig;
    }

    /**
     * Finalize signature to desired level
     * @param sdoc SignedDoc object
     * @param sig Signature object
     * @param sigVal signature value
     * @param profile profile. Use null for default (e.g. profile in signed doc)
     * @return finalized signature
     */
    public static Signature finalizeSignature(SignedDoc sdoc, Signature sig, byte[] sigVal, String profile)
            throws DigiDocException
    {
        String prf = profile;
        if(prf == null)
            prf = sdoc.getProfile();
        if(m_logger.isDebugEnabled())
            m_logger.debug("Finalize sig: " + sig.getId() + " profile: " + prf + " sdoc: " + sdoc.getFormat() + "/" + sdoc.getVersion());
        // xades-bes
        finalizeXadesBES(sig, sigVal);
        if(prf != null) {
            // T
            if(prf.equals(SignedDoc.BDOC_PROFILE_T) ||
                    prf.equals(SignedDoc.BDOC_PROFILE_CL) ||
                    prf.equals(SignedDoc.BDOC_PROFILE_TS))
                finalizeXadesT(sdoc, sig);
            // C-L
            if(prf.equals(SignedDoc.BDOC_PROFILE_CL) ||
                    prf.equals(SignedDoc.BDOC_PROFILE_TM) ||
                    prf.equals(SignedDoc.BDOC_PROFILE_TS))
                finalizeXadesC(sdoc, sig);
            // TM
            if(prf.equals(SignedDoc.BDOC_PROFILE_TM))
                finalizeXadesXL_TM(sdoc, sig);
            // TS
            if(prf.equals(SignedDoc.BDOC_PROFILE_TS))
                finalizeXadesXL_TS(sdoc, sig);

        }
        return sig;
    }

}
