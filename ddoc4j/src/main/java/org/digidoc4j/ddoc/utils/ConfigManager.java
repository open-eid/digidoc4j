package org.digidoc4j.ddoc.utils;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.factory.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Properties;

/**
 * Configuration reader for JDigiDoc
 */
public class ConfigManager {
    /** Resource bundle */
    private static Properties m_props = null;
    /** singleton instance */
    private static ConfigManager m_instance = null;
    /** notary factory instance */
    private static NotaryFactory m_notFac = null;
    /** canonicalization factory instance */
    private static CanonicalizationFactory m_canFac = null;

    /** log4j logger */
    private static Logger m_logger = LoggerFactory.getLogger(ConfigManager.class);
    private static SignatureFactory m_sigFac = null;
    private static TrustServiceFactory m_tslFac = null;

    /**
     * Singleton accessor
     */
    public static ConfigManager instance() {
        if(m_instance == null)
            m_instance = new ConfigManager();
        return m_instance;
    }

    /**
     * ConfigManager default constructor
     */
    private ConfigManager() {
    }

    /**
     * Resets the configuration table
     */
    public void reset() {
        m_props = new Properties();
    }

    /**
     * Checks if this certificate has non-repudiation bit set
     * @param cert X509Certificate object
     * @return true if ok
     */
    public static boolean isSignatureKey(X509Certificate cert)
    {
        if(cert != null) {
            boolean keyUsages[] = cert.getKeyUsage();
            if(keyUsages != null && keyUsages.length > 2 && keyUsages[1] == true)
                return true;
        }
        return false;
    }

    /**
     * Add provider used in many methods of this library
     */
    public static Provider addProvider()
    {
        try {
            String s = ConfigManager.
                    instance().getStringProperty("DIGIDOC_SECURITY_PROVIDER",
                    "org.bouncycastle.jce.provider.BouncyCastleProvider");
            Provider prv = (Provider)Class.forName(ConfigManager.
                    instance().getStringProperty("DIGIDOC_SECURITY_PROVIDER",
                    "org.bouncycastle.jce.provider.BouncyCastleProvider")).newInstance();
            Security.addProvider(prv);
            return prv;
        } catch(Exception ex) {
            m_logger.error("Error adding provider: " + ex);
        }
        return null;
    }

    /**
     * Init method for reading the config data
     * from a properties file. Note that this method
     * doesn't reset the configuration table held in
     * memory. Thus you can use it multpile times and
     * add constantly new configuration entries. Use the
     * reset() method to reset the configuration table.
     * @param cfgFileName config file anme or URL
     * @return success flag
     */
    public static boolean init(String cfgFileName) {
        boolean bOk = false;
        try {
            if(m_props == null)
                m_props = new Properties();
            InputStream isCfg = null;
            URL url = null;
            if(cfgFileName.startsWith("http")) {
                url = new URL(cfgFileName);
                isCfg = url.openStream();
            } else if(cfgFileName.startsWith("jar://")) {
                ClassLoader cl = ConfigManager.class.getClassLoader();
                isCfg = cl.getResourceAsStream(cfgFileName.substring(6));
            } else {
                isCfg = new FileInputStream(cfgFileName);
            }
            m_props.load(isCfg);
            isCfg.close();
            url = null;
            bOk = true;
        } catch (Exception ex) {
            m_logger.error("Cannot read config file: " +
                    cfgFileName + " Reason: " + ex.toString());
        }
        // initialize
        return bOk;
    }

    /**
     * Init method for settings the config data
     * from a any user defined source
     * @param hProps config data
     */
    public static void init(Hashtable hProps) {
        m_props = new Properties();
        m_props.putAll(hProps);
    }

    /**
     * Returns the TrustServiceFactory instance
     * @return TrustServiceFactory implementation
     */
    public TrustServiceFactory getTslFactory()
            throws DigiDocException
    {
        try {
            if(m_tslFac == null) {
                m_tslFac = (TrustServiceFactory)Class.
                        forName(getProperty("DIGIDOC_TSLFAC_IMPL")).newInstance();
                if(m_tslFac != null) {
                    m_tslFac.init();
                }
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_INIT_SIG_FAC);
        }
        return m_tslFac;
    }

    /**
     * Returns the NotaryFactory instance
     * @return NotaryFactory implementation
     */
    public NotaryFactory getNotaryFactory()
            throws DigiDocException
    {
        try {
            if(m_notFac == null) {
                m_notFac = (NotaryFactory)Class.
                        forName(getProperty("DIGIDOC_NOTARY_IMPL")).newInstance();
                m_notFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_NOT_FAC_INIT);
        }
        return m_notFac;
    }

    /**
     * Returns the DigiDocFactory instance
     * @return DigiDocFactory implementation
     */
    public DigiDocFactory getDigiDocFactory()
            throws DigiDocException
    {
        DigiDocFactory ddocFac = null;
        try {
            ddocFac = (DigiDocFactory)Class.
                    forName(getProperty("DIGIDOC_FACTORY_IMPL")).newInstance();
            ddocFac.init();
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_DIG_FAC_INIT);
        }
        return ddocFac;
    }


    /**
     * Returns the CanonicalizationFactory instance
     * @return CanonicalizationFactory implementation
     */
    public CanonicalizationFactory getCanonicalizationFactory()
            throws DigiDocException
    {
        try {
            if(m_canFac == null) {
                m_canFac = (CanonicalizationFactory)Class.
                        forName(getProperty("CANONICALIZATION_FACTORY_IMPL")).newInstance();
                m_canFac.init();
            }
        } catch(DigiDocException ex) {
            throw ex;
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_CAN_FAC_INIT);
        }
        return m_canFac;
    }

    /**
     * Retrieves the value for the spcified key
     * @param key property name
     */
    public String getProperty(String key) {
        return m_props.getProperty(key);
    }

    /**
     * Retrieves a string value for the specified key
     * @param key property name
     * @param def default value
     */
    public String getStringProperty(String key, String def) {
        return m_props.getProperty(key, def);
    }

    public void setStringProperty(String key, String value) {
        if(m_props != null)
            m_props.put(key, value);
    }

    /**
     * Retrieves an int value for the specified key
     * @param key property name
     * @param def default value
     */
    public int getIntProperty(String key, int def) {
        int rc = def;
        try {
            String s = m_props.getProperty(key);
            if(s != null && s.trim().length() > 0)
                rc = Integer.parseInt(s);
        } catch(NumberFormatException ex) {
            m_logger.error("Error parsing number: " + key, ex);
        }
        return rc;
    }

    /**
     * Retrieves a long value for the specified key
     * @param key property name
     * @param def default value
     */
    public long getLongProperty(String key, long def) {
        long rc = def;
        try {
            String s = m_props.getProperty(key);
            if(s != null && s.trim().length() > 0)
                rc = Long.parseLong(s);
        } catch(NumberFormatException ex) {
            m_logger.error("Error parsing number: " + key, ex);
        }
        return rc;
    }

    /**
     * Retrieves a boolean value for the specified key
     * @param key property name
     * @param def default value
     */
    public boolean getBooleanProperty(String key, boolean def) {
        boolean rc = def;
        try {
            String s = m_props.getProperty(key);
            if(s != null) {
                if(s.trim().equalsIgnoreCase("TRUE"))
                    rc = true;
                if(s.trim().equalsIgnoreCase("FALSE"))
                    rc = false;
            }
        } catch(NumberFormatException ex) {
            m_logger.error("Error parsing boolean: " + key, ex);
        }
        return rc;
    }

    /**
     * Returns default digest type value
     * @param sdoc SignedDoc object
     * @return default digest type
     */
    public String getDefaultDigestType(SignedDoc sdoc)
    {
        return SignedDoc.SHA1_DIGEST_TYPE;
    }

    /**
     * Returns digest algorithm URI corresponding to
     * searched digest type value
     * @param digType digest type
     * @return digest algorithm URI
     */
    public static String digType2Alg(String digType)
    {
        if(digType != null) {
            if(digType.equals(SignedDoc.SHA1_DIGEST_TYPE))
                return SignedDoc.SHA1_DIGEST_ALGORITHM;
        }
        return null;
    }

    /**
     * Returns signature method URI corresponding to
     * searched digest type value
     * @param sigMeth signature method uri
     * @param bCvc CVC or ASN.1 cipher (only used for ECDSA ciphers)
     * @return signature method URI
     */
    public static String sigMeth2SigType(String sigMeth, boolean bCvc)
    {
        if(sigMeth != null) {
            if(sigMeth.equals(SignedDoc.ECDSA_SHA1_SIGNATURE_METHOD))
                return bCvc ? "SHA1withCVC-ECDSA" : "SHA1withECDSA";
            if(sigMeth.equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD))
                return "SHA1withRSA";
        }
        return null;
    }

    /**
     * Returns digest type for given algorithm URI
     * @param digAlg digest algorithm URI
     * @return digest type
     */
    public static String digAlg2Type(String digAlg)
    {
        if(digAlg != null) {
            if(digAlg.equals(SignedDoc.SHA1_DIGEST_ALGORITHM))
                return SignedDoc.SHA1_DIGEST_TYPE;
        }
        return null;
    }

    /**
     * Returns digest type for given signature method URI
     * @param sigMeth signature method algorithm URI
     * @return digest type
     */
    public static String sigMeth2Type(String sigMeth)
    {
        if(sigMeth != null) {
            if(sigMeth.equals(SignedDoc.RSA_SHA1_SIGNATURE_METHOD))
                return SignedDoc.SHA1_DIGEST_TYPE;
            if(sigMeth.equals(SignedDoc.ECDSA_SHA1_SIGNATURE_METHOD))
                return SignedDoc.SHA1_DIGEST_TYPE;
        }
        return null;
    }

}
