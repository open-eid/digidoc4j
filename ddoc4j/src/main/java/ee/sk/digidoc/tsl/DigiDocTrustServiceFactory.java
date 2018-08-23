package ee.sk.digidoc.tsl;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.factory.TrustServiceFactory;
import ee.sk.utils.ConfigManager;
import ee.sk.utils.ConvertUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.Principal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Vector;

/**
 * SAX implementation of TrustServiceFactory
 * Provides methods for reading a DigiDoc file
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class DigiDocTrustServiceFactory 
	implements TrustServiceFactory
{
	/** log4j logger */
	private static Logger m_logger = LoggerFactory.getLogger(DigiDocTrustServiceFactory.class);
	/** TSL list */
	private List m_tsls;
	
	
	/** 
     * initializes the implementation class 
     */
    public void init()
        throws DigiDocException
    {
    	try {
    		ConfigManager cfg = ConfigManager.instance();
    		// read in local jdigidoc config file
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("Reading local config file");
    		TrustServiceStatusList tsl = new TrustServiceStatusList();
    		SchemeInformation si = new SchemeInformation();
    		si.setVersionIdentifier(1);
    		si.setSequenceNumber(1);
    		si.setType(SchemeInformation.TYPE_LOCAL);
    		tsl.setSchemeInformation(si);
    		m_tsls = new ArrayList();
    		m_tsls.add(tsl);
    		// read CA-s
    		int nCas = cfg.getIntProperty("DIGIDOC_CAS", 0);
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("CA-s: " + nCas);
    		for(int c = 1; c <= nCas; c++) {
    			TrustServiceProvider tsp = addTspProvider(
    					cfg.getStringProperty("DIGIDOC_CA_" + c + "_NAME", null), 
    					cfg.getStringProperty("DIGIDOC_CA_" + c + "_TRADENAME", null));
    			int nCerts = cfg.getIntProperty("DIGIDOC_CA_" + c + "_CERTS", 0);
    			for(int n = 1; n <= nCerts; n++) {
    				String certLoc = cfg.getStringProperty("DIGIDOC_CA_" + c + "_CERT" + n, null);
    				if(m_logger.isDebugEnabled())
            			m_logger.debug("CA" + c + " ca-cert" + n + " - " + certLoc);
    				try {
    				  X509Certificate cert = readCertificate(certLoc);
    				  if(cert != null && tsp != null) 
    					addCATspService(tsp, cert);
    				} catch(Exception ex2) {
    					m_logger.warn("Failed to read CA cert: " + certLoc);
    				}
    			}
    			int nOcsps = cfg.getIntProperty("DIGIDOC_CA_" + c + "_OCSPS", 0);
    			if(m_logger.isDebugEnabled())
        			m_logger.debug("OCSP-s: " + nOcsps);
    			for(int n = 1; n <= nOcsps; n++) {
    				String certLoc = cfg.getStringProperty("DIGIDOC_CA_" + c + "_OCSP" + n + "_CERT", null);
    				if(m_logger.isDebugEnabled())
            			m_logger.debug("CA" + c + " ocsp-cert" + n + " - " + certLoc);
    				TSPService tsps = null;
    				try {
    				  X509Certificate cert = readCertificate(certLoc);
    				  if(cert != null && tsp != null) {
    				    tsps = addOcspTspService(tsp, cert,
    						cfg.getStringProperty("DIGIDOC_CA_" + c + "_OCSP" + n + "_CN", null),
    						cfg.getStringProperty("DIGIDOC_CA_" + c + "_OCSP" + n + "_URL", null),
    						cfg.getStringProperty("DIGIDOC_CA_" + c + "_OCSP" + n + "_CN", null),
    						cfg.getStringProperty("DIGIDOC_CA_" + c + "_OCSP" + n + "_CA_CN", null));
    				  }
    				} catch(Exception ex2) {
    					m_logger.warn("Failed to read OCSP responder cert: " + certLoc);
    				}
    				int j = 1;
    				do {
    					certLoc = cfg.getStringProperty("DIGIDOC_CA_" + c + "_OCSP" + n + "_CERT_" + j, null);
        				if(m_logger.isDebugEnabled())
                			m_logger.debug("CA" + c + " ocsp-cert" + n + "/" + j + " - " + certLoc);
    					if(certLoc != null && tsps != null) {
    						try {
    							X509Certificate cert = readCertificate(certLoc);
    		    				  if(cert != null) {
    		    				    tsps.addCertificate(cert);
    		    				  }
    						} catch(Exception ex) {
    							m_logger.warn("Failed to read OCSP responder cert: " + certLoc);
    						}
    					}
    					j++;
    				} while(certLoc != null);
    				// TODO: authority-key-identifier
    			}
    			if(m_logger.isDebugEnabled())
        			m_logger.debug("Local config: " + tsl);
    			
    		}
    		// Read TSL-s
    		// read in all other TSL-s in tsl dir
			String sTslDir = cfg.getStringProperty("DIGIDOC_TSL_DIR", null);
			if(sTslDir != null && sTslDir.length() > 0) {
				File fTslDir = new File(sTslDir);
				File[] lTsls = fTslDir.listFiles();
				for(int i = 0; (lTsls != null) && (i < lTsls.length); i++) {
					File f = lTsls[i];
					if(f.isFile() && f.canRead()) {
						if(m_logger.isDebugEnabled())
		        			m_logger.debug("Reading TSL: " + f.getAbsolutePath());
						TslParser parser = new TslParser();
						FileInputStream fis = new FileInputStream(f);
						TrustServiceStatusList tsl2 = parser.readTSL(fis);
						fis.close();
						if(tsl2 != null) {
							if(m_logger.isDebugEnabled())
			        			m_logger.debug("Got TSL: " + tsl2);
							m_tsls.add(tsl2);
						}
					}
				}
			}
    		
    	} catch(DigiDocException ex) {
    		m_logger.error("Error init TrustServiceFactory dd: " + ex);
    		ex.printStackTrace();
    		throw ex;
    	} catch(Exception ex) {
    		m_logger.error("Error init TrustServiceFactory: " + ex);
    		ex.printStackTrace();
    	}
    }
    
    /**
     * Find tsl by type name
     * @param type tsl type
     * @return TrustServiceStatusList object if found or null
     */
    private TrustServiceStatusList findTslByType(String type)
    {
    	for(int i = 0; (m_tsls != null) && (i < m_tsls.size()); i++) {
    		TrustServiceStatusList tsl = (TrustServiceStatusList)m_tsls.get(i);
    		if(tsl.getSchemeInformation() != null && 
    				tsl.getSchemeInformation().getType() != null &&
    				tsl.getSchemeInformation().getType().equals(type))
    			return tsl;
    	}
    	return null;
    }
    
    /**
     * Adds info of a new Trust service provider
     * @param name short name [optional]
     * @param tradeName long name [optional]
     * @return TrustServiceProvider object
     */
    public TrustServiceProvider addTspProvider(String name, String tradeName)
    {
    	TrustServiceStatusList tsl = findTslByType(SchemeInformation.TYPE_LOCAL);
    	if(tsl != null) {
    		TrustServiceProvider tsp = new TrustServiceProvider();
    		tsl.addTrustServiceProvider(tsp);
    		TSPInformation tsi = new TSPInformation();
    		tsi.addName(new MultiLangString(null, name));
    		tsi.addTradeName(new MultiLangString(null, tradeName));
    		tsp.setTSPInformation(tsi);
    		return tsp;
    	}
    	return null;
    }
    
    /**
     * Add new CA service
     * @param tspProvider TSP provider
     * @param cert ca cert
     * @return TSPService object
     */
    public TSPService addCATspService(TrustServiceProvider tspProvider, X509Certificate cert)
    {
    	TSPService tsps = new TSPService();
    	tsps.setType(TSPService.TSP_TYPE_CA_QC);
    	tsps.addCertificate(cert);
    	tsps.addSubjectName(new MultiLangString(null, cert.getSubjectDN().getName()));
    	tsps.addName(new MultiLangString(null, ConvertUtils.getCommonName(cert.getSubjectDN().getName())));
    	tsps.setCn(ConvertUtils.getCommonName(cert.getSubjectDN().getName()));
    	tspProvider.addTSPService(tsps);
    	return tsps;
    }
    
    /**
     * Add new OCSP service
     * @param tspProvider TSP provider
     * @param cert ca cert
     * @param name service name
     * @param oscpUrl OCSP responder url
     * @param cn OCSP responder id
     * @param caCn responder ca CN
     * @return TSPService object
     */
    public TSPService addOcspTspService(TrustServiceProvider tspProvider, X509Certificate cert, String name, String ocspUrl, String cn, String caCn)
    {
    	TSPService tsps = new TSPService();
		tsps.setType(TSPService.TSP_TYPE_EXT_OCSP_QC);
		tsps.addCertificate(cert);
		tsps.addSubjectName(new MultiLangString(null, cert.getSubjectDN().getName()));
		tsps.addName(new MultiLangString(null, name));
		tsps.addServiceAccessPoint(ocspUrl);
		tsps.setCn(cn);
		tsps.setCaCn(caCn);
		tspProvider.addTSPService(tsps);
		return tsps;
    }
			
    /**
     * Reads the cert from a file, URL or from another
     * location somewhere in the CLASSPATH such as
     * in the librarys jar file.
     * @param certLocation certificates file name,
     * or URL. You can use url in form jar://<location> to read
     * a certificate from the car file or some other location in the
     * CLASSPATH
     * @return certificate object
     */
    private static X509Certificate readCertificate(String certLocation)
        throws DigiDocException
    {
        X509Certificate cert = null;
        try {
        	InputStream isCert = null;
            URL url = null;
            if(certLocation != null) {
            if(certLocation.startsWith("http")) {
                url = new URL(certLocation);
                isCert = url.openStream();
            } else if(certLocation.startsWith("jar://")) {
              ClassLoader cl = ConfigManager.instance().getClass().getClassLoader();
              isCert = cl.getResourceAsStream(certLocation.substring(6));
            } else {
            	isCert = new FileInputStream(certLocation);
            }
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      		cert = (X509Certificate)certificateFactory.generateCertificate(isCert);
      		isCert.close();
      		if(m_logger.isDebugEnabled())
    			m_logger.debug("Read cert: " + certLocation + " - " + ((cert != null) ? "OK" : "NULL"));
            }
        } catch(Exception ex) {
            DigiDocException.handleException(ex, DigiDocException.ERR_READ_FILE);
        }
        return cert;
    }
    
    private X509Certificate findCaForCertInTsl(TrustServiceStatusList tsl, X509Certificate cert, Date dtSigning)
    {
    	Principal caP = cert.getIssuerDN();
    	//String caDn = cert.getIssuerDN().getName();
    	String subDn = cert.getSubjectDN().getName();
    	for(int j = 0; j < tsl.getNumProviders(); j++) {
			TrustServiceProvider tsp = tsl.getTrustServiceProvider(j);
			for(int l = 0; l < tsp.getNumServices(); l++) {
			  TSPService tsps = tsp.getTSPService(l);
			  if(tsps.isCA()) {
			  for(int m = 0; m < tsps.getNumCertificates(); m++) {
				  X509Certificate c2 = tsps.getCertificate(m);
				  if(c2 != null) {
				  Principal c2p = c2.getSubjectDN();
				  String ca2Dn = c2.getSubjectDN().getName();
				  if(c2p.equals(caP) &&
					((dtSigning == null) ||
					(dtSigning != null && dtSigning.after(c2.getNotBefore()) && dtSigning.before(c2.getNotAfter())))) {
					  if(m_logger.isDebugEnabled())
							m_logger.debug("Found matching CA dn: " + ca2Dn);
				    try {
				      cert.verify(c2.getPublicKey());
				      if(m_logger.isDebugEnabled())
						  m_logger.debug("CA: " + ca2Dn + " IS issuer of: " + subDn + " serial: " + c2.getSerialNumber().toString());
				      return c2;
				    } catch(Exception ex) {
				    	if(m_logger.isDebugEnabled())
						  m_logger.debug("CA: " + ca2Dn + " IS NOT issuer of: " + subDn);
				    }
				  }
			  } // if c2
			  } // for
			  } // if isCA
			}
    	}
		return null;
    }
    
    private X509Certificate findOcspInTsl(TrustServiceStatusList tsl, String cn)
    {
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Search OCSP by cn: " + cn);
    	for(int j = 0; j < tsl.getNumProviders(); j++) {
			TrustServiceProvider tsp = tsl.getTrustServiceProvider(j);
			if(m_logger.isDebugEnabled())
    			m_logger.debug("TSP: " + tsp.getTSPInformation().getName(0));
			for(int l = 0; l < tsp.getNumServices(); l++) {
			  TSPService tsps = tsp.getTSPService(l);
			  if(m_logger.isDebugEnabled())
	    			m_logger.debug("Service: " + tsps.getCn() + " ocsp: " + tsps.isOCSP() + " CA: " + tsps.isCA());
			  if(tsps.isOCSP() && tsps.getCn() != null && tsps.getCn().equalsIgnoreCase(cn)) {
				  if(m_logger.isDebugEnabled())
						m_logger.debug("Found OCSP: " + cn);
				  return tsps.getCertificate(0);
			  }
			}
    	}
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Did not find ocsp for: " + cn);
		return null;
    }
    
    private X509Certificate[] findOcspsInTsl(TrustServiceStatusList tsl, String cn, String serialNr)
    {
    	X509Certificate[] lcert = null;
    	Vector vec = new Vector();
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Search OCSP by cn: " + cn + " serial: " + serialNr);
    	for(int j = 0; j < tsl.getNumProviders(); j++) {
			TrustServiceProvider tsp = tsl.getTrustServiceProvider(j);
			if(m_logger.isDebugEnabled())
    			m_logger.debug("TSP: " + tsp.getTSPInformation().getName(0));
			for(int l = 0; l < tsp.getNumServices(); l++) {
			  TSPService tsps = tsp.getTSPService(l);
			  if(m_logger.isDebugEnabled())
	    			m_logger.debug("Service: " + tsps.getCn() + " ocsp: " + tsps.isOCSP() + " CA: " + tsps.isCA());
			  if(tsps.isOCSP() && tsps.getCn() != null && tsps.getCn().equalsIgnoreCase(cn)) {
				  if(m_logger.isDebugEnabled())
						m_logger.debug("Found OCSP: " + cn);
				  for(int m = 0; m < tsps.getNumCertificates(); m++) {
					  X509Certificate cert = tsps.getCertificate(m);
					  if(serialNr == null || (serialNr != null && serialNr.equals(cert.getSerialNumber().toString()))) {
						  if(m_logger.isDebugEnabled() && cert != null)
								m_logger.debug("Found cert: " + cert.getSubjectDN().toString() + " serial: " + cert.getSerialNumber().toString());
						  vec.add(cert);
					  }
				  }
			  }
			}
    	}
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Found: " + vec.size() + " certs for: " + cn);
    	lcert = new X509Certificate[vec.size()];
    	for(int j = 0; j < vec.size(); j++)
    		lcert[j] = (X509Certificate)vec.elementAt(j);
		return lcert;
    }
    
    /**
     * Finds direct CA cert for given user cert
     * @param cert user cert
     * @param bUseLocal use also ca certs registered in local config file
     * @return CA cert or null if not found
     * @deprecated use findCaForCert(X509Certificate cert, boolean bUseLocal, Date dtSigning)
     */
    public X509Certificate findCaForCert(X509Certificate cert, boolean bUseLocal) 
    {
    	return findCaForCert(cert, bUseLocal, null);
    }
    
    /**
     * Finds direct CA cert for given user cert
     * @param cert user cert
     * @param bUseLocal use also ca certs registered in local config file
     * @param dtSigning signing timestamp. Used to pick correct ca if many of them apply
     * @return CA cert or null if not found
     */
    public X509Certificate findCaForCert(X509Certificate cert, boolean bUseLocal, Date dtSigning) 
    {
    	Principal caP = cert.getIssuerDN();
    	String caDn = cert.getIssuerDN().getName();
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Search CA: " + caDn);
    	// find in TSL files at first
    	for(int i = 0; (m_tsls != null) && (i < m_tsls.size()); i++) {
    		TrustServiceStatusList tsl = (TrustServiceStatusList)m_tsls.get(i);
    		if((tsl.isLocal() && bUseLocal) || !tsl.isLocal()) {
    			X509Certificate ca = findCaForCertInTsl(tsl, cert, dtSigning);
    			if(ca != null)
    				return ca;
    		}
    	}
    	return null;
    }
    
    /**
     * Finds direct OCSP cert for given ocsp responder id
     * @param cn OCSP responder-id
     * @param bUseLocal use also ca certs registered in local config file
     * @return OCSP cert or null if not found
     */
    public X509Certificate findOcspByCN(String cn, boolean bUseLocal) 
    {
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Search OCSP: " + cn + " use-local: " + bUseLocal);
    	// find in TSL files at first
    	for(int i = 0; (m_tsls != null) && (i < m_tsls.size()); i++) {
    		TrustServiceStatusList tsl = (TrustServiceStatusList)m_tsls.get(i);
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("TSL: " + tsl.getSchemeInformation().getSchemeName(0) + " local: " + tsl.isLocal());
    		if((tsl.isLocal() && bUseLocal) || !tsl.isLocal()) {
    			X509Certificate cert = findOcspInTsl(tsl, cn);
    			if(cert != null)
    				return cert;
    		}
    	}
    	return null;
    }
    
    /**
     * Finds direct OCSP cert for given ocsp responder id
     * @param cn OCSP responder-id
     * @param bUseLocal use also ca certs registered in local config file
     * @param serialNr serial number or NULL
     * @return OCSP cert or null if not found
     */
    public X509Certificate[] findOcspsByCNAndNr(String cn, boolean bUseLocal, String serialNr) 
    {
    	X509Certificate[] lcert = null;
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Search OCSP: " + cn + " use-local: " + bUseLocal + " serial: " + serialNr);
    	// find in TSL files at first
    	for(int i = 0; (m_tsls != null) && (lcert == null) && (i < m_tsls.size()); i++) {
    		TrustServiceStatusList tsl = (TrustServiceStatusList)m_tsls.get(i);
    		if(m_logger.isDebugEnabled())
    			m_logger.debug("TSL: " + tsl.getSchemeInformation().getSchemeName(0) + " local: " + tsl.isLocal());
    		if((tsl.isLocal() && bUseLocal) || !tsl.isLocal()) {
    			// TODO: find certs
    			lcert = findOcspsInTsl(tsl, cn, serialNr);
    			X509Certificate cert = findOcspInTsl(tsl, cn);
    		}
    	}
    	return lcert;
    }
    
    /**
     * Finds OCSP url for given user cert
     * @param cert user cert
     * @param nUrl index of url if many exist
     * @param bUseLocal use also ca certs registered in local config file
     * @return CA cert or null if not found
     */
    public String findOcspUrlForCert(X509Certificate cert, int nUrl, boolean bUseLocal) 
    {
    	String caDn = cert.getIssuerDN().getName();
    	String caCn = ConvertUtils.getCommonName(caDn);
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Search ocsp url for CA: " + caCn);
    	// find in TSL files at first
    	for(int i = 0; (m_tsls != null) && (i < m_tsls.size()); i++) {
    		TrustServiceStatusList tsl = (TrustServiceStatusList)m_tsls.get(i);
    		if((tsl.isLocal() && bUseLocal) || !tsl.isLocal()) {
    			for(int j = 0; j < tsl.getNumProviders(); j++) {
    				TrustServiceProvider tsp = tsl.getTrustServiceProvider(j);
    				for(int l = 0; l < tsp.getNumServices(); l++) {
    				  TSPService tsps = tsp.getTSPService(l);
    				  if(m_logger.isDebugEnabled())
							m_logger.debug("Checking tsp service: " + caCn);
    				  if(tsps.isOCSP() && tsps.getCaCn() != null && tsps.getCaCn().equals(caCn)) {
    					  if(m_logger.isDebugEnabled())
    							m_logger.debug("Found OCSP: " + caCn);
    					  if(tsps.getServiceAccessPoints() != null && nUrl >= 0 && nUrl < tsps.getServiceAccessPoints().length) {
    						  if(m_logger.isDebugEnabled())
      							m_logger.debug("Found ocsp URL: " + tsps.getServiceAccessPoints()[nUrl]);
    						  return tsps.getServiceAccessPoints()[nUrl];
    					  }
    				  }
    				}
    	    	}
    		}
    	}
    	String sUrl = ConfigManager.instance().getProperty("DIGIDOC_OCSP_RESPONDER_URL");
    	if(m_logger.isDebugEnabled())
			m_logger.debug("Using default URL: " + sUrl);
    	return sUrl;
    }
    
}
