package org.digidoc4j.ddoc.tsl;

import org.digidoc4j.ddoc.utils.ConvertUtils;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


/**
 * Models the ETSI TS 102 231 V3.1.1. TSL TSPService type
 * @author Veiko Sinivee
 */
public class TSPService {
	/** service type identifier */
	private String m_type;
	/** service names */
	private List m_names;
	/** certificates */
	private List m_certs;
	/** subject names */
	private List m_subjectNames;
	/** service status */
	private String m_status;
	/** starting timestamp */
	private Date m_statusSdt;
	/** service definition URI-s */
	private List m_definitionUris;
	/** qualities of TSP */
	private List m_qualities;
	/** service access points */
	private List m_accessPoints;
	// additional params
	private String m_cn;
	private String m_hash;
	private String m_caCN;
	private String m_caHash;
	
	public static final String TSP_TYPE_CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
	
	public static final String TSP_TYPE_EXT_OCSP_QC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/OCSP-QC";
	public static final String TSP_TYPE_EXT_CRL_QC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/CRL-QC";
	public static final String TSP_TYPE_EXT_ROOT_QC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/RootCA-QC";
	public static final String TSP_TYPE_EXT_TSS_QC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/TSS-QC";
		
	public static final String TSP_TYPE_QC_WITHSSCD = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/SvcInfoExt/QCWithSSCD";
	public static final String TSP_TYPE_OCSP = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP";
	
	public static final String TSP_STATUS_UNDERSUPERVISION = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision";
	public static final String TSP_STATUS_SUPERVISIONINCESSATION = "http: //uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList /Svcstatus/supervisionincessation";
	public static final String TSP_STATUS_SUPERVISIONCEASED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList /Svcstatus/supervisionceased";
	public static final String TSP_STATUS_SUPERVISIONREVOKED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList /Svcstatus/supervisionrevoked";
	public static final String TSP_STATUS_ACCREDITED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList /Svcstatus/accredited";
	public static final String TSP_STATUS_ACCREDITATIONCEASED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList /Svcstatus/accreditationceased";
	public static final String TSP_STATUS_ACCREDITATIONREVOKED = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList /Svcstatus/accreditationrevoked";
	
	
	/**
	 * Default constructor for TSPService
	 */
	public TSPService()
	{
		m_type = null;
		m_names = null;
		m_certs = null;
		m_subjectNames = null;
		m_status = null;
		m_statusSdt = null;
		m_definitionUris = null;
		m_qualities = null;
		m_accessPoints = null;
		m_cn = null;
		m_hash = null;
		m_caCN = null;
		m_caHash = null;
	}
	
	// accessors
	public String getType() { return m_type; }
	public MultiLangString[] getNames() { return ConvertUtils.list2mls(m_names); }
	public MultiLangString getName(int n) { return ConvertUtils.getListObj(m_names, n); }
	public MultiLangString[] getSubjectNames() { return ConvertUtils.list2mls(m_subjectNames); }
	public MultiLangString getSubjectName(int n) { return ConvertUtils.getListObj(m_subjectNames, n); }
	public MultiLangString[] getServiceDefinitionURIs() { return ConvertUtils.list2mls(m_definitionUris); }
	public MultiLangString getServiceDefinitionURI(int n) { return ConvertUtils.getListObj(m_definitionUris, n); }
	public String getStatus() { return m_status; }
	public Date getStatusStartingTime() { return m_statusSdt; }
	public int getNumCertificates() { return ((m_certs != null) ? m_certs.size() : 0); }
	public X509Certificate[] getCertificates() {
		X509Certificate[] arr = null;
		if(m_certs != null && m_certs.size() > 0) {
			arr = new X509Certificate[m_certs.size()];
			for(int i = 0; i < m_certs.size(); i++) 
				arr[i] = (X509Certificate)m_certs.get(i);
		}
		return arr; 
	}
	public X509Certificate getCertificate(int n) { 
		if(m_certs != null && n >= 0 && n < m_certs.size())
			return (X509Certificate)m_certs.get(n);
		else
			return null; 
	}
	public Quality[] getQualities() {
		Quality[] arr = null;
		if(m_qualities != null && m_qualities.size() > 0) {
			arr = new Quality[m_qualities.size()];
			for(int i = 0; i < m_qualities.size(); i++) 
				arr[i] = (Quality)m_qualities.get(i);
		}
		return arr; 
	}
	public Quality getQuality(int n) {
		if(m_qualities != null && n >= 0 && n < m_qualities.size())
			return (Quality)m_qualities.get(n);
		else
			return null; 
	}
	public String[] getServiceAccessPoints() { return ConvertUtils.list2strings(m_accessPoints); }
	public String getServiceAccessPoint(int n) { return ConvertUtils.getListString(m_accessPoints, n); }
	public String getCn() { return m_cn; }
	public String getHash() { return m_hash; }
	public String getCaCn() { return m_caCN; }
	public String getCaHash() { return m_caHash; }
	public boolean isCA()
	{
		return m_type == null || m_type.equals(TSP_TYPE_CA_QC);
	}
	public boolean isOCSP()
	{
		return m_type != null || m_type.equals(TSP_TYPE_OCSP);
	}
	
	// mutators
	public void setType(String s) { m_type = s; }
	public void addName(MultiLangString s) { m_names = ConvertUtils.addObject(m_names, s); }
	public void addSubjectName(MultiLangString s) { m_subjectNames = ConvertUtils.addObject(m_subjectNames, s); }
	public void addServiceDefinitionURI(MultiLangString s) { m_definitionUris = ConvertUtils.addObject(m_definitionUris, s); }
	public void setStatus(String s) { m_status = s; }
	public void setStatusStartingTime(Date d) { m_statusSdt = d; }
	public void addCertificate(X509Certificate a) { 
		if(m_certs == null)
			m_certs = new ArrayList();
		m_certs.add(a); 
	}
	public void addQuality(Quality a) {
		if(m_qualities == null)
			m_qualities = new ArrayList();
		m_qualities.add(a); 
	}
	public void addServiceAccessPoint(String s) { m_accessPoints = ConvertUtils.addObject(m_accessPoints, s); }
	public void setCn(String s) { m_cn = s; }
	public void setHash(String s) { m_hash = s; }
	public void setCaCn(String s) { m_caCN = s; }
	public void setCaHash(String s) { m_caHash = s; }
	
	/**
     * Returns elements stringified form for debugging
     * @return elements stringified form
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer("[TSPService");
    	sb.append(ConvertUtils.stringElemToString("type", m_type));
    	sb.append(ConvertUtils.stringElemToString("status", m_status));
    	sb.append(ConvertUtils.dateElemToString("status-dt", m_statusSdt));
    	sb.append(ConvertUtils.stringElemToString("cn", m_cn));
    	sb.append(ConvertUtils.stringElemToString("hash", m_hash));
    	sb.append(ConvertUtils.stringElemToString("ca-cn", m_caCN));
    	sb.append(ConvertUtils.stringElemToString("ca-hash", m_caHash));
    	sb.append("[Names");
    	for(int i = 0; (m_names != null) && (i < m_names.size()); i++)
    		sb.append((MultiLangString)m_names.get(i));
    	sb.append("][SubjectNames");
    	for(int i = 0; (m_subjectNames != null) && (i < m_subjectNames.size()); i++)
    		sb.append((MultiLangString)m_subjectNames.get(i));
    	sb.append("][ServiceDefinitionURIs");
    	for(int i = 0; (m_definitionUris != null) && (i < m_definitionUris.size()); i++)
    		sb.append((MultiLangString)m_definitionUris.get(i));
    	sb.append("][Certs");
    	for(int i = 0; (m_certs != null) && (i < m_certs.size()); i++)
    		sb.append(ConvertUtils.stringElemToString("cert", ((X509Certificate)m_certs.get(i)).getSubjectDN().getName()));
    	sb.append("]");
    	if(m_qualities != null && m_qualities.size() > 0) {
    	sb.append("[Qualities");
    	for(int i = 0; (m_qualities != null) && (i < m_qualities.size()); i++)
    		sb.append((Quality)m_qualities.get(i));
    	sb.append("]");
    	}
    	if(m_accessPoints != null && m_accessPoints.size() > 0) {
    	sb.append("[AccessPoints");
    	for(int i = 0; (m_accessPoints != null) && (i < m_accessPoints.size()); i++)
    		sb.append((String)m_accessPoints.get(i));
    	sb.append("]");
    	}
    	
    	sb.append("]");
    	return sb.toString();
    }
}
