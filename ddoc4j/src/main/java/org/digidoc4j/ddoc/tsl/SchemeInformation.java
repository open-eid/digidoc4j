package org.digidoc4j.ddoc.tsl;

import org.digidoc4j.ddoc.utils.ConvertUtils;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL SchemeInformation type
 * @author Veiko Sinivee
 */
public class SchemeInformation {
	/** version identifier */
	private int m_version;
	/** sequence number */
	private int m_seqNr;
	/** type */
	private String m_type;
	/** operator names */
	private List m_operatorNames;
	/** postal addresses */
	private List m_postalAddresses;
	/** electronic addresses */
	private List m_electronicAddresses;
	/** scheme names */
	private List m_schemeNames;
	/** scheme information URI-s */
	private List m_schemeInformationUris;
	/** status determination approach */
	private String m_statusDeterminationApproach;
	/** scheme type comminity rules */
	private List m_schemeTypeCommunityRules;
	/** scheme territoty */
	private String m_schemeTerritory;
	/** policy or legal notices */
	private List m_policyOrLegalNotices;
	/** historical information period */
	private int m_historicalInformationPeriod;
	/** list issue date */
	private Date m_issueDate;
	/** next updates */
	private List m_nextUpdates;
	/** distribution points */
	private List m_distributionPoints;
	
	public static final String TYPE_LOCAL = "LOCAL";
	public static final String TYPE_GENERIC = "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic";
	
	
	/**
	 * Default constructor for SchemeInformation
	 */
	public SchemeInformation() {
		m_version = 0;
		m_seqNr = 0;
		m_type = null;
		m_operatorNames = null;
		m_postalAddresses = null;
		m_electronicAddresses = null;
		m_schemeNames = null;
		m_schemeInformationUris = null;
		m_statusDeterminationApproach = null;
		m_schemeTypeCommunityRules = null;
		m_schemeTerritory = null;
		m_policyOrLegalNotices = null;
		m_historicalInformationPeriod = 0;
		m_issueDate = null;
		m_nextUpdates = null;
		m_distributionPoints = null;
	}
	
	// accessors
	public int getVersionIdentifier() { return m_version; }
	public int getSequenceNumber() { return m_seqNr; }
	public String getType() { return m_type; }
	public MultiLangString[] getOperatorNames() { return ConvertUtils.list2mls(m_operatorNames); }
	public PostalAddress[] getPostalAddresses() {
		PostalAddress[] arr = null;
		if(m_postalAddresses != null && m_postalAddresses.size() > 0) {
			arr = new PostalAddress[m_postalAddresses.size()];
			for(int i = 0; i < m_postalAddresses.size(); i++) 
				arr[i] = (PostalAddress)m_postalAddresses.get(i);
		}
		return arr; 
	}
	public MultiLangString[] getElectronicAddresses() { return ConvertUtils.list2mls(m_electronicAddresses); }
	public MultiLangString[] getSchemeNames() { return ConvertUtils.list2mls(m_schemeNames); }
	public MultiLangString[] getSchemeInformationURIs() { return ConvertUtils.list2mls(m_schemeInformationUris); }
	public String getStatusDeterminationApproach() { return m_statusDeterminationApproach; }
	public MultiLangString[] getSchemeTypeCommunityRules() { return ConvertUtils.list2mls(m_schemeTypeCommunityRules); }
	public String getSchemeTerritory() { return m_schemeTerritory; }
	public MultiLangString[] getPolicyOrLegalNotices() { return ConvertUtils.list2mls(m_policyOrLegalNotices); }
	public int getHistoricalInformationPeriod() { return m_historicalInformationPeriod; }
	public Date getListIssueDate() { return m_issueDate; }
	public Date[] getNextUpdates() { return ConvertUtils.list2dates(m_nextUpdates); }
	public MultiLangString[] getDistributionPoints() { return ConvertUtils.list2mls(m_distributionPoints); }
	
	public MultiLangString getOperatorName(int n) { return ConvertUtils.getListObj(m_operatorNames, n); }
	public PostalAddress getPostalAddress(int n) { 
		if(m_postalAddresses != null && n >= 0 && n < m_postalAddresses.size())
			return (PostalAddress)m_postalAddresses.get(n);
		else
			return null; 
	}
	public MultiLangString getElectronicAddress(int n) { return ConvertUtils.getListObj(m_electronicAddresses, n); }
	public MultiLangString getDistributionPoint(int n) { return ConvertUtils.getListObj(m_distributionPoints, n); }
	public MultiLangString getSchemeName(int n) { return ConvertUtils.getListObj(m_schemeNames, n); }
	public MultiLangString getSchemeInformationURI(int n) { return ConvertUtils.getListObj(m_schemeInformationUris, n); }
	public MultiLangString getSchemeTypeCommunityRule(int n) { return ConvertUtils.getListObj(m_schemeTypeCommunityRules, n); }
	public MultiLangString getPolicyOrLegalNotice(int n) { return ConvertUtils.getListObj(m_policyOrLegalNotices, n); }
	
	// mutators
	public void setVersionIdentifier(int n) { m_version = n; }
	public void setSequenceNumber(int n) { m_seqNr = n; }
	public void setType(String s) { m_type = s; }
	public void addOperatorName(MultiLangString s) { m_operatorNames = ConvertUtils.addObject(m_operatorNames, s); }
	public void addPostalAddress(PostalAddress a) { 
		if(m_postalAddresses == null)
			m_postalAddresses = new ArrayList();
		m_postalAddresses.add(a); 
	}
	public void addElectronicAddress(MultiLangString s) { m_electronicAddresses = ConvertUtils.addObject(m_electronicAddresses, s); }
	public void addSchemeName(MultiLangString s) { m_schemeNames = ConvertUtils.addObject(m_schemeNames, s); }
	public void addSchemeInformationURI(MultiLangString s) { m_schemeInformationUris = ConvertUtils.addObject(m_schemeInformationUris, s); }
	public void setStatusDeterminationApproach(String s) { m_statusDeterminationApproach = s; }
	public void addSchemeTypeCommunityRule(MultiLangString s) { m_schemeTypeCommunityRules = ConvertUtils.addObject(m_schemeTypeCommunityRules, s); }
	public void setSchemeTerritory(String s) { m_schemeTerritory = s; }
	public void addPolicyOrLegalNotice(MultiLangString s) { m_policyOrLegalNotices = ConvertUtils.addObject(m_policyOrLegalNotices, s); }
	public void setHistoricalInformationPeriod(int n) { m_historicalInformationPeriod = n; }
	public void setListIssueDate(Date d) { m_issueDate = d; }
	public void addNextUpdate(Date d) { m_nextUpdates = ConvertUtils.addObject(m_nextUpdates, d); }
	public void addDistributionPoint(MultiLangString s) { m_distributionPoints = ConvertUtils.addObject(m_distributionPoints, s); }
	
	/**
     * Returns elements stringified form for debugging
     * @return elements stringified form
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer("[SchemeInformation");
    	sb.append(ConvertUtils.intElemToString("ver", m_version));
    	sb.append(ConvertUtils.intElemToString("seq", m_seqNr));
    	sb.append(ConvertUtils.stringElemToString("type", m_type));
    	sb.append("[OperatorNames");
    	for(int i = 0; (m_operatorNames != null) && (i < m_operatorNames.size()); i++)
    		sb.append((MultiLangString)m_operatorNames.get(i));
    	sb.append("][PostalAddresses");
    	for(int i = 0; (m_postalAddresses != null) && (i < m_postalAddresses.size()); i++)
    		sb.append((PostalAddress)m_postalAddresses.get(i));
    	sb.append("][ElectronicAddresses");
    	for(int i = 0; (m_electronicAddresses != null) && (i < m_electronicAddresses.size()); i++)
    		sb.append((MultiLangString)m_electronicAddresses.get(i));
    	sb.append("][SchemeNames");
    	for(int i = 0; (m_schemeNames != null) && (i < m_schemeNames.size()); i++)
    		sb.append((MultiLangString)m_schemeNames.get(i));
    	sb.append("][SchemeInfoURIs");
    	for(int i = 0; (m_schemeInformationUris != null) && (i < m_schemeInformationUris.size()); i++)
    		sb.append((MultiLangString)m_schemeInformationUris.get(i));
    	sb.append("]");
    	sb.append(ConvertUtils.stringElemToString("status-approach", m_statusDeterminationApproach));
    	sb.append("][CommunityRules");
    	for(int i = 0; (m_schemeTypeCommunityRules != null) && (i < m_schemeTypeCommunityRules.size()); i++)
    		sb.append((MultiLangString)m_schemeTypeCommunityRules.get(i));
    	sb.append(ConvertUtils.stringElemToString("territory", m_schemeTerritory));
    	sb.append("][Policies");
    	for(int i = 0; (m_policyOrLegalNotices != null) && (i < m_policyOrLegalNotices.size()); i++)
    		sb.append((MultiLangString)m_policyOrLegalNotices.get(i));
    	sb.append("]");
    	sb.append(ConvertUtils.intElemToString("info-period", m_historicalInformationPeriod));
    	sb.append(ConvertUtils.dateElemToString("issue-date", m_issueDate));
    	sb.append("[NextUpdate");
    	for(int i = 0; (m_nextUpdates != null) && (i < m_nextUpdates.size()); i++)
    		sb.append(ConvertUtils.dateElemToString("next-update", (Date)m_nextUpdates.get(i)));
    	sb.append("][DistributionPoints");
    	for(int i = 0; (m_distributionPoints != null) && (i < m_distributionPoints.size()); i++)
    		sb.append((MultiLangString)m_distributionPoints.get(i));
    	sb.append("]");
    	
    	
    	sb.append("]");
    	return sb.toString();
    }
}
