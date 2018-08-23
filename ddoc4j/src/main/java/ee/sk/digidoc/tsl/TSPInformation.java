package ee.sk.digidoc.tsl;

import ee.sk.utils.ConvertUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL TSPInformation type
 * @author Veiko Sinivee
 */
public class TSPInformation {
	/** TSP names */
	private List m_names;
	/** TSP trade names */
	private List m_tradeNames;
	/** postal addresses */
	private List m_postalAddresses;
	/** electronic addresses */
	private List m_electronicAddresses;
	/** information URI-s */
	private List m_informationUris;

	/**
	 * Default constructor for TSPInformation
	 */
	public TSPInformation() {
		m_names = null;
		m_postalAddresses = null;
		m_electronicAddresses = null;
		m_tradeNames = null;
		m_informationUris = null;
	}
	
	// accessors
	public MultiLangString[] getNames() { return ConvertUtils.list2mls(m_names); }
	public MultiLangString[] getTradeNames() { return ConvertUtils.list2mls(m_tradeNames); }
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
	public MultiLangString[] getInformationURIs() { return ConvertUtils.list2mls(m_informationUris); }
	
	public MultiLangString getName(int n) { return ConvertUtils.getListObj(m_names, n); }
	public MultiLangString getTradeName(int n) { return ConvertUtils.getListObj(m_tradeNames, n); }
	public PostalAddress getPostalAddress(int n) {
		if(m_postalAddresses != null && n >= 0 && n < m_postalAddresses.size())
			return (PostalAddress)m_postalAddresses.get(n);
		else
			return null; 
	}
	public MultiLangString getElectronicAddress(int n) { return ConvertUtils.getListObj(m_electronicAddresses, n); }
	public MultiLangString getInformationURI(int n) { return ConvertUtils.getListObj(m_informationUris, n); }
	
	// mutators
	public void addName(MultiLangString s) { m_names = ConvertUtils.addObject(m_names, s); }
	public void addTradeName(MultiLangString s) { m_tradeNames = ConvertUtils.addObject(m_tradeNames, s); }
	public void addPostalAddress(PostalAddress a) {
		if(m_postalAddresses == null)
			m_postalAddresses = new ArrayList();
		m_postalAddresses.add(a); 
	}
	public void addElectronicAddress(MultiLangString s) { m_electronicAddresses = ConvertUtils.addObject(m_electronicAddresses, s); }
	public void addInformationURI(MultiLangString s) { m_informationUris = ConvertUtils.addObject(m_informationUris, s); }
	
	/**
     * Returns elements stringified form for debugging
     * @return elements stringified form
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer("[TSPInformation");
    	sb.append("[Names");
    	for(int i = 0; (m_names != null) && (i < m_names.size()); i++)
    		sb.append((MultiLangString)m_names.get(i));
    	sb.append("][TradeNames");
    	for(int i = 0; (m_tradeNames != null) && (i < m_tradeNames.size()); i++)
    		sb.append((MultiLangString)m_tradeNames.get(i));
    	sb.append("][PostalAddresses");
    	for(int i = 0; (m_postalAddresses != null) && (i < m_postalAddresses.size()); i++)
    		sb.append((PostalAddress)m_postalAddresses.get(i));
    	sb.append("][ElectronicAddresses");
    	for(int i = 0; (m_electronicAddresses != null) && (i < m_electronicAddresses.size()); i++)
    		sb.append((MultiLangString)m_electronicAddresses.get(i));
    	sb.append("][InfoURIs");
    	for(int i = 0; (m_informationUris != null) && (i < m_informationUris.size()); i++)
    		sb.append((MultiLangString)m_informationUris.get(i));
    	sb.append("]");
    	
    	
    	sb.append("]");
    	return sb.toString();
    }
    
}
