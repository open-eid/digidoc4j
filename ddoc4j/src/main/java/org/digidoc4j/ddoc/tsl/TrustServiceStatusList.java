package org.digidoc4j.ddoc.tsl;
import java.util.ArrayList;
import java.util.List;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL TrustServiceStatusList type
 * @author Veiko Sinivee
 */
public class TrustServiceStatusList {
	/** scheme information */
	private SchemeInformation m_schemeInfo;
	/** TSP-s */
	private List m_tsps;
	
	/**
	 * Default constructor for TrustServiceStatusList
	 */
	public TrustServiceStatusList()
	{
		m_schemeInfo = null;
		m_tsps = null;
	}
	
	// accessors
	public SchemeInformation getSchemeInformation() { return m_schemeInfo; }
	public int getNumProviders() { return ((m_tsps != null) ? m_tsps.size() : 0); }
	public TrustServiceProvider[] getTrustServiceProviders() {
		TrustServiceProvider[] arr = null;
		if(m_tsps != null && m_tsps.size() > 0) {
			arr = new TrustServiceProvider[m_tsps.size()];
			for(int i = 0; i < m_tsps.size(); i++) 
				arr[i] = (TrustServiceProvider)m_tsps.get(i);
		}
		return arr; 
	}
	public TrustServiceProvider getTrustServiceProvider(int n) { 
		if(m_tsps != null && n >= 0 && n < m_tsps.size())
			return (TrustServiceProvider)m_tsps.get(n);
		else
			return null; 
	}
	public boolean isLocal()
	{
		return m_schemeInfo != null && 
			m_schemeInfo.getType() != null &&
			m_schemeInfo.getType().equals(SchemeInformation.TYPE_LOCAL);
	}
	
	// mutators
	public void setSchemeInformation(SchemeInformation si) { m_schemeInfo = si; }
	public void addTrustServiceProvider(TrustServiceProvider a) { 
		if(m_tsps == null)
			m_tsps = new ArrayList();
		m_tsps.add(a); 
	}

	/**
     * Returns elements stringified form for debugging
     * @return elements stringified form
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer("[TrustServiceStatusList");
    	if(m_schemeInfo != null)
    		sb.append(m_schemeInfo);
    	for(int i = 0; (m_tsps != null) && (i < m_tsps.size()); i++)
    		sb.append((TrustServiceProvider)m_tsps.get(i));
    	sb.append("]");
    	return sb.toString();
    }
}
