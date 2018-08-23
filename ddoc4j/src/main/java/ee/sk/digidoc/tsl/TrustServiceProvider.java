package ee.sk.digidoc.tsl;
import java.util.ArrayList;
import java.util.List;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL TrustServiceProvider type
 * @author Veiko Sinivee
 */
public class TrustServiceProvider {
	/** TSP info */
	private TSPInformation m_tspInfo;
	/** TSP services */
	private List m_services;
	
	/**
	 * Default constructor for TrustServiceProvider
	 */
	public TrustServiceProvider()
	{
		m_tspInfo = null;
		m_services = null;
	}
	
	// accessors
	public TSPInformation getTSPInformation() { return m_tspInfo; }
	public int getNumServices() { return ((m_services != null) ? m_services.size() : 0); }
	public TSPService[] getTSPServices() {
		TSPService[] arr = null;
		if(m_services != null && m_services.size() > 0) {
			arr = new TSPService[m_services.size()];
			for(int i = 0; i < m_services.size(); i++) 
				arr[i] = (TSPService)m_services.get(i);
		}
		return arr; 
	}
	public TSPService getTSPService(int n) { 
		if(m_services != null && n >= 0 && n < m_services.size())
			return (TSPService)m_services.get(n);
		else
			return null; 
	}
	
	// mutators
	public void setTSPInformation(TSPInformation i) { m_tspInfo = i; }
	public void addTSPService(TSPService a) { 
		if(m_services == null)
			m_services = new ArrayList();
		m_services.add(a); 
	}
	
	/**
     * Returns elements stringified form for debugging
     * @return elements stringified form
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer("[TrustServiceProvider");
    	if(m_tspInfo != null)
    		sb.append(m_tspInfo);
    	for(int i = 0; (m_services != null) && (i < m_services.size()); i++)
    		sb.append((TSPService)m_services.get(i));
    	sb.append("]");
    	return sb.toString();
    }
}
