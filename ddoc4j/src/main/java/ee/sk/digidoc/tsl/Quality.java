package ee.sk.digidoc.tsl;
import ee.sk.utils.ConvertUtils;


/**
 * Models the ETSI TS 102 231 V3.1.1. TSL QualityElement
 * @author Veiko Sinivee
 */
public class Quality {
	/** quality name or URI */
	private String m_name;
	/** quality value */
	private int m_value;
	
	public static final String QUALITY_PRIVATE_KEY = "http://uri.eesti.ee/TSL/QualityParameter/PrivateKeyCarrier";
	public static final String QUALITY_CRYPTO = "http://uri.eesti.ee/TSL/QualityParameter/CryptoAlgorithmLevel";
	public static final String QUALITY_CA = "http://uri.eesti.ee/TSL/QualityParameter/CAQuality";
	public static final String QUALITY_ASSESSMENT = "http://uri.eesti.ee/TSL/QualityParameter/AssessmentQuality";
	
	
	/**
	 * Default constructor for Quality
	 */
	public Quality()
	{
		m_name = null;
		m_value = 0;
	}
	
	// accessors
	public String getName() { return m_name; }
	public int getValue() { return m_value; }
	
	// mutators
	public void setName(String s) { m_name = s; }
	public void setValue(int n) { m_value = n; }
	
	
	/**
     * Returns elements stringified form for debugging
     * @return elements stringified form
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer("[Quality");
    	sb.append(ConvertUtils.stringElemToString("name", m_name));
    	sb.append(ConvertUtils.intElemToString("value", m_value));
    	sb.append("]");
    	return sb.toString();
    }
}
