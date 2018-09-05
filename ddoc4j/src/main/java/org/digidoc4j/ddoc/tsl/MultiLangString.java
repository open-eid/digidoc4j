package org.digidoc4j.ddoc.tsl;
import org.digidoc4j.ddoc.utils.ConvertUtils;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL MultiLangString type
 * @author Veiko Sinivee
 */
public class MultiLangString {
	/** lang attribute */
	private String m_lang;
	/** value of string */
	private String m_value;
	
	/**
	 * Default constructor for MultiLangString
	 */
	public MultiLangString()
	{
		m_lang = null;
		m_value = null;
	}

	/**
	 * Paramterized constrctor for MultiLangString
	 * @param lang lang attribute
	 * @param value value of string
	 */
	public MultiLangString(String lang, String value)
	{
		m_lang = lang;
		m_value = value;
	}
	
	// accessors
	public String getLang() { return m_lang; }
	public String getValue() { return m_value; }
	
	// mutators
	public void setLang(String s) { m_lang = s; }
	public void setValue(String s) { m_value = s; }

	/**
     * Returns elements stringified form for debugging
     * @return elements stringified form
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer("(");
    	sb.append(ConvertUtils.stringElemToString("lang", m_lang));
    	sb.append(ConvertUtils.stringElemToString("value", m_value));
    	sb.append(")");
    	return sb.toString();
    }
}
