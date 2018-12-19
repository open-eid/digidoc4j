package org.digidoc4j.ddoc.tsl;

import org.digidoc4j.ddoc.utils.ConvertUtils;

/**
 * Models the ETSI TS 102 231 V3.1.1. TSL PostalAddress type
 * @author Veiko Sinivee
 */
public class PostalAddress {
	/** lang attribute */
	private String m_lang;
	/** StreetAddress */
	private String m_street;
	/** Locality */
	private String m_locality;
	/** StateOrProvince */
	private String m_state;
	/** PostalCode */
	private String m_code;
	/** CountryName */
	private String m_country;
	
	/**
	 * Default constructor for PostalAddress
	 */
	public PostalAddress()
	{
		m_lang = null;
		m_street = null;
		m_locality = null;
		m_state = null;
		m_code = null;
		m_country = null;
	}

	/**
	 * Paramterized constrctor for PostalAddress
	 * @param lang lang attribute
	 * @param value value of string
	 */
	public PostalAddress(String lang, String street, String locality,
			String state, String code, String country)
	{
		m_lang = lang;
		m_street = street;
		m_locality = locality;
		m_state = state;
		m_code = code;
		m_country = country;
	}
	
	// accessors
	public String getLang() { return m_lang; }
	public String getStreetAddress() { return m_street; }
	public String getLocality() { return m_locality; }
	public String getStateOrProvince() { return m_state; }
	public String getPostalCode() { return m_code; }
	public String getCountryName() { return m_country; }
	
	// mutators
	public void setLang(String s) { m_lang = s; }
	public void setStreetAddress(String s) { m_street = s; }
	public void setLocality(String s) { m_locality = s; }
	public void setStateOrProvince(String s) { m_state = s; }
	public void setPostalCode(String s) { m_code = s; }
	public void setCountryName(String s) { m_country = s; }

	/**
     * Returns elements stringified form for debugging
     * @return elements stringified form
     */
    public String toString() {
    	StringBuffer sb = new StringBuffer("[PostalAddress");
    	sb.append(ConvertUtils.stringElemToString("lang", m_lang));
    	sb.append(ConvertUtils.stringElemToString("street", m_street));
    	sb.append(ConvertUtils.stringElemToString("locality", m_locality));
    	sb.append(ConvertUtils.stringElemToString("state", m_state));
    	sb.append(ConvertUtils.stringElemToString("code", m_code));
    	sb.append(ConvertUtils.stringElemToString("country", m_country));
    	sb.append("]");
    	return sb.toString();
    }
}

