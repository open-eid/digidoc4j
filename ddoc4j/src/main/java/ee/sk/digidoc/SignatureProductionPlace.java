package ee.sk.digidoc;

import java.io.Serializable;

/**
 * Models the SignatureProductionPlace element of
 * an XML-DSIG/ETSI Signature.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class SignatureProductionPlace  implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** city name */
    private String m_city;
    /** state name */
    private String m_state;
    /** county name */
    private String m_country;
    /** postal code */
    private String m_zip;

    /**
     * Creates new SignatureProductionPlace
     * Initializes everything to null
     */
    public SignatureProductionPlace() {
        m_city = null;
        m_state = null;
        m_country = null;
        m_zip = null;
    }

    /**
     * Creates new SignatureProductionPlace
     * @param city city name
     * @param state state or province name
     * @param country country name
     * @param zip postal code
     */
    public SignatureProductionPlace(String city, String state,
                                    String country, String zip)
    {
        m_city = city;
        m_state = state;
        m_country = country;
        m_zip = zip;
    }

    /**
     * Accessor for city attribute
     * @return value of city attribute
     */
    public String getCity() {
        return m_city;
    }

    /**
     * Mutator for city attribute
     * @param str new value for city attribute
     */
    public void setCity(String str)
    {
        m_city = str;
    }

    /**
     * Accessor for stateOrProvince attribute
     * @return value of stateOrProvince attribute
     */
    public String getStateOrProvince() {
        return m_state;
    }

    /**
     * Mutator for stateOrProvince attribute
     * @param str new value for stateOrProvince attribute
     */
    public void setStateOrProvince(String str)
    {
        m_state = str;
    }

    /**
     * Accessor for countryName attribute
     * @return value of countryName attribute
     */
    public String getCountryName() {
        return m_country;
    }

    /**
     * Mutator for countryName attribute
     * @param str new value for countryName attribute
     */
    public void setCountryName(String str)
    {
        m_country = str;
    }

    /**
     * Accessor for postalCode attribute
     * @return value of postalCode attribute
     */
    public String getPostalCode() {
        return m_zip;
    }

    /**
     * Mutator for postalCode attribute
     * @param str new value for postalCode attribute
     */
    public void setPostalCode(String str)
    {
        m_zip = str;
    }

}
