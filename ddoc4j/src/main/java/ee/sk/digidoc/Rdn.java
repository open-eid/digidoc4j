package ee.sk.digidoc;

import java.io.Serializable;

/**
 * Holds data of one relative distinguished name (RDN) from a DN
 * normalized according to RFC4514
 * @author Veiko Sinivee
 */
public class Rdn implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** field id or short name */
    private String m_id;
    /** field name or description */
    private String m_name;
    /** field value */
    private String m_value;

    /**
     String  X.500 AttributeType
     ------  --------------------------------------------
     CN      commonName (2.5.4.3)
     L       localityName (2.5.4.7)
     ST      stateOrProvinceName (2.5.4.8)
     O       organizationName (2.5.4.10)
     OU      organizationalUnitName (2.5.4.11)
     C       countryName (2.5.4.6)
     STREET  streetAddress (2.5.4.9)
     DC      domainComponent (0.9.2342.19200300.100.1.25)
     UID     userId (0.9.2342.19200300.100.1.1)
     */
    public static final String[] RDN_IDS = { "CN", "L", "ST", "O", "OU", "C", "STREET", "DC", "UID" };
    public static final String[] RDN_NAMES = { "commonName", "localityName", "stateOrProvinceName", "organizationName", "organizationalUnitName", "countryName", "streetAddress", "domainComponent", "userId" };


    /**
     * Default constructor for Rdn
     */
    public Rdn()
    {
        m_id = null;
        m_name = null;
        m_value = null;
    }

    /**
     * Parametrized constructor for Rdn
     */
    public Rdn(String id, String name, String value)
    {
        m_id = id;
        m_name = name;
        m_value = value;
    }

    // accessors
    public String getId() { return m_id; }
    public String getName() { return m_name; }
    public String getValue() { return m_value; }

    // mutators
    public void setId(String s) { m_id = s; }
    public void setName(String s) { m_name = s; }
    public void setValue(String s) { m_value = s; }

}
