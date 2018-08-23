package ee.sk.digidoc;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * Models the ETSI <Include> element
 * Holds info about source of data used to
 * calculate timestamp hash. Such elements will
 * be serialized as part of a timestamp element.
 * @author  Veiko Sinivee
 * @version 1.0
 */
public class IncludeInfo implements Serializable
{
    private static final long serialVersionUID = 1L;
    /** elements URI atribute */
    private String m_uri;
    /** parent object - TimestampInfo ref */
    private TimestampInfo m_timestamp;

    /**
     * Creates new IncludeInfo
     * and initializes everything to null
     */
    public IncludeInfo() {
        m_uri = null;
        m_timestamp = null;
    }

    /**
     * Creates new IncludeInfo
     * @param uri URI atribute value
     * @throws DigiDocException for validation errors
     */
    public IncludeInfo(String uri)
            throws DigiDocException
    {
        setUri(uri);
        m_timestamp = null;
    }

    /**
     * Accessor for TimestampInfo attribute
     * @return value of TimestampInfo attribute
     */
    public TimestampInfo getTimestampInfo()
    {
        return m_timestamp;
    }

    /**
     * Mutator for TimestampInfo attribute
     * @param uprops value of TimestampInfo attribute
     */
    public void setTimestampInfo(TimestampInfo t)
    {
        m_timestamp = t;
    }

    /**
     * Accessor for Uri attribute
     * @return value of Uri attribute
     */
    public String getUri() {
        return m_uri;
    }

    /**
     * Mutator for Uri attribute
     * @param str new value for Uri attribute
     * @throws DigiDocException for validation errors
     */
    public void setUri(String str)
            throws DigiDocException
    {
        DigiDocException ex = validateUri(str);
        if(ex != null)
            throw ex;
        m_uri = str;
    }

    /**
     * Helper method to validate Uri
     * @param str input data
     * @return exception or null for ok
     */
    private DigiDocException validateUri(String str)
    {
        DigiDocException ex = null;
        if(str == null)
            ex = new DigiDocException(DigiDocException.ERR_INCLUDE_URI,
                    "URI atribute cannot be empty", null);
        return ex;
    }

    /**
     * Helper method to validate the whole
     * IncludeInfo object
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = validateUri(m_uri);
        if(ex != null)
            errs.add(ex);
        return errs;
    }

}
