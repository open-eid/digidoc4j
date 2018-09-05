package org.digidoc4j.ddoc;

import java.io.Serializable;

/**
 * Models the QualifyingProperties element of
 * an BDOC.
 * @author  Kalev Suik
 * @version 1.0
 */

public class QualifyingProperties implements Serializable
{
    private static final long serialVersionUID = 1L;
    private String m_Target;

    public String getTarget() {
        return m_Target;
    }

    public void setTarget(String target) {
        m_Target = target;
    }

}
