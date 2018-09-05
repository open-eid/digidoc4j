package org.digidoc4j.ddoc;

import java.util.Vector;

/**
 * Holds info of an xml element used in signature format
 */
public class XmlElemDef {
    private String m_tag;
    private boolean m_bMultiple;
    private XmlElemDef[] m_children;

    public XmlElemDef(String tag, boolean bMultiple, XmlElemDef[]  children)
    {
        m_tag = tag;
        m_bMultiple = bMultiple;
        m_children = children;
    }

    // accessors
    public String getTag() { return m_tag; }
    public boolean isMultiple() { return m_bMultiple; }
    public XmlElemDef[] getChildren() { return m_children; }

    public XmlElemDef findChildByTag(String tag)
    {
        if(m_tag != null && m_tag.equals(tag))
            return this;
        for(int i = 0; (m_children != null) && (i < m_children.length); i++) {
            XmlElemDef e = m_children[i].findChildByTag(tag);
            if(e != null)
                return e;
        }
        return null;
    }

    public boolean hasPath(Vector vec)
    {
        if(vec.size() > 0) {
            String tag = (String)vec.get(0);
            if(tag.equals(m_tag)) {
                vec.remove(0);
                if(vec.size() == 0) {
                    return true;
                } else {
                    for(int i = 0; (m_children != null) && (i < m_children.length); i++) {
                        XmlElemDef e = m_children[i];
                        if(e.hasPath(vec)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }


}
