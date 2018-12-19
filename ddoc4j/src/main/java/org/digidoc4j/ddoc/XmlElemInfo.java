package org.digidoc4j.ddoc;

import java.util.Vector;

/**
 * Holds info of an xml element actually encountered in a signed document
 */
public class XmlElemInfo {
    private String m_tag;
    private String m_id;
    private XmlElemInfo m_parent;
    private Vector m_children;

    public XmlElemInfo(String tag, String id, XmlElemInfo parent)
    {
        m_tag = tag;
        m_id = id;
        m_parent = parent;
    }

    // accessors
    public String getTag() { return m_tag; }
    public String getId() { return m_id; }
    public XmlElemInfo getParent() { return m_parent; }

    public String getPath(boolean bWithId)
    {
        StringBuffer sb = new StringBuffer();
        XmlElemInfo e = this;
        do {
            sb.insert(0, e.getTag());
            sb.insert(0, "/");
            e = e.getParent();
        } while(e != null);
        if(bWithId && m_id != null) {
            sb.append("@id=");
            sb.append(m_id);
        }
        return sb.toString();
    }

    public void addChild(XmlElemInfo e)
    {
        if(m_children == null)
            m_children = new Vector();
        m_children.add(e);
    }

    public Vector getPathTags()
    {
        Vector vec = new Vector();
        XmlElemInfo e = this;
        do {
            vec.insertElementAt(e.getTag(), 0);
            e = e.getParent();
        } while(e != null);
        return vec;
    }

    public void findElementsWithTag(Vector vec, String tag)
    {
        if(m_tag.equals(tag))
            vec.add(this);
        for(int i = 0; (m_children != null) && (i < m_children.size()); i++) {
            XmlElemInfo e = (XmlElemInfo)m_children.get(i);
            e.findElementsWithTag(vec, tag);
        }
    }

    public XmlElemInfo getRootElem()
    {
        if(m_parent != null)
            return m_parent.getRootElem();
        else
            return this;
    }

    public String getRootTag()
    {
        XmlElemInfo eRoot = getRootElem();
        if(eRoot != null)
            return eRoot.getTag();
        return null;
    }
}
