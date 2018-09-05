package org.digidoc4j.ddoc.c14n;

import java.util.ArrayList;

public final class TinyXMLParser_Element extends TinyXMLParser_Node {
    public TinyXMLParser_Tag Begin;
    public TinyXMLParser_Tag End;


    public TinyXMLParser_Element()
    {
        super();
    }


    public ArrayList get_Attributes()
    {
        return this.Begin.Attributes;
    }

    public String get_TagName()
    {
        return this.get_NameOfBeginTagFragment().get_DataString();
    }

    public TinyXMLParser_Fragment get_NameOfBeginTagFragment()
    {
        return TinyXMLParser_Element.TagNameOf(this.Begin.Begin.get_Next());
    }

    public TinyXMLParser_Fragment get_NameOfEndTagFragment()
    {
        return TinyXMLParser_Element.TagNameOf(this.End.Begin.get_Next());
    }

    public boolean get_IsValid()
    {

        if ((this.Begin == null))
        {
            return false;
        }


        if (this.Begin.End.get_Item("/>"))
        {

            if (!(this.End == null))
            {
                return false;
            }

        }
        else
        {

            if ((this.End == null))
            {
                return false;
            }


            if (!this.End.Begin.get_Next().get_IsLiteral())
            {
                return false;
            }


            if (!this.get_NameOfEndTagFragment().get_DataString().equals(this.get_NameOfBeginTagFragment().get_DataString()))
            {
                return false;
            }

        }

        return true;
    }

    public TinyXMLParser_Attribute GetXMLNSAttributeValue(String p)
    {
        TinyXMLParser_Attribute u;
        int i;
        TinyXMLParser_Attribute a;

        u = null;

        for (i = 0; (i < this.get_Attributes().size()); i++)
        {
            a = ((TinyXMLParser_Attribute)this.get_Attributes().get(i));

            if (a.get_NameString().equals(p))
            {
                u = a;
                break;
            }

        }

        return u;
    }

    public static TinyXMLParser_Fragment TagNameOf(TinyXMLParser_Fragment f)
    {
        TinyXMLParser_Fragment u;
        boolean seek;

        u = f.Clone();
        seek = true;
        while (seek)
        {

            if ((u.get_Next() == null))
            {
                seek = false;
            }
            else
            {

                if (!(u.get_Next().get_Item("-") || u.get_Next().get_IsLiteral()))
                {
                    seek = false;
                }

            }


            if (seek)
            {
                u.Join(u.get_Next());
            }

        }
        return u;
    }

    public static TinyXMLParser_Element Of(TinyXMLParser_Element parent, TinyXMLParser_Fragment f)
    {
        TinyXMLParser_Element n;

        n = new TinyXMLParser_Element();
        n.Parent = parent;
        n.Begin = TinyXMLParser_Tag.Of(f);
        return n;
    }

}
