package org.digidoc4j.ddoc.c14n;

import java.util.ArrayList;

public final class TinyXMLParser_Tag {

    public TinyXMLParser_Fragment Begin;
    public TinyXMLParser_Fragment End;
    public ArrayList Attributes;

    public TinyXMLParser_Tag() {
    }

    public String get_Name()
    {
        return this.get_NameFragment().get_DataString();
    }

    public TinyXMLParser_Fragment get_NameFragment()
    {
        return TinyXMLParser_Element.TagNameOf(this.Begin.get_Next());
    }

    public String get_DataString()
    {
        return FragmentBase.GetDataBetweenFragments(this.Begin, this.End);
    }

    public boolean get_CanHaveAttributes()
    {

        if (this.Begin.get_Item("<"))
        {
            return true;
        }


        if (this.Begin.get_Item("<?"))
        {
            return true;
        }

        return false;
    }

    public static TinyXMLParser_Tag Of(TinyXMLParser_Fragment f)
    {
        TinyXMLParser_Tag n;
        boolean seek;
        TinyXMLParser_Attribute a;

        n = new TinyXMLParser_Tag();
        n.Begin = f;
        n.End = f.get_Next();
        seek = true;

        if (!(n.End == null))
        {

            if (f.get_Item("<"))
            {
                n.End = n.End.get_Next();
                n.Attributes = new ArrayList();
                while (seek)
                {

                    if (n.End.get_IsLiteral())
                    {
                        a = TinyXMLParser_Attribute.Of(n.End);

                        if (!(a == null))
                        {
                            n.End = a.ValueEnd.get_Next();
                            n.Attributes.add(a);
                            continue;
                        }

                    }
                    else
                    {

                        if (n.End.get_Item(">"))
                        {
                            seek = false;
                        }
                        else
                        {

                            if (n.End.get_Item("/>"))
                            {
                                seek = false;
                            }
                            else
                            {

                                if ((n.End.get_Next() == null))
                                {
                                    seek = false;
                                }

                            }

                        }

                    }


                    if (seek)
                    {
                        n.End = n.End.get_Next();
                    }

                }
            }
            else
            {

                if (f.get_Item("</"))
                {
                    while (seek)
                    {

                        if (n.End.get_Item(">"))
                        {
                            seek = false;
                        }
                        else
                        {

                            if ((n.End.get_Next() == null))
                            {
                                seek = false;
                            }
                            else
                            {
                                n.End = n.End.get_Next();
                            }

                        }

                    }
                }
                else
                {

                    if (f.get_Item("<?"))
                    {
                        n.Attributes = new ArrayList();
                        while (seek)
                        {

                            if (n.End.get_IsLiteral())
                            {
                                a = TinyXMLParser_Attribute.Of(n.End);

                                if (!(a == null))
                                {
                                    n.End = a.ValueEnd.get_Next();
                                    n.Attributes.add(a);
                                    continue;
                                }

                            }


                            if (n.End.get_Item("?>"))
                            {
                                seek = false;
                            }
                            else
                            {

                                if ((n.End.get_Next() == null))
                                {
                                    seek = false;
                                }
                                else
                                {
                                    n.End = n.End.get_Next();
                                }

                            }

                        }
                    }
                    else
                    {

                        if (f.get_Item("<!--"))
                        {
                            while (seek)
                            {

                                if (n.End.get_Item("-->"))
                                {
                                    seek = false;
                                }
                                else
                                {

                                    if ((n.End.get_Next() == null))
                                    {
                                        seek = false;
                                    }
                                    else
                                    {
                                        n.End = n.End.get_Next();
                                    }

                                }

                            }
                        }
                        else
                        {
                            n = null;
                        }

                    }

                }

            }

        }

        return n;
    }

}
