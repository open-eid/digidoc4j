package ee.sk.digidoc.c14n;

import ee.sk.digidoc.c14n.common.StringImplementation;

public class TinyXMLParser_Attribute {
    public TinyXMLParser_Fragment NameFragment;
    public TinyXMLParser_Fragment EqualsFragment;
    public TinyXMLParser_Fragment ValueBegin;
    public TinyXMLParser_Fragment ValueEnd;


    public TinyXMLParser_Attribute()
    {
    }


    public String get_NamePrefix()
    {
        int i;

        i = this.get_NameString().indexOf(":");

        if ((i > -1))
        {
            return StringImplementation.Substring(this.get_NameString(), (int)0, i);
        }

        return null;
    }

    public String get_NameString()
    {
        return this.NameFragment.get_DataString();
    }

    public String get_Name()
    {
        int i;

        i = this.get_NameString().indexOf(":");

        if ((i > -1))
        {
            return this.get_NameString().substring(i);
        }

        return this.get_NameString();
    }

    public TinyXMLParser_Fragment get_ValueFragment()
    {
        TinyXMLParser_Fragment f;

        f = this.ValueBegin.Clone();
        f.Offset = this.ValueBegin.get_LastOffset();
        f.Length = this.get_ValueLength();
        return f;
    }

    public int get_ValueLength()
    {
        return (this.ValueEnd.Offset - this.ValueBegin.get_LastOffset());
    }

    public String get_DataString()
    {
        return FragmentBase.GetDataBetweenFragments(this.ValueBegin, this.ValueEnd);
    }

    public boolean get_IsXMLNS()
    {

        if (!(this.get_NamePrefix() == null))
        {
            return this.get_NamePrefix().equals("xmlns");
        }

        return this.get_Name().equals("xmlns");
    }

    public int CompareTo(TinyXMLParser_Attribute b)
    {

        if ((this.get_NamePrefix() == null))
        {

            if (this.get_IsXMLNS())
            {
                return -1;
            }

        }


        if ((b.get_NamePrefix() == null))
        {

            if (b.get_IsXMLNS())
            {
                return 1;
            }

        }


        if (this.get_IsXMLNS())
        {

            if (b.get_IsXMLNS())
            {
                return this.get_Name().compareTo(b.get_Name());
            }

            return -1;
        }


        if (b.get_IsXMLNS())
        {
            return 1;
        }


        if ((this.get_NamePrefix() == null))
        {

            if ((b.get_NamePrefix() == null))
            {
                return this.get_NameString().compareTo(b.get_NameString());
            }

            return -1;
        }


        if ((b.get_NamePrefix() == null))
        {
            return 1;
        }

        return this.get_NameString().compareTo(b.get_NameString());
    }

    public void ToConsole()
    {
    }

    public static TinyXMLParser_Attribute Of(TinyXMLParser_Fragment f)
    {
        TinyXMLParser_Attribute n;
        boolean seek;

        n = new TinyXMLParser_Attribute();
        n.NameFragment = TinyXMLParser_Element.TagNameOf(f);
        n.EqualsFragment = n.NameFragment.get_NextNonSpace();

        if (!n.EqualsFragment.get_Item("="))
        {
            return null;
        }

        n.ValueBegin = n.EqualsFragment.get_NextNonSpace();

        if (n.ValueBegin != null && !n.ValueBegin.get_IsQuote())
        {
            return null;
        }

        n.ValueEnd = n.ValueBegin.get_Next();
        seek = true;
        while (seek)
        {

            if ((n.ValueEnd == null))
            {
                seek = false;
            }
            else
            {

                if (!(!n.ValueEnd.get_IsQuote() || !n.ValueEnd.get_DataString().equals(n.ValueBegin.get_DataString())))
                {
                    seek = false;
                }

            }


            if (seek)
            {
                n.ValueEnd = n.ValueEnd.get_Next();
            }

        }
        return n;
    }

}
