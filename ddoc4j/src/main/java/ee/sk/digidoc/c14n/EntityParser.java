package ee.sk.digidoc.c14n;

import ee.sk.digidoc.c14n.common.Convert;

public final class EntityParser
{
    public byte[] Data;
    public int Offset;
    public int Length;
    public EntityParser_Handler Resolver;
    private String _text;


    public EntityParser()
    {
        this.Resolver = new EntityParser_DefaultHandler();
    }


    public String get_DataString()
    {
        return Convert.ToString(this.Data, this.Offset, this.Length);
    }

    private void Parse()
    {
        EntityParser_Fragment f;
        StringBuffer b;
        EntityParser_Entity u;
        String r;

        f = EntityParser_Fragment.Of(this.Data, this.Offset, new FragmentBase_Bounds(this.Offset, this.Length));

        if ((f == null))
        {
            return;
        }

        f.SplitMarkup();
        b = new StringBuffer();
        while (!(f == null))
        {

            if (f.get_IsMarkup())
            {

                if (f.get_Item("&"))
                {
                    u = EntityParser_Entity.Of(f);

                    if (!(u == null))
                    {

                        if (!(this.Resolver == null))
                        {
                            r = this.Resolver.ResolveEntity(u);

                            if (!(r == null))
                            {
                                b.append(r);
                                f = u.End.get_Next();
                                continue;
                            }

                        }

                    }

                }

            }


            if (!(this.Resolver == null))
            {
                b.append(this.Resolver.ResolveText(f.get_DataString()));
            }
            else
            {
                b.append(f.get_DataString());
            }

            f = f.get_Next();
        }
        this._text = b.toString();
    }

    public String get_Text()
    {

        if ((this.Length == 0))
        {
            return "";
        }


        if ((this._text == null))
        {
            this.Parse();
        }

        return this._text;
    }

    public static EntityParser Of(byte[] data, int offset, int length)
    {
        EntityParser n;

        n = new EntityParser();
        n.Data = data;
        n.Offset = offset;
        n.Length = length;
        return n;
    }

    public static EntityParser Of(FragmentBase fragment)
    {
        return EntityParser.Of(fragment.Data, fragment.Offset, fragment.Length);
    }

}
