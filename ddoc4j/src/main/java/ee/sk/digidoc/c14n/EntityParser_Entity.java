package ee.sk.digidoc.c14n;

import ee.sk.digidoc.c14n.common.Convert;

public class EntityParser_Entity {

    public EntityParser_Fragment Begin;
    public EntityParser_Fragment Hash;
    public EntityParser_Fragment Name;
    public EntityParser_Fragment End;

    public EntityParser_Entity() {
    }


    public boolean get_Item(String ds) {
        return this.get_Text().equals(ds);
    }

    public int get_OriginalStringLength() {
        return (this.End.get_LastOffset() - this.Begin.Offset);
    }

    public String get_OriginalString() {
        return Convert.ToString(this.Begin.Data, this.Begin.Offset, this.get_OriginalStringLength());
    }

    public boolean get_IsNumeric()
    {
        return !(this.Hash == null);
    }

    public String get_HexValue()
    {
        return Convert.ToHexString(this.get_IntegerValue(), false).toUpperCase();
    }

    public int get_IntegerValue() {

        if (this.get_IsHexNumber()) {
            return Convert.ToInt32(this.get_HexNumberBytes(), (int)0);
        }

        return Convert.ToInt32(this.get_Text());
    }

    public String get_Text()
    {
        return this.Name.get_DataString();
    }

    public boolean get_IsHexNumber()
    {
        return this.get_Text().startsWith("x");
    }

    public boolean get_IsValid()
    {
        return true;
    }

    public byte[] get_HexNumberBytes()
    {
        return Convert.FromHexString(this.get_Text().substring((int)1));
    }

    public static EntityParser_Entity Of(EntityParser_Fragment f) {
        EntityParser_Entity n;


        if ((f == null))
        {
            return null;
        }


        if ((f.get_Next() == null))
        {
            return null;
        }


        if (!f.get_Item("&"))
        {
            return null;
        }

        n = new EntityParser_Entity();
        n.Begin = f;

        if (f.get_Next().get_Item("#"))
        {
            n.Hash = f.get_Next();

            if ((n.Hash.get_Next() == null))
            {
                return null;
            }

            n.Name = n.Hash.get_Next();
        }
        else
        {
            n.Name = f.get_Next();
        }


        if ((n.Name.get_Next() == null))
        {
            return null;
        }


        if (!n.Name.get_Next().get_Item(";"))
        {
            return null;
        }

        n.End = n.Name.get_Next();

        if (!n.get_IsValid())
        {
            return null;
        }

        return n;
    }

}
