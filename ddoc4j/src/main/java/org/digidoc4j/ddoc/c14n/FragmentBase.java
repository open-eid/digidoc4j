package org.digidoc4j.ddoc.c14n;

import org.digidoc4j.ddoc.c14n.common.Convert;

/**
 * a fragment represents a special bytestream, a class of bytes, for example
 * - spaces \x20 \x09 \x0D \0x0A
 * - markup for xml < > / "
 * it is alike java tokenizer yet different
 */
public abstract class FragmentBase {
    public byte[] Data;
    public int Offset;
    public int Length;
    public FragmentBase_Bounds ExplicitBounds;


    protected FragmentBase()
    {
    }

    /**
     * if a fragment is too wide it can contain multiple child fragments like start and close
     * fragment both. So after this method is called they are split apart.
     */
    protected boolean SplitBy(String[] e)
    {
        boolean ret;
        String var;
        String[] stringArray3;
        int num4;

        ret = false;
        stringArray3 = e;

        for (num4 = 0; (num4 < (stringArray3.length)); num4++)
        {
            var = stringArray3[num4];

            if (this.SplitBy(var))
            {
                ret = true;
                break;
            }

        }

        return ret;
    }

    abstract protected boolean SplitBy(String e);

    /**
     * returns true if the whole fragment starts with a given string
     */
    public boolean StartsWith(String e)
    {

        if ((e.length() > this.Length))
        {
            return false;
        }

        return Convert.ToString(this.Data, this.Offset, e.length()).equals(e);
    }

    /**
     * returns a utf8 string that represents the bytes in this fragment
     */
    public String get_DataString()
    {
        return Convert.ToString(this.Data, this.Offset, this.Length, "UTF-8");
    }

    public boolean get_Item(String ds)
    {
        return this.get_DataString().equals(ds);
    }

    public boolean get_Item(String[] ds)
    {
        int i;


        for (i = 0; (i < (ds.length)); i++)
        {

            if (this.get_Item(ds[i]))
            {
                return true;
            }

        }

        return false;
    }

    /**
     * returns the offset where the next fragment should begin
     */
    public int get_LastOffset()
    {
        return (this.Offset + this.Length);
    }

    protected char GetChar(int o)
    {
        char c;

        c = ((char)this.Data[(this.Offset + o)]);
        return c;
    }

    protected boolean InBounds(int p)
    {

        if ((p < 0))
        {
            return false;
        }


        if (!(this.ExplicitBounds == null))
        {

            if (!this.ExplicitBounds.InBounds(p))
            {
                return false;
            }

        }

        return (p < (this.Data.length));
    }

    protected static void SplitBy(FragmentBase left, FragmentBase right, int length)
    {
        left.Length = length;
        right.Length = (right.Length - length);
        right.Offset = (right.Offset + length);
    }

    /**
     * returns the string between to fragments,
     * used if only start and end tags are known
     */
    public static String GetDataBetweenFragments(FragmentBase from, FragmentBase to)
    {
        return Convert.ToString(from.Data, (from.Offset + from.Length), (to.Offset - from.get_LastOffset()));
    }

}

