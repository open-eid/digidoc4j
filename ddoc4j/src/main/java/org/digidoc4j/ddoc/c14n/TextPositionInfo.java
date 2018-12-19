package org.digidoc4j.ddoc.c14n;

import org.digidoc4j.ddoc.c14n.common.StringImplementation;

public class TextPositionInfo {
    public byte[] Data;
    public int Offset;


    public TextPositionInfo(byte[] d, int o)
    {
        this.Data = d;
        this.Offset = o;
    }


    public String toString()
    {
        Object[] objectArray1;

        objectArray1 = new Object[]
            {
                "[line ",
                new Integer(this.get_Line()),
                ", col ",
                new Integer(this.get_Column()),
                "]"
            };
        return StringImplementation.Concat(objectArray1);
    }

    public int get_Line()
    {
        int n;
        int i;

        n = 1;

        for (i = this.Offset; (i > -1); i--)
        {

            if ((this.Data[i] == 10))
            {
                n++;
            }

        }

        return n;
    }

    public int get_Column()
    {
        int n;
        int i;

        n = 0;

        for (i = this.Offset; (i > -1); i--)
        {

            if ((this.Data[i] == 10))
            {
                break;
            }

            n++;
        }

        return n;
    }

}
