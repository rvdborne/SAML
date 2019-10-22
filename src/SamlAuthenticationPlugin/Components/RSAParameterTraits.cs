using System;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    internal class RSAParameterTraits
    {
        public RSAParameterTraits(int modulusLengthInBits)
        {
            // The modulus length is supposed to be one of the common lengths, which is the commonly referred to strength of the key,
            // like 1024 bit, 2048 bit, etc.  It might be a few bits off though, since if the modulus has leading zeros it could show
            // up as 1016 bits or something like that.
            int assumedLength = -1;
            double logbase = Math.Log(modulusLengthInBits, 2);
            if (logbase == (int)logbase)
            {
                // It's already an even power of 2
                assumedLength = modulusLengthInBits;
            }
            else
            {
                // It's not an even power of 2, so round it up to the nearest power of 2.
                assumedLength = (int)(logbase + 1.0);
                assumedLength = (int)(Math.Pow(2, assumedLength));
                System.Diagnostics.Debug.Assert(false);  // Can this really happen in the field?  I've never seen it, so if it happens
                // you should verify that this really does the 'right' thing!
            }

            switch (assumedLength)
            {
                case 1024:
                    size_Mod = 0x80;
                    size_Exp = -1;
                    size_D = 0x80;
                    size_P = 0x40;
                    size_Q = 0x40;
                    size_DP = 0x40;
                    size_DQ = 0x40;
                    size_InvQ = 0x40;
                    break;
                case 2048:
                    size_Mod = 0x100;
                    size_Exp = -1;
                    size_D = 0x100;
                    size_P = 0x80;
                    size_Q = 0x80;
                    size_DP = 0x80;
                    size_DQ = 0x80;
                    size_InvQ = 0x80;
                    break;
                case 4096:
                    size_Mod = 0x200;
                    size_Exp = -1;
                    size_D = 0x200;
                    size_P = 0x100;
                    size_Q = 0x100;
                    size_DP = 0x100;
                    size_DQ = 0x100;
                    size_InvQ = 0x100;
                    break;
                default:
                    System.Diagnostics.Debug.Assert(false); // Unknown key size?
                    break;
            }
        }

        public int size_Mod = -1;
        public int size_Exp = -1;
        public int size_D = -1;
        public int size_P = -1;
        public int size_Q = -1;
        public int size_DP = -1;
        public int size_DQ = -1;
        public int size_InvQ = -1;
    }
}
