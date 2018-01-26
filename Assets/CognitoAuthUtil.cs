using System;
using System.Text;

using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;


/*
 *  The following code is cut and pasted from the blog article
 *     http://blog.mmlac.com/aws-cognito-srp-login-c-sharp-dot-net/
 *  By Markus Lachinger. See below for license information
 *  
 *  **However**, below that you will find a classed called Hkdf, 
 *  which his code references but does not include. *That* code
 *  is cut and pasted from the following github gist:
 *    https://gist.github.com/CodesInChaos/8710228
 *  which does not include a license. So, use at your own risk!
 *  
 *  Please *do not* contact me for support. Thanks.
 */



/*  MIT LICENSE
 
Copyright (c) 2017 Markus Lachinger <business@mmlac.com>
 
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
 
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 
*/



/**
 * Class for SRP client side math.
 */
class AuthenticationHelper
{


    // static variables

    private static String HEX_N =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                    + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                    + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                    + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                    + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                    + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
    public static BigInteger N = new BigInteger(HEX_N, 16);
    private static BigInteger g = BigInteger.ValueOf(2);
    public static BigInteger k;

    public static int EPHEMERAL_KEY_LENGTH = 1024;
    public static int DERIVED_KEY_SIZE = 16;
    public static String DERIVED_KEY_INFO = "Caldera Derived Key";
    public static SecureRandom SECURE_RANDOM;




    //static initializer


    static AuthenticationHelper()
    {
        SECURE_RANDOM = SecureRandom.GetInstance("SHA1PRNG");

        HashAlgorithm messageDigest = THREAD_MESSAGE_DIGEST;
        byte[] nArr = N.ToByteArray();
        byte[] gArr = g.ToByteArray();
        byte[] content = new byte[nArr.Length + gArr.Length];
        Buffer.BlockCopy(nArr, 0, content, 0, nArr.Length);
        Buffer.BlockCopy(gArr, 0, content, nArr.Length, gArr.Length);
        byte[] digest = messageDigest.ComputeHash(content);
        k = new BigInteger(1, digest);

        Console.WriteLine();
    }

    [ThreadStatic] private static HashAlgorithm THREAD_MESSAGE_DIGEST = HashAlgorithm.Create("SHA-256");



    // methods below - all stateless



    // return the Tuple of ( A, a )
    public static Tuple<BigInteger, BigInteger> CreateAaTuple()
    {
        BigInteger a, A;
        do {
            a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).Mod(N);
            A = g.ModPow(a, N);
        } while (A.Mod(N).Equals(BigInteger.Zero));

        return Tuple.Create<BigInteger, BigInteger>(A, a);
    }



    //raturns the claim
    public static byte[] authenticateUser(String username,
                                            String password,
                                            String poolName,
                                            Tuple<BigInteger, BigInteger> TupleAa,
                                            String saltString,
                                            String srp_b,
                                            String secretBlock,
                                            String formattedTimestamp)
    {

        byte[] authSecretBlock = System.Convert.FromBase64String(secretBlock);


        BigInteger B = new BigInteger(srp_b, 16);
        if (B.Mod(AuthenticationHelper.N).Equals(BigInteger.Zero)) {
            throw new Exception("B cannot be zero");
        }

        BigInteger salt = new BigInteger(saltString, 16);

        // We need to generate the key to hash the response based on our A and what AWS sent back
        byte[] key = getPasswordAuthenticationKey(username, password, poolName, TupleAa, B, salt);

        // HMAC our data with key (HKDF(S)) (the shared secret)
        byte[] hmac;
        try {
            HMAC mac = HMAC.Create("HMACSHA256");
            mac.Key = key;

            //bytes bytes bytes....
            byte[] poolNameByte = Encoding.UTF8.GetBytes(poolName);
            byte[] name = Encoding.UTF8.GetBytes(username);
            //secretBlock here
            byte[] timeByte = Encoding.UTF8.GetBytes(formattedTimestamp);
            byte[] content = new byte[poolNameByte.Length + name.Length + authSecretBlock.Length + timeByte.Length];

            Buffer.BlockCopy(poolNameByte, 0, content, 0, poolNameByte.Length);
            Buffer.BlockCopy(name, 0, content, poolNameByte.Length, name.Length);
            Buffer.BlockCopy(authSecretBlock, 0, content, poolNameByte.Length + name.Length, authSecretBlock.Length);
            Buffer.BlockCopy(timeByte, 0, content, poolNameByte.Length + name.Length + authSecretBlock.Length, timeByte.Length);

            hmac = mac.ComputeHash(content);
        } catch (Exception e) {
            throw new Exception("Exception in authentication", e);
        }

        return hmac;
    }






    public static byte[] getPasswordAuthenticationKey(String userId,
                                                String userPassword,
                                                String poolName,
                                                Tuple<BigInteger, BigInteger> Aa,
                                                BigInteger B,
                                                BigInteger salt)
    {
        // Authenticate the password
        // u = H(A, B)
        HashAlgorithm messageDigest = THREAD_MESSAGE_DIGEST;
        byte[] aArr = Aa.Item1.ToByteArray();
        byte[] bArr = B.ToByteArray();
        byte[] content = new byte[aArr.Length + bArr.Length];
        Buffer.BlockCopy(aArr, 0, content, 0, aArr.Length);
        Buffer.BlockCopy(bArr, 0, content, aArr.Length, bArr.Length);
        byte[] digest = messageDigest.ComputeHash(content);


        BigInteger u = new BigInteger(1, digest);
        if (u.Equals(BigInteger.Zero)) {
            throw new Exception("Hash of A and B cannot be zero");
        }

        // x = H(salt | H(poolName | userId | ":" | password))
        byte[] poolArr = Encoding.UTF8.GetBytes(poolName);
        byte[] idArr = Encoding.UTF8.GetBytes(userId);
        byte[] colonArr = Encoding.UTF8.GetBytes(":");
        byte[] passArr = Encoding.UTF8.GetBytes(userPassword);

        byte[] userIdContent = new byte[poolArr.Length + idArr.Length + colonArr.Length + passArr.Length];
        Buffer.BlockCopy(poolArr, 0, userIdContent, 0, poolArr.Length);
        Buffer.BlockCopy(idArr, 0, userIdContent, poolArr.Length, idArr.Length);
        Buffer.BlockCopy(colonArr, 0, userIdContent, poolArr.Length + idArr.Length, colonArr.Length);
        Buffer.BlockCopy(passArr, 0, userIdContent, poolArr.Length + idArr.Length + colonArr.Length, passArr.Length);

        byte[] userIdHash = messageDigest.ComputeHash(userIdContent);

        byte[] saltArr = salt.ToByteArray();
        byte[] xArr = new byte[saltArr.Length + userIdHash.Length];
        Buffer.BlockCopy(saltArr, 0, xArr, 0, saltArr.Length);
        Buffer.BlockCopy(userIdHash, 0, xArr, saltArr.Length, userIdHash.Length);

        byte[] xDigest = messageDigest.ComputeHash(xArr);
        BigInteger x = new BigInteger(1, xDigest);
        BigInteger S = (B.Subtract(k.Multiply(g.ModPow(x, N))).ModPow(Aa.Item2.Add(u.Multiply(x)), N)).Mod(N);

        Hkdf hkdf = new Hkdf();
        byte[] key = hkdf.DeriveKey(u.ToByteArray(), S.ToByteArray(), Encoding.UTF8.GetBytes(DERIVED_KEY_INFO), DERIVED_KEY_SIZE);

        return key;
    }





    /// <summary>
    /// [RMS] This code is from https://gist.github.com/CodesInChaos/8710228
    /// </summary>
    class Hkdf
    {
        Func<byte[], byte[], byte[]> keyedHash;

        public Hkdf()
        {
            var hmac = new HMACSHA256();
            keyedHash = (key, message) =>
            {
                hmac.Key = key;
                return hmac.ComputeHash(message);
            };
        }

        public byte[] Extract(byte[] salt, byte[] inputKeyMaterial)
        {
            return keyedHash(salt, inputKeyMaterial);
        }

        public byte[] Expand(byte[] prk, byte[] info, int outputLength)
        {
            var resultBlock = new byte[0];
            var result = new byte[outputLength];
            var bytesRemaining = outputLength;
            for (int i = 1; bytesRemaining > 0; i++) {
                var currentInfo = new byte[resultBlock.Length + info.Length + 1];
                Array.Copy(resultBlock, 0, currentInfo, 0, resultBlock.Length);
                Array.Copy(info, 0, currentInfo, resultBlock.Length, info.Length);
                currentInfo[currentInfo.Length - 1] = (byte)i;
                resultBlock = keyedHash(prk, currentInfo);
                Array.Copy(resultBlock, 0, result, outputLength - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
                bytesRemaining -= resultBlock.Length;
            }
            return result;
        }

        public byte[] DeriveKey(byte[] salt, byte[] inputKeyMaterial, byte[] info, int outputLength)
        {
            var prk = Extract(salt, inputKeyMaterial);
            var result = Expand(prk, info, outputLength);
            return result;
        }
    }


}
