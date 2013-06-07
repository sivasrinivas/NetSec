//package netsec;
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */


import java.math.BigInteger;

/**
 *
 * @author APARNA
 */
public class RSA {

    private BigInteger n,d,e;
    public RSA(BigInteger p,BigInteger q, BigInteger e)
    {
        this.e=e;
              
        n=p.multiply(q);
        BigInteger phi=  (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        d = e.modInverse(phi);
    }
    
  public BigInteger rsaEncrypt(BigInteger message)
  {
     
      return message.modPow(e, n);
      
  }

  public BigInteger rsaEncrypt(BigInteger message,BigInteger e,BigInteger n)
  {
     
      return message.modPow(e, n);
      
  }
   
  public BigInteger rsaDecrypt(BigInteger c)
  {
    
    return c.modPow(d, n);
  } 
}
