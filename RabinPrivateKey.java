package edu.sjsu.crypto.ciphersys.publicKey;
import edu.sjsu.yazdankhah.crypto.util.cipherutils.FileUtil;
import java.io.Serializable;
import java.math.BigInteger;

public class RabinPrivateKey implements Serializable {
  private static final long serialVersionUID = -7039987426308509488L;

  private BigInteger P;
  private BigInteger Q;

  public void save(String fqn) {
     FileUtil.saveObj(this, fqn);
  }

  public void restore(String fqn) {
     RabinPrivateKey tempPrivateKey = (RabinPrivateKey)FileUtil.restoreObj(fqn);
     this.P = tempPrivateKey.getP();
     this.Q = tempPrivateKey.getQ();
  }

  public BigInteger getP() {
     return this.P;
  }

  public BigInteger getQ() {
     return this.Q;
  }

  public void setP(BigInteger P) {
     this.P = P;
  }

  public void setQ(BigInteger Q) {
     this.Q = Q;
  }

  public boolean equals(Object o) {
     if (o == this) {
        return true;
     } else if (!(o instanceof RabinPrivateKey)) {
        return false;
     } else {
    	 RabinPrivateKey other = (RabinPrivateKey)o;
        if (!other.canEqual(this)) {
           return false;
        } else {
           Object this$P = this.getP();
           Object other$P = other.getP();
           if (this$P == null) {
              if (other$P != null) {
                 return false;
              }
           } else if (!this$P.equals(other$P)) {
              return false;
           }

           Object this$Q = this.getQ();
           Object other$Q = other.getQ();
           if (this$Q == null) {
              if (other$Q != null) {
                 return false;
              }
           } else if (!this$Q.equals(other$Q)) {
              return false;
           }

           return true;
        }
     }
  }

  protected boolean canEqual(Object other) {
     return other instanceof RabinPrivateKey;
  }

  public int hashCode() {
     int result = 1;
     final Object $P = this.getP();
     result = result * 59 + ($P == null ? 43 : $P.hashCode());
     final Object $Q = this.getQ();
     result = result * 59 + ($Q == null ? 43 : $Q.hashCode());
     return result;
  }

  public String toString() {
     return "RabinPrivateKey(P=" + this.getP() + ", Q=" + this.getQ() + ")";
  }

  public RabinPrivateKey(BigInteger P, BigInteger Q) {
     this.P = P;
     this.Q = Q;
  }
}