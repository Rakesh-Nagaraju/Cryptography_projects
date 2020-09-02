package edu.sjsu.crypto.ciphersys.publicKey;

import edu.sjsu.yazdankhah.crypto.util.cipherutils.FileUtil;
import java.math.BigInteger;
import java.io.Serializable;

public class RabinPublicKey implements Serializable
{
    private static final long serialVersionUID = -4194398601805539439L;
    private String holderName;
    private BigInteger N;
    
    public void save(final String fqn) {
        FileUtil.saveObj((Object)this, fqn);
    }
    
    public void restore(final String fqn) {
        final RabinPublicKey tempPrivateKey = (RabinPublicKey)FileUtil.restoreObj(fqn);
        this.holderName = tempPrivateKey.getHolderName();
        this.N = tempPrivateKey.getN();
    }
    
    public String getHolderName() {
        return this.holderName;
    }
    
    public BigInteger getN() {
        return this.N;
    }
    
    
    public void setHolderName(final String holderName) {
        this.holderName = holderName;
    }
    
    public void setN(final BigInteger N) {
        this.N = N;
    }
    
    
    @Override
    public boolean equals(final Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof RabinPublicKey)) {
            return false;
        }
        final RabinPublicKey other = (RabinPublicKey)o;
        if (!other.canEqual(this)) {
            return false;
        }
        final Object this$holderName = this.getHolderName();
        final Object other$holderName = other.getHolderName();
        Label_0065: {
            if (this$holderName == null) {
                if (other$holderName == null) {
                    break Label_0065;
                }
            }
            else if (this$holderName.equals(other$holderName)) {
                break Label_0065;
            }
            return false;
        }
        final Object this$N = this.getN();
        final Object other$N = other.getN();
        Label_0102: {
            if (this$N == null) {
                if (other$N == null) {
                    break Label_0102;
                }
            }
            else if (this$N.equals(other$N)) {
                break Label_0102;
            }
            return false;
        }
		return false;
    }
    
    protected boolean canEqual(final Object other) {
        return other instanceof RabinPublicKey;
    }
    
    @Override
    public int hashCode() {
        int result = 1;
        final Object $holderName = this.getHolderName();
        result = result * 59 + (($holderName == null) ? 43 : $holderName.hashCode());
        final Object $N = this.getN();
        result = result * 59 + (($N == null) ? 43 : $N.hashCode());
        return result;
    }
    
    @Override
    public String toString() {
        return "RabinPublicKey(holderName=" + this.getHolderName() + ", N=" + this.getN() + ")";
    }
    
    public RabinPublicKey(final String holderName, final BigInteger N) {
        this.holderName = holderName;
        this.N = N;
    }
}