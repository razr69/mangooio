package io.mangoo.crypto;

import static io.mangoo.test.hamcrest.RegexMatcher.matches;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import org.junit.Before;
import org.junit.Test;

import io.mangoo.core.Application;

/**
 * 
 * @author svenkubiak
 *
 */
@SuppressWarnings("unchecked")
public class OriginalCryptoTest {
    private static Crypto crypto;
    private static final String base64Pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
    private static final String plainText = "This\nis\ra super secret message!";
    private static final String key = "My voice\nis\rmy password!$";
    
    @Before
    public void init() {
        crypto = Application.getInjector().getInstance(Crypto.class);
    }
    
    @Test
    public void testEncryption() {
        //when
        String encrypt = crypto.encrypt(plainText);

        //then
        assertThat(encrypt, not(nullValue()));
        assertThat(encrypt, matches(base64Pattern));
        assertThat(encrypt, not(equalTo(plainText)));
    }
    
    @Test
    public void testEncryptionWithKey() {
        //when
        String encrypt = crypto.encrypt(plainText, key);
        
        //then
        assertThat(encrypt, not(nullValue()));
        assertThat(encrypt, matches(base64Pattern));
        assertThat(encrypt, not(equalTo(plainText)));
    }
    
    @Test
    public void testDecryption() {
        //given
        String encrypt = crypto.encrypt(plainText);
        
        //when
        String decrypt = crypto.decrypt(encrypt);

        //then
        assertThat(decrypt, not(nullValue()));
        assertThat(decrypt, equalTo(plainText));
    }
    
    @Test
    public void testDecryptionWithKey() {
        //given
        String encrypt = crypto.encrypt(plainText, key);

        //when
        String decrypt = crypto.decrypt(encrypt, key);

        //then
        assertThat(decrypt, not(nullValue()));
        assertThat(decrypt, equalTo(plainText));
    }
}