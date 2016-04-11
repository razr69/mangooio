package io.mangoo.crypto;

import static io.mangoo.test.hamcrest.RegexMatcher.matches;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import io.mangoo.core.Application;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import de.uni_bremen.agra.fomeja.FomejaModelList;
import de.uni_bremen.agra.fomeja.annotations.Constraint;
import de.uni_bremen.agra.fomeja.annotations.Variable;
import de.uni_bremen.agra.fomeja.utils.constraintmethods.StringMethods;

/**
 * 
 * @author svenkubiak
 *
 */
@SuppressWarnings("unchecked")
@RunWith(Parameterized.class)
public class CryptoASCIIKeyTest {
	private static final boolean VALIDATE_DATA = true;
	private static final int DATA_LIMIT = 1<<8;

	private static Crypto crypto;
	private static final String base64Pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";

	@Parameters(name = "{index} w/ gen plaintext and key")
	public static Collection<Object[]> parametersASCII() {
		return new FomejaModelList<>(EncryptionDataASCIIKey.class, VALIDATE_DATA, DATA_LIMIT);
	}

	@Parameter(0)
	public String plainText;

	@Parameter(1)
	public String key;

	@Before
	public void init() {
		crypto = Application.getInjector().getInstance(Crypto.class);
	}

	@Test
	public void testEncryption() {
		// when
		String encrypt = crypto.encrypt(this.plainText);

		// then
		assertThat(encrypt, not(nullValue()));
		assertThat(encrypt, matches(base64Pattern));
		assertThat(encrypt, not(equalTo(this.plainText)));
	}

	@Test
	public void testEncryptionWithKey() {
		// when
		String encrypt = crypto.encrypt(this.plainText, this.key);

		// then
		assertThat(encrypt, not(nullValue()));
		assertThat(encrypt, matches(base64Pattern));
		assertThat(encrypt, not(equalTo(this.plainText)));
	}

	@Test
	public void testDecryption() {
		// given
		String encrypt = crypto.encrypt(this.plainText);

		// when
		String decrypt = crypto.decrypt(encrypt);

		// then
		assertThat(decrypt, not(nullValue()));
		assertThat(decrypt, equalTo(this.plainText));
	}

	@Test
	public void testDecryptionWithKey() {
		// given
		String encrypt = crypto.encrypt(this.plainText, this.key);

		// when
		String decrypt = crypto.decrypt(encrypt, this.key);

		// then
		assertThat(decrypt, not(nullValue()));
		assertThat(decrypt, equalTo(this.plainText));
	}

	/**
	 * 
	 * @author Max Nitze
	 */
	public static class EncryptionDataASCIIKey {
		@Variable(order=0, alter=1)
		private String plainText;

		@Variable(order=1, alter=1)
		private String key;

		public EncryptionDataASCIIKey() {
			this.plainText = "";
			this.key = "";
		}

		@Constraint
		public boolean plainTextLength() {
			return this.plainText.length() > 0 && this.plainText.length() < 24;
		}

		@Constraint
		public boolean plainTextEncoding() {
			return StringMethods.anyCharASCII(this.plainText)
					&& !StringMethods.allCharsASCII(this.plainText)
					&& StringMethods.anyCharUTF8(this.plainText)
					&& !StringMethods.allCharsUTF8(this.plainText);
		}

		@Constraint
		public boolean keyLength() {
			return this.key.length()*8 == 128;
		}

		@Constraint
		public boolean keyEncoding() {
			return StringMethods.allCharsASCII(this.key);
		}
	}
}