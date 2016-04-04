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
public class CryptoNonASCIIKeyTest {
	private static Crypto crypto;
	private static final String base64Pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";

	@Parameters(name = "{index}: plainText = \"{0}\", key = \"{1}\"")
	public static Collection<Object[]> parametersASCII() {
		return new FomejaModelList<>(EncryptionDataNonASCIIKey.class, 1<<8);
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
	public static class EncryptionDataNonASCIIKey {
		private static char[] allowedASCIIChars;
		private static int[] allowedASCIICharsMap;
		private static char[] forbiddenASCIIChars;
		static {
			allowedASCIIChars = new char[] {
					'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
					'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
					'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
					'!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
					':', ';', '<', '=', '>', '?', '@',
					'[', '\\', ']', '^', '_', '`',
					'{', '|', '}', '~'
			};

			allowedASCIICharsMap = new int[1<<7];
			for (int c : allowedASCIIChars)
				allowedASCIICharsMap[c] = 1;

			forbiddenASCIIChars = new char[(1<<7)-allowedASCIIChars.length];

			int i=0;
			for (char c=0; c<(1<<7); c++)
				if (allowedASCIICharsMap[c] == 0)
					forbiddenASCIIChars[i++] = c;
		}

		@Variable(order=0, alter=1)
		private String plainText;

		@Variable(order=1, alter=1)
		private String key;

		public EncryptionDataNonASCIIKey() {
			this.plainText = "";
			this.key = "";
		}

		@Constraint
		public boolean plainTextLength() {
			return this.plainText.length() > 0 && this.plainText.length() < 24;
		}

		@Constraint
		public boolean plainTextEncoding() {
			return !StringMethods.hasAnyChar(this.plainText, forbiddenASCIIChars)
					&& StringMethods.anyCharASCII(this.plainText)
					&& !StringMethods.allCharsASCII(this.plainText)
					&& StringMethods.anyCharUTF8(this.plainText)
					&& !StringMethods.allCharsUTF8(this.plainText);
		}

		@Constraint
		public boolean keyLength() {
			return this.key.length() == 16;
		}

		@Constraint
		public boolean keyEncoding() {
			return !StringMethods.anyCharASCII(this.key);
		}
	}
}