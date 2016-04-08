package io.mangoo.crypto;

import static io.mangoo.test.hamcrest.RegexMatcher.matches;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import io.mangoo.core.Application;

import java.util.Collection;

import org.junit.Before;
import org.junit.Ignore;
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
@Ignore
public class CryptoASCIIKeyBitEncodingTest {
	private static Crypto crypto;
	private static final String base64Pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";

	@Parameters(name = "{index}: plainText = \"{0}\", key = \"{1}\"")
	public static Collection<Object[]> parametersASCII() {
		return new FomejaModelList<>(EncryptionDataASCIIKey.class, 1<<8);
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
		private static char[] allowedASCIIChars;
		private static int[] allowedASCIICharsMap;
		private static char[] forbiddenASCIIChars;
		static {
			allowedASCIIChars = new char[] {
					'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
					'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
					'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
					' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
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

		@Variable(order=-1)
		private int keyC00Bytes;
		@Variable(order=-1)
		private int keyC01Bytes;
		@Variable(order=-1)
		private int keyC02Bytes;
		@Variable(order=-1)
		private int keyC03Bytes;
		@Variable(order=-1)
		private int keyC04Bytes;
		@Variable(order=-1)
		private int keyC05Bytes;
		@Variable(order=-1)
		private int keyC06Bytes;
		@Variable(order=-1)
		private int keyC07Bytes;
		@Variable(order=-1)
		private int keyC08Bytes;
		@Variable(order=-1)
		private int keyC09Bytes;
		@Variable(order=-1)
		private int keyC10Bytes;
		@Variable(order=-1)
		private int keyC11Bytes;
		@Variable(order=-1)
		private int keyC12Bytes;
		@Variable(order=-1)
		private int keyC13Bytes;
		@Variable(order=-1)
		private int keyC14Bytes;
		@Variable(order=-1)
		private int keyC15Bytes;
		@Variable(order=-1)
		private int keyBytes;

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
			return !StringMethods.hasAnyChar(this.plainText, forbiddenASCIIChars)
					&& StringMethods.anyCharASCII(this.plainText)
					&& !StringMethods.allCharsASCII(this.plainText)
					&& StringMethods.anyCharUTF8(this.plainText)
					&& !StringMethods.allCharsUTF8(this.plainText);
		}

		@Constraint
		public boolean keyBytesSum() {
			return this.keyBytes ==
					this.keyC00Bytes + this.keyC01Bytes + this.keyC02Bytes + this.keyC03Bytes
					+ this.keyC04Bytes + this.keyC05Bytes + this.keyC06Bytes + this.keyC07Bytes
					+ this.keyC08Bytes + this.keyC09Bytes + this.keyC10Bytes + this.keyC11Bytes
					+ this.keyC12Bytes + this.keyC13Bytes + this.keyC14Bytes + this.keyC15Bytes;
		}

		@Constraint
		public boolean keyLength() {
			return this.keyBytes == 128 || this.keyBytes == 192 || this.keyBytes == 256;
		}

		@Constraint
		public boolean keyEncoding() {
			return !StringMethods.hasAnyChar(this.key, forbiddenASCIIChars)
					&& StringMethods.allCharsUTF8(this.key)
					&& this.key.charAt(0) != ' '
					&& this.key.charAt(15) != ' ';
		}

		@Constraint
		public boolean keyC00Encoding() {
			return StringMethods.isASCII(this.key.charAt(0)) && this.keyC00Bytes == 8
					|| this.key.charAt(0) >= 128 && this.key.charAt(0) < 256 && this.keyC00Bytes == 16;
		}

		@Constraint
		public boolean keyC01Encoding() {
			return StringMethods.isASCII(this.key.charAt(1)) && this.keyC01Bytes == 8
					|| this.key.charAt(1) >= 128 && this.key.charAt(1) < 256 && this.keyC01Bytes == 16;
		}

		@Constraint
		public boolean keyC02Encoding() {
			return StringMethods.isASCII(this.key.charAt(2)) && this.keyC02Bytes == 8
					|| this.key.charAt(2) >= 128 && this.key.charAt(2) < 256 && this.keyC02Bytes == 16;
		}

		@Constraint
		public boolean keyC03Encoding() {
			return StringMethods.isASCII(this.key.charAt(3)) && this.keyC03Bytes == 8
					|| this.key.charAt(3) >= 128 && this.key.charAt(3) < 256 && this.keyC03Bytes == 16;
		}

		@Constraint
		public boolean keyC04Encoding() {
			return StringMethods.isASCII(this.key.charAt(4)) && this.keyC04Bytes == 8
					|| this.key.charAt(4) >= 128 && this.key.charAt(4) < 256 && this.keyC04Bytes == 16;
		}

		@Constraint
		public boolean keyC05Encoding() {
			return StringMethods.isASCII(this.key.charAt(5)) && this.keyC05Bytes == 8
					|| this.key.charAt(5) >= 128 && this.key.charAt(5) < 256 && this.keyC05Bytes == 16;
		}

		@Constraint
		public boolean keyC06Encoding() {
			return StringMethods.isASCII(this.key.charAt(6)) && this.keyC06Bytes == 8
					|| this.key.charAt(6) >= 128 && this.key.charAt(6) < 256 && this.keyC06Bytes == 16;
		}

		@Constraint
		public boolean keyC07Encoding() {
			return StringMethods.isASCII(this.key.charAt(7)) && this.keyC07Bytes == 8
					|| this.key.charAt(7) >= 128 && this.key.charAt(7) < 256 && this.keyC07Bytes == 16;
		}

		@Constraint
		public boolean keyC08Encoding() {
			return StringMethods.isASCII(this.key.charAt(8)) && this.keyC08Bytes == 8
					|| this.key.charAt(8) >= 128 && this.key.charAt(8) < 256 && this.keyC08Bytes == 16;
		}

		@Constraint
		public boolean keyC09Encoding() {
			return StringMethods.isASCII(this.key.charAt(9)) && this.keyC09Bytes == 8
					|| this.key.charAt(9) >= 128 && this.key.charAt(9) < 256 && this.keyC09Bytes == 16;
		}

		@Constraint
		public boolean keyC10Encoding() {
			return StringMethods.isASCII(this.key.charAt(10)) && this.keyC10Bytes == 8
					|| this.key.charAt(10) >= 128 && this.key.charAt(10) < 256 && this.keyC10Bytes == 16;
		}

		@Constraint
		public boolean keyC11Encoding() {
			return StringMethods.isASCII(this.key.charAt(11)) && this.keyC11Bytes == 8
					|| this.key.charAt(11) >= 128 && this.key.charAt(11) < 256 && this.keyC11Bytes == 16;
		}

		@Constraint
		public boolean keyC12Encoding() {
			return StringMethods.isASCII(this.key.charAt(12)) && this.keyC12Bytes == 8
					|| this.key.charAt(12) >= 128 && this.key.charAt(12) < 256 && this.keyC12Bytes == 16;
		}

		@Constraint
		public boolean keyC13Encoding() {
			return StringMethods.isASCII(this.key.charAt(13)) && this.keyC13Bytes == 8
					|| this.key.charAt(13) >= 128 && this.key.charAt(13) < 256 && this.keyC13Bytes == 16;
		}

		@Constraint
		public boolean keyC14Encoding() {
			return StringMethods.isASCII(this.key.charAt(14)) && this.keyC14Bytes == 8
					|| this.key.charAt(14) >= 128 && this.key.charAt(14) < 256 && this.keyC14Bytes == 16;
		}

		@Constraint
		public boolean keyC15Encoding() {
			return StringMethods.isASCII(this.key.charAt(15)) && this.keyC15Bytes == 8
					|| this.key.charAt(15) >= 128 && this.key.charAt(15) < 256 && this.keyC15Bytes == 16;
		}
	}
}